/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "knot/common/log.h"
#include "knot/server/journal.h"
#include "knot/server/serialization.h"
#include "knot/zone/serial.h"
#include "libknot/libknot.h"
#include "contrib/endian.h"
#include "contrib/files.h"

/*! \brief Primary journal database name for main data storage. */
#define DATA_DB_NAME "data"
/*! \brief Secondary journal database name for metadata storage. */
#define META_DB_NAME "meta"
/*! \brief The key to access the version string. */
#define VERSION_KEY "version"
/*! \brief The key to access the metadata structure. */
#define METADATA_KEY "metadata"
/*! \brief Minimum journal size. */
#define FSLIMIT_MIN (1 * 1024 * 1024)
/*! \brief How many deletes per transaction do we perform. */
#define SYNC_BATCH 100
/*! \brief Define 1 for batch removal, 0 for mdb_drop call.
 * Experimental results show better page management for batch removal
 * with a small performance drop. */
#define JOURNAL_BATCH_FLUSH 1

/*! \brief Journal version. */
const char *JOURNAL_VERSION = "1.0";

#define make_key(serial, key) \
	uint32_t serial ## _be = htobe32(serial); \
	knot_db_val_t key = { &(serial ## _be), sizeof(serial) }

#define set_key(serial, new_serial) \
	serial ## _be = htobe32(new_serial)

#define get_key(data) \
	be32toh(*(uint32_t *) data)

enum {
	LAST_FLUSHED_VALID = 1 << 0, /* "last flush is valid" flag. */
	SERIAL_TO_VALID    = 1 << 1, /* "last serial_to is valid" flag. */
};

typedef struct journal_metadata {
	uint32_t first_serial;
	uint32_t last_serial;
	uint32_t last_serial_to;
	uint32_t last_flushed;
	uint32_t flags;
} journal_metadata_t;

static void copy_metadata(journal_metadata_t *a, journal_metadata_t *b)
{
	memcpy(a, b, sizeof(*a));
}

struct journal {
	knot_db_t *db;                 /*!< DB handler. */
	knot_db_t *meta_db;            /*!< Metadata DB handler. */
	const knot_db_api_t *db_api;   /*!< DB API backend. */
	char *path;                    /*!< Path to journal file. */
	size_t fslimit;                /*!< File size limit. */
	const knot_dname_t *zone_name; /*!< Associated zone name. */
	journal_metadata_t metadata;   /*!< Metadata. */
};

typedef struct journal_store_ctx {
	journal_t *journal;
	knot_db_txn_t *txn;
	knot_db_val_t *key;
	knot_db_val_t *val;
	journal_metadata_t metadata;
	int ret;
} journal_store_ctx_t;

static int store_ctx_abort(journal_store_ctx_t *ctx)
{
	ctx->journal->db_api->txn_abort(ctx->txn);
	return ctx->ret;
}

static int store_ctx_commit(journal_store_ctx_t *ctx)
{
	int ret = ctx->journal->db_api->txn_commit(ctx->txn);
	if (ret != KNOT_EOK) {
		store_ctx_abort(ctx);
		return ret;
	}

	ctx->metadata.flags |= ctx->journal->metadata.flags;
	copy_metadata(&ctx->journal->metadata, &ctx->metadata);
	return ctx->ret;
}

static int store_ctx_rebegin_txn(journal_store_ctx_t *ctx)
{
	int ret = store_ctx_commit(ctx);
	if (ret != KNOT_EOK) {
		store_ctx_abort(ctx);
		return ret;
	}

	return ctx->journal->db_api->txn_begin(ctx->journal->db, ctx->txn, 0);
}

static int load_metadata(journal_t *j)
{
	assert(j);

	knot_db_txn_t txn;
	int ret = j->db_api->txn_begin(j->meta_db, &txn, KNOT_DB_RDONLY);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_db_val_t key;
	key.len = strlen(VERSION_KEY);
	key.data = (void *)VERSION_KEY;

	knot_db_val_t val;
	ret = j->db_api->find(&txn, &key, &val, 0);
	if (ret != KNOT_EOK) {
		if (ret == KNOT_ENOENT) {
			ret = KNOT_EOK;
		}
		goto abort;
	}

	/* Compare journal version. For now just return error. */
	if (val.len != strlen(JOURNAL_VERSION) ||
	    strncmp(val.data, JOURNAL_VERSION, val.len) != 0) {
		log_zone_error(j->zone_name, "different journal version detected, overwriting");
		val.len = strlen(JOURNAL_VERSION);
		val.data = (void *)JOURNAL_VERSION;
		knot_db_txn_t write_txn;
		int ret = j->db_api->txn_begin(j->meta_db, &write_txn, 0);
		if (ret != KNOT_EOK) {
			goto abort;
		}
		j->db_api->insert(&write_txn, &key, &val, 0);
		if (ret != KNOT_EOK) {
			goto abort;
		}
		ret = j->db_api->txn_commit(&write_txn);
		if (ret != KNOT_EOK) {
			goto abort;
		}
	}

	key.len = strlen(METADATA_KEY);
	key.data = (void *)METADATA_KEY;

	ret = j->db_api->find(&txn, &key, &val, 0);
	if (ret != KNOT_EOK) {
		goto abort;
	}

	if (val.len != sizeof(journal_metadata_t)) {
		ret = KNOT_EMALF;
		goto abort;
	}

	journal_metadata_t *metadata = val.data;
	j->metadata.first_serial   = be32toh(metadata->first_serial);
	j->metadata.last_serial    = be32toh(metadata->last_serial);
	j->metadata.last_serial_to = be32toh(metadata->last_serial_to);
	j->metadata.last_flushed   = be32toh(metadata->last_flushed);
	j->metadata.flags          = be32toh(metadata->flags);

abort:
	/* We can just abort read-only transactions. */
	j->db_api->txn_abort(&txn);

	return ret;
}

static int store_metadata(journal_t *j)
{
	assert(j);

	knot_db_txn_t txn;
	int ret = j->db_api->txn_begin(j->meta_db, &txn, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_db_val_t key = { (void *)VERSION_KEY, strlen(VERSION_KEY) };
	knot_db_val_t val = { (void *)JOURNAL_VERSION, strlen(JOURNAL_VERSION) };

	ret = j->db_api->insert(&txn, &key, &val, 0);
	if (ret != KNOT_EOK) {
		j->db_api->txn_abort(&txn);
		return ret;
	}

	journal_metadata_t metadata = {
		htobe32(j->metadata.first_serial),
		htobe32(j->metadata.last_serial),
		htobe32(j->metadata.last_serial_to),
		htobe32(j->metadata.last_flushed),
		htobe32(j->metadata.flags)
	};
	knot_db_val_t key2 = { METADATA_KEY, strlen(METADATA_KEY) };
	knot_db_val_t val2 = { &metadata, sizeof(metadata) };

	ret = j->db_api->insert(&txn, &key2, &val2, 0);
	if (ret != KNOT_EOK) {
		j->db_api->txn_abort(&txn);
		return ret;
	}

	ret = j->db_api->txn_commit(&txn);
	if (ret != KNOT_EOK) {
		j->db_api->txn_abort(&txn);
		return ret;
	}

	return KNOT_EOK;
}

/*! \brief Serialize SOA "to" serial. */
static int serialize_soa_to(changeset_t *ch, uint8_t **data, size_t *remaining)
{
	if (*remaining < sizeof(uint32_t)) {
		return KNOT_ESPACE;
	}

	uint32_t soa_to_be = htobe32(knot_soa_serial(&ch->soa_to->rrs));
	memcpy(*data, &soa_to_be, sizeof(soa_to_be));
	*data += sizeof(soa_to_be);
	*remaining -= sizeof(soa_to_be);

	return KNOT_EOK;
}

/*! \brief Deserialize SOA "to" serial. */
static int deserialize_soa_to(void *entry, size_t remaining, uint32_t *soa_to)
{
	if (remaining < sizeof(uint32_t)) {
		return KNOT_ESPACE;
	}

	uint32_t soa_to_be;
	memcpy(&soa_to_be, entry, sizeof(soa_to_be));
	*soa_to = be32toh(soa_to_be);

	return KNOT_EOK;
}

static int pack_data_into(changeset_t *ch, uint8_t *data, size_t len)
{
	/* Add serial_to at the beginning of the stream. */
	int ret = serialize_soa_to(ch, &data, &len);
	assert(ret == KNOT_EOK);

	/* Serialize changeset. */
	return changeset_serialize(ch, data, len);
}

static int prepare_val_from_changeset(knot_db_val_t *val, changeset_t *ch, journal_t *j)
{
	assert(val != NULL);
	assert(ch != NULL);

	/* Add serial_to at the beginning of the stream. */
	size_t entry_size = sizeof(uint32_t) + changeset_serialized_size(ch);

	/* Refuse changesets too large (with guesstimated 4 pages reserve). */
	if (entry_size + 4*4096 >= j->fslimit) {
		return KNOT_ESPACE;
	}

	/* Reserve space for the journal entry. */
	uint8_t *data = malloc(entry_size);
	if (data == NULL) {
		return KNOT_ENOMEM;
	}

	/* Serialize the "to" serial and the changeset. */
	int ret = pack_data_into(ch, data, entry_size);
	if (ret != KNOT_EOK) {
		free(data);
		return ret;
	}

	val->len = entry_size;
	val->data = data;
	return KNOT_EOK;
}

static int try_replace_changeset(journal_store_ctx_t *ctx)
{
	int ret;
	journal_t *j = ctx->journal;
	uint32_t current_serial = j->metadata.first_serial;
	knot_db_val_t first_val;
	make_key(current_serial, first_key);

	/* Note: we require a guarantee that:
	 * ctx->metadata.serial_to == ctx->key.val, i.e. continuity is preserved
	 * ctx->metadata.first_serial is valid (it is unless journal_count() == 0)
	 * journal_count() != 0 */

	do {
		/* Find the first available changeset to remove. */
		ret = j->db_api->find(ctx->txn, &first_key, &first_val, 0);
		if (ret != KNOT_EOK) {
			assert(ret != KNOT_ENOENT); /* Cannot occur - last_flushed must be
			                             * equal to last_serial and that is
			                             * taken care of. */
			store_ctx_abort(ctx);
			return ret;
		}

		/* Get the changeset's "to" serial. */
		uint32_t soa_to = 0;
		ret = deserialize_soa_to(first_val.data, first_val.len, &soa_to);
		assert(ret == KNOT_EOK);

		/* Delete the changeset from DB. */
		ret = j->db_api->del(ctx->txn, &first_key);
		if (ret != KNOT_EOK) {
			store_ctx_abort(ctx);
			return ret;
		}

		/* Update the new first serial. */
		ctx->metadata.first_serial = soa_to;

		/* Attempt another insert. */
		ret = j->db_api->insert(ctx->txn, ctx->key, ctx->val, 0);
		ctx->ret = ret;
		if (ret == KNOT_ELIMIT) { /* Transaction is full, commit and re-begin it. */
			ret = store_ctx_rebegin_txn(ctx);
			if (ret != KNOT_EOK) {
				store_ctx_abort(ctx);
				return ret;
			}
			ret = j->db_api->insert(ctx->txn, ctx->key, ctx->val, 0);
		}
		if (ret != KNOT_EOK && ret != KNOT_ESPACE) {
			return store_ctx_abort(ctx);
		}
		if (ret == KNOT_EOK) {
			ctx->metadata.last_serial = get_key(ctx->key->data);
			deserialize_soa_to(ctx->val->data, ctx->val->len,
			                   &ctx->metadata.last_serial_to);
			ctx->metadata.flags |= SERIAL_TO_VALID;
		}

		/* Check if we've just deleted the last flushed changeset from journal. */
		if (serial_compare(current_serial, j->metadata.last_flushed) == 0) {
			ctx->metadata.flags &= ~LAST_FLUSHED_VALID;
			if (ret == KNOT_ESPACE) {
				/* The last insert was not successful and we ran
			     * out of flushed (removable) changesets. */
				ctx->metadata.flags &= ~SERIAL_TO_VALID;
				ctx->ret = KNOT_EBUSY;
				return store_ctx_commit(ctx);
			}
		}

		set_key(current_serial, soa_to);
	} while (ret == KNOT_ESPACE);

	return store_ctx_commit(ctx);
}

static int load_changeset(knot_db_val_t *val, const knot_dname_t *zone_name,
                          changeset_t **ch)
{
	changeset_t *t_ch = changeset_new(zone_name);
	if (t_ch == NULL) {
		return KNOT_ENOMEM;
	}

	/* Read journal entry. LMDB guarantees contiguous memory. */
	int ret = changeset_deserialize(t_ch, val->data + sizeof(uint32_t),
	                                val->len - sizeof(uint32_t));
	if (ret != KNOT_EOK) {
		changeset_free(t_ch);
		return ret;
	}

	*ch = t_ch;

	return KNOT_EOK;
}

static int journal_drop(journal_t *j)
{
	if (j == NULL) {
		return KNOT_EINVAL;
	}

#if JOURNAL_BATCH_FLUSH
	int ret, count, i;
	knot_db_iter_t *iter;
#else
	int ret;
#endif //JOURNAL_BATCH_FLUSH

	knot_db_txn_t txn;
	ret = j->db_api->txn_begin(j->db, &txn, 0);
	if (ret != KNOT_EOK) {
		return KNOT_ENOMEM;
	}

#if JOURNAL_BATCH_FLUSH
	count = j->db_api->count(&txn);
#else
	ret = j->db_api->clear(&txn);
	if (ret != KNOT_EOK) {
		j->db_api->txn_abort(&txn);
		return ret;
	}
#endif //JOURNAL_BATCH_FLUSH

	ret = j->db_api->txn_commit(&txn);
	if (ret != KNOT_EOK) {
		j->db_api->txn_abort(&txn);
		return ret;
	}

#if JOURNAL_BATCH_FLUSH
	knot_db_val_t key;

	while (count > 0) {
		ret = j->db_api->txn_begin(j->db, &txn, 0);
		if (ret != KNOT_EOK) {
			return KNOT_ENOMEM;
		}

		iter = j->db_api->iter_begin(&txn, KNOT_DB_FIRST);
		if (iter == NULL) {
			j->db_api->txn_abort(&txn);
			return KNOT_ENOMEM;
		}

		for (i = 0; i < SYNC_BATCH; ++i) {
			ret = j->db_api->iter_key(iter, &key);
			if (ret != KNOT_EOK) {
				j->db_api->txn_abort(&txn);
				return ret;
			}

			ret = j->db_api->del(&txn, &key);
			if (ret != KNOT_EOK) {
				j->db_api->txn_abort(&txn);
				return ret;
			}

			iter = j->db_api->iter_next(iter);
			if (iter == NULL) {
				break;
			}
		}

		j->db_api->iter_finish(iter);

		ret = j->db_api->txn_commit(&txn);
		if (ret != KNOT_EOK) {
			j->db_api->txn_abort(&txn);
			return ret;
		}

		count -= (i + 1);
	}
#endif //JOURNAL_BATCH_FLUSH

	j->metadata.first_serial = 0;

	return KNOT_EOK;
}

static int store_changeset(changeset_t *ch, journal_t *j)
{
	assert(ch);
	assert(j);

	int ret = 0;
	uint32_t k = knot_soa_serial(&ch->soa_from->rrs);

	/* Let's check if we're continuing with the current
	 * sequence of changes (serials). */
	if ((j->metadata.flags & SERIAL_TO_VALID) != 0
	    && k != j->metadata.last_serial_to) {
		/* New sequence, discard all old changesets. */
		if (j->metadata.last_flushed == j->metadata.last_serial) {
			ret = journal_drop(j);
			if (ret != KNOT_EOK) {
				return ret;
			}
			j->metadata.flags &= ~SERIAL_TO_VALID;
			j->metadata.flags &= ~LAST_FLUSHED_VALID;
		} else {
			return KNOT_EBUSY;
		}
	}

	make_key(k, key);
	knot_db_val_t val;
	ret = prepare_val_from_changeset(&val, ch, j);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Start a new transaction. */
	knot_db_txn_t txn;
	ret = j->db_api->txn_begin(j->db, &txn, 0);
	if (ret != KNOT_EOK) {
		goto end;
	}

	journal_store_ctx_t ctx = {
		.journal = j,
		.txn = &txn,
		.key = &key,
		.val = &val,
		.metadata = j->metadata
	};

	/* Attempt an insert. */
	ret = j->db_api->insert(&txn, &key, &val, 0);
	if (ret == KNOT_EOK) {
		/* \todo: performance? I wanted a flag, but it seemed too complicated
		 * to implement. */
		if (j->db_api->count(&txn) == 1) {
			ctx.metadata.first_serial = k; /* Inserted the first changeset. */
		}
		ctx.metadata.last_serial    = k;
		ctx.metadata.last_serial_to = knot_soa_serial(&ch->soa_to->rrs);
		ctx.metadata.flags         |= SERIAL_TO_VALID;
		ret = store_ctx_commit(&ctx);
		goto end;
	}
	if (ret != KNOT_ESPACE) {
		j->db_api->txn_abort(&txn);
		goto end;
	}

	/* Right now we know there's not enough space for the new changeset. Here
	 * are the possible scenarios (in order of probability, probably):
	 * 1) We flushed recently and we may need to delete one or more of already
	 *    flushed changesets. We do so and insert successfuly.
	 * 2) We flushed recently but after removing all flushed entries, we still
	 *    cannot insert. We commit and fail. The next store_changeset() call
	 *    will succeed or fail while deleting all entries.
	 * 3) We haven't flushed yet or all flushed entries are already deleted. We
	 *    have to fail.
	 * 4) There are no entries left and we still cannot insert. Fail.
	 */

	/* If there are any flushed changesets, we can purge them. If not, fail. */
	if ((j->metadata.flags & LAST_FLUSHED_VALID) == 0 || journal_count(j) == 0) {
		j->db_api->txn_abort(&txn);
		ret = KNOT_EBUSY;
		goto end;
	}

	/* We don't have enough space. Try to remove some (hopefully not all) items. */
	ret = try_replace_changeset(&ctx);

end:
	free(val.data);
	return ret;
}

static int init_db(journal_t *j)
{
	j->db_api = knot_db_lmdb_api();
	struct knot_db_lmdb_opts opts = KNOT_DB_LMDB_OPTS_INITIALIZER;
	opts.path = j->path;
	opts.mapsize = j->fslimit;
	opts.maxdbs = 2; /* One DB for data, one for metadata. */
#ifdef JOURNAL_TEST_ENV
	opts.flags.env = KNOT_DB_LMDB_NOSYNC;
#endif

	/* Init DB. */
	opts.dbname = DATA_DB_NAME;
	int ret = j->db_api->init(&j->db, NULL, &opts);
	if (ret != KNOT_EOK) {
		return ret;
	}

	opts.dbname = META_DB_NAME;
	ret = j->db_api->init(&j->meta_db, NULL, &opts);
	if (ret != KNOT_EOK) {
		j->db_api->deinit(j->db);
		return ret;
	}

	ret = load_metadata(j);
	if (ret != KNOT_EOK) {
		j->db_api->deinit(j->db);
		j->db_api->deinit(j->meta_db);
		return ret;
	}

	return KNOT_EOK;
}

journal_t *journal_new()
{
	journal_t *j = malloc(sizeof(*j));
	if (j == NULL) {
		return NULL;
	}

	memset(j, 0, sizeof(*j));
	return j;
}

void journal_free(journal_t **j)
{
	if (j == NULL || *j == NULL) {
		return;
	}

	free(*j);

	*j = NULL;
}

int journal_open(journal_t *j, const char *path, size_t fslimit,
                 const knot_dname_t *zone_name)
{
	if (j == NULL || path == NULL || zone_name == NULL) {
		return EINVAL;
	}

	if (j->path != NULL) {
		return KNOT_EBUSY;
	}

	/* Set file size. */
	j->fslimit = (fslimit > FSLIMIT_MIN) ? fslimit : FSLIMIT_MIN;

	/* Copy path. */
	j->path = strdup(path);
	if (j->path == NULL) {
		return KNOT_ENOMEM;
	}

	j->zone_name = zone_name;

	int ret = init_db(j);
	if (ret != KNOT_EOK) {
		goto free_path;
	}

	/* Check if we by any chance opened the DB with smaller mapsize than before.
	 * If so, we need to return error, flush and retry. */
	if (knot_db_lmdb_get_mapsize(j->db) > j->fslimit) {
		if (j->metadata.last_flushed != j->metadata.last_serial) {
			return KNOT_EAGAIN;
		} else {
			/* Deinit DB. */
			j->db_api->deinit(j->db);
			j->db_api->deinit(j->meta_db);
			j->db = NULL;
			j->meta_db = NULL;
			if (!remove_path(j->path)) {
				ret = KNOT_ERROR;
				goto free_path;
			}
			ret = init_db(j);
			if (ret != KNOT_EOK) {
				goto free_path;
			}
		}
	}

	return KNOT_EOK;

free_path:
	free(j->path);
	return ret;
}

void journal_close(journal_t *j)
{
	if (j == NULL || j->path == NULL) {
		return;
	}

	int ret = store_metadata(j);
	if (ret != KNOT_EOK) {
		log_zone_error(j->zone_name, "unable to store journal metadata");
	}

	/* Deinit DB. */
	j->db_api->deinit(j->db);
	j->db_api->deinit(j->meta_db);

	free(j->path);
	j->db = NULL;
	j->meta_db = NULL;
	j->path = NULL;
}

int journal_load_changesets(journal_t *j, list_t *dst, uint32_t from)
{
	if (j == NULL || dst == NULL) {
		return KNOT_EINVAL;
	}

	knot_db_txn_t txn;
	int ret = j->db_api->txn_begin(j->db, &txn, KNOT_DB_RDONLY);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Reserve space for the journal key. */
	make_key(from, key);
	knot_db_val_t val;

	knot_db_iter_t *iter = j->db_api->iter_begin(&txn, KNOT_DB_NOOP);
	if (iter == NULL) {
		ret = KNOT_ERROR;
		goto abort;
	}

	iter = j->db_api->iter_seek(iter, &key, 0);
	if (iter == NULL) {
		ret = KNOT_ENOENT;
		goto abort;
	}

	ret = j->db_api->iter_val(iter, &val);
	if (ret != KNOT_EOK) {
		goto abort;
	}

	uint32_t soa_to = 0;
	changeset_t *ch = NULL;
	while (ret == KNOT_EOK) {
		ret = deserialize_soa_to(val.data, val.len, &soa_to);
		assert(ret == KNOT_EOK);

		ret = load_changeset(&val, j->zone_name, &ch);
		if (ret != KNOT_EOK) {
			goto abort;
		}

		/* Insert into changeset list. */
		add_tail(dst, &ch->n);
		set_key(from, soa_to);

		iter = j->db_api->iter_next(iter);
		if (iter == NULL) {
			ret = KNOT_ENOENT;
			break;
		}

		ret = j->db_api->iter_key(iter, &val);
		if (ret != KNOT_EOK) {
			break;
		}

		if (soa_to != get_key(val.data)) {
			ret = j->db_api->find(&txn, &key, &val, 0);
			if (ret != KNOT_EOK) {
				break;
			}
		} else {
			ret = j->db_api->iter_val(iter, &val);
			if (ret != KNOT_EOK) {
				break;
			}
		}
	}

	/* It's okay, we just found none of the next key. */
	if (!EMPTY_LIST(*dst) && ret == KNOT_ENOENT) {
		ret = KNOT_EOK;
	}

abort:
	j->db_api->iter_finish(iter);
	/* We can just abort read-only transactions. */
	j->db_api->txn_abort(&txn);

	return ret;
}

int journal_store_changesets(journal_t *journal, list_t *src)
{
	if (journal == NULL || src == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;

	/* Begin writing to journal. */
	changeset_t *chs = NULL;
	WALK_LIST(chs, *src) {
		ret = store_changeset(chs, journal);
		if (ret != KNOT_EOK) {
			break;
		}
	}

	return ret;
}

int journal_store_changeset(journal_t *journal, changeset_t *ch)
{
	if (journal == NULL || ch == NULL) {
		return KNOT_EINVAL;
	}

	return store_changeset(ch, journal);
}

int journal_count(journal_t *journal)
{
	if (journal == NULL) {
		return KNOT_EINVAL;
	}

	knot_db_txn_t txn;
	int ret = journal->db_api->txn_begin(journal->db, &txn, KNOT_DB_RDONLY);
	if (ret != KNOT_EOK) {
		return KNOT_ENOMEM;
	}

	int count = journal->db_api->count(&txn);
	journal->db_api->txn_abort(&txn);
	return count;
}

bool journal_exists(const char *path)
{
	if (path == NULL) {
		return false;
	}

	/* Check journal file existence. */
	struct stat st;
	return stat(path, &st) == 0;
}

int journal_flush(journal_t *j)
{
	j->metadata.last_flushed = j->metadata.last_serial;
	j->metadata.flags |= LAST_FLUSHED_VALID;

	return KNOT_EOK;
}
