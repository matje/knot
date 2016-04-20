/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <fcntl.h>

#include "knot/server/journal.h"
#include "knot/server/serialization.h"
#include "libknot/db/db_lmdb.h"
#include "libknot/rrtype/soa.h"
#include "libknot/errcode.h"
#include "contrib/macros.h"

/*! \brief Infinite file size limit. */
#define FSLIMIT_DEFAULT (1 * 1024 * 1024 * (size_t)1024)
/*! \brief Minimum journal size. */
#define FSLIMIT_MIN (1 * 1024 * 1024)
/*! \brief How many deletes per transaction do we perform. */
#define SYNC_BATCH 100
/*! \brief Define 1 for batch removal, 0 for mdb_drop call.
 * Experimental results show better page management for batch removal
 * with a small performance drop. */
#define JOURNAL_BATCH_FLUSH 1

static int load_changeset(knot_db_val_t *val, const knot_dname_t *zone_name, list_t *chgs)
{
	changeset_t *ch = changeset_new(zone_name);
	if (ch == NULL) {
		return KNOT_ENOMEM;
	}

	/* Read journal entry. LMDB guarantees contiguous memory. */
	int ret = changeset_unpack_from(ch, val->data, val->len);
	if (ret != KNOT_EOK) {
		changeset_free(ch);
		return ret;
	}

	/* Insert into changeset list. */
	add_tail(chgs, &ch->n);

	return KNOT_EOK;
}

static int store_changeset(changeset_t *ch, journal_t *j)
{
	assert(ch);
	assert(j);

	uint32_t k = knot_soa_serial(&ch->soa_from->rrs);
	knot_db_val_t key = { &k, sizeof(k) };
	size_t entry_size = 0;
	int ret = changeset_binary_size(ch, &entry_size);
	assert(ret == KNOT_EOK);

	/* Reserve space for the journal entry. */
	knot_db_val_t val;
	val.len = entry_size;
	val.data = malloc(val.len);
	if (val.data == NULL) {
		return KNOT_ENOMEM;
	}

	ret = changeset_pack_to(ch, val.data, val.len);
	if (ret != KNOT_EOK) {
		goto end;
	}

	knot_db_txn_t txn;
	ret = j->db_api->txn_begin(j->db, &txn, 0);
	if (ret != KNOT_EOK) {
		goto end;
	}

	ret = j->db_api->insert(&txn, &key, &val, 0);
	if (ret != KNOT_EOK) {
		ret = KNOT_EBUSY;
		j->db_api->txn_abort(&txn);
		goto end;
	}

	ret = j->db_api->txn_commit(&txn);
	if (ret != KNOT_EOK) {
		j->db_api->txn_abort(&txn);
	}

end:
	free(val.data);
	return ret;
}

journal_t *journal_open(const char *path, size_t fslimit)
{
	assert(path);

	journal_t *j = malloc(sizeof(*j));
	if (j == NULL) {
		return NULL;
	}
	memset(j, 0, sizeof(journal_t));

	/* Set file size. */
	if (fslimit == 0) {
		j->fslimit = FSLIMIT_DEFAULT;
	} else if (fslimit < FSLIMIT_MIN) {
		j->fslimit = FSLIMIT_MIN;
	} else {
		j->fslimit = fslimit;
	}

	/* Copy path. */
	j->path = strdup(path);
	if (j->path == NULL) {
		goto fail;
	}

	j->db_api = knot_db_lmdb_api();
	struct knot_db_lmdb_opts opts = KNOT_DB_LMDB_OPTS_INITIALIZER;
	opts.path = path;
	opts.mapsize = j->fslimit;

	/* Init DB. */
	int ret = j->db_api->init(&j->db, NULL, &opts);
	if (ret != KNOT_EOK) {
		free(j->path);
		goto fail;
	}

	return j;

fail:
	free(j);

	return NULL;
}

void journal_close(journal_t **j)
{
	/* Check journal. */
	if (j == NULL || *j == NULL) {
		return;
	}

	journal_t *dj = *j;
	*j = NULL;

	/* Deinit DB. */
	dj->db_api->deinit(dj->db);

	/* Free allocated resources. */
	free(dj->path);
	free(dj);
}

int journal_load_changesets(journal_t *j, const knot_dname_t *zone_name,
                            list_t *dst, uint32_t from)
{
	if (j == NULL || zone_name == NULL || dst == NULL) {
		return KNOT_EINVAL;
	}

	knot_db_txn_t txn;
	int ret = j->db_api->txn_begin(j->db, &txn, KNOT_DB_RDONLY);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Reserve space for the journal key. */
	knot_db_val_t key;
	uint32_t key_data;
	key.len = sizeof(key_data);
	key.data = &key_data;
	*((uint32_t *)key.data) = from;

	knot_db_val_t val;

	ret = j->db_api->find(&txn, &key, &val, 0);
	if (ret != KNOT_EOK) {
		goto abort;
	}

	while (ret == KNOT_EOK) {
		ret = load_changeset(&val, zone_name, dst);
		if (ret != KNOT_EOK) {
			goto abort;
		}

		changeset_t *last = TAIL(*dst);
		*((uint32_t *)key.data) = knot_soa_serial(&last->soa_to->rrs);

		ret = j->db_api->find(&txn, &key, &val, 0);
	}

	/* It's okay, we just found none of the next key. */
	if (!EMPTY_LIST(*dst) && ret == KNOT_ENOENT) {
		ret = KNOT_EOK;
	}

abort:
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

		count -= (i + 1);

		ret = j->db_api->txn_commit(&txn);
		if (ret != KNOT_EOK) {
			j->db_api->txn_abort(&txn);
			return ret;
		}
	}
#endif //JOURNAL_BATCH_FLUSH

	return KNOT_EOK;
}
