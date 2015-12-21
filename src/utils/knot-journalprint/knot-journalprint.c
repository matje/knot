/*  Copyright (C) 2015, 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/server/journal.h"
#include "knot/server/serialization.h"
#include "knot/updates/changesets.h"
#include "libknot/libknot.h"

#include <stdio.h>
#include <inttypes.h>

typedef struct journal_metadata {
	uint32_t first_serial;
	uint32_t last_serial;
	uint32_t last_serial_to;
	uint32_t last_flushed;
	uint32_t flags;
} journal_metadata_t;

struct journal {
	knot_db_t *db;                 /*!< DB handler. */
	knot_db_t *meta_db;            /*!< Metadata DB handler. */
	const knot_db_api_t *db_api;   /*!< DB API backend. */
	char *path;                    /*!< Path to journal file. */
	size_t fslimit;                /*!< File size limit. */
	const knot_dname_t *zone_name; /*!< Associated zone name. */
	journal_metadata_t metadata;   /*!< Metadata. */
};

const knot_dump_style_t NSUPDATE_STYLE = {
	.wrap = false,
	.show_class = true,
	.show_ttl = true,
	.verbose = false,
	.empty_ttl = false,
	.human_ttl = false,
	.human_tmstamp = true,
	.generic = false,
	.ascii_to_idn = NULL
};


static void print_rrset(knot_rrset_t *rrset)
{
	// Ignore OPT records.
	if (rrset->type == KNOT_RRTYPE_OPT) {
		return;
	}

	// Exclude TSIG record.
	if (rrset->type == KNOT_RRTYPE_TSIG) {
		return;
	}

	size_t buflen = 8192;
	char *buf = calloc(buflen, 1);

	while (knot_rrset_txt_dump(rrset, buf, buflen, &NSUPDATE_STYLE) < 0) {
		buflen += 4096;
		// Oversize protection.
		if (buflen > 100000) {
			break;
		}

		char *newbuf = realloc(buf, buflen);
		if (newbuf == NULL) {
			break;
		}
		buf = newbuf;
	}
	printf("%s", buf);

	free(buf);
}

static void print_changeset(changeset_t *ch)
{
	printf("soa from ");
	print_rrset(ch->soa_from);

	changeset_iter_t iter;
	int ret = changeset_iter_rem(&iter, ch, false);
	if (ret != KNOT_EOK) {
		return;
	}

	knot_rrset_t rrset = changeset_iter_next(&iter);
	while (!knot_rrset_empty(&rrset)) {
		printf("del ");
		print_rrset(&rrset);
		rrset = changeset_iter_next(&iter);
	}

	changeset_iter_clear(&iter);

	printf("soa to ");
	print_rrset(ch->soa_to);

	ret = changeset_iter_add(&iter, ch, false);
	if (ret != KNOT_EOK) {
		return;
	}

	rrset = changeset_iter_next(&iter);
	while (!knot_rrset_empty(&rrset)) {
		printf("add ");
		print_rrset(&rrset);
		rrset = changeset_iter_next(&iter);
	}

	changeset_iter_clear(&iter);
}

static void process_item(void *data, size_t len)
{
	changeset_t *ch = changeset_new("");
	if (ch == NULL) {
		return;
	}

	int ret = changeset_deserialize(ch, data + sizeof(uint32_t), len - sizeof(uint32_t));
	if (ret != KNOT_EOK) {
		changeset_free(ch);
		return;
	}

	print_changeset(ch);
	changeset_free(ch);
}

static void print_journal(journal_t *j)
{
	int ret = 0;
	unsigned int count = 0;
	knot_db_iter_t *iter;
	knot_db_txn_t txn;

	ret = j->db_api->txn_begin(j->db, &txn, KNOT_DB_RDONLY);
	if (ret != KNOT_EOK) {
		printf("Error: cannot begin a transaction.\n");
		return;
	}

	iter = j->db_api->iter_begin(&txn, KNOT_DB_FIRST);

	knot_db_val_t key, val;
	while (iter != NULL) {
		ret = j->db_api->iter_key(iter, &key);
		if (ret != KNOT_EOK) {
			j->db_api->txn_abort(&txn);
			return;
		}

		ret = j->db_api->iter_val(iter, &val);
		if (ret != KNOT_EOK) {
			j->db_api->txn_abort(&txn);
			return;
		}

		printf("%"PRIu32"\n", be32toh(*((uint32_t *) key.data)));
		process_item(val.data, val.len);
		++count;

		iter = j->db_api->iter_next(iter);
	}

	j->db_api->iter_finish(iter);
	j->db_api->txn_abort(&txn);
}

int main(int argc, char **argv)
{
	int ret = 0;

	if (argc == 1) {
		ret = 1;
		printf("Error: DB not specified.\n");
		goto exit;
	}

	uint8_t *apex = (uint8_t *)"\4test";
	journal_t *j = journal_new();
	journal_open(j, argv[1], 0, apex);
	if (j == NULL) {
		ret = 2;
		printf("Error: cannot open DB.\n");
		goto exit;
	}

	print_journal(j);

	journal_close(j);
	journal_free(&j);

exit:
	return ret;
}



