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

#include "time.h"

#include "knot/common/stats.h"
#include "knot/common/log.h"
#include "knot/modules/query_stats.h"

static const char *descriptions[] = {
	[ctr_none]                = "none",
	[ctr_opcode_query]        = "query",
	[ctr_opcode_iquery]       = "iquery",
	[ctr_opcode_status]       = "status",
	[ctr_opcode_notify]       = "notify",
	[ctr_opcode_update]       = "update",
	[ctr_qtype_invalid]       = "invalid",
	[ctr_qtype_normal]        = "normal",
	[ctr_qtype_axfr]          = "axfr",
	[ctr_qtype_ixfr]          = "ixfr",
	[ctr_qtype_notify]        = "notify",
	[ctr_qtype_update]        = "update",
	[ctr_rcode_ok]            = "ok",
	[ctr_rcode_formerr]       = "formerr",
	[ctr_rcode_servfail]      = "servfail",
	[ctr_rcode_nxdomain]      = "nxdomain",
	[ctr_rcode_notimpl]       = "notimpl",
	[ctr_rcode_refused]       = "refused",
	[ctr_rcode_yxdomain]      = "yxdomain",
	[ctr_rcode_yxrrset]       = "yxrrset",
	[ctr_rcode_nxrrset]       = "nxrrset",
	[ctr_rcode_notauth]       = "notauth",
	[ctr_rcode_notzone]       = "notzone",
	[ctr_rcode_badvers]       = "badvers",
	[ctr_rcode_tsig_badsig]   = "tsig-badsig",
	[ctr_rcode_tsig_badkey]   = "tsig-badkey",
	[ctr_rcode_tsig_badtime]  = "tsig-badtime",
	[ctr_rcode_tsig_badtrunc] = "tsig-badtrunc",
	[ctr_rrl_ok]              = "rrl-ok",
	[ctr_rrl_slip]            = "rrl-slip",
	[ctr_rrl_drop]            = "rrl-drop",
};

#define CTRS (sizeof(descriptions) / sizeof(const char *) - 1)

int counters_max_index(void)
{
	return CTRS;
}

const char *get_descriptions(int index)
{
	return descriptions[index];
}

static const ctr_block_t blocks[] = {
	{ ctr_opcode_query,  ctr_opcode_update,       "opcode" },
	{ ctr_qtype_invalid, ctr_qtype_update,        "qtype" },
	{ ctr_rcode_ok,      ctr_rcode_tsig_badtrunc, "rcode" },
	{ ctr_rrl_ok,        ctr_rrl_drop,            "rrl" },
};

#define BLOCKS (sizeof(blocks) / sizeof(ctr_block_t))

int blocks_count(void)
{
	return BLOCKS;
}

ctr_block_t get_block(int index)
{
	return blocks[index];
}

stats_t *global_stats = NULL;

/*!
 * \brief Writes knots version
 * \param output
 */
static void write_version(FILE *output)
{
	fprintf(output, "knot-dns-%s'", PACKAGE_VERSION);
}

/*!
 * \brief Writes query stats counters.
 * \param output Output file.
 * \param qstats Source of data.
 */
static void write_counters(FILE *output, query_stats_t *qstats)
{
	int block_idx = 0;
	counter_t ctr = ctr_none + 1;
	while (ctr < CTRS) {
		// Printf block description.
		if (block_idx < BLOCKS && ctr == blocks[block_idx].begin) {
			fprintf(output,"%s:\n", blocks[block_idx].description);
		}
		// If not set otherwise, save only not empty items.
		if (qstats->counters[ctr] != 0 || qstats->save_all) {
			// Check if belongs to a block for indentation.
			if (block_idx < BLOCKS) {
				fprintf(output,"  ");
			}
			if (descriptions[ctr]) {
				fprintf(output,"%s: %ld\n", descriptions[ctr],
				                            qstats->counters[ctr]);
			} else {
				fprintf(output,"unknown: %ld\n", qstats->counters[ctr]);
			}
		}
		// Increase block id at current blocks end.
		if (ctr == blocks[block_idx].end) {
			++block_idx;
		}
		ctr++;
	}
}

/*!
 * \brief Print array of long int.
 * \param output File to be written into.
 * \param record Source array.
 * \param max_index Array size.
 * \param save_all Flag to determine if emty items should be saved.
 * \param msg Message to descibe array. NULL for no description.
 */
static void write_recorded_sizes(FILE *output, knot_atomic_t *record, int max_index,
                                 int save_all, char *msg)
{
	assert(max_index > 0);
	if (msg) {
		fprintf(output, "%s", msg);
	}
	if (!output || !record) {
		return;
	}
	for (int i = 0; i < max_index; i++) {
		if (record[i] != 0 || save_all) {
			fprintf(output, "  %d: %ld\n", i, record[i]);
		}
	}
}

/*!
 * \brief Save statistics into a file.
 * \param qdata Statistics source.
 * \param scope String describing statistics scope. Either global or zone name.
 * \return error code
 */
static int stats_save(query_stats_t *qdata, char *scope)
{
	assert(qdata->file != NULL && qdata->counters != NULL);
	FILE *output = NULL;
	// Open temporary file to replace old record with new
	char tmp_pathname[strlen(qdata->file) + 2];
	if (qdata->srec) {
		snprintf(tmp_pathname,sizeof(tmp_pathname),"%s~" , qdata->file);
		output = fopen(tmp_pathname, "w");
	}
	// Open file for appending
	else {
		output = fopen(qdata->file, "a");
	}
	if (output == NULL) {
		return knot_map_errno();
	}

	// Write record header
	fprintf(output, "---\n'statistics info':\n  scope: %s\n", scope);
	fprintf(output, "  timestamp: %lu\n", (unsigned long)time(NULL));
	fprintf(output, "  version: ");
	write_version(output);
	fprintf(output, "\n");
	// Write number of queries
	fprintf(output, "queries: %ld\n", qdata->query);
	// Write recorded request and response sizes
	write_recorded_sizes(output, qdata->request_size, HIST_REQUEST,
	                     qdata->save_all, "'recorded-request-sizes':\n");
	write_recorded_sizes(output, qdata->request_size, HIST_REQUEST,
	                     qdata->save_all, "'recorded-response-sizes':\n");
	// Write counters
	write_counters(output, qdata);

	fclose(output);
	// Atomic record replacement
	if (qdata->srec){
		rename(tmp_pathname, qdata->file);
	}

	return KNOT_EOK;
}

/*!
 * \brief Finding global module for statistics
 * Not needed?
 * \param query_modules List of modules.
 * \return Module for global statistics.
 */
static inline struct query_module *find_stats_module(list_t query_modules)
{
	struct query_module *qm = NULL;
	WALK_LIST(qm, query_modules) {
		if (qm->id->name[0] == C_MOD_QUERY_STATS[0] &&
		    memcmp(qm->id->name + 1, C_MOD_QUERY_STATS + 1,
			   C_MOD_QUERY_STATS[0]) == 0) {
			return qm;
		}
	}
	return NULL;
}

query_stats_t *get_query_stats_from_module(list_t query_modules)
{
	struct query_module *qm = find_stats_module(query_modules);
	if (qm != NULL) {
		return get_query_stats(qm);
	}
	else return NULL;
}

void stats_dump(knot_zonedb_t *db)
{
	global_stats_dump();

	if (db != NULL) {
		knot_zonedb_foreach(db, zone_stats_dump);
	}
}

void zone_stats_dump(zone_t *zone)
{
	// Find stats module belonging to given zone
	query_stats_t *qstats = get_query_stats_from_module(zone->query_modules);
	if (qstats != NULL) {
		char *name = knot_dname_to_str_alloc(zone->name);
		if (name == NULL) {
			log_warning("knot dname to string conversion failed");
		}
		int ret;
		if ((ret = stats_save(qstats, name)) != KNOT_EOK) {
			log_warning("Writing statistics into a file failed with %d for zone %s",
				    ret, name);
		} else {
			log_info("%s stats dumped to file '%s'", name, qstats->file);
		}
		free(name);
	}
}

void global_stats_dump(void)
{
	if (global_stats == NULL || global_stats->query_stats == NULL ||
	    global_stats->query_stats->file == NULL ||
		global_stats->query_stats->counters == NULL) {
		return;
	}
	int ret;
	if ((ret = stats_save(global_stats->query_stats, "global")) != KNOT_EOK) {
		log_warning("Writing statistics into a file failed with %d", ret);
	}
	else {
		log_info("Global stats dumped to file '%s'.", global_stats->query_stats->file);
	}
}

query_stats_t *init_query_stats(void)
{
	query_stats_t *stats = malloc(sizeof(*stats));
	if(stats == NULL) {
		log_warning("failed to allocate memory");
		return NULL;
	}
	stats->counters = calloc(sizeof(descriptions), sizeof(stats->counters));
	if(stats->counters == NULL) {
		log_warning("failed to allocate memory");
		free(stats);
		return NULL;
	}

	stats->query = 0;
	stats->save_all = 0;
	stats->srec = 0;

	memset(stats->request_size,  0, HIST_REQUEST  * sizeof(knot_atomic_t));
	memset(stats->response_size, 0, HIST_RESPONSE * sizeof(knot_atomic_t));

	stats->file = NULL;

	return stats;
}

stats_t *init_global_stats(void)
{
	stats_t *stats = malloc(sizeof(*stats));
	if (stats == NULL) {
		log_warning("failed to allocate memory");
		return NULL;
	}

	stats->query_stats = NULL;
	stats->dump_timer = 0;
	stats->thread_state = 0;

	return stats;
}

static void *dumper(void *server)
{
	server_t *serv = server;
	while (1) {
		if (global_stats != NULL && global_stats->dump_timer > 0) {
			stats_dump(serv->zone_db);
			sleep(global_stats->dump_timer);
		}
	}

	return NULL;
}

void global_stats_init()
{
	if (global_stats == NULL) {
		global_stats = init_global_stats();
	}

	if (global_stats != NULL && global_stats->query_stats == NULL) {
		global_stats->query_stats = init_query_stats();
	}
}

int reconfigure_statistics(conf_t *conf, server_t *server)
{
	global_stats_init();
	conf_val_t val = conf_get(conf, C_STATS, C_STATS_TIMER);
	global_stats->dump_timer = conf_int(&val);
	if (global_stats->dump_timer > 0) {
		if(!global_stats->thread_state) {
			int ret = pthread_create(&global_stats->dump_handler, NULL, dumper, server);
			if (ret != 0) {
				log_warning("Failed to create a thread for statistics.");
			} else {
				global_stats->thread_state = 1;
			}
		}
	} else if (global_stats->thread_state) {
		pthread_cancel(global_stats->dump_handler);
		pthread_join(global_stats->dump_handler, NULL);
		global_stats->thread_state = 0;
	}

	return KNOT_EOK;
}

void deinit_query_stats(query_stats_t *stats)
{
	if (stats == NULL) {
		return;
	}

	if (stats->counters != NULL) {
		free(stats->counters);
	}

	if (stats->file != NULL) {
		free(stats->file);
	}

	free(stats);
	stats = NULL;
}

void deinit_global_stats(stats_t *stats)
{
	if (stats == NULL) {
		return;
	}

	if (stats->thread_state) {
		pthread_cancel(stats->dump_handler);
		pthread_join(stats->dump_handler, NULL);
	}

	if (stats->query_stats != NULL) {
		deinit_query_stats(stats->query_stats);
	}

	free(stats);
	stats = NULL;
}
