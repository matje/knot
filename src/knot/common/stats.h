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

#pragma once

#include "knot/nameserver/process_query.h"
#include "knot/zone/zonedb.h"
#include "contrib/atomic.h"

#define BUCKET_SIZE	16
#define HIST_REQUEST	(288 / BUCKET_SIZE)
#define HIST_RESPONSE	(4096 / BUCKET_SIZE)

typedef enum {
	ctr_none = 0,
	ctr_opcode_query,
	ctr_opcode_iquery,
	ctr_opcode_status,
	ctr_opcode_notify,
	ctr_opcode_update,
	ctr_qtype_invalid,
	ctr_qtype_normal,
	ctr_qtype_axfr,
	ctr_qtype_ixfr,
	ctr_qtype_notify,
	ctr_qtype_update,
	ctr_rcode_ok,
	ctr_rcode_formerr,
	ctr_rcode_servfail,
	ctr_rcode_nxdomain,
	ctr_rcode_notimpl,
	ctr_rcode_refused,
	ctr_rcode_yxdomain,
	ctr_rcode_yxrrset,
	ctr_rcode_nxrrset,
	ctr_rcode_notauth,
	ctr_rcode_notzone,
	ctr_rcode_badvers,
	ctr_rcode_tsig_badsig,
	ctr_rcode_tsig_badkey,
	ctr_rcode_tsig_badtime,
	ctr_rcode_tsig_badtrunc,
	ctr_rrl_ok,
	ctr_rrl_slip,
	ctr_rrl_drop,
} counter_t;

typedef struct {
	counter_t begin;
	counter_t end;
	char *description;
} ctr_block_t;

typedef struct {
	knot_atomic_t *counters;
	knot_atomic_t query;
	knot_atomic_t request_size[HIST_REQUEST];
	knot_atomic_t response_size[HIST_RESPONSE];
	char *file;
	bool save_all;
	bool single_record;
} query_stats_t;

typedef struct {
	query_stats_t *query_stats;
	bool active_thread;
	pthread_t dump_handler;
	uint32_t dump_timer;
} stats_t;

// Global statistics.
extern stats_t *global_stats;

int counters_max_index(void);
int blocks_count(void);
const char *get_descriptions(int index);
ctr_block_t get_block(int index);

query_stats_t *get_query_stats_from_module(list_t query_modules);

/*!
 * \brief Save statistics of specific zone.
 * \param zone Source zone
 */
void zone_stats_dump(zone_t *zone);

/*!
 * \brief Function for saving global statistics. If statistics are off, nothing will happen.
 */
void global_stats_dump(void);

static inline void stats_inc(counter_t ctr)
{
	if (global_stats->query_stats->counters != NULL) {
		knot_atomic_add(global_stats->query_stats->counters + ctr, 1);
	}
}

static inline void stats_dec(counter_t ctr)
{
	if (global_stats->query_stats->counters != NULL) {
		knot_atomic_sub(global_stats->query_stats->counters + ctr, 1);
	}
}

static inline void stats_add(counter_t ctr, unsigned int val)
{
	if (global_stats->query_stats->counters != NULL) {
		knot_atomic_add(global_stats->query_stats->counters + ctr, val);
	}
}

static inline void stats_sub(counter_t ctr, unsigned int val)
{
	if (global_stats->query_stats->counters != NULL) {
		knot_atomic_sub(global_stats->query_stats->counters + ctr, val);
	}
}

/*!
 * \brief Inicialize query stats structure
 * \return Inicialized structure
 */
query_stats_t *init_query_stats(void);

/*!
 * \brief Destroy query_stats_t structure
 * \param stats  Structure to be deinitialized
 */
void deinit_query_stats(query_stats_t *stats);

int stats_reconfigure(conf_t *conf, server_t *server);

/*!
 * \brief Destroy stats_t structure
 * \param stats  Structure to be deinitialized
 */
void stats_deinit(void);

