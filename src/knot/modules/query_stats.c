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

#include <stdio.h>

#include "contrib/mempattern.h"
#include "libknot/libknot.h"
#include "knot/common/log.h"
#include "knot/nameserver/process_query.h"
#include "knot/modules/query_stats.h"

/* Module configuration scheme. */
#define MOD_FILE	"\x04""file"
#define MOD_SING_REC	"\x0D""single-record"
#define MOD_SAVE_ALL	"\x08""save-all"

const yp_item_t scheme_mod_query_stats[] = {
	{ C_ID,         YP_TSTR, YP_VNONE },
	{ MOD_FILE,     YP_TSTR, YP_VSTR = {"knot.stats"} },
	{ MOD_SING_REC, YP_TBOOL, YP_VNONE },
	{ MOD_SAVE_ALL, YP_TBOOL, YP_VNONE },
	{ C_COMMENT,    YP_TSTR, YP_VNONE },
	{ NULL }
};

struct query_stats_ctx {
	query_stats_t *data;
	const knot_dname_t *zone_name;
};

static inline counter_t opcode_to_counter(knot_opcode_t opcode)
{
	switch (opcode) {
	case KNOT_OPCODE_QUERY:
		return ctr_opcode_query;
	case KNOT_OPCODE_IQUERY:
		return ctr_opcode_iquery;
	case KNOT_OPCODE_STATUS:
		return ctr_opcode_status;
	case KNOT_OPCODE_NOTIFY:
		return ctr_opcode_notify;
	case KNOT_OPCODE_UPDATE:
		return ctr_opcode_update;
	default:
		return ctr_none;
	}
}

static inline counter_t type_to_counter(knot_pkt_type_t type)
{
	switch (type) {
	case KNOT_QUERY_NORMAL:
		return ctr_qtype_normal;
	case KNOT_QUERY_AXFR:
		return ctr_qtype_axfr;
	case KNOT_QUERY_IXFR:
		return ctr_qtype_ixfr;
	case KNOT_QUERY_NOTIFY:
		return ctr_qtype_notify;
	case KNOT_QUERY_UPDATE:
		return ctr_qtype_update;
	default:
		return ctr_none;
	}
}

static inline counter_t rcode_to_counter(knot_rcode_t type)
{
	switch (type) {
	case KNOT_RCODE_NOERROR:
		return ctr_rcode_ok;
	case KNOT_RCODE_FORMERR:
		return ctr_rcode_formerr;
	case KNOT_RCODE_SERVFAIL:
		return ctr_rcode_servfail;
	case KNOT_RCODE_NXDOMAIN:
		return ctr_rcode_nxdomain;
	case KNOT_RCODE_NOTIMPL:
		return ctr_rcode_notimpl;
	case KNOT_RCODE_REFUSED:
		return ctr_rcode_refused;
	case KNOT_RCODE_YXDOMAIN:
		return ctr_rcode_yxdomain;
	case KNOT_RCODE_YXRRSET:
		return ctr_rcode_yxrrset;
	case KNOT_RCODE_NXRRSET:
		return ctr_rcode_nxrrset;
	case KNOT_RCODE_NOTAUTH:
		return ctr_rcode_notauth;
	case KNOT_RCODE_NOTZONE:
		return ctr_rcode_notzone;
	case KNOT_RCODE_BADVERS:
		return ctr_rcode_badvers;
	default:
		return ctr_none;
	}
}

static inline counter_t tsig_error_to_counter(knot_tsig_error_t type)
{
	switch (type) {
	case KNOT_TSIG_ERR_BADSIG:
		return ctr_rcode_tsig_badsig;
	case KNOT_TSIG_ERR_BADKEY:
		return ctr_rcode_tsig_badkey;
	case KNOT_TSIG_ERR_BADTIME:
		return ctr_rcode_tsig_badtime;
	case KNOT_TSIG_ERR_BADTRUNC:
		return ctr_rcode_tsig_badtrunc;
	default:
		return ctr_none;
	}
}

static int count(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	if (pkt == NULL || qdata == NULL || ctx == NULL) {
		return KNOT_STATE_FAIL;
	}

	struct query_stats_ctx *qsc = ctx;
	query_stats_t *qs = qsc->data;

	knot_atomic_t *opcode = qsc->data->counters + opcode_to_counter(knot_wire_get_opcode(qdata->query->wire));
	knot_atomic_t *rcode = qsc->data->counters + rcode_to_counter(qdata->rcode);
	knot_atomic_t *type = qsc->data->counters + type_to_counter(qdata->packet_type);
	knot_atomic_t *tsig = qsc->data->counters + tsig_error_to_counter(qdata->rcode_tsig);

	int query_size = qdata->query->size / BUCKET_SIZE;
	if (query_size >= HIST_REQUEST) {
		query_size = HIST_REQUEST - 1;
	}

	knot_atomic_add(qs->request_size + query_size, 1);

	knot_atomic_add(&qs->query, 1);
	knot_atomic_add(opcode, 1);
	knot_atomic_add(rcode, 1);
	knot_atomic_add(type, 1);
	knot_atomic_add(tsig, 1);

	return KNOT_STATE_DONE;
}

static void stats_save_param(struct query_module *self, struct query_stats_ctx *qsc)
{
	// Save all?
	conf_val_t val = conf_mod_get(self->config, MOD_SAVE_ALL, self->id);
	if (conf_bool(&val)) {
		qsc->data->save_all = 1;
	} else {
		qsc->data->save_all = 0;
	}

	// One record?
	val = conf_mod_get(self->config, MOD_SING_REC, self->id);
	if (conf_bool(&val)) {
		qsc->data->srec = 1;
	} else {
		qsc->data->srec = 0;
	}
}

static void stats_file_name(struct query_module *self, struct query_stats_ctx *qsc)
{
	// Get file to write to
	conf_val_t val = conf_mod_get(self->config, MOD_FILE, self->id);
	if (val.code == KNOT_EOK) {
		qsc->data->file = strdup(conf_str(&val));
	} else {
	// if default, force appending by wiping onerecord flag
		qsc->data->srec = 1;
	}
}

static void stats_init(struct query_module *self, struct query_stats_ctx *qsc,
		       const knot_dname_t *zone)
{
	// if global module - use global structure, else init new
	if (zone == NULL) {
		if (global_stats == NULL) {
			global_stats = init_global_stats();
		}
		if (global_stats->query_stats == NULL) {
			global_stats->query_stats = init_query_stats();
		}
		qsc->data = global_stats->query_stats;
		qsc->zone_name = NULL;
	} else { // If zone specific - create new
		qsc->data = init_query_stats();
		qsc->zone_name = zone;
	}
}

int query_stats_load(struct query_plan *plan, struct query_module *self,
                     const knot_dname_t *zone)
{
	struct query_stats_ctx *qsc = mm_alloc(self->mm, sizeof(*qsc));
	if (qsc == NULL) {
		MODULE_ERR(C_MOD_QUERY_STATS, "not enough memory");
		return KNOT_ENOMEM;
	}

	// init structure
	stats_init(self, qsc, zone);
	// save parameters
	stats_save_param(self, qsc);
	// file name
	stats_file_name(self, qsc);

	self->ctx = qsc;
	return query_plan_step(plan, QPLAN_END, count, self->ctx);
}

int query_stats_unload(struct query_module *self)
{
	struct query_stats_ctx *qsc = self->ctx;
	if (qsc->zone_name == NULL) {
		qsc->data = NULL;
	} else {
		deinit_query_stats(qsc->data);
	}
	return KNOT_EOK;
}

inline struct query_module *find_stats_module(list_t query_modules)
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

query_stats_t *get_query_stats(struct query_module *self)
{
	if (self->id->name[0] == C_MOD_QUERY_STATS[0] &&
	    memcmp(self->id->name + 1, C_MOD_QUERY_STATS + 1,
	           C_MOD_QUERY_STATS[0]) != 0) {
		return NULL;
	}
	struct query_stats_ctx *qsc = self->ctx;
	return qsc->data;
}
