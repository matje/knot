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

#include "knot/common/log.h"
#include "knot/modules/rrl.h"
#include "knot/server/rrl.h"
#include "contrib/sockaddr.h"
#include "contrib/mempattern.h"
#include "knot/nameserver/process_query.h"

/* Module configuration scheme. */
#define MOD_RATE_LIMIT		"\x0A""rate-limit"
#define MOD_SLIP		"\x04""slip"
#define MOD_TBL_SIZE		"\x0A""table-size"
#define MOD_WHITELIST		"\x09""whitelist"

const yp_item_t scheme_mod_rrl[] = {
	{ C_ID,           YP_TSTR,  YP_VNONE },
	{ MOD_RATE_LIMIT, YP_TINT,  YP_VINT = { 1, INT32_MAX, 0 } },
	{ MOD_SLIP,       YP_TINT,  YP_VINT = { 0, RRL_SLIP_MAX, 1 } },
	{ MOD_TBL_SIZE,	  YP_TINT,  YP_VINT = { 1, INT32_MAX, 393241 } },
	{ MOD_WHITELIST,  YP_TDATA, YP_VDATA = { 0, NULL, addr_range_to_bin,
	                                         addr_range_to_txt }, YP_FMULTI },
	{ C_COMMENT,      YP_TSTR,  YP_VNONE },
	{ NULL }
};

int check_mod_rrl(conf_check_t *args)
{
	conf_val_t rl = conf_rawid_get_txn(args->conf, args->txn, C_MOD_RRL,
	                                   MOD_RATE_LIMIT, args->id, args->id_len);
	if (rl.code != KNOT_EOK) {
		args->err_str = "no rate limit specified";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

typedef struct {
	rrl_table_t *rrl;
	int slip;
	conf_val_t whitelist;
} rrl_ctx_t;

static int ratelimit_apply(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	if (pkt == NULL || qdata == NULL || ctx == NULL) {
		return KNOT_STATE_FAIL;
	}

	rrl_ctx_t *context = ctx;

	/* Exempt clients. */
	if (conf_addr_range_match(&context->whitelist, qdata->param->remote)) {
		return state;
	}

	rrl_req_t rrl_rq = { 0 };
	rrl_rq.w = pkt->wire;
	rrl_rq.query = qdata->query;
	if (!EMPTY_LIST(qdata->wildcards)) {
		rrl_rq.flags = RRL_WILDCARD;
	}

	int ret = rrl_query(context->rrl, qdata->param->remote, &rrl_rq, qdata->zone);
	if (ret == KNOT_EOK) {
		/* Rate limiting not applied. */
		return state;
	}

	/* Now it is slip or drop. */
	if (context->slip > 0 && rrl_slip_roll(context->slip)) {
		/* Answer slips. */
		if (process_query_error(pkt, qdata) != KNOT_STATE_DONE) {
			return KNOT_STATE_FAIL;
		}
		knot_wire_set_tc(pkt->wire);
	} else {
		/* Drop answer. */
		pkt->size = 0;
	}

	return KNOT_STATE_DONE;
}

int rrl_load(struct query_plan *plan, struct query_module *self,
             const knot_dname_t *zone)
{
	if (plan == NULL || self == NULL) {
		return KNOT_EINVAL;
	}

	/* Create RRL context. */
	rrl_ctx_t *ctx = mm_alloc(self->mm, sizeof(rrl_ctx_t));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}
	memset(ctx, 0, sizeof(*ctx));

	/* Create table. */
	conf_val_t val = conf_mod_get(self->config, MOD_TBL_SIZE, self->id);
	ctx->rrl = rrl_create(conf_int(&val));
	if (ctx->rrl == NULL) {
		mm_free(self->mm, ctx);
		return KNOT_ENOMEM;
	}

	/* Set locks. */
	int ret = rrl_setlocks(ctx->rrl, RRL_LOCK_GRANULARITY);
	if (ret != KNOT_EOK) {
		rrl_unload(self);
		return ret;
	}

	/* Set rate limit. */
	val = conf_mod_get(self->config, MOD_RATE_LIMIT, self->id);
	ret = rrl_setrate(ctx->rrl, conf_int(&val));
	if (ret != KNOT_EOK) {
		rrl_unload(self);
		return ret;
	}

	/* Get whitelist */
	val = conf_mod_get(self->config, MOD_WHITELIST, self->id);
	ctx->whitelist = val;

	/* Get slip */
	val = conf_mod_get(self->config, MOD_SLIP, self->id);
	ctx->slip = conf_int(&val);

	self->ctx = ctx;

	return query_plan_step(plan, QPLAN_END, ratelimit_apply, self->ctx);
}

int rrl_unload(struct query_module *self)
{
	if (self == NULL) {
		return KNOT_EINVAL;
	}

	rrl_ctx_t *ctx = self->ctx;
	rrl_destroy(ctx->rrl);
	mm_free(self->mm, self->ctx);

	return KNOT_EOK;
}
