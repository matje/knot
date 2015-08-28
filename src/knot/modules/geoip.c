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

#include <GeoIP.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/modules/geoip.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/process_query.h"

/*
 * mod-geoip:
 *   - id: default
 *     database4: /usr/share/GeoIP/GeoIP.dat
 *     database6: /usr/share/GeoIP/GeoIPv6.dat
 *
 * template:
 *   - id: default
 *     module: mod-geoip/default
 */

// TODO: possibly switch to https://github.com/maxmind/libmaxminddb

#define LOG_PREFIX "GeoIP module, "
#define geoip_error(msg...) log_error(LOG_PREFIX msg)
#define geoip_info(msg...) log_info(LOG_PREFIX msg)

const yp_item_t scheme_mod_geoip[] = {
	{ C_ID,        YP_TSTR, YP_VNONE },
	{ C_GEOIP_DB4, YP_TSTR, YP_VNONE },
	{ C_GEOIP_DB6, YP_TSTR, YP_VNONE },
	{ C_COMMENT,   YP_TSTR, YP_VNONE },
	{ NULL }
};

struct geoip_ctx {
	GeoIP *db4;
	GeoIP *db6;
};

static struct geoip_ctx *geoip_ctx_new(void)
{
	return calloc(1, sizeof(struct geoip_ctx));
}

static void geoip_ctx_free(struct geoip_ctx *ctx)
{
	if (!ctx) {
		return;
	}

	GeoIP_delete(ctx->db4);
	GeoIP_delete(ctx->db6);
	free(ctx);
}

static const char *get_country(struct geoip_ctx *ctx, const struct sockaddr_storage *ss)
{
	assert(ctx);
	assert(ss);

	GeoIPLookup lookup = { 0 };

	if (ss->ss_family == AF_INET && ctx->db4 != NULL) {
		struct sockaddr_in *sa = (struct sockaddr_in *)ss;
		uint32_t ipnum = ntohl(sa->sin_addr.s_addr);
		return GeoIP_country_code_by_ipnum_gl(ctx->db4, ipnum, &lookup);
	}

	if (ss->ss_family == AF_INET6 && ctx->db6 != NULL) {
		struct sockaddr_in6 *sa = (struct sockaddr_in6 *)ss;
		return GeoIP_country_code_by_ipnum_v6_gl(ctx->db6, sa->sin6_addr, &lookup);
	}

	return NULL;
}

static int geoip_addional(int state, knot_pkt_t *pkt, struct query_data *qdata, void *_ctx)
{
	assert(pkt);
	assert(qdata);
	assert(_ctx);

	struct geoip_ctx *ctx = _ctx;

	// synthesize TXT record with country of the originating query

	const knot_dname_t *owner = (uint8_t *)"\x7""country""\x5""geoip";

	const char *country = get_country(ctx, qdata->param->remote);
	if (country == NULL) {
		country = "unknown";
	}

	uint8_t buffer[16] = { 0 };
	int wrote = snprintf((char *)buffer, sizeof(buffer), "%c%s",
				(int)strlen(country), country);
	if (wrote < 0) {
		return ERROR;
	}

	knot_rrset_t *rr;
	rr = knot_rrset_new(owner, KNOT_RRTYPE_TXT, KNOT_CLASS_IN, &pkt->mm);
	knot_rrset_add_rdata(rr, buffer, wrote, 0, &pkt->mm);
	knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, rr, KNOT_PF_NULL);

	return state;
}

static bool is_configured(conf_check_t *args, const yp_name_t *option)
{
	conf_val_t database = conf_rawid_get_txn(args->conf, args->txn,
	                                         C_MOD_GEOIP, option,
	                                         args->previous->id,
	                                         args->previous->id_len);

	return (database.code == KNOT_EOK);
}

int geoip_check(conf_check_t *args)
{
	if (is_configured(args, C_GEOIP_DB4) || is_configured(args, C_GEOIP_DB6)) {
		return KNOT_EOK;
	}

	*args->err_str = "no database specified";
	return KNOT_EINVAL;
}

int open_database(GeoIP **db_ptr, int family, struct query_module *self)
{
	assert(db_ptr);
	assert(family == AF_INET || family == AF_INET6);
	assert(self);

	const yp_name_t *option = family == AF_INET ? C_GEOIP_DB4 : C_GEOIP_DB6;
	conf_val_t val = conf_mod_get(self->config, option, self->id);
	if (val.code != KNOT_EOK) {
		*db_ptr = NULL;
		return KNOT_EOK;
	}

	const char *path = conf_str(&val);
	assert(path);

	GeoIP *db = GeoIP_open(path, GEOIP_MEMORY_CACHE);
	if (!db) {
		return KNOT_EINVAL;
	}

	unsigned int edition = GeoIP_database_edition(db);
	bool valid_db;

	switch (edition) {
	case GEOIP_COUNTRY_EDITION:
	case GEOIP_LARGE_COUNTRY_EDITION:
		valid_db = (family == AF_INET);
		break;
	case GEOIP_COUNTRY_EDITION_V6:
	case GEOIP_LARGE_COUNTRY_EDITION_V6:
		valid_db = (family == AF_INET6);
		break;
	default:
		valid_db = false;
		break;
	}

	if (!valid_db) {
		GeoIP_delete(db);
		return KNOT_ENOTSUP;
	}

	*db_ptr = db;
	return KNOT_EOK;
}

int geoip_load(struct query_plan *plan, struct query_module *self)
{
	assert(plan);
	assert(self);

	struct geoip_ctx *ctx = geoip_ctx_new();
	if (!ctx) {
		geoip_error("failed to allocate context");
		return KNOT_ENOMEM;
	}

	int r;

	r = open_database(&ctx->db4, AF_INET, self);
	if (r != KNOT_EOK) {
		geoip_error("failed to open IPv4 database (%s)", knot_strerror(r));
		geoip_ctx_free(ctx);
		return KNOT_EINVAL;
	}

	r = open_database(&ctx->db6, AF_INET6, self);
	if (r != KNOT_EOK) {
		geoip_error("failed to open IPv6 database (%s)", knot_strerror(r));
		geoip_ctx_free(ctx);
		return KNOT_EINVAL;
	}

	assert(ctx->db4 || ctx->db6);

	query_plan_step(plan, QPLAN_ADDITIONAL, geoip_addional, ctx);

	self->ctx = ctx;

	return KNOT_EOK;
}

int geoip_unload(struct query_module *self)
{
	assert(self);

	struct geoip_ctx *ctx = self->ctx;
	assert(self->ctx);
	geoip_ctx_free(ctx);
	self->ctx = NULL;

	return KNOT_EOK;
}
