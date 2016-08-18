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
#include <stdint.h>

#include "contrib/trim.h"
#include "dnssec/random.h"
#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/query/layer.h"
#include "knot/query/query.h"
#include "knot/zone/zone.h"
#include "libknot/errcode.h"

#include "contrib/mempattern.h" // mm_free()
#include "knot/nameserver/axfr.h" // struct xfr_proc
#include "knot/zone/zonefile.h" // err_handler_logger_t
#include <urcu.h> // synchronize_rcu()
#include "contrib/print.h" // time_diff
#include "knot/zone/serial.h" // serial_compare (move to libknot)

#warning TSIG checking disabled
#define NS_NEED_TSIG_SIGNED(...) \
	log_debug("[debug] %s:%d missing TSIG check", __func__, __LINE__)

/*
 *  REFRESH EVENT PROCESSING
 *  ========================
 *                               O
 *                               |
 *                         +-----v-----+
 *                         |   BEGIN   |
 *                         +---+---+---+
 *               has SOA       |   |           no SOA
 *         +-------------------+   +------------------------------+
 *         |                                                      |
 *  +------v------+  outdated  +--------------+   error   +-------v------+
 *  |  SOA query  +------------>  IXFR query  +----------->  AXFR query  |
 *  +-----+---+---+            +------+-------+           +----+----+----+
 *  error |   | current               | success        success |    | error
 *        |   +-----+ +---------------+                        |    |
 *        |         | | +--------------------------------------+    |
 *        |         | | |              +----------+  +--------------+
 *        |         | | |              |          |  |
 *        |      +--v-v-v--+           |       +--v--v--+
 *        |      |  DONE   |           |       |  FAIL  |
 *        |      +---------+           |       +--------+
 *        +----------------------------+
 */

enum refresh_state {
	REFRESH_STATE_INVALID = 0,
	REFRESH_STATE_SOA_QUERY,
	REFRESH_STATE_TRANSFER,
};

struct refresh_result {
	zone_contents_t *zone;
	unsigned messages; //
	unsigned bytes;
	time_t begin;
	time_t end;
};

struct refresh_data {
	enum refresh_state state;
	const knot_dname_t *zone;
	const knot_rrset_t *soa;
	struct answer_data adata;

	struct refresh_result result;
};

#define TRACEPOINT() log_debug("[debug] %s:%d\n", __func__, __LINE__)


// XXX: -- AXFR --

static void axfr_cleanup(struct answer_data *data)
{
	assert(data != NULL);

	struct xfr_proc *proc = data->ext;
	if (proc) {
		zone_contents_deep_free(&proc->contents);
		mm_free(data->mm, proc);
		data->ext = NULL;
	}
}

static int axfr_init(struct refresh_data *rdata)
{
	assert(rdata);
	struct answer_data *data = &rdata->adata;

	/* Create new zone contents. */
	rdata->result.zone = zone_contents_new(rdata->zone);
	if (!rdata->result.zone) {
		return KNOT_ENOMEM;
	}

	/* Create new processing context. */
	struct xfr_proc *proc = mm_alloc(data->mm, sizeof(struct xfr_proc));
	if (proc == NULL) {
		zone_contents_deep_free(&rdata->result.zone);
		return KNOT_ENOMEM;
	}

	memset(proc, 0, sizeof(struct xfr_proc));
//	proc->contents = new_contents;
	gettimeofday(&proc->tstamp, NULL);

	/* Set up cleanup callback. */
	data->ext = proc;
	data->ext_cleanup = &axfr_cleanup;

	return KNOT_EOK;
}

//static int axfr_answer_finalize(struct refresh_data *rdata)
//{
//	struct answer_data *adata = &rdata->adata;
//	struct timeval now;
//	gettimeofday(&now, NULL);
//
//	/*
//	 * Adjust zone so that node count is set properly and nodes are
//	 * marked authoritative / delegation point.
//	 */
//	struct xfr_proc *proc = adata->ext;
//	int rc = zone_contents_adjust_full(proc->contents);
//	if (rc != KNOT_EOK) {
//		return rc;
//	}
//
//	err_handler_logger_t handler;
//	handler._cb.cb = err_handler_logger;
//	rc = zone_do_sem_checks(proc->contents, false, &handler._cb);
//
//	if (rc != KNOT_EOK) {
//		return rc;
//	}
//
//	/* Switch contents. */
//	zone_t *zone = adata->param->zone;
//	zone_contents_t *old_contents =
//	                zone_switch_contents(zone, proc->contents);
//	zone->flags &= ~ZONE_EXPIRED;
//	synchronize_rcu();
//
//	if (old_contents != NULL) {
//		AXFRIN_LOG(LOG_INFO, "finished, "
//		           "serial %u -> %u, %.02f seconds, %u messages, %u bytes",
//		           zone_contents_serial(old_contents),
//		           zone_contents_serial(proc->contents),
//		           time_diff(&proc->tstamp, &now) / 1000.0,
//		           proc->npkts, proc->nbytes);
//	} else {
//		AXFRIN_LOG(LOG_INFO, "finished, "
//		           "serial %u, %.02f seconds, %u messages, %u bytes",
//		           zone_contents_serial(proc->contents),
//		           time_diff(&proc->tstamp, &now) / 1000.0,
//		           proc->npkts, proc->nbytes);
//	}
//
//	/* Do not free new contents with cleanup. */
//	zone_contents_deep_free(&old_contents);
//	proc->contents = NULL;
//
//	return KNOT_EOK;
//}

static int axfr_consume_packet(knot_pkt_t *pkt, zone_contents_t *zone)
{
	assert(pkt);
	assert(zone);

	zcreator_t zc = { .z = zone, .master = false, .ret = KNOT_EOK };

	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	const knot_rrset_t *answer_rr = knot_pkt_rr(answer, 0);
	for (uint16_t i = 0; i < answer->count; ++i) {
		if (answer_rr[i].type == KNOT_RRTYPE_SOA &&
		    node_rrtype_exists(zc.z->apex, KNOT_RRTYPE_SOA)) {
			return KNOT_STATE_DONE;
		} else {
			int ret = zcreator_step(&zc, &answer_rr[i]);
			if (ret != KNOT_EOK) {
				return KNOT_STATE_FAIL;
			}
		}
	}

	return KNOT_STATE_CONSUME;
}

int axfr_consume(knot_pkt_t *pkt, struct refresh_data *rdata)
{
	struct answer_data *adata = &rdata->adata;

	if (pkt == NULL || adata == NULL) {
		return KNOT_STATE_FAIL;
	}

	/* Check RCODE. */
	uint8_t rcode = knot_wire_get_rcode(pkt->wire);
	if (rcode != KNOT_RCODE_NOERROR) {
		const knot_lookup_t *lut = knot_lookup_by_id(knot_rcode_names, rcode);
		if (lut != NULL) {
			AXFRIN_LOG(LOG_WARNING, "server responded with %s", lut->name);
		}
		return KNOT_STATE_FAIL;
	}

	/* Initialize processing with first packet. */
	if (adata->ext == NULL) {
		NS_NEED_TSIG_SIGNED(&adata->param->tsig_ctx, 0);
		AXFRIN_LOG(LOG_INFO, "starting");

		int ret = axfr_init(rdata);
		if (ret != KNOT_EOK) {
			AXFRIN_LOG(LOG_WARNING, "failed (%s)", knot_strerror(ret));
			return KNOT_STATE_FAIL;
		}
	} else {
		NS_NEED_TSIG_SIGNED(&adata->param->tsig_ctx, 100);
	}

	/* Update counters. */
	struct xfr_proc *counters = adata->ext;
	counters->npkts += 1;
	counters->nbytes += pkt->size;

	/* Process answer packet. */
	int ret = axfr_consume_packet(pkt, rdata->result.zone);
	if (ret == KNOT_STATE_DONE) {
		NS_NEED_TSIG_SIGNED(&adata->param->tsig_ctx, 0);
		/* This was the last packet, finalize zone and publish it. */
//		int fret = axfr_answer_finalize(rdata);
//		if (fret != KNOT_EOK) {
//			ret = KNOT_STATE_FAIL;
//		}
	}

	return ret;
}

static int soa_query_produce(knot_layer_t *layer, knot_pkt_t *pkt)
{
	TRACEPOINT();

	struct refresh_data *data = layer->data;

	query_init_pkt(pkt);

	int r = knot_pkt_put_question(pkt, data->zone, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);
	if (r != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

	return KNOT_STATE_CONSUME;
}

static int soa_query_consume(knot_layer_t *layer, knot_pkt_t *pkt)
{
	TRACEPOINT();

	struct refresh_data *data = layer->data;

	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	if (answer->count != 1) {
		return KNOT_STATE_FAIL;
	}

	const knot_rrset_t *rr = knot_pkt_rr(answer, 0);
	if (rr->type != KNOT_RRTYPE_SOA || rr->rrs.rr_count != 1) {
		return KNOT_STATE_FAIL;
	}

	uint32_t local_serial = knot_soa_serial(&data->soa->rrs);
	uint32_t remote_serial = knot_soa_serial(&rr->rrs);
	log_debug("serial local %u, remote %u", local_serial, remote_serial);

	if (serial_compare(remote_serial, local_serial) > 0) {
		data->state = REFRESH_STATE_TRANSFER;
		//return KNOT_STATE_PRODUCE;
		return KNOT_STATE_RESET;
	} else {
		return KNOT_STATE_DONE;
	}
}

static int transfer_produce(knot_layer_t *layer, knot_pkt_t *pkt)
{
	TRACEPOINT();
	struct refresh_data *data = layer->data;

	uint16_t qtype = data->soa ? KNOT_RRTYPE_IXFR : KNOT_RRTYPE_AXFR;

	query_init_pkt(pkt);
	knot_pkt_put_question(pkt, data->zone, KNOT_CLASS_IN, qtype);

	if (data->soa) {
		knot_pkt_begin(pkt, KNOT_AUTHORITY);
		knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, data->soa, 0);
	}

	return KNOT_STATE_CONSUME;
}

static int transfer_consume(knot_layer_t *layer, knot_pkt_t *pkt)
{
	TRACEPOINT();

	struct refresh_data *data = layer->data;
	return axfr_consume(pkt, data);
//	return KNOT_STATE_FAIL;
}

static int refresh_begin(knot_layer_t *layer, void *_data)
{
	layer->data = _data;
	struct refresh_data *data = _data;

	if (data->soa) {
		data->state = REFRESH_STATE_SOA_QUERY;
	} else {
		data->state = REFRESH_STATE_TRANSFER;
	}

	return KNOT_STATE_PRODUCE;
}

static int refresh_produce(knot_layer_t *layer, knot_pkt_t *pkt)
{
	struct refresh_data *data = layer->data;

	switch (data->state) {
	case REFRESH_STATE_SOA_QUERY: return soa_query_produce(layer, pkt);
	case REFRESH_STATE_TRANSFER:  return transfer_produce(layer, pkt);
	default:
		return KNOT_STATE_FAIL;
	}
}

static int refresh_consume(knot_layer_t *layer, knot_pkt_t *pkt)
{
	struct refresh_data *data = layer->data;

	switch (data->state) {
	case REFRESH_STATE_SOA_QUERY: return soa_query_consume(layer, pkt);
	case REFRESH_STATE_TRANSFER:  return transfer_consume(layer, pkt);
	default:
		return KNOT_STATE_FAIL;
	}
}

static int refresh_reset(knot_layer_t *layer)
{
	return KNOT_STATE_PRODUCE;
}

static const knot_layer_api_t REFRESH_API = {
	.begin = refresh_begin,
	.produce = refresh_produce,
	.consume = refresh_consume,
	.reset = refresh_reset,
};

static int publish_zone(zone_t *zone, zone_contents_t *content)
{
	int r = zone_contents_adjust_full(content);
	if (r != KNOT_EOK) {
		return r;
	}

	err_handler_logger_t handler;
	handler._cb.cb = err_handler_logger;
	r = zone_do_sem_checks(content, false, &handler._cb);
	if (r != KNOT_EOK) {
		return r;
	}

	zone_contents_t *old = zone_switch_contents(zone, content);
	zone->flags &= ~ZONE_EXPIRED;
	synchronize_rcu();

	/// XXX:
	log_debug("[debug] NEW ZONE CONTENT PUBLISHED");
	log_zone_info(zone->name, "NEW CONTENT, serial %u", zone_contents_serial(content));

	zone_contents_deep_free(&old);

	return KNOT_EOK;
}

#include "knot/query/requestor.h"

static int x_try_refresh(conf_t *conf, zone_t *zone, const conf_remote_t *master, void *ctx)
{
	// XXX: COPY PASTED

	assert(zone);
	assert(master);

	// TMP
	struct process_answer_param pap = { 0 };
	pap.zone = zone;
	pap.conf = conf;
	pap.remote = &master->addr;

	struct refresh_data data = {
		.zone = zone->name,
		.soa = NULL, // TODO: set me
		.adata = { .param = &pap },
	};

	knot_rrset_t soa = { 0 };
	if (zone->contents) {
		soa = node_rrset(zone->contents->apex, KNOT_RRTYPE_SOA);
		data.soa = &soa;
	}

	struct knot_requestor requestor;
	knot_requestor_init(&requestor, &REFRESH_API, &data, NULL);

	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	if (!pkt) {
		knot_requestor_clear(&requestor);
		return KNOT_ENOMEM;
	}

	const struct sockaddr *dst = (struct sockaddr *)&master->addr;
	const struct sockaddr *src = (struct sockaddr *)&master->via;
	struct knot_request *req = knot_request_make2(NULL, dst, src, pkt, &master->key, 0);
	if (!req) {
		knot_request_free(req, NULL);
		knot_requestor_clear(&requestor);
		return KNOT_ENOMEM;
	}

	// XXX: hardcoded
	int timeout = 2000;

	int ret = knot_requestor_exec(&requestor, req, timeout);
	knot_request_free(req, NULL);
	knot_requestor_clear(&requestor);

	// XXX: memoru allocator

	if (data.result.zone) {
		ret = publish_zone(zone, data.result.zone);
	}

	return ret;
}

#define BOOTSTRAP_RETRY (30) /*!< Interval between AXFR bootstrap retries. */
#define BOOTSTRAP_MAXTIME (24*60*60) /*!< Maximum AXFR retry cap of 24 hours. */

#define LOG_TRANSFER(severity, pkt_type, msg, ...) \
	if (pkt_type == KNOT_QUERY_AXFR) { \
		ZONE_QUERY_LOG(severity, zone, master, "AXFR, incoming", msg, ##__VA_ARGS__); \
	} else { \
		ZONE_QUERY_LOG(severity, zone, master, "IXFR, incoming", msg, ##__VA_ARGS__); \
	}

/*! \brief Get next bootstrap interval. */
uint32_t bootstrap_next(uint32_t interval)
{
	interval *= 2;
	interval += dnssec_random_uint32_t() % BOOTSTRAP_RETRY;
	if (interval > BOOTSTRAP_MAXTIME) {
		interval = BOOTSTRAP_MAXTIME;
	}
	return interval;
}

/*! \brief Get SOA from zone. */
static const knot_rdataset_t *zone_soa(zone_t *zone)
{
	return node_rdataset(zone->contents->apex, KNOT_RRTYPE_SOA);
}

//static int try_refresh(conf_t *conf, zone_t *zone, const conf_remote_t *master, void *ctx)
//{
//	assert(zone);
//	assert(master);
//
//	int ret = zone_query_execute(conf, zone, KNOT_QUERY_NORMAL, master);
//	if (ret != KNOT_EOK && ret != KNOT_LAYER_ERROR) {
//		ZONE_QUERY_LOG(LOG_WARNING, zone, master, "refresh, outgoing",
//		               "failed (%s)", knot_strerror(ret));
//	}
//
//	return ret;
//}

/*! \brief Schedule expire event, unless it is already scheduled. */
static void start_expire_timer(conf_t *conf, zone_t *zone, const knot_rdataset_t *soa)
{
	if (zone_events_is_scheduled(zone, ZONE_EVENT_EXPIRE)) {
		return;
	}

	zone_events_schedule(zone, ZONE_EVENT_EXPIRE, knot_soa_expire(soa));
}

int event_refresh(conf_t *conf, zone_t *zone)
{
	assert(zone);

	/* Ignore if not slave zone. */
	if (!zone_is_slave(conf, zone)) {
		return KNOT_EOK;
	}

	if (zone_contents_is_empty(zone->contents)) {
		/* No contents, schedule retransfer now. */
		zone_events_schedule(zone, ZONE_EVENT_XFER, ZONE_EVENT_NOW);
		return KNOT_EOK;
	}

	int ret = zone_master_try(conf, zone, x_try_refresh, NULL, "refresh");
	const knot_rdataset_t *soa = zone_soa(zone);
	if (ret != KNOT_EOK) {
		log_zone_error(zone->name, "refresh, failed (%s)",
		               knot_strerror(ret));
		/* Schedule next retry. */
		zone_events_schedule(zone, ZONE_EVENT_REFRESH, knot_soa_retry(soa));
		start_expire_timer(conf, zone, soa);
	} else {
		/* SOA query answered, reschedule refresh timer. */
		zone_events_schedule(zone, ZONE_EVENT_REFRESH, knot_soa_refresh(soa));
	}

	return KNOT_EOK;
}

#if 0

/*! \brief Execute zone transfer request. */
static int zone_query_transfer(conf_t *conf, zone_t *zone, const conf_remote_t *master,
                               uint16_t pkt_type)
{
	assert(zone);
	assert(master);

	int ret = zone_query_execute(conf, zone, pkt_type, master);
	if (ret != KNOT_EOK) {
		/* IXFR failed, revert to AXFR. */
		if (pkt_type == KNOT_QUERY_IXFR) {
			LOG_TRANSFER(LOG_NOTICE, pkt_type, "fallback to AXFR");
			return zone_query_transfer(conf, zone, master, KNOT_QUERY_AXFR);
		}

		/* Log connection errors. */
		LOG_TRANSFER(LOG_WARNING, pkt_type, "failed (%s)", knot_strerror(ret));
	}

	return ret;
}

struct transfer_data {
	uint16_t pkt_type;
};

static int try_xfer(conf_t *conf, zone_t *zone, const conf_remote_t *master, void *_data)
{
	assert(zone);
	assert(master);
	assert(_data);

	struct transfer_data *data = _data;

	return zone_query_transfer(conf, zone, master, data->pkt_type);
}
#endif

int event_xfer(conf_t *conf, zone_t *zone)
{
	return KNOT_ENOTSUP;
#if 0
	assert(zone);

	/* Ignore if not slave zone. */
	if (!zone_is_slave(conf, zone)) {
		return KNOT_EOK;
	}

	struct transfer_data data = { 0 };
	const char *err_str = "";

	/* Determine transfer type. */
	bool is_bootstrap = zone_contents_is_empty(zone->contents);
	if (is_bootstrap || zone->flags & ZONE_FORCE_AXFR) {
		data.pkt_type = KNOT_QUERY_AXFR;
		err_str = "AXFR, incoming";
	} else {
		data.pkt_type = KNOT_QUERY_IXFR;
		err_str = "IXFR, incoming";
	}

	/* Execute zone transfer. */
	int ret = zone_master_try(conf, zone, try_xfer, &data, err_str);
	zone_clear_preferred_master(zone);
	if (ret != KNOT_EOK) {
		log_zone_error(zone->name, "%s, failed (%s)", err_str,
		               knot_strerror(ret));
		if (is_bootstrap) {
			zone->bootstrap_retry = bootstrap_next(zone->bootstrap_retry);
			zone_events_schedule(zone, ZONE_EVENT_XFER, zone->bootstrap_retry);
		} else {
			const knot_rdataset_t *soa = zone_soa(zone);
			zone_events_schedule(zone, ZONE_EVENT_XFER, knot_soa_retry(soa));
			start_expire_timer(conf, zone, soa);
		}

		return KNOT_EOK;
	}

	assert(!zone_contents_is_empty(zone->contents));
	const knot_rdataset_t *soa = zone_soa(zone);

	/* Rechedule events. */
	zone_events_schedule(zone, ZONE_EVENT_REFRESH, knot_soa_refresh(soa));
	zone_events_schedule(zone, ZONE_EVENT_NOTIFY,  ZONE_EVENT_NOW);
	zone_events_cancel(zone, ZONE_EVENT_EXPIRE);
	conf_val_t val = conf_zone_get(conf, C_ZONEFILE_SYNC, zone->name);
	int64_t sync_timeout = conf_int(&val);
	if (sync_timeout == 0) {
		zone_events_schedule(zone, ZONE_EVENT_FLUSH, ZONE_EVENT_NOW);
	} else if (sync_timeout > 0 &&
	           !zone_events_is_scheduled(zone, ZONE_EVENT_FLUSH)) {
		zone_events_schedule(zone, ZONE_EVENT_FLUSH, sync_timeout);
	}

	/* Transfer cleanup. */
	zone->bootstrap_retry = ZONE_EVENT_NOW;
	zone->flags &= ~ZONE_FORCE_AXFR;

	/* Trim extra heap. */
	if (!is_bootstrap) {
		mem_trim();
	}

	return KNOT_EOK;
#endif
}
