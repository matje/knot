/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <urcu.h>
#include <uv.h>
#ifdef HAVE_SYS_UIO_H			// struct iovec (OpenBSD)
#include <sys/uio.h>
#endif // HAVE_SYS_UIO_H
#ifdef HAVE_CAP_NG_H
#include <cap-ng.h>
#endif /* HAVE_CAP_NG_H */

#include "dnssec/random.h"
#include "knot/server/tcp-handler.h"
#include "knot/common/fdset.h"
#include "knot/common/log.h"
#include "knot/nameserver/process_query.h"
#include "knot/query/layer.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "contrib/time.h"
#include "contrib/ucw/mempool.h"
#include "contrib/wire_ctx.h"

/*! \brief TCP context data. */
typedef struct loop_ctx {
	server_t *server;           /*!< Name server structure. */
	unsigned thread_id;         /*!< Thread identifier. */
	dthread_t * thread;
	unsigned *iostate;
	iohandler_t *handler;
	ref_t *ifaces_ref;
} loop_ctx_t;

typedef struct handle_ctx {
	void (*free)(void *);
	uint64_t last_time;
} handle_ctx_t;

typedef struct tcp_client {
	handle_ctx_t ctx;
	uv_tcp_t handle;
	knot_layer_t layer;
	knot_mm_t mm;
	uv_buf_t *buf;
} tcp_client_t;

typedef struct tcp_server {
	handle_ctx_t ctx;
	uv_tcp_t handle;
	server_t *server;
	unsigned thread_id;
	ref_t *ifaces_ref;
} tcp_server_t;

typedef struct write_ctx {
	handle_ctx_t ctx;
	uv_write_t req;
	uv_buf_t tx[2];
	uint16_t pktsize;
	uint8_t buf[KNOT_WIRE_MAX_PKTSIZE];
} write_ctx_t;

typedef struct cancel_ctx {
	handle_ctx_t ctx;
	uv_idle_t handle;
} cancel_ctx_t;

typedef struct sweep_ctx {
	handle_ctx_t ctx;
	uv_timer_t handle;
} sweep_ctx_t;

void on_connection(uv_stream_t* server, int status);
void cancel_check(uv_idle_t* handle);
void sweep(uv_timer_t *timer);
void on_close_free(uv_handle_t* handle);

void client_free(void *ctx)
{
	tcp_client_t *client = ctx;
	mp_delete(client->layer.mm->ctx);
	mp_delete(client->mm.ctx);
}

tcp_client_t *client_alloc(uv_loop_t *loop)
{
	knot_mm_t mm_tmp = { 0 };
	mm_ctx_mempool(&mm_tmp, 16 * MM_DEFAULT_BLKSIZE);
	tcp_client_t *client = mm_alloc(&mm_tmp, sizeof(tcp_client_t));
	memset(client, 0, sizeof(tcp_client_t));
	client->mm = mm_tmp;
	client->ctx.last_time = uv_now(loop);
	client->handle.data = client;
	client->ctx.free = client_free;
	uv_tcp_init(loop, &client->handle);

	knot_mm_t *query_mm = mm_alloc(&client->mm, sizeof(knot_mm_t));
	mm_ctx_mempool(query_mm, 16 * MM_DEFAULT_BLKSIZE);
	knot_layer_init(&client->layer, query_mm, process_query_layer());
	return client;
}

void server_free(void *ctx)
{
	tcp_server_t *server = ctx;
	ref_release(server->ifaces_ref);
	free(server);
}

int server_alloc_listen(uv_loop_t *loop, int fd, ref_t *ref)
{
	tcp_server_t *server;
	if (loop == NULL) {
		return KNOT_EINVAL;
	}
	server = malloc(sizeof(tcp_server_t));
	if (server==NULL) {
		return KNOT_ENOMEM;
	}
	memset(server, 0, sizeof(tcp_server_t));
	server->ctx.free = server_free;
	uv_tcp_init(loop, &server->handle);
	uv_tcp_open(&server->handle, fd);
	server->handle.data = server;
	server->ifaces_ref = ref;
	ref_retain(server->ifaces_ref);
	if (uv_listen((uv_stream_t *) &server->handle, 128, on_connection) < 0) {
		// TODO
		return KNOT_ERROR;
	}
	return KNOT_EOK;
}

write_ctx_t *write_ctx_alloc()
{
	write_ctx_t *res = malloc(sizeof(write_ctx_t));
	memset(res, 0, sizeof(write_ctx_t));
	res->tx[0].base = (char *)&res->pktsize;
	res->tx[0].len = sizeof(uint16_t);
	res->tx[1].base = (char *)res->buf;
	res->tx[1].len = KNOT_WIRE_MAX_PKTSIZE;
	res->req.data = res;
	res->ctx.free = free;
	return res;
}

cancel_ctx_t *cancel_point_alloc(uv_loop_t *loop) {
	cancel_ctx_t *res = malloc(sizeof(cancel_ctx_t));
	memset(res, 0, sizeof(cancel_ctx_t));
	res->ctx.free = free;
	uv_idle_init(loop, &res->handle);
	res->handle.data = res;
	uv_idle_start(&res->handle, cancel_check);
	return res;
}

sweep_ctx_t *sweep_alloc(uv_loop_t *loop) {
	sweep_ctx_t *res = malloc(sizeof(sweep_ctx_t));
	memset(res, 0, sizeof(sweep_ctx_t));
	uv_timer_init(loop, &res->handle);
	uv_timer_start(&res->handle, sweep, TCP_SWEEP_INTERVAL * 1000, TCP_SWEEP_INTERVAL * 1000);
	res->ctx.free = free;
	res->handle.data = res;
	return res;
}

/*
 * Forward decls.
 */
#define TCP_THROTTLE_LO 0 /*!< Minimum recovery time on errors. */
#define TCP_THROTTLE_HI 2 /*!< Maximum recovery time on errors. */

/*! \brief Calculate TCP throttle time (random). */
static inline int tcp_throttle() {
	return TCP_THROTTLE_LO + (dnssec_random_uint16_t() % TCP_THROTTLE_HI);
}



int tcp_accept(int fd)
{
	/* Accept incoming connection. */
	int incoming = net_accept(fd, NULL);

	/* Evaluate connection. */
	if (incoming >= 0) {
#ifdef SO_RCVTIMEO
		struct timeval tv;
		rcu_read_lock();
		tv.tv_sec = conf()->cache.srv_tcp_idle_timeout;
		rcu_read_unlock();
		tv.tv_usec = 0;
		if (setsockopt(incoming, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
			log_warning("TCP, failed to set up watchdog timer"
			            ", fd %d", incoming);
		}
#endif
	}

	return incoming;
}

void on_write (uv_write_t* req, int status)
{
	fprintf(stderr, "on_write: status: %d, error: %s\n", status, uv_strerror(status));
	write_ctx_t *ctx = req->data;
	ctx->ctx.free(ctx);
}

/*!
 * \brief TCP event handler function.
 */
static int tcp_handle(uv_tcp_t *handle, uv_buf_t *rx)
{
	uv_loop_t *loop = handle->loop;
	loop_ctx_t *tcp = loop->data;
	tcp_client_t *client = handle->data;
	/* Create query processing parameter. */
	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof(struct sockaddr_storage));
	struct process_query_param param = {0};
	//uv_fileno((uv_handle_t *)client, &param.socket);
	param.remote = &ss;
	param.server = tcp->server;
	param.thread_id = tcp->thread_id;

	/* Receive peer name. */
	int addrlen = sizeof(struct sockaddr_storage);
	uv_tcp_getpeername(handle, (struct sockaddr *)&ss, &addrlen);

	/* Initialize processing layer. */
	client->layer.state = knot_layer_begin(&client->layer, &param);

	write_ctx_t *write = write_ctx_alloc();

	/* Create packets. */
	knot_pkt_t *ans = knot_pkt_new(write->tx[1].base, write->tx[1].len, client->layer.mm);
	knot_pkt_t *query = knot_pkt_new(rx->base, rx->len, client->layer.mm);

	/* Input packet. */
	(void) knot_pkt_parse(query, 0);
	int state = knot_layer_consume(&client->layer, query);

	/* Resolve until NOOP or finished. */
	int ret = KNOT_EOK;
	while (state & (KNOT_STATE_PRODUCE|KNOT_STATE_FAIL)) {
		state = knot_layer_produce(&client->layer, ans);

		/* Send, if response generation passed and wasn't ignored. */
		if (ans->size > 0 && !(state & (KNOT_STATE_FAIL|KNOT_STATE_NOOP))) {
			write->pktsize = htons(ans->size);
			write->tx[1].base = (char *)ans->wire;
			write->tx[1].len = ans->size;
			uv_write(&write->req, (uv_stream_t *)handle, write->tx, 2, on_write);
			if (state & (KNOT_STATE_PRODUCE|KNOT_STATE_FAIL)) {
				write = write_ctx_alloc();
			} else {
				write = NULL;
			}
		}
	}

	if (write != NULL) {
		write->ctx.free(write);
	}

	/* Reset after processing. */
	knot_layer_finish(&client->layer);

	/* Cleanup. */
	knot_pkt_free(&query);
	knot_pkt_free(&ans);

	return ret;
}

void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {

	fprintf(stderr, "alloc\n");
	tcp_client_t *client = handle->data;
	buf->base = mm_alloc(client->layer.mm, 2 * KNOT_WIRE_MAX_PKTSIZE);
	buf->base += KNOT_WIRE_MAX_PKTSIZE;
	buf->len = KNOT_WIRE_MAX_PKTSIZE;
}

void echo_read(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
	if (nread == UV_EOF) {
		fprintf(stderr, "EOF\n");
		uv_close((uv_handle_t*)handle, on_close_free);
		return;
	}

	if (nread < 0) {
		//error
		fprintf(stderr, "Read error!, error: %s\n", uv_strerror(nread));
		uv_close((uv_handle_t*)handle, on_close_free);
		return;
	}

	fprintf(stderr, "OK.OK, %ld\n", nread);
	tcp_client_t * client = handle->data;

	//TODO timeout

	uv_buf_t *prev_buf = client->buf;
	uv_buf_t buffer;


	if (prev_buf != NULL && prev_buf->len > 0) {
		memcpy(buf->base - prev_buf->len, prev_buf->base, prev_buf->len);
		buffer.base = buf->base - prev_buf->len;
		buffer.len = nread + prev_buf->len;
	} else {
		buffer.base = buf->base;
		buffer.len = nread;
	}
	fprintf(stderr, "buffer, %lu\n", buffer.len);

	wire_ctx_t rx = wire_ctx_init_const((uint8_t *)buffer.base, buffer.len);

	while (rx.error == KNOT_EOK) {
		uint16_t pktsize = wire_ctx_read_u16(&rx);
		if (wire_ctx_can_read(&rx, pktsize)) {
			buffer.base += wire_ctx_offset(&rx);
			buffer.len = pktsize;
			tcp_handle((uv_tcp_t *)handle, &buffer);
			wire_ctx_skip(&rx, pktsize);
		} else {
			wire_ctx_skip(&rx, -2);
			break;
		}
	}

	client->ctx.last_time = uv_now(client->handle.loop);

	uint16_t remaining = wire_ctx_available(&rx);
	if (remaining > 0) {
		if (prev_buf == NULL) {
			prev_buf = malloc(sizeof(uv_buf_t) + KNOT_WIRE_MAX_PKTSIZE);
			prev_buf->base = (void *)prev_buf + sizeof(uv_buf_t);
			client->buf = prev_buf;
		}
		wire_ctx_read(&rx, (uint8_t *)prev_buf->base, remaining);
		prev_buf->len = remaining;
	}

	mp_flush(client->layer.mm->ctx);
}

void on_connection(uv_stream_t* server, int status)
{
	if (status == -1) {
		return;
	}

	tcp_client_t *client = client_alloc(server->loop);
	/* From documentation:
	 * When the uv_connection_cb callback is called it is guaranteed
	 * that this function will complete successfully the first time.
	 */
	uv_accept(server, (uv_stream_t*) &client->handle);
	uv_read_start((uv_stream_t*) &client->handle, alloc_buffer, echo_read);
}

void on_close_free(uv_handle_t* handle)
{
	handle_ctx_t *ctx = handle->data;
	loop_ctx_t *tcp = handle->loop->data;

	if (ctx != NULL) {
		fprintf(stderr, "thread:%u,handle:free\n", tcp->thread_id);
		ctx->free(ctx);
	} else {
		fprintf(stderr, "thread:%u,handle:____\n",tcp->thread_id);
	}

}

void sweep_handle(uv_handle_t* handle, void* arg)
{
	handle_ctx_t *ctx = handle->data;
	if (ctx->last_time != 0 && ctx->last_time < *((uint64_t *)arg)) {
		fprintf(stderr, "\tsweep\n");
		uv_close(handle, on_close_free);
	}
}

void sweep(uv_timer_t *timer) {
	/* Timeout. */
	rcu_read_lock();
	int timeout = 1000 * conf()->cache.srv_tcp_reply_timeout;
	rcu_read_unlock();
	fprintf(stderr, "sweeper ...\n");
	uint64_t sweep_time = uv_now(timer->loop) - timeout;
	uv_walk(timer->loop, sweep_handle, &sweep_time);
}

void close_handle(uv_handle_t* handle, void* arg)
{
	uv_close(handle, on_close_free);
}

void reconfigure_loop(uv_loop_t *loop)
{
	loop_ctx_t *tcp = loop->data;

	ref_release(tcp->ifaces_ref);

	cancel_point_alloc(loop);
	sweep_alloc(loop);
	rcu_read_lock();
	iface_t *i = NULL;
	tcp->ifaces_ref = &tcp->handler->server->ifaces->ref;
	WALK_LIST(i, tcp->handler->server->ifaces->l) {
		int ret = server_alloc_listen(loop, i->fd_tcp, tcp->ifaces_ref);
		if (ret) {
		/* LISTEN ERROR */
		}
	}
	rcu_read_unlock();
}

void cancel_check(uv_idle_t* handle)
{
	loop_ctx_t *tcp = handle->loop->data;
	dthread_t *thread = tcp->thread;
	/* Check for cancellation. */
	if (dt_is_cancelled(thread)) {
		fprintf(stderr, "thread:%u,STOP\n", tcp->thread_id);
		uv_stop(handle->loop);
	}

	/* Check handler state. */
	if (unlikely(*tcp->iostate & ServerReload)) {
		*tcp->iostate &= ~ServerReload;
		uv_walk(handle->loop, close_handle, NULL);
		reconfigure_loop(handle->loop);
	}
}

int tcp_master(dthread_t *thread)
{
	if (!thread || !thread->data) {
		return KNOT_EINVAL;
	}

	loop_ctx_t tcp;
	memset(&tcp, 0, sizeof(loop_ctx_t));
	tcp.handler = (iohandler_t *)thread->data;
	if (tcp.handler->server == NULL || tcp.handler->server->ifaces == NULL) {
		return KNOT_EINVAL;
	}

	tcp.server = tcp.handler->server;
	tcp.thread_id = tcp.handler->thread_id[dt_get_id(thread)];
	tcp.thread = thread;
	tcp.iostate = &tcp.handler->thread_state[dt_get_id(thread)];

	uv_loop_t loop;
	uv_loop_init(&loop);
	loop.data = &tcp;

	reconfigure_loop(&loop);
	*tcp.iostate &= ~ServerReload;

	int ret = uv_run(&loop, UV_RUN_DEFAULT);
	fprintf(stderr, "thread:%u,afterRUN\n", tcp.thread_id);
	uv_walk(&loop, close_handle, NULL);
	uv_run(&loop, UV_RUN_ONCE);
	uv_loop_close(&loop);

	ref_release(tcp.ifaces_ref);
	return ret;
}

#if 0
int tcp_master(dthread_t *thread)
{
	if (!thread || !thread->data) {
		return KNOT_EINVAL;
	}

	iohandler_t *handler = (iohandler_t *)thread->data;
	unsigned *iostate = &handler->thread_state[dt_get_id(thread)];

	int ret = KNOT_EOK;
	ref_t *ref = NULL;
	loop_ctx_t tcp;
	memset(&tcp, 0, sizeof(loop_ctx_t));

	/* Create big enough memory cushion. */
	knot_mm_t mm = { 0 };
	mm_ctx_mempool(&mm, 16 * MM_DEFAULT_BLKSIZE);

	/* Create TCP answering context. */
	tcp.server = handler->server;
	tcp.thread_id = handler->thread_id[dt_get_id(thread)];
	knot_layer_init(&tcp.layer, &mm, process_query_layer());

	/* Prepare structures for bound sockets. */
	conf_val_t val = conf_get(conf(), C_SRV, C_LISTEN);
	fdset_init(&tcp.set, conf_val_count(&val) + CONF_XFERS);

	/* Create iovec abstraction. */
	for (unsigned i = 0; i < 2; ++i) {
		tcp.iov[i].iov_len = KNOT_WIRE_MAX_PKTSIZE;
		tcp.iov[i].iov_base = malloc(tcp.iov[i].iov_len);
		if (tcp.iov[i].iov_base == NULL) {
			ret = KNOT_ENOMEM;
			goto finish;
		}
	}

	/* Initialize sweep interval. */
	timev_t next_sweep = {0};
	time_now(&next_sweep);
	next_sweep.tv_sec += TCP_SWEEP_INTERVAL;

	for(;;) {

		/* Check handler state. */
		if (unlikely(*iostate & ServerReload)) {
			*iostate &= ~ServerReload;

			/* Cancel client connections. */
			for (unsigned i = tcp.client_threshold; i < tcp.set.n; ++i) {
				close(tcp.set.pfd[i].fd);
			}

			ref_release(ref);
			ref = server_set_ifaces(handler->server, &tcp.set, IO_TCP, tcp.thread_id);
			if (tcp.set.n == 0) {
				break; /* Terminate on zero interfaces. */
			}

			tcp.client_threshold = tcp.set.n;
		}

		/* Check for cancellation. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* Serve client requests. */
		tcp_wait_for_events(&tcp);

		/* Sweep inactive clients. */
		if (tcp.last_poll_time.tv_sec >= next_sweep.tv_sec) {
			fdset_sweep(&tcp.set, &tcp_sweep, NULL);
			time_now(&next_sweep);
			next_sweep.tv_sec += TCP_SWEEP_INTERVAL;
		}
	}

finish:
	free(tcp.iov[0].iov_base);
	free(tcp.iov[1].iov_base);
	mp_delete(mm.ctx);
	fdset_clear(&tcp.set);
	ref_release(ref);

	return ret;
}

/*! \brief Sweep TCP connection. */
static enum fdset_sweep_state tcp_sweep(fdset_t *set, int i, void *data)
{
	UNUSED(data);
	assert(set && i < set->n && i >= 0);
	int fd = set->pfd[i].fd;

	/* Best-effort, name and shame. */
	struct sockaddr_storage ss;
	socklen_t len = sizeof(struct sockaddr_storage);
	if (getpeername(fd, (struct sockaddr*)&ss, &len) == 0) {
		char addr_str[SOCKADDR_STRLEN] = {0};
		sockaddr_tostr(addr_str, sizeof(addr_str), (struct sockaddr *)&ss);
		log_notice("TCP, terminated inactive client, address '%s'", addr_str);
	}

	close(fd);

	return FDSET_SWEEP;
}

static int tcp_event_accept(loop_ctx_t *tcp, unsigned i)
{
	/* Accept client. */
	int fd = tcp->set.pfd[i].fd;
	int client = tcp_accept(fd);
	if (client >= 0) {
		/* Assign to fdset. */
		int next_id = fdset_add(&tcp->set, client, POLLIN, NULL);
		if (next_id < 0) {
			close(client);
			return next_id; /* Contains errno. */
		}

		/* Update watchdog timer. */
		rcu_read_lock();
		int timeout = conf()->cache.srv_tcp_hshake_timeout;
		fdset_set_watchdog(&tcp->set, next_id, timeout);
		rcu_read_unlock();

		return KNOT_EOK;
	}

	return client;
}

static int tcp_event_serve(loop_ctx_t *tcp, unsigned i)
{
	int fd = tcp->set.pfd[i].fd;
	int ret = tcp_handle(tcp, fd, &tcp->iov[0], &tcp->iov[1]);

	/* Flush per-query memory. */
	mp_flush(tcp->layer.mm->ctx);

	if (ret == KNOT_EOK) {
		/* Update socket activity timer. */
		rcu_read_lock();
		int timeout = conf()->cache.srv_tcp_idle_timeout;
		fdset_set_watchdog(&tcp->set, i, timeout);
		rcu_read_unlock();
	}

	return ret;
}

/*!
 * \brief TCP event handler function.
 */
static int tcp_handle(loop_ctx_t *tcp, int fd,
                      struct iovec *rx, struct iovec *tx)
{
	/* Create query processing parameter. */
	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof(struct sockaddr_storage));
	struct process_query_param param = {0};
	param.socket = fd;
	param.remote = &ss;
	param.server = tcp->server;
	//param.thread_id = tcp->thread_id;
	rx->iov_len = KNOT_WIRE_MAX_PKTSIZE;
	tx->iov_len = KNOT_WIRE_MAX_PKTSIZE;

	/* Receive peer name. */
	socklen_t addrlen = sizeof(struct sockaddr_storage);
	if (getpeername(fd, (struct sockaddr *)&ss, &addrlen) < 0) {
		;
	}

	/* Timeout. */
	rcu_read_lock();
	int timeout = 1000 * conf()->cache.srv_tcp_reply_timeout;
	rcu_read_unlock();

	/* Receive data. */
	int ret = net_dns_tcp_recv(fd, rx->iov_base, rx->iov_len, timeout);
	if (ret <= 0) {
		if (ret == KNOT_EAGAIN) {
			char addr_str[SOCKADDR_STRLEN] = {0};
			sockaddr_tostr(addr_str, sizeof(addr_str), (struct sockaddr *)&ss);
			log_warning("TCP, connection timed out, address '%s'",
			            addr_str);
		}
		return KNOT_ECONNREFUSED;
	} else {
		rx->iov_len = ret;
	}

	/* Initialize processing layer. */

	tcp->layer.state = knot_layer_begin(&tcp->layer, &param);

	/* Create packets. */
	knot_pkt_t *ans = knot_pkt_new(tx->iov_base, tx->iov_len, tcp->layer.mm);
	knot_pkt_t *query = knot_pkt_new(rx->iov_base, rx->iov_len, tcp->layer.mm);

	/* Input packet. */
	(void) knot_pkt_parse(query, 0);
	int state = knot_layer_consume(&tcp->layer, query);

	/* Resolve until NOOP or finished. */
	ret = KNOT_EOK;
	while (state & (KNOT_STATE_PRODUCE|KNOT_STATE_FAIL)) {
		state = knot_layer_produce(&tcp->layer, ans);

		/* Send, if response generation passed and wasn't ignored. */
		if (ans->size > 0 && !(state & (KNOT_STATE_FAIL|KNOT_STATE_NOOP))) {
			if (net_dns_tcp_send(fd, ans->wire, ans->size, timeout) != ans->size) {
				ret = KNOT_ECONNREFUSED;
				break;
			}
		}
	}

	/* Reset after processing. */
	knot_layer_finish(&tcp->layer);

	/* Cleanup. */
	knot_pkt_free(&query);
	knot_pkt_free(&ans);

	return ret;
}




static int tcp_wait_for_events(loop_ctx_t *tcp)
{
	/* Wait for events. */
	fdset_t *set = &tcp->set;
	int nfds = poll(set->pfd, set->n, TCP_SWEEP_INTERVAL * 1000);

	/* Mark the time of last poll call. */
	time_now(&tcp->last_poll_time);
	bool is_throttled = (tcp->last_poll_time.tv_sec < tcp->throttle_end.tv_sec);
	if (!is_throttled) {
		/* Configuration limit, infer maximal pool size. */
		rcu_read_lock();
		int clients = conf()->cache.srv_max_tcp_clients;
		unsigned max_per_set = MAX(clients / conf_tcp_threads(conf()), 1);
		rcu_read_unlock();
		/* Subtract master sockets check limits. */
		is_throttled = (set->n - tcp->client_threshold) >= max_per_set;
	}

	/* Process events. */
	unsigned i = 0;
	while (nfds > 0 && i < set->n) {
		bool should_close = false;
		int fd = set->pfd[i].fd;
		if (set->pfd[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
			should_close = (i >= tcp->client_threshold);
			--nfds;
		} else if (set->pfd[i].revents & (POLLIN)) {
			/* Master sockets */
			if (i < tcp->client_threshold) {
				if (!is_throttled && tcp_event_accept(tcp, i) == KNOT_EBUSY) {
					time_now(&tcp->throttle_end);
					tcp->throttle_end.tv_sec += tcp_throttle();
				}
			/* Client sockets */
			} else {
				if (tcp_event_serve(tcp, i) != KNOT_EOK) {
					should_close = true;
				}
			}
			--nfds;
		}

		/* Evaluate */
		if (should_close) {
			fdset_remove(set, i);
			close(fd);
		} else {
			++i;
		}
	}

	return nfds;
}

#endif
