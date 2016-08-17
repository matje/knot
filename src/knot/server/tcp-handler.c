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

enum handle_type {
	UNKNOWN = 0,
	TCP_CLIENT,
	TCP_SERVER,
};

/*! \brief TCP context data. */
typedef struct loop_ctx {
	server_t *server;           /*!< Name server structure. */
	unsigned thread_id;         /*!< Thread identifier. */
	dthread_t * thread;
	unsigned *iostate;
	iohandler_t *handler;
	ifacelist_t* old_ifaces;
} loop_ctx_t;

typedef struct tcp_ctx {
	void (*free)(void *);
	enum handle_type type;
} tcp_ctx_t;

typedef struct tcp_client {
	tcp_ctx_t ctx;
	uv_tcp_t handle;
	uint64_t last_time;
	knot_layer_t layer;
	knot_mm_t mm;
	uv_buf_t *buf;
} tcp_client_t;

typedef struct tcp_server {
	tcp_ctx_t ctx;
	uv_tcp_t handle;
	server_t *server;
	unsigned thread_id;
	ref_t *ifaces_ref;
} tcp_server_t;

typedef struct write_ctx {
	uv_write_t req;
	uv_buf_t tx[2];
	uint16_t pktsize;
	uint8_t buf[KNOT_WIRE_MAX_PKTSIZE];
} write_ctx_t;

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
	client->last_time = uv_now(loop);
	client->handle.data = client;
	client->ctx.free = client_free;
	client->ctx.type = TCP_CLIENT;
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

int server_alloc_listen(tcp_server_t **res, uv_loop_t *loop, int fd, ref_t *ref)
{
	tcp_server_t *server;
	if (loop == NULL || res == NULL) {
		return KNOT_EINVAL;
	}
	server = malloc(sizeof(tcp_server_t));
	if (server==NULL) {
		return KNOT_ENOMEM;
	}
	memset(server, 0, sizeof(tcp_server_t));
	server->ctx.free = server_free;
	server->ctx.type = TCP_SERVER;
	uv_tcp_init(loop, &server->handle);
	uv_tcp_open(&server->handle, fd);
	server->handle.data = server;
	server->ifaces_ref = ref;
	ref_retain(server->ifaces_ref);
	int ret = uv_listen((uv_stream_t *) &server->handle, TCP_BACKLOG_SIZE, on_connection);
	if (ret  < 0) {
		struct sockaddr_storage ss;
		int addrlen = sizeof(struct sockaddr_storage);
		uv_tcp_getsockname(&server->handle, (struct sockaddr *)&ss, &addrlen);
		char addr_str[SOCKADDR_STRLEN] = {0};
		sockaddr_tostr(addr_str, sizeof(addr_str), (struct sockaddr *)&ss);
		log_error("cannot open socket, address '%s' (%s)", addr_str, uv_strerror(ret));
		return KNOT_ERROR;
	}
	*res = server;
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
	return res;
}

void on_write (uv_write_t* req, int status)
{
	free(req->data);
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
		free(write);
	}

	/* Reset after processing. */
	knot_layer_finish(&client->layer);

	/* Cleanup. */
	knot_pkt_free(&query);
	knot_pkt_free(&ans);

	return ret;
}

void read_buffer_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {

	fprintf(stderr, "alloc\n");
	tcp_client_t *client = handle->data;
	buf->base = mm_alloc(client->layer.mm, 2 * KNOT_WIRE_MAX_PKTSIZE);
	buf->base += KNOT_WIRE_MAX_PKTSIZE;
	buf->len = KNOT_WIRE_MAX_PKTSIZE;
}

void on_read(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
	if (nread == UV_EOF || nread < 0) {
		uv_close((uv_handle_t*)handle, on_close_free);
		return;
	}

	tcp_client_t * client = handle->data;
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

	uint16_t remaining = wire_ctx_available(&rx);
	if (remaining > 0) {
		if (prev_buf == NULL) {
			prev_buf = mm_alloc(&client->mm, sizeof(uv_buf_t));
			prev_buf->base = mm_alloc(&client->mm, KNOT_WIRE_MAX_PKTSIZE);
			client->buf = prev_buf;
		}
		wire_ctx_read(&rx, (uint8_t *)prev_buf->base, remaining);
		prev_buf->len = remaining;
	}

	client->last_time = uv_now(client->handle.loop);
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
	uv_read_start((uv_stream_t*) &client->handle, read_buffer_alloc, on_read);
}

void on_close_free(uv_handle_t* handle)
{
	if (handle->type == UV_TCP) {
		tcp_ctx_t *ctx = handle->data;
		if (ctx != NULL) {
			ctx->free(ctx);
		}
	}
}

void sweep_client(uv_handle_t* handle, void* arg)
{
	tcp_ctx_t *ctx = handle->data;
	if (handle->type != UV_TCP || ctx->type != TCP_CLIENT) {
		return;
	}
	uint64_t last_time = ((tcp_client_t *)ctx)->last_time;
	uint64_t sweep_time = *((uint64_t *)arg);
	if (last_time != 0 && last_time < sweep_time) {
		struct sockaddr_storage ss;
		int addrlen = sizeof(struct sockaddr_storage);
		uv_tcp_getpeername((uv_tcp_t *)handle, (struct sockaddr *)&ss, &addrlen);
		char addr_str[SOCKADDR_STRLEN] = {0};
		sockaddr_tostr(addr_str, sizeof(addr_str), (struct sockaddr *)&ss);
		log_notice("TCP, terminated inactive client, address '%s'", addr_str);
		uv_close(handle, on_close_free);
	}
}

void tcp_sweep(uv_timer_t *timer) {
	/* Timeout. */
	rcu_read_lock();
	int timeout = 1000 * conf()->cache.srv_tcp_reply_timeout;
	rcu_read_unlock();
	uint64_t sweep_time = uv_now(timer->loop) - timeout;
	uv_walk(timer->loop, sweep_client, &sweep_time);
}

void close_client(uv_handle_t* handle, void* arg)
{
	if (handle->type == UV_TCP) {
		tcp_ctx_t *ctx = handle->data;
		if (ctx->type == TCP_CLIENT) {
			uv_close(handle, on_close_free);
		}
	}
}

void close_all(uv_handle_t* handle, void* arg)
{
	uv_close(handle, on_close_free);
}

void close_handle_fd(uv_handle_t* handle, void* arg)
{
	int fd=-1;
	uv_fileno(handle, &fd);
	if (fd == *((int *)arg)) {
		fprintf(stderr, "clossing fd:%d\n", fd);
		uv_close(handle, on_close_free);
	}
}

void reconfigure_loop(uv_loop_t *loop)
{
	loop_ctx_t *tcp = loop->data;
	iface_t *i = NULL;

	uv_walk(loop, close_client, NULL);
	if (tcp->old_ifaces != NULL) {
		WALK_LIST(i, tcp->old_ifaces->u) {
			uv_walk(loop, close_handle_fd, &i->fd_tcp);
		}
		ref_release(&tcp->old_ifaces->ref);
	}

	rcu_read_lock();

	tcp->old_ifaces  = tcp->handler->server->ifaces;
	int multiproccess = tcp->server->handlers[IO_TCP].size > 1;

	WALK_LIST(i, tcp->handler->server->ifaces->u) {
		tcp_server_t *server;
		int ret = server_alloc_listen(&server, loop, i->fd_tcp, &tcp->old_ifaces->ref);
		if (ret) {
			/* LISTEN ERROR */
			fprintf(stderr, "LISTEN_ERROR, %d\n", ret);
		} else {
			fprintf(stderr, "listening fd:%d\n", i->fd_tcp);
		}
		//uv_tcp_simultaneous_accepts(&server->handle, ! multiproccess);
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

	uv_idle_t cancel_point;
	uv_idle_init(&loop, &cancel_point);
	uv_idle_start(&cancel_point, cancel_check);

	uv_timer_t sweep_timer;
	uv_timer_init(&loop, &sweep_timer);
	uv_timer_start(&sweep_timer, tcp_sweep, TCP_SWEEP_INTERVAL * 1000, TCP_SWEEP_INTERVAL * 1000);

	reconfigure_loop(&loop);
	*tcp.iostate &= ~ServerReload;

	int ret = uv_run(&loop, UV_RUN_DEFAULT);
	fprintf(stderr, "thread:%u,afterRUN\n", tcp.thread_id);
	uv_walk(&loop, close_all, NULL);
	uv_run(&loop, UV_RUN_ONCE);
	uv_loop_close(&loop);

	ref_release(&tcp.old_ifaces->ref);
	return ret;
}
