#ifndef __SERVER_H__
#define __SERVER_H__

#include <stdlib.h>
#include <pthread.h>
#include "service.h"
#include "connote.h"
#include "lsquic.h"
#include "config.h"
#include "define.h"
#include "list.h"
#include "ev.h"

struct server {
	struct list_head service_head;
	size_t n_service;
	size_t n_running_service;
	/* mutithreading or multiprocessing */
	unsigned long task_flags;

	ev_signal signal_quit;
	ev_signal signal_int;
	ev_signal signal_term;

	struct ev_loop *loop;
	ev_timer tw;;

} __attribute__((aligned(sizeof(long))));

struct server_event_loop {
	struct ev_loop *loop;
	ev_timer timer;
	ev_async async_w;
	struct server *sr;
} __attribute__((aligned(sizeof(long))));

struct server_event {
	struct ev_io w;
	// ev_timer timer;
};

struct server *server_init();
void server_add_service(struct server *sr, struct service *se);
int server_launch_service(struct server *sr, struct config_manager *cm);
size_t server_add_event(struct service *se);
int server_run_event(struct service *se);
int server_run_service(struct server *sr, struct service *se);
void server_recv_data(EV_P_ ev_io *w, int revents);
int server_run(struct server *sr);

lsquic_conn_ctx_t *server_on_new_conn(void *stream_if_ctx, struct lsquic_conn *conn);
void server_on_goaway_received(lsquic_conn_t *stream_if_ctx);
void server_on_conn_closed(lsquic_conn_t *conn);
lsquic_stream_ctx_t *server_on_new_stream(void *stream_if_ctx, struct lsquic_stream *stream);
void server_on_read(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc);
void server_on_write(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc);
void server_on_close(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc);
ssize_t server_on_dg_write(lsquic_conn_t *conn, void *buf, size_t sz);
void server_on_datagram(lsquic_conn_t *conn, const void *buf, size_t bufsz);
void server_on_reset(lsquic_stream_t *s, lsquic_stream_ctx_t *h, int how);
void server_on_conncloseframe_received(lsquic_conn_t *c,
		int app_error, uint64_t error_code,
		const char *reason, int reason_len);
void server_process_service(struct service *se);

static struct lsquic_stream_if default_server_stream_if = {
	.on_new_conn = server_on_new_conn,
	.on_goaway_received = server_on_goaway_received,
	.on_conn_closed = server_on_conn_closed,
	.on_new_stream = server_on_new_stream,
	.on_read = server_on_read,
	.on_write = server_on_write,
	.on_close = server_on_close,
	.on_dg_write = server_on_dg_write,
	.on_datagram = server_on_datagram,
	.on_reset = server_on_reset,
	.on_conncloseframe_received = server_on_conncloseframe_received,
};

#endif
