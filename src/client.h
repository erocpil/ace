#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <pthread.h>
#include "upstream.h"
#include "service.h"
#include "connote.h"
#include "lsquic.h"
#include "config.h"
#include "define.h"
#include "list.h"
#include "ev.h"

struct client {
	/* mutithreading or multiprocessing */
	unsigned long task_flags;
	struct list_head service_head;
	size_t n_service;
	size_t n_running_service;

	struct lsquic_stream_if *stream_if;
	lsquic_packets_out_f packets_out;

	ev_signal signal_quit;
	ev_signal signal_int;
	ev_signal signal_term;

	struct ev_loop *loop;
	ev_timer tw;;

} __attribute__((aligned(sizeof(long))));

struct client_event_loop {
	struct ev_loop *loop;
	ev_timer timer;
	ev_async async_w;
	struct upstream *up;
	struct client *ct;
} __attribute__((aligned(sizeof(long))));

struct client_event {
	struct ev_io w;
	// ev_timer timer;
};

struct client *client_init();
void client_add_service(struct client *ct, struct service *se);
int client_launch_service(struct client *ct, struct config_manager *cm);
size_t client_add_event(struct service *se);
int client_run_event(struct service *se);
int client_run_service(struct client *ct, struct service *se);
void client_recv_data(EV_P_ ev_io *w, int revents);
int client_run(struct client *ct);

lsquic_conn_ctx_t *client_on_new_conn(void *stream_if_ctx, struct lsquic_conn *conn);
void client_on_goaway_received(lsquic_conn_t *stream_if_ctx);
void client_on_conn_closed(lsquic_conn_t *conn);
lsquic_stream_ctx_t *client_on_new_stream(void *stream_if_ctx, struct lsquic_stream *stream);
void client_on_read(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc);
void client_on_write(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc);
void client_on_close(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc);
ssize_t client_on_dg_write(lsquic_conn_t *conn, void *buf, size_t sz);
void client_on_datagram(lsquic_conn_t *conn, const void *buf, size_t bufsz);
void client_on_hsk_done(lsquic_conn_t *conn, enum lsquic_hsk_status status);
void client_on_reset(lsquic_stream_t *s, lsquic_stream_ctx_t *h, int how);
void client_on_conncloseframe_received(lsquic_conn_t *c,
		int app_error, uint64_t error_code,
		const char *reason, int reason_len);
void client_process_service(struct service *se);

static struct lsquic_stream_if default_client_stream_if = {
	.on_new_conn = client_on_new_conn,
	.on_goaway_received = client_on_goaway_received,
	.on_conn_closed = client_on_conn_closed,
	.on_new_stream = client_on_new_stream,
	.on_read = client_on_read,
	.on_write = client_on_write,
	.on_close = client_on_close,
	.on_dg_write = client_on_dg_write,
	.on_datagram = client_on_datagram,
	.on_hsk_done = client_on_hsk_done,
	.on_reset = client_on_reset,
	.on_conncloseframe_received = client_on_conncloseframe_received,
};

#endif
