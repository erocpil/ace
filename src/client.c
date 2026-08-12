#include "client.h"
#include "task.h"
#include "link.h"
#include "runner.h"

struct client *client_init()
{
	struct client *ct = (struct client*)malloc(sizeof(struct client));
	if (!ct) {
		return NULL;
	}
	memset(ct, 0, sizeof(*ct));
	INIT_LIST_HEAD(&ct->service_head);
	/* client's default event loop */
	ct->loop = EV_DEFAULT;

	ace_runner_init_signal(ct->loop,
			&ct->signal_quit, &ct->signal_int, &ct->signal_term,
			(void*)ct);

	return ct;
}

int client_launch_service(struct client *ct, struct config_manager *cm)
{
	log();

	int n_connote = 0;
	struct config *pos = NULL;

	list_for_each_entry(pos, &cm->config_head, config_node) {
		if (-1 == config_check(pos)) {
			elog("config_check failed, skipping");
			continue;
		}
	}

	list_for_each_entry(pos, &cm->config_head, config_node) {
		struct service *se = service_init(pos);
		if (!se) {
			continue;
		}
		struct client_event_loop *evl = (struct client_event_loop*)malloc(sizeof(struct client_event_loop));
		if (!evl) {
			elog("malloc client_event_loop failed, skipping");
			continue;
		}
		// rlog("evl %p", evl);
		memset(evl, 0, sizeof(*evl));
		evl->ct = ct;
		se->loop = (void*)evl;
		se->run_event = client_run_event;
		se->process = client_process_service;
		client_add_service(ct, se);
	}

	return n_connote;
}

void client_add_service(struct client *sr, struct service *se)
{
	ace_runner_add_service(&sr->service_head, &sr->n_service, se);
}

static void client_timeout_cb(EV_P_ ev_timer *w, int revents)
{
	client_process_service(w->data);
}

/* client_run - run each service */
int client_run(struct client *ct)
{
	struct service *pos = NULL;
	list_for_each_entry(pos, &ct->service_head, service_node) {
		ace_runner_run_service(&ct->n_running_service, pos);
	}

	return ace_runner_run(ct->loop, &ct->tw,
			ct->n_service, (void*)ct,
			client_timeout_cb);
}

#define client_recv_data ace_runner_recv_data

static inline void client_timer_expired(EV_P_ ev_timer *timer, int revents)
{
	client_process_service(timer->data);
}

static void client_async_w_cb(EV_P_ ev_async *w, int revents)
{
	return;
	/* TEST */
	slog();

	static int i = 0;
	struct service *se = (struct service*)w->data;

	if (service_is_running(se)) {
		ylog();
		i++;
	}
	if (i == 3) {
		rlog();
	}
}

static int client_process_upstream_read(struct upstream_echo *echo)
{
	int n_skb_processed = 0;

	rlog("echo->n_rq %u", echo->n_rq);
	if (!echo->external) {
		rlog("echo %p connecting ...", echo);
		struct service *se = (struct service*)echo->up->entity;
		if (se == echo->up->entity) {
			rlog("TODO entity and se");
		}
		/* 1. make a new ce */
		struct list_head *head = &se->config.co_config_head;
		if (list_empty(head)) {
			return -1;
		}
		struct co_config *co =
			list_first_entry(head, struct co_config, co_config_node);
		struct connote *ce = connote_init(co);
		if (!ce) {
			eslog("connote_init()");
			return -1;
		}
		struct client_event *ev = (struct client_event*)malloc(sizeof(struct client_event));
		if (!ev) {
			eslog("malloc client_event failed");
			return -1;
		}
		ce->event = (void*)ev;
		service_add_connote(se, ce);
		ev->w.data = ce;
		ev_io_init(&ev->w, client_recv_data, ce->fd, EV_READ);
		ev_io_start(((struct client_event_loop*)se->loop)->loop, &ev->w);
		/* 2. connect the new ce */
		if (co->bindtodevice) {
			if (link_get_status(co->if_name) < 0) {
				rlog("device %s down, skipping", co->if_name);
				return -1;
			}
		} else {
			ylog("no bindtodevice");
		}
		struct lsquic_conn *lconn = service_connect_nop(ce);
		if (!lconn) {
			ylog();
			return -1;
		}
		/* 2.5 */
#if 1
		{
			rlog("nop head");
			struct lsquic_conn_ctx *lconn_ctx = lsquic_conn_get_ctx(lconn);
			struct lsquic_stream_ctx *sc = lconn_ctx->pending;
			struct sk_buff *skb = sc->tx;
			/* this will trigger 0-RTT */
			struct upstream_skb_head nh = {
				.length = 0,
				.theme = (unsigned short int)-1,
				.serial = (unsigned short int)-1,
			};
			memcpy(skb->head, &nh, sizeof(nh));
			skb_put(skb, sizeof(nh));
			SKB_DUMP(skb);
			upstream_skb_head_dump(&nh);
		}
#endif
		se->process(se);

		/* 3. place external entity */
		struct lsquic_conn_ctx *lconn_ctx = lsquic_conn_get_ctx(lconn);
		rlog("echo %p up %p se %p ce %p lconn_ctx %p",
				echo, echo->up, se, ce, lconn_ctx);
		echo->external = (void*)lconn_ctx;
		lconn_ctx->internal = (void*)echo;
		if (ce->cc->auto_stream0) {
			// XXX
		}
	}

	if (!echo->n_rq) {
		rlog("no echo->n_rq, conn is in progress");
		return 0;
	}

	struct lsquic_conn_ctx *lconn_ctx = (struct lsquic_conn_ctx*)echo->external;
	log("n_rq %u", echo->n_rq);
	rlog("lconn_ctx %p", lconn_ctx);

	if (!lconn_ctx->s0) {
		/* conn(stream 0) is not ready */
		ylog("conn is not ready, all %d skb remains unprocessed", echo->n_rq);
		return 0;
	}

	struct sk_buff *skb = NULL;
	struct sk_buff *n = NULL;
	list_for_each_entry_safe(skb, n, &echo->recv_queue, skb_node) {
		struct upstream_skb_head *head = (struct upstream_skb_head*)skb->head;
		log("%p %u %u %u", head, head->length, head->theme, head->serial);
		struct task *task = task_create(skb, TASK_ROLE_SEND);
		if (!task) {
			elog("TODO free ...");
			return -1;
		}

		if (-1 == task->init(task)) {
			elog("task->init() failed, skipping");
			skb_free(skb);
			continue;
		}

		/* now that task was initialized, send info to server */
		struct lsquic_stream_ctx *sc = lsquic_stream_get_ctx(lconn_ctx->s0);
		rlog("lconn_ctx %p stream %p sc %p tx %p",
				lconn_ctx, lconn_ctx->s0, sc, sc->tx);
		rlog("sc %p n_rxq %u n_txq %u", sc, sc->n_rxq, sc->n_txq);

		/* reset skb in case nop */
		sc->tx->len = 0;
		sc->tx->tail = 0;
		sc->tx->offset = 0;
		/* prepare negotiation info */
		if (-1 == task->nego(task, sc->tx)) {
			elog("task->nego() failed, skipping");
			skb_free(skb);
			continue;
		}

		/* push data to head to send the whole buffer */
		skb_push(sc->tx, sizeof(*head));
		SKB_DUMP(sc->tx);
		sc->subtask = task_get_sub_at(task, 0);
		lsquic_stream_wantwrite(lconn_ctx->s0, 1);

		lconn_ctx->task = task;
		struct subtask *st = NULL;
		/* !!! first one is for stream(0) */
		for (unsigned short int i = 1; i < task->n_sub; i++) {
			/* no need to assign rx/tx buffer */
			struct lsquic_stream_ctx *sc =
				service_stream_ctx_malloc(lconn_ctx->ce->cc, 0, 0);
			sc->subtask = task_get_sub_at(task, i);
			lconn_ctx_add_pending_stream_ctx(lconn_ctx, sc);
			lsquic_conn_make_stream(lconn_ctx->lconn);
		}

		upstream_echo_del_rq(echo, skb);
		skb_free(skb);
	}

	return n_skb_processed;
}

static int client_process_upstream_write(struct upstream_echo *echo, struct sk_buff *skb)
{
	// return echo->up->tx_process_func(echo, skb);
	int (*tx_process_func)(struct upstream_echo*, struct sk_buff*) =
		echo->up->tx_process_func;
	int n = tx_process_func(echo, skb);
	return n;
}

/* !!!run in service thread or process!!! */
int client_run_event(struct service *se)
{
	log();
	if (!se) {
		elog();
		return -1;
	}

	size_t n_connote = 0;
	struct connote *ce = NULL;
	unsigned int flags = EVFLAG_NOENV;
	struct client_event_loop *evl = (struct client_event_loop*)se->loop;
	unsigned long task_flags = evl->ct->task_flags;

	switch (task_flags) {
		case TASK_MULTITHREADING:
			flags = EVFLAG_AUTO;
			break;
		case TASK_MULTIPROCESSING:
			// FIXME
			flags = EVFLAG_FORKCHECK;
			break;
		default:
			// TODO
			elog();
			break;
	}

	/* init */
	evl->loop = ev_loop_new(flags);
	evl->timer.data = se;
	ev_init(&evl->timer, client_timer_expired);

	ev_async_init(&evl->async_w, client_async_w_cb);
	evl->async_w.data = (void*)se;

	struct config *cc = &se->config;
	evl->up = upstream_init(evl->loop, 4, cc->retry, cc->retry_timeout, cc->file,
			client_process_upstream_read, NULL, 0);
	if (!evl->up) {
		eslog("upstream_init()");
		upstream_free(evl->up);
		return -1;
	}
	evl->up->entity = (void*)se;

	/* run */
	if (0 != upstream_listen(evl->up)) {
		elog("upstream_listen() failed");
		return -1;
	}

	ev_async_start(evl->loop, &evl->async_w);

	ev_run(evl->loop, 0);
	rlog();

	return 0;
}

lsquic_conn_ctx_t *client_on_new_conn(void *stream_if_ctx, struct lsquic_conn *conn)
{
	struct service *se = (struct service*)stream_if_ctx;
	struct lsquic_conn_ctx *lconn_ctx = lconn_ctx_malloc();
	lconn_ctx->ce = lsquic_conn_get_peer_ctx(conn, NULL);
	clog("ce %p from lsquic_engine_connect()", lconn_ctx->ce);
	lconn_ctx->lconn = conn;
	service_add_client_conn(se, lconn_ctx);

	lsquic_conn_set_ctx(conn, lconn_ctx);
	struct lsquic_stream_ctx *sc =
		service_stream_ctx_malloc_pending(conn, -1, -1);
	ylog("pending sc %p for s0", sc);
	lsquic_conn_make_stream(conn);

	return lconn_ctx;
}

void client_on_goaway_received(lsquic_conn_t *stream_if_ctx)
{
	elog();
}

void client_on_conn_closed(lsquic_conn_t *conn)
{
	struct lsquic_conn_ctx *lconn_ctx = lsquic_conn_get_ctx(conn);
	hpelog("conn %p ctx %p", conn, lconn_ctx);
	if (lconn_ctx->keylog_file) {
		blog("keylog file %p closed", lconn_ctx->keylog_file);
		fclose(lconn_ctx->keylog_file);
	}

	struct connote *ce = lconn_ctx->ce;
	struct service *se = ce->service;
	struct client_event_loop *evl = (struct client_event_loop*)se->loop;
	struct client_event *ev = (struct client_event*)ce->event;

	service_del_client_conn(se, lconn_ctx);

	if (ev_is_active(&ev->w)) {
		ylog("ev_io_stop(service %p connote %p fd %d)", se, ce, ce->fd);
		ev_io_stop(evl->loop, &ev->w);
	}

	struct sk_buff *skb = NULL;
	struct task *task = (struct task*)lconn_ctx->task;
	if (task) {
		/* if this conn has been assigned a task */
		ylog("task exit");
		skb = task->exit(task);
		log("task exit returned skb %p", skb);
	}

	/* notify upstream */
	if (!skb) {
		skb = skb_malloc(-1);
		if (!skb) {
			eslog("skb_malloc() in on_conn_closed");
			return;
		} else {
			ylog("make default skb");
			struct upstream_skb_head *head = (struct upstream_skb_head*)skb->head;
			skb_put(skb, sizeof(*head));
			head->length = 0;
			head->serial = 0;
			head->theme = 0;
		}
	}
	// SKB_DUMP(skb);
	// upstream_skb_head_dump((struct upstream_skb_head*)skb->head);
	/* set NULL to indicate no conn */
#if 1
	/* FIXME */
	struct upstream_echo *echo = (struct upstream_echo*)lconn_ctx->internal;
	if (echo) {
		ylog("echo back");
		echo->external = NULL;
		client_process_upstream_write(echo, skb);
	} else {
		skb_free(skb);
	}
#endif

	lsquic_conn_set_ctx(conn, NULL);
	free(lconn_ctx);

	return;
}

lsquic_stream_ctx_t *client_on_new_stream(void *stream_if_ctx, struct lsquic_stream *stream)
{
	if (!stream) {
		// TODO
		elog("going away conn");
		// lsquic_conn_close();
		return NULL;
	};

	size_t id = lsquic_stream_id(stream);
	ylog("stream_if_ctx %p stream %p id %lu", stream_if_ctx, stream, id);

	struct lsquic_conn *lconn = lsquic_stream_conn(stream);
	struct lsquic_conn_ctx *lconn_ctx = lsquic_conn_get_ctx(lconn);
	struct lsquic_stream_ctx *sc = NULL;

	if (!id) {
		sc = lconn_ctx->pending;
		sc->stream = stream;
		rlog("TODO stream(0) %p", stream);
		rlog("s0 %p sc %p %p", stream, lsquic_stream_get_ctx(stream), sc);
		lconn_ctx->s0 = stream;
		lconn_ctx->pending = NULL;
		lsquic_stream_wantwrite(stream, 1);
		return sc;
	}

	char type = lsquic_stream_id(stream) & 0x3;
	/* RFC 9000 2.1. Table 1 */
	switch (type) {
		case 0x00:
			ylog("bi stream from client %p %p", stream, sc);
			assert(stream_is_cibi(stream));
			sc = lconn_ctx_del_pending_stream_ctx(lconn_ctx);
			if (sc) {
				rlog("s %p sc %p st %p", stream, sc, sc->subtask);
				lconn_ctx_add_running_stream_ctx(lconn_ctx, sc);
			}
			break;
		case 0x01:
			ylog("bi stream from server %p %p", stream, sc);
			assert(stream_is_sibi(stream));
			rlog("N/A");
			break;
		case 0x02:
			ylog("un stream from client %p %p", stream, sc);
			assert(stream_is_ciun(stream));
			break;
		case 0x03:
			ylog("un stream from server %p %p", stream, sc);
			assert(stream_is_siun(stream));
			break;
		default:
			break;
	}
	if (!sc) {
		rlog("FIXME");
		return NULL;
	}
	sc->stream = stream;

	/* XXX */
	return sc;
}

void client_on_conncloseframe_received(lsquic_conn_t *c,
		int app_error, uint64_t error_code,
		const char *reason, int reason_len)
{
	ylog("TODO maybe delete session file");
	for (int i = 0; i < reason_len; i++) {
		printf("%c", reason[i]);
	}
	printf("\n");
}

void client_on_reset(lsquic_stream_t *s, lsquic_stream_ctx_t *h, int how)
{
	if (!s) {
		elog("stream NULL");
		return;
	}
	ylog("stream %ld was reset %d %s",
			lsquic_stream_id(s), how,
			(0 == how) ? "read" : "write");
}

void client_on_read(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc)
{
	service_on_read(stream, sc);

	return;
}

void client_on_write(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc)
{
	service_on_write(stream, sc);
}

void client_on_hsk_done(lsquic_conn_t *conn, enum lsquic_hsk_status status)
{
	switch (status) {
		case LSQ_HSK_OK:
			{
				log(Yellow "LSQ_HSK_OK" RESET " handshake successful");
				struct lsquic_conn_ctx *lconn_ctx = lsquic_conn_get_ctx(conn);
				/* TODO check if skb memleak */
				struct sk_buff *skb = NULL;

				/* notify upstream */
				skb = skb_malloc(-1);
				if (!skb) {
					eslog("skb_malloc() in on_hsk_done");
					return;
				} else {
					ylog("notify upstream");
					struct upstream_skb_head *head = (struct upstream_skb_head*)skb->head;
					char *msg = "Connected!\n";
					size_t msg_len = strlen(msg) + 1;
					skb_put(skb, sizeof(*head) + msg_len);
					head->length = 0;
					head->serial = (unsigned short int)-1;
					head->theme = (unsigned short int)-1;
					/* don't bother to pull */
					memcpy(skb->data + sizeof(*head), msg, msg_len);
				}
				SKB_DUMP(skb);
				upstream_skb_head_dump((struct upstream_skb_head*)skb->head);
#if 1
				struct upstream_echo *echo = (struct upstream_echo*)lconn_ctx->internal;
				if (echo) {
					ylog("echo back");
					client_process_upstream_write(echo, skb);
				}
#endif
			}
			break;
		case LSQ_HSK_RESUMED_OK:
			{
				log(Green "LSQ_HSK_RESUMED_OK" RESET " handshake resume successful");
				struct lsquic_conn_ctx *lconn_ctx = lsquic_conn_get_ctx(conn);
				/* TODO check if skb memleak */
				struct sk_buff *skb = NULL;

				/* notify upstream */
				skb = skb_malloc(-1);
				if (!skb) {
					eslog("skb_malloc() in on_new_stream");
					return;
				} else {
					ylog("notify upstream");
					struct upstream_skb_head *head = (struct upstream_skb_head*)skb->head;
					char *msg = "Resumed!\n";
					size_t msg_len = strlen(msg) + 1;
					skb_put(skb, sizeof(*head) + msg_len);
					head->length = 0;
					head->serial = (unsigned short int)-1;
					head->theme = (unsigned short int)-1;
					/* don't bother to pull */
					memcpy(skb->data + sizeof(*head), msg, msg_len);
				}
				SKB_DUMP(skb);
				upstream_skb_head_dump((struct upstream_skb_head*)skb->head);
#if 1
				struct upstream_echo *echo = (struct upstream_echo*)lconn_ctx->internal;
				if (echo) {
					ylog("echo back");
					client_process_upstream_write(echo, skb);
				}
#endif
			}
			break;
		default:
			{
				log("handshake failed");
				ylog("TODO hsk_failed call_back(), maybe delete session file");
			}
			break;
	}
}

void client_on_close(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc)
{
	elog("stream(%ld) %p sc %p rx %lu tx %lu", lsquic_stream_id(stream), stream,
			sc, sc->rx_bytes, sc->tx_bytes);
	service_stream_ctx_free(sc);
}

ssize_t client_on_dg_write(lsquic_conn_t *conn, void *buf, size_t sz)
{
	elog();
	return 0;
}

void client_on_datagram(lsquic_conn_t *conn, const void *buf, size_t bufsz)
{
	elog();
}

void client_process_service(struct service *se)
{
	int diff;
	ev_tstamp timeout;
	struct client_event_loop *evl = (struct client_event_loop*)se->loop;

	ev_timer_stop(evl->loop, &evl->timer);
	if (service_is_stopped(se)) {
		elog("service %p is stopped %d", se, se->state);
		return;
	}

	lsquic_engine_process_conns(se->engine);

	if (lsquic_engine_earliest_adv_tick(se->engine, &diff)) {
		if (diff >= LSQUIC_DF_CLOCK_GRANULARITY) {
			timeout = (ev_tstamp) diff / 1000000;
		} else if (diff <= 0) {
			timeout = 0.0;
		} else {
			timeout = (ev_tstamp) LSQUIC_DF_CLOCK_GRANULARITY / 1000000;
		}
		// ylog("timeout %f", timeout);
		ev_timer_init(&evl->timer, client_timer_expired, timeout, 0.);
		ev_timer_start(evl->loop, &evl->timer);
	} else {
		plog("no more connection");
	}
}
