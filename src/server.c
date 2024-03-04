#include "server.h"
#include "task.h"

/**
 * s0_rx_func - stream(0) handler
 * return value: see server_on_read()
 */
ssize_t s0_rx_func(struct lsquic_stream_ctx *sc)
{
	ylog();
	assert(!lsquic_stream_id(sc->stream));
	struct sk_buff *skb = sc->rx;
	struct upstream_skb_head *head = (struct upstream_skb_head*)skb->head;

	/* wait for head */
	if (skb->len < sizeof(struct upstream_skb_head)) {
		return 0;
	}

	/* check if whole buffer was received */
	if (skb->len < sizeof(*head) + head->length) {
		clog("skb->len %u head->length %u", skb->len, head->length);
		return 0;
	} else {
		upstream_skb_head_dump(head);
		SKB_DUMP(skb);
	}

	switch (head->theme) {
		case TASK_THEME_SENDFILE:
			assert(!TASK_THEME_SENDFILE);
		case TASK_THEME_PERF:
			/* sendfile */
			ylog("length %u sendfile %u stream %u info %s",
					head->length, head->theme, head->serial, (char*)(head + 1));

			struct task *task = task_create(skb, TASK_ROLE_RECV);
			SKB_DUMP(skb);
			if (!task) {
				elog("TODO free ...");
				return -1;
			}

			/* parse negotiation info */
			if (-1 == task->nego(task, skb)) {
				elog("TODO task->nego()");
				exit(-EXIT_FAILURE);
			}
			SKB_DUMP(skb);

			if (-1 == task->init(task)) {
				elog("TODO task->init()");
				exit(-EXIT_FAILURE);
			}
			SKB_DUMP(skb);

			lsquic_conn_get_ctx(lsquic_stream_conn(sc->stream))->task = task;

			struct lsquic_conn_ctx *lconn_ctx =
				lsquic_conn_get_ctx(lsquic_stream_conn(sc->stream));

			ylog("task %p lconn_ctx %p", task, lconn_ctx);

			/* echo the request back to start xmit */
			struct sk_buff *tx = list_first_entry(&sc->txq, struct sk_buff, skb_node);
			assert(skb->len == skb->tail);
			if (tx->end >= skb->end) {
				tx->end = skb->end;
			} else {
				rlog("%u %u TODO malloc() a new tx skb", tx->end, skb->end);
				exit(-EXIT_FAILURE);
			}
			tx->len = skb->len;
			tx->tail = skb->tail;
			memcpy(sc->tx->head, sc->rx->head, skb->len);
			tx->data = tx->head;
			tx->offset = 0; /* clear offset to start over */
			SKB_DUMP(tx);
			clog("copy rx to tx and echo back");
			lsquic_stream_wantwrite(sc->stream, 1);
			blog("prepare to received file with %u stream including s0", task->n_sub);

			/* !!! first one is for stream(0) */
			/* now set the done callback */
			struct subtask *def = ((struct subtask*)sc->subtask);
			struct subtask *_subtask = task_get_sub_at(task, 0);
			/* there maybe a better way to start the state machine */
			ssize_t (*start_func)(struct lsquic_stream_ctx *sc) = _subtask->rx_func;

			/* replace default subtask */
			_subtask->rx_func = def->rx_func;
			_subtask->tx_func = def->tx_func;
			sc->subtask = _subtask;
			/* prepare n_sub - 1 sc for pending */
			for (unsigned short int i = 1; i < task->n_sub; i++) {
				/* no need to assign rx/tx buffer */
				struct lsquic_stream_ctx *sc =
					service_stream_ctx_malloc(lconn_ctx->ce->cc, 0, 0);
				sc->subtask = task_get_sub_at(task, i);
				lconn_ctx_add_pending_stream_ctx(lconn_ctx, sc);
				ylog("pending sc %p", sc);
			}
			start_func(sc);
			break;
		default:
			rlog("nop head %u %u %u", head->length, head->theme, head->serial);
			/* start over */
			skb->len = 0;
			skb->tail = 0;
			skb->offset = 0;
			break;
	}
	return 0;
}

/* s0_tx_func - stream(0) handler
 */
ssize_t s0_tx_func(struct lsquic_stream_ctx *sc)
{
	struct sk_buff *skb = sc->tx;
	struct upstream_skb_head *head = (struct upstream_skb_head*)skb->head;
	if ((unsigned short int)-1 == head->theme) {
		/* phase 2: a TASK_EXIT has been sent to RECV by s0 */
		ylog("s0 done");
		lsquic_stream_wantwrite(sc->stream, 0);
		return TASK_DONE;
	} else {
		/* phase 1: reply */
		lsquic_stream_wantwrite(sc->stream, 0);
		return TASK_GOON;
	}
	ylog();
	return TASK_GOON;
}

static struct subtask default_subtask = {
	.task = NULL,
	.rx_func = s0_rx_func,
	.tx_func = s0_tx_func,
	.no = 0,
};

static void server_exit(struct ev_loop *loop, ev_signal *s, int revents)
{
	if (EV_ERROR & revents) {
		elog("invalid event");
	}

	struct server *sr = (struct server*)s->data;
	struct service *se = NULL;
	list_for_each_entry(se, &sr->service_head, service_node) {
		ylog("exit se %p %lu conn", se, se->n_client_conn);
		struct lsquic_conn_ctx *lconn_ctx = NULL;
		list_for_each_entry(lconn_ctx, &se->conn_head, conn_node) {
			lsquic_conn_close(lconn_ctx->lconn);
		}
	}
}

static void server_signal_quit(struct ev_loop *loop, ev_signal *s, int revents)
{
	ylog("Signal QUIT captured");
	server_exit(loop, s, revents);
}

static void server_signal_int(struct ev_loop *loop, ev_signal *s, int revents)
{
	ylog("Signal INT captured");
	server_exit(loop, s, revents);
	exit(-EXIT_FAILURE);
}

static void server_signal_term(struct ev_loop *loop, ev_signal *s, int revents)
{
	ylog("Signal TERM captured");
	server_exit(loop, s, revents);
	exit(-EXIT_FAILURE);
}

static void server_init_signal(struct server *sr)
{
	sr->signal_quit.data = (void*)sr;
	sr->signal_int.data = (void*)sr;
	sr->signal_term.data = (void*)sr;
	ev_signal_init(&sr->signal_quit, server_signal_quit, SIGQUIT);
	ev_signal_init(&sr->signal_int, server_signal_int, SIGINT);
	ev_signal_init(&sr->signal_term, server_signal_term, SIGTERM);
	ev_signal_start(sr->loop, &sr->signal_quit);
	ev_signal_start(sr->loop, &sr->signal_int);
	ev_signal_start(sr->loop, &sr->signal_term);
}

struct server *server_init()
{
	struct server *sr = (struct server*)malloc(sizeof(struct server));
	if (!sr) {
		return NULL;
	}
	memset(sr, 0, sizeof(*sr));
	INIT_LIST_HEAD(&sr->service_head);
	/* server's default event loop */
	sr->loop = EV_DEFAULT;

	server_init_signal(sr);

	return sr;
}

int server_launch_service(struct server *sr, struct config_manager *cm)
{
	log();

	int n_connote = 0;
	struct config *pos = NULL;

	list_for_each_entry(pos, &cm->config_head, config_node) {
		if (-1 == config_check(pos)) {
			exit(-EXIT_FAILURE);
		}
	}

	list_for_each_entry(pos, &cm->config_head, config_node) {
		struct service *se = service_init(pos);
		elog("se %p", se);
		if (!se) {
			elog();
			continue;
		}
		struct co_config *co_pos = NULL;
		list_for_each_entry(co_pos, &pos->co_config_head, co_config_node) {
			struct connote *ce = connote_init(co_pos);
			elog("  cc %p ce %p", co_pos, ce);
			if (!ce) {
				elog();
				exit(-EXIT_FAILURE);
				// TODO free ce and go on
				continue;
			}
			struct server_event *ev = (struct server_event*)malloc(sizeof(struct server_event));
			if (!ev) {
				// TODO
				exit(-EXIT_FAILURE);
				return -1;
			}
			ce->event = (void*)ev;
			service_add_connote(se, ce);
			n_connote++;
		}
		struct server_event_loop *evl = (struct server_event_loop*)malloc(sizeof(struct server_event_loop));
		if (!evl) {
			// TODO
			exit(-EXIT_FAILURE);
			return -1;
		}
		memset(evl, 0, sizeof(*evl));
		evl->sr = sr;
		se->loop = (void*)evl;
		se->run_event = server_run_event;
		se->process = server_process_service;
		server_add_service(sr, se);
	}

	return n_connote;
}

void server_add_service(struct server *sr, struct service *se)
{
	struct list_head *head = &sr->service_head;
	struct list_head *node = &se->service_node;
	list_add_tail(head, node);
	sr->n_service++;
}

static void server_timeout_func(EV_P_ ev_timer *w, int revents)
{
#if 0
	log();
	struct server *sr = (struct server*)w->data;
	struct service *pos = NULL;
	struct list_head *head = &sr->service_head;
	list_for_each_entry(pos, head, service_node) {
		struct server_event_loop *evl = (struct server_event_loop*)pos->loop;
		if (!ev_async_pending(&evl->async_w)) {
			log();
			ev_async_send(evl->loop, &evl->async_w);
		}
	}
#endif

	w->repeat = 1.;
	ev_timer_again(loop, w);
}

/* client_run - run each service */
int server_run(struct server *sr)
{
	if (!sr || !sr->n_service) {
		elog();
		return -1;
	}
	struct service *pos = NULL;
	struct list_head *head = &sr->service_head;
	list_for_each_entry(pos, head, service_node) {
		server_run_service(sr, pos);
	}

	if (sr->n_service > 0) {
		log();
		ev_timer_init (&sr->tw, server_timeout_func, 1., 0.);
		sr->tw.data = (void*)sr;
		ev_timer_start (sr->loop, &sr->tw);
		ev_run(sr->loop, 0);
	}
	log();

	return 0;
}

/* client_run_service - run on service */
int server_run_service(struct server *sr, struct service *se)
{
	int s = 0;
	pthread_t thread;

	s = pthread_create(&thread, NULL, service_func, (void*)se);
	if (-1 == s) {
		eslog("pthread_create()");
		/// TODO free se
	} else {
		sr->n_running_service++;
	}

	return s;
}

static inline void server_timer_expired(EV_P_ ev_timer *timer, int revents)
{
	server_process_service(timer->data);
}

static void server_async_w_cb (EV_P_ ev_async *w, int revents)
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
		// service_set_stopped(se);
	}
}

void server_recv_data(EV_P_ ev_io *w, int revents)
{
	service_packets_in(w->data);
}

/* !!!run in service thread or process!!! */
int server_run_event(struct service *se)
{
	log();
	if (!se) {
		elog();
		return -1;
	}

	size_t n_connote = 0;
	struct connote *ce = NULL;
	unsigned int flags = EVFLAG_NOENV;
	struct server_event_loop *evl = (struct server_event_loop*)se->loop;
	unsigned long task_flags = evl->sr->task_flags;

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
			clog();
			break;
	}
	evl->loop = ev_loop_new(flags);
	list_for_each_entry(ce, &se->connote_head, connote_node) {
		struct server_event *e = ((struct server_event*)ce->event);
		e->w.data = ce;
		ev_io_init(&e->w, server_recv_data, ce->fd, EV_READ);
		ev_io_start(evl->loop, &e->w);
		n_connote++;
	}

	ev_init(&evl->timer, server_timer_expired);
	evl->timer.data = (void*)se;

	ev_async_init(&evl->async_w, server_async_w_cb);
	evl->async_w.data = (void*)se;

	service_set_running(se);
	ylog("service %p set running %d", se, se->state);

	ev_async_start(evl->loop, &evl->async_w);
	ev_run(evl->loop, 0);

	return 0;
}

lsquic_conn_ctx_t *server_on_new_conn(void *stream_if_ctx, struct lsquic_conn *conn)
{
	struct service *se = (struct service*)stream_if_ctx;
	struct lsquic_conn_ctx *lconn_ctx = lconn_ctx_malloc();
	assert(!lconn_ctx->pending);
	lconn_ctx->ce = lsquic_conn_get_peer_ctx(conn, NULL);
	lconn_ctx->lconn = conn;
	service_add_client_conn(se, lconn_ctx);
	clog("conn %p ctx %p", conn, lconn_ctx);

	/* if stream is make here, then on_new_stream() gets no conn_ctx */
	// ylog("FIXME lsquic_conn_make_stream()");
	// lsquic_conn_make_stream(conn);

	return lconn_ctx;
}

void server_on_goaway_received(lsquic_conn_t *stream_if_ctx)
{
	elog();
}

void server_on_conn_closed(lsquic_conn_t *conn)
{
	struct lsquic_conn_ctx *lconn_ctx = lsquic_conn_get_ctx(conn);
	hpelog("conn %p ctx %p", conn, lconn_ctx);
	if (lconn_ctx->keylog_file) {
		blog("keylog file %p closed", lconn_ctx->keylog_file);
		fclose(lconn_ctx->keylog_file);
	}

	struct connote *ce = lconn_ctx->ce;
	struct service *se = ce->service;
	service_del_client_conn(se, lconn_ctx);

	struct task *task = (struct task*)lconn_ctx->task;
	if (task) {
		task->exit(task);
	}

	lsquic_conn_set_ctx(conn, NULL);
	free(lconn_ctx);
}

lsquic_stream_ctx_t *server_on_new_stream(void *stream_if_ctx,
		struct lsquic_stream *stream)
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
	// clog("stream %p lconn %p ctx %p pending %p", stream, lconn, lconn_ctx, lconn_ctx->pending);
	struct connote *ce = lconn_ctx->ce;
	struct lsquic_stream_ctx *sc = NULL;
	barrier();

	char type = id & 0x3;
	/* RFC 9000 2.1. Table 1 */
	ylog("type %d", type);
	switch (type) {
		case 0x00:
			ylog("bi stream from client %p %ld %p", stream, id, sc);
			assert(stream_is_cibi(stream));
			if (!lsquic_stream_id(stream)) {
				/* stream 0 */
				sc = service_stream_ctx_malloc_pending(lconn, -1, -1);
				assert(sc == lconn_ctx->pending);
				ylog("pending sc %p for s0", sc);
				sc->subtask = &default_subtask;
				sc->stream = stream;
				clog("TODO stream(0) %p", stream);
				clog("s0 %p sc %p %p", stream, lsquic_stream_get_ctx(stream), sc);
				lconn_ctx->s0 = stream;
				lconn_ctx->pending = NULL;
			} else {
				sc = lconn_ctx_del_pending_stream_ctx(lconn_ctx);
				if (sc) {
					rlog("s %p sc %p st %p", stream, sc, sc->subtask);
					lconn_ctx_add_running_stream_ctx(lconn_ctx, sc);
				}
			}
			sc->new_action = ACTION_WANT_READ;
			break;
		case 0x01:
			ylog("bi stream from server %p %p", stream, sc);
			assert(stream_is_sibi(stream));
			sc = service_stream_ctx_malloc(lconn_ctx->ce->cc, -1, -1);
			sc->new_action = ACTION_WANT_NONE;
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
	sc->stream = stream;

	switch (sc->new_action) {
		case ACTION_WANT_READ:
			lsquic_stream_wantread(stream, 1);
			lsquic_stream_wantwrite(stream, 0);
			clog("stream(%p %ld) wantread", stream, id);
			break;
		case ACTION_WANT_WRITE:
			lsquic_stream_wantread(stream, 0);
			lsquic_stream_wantwrite(stream, 1);
			clog("wantwrite");
			break;
		case ACTION_WANT_READWRITE:
			lsquic_stream_wantread(stream, 1);
			lsquic_stream_wantwrite(stream, 1);
			clog("wantreadwrite");
			break;
		case ACTION_WANT_NONE:
			lsquic_stream_wantread(stream, 0);
			lsquic_stream_wantwrite(stream, 0);
			blog("no action for stream(%p %ld)", stream, id);
			break;
		default:
			lsquic_stream_wantread(stream, 0);
			lsquic_stream_wantwrite(stream, 0);
			elog("error action %d for stream %p, closing", sc->new_action, stream);
			lsquic_stream_close(stream);
			break;
	}

	assert(lconn_ctx->pending == NULL);
	return sc;
}

void server_on_conncloseframe_received(lsquic_conn_t *c,
		int app_error, uint64_t error_code,
		const char *reason, int reason_len)
{
	ylog();
	for (int i = 0; i < reason_len; i++) {
		printf("%c", reason[i]);
	}
	printf("\n");
}

void server_on_reset(lsquic_stream_t *s, lsquic_stream_ctx_t *h, int how)
{
	if (!s) {
		elog("stream NULL");
		return;
	}
	ylog("stream %ld was reset %d %s",
			lsquic_stream_id(s), how,
			(0 == how) ? "read" : "write");
}

void server_on_read(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc)
{
	service_on_read(stream, sc);

	return;
}

void server_on_write(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc)
{
	service_on_write(stream, sc);
}

void server_on_close(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc)
{
	elog("stream(%ld) %p", lsquic_stream_id(stream), stream);
	elog("sc %p rx %lu tx %lu", sc, sc->rx_bytes, sc->tx_bytes);
	service_stream_ctx_free(sc);
}

ssize_t server_on_dg_write(lsquic_conn_t *conn, void *buf, size_t sz)
{
	elog();
	return 0;
}

void server_on_datagram(lsquic_conn_t *conn, const void *buf, size_t bufsz)
{
	elog();
}

void server_process_service(struct service *se)
{
	int diff;
	ev_tstamp timeout;
	struct server_event_loop *evl = (struct server_event_loop*)se->loop;

	ev_timer_stop(evl->loop, &evl->timer);
	if (service_is_stopped(se)) {
		elog("service %p is stopped %d", se, se->state);
		return;
	}

	lsquic_engine_process_conns(se->engine);

	if (lsquic_engine_earliest_adv_tick(se->engine, &diff)) {
		if (diff >= LSQUIC_DF_CLOCK_GRANULARITY) {
			timeout = (ev_tstamp) diff / 1000000;
		} else if (diff < 0) {
			timeout = 0.0;
		} else {
			timeout = (ev_tstamp) LSQUIC_DF_CLOCK_GRANULARITY / 1000000;
		}
		ev_timer_init(&evl->timer, server_timer_expired, timeout, 0.);
		ev_timer_start(evl->loop, &evl->timer);
	} else {
		rlog("no more connection");
	}
}
