#include "client.h"
#include "task.h"
#include "task_dispatch.h"
#include "link.h"
#include "link_monitor.h"
#include "runner.h"

static int client_process_upstream_read(struct upstream_echo *echo);
static void client_link_carrier_cb(const char *ifname, int up, void *user);

/* A service event loop has finished (idle-exit or startup failure).  Runs on
 * the main loop; break it once every service has exited so the client process
 * can shut down without an external signal. */
static void client_stop_w_cb(EV_P_ ev_async *w, int revents)
{
	struct client *ct = (struct client*)w->data;
	size_t n = __atomic_load_n(&ct->n_finished_service, __ATOMIC_ACQUIRE);

	if (n >= ct->n_service) {
		ylog("all %lu service(s) finished, breaking main loop", ct->n_service);
		ev_break(EV_A_ EVBREAK_ALL);
	}
}

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

	/* Service threads signal this watcher (thread-safely) when their own
	 * event loop exits; the main loop breaks once all of them are done. */
	ev_async_init(&ct->stop_w, client_stop_w_cb);
	ct->stop_w.data = (void*)ct;
	ev_async_start(ct->loop, &ct->stop_w);

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
		se->stop_event = client_stop_event;
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
	struct client *ct = (struct client*)w->data;
	struct service *pos = NULL;
	list_for_each_entry(pos, &ct->service_head, service_node) {
		client_process_service(EV_A_ pos);
	}
}

/* client_run - run each service */
int client_run(struct client *ct)
{
	struct service *pos = NULL;
	/* Best-effort: carrier monitoring is optional; a NULL monitor (e.g. no
	 * netlink permission in a container) must not prevent startup. */
	struct link_monitor *lm = link_monitor_init(ct->loop,
						    client_link_carrier_cb, (void*)ct);

	list_for_each_entry(pos, &ct->service_head, service_node) {
		ace_runner_run_service(&ct->n_running_service, pos);
	}

	int result = ace_runner_run(ct->loop, &ct->tw,
			ct->n_service, (void*)ct,
			client_timeout_cb);
	ace_runner_stop_services(&ct->service_head);
	if (ace_runner_join_services(&ct->service_head,
			&ct->n_running_service) != 0) {
		result = -1;
	}
	link_monitor_stop(lm);
	return result;
}

#define client_recv_data ace_runner_recv_data

static const uint64_t client_probe_nonce = UINT64_C(0x1020304050607080);

static ssize_t client_probe_rx(struct lsquic_stream_ctx *sc)
{
	struct upstream_skb_head head;
	struct ace_probe probe;

	if (task_frame_validate(sc->rx->head, sc->rx->len, &head) == 0) {
		return TASK_GOON;
	}
	if (task_frame_validate(sc->rx->head, sc->rx->len, &head) != 1 ||
	    task_payload_validate(&head,
		sc->rx->head + ACE_FRAME_HDR_LEN) != 0 ||
	    head.theme != TASK_THEME_PROBE) {
		return TASK_FAIL;
	}
	if (ace_probe_decode(
		(const unsigned char *)sc->rx->head + ACE_FRAME_HDR_LEN,
		head.length, &probe) != 0) {
		return TASK_FAIL;
	}
	if (probe.nonce != client_probe_nonce) {
		return TASK_FAIL;
	}
	log("QUIC_PROBE_OK nonce=%lu bytes=%u checksum=%08x",
	    probe.nonce, probe.data_length, probe.checksum);
	/* The probe establishes that the control stream works; keep it available
	 * for the real task negotiation that follows. */
	sc->rx->len = 0;
	sc->rx->tail = 0;
	sc->rx->offset = 0;
	sc->rx->data = sc->rx->head;
	struct lsquic_conn_ctx *lconn_ctx =
		lsquic_conn_get_ctx(lsquic_stream_conn(sc->stream));
	struct upstream_echo *echo = lconn_ctx ? lconn_ctx->internal : NULL;
	if (echo && echo->n_rq > 0 && client_process_upstream_read(echo) < 0) {
		return TASK_FAIL;
	}
	return TASK_GOON;
}

static ssize_t client_probe_tx(struct lsquic_stream_ctx *sc)
{
	lsquic_stream_wantwrite(sc->stream, 0);
	lsquic_stream_wantread(sc->stream, 1);
	return TASK_GOON;
}

static struct subtask client_probe_subtask = {
	.rx_func = client_probe_rx,
	.tx_func = client_probe_tx,
};

int client_connect_once(struct service *se)
{
	struct client_event_loop *evl;
	struct co_config *co;
	struct connote *ce;
	struct client_event *event;

	if (!se || !se->loop || list_empty(&se->config.co_config_head)) {
		errno = EINVAL;
		return -1;
	}
	evl = (struct client_event_loop *)se->loop;
	if (!evl->loop) {
		errno = EINVAL;
		return -1;
	}
	co = list_first_entry(&se->config.co_config_head,
			struct co_config, co_config_node);
	ce = connote_init(co);
	if (!ce) {
		return -1;
	}
	event = calloc(1, sizeof(*event));
	if (!event) {
		connote_free(ce);
		return -1;
	}
	ce->event = event;
	service_add_connote(se, ce);
	event->w.data = ce;
	ev_io_init(&event->w, client_recv_data, ce->fd, EV_READ);
	ev_io_start(evl->loop, &event->w);
	if (!service_connect(ce)) {
		ev_io_stop(evl->loop, &event->w);
		service_del_connote(ce);
		connote_free(ce);
		free(event);
		return -1;
	}
	log("AUTO_CONNECT_STARTED host=%s port=%u", co->host, co->port);
	return 0;
}

static inline void client_timer_expired(EV_P_ ev_timer *timer, int revents)
{
	client_process_service(EV_A_ timer->data);
}

/* link_monitor carrier callback (runs on the MAIN loop).  On carrier loss,
 * notify each service whose co_config is bound to the affected interface so
 * its loop can abort those connections immediately instead of waiting for the
 * QUIC no-progress/idle timeout. */
static void client_link_carrier_cb(const char *ifname, int up, void *user)
{
	struct client *ct = (struct client *)user;
	struct service *se = NULL;

	log("link carrier %s on %s", up ? "UP" : "DOWN", ifname);
	if (up || !ct)
		return;

	list_for_each_entry(se, &ct->service_head, service_node) {
		struct client_event_loop *evl = (struct client_event_loop *)se->loop;
		struct co_config *co;

		if (!evl || !evl->loop || list_empty(&se->config.co_config_head))
			continue;
		co = list_first_entry(&se->config.co_config_head,
				      struct co_config, co_config_node);
		if (!co->if_name[0] || strcmp(co->if_name, ifname) != 0)
			continue;

		strncpy(evl->carrier_ifname, ifname,
			sizeof(evl->carrier_ifname) - 1);
		evl->carrier_ifname[sizeof(evl->carrier_ifname) - 1] = '\0';
		ev_async_send(evl->loop, &evl->carrier_w);
	}
}

/* Runs on the SERVICE loop: abort every connection bound to the interface
 * that just lost carrier (lsquic_conn_abort is deferred, so it does not
 * re-enter client_on_conn_closed mid-iteration). */
static void client_carrier_cb(EV_P_ ev_async *w, int revents)
{
	struct service *se = (struct service *)w->data;
	struct client_event_loop *evl = (struct client_event_loop *)se->loop;
	struct lsquic_conn_ctx *lc = NULL;
	struct lsquic_conn_ctx *tmp = NULL;

	log("carrier lost on %s, aborting bound connections",
	    evl->carrier_ifname);

	list_for_each_entry_safe(lc, tmp, &se->conn_head, conn_node) {
		if (!lc->ce || !lc->ce->cc)
			continue;
		if (strcmp(lc->ce->cc->if_name, evl->carrier_ifname) != 0)
			continue;
		log("aborting connection %p bound to %s", lc->lconn,
		    evl->carrier_ifname);
		lsquic_conn_abort(lc->lconn);
	}
}

static void client_async_w_cb(EV_P_ ev_async *w, int revents)
{
	struct service *se = (struct service*)w->data;
	if (service_is_stopped(se)) {
		ev_break(EV_A_ EVBREAK_ALL);
	}
}

/* Drain upstream requests queued behind a just-finished task.  Runs on the
 * event loop (async), so lsquic_engine_connect() is not invoked re-entrantly
 * from within client_on_conn_closed(). */
static void client_drain_cb(EV_P_ ev_async *w, int revents)
{
	struct client_event_loop *evl = (struct client_event_loop*)w->data;
	struct upstream_echo *echo = NULL;

	if (!evl || !evl->up) {
		return;
	}
	list_for_each_entry(echo, &evl->up->echo_head, echo_node) {
		if (echo->n_rq > 0) {
			client_process_upstream_read(echo);
		}
	}
}

/* True if any upstream echo still has queued work (a request waiting to be
 * dispatched, or a response waiting to be written back). */
static int client_has_pending_work(struct client_event_loop *evl)
{
	struct upstream_echo *echo = NULL;

	if (!evl || !evl->up) {
		return 0;
	}
	list_for_each_entry(echo, &evl->up->echo_head, echo_node) {
		if (echo->n_rq > 0 || echo->n_sq > 0) {
			return 1;
		}
	}
	return 0;
}

/* Break the event loop once the last connection is gone and nothing is
 * queued.  Runs deferred (async) so the task-exit response, which
 * client_on_conn_closed() queued on the upstream send queue, has a chance to
 * flush before we tear the loop down; a direct ev_break() from inside the
 * conn-closed callback would skip the pending write watcher. */
static void client_idle_exit_cb(EV_P_ ev_async *w, int revents)
{
	struct service *se = (struct service*)w->data;
	struct client_event_loop *evl = se ? (struct client_event_loop*)se->loop : NULL;

	if (!evl || !evl->loop || !se) {
		return;
	}
	/* Still a live connection: nothing to do. */
	if (se->n_client_conn > 0) {
		return;
	}
	/* A request or response is still in flight; re-check next iteration. */
	if (client_has_pending_work(evl)) {
		ev_async_send(evl->loop, &evl->idle_w);
		return;
	}
	ylog("no active connection and no queued work, breaking event loop");
	ev_break(EV_A_ EVBREAK_ALL);
}

void client_stop_event(struct service *se)
{
	struct client_event_loop *evl = (struct client_event_loop*)se->loop;
	if (evl && evl->loop) {
		ev_async_send(evl->loop, &evl->async_w);
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
		se->process(*(struct ev_loop **)se->loop, se);

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
		/* One task per connection: if a task is already in flight, defer
		 * the remaining requests.  They are re-drained after the current
		 * task's connection closes (client_on_conn_closed). */
		if (lconn_ctx->task)
			break;
		struct upstream_skb_head *head = (struct upstream_skb_head*)skb->head;
		log("%p %u %u %u", head, head->length, head->theme, head->serial);
		struct task *task = task_create(skb, TASK_ROLE_SEND);
		if (!task) {
			elog("TODO free ...");
			return -1;
		}

		if (-1 == task->init(task)) {
			elog("task->init() failed, skipping");
			task->exit(task);
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
			task->exit(task);
			skb_free(skb);
			continue;
		}

		/* the nego already wrote the wire frame at tx->head; send it */
		SKB_DUMP(sc->tx);
		sc->subtask = task_get_sub_at(task, 0);
		lsquic_stream_wantwrite(lconn_ctx->s0, 1);

		lconn_ctx->task = task;
		struct subtask *st = NULL;
		/* !!! first one is for stream(0) */
		for (unsigned short int i = 1; i < task->n_sub; i++) {
			/* no need to assign rx/tx buffer */
			struct lsquic_stream_ctx *sc =
				service_stream_ctx_malloc(lconn_ctx, 0, 0);
			if (!sc) {
				lsquic_conn_abort(lconn_ctx->lconn);
				return -1;
			}
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
	if (!echo || !echo->up || !echo->up->tx_process_func) {
		elog("echo=%p up=%p tx_process_func=%p",
		     (void*)echo, echo ? (void*)echo->up : NULL,
		     (echo && echo->up) ? (void*)echo->up->tx_process_func : NULL);
		skb_free(skb);
		return -1;
	}
	int (*tx_process_func)(struct upstream_echo*, struct sk_buff*) =
		echo->up->tx_process_func;
	int n = tx_process_func(echo, skb);
	return n;
}

/* !!!run in service thread or process!!! */
int client_run_event(struct service *se)
{
	int result = -1;
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
	ev_timer_init(&evl->timer, client_timer_expired, 0., 0.);
	evl->timer.data = se;

	ev_async_init(&evl->async_w, client_async_w_cb);
	evl->async_w.data = (void*)se;

	ev_async_init(&evl->drain_w, client_drain_cb);
	evl->drain_w.data = (void*)evl;

	ev_async_init(&evl->idle_w, client_idle_exit_cb);
	evl->idle_w.data = (void*)se;

	ev_async_init(&evl->carrier_w, client_carrier_cb);
	evl->carrier_w.data = (void*)se;

	struct config *cc = &se->config;
	evl->up = upstream_init(evl->loop, 4, cc->retry, cc->retry_timeout, cc->file,
			client_process_upstream_read, NULL, 0);
	if (!evl->up) {
		eslog("upstream_init()");
		goto cleanup_loop;
	}
	evl->up->entity = (void*)se;

	/* run */
	if (0 != upstream_listen(evl->up)) {
		elog("upstream_listen() failed");
		goto cleanup_upstream;
	}

	ev_async_start(evl->loop, &evl->async_w);
	ev_async_start(evl->loop, &evl->drain_w);
	ev_async_start(evl->loop, &evl->idle_w);
	ev_async_start(evl->loop, &evl->carrier_w);
	if (service_is_stopped(se)) {
		result = 0;
		goto cleanup_async;
	}
	if (cc->auto_connect && client_connect_once(se) != 0) {
		eslog("client_connect_once()");
		goto cleanup_async;
	}

	ev_run(evl->loop, 0);
	service_set_stopped(se);
	rlog();
	result = 0;

cleanup_async:
	ev_async_stop(evl->loop, &evl->async_w);
	ev_async_stop(evl->loop, &evl->drain_w);
	ev_async_stop(evl->loop, &evl->idle_w);
	ev_async_stop(evl->loop, &evl->carrier_w);
cleanup_upstream:
	upstream_free(evl->up);
	evl->up = NULL;
cleanup_loop:
	ev_loop_destroy(evl->loop);
	evl->loop = NULL;
	/* Tell the main loop this service's event loop has exited (thread-safe:
	 * ev_async_send is the libev cross-thread wakeup).  The main loop breaks
	 * once every service has finished. */
	if (evl->ct && evl->ct->loop) {
		__atomic_fetch_add(&evl->ct->n_finished_service, 1, __ATOMIC_RELEASE);
		ev_async_send(evl->ct->loop, &evl->ct->stop_w);
	}
	return result;
}

lsquic_conn_ctx_t *client_on_new_conn(void *stream_if_ctx, struct lsquic_conn *conn)
{
	struct service *se = (struct service*)stream_if_ctx;
	struct lsquic_conn_ctx *lconn_ctx = lconn_ctx_malloc(se);
	if (!lconn_ctx) {
		lsquic_conn_abort(conn);
		return NULL;
	}
	lconn_ctx->ce = lsquic_conn_get_peer_ctx(conn, NULL);
	clog("ce %p from lsquic_engine_connect()", lconn_ctx->ce);
	lconn_ctx->lconn = conn;
	service_add_client_conn(se, lconn_ctx);

	lsquic_conn_set_ctx(conn, lconn_ctx);
	ace_conn_handshaking(&lconn_ctx->conn);
	struct lsquic_stream_ctx *sc =
		service_stream_ctx_malloc_pending(lconn_ctx, -1, -1);
	if (!sc) {
		lsquic_conn_abort(conn);
		return lconn_ctx;
	}
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

	if (evl->loop && ev_is_active(&ev->w)) {
		ylog("ev_io_stop(service %p connote %p fd %d)", se, ce, ce->fd);
		ev_io_stop(evl->loop, &ev->w);
	}

	struct sk_buff *skb = NULL;
	struct task *task = (struct task*)lconn_ctx->task;
	int task_complete = task && task->n_sub_done >= task->n_sub;
	lconn_ctx->conn.task_complete = (unsigned int)task_complete;

	/* P2: record connection outcome via state machine + counter */
	if (!lconn_ctx->conn.close_reported) {
		lconn_ctx->conn.close_reported = 1;
		if (!task_complete && service_is_running(se)) {
			ace_conn_fail(&lconn_ctx->conn, ACE_CLOSE_RESET);
			elog("QUIC_EVENT connection status=lost task_complete=0");
			/* Only a task that was in-flight and failed to complete is a
			 * service failure.  The auto-connect warmup probe connection
			 * has no task, so its eventual loss (peer idle timeout /
			 * reset) must not flip the service outcome to failure. */
			if (task)
				se->n_conn_failed++;
		} else {
			ace_conn_close(&lconn_ctx->conn,
				       task_complete
				       ? ACE_CLOSE_USER_REQUEST
				       : ACE_CLOSE_PEER_GRACEFUL);
			se->n_conn_closed++;
		}
	}
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
		/* More requests may be queued; start the next connection on the
		 * next loop iteration (async) so lsquic_engine_connect() is not
		 * called re-entrantly from on_conn_closed. */
		if (echo->n_rq > 0 && evl->loop) {
			ev_async_send(evl->loop, &evl->drain_w);
		}
	} else {
		skb_free(skb);
	}
#endif

	/* Last connection gone: schedule an idle-exit check.  Deferred so the
	 * task-exit response queued above can flush first (see client_idle_exit_cb). */
	if (evl->loop && se->n_client_conn == 0) {
		ev_async_send(evl->loop, &evl->idle_w);
	}

	/* stream 0 may never have been established: free its pending ctx */
	if (lconn_ctx->pending) {
		service_stream_ctx_free(lconn_ctx->pending);
		lconn_ctx->pending = NULL;
	}

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
		unsigned char probe_data[TASK_PROBE_DATA_SIZE];
		for (size_t i = 0; i < TASK_PROBE_DATA_SIZE; ++i) {
			probe_data[i] = (unsigned char)(i * 31U + 7U);
		}

		struct ace_probe probe = {
			.magic       = TASK_PROBE_MAGIC,
			.nonce       = client_probe_nonce,
			.data_length = TASK_PROBE_DATA_SIZE,
			.checksum    = task_checksum32(probe_data, TASK_PROBE_DATA_SIZE),
			.data        = probe_data,
		};

		size_t probe_frame_length = ace_probe_encode(NULL, 0, 1, &probe);
		if (probe_frame_length == 0) {
			lsquic_conn_abort(lconn);
			return NULL;
		}

		sc = lconn_ctx->pending;
		if (!sc || !sc->tx || sc->tx->end < probe_frame_length) {
			lsquic_conn_abort(lconn);
			return NULL;
		}
		sc->stream = stream;
		rlog("TODO stream(0) %p", stream);
		rlog("s0 %p sc %p %p", stream, lsquic_stream_get_ctx(stream), sc);
		lconn_ctx->s0 = stream;
		lconn_ctx->pending = NULL;

		ace_probe_encode(sc->tx->head, sc->tx->end, 1, &probe);
		sc->tx->data = sc->tx->head;
		sc->tx->len = probe_frame_length;
		sc->tx->tail = sc->tx->len;
		sc->tx->offset = 0;
		sc->subtask = &client_probe_subtask;
		lsquic_stream_wantwrite(stream, 1);
		return sc;
	}

	char type = lsquic_stream_id(stream) & 0x3;
	/* RFC 9000 2.1. Table 1 */
	switch (type) {
		case 0x00:
			ylog("bi stream from client %p %p", stream, sc);
			sc = lconn_ctx_del_pending_stream_ctx(lconn_ctx);
			if (sc) {
				rlog("s %p sc %p st %p", stream, sc, sc->subtask);
				lconn_ctx_add_running_stream_ctx(lconn_ctx, sc);
			}
			break;
		case 0x01:
			ylog("bi stream from server %p %p", stream, sc);
			rlog("N/A");
			break;
		case 0x02:
			ylog("un stream from client %p %p", stream, sc);
			break;
		case 0x03:
			ylog("un stream from server %p %p", stream, sc);
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
				ace_conn_active(&lconn_ctx->conn);
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
						/* drain upstream requests queued while the
						 * conn was still handshaking (s0 not ready). */
						client_process_upstream_read(echo);
					} else {
						skb_free(skb);
					}
#endif
			}
			break;
		case LSQ_HSK_RESUMED_OK:
			{
				log(Green "LSQ_HSK_RESUMED_OK" RESET " handshake resume successful");
				struct lsquic_conn_ctx *lconn_ctx = lsquic_conn_get_ctx(conn);
				ace_conn_active(&lconn_ctx->conn);
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
						/* drain upstream requests queued while the
						 * conn was still handshaking (s0 not ready). */
						client_process_upstream_read(echo);
					} else {
						skb_free(skb);
					}
#endif
			}
			break;
		default:
			{
				struct lsquic_conn_ctx *lconn_ctx = lsquic_conn_get_ctx(conn);
				if (lconn_ctx) {
					ace_conn_fail(&lconn_ctx->conn, ACE_CLOSE_TLS_FAILURE);
					if (lconn_ctx->ce && lconn_ctx->ce->service) {
						lconn_ctx->ce->service->n_conn_failed++;
					}
				}
				elog("QUIC_EVENT handshake status=failed code=%d", status);
				lsquic_conn_abort(conn);
			}
			break;
	}
}

void client_on_close(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc)
{
	if (!sc) {
		elog("stream(%ld) %p sc=NULL (lsquic delivered null stream context)",
		     lsquic_stream_id(stream), stream);
		return;
	}
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

void client_process_service(EV_P_ struct service *se)
{
	int diff;
	ev_tstamp timeout;
	struct client_event_loop *evl = (struct client_event_loop*)se->loop;
	if (se->processing) {
		se->process_pending = 1;
		return;
	}
	se->processing = 1;

	ev_timer_stop(EV_A_ &evl->timer);
	if (service_is_stopped(se)) {
		elog("service %p is stopped %d", se, se->state);
		se->processing = 0;
		return;
	}

	do {
		se->process_pending = 0;
		lsquic_engine_process_conns(se->engine);
	} while (se->process_pending);

	if (lsquic_engine_earliest_adv_tick(se->engine, &diff)) {
		if (diff >= LSQUIC_DF_CLOCK_GRANULARITY) {
			timeout = (ev_tstamp) diff / 1000000;
		} else if (diff <= 0) {
			timeout = 0.0;
		} else {
			timeout = (ev_tstamp) LSQUIC_DF_CLOCK_GRANULARITY / 1000000;
		}
		// ylog("timeout %f", timeout);
		ev_timer_set(&evl->timer, timeout, 0.);
		ev_timer_start(EV_A_ &evl->timer);
	} else {
		plog("no more connection");
	}
	se->processing = 0;
}
