#include "runner.h"
#include "packet_io.h"

static void runner_signal_quit(struct ev_loop *loop, ev_signal *s, int revents)
{
	ylog("Signal QUIT captured, shutting down");
	ev_break(loop, EVBREAK_ALL);
}

static void runner_signal_int(struct ev_loop *loop, ev_signal *s, int revents)
{
	ylog("Signal INT captured, shutting down");
	ev_break(loop, EVBREAK_ALL);
}

static void runner_signal_term(struct ev_loop *loop, ev_signal *s, int revents)
{
	ylog("Signal TERM captured, shutting down");
	ev_break(loop, EVBREAK_ALL);
}

void ace_runner_init_signal(struct ev_loop *loop,
		ev_signal *sq, ev_signal *si, ev_signal *st,
		void *data)
{
	sq->data = data;
	si->data = data;
	st->data = data;
	ev_signal_init(sq, runner_signal_quit, SIGQUIT);
	ev_signal_init(si, runner_signal_int, SIGINT);
	ev_signal_init(st, runner_signal_term, SIGTERM);
	ev_signal_start(loop, sq);
	ev_signal_start(loop, si);
	ev_signal_start(loop, st);
}

void ace_runner_add_service(struct list_head *head, size_t *n_service,
		struct service *se)
{
	list_add_tail(&se->service_node, head);
	(*n_service)++;
}

int ace_runner_run_service(size_t *n_running, struct service *se)
{
	int s;

	/* Publish RUNNING before pthread_create so an immediate process signal
	 * cannot be overwritten by the worker while the main thread joins it. */
	service_set_running(se);
	s = pthread_create(&se->thread, NULL, service_func, (void*)se);
	if (s == 0) {
		se->thread_started = 1;
		(*n_running)++;
	} else {
		service_set_stopped(se);
		eslog("pthread_create()");
	}

	return s;
}

void ace_runner_stop_services(struct list_head *head)
{
	struct service *se = NULL;

	list_for_each_entry(se, head, service_node) {
		service_set_stopped(se);
		if (se->stop_event) {
			se->stop_event(se);
		}
	}
}

int ace_runner_join_services(struct list_head *head, size_t *n_running)
{
	int result = 0;
	struct service *se = NULL;

	list_for_each_entry(se, head, service_node) {
		if (!se->thread_started) {
			continue;
		}
		int rc = pthread_join(se->thread, NULL);
		if (rc != 0) {
			errno = rc;
			eslog("pthread_join()");
			result = -1;
		} else if (*n_running > 0) {
			(*n_running)--;
		}
		if (se->run_result != 0) {
			result = -1;
		}
		se->thread_started = 0;
	}
	return result;
}

int ace_runner_run(struct ev_loop *loop, ev_timer *tw,
		size_t n_service, void *data,
		void (*timeout_func)(EV_P_ ev_timer*, int))
{
	(void)tw;
	(void)data;
	(void)timeout_func;
	if (!n_service) {
		elog("no services to run");
		return -1;
	}

	/* Each QUIC engine is owned and scheduled by its service thread's loop.
	 * The main loop only handles process signals; touching service watchers here
	 * would cross libev loop and thread boundaries. */
	ev_run(loop, 0);
	log("event loop exited, shutting down");

	return 0;
}

void ace_runner_recv_data(EV_P_ ev_io *w, int revents)
{
	service_packets_in(w->data);
}
