#include "runner.h"

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
	pthread_t thread;

	s = pthread_create(&thread, NULL, service_func, (void*)se);
	if (s == 0) {
		(*n_running)++;
	} else {
		eslog("pthread_create()");
	}

	return s;
}

int ace_runner_run(struct ev_loop *loop, ev_timer *tw,
		size_t n_service, void *data,
		void (*timeout_func)(EV_P_ ev_timer*, int))
{
	if (!n_service) {
		elog("no services to run");
		return -1;
	}

	ev_timer_init(tw, timeout_func, 1., 0.);
	tw->data = data;
	ev_timer_start(loop, tw);
	ev_run(loop, 0);
	log("event loop exited, shutting down");

	return 0;
}

void ace_runner_recv_data(EV_P_ ev_io *w, int revents)
{
	service_packets_in(w->data);
}
