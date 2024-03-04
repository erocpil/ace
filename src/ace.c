#include <sys/time.h>
#include <sys/resource.h>
#include "ace.h"

void rlimit()
{
	struct rlimit v;   //you can decelare any variable

	if (-1 == getrlimit(RLIMIT_CORE, &v)) {
		eslog("getrlimit()");
	}
	clog("default softlimit %lu hardlimit %lu", v.rlim_cur, v.rlim_max);
	// v.rlim_cur = 0 ;
	// set maximum soft limit of the file(unlimited)
	v.rlim_cur = RLIM_INFINITY;
	//for reference to the soft limit(unlimited)
	v.rlim_max = RLIM_INFINITY;
	if (-1 == setrlimit(RLIMIT_CORE, &v)) {
		eslog("setrlimit()");
	}
	clog("current softlimit %lu hardlimit %lu", v.rlim_cur, v.rlim_max);

	// test core dump
	// *(int *)1 = 2;
}

int main(int argc, const char *argv[])
{
	PRINT_VERSION("ACE");
	glog("ACE cpu_frequency %lf", MHz);


	// daemon(1, 1);

	rlimit();

	// config

	// daemon

	// fork

	if (argc != 2) {
		exit(-EXIT_FAILURE);
	}

	unsigned short int flags = atoi(argv[1]);

	LIST_HEAD(config_head);

	switch (flags) {
		case 0:
			{
				struct client *ct = client_init();
				if (ct) {
					struct config_manager *cm = config_init(NULL, flags, 1);
					if (!cm) {
						eslog();
						exit(-EXIT_FAILURE);
					}

					struct config *c = config_get_last(cm);
					c->stream_if = &default_client_stream_if;
					c->cpu = 1;
					// c->log_level = "debug";
					c->retry = 3;
					c->retry_timeout = 1000;
					c->file = "/var/run/client";

					struct co_config *co = config_get_first_co(c);
					co->action |= ACTION_WANT_READ;
					co->action |= ACTION_ONE_MORE << 16;
					co->auto_stream0 = 1;

					size_t n = client_launch_service(ct, cm);
					if (ct->n_service) {
						log("%lu connote in %ld client launched", n, ct->n_service);
						client_run(ct);
						log();
					} else {
						elog("launched no service");
					}
				} else {
					elog("created no service");
					exit(-EXIT_FAILURE);
				}
			}
			break;
		case 1:
			{
				struct server *sr = server_init();
				if (sr) {
					struct config_manager *cm = config_init(NULL, flags, 1);
					if (!cm) {
						eslog();
						exit(-EXIT_FAILURE);
					}

					struct config *c = config_get_last(cm);
					c->stream_if = &default_server_stream_if;
					c->cpu = 2;
					// c->log_level = "debug";

					struct co_config *co = config_get_first_co(c);
					co->action |= ACTION_ONE_MORE << 16;

					size_t n = server_launch_service(sr, cm);
					if (sr->n_service) {
						log("%lu connote in %ld service launched", n, sr->n_service);
						server_run(sr);
						log();
					} else {
						elog("launched no service");
					}
				} else {
					elog("created no service");
					exit(-EXIT_FAILURE);
				}
			}
			break;
		default:
			exit(-EXIT_FAILURE);
	}

	return 0;
}
