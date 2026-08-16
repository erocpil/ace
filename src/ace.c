#include <sys/time.h>
#include <sys/resource.h>
#include "ace.h"
#include "config_file.h"

void rlimit()
{
	struct rlimit v;

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
	// glog("ACE cpu_frequency %lf", MHz);  // MHz undefined when lscpu fails


	// daemon(1, 1);

	rlimit();

	// config

	// daemon

	// fork

	if (argc != 2) {
		return EXIT_FAILURE;
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
						return EXIT_FAILURE;
					}

					struct config *c = config_get_last(cm);
					c->stream_if = &default_client_stream_if;
					c->cpu = 1;
					// c->log_level = "debug";
					c->retry = 3;
					c->retry_timeout = 1000;
				c->file = getenv("ACE_UPSTREAM_FILE");
				if (!c->file || !c->file[0]) {
					c->file = "/var/run/client";
				}
				c->auto_connect = 1;

					struct co_config *co = config_get_first_co(c);
					if (getenv("ACE_IP_VERSION") && !strcmp(getenv("ACE_IP_VERSION"), "6")) {
						strncpy(co->host, "::1", sizeof(co->host) - 1);
						co->ipver = 6;
					}
					co->action |= ACTION_WANT_READ;
					co->action |= ACTION_ONE_MORE << 16;
					co->auto_stream0 = 1;

					if (config_file_load_env(cm) != 0) {
						elog("failed to load config file, aborting");
						return EXIT_FAILURE;
					}

					size_t n = client_launch_service(ct, cm);
					if (ct->n_service) {
						log("%lu connote in %ld client launched", n, ct->n_service);
						if (client_run(ct) != 0) {
							return EXIT_FAILURE;
						}
						log();
					} else {
						elog("launched no service");
					}
				} else {
					elog("created no service");
					return EXIT_FAILURE;
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
						return EXIT_FAILURE;
					}

					struct config *c = config_get_last(cm);
					c->stream_if = &default_server_stream_if;
					c->cpu = 2;
					// c->log_level = "debug";

					struct co_config *co = config_get_first_co(c);
					if (getenv("ACE_IP_VERSION") && !strcmp(getenv("ACE_IP_VERSION"), "6")) {
						strncpy(co->host, "::", sizeof(co->host) - 1);
						co->ipver = 6;
					}
					co->action |= ACTION_ONE_MORE << 16;

					if (config_file_load_env(cm) != 0) {
						elog("failed to load config file, aborting");
						return EXIT_FAILURE;
					}

					size_t n = server_launch_service(sr, cm);
					if (sr->n_service) {
						log("%lu connote in %ld service launched", n, sr->n_service);
						if (server_run(sr) != 0) {
							return EXIT_FAILURE;
						}
						log();
					} else {
						elog("launched no service");
					}
				} else {
					elog("created no service");
					return EXIT_FAILURE;
				}
			}
			break;
		default:
			return EXIT_FAILURE;
	}

	return 0;
}
