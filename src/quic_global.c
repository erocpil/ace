#include <pthread.h>
#include <stdlib.h>
#include "lsquic.h"
#include "quic_global.h"

static pthread_once_t quic_once = PTHREAD_ONCE_INIT;
static int quic_init_result = -1;

static void quic_global_cleanup_at_exit(void)
{
	if (quic_init_result == 0) {
		lsquic_global_cleanup();
	}
}

static void quic_global_init_once(void)
{
	quic_init_result = lsquic_global_init(
			LSQUIC_GLOBAL_CLIENT | LSQUIC_GLOBAL_SERVER);
	if (quic_init_result == 0 && atexit(quic_global_cleanup_at_exit) != 0) {
		quic_init_result = -1;
		lsquic_global_cleanup();
	}
}

int ace_quic_global_init(void)
{
	return pthread_once(&quic_once, quic_global_init_once) == 0 ?
		quic_init_result : -1;
}
