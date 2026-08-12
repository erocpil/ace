#include <assert.h>
#include <pthread.h>
#include "quic_global.h"

static void *initialize(void *unused)
{
	(void)unused;
	return (void *)(long)ace_quic_global_init();
}

int main(void)
{
	pthread_t threads[16];
	for (size_t i = 0; i < 16; ++i)
		assert(pthread_create(&threads[i], NULL, initialize, NULL) == 0);
	for (size_t i = 0; i < 16; ++i) {
		void *result = NULL;
		assert(pthread_join(threads[i], &result) == 0);
		assert((long)result == 0);
	}
	return 0;
}
