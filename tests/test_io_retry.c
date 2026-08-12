#include <assert.h>
#include "io_retry.h"

int main(void)
{
	assert(ace_io_retryable(EAGAIN));
	assert(ace_io_retryable(EWOULDBLOCK));
	assert(ace_io_retryable(EINTR));
	assert(!ace_io_retryable(EBADF));
	assert(!ace_io_retryable(ECONNRESET));
	return 0;
}
