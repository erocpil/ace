#ifndef ACE_IO_RETRY_H
#define ACE_IO_RETRY_H

#include <errno.h>

static inline int ace_io_retryable(int error)
{
	return error == EAGAIN || error == EWOULDBLOCK || error == EINTR;
}

#endif
