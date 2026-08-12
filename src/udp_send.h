#ifndef ACE_UDP_SEND_H
#define ACE_UDP_SEND_H

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>

typedef ssize_t (*ace_sendmsg_fn)(int, const struct msghdr *, int);

static inline int ace_zerocopy_unsupported(int error)
{
	return error == EINVAL || error == EOPNOTSUPP || error == ENOTSUP;
}

static inline ssize_t ace_udp_sendmsg(int fd, const struct msghdr *msg,
		ace_sendmsg_fn send_fn)
{
	size_t expected = 0;
	for (size_t i = 0; i < msg->msg_iovlen; ++i) {
		if (msg->msg_iov[i].iov_len > SSIZE_MAX - expected) {
			errno = EOVERFLOW;
			return -1;
		}
		expected += msg->msg_iov[i].iov_len;
	}

#ifdef MSG_ZEROCOPY
	ssize_t sent = send_fn(fd, msg, MSG_ZEROCOPY);
	if (sent < 0 && ace_zerocopy_unsupported(errno)) {
		sent = send_fn(fd, msg, 0);
	}
#else
	ssize_t sent = send_fn(fd, msg, 0);
#endif
	if (sent >= 0 && (size_t)sent != expected) {
		errno = EIO;
		return -1;
	}
	return sent;
}

#endif
