#include <assert.h>
#include <errno.h>
#include <string.h>
#include "udp_send.h"

static int calls;
static int seen_flags[2];
static ssize_t results[2];
static int errors[2];

static ssize_t fake_sendmsg(int fd, const struct msghdr *msg, int flags)
{
	(void)fd;
	(void)msg;
	int i = calls++;
	seen_flags[i] = flags;
	errno = errors[i];
	return results[i];
}

static void reset_fake(void)
{
	calls = 0;
	memset(seen_flags, 0, sizeof(seen_flags));
	memset(results, 0, sizeof(results));
	memset(errors, 0, sizeof(errors));
}

int main(void)
{
	char a[3], b[5];
	struct iovec iov[] = {{a, sizeof(a)}, {b, sizeof(b)}};
	struct msghdr msg = {.msg_iov = iov, .msg_iovlen = 2};

	reset_fake();
	results[0] = 8;
	assert(ace_udp_sendmsg(1, &msg, fake_sendmsg) == 8);
	assert(calls == 1);

#ifdef MSG_ZEROCOPY
	reset_fake();
	results[0] = -1;
	errors[0] = EOPNOTSUPP;
	results[1] = 8;
	assert(ace_udp_sendmsg(1, &msg, fake_sendmsg) == 8);
	assert(calls == 2);
	assert(seen_flags[0] == MSG_ZEROCOPY);
	assert(seen_flags[1] == 0);
#endif

	reset_fake();
	results[0] = -1;
	errors[0] = EAGAIN;
	assert(ace_udp_sendmsg(1, &msg, fake_sendmsg) == -1);
	assert(errno == EAGAIN);
	assert(calls == 1);

	reset_fake();
	results[0] = 4;
	assert(ace_udp_sendmsg(1, &msg, fake_sendmsg) == -1);
	assert(errno == EIO);

	return 0;
}
