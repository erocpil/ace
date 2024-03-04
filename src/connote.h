#ifndef __CONNOTE_H__
#define __CONNOTE_H__

#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>
#include <fcntl.h>
#include "config.h"
#include "define.h"
#include "list.h"

struct connote {
	struct list_head connote_node;
	int fd;
	int pad;
	struct service *service;
	struct device *device;
	struct mass *mass;

	volatile size_t rx_bytes;
	volatile size_t tx_bytes;

	struct co_config *cc;

	// FILE *keylog_file;

	struct sockaddr_storage sas;
	struct sockaddr_storage local_addr;

	void *event;
} __attribute__((aligned(sizeof(long))));

static inline int set_nonblocking(int fd)
{
	int flags = 0;

	flags = fcntl(fd, F_GETFL);
	if (-1 == flags) {
		return -1;
	}

	if (0 != fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
		return -1;
	}

	return 0;
}

struct connote *connote_init(struct co_config *cc);
int connote_init_server(struct connote *ce);
int connote_init_client(struct connote *ce);
void connote_free(struct connote *ce);

#endif
