#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include "connote.h"
#include "packet_io.h"

static void fill_cc(struct co_config *cc, const char *host,
		unsigned short port, int ipver, unsigned long flags)
{
	memset(cc, 0, sizeof(*cc));
	strncpy(cc->host, host, sizeof(cc->host) - 1);
	cc->port = port;
	cc->ipver = ipver;
	cc->flags = flags;
}

int main(void)
{
	/* set_nonblocking toggles O_NONBLOCK */
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	assert(fd >= 0);
	assert(set_nonblocking(fd) == 0);
	assert(fcntl(fd, F_GETFL) & O_NONBLOCK);
	close(fd);

	/* server socket: bound, non-blocking, ephemeral port assigned */
	struct co_config scc;
	fill_cc(&scc, "127.0.0.1", 0, 4, 1);
	struct connote *sce = connote_init(&scc);
	assert(sce != NULL);
	assert(sce->fd >= 0);
	assert(fcntl(sce->fd, F_GETFL) & O_NONBLOCK);
	assert(sce->local_addr.ss_family == AF_INET);
	assert(ntohs(((struct sockaddr_in *)&sce->local_addr)->sin_port) != 0);
	connote_free(sce);

	/* client socket: non-blocking, connected to peer (UDP connect needs no peer) */
	struct co_config ccc;
	fill_cc(&ccc, "127.0.0.1", 12345, 4, 0);
	struct connote *cce = connote_init(&ccc);
	assert(cce != NULL);
	assert(cce->fd >= 0);
	assert(fcntl(cce->fd, F_GETFL) & O_NONBLOCK);
	assert(cce->local_addr.ss_family == AF_INET);
	connote_free(cce);

	/* NULL co_config -> client conn, socket not created yet */
	struct connote *nce = connote_init(NULL);
	assert(nce != NULL);
	assert(nce->fd == -1);
	connote_free(nce);

	/* invalid flags -> init fails */
	struct co_config icc;
	fill_cc(&icc, "127.0.0.1", 0, 4, 99);
	assert(connote_init(&icc) == NULL);

	return 0;
}
