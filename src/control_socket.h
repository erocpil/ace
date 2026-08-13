#ifndef __CONTROL_SOCKET_H__
#define __CONTROL_SOCKET_H__

#include <stddef.h>
#include <sys/socket.h>

/*
 * control_socket — Unix domain socket lifecycle for the local control plane.
 *
 * FD ownership contract:
 *   - control_socket_un_create() returns a bound listening fd owned by the
 *     caller (e.g. closed by upstream_free()).  On failure it returns -1 and
 *     closes any fd it created, so the caller has nothing to clean up.
 *   - control_socket_accept() returns an accepted client fd owned by the
 *     caller, handed off to the echo lifecycle (closed on echo teardown).
 * Neither function closes the fd it returns on success; callers must close it
 * exactly once and must not double-close.
 */

/* Create, bind (and unlink any stale socket file) a Unix stream socket at
 * @file.  Returns the fd on success, -1 on error (errno set). */
int control_socket_un_create(const char *file);

/* Accept one connection on @listen_fd.  @addr/@addrlen, if non-NULL, receive
 * the peer address as in accept(2).  Returns the client fd on success, -1 on
 * error (errno set). */
int control_socket_accept(int listen_fd, struct sockaddr *addr,
			  socklen_t *addrlen);

#endif
