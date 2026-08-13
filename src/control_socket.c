#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "control_socket.h"
#include "define.h"

int control_socket_un_create(const char *file)
{
	struct sockaddr_un sun;

	if (!file || strlen(file) + 1 > sizeof(sun.sun_path)) {
		errno = EINVAL;
		return -1;
	}

	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	if (!access(file, F_OK)) {
		ylog("unlink %s", file);
		if (unlink(file) == -1) {
			close(fd);
			return -1;
		}
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, file, sizeof(sun.sun_path) - 1);

	if (bind(fd, (struct sockaddr*)&sun, sizeof(sun)) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

int control_socket_accept(int listen_fd, struct sockaddr *addr,
			  socklen_t *addrlen)
{
	return accept(listen_fd, addr, addrlen);
}
