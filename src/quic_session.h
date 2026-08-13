#ifndef __QUIC_SESSION_H__
#define __QUIC_SESSION_H__

#include <stddef.h>
#include <openssl/ssl.h>
#include <sys/socket.h>

/* session resume persistence: build file path, save/load resume info */
int session_resume_file_path(char *output, size_t output_size,
		const char *path, const struct sockaddr *peer, const char *device);
int on_new_session(SSL *ssl, SSL_SESSION *session);
ssize_t load_sess_resume_info(const char *name, unsigned char **info);

#endif
