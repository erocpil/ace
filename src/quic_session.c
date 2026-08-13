#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include "quic_session.h"
#include "connote.h"
#include "service.h"
#include "net_addr.h"

int session_resume_file_path(char *output, size_t output_size,
		const char *path, const struct sockaddr *peer, const char *device)
{
	char key[INET6_ADDRSTRLEN + 16];
	if (!path || ace_sockaddr_key(peer, key, sizeof(key)) != 0) return -1;
	return snprintf(output, output_size, "%s/%s-%s", path, key,
			device ? device : "") < (int)output_size ? 0 : -1;
}

int on_new_session(SSL *ssl, SSL_SESSION *session)
{
	unsigned char *buf;
	size_t bufsz, nw;
	FILE *file;

	/* https://lsquic.readthedocs.io/en/v3.1.1/tutorial.html#get-this-and-that-api
	 * The CID returned by lsquic_conn_id() is that used for logging: server
	 * and client should return the same CID. As noted earlier, you should not
	 * rely on this value to identify a connection! You can get a pointer to
	 * the connection from a stream and a pointer to the engine from a
	 * connection. Calling lsquic_conn_get_sockaddr() will point local and peer
	 * to the socket addressess of the current path. QUIC supports multiple
	 * paths during migration, but access to those paths has not been exposed
	 * via an API yet. This may change when or if QUIC adds true multipath
	 * support.
	 */
	struct lsquic_conn *lconn = lsquic_ssl_to_conn(ssl);
	struct lsquic_conn_ctx *lconn_ctx = lsquic_conn_get_ctx(lconn);
	if(lconn_ctx->session_resume_saved) {
		return 0;
	}
	const struct sockaddr *local = NULL;
	const struct sockaddr *peer = NULL;
	lsquic_conn_get_sockaddr(lconn, &local, &peer);
	if (local && peer) {
		char local_text[80] = { 0 };
		char peer_text[80] = { 0 };
		if (ace_sockaddr_format(local, local_text, sizeof(local_text)) != 0 ||
				ace_sockaddr_format(peer, peer_text, sizeof(peer_text)) != 0) {
			return 0;
		}
		log("confirmed connection on net_dev " Yellow "%s " RESET
				"local " Cyan "%s " RESET
				"peer " Green "%s" RESET,
				lconn_ctx->ce->cc->if_name,
				local_text, peer_text);
	} else {
		elog();
		return 0;
	}

	char sess[512] = { 0 };
	const char *session_path = lconn_ctx->ce->service->config.session_path;
	if (mkdir(session_path, 0700) != 0 && errno != EEXIST) {
		eslog("cannot create session directory %s: %s",
				session_path, strerror(errno));
		return 0;
	}
	if (session_resume_file_path(sess, sizeof(sess),
			lconn_ctx->ce->service->config.session_path, peer,
			// lconn_ctx->ce->service->alpn,
			lconn_ctx->ce->cc->if_name) != 0) return 0;

	if (0 != lsquic_ssl_sess_to_resume_info(ssl, session, &buf, &bufsz)) {
		elog("lsquic_ssl_sess_to_resume_info failed");
		return 0;
	}

	file = fopen(sess, "wb");
	if (!file) {
		elog("cannot open %s for writing: %s", sess, strerror(errno));
		free(buf);
		return 0;
	}

	nw = fwrite(buf, 1, bufsz, file);
	if (nw == bufsz) {
		ylog("wrote %zd bytes of session resumption information to %s", nw, sess);
	} else {
		elog("error: fwrite(%s) returns %zd instead of %zd: %s",
				sess, nw, bufsz, strerror(errno));
	}

	fclose(file);
	free(buf);

	lconn_ctx->session_resume_saved = 1;

	return 0;
}

ssize_t load_sess_resume_info(const char *name, unsigned char **info)
{
	log("tring to resume session from file \"%s\"", name);
	FILE *file = fopen(name, "rb");
	if (!file) {
		eslog("\"%s\"", name);
		log("use 1-RTT");
		return 0;
	}
	struct stat st;
	stat(name, &st);
	size_t length = st.st_size;
	*info = (unsigned char*)malloc(length);
	if (!*info) {
		elog("malloc() %d %s", errno, strerror(errno));
		fclose(file);
		return -1;
	}
	ssize_t n = fread(*info, 1, length, file);
	if (!n && !feof(file)) {
		elog("fread() %d %s", errno, strerror(errno));
		free(*info);
		*info = NULL;
	}
	fclose(file);

	return n;
}

