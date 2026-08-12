#ifndef __TLS_CONTEXT_H__
#define __TLS_CONTEXT_H__

#include <openssl/ssl.h>
#include <stddef.h>

/* A TLS context owns an SSL_CTX and the verification policy for a
 * single QUIC endpoint (server or client). */

struct tls_ctx;

enum tls_ctx_mode {
	TLS_CTX_MODE_SERVER = 0,
	TLS_CTX_MODE_CLIENT = 1,
};

struct tls_ctx_params {
	/* Mode */
	enum tls_ctx_mode mode;

	/* Certificate and private key (PEM).  Required for server. */
	const char *cert_file;
	const char *key_file;

	/* CA verification: at least one of ca_file or ca_path must be set
	 * to enable peer verification.  If both are NULL the context is
	 * insecure and will accept any peer certificate. */
	const char *ca_file;
	const char *ca_path;

	/* Expected server hostname (client only).  When non-NULL and
	 * verification is enabled, the peer certificate must match this
	 * name (RFC 6125 / X509_check_host). */
	const char *hostname;

	/* Force-disable verification even when CA is configured.  Only
	 * intended for development and integration tests. */
	int insecure;

	/* Optional ALPN list (comma-separated, e.g. "main,ace").
	 * On the server side the first supported protocol from the client
	 * offer is selected.  On the client side the entire list is
	 * advertised. */
	const char *alpn;

	/* Optional SSLKEYLOG path for debugging (sets SSLKEYLOGFILE). */
	const char *keylog_path;

	/* Optional session-resume directory path (client only). */
	const char *session_path;

	/* Callback invoked when a new TLS session is established (client
	 * only, for session resumption).  May be NULL. */
	int (*on_new_session)(SSL *ssl, SSL_SESSION *session);
};

/* Create a TLS context from the given parameters.
 * Returns NULL and logs the reason on failure.
 * The caller owns the returned context and must free it with tls_ctx_free(). */
struct tls_ctx *tls_ctx_new(const struct tls_ctx_params *params);

/* Return the underlying SSL_CTX pointer.  The pointer is valid until
 * tls_ctx_free() is called. */
SSL_CTX *tls_ctx_ssl(const struct tls_ctx *ctx);

/* Return non-zero if peer certificate verification is active. */
int tls_ctx_verify_enabled(const struct tls_ctx *ctx);

/* Free the TLS context and its SSL_CTX.  Safe to call with NULL. */
void tls_ctx_free(struct tls_ctx *ctx);

#endif /* __TLS_CONTEXT_H__ */
