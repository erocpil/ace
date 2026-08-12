#define _GNU_SOURCE
#include "tls_context.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "define.h"

/* ------------------------------------------------------------------ */
/* Per-SSL_CTX storage via ex_data                                    */
/* ------------------------------------------------------------------ */

static int tls_ctx_ex_data_idx = -1;

/* Lightweight ALPN descriptor stored on SSL_CTX so the select callback
 * can read it without a global table. */
struct tls_alpn_store {
	unsigned char *protos;      /* wire-format list */
	unsigned int   protos_len;
};

static void tls_alpn_store_free(struct tls_alpn_store *s)
{
	if (s) {
		free(s->protos);
		free(s);
	}
}

static void tls_ctx_ex_data_free(void *parent, void *ptr,
				 CRYPTO_EX_DATA *ad, int idx,
				 long argl, void *argp)
{
	(void)parent; (void)ad; (void)idx; (void)argl; (void)argp;
	/* ptr is the struct tls_ctx * stored by SSL_CTX_set_ex_data.
	 * Do NOT free it here — ownership stays with the caller who
	 * must call tls_ctx_free().  This callback exists only so
	 * BoringSSL doesn't complain about a missing destructor. */
	(void)ptr;
}

/* ------------------------------------------------------------------ */
/* Context struct                                                     */
/* ------------------------------------------------------------------ */

struct tls_ctx {
	SSL_CTX    *ssl_ctx;
	int         verify_enabled;
	char       *hostname;   /* owned copy for the verify callback */
	int         mode;
	char       *alpn_str;   /* owned copy for diagnostics */
};

/* ------------------------------------------------------------------ */
/* Forward declarations                                               */
/* ------------------------------------------------------------------ */
static int  tls_ctx_verify_callback(int preverify_ok, X509_STORE_CTX *store_ctx);
static int  tls_ctx_alpn_select(SSL *ssl, const unsigned char **out,
				unsigned char *outlen, const unsigned char *in,
				unsigned int inlen, void *arg);
static void tls_ctx_keylog_cb(const SSL *ssl, const char *line);
static struct tls_alpn_store *tls_alpn_build(const char *alpn_list);

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

struct tls_ctx *tls_ctx_new(const struct tls_ctx_params *params)
{
	struct tls_ctx *ctx;
	struct tls_alpn_store *alpn_store = NULL;

	if (!params) {
		blog("tls_ctx_new: NULL params");
		return NULL;
	}

	/* One-time ex_data index registration. */
	if (tls_ctx_ex_data_idx < 0) {
		tls_ctx_ex_data_idx = SSL_CTX_get_ex_new_index(
			0, NULL, NULL, NULL, tls_ctx_ex_data_free);
		if (tls_ctx_ex_data_idx < 0) {
			elog("SSL_CTX_get_ex_new_index() failed");
			return NULL;
		}
	}

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->mode = params->mode;

	/* ---- create SSL_CTX ---- */
	ctx->ssl_ctx = SSL_CTX_new(TLS_method());
	if (!ctx->ssl_ctx) {
		elog("SSL_CTX_new() failed");
		goto fail;
	}

	SSL_CTX_set_min_proto_version(ctx->ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ctx->ssl_ctx, TLS1_3_VERSION);

	/* Store the tls_ctx pointer on the SSL_CTX so callbacks can
	 * retrieve it via SSL_CTX_get_ex_data. */
	if (1 != SSL_CTX_set_ex_data(ctx->ssl_ctx, tls_ctx_ex_data_idx, ctx)) {
		elog("SSL_CTX_set_ex_data() failed");
		goto fail;
	}

	/* ---- certificate and key (server) ---- */
	if (params->mode == TLS_CTX_MODE_SERVER) {
		if (!params->cert_file || !params->key_file) {
			elog("server requires cert_file and key_file");
			goto fail;
		}
		if (1 != SSL_CTX_use_certificate_chain_file(
				ctx->ssl_ctx, params->cert_file)) {
			elog("SSL_CTX_use_certificate_chain_file(%s) failed",
			     params->cert_file);
			goto fail;
		}
		if (1 != SSL_CTX_use_PrivateKey_file(
				ctx->ssl_ctx, params->key_file,
				SSL_FILETYPE_PEM)) {
			elog("SSL_CTX_use_PrivateKey_file(%s) failed",
			     params->key_file);
			goto fail;
		}
	}

	/* ---- CA / verification ---- */
	if (params->insecure) {
		ctx->verify_enabled = 0;
		blog("TLS verify disabled (insecure mode)");
	} else if (params->mode == TLS_CTX_MODE_CLIENT &&
		   (params->ca_file || params->ca_path)) {
		/* Client verifies the server certificate. */
		if (1 != SSL_CTX_load_verify_locations(
				ctx->ssl_ctx,
				params->ca_file,
				params->ca_path)) {
			elog("SSL_CTX_load_verify_locations() failed");
			goto fail;
		}
		SSL_CTX_set_default_verify_paths(ctx->ssl_ctx);
		SSL_CTX_set_verify(ctx->ssl_ctx,
				   SSL_VERIFY_PEER |
				   SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
				   tls_ctx_verify_callback);
		ctx->verify_enabled = 1;
		blog("TLS peer verification enabled");
	} else {
		ctx->verify_enabled = 0;
		blog("TLS peer verification disabled (no CA configured)");
	}

	/* Store hostname for the verify callback (client only). */
	if (params->hostname && params->hostname[0]) {
		ctx->hostname = strdup(params->hostname);
		if (!ctx->hostname) {
			elog("strdup(hostname) failed");
			goto fail;
		}
	}

	/* ---- ALPN ---- */
	if (params->alpn && params->alpn[0]) {
		alpn_store = tls_alpn_build(params->alpn);
		if (alpn_store) {
			SSL_CTX_set_ex_data(ctx->ssl_ctx,
					    tls_ctx_ex_data_idx + 1,
					    alpn_store);
			if (params->mode == TLS_CTX_MODE_CLIENT) {
				SSL_CTX_set_alpn_protos(ctx->ssl_ctx,
					alpn_store->protos,
					alpn_store->protos_len);
			}
			if (params->mode == TLS_CTX_MODE_SERVER) {
				SSL_CTX_set_alpn_select_cb(ctx->ssl_ctx,
					tls_ctx_alpn_select, NULL);
			}
		}
		ctx->alpn_str = strdup(params->alpn);
	}

	/* ---- keylog ---- */
	if (params->keylog_path && params->keylog_path[0]) {
		setenv("SSLKEYLOGFILE", params->keylog_path, 1);
		SSL_CTX_set_keylog_callback(ctx->ssl_ctx, tls_ctx_keylog_cb);
	}

	/* ---- session resumption (client) ---- */
	if (params->mode == TLS_CTX_MODE_CLIENT &&
	    params->session_path && params->session_path[0]) {
		SSL_CTX_set_session_cache_mode(ctx->ssl_ctx,
					       SSL_SESS_CACHE_CLIENT);
		SSL_CTX_set_early_data_enabled(ctx->ssl_ctx, 1);
		if (params->on_new_session) {
			SSL_CTX_sess_set_new_cb(ctx->ssl_ctx,
						params->on_new_session);
		}
	}

	blog("tls_ctx %p ssl_ctx=%p verify=%d mode=%s",
	     (void *)ctx, (void *)ctx->ssl_ctx, ctx->verify_enabled,
	     ctx->mode == TLS_CTX_MODE_SERVER ? "server" : "client");

	return ctx;

fail:
	tls_alpn_store_free(alpn_store);
	tls_ctx_free(ctx);
	return NULL;
}

SSL_CTX *tls_ctx_ssl(const struct tls_ctx *ctx)
{
	return ctx ? ctx->ssl_ctx : NULL;
}

int tls_ctx_verify_enabled(const struct tls_ctx *ctx)
{
	return ctx ? ctx->verify_enabled : 0;
}

void tls_ctx_free(struct tls_ctx *ctx)
{
	struct tls_alpn_store *alpn;

	if (!ctx)
		return;

	if (ctx->ssl_ctx) {
		alpn = SSL_CTX_get_ex_data(ctx->ssl_ctx,
					   tls_ctx_ex_data_idx + 1);
		tls_alpn_store_free(alpn);
		SSL_CTX_free(ctx->ssl_ctx);
	}
	free(ctx->hostname);
	free(ctx->alpn_str);
	free(ctx);
}

/* ------------------------------------------------------------------ */
/* Verification callback                                              */
/* ------------------------------------------------------------------ */

static int tls_ctx_verify_callback(int preverify_ok,
				   X509_STORE_CTX *store_ctx)
{
	X509   *cert  = X509_STORE_CTX_get_current_cert(store_ctx);
	int     depth = X509_STORE_CTX_get_error_depth(store_ctx);
	int     err   = X509_STORE_CTX_get_error(store_ctx);
	SSL    *ssl   = X509_STORE_CTX_get_ex_data(store_ctx,
					SSL_get_ex_data_X509_STORE_CTX_idx());

	blog("tls_verify: preverify=%d depth=%d err=%d:%s",
	     preverify_ok, depth, err,
	     X509_verify_cert_error_string(err));

	/* If default verification passed and this is the leaf cert,
	 * additionally check hostname when configured. */
	if (preverify_ok && depth == 0 && cert && ssl) {
		SSL_CTX       *ssl_ctx = SSL_get_SSL_CTX(ssl);
		struct tls_ctx *ctx   = ssl_ctx
			? SSL_CTX_get_ex_data(ssl_ctx, tls_ctx_ex_data_idx)
			: NULL;

		if (ctx && ctx->hostname) {
			if (X509_check_host(cert, ctx->hostname,
					    strlen(ctx->hostname),
					    0, NULL) != 1) {
				elog("hostname mismatch: expected '%s'",
				     ctx->hostname);
				return 0;  /* reject */
			}
			blog("hostname '%s' verified", ctx->hostname);
		}
	}

	return preverify_ok;
}

/* ------------------------------------------------------------------ */
/* ALPN                                                               */
/* ------------------------------------------------------------------ */

static struct tls_alpn_store *tls_alpn_build(const char *alpn_list)
{
	const char *start, *end;
	size_t       bufsz = 0;
	unsigned char *buf, *p;
	struct tls_alpn_store *s;

	/* First pass: calculate total size. */
	for (start = alpn_list; *start; ) {
		end = strchrnul(start, ',');
		size_t len = (size_t)(end - start);
		if (len < 1 || len > 255) {
			elog("ALPN proto len %zu out of range", len);
			return NULL;
		}
		bufsz += 1 + len;
		start = (*end == ',') ? end + 1 : end;
	}

	if (bufsz == 0)
		return NULL;

	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;

	buf = calloc(1, bufsz);
	if (!buf) {
		free(s);
		return NULL;
	}

	p = buf;
	for (start = alpn_list; *start; ) {
		end = strchrnul(start, ',');
		size_t len = (size_t)(end - start);
		*p++ = (unsigned char)len;
		memcpy(p, start, len);
		p += len;
		start = (*end == ',') ? end + 1 : end;
	}

	s->protos     = buf;
	s->protos_len = (unsigned int)bufsz;
	return s;
}

static int tls_ctx_alpn_select(SSL *ssl, const unsigned char **out,
			       unsigned char *outlen,
			       const unsigned char *in,
			       unsigned int inlen,
			       void *arg)
{
	(void)arg;
	SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(ssl);
	struct tls_alpn_store *alpn = ssl_ctx
		? SSL_CTX_get_ex_data(ssl_ctx, tls_ctx_ex_data_idx + 1)
		: NULL;

	if (!alpn || alpn->protos_len == 0) {
		/* No ALPN configured — use client's first offer. */
		*out    = in + 1;
		*outlen = in[0];
		return SSL_TLSEXT_ERR_OK;
	}

	int r = SSL_select_next_proto((unsigned char **)out, outlen,
				       alpn->protos, alpn->protos_len,
				       in, inlen);

	if (r == OPENSSL_NPN_NEGOTIATED) {
		blog("ALPN negotiated: %.*s", (int)*outlen, *out);
		return SSL_TLSEXT_ERR_OK;
	}

	/* No overlap — fall back to client's first offer so handshakes
	 * don't fail hard. */
	*out    = in + 1;
	*outlen = in[0];
	return SSL_TLSEXT_ERR_OK;
}

/* ------------------------------------------------------------------ */
/* Keylog                                                             */
/* ------------------------------------------------------------------ */

static void tls_ctx_keylog_cb(const SSL *ssl, const char *line)
{
	(void)ssl;
	const char *path = getenv("SSLKEYLOGFILE");
	if (!path)
		return;
	FILE *f = fopen(path, "a");
	if (f) {
		fprintf(f, "%s\n", line);
		fclose(f);
	}
}
