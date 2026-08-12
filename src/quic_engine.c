/*
 * quic_engine.c — lsquic engine assembly and lifecycle
 *
 * Extracted from service.c (P5 module boundary).
 * Assembles engine settings + API, creates/destroys the lsquic engine,
 * and builds the TLS context + SNI lookup table the engine consults.
 */
#include "quic_engine.h"
#include "service.h"     /* struct service, struct config, hash, tls_context */
#include "quic_global.h" /* ace_quic_global_init */
#include "define.h"      /* log macros */

/* session-resume callback lives in service.c (session layer) */
int on_new_session(SSL *ssl, SSL_SESSION *session);

static inline int service_init_ssl_ctx(struct service *se);
static int service_init_ssl_ctx_server(struct service *se);
static int service_init_ssl_ctx_client(struct service *se);

/* peer_ctx from lsquic_engine_connect()
 * peer_ctx from lsquic_engine_packet_in() */
static SSL_CTX *service_get_ssl_ctx(void *peer_ctx, const struct sockaddr *unused)
{
	const struct service *se = ((struct connote*)peer_ctx)->service;
	blog("se %p peer_ctx(ce) %p ssl_ctx %p", se, peer_ctx, se->ssl_ctx);
	return se->ssl_ctx;
}

static struct ssl_ctx_st *service_lookup_cert(void *cert_lu_ctx,
		const struct sockaddr *sa_UNUSED, const char *sni)
{
	struct service *se = (struct service*)cert_lu_ctx;
	SSL_CTX *ssl_ctx = NULL;

	struct ace_hash *h = se->cert_hash;
	ace_hash_count(h);

	if (sni) {
		log("sni %s %lu", sni, strlen(sni));
	} else {
		log("empty sni");
		for (unsigned int i = 0; i < h->n_bucket; i++) {
			struct ace_hash_head *ha = &h->ha_head[i];
			if (ha->n_elem > 0) {
				struct ace_hash_elem *elem =
					hlist_entry(ha->hl_head.first, struct ace_hash_elem, hl_node);
				ssl_ctx = (SSL_CTX*)elem->val;
				log("ssl_ctx %p", ssl_ctx);
				return ssl_ctx;
			}
		}
	}

	return NULL;
}

static int service_log_buf(void *logger_ctx, const char *buf, size_t len)
{
	FILE *out = (FILE*)logger_ctx;
	fwrite(buf, 1, len, out);
	fflush(out);
	return 0;
}

static int service_add_alpn(struct service *se, char *alpn)
{
	size_t cur = strlen(se->alpn);
	size_t need = 1 + strlen(alpn);
	if (cur + need + 1 > sizeof(se->alpn)) {
		elog("ALPN overflow: cur=%zu need=%zu max=%zu", cur, need, sizeof(se->alpn));
		return -1;
	}
	char *p = se->alpn + cur;
	char l = strlen(alpn);
	memcpy(p, &l, sizeof(char));
	memcpy(p + 1, alpn, l);

	return 0;
}

struct service *service_init_engine(struct service *se)
{
	char err_buf[128] = { 0 };
	struct lsquic_engine_settings *es = NULL;
	struct lsquic_engine_api *ea = NULL;
	unsigned long flags = se->config.flags & FLAGS_MASK;
	log("init %s", flags ? "server" : "client");

	/* for each cert, set keylog */
	// SSL_CTX_set_keylog_callback(cert->ce_ssl_ctx, keylog_log_line);
	// TODO
	// load se->certs
	if (0 != service_init_ssl_ctx(se)) {
		elog();
		return NULL;
	}

	es = se->engine_settings;
	lsquic_engine_init_settings(es, flags);
	// TODO
	es->es_ecn = LSQUIC_DF_ECN;
	es->es_handshake_to = 3000000;
	es->es_ping_period = 2;
	es->es_idle_timeout = 3;
	/* Bound detection of a path that remains open locally but makes no QUIC
	 * progress (for example, a crashed or partitioned peer). */
	es->es_noprogress_timeout = 3;
	// es->es_versions = LSQVER_I001;
	// es->es_ql_bits = 0;
	// on_datagram
	// es.es_datagrams = 1;
	// es.es_init_max_data = 0;
	// es.es_init_max_streams_bidi = 0;
	// es.es_init_max_streams_uni = 0;
	// es.es_max_streams_in = 0;

	// TODO
	se->s_log_fh = stderr;
	setvbuf(se->s_log_fh, NULL, _IOLBF, 0);
	se->file_logger_if.log_buf = service_log_buf;
	lsquic_logger_init(&se->file_logger_if, se->s_log_fh, LLTS_HHMMSSUS);

	// lsquic_logger_lopt("=notice");
	// lsquic_set_log_level("warn");
	lsquic_set_log_level(se->config.log_level);

	if (ace_quic_global_init() != 0) {
		elog("lsquic_global_init()");
		return NULL;
	}

	ea = se->engine_api;
	ea->ea_settings = es;
	ea->ea_stream_if = se->config.stream_if;
	ea->ea_stream_if_ctx = (void*)se;
	ea->ea_packets_out = se->config.packets_out;
	ea->ea_packets_out_ctx = (void*)se;
	// TODO
	// ea->ea_pmi = pmi;
	// ea->ea_pmi_ctx = pmi_ctx;
	// TODO check if certs
	ea->ea_get_ssl_ctx = service_get_ssl_ctx;
	ea->ea_lookup_cert = service_lookup_cert;
	ea->ea_cert_lu_ctx = se;
	/**
	 * The optional ALPN string is used by the client if @ref LSENG_HTTP
	 * is not set.
	 */
	ea->ea_alpn = "main";
	service_add_alpn(se, "main");
	service_add_alpn(se, "ace");

	if (0 != lsquic_engine_check_settings(es, flags, err_buf, sizeof(err_buf))) {
		elog("lsquic_engine_check_settings()");
	}

	se->engine = lsquic_engine_new(flags, ea);
	if (!se->engine) {
		elog("lsquic_engine_new()");
		return NULL;
	}

	return se;
}

static inline int service_init_ssl_ctx(struct service *se)
{
	return (se->config.flags & FLAGS_MASK & LSENG_SERVER) ?
		service_init_ssl_ctx_server(se) : service_init_ssl_ctx_client(se);
}

int service_init_cert_hash(struct service *se)
{
	size_t n_bucket = se->config.n_cert_hash_bucket;
	size_t n_elem = se->config.n_cert_hash_elem;
	if (!n_bucket || !n_elem) {
		errno = EINVAL;
		return -1;
	}

	// TODO check n_bucket and n_elem
	se->cert_hash = ace_hash_create(n_bucket, n_elem);

	if (!se->cert_hash) {
		return -1;
	}

	return 0;
}

int service_init_ssl_ctx_map(struct service *se)
{
	/* Register the tls_ctx's SSL_CTX in the cert hash so
	 * service_lookup_cert() can return it for any SNI value.
	 * Multi-cert SNI support is future work. */
	if (!se->ssl_ctx) {
		elog("ssl_ctx not initialized before map");
		return -1;
	}

	char *key = "sni";
	char *val = (char *)se->ssl_ctx;
	unsigned int klen = strlen(key) + 1;
	unsigned int vlen = 0;

	if (0 != ace_hash_add(se->cert_hash, key, klen, val, vlen)) {
		elog("cert_hash insert failed");
		return -1;
	}

	blog("cert_hash: registered %s -> ssl_ctx=%p", key, (void *)se->ssl_ctx);
	return 0;
}

static int service_init_ssl_ctx_server(struct service *se)
{
	const char *cert_file = getenv("ACE_CERT_FILE");
	const char *key_file  = getenv("ACE_KEY_FILE");
	const char *ca_file   = getenv("ACE_CA_FILE");
	const char *ca_path   = getenv("ACE_CA_PATH");
	const char *insecure  = getenv("ACE_TLS_INSECURE");

	if (!cert_file || !*cert_file) cert_file = ACE_DEFAULT_CERT_FILE;
	if (!key_file  || !*key_file)  key_file  = ACE_DEFAULT_KEY_FILE;

	struct tls_ctx_params params = {
		.mode         = TLS_CTX_MODE_SERVER,
		.cert_file    = cert_file,
		.key_file     = key_file,
		.ca_file      = ca_file,
		.ca_path      = ca_path,
		.insecure     = (insecure && !strcmp(insecure, "1")),
		.alpn         = "main,ace",
	};

	se->tls = tls_ctx_new(&params);
	if (!se->tls) {
		elog("tls_ctx_new() failed for server");
		return -1;
	}

	se->ssl_ctx = tls_ctx_ssl(se->tls);
	return 0;
}

static int service_init_ssl_ctx_client(struct service *se)
{
	const char *ca_file   = getenv("ACE_CA_FILE");
	const char *ca_path   = getenv("ACE_CA_PATH");
	const char *hostname  = getenv("ACE_HOSTNAME");
	const char *insecure  = getenv("ACE_TLS_INSECURE");

	/* When no explicit hostname and not in insecure mode, try to
	 * derive it from the first co_config's host field. */
	char hostname_buf[256] = { 0 };
	if (!hostname && !(insecure && !strcmp(insecure, "1"))) {
		struct co_config *cc =
			list_first_entry_or_null(&se->config.co_config_head,
						 struct co_config,
						 co_config_node);
		if (cc && cc->host[0]) {
			strncpy(hostname_buf, cc->host, sizeof(hostname_buf) - 1);
			hostname = hostname_buf;
		}
	}

	struct tls_ctx_params params = {
		.mode           = TLS_CTX_MODE_CLIENT,
		.ca_file        = ca_file,
		.ca_path        = ca_path,
		.hostname       = hostname,
		.insecure       = (insecure && !strcmp(insecure, "1")),
		.alpn           = "main,ace",
		.keylog_path    = se->config.keylog_path,
		.session_path   = se->config.session_path,
		.on_new_session = on_new_session,
	};

	se->tls = tls_ctx_new(&params);
	if (!se->tls) {
		elog("tls_ctx_new() failed for client");
		return -1;
	}

	se->ssl_ctx = tls_ctx_ssl(se->tls);
	return 0;
}

void service_destroy_engine(struct service *se)
{
	if (!se || !se->engine)
		return;
	lsquic_engine_destroy(se->engine);
	se->engine = NULL;
}
