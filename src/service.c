#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include "service.h"
#include "task.h"

static inline int service_init_ssl_ctx(struct service *se);
static int service_init_ssl_ctx_server(struct service *se);
static int service_init_ssl_ctx_client(struct service *se);

// peer_ctx from lsquic_engine_connect()
// peer_ctx from lsquic_engine_packet_in()
static SSL_CTX *service_get_ssl_ctx(void *peer_ctx, const struct sockaddr *unused)
{
	const struct service *se = ((struct connote*)peer_ctx)->service;
	blog("se %p peer_ctx(ce) %p ssl_ctx %p", se, peer_ctx, se->ssl_ctx);
	return se->ssl_ctx;
}

struct service *service_init(struct config *c)
{
	log();
	struct service *se = (struct service*)malloc(sizeof(struct service));
	if (!se) {
		eslog("malloc(se)");
		return NULL;
	}
	memset(se, 0, sizeof(*se));

	se->engine_settings = (struct lsquic_engine_settings*)
		malloc(sizeof(struct lsquic_engine_settings));
	if (!se->engine_settings) {
		eslog("malloc(engine_settings se %p)", se);
		free(se);
		return NULL;
	}
	se->engine_api = (struct lsquic_engine_api*)
		malloc(sizeof(struct lsquic_engine_api));
	if (!se->engine_api) {
		eslog("malloc(engine_api se %p)", se);
		free(se->engine_settings);
		free(se);
		return NULL;
	}

	/* !!! */
	c->flags |= (long)se;
	memcpy(&se->config, c, sizeof(*c));

	if (0 != service_init_cert_hash(se)) {
		elog();
		free(se);
		return NULL;
	}

	INIT_LIST_HEAD(&se->service_node);
	INIT_LIST_HEAD(&se->connote_head);
	INIT_LIST_HEAD(&se->conn_head);

	return se;
}

void service_free(struct service *se)
{
	if (!se) {
		return;
	}
	if (se->engine_settings) {
		free(se->engine_settings);
	}
	if (se->engine_api) {
		free(se->engine_api);
	}
	if (se->cert_hash) {
		/* TODO free_func() */
		ace_hash_free(se->cert_hash, NULL);
	}
	// TODO free se->ssl_ctx

	free(se);
}

struct ssl_ctx_st *service_lookup_cert(void *cert_lu_ctx,
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
	char *p = se->alpn + strlen(se->alpn);
	char l = strlen(alpn);
	memcpy(p, &l, sizeof(char));
	memcpy(p + 1, alpn, strlen(alpn));

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

	lsquic_global_init(flags & LSENG_SERVER ? LSQUIC_GLOBAL_SERVER : LSQUIC_GLOBAL_CLIENT);

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
	assert(n_bucket);
	assert(n_elem);

	// TODO check n_bucket and n_elem
	se->cert_hash = ace_hash_create(n_bucket, n_elem);

	if (!se->cert_hash) {
		return -1;
	}

	return 0;
}

static int CertVerifyCallback()
{
	elog("TODO");
	return 0;
}

static int service_select_alpn(SSL *ssl, const unsigned char **out,
		unsigned char *outlen, const unsigned char *in,
		unsigned int inlen, void *arg)
{
	elog();
	struct service *se = (struct service*)arg;

	int r = SSL_select_next_proto((unsigned char **)out, outlen, in, inlen,
			(unsigned char*)se->alpn, strlen(se->alpn));
	if (r == OPENSSL_NPN_NEGOTIATED) {
		log("alpn \"%s\" SSL_TLSEXT_ERR_OK", in);
		// TODO setup callbacks of this ALPN
		return SSL_TLSEXT_ERR_OK;
	} else {
		log("no supported protocol can be selected from '%.*s'",
				(int)inlen, (char*)in);
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}
}

static void hexstr(const unsigned char *buf,
		size_t bufsz, char *out, size_t outsz)
{
	static const char b2c[] = "0123456789ABCDEF";
	const unsigned char *const end_input = buf + bufsz;
	char *const end_output = out + outsz;

	while (buf < end_input && out + 2 < end_output)
	{
		*out++ = b2c[ *buf >> 4 ];
		*out++ = b2c[ *buf & 0xF ];
		++buf;
	}

	if (buf < end_input)
		out[-1] = '!';

	*out = '\0';
}

static void service_keylog_line(const SSL *ssl, const char *line)
{
	const char *keylog= getenv("SSLSKEYLOG");
	const lsquic_conn_t *conn = lsquic_ssl_to_conn(ssl);
	struct lsquic_conn_ctx *lconn_ctx = lsquic_conn_get_ctx(conn);
	FILE *file = NULL;

	if (lconn_ctx) {
		file = lconn_ctx->keylog_file;
		/*
		log("se %p ce %p lconn_ctx %p keylog_file %p",
				lconn_ctx->ce->service, lconn_ctx->ce, lconn_ctx,
				lconn_ctx->keylog_file);
				*/
	} else {
		/* when a server log a key during hsk, ctx was not created */
		blog("server in hsk");
	}

	if (!file) {
		int sz;
		char id_str[MAX_CID_LEN * 2 + 1];
		char path[PATH_MAX];

		const lsquic_cid_t *cid = lsquic_conn_id(conn);
		hexstr(cid->idbuf, cid->len, id_str, sizeof(id_str));
		sz = snprintf(path, sizeof(path), "%s/%s.keys", keylog, id_str);
		if ((size_t) sz >= sizeof(path)) {
			elog("%s: key log path too long", __func__);
			return;
		}
		file = fopen(path, "ab");
		if (!file) {
			eslog("could not open %s for writing", path);
			return;
		} else {
			log("open keylog file %p \"%s\"", file, path);
		}
		if (lconn_ctx) {
			rlog("server got lconn_ctx");
			lconn_ctx->keylog_file = file;
		}
	}
	fputs(line, file);
	fputs("\n", file);
	fflush(file);
	if (!lconn_ctx) {
		/* for a server in hsk */
		fclose(file);
	}
}

static int service_init_ssl_ctx_map(struct service *se)
{
	SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
	if (!ssl_ctx) {
		log();
		return -1;
	}

	SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_set_alpn_select_cb(ssl_ctx, service_select_alpn, se);
	SSL_CTX_set_default_verify_paths(ssl_ctx);

	if (0) {
		log("Setting CA");
		if (!SSL_CTX_load_verify_locations(
					ssl_ctx, "root.cert.pem", NULL)) {
			elog("Failed to load root certificates.\n");
			exit(-1);
			return -1;
		}
		log("Setting verify");
		SSL_CTX_set_verify(ssl_ctx,
				SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
				CertVerifyCallback);
	} else {
		log("Setting no verify");
	}
	log("Setting cert %s", "cert.pem");
	if (1 != SSL_CTX_use_certificate_chain_file(
				ssl_ctx, "cert.pem")) {
		eslog("SSL_CTX_use_certificate_chain_file()");
		SSL_CTX_free(ssl_ctx);
		return -1;
	}
	/* TODO .pkcs8 file */
	log("Setting psk %s", "rsa_private.key");
	if (1 != SSL_CTX_use_PrivateKey_file(
				ssl_ctx, "rsa_private.key",
				SSL_FILETYPE_PEM)) {
		elog("SSL_CTX_use_PrivateKey_file()");
		SSL_CTX_free(ssl_ctx);
		return -1;
	}

	/* keylog */
	if (se->config.keylog_path && strlen(se->config.keylog_path) > 0) {
		unsetenv("SSLSKEYLOG");
		setenv("SSLSKEYLOG", se->config.keylog_path, 1);
		SSL_CTX_set_keylog_callback(ssl_ctx, service_keylog_line);
	}

#if 0
	if (!sconf.keylog().empty()) {
		unsetenv("SSLSKEYLOG");
		setenv("SSLSKEYLOG", sconf.keylog().c_str(), 1);
		// log("keylog %s", sconf.keylog().c_str());
		SSL_CTX_set_keylog_callback(ssl_ctx, keylog_line);
	}
#endif

	/* TODO ssl.h SSL_CTX_sess_set_new_cb SSL_SESS_CACHE_SERVER */
	/* session */
	/*
	 // server doesn't need it?
	 if (!sconf.resume().empty()) {
	 log("resume");
	// SSL_CTX_set_session_cache_mode(lsquic.ssl_ctx, SSL_SESS_CACHE_CLIENT);
	const int was = SSL_CTX_set_session_cache_mode(ssl_ctx, 1);
	log("set SSL session cache mode to 1 (was: %d)", was);
	// SSL_CTX_set_early_data_enabled(ssl_ctx, 1);
	// SSL_CTX_sess_set_new_cb(ssl_ctx, prog_new_session_cb);
	}
	*/

	char *key = "sni";
	char *val = (char*)ssl_ctx;
	unsigned int klen = strlen(key) + 1;
	unsigned int vlen = 0;
	log("%s %d %p %d", key, klen, val, vlen);
	ace_hash_add(se->cert_hash, key, klen, val, vlen);

	if (ace_hash_lookup(se->cert_hash, key, klen, &val, &vlen)) {
		log("%s %d %p %d", key, klen, val, vlen);
	} else {
		log("%s %d %p %d", key, klen, val, vlen);
		elog("hash lookup");
	}

#if 0
	{
		char *key = "ace";
		char *val = "sni as value";
		unsigned int klen = strlen(key) + 1;
		unsigned int vlen = strlen(val) + 1;
		log("%s %d %s %d", key, klen, val, vlen);
		ace_hash_add(se->cert_hash, key, klen, val, vlen);
		log("%s %d %s %d", key, klen, val, vlen);

		if (ace_hash_lookup(se->cert_hash, key, klen, &val, &vlen)) {
			log("%s %d %s %d", key, klen, val, vlen);
		} else {
			log("%s %d %s %d", key, klen, val, vlen);
			elog("hash lookup");
		}
	}
#endif

	return 0;
}

static int service_init_ssl_ctx_server(struct service *se)
{
	SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
	if (!ssl_ctx) {
		elog("SSL_CTX_new()");
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
		return -1;
	}
	SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_set_default_verify_paths(ssl_ctx);

	blog("se %p ssl_ctx %p", se, ssl_ctx);
	se->ssl_ctx = ssl_ctx;

	return 0;
}

/* TODO check path/file length */
/* TODO append alpn */
/* FIXME se->alpn */
#define session_resume_file_path(sess, path, peer, dev) \
do { \
	struct sockaddr_in *_peer = (struct sockaddr_in*)(peer); \
	snprintf((sess), sizeof(sess), "%s/%s_%d-%s", \
			(path), inet_ntoa(_peer->sin_addr), ntohs(_peer->sin_port), (dev)); \
} while (0)

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
	int addr = lsquic_conn_get_sockaddr(lconn, &local, &peer);
	if (local && peer) {
		char s[16] = { 0 };
		strncpy(s, inet_ntoa(((struct sockaddr_in*)peer)->sin_addr), 16);
		log("confirmed connection on net_dev " Yellow "%s " RESET
				"local " Cyan "%s:%u " RESET
				"peer " Green "%s:%u" RESET,
				lconn_ctx->ce->cc->if_name,
				inet_ntoa(((struct sockaddr_in*)local)->sin_addr),
				ntohs(((struct sockaddr_in*)local)->sin_port),
				s,
				ntohs(((struct sockaddr_in*)peer)->sin_port));
	} else {
		elog();
		return 0;
	}

	char sess[512] = { 0 };
	session_resume_file_path(sess, lconn_ctx->ce->service->config.session_path,
			(struct sockaddr_in*)peer,
			// lconn_ctx->ce->service->alpn,
			lconn_ctx->ce->cc->if_name);

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

static int service_init_ssl_ctx_client(struct service *se)
{
	log();
	// FIXME
#if 0
	unsigned char ticket_keys[48] = {0};
	{
		srand((unsigned int)(time(NULL)));
		for (int i = 0; i < sizeof(ticket_keys); i++) {
			ticket_keys[i] =  rand() % (unsigned char)(-1);
		}
	}
#endif

	SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
	if (!ssl_ctx) {
		elog("SSL_CTX_new()");
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
		return -1;
	}
	SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_set_default_verify_paths(ssl_ctx);

	if (se->config.keylog_path && strlen(se->config.keylog_path) > 0) {
		unsetenv("SSLSKEYLOG");
		setenv("SSLSKEYLOG", se->config.keylog_path, 1);
		SSL_CTX_set_keylog_callback(ssl_ctx, service_keylog_line);
	}

	if (se->config.session_path && strlen(se->config.session_path) > 0) {
		SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_CLIENT);
		SSL_CTX_set_early_data_enabled(ssl_ctx, 1);
		SSL_CTX_sess_set_new_cb(ssl_ctx, on_new_session);
	}

	blog("se %p ssl_ctx %p", se, ssl_ctx);
	se->ssl_ctx = ssl_ctx;

	return 0;
}

void service_add_connote(struct service *se, struct connote *ce)
{
	struct list_head *head = &se->connote_head;
	struct list_head *node = &ce->connote_node;
	list_add_tail(node, head);
	se->n_connote++;
	ce->service = se;
}

void service_del_connote(struct connote *ce)
{
	struct list_head *node = &ce->connote_node;
	list_del(node);
	ce->service->n_connote--;
	ce->service = NULL;
}

void *service_func(void *arg)
{
	log();
	struct service *se = (struct service*)arg;

	clog("pid %d tid %d thread %lu",
			getpid(), gettid(), pthread_self());
	set_affinity(se->config.cpu);

	service_init_engine(se);

	service_init_cert_hash(se);

	if (-1 == service_init_ssl_ctx_map(se)) {
		exit(-EXIT_FAILURE);
	}

	se->run_event(se);

	rlog("service %p destroyed", se);
	lsquic_engine_destroy(se->engine);
	/* TODO check comments of this function */
	lsquic_global_cleanup();

	return NULL;
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

struct lsquic_conn *service_connect_nop(struct connote *ce)
{
	struct service *se = ce->service;
	log("se %p ce %p", se, ce);

	char sess[512] = { 0 };
	session_resume_file_path(sess, ce->service->config.session_path,
			(struct sockaddr_in*)&ce->sas,
			// lconn_ctx->ce->service->alpn,
			ce->cc->if_name);

	unsigned char *resume_info = NULL;
	ssize_t resume_info_length =
		load_sess_resume_info(sess, &resume_info);
	if (resume_info_length <= 0) {
		resume_info_length = 0;
	}

	lsquic_conn_t *lconn = lsquic_engine_connect(
			se->engine, N_LSQVER,
			(struct sockaddr *)&ce->local_addr,
			(const struct sockaddr*)&ce->sas,
			(void*)(uintptr_t)ce,
			NULL, NULL, 0,
			resume_info_length ? resume_info : NULL, resume_info_length, /* resume */
			NULL, 0);
	if (!lconn) {
		eslog("lsquic_engine_connect()");
		return NULL;
	} else {
		log("%p", lsquic_conn_get_ctx(lconn));
		log("lsquic_engine_connect()");
	}

	// se->process(se);

	return lconn;
}

struct lsquic_conn *service_connect(struct connote *ce)
{
	struct service *se = ce->service;
	log("se %p ce %p", se, ce);

	char sess[512] = { 0 };
	session_resume_file_path(sess, ce->service->config.session_path,
			(struct sockaddr_in*)&ce->sas,
			// lconn_ctx->ce->service->alpn,
			ce->cc->if_name);

	unsigned char *resume_info = NULL;
	ssize_t resume_info_length =
		load_sess_resume_info(sess, &resume_info);
	if (resume_info_length <= 0) {
		resume_info_length = 0;
	}

	lsquic_conn_t *lconn = lsquic_engine_connect(
			se->engine, N_LSQVER,
			(struct sockaddr *)&ce->local_addr,
			(const struct sockaddr*)&ce->sas,
			(void*)(uintptr_t)ce,
			NULL, NULL, 0,
			resume_info_length ? resume_info : NULL, resume_info_length, /* resume */
			NULL, 0);
	if (!lconn) {
		eslog("lsquic_engine_connect()");
		return NULL;
	} else {
		log("%p", lsquic_conn_get_ctx(lconn));
		log("lsquic_engine_connect()");
	}

	se->process(se);

	return lconn;
}

void service_stream_ctx_free(struct lsquic_stream_ctx *sc)
{
	if (!sc) {
		return;
	}

	size_t id = lsquic_stream_id(sc->stream);
	struct sk_buff *skb = NULL;
	struct sk_buff *n = NULL;
	list_for_each_entry_safe(skb, n, &sc->rxq, skb_node) {
		lstream_ctx_del_rxq(sc, skb);
		skb_free(skb);
	}
	sc->rx = NULL;
	skb = NULL;
	n = NULL;
	list_for_each_entry_safe(skb, n, &sc->txq, skb_node) {
		lstream_ctx_del_txq(sc, skb);
		skb_free(skb);
	}
	sc->tx = NULL;

	assert(!sc->n_rxq);
	assert(!sc->n_txq);

	free(sc);
}

struct lsquic_stream_ctx *service_stream_ctx_malloc(struct co_config *cc,
		ssize_t rx_len, ssize_t tx_len)
{
	struct lsquic_stream_ctx *sc = lstream_ctx_malloc();

	INIT_LIST_HEAD(&sc->stream_node);
	INIT_LIST_HEAD(&sc->rxq);
	INIT_LIST_HEAD(&sc->txq);
	sc->rx = skb_malloc(rx_len);
	lstream_ctx_add_rxq(sc, sc->rx);
	sc->tx = skb_malloc(tx_len);
	lstream_ctx_add_txq(sc, sc->tx);
	sc->rx_func = cc->rx_func;
	sc->tx_func = cc->tx_func;
	/* FIXME */
	sc->new_action = cc->action & ACTION_MASK;
	sc->end_action = cc->action >> ACTION_SHIFT;

	return sc;
}

struct lsquic_stream_ctx *service_stream_ctx_malloc_pending(struct lsquic_conn *lconn,
		ssize_t rx_len, ssize_t tx_len)
{
	return (lsquic_conn_get_ctx(lconn)->pending =
			service_stream_ctx_malloc(
				lsquic_conn_get_ctx(lconn)->ce->cc, rx_len, tx_len));
}

ssize_t service_rx_func(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc)
{
	ssize_t n = 0;
	struct sk_buff *rx = sc->rx;

	/* use len to indicate how long has been received */
	size_t length = rx->end - rx->len;
	if (!length) {
		SKB_DUMP(rx);
		rlog("stream %p sc %p !length", stream, sc);
		lsquic_stream_wantread(stream, 0);
		return -1;
	}

	if (length > DEFAULT_RX_BUFF_ONCE) {
		length = DEFAULT_RX_BUFF_ONCE;
	}

	n = lsquic_stream_read(stream,
			rx->head + rx->len,
			length);
	if (n > 0) {
		/* forward len */
		void *tail = skb_put(rx, n);
		if (!tail) {
			SKB_DUMP(rx);
			rlog("TODO receive buffer full");
		}
		sc->rx_bytes += n;
		if (rx->len == rx->end) {
			// clog("TODO maybe del this skb from list?");
			lsquic_stream_wantread(stream, 0);
		}
	} else if (0 == n) {
		// FIXME shutdown 0 or 2?
		// ylog("read 0 and shutdonw");
		ylog("read 0");
		// lsquic_stream_shutdown(stream, 0);
	} else {
		// -1 == n
		// lsquic.h:
		// ssize_t lsquic_stream_read (lsquic_stream_t *s, void *buf, size_t len);
		if (EWOULDBLOCK == errno) {
			;
		} else if (lsquic_stream_is_rejected(stream)) {
			ylog("lsquic_stream_is_rejected(%p)", stream);
			lsquic_stream_close(stream);
		} else {
			if (EBADF == errno) {
				elog("EBADF");
			} else if (ECONNRESET == errno) {
				elog("ECONNRESET");
			} else {
				elog("unknown errno %d", errno);
			}
			eslog("lsquic_stream_read(%p %p %ld)",
					stream, rx->head + rx->len, length);
			lsquic_stream_close(stream);
		}
	}

	return n;
}

/** service_tx_func - get each skb from txq and send
 *
 * sc->tx indicates the current skb, it is NULL when the q is empty
 */
ssize_t service_tx_func(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc)
{
	if (!sc->n_txq) {
		elog("sc %p has nothing to send, close write", sc);
		lsquic_stream_wantwrite(stream, 0);
		return 0;
	}

	sc->tx = list_first_entry(&sc->txq, struct sk_buff, skb_node);
	struct sk_buff *tx = sc->tx;

	/* fyr：echo_client_on_write() */
	/* Here we make an assumption that we can write the whole buffer.
	 * Don't do it in a real program.
	 */
	size_t length = tx->len - tx->offset;
	if (!length) {
		rlog();
		return 0;
	}

	if (length > DEFAULT_TX_BUFF_ONCE) {
		length = DEFAULT_TX_BUFF_ONCE;
	}

	/* write from data, this means data == head at the very beginning */
	assert(tx->data == tx->head);
	ssize_t n = lsquic_stream_write(stream,
			tx->data + tx->offset,
			length);
	if (n >= 0) {
		lsquic_stream_flush(stream);
		tx->offset += n;
		sc->tx_bytes += n;
		assert(tx->offset <= tx->len);
		if (tx->offset == tx->len) {
		}
	} else {
		/*
		   eslog("lsquic_stream_write(%p %p %ld), abort conn %p",
		   stream, tx->data + tx->offset, length,
		   lsquic_stream_conn(stream));
		   */
		lsquic_stream_wantwrite(stream, 0);
		lsquic_conn_abort(lsquic_stream_conn(stream));
	}

	return n;
}

int service_packets_out(void *packets_out_ctx,
		const struct lsquic_out_spec *out_spec,
		unsigned int n_packets_out)
{
	unsigned int n_orig = n_packets_out;
	struct service *se = (struct service*)packets_out_ctx;
	size_t out_limit = se->config.out_limit;
	struct msghdr msg = {
		.msg_flags = 0,
		.msg_control = NULL,
		.msg_controllen = 0,
	};

	size_t n = 0;

	// TODO cmsg(3)

	if (!n_packets_out) {
		return 0;
	}

#if 0
	if (out_limit > n_packets_out) {
		out_limit = n_packets_out;
	}
#else
	out_limit = n_packets_out;
#endif

	do {
		struct connote *ce = (struct connote*)out_spec[n].peer_ctx;
		msg.msg_name = (void*)out_spec[n].dest_sa;
		msg.msg_namelen = (AF_INET == out_spec[n].dest_sa->sa_family ?
				sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
		msg.msg_iov = out_spec[n].iov;
		msg.msg_iovlen = out_spec[n].iovlen;
		msg.msg_flags = 0;
		// TODO send unsent
		// TODO LSQUIC_PREFERRED_ADDR
		// TODO cmsg, ecn
		// if server
		if (sendmsg(ce->fd, &msg, MSG_ZEROCOPY) < 0) {
			eslog("sendmsg(%d %lu)", ce->fd, msg.msg_iovlen);
			ylog("TODO send unsent");
			break;
		} else {
			// log("sendmsg(%d #%lu)", ce->fd, n);
		}
	} while (++n < out_limit);

	if (n > 0) {
		return n;
	}

	return -1;
}

void service_packets_in(struct connote *ce)
{
	int ecn = 0;
	ssize_t nread = 0;
	struct sockaddr_storage peer_sas;
	struct sockaddr_storage local_sas;
	// TODO buffer size
	unsigned char buf[0x1000] = { 0 };
	// struct connote *ce = (struct connote*)w->data;
	struct service *se = ce->service;

	struct iovec vec[1] = {{ buf, sizeof(buf) }};
	unsigned char ctl_buf[CTL_SZ];
	struct msghdr msg = {
		.msg_name       = &peer_sas,
		.msg_namelen    = sizeof(peer_sas),
		.msg_iov        = vec,
		.msg_iovlen     = 1,
		.msg_control    = ctl_buf,
		.msg_controllen = sizeof(ctl_buf),
		.msg_flags = 0,
	};
	nread = recvmsg(ce->fd, &msg, 0);
	// ylog("nread %ld", nread);
	if (-1 == nread) {
		if (!(EAGAIN == errno || EWOULDBLOCK == errno)) {
			hpeslog("recvmsg(%d)", ce->fd);
		}
		return;
	}
	// FIXME
	memcpy(&local_sas, &ce->local_addr, sizeof(local_sas));
	ecn = 0;

	// TODO
	// proc_ancillary(&msg, &local_sas, &ecn);

	int n = lsquic_engine_packet_in(
			ce->service->engine, buf, nread,
			(struct sockaddr*)&local_sas,
			(struct sockaddr*)&peer_sas,
			(void *)ce, ecn);
#if 0
	log("local_sas %s:%u", inet_ntoa(((struct sockaddr_in*)&local_sas)->sin_addr), ntohs(((struct sockaddr_in*)&local_sas)->sin_port));
	log("peer_sas %s:%u", inet_ntoa(((struct sockaddr_in*)&peer_sas)->sin_addr), ntohs(((struct sockaddr_in*)&peer_sas)->sin_port));
#endif
	switch (n) {
		case 0:
			se->process(ce->service);
			break;
		case 1:
			blog();
			// FIXME
			se->process(ce->service);
			break;
		case -1:
			elog("lsquic_engine_packet_in()");
			break;
		default:
			break;
	}
}

ssize_t service_on_read(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc)
{
	ssize_t n = service_rx_func(stream, sc);

	if (n > 0) {
		struct subtask *subtask = (struct subtask*)sc->subtask;
		ssize_t sr = subtask->rx_func(sc);
		// log("sr %ld", sr);
		if (likely(TASK_GOON == sr)) {
			;
		} else if (TASK_DONE == sr) {
			int r = subtask->done(sc);
			// log("r %d", r);
			if (TASK_DONE == r) {
				lsquic_stream_wantread(stream, 0);
				lsquic_stream_shutdown(stream, 0);
				ylog("stream %lu read done and shutdown read",
						lsquic_stream_id(sc->stream));
			} else if (TASK_EXIT == r) {
				lsquic_stream_close(stream);
				lsquic_conn_close(lsquic_stream_conn(stream));
				ylog("stream %lu read done and shutdown conn",
						lsquic_stream_id(sc->stream));
			} else if (TASK_FAIL == r) {
				ylog("abort conn %p due to task exit error",
						lsquic_stream_conn(stream));
				lsquic_stream_close(sc->stream);
				lsquic_conn_abort(lsquic_stream_conn(stream));
			} else {
				elog("Unknown value returned by subtask");
				exit(-EXIT_FAILURE);
			}
		} else {
			elog("Unknown value returned by subtask");
			exit(-EXIT_FAILURE);
		}
	} else if (!n) {
		blog("stream %ld read 0 and shutdown 0", lsquic_stream_id(stream));
		lsquic_stream_shutdown(stream, 0);
	} else {
		clog();
		if (EWOULDBLOCK == errno) {
		} else {
		}
	}

	return 0;
}

ssize_t service_on_write(struct lsquic_stream *stream, lsquic_stream_ctx_t *sc)
{
	size_t id = lsquic_stream_id(sc->stream);
	// ylog("stream %p %lu writing subtask %p", stream, lsquic_stream_id(stream), sc->subtask);

	if (!id) {
		// SKB_DUMP(sc->tx);
	}
	ssize_t n = service_tx_func(stream, sc);
	if (n >= 0) {
		if (sc->tx->offset == sc->tx->len) {
			/* notify task that a skb is completely sent */
			struct subtask *subtask = (struct subtask*)sc->subtask;
			if (!subtask) {
				ylog("no subtask stream %p", stream);
				lsquic_stream_wantwrite(stream, 0);
				return 0;
			}
			if (!id) {
				// SKB_DUMP(sc->tx);
			}
			ssize_t sr = subtask->tx_func(sc);
			// SKB_DUMP(sc->tx);
			// rlog("id %lu sr %ld", id, sr);
			if (likely(TASK_GOON == sr)) {
				lsquic_stream_flush(sc->stream);
			} else if (TASK_DONE == sr) {
				int r = subtask->done(sc);
				if (TASK_DONE == r) {
					/* peer may not be unable to process streams if conn
					 * were shutdown here */
					lsquic_stream_wantwrite(stream, 0);
					lsquic_stream_shutdown(stream, 1);
					ylog("stream %lu write done and shutdown write", id);
				} else if (TASK_EXIT == r) {
					lsquic_stream_close(sc->stream);
					lsquic_conn_close(lsquic_stream_conn(stream));
					ylog("stream %lu write done and shutdown conn",
							lsquic_stream_id(sc->stream));
				} else if (TASK_FAIL == r) {
					ylog("abort conn %p due to task exit error",
							lsquic_stream_conn(stream));
					lsquic_stream_close(sc->stream);
					lsquic_conn_abort(lsquic_stream_conn(stream));
				} else {
					elog("Unknown value returned by subtask");
					exit(-EXIT_FAILURE);
				}
			} else {
				elog("Unknown value returned by subtask");
				exit(-EXIT_FAILURE);
			}
		}
#if 0
	} else if (!n) {
		blog();
		lsquic_stream_wantwrite(stream, 0);
#endif
	} else {
		clog();
		if (EWOULDBLOCK == errno) {
		} else {
			eslog("lsquic_stream_write(%p %p), abort conn %p",
					stream, sc->tx->data + sc->tx->offset,
					lsquic_stream_conn(stream));
			lsquic_conn_abort(lsquic_stream_conn(stream));
		}
	}

	/* TODO if txq is empty */

	return 0;
}
