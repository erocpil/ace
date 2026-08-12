#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include "service.h"
#include "task.h"
#include "udp_send.h"
#include "io_retry.h"
#include "net_addr.h"
#include "quic_global.h"
#include "tls_context.h"

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

	/* P3: initialise service-level memory budget */
	ace_mem_budget_init(&se->mem_budget, "service",
	                    ACE_MEM_DEFAULT_SERVICE_BUDGET, NULL);

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

	/* stash service reference for callbacks */
	c->owner = se;
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
	if (se->tls) {
		tls_ctx_free(se->tls);
	}

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

static int service_init_ssl_ctx_map(struct service *se)
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

/* TODO check path/file length */
/* TODO append alpn */
/* FIXME se->alpn */
static int session_resume_file_path(char *output, size_t output_size,
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
	int addr = lsquic_conn_get_sockaddr(lconn, &local, &peer);
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

	se->run_result = 1;
	if (!service_init_engine(se)) {
		se->run_result = -1;
		elog("QUIC_EVENT service_start status=failed stage=engine");
		return NULL;
	}

	service_init_cert_hash(se);

	if (-1 == service_init_ssl_ctx_map(se)) {
		se->run_result = -1;
		elog("QUIC_EVENT service_start status=failed stage=tls");
		lsquic_engine_destroy(se->engine);
		return NULL;
	}

	int event_result = se->run_event(se);
	if (event_result != 0 || se->run_result < 0) {
		se->run_result = -1;
	} else {
		se->run_result = 0;
	}
	log("QUIC_EVENT service_stop status=%s",
			se->run_result == 0 ? "ok" : "failed");

	rlog("service %p destroyed", se);
	lsquic_engine_destroy(se->engine);

	/*
	 * P2: engine destroy may fire late conn_closed callbacks.
	 * Aggregate connection outcomes AFTER all callbacks complete.
	 */
	if (se->n_conn_failed > 0)
		se->run_result = -1;
	log("QUIC_EVENT service_final status=%s closed=%d failed=%d",
	    se->run_result == 0 ? "ok" : "failed",
	    se->n_conn_closed, se->n_conn_failed);

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
	if (session_resume_file_path(sess, sizeof(sess), ce->service->config.session_path,
			(const struct sockaddr*)&ce->sas,
			// lconn_ctx->ce->service->alpn,
			ce->cc->if_name) != 0) return NULL;

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
	free(resume_info);
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
	if (session_resume_file_path(sess, sizeof(sess), ce->service->config.session_path,
			(const struct sockaddr*)&ce->sas,
			// lconn_ctx->ce->service->alpn,
			ce->cc->if_name) != 0) return NULL;

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
	free(resume_info);
	if (!lconn) {
		eslog("lsquic_engine_connect()");
		return NULL;
	} else {
		log("%p", lsquic_conn_get_ctx(lconn));
		log("lsquic_engine_connect()");
	}

	se->process(*(struct ev_loop **)se->loop, se);

	return lconn;
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
		msg.msg_namelen = ace_sockaddr_len(out_spec[n].dest_sa);
		if (msg.msg_namelen == 0) {
			errno = EAFNOSUPPORT;
			break;
		}
		msg.msg_iov = out_spec[n].iov;
		msg.msg_iovlen = out_spec[n].iovlen;
		msg.msg_flags = 0;
		// TODO send unsent
		// TODO LSQUIC_PREFERRED_ADDR
		// TODO cmsg, ecn
		// if server
		if (ace_udp_sendmsg(ce->fd, &msg, sendmsg) < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
				eslog("sendmsg(%d %lu)", ce->fd, msg.msg_iovlen);
			}
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

	ace_parse_ancillary(&msg, &local_sas, &ecn);

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
			se->process(*(struct ev_loop **)ce->service->loop, ce->service);
			break;
		case 1:
			blog();
			// FIXME
			se->process(*(struct ev_loop **)ce->service->loop, ce->service);
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
				lsquic_stream_close(stream);
				lsquic_conn_abort(lsquic_stream_conn(stream));
				return 0;
			}
		} else {
			elog("Unknown value returned by subtask");
			lsquic_stream_close(stream);
			lsquic_conn_abort(lsquic_stream_conn(stream));
			return 0;
		}
	} else if (!n) {
		blog("stream %ld read 0 and shutdown 0", lsquic_stream_id(stream));
		lsquic_stream_shutdown(stream, 0);
	} else {
		clog();
		if (ace_io_retryable(errno)) {
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
					lsquic_stream_close(stream);
					lsquic_conn_abort(lsquic_stream_conn(stream));
					return 0;
				}
			} else {
				elog("Unknown value returned by subtask");
				lsquic_stream_close(stream);
				lsquic_conn_abort(lsquic_stream_conn(stream));
				return 0;
			}
		}
#if 0
	} else if (!n) {
		blog();
		lsquic_stream_wantwrite(stream, 0);
#endif
	} else {
		clog();
		if (ace_io_retryable(errno)) {
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
