#include "config.h"
#include "service.h"

/* TODO command line params */

/**
 * config_init - allocate a config and given number of co_config
 * @_cm: config_manager that will hold config and co_config
 * @flags: indicate server or client
 * @n: number of co_config
 *
 * all elements are initialized with default values.
 *
 * Returns a config manager, %NULL is returned if there is no memory.
 */
struct config_manager *config_init(
		struct config_manager *_cm,
		int flags, unsigned int n)
{
	struct config_manager *cm = NULL;

	if (flags != 0 && flags != 1) {
		elog("wrong flags %d", flags);
		return NULL;
	}
	if (!n || n > MAX_CO_CONFIG) {
		elog("wrong number of co_config %d", n);
		return NULL;
	}

	if (!_cm) {
		cm = (struct config_manager*)
			malloc(sizeof(struct config_manager));
		if (!cm) {
			return NULL;
		}
		memset(cm, 0, sizeof(*cm));
		INIT_LIST_HEAD(&cm->config_head);
	} else {
		cm = _cm;
	}

	struct config *c = (struct config*)malloc(sizeof(struct config));
	if (!c) {
		free(cm);
		return NULL;
	}
	memset(c, 0, sizeof(*c));
	INIT_LIST_HEAD(&c->config_node);
	INIT_LIST_HEAD(&c->co_config_head);
	list_add_tail(&c->config_node, &cm->config_head);
	cm->n_config++;
	c->flags = flags;
	c->n_cert_hash_bucket = 16;
	c->n_cert_hash_elem = 128;
	c->out_limit = 16;
	c->log_level = "warn";
	c->packets_out = service_packets_out;
	if (flags) {
		c->keylog_path = "../skeylog/";
		c->session_path = NULL;
	} else {
		c->keylog_path = "../ckeylog/";
		c->session_path = "../session/";
	}

	for (unsigned int i = 0; i < n; i++) {
		struct co_config *co = (struct co_config*)malloc(sizeof(struct co_config));
		if (!co) {
			free(c);
			free(cm);
			return NULL;
		}
		memset(co, 0, sizeof(*co));
		INIT_LIST_HEAD(&co->co_config_node);
		list_add_tail(&co->co_config_node, &c->co_config_head);

		co->flags = flags;
		co->rx_func = service_on_read;
		co->tx_func = service_on_write;
		co->rx_buff_size = DEFAULT_SKB_SIZE;
		co->tx_buff_size = DEFAULT_SKB_SIZE;
		/* server's default action is read */
		co->action |= (flags ? ACTION_WANT_READ : ACTION_WANT_WRITE);

		co->port = 12345 + i;
		if (flags) {
			strncpy(co->host, "0.0.0.0", sizeof(co->host) - 1);
			co->if_name[0] = '\0';
		} else {
			strncpy(co->host, "127.0.0.1", sizeof(co->host) - 1);
			// sprintf(co->if_name, "%s", "lo");
			// strncpy(co->host, "2.2.2.2", sizeof(co->host) - 1);
			// sprintf(co->if_name, "%s", "ens2f1");
		}
	}
	c->n_co_config += n;

	return cm;
}

inline struct config *config_get_first(struct config_manager *cm)
{
	return list_first_entry(&cm->config_head, struct config, config_node);
}

inline struct config *config_get_last(struct config_manager *cm)
{
	return list_last_entry(&cm->config_head, struct config, config_node);
}

inline struct config *config_get_prev(struct config *c)
{
	return list_prev_entry(c, config_node);
}

inline struct config *config_get_next(struct config *c)
{
	return list_next_entry(c, config_node);
}

inline struct co_config *config_get_first_co(struct config *c)
{
	return list_first_entry(&c->co_config_head, struct co_config, co_config_node);
}

inline struct co_config *config_get_last_co(struct config *c)
{
	return list_last_entry(&c->co_config_head, struct co_config, co_config_node);
}

inline struct co_config *config_get_prev_co(struct co_config *co)
{
	return list_prev_entry(co, co_config_node);
}

inline struct co_config *config_get_next_co(struct co_config *co)
{
	return list_next_entry(co, co_config_node);
}

int config_check_directory(char *path)
{
	struct stat st = {0};

	if (stat(path, &st) == -1) {
		if (mkdir(path, 0700) == -1) {
			eslog("mkdir(%s)", path);
			return -1;
		} else {
			blog("keylog directory '%s' created", path);
		}
	} else {
		blog("keylog directory '%s' already exists", path);
	}

	return 0;
}

int config_check(struct config *ch)
{
	unsigned long flags = ch->flags & FLAGS_MASK;

	/* 4096 - 255 - 1('/') */
	if (ch->keylog_path && strlen(ch->keylog_path) > (PATH_MAX - NAME_MAX - 1)) {
		elog("key log path too long");
		return -1;
	}

	if (-1 == config_check_directory(ch->keylog_path)) {
		return -1;
	}

	if (flags & LSENG_SERVER) {
		/* TODO check server config */
	} else {
		/* TODO check client config */
	}

	return 0;
}

inline int set_affinity(int c)
{
	int r = 0;
	int s = 0;
	cpu_set_t mask;
	cpu_set_t cpuset;
	pthread_t thread = pthread_self();

	CPU_ZERO(&mask);
	CPU_SET(c, &mask);

	r = pthread_setaffinity_np(thread, sizeof(mask), &mask);
	if (r != 0) {
		eslog();
	} else {
		clog("thread %lu, cpu %d", pthread_self(), c);
	}

	s = pthread_getaffinity_np(thread, sizeof(cpuset), &cpuset);
	if (s != 0) {
		eslog("pthread_getaffinity_np()");
	} else {
		log("Set returned by pthread_getaffinity_np() contained:");
		for (size_t j = 0; j < CPU_SETSIZE; j++) {
			if (CPU_ISSET(j, &cpuset)) {
				log("    CPU %zu", j);
			}
		}
	}

	return r;
}
