#ifndef __CONFIG_H__
#define __CONFIG_H__

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/limits.h>
#include <net/if.h>
#include <pthread.h>
#include "lsquic.h"
#include "define.h"
#include "list.h"
#include "git_version.h"

#define MAX_CO_CONFIG 128

#define FLAGS_MASK (0x03)
#define TASK_MULTITHREADING 0
#define TASK_MULTIPROCESSING 1

#define ACTION_MASK (0xffff)
#define ACTION_SHIFT (sizeof(short int) << 3)
/* used by co_config.action & 0xffff */
#define ACTION_WANT_NONE (0)
#define ACTION_WANT_READ (1 << 0)
#define ACTION_WANT_WRITE (1 << 1)
#define ACTION_WANT_READWRITE (ACTION_WANT_READ | ACTION_WANT_WRITE)
/* used by co_config.action >> (sizeof(short) << 3) */
#define ACTION_CLOSE (1 << 0)
#define ACTION_NOTIFY (1 << 1)
#define ACTION_ONE_MORE (1 << 2)
#define ACTION_GO_ON (1 << 3)

#define DEFAULT_RX_BUFF_ONCE (0x400)
#define DEFAULT_TX_BUFF_ONCE (0x400)

/* one instance of connote */
struct co_config {
	struct list_head co_config_node;

	ssize_t (*rx_func)(lsquic_stream_t*, lsquic_stream_ctx_t*);
	ssize_t (*tx_func)(lsquic_stream_t*, lsquic_stream_ctx_t*);
	size_t rx_buff_size;
	size_t tx_buff_size;
	unsigned int action;
	union {
		unsigned short int auto_stream;
		unsigned short int auto_stream0;
		unsigned short int auto_stream1;
	};

	/* the least significant 2 bits are flags,
	 * others are a pointer to a connote
	 */
	unsigned long flags;
	int ipver;
	unsigned short port;
	char host[256];
	char if_name[IFNAMSIZ];
	int bindtodevice;
} __attribute__((aligned(sizeof(long))));

/* one instance of service(lsquic_engine) */
struct config {
	struct list_head config_node;
	struct list_head co_config_head;
	size_t n_co_config;
	/* the least significant 2 bits are flags,
	 * others are a pointer to a server or client
	 */
	unsigned long flags;
	/* TODO size and mask */

	/* cert hash */
	size_t n_cert_hash_bucket;
	size_t n_cert_hash_elem;

	/* lsquic */
	struct lsquic_stream_if *stream_if;
	lsquic_packets_out_f packets_out;
	char *log_level;
	size_t out_limit;
	size_t in_limit;
	char *keylog_path;
	char *session_path;

	/* endpoint */
	size_t cpu;

	/* upstream */
	uint32_t retry;
	/* us */
	uint32_t retry_timeout;
	char *file;
} __attribute__((aligned(sizeof(long))));

struct config_manager {
	struct list_head config_head;
	size_t n_config;
};

#define PRINT_VERSION(msg) \
	do { \
		printf(Blue "Quic:" Cyan "%s " \
				Blue "Commit:" Yellow "%s%s " \
				Blue "Branch:" Green "%s" RESET "\n\n", \
				(msg), git_hash, git_status, git_branch); \
	} while (0)

struct config_manager *config_init(
		struct config_manager *_cm, int flags, unsigned int n);
struct config *config_get_first(struct config_manager *cm);
struct config *config_get_last(struct config_manager *cm);
struct config *config_get_prev(struct config *c);
struct config *config_get_next(struct config *c);
struct co_config *config_get_first_co(struct config *c);
struct co_config *config_get_last_co(struct config *c);
struct co_config *config_get_prev_co(struct co_config *co);
struct co_config *config_get_next_co(struct co_config *co);
int config_check_directory(char *path);
int config_check(struct config *ch);
int set_affinity(int c);

#endif
