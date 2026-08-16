#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config_file.h"

static void test_apply_endpoint(void)
{
	struct config c;
	struct co_config co;

	memset(&c, 0, sizeof(c));
	memset(&co, 0, sizeof(co));

	assert(config_file_apply(&c, &co, "host", "10.0.0.1") == 0);
	assert(strcmp(co.host, "10.0.0.1") == 0);

	assert(config_file_apply(&c, &co, "port", "9999") == 0);
	assert(co.port == 9999);
	assert(config_file_apply(&c, &co, "port", "0") == 0);
	assert(co.port == 0);
	assert(config_file_apply(&c, &co, "port", "65535") == 0);
	assert(co.port == 65535);
	/* out of range / malformed */
	assert(config_file_apply(&c, &co, "port", "65536") == -2);
	assert(config_file_apply(&c, &co, "port", "abc") == -2);
	assert(config_file_apply(&c, &co, "port", "-1") == -2);
	assert(config_file_apply(&c, &co, "port", "") == -2);

	assert(config_file_apply(&c, &co, "if_name", "lo") == 0);
	assert(strcmp(co.if_name, "lo") == 0);

	assert(config_file_apply(&c, &co, "bindtodevice", "true") == 0);
	assert(co.bindtodevice == 1);
	assert(config_file_apply(&c, &co, "bindtodevice", "off") == 0);
	assert(co.bindtodevice == 0);
	assert(config_file_apply(&c, &co, "bindtodevice", "maybe") == -2);
}

static void test_apply_service(void)
{
	struct config c;
	struct co_config co;

	memset(&c, 0, sizeof(c));
	memset(&co, 0, sizeof(co));

	assert(config_file_apply(&c, &co, "cpu", "3") == 0);
	assert(c.cpu == 3);

	assert(config_file_apply(&c, &co, "retry", "5") == 0);
	assert(c.retry == 5);
	assert(config_file_apply(&c, &co, "retry", "4294967295") == 0);
	assert(c.retry == 4294967295u);
	assert(config_file_apply(&c, &co, "retry", "4294967296") == -2);
	assert(config_file_apply(&c, &co, "retry", "12x") == -2);

	assert(config_file_apply(&c, &co, "retry_timeout", "1500") == 0);
	assert(c.retry_timeout == 1500);

	assert(config_file_apply(&c, &co, "file", "/tmp/ace.sock") == 0);
	assert(c.file != NULL && strcmp(c.file, "/tmp/ace.sock") == 0);
	free(c.file);

	assert(config_file_apply(&c, &co, "log_level", "debug") == 0);
	assert(c.log_level != NULL && strcmp(c.log_level, "debug") == 0);
	free(c.log_level);

	assert(config_file_apply(&c, &co, "session_path", "sess") == 0);
	assert(c.session_path != NULL && strcmp(c.session_path, "sess") == 0);
	free(c.session_path);

	assert(config_file_apply(&c, &co, "keylog_path", "/tmp/klog") == 0);
	assert(c.keylog_path != NULL && strcmp(c.keylog_path, "/tmp/klog") == 0);
	free(c.keylog_path);

	assert(config_file_apply(&c, &co, "auto_connect", "0") == 0);
	assert(c.auto_connect == 0);
	assert(config_file_apply(&c, &co, "auto_connect", "true") == 0);
	assert(c.auto_connect == 1);
	assert(config_file_apply(&c, &co, "auto_connect", "x") == -2);
}

static void test_apply_errors(void)
{
	struct config c;
	struct co_config co;
	char toolong[512];

	memset(&c, 0, sizeof(c));
	memset(&co, 0, sizeof(co));

	assert(config_file_apply(&c, &co, "nonsense", "1") == -1);

	/* empty value for a string key is malformed */
	assert(config_file_apply(&c, &co, "host", "") == -2);

	/* oversized host (co->host is 256 bytes) */
	memset(toolong, 'a', sizeof(toolong) - 1);
	toolong[sizeof(toolong) - 1] = '\0';
	assert(config_file_apply(&c, &co, "host", toolong) == -2);

	/* NULL guards */
	assert(config_file_apply(NULL, &co, "cpu", "1") == -2);
	assert(config_file_apply(&c, NULL, "cpu", "1") == -2);
	assert(config_file_apply(&c, &co, NULL, "1") == -2);
}

/* Build a one-config, one-co_config manager for config_file_load. */
static struct config_manager *make_cm(void)
{
	struct config_manager *cm = calloc(1, sizeof(*cm));
	struct config *c;
	struct co_config *co;

	assert(cm);
	INIT_LIST_HEAD(&cm->config_head);

	c = calloc(1, sizeof(*c));
	assert(c);
	INIT_LIST_HEAD(&c->config_node);
	INIT_LIST_HEAD(&c->co_config_head);
	list_add_tail(&c->config_node, &cm->config_head);

	co = calloc(1, sizeof(*co));
	assert(co);
	INIT_LIST_HEAD(&co->co_config_node);
	list_add_tail(&co->co_config_node, &c->co_config_head);

	return cm;
}

static void free_cm(struct config_manager *cm)
{
	struct config *c = list_first_entry(&cm->config_head, struct config, config_node);
	struct co_config *co = list_first_entry(&c->co_config_head, struct co_config, co_config_node);

	free(c->file);
	free(c->log_level);
	free(c->session_path);
	free(c->keylog_path);
	free(co);
	free(c);
	free(cm);
}

static void write_file(const char *path, const char *content)
{
	FILE *fp = fopen(path, "w");
	assert(fp);
	fputs(content, fp);
	fclose(fp);
}

static void test_load_file(void)
{
	struct config_manager *cm;
	struct config *c;
	struct co_config *co;
	const char *path = "/tmp/ace_cfg_test.conf";

	write_file(path,
		   "# a comment\n"
		   "\n"
		   "host = 192.168.1.50\n"
		   "port = 9999\n"
		   "cpu = 2\n"
		   "retry = 7\n"
		   "retry_timeout = 2500\n"
		   "auto_connect = false\n"
		   "if_name = lo\n"
		   "bindtodevice = true\n"
		   "log_level = debug\n");

	cm = make_cm();
	assert(config_file_load(cm, path) == 0);
	c = list_last_entry(&cm->config_head, struct config, config_node);
	co = list_first_entry(&c->co_config_head, struct co_config, co_config_node);

	assert(strcmp(co->host, "192.168.1.50") == 0);
	assert(co->port == 9999);
	assert(c->cpu == 2);
	assert(c->retry == 7);
	assert(c->retry_timeout == 2500);
	assert(c->auto_connect == 0);
	assert(strcmp(co->if_name, "lo") == 0);
	assert(co->bindtodevice == 1);
	assert(c->log_level != NULL && strcmp(c->log_level, "debug") == 0);

	free_cm(cm);
	remove(path);
}

static void test_load_file_errors(void)
{
	struct config_manager *cm;
	const char *path = "/tmp/ace_cfg_test_bad.conf";

	/* unknown key */
	write_file(path, "bogus = 1\n");
	cm = make_cm();
	assert(config_file_load(cm, path) == -1);
	free_cm(cm);
	remove(path);

	/* missing '=' */
	write_file(path, "host 10.0.0.1\n");
	cm = make_cm();
	assert(config_file_load(cm, path) == -1);
	free_cm(cm);
	remove(path);

	/* bad value */
	write_file(path, "port = 70000\n");
	cm = make_cm();
	assert(config_file_load(cm, path) == -1);
	free_cm(cm);
	remove(path);

	/* nonexistent file */
	cm = make_cm();
	assert(config_file_load(cm, "/tmp/ace_cfg_test_absent.conf") == -1);
	free_cm(cm);
}

int main(void)
{
	test_apply_endpoint();
	test_apply_service();
	test_apply_errors();
	test_load_file();
	test_load_file_errors();
	return 0;
}
