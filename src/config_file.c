#include "config_file.h"
#include "define.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Maximum length of one config-file line (excluding the terminator). */
#define CONFIG_FILE_MAX_LINE 4096U

/* --- small parsers (no strtoul: explicit bounds, no locale surprises) --- */

static int config_file_parse_u16(const char *s, unsigned short *out)
{
	unsigned long v = 0;

	if (!s || !*s)
		return -1;
	for (const char *p = s; *p; ++p) {
		if (*p < '0' || *p > '9')
			return -1;
		v = v * 10 + (unsigned long)(*p - '0');
		if (v > 65535UL)
			return -1;
	}
	*out = (unsigned short)v;
	return 0;
}

static int config_file_parse_u32(const char *s, uint32_t *out)
{
	unsigned long v = 0;

	if (!s || !*s)
		return -1;
	for (const char *p = s; *p; ++p) {
		if (*p < '0' || *p > '9')
			return -1;
		unsigned long next = v * 10 + (unsigned long)(*p - '0');
		if (next > 0xFFFFFFFFUL || next < v)
			return -1;
		v = next;
	}
	*out = (uint32_t)v;
	return 0;
}

static int config_file_parse_size(const char *s, size_t *out)
{
	unsigned long long v = 0;

	if (!s || !*s)
		return -1;
	for (const char *p = s; *p; ++p) {
		if (*p < '0' || *p > '9')
			return -1;
		unsigned long long next = v * 10 + (unsigned long long)(*p - '0');
		if (next < v || next > (unsigned long long)SIZE_MAX)
			return -1;
		v = next;
	}
	*out = (size_t)v;
	return 0;
}

/* Accept 0/1/true/false (case-insensitive). */
static int config_file_parse_bool(const char *s, int *out)
{
	if (!s)
		return -1;
	if (!strcasecmp(s, "1") || !strcasecmp(s, "true") ||
	    !strcasecmp(s, "yes") || !strcasecmp(s, "on")) {
		*out = 1;
		return 0;
	}
	if (!strcasecmp(s, "0") || !strcasecmp(s, "false") ||
	    !strcasecmp(s, "no") || !strcasecmp(s, "off")) {
		*out = 0;
		return 0;
	}
	return -1;
}

/* Duplicate @s into @dst.  The OLD value is intentionally NOT freed: it may
 * be a string literal ("session", "warn") or an env-var pointer, neither of
 * which is heap-owned.  config is a process-lifetime singleton loaded once at
 * startup, so overwriting a field more than once is the only leak source and
 * is negligible. */
static int config_file_set_str(char **dst, const char *s)
{
	char *copy;

	if (!s || !*s)
		return -1;
	copy = strdup(s);
	if (!copy)
		return -1;
	*dst = copy;
	return 0;
}

/* --- key application --- */

int config_file_apply(struct config *c, struct co_config *co,
                      const char *key, const char *value)
{
	if (!c || !co || !key || !value)
		return -2;

	/* endpoint (co_config) keys */
	if (!strcmp(key, "host")) {
		if (!*value || strlen(value) >= sizeof(co->host))
			return -2;
		strncpy(co->host, value, sizeof(co->host) - 1);
		co->host[sizeof(co->host) - 1] = '\0';
		return 0;
	}
	if (!strcmp(key, "port")) {
		if (config_file_parse_u16(value, &co->port) != 0)
			return -2;
		return 0;
	}
	if (!strcmp(key, "if_name")) {
		if (strlen(value) >= sizeof(co->if_name))
			return -2;
		strncpy(co->if_name, value, sizeof(co->if_name) - 1);
		co->if_name[sizeof(co->if_name) - 1] = '\0';
		return 0;
	}
	if (!strcmp(key, "bindtodevice")) {
		int b;
		if (config_file_parse_bool(value, &b) != 0)
			return -2;
		co->bindtodevice = b;
		return 0;
	}

	/* service (config) keys */
	if (!strcmp(key, "cpu")) {
		if (config_file_parse_size(value, &c->cpu) != 0)
			return -2;
		return 0;
	}
	if (!strcmp(key, "retry")) {
		if (config_file_parse_u32(value, &c->retry) != 0)
			return -2;
		return 0;
	}
	if (!strcmp(key, "retry_timeout")) {
		if (config_file_parse_u32(value, &c->retry_timeout) != 0)
			return -2;
		return 0;
	}
	if (!strcmp(key, "file")) {
		if (config_file_set_str(&c->file, value) != 0)
			return -2;
		return 0;
	}
	if (!strcmp(key, "log_level")) {
		if (config_file_set_str(&c->log_level, value) != 0)
			return -2;
		return 0;
	}
	if (!strcmp(key, "session_path")) {
		if (config_file_set_str(&c->session_path, value) != 0)
			return -2;
		return 0;
	}
	if (!strcmp(key, "keylog_path")) {
		if (config_file_set_str(&c->keylog_path, value) != 0)
			return -2;
		return 0;
	}
	if (!strcmp(key, "auto_connect")) {
		int b;
		if (config_file_parse_bool(value, &b) != 0)
			return -2;
		c->auto_connect = b;
		return 0;
	}

	return -1; /* unknown key */
}

/* --- file loading --- */

/* Trim leading/trailing ASCII whitespace in-place; returns the start of
 * the trimmed span. */
static char *config_file_trim(char *s)
{
	char *end;

	while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
		s++;
	end = s + strlen(s);
	while (end > s && (end[-1] == ' ' || end[-1] == '\t' ||
			   end[-1] == '\r' || end[-1] == '\n'))
		--end;
	*end = '\0';
	return s;
}

int config_file_load(struct config_manager *cm, const char *path)
{
	FILE *fp;
	char line[CONFIG_FILE_MAX_LINE + 2];
	unsigned long lineno = 0;
	int rc = 0;
	struct config *c;
	struct co_config *co;

	if (!cm || !path) {
		errno = EINVAL;
		return -1;
	}

	c = list_last_entry(&cm->config_head, struct config, config_node);
	co = list_first_entry(&c->co_config_head, struct co_config, co_config_node);

	fp = fopen(path, "r");
	if (!fp) {
		eslog("cannot open config file \"%s\"", path);
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		char *key, *value, *eq;

		++lineno;
		if (strlen(line) >= sizeof(line) - 1 &&
		    line[sizeof(line) - 2] != '\n') {
			elog("config \"%s\" line %lu: too long", path, lineno);
			rc = -1;
			break;
		}

		key = config_file_trim(line);
		if (!*key || *key == '#')
			continue; /* blank or comment */

		eq = strchr(key, '=');
		if (!eq) {
			elog("config \"%s\" line %lu: missing '='", path, lineno);
			rc = -1;
			break;
		}
		*eq = '\0';
		value = config_file_trim(eq + 1);

		key = config_file_trim(key);
		if (!*key) {
			elog("config \"%s\" line %lu: empty key", path, lineno);
			rc = -1;
			break;
		}

		int r = config_file_apply(c, co, key, value);
		if (r == -1) {
			elog("config \"%s\" line %lu: unknown key \"%s\"",
			     path, lineno, key);
			rc = -1;
			break;
		}
		if (r == -2) {
			elog("config \"%s\" line %lu: bad value for \"%s\"",
			     path, lineno, key);
			rc = -1;
			break;
		}
	}

	if (ferror(fp) && rc == 0) {
		eslog("read error on config file \"%s\"", path);
		rc = -1;
	}
	fclose(fp);

	return rc;
}

int config_file_load_env(struct config_manager *cm)
{
	const char *path = getenv("ACE_CONFIG_FILE");

	if (!path || !*path)
		return 0; /* no config file requested */
	return config_file_load(cm, path);
}
