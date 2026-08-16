#ifndef ACE_CONFIG_FILE_H
#define ACE_CONFIG_FILE_H

#include "config.h"

/*
 * config_file — optional startup configuration file.
 *
 * A minimal `key = value` text format, parsed with no third-party
 * dependencies.  It is an OPTIONAL layer: when no file is given (the
 * ACE_CONFIG_FILE environment variable is unset), ACE keeps its existing
 * hardcoded defaults plus environment-variable overrides.  When a file IS
 * loaded, it is applied AFTER main()'s hardcoded defaults and env-var
 * overrides, so it is the highest-priority layer:
 *
 *     hardcoded default  <  environment variable  <  config file
 *
 * Unknown keys and malformed values are hard errors (fail fast), so a
 * typo in the file cannot silently leave a default in place.
 *
 * String values (file, log_level, session_path, keylog_path, host,
 * if_name) are copied; the former four are strdup()'d into the config and
 * are NOT freed (config is a process-lifetime singleton, matching how the
 * env-var pointers are already handled).  Call config_file_load() at most
 * once per process.
 */

/* Apply a single "key=value" directive to @c / @co.
 *
 * @c    target config (non-NULL)
 * @co   target co_config (non-NULL); host/port/if_name/bindtodevice land here
 * @key  trimmed directive key (non-NULL, NUL-terminated)
 * @value trimmed directive value (non-NULL, NUL-terminated)
 *
 * Returns 0 on success, -1 on an unknown key, -2 on a malformed value.
 */
int config_file_apply(struct config *c, struct co_config *co,
                      const char *key, const char *value);

/* Load and apply a config file to the manager's last config (and its
 * first co_config).  Returns 0 on success, -1 on any error (unreadable
 * file, unknown key, malformed value, oversized line).  On error, the
 * first offending line number is logged.
 */
int config_file_load(struct config_manager *cm, const char *path);

/* Load ACE_CONFIG_FILE if it is set (and non-empty).  No-op returning 0
 * when the variable is unset/empty; -1 when the named file fails to load.
 * This is the single entry point main() should call after it has applied
 * its hardcoded defaults and environment-variable overrides.
 */
int config_file_load_env(struct config_manager *cm);

#endif /* ACE_CONFIG_FILE_H */
