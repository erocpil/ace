#!/bin/sh
set -eu

root=${1:-.}
grep -F 'kill -KILL "$SERVER_PID"' "$root/scripts/fault-injection-test.sh" >/dev/null
grep -F 'QUIC_EVENT connection status=lost' "$root/scripts/fault-injection-test.sh" >/dev/null
grep -F 'client returned success after injected peer loss' "$root/scripts/fault-injection-test.sh" >/dev/null
grep -F 'task->n_sub_done' "$root/src/client.c" >/dev/null
grep -F 'n_conn_failed' "$root/src/client.c" >/dev/null
grep -F 'es->es_noprogress_timeout = 3' "$root/src/service.c" >/dev/null
