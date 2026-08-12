#!/bin/sh
set -eu

root=${1:-.}
grep -F 'pthread_once(&quic_once' "$root/src/quic_global.c" >/dev/null
grep -F 'LSQUIC_GLOBAL_CLIENT | LSQUIC_GLOBAL_SERVER' "$root/src/quic_global.c" >/dev/null
grep -F 'atexit(quic_global_cleanup_at_exit)' "$root/src/quic_global.c" >/dev/null
if grep -F 'lsquic_global_cleanup()' "$root/src/service.c" >/dev/null; then
	echo "individual service threads must not clean up process-global lsquic state" >&2
	exit 1
fi
