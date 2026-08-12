#!/bin/sh
set -eu

script=${1:-scripts/smoke-test.sh}

grep -F '${SERVER_PID:-}' "$script" >/dev/null
grep -F '${CLIENT_PID:-}' "$script" >/dev/null
grep -F 'ss -uln' "$script" >/dev/null
grep -F 'server_on_new_conn' "$script" >/dev/null
grep -F 'LSQ_HSK_OK' "$script" >/dev/null
grep -F 'QUIC_PROBE_OK' "$script" >/dev/null
grep -F 'QUIC_PROBE_ECHO' "$script" >/dev/null
grep -F 'stdbuf -oL -eL' "$script" >/dev/null
grep -F 'Client service thread was not joined' "$script" >/dev/null
grep -F 'Server service thread was not joined' "$script" >/dev/null
if grep -F "12345.*ace" "$script" >/dev/null; then
	echo "smoke test requires privileged process metadata from ss" >&2
	exit 1
fi
