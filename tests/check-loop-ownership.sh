#!/bin/sh
set -eu

runner=${1:-src/runner.c}

if grep -F 'ev_timer_start(loop, tw)' "$runner" >/dev/null; then
	echo "main loop must not schedule service processing" >&2
	exit 1
fi
grep -F 'Each QUIC engine is owned' "$runner" >/dev/null
grep -F 'service_set_running(se)' "$runner" >/dev/null
grep -F 'pthread_join(se->thread' "$runner" >/dev/null
