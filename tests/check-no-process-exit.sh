#!/bin/sh
set -eu

root=${1:-.}
status=0

for source in ace.c client.c server.c service.c task_dispatch.c task_sendfile.c task_perf.c connote.c upstream.c; do
	if grep -En '(^|[^>.[:alnum:]_])exit[[:space:]]*\(' "$root/src/$source"; then
		status=1
	fi
done

if [ "$status" -ne 0 ]; then
	echo "production network/task paths must return or abort one connection, not exit the process" >&2
	exit 1
fi
