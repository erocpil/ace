#!/bin/sh
set -eu

root=${1:-.}
grep -F 'if (client_run(ct) != 0)' "$root/src/ace.c" >/dev/null
grep -F 'if (server_run(sr) != 0)' "$root/src/ace.c" >/dev/null
grep -F 'QUIC_EVENT handshake status=failed' "$root/src/client.c" >/dev/null
grep -F 'QUIC_EVENT service_stop status=' "$root/src/service.c" >/dev/null
