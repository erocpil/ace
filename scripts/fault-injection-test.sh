#!/bin/bash
set -euo pipefail

ACE_BUILD_DIR=${ACE_BUILD_DIR:-build}
CERT_DIR=$(mktemp -d /tmp/ace-fault-cert.XXXXXX)
SERVER_LOG=/tmp/ace-fault-server.log
CLIENT_LOG=/tmp/ace-fault-client.log
SERVER_PID=
CLIENT_PID=

stop_process() {
	local pid=$1

	kill -KILL "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
}

cleanup() {
	[ -z "$CLIENT_PID" ] || stop_process "$CLIENT_PID"
	[ -z "$SERVER_PID" ] || stop_process "$SERVER_PID"
	rm -f "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem"
	rmdir "$CERT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

cd "$(dirname "$0")/.."
openssl req -newkey rsa:2048 -nodes -x509 -days 1 \
	-keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" -subj '/CN=localhost' \
	>/dev/null 2>&1
export ACE_CERT_FILE="$CERT_DIR/cert.pem" ACE_KEY_FILE="$CERT_DIR/key.pem"
# Self-signed cert — explicitly opt into insecure mode.
export ACE_TLS_INSECURE=1

stdbuf -oL -eL "./${ACE_BUILD_DIR}/src/ace" 1 >"$SERVER_LOG" 2>&1 & SERVER_PID=$!
sleep 0.5
stdbuf -oL -eL "./${ACE_BUILD_DIR}/src/ace" 0 >"$CLIENT_LOG" 2>&1 & CLIENT_PID=$!
for _attempt in $(seq 1 100); do
	grep -q 'QUIC_PROBE_OK' "$CLIENT_LOG" 2>/dev/null && break
	sleep 0.1
done
grep -q 'QUIC_PROBE_OK' "$CLIENT_LOG"

kill -KILL "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=
for _attempt in $(seq 1 100); do
	grep -q 'QUIC_EVENT connection status=lost' "$CLIENT_LOG" 2>/dev/null && break
	sleep 0.1
done
grep -q 'QUIC_EVENT connection status=lost' "$CLIENT_LOG"

# The client exits on its own once the last connection is lost (idle-exit).
# A probe-only client has no in-flight task, so the loss is not a *task*
# failure and the service exits 0; the observable signal is the
# "status=lost" log asserted above.
set +e
for _attempt in $(seq 1 100); do
	kill -0 "$CLIENT_PID" 2>/dev/null || break
	sleep 0.1
done
wait "$CLIENT_PID"
set -e
CLIENT_PID=
printf '[PASS] peer loss was observable and the client exited on its own\n'
