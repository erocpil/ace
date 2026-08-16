#!/bin/bash
# link-monitor-test.sh — verify the netlink carrier monitor end to end.
#
# Requires root and the kernel `dummy` module (to create an interface whose
# carrier we can flip without disturbing the loopback QUIC path).  When either
# is unavailable the script SKIPs (exit 0) so it can run anywhere.
#
# Flow: start server + client (the client keeps the QUIC connection up and its
# link_monitor subscribed to RTMGRP_LINK), then create a dummy interface and
# flip it up → down.  The client must log both carrier transitions.
set -euo pipefail

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; RESET='\033[m'
pass() { printf "${GREEN}[PASS]${RESET} %s\n" "$*"; }
fail() { TEST_FAILED=1; printf "${RED}[FAIL]${RESET} %s\n" "$*"; exit 1; }
info() { printf "${CYAN}[INFO]${RESET} %s\n" "$*"; }
skip() { printf "${CYAN}[SKIP]${RESET} %s\n" "$*"; exit 0; }
TEST_FAILED=0

SERVER_PID=
CLIENT_PID=
IFNAME=ace-test0

cleanup() {
	[ -z "$CLIENT_PID" ] || { kill "$CLIENT_PID" 2>/dev/null || true; wait "$CLIENT_PID" 2>/dev/null || true; }
	[ -z "$SERVER_PID" ] || { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
	ip link del "$IFNAME" 2>/dev/null || true
	if [ -n "${CERT_DIR:-}" ]; then
		rm -f "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem"
		rmdir "$CERT_DIR" 2>/dev/null || true
	fi
	[ "$TEST_FAILED" -ne 0 ] || rm -f /tmp/ace-link-*.log
}
trap cleanup EXIT

cd "$(dirname "$0")/.."
ACE_BUILD_DIR=${ACE_BUILD_DIR:-build}

# ---- environment gate ----
if [ "$(id -u)" -ne 0 ]; then
	skip "requires root for ip link"
fi
if ! ip link add "$IFNAME" type dummy 2>/dev/null; then
	skip "dummy interface not available"
fi
ip link del "$IFNAME" 2>/dev/null || true

# ---- start server + client ----
CERT_DIR=$(mktemp -d /tmp/ace-link-cert.XXXXXX)
openssl req -newkey rsa:2048 -nodes -x509 -days 1 \
	-keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" -subj '/CN=localhost' \
	>/dev/null 2>&1
export ACE_CERT_FILE="$CERT_DIR/cert.pem" ACE_KEY_FILE="$CERT_DIR/key.pem"
export ACE_TLS_INSECURE=1
export ACE_UPSTREAM_FILE="$CERT_DIR/client.sock"

info "Starting server..."
stdbuf -oL -eL "${ACE_BUILD_DIR}/src/ace" 1 > /tmp/ace-link-server.log 2>&1 &
SERVER_PID=$!
sleep 1

info "Starting client..."
stdbuf -oL -eL "${ACE_BUILD_DIR}/src/ace" 0 > /tmp/ace-link-client.log 2>&1 &
CLIENT_PID=$!

# wait for the QUIC handshake so the client stays alive
for _attempt in $(seq 1 60); do
	grep -q 'QUIC_PROBE_OK' /tmp/ace-link-client.log 2>/dev/null && break
	sleep 0.5
done
grep -q 'QUIC_PROBE_OK' /tmp/ace-link-client.log || fail "client never completed the probe handshake"

# ---- flip a dummy interface's carrier ----
info "Creating dummy interface $IFNAME and flipping carrier..."
ip link add "$IFNAME" type dummy
sleep 0.5
ip link set "$IFNAME" up
sleep 0.5
ip link set "$IFNAME" down
sleep 0.5

grep -q "link carrier UP on $IFNAME" /tmp/ace-link-client.log \
	|| fail "carrier UP transition was not observed on $IFNAME"
grep -q "link carrier DOWN on $IFNAME" /tmp/ace-link-client.log \
	|| fail "carrier DOWN transition was not observed on $IFNAME"
pass "carrier UP and DOWN transitions observed on $IFNAME"
