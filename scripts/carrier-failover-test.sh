#!/bin/bash
# carrier-failover-test.sh — verify carrier loss aborts connections bound to
# the affected interface (the carrier-lost → teardown seam).
#
# Requires root.  Uses the loopback interface: the client is configured (via
# ACE_CONFIG_FILE) with `if_name = lo`, which makes connote_init_client
# SO_BINDTODEVICE lo.  Its auto-connect then completes over loopback, giving a
# live connection bound to lo; we then `ip link set lo down` and assert the
# client aborts that connection immediately instead of waiting for the QUIC
# no-progress/idle timeout.  The trap restores `ip link set lo up`.
#
# NOTE: this briefly takes loopback down.  Run it only in an isolated
# environment; the trap always restores lo.
set -euo pipefail

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; RESET='\033[m'
pass() { printf "${GREEN}[PASS]${RESET} %s\n" "$*"; }
fail() { TEST_FAILED=1; printf "${RED}[FAIL]${RESET} %s\n" "$*"; exit 1; }
info() { printf "${CYAN}[INFO]${RESET} %s\n" "$*"; }
skip() { printf "${CYAN}[SKIP]${RESET} %s\n" "$*"; exit 0; }
TEST_FAILED=0

SERVER_PID=
CLIENT_PID=
IFNAME=lo

cleanup() {
	[ -z "$CLIENT_PID" ] || { kill "$CLIENT_PID" 2>/dev/null || true; wait "$CLIENT_PID" 2>/dev/null || true; }
	[ -z "$SERVER_PID" ] || { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
	ip link set "$IFNAME" up 2>/dev/null || true
	rm -rf "$CFG_DIR"
	if [ -n "${CERT_DIR:-}" ]; then
		rm -f "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem"
		rmdir "$CERT_DIR" 2>/dev/null || true
	fi
	[ "$TEST_FAILED" -ne 0 ] || rm -f /tmp/ace-cf-*.log
}
trap cleanup EXIT

cd "$(dirname "$0")/.."
ACE_BUILD_DIR=${ACE_BUILD_DIR:-build}

if [ "$(id -u)" -ne 0 ]; then
	skip "requires root for ip link set lo down"
fi

CFG_DIR=$(mktemp -d /tmp/ace-cf.XXXXXX)
cat > "$CFG_DIR/ace.conf" <<EOF
if_name = $IFNAME
EOF

CERT_DIR=$(mktemp -d /tmp/ace-cf-cert.XXXXXX)
openssl req -newkey rsa:2048 -nodes -x509 -days 1 \
	-keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" -subj '/CN=localhost' \
	>/dev/null 2>&1
export ACE_CERT_FILE="$CERT_DIR/cert.pem" ACE_KEY_FILE="$CERT_DIR/key.pem"
export ACE_TLS_INSECURE=1
export ACE_UPSTREAM_FILE="$CFG_DIR/client.sock"

info "Starting server..."
stdbuf -oL -eL "${ACE_BUILD_DIR}/src/ace" 1 > /tmp/ace-cf-server.log 2>&1 &
SERVER_PID=$!
sleep 1

info "Starting client bound to $IFNAME..."
ACE_CONFIG_FILE="$CFG_DIR/ace.conf" stdbuf -oL -eL \
	"${ACE_BUILD_DIR}/src/ace" 0 > /tmp/ace-cf-client.log 2>&1 &
CLIENT_PID=$!

# wait for the handshake so there is a live bound connection
for _attempt in $(seq 1 60); do
	grep -q 'QUIC_PROBE_OK' /tmp/ace-cf-client.log 2>/dev/null && break
	sleep 0.5
done
grep -q 'QUIC_PROBE_OK' /tmp/ace-cf-client.log || fail "client never established a live connection over $IFNAME"

info "Taking $IFNAME down..."
ip link set "$IFNAME" down
sleep 0.5

grep -q "link carrier DOWN on $IFNAME" /tmp/ace-cf-client.log \
	|| fail "carrier DOWN transition was not observed on $IFNAME"
grep -q "aborting connection .* bound to $IFNAME" /tmp/ace-cf-client.log \
	|| fail "no connection abort observed for the carrier-lost interface $IFNAME"
pass "carrier loss aborted the connection bound to $IFNAME"
