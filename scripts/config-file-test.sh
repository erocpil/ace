#!/bin/bash
# config-file-test.sh — verify the optional ACE_CONFIG_FILE layer end to end.
#
# Two checks:
#   1. an unknown key in the config file fails fast (client exits non-zero
#      and logs "unknown key") — the fail-fast contract;
#   2. a session_path override in the config file actually reaches the session
#      resume writer (default is "session/"), proving values are applied and
#      not merely parsed.
set -euo pipefail

RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; RESET='\033[m'
pass() { printf "${GREEN}[PASS]${RESET} %s\n" "$*"; }
fail() { TEST_FAILED=1; printf "${RED}[FAIL]${RESET} %s\n" "$*"; exit 1; }
info() { printf "${CYAN}[INFO]${RESET} %s\n" "$*"; }
TEST_FAILED=0

SERVER_PID=
CLIENT_PID=

cleanup() {
	[ -z "$CLIENT_PID" ] || { kill "$CLIENT_PID" 2>/dev/null || true; wait "$CLIENT_PID" 2>/dev/null || true; }
	[ -z "$SERVER_PID" ] || { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
	rm -rf "$CFG_DIR"
	rm -rf /tmp/ace-cfg-session
	if [ -n "${CERT_DIR:-}" ]; then
		rm -f "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem"
		rmdir "$CERT_DIR" 2>/dev/null || true
	fi
	[ "$TEST_FAILED" -ne 0 ] || rm -f /tmp/ace-cfg-*.log
}
trap cleanup EXIT

cd "$(dirname "$0")/.."
ACE_BUILD_DIR=${ACE_BUILD_DIR:-build}
CFG_DIR=$(mktemp -d /tmp/ace-cfg.XXXXXX)

# ---- 1. fail-fast on an unknown key ----
cat > "$CFG_DIR/bad.conf" <<'EOF'
bogus_key = 1
EOF
info "Testing fail-fast on an unknown config key..."
set +e
ACE_CONFIG_FILE="$CFG_DIR/bad.conf" stdbuf -oL -eL \
	"${ACE_BUILD_DIR}/src/ace" 0 > "$CFG_DIR/bad.log" 2>&1
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
	fail "client accepted an unknown config key (exit 0)"
fi
grep -q 'unknown key' "$CFG_DIR/bad.log" || fail "expected 'unknown key' in the bad-config log"
pass "Unknown config key fails fast (exit $rc)"

# ---- 2. session_path override takes effect ----
CERT_DIR=$(mktemp -d /tmp/ace-cfg-cert.XXXXXX)
openssl req -newkey rsa:2048 -nodes -x509 -days 1 \
	-keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" -subj '/CN=localhost' \
	>/dev/null 2>&1
export ACE_CERT_FILE="$CERT_DIR/cert.pem" ACE_KEY_FILE="$CERT_DIR/key.pem"
# Self-signed cert — explicitly opt into insecure mode.
export ACE_TLS_INSECURE=1
export ACE_UPSTREAM_FILE="$CFG_DIR/client.sock"

cat > "$CFG_DIR/good.conf" <<'EOF'
session_path = /tmp/ace-cfg-session
EOF

info "Starting server..."
stdbuf -oL -eL "${ACE_BUILD_DIR}/src/ace" 1 > /tmp/ace-cfg-server.log 2>&1 &
SERVER_PID=$!
sleep 1

info "Starting client with ACE_CONFIG_FILE=$CFG_DIR/good.conf ..."
ACE_CONFIG_FILE="$CFG_DIR/good.conf" stdbuf -oL -eL \
	"${ACE_BUILD_DIR}/src/ace" 0 > /tmp/ace-cfg-client.log 2>&1 &
CLIENT_PID=$!

for _attempt in $(seq 1 60); do
	grep -q 'to /tmp/ace-cfg-session/' /tmp/ace-cfg-client.log 2>/dev/null && break
	sleep 0.5
done
grep -q 'to /tmp/ace-cfg-session/' /tmp/ace-cfg-client.log \
	|| fail "session_path from the config file was not applied (no write to /tmp/ace-cfg-session/)"
pass "config file session_path override took effect"
