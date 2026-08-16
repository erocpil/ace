#!/bin/bash
# test-lib.sh — shared helpers for ACE integration scripts.
#
# Sourced (not executed) by the scripts under scripts/.  Each script does
# `cd "$(dirname "$0")/.."` first, so the repo root is the working directory
# and this file is reachable as `scripts/test-lib.sh`.
#
# The single most important helper is ace_send_control: it replaces the old
# `sleep 1` + one-shot `socat ... || true` pattern that caused the
# quic-integration flake.  The client's upstream control socket is a UNIX
# socket bound inside a service thread; on a slow or loaded CI runner the fixed
# `sleep 1` could expire before the socket was bound, `socat` failed, `|| true`
# swallowed the error, the command was lost, and the transfer poll timed out.
# ace_send_control instead retries the connect until the socket accepts the
# command (socat exit 0 == the command reached the kernel socket buffer), and
# only then returns success.

# Send one control command line, retrying until the upstream socket accepts it.
# Args: <socket-path> <command> [max-tries] [retry-delay-seconds]
ace_send_control() {
    local sock="$1" cmd="$2" tries="${3:-50}" delay="${4:-0.2}" i
    for i in $(seq 1 "$tries"); do
        if printf '%s\n' "$cmd" | socat - "UNIX-CONNECT:$sock" >/dev/null 2>&1; then
            return 0
        fi
        sleep "$delay"
    done
    return 1
}

# Wait until the upstream socket accepts a connection, then drop it.  The probe
# connection is a normal accept+EOF on the client (its echo object is cleaned
# up safely); use it only where a later hold-open send must be sure the socket
# is already listening.
ace_wait_connect() {
    local sock="$1" tries="${2:-50}" delay="${3:-0.2}" i
    for i in $(seq 1 "$tries"); do
        if socat -u /dev/null "UNIX-CONNECT:$sock" >/dev/null 2>&1; then
            return 0
        fi
        sleep "$delay"
    done
    return 1
}
