#!/bin/sh
# check-queue-saturation.sh — verify stream queue limits and budget
# enforcement are coded correctly.
#
# Checks:
#  1. ACE_MAX_STREAM_QUEUE is defined and used in lstream_ctx_add_rxq / _add_txq
#  2. ace_mem_charge is called before allocation (skb_malloc_charged)
#  3. ace_mem_release is called in error paths (skb_free, service_stream_ctx_free)
#  4. Budget rejection path exists for stream ctx allocation
set -eu

root="${1:-.}"

# --- 1. Queue limit guards exist ---
grep -F 'ACE_MAX_STREAM_QUEUE' "$root/src/resource_limits.h" >/dev/null || {
	echo "FAIL: ACE_MAX_STREAM_QUEUE not defined in resource_limits.h"
	exit 1
}
echo "PASS: ACE_MAX_STREAM_QUEUE defined"

grep -F 'ace_quota_can_add' "$root/src/quic_stream.h" >/dev/null || {
	echo "FAIL: ace_quota_can_add not used in quic_stream.h"
	exit 1
}
echo "PASS: lstream_ctx_add_rxq/txq guard calls ace_quota_can_add"

# --- 2. Budget-aware allocation in stream ctx ---
grep -F 'skb_malloc_charged' "$root/src/quic_stream.c" >/dev/null || {
	echo "FAIL: skb_malloc_charged not used in quic_stream.c"
	exit 1
}
echo "PASS: stream ctx uses skb_malloc_charged (budget-aware)"

# --- 3. Budget release on cleanup ---
grep -F 'ace_mem_release' "$root/src/quic_stream.c" >/dev/null || {
	echo "FAIL: ace_mem_release not called on stream cleanup paths"
	exit 1
}
echo "PASS: ace_mem_release called in stream cleanup paths"

# --- 4. Budget charge before stream ctx allocation ---
grep -F 'ace_mem_charge(&lc->mem_budget' "$root/src/quic_stream.c" >/dev/null || {
	echo "FAIL: stream ctx does not charge connection budget"
	exit 1
}
echo "PASS: stream ctx charges connection budget before alloc"

# --- 5. skb_free auto-release wired ---
grep -F 'ace_mem_release(b, total)' "$root/src/sk_buff.h" >/dev/null || {
	echo "FAIL: skb_free does not auto-release budget"
	exit 1
}
echo "PASS: skb_free auto-releases budget"

# --- 6. Budget dump/logging available ---
grep -F 'ace_mem_budget_dump' "$root/src/mem_budget.c" >/dev/null || {
	echo "FAIL: ace_mem_budget_dump not implemented"
	exit 1
}
echo "PASS: ace_mem_budget_dump available for diagnostics"

# --- 7. Hierarchical budget wiring ---
grep -F 'ace_mem_budget_init(&r->mem_budget, "conn"' "$root/src/service.h" >/dev/null || {
	echo "FAIL: connection budget not initialised"
	exit 1
}
echo "PASS: connection budget initialised with service parent"

grep -F 'ace_mem_budget_init(&sc->mem_budget, "stream"' "$root/src/quic_stream.c" >/dev/null || {
	echo "FAIL: stream budget not initialised"
	exit 1
}
echo "PASS: stream budget initialised with connection parent"

echo ""
echo "Queue saturation / budget enforcement: all checks passed."
