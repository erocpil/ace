# Architecture conformance

Status of the codebase against the original six-layer architecture design and
its three design ideas. Updated as of commit `ff1d0b8`.

Status key: ✅ implemented · ⚠️ partial · ❌ absent / stub.

## Layer 1 — Application / API

- ✅ Config — hardcoded defaults, environment variables, and an optional
  `key = value` config file (`ACE_CONFIG_FILE`, `src/config_file.c`). Priority:
  default < environment variable < config file.
- ✅ Task — task/subtask framework (`src/task.h`, `src/task_dispatch.c`) with two
  task types: sendfile (`src/task_sendfile.c`) and perf (`src/task_perf.c`).
  `probe` is a control-stream message, not a task (the dead command word was
  removed).
- ✅ CPU set — per-service affinity (`set_affinity`, `src/config.c`).
- ✅ Memory — layered budget process→service→connection→stream (`src/mem_budget.c`).
- ✅ IPC — AF_UNIX control socket with text commands (`src/control_socket.c`,
  `src/control_command.c`).
- ❌ Channel API — `ace_init_client` / `ace_init_server` / `ace_connect` are
  declared in `src/ace.h` but never defined. ace builds as an executable, not a
  linkable library.

## Layer 2 — Communication / Session Runtime

- ✅ Session maintain — the service owns the lsquic engine and event loop; session
  resumption is persisted (`src/quic_session.c`).
- ✅ Data forward — local socket ↔ QUIC, bidirectional (`src/upstream.c`).
- ❌ Stream LB algorithm — none; sendfile splits a file across streams serially.
- ❌ Packet filter — none.
- ⚠️ Low-overhead handshake — session resumption is implemented, but there is no
  0-RTT early data and TLS peer identity verification is disabled.
- ✅ Link detection — carrier monitoring via netlink (`src/link_monitor.c`).
  Carrier loss aborts connections bound to the affected interface. QUIC-level
  liveness still relies on the lsquic ping/idle/no-progress timeouts.
- ⚠️ Fast recovery — delegated to lsquic, not self-authored.
- ⚠️ Stream multiplexing and balancing — multiplexing exists (one subtask per
  stream); balancing does not.
- ✅ Batch processing — `service_packets_out` sends a batch in one call; the
  upstream queue is bounded by `n_skb_batch`.
- ✅ Protocol processing — wire codec (`src/protocol_codec.c`,
  `src/task_protocol.h`).

## Layer 3 — Protocol / Transport

- ✅ QUIC client/server library and stack — third-party lsquic (vendored,
  v3.3.1).
- ⚠️ Kernel-socket path — AF_UNIX/TCP socket helpers and the `alpha` debug binary
  exist, but the main data path is QUIC-only; there is no dual-link fallback.

## Layer 4 — Event abstraction

- ❌ No abstraction layer. libev is a hard dependency — `ev_*` types and calls run
  throughout `runner.c`, `service.c`, `upstream.c`, `client.c`, and `server.c`.
  The diagram's "swap in libuv/libevent/epoll/poll/select" does not hold in code.

## Layer 5 — Linux networking

- ✅ AF_INET — UDP sockets, IPv4/IPv6, packet-info, ECN (`src/packet_io.c`).
- ✅ AF_UNIX — control socket.
- ✅ AF_NETLINK — `RTMGRP_LINK` subscription on the event loop
  (`src/link_monitor.c`).

## Layer 6 — Device / network state

- ✅ Carrier — per-interface carrier state, transition callback, and connection
  teardown on loss.
- ❌ Address — `RTM_NEWADDR` is log-only; no address state, no subscription.
- ❌ Route — `RTM_NEWROUTE` is log-only; no route state, no subscription.
- ❌ Domain name — none.
- ⚠️ Event coverage — only `RTMGRP_LINK` is subscribed; the address/route netlink
  groups are not.

## The three design ideas

1. Application semantics decoupled from transport — partial: task/session
   abstractions exist, but the structs embed lsquic types and there is no public
   Channel API.
2. Runtime decoupled from the event mechanism — absent: libev is hardcoded.
3. Linux network/device state folded into the communication system — partial:
   carrier is modeled and wired; address, route, and DNS are not.

## Remaining gaps

Functional gaps (in the diagram's spirit):

- Channel API (Layer 1).
- Event abstraction layer (Layer 4).
- Device/network state beyond carrier: address, route, domain name (Layer 6).
- Kernel-socket dual path (Layer 3).

Correctness/security debt — independent of the diagram, but should be cleared
before the layers above:

- TLS peer identity verification (currently disabled).
- Wire format is native ABI (contains `size_t`); not fixed-width or
  cross-architecture.

Deferred / not planned:

- Stream LB algorithm, packet filter, and a self-authored fast recovery — lsquic
  already provides the latter two concerns.
