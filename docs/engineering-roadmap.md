# ACE Engineering Roadmap

## Goal

Turn ACE from a QUIC research prototype into a reproducible and testable QUIC
client/server implementation. Work that does not directly affect the QUIC
connection, stream, packet, or task data paths is deliberately deferred.

Every completed item should include focused tests where practical. Before an
item is considered complete, run its focused tests and the full available
regression suite.

## Priority order

### P0: QUIC data-path safety

- [x] Make `sk_buff` allocation reject invalid/oversized lengths and handle
      allocation failure; cover allocation and basic boundary operations with a
      focused unit test. Further queue/ownership hardening remains below.
- [x] Validate the outer task frame before dispatching by theme or serial.
- [x] Validate send-file negotiation lengths, stream count, file size, and
      integer arithmetic before allocating memory or accessing payload data.
- [x] Confine received files to a fixed root directory; reject absolute
      paths, traversal, embedded NUL bytes, and invalid components.
- [x] Replace `exit()` in QUIC callbacks, socket setup, and task handlers with
      connection-, stream-, or task-scoped failures; enforce this with CTest.
      Input- and event-dependent `assert()` calls have also been removed.
- [x] Put explicit limits on frame size, stream count, queued buffers, task
      memory, and output file size.

Exit criterion: malformed or oversized peer input cannot terminate the process,
escape the receive directory, or cause unchecked allocation/access. Parser and
buffer tests pass under ASan and UBSan.

### P1: Minimal end-to-end QUIC path

- [x] Provide a deterministic client connection trigger suitable for tests.
- [x] Verify TLS handshake, connection creation, stream creation, payload
      transfer, checksum, and orderly connection close. The localhost smoke test
      verifies a deterministic probe followed by a 98,304-byte random file over
      three data streams, byte-for-byte persisted output, connection close, and
      joined service threads.
- [x] Handle partial stream reads/writes, `EAGAIN`/`EINTR`, packet-send
      backpressure, short datagrams, and unsupported `MSG_ZEROCOPY` fallback.
- [x] Correctly stop, join, and destroy service event loops and worker threads.
      The shutdown path also frees the client upstream socket/queues. Full
      ownership auditing of every connection allocation remains under P2.
- [x] Propagate client/server service failures through exit status and emit
      stable `QUIC_EVENT` service/handshake outcome records.

Exit criterion: an automated localhost test transfers a file and verifies its
checksum; the same test detects handshake, transfer, and shutdown failures.

### P2: QUIC correctness and resilience

- [ ] Add tests for concurrent streams, connection loss, peer abort, timeout,
      retry, queue pressure, and malformed frames. Three concurrent file streams,
      truncation/corruption matrices, retry classification, and quota boundaries
      are covered. A bounded peer-loss harness and a three-second QUIC
      no-progress timeout now exist, but the live peer-loss run is not yet stable;
      explicit peer-abort and queue-saturation integration tests remain.
- [x] Complete shared IPv4/IPv6 address formatting, sockaddr sizing, destination
      packet-info parsing, and ECN ancillary-data extraction. Both IPv4 and IPv6
      localhost handshakes, probe echoes, three-stream transfers, and shutdowns
      have passed; IPv6 remains a separately selected smoke-test mode.
- [ ] Define ownership for connection, stream, task, TLS, session, and packet
      buffers and verify it with leak detection. Stream queues, sendfile task
      mappings/metadata, session resume input, upstream queues, and event loops
      now have explicit cleanup; full-process LSan still remains.
- [x] Add a libFuzzer target for frame and negotiation parsing. The Clang
      ASan-backed smoke corpus completed 10,000 runs without a parser failure.
- [x] Make lsquic global initialization process-wide and thread-safe with
      `pthread_once`; initialize client/server support together and clean it up
      once at process exit, never from an individual service thread.

Exit criterion: sanitizer and fuzz smoke runs are clean, and failure injection
does not leak resources or terminate unrelated connections.

### P3: Reproducible build and continuous regression

- [ ] Use target-scoped CMake options and imported dependency targets.
- [x] Provide Debug, Release, ASan, UBSan, LSan, and fuzz CMake presets. Debug,
      ASan, UBSan, fuzz, and the LSan build have compiled; runtime LSan cannot
      execute in the current ptrace environment and remains to be verified in CI.
- [x] Pin the lsquic commit and libev archive SHA-256, use HTTPS downloads, and
      verify both fresh and cached dependency sources.
- [ ] Add CI for GCC and Clang, focused unit tests, end-to-end tests, ASan, and
      UBSan.
- [ ] Validate x86_64 continuously and add an ARM64 compile/test job when an
      ARM64 environment is available.

Exit criterion: a clean checkout has documented, deterministic commands for
building and running all tests, with CI enforcing them.

### P4: Non-QUIC and product features

- [ ] Improve the telnet/control interface and configuration format.
- [ ] Complete performance tooling, daemonization, multiprocess mode, and CPU
      affinity policy.
- [ ] Refine logging, packaging, installation, and user documentation.
- [x] Remove repository test keys and generate short-lived certificates in the
      build or test temporary directory.

These items remain last unless one blocks an earlier QUIC milestone or fixes a
security defect.

## Regression policy

Use the following layers after each change:

1. Run the new focused unit test.
2. Run all tests registered with CTest.
3. Compile the affected production sources with warnings enabled.
4. When dependencies are present, build `ace` and `alpha` and run the end-to-end
   smoke test.
5. For memory- or parser-related work, repeat under ASan and UBSan.

If a layer cannot run because an external dependency or architecture is not
available, record that explicitly; do not report the item as fully verified.

## Next work queue

The remaining work should continue in this order:

1. Stabilize the live peer-loss fault-injection test and verify that a crashed
   peer produces a bounded timeout, a stable loss event, and a non-zero client
   result without requiring manual termination.
2. Add explicit peer-abort and queue-saturation integration tests, including
   isolation between unrelated connections.
3. Run the full executable suite with LSan in an environment that permits leak
   sanitizer process inspection; fix and document every confirmed leak.
4. Keep the new GitHub Actions pipeline green for GCC/Clang Debug and Release,
   ASan/UBSan, the bounded protocol fuzz campaign, and real IPv4/IPv6 QUIC
   integration tests.
5. Add ARM64 dependency build, compile, unit-test, and QUIC integration jobs
   when a maintained ARM64 GitHub runner is selected and available.
6. Only after the QUIC and build gates above are stable, continue with the
   control/configuration interface, packaging, performance tooling, and other
   non-QUIC product work.

## Current baseline (2026-08-12)

- The dependency bootstrap now pins BoringSSL API 18, defaults to GitHub, and
  initializes lsquic submodules. On x86_64, BoringSSL, libev, and lsquic build
  successfully into `lib/x86_64`.
- `ace`, `alpha`, and 15 CTest regressions build and pass. Coverage includes
  buffers, task parsing, partial I/O, UDP fallback, IPv4/IPv6 address handling,
  concurrent process-global QUIC initialization, lifecycle/ownership contracts,
  dependency pins, ephemeral certificates, observability, and test-harness safety.
- The localhost smoke test proves a real QUIC handshake and validated 4096-byte
  probe echo, transfers a 98,304-byte random file over three streams and compares
  it byte-for-byte, then requires orderly close and joined service threads. Both
  IPv4 and IPv6 modes have passed outside the restricted network sandbox.
- ASan (with leak detection disabled in this ptrace environment) and UBSan each
  pass all 15 CTest cases. The Clang fuzz target passes 10,000 runs. A dedicated
  LSan build succeeds, but LSan runtime validation is blocked by ptrace.
- Dependency bootstrap pins BoringSSL API 18, lsquic commit
  `b373fe522048a6885b0cdeebfa583a61dee2ff1f`, and libev SHA-256
  `507eb7b8d1015fbec5b935f34ebed15bf346bed04a11ab82b8eee848c4205aea`.
- Repository test credentials have been removed; build and integration tests use
  generated one-day certificates.
- The live peer-loss integration run remains open: its contract test passes and
  process waits are bounded, but the current real run has not yet produced a
  stable loss callback after the peer is killed. Do not treat this as verified.
- GitHub Actions now defines GCC/Clang Debug and Release builds, all CTest
  regressions, ASan/UBSan jobs, a 10,000-run Clang fuzz smoke job, and separate
  IPv4/IPv6 real QUIC integration jobs. Its first remote run must still be
  observed and any runner-specific failures corrected before CI is considered
  proven stable.
- There is still no ARM64 validation environment and no explicit
  queue-saturation integration test.
- The repository has only a `main` branch. There are no separate `x86_64` and
  `arm64` branches on which to apply an architecture rebase workflow.
