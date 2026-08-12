# ACE Project Assessment — 2026-08-12

## Executive summary

ACE has advanced from a QUIC research prototype that merely compiled into an
engineering prototype with a reproducible, continuously tested, real end-to-end
QUIC path. It is suitable for QUIC transport experiments, controlled-network
validation, and continued protocol development. It is not yet suitable for
untrusted public networks, unattended production operation, or deployments
with strict availability and resource-leak requirements.

The normal data path is now the strongest part of the project. The next phase
should concentrate on authenticated TLS, abnormal connection state handling,
complete resource ownership, and a portable wire format rather than adding
unrelated product features.

## Maturity scorecard

| Area | Score | Assessment |
|---|---:|---|
| Basic QUIC path | 8/10 | Real IPv4/IPv6 handshake and multi-stream transfer pass continuously |
| Input safety and limits | 7/10 | Central validation and explicit quotas exist; broader adversarial coverage remains |
| Automated testing | 7/10 | Strong CI breadth, but many CTest entries are source-contract checks rather than runtime tests |
| Reproducible builds | 7/10 | Dependencies are pinned and CI-proven; CMake remains globally scoped |
| Fault resilience | 5/10 | Timeouts and failure propagation exist; live peer-loss validation is not stable |
| Resource ownership | 5/10 | Major paths were cleaned up, but full-process leak freedom is unproven |
| TLS security | 3/10 | Encryption works, but peer identity verification is disabled |
| Maintainability | 5/10 | Tests and documentation improved; several core source files remain oversized |
| Cross-architecture support | 3/10 | ARM64 paths exist, but there is no ARM64 compile, test, or interoperability proof |
| Production readiness | 4/10 | Useful engineering prototype, not a production service |

## Verified capabilities

### Real QUIC data path

The project now continuously verifies:

- automatic client connection establishment;
- TLS/QUIC handshake and session resumption;
- connection and stream creation;
- a checksummed 4096-byte control-stream probe;
- a 98,304-byte random file transferred over three data streams;
- byte-for-byte validation of the persisted file;
- IPv4 and IPv6 operation;
- signal-driven shutdown and joined service threads.

The latest local build and all 15 registered CTest cases pass. The latest
GitHub Actions runs also pass across nine jobs: GCC and Clang Debug/Release,
ASan, UBSan, a 10,000-run Clang fuzz campaign, and real IPv4/IPv6 QUIC
integration tests.

### Data-path safety

Protocol parsing now centralizes the most important trust boundaries:

- maximum frame, stream, task-memory, queue, and file sizes;
- checked negotiation lengths and integer arithmetic;
- rejection of malformed, truncated, and oversized frames;
- filename allow-listing and receive-root confinement;
- rejection of traversal, absolute paths, and embedded NUL bytes;
- copied header parsing to avoid unaligned access;
- probe magic, size, and checksum validation.

QUIC callbacks and socket/task paths no longer terminate the whole process with
`exit()`. Failures are instead propagated at stream, connection, service, or
process-result scope.

### Lifecycle and concurrency

The service thread owns its QUIC engine and event loop. Shutdown ordering now
stops service loops, joins worker threads, and destroys engines. Process-global
lsquic initialization uses `pthread_once`, initializes client and server support
together, and performs cleanup once at process exit. A concurrent initialization
unit test covers this lifecycle.

### Build and dependency integrity

The dependency bootstrap pins BoringSSL and lsquic commits, verifies the libev
archive SHA-256, uses HTTPS, and supports explicit GitHub or Gitee source
selection. Debug, Release, ASan, UBSan, LSan, and fuzz presets exist. Test
certificates are generated in build or temporary directories; repository test
private keys were removed.

## Critical gaps

### P0: TLS peer identity is not verified

TLS 1.3 encryption is active, but certificate verification is currently behind
a permanently false branch and the runtime selects the no-verification path.
Consequently, a client cannot authenticate the server and a man-in-the-middle
can substitute a certificate.

Required work:

1. Enable server-certificate verification by default.
2. Add hostname/SNI verification.
3. Add configurable CA file and CA directory support.
4. Make insecure mode explicit and restricted to development/tests.
5. Add unknown-CA, expired-certificate, and hostname-mismatch integration tests.
6. Add optional mutual TLS only if the product requirements call for it.

ACE must not be described as suitable for untrusted networks until this is
complete.

### P0: Peer-loss handling is not closed end to end

A three-second idle/no-progress policy, stable failure events, and result
propagation are present, but the live peer-loss test does not yet behave
reliably enough for CI. There is also a result-ordering risk: the service can
calculate and log a successful result before engine destruction invokes a late
connection-close callback that changes the result to failure.

Required work:

1. Define distinct user-close, graceful peer-close, timeout, reset, abort, and
   transport-error states.
2. Drain/process close callbacks before freezing the final service result.
3. Notify the main loop when a service fails instead of relying on a later
   external signal.
4. Stabilize the live peer-loss test and add it to CI.
5. Verify that one failed connection cannot terminate or corrupt unrelated
   connections.

## High-priority engineering gaps

### Runtime-test depth

The 15 CTest entries include six compiled C tests and nine shell/source-contract
checks. Contract checks prevent important structural regressions, but they do
not prove runtime behavior. Test reporting should distinguish unit, contract,
integration, fault, fuzz, and sanitizer layers.

Missing behavioral coverage includes:

- multiple simultaneous connections;
- peer abort and handshake timeout;
- packet loss, reordering, and duplication;
- queue and flow-control saturation;
- retry exhaustion;
- disk-full and file-descriptor exhaustion;
- corrupted session-resumption data;
- repeated connection/task churn and long-duration soak tests.

### Resource ownership and leaks

ASan and UBSan pass, but ASan CI disables leak detection and full-process LSan
has not run in a compatible environment. The code still contains unresolved
ownership notes around stream queues, task buffers, TLS contexts, external
`sk_buff` data, and error-path cleanup.

Required work:

1. Document owned and borrowed references for every connection, stream, task,
   TLS, session, packet, and queue object.
2. Establish create/destroy symmetry and test every failure path.
3. Run complete executable and integration suites under LSan outside ptrace.
4. Add repeated lifecycle tests that check for sustained heap growth.

### Wire-format portability

The protocol currently serializes native C structures, including a `size_t`
field, and therefore depends on native pointer width, byte order, padding, and
compiler ABI. ARM64 compilation alone would not prove protocol interoperability
with x86_64.

Required work:

1. Replace native-layout wire structures with fixed-width integers.
2. Define byte order for every numeric field.
3. Add explicit encode/decode functions rather than sending structure memory.
4. Add golden protocol vectors and cross-architecture parser tests.
5. Version the wire format before compatibility becomes harder to change.

## Build-system assessment

The top-level CMake currently applies `-g -O0` and several warning suppressions
globally. This undermines Release semantics and hides potentially important
diagnostics such as ignored results. Global include and link directories also
make dependency provenance less explicit.

Recommended improvements:

- let CMake build types control optimization and debug information;
- move options and definitions to individual targets;
- restore important warnings and add a main-program `-Werror` CI build;
- use imported targets and explicit system-library discovery;
- include runner OS, architecture, and compiler information in dependency cache
  keys or publish dependency artifacts from a dedicated job.

## Maintainability assessment

The main source tree is approximately 8,900 lines, with substantial logic
concentrated in a few files:

- `service.c`: approximately 1,250 lines;
- `upstream.c`: approximately 1,000 lines;
- `task.c`: approximately 950 lines;
- `client.c`: approximately 825 lines;
- `server.c`: approximately 620 lines.

New features should not continue accumulating in these files. Gradual splits
into TLS, engine, packet, stream I/O, protocol codec, session storage, send-file,
and performance modules would reduce ownership ambiguity and improve focused
testing.

## Configuration and operations

Important behavior remains hard-coded: port, CPU affinity, retry policy,
timeouts, host, and stream actions. Environment variables currently cover only
the needs of development and integration tests.

Production-oriented configuration eventually needs:

- listen/connect addresses and ports;
- CA, certificate, key, secure/insecure, and optional mTLS policy;
- timeout and quota settings;
- configurable or disabled CPU affinity;
- session, keylog, receive, and control-socket paths;
- structured log levels, metrics, health checks, and stable error codes.

Automatically generated certificates are appropriate for development and tests,
not as a production trust model.

## Cross-architecture status

Only the `main` branch exists; the repository does not provide the separate
`x86_64` and `arm64` branches expected by the shared-architecture workflow.
Current evidence supports the following claims only:

- x86_64 builds and tests continuously;
- ARM64 library/link paths exist;
- ARM64 compilation and tests are not continuously verified;
- x86_64/ARM64 protocol interoperability is unverified.

ARM64 should therefore be described as a prepared code path, not a supported
platform.

## Recommended execution order

### Phase 1: security and real failure behavior

1. Enable authenticated TLS and add negative certificate tests.
2. Correct connection-close and final-result ordering.
3. Stabilize peer-loss injection and run it in CI.
4. Add peer-abort, timeout, queue-pressure, and connection-isolation tests.

### Phase 2: ownership and protocol

5. Complete full-process LSan validation.
6. Formalize object ownership and close all error-path leaks.
7. Introduce a fixed-width, fixed-byte-order protocol codec.
8. Add golden vectors and cross-architecture parsing tests.

### Phase 3: engineering quality

9. Correct Release semantics and move CMake settings to targets.
10. Restore critical compiler warnings and add a `-Werror` gate.
11. Split oversized source modules along ownership boundaries.
12. Add ARM64 compile, unit, and integration CI.

### Phase 4: productization

13. Add a formal CLI and configuration schema.
14. Add structured logging, metrics, health checks, and stable errors.
15. Add installation, packaging, compatibility, and upgrade policy.
16. Establish performance benchmarks, soak tests, and a capacity model.

## Final assessment

ACE's normal QUIC data path is now real, repeatable, and continuously tested.
Its limiting factors are no longer basic handshake or file transfer. The path
from engineering prototype to deployable service now depends on authenticated
TLS, deterministic abnormal-connection handling, proven resource ownership, and
a portable versioned wire protocol.
