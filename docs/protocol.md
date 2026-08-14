# ACE Protocol v1

Fixed-width, big-endian wire protocol carried over QUIC streams. This document is the
authoritative description of the frame and payload formats. The reference implementation is
`src/protocol_types.h` (wire types) and `src/protocol_codec.[ch]` (encode/decode). Golden-vector
tests against this description are tracked under P10.

## Byte order and struct layout

All multi-byte integers are big-endian on the wire. Wire structs store multi-byte fields as
`uint8_t[N]` arrays and read/write them through the `ace_rd16/32/64` / `ace_wr16/32/64` helpers,
so their layout is independent of compiler padding, alignment, and host endianness. Decoded values
are native-endian and range-checked by the codec.

## Frame

Every frame has a 16-byte header followed by a payload:

```
offset  size  field
0       4     magic       0x41 0x43 0x45 0x01  ("ACE" + version 1)
4       1     version     1
5       1     header_len  16
6       2     flags       bit flags, big-endian uint16
8       2     theme       frame type, big-endian uint16
10      2     stream_id   stream index, big-endian uint16
12      4     payload_len payload byte length, big-endian uint32
```

`magic` and `version` are fixed; a frame failing either check is rejected immediately. The
decoded descriptor is `struct ace_frame` (native order); `ace_frame_decode` / `ace_frame_encode`
convert to and from the wire form.

### Flags

```
ACE_FRAME_FLAG_LAST    = 1 << 0   final frame of a task (the "done" marker)
ACE_FRAME_FLAG_CONTROL = 1 << 1   control / capability frame
```

### Theme

```
TASK_THEME_SENDFILE = 0   single-file transfer
TASK_THEME_PERF     = 1   performance benchmark
TASK_THEME_PROBE    = 2   4096-byte echo probe
```

`theme` must be `< TASK_THEME_MAX` and `stream_id` must be in `[1, TASK_MAX_DATA_STREAMS]`;
violations are rejected by `task_frame_validate`.

## Payload formats

### Sendfile negotiation (`theme = SENDFILE`, `flags = 0`)

Fixed 18-byte header, then three NUL-terminated strings, then `n_segments` chunk-plan entries:

```
offset  size  field
0       2     code        uint16
2       2     path_len    uint16
4       2     file_len    uint16
6       2     type_len    uint16
8       4     length      uint32, total file byte length
12      2     n_segments  uint16, number of chunk-plan entries
14      4     file_hash   uint32, FNV-1a over the whole file
18      ...   path, file, type   NUL-terminated strings, in order
...     ...   chunks     n_segments × 12-byte entries
```

`path`, `file`, and `type` are `dirname`, `basename`, and `magic()` MIME type of the source path.
Each string is validated as exactly one NUL-terminated C string. `length` is the file size,
bounded by `ACE_MAX_FILE_SIZE`. `file_hash` is the sender's whole-file identity; the receiver
persists it in the `.acemeta` sidecar and refuses to resume a transfer whose current `file_hash`
differs (a same-name same-length but different-content source is retransmitted fresh, never mixed).

### Chunk-plan entry

Each entry describes one contiguous byte range carried by one data stream:

```
offset  size  field
0       8     offset   uint64, byte offset within the file
8       4     size     uint32, byte length of this segment
```

The plan must tile the file exactly: entries are contiguous, the first `offset` is 0, each
subsequent `offset` equals the prior `offset + size`, and the final `offset + size` equals
`length`. `n_segments` must not exceed `length` (otherwise a segment would be zero-length, which
the receiver cannot complete); both ends reject that. The sender builds the plan
(`sendfile_build_chunks`); the receiver validates it and drives its mmap offsets from it,
requiring `n_segments == n_sub - 1`.

### Performance negotiation (`theme = PERF`, `flags = 0`)

```
offset  size  field
0       2     code   uint16
2       2     dual   uint16
```

### Probe (`theme = PROBE`, `flags = 0`)

Fixed 24-byte header, then `data_length` bytes:

```
offset  size  field
0       8     magic        uint64 = 0x4143455155494350 ("ACEQUICP")
8       8     nonce        uint64
16      4     data_length  uint32
20      4     checksum     uint32, FNV-1a over the data
24      ...   data         data_length bytes
```

## Control frames

### Done frame (`flags = LAST`)

A frame with `flags = ACE_FRAME_FLAG_LAST` signals the end of a task. Its `theme` is the task's
theme, `stream_id` is 1, and `payload_len` is 0. The receiver of a `sf` answers the final data
segment with a done frame; the sender treats `FLAG_LAST` on the control stream as task
completion.

### Resume bitmap frame (`flags = CONTROL`)

The receiver of a sendfile negotiation answers with a resume frame when it already holds some
segments from a prior interrupted transfer (recorded in the `.acemeta` sidecar). The frame is
`theme = SENDFILE`, `flags = ACE_FRAME_FLAG_CONTROL`, `stream_id = 1`, payload = `n_segments`
bytes — one byte per segment in chunk-plan order, `1` = complete and verified (skip), `0` =
missing (retransmit). `ace_sendfile_resume_decode` rejects non-`{0,1}` bytes, an empty payload,
and `n_segments > ACE_MAX_TASK_STREAMS`.

## Checksum

`task_checksum32` is FNV-1a, 32-bit:

```
hash = 2166136261
for each byte b: hash = (hash XOR b) * 16777619   (mod 2^32)
```

It is used for probe data integrity and, per segment, for the sendfile metadata sidecar
(`.acemeta`) that drives resume. It detects accidental corruption, not deliberate tampering.

## Sendfile transfer state machine

1. Sender runs `init` (build chunk plan) then `nego` (encode nego to the control stream).
2. Receiver runs `nego` (decode) then `init`; `init` reads any prior `.acemeta` and decides
   fresh vs resume.
3. Receiver replies on the control stream: verbatim nego echo on a fresh transfer, or a
   `CONTROL` resume bitmap on resume.
4. Sender receives the reply, arms data streams (`wantwrite`), and on resume skips the segments
   flagged complete (no data sent, write side shut down).
5. When every data segment is done, the receiver sends a `FLAG_LAST` done frame.
6. Sender receives the done frame, stream 0 completes, the task exits and the connection closes.

`init` and `nego` run in opposite order on the two roles: sender is `init` → `nego`, receiver is
`nego` → `init`. Any per-task field touched by both callbacks must respect that ordering.

## Resource limits

```
ACE_MAX_TASK_STREAMS   = 64    data streams + control stream 0
TASK_MAX_DATA_STREAMS  = 63    data streams (stream_id upper bound)
TASK_MAX_FRAME_SIZE    = 64 KiB
ACE_MAX_FILE_SIZE      = 1 GiB
```
