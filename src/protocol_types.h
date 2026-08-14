#ifndef ACE_PROTOCOL_TYPES_H
#define ACE_PROTOCOL_TYPES_H

/*
 * ACE Protocol v1 — fixed-width, network-byte-order wire types.
 *
 * All multi-byte integers are big-endian on the wire.  Wire structs use
 * byte arrays + explicit offset reads so their layout is independent of
 * compiler padding, alignment, and host endianness — the property that
 * makes cross-architecture golden vectors possible (P10).
 */

#include <stdint.h>
#include "define.h"  /* __attribute__((packed)) */

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define ACE_PROTO_MAGIC   UINT32_C(0x41434501)  /* "ACE" + version 1 */
#define ACE_PROTO_VERSION 1

#define ACE_FRAME_HDR_LEN  16

enum {
	ACE_FRAME_FLAG_NONE      = 0,
	ACE_FRAME_FLAG_LAST      = 1 << 0,   /* final frame of a task */
	ACE_FRAME_FLAG_CONTROL   = 1 << 1,   /* control/capability frame */
};

/* Decoded frame descriptor — all fields in native byte order. */
struct ace_frame {
	uint32_t  payload_len;    /* bytes after header */
	uint16_t  theme;          /* TASK_THEME_* */
	uint16_t  stream_id;      /* stream index */
	uint16_t  flags;
	uint8_t   version;
};

/* ------------------------------------------------------------------ */
/* Wire structs (packed, big-endian)                                   */
/* ------------------------------------------------------------------ */

struct ace_wire_frame {
	unsigned char magic[4];       /* 0x41 0x43 0x45 0x01 */
	uint8_t       version;
	uint8_t       header_len;
	uint8_t       flags[2];       /* big-endian uint16 */
	uint8_t       theme[2];       /* big-endian uint16 */
	uint8_t       stream_id[2];   /* big-endian uint16 */
	uint8_t       payload_len[4]; /* big-endian uint32 */
} __attribute__((packed));

/* sendfile negotiation payload */
struct ace_wire_sendfile_nego {
	uint8_t  code[2];          /* uint16 be */
	uint8_t  path_len[2];      /* uint16 be */
	uint8_t  file_len[2];      /* uint16 be */
	uint8_t  type_len[2];      /* uint16 be */
	uint8_t  length[4];        /* uint32 be — was size_t! */
	uint8_t  n_segments[2];    /* uint16 be — number of chunk-plan entries */
	uint8_t  file_hash[4];     /* uint32 be — FNV-1a over the whole file */
	/* followed by path, file, type strings, then n_segments chunk entries */
} __attribute__((packed));

/* One chunk-plan entry: a contiguous byte range carried by one stream. */
struct ace_wire_sendfile_chunk {
	uint8_t  offset[8];        /* uint64 be — byte offset within the file */
	uint8_t  size[4];          /* uint32 be — byte length of this segment */
} __attribute__((packed));

#define ACE_WIRE_SENDFILE_NEGO_LEN 18
#define ACE_WIRE_SENDFILE_CHUNK_LEN 12

/* perf negotiation payload */
struct ace_wire_perf_nego {
	uint8_t  code[2];       /* uint16 be */
	uint8_t  dual[2];       /* uint16 be */
} __attribute__((packed));

#define ACE_WIRE_PERF_NEGO_LEN 4

/* probe payload (unchanged from v0, already fixed-width) */
struct ace_wire_probe {
	uint8_t  magic[8];      /* uint64 be — TASK_PROBE_MAGIC */
	uint8_t  nonce[8];      /* uint64 be */
	uint8_t  data_length[4];/* uint32 be */
	uint8_t  checksum[4];   /* uint32 be */
	/* followed by data_length bytes of random data */
} __attribute__((packed));

#define ACE_WIRE_PROBE_LEN 24

/* ------------------------------------------------------------------ */
/* Byte-order helpers                                                  */
/* ------------------------------------------------------------------ */

/* Read big-endian uint16 from 2-byte array. */
static inline uint16_t ace_rd16(const unsigned char p[2])
{
	return ((uint16_t)p[0] << 8) | p[1];
}

/* Write big-endian uint16 to 2-byte array. */
static inline void ace_wr16(unsigned char p[2], uint16_t v)
{
	p[0] = (unsigned char)(v >> 8);
	p[1] = (unsigned char)(v & 0xFF);
}

/* Read big-endian uint32 from 4-byte array. */
static inline uint32_t ace_rd32(const unsigned char p[4])
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] <<  8) |  p[3];
}

/* Write big-endian uint32 to 4-byte array. */
static inline void ace_wr32(unsigned char p[4], uint32_t v)
{
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)((v >> 16) & 0xFF);
	p[2] = (unsigned char)((v >>  8) & 0xFF);
	p[3] = (unsigned char)(v & 0xFF);
}

/* Read big-endian uint64 from 8-byte array. */
static inline uint64_t ace_rd64(const unsigned char p[8])
{
	return ((uint64_t)ace_rd32(p) << 32) | ace_rd32(p + 4);
}

/* Write big-endian uint64 to 8-byte array. */
static inline void ace_wr64(unsigned char p[8], uint64_t v)
{
	ace_wr32(p,     (uint32_t)(v >> 32));
	ace_wr32(p + 4, (uint32_t)(v & 0xFFFFFFFF));
}

#endif /* ACE_PROTOCOL_TYPES_H */
