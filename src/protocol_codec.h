#ifndef ACE_PROTOCOL_CODEC_H
#define ACE_PROTOCOL_CODEC_H

/*
 * ACE Protocol v1 — fixed-width, network-byte-order wire format.
 *
 * Frame header (14 bytes, every frame):
 *   magic       uint32   "ACE\x01" = 0x41434501
 *   version     uint8    1
 *   header_len  uint8    14 (allows future header extension)
 *   flags       uint16   per-frame flags (reserved)
 *   theme       uint16   TASK_THEME_*
 *   stream_id   uint16   stream index (0 = control)
 *   payload_len uint32   payload bytes following the header
 *
 * All multi-byte integers are big-endian on the wire.  Decoded values
 * are native-endian and have been range-checked.
 */

#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Wire-frame header                                                   */
/* ------------------------------------------------------------------ */

#define ACE_PROTO_MAGIC   UINT32_C(0x41434501)  /* "ACE" + version 1 */
#define ACE_PROTO_VERSION 1

/* Use uint8_t arrays + explicit offset reads to avoid any compiler
 * padding or alignment dependency. */
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

#include "define.h"  /* __attribute__((packed)) support */

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
	uint8_t  code[2];       /* uint16 be */
	uint8_t  path_len[2];   /* uint16 be */
	uint8_t  file_len[2];   /* uint16 be */
	uint8_t  type_len[2];   /* uint16 be */
	uint8_t  length[4];     /* uint32 be — was size_t! */
	/* followed by path, file, type strings */
} __attribute__((packed));

#define ACE_WIRE_SENDFILE_NEGO_LEN 12

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
/* Helpers                                                             */
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

/* ------------------------------------------------------------------ */
/* Frame encode / decode                                               */
/* ------------------------------------------------------------------ */

/* Decode a wire frame header.  Returns 0 on success, -1 if the
 * buffer is too short or the magic/version is invalid. */
static inline int ace_frame_decode(const unsigned char *buf, size_t buflen,
				   struct ace_frame *out)
{
	if (!buf || buflen < ACE_FRAME_HDR_LEN || !out)
		return -1;

	if (buf[0] != 0x41 || buf[1] != 0x43 ||
	    buf[2] != 0x45 || buf[3] != 0x01)
		return -1;  /* bad magic */

	out->version   = buf[4];
	/* header_len at buf[5] stored for future extension */

	if (out->version != ACE_PROTO_VERSION)
		return -1;

	out->flags      = ace_rd16(buf + 6);
	out->theme      = ace_rd16(buf + 8);
	out->stream_id  = ace_rd16(buf + 10);
	out->payload_len = ace_rd32(buf + 12);

	return 0;
}

/* Encode a frame header into a buffer.  buf must have at least
 * ACE_FRAME_HDR_LEN bytes. */
static inline void ace_frame_encode(unsigned char *buf,
				    const struct ace_frame *f)
{
	buf[0]  = 0x41; buf[1] = 0x43; buf[2] = 0x45; buf[3] = 0x01;
	buf[4]  = ACE_PROTO_VERSION;
	buf[5]  = ACE_FRAME_HDR_LEN;
	ace_wr16(buf +  6, f->flags);
	ace_wr16(buf +  8, f->theme);
	ace_wr16(buf + 10, f->stream_id);
	ace_wr32(buf + 12, f->payload_len);
}

/* ------------------------------------------------------------------ */
/* Payload encode / decode                                             */
/* ------------------------------------------------------------------ */

/* Decoded sendfile negotiation — strings point into the wire buffer.
 * All integer fields are in native byte order and validated. */
struct ace_sendfile_nego {
	uint16_t       code;
	const char    *path;         /* not NUL-terminated in wire buf */
	const char    *file;         /* not NUL-terminated */
	const char    *type;         /* not NUL-terminated */
	uint16_t       path_len;
	uint16_t       file_len;
	uint16_t       type_len;
	uint32_t       file_length;  /* was size_t */
};

/* Decode a sendfile negotiation from a wire buffer.  Returns 0 on
 * success, -1 on malformed input.  Strings in *out point into buf. */
int ace_sendfile_nego_decode(const unsigned char *buf, size_t buflen,
			     struct ace_sendfile_nego *out);

/* Decoded perf negotiation. */
struct ace_perf_nego {
	uint16_t code;
	uint16_t dual;
};

static inline int ace_perf_nego_decode(const unsigned char *buf,
				       size_t buflen,
				       struct ace_perf_nego *out)
{
	if (!buf || buflen < ACE_WIRE_PERF_NEGO_LEN)
		return -1;
	if (out) {
		out->code = ace_rd16(buf);
		out->dual = ace_rd16(buf + 2);
	}
	return 0;
}

/* Decoded probe.  data/data_length point into the wire buffer. */
struct ace_probe {
	uint64_t       magic;
	uint64_t       nonce;
	uint32_t       checksum;
	const unsigned char *data;
	uint32_t       data_length;
};

int ace_probe_decode(const unsigned char *buf, size_t buflen,
		     struct ace_probe *out);

/* Encode frame + sendfile nego into a pre-allocated buffer.
 * Returns total encoded length, or 0 on overflow. */
size_t ace_sendfile_nego_encode(unsigned char *buf, size_t bufsz,
				uint16_t stream_id,
				const struct ace_sendfile_nego *nego);

/* Encode frame + perf nego. */
size_t ace_perf_nego_encode(unsigned char *buf, size_t bufsz,
			    uint16_t stream_id,
			    const struct ace_perf_nego *nego);

/* Encode frame + probe. */
size_t ace_probe_encode(unsigned char *buf, size_t bufsz,
			uint16_t stream_id,
			const struct ace_probe *probe);

#endif /* ACE_PROTOCOL_CODEC_H */
