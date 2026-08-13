#ifndef ACE_PROTOCOL_CODEC_H
#define ACE_PROTOCOL_CODEC_H

/*
 * ACE Protocol v1 — frame + payload codec.
 *
 * Wire types, constants, and byte-order helpers live in protocol_types.h.
 * This header provides frame encode/decode and payload encode/decode on top
 * of those types.  Decoded values are native-endian and range-checked.
 */

#include <stddef.h>
#include <stdint.h>
#include "protocol_types.h"

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
