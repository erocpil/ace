#include "protocol_codec.h"
#include "resource_limits.h"
#include "task_protocol.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/* Sendfile nego decode                                                */
/* ------------------------------------------------------------------ */

int ace_sendfile_nego_decode(const unsigned char *buf, size_t buflen,
			     struct ace_sendfile_nego *out)
{
	size_t strings_len;
	const unsigned char *strings;
	uint16_t code, path_len, file_len, type_len;
	uint32_t file_length;

	if (!buf || buflen < ACE_WIRE_SENDFILE_NEGO_LEN)
		return -1;

	code        = ace_rd16(buf);
	path_len    = ace_rd16(buf + 2);
	file_len    = ace_rd16(buf + 4);
	type_len    = ace_rd16(buf + 6);
	file_length = ace_rd32(buf + 8);

	/* Validate ranges */
	if (path_len == 0 || path_len > 4096 ||
	    file_len == 0 || file_len > 256 ||
	    type_len == 0 || type_len > 1024 ||
	    file_length == 0 ||
	    file_length > ACE_MAX_FILE_SIZE)
		return -1;

	strings_len = (size_t)path_len + file_len + type_len;
	if (strings_len != buflen - ACE_WIRE_SENDFILE_NEGO_LEN)
		return -1;

	strings = buf + ACE_WIRE_SENDFILE_NEGO_LEN;

	/* Validate C-string-ness */
	if (strings[path_len - 1] != '\0' ||
	    strings[path_len + file_len - 1] != '\0' ||
	    strings[path_len + file_len + type_len - 1] != '\0')
		return -1;

	if (out) {
		out->code        = code;
		out->path_len    = path_len;
		out->file_len    = file_len;
		out->type_len    = type_len;
		out->file_length = file_length;
		out->path = (const char *)strings;
		out->file = (const char *)(strings + path_len);
		out->type = (const char *)(strings + path_len + file_len);
	}

	return 0;
}

/* ------------------------------------------------------------------ */
/* Probe decode                                                        */
/* ------------------------------------------------------------------ */

int ace_probe_decode(const unsigned char *buf, size_t buflen,
		     struct ace_probe *out)
{
	uint64_t magic, nonce;
	uint32_t data_length, checksum;

	if (!buf || buflen < ACE_WIRE_PROBE_LEN)
		return -1;

	magic       = ace_rd64(buf);
	nonce       = ace_rd64(buf + 8);
	data_length = ace_rd32(buf + 16);
	checksum    = ace_rd32(buf + 20);

	if (magic != UINT64_C(0x4143455155494350)) /* "ACEQUICP" */
		return -1;

	if (buflen != ACE_WIRE_PROBE_LEN + data_length)
		return -1;

	/* Validate checksum */
	if (task_checksum32(buf + ACE_WIRE_PROBE_LEN, data_length) != checksum)
		return -1;

	if (out) {
		out->magic       = magic;
		out->nonce       = nonce;
		out->data_length = data_length;
		out->checksum    = checksum;
		out->data        = buf + ACE_WIRE_PROBE_LEN;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* Encode helpers                                                      */
/* ------------------------------------------------------------------ */

size_t ace_sendfile_nego_encode(unsigned char *buf, size_t bufsz,
				uint16_t stream_id,
				const struct ace_sendfile_nego *nego)
{
	if (!nego)
		return 0;

	size_t total = ACE_FRAME_HDR_LEN + ACE_WIRE_SENDFILE_NEGO_LEN +
		       (size_t)nego->path_len + nego->file_len + nego->type_len;

	if (!buf || bufsz < total)
		return 0;

	unsigned char *p = buf;

	/* Frame header */
	struct ace_frame f = {
		.payload_len = (uint32_t)(total - ACE_FRAME_HDR_LEN),
		.theme       = 0,  /* TASK_THEME_SENDFILE */
		.stream_id   = stream_id,
		.flags       = 0,
		.version     = ACE_PROTO_VERSION,
	};
	ace_frame_encode(p, &f);
	p += ACE_FRAME_HDR_LEN;

	/* Nego */
	ace_wr16(p,      nego->code);
	ace_wr16(p + 2,  nego->path_len);
	ace_wr16(p + 4,  nego->file_len);
	ace_wr16(p + 6,  nego->type_len);
	ace_wr32(p + 8,  nego->file_length);
	p += ACE_WIRE_SENDFILE_NEGO_LEN;

	memcpy(p, nego->path, nego->path_len);
	p += nego->path_len;
	memcpy(p, nego->file, nego->file_len);
	p += nego->file_len;
	memcpy(p, nego->type, nego->type_len);

	return total;
}

size_t ace_perf_nego_encode(unsigned char *buf, size_t bufsz,
			    uint16_t stream_id,
			    const struct ace_perf_nego *nego)
{
	size_t total = ACE_FRAME_HDR_LEN + ACE_WIRE_PERF_NEGO_LEN;

	if (!buf || bufsz < total || !nego)
		return 0;

	unsigned char *p = buf;

	struct ace_frame f = {
		.payload_len = ACE_WIRE_PERF_NEGO_LEN,
		.theme       = 1,  /* TASK_THEME_PERF */
		.stream_id   = stream_id,
		.flags       = 0,
		.version     = ACE_PROTO_VERSION,
	};
	ace_frame_encode(p, &f);
	p += ACE_FRAME_HDR_LEN;

	ace_wr16(p,     nego->code);
	ace_wr16(p + 2, nego->dual);

	return total;
}

size_t ace_probe_encode(unsigned char *buf, size_t bufsz,
			uint16_t stream_id,
			const struct ace_probe *probe)
{
	if (!probe)
		return 0;

	/* If probe declares payload, the data pointer must be valid. */
	if (probe->data_length > 0 && !probe->data)
		return 0;

	size_t total = ACE_FRAME_HDR_LEN + ACE_WIRE_PROBE_LEN + probe->data_length;

	/* buf==NULL is a dry-run: return required size without writing. */
	if (!buf)
		return total;

	if (bufsz < total)
		return 0;

	unsigned char *p = buf;

	struct ace_frame f = {
		.payload_len = (uint32_t)(total - ACE_FRAME_HDR_LEN),
		.theme       = 2,  /* TASK_THEME_PROBE */
		.stream_id   = stream_id,
		.flags       = 0,
		.version     = ACE_PROTO_VERSION,
	};
	ace_frame_encode(p, &f);
	p += ACE_FRAME_HDR_LEN;

	ace_wr64(p,      probe->magic);
	ace_wr64(p + 8,  probe->nonce);
	ace_wr32(p + 16, probe->data_length);
	ace_wr32(p + 20, probe->checksum);
	p += ACE_WIRE_PROBE_LEN;

	if (probe->data_length > 0 && probe->data)
		memcpy(p, probe->data, probe->data_length);

	return total;
}
