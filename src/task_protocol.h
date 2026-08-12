#ifndef ACE_TASK_PROTOCOL_H
#define ACE_TASK_PROTOCOL_H

/*
 * ACE Protocol v1 — wire format uses protocol_codec.h.
 * This header retains internal helpers and the validation API that
 * callers use, now backed by the fixed-width codec.
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "resource_limits.h"
#include "protocol_codec.h"

#define TASK_MAX_FRAME_SIZE   (64U * 1024U)
#define TASK_MAX_DATA_STREAMS (ACE_MAX_TASK_STREAMS - 1U)
#define TASK_MAX_FILE_SIZE    ACE_MAX_FILE_SIZE
#define TASK_MAX_TYPE_LENGTH  1024U
#define TASK_RECEIVE_ROOT     "received"

enum {
	TASK_THEME_SENDFILE = 0,
	TASK_THEME_PERF,
	TASK_THEME_PROBE,
	TASK_THEME_MAX,
};

#define TASK_PROBE_MAGIC     UINT64_C(0x4143455155494350)
#define TASK_PROBE_DATA_SIZE 4096U

/* ------------------------------------------------------------------ */
/* Legacy internal header — used inside sk_buff for bookkeeping.      */
/* NOT a wire format.  Wire format is struct ace_frame (14 bytes).    */
/* ------------------------------------------------------------------ */

struct upstream_skb_head {
	uint32_t length;       /* payload length (<= TASK_MAX_FRAME_SIZE) */
	uint16_t theme;        /* TASK_THEME_* */
	uint16_t serial;       /* stream index */
};

/* ------------------------------------------------------------------ */
/* Checksum                                                            */
/* ------------------------------------------------------------------ */

static inline uint32_t task_checksum32(const void *data, size_t length)
{
	const unsigned char *bytes = data;
	uint32_t hash = UINT32_C(2166136261);
	for (size_t i = 0; i < length; ++i) {
		hash = (hash ^ bytes[i]) * UINT32_C(16777619);
	}
	return hash;
}

/* ------------------------------------------------------------------ */
/* String / filename helpers                                           */
/* ------------------------------------------------------------------ */

static inline int task_protocol_c_string(const unsigned char *value,
					 size_t length)
{
	return length > 0 && value[length - 1] == '\0' &&
		memchr(value, '\0', length - 1) == NULL;
}

static inline int task_filename_validate(const char *name)
{
	size_t length;

	if (!name)
		return -1;
	length = strlen(name);
	if (length == 0 || length > NAME_MAX || name[0] == '.' ||
	    strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		return -1;
	for (size_t i = 0; i < length; ++i) {
		unsigned char c = (unsigned char)name[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
			return -1;
	}
	return 0;
}

static inline int task_receive_path(char *output, size_t output_size,
				    const char *root, const char *name)
{
	size_t root_length, name_length;

	if (!output || !root || task_filename_validate(name) != 0)
		return -1;
	root_length = strlen(root);
	name_length = strlen(name);
	if (root_length == 0 || root_length + 2 > output_size ||
	    name_length > output_size - root_length - 2)
		return -1;
	memcpy(output, root, root_length);
	output[root_length] = '/';
	memcpy(output + root_length + 1, name, name_length + 1);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Frame validation (v1 codec)                                         */
/* ------------------------------------------------------------------ */

/* Returns 1 for a complete valid frame, 0 when more bytes are needed,
 * -1 for malformed input.  out is filled with the decoded frame
 * descriptor (native byte order). */
static inline int task_frame_validate(const void *data, size_t available,
				      struct upstream_skb_head *out)
{
	struct ace_frame f;

	if (!data || available < ACE_FRAME_HDR_LEN)
		return 0;

	if (ace_frame_decode((const unsigned char *)data, available, &f) != 0)
		return -1;

	if (f.theme >= TASK_THEME_MAX || f.stream_id == 0 ||
	    f.stream_id > TASK_MAX_DATA_STREAMS ||
	    f.payload_len > TASK_MAX_FRAME_SIZE - ACE_FRAME_HDR_LEN)
		return -1;

	if (available < ACE_FRAME_HDR_LEN + (size_t)f.payload_len)
		return 0;

	if (out) {
		out->length = f.payload_len;
		out->theme  = f.theme;
		out->serial = f.stream_id;
	}

	return 1;
}

/* ------------------------------------------------------------------ */
/* Payload validation (v1 codec)                                       */
/* ------------------------------------------------------------------ */

static inline int task_payload_validate(const struct upstream_skb_head *head,
					const void *payload)
{
	if (!head || !payload)
		return -1;

	switch (head->theme) {
	case TASK_THEME_SENDFILE:
		return ace_sendfile_nego_decode(
			(const unsigned char *)payload,
			head->length, NULL) == 0 ? 0 : -1;
	case TASK_THEME_PERF: {
		struct ace_perf_nego nego;
		return ace_perf_nego_decode(
			(const unsigned char *)payload,
			head->length, &nego) == 0 ? 0 : -1;
	}
	case TASK_THEME_PROBE: {
		struct ace_probe probe;
		return ace_probe_decode(
			(const unsigned char *)payload,
			head->length, &probe) == 0 ? 0 : -1;
	}
	default:
		return -1;
	}
}

/* ---- Legacy validate wrappers kept for existing callers ---- */

/* These are thin wrappers over ace_*_decode() that validate without
 * producing an output struct (used by tests and existing code). */

static inline int sendfile_nego_validate(const void *payload, size_t length)
{
	return ace_sendfile_nego_decode(
		(const unsigned char *)payload, length, NULL);
}

/* ------------------------------------------------------------------ */
/* Convenience: fill upstream_skb_head from an ace_frame              */
/* ------------------------------------------------------------------ */

static inline void task_frame_to_head(const struct ace_frame *f,
				      struct upstream_skb_head *head)
{
	head->length = f->payload_len;
	head->theme  = f->theme;
	head->serial = f->stream_id;
}

#endif /* ACE_TASK_PROTOCOL_H */
