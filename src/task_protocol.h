#ifndef ACE_TASK_PROTOCOL_H
#define ACE_TASK_PROTOCOL_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "resource_limits.h"

#define TASK_MAX_FRAME_SIZE (64U * 1024U)
#define TASK_MAX_DATA_STREAMS (ACE_MAX_TASK_STREAMS - 1U)
#define TASK_MAX_FILE_SIZE ACE_MAX_FILE_SIZE
#define TASK_MAX_TYPE_LENGTH 1024U
#define TASK_RECEIVE_ROOT "received"

enum {
	TASK_THEME_SENDFILE = 0,
	TASK_THEME_PERF,
	TASK_THEME_PROBE,
	TASK_THEME_MAX,
};

#define TASK_PROBE_MAGIC UINT64_C(0x4143455155494350)
#define TASK_PROBE_DATA_SIZE 4096U

struct task_probe {
	uint64_t magic;
	uint64_t nonce;
	uint32_t data_length;
	uint32_t checksum;
};

static inline uint32_t task_checksum32(const void *data, size_t length)
{
	const unsigned char *bytes = data;
	uint32_t hash = UINT32_C(2166136261);
	for (size_t i = 0; i < length; ++i) {
		hash = (hash ^ bytes[i]) * UINT32_C(16777619);
	}
	return hash;
}

struct upstream_skb_head {
	uint32_t length;
	uint16_t theme;
	uint16_t serial;
};

struct sendfile_nego {
	uint16_t code;
	uint16_t path_len;
	uint16_t file_len;
	uint16_t type_len;
	size_t length;
	char head[];
} __attribute__((aligned(sizeof(char*))));

struct perf_nego {
	uint16_t code;
	uint16_t dual;
} __attribute__((aligned(sizeof(char))));

static inline int task_protocol_c_string(const unsigned char *value, size_t length)
{
	return length > 0 && value[length - 1] == '\0' &&
		memchr(value, '\0', length - 1) == NULL;
}

static inline int task_filename_validate(const char *name)
{
	size_t length;

	if (!name) {
		return -1;
	}
	length = strlen(name);
	if (length == 0 || length > NAME_MAX || name[0] == '.' ||
			strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
		return -1;
	}
	for (size_t i = 0; i < length; ++i) {
		unsigned char c = (unsigned char)name[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) {
			return -1;
		}
	}
	return 0;
}

static inline int task_receive_path(char *output, size_t output_size,
		const char *root, const char *name)
{
	size_t root_length;
	size_t name_length;

	if (!output || !root || task_filename_validate(name) != 0) {
		return -1;
	}
	root_length = strlen(root);
	name_length = strlen(name);
	if (root_length == 0 || root_length + 2 > output_size ||
			name_length > output_size - root_length - 2) {
		return -1;
	}
	memcpy(output, root, root_length);
	output[root_length] = '/';
	memcpy(output + root_length + 1, name, name_length + 1);
	return 0;
}

/* Returns 1 for a complete valid frame, 0 when more bytes are needed, -1 for
 * malformed input. The copied header avoids unaligned accesses. */
static inline int task_frame_validate(const void *data, size_t available,
		struct upstream_skb_head *out)
{
	struct upstream_skb_head head;

	if (!data || available < sizeof(head)) {
		return 0;
	}
	memcpy(&head, data, sizeof(head));
	if (head.theme >= TASK_THEME_MAX || head.serial == 0 ||
			head.serial > TASK_MAX_DATA_STREAMS ||
			head.length > TASK_MAX_FRAME_SIZE - sizeof(head)) {
		return -1;
	}
	if (available < sizeof(head) + (size_t)head.length) {
		return 0;
	}
	if (out) {
		*out = head;
	}
	return 1;
}

static inline int sendfile_nego_validate(const void *payload, size_t length)
{
	struct sendfile_nego nego;
	size_t strings_length;
	const unsigned char *strings;

	if (!payload || length < sizeof(nego)) {
		return -1;
	}
	memcpy(&nego, payload, sizeof(nego));
	if (nego.path_len == 0 || nego.path_len > PATH_MAX ||
			nego.file_len == 0 || nego.file_len > NAME_MAX + 1U ||
			nego.type_len == 0 || nego.type_len > TASK_MAX_TYPE_LENGTH ||
			nego.length == 0 || nego.length > TASK_MAX_FILE_SIZE) {
		return -1;
	}
	strings_length = (size_t)nego.path_len + nego.file_len + nego.type_len;
	if (strings_length != length - sizeof(nego)) {
		return -1;
	}
	strings = (const unsigned char *)payload + sizeof(nego);
	if (!task_protocol_c_string(strings, nego.path_len)) {
		return -1;
	}
	strings += nego.path_len;
	if (!task_protocol_c_string(strings, nego.file_len)) {
		return -1;
	}
	strings += nego.file_len;
	return task_protocol_c_string(strings, nego.type_len) ? 0 : -1;
}

static inline int task_payload_validate(const struct upstream_skb_head *head,
		const void *payload)
{
	if (!head || !payload) {
		return -1;
	}
	switch (head->theme) {
	case TASK_THEME_SENDFILE:
		return sendfile_nego_validate(payload, head->length);
	case TASK_THEME_PERF:
		return head->length == sizeof(struct perf_nego) ? 0 : -1;
	case TASK_THEME_PROBE: {
		struct task_probe probe;
		if (head->length < sizeof(probe)) {
			return -1;
		}
		memcpy(&probe, payload, sizeof(probe));
		if (probe.magic != TASK_PROBE_MAGIC ||
				probe.data_length != head->length - sizeof(probe)) {
			return -1;
		}
		return task_checksum32((const unsigned char *)payload + sizeof(probe),
				probe.data_length) == probe.checksum ? 0 : -1;
	}
	default:
		return -1;
	}
}

#endif
