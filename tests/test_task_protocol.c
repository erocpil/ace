#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "task_protocol.h"

struct sendfile_frame {
	struct upstream_skb_head frame;
	struct sendfile_nego nego;
	char strings[32];
};

static size_t valid_sendfile_frame(struct sendfile_frame *value)
{
	const char path[] = "tmp";
	const char file[] = "data.bin";
	const char type[] = "binary";
	unsigned char *p = (unsigned char *)value->strings;

	memset(value, 0, sizeof(*value));
	value->frame.theme = TASK_THEME_SENDFILE;
	value->frame.serial = 3;
	value->nego.path_len = sizeof(path);
	value->nego.file_len = sizeof(file);
	value->nego.type_len = sizeof(type);
	value->nego.length = 4096;
	memcpy(p, path, sizeof(path));
	p += sizeof(path);
	memcpy(p, file, sizeof(file));
	p += sizeof(file);
	memcpy(p, type, sizeof(type));
	value->frame.length = sizeof(value->nego) + sizeof(path) + sizeof(file) + sizeof(type);
	return sizeof(value->frame) + value->frame.length;
}

static void test_frame_validation(void)
{
	struct sendfile_frame value;
	struct upstream_skb_head head;
	size_t length = valid_sendfile_frame(&value);

	assert(task_frame_validate(&value, sizeof(value.frame) - 1, &head) == 0);
	assert(task_frame_validate(&value, length - 1, &head) == 0);
	assert(task_frame_validate(&value, length, &head) == 1);
	assert(head.length == value.frame.length);
	value.frame.theme = TASK_THEME_MAX;
	assert(task_frame_validate(&value, length, NULL) == -1);
	value.frame.theme = TASK_THEME_SENDFILE;
	value.frame.serial = 0;
	assert(task_frame_validate(&value, length, NULL) == -1);
	value.frame.serial = TASK_MAX_DATA_STREAMS + 1;
	assert(task_frame_validate(&value, length, NULL) == -1);
	value.frame.serial = 1;
	value.frame.length = TASK_MAX_FRAME_SIZE;
	assert(task_frame_validate(&value, length, NULL) == -1);
	valid_sendfile_frame(&value);
	for (size_t i = 0; i < length; ++i) {
		assert(task_frame_validate(&value, i, NULL) == 0);
	}
}

static void test_sendfile_validation(void)
{
	struct sendfile_frame value;
	struct upstream_skb_head head;
	size_t length = valid_sendfile_frame(&value);
	unsigned char *payload = (unsigned char *)&value.nego;

	assert(task_frame_validate(&value, length, &head) == 1);
	assert(task_payload_validate(&head, payload) == 0);
	value.nego.length = 0;
	assert(task_payload_validate(&head, payload) == -1);
	value.nego.length = TASK_MAX_FILE_SIZE + 1ULL;
	assert(task_payload_validate(&head, payload) == -1);
	value.nego.length = 4096;
	value.nego.path_len++;
	assert(task_payload_validate(&head, payload) == -1);
	value.nego.path_len--;
	value.strings[value.nego.path_len - 1] = 'x';
	assert(task_payload_validate(&head, payload) == -1);
}

static void test_resource_limits(void)
{
	assert(ace_quota_can_add(ACE_MAX_UPSTREAM_QUEUE - 1, ACE_MAX_UPSTREAM_QUEUE));
	assert(!ace_quota_can_add(ACE_MAX_UPSTREAM_QUEUE, ACE_MAX_UPSTREAM_QUEUE));
	assert(ace_task_memory_valid(ACE_MAX_TASK_STREAMS, 1));
	assert(!ace_task_memory_valid(ACE_MAX_TASK_STREAMS + 1U, 1));
	assert(ace_task_memory_valid(4, ACE_MAX_TASK_MEMORY / 4));
	assert(!ace_task_memory_valid(4, ACE_MAX_TASK_MEMORY / 4 + 1));
}

static void test_perf_validation(void)
{
	struct upstream_skb_head head = {
		.length = sizeof(struct perf_nego),
		.theme = TASK_THEME_PERF,
		.serial = 1,
	};
	struct perf_nego perf = { 0 };

	assert(task_payload_validate(&head, &perf) == 0);
	head.length++;
	assert(task_payload_validate(&head, &perf) == -1);
}

static void test_probe_validation(void)
{
	struct {
		struct task_probe probe;
		unsigned char data[4];
	} payload = {
		.probe = {
			.magic = TASK_PROBE_MAGIC,
			.nonce = 42,
			.data_length = 4,
		},
		.data = {1, 2, 3, 4},
	};
	struct upstream_skb_head head = {
		.length = sizeof(payload.probe) + sizeof(payload.data),
		.theme = TASK_THEME_PROBE,
		.serial = 1,
	};
	payload.probe.checksum = task_checksum32(payload.data, sizeof(payload.data));

	assert(task_payload_validate(&head, &payload) == 0);
	payload.data[2] ^= 1;
	assert(task_payload_validate(&head, &payload) == -1);
	payload.data[2] ^= 1;
	payload.probe.data_length++;
	assert(task_payload_validate(&head, &payload) == -1);
	payload.probe.data_length--;
	head.length--;
	assert(task_payload_validate(&head, &payload) == -1);
}

static void test_receive_path(void)
{
	char path[64];

	assert(task_receive_path(path, sizeof(path), "received", "data-01.bin") == 0);
	assert(strcmp(path, "received/data-01.bin") == 0);
	assert(task_receive_path(path, sizeof(path), "received", "../data") == -1);
	assert(task_receive_path(path, sizeof(path), "received", "/tmp/data") == -1);
	assert(task_receive_path(path, sizeof(path), "received", ".hidden") == -1);
	assert(task_receive_path(path, sizeof(path), "received", "a/b") == -1);
	assert(task_receive_path(path, 8, "received", "data") == -1);
}

int main(void)
{
	test_frame_validation();
	test_sendfile_validation();
	test_perf_validation();
	test_probe_validation();
	test_receive_path();
	test_resource_limits();
	return 0;
}
