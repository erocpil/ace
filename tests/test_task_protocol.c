#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "task_protocol.h"

/* ---- Wire buffer for encoded frames ---- */
static unsigned char wire[4096];

static size_t make_sendfile_frame(void)
{
	struct ace_sendfile_chunk chunks[1] = { { .offset = 0, .size = 4096 } };
	struct ace_sendfile_nego nego = {
		.code        = 0,
		.path        = "tmp",
		.path_len    = 4,   /* "tmp\0" */
		.file        = "data.bin",
		.file_len    = 9,   /* "data.bin\0" */
		.type        = "binary",
		.type_len    = 7,   /* "binary\0" */
		.file_length = 4096,
		.n_segments  = 1,
		.chunks      = chunks,
	};
	return ace_sendfile_nego_encode(wire, sizeof(wire), 3, &nego);
}

static void test_frame_validation(void)
{
	struct upstream_skb_head head;
	size_t length = make_sendfile_frame();

	/* Too short for header */
	assert(task_frame_validate(wire, ACE_FRAME_HDR_LEN - 1, &head) == 0);

	/* Too short for full frame */
	assert(task_frame_validate(wire, length - 1, &head) == 0);

	/* Valid frame */
	assert(task_frame_validate(wire, length, &head) == 1);
	assert(head.serial == 3);

	/* Bad magic */
	wire[0] = 0xFF;
	assert(task_frame_validate(wire, length, NULL) == -1);
	make_sendfile_frame();

	/* Out-of-range theme */
	wire[8] = 0xFF;
	wire[9] = 0xFF;
	assert(task_frame_validate(wire, length, NULL) == -1);
	make_sendfile_frame();

	/* stream_id == 0 invalid */
	ace_wr16(wire + 10, 0);
	assert(task_frame_validate(wire, length, NULL) == -1);
}

static void test_sendfile_validation(void)
{
	struct upstream_skb_head head;
	size_t length = make_sendfile_frame();

	assert(task_frame_validate(wire, length, &head) == 1);
	assert(task_payload_validate(&head, wire + ACE_FRAME_HDR_LEN) == 0);

	/* Corrupt length field to 0 */
	wire[ACE_FRAME_HDR_LEN + 8] = 0;
	wire[ACE_FRAME_HDR_LEN + 9] = 0;
	wire[ACE_FRAME_HDR_LEN + 10] = 0;
	wire[ACE_FRAME_HDR_LEN + 11] = 0;
	length = make_sendfile_frame();  /* get updated head.length */
	assert(task_frame_validate(wire, length, &head) == 1);
	assert(task_payload_validate(&head, wire + ACE_FRAME_HDR_LEN) == 0);
	/* Actually corrupt: */
	ace_wr32(wire + ACE_FRAME_HDR_LEN + 8, 0);
	head.length = ace_rd32(wire + 12);  /* payload_len from frame */
	wire[12] = 0; wire[13] = 0; wire[14] = 0; wire[15] = 0;
	/* invalid: file_length=0 */
	length = make_sendfile_frame();
	assert(task_frame_validate(wire, length, &head) == 1);
	/* corrupt file_length to 0 */
	ace_wr32(wire + ACE_FRAME_HDR_LEN + 8, 0);
	assert(task_frame_validate(wire, length, &head) == 1);
	assert(task_payload_validate(&head, wire + ACE_FRAME_HDR_LEN) == -1);

	/* corrupt file_length to exceed max */
	length = make_sendfile_frame();
	assert(task_frame_validate(wire, length, &head) == 1);
	ace_wr32(wire + ACE_FRAME_HDR_LEN + 8, ACE_MAX_FILE_SIZE + 1U);
	assert(task_payload_validate(&head, wire + ACE_FRAME_HDR_LEN) == -1);
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
	struct ace_perf_nego nego = { .code = 1, .dual = 1 };
	size_t length = ace_perf_nego_encode(wire, sizeof(wire), 1, &nego);
	struct upstream_skb_head head;

	assert(length > 0);
	assert(task_frame_validate(wire, length, &head) == 1);
	assert(task_payload_validate(&head, wire + ACE_FRAME_HDR_LEN) == 0);

	/* Under-sized payload (payload_len < 4) */
	ace_wr32(wire + 12, ACE_WIRE_PERF_NEGO_LEN - 1);
	head.length = ACE_WIRE_PERF_NEGO_LEN - 1;
	assert(task_payload_validate(&head, wire + ACE_FRAME_HDR_LEN) == -1);
}

static void test_probe_validation(void)
{
	unsigned char probe_data[4] = {1, 2, 3, 4};
	struct ace_probe probe = {
		.magic       = TASK_PROBE_MAGIC,
		.nonce       = 42,
		.data_length = 4,
		.checksum    = task_checksum32(probe_data, 4),
		.data        = probe_data,
	};
	size_t length = ace_probe_encode(wire, sizeof(wire), 1, &probe);
	struct upstream_skb_head head;

	assert(length > 0);
	assert(task_frame_validate(wire, length, &head) == 1);
	assert(task_payload_validate(&head, wire + ACE_FRAME_HDR_LEN) == 0);

	/* Corrupt data */
	wire[ACE_FRAME_HDR_LEN + ACE_WIRE_PROBE_LEN + 2] ^= 1;
	assert(task_payload_validate(&head, wire + ACE_FRAME_HDR_LEN) == -1);
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
