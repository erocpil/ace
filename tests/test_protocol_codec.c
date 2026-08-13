#include "../src/protocol_codec.h"
#include "../src/task_protocol.h"
#include <assert.h>
#include <string.h>

int main(void)
{
	unsigned char buf[512];

	/* ---- 1. NULL nego to ace_sendfile_nego_encode ---- */
	assert(ace_sendfile_nego_encode(buf, sizeof(buf), 0, NULL) == 0);

	/* ---- 2. NULL probe to ace_probe_encode ---- */
	assert(ace_probe_encode(buf, sizeof(buf), 0, NULL) == 0);

	/* ---- 3. probe with data_length>0 but data==NULL ---- */
	struct ace_probe probe_bad = {
		.magic = UINT64_C(0x4143455155494350),
		.nonce = 42,
		.data_length = 100,
		.data = NULL,
		.checksum = 0,
	};
	assert(ace_probe_encode(buf, sizeof(buf), 0, &probe_bad) == 0);

	/* ---- 4. probe dry-run (buf==NULL) ---- */
	const unsigned char probe_data[16] = "0123456789ABCDEF";
	struct ace_probe probe_ok = {
		.magic = UINT64_C(0x4143455155494350),
		.nonce = 1,
		.data_length = 16,
		.data = probe_data,
		.checksum = task_checksum32(probe_data, 16),
	};
	size_t dry = ace_probe_encode(NULL, 0, 0, &probe_ok);
	assert(dry == ACE_FRAME_HDR_LEN + ACE_WIRE_PROBE_LEN + 16);

	/* ---- 5. probe round-trip ---- */
	unsigned char probe_buf[256];
	size_t n = ace_probe_encode(probe_buf, sizeof(probe_buf), 0, &probe_ok);
	assert(n == ACE_FRAME_HDR_LEN + ACE_WIRE_PROBE_LEN + 16);

	struct ace_frame f;
	assert(ace_frame_decode(probe_buf, n, &f) == 0);
	assert(f.theme == 2);  /* TASK_THEME_PROBE */
	assert(f.payload_len == ACE_WIRE_PROBE_LEN + 16);

	struct ace_probe decoded;
	assert(ace_probe_decode(probe_buf + ACE_FRAME_HDR_LEN, f.payload_len, &decoded) == 0);
	assert(decoded.magic == UINT64_C(0x4143455155494350));
	assert(decoded.nonce == 1);
	assert(decoded.data_length == 16);
	assert(decoded.checksum == task_checksum32(probe_data, 16));

	/* ---- 6. sendfile_nego NULL-proof ---- */
	/* nego is checked first, so a NULL nego with any buf returns 0. */
	assert(ace_sendfile_nego_encode(probe_buf, sizeof(probe_buf), 3, NULL) == 0);

	/* ---- 7. Buffer too small ---- */
	struct ace_sendfile_chunk sfn_chunks[1] = { { .offset = 0, .size = 42 } };
	struct ace_sendfile_nego sfn = {
		.code = 1,
		.path = "/tmp/x",
		.file = "out",
		.type = "bin",
		.path_len = 6,
		.file_len = 3,
		.type_len = 3,
		.file_length = 42,
		.n_segments = 1,
		.chunks = sfn_chunks,
	};
	size_t sfn_total = ACE_FRAME_HDR_LEN + ACE_WIRE_SENDFILE_NEGO_LEN
		+ 6 + 3 + 3 + ACE_WIRE_SENDFILE_CHUNK_LEN;
	assert(ace_sendfile_nego_encode(NULL, 0, 0, &sfn) == sfn_total);
	assert(ace_sendfile_nego_encode(probe_buf, sfn_total - 1, 0, &sfn) == 0);
	assert(ace_sendfile_nego_encode(probe_buf, sfn_total, 0, &sfn) == sfn_total);

	/* ---- 8. perf dry-run and buffer sizing ---- */
	struct ace_perf_nego pfn = { .code = 1, .dual = 1 };
	size_t pfn_total = ACE_FRAME_HDR_LEN + ACE_WIRE_PERF_NEGO_LEN;
	assert(ace_perf_nego_encode(NULL, 0, 0, &pfn) == pfn_total);
	assert(ace_perf_nego_encode(probe_buf, pfn_total - 1, 0, &pfn) == 0);
	assert(ace_perf_nego_encode(probe_buf, pfn_total, 0, &pfn) == pfn_total);
	assert(ace_perf_nego_encode(probe_buf, sizeof(probe_buf), 0, NULL) == 0);

	/* ---- 9. Frame magic/version rejection ---- */
	unsigned char bad_magic[4] = {0x41, 0x43, 0x45, 0x02}; /* version 2 */
	assert(ace_frame_decode(bad_magic, 4, &f) == -1);

	/* ---- 10. Frame too short ---- */
	unsigned char short_buf[ACE_FRAME_HDR_LEN - 1];
	memset(short_buf, 0, sizeof(short_buf));
	assert(ace_frame_decode(short_buf, sizeof(short_buf), &f) == -1);

	return 0;
}
