#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include "protocol_types.h"

int main(void)
{
	/* Wire structs must stay fixed-size across compilers/archs. */
	assert(sizeof(struct ace_wire_frame) == 16);
	assert(sizeof(struct ace_wire_sendfile_nego) == 14);
	assert(sizeof(struct ace_wire_sendfile_chunk) == 12);
	assert(sizeof(struct ace_wire_perf_nego) == 4);
	assert(sizeof(struct ace_wire_probe) == 24);
	assert(ACE_WIRE_SENDFILE_NEGO_LEN == 14);
	assert(ACE_WIRE_SENDFILE_CHUNK_LEN == 12);
	assert(ACE_WIRE_PERF_NEGO_LEN == 4);
	assert(ACE_WIRE_PROBE_LEN == 24);
	assert(ACE_FRAME_HDR_LEN == 16);

	/* Byte-order helpers: big-endian on the wire, round-trip exact. */
	unsigned char b16[2];
	ace_wr16(b16, 0x1234);
	assert(ace_rd16(b16) == 0x1234);
	assert(b16[0] == 0x12 && b16[1] == 0x34);   /* high byte first */
	ace_wr16(b16, 0xFFFF);
	assert(ace_rd16(b16) == 0xFFFF);

	unsigned char b32[4];
	ace_wr32(b32, 0x12345678);
	assert(ace_rd32(b32) == 0x12345678);
	assert(b32[0] == 0x12 && b32[1] == 0x34 &&
	       b32[2] == 0x56 && b32[3] == 0x78);
	ace_wr32(b32, 0xFFFFFFFF);
	assert(ace_rd32(b32) == 0xFFFFFFFF);

	unsigned char b64[8];
	ace_wr64(b64, UINT64_C(0x0123456789ABCDEF));
	assert(ace_rd64(b64) == UINT64_C(0x0123456789ABCDEF));
	assert(b64[0] == 0x01 && b64[7] == 0xEF);
	ace_wr64(b64, UINT64_C(0xFFFFFFFFFFFFFFFF));
	assert(ace_rd64(b64) == UINT64_C(0xFFFFFFFFFFFFFFFF));

	return 0;
}
