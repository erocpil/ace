#include <stddef.h>
#include <stdint.h>
#include "task_protocol.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct upstream_skb_head head;
	int status = task_frame_validate(data, size, &head);
	if (status == 1) {
		task_payload_validate(&head, data + ACE_FRAME_HDR_LEN);
	}
	return 0;
}
