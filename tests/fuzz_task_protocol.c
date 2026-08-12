#include <stddef.h>
#include <stdint.h>
#include "task_protocol.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct upstream_skb_head head;
	int status = task_frame_validate(data, size, &head);
	if (status == 1) {
		task_payload_validate(&head, data + sizeof(head));
	}
	return 0;
}
