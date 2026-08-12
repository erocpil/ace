#ifndef ACE_RESOURCE_LIMITS_H
#define ACE_RESOURCE_LIMITS_H

#include <stddef.h>
#include <stdint.h>

#define ACE_MAX_FILE_SIZE (1024ULL * 1024ULL * 1024ULL)
#define ACE_MAX_TASK_STREAMS 64U
#define ACE_MAX_TASK_MEMORY (8U * 1024U * 1024U)
#define ACE_MAX_UPSTREAM_QUEUE 64U
#define ACE_MAX_STREAM_QUEUE 64U

static inline int ace_quota_can_add(uint32_t current, uint32_t limit)
{
	return current < limit;
}

static inline int ace_task_memory_valid(size_t streams, size_t bytes_per_stream)
{
	return streams <= ACE_MAX_TASK_STREAMS &&
		(bytes_per_stream == 0 || streams <= ACE_MAX_TASK_MEMORY / bytes_per_stream);
}

#endif
