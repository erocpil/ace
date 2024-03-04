/* a mimic of kernel's sk_buff */
#ifndef __SK_BUFF_H__
#define __SK_BUFF_H__

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "list.h"
#include "define.h"

#define DEFAULT_SKB_SIZE (0x10000) /* 64K */

/*
 * +------------+---------------+-------------+
 * |            |      len      |             |
 * +------------+---------------+-------------+
 * head*        data*           h+tail        h+end
 *                              d+len
 *
 *
 */
/**
 * Inspired by the kernel struct sk_buff
 */
struct sk_buff {
	struct list_head skb_node;
	unsigned int offset;
	unsigned int len;
	unsigned int tail;
	unsigned int end;
	unsigned char *head;
	unsigned char *data;
	/**
	 * data could be malloc()ed with sk_buff or assigned a pointer,
	 * TODO for the later case, service_sk_buff_free() will not free the pointer.
	 */
} __attribute__((aligned(sizeof(char))));

#define SKB_DUMP(skb) \
	do { \
		struct sk_buff *_skb = (skb); \
		log("skb  %p", _skb); \
		log("  skb_node  %p %p", _skb->skb_node.prev, _skb->skb_node.next); \
		log("  offset    %u", _skb->offset); \
		log("  len       %u", _skb->len); \
		log("  tail      %u", _skb->tail); \
		log("  end       %u", _skb->end); \
		log("  head      %p", _skb->head); \
		log("  data      %p", _skb->data); \
	} while (0)

static inline void skb_reset_tail_pointer(struct sk_buff *skb)
{
	skb->tail = skb->data - skb->head;
}

static inline void skb_set_tail_pointer(struct sk_buff *skb, const int offset)
{
	skb_reset_tail_pointer(skb);
	skb->tail += offset;
}

static inline void skb_set_end_offset(struct sk_buff *skb, unsigned int offset)
{
	skb->end = offset;
}

static inline unsigned char *skb_tail_pointer(const struct sk_buff *skb)
{
	return skb->head + skb->tail;
}

/**
 * skb_reserve - adjust headroom
 * @skb: buffer to alter
 * @len: bytes to move
 *
 * Increase the headroom of an empty sk_buff by reducing the tail
 * room. This is only allowed for an empty buffer.
 */
static inline void *skb_reserve(struct sk_buff *skb, unsigned int len)
{
	if (skb->tail + len > skb->end) {
		return NULL;
	}

	skb->data += len;
	skb->tail += len;

	return skb->data;
}

/**
 * skb_put - add data to a buffer
 * @skb: buffer to use
 * @len: amount of data to add
 *
 * This function extends the used data of the buffer. If this would
 * exceed the total buffer size NULL will be returned. A pointer to the
 * first byte of the extra data is returned.
 */
static void *skb_put(struct sk_buff *skb, unsigned int len)
{
	void *tmp = skb_tail_pointer(skb);

	if (unlikely(skb->tail + len > skb->end)) {
		return NULL;
	}

	skb->tail += len;
	skb->len += len;

	return tmp;
}

/**
 * skb_push - add data to the start of a buffer
 * @skb: buffer to use
 * @len: amount of data to add
 *
 * This function extends the used data area of the buffer at the buffer
 * start. If this would exceed the total buffer headroom NULL will
 * be returned. A pointer to the first byte of the extra data is returned.
 */
static inline void *skb_push(struct sk_buff *skb, unsigned int len)
{
	if (unlikely(skb->data - len < skb->head)) {
		return NULL;
	}

	skb->data -= len;
	skb->len += len;

	return skb->data;
}

/**
 * skb_pull - remove data from the start of a buffer
 * @skb: buffer to use
 * @len: amount of data to remove
 *
 * This function removes data from the start of a buffer, returning
 * the memory to the headroom. A pointer to the next data in the buffer
 * is returned. Once the data has been pulled future pushes will overwrite
 * the old data.
 */
static inline void *skb_pull(struct sk_buff *skb, unsigned int len)
{
	if (unlikely(len > skb->tail)) {
		return NULL;
	}

	skb->data += len;
	skb->len -= len;

	return skb->data;
}

static inline void skb_free(struct sk_buff *skb)
{
	if (skb) {
		// SKB_DUMP(skb);
		if ((void*)(skb + 1) != skb->head ) {
			if (skb->head) {
				free(skb->head);
			}
		}
		free(skb);
	}
}

static struct sk_buff *skb_malloc(ssize_t len)
{
	struct sk_buff *r = NULL;
	size_t size = sizeof(struct sk_buff);

	if (!len) {
		r = malloc(size);
		memset(r, 0, sizeof(struct sk_buff));
		INIT_LIST_HEAD(&r->skb_node);
		return r;
	}

	if (-1 == len) {
		len = DEFAULT_SKB_SIZE;
	}
	size += len;
	r = (struct sk_buff*)malloc(size);
	r->head = (unsigned char*)(r + 1);
	r->data = r->head;
	skb_reset_tail_pointer(r);
	skb_set_end_offset(r, len);
	memset(r, 0, offsetof(struct sk_buff, tail));
	INIT_LIST_HEAD(&r->skb_node);

	return r;
}

#endif
