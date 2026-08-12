#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sk_buff.h"

static void test_rejects_invalid_length(void)
{
	assert(skb_malloc(-2) == NULL);
#if SSIZE_MAX > UINT32_MAX
	assert(skb_malloc((ssize_t)UINT32_MAX + 1) == NULL);
#endif
}

static void test_zero_length_buffer(void)
{
	struct sk_buff *skb = skb_malloc(0);

	assert(skb != NULL);
	assert(skb->head == NULL);
	assert(skb->data == NULL);
	assert(skb->len == 0);
	assert(skb->tail == 0);
	assert(skb->end == 0);
	skb_free(skb);
}

static void test_default_buffer(void)
{
	struct sk_buff *skb = skb_malloc(-1);

	assert(skb != NULL);
	assert(skb->head != NULL);
	assert(skb->data == skb->head);
	assert(skb->end == DEFAULT_SKB_SIZE);
	skb_free(skb);
}

static void test_boundary_operations(void)
{
	struct sk_buff *skb = skb_malloc(16);
	unsigned char *payload;

	assert(skb != NULL);
	assert(skb_reserve(skb, 4) == skb->head + 4);
	payload = skb_put(skb, 12);
	assert(payload == skb->head + 4);
	memset(payload, 0x5a, 12);
	assert(skb->len == 12);
	assert(skb->tail == 16);
	assert(skb_put(skb, 1) == NULL);
	assert(skb_reserve(skb, 1) == NULL);
	assert(skb_pull(skb, 13) == NULL);
	assert(skb_pull(skb, 12) == skb->head + 16);
	assert(skb->len == 0);
	skb_free(skb);
}

int main(void)
{
	test_rejects_invalid_length();
	test_zero_length_buffer();
	test_default_buffer();
	test_boundary_operations();
	return 0;
}
