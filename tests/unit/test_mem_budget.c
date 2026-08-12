/*
 * test_mem_budget.c — unit tests for ace_mem_budget
 *
 * Compile: gcc -o test_mem_budget test_mem_budget.c ../src/mem_budget.c \
 *          -I../src -Wall -Wextra -Werror -UNDEBUG
 */
#include "mem_budget.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

/* needed for skb_malloc_charged / skb_free tests */
#include "sk_buff.h"

#define TEST(name) static void name(void)
#define RUN(name) do { \
	printf("  %-40s", #name); \
	name(); \
	printf("PASS\n"); \
} while (0)

/* --- charge / release basics --- */

TEST(test_charge_release_basic)
{
	struct ace_mem_budget b;
	ace_mem_budget_init(&b, "test", 1024, NULL);

	assert(0 == ace_mem_charge(&b, 512));
	assert(b.current == 512);
	assert(b.high_water == 512);
	assert(b.n_charge_ok == 1);

	ace_mem_release(&b, 512);
	assert(b.current == 0);
	assert(b.n_release == 1);
	/* high_water persists */
	assert(b.high_water == 512);
}

TEST(test_charge_zero)
{
	struct ace_mem_budget b;
	ace_mem_budget_init(&b, "test", 1024, NULL);

	/* charging 0 is a no-op */
	assert(0 == ace_mem_charge(&b, 0));
	assert(b.current == 0);
	assert(b.n_charge_ok == 0);
}

TEST(test_charge_exceeds_limit)
{
	struct ace_mem_budget b;
	ace_mem_budget_init(&b, "test", 100, NULL);

	assert(0 == ace_mem_charge(&b, 80));
	assert(0 != ace_mem_charge(&b, 30)); /* 80+30 > 100 */
	assert(errno == ENOMEM);
	assert(b.current == 80); /* unchanged on failure */
	assert(b.n_charge_fail == 1);
}

TEST(test_charge_at_limit)
{
	struct ace_mem_budget b;
	ace_mem_budget_init(&b, "test", 100, NULL);

	assert(0 == ace_mem_charge(&b, 100));
	assert(b.current == 100);

	assert(0 != ace_mem_charge(&b, 1));
	assert(b.current == 100);
}

TEST(test_unlimited)
{
	struct ace_mem_budget b;
	ace_mem_budget_init(&b, "test", 0, NULL); /* 0 = unlimited */

	size_t big = 1024UL * 1024UL * 1024UL; /* 1 GiB */
	assert(0 == ace_mem_charge(&b, big));
	assert(b.current == big);
	ace_mem_release(&b, big);
	assert(b.current == 0);
}

TEST(test_high_water)
{
	struct ace_mem_budget b;
	ace_mem_budget_init(&b, "test", 2048, NULL);

	assert(0 == ace_mem_charge(&b, 500));
	assert(0 == ace_mem_charge(&b, 300));
	assert(b.high_water == 800);

	ace_mem_release(&b, 300);
	assert(b.current == 500);
	assert(b.high_water == 800); /* high-water persists */

	ace_mem_budget_reset_hwm(&b);
	assert(b.high_water == 500); /* reset to current */
}

TEST(test_release_underflow)
{
	struct ace_mem_budget b;
	ace_mem_budget_init(&b, "test", 1024, NULL);

	/* release more than charged — should clamp, not crash */
	ace_mem_release(&b, 100);
	assert(b.current == 0); /* clamped */
}

/* --- hierarchical budgets --- */

TEST(test_hierarchical_charge)
{
	struct ace_mem_budget parent, child;
	ace_mem_budget_init(&parent, "parent", 1000, NULL);
	ace_mem_budget_init(&child, "child", 500, &parent);

	/* charge child, parent should reflect it too */
	assert(0 == ace_mem_charge(&child, 200));
	assert(child.current == 200);
	assert(parent.current == 200);

	assert(0 == ace_mem_charge(&child, 100));
	assert(child.current == 300);
	assert(parent.current == 300);
}

TEST(test_hierarchical_parent_limit)
{
	struct ace_mem_budget parent, child;
	ace_mem_budget_init(&parent, "parent", 400, NULL);
	ace_mem_budget_init(&child, "child", 500, &parent);

	/* child limit is 500, but parent limit is 400 */
	assert(0 == ace_mem_charge(&child, 350));
	assert(0 != ace_mem_charge(&child, 100)); /* would push parent to 450 > 400 */
	assert(errno == ENOMEM);
	assert(child.current == 350); /* unchanged */
	assert(parent.current == 350); /* unchanged */
}

TEST(test_hierarchical_child_limit)
{
	struct ace_mem_budget parent, child;
	ace_mem_budget_init(&parent, "parent", 1000, NULL);
	ace_mem_budget_init(&child, "child", 100, &parent);

	/* child limit is tighter than parent */
	assert(0 == ace_mem_charge(&child, 80));
	assert(0 != ace_mem_charge(&child, 30)); /* 110 > 100 */
	assert(errno == ENOMEM);
	assert(parent.current == 80); /* parent unaffected by child failure */
}

TEST(test_hierarchical_release)
{
	struct ace_mem_budget parent, child;
	ace_mem_budget_init(&parent, "parent", 1000, NULL);
	ace_mem_budget_init(&child, "child", 500, &parent);

	assert(0 == ace_mem_charge(&child, 300));
	ace_mem_release(&child, 150);

	assert(child.current == 150);
	assert(parent.current == 150);
}

/* --- can_charge helper --- */

TEST(test_can_charge)
{
	struct ace_mem_budget parent, child;
	ace_mem_budget_init(&parent, "parent", 500, NULL);
	ace_mem_budget_init(&child, "child", 300, &parent);

	assert(ace_mem_budget_chain_can_charge(&child, 200));
	assert(ace_mem_budget_chain_can_charge(&child, 300));

	assert(0 == ace_mem_charge(&child, 250));
	assert(!ace_mem_budget_chain_can_charge(&child, 300)); /* child: 250+300 > 300 */
	assert(ace_mem_budget_chain_can_charge(&child, 50));    /* child OK: 250+50 = 300 */

	assert(!ace_mem_budget_chain_can_charge(&child, 300)); /* parent: 250+300 > 500 */
}

/* --- charge_alloc convenience --- */

TEST(test_charge_alloc)
{
	struct ace_mem_budget b;
	ace_mem_budget_init(&b, "test", 64, NULL);

	void *p = ace_mem_charge_alloc(&b, 32);
	assert(p != NULL);
	assert(b.current == 32);
	free(p);
	ace_mem_release(&b, 32);
	assert(b.current == 0);
}

TEST(test_charge_alloc_fail)
{
	struct ace_mem_budget b;
	ace_mem_budget_init(&b, "test", 20, NULL);

	/* budget exceeded */
	void *p = ace_mem_charge_alloc(&b, 100);
	assert(p == NULL);
	assert(b.current == 0); /* budget untouched */
	assert(b.n_charge_fail == 1);
}

/* --- NULL budget (graceful no-op) --- */

TEST(test_null_budget)
{
	assert(0 == ace_mem_charge(NULL, 1024));
	ace_mem_release(NULL, 1024); /* should not crash */
	assert(ace_mem_budget_chain_can_charge(NULL, 1024));
}

/* --- skb_malloc_charged integration (smoke) --- */
/* mocks the skb allocator */

struct ace_mem_budget *mock_skb_budget; /* for asserting in test */

TEST(test_skb_charged_integration)
{
	struct ace_mem_budget b;
	ace_mem_budget_init(&b, "test", 1024 * 1024, NULL);

	/* allocate a charged skb (via header inline) */
	struct sk_buff *skb = skb_malloc_charged(&b, -1); /* default 64K */
	assert(skb != NULL);
	assert(skb->budget == &b);
	assert(b.current > 0);

	/* free should auto-release */
	size_t before = b.current;
	skb_free(skb);
	assert(b.current < before); /* some memory released */
}

TEST(test_skb_charged_fail)
{
	struct ace_mem_budget b;
	ace_mem_budget_init(&b, "test", 100, NULL); /* very tight */

	/* 64K default won't fit in 100 bytes */
	errno = 0;
	struct sk_buff *skb = skb_malloc_charged(&b, -1);
	assert(skb == NULL);
	assert(errno == ENOMEM);
	assert(b.current == 0); /* budget untouched */
	assert(b.n_charge_fail == 1);
}

int main(void)
{
	printf("mem_budget tests:\n");

	RUN(test_charge_release_basic);
	RUN(test_charge_zero);
	RUN(test_charge_exceeds_limit);
	RUN(test_charge_at_limit);
	RUN(test_unlimited);
	RUN(test_high_water);
	RUN(test_release_underflow);

	printf("hierarchical budget tests:\n");

	RUN(test_hierarchical_charge);
	RUN(test_hierarchical_parent_limit);
	RUN(test_hierarchical_child_limit);
	RUN(test_hierarchical_release);

	printf("helpers & edge cases:\n");

	RUN(test_can_charge);
	RUN(test_charge_alloc);
	RUN(test_charge_alloc_fail);
	RUN(test_null_budget);

	printf("sk_buff integration:\n");

	RUN(test_skb_charged_integration);
	RUN(test_skb_charged_fail);

	printf("\nAll tests passed.\n");
	return 0;
}
