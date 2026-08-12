#include "mem_budget.h"
#include "define.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Charge bytes against this budget and all ancestors.
 * On failure, NO bytes are charged at any level.
 */
int ace_mem_charge(struct ace_mem_budget *b, size_t bytes)
{
	if (!b || bytes == 0) {
		return 0;
	}

	/* walk up to the root to verify the whole chain can absorb the charge */
	struct ace_mem_budget *cur = b;
	while (cur) {
		if (cur->limit > 0 && cur->current + bytes > cur->limit) {
			b->n_charge_fail++;
			clog("mem_budget(%s): charge %zu failed "
			     "(current=%zu limit=%zu)",
			     b->name, bytes, cur->current, cur->limit);
			errno = ENOMEM;
			return -1;
		}
		cur = cur->parent;
	}

	/* all good — apply bottom-up */
	cur = b;
	while (cur) {
		cur->current += bytes;
		if (cur->current > cur->high_water) {
			cur->high_water = cur->current;
		}
		cur->n_charge_ok++;
		cur = cur->parent;
	}

	return 0;
}

/*
 * Release bytes from this budget and all ancestors.
 */
void ace_mem_release(struct ace_mem_budget *b, size_t bytes)
{
	if (!b || bytes == 0) {
		return;
	}

	struct ace_mem_budget *cur = b;
	while (cur) {
		if (cur->current >= bytes) {
			cur->current -= bytes;
		} else {
			/*
			 * Underflow — should never happen in correct code.
			 * Clamp to zero and log.
			 */
			clog("mem_budget(%s): release underflow "
			     "(current=%zu bytes=%zu)",
			     cur->name, cur->current, bytes);
			cur->current = 0;
		}
		cur->n_release++;
		cur = cur->parent;
	}
}

/*
 * Check entire ancestor chain.
 */
bool ace_mem_budget_chain_can_charge(const struct ace_mem_budget *b,
                                     size_t bytes)
{
	if (!b || bytes == 0) {
		return true;
	}

	const struct ace_mem_budget *cur = b;
	while (cur) {
		if (!ace_mem_budget_can_charge(cur, bytes)) {
			return false;
		}
		cur = cur->parent;
	}
	return true;
}

/*
 * Dump one line to stderr.
 */
void ace_mem_budget_dump(const struct ace_mem_budget *b)
{
	if (!b) {
		return;
	}
	blog("mem_budget(%s): cur=%-10zu limit=%-10zu hwm=%-10zu "
	     "ok=%-6lu fail=%-6lu rel=%-6lu",
	     b->name,
	     b->current,
	     b->limit,
	     b->high_water,
	     (unsigned long)b->n_charge_ok,
	     (unsigned long)b->n_charge_fail,
	     (unsigned long)b->n_release);
}
