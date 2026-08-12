/*
 * ace_mem_budget.h — Layered Memory Budget
 *
 * Rule: charge before allocate, release after free.
 * A budget rejected at any layer propagates upward as a rejection.
 *
 * Limitation: ACE can only account for ACE-allocated memory.
 * lsquic and BoringSSL internal allocations are NOT tracked.
 * Counters should be read as "ACE-owned accounted bytes".
 */
#ifndef ACE_MEM_BUDGET_H
#define ACE_MEM_BUDGET_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* --- default limits --- */

#define ACE_MEM_DEFAULT_STREAM_BUDGET   (256U * 1024U)   /* per-stream RX or TX   */
#define ACE_MEM_DEFAULT_CONN_BUDGET     (4U * 1024U * 1024U)   /* per-connection       */
#define ACE_MEM_DEFAULT_SERVICE_BUDGET  (64U * 1024U * 1024U)  /* per-service (engine) */
#define ACE_MEM_DEFAULT_PROCESS_BUDGET  (256U * 1024U * 1024U) /* per-process          */

/* --- budget structure --- */

struct ace_mem_budget {
	const char    *name;           /* human-readable label for logging           */
	size_t         limit;          /* hard cap, 0 = unlimited                    */
	size_t         current;        /* bytes currently charged                    */
	size_t         high_water;     /* peak observed                             */
	uint64_t       n_charge_ok;    /* successful charge calls                   */
	uint64_t       n_charge_fail;  /* rejected charge calls                     */
	uint64_t       n_release;      /* release calls                             */
	struct ace_mem_budget *parent; /* NULL for root budgets                     */
};

/* --- API --- */

/*
 * Initialise a budget.  Set limit=0 for unlimited.
 * parent may be NULL for a root budget.
 */
static inline void ace_mem_budget_init(struct ace_mem_budget *b,
                                       const char *name,
                                       size_t limit,
                                       struct ace_mem_budget *parent)
{
	memset(b, 0, sizeof(*b));
	b->name   = name;
	b->limit  = limit;
	b->parent = parent;
}

/*
 * Charge `bytes` against this budget and all ancestors.
 * Returns 0 on success, -1 on failure (errno=ENOMEM).
 * On failure NO bytes are charged anywhere.
 */
int ace_mem_charge(struct ace_mem_budget *b, size_t bytes);

/*
 * Release `bytes` from this budget and all ancestors.
 * Must never release more than was charged (debug builds assert).
 */
void ace_mem_release(struct ace_mem_budget *b, size_t bytes);

/*
 * Convenience: charge + allocate.  Returns NULL on failure.
 * On failure budget is NOT touched and errno is set.
 */
static inline void *ace_mem_charge_alloc(struct ace_mem_budget *b, size_t bytes)
{
	if (0 != ace_mem_charge(b, bytes)) {
		return NULL;
	}
	void *p = malloc(bytes);
	if (!p) {
		ace_mem_release(b, bytes);
		return NULL;
	}
	return p;
}

/*
 * Dump budget state to stderr (one line).
 */
void ace_mem_budget_dump(const struct ace_mem_budget *b);

/*
 * Reset high_water to current (for periodic reporting).
 */
static inline void ace_mem_budget_reset_hwm(struct ace_mem_budget *b)
{
	b->high_water = b->current;
}

/*
 * Returns true if the budget would accept `bytes` today (also checks ancestors).
 */
static inline bool ace_mem_budget_can_charge(const struct ace_mem_budget *b, size_t bytes)
{
	return b->limit == 0 || b->current + bytes <= b->limit;
}

/*
 * Check entire ancestor chain.
 */
bool ace_mem_budget_chain_can_charge(const struct ace_mem_budget *b, size_t bytes);

#endif /* ACE_MEM_BUDGET_H */
