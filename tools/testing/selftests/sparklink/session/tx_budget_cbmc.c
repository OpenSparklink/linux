// SPDX-License-Identifier: GPL-2.0-only
#include <stdbool.h>
#include <stdint.h>
typedef uint64_t u64;
#include "sle_tx_budget.h"

extern uint64_t nondet_u64(void);
extern unsigned int nondet_uint(void);

/* Direct production helper, not a second budget implementation. No locks,
 * scheduler, protocol credit, USB latency or WCET are modeled here. */
void verify_tx_budget(void)
{
	u64 start = nondet_u64(), age = 0;
	struct sl_tx_budget b = sl_tx_budget_begin(start);

	__CPROVER_assert(b.start_ns == start && !b.packets && !b.bytes &&
			 b.stop == SL_TX_BUDGET_NONE, "initial empty budget");
	for (unsigned int i = 0; i < 12; i++) {
		unsigned int length = nondet_uint();
		u64 advance = nondet_u64();
		struct sl_tx_budget before = b;
		bool accepted;

		__CPROVER_assume(advance <= 4000000ULL);
		age += advance;
		/* Absolute clock may wrap; elapsed age cannot wrap in this bound. */
		accepted = sl_tx_budget_charge(&b, length, start + age);
		__CPROVER_assert(b.start_ns == start, "origin never refreshed");
		__CPROVER_assert(b.packets <= SL_TX_QUANTUM_PACKETS &&
				 b.bytes <= SL_TX_QUANTUM_BYTES, "finite counters");
		if (accepted) {
			__CPROVER_assert(length && length <= SL_TX_QUANTUM_BYTES &&
				age < SL_TX_QUANTUM_NS && before.stop == SL_TX_BUDGET_NONE,
				"accepted only inside original service limits");
			__CPROVER_assert(b.packets == before.packets + 1 &&
				b.bytes >= before.bytes && b.bytes - before.bytes == length &&
				b.stop == SL_TX_BUDGET_NONE, "exact accepted accounting");
		} else {
			__CPROVER_assert(b.packets == before.packets && b.bytes == before.bytes &&
				b.stop != SL_TX_BUDGET_NONE, "rejection preserves accounting");
		}
		if (before.stop != SL_TX_BUDGET_NONE)
			__CPROVER_assert(!accepted && b.stop == before.stop, "stop is latched");
	}
	b = sl_tx_budget_begin(start);
	__CPROVER_assert(!b.packets && !b.bytes && b.stop == SL_TX_BUDGET_NONE,
			 "new quantum starts empty");
	__CPROVER_assert(!sl_tx_budget_charge(&b, 1, start + SL_TX_QUANTUM_NS) &&
			 !b.packets && !b.bytes && b.stop == SL_TX_BUDGET_ELAPSED,
			 "exact deadline denies next operation");
}
