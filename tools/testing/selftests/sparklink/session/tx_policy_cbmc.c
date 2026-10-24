// SPDX-License-Identifier: GPL-2.0-only
#include <stdbool.h>
#include "sle_tx_policy.h"
extern unsigned int nondet_uint(void);

/* Direct production policy. No USB, locks, credit accuracy, clocks or dynamic
 * queue changes are modeled. Bounded progress assumes each selected PDU really
 * finishes and the chosen readiness set stays eligible for 18 completions.
 */
void verify_tx_policy(void)
{
	struct sl_tx_policy zero = { 0 };
	unsigned int ready = nondet_uint() & ((1U << SL_SESSION_CHANNELS) - 1);
	unsigned int ages[SL_SESSION_CHANNELS] = { 0 };
	struct sl_tx_policy p = { nondet_uint(), nondet_uint(), nondet_uint() };

	__CPROVER_assert(!zero.fixed_next && !zero.normal_next && !zero.fixed_run,
		"zero initialized policy");
	__CPROVER_assume(p.fixed_next < SL_SESSION_CHANNELS);
	__CPROVER_assume(p.normal_next < SL_SESSION_CHANNELS);
	__CPROVER_assume(p.fixed_run <= SL_TX_FIXED_BURST);
	for (unsigned int n = 0; n < 18; n++) {
		unsigned int run = p.fixed_run;
		int slot = sl_tx_policy_choose(&p, ready);
		struct sl_tx_policy selected = p;
		unsigned int fixed = ready & ((1U << SL_FIXED_CHANNELS) - 1);
		unsigned int normal = ready & ~((1U << SL_FIXED_CHANNELS) - 1);

		__CPROVER_assert((!ready && slot == -1) || (ready && slot >= 0 &&
			slot < SL_SESSION_CHANNELS && (ready & (1U << slot))),
			"choose only eligible bounded slot");
		__CPROVER_assert(p.fixed_run == run, "selection spends no completed quota");
		__CPROVER_assert(sl_tx_policy_choose(&p, ready) == slot &&
			p.fixed_next == selected.fixed_next && p.normal_next == selected.normal_next &&
			p.fixed_run == selected.fixed_run, "credit wait retains selected turn");
		if (fixed && normal)
			__CPROVER_assert((slot < SL_FIXED_CHANNELS) == (run < SL_TX_FIXED_BURST),
				"bounded fixed priority and owed normal turn");
		if (slot < 0)
			continue;
		struct sl_tx_policy yielded = p;
		sl_tx_policy_yield(&yielded, slot);
		__CPROVER_assert(yielded.fixed_run == run, "retry yield earns no completion");
		sl_tx_policy_complete(&p, slot);
		__CPROVER_assert(p.fixed_next < SL_SESSION_CHANNELS &&
			p.normal_next < SL_SESSION_CHANNELS && p.fixed_run <= SL_TX_FIXED_BURST,
			"completion preserves finite policy state");
		__CPROVER_assert(slot < SL_FIXED_CHANNELS ? p.normal_next == selected.normal_next :
			p.fixed_next == selected.fixed_next, "independent class cursors");
		for (unsigned int i = 0; i < SL_SESSION_CHANNELS; i++) {
			if (i == (unsigned int)slot)
				ages[i] = 0;
			else if (ready & (1U << i))
				ages[i]++;
			__CPROVER_assert(ages[i] < 18, "all continuously ready slots progress in bounded completions");
		}
	}
}
