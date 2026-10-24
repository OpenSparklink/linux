/* SPDX-License-Identifier: GPL-2.0-only */
/* Actual production header; Linux jiffies signed-difference dependency.
 * Unsigned clock wrap is intentional C modulo arithmetic, not an overflow bug.
 * Deadlines/elapsed are <=5000 ticks, inside the signed half-range on32/64bit.
 */
#include <stdbool.h>
#define time_after_eq(a,b) ((long)((a)-(b)) >= 0)
#include "sle_session_schedule.h"
_Static_assert(sizeof(unsigned long)*8 == EXPECTED_CLOCK_BITS, "expected jiffies word width");
extern unsigned long nondet_ulong(void);
void verify_original_deadlines(void)
{
	unsigned long base=nondet_ulong(), elapsed=nondet_ulong();
	__CPROVER_assume(elapsed<=5000);
	unsigned long now=base+elapsed;
	struct sl_session_schedule p={0};
	__CPROVER_assert(!p.pending,"idle has no timer");
	unsigned long least=5001;
	for(unsigned int i=0;i<4;i++) {
		unsigned long offset=nondet_ulong();__CPROVER_assume(offset<=5000);
		unsigned long deadline=base+offset, original=deadline;
		unsigned long remaining=offset>elapsed?offset-elapsed:0;
		if(remaining<least)least=remaining;
		sl_session_schedule_deadline(&p,now,deadline);
		__CPROVER_assert(p.pending&&p.delay==least,"earliest original deadline including wrap and expiry");
		__CPROVER_assert(deadline==original,"wakeup never refreshes original deadline");
	}
	sl_session_schedule_delay(&p,0);
	sl_session_schedule_deadline(&p,now,base+5000);
	__CPROVER_assert(p.pending&&p.delay==0,"pending event not postponed by deadline");
}
