/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SLE_SESSION_SCHEDULE_H
#define _SLE_SESSION_SCHEDULE_H
/* Production earliest original-deadline selection. Callers supply one jiffies
 * snapshot; all finite deadlines are within half the unsigned clock range.
 * No arrival, wakeup, retry or credit event creates a replacement deadline. */
struct sl_session_schedule {
	bool pending;
	unsigned long delay;
};
static inline void sl_session_schedule_delay(struct sl_session_schedule *p,
					      unsigned long delay)
{
	if (!p->pending || delay < p->delay)
		p->delay = delay;
	p->pending = true;
}
static inline void sl_session_schedule_deadline(struct sl_session_schedule *p,
				unsigned long now, unsigned long deadline)
{
	sl_session_schedule_delay(p, time_after_eq(now, deadline) ? 0 : deadline - now);
}
#endif
