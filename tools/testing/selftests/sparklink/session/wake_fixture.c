// SPDX-License-Identifier: GPL-2.0-only
/* Linux workqueue, spinlock and kref APIs are explicit sequential dependencies.
 * Actual production kick/schedule bodies are inserted. Not a scheduler/UAF proof.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include "sle_channel_state.h"
typedef struct { bool held; } spinlock_t;
struct delayed_work { bool pending, running; unsigned long delay; };
struct sl_connection_session {
	spinlock_t lock;
	struct sl_channel_progress progress;
	struct delayed_work work;
	unsigned int refs;
};
static bool irq_disabled;
static struct sl_connection_session *owner;
static void *system_unbound_wq;
#define spin_lock_irqsave(l, f) do { (f) = irq_disabled; irq_disabled = true; assert(!(l)->held); (l)->held = true; } while (0)
#define spin_unlock_irqrestore(l, f) do { assert((l)->held); (l)->held = false; irq_disabled = (f); } while (0)
#define msecs_to_jiffies(ms) (ms)
static void sl_connection_session_get(void *p)
{
	struct sl_connection_session *s = p;
	assert(s->refs); s->refs++;
}
static void sl_connection_session_put(void *p)
{
	struct sl_connection_session *s = p;
	assert(s->refs > 1); s->refs--;
}
static bool queue_delayed_work(void *queue, struct delayed_work *work, unsigned long delay)
{
	(void)queue;
	assert(owner->lock.held && irq_disabled);
	if (work->pending)
		return false;
	work->pending = true; work->delay = delay; return true;
}
static bool mod_delayed_work(void *queue, struct delayed_work *work, unsigned long delay)
{
	bool already = work->pending;
	(void)queue;
	assert(owner->lock.held && irq_disabled);
	work->pending = true; work->delay = delay; return already;
}
/* @@FUNCTIONS@@ */
static void begin(struct sl_connection_session *s)
{
	assert(s->work.pending && !s->work.running);
	s->work.pending = false; s->work.running = true;
}
static void finish(struct sl_connection_session *s)
{
	assert(s->work.running); s->work.running = false;
	sl_connection_session_put(s); /* production sl_work's final put */
}
static void stop(struct sl_connection_session *s)
{
	/* Production stop closes under Session lock, then cancel/join outside it.
	 * Sequential fixture has no actual kernel worker/callback concurrency. */
	sl_channel_close(&s->progress);
	if (s->work.pending) {
		s->work.pending = false; sl_connection_session_put(s);
	}
}
int main(void)
{
	struct sl_connection_session s = { .refs = 1 };
	owner = &s;
	sl_connection_session_kick(&s); assert(s.refs == 1 && !s.work.pending);
	sl_channel_start(&s.progress, 2042, 2047);
	sl_schedule(&s); assert(s.refs == 2 && s.work.delay == 10);
	sl_connection_session_kick(&s); assert(s.refs == 2 && s.work.delay == 0);
	for (unsigned int i = 0; i < 32; i++) sl_connection_session_kick(&s);
	assert(s.refs == 2 && s.work.pending);
	sl_schedule(&s); assert(s.refs == 2 && s.work.delay == 0); /* no postponed event */
	begin(&s);
	sl_connection_session_kick(&s); assert(s.refs == 3 && s.work.pending);
	sl_schedule(&s); assert(s.refs == 3 && s.work.delay == 0);
	finish(&s); begin(&s); finish(&s); assert(s.refs == 1);
	sl_connection_session_kick(&s); begin(&s);
	sl_connection_session_kick(&s); assert(s.refs == 3);
	stop(&s); assert(s.refs == 2 && !s.work.pending);
	sl_connection_session_kick(&s); sl_schedule(&s); assert(s.refs == 2 && !s.work.pending);
	finish(&s); assert(s.refs == 1 && !irq_disabled && !s.lock.held);
	puts("ACTUAL_SESSION_WAKE_SEQUENTIAL_DEPENDENCIES_PASS");
	return 0;
}
