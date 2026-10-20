// SPDX-License-Identifier: GPL-2.0-only
/* Explicit sequential Linux workqueue/hrtimer/spinlock/kref API dependencies.
 * Production enqueue, deadline callback and nonjoining disarm bodies inserted.
 * Runtime parent owns timer memory through actual stop's timer-before-work join.
 * These APIs do NOT prove Linux scheduling, concurrent UAF or drain progress.
 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "sle_channel_state.h"
typedef struct { bool held; } spinlock_t;
typedef uint64_t ktime_t;
enum hrtimer_restart { HRTIMER_NORESTART };
#define HRTIMER_MODE_REL_SOFT 5
struct hrtimer { bool pending, running; ktime_t delay; };
struct delayed_work { bool pending, running; unsigned long delay; };
struct sl_connection_session {
 spinlock_t lock;
 struct sl_channel_progress progress;
 struct delayed_work work;
 struct hrtimer wake_timer;
 unsigned int refs;
};
static bool irq_disabled;
static struct sl_connection_session *owner;
static void *system_unbound_wq;
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define spin_lock_irqsave(l, f) do { (f) = irq_disabled; irq_disabled = true; assert(!(l)->held); (l)->held = true; } while (0)
#define spin_unlock_irqrestore(l, f) do { assert((l)->held); (l)->held = false; irq_disabled = (f); } while (0)
#define msecs_to_jiffies(ms) (ms)
#define jiffies_to_nsecs(j) ((uint64_t)(j)*1000000ULL) /* fixture HZ=1000 */
#define ns_to_ktime(ns) (ns)
static void sl_connection_session_get(void *p) {
 struct sl_connection_session *s=p;assert(s->refs);s->refs++;
}
static void sl_connection_session_put(void *p) {
 struct sl_connection_session *s=p;assert(s->refs>1);s->refs--;
}
static bool queue_delayed_work(void *queue,struct delayed_work *w,unsigned long delay) {
 (void)queue;assert(owner->lock.held&&irq_disabled);assert(!delay);
 if(w->pending)return false;
 w->pending=true;w->delay=delay;return true;
}
static bool mod_delayed_work(void *queue,struct delayed_work *w,unsigned long delay) {
 bool already=w->pending;(void)queue;assert(owner->lock.held&&irq_disabled);assert(!delay);
 w->pending=true;w->delay=delay;return already;
}
static void hrtimer_start(struct hrtimer *t,ktime_t delay,int mode) {
 assert(owner->lock.held&&irq_disabled&&delay&&mode==HRTIMER_MODE_REL_SOFT);
 t->pending=true;t->delay=delay;
}
static int hrtimer_try_to_cancel(struct hrtimer *t) {
 assert(owner->lock.held&&irq_disabled);
 if(t->running)return -1; /* nonjoining API must not wait under Session lock */
 int was=t->pending;t->pending=false;return was;
}
/* @@FUNCTIONS@@ */
static void begin(struct sl_connection_session *s) {
 assert(s->work.pending&&!s->work.running);s->work.pending=false;s->work.running=true;
}
static void finish(struct sl_connection_session *s) {
 assert(s->work.running);s->work.running=false;
 sl_connection_session_put(s); /* actual sl_work's final put is a dependency */
}
static void fire(struct sl_connection_session *s) {
 assert(s->wake_timer.pending&&!s->wake_timer.running);
 s->wake_timer.pending=false;s->wake_timer.running=true;
 assert(sl_deadline_wake(&s->wake_timer)==HRTIMER_NORESTART);
 s->wake_timer.running=false;
}
static void stop(struct sl_connection_session *s) {
 /* Abstract sequential close/cancel boundary. Actual production stop's source
  * order is checked independently; actual concurrent timer/work join is not
  * simulated as always successful here. A running worker retains its ref. */
 sl_channel_close(&s->progress);assert(!s->wake_timer.running);s->wake_timer.pending=false;
 if(s->work.pending){s->work.pending=false;sl_connection_session_put(s);}
}
int main(void) {
 struct sl_connection_session s={.refs=1};owner=&s;
 sl_connection_session_kick(&s);sl_schedule(&s,5000);assert(s.refs==1&&!s.work.pending&&!s.wake_timer.pending);
 sl_channel_start(&s.progress,2042,2047);
 sl_schedule(&s,5000);assert(s.refs==1&&s.wake_timer.pending&&s.wake_timer.delay==5000000000ULL&&!s.work.pending);
 sl_connection_session_kick(&s);assert(s.refs==2&&s.work.pending&&!s.work.delay);
 for(unsigned i=0;i<32;i++)sl_connection_session_kick(&s);
 sl_schedule(&s,4000);assert(s.refs==2&&s.work.pending&&!s.work.delay&&s.wake_timer.delay==4000000000ULL);
 fire(&s);assert(s.refs==2&&s.work.pending); /* timer coalesces with event */
 begin(&s);sl_schedule(&s,100);fire(&s);assert(s.refs==3&&s.work.pending);
 sl_schedule(&s,0);assert(s.refs==3&&!s.work.delay);
 finish(&s);begin(&s);finish(&s);assert(s.refs==1);
 sl_schedule(&s,10);sl_cancel_wake_hint(&s);assert(!s.wake_timer.pending&&s.refs==1);
 s.wake_timer.running=true;sl_cancel_wake_hint(&s);assert(s.wake_timer.running);s.wake_timer.running=false;
 sl_connection_session_kick(&s);begin(&s);sl_schedule(&s,1000);sl_connection_session_kick(&s);assert(s.refs==3);
 stop(&s);assert(s.refs==2&&!s.work.pending&&!s.wake_timer.pending);
 sl_connection_session_kick(&s);sl_schedule(&s,10);sl_cancel_wake_hint(&s);
 assert(s.refs==2&&!s.work.pending&&!s.wake_timer.pending);
 assert(sl_deadline_wake(&s.wake_timer)==HRTIMER_NORESTART);assert(s.refs==2&&!s.work.pending);
 finish(&s);assert(s.refs==1&&!irq_disabled&&!s.lock.held);
 puts("ACTUAL_SESSION_WAKE_SEQUENTIAL_DEPENDENCIES_PASS");return 0;
}
