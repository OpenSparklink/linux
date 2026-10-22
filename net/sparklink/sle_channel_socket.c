// SPDX-License-Identifier: GPL-2.0-only
/* Runtime-owned connection session, bounded fixed/dynamic basic channels and
 * fd bindings. Reliable modes and TCID reuse still require verified barriers. */
#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/hrtimer.h>
#include <linux/kref.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/sparklink_native.h>
#include <linux/sparklink_channel.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <net/tcp_states.h>
#include <uapi/linux/sparklink_socket.h>
#include "sle_channel_wire.h"
#include "sle_channel_state.h"
#include "sle_channel_grant.h"
#include "sle_message_security.h"
#include "sle_channel_table.h"
#include "sle_dynamic_state.h"
#include "sle_fragment_cursor.h"
#include "sle_security_relay.h"
#include "sle_session_schedule.h"
#include "sle_tx_budget.h"
#include "sle_tx_policy.h"
#define CREATE_TRACE_POINTS
#include <trace/events/sparklink.h>

_Static_assert(sizeof(struct sl_fragment_cursor) <= sizeof_field(struct sk_buff, cb),
	       "fragment cursor fits private skb control buffer");
_Static_assert(sizeof(struct sparklink_send_constraint) == 48, "send constraint ABI");
_Static_assert(sizeof(struct sparklink_message_security) == 40 &&
               sizeof(struct sparklink_message_security) <= sizeof_field(struct sk_buff, cb),
               "message context layout and skb ownership");
_Static_assert(sizeof(struct sockaddr_sparklink_dynamic) == 64,
	       "dynamic address layout");
_Static_assert(SL_FIXED_CHANNELS == 2 && SL_CHANNEL_USER_SLOT == 0 &&
		       SL_CHANNEL_SMTC_SLOT == 1,
	       "fixed channel table bounds");
_Static_assert(SL_GRANT_TX == SPARKLINK_SOCKET_TX && SL_GRANT_RX == SPARKLINK_SOCKET_RX, "grant direction UAPI mismatch");

#define SL_CHANNEL_TX 8
#define SL_CHANNEL_RX 16

struct sl_basic_channel {
	u8 local_tcid, remote_tcid, pi;
	unsigned int mtu, mps;
	struct sl_binding_progress binding;
	bool dynamic;
	struct sl_dynamic_progress negotiation;
	unsigned long dynamic_deadline;
	unsigned int pending_directions, source_port, destination_port, aid,
		slqi;
	int dynamic_error;
	bool dynamic_notified, close_id_assigned, peer_closed;
	struct sock *sk; /* held reference; session lock protects detach/delivery */
	struct sk_buff_head tx, rx;
	u64 rx_dropped;
};
struct sl_connection_session {
	struct kref refs;
	void *security; /* pinned Rust owner; same physical Session lifetime */
	u16 controller, handle;
	u64 generation, lifetime, epoch;
	spinlock_t lock; /* state + channel; never spans blocking transport */
	struct sl_channel_progress progress;
	unsigned long deadline;
	unsigned long unknown_deadline; /* worker-only bounded snapshot uncertainty */
	struct delayed_work work;
	/* Runtime/table owns the Session until stop joins timer then worker.
	 * This timer borrows that owner reference; it only queues a state hint.
	 */
	struct hrtimer wake_timer;
	struct sl_basic_channel channels[SL_SESSION_CHANNELS];
	unsigned int next_signal_id, next_tcid; /* Session lock, never reused */
	struct sl_channel_signal
		rejection[4]; /* worker-only bounded unsupported requests */
	unsigned int rejection_count;
	unsigned long rejection_deadline[4];
	unsigned long response_deadline;
	bool service_running; /* Session lock publishes worker-only fields to inspection */
	bool work_progress, work_retry; /* serialized worker-only send results */
	bool rx_budget_exhausted, tx_budget_exhausted;
	bool tx_blocked; /* last data attempt could not progress; worker-only */
	u64 service_sequence, tx_sequence; /* worker-only observer IDs, not authority */
	u64 admission_sequence; /* Session lock; trace-only, never authorization */
	struct sl_tx_policy tx_policy; /* serialized worker-only class turns */
	u16 acb_maximum; /* controller packet size, distinct from DTAP MTU */
	int fragment_slot; /* sole operation slot; Session lock protects ownership */
	struct sk_buff *tx_inflight; /* Session-owned, never in an fd queue */
	struct sl_channel_grant tx_grant; /* immutable bounded operation scope */
	bool tx_started; /* set at first successful actual atomic USB submit */
	bool response_pending; /* identifier zero is valid; serialized worker-only */
	u8 response_id;
	u32 response_mask; /* only serialized session worker writes these */
	u8 rx_buffer[2047]; /* sole connection consumer, fixed budget */
};
struct sl_socket_binding {
	struct sock sk;
	struct sl_channel_grant grant; /* immutable after bind publication */
	spinlock_t lock; /* publication of session reference */
	struct sl_connection_session *session;
	unsigned int channel_slot; /* immutable after binding publication */
};
struct sl_submit_scope {
	struct sl_connection_session *session;
	struct sl_basic_channel *channel;
	struct sk_buff *operation;
	u64 sequence;
	unsigned int boundary, length, offset;
};
struct sl_tx_step { bool attempted, submitted; int result; u32 wait; };
static struct proto sl_channel_proto;

static struct sl_socket_binding *sl_sk(struct sock *sk)
{
	return container_of(sk, struct sl_socket_binding, sk);
}
/* Session lock protects channel.sk's held socket reference. The grant lives
 * in that SocketBinding, not a copied policy in Session/Channel. */
static int sl_permits(struct sl_connection_session *s, struct sl_basic_channel *c,
                      unsigned int direction)
{
	struct sl_grant_scope scope = { .controller = s->controller,
		.generation = s->generation, .lifetime = s->lifetime, .epoch = s->epoch,
		.handle = s->handle, .local_tcid = c->local_tcid,
		.remote_tcid = c->remote_tcid, .pi = c->pi };

	return c->sk &&
	       (!c->dynamic || c->negotiation.phase == SL_DYN_OPEN ||
		(direction == SL_GRANT_RX && c->peer_closed)) &&
	       sl_grant_permits(&sl_sk(c->sk)->grant, scope, direction);
}
/* Caller holds Runtime Host/data/gate then Session. Owner reads never take
 * Host or the Session table mutex. Management/physical retirement closes the
 * outer authority before stopping Owner, so no check-to-submit window opens. */
static int sl_grant_current(struct sl_connection_session *s,
			    const struct sl_channel_grant *grant, u64 revision)
{
	int level;
	if (!grant->security)
		return 0;
	level = sl_security_owner_level_rust(s->security, revision);
	return level >= 0 && sl_grant_security_permits(grant, revision, level) ?
		       0 :
		       -EACCES;
}
/* Runtime Host/data/gate and Session are held. Constraint only tightens the
 * original Grant. Even minimum0 must retain its requested receipt epoch. */
static int sl_constraint_check(struct sl_connection_session *s,
			       struct sl_basic_channel *c,
			       const struct sparklink_send_constraint *m,
			       u64 revision)
{
	u64 now;
	if (!m->security_epoch)
		return 0;
	now = ktime_get_ns();
	if (!sl_send_constraint_timely(m->deadline_monotonic_ns, now))
		return -ETIMEDOUT;
	if (m->deadline_monotonic_ns - now > 5ULL * NSEC_PER_SEC)
		return -EINVAL;
	return sl_send_constraint_valid(m) &&
			       sl_send_constraint_identity(
				       m, s->generation, s->lifetime,
				       s->controller, s->handle, c->local_tcid,
				       c->remote_tcid, c->pi) &&
			       sl_send_constraint_permits(
				       m->security_epoch, m->minimum, revision,
				       sl_security_owner_level_rust(s->security,
								    revision)) ?
		       0 :
		       -EACCES;
}
static int sl_security_check(struct sl_connection_session *s,
			     struct sl_basic_channel *c, u64 revision)
{
	return c->sk ? sl_grant_current(s, &sl_sk(c->sk)->grant, revision) :
		       -ENOTCONN;
}
/* Pending setup has no grant yet. Closing/terminal channels never regain data
 * permission even while their protocol cleanup remains Session-owned. */
static int sl_dynamic_status(struct sl_basic_channel *c)
{
	if (!c->dynamic || c->negotiation.phase == SL_DYN_OPEN)
		return 0;
	switch (c->negotiation.phase) {
	case SL_DYN_LISTEN:
	case SL_DYN_CONNECT:
	case SL_DYN_CONNECT_SENT:
	case SL_DYN_RESPONSE:
		return -EAGAIN;
	default:
		return -ENOTCONN;
	}
}
/* Same detach-under-queue-lock/free-outside-lock semantics as skb_queue_purge.
 * These skbs are still author-owned and have no accepted physical prefix.
 * Stage 3 records their local queue retirement, never a credit refund or a
 * Session/USB drain. A begun PDU remains in tx_inflight and is not touched.
 */
static void sl_purge_tx(struct sl_connection_session *s,
			struct sl_basic_channel *c)
{
	struct sk_buff_head discarded;
	struct sk_buff *skb;
	unsigned long flags;

	__skb_queue_head_init(&discarded);
	spin_lock_irqsave(&c->tx.lock, flags);
	skb_queue_splice_init(&c->tx, &discarded);
	spin_unlock_irqrestore(&c->tx.lock, flags);
	while ((skb = __skb_dequeue(&discarded))) {
		struct sl_fragment_cursor *cursor = (void *)skb->cb;

		trace_sparklink_session_queue(s->controller, s->generation,
			s->lifetime, s->epoch, cursor->observation,
			c - s->channels, skb->len, cursor->deadline, 3);
		kfree_skb_reason(skb, SKB_DROP_REASON_QUEUE_PURGE);
	}
}

static void sl_session_destroy(struct kref *refs)
{
	struct sl_connection_session *s = container_of(refs, struct sl_connection_session, refs);
	unsigned int i;

	WARN_ON(delayed_work_pending(&s->work));
	WARN_ON(hrtimer_active(&s->wake_timer));
	WARN_ON(s->tx_inflight);
	for (i = 0; i < SL_SESSION_CHANNELS; i++) {
		WARN_ON(s->channels[i].sk);
		sl_purge_tx(s, &s->channels[i]);
		skb_queue_purge(&s->channels[i].rx);
	}
	sl_security_owner_destroy_rust(s->security);
	kfree(s);
}
void *sl_connection_session_security(void *opaque)
{
	struct sl_connection_session *s = opaque;
	return s->security; /* immutable, caller retains a session kref */
}
void sl_connection_session_get(void *opaque)
{
	struct sl_connection_session *s = opaque;
	kref_get(&s->refs);
}
void sl_connection_session_put(void *opaque)
{
	struct sl_connection_session *s = opaque;
	kref_put(&s->refs, sl_session_destroy);
}
static struct sl_connection_session *sl_binding_session(struct sock *sk)
{
	struct sl_socket_binding *binding = sl_sk(sk);
	struct sl_connection_session *s;
	unsigned long flags;

	spin_lock_irqsave(&binding->lock, flags);
	s = binding->session;
	if (s)
		sl_connection_session_get(s);
	spin_unlock_irqrestore(&binding->lock, flags);
	return s;
}
/* sl_binding_session acquired the publication lock; slot never changes while
 * this fd object exists. The retained Session reference keeps its table alive. */
static struct sl_basic_channel *sl_bound_channel(struct sock *sk, struct sl_connection_session *s)
{
	return &s->channels[sl_sk(sk)->channel_slot];
}
static struct sl_channel_progress sl_snapshot(struct sl_connection_session *s)
{
	unsigned long flags;
	struct sl_channel_progress view;
	spin_lock_irqsave(&s->lock, flags);
	view = s->progress;
	spin_unlock_irqrestore(&s->lock, flags);
	return view;
}
static void sl_schedule(struct sl_connection_session *s, unsigned long delay)
{
	unsigned long flags;
	spin_lock_irqsave(&s->lock, flags);
	if (sl_channel_active(s->progress)) {
		if (delay) {
			/* timer_list's outer wheel can round a five-second arm up
			 * by 512ms at HZ=1000. Preserve the selected original due
			 * time using hrtimer; never run protocol work in its callback.
			 */
			hrtimer_start(&s->wake_timer, ns_to_ktime(jiffies_to_nsecs(delay)),
				      HRTIMER_MODE_REL_SOFT);
		} else {
			sl_connection_session_get(s);
			if (!queue_delayed_work(system_unbound_wq, &s->work, 0))
				sl_connection_session_put(s);
		}
	}
	spin_unlock_irqrestore(&s->lock, flags);
}
/* Event hint only: state/credit/grant remain authoritative at actual use.
 * The Session lock serializes queue admission with stop's close-before-join.
 * A fresh queue owns one kref, including a requeue while the callback runs;
 * modifying an already pending item keeps its original queue reference.
 * Ready events enqueue this one work item immediately. The separate original-
 * deadline timer only hints through this same admission. Closed admission is
 * serialized before timer cancel/join and then work cancel/join.
 */
void sl_connection_session_kick(void *opaque)
{
	struct sl_connection_session *s = opaque;
	unsigned long flags;

	spin_lock_irqsave(&s->lock, flags);
	if (sl_channel_active(s->progress)) {
		sl_connection_session_get(s);
		if (mod_delayed_work(system_unbound_wq, &s->work, 0))
			sl_connection_session_put(s);
	}
	spin_unlock_irqrestore(&s->lock, flags);
}
static enum hrtimer_restart sl_deadline_wake(struct hrtimer *timer)
{
	struct sl_connection_session *s = container_of(timer, struct sl_connection_session, wake_timer);

	/* No borrowed pointer escapes; Runtime's owner survives hrtimer_cancel.
	 * kick takes a queue ref only after checking active under Session lock.
	 */
	sl_connection_session_kick(s);
	return HRTIMER_NORESTART;
}
static void sl_cancel_wake_hint(struct sl_connection_session *s)
{
	unsigned long flags;

	spin_lock_irqsave(&s->lock, flags);
	/* Never join while holding the callback's Session lock. A running
	 * callback may leave one coalesced hint, not a new deadline or authority.
	 */
	hrtimer_try_to_cancel(&s->wake_timer);
	spin_unlock_irqrestore(&s->lock, flags);
}
static void sl_socket_fault(struct sock *sk, int error)
{
	WRITE_ONCE(sk->sk_err, -error);
	WRITE_ONCE(sk->sk_shutdown, SHUTDOWN_MASK);
	WRITE_ONCE(sk->sk_state, TCP_CLOSE);
	sk->sk_error_report(sk);
	sk->sk_state_change(sk);
}
static void sl_notify(struct sl_connection_session *s, int error)
{
	unsigned long flags;
	struct sock *sockets[SL_SESSION_CHANNELS];
	unsigned int i;

	spin_lock_irqsave(&s->lock, flags);
	if (error)
		sl_channel_fail(&s->progress);
	for (i = 0; i < SL_SESSION_CHANNELS; i++) {
		sockets[i] = s->channels[i].sk;
		if (sockets[i])
			sock_hold(sockets[i]);
	}
	spin_unlock_irqrestore(&s->lock, flags);
	for (i = 0; i < SL_SESSION_CHANNELS; i++) {
		if (!sockets[i])
			continue;
		if (error)
			sl_socket_fault(sockets[i], error);
		else {
			sockets[i]->sk_write_space(sockets[i]);
			sockets[i]->sk_data_ready(sockets[i]);
		}
		sock_put(sockets[i]);
	}
}
static void sl_wake(struct sl_connection_session *s) { sl_notify(s, 0); }
static void sl_fault(struct sl_connection_session *s, int error) { sl_notify(s, error); }
static void sl_progress_event(struct sl_connection_session *s, unsigned int event, unsigned int mtu, unsigned int mps)
{
	unsigned long flags;
	enum sl_channel_phase before, after;
	int expired;
	unsigned int i;

	spin_lock_irqsave(&s->lock, flags);
	before = s->progress.phase;
	expired = time_after_eq(jiffies, s->deadline);
	switch (event) {
	case 1: sl_channel_request_submitted(&s->progress, expired); break;
	case 2: sl_channel_peer_capability(&s->progress, mtu, mps, expired); break;
	case 3: sl_channel_response_submitted(&s->progress, expired); break;
	default: sl_channel_tick(&s->progress, expired); break;
	}
	after = s->progress.phase;
	if (after == SL_CH_OPEN) {
		for (i = 0; i < SL_FIXED_CHANNELS; i++) {
			s->channels[i].mtu = sl_channel_payload_limit(s->progress, s->channels[i].remote_tcid);
			s->channels[i].mps = s->progress.mps;
		}
	}
	spin_unlock_irqrestore(&s->lock, flags);
	if (before == SL_CH_NEGOTIATING && after == SL_CH_FAILED)
		sl_fault(s, expired ? -ETIMEDOUT : -EPROTO);
	else if (before != SL_CH_OPEN && after == SL_CH_OPEN)
		sl_wake(s);
}

/* Invoked inside actual Runtime Host/data/gate commit. Order is those locks
 * then session lock. No caller holds session lock over any Runtime API/wait.
 * Last-fd detach and actual USB queueing therefore have one linearization. */
static int sl_session_submit(void *scope, u64 security_revision,
			     int (*submit)(void *), void *context)
{
	struct sl_submit_scope *permission = scope;
	struct sl_connection_session *s = permission->session;
	struct sl_basic_channel *c = permission->channel;
	int ret;

	spin_lock(&s->lock); /* Runtime commit has IRQs disabled */
	if (!sl_channel_active(s->progress))
		ret = -ECANCELED;
	else if (permission->operation) {
		struct sl_grant_scope observed = { .controller = s->controller,
						   .generation = s->generation,
						   .lifetime = s->lifetime,
						   .epoch = s->epoch,
						   .handle = s->handle,
						   .local_tcid = c->local_tcid,
						   .remote_tcid =
							   c->remote_tcid,
						   .pi = c->pi };
		struct sl_fragment_cursor *cursor =
			(void *)permission->operation->cb;
		if (s->tx_inflight != permission->operation ||
		    s->fragment_slot != c - s->channels)
			ret = -ECANCELED;
		else if (!sl_grant_permits(&s->tx_grant, observed,
					   SL_GRANT_TX) ||
			 sl_grant_current(s, &s->tx_grant, security_revision))
			ret = -EACCES;
		else if (cursor->security_epoch &&
			 !sl_send_constraint_permits(
				 cursor->security_epoch,
				 cursor->minimum_security, security_revision,
				 sl_security_owner_level_rust(
					 s->security, security_revision)))
			ret = -EACCES;
		else if ((cursor->intent_deadline_ns &&
			  !sl_send_constraint_timely(cursor->intent_deadline_ns,
						     ktime_get_ns())) ||
			 time_after_eq(jiffies, cursor->deadline))
			ret = -ETIMEDOUT;
		else if (!s->tx_started && (!sl_binding_live(c->binding) ||
					    !sl_permits(s, c, SL_GRANT_TX)))
			ret = -ECANCELED;
		else {
			ret = submit(context);
			if (!ret)
				s->tx_started = true; /* same linearization as first USB acceptance */
		}
	} else if (c && !sl_binding_live(c->binding))
		ret = -ECANCELED;
	else if (c && (!sl_permits(s, c, SL_GRANT_TX) ||
		       sl_security_check(s, c, security_revision)))
		ret = -EACCES;
	else
		ret = submit(context); /* atomic queue only; no wait or protocol reentry */
	trace_sparklink_session_tx(s->controller, s->generation, s->lifetime,
		s->service_sequence, permission->sequence, c ? c - s->channels : -1,
		permission->boundary, permission->length, permission->offset, ret,
		SPARKLINK_ACB_WAIT_NONE, 2);
	spin_unlock(&s->lock);
	return ret;
}
/* Scheduling evidence only. The actual Runtime/Ticket consent still decides
 * authority, identity, deadline, reservation and USB acceptance. */
static void sl_send_result(struct sl_connection_session *s, int ret, u32 wait)
{
	if (!ret)
		s->work_progress = true;
	else if (ret == -EAGAIN && wait != SPARKLINK_ACB_WAIT_CREDIT)
		s->work_retry = true;
}
static int sl_send(struct sl_connection_session *s, struct sl_basic_channel *c, const u8 *data, size_t length)
{
	struct sl_submit_scope permission = { .session = s, .channel = c,
		.sequence = ++s->tx_sequence, .length = length };
	u32 wait = SPARKLINK_ACB_WAIT_RETRY;
	int ret;

	trace_sparklink_session_tx(s->controller, s->generation, s->lifetime,
		s->service_sequence, permission.sequence, c ? c - s->channels : -1,
		0, length, 0, -EINPROGRESS, SPARKLINK_ACB_WAIT_NONE, 0);
	ret = sparklink_native_acb_send_deferred(s->controller, s->generation, s->lifetime,
		s->handle, 0, data, length, s->epoch, sl_session_submit, &permission, &wait);
	trace_sparklink_session_tx(s->controller, s->generation, s->lifetime,
		s->service_sequence, permission.sequence, c ? c - s->channels : -1,
		0, length, 0, ret, wait, 1);
	sl_send_result(s, ret, wait);
	return ret;
}

/* Session lock protects all channel transitions and the immutable final grant.
 * Called only inside Runtime Host/data/gate admission or actual submit consent.
 */
static int sl_dynamic_grant(struct sl_connection_session *s,
			    struct sl_basic_channel *c,
			    struct sl_channel_grant *grant)
{
	struct sl_grant_scope scope = { .controller = s->controller,
					.generation = s->generation,
					.lifetime = s->lifetime,
					.epoch = s->epoch,
					.handle = s->handle,
					.local_tcid = c->local_tcid,
					.remote_tcid = c->remote_tcid,
					.pi = c->pi };
	return c->sk && sl_binding_live(c->binding) &&
	       sl_grant_init(grant, scope, c->pending_directions, 0);
}
static void sl_dynamic_open(struct sl_basic_channel *c,
			    struct sl_channel_grant grant)
{
	/* No application grant exists before this one publication. c->sk remains
	 * attached under Session lock until release removes it before orphaning. */
	sl_sk(c->sk)->grant = grant;
	WRITE_ONCE(c->sk->sk_state, TCP_ESTABLISHED);
	if (c->sk->sk_socket)
		WRITE_ONCE(c->sk->sk_socket->state, SS_CONNECTED);
}
static void sl_dynamic_closing(struct sl_connection_session *s,
			       struct sl_basic_channel *c)
{
	if (c->negotiation.phase != SL_DYN_CLOSE || c->close_id_assigned)
		return;
	if (s->next_signal_id > 255) {
		c->negotiation.phase = SL_DYN_FAILED;
		c->dynamic_error = -ENOSPC;
		return;
	}
	c->negotiation.identifier = s->next_signal_id++;
	c->close_id_assigned = true;
	c->dynamic_deadline = jiffies + msecs_to_jiffies(5000);
}
struct sl_dynamic_received {
	struct sl_connection_session *session;
	struct sl_channel_signal message;
	bool changed;
};
static int sl_dynamic_receive(void *context, u64 security_revision)
{
	(void)security_revision; /* Dynamic protected modes remain unsupported. */
	struct sl_dynamic_received *r = context;
	struct sl_connection_session *s = r->session;
	struct sl_channel_signal *m = &r->message;
	struct sl_basic_channel *c = NULL;
	struct sl_channel_grant grant;
	unsigned int i, result = 1;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&s->lock, flags);
	if (s->progress.phase != SL_CH_OPEN)
		goto unlock;
	r->changed = true;
	if (m->code == SL_CMTC_CONNECT_REQ) {
		for (i = SL_FIXED_CHANNELS; i < SL_SESSION_CHANNELS; i++) {
			struct sl_basic_channel *entry = &s->channels[i];
			if (entry->remote_tcid == m->source) {
				result = 4;
				goto reject;
			} /* bounded tombstones */
			if (entry->dynamic &&
			    entry->negotiation.phase == SL_DYN_LISTEN &&
			    sl_binding_live(entry->binding) &&
			    entry->source_port == m->destination_port &&
			    entry->destination_port == m->source_port &&
			    entry->aid == m->aid)
				c = entry;
		}
		if (!c || !m->ports || !m->exclusive || m->measurement ||
		    m->slqi_count != 1 || m->slqi[0] != c->slqi)
			goto reject;
		if (time_after_eq(jiffies, c->dynamic_deadline)) {
			c->negotiation.phase = SL_DYN_FAILED;
			c->dynamic_error = -ETIMEDOUT;
			goto reject;
		}
		if (m->mtu > c->mtu || m->mtu > s->progress.mtu) {
			result = 2;
			goto reject;
		}
		if (m->mps > c->mps || m->mps > s->progress.mps ||
		    m->mps < m->mtu + 5U) {
			result = 3;
			goto reject;
		}
		c->remote_tcid = m->source;
		c->mtu = m->mtu;
		c->mps = m->mps;
		c->negotiation.peer_identifier = m->identifier;
		c->negotiation.phase = SL_DYN_RESPONSE;
	} else if (m->code == SL_CMTC_CONNECT_RSP) {
		for (i = SL_FIXED_CHANNELS; i < SL_SESSION_CHANNELS; i++)
			if (s->channels[i].local_tcid == m->source)
				c = &s->channels[i];
		if (!c || m->identifier != c->negotiation.identifier ||
		    (c->negotiation.phase != SL_DYN_CONNECT_SENT &&
		     c->negotiation.phase != SL_DYN_ABANDONED))
			goto unlock;
		if (time_after_eq(jiffies, c->dynamic_deadline)) {
			c->negotiation.phase = SL_DYN_FAILED;
			c->dynamic_error = -ETIMEDOUT;
			goto unlock;
		}
		if (m->result) {
			sl_dynamic_connected(&c->negotiation, m->identifier,
					     m->result);
			c->dynamic_error = -ECONNREFUSED;
			goto unlock;
		}
		for (i = SL_FIXED_CHANNELS; i < SL_SESSION_CHANNELS; i++)
			if (&s->channels[i] != c &&
			    s->channels[i].remote_tcid == m->destination) {
				c->negotiation.phase = SL_DYN_FAILED;
				c->dynamic_error = -EPROTO;
				goto unlock;
			}
		c->remote_tcid = m->destination;
		if (c->negotiation.phase == SL_DYN_CONNECT_SENT) {
			if (!sl_dynamic_grant(s, c, &grant)) {
				c->negotiation.phase = SL_DYN_ABANDONED;
			} else
				sl_dynamic_open(c, grant);
		}
		sl_dynamic_connected(&c->negotiation, m->identifier, 0);
		sl_dynamic_closing(s, c);
	} else {
		for (i = SL_FIXED_CHANNELS; i < SL_SESSION_CHANNELS; i++) {
			struct sl_basic_channel *entry = &s->channels[i];
			/* A peer close can overtake its create response. It may
			 * cancel our already-submitted setup, never mint a Grant. */
			if (m->code == SL_CMTC_CLOSE_REQ && entry->dynamic &&
			    entry->local_tcid == m->destination &&
			    !entry->remote_tcid &&
			    (entry->negotiation.phase == SL_DYN_CONNECT_SENT ||
			     entry->negotiation.phase == SL_DYN_ABANDONED)) {
				entry->remote_tcid = m->source;
				c = entry;
			}
			if (entry->dynamic &&
			    (m->code == SL_CMTC_CLOSE_REQ ?
				     entry->local_tcid == m->destination &&
					     entry->remote_tcid == m->source :
				     entry->local_tcid == m->source &&
					     entry->remote_tcid ==
						     m->destination))
				c = entry;
		}
		if (!c)
			goto unlock;
		if (m->code == SL_CMTC_CLOSE_REQ &&
		    (c->negotiation.phase == SL_DYN_OPEN ||
		     c->negotiation.phase == SL_DYN_RESPONSE ||
		     c->negotiation.phase == SL_DYN_CONNECT_SENT ||
		     c->negotiation.phase == SL_DYN_ABANDONED ||
		     c->negotiation.phase == SL_DYN_CLOSE ||
		     c->negotiation.phase == SL_DYN_CLOSE_SENT)) {
			c->negotiation.peer_identifier = m->identifier;
			if (c->negotiation.phase == SL_DYN_OPEN)
				c->dynamic_deadline =
					jiffies + msecs_to_jiffies(5000);
			c->negotiation.phase = SL_DYN_CLOSE_RESPONSE;
			c->peer_closed = true;
		} else if (m->code == SL_CMTC_CLOSE_RSP &&
			   c->negotiation.phase == SL_DYN_CLOSE_SENT &&
			   m->identifier == c->negotiation.identifier)
			c->negotiation.phase = SL_DYN_RETIRED;
	}
	goto unlock;
reject:
	if (s->rejection_count < ARRAY_SIZE(s->rejection)) {
		s->rejection_deadline[s->rejection_count] = jiffies + msecs_to_jiffies(5000);
		s->rejection[s->rejection_count++] =
			(struct sl_channel_signal){ .code = SL_CMTC_CONNECT_RSP,
						    .identifier = m->identifier,
						    .source = m->source,
						    .result = result };
	}
unlock:
	spin_unlock_irqrestore(&s->lock, flags);
	return ret;
}
struct sl_dynamic_submit {
	struct sl_connection_session *session;
	struct sl_basic_channel *channel;
	enum sl_dynamic_phase phase;
	size_t pdu_bytes;
	u64 observation; /* worker-owned control namespace, never a wire identifier */
};
static int sl_dynamic_consent(void *context, u64 security_revision,
			      int (*submit)(void *), void *argument)
{
	(void)security_revision; /* Dynamic control is not a protected data Grant. */
	struct sl_dynamic_submit *a = context;
	struct sl_connection_session *s = a->session;
	struct sl_basic_channel *c = a->channel;
	struct sl_channel_grant grant = { 0 };
	enum sl_dynamic_phase phase = a->phase;
	int ret;
	spin_lock(&s->lock); /* Runtime Host/data/gate has IRQs disabled */
	if (s->progress.phase != SL_CH_OPEN || s->fragment_slot >= 0 ||
	    c->negotiation.phase != phase)
		ret = -ECANCELED;
	else if (!a->pdu_bytes || a->pdu_bytes > s->progress.mps)
		ret = -EMSGSIZE;
	else if (time_after_eq(jiffies, c->dynamic_deadline))
		ret = -ETIMEDOUT;
	else if ((phase == SL_DYN_CONNECT || phase == SL_DYN_RESPONSE) &&
		 !sl_binding_live(c->binding))
		ret = -ECANCELED;
	else if (phase == SL_DYN_RESPONSE && !sl_dynamic_grant(s, c, &grant))
		ret = -ECANCELED;
	else {
		ret = submit(argument);
		if (!ret) {
			if (phase == SL_DYN_RESPONSE)
				sl_dynamic_open(c, grant);
			sl_dynamic_submitted(&c->negotiation);
		}
	}
	trace_sparklink_session_tx(s->controller, s->generation, s->lifetime,
		s->service_sequence, a->observation, -1, 0, a->pdu_bytes, 0,
		ret, SPARKLINK_ACB_WAIT_NONE, 2);
	spin_unlock(&s->lock);
	return ret;
}
struct sl_routed_data {
	struct sl_connection_session *session;
	struct sl_basic_channel *channel;
	const struct sl_channel_frame *frame;
	struct sk_buff *skb;
	struct sock *wake;
	u64 receipt_revision;
	unsigned int pdu_length;
};
/* Host/data/gate -> Session -> RX. All allocation/copy and wakeups are outside
 * this callback. It publishes immutable receipt facts, never a policy grant. */
static int sl_deliver(void *context, u64 current_revision)
{
	struct sl_routed_data *r = context;
	struct sl_connection_session *s = r->session;
	struct sl_basic_channel *c = r->channel;
	const struct sl_channel_frame *frame = r->frame;
	struct sparklink_message_security *metadata = (void *)r->skb->cb;
	unsigned long flags;
	int level;

	spin_lock_irqsave(&s->lock, flags);
	if (s->progress.phase == SL_CH_OPEN && sl_binding_live(c->binding) &&
	    sl_permits(s, c, SL_GRANT_RX) &&
	    !sl_security_check(s, c, current_revision) &&
	    (!sl_sk(c->sk)->grant.security ||
	     sl_sk(c->sk)->grant.security_epoch == r->receipt_revision) &&
	    (!c->dynamic || c->negotiation.phase == SL_DYN_OPEN) &&
	    frame->tcid == c->local_tcid && frame->pi == c->pi &&
	    frame->length <= c->mtu && r->pdu_length <= c->mps) {
		*metadata = (struct sparklink_message_security){
			.version = SPARKLINK_MESSAGE_SECURITY_VERSION,
			.size = sizeof(*metadata),
			.controller = s->controller,
			.handle = s->handle,
			.generation = s->generation,
			.lifetime = s->lifetime,
			.security_epoch = r->receipt_revision,
			.local_tcid = c->local_tcid,
			.remote_tcid = c->remote_tcid,
			.pi = c->pi,
		};
		/* An old/uncorrelated receipt remains unknown, never gets today's
		 * grade. Whole protected bindings reject it above; basic RX may expose
		 * unknown facts for policy to reject without pretending it was secure. */
		level = r->receipt_revision == current_revision ?
				sl_security_owner_level_rust(s->security,
							     current_revision) :
				-EACCES;
		sl_message_receipt_observe(metadata, current_revision, level);
		spin_lock(&c->rx.lock);
		if (c->rx.qlen < SL_CHANNEL_RX &&
		    atomic_read(&c->sk->sk_rmem_alloc) <
			    READ_ONCE(c->sk->sk_rcvbuf) &&
		    sk_rmem_schedule(c->sk, r->skb, r->skb->truesize)) {
			skb_set_owner_r(r->skb, c->sk);
			__skb_queue_tail(&c->rx, r->skb);
			r->skb = NULL;
			r->wake = c->sk;
			sock_hold(r->wake);
		}
		spin_unlock(&c->rx.lock);
	}
	if (r->skb)
		c->rx_dropped++;
	spin_unlock_irqrestore(&s->lock, flags);
	return 0;
}
/* Exactly one session worker consumes the connection's ACB queue. Decode once,
 * route CMTC to session state, then route DTAP by local TCID/PI to channel RX. */
static void sl_route(struct sl_connection_session *s, const u8 *bytes,
		     size_t length, u64 security_revision)
{
	unsigned long flags;
	struct sl_channel_frame frame;
	struct sl_basic_channel *c;
	int slot;
	struct sl_channel_cap cap;
	struct sk_buff *skb;
	struct sock *sk = NULL;
	unsigned int code, identifier, mask;
	int ret;

	ret = sl_channel_frame_decode(bytes, length, &frame);
	if (ret)
		return;
	if (frame.tcid == SL_CHANNEL_CMTC) {
		if (frame.length && frame.data[0] >= SL_CMTC_CONNECT_REQ &&
		    frame.data[0] <= SL_CMTC_CLOSE_RSP) {
			struct sl_dynamic_received r = { .session = s };
			if (length > sl_snapshot(s).mps)
				return;
			if (!sl_channel_signal_decode(frame.data, frame.length,
						      &r.message) &&
			    !sparklink_native_session_admit(
				    s->controller, s->generation, s->lifetime,
				    s->handle, s->epoch, sl_dynamic_receive,
				    &r) &&
			    r.changed)
				sl_wake(s);
			return;
		}
		if (sl_channel_cap_decode(frame.data, frame.length, &code,
					  &identifier, &mask, &cap))
			return;
		if (code == 1) {
			if (s->response_pending &&
			    s->response_id != identifier) {
				sl_fault(s, -EPROTO);
				return;
			}
			if (!s->response_pending)
				s->response_deadline =
					jiffies + msecs_to_jiffies(5000);
			s->response_pending = true;
			s->response_id = identifier;
			s->response_mask = mask;
		} else if (identifier == SL_CHANNEL_CAP_IDENTIFIER &&
			   sl_snapshot(s).request_submitted) {
			sl_progress_event(s, 2, cap.mtu, cap.mps);
		}
		return;
	}
	slot = sl_channel_rx_slot(frame.tcid, frame.pi);
	if (slot < 0) {
		unsigned int i;
		spin_lock_irqsave(&s->lock, flags);
		for (i = SL_FIXED_CHANNELS; i < SL_SESSION_CHANNELS; i++)
			if (s->channels[i].dynamic &&
			    s->channels[i].local_tcid == frame.tcid &&
			    s->channels[i].pi == frame.pi) {
				slot = i;
				break;
			}
		spin_unlock_irqrestore(&s->lock, flags);
	}
	if (slot < 0)
		return;
	c = &s->channels[slot];
	skb = alloc_skb(frame.length, GFP_KERNEL);
	if (!skb)
		return;
	memset(skb->cb, 0, sizeof(skb->cb));
	memcpy(skb_put(skb, frame.length), frame.data, frame.length);
	{
		struct sl_routed_data r = { .session = s,
					    .channel = c,
					    .frame = &frame,
					    .skb = skb,
					    .receipt_revision =
						    security_revision,
					    .pdu_length = length };
		/* Retirement may win before delivery; it cannot mint known/current
		 * facts or attach data to a successor controller/lifetime. */
		sparklink_native_session_admit(s->controller, s->generation,
					       s->lifetime, s->handle, s->epoch,
					       sl_deliver, &r);
		skb = r.skb;
		sk = r.wake;
	}
	kfree_skb(skb);
	if (sk) {
		sk->sk_data_ready(sk);
		sock_put(sk);
	}
}
/* No physical prefix exists: queue timeout retires only its application
 * Binding. It cannot consume another Channel's queues or stop the controller. */
static void sl_fail_channel(struct sl_connection_session *s,
			    struct sl_basic_channel *c, int error)
{
	unsigned long flags;
	struct sock *sk;
	spin_lock_irqsave(&s->lock, flags);
	sl_binding_retire(&c->binding);
	sk = c->sk;
	if (sk)
		sock_hold(sk);
	spin_unlock_irqrestore(&s->lock, flags);
	sl_purge_tx(s, c);
	skb_queue_purge(&c->rx);
	if (sk) {
		sl_socket_fault(sk, error);
		sock_put(sk);
	}
}
struct sl_security_probe {
	struct sl_connection_session *session;
	struct sl_basic_channel *channel;
};
static int sl_security_probe(void *context, u64 security_revision)
{
	struct sl_security_probe *p = context;
	unsigned long flags;
	int ret;
	spin_lock_irqsave(&p->session->lock, flags);
	ret = p->channel->sk && sl_binding_live(p->channel->binding) ?
		      sl_security_check(p->session, p->channel,
					security_revision) :
		      0;
	spin_unlock_irqrestore(&p->session->lock, flags);
	return ret;
}
/* Serialized worker or stop-after-join only. Physical credit lives in Runtime
 * and is never returned by dropping an operation or closing its author fd. */
static void sl_retire_tx(struct sl_connection_session *s)
{
	unsigned long flags;
	struct sk_buff *skb;
	spin_lock_irqsave(&s->lock, flags);
	skb = s->tx_inflight;
	if (skb) {
		struct sl_fragment_cursor *cursor = (void *)skb->cb;
		trace_sparklink_session_queue(s->controller, s->generation, s->lifetime,
			s->epoch, cursor->observation, s->fragment_slot, skb->len,
			cursor->deadline, 2);
		sl_binding_finish_tx(&s->channels[s->fragment_slot].binding);
		s->tx_inflight = NULL;
		s->tx_started = false;
		s->fragment_slot = -1;
	}
	spin_unlock_irqrestore(&s->lock, flags);
	kfree_skb(skb);
}
static void sl_expire_queued_channel(struct sl_connection_session *s, struct sl_basic_channel *c)
{
	unsigned long flags;
	struct sk_buff *skb;
	bool expired;

	/* A queued channel's original deadline cannot be hidden behind another
	 * channel's begun PB sequence. Expire only its unsubmitted local queue. */
	spin_lock_irqsave(&s->lock, flags);
	spin_lock(&c->tx.lock);
	skb = skb_peek(&c->tx);
	expired = skb && time_after_eq(jiffies,
		((struct sl_fragment_cursor *)skb->cb)->deadline);
	spin_unlock(&c->tx.lock);
	spin_unlock_irqrestore(&s->lock, flags);
	if (expired) {
		sl_fail_channel(s, c, -ETIMEDOUT);
		s->work_progress = true;
	}
}
static int sl_transmit_channel(struct sl_connection_session *s, struct sl_basic_channel *c,
			       struct sl_tx_budget *budget, struct sl_tx_step *step)
{
	unsigned long flags;
	struct sk_buff *skb;
	struct sl_fragment_cursor *cursor;
	struct sl_submit_scope permission = { .session = s, .channel = c };
	unsigned int length, boundary;
	int slot = c - s->channels, ret = 0;
	bool started, local_timeout, local_constraint;
	u32 wait = SPARKLINK_ACB_WAIT_RETRY;

	*step = (struct sl_tx_step){ 0 };
	spin_lock_irqsave(&s->lock, flags);
	if (s->tx_inflight && s->fragment_slot != slot) {
		spin_unlock_irqrestore(&s->lock, flags);
		return 0; /* PB has no TCID: never interleave physical PDUs. */
	}
	if (!s->tx_inflight && s->progress.phase == SL_CH_OPEN &&
	    sl_binding_live(c->binding) && sl_permits(s, c, SL_GRANT_TX) && !c->binding.busy) {
		s->tx_inflight = skb_dequeue(&c->tx);
		if (s->tx_inflight) {
			struct sl_fragment_cursor *observed = (void *)s->tx_inflight->cb;
			trace_sparklink_session_queue(s->controller, s->generation, s->lifetime,
				s->epoch, observed->observation, slot, s->tx_inflight->len,
				observed->deadline, 1);
			sl_binding_start_tx(&c->binding);
			s->fragment_slot = slot;
			s->tx_started = false;
			s->tx_grant = sl_sk(c->sk)->grant;
		}
	}
	skb = s->tx_inflight;
	spin_unlock_irqrestore(&s->lock, flags);
	if (!skb)
		return 0;
	cursor = (void *)skb->cb;
	permission.operation = skb;
	if (time_after_eq(jiffies, cursor->deadline) ||
        (cursor->intent_deadline_ns && !sl_send_constraint_timely(cursor->intent_deadline_ns, ktime_get_ns())))
        ret = -ETIMEDOUT;
	else if (!sl_fragment_next(skb->len, cursor->offset, s->acb_maximum, &length, &boundary))
		ret = -EPROTO;
	else {
		if (!sl_tx_budget_charge(budget, length, ktime_get_ns())) {
			s->tx_budget_exhausted = true;
			return 0; /* Keep this operation and its original deadline. */
		}
		permission.sequence = cursor->observation;
		permission.boundary = boundary; permission.length = length;
		permission.offset = cursor->offset;
		step->attempted = true;
		trace_sparklink_session_tx(s->controller, s->generation, s->lifetime,
			s->service_sequence, permission.sequence, slot, boundary, length,
			cursor->offset, -EINPROGRESS, SPARKLINK_ACB_WAIT_NONE, 0);
		ret = sparklink_native_acb_send_deferred(s->controller, s->generation,
			s->lifetime, s->handle, boundary, skb->data + cursor->offset, length,
			s->epoch, sl_session_submit, &permission, &wait);
		step->result = ret; step->wait = wait; step->submitted = !ret;
		trace_sparklink_session_tx(s->controller, s->generation, s->lifetime,
			s->service_sequence, permission.sequence, slot, boundary, length,
			cursor->offset, ret, wait, 1);
	}
	sl_send_result(s, ret, wait);
	spin_lock_irqsave(&s->lock, flags);
	if (!ret && !sl_fragment_advance(cursor, skb->len, length))
		ret = -EPROTO;
	started = s->tx_started;
	local_timeout = ret == -ETIMEDOUT && !started;
    local_constraint = ret == -EACCES && !started && cursor->security_epoch;
	if (ret == -EAGAIN && !started && sl_binding_live(c->binding)) {
		/* Zero submitted prefix: return author-owned work for fair scheduling.
		 * Close linearizes under this lock and may purge it after retirement. */
		sl_binding_finish_tx(&c->binding);
		skb_queue_head(&c->tx, skb);
		s->tx_inflight = NULL;
		s->fragment_slot = -1;
		skb = NULL;
	} else if (ret == -EAGAIN && !started) {
		ret = 0; /* detached before any USB acceptance */
	} else if (ret == -EAGAIN || (!ret && cursor->offset < skb->len)) {
		/* Once started, fd detach cannot erase this Session-owned obligation.
		 * Runtime still verifies managed epoch/lifetime before every USB submit. */
		if (started)
			skb = NULL;
	} else if (ret == -ECANCELED && !started) {
		ret = 0; /* author closed before first submit: no physical obligation */
	}
	spin_unlock_irqrestore(&s->lock, flags);
	if (skb) {
		sl_retire_tx(s);
		s->work_progress = true; /* bounded retirement exposes the next queued item */
	}
	if (local_timeout || local_constraint) {
		sl_fail_channel(s, c, ret);
		ret = 0;
	}
	sl_wake(s);
	return ret == -EAGAIN ? 0 : ret;
}
/* Snapshot runnable queues under the existing Session -> queue lock order.
 * Selection is only a hint; actual submit rechecks all physical authority.
 */
static int sl_tx_select(struct sl_connection_session *s)
{
	unsigned long flags;
	unsigned int i, ready = 0;
	int slot;

	spin_lock_irqsave(&s->lock, flags);
	if (s->fragment_slot >= 0) {
		slot = s->fragment_slot;
	} else {
		for (i = 0; i < SL_SESSION_CHANNELS; i++) {
			struct sl_basic_channel *c = &s->channels[i];

			if (!sl_binding_live(c->binding) || c->binding.busy ||
			    !sl_permits(s, c, SL_GRANT_TX))
				continue;
			spin_lock(&c->tx.lock);
			if (skb_peek(&c->tx))
				ready |= 1U << i;
			spin_unlock(&c->tx.lock);
		}
		slot = sl_tx_policy_choose(&s->tx_policy, ready);
	}
	spin_unlock_irqrestore(&s->lock, flags);
	return slot;
}
/* At most six empty visits between budgeted attempts. A begun PB stream
 * retains the physical connection until its PDU ends, then advance its class.
 * This loop owns no new references and never creates or refunds credit. */
static int sl_transmit_batch(struct sl_connection_session *s, struct sl_tx_budget *budget)
{
	unsigned int i, idle = 0;
	int slot, ret;
	struct sl_tx_step step;

	s->tx_blocked = false;
	for (i = 0; i < SL_SESSION_CHANNELS; i++)
		sl_expire_queued_channel(s, &s->channels[i]);
	while (sl_channel_active(sl_snapshot(s))) {
		slot = sl_tx_select(s);
		if (slot < 0)
			break;
		ret = sl_transmit_channel(s, &s->channels[slot], budget, &step);
		if (ret || budget->stop != SL_TX_BUDGET_NONE)
			return ret;
		/* All channels share this physical pool/transport. Return to original
		 * event/deadline scheduling at a real credit wait or other retry. */
		if (step.attempted && step.result == -EAGAIN) {
			s->tx_blocked = true;
			/* No credit means no PDU was served. Retain this turn until
			 * real pool progress; rotating on each empty-pool probe lets a
			 * long peer repeatedly consume the next returned credit. */
			if (s->fragment_slot < 0 &&
			    step.wait != SPARKLINK_ACB_WAIT_CREDIT)
				sl_tx_policy_yield(&s->tx_policy, slot);
			break;
		}
		if (step.submitted && s->fragment_slot < 0)
			sl_tx_policy_complete(&s->tx_policy, slot);
		if (step.submitted)
			idle = 0;
		else if (++idle == SL_SESSION_CHANNELS)
			break;
	}
	return 0;
}
static void sl_shift_rejection(struct sl_connection_session *s)
{
	s->rejection_count--;
	memmove(s->rejection, s->rejection + 1,
		s->rejection_count * sizeof(s->rejection[0]));
	memmove(s->rejection_deadline, s->rejection_deadline + 1,
		s->rejection_count * sizeof(s->rejection_deadline[0]));
	s->work_progress = true;
}
static void sl_dynamic_work(struct sl_connection_session *s)
{
	unsigned int i;
	unsigned long flags;
	u8 signal[32], wire[36];
	int n, ret;
	bool wake = false;

	for (i = SL_FIXED_CHANNELS; i < SL_SESSION_CHANNELS; i++) {
		struct sl_basic_channel *c = &s->channels[i];
		struct sl_channel_signal m = { 0 };
		struct sl_dynamic_submit consent = { .session = s,
						     .channel = c };
		bool notify = false;
		int error = 0;
		u32 wait = SPARKLINK_ACB_WAIT_RETRY;
		spin_lock_irqsave(&s->lock, flags);
		if (!c->dynamic) {
			spin_unlock_irqrestore(&s->lock, flags);
			continue;
		}
		sl_dynamic_tick(&c->negotiation,
				time_after_eq(jiffies, c->dynamic_deadline));
		if ((c->negotiation.phase == SL_DYN_FAILED ||
		     c->negotiation.phase == SL_DYN_RETIRED ||
		     c->negotiation.phase == SL_DYN_CLOSE_RESPONSE) &&
		    !c->dynamic_notified) {
			c->dynamic_notified = true;
			notify = true;
			error = c->dynamic_error ? c->dynamic_error :
						   -ETIMEDOUT;
		}
		consent.phase = c->negotiation.phase;
		if (s->progress.phase == SL_CH_OPEN && s->fragment_slot < 0) {
			m.source = c->local_tcid;
			m.destination = c->remote_tcid;
			m.identifier = c->negotiation.identifier;
			switch (consent.phase) {
			case SL_DYN_CONNECT:
				if (c->mtu > s->progress.mtu ||
				    c->mps > s->progress.mps ||
				    s->progress.mps < 26) {
					c->negotiation.phase = SL_DYN_FAILED;
					c->dynamic_error = -EMSGSIZE;
				s->work_progress = true;
					break;
				}
				m.code = SL_CMTC_CONNECT_REQ;
				m.mtu = c->mtu;
				m.mps = c->mps;
				m.exclusive = 1;
				m.ports = 1;
				m.source_port = c->source_port;
				m.destination_port = c->destination_port;
				m.aid = c->aid;
				m.slqi_count = 1;
				m.slqi[0] = c->slqi;
				break;
			case SL_DYN_RESPONSE:
			case SL_DYN_REJECT:
				m.code = SL_CMTC_CONNECT_RSP;
				m.identifier = c->negotiation.peer_identifier;
				m.source = c->remote_tcid;
				m.destination = c->local_tcid;
				m.result = consent.phase == SL_DYN_REJECT ? 1 :
									    0;
				break;
			case SL_DYN_CLOSE:
				m.code = SL_CMTC_CLOSE_REQ;
				break;
			case SL_DYN_CLOSE_RESPONSE:
				m.code = SL_CMTC_CLOSE_RSP;
				m.identifier = c->negotiation.peer_identifier;
				m.source = c->remote_tcid;
				m.destination = c->local_tcid;
				break;
			default:
				break;
			}
		}
		spin_unlock_irqrestore(&s->lock, flags);
		if (notify) {
			if (c->peer_closed) {
				struct sock *sk;
				bool granted;
				spin_lock_irqsave(&s->lock, flags);
				sk = c->sk;
				granted = sk && sl_sk(sk)->grant.scope.lifetime;
				if (sk)
					sock_hold(sk);
				spin_unlock_irqrestore(&s->lock, flags);
				sl_purge_tx(s, c); /* begun PDU is Session-owned */
				if (sk) {
					if (!granted)
						sl_socket_fault(sk,
								-ECONNRESET);
					WRITE_ONCE(sk->sk_state, TCP_CLOSE);
					sk->sk_data_ready(sk);
					sk->sk_state_change(sk);
					sock_put(sk);
				}
			} else
				sl_fail_channel(s, c, error);
			wake = true;
		}
		if (!m.code)
			continue;
		n = sl_channel_signal_encode(signal, sizeof(signal), &m);
		if (n >= 0)
			n = sl_channel_frame_encode(wire, sizeof(wire),
						    SL_CHANNEL_CMTC, 0, signal,
						    n);
		consent.pdu_bytes = n > 0 ? n : 0;
		if (n < 0) {
			ret = n;
		} else {
			consent.observation = ++s->tx_sequence;
			trace_sparklink_session_tx(s->controller, s->generation,
				s->lifetime, s->service_sequence, consent.observation,
				-1, 0, n, 0, -EINPROGRESS, SPARKLINK_ACB_WAIT_NONE, 0);
			ret = sparklink_native_acb_send_deferred(s->controller,
				s->generation, s->lifetime, s->handle, 0, wire, n,
				s->epoch, sl_dynamic_consent, &consent, &wait);
			trace_sparklink_session_tx(s->controller, s->generation,
				s->lifetime, s->service_sequence, consent.observation,
				-1, 0, n, 0, ret, wait, 1);
		}
		sl_send_result(s, ret, wait);
		if (!ret)
			wake = true;
		if (ret && ret != -EAGAIN && ret != -ECANCELED) {
			spin_lock_irqsave(&s->lock, flags);
			c->negotiation.phase = SL_DYN_FAILED;
			c->dynamic_error = ret;
			s->work_progress = true;
			spin_unlock_irqrestore(&s->lock, flags);
		}
	}
	/* Drop expired unsent negative responses even behind another PDU. Their
	 * original deadline must not turn into immediate reschedule spinning. */
	while (s->rejection_count && time_after_eq(jiffies, s->rejection_deadline[0]))
		sl_shift_rejection(s);
	/* Explicit failure only, bounded FIFO; no fabricated success for unknown endpoints. */
	if (s->rejection_count && s->fragment_slot < 0 &&
	    sl_snapshot(s).phase == SL_CH_OPEN) {
		n = sl_channel_signal_encode(signal, sizeof(signal),
					     &s->rejection[0]);
		if (n >= 0)
			n = sl_channel_frame_encode(wire, sizeof(wire),
						    SL_CHANNEL_CMTC, 0, signal,
						    n);
		ret = n < 0 ? n : sl_send(s, NULL, wire, n);
		if (!ret)
			sl_shift_rejection(s);
	}
	if (wake)
		sl_wake(s);
}
/* One bounded pass, then sleep until an event, earliest original deadline,
 * or explicit non-credit EAGAIN retry. Caller is the sole Session worker.
 * Queue peeks take TX lock beneath Session lock: detach purges outside it. */
static struct sl_session_schedule sl_next_schedule(struct sl_connection_session *s)
{
	struct sl_session_schedule plan = { 0 };
	unsigned long flags, now = jiffies;
	bool runnable = false;
	unsigned int i;

	spin_lock_irqsave(&s->lock, flags);
	if (!sl_channel_active(s->progress))
		goto unlock;
	if (s->progress.phase == SL_CH_NEGOTIATING) {
		sl_session_schedule_deadline(&plan, now, s->deadline);
		runnable = !s->progress.request_submitted;
	}
	if (s->unknown_deadline)
		sl_session_schedule_deadline(&plan, now, s->unknown_deadline);
	if (s->response_pending) {
		sl_session_schedule_deadline(&plan, now, s->response_deadline);
		runnable |= s->fragment_slot < 0;
	}
	if (s->rejection_count) {
		sl_session_schedule_deadline(&plan, now, s->rejection_deadline[0]);
		runnable |= s->fragment_slot < 0;
	}
	if (s->tx_inflight) {
		struct sl_fragment_cursor *cursor = (void *)s->tx_inflight->cb;
		sl_session_schedule_deadline(&plan, now, cursor->deadline);
		runnable = true;
	}
	for (i = 0; i < SL_SESSION_CHANNELS; i++) {
		struct sl_basic_channel *c = &s->channels[i];
		struct sk_buff *skb;
		if (c->dynamic && sl_dynamic_pending(c->negotiation)) {
			sl_session_schedule_deadline(&plan, now, c->dynamic_deadline);
			if (s->progress.phase == SL_CH_OPEN && s->fragment_slot < 0 &&
			    (c->negotiation.phase == SL_DYN_CONNECT ||
			     c->negotiation.phase == SL_DYN_RESPONSE ||
			     c->negotiation.phase == SL_DYN_REJECT ||
			     c->negotiation.phase == SL_DYN_CLOSE ||
			     c->negotiation.phase == SL_DYN_CLOSE_RESPONSE))
				runnable = true;
		}
		if (c->dynamic && !c->dynamic_notified &&
		    (c->negotiation.phase == SL_DYN_FAILED || c->negotiation.phase == SL_DYN_RETIRED))
			sl_session_schedule_delay(&plan, 0);
		if (!sl_binding_live(c->binding))
			continue;
		spin_lock(&c->tx.lock);
		skb = skb_peek(&c->tx);
		if (skb) {
			struct sl_fragment_cursor *cursor = (void *)skb->cb;
			sl_session_schedule_deadline(&plan, now, cursor->deadline);
			runnable = true;
		}
		spin_unlock(&c->tx.lock);
	}
	if (s->rx_budget_exhausted ||
	    (runnable && !s->tx_blocked && (s->work_progress || s->tx_budget_exhausted)))
		sl_session_schedule_delay(&plan, 0);
	else if ((runnable || s->unknown_deadline) && s->work_retry)
		sl_session_schedule_delay(&plan, msecs_to_jiffies(10));
unlock:
	spin_unlock_irqrestore(&s->lock, flags);
	return plan;
}
static void sl_work(struct work_struct *work)
{
	struct sl_connection_session *s = container_of(to_delayed_work(work), struct sl_connection_session, work);
	u8 signal[32], wire[36];
	size_t size;
	int ret = 0, n;
	unsigned int i;
	struct sl_session_schedule plan = { 0 };
	struct sl_tx_budget budget = { 0 };
	u64 began = ktime_get_ns(), security_revision;
	unsigned long state_flags;

	spin_lock_irqsave(&s->lock, state_flags);
	s->service_running = true;
	spin_unlock_irqrestore(&s->lock, state_flags);

	s->service_sequence++;
	trace_sparklink_session_work(s->controller, s->generation, s->lifetime,
		s->epoch, s->service_sequence, 0, 0, 0, 0, 0, ~0UL, 0);
	s->work_progress = s->work_retry = s->rx_budget_exhausted = s->tx_budget_exhausted = false;
	s->tx_blocked = false;
	if (!sl_channel_active(sl_snapshot(s)))
		goto put;
	ret = sparklink_native_session_status(s->controller, s->generation, s->lifetime, s->handle, s->epoch);
	if (ret == -EAGAIN) {
		s->work_retry = true;
		/* Unknown physical state is bounded independently of CMTC deadline. */
		sl_progress_event(s, 0, 0, 0);
		if (!s->unknown_deadline)
			s->unknown_deadline = jiffies + msecs_to_jiffies(5000);
		if (time_after_eq(jiffies, s->unknown_deadline))
			sl_fault(s, -ETIMEDOUT);
		goto again;
	}
	s->unknown_deadline = 0;
	if (ret) {
		sl_fault(s, ret);
		goto put;
	}
	for (i = 0; i < SL_SESSION_CHANNELS; i++) {
		struct sl_security_probe p = { s, &s->channels[i] };
		bool protected;
		spin_lock_irqsave(&s->lock, state_flags);
		protected = p.channel->sk &&
			    sl_binding_live(p.channel->binding) &&
			    sl_sk(p.channel->sk)->grant.security;
		spin_unlock_irqrestore(&s->lock, state_flags);
		if (!protected)
			continue;
		ret = sparklink_native_session_admit(s->controller,
						     s->generation, s->lifetime,
						     s->handle, s->epoch,
						     sl_security_probe, &p);
		if (ret == -EACCES)
			sl_fail_channel(s, p.channel, ret);
	}
	sl_progress_event(s, 0, 0, 0);
	if (!sl_channel_active(sl_snapshot(s)))
		goto put;
	if (!sl_snapshot(s).request_submitted) {
		n = sl_channel_cap_request(signal, sizeof(signal), SL_CHANNEL_CAP_IDENTIFIER);
		if (n >= 0)
			n = sl_channel_frame_encode(wire, sizeof(wire), SL_CHANNEL_CMTC, 0, signal, n);
		if (n < 0) { sl_fault(s, n); goto put; }
		ret = sl_send(s, NULL, wire, n);
		if (ret == -EAGAIN)
			goto again;
		if (ret) { sl_fault(s, ret); goto put; }
		sl_progress_event(s, 1, 0, 0);
	}
	for (i = 0; i < 16 && sl_channel_active(sl_snapshot(s)); i++) {
		ret = sparklink_native_acb_take(s->controller, s->generation,
						s->lifetime, s->handle,
						s->rx_buffer,
						sizeof(s->rx_buffer), &size,
						&security_revision);
		if (ret == -EAGAIN)
			break;
		if (ret) { sl_fault(s, ret); break; }
		sl_route(s, s->rx_buffer, size, security_revision);
	}
	s->rx_budget_exhausted = i == 16;
	if (!sl_channel_active(sl_snapshot(s)))
		goto put;
	if (s->response_pending && time_after_eq(jiffies, s->response_deadline)) {
		sl_fault(s, -ETIMEDOUT);
		goto put;
	}
	if (s->response_pending && s->fragment_slot < 0) {
		n = sl_channel_cap_response(signal, sizeof(signal), s->response_id, s->response_mask, sl_snapshot(s).maximum, sl_snapshot(s).maximum_mps);
		if (n >= 0)
			n = sl_channel_frame_encode(wire, sizeof(wire), SL_CHANNEL_CMTC, 0, signal, n);
		if (n < 0) { sl_fault(s, n); goto put; }
		ret = sl_send(s, NULL, wire, n);
		if (ret == -EAGAIN)
			goto again;
		if (ret) { sl_fault(s, ret); goto put; }
		s->response_pending = false;
		sl_progress_event(s, 3, 0, 0);
	}
	sl_dynamic_work(s);
	budget = sl_tx_budget_begin(ktime_get_ns());
	ret = sl_transmit_batch(s, &budget);
	if (ret) { sl_fault(s, ret); goto put; }
again:
	sl_progress_event(s, 0, 0, 0);
	plan = sl_next_schedule(s);
	if (plan.pending)
		sl_schedule(s, plan.delay);
put:
	if (!plan.pending)
		sl_cancel_wake_hint(s);
	if (!sl_channel_active(sl_snapshot(s)))
		sl_retire_tx(s);
	trace_sparklink_session_work(s->controller, s->generation, s->lifetime,
		s->epoch, s->service_sequence, 1, budget.packets, budget.bytes,
		budget.stop, ktime_get_ns() - began, plan.pending ? plan.delay : ~0UL, ret);
	/* Inspection holds the same lock; when false it may read worker-private
	 * pending-control fields. This does not mean the final work ref drained.
	 */
	spin_lock_irqsave(&s->lock, state_flags);
	s->service_running = false;
	spin_unlock_irqrestore(&s->lock, state_flags);
	sl_connection_session_put(s);
}
void *sl_connection_session_create(u16 controller, u64 generation, u64 lifetime, u16 handle, u64 epoch, u16 maximum)
{
	struct sl_connection_session *s = kzalloc(sizeof(*s), GFP_KERNEL);
	unsigned int i;
	if (!s)
		return NULL;
	if (maximum < 24 || maximum > SL_FRAGMENT_PDU_MAX) { kfree(s); return NULL; }
	s->security = sl_security_owner_create_rust(controller, generation, lifetime, handle, epoch);
	if (!s->security) { kfree(s); return NULL; }
	kref_init(&s->refs);
	s->controller = controller; s->generation = generation; s->lifetime = lifetime; s->handle = handle; s->epoch = epoch;
	spin_lock_init(&s->lock);
	INIT_DELAYED_WORK(&s->work, sl_work);
	hrtimer_setup(&s->wake_timer, sl_deadline_wake, CLOCK_MONOTONIC, HRTIMER_MODE_REL_SOFT);
	for (i = 0; i < SL_SESSION_CHANNELS; i++) {
		struct sl_basic_channel *c = &s->channels[i];
		skb_queue_head_init(&c->tx);
		skb_queue_head_init(&c->rx);
		c->local_tcid = i >= SL_FIXED_CHANNELS	  ? 0 :
				i == SL_CHANNEL_USER_SLOT ? SL_CHANNEL_CUTC :
							    SL_CHANNEL_SMTC;
		c->remote_tcid = c->local_tcid;
		c->pi = i == SL_CHANNEL_USER_SLOT ? SPARKLINK_SOCKET_USER_PI : 0;
	}
	/* Physical session exists before any application fd. Start the sole CMTC
	 * negotiation at the first authorized channel binding, never at allocation
	 * or each subsequent fd open. Inactive sessions have no work/timer refs.
	 */
	s->acb_maximum = maximum;
	s->fragment_slot = -1;
	s->next_signal_id = 1;
	s->next_tcid = 0x80;
	s->progress.maximum = SL_FRAGMENT_PDU_MAX - 5;
	s->progress.maximum_mps = SL_FRAGMENT_PDU_MAX;
	return s;
}
void sl_connection_session_stop(void *opaque, int error)
{
	unsigned long flags;
	struct sl_connection_session *s = opaque;
	struct sock *sockets[SL_SESSION_CHANNELS];
	unsigned int i;

	sl_security_owner_stop_rust(s->security);
	spin_lock_irqsave(&s->lock, flags);
	sl_channel_close(&s->progress);
	for (i = 0; i < SL_SESSION_CHANNELS; i++) {
		sl_binding_retire(&s->channels[i].binding);
		sockets[i] = s->channels[i].sk;
		s->channels[i].sk = NULL;
	}
	spin_unlock_irqrestore(&s->lock, flags);
	for (i = 0; i < SL_SESSION_CHANNELS; i++) {
		if (sockets[i]) {
			sl_socket_fault(sockets[i], error);
			sock_put(sockets[i]); /* session's binding reference */
		}
	}
	/* Owner/action ref is still held. No Session lock across either join;
	 * close above rejects timer/event callbacks before the owner can drop.
	 */
	hrtimer_cancel(&s->wake_timer);
	if (cancel_delayed_work_sync(&s->work))
		sl_connection_session_put(s); /* queued work owned one reference */
	sl_retire_tx(s); /* joined worker cannot hold the borrowed operation */
	for (i = 0; i < SL_SESSION_CHANNELS; i++) {
		sl_purge_tx(s, &s->channels[i]);
		skb_queue_purge(&s->channels[i].rx);
	}
}
struct sl_bind_admission {
	struct socket *sock;
	struct sl_socket_binding *binding;
	struct sl_connection_session *session;
	struct sl_channel_grant grant;
	unsigned int channel_slot;
};
/* Final publication takes Host/data/gate -> Binding -> Session. No sleeping
 * allocation/lookup spans any of these locks. Revoked first cannot mint. */
static int sl_publish_binding(void *context, u64 security_revision)
{
	struct sl_bind_admission *admission = context;
	struct socket *sock = admission->sock;
	struct sl_socket_binding *binding = admission->binding;
	struct sl_connection_session *s = admission->session;
	struct sl_basic_channel *c = &s->channels[admission->channel_slot];
	unsigned long flags, binding_flags;
	int ret = 0;
	int level = admission->grant.security ?
			    sl_security_owner_level_rust(s->security,
							 security_revision) :
			    0;
	if (level < 0 ||
	    !sl_grant_init_security(&admission->grant, admission->grant.scope,
				    admission->grant.directions,
				    admission->grant.security,
				    security_revision, level))
		return -EACCES;
	spin_lock_irqsave(&binding->lock, binding_flags);
	spin_lock_irqsave(&s->lock, flags);
	if (binding->session)
		ret = -EINVAL;
	else if (s->progress.phase != SL_CH_UNBOUND && !sl_channel_active(s->progress))
		ret = -ECONNRESET;
	else if (c->binding.retired)
		ret = -EOPNOTSUPP; /* no qualified same-life CUTC close/rebind barrier */
	else if (c->binding.bound)
		ret = -EADDRINUSE;
	else {
		if (s->progress.phase == SL_CH_UNBOUND) {
			sl_channel_start(&s->progress, s->progress.maximum, s->progress.maximum_mps);
			s->deadline = jiffies + msecs_to_jiffies(5000);
		}
		binding->grant = admission->grant;
		binding->channel_slot = admission->channel_slot;
		sl_binding_attach(&c->binding);
		c->sk = sock->sk;
		sock_hold(sock->sk);
		binding->session = s; /* transfer caller's session reference */
		sock->state = SS_CONNECTED;
		WRITE_ONCE(sock->sk->sk_state, TCP_ESTABLISHED);
	}
	spin_unlock_irqrestore(&s->lock, flags);
	spin_unlock_irqrestore(&binding->lock, binding_flags);
	return ret;
}
struct sl_dynamic_admission {
	struct socket *sock;
	struct sl_connection_session *session;
	const struct sockaddr_sparklink_dynamic *address;
	bool active;
};
static int sl_dynamic_publish(void *context, u64 security_revision)
{
	(void)security_revision; /* Dynamic protected modes remain unsupported. */
	struct sl_dynamic_admission *a = context;
	struct sl_connection_session *s = a->session;
	struct sl_socket_binding *b = sl_sk(a->sock->sk);
	const struct sockaddr_sparklink_dynamic *in = a->address;
	struct sl_basic_channel *c = NULL;
	unsigned long flags, binding_flags;
	unsigned int i, slot = 0;
	int ret = 0;

	spin_lock_irqsave(&b->lock, binding_flags);
	spin_lock_irqsave(&s->lock, flags);
	if (b->session) {
		ret = -EINVAL;
		goto unlock;
	}
	if (s->progress.phase != SL_CH_UNBOUND &&
	    !sl_channel_active(s->progress)) {
		ret = -ENOTCONN;
		goto unlock;
	}
	if (a->active && s->acb_maximum < 26) {
		ret = -EOPNOTSUPP;
		goto unlock;
	}
	for (i = SL_FIXED_CHANNELS; i < SL_SESSION_CHANNELS; i++) {
		struct sl_basic_channel *entry = &s->channels[i];
		if (entry->dynamic && sl_binding_live(entry->binding) &&
		    entry->source_port == in->source_port &&
		    entry->destination_port == in->destination_port &&
		    entry->aid == in->aid) {
			ret = -EADDRINUSE;
			goto unlock;
		}
		if (!c && entry->negotiation.phase == SL_DYN_UNUSED) {
			c = entry;
			slot = i;
		}
	}
	if (!c || s->next_tcid > 0xdf ||
	    (a->active && s->next_signal_id > 255)) {
		ret = -ENOSPC;
		goto unlock;
	}
	if (s->progress.phase == SL_CH_UNBOUND) {
		sl_channel_start(&s->progress, s->progress.maximum,
				 s->progress.maximum_mps);
		s->deadline = jiffies + msecs_to_jiffies(5000);
	}
	c->dynamic = true;
	c->local_tcid = s->next_tcid++;
	c->pi = in->base.pi;
	c->mtu = in->mtu;
	c->mps = in->mps;
	c->source_port = in->source_port;
	c->destination_port = in->destination_port;
	c->aid = in->aid;
	c->slqi = in->slqi;
	c->pending_directions = in->base.directions;
	c->negotiation.phase = a->active ? SL_DYN_CONNECT : SL_DYN_LISTEN;
	c->negotiation.identifier = a->active ? s->next_signal_id++ : 0;
	c->dynamic_deadline = jiffies + msecs_to_jiffies(5000);
	sl_binding_attach(&c->binding);
	c->sk = a->sock->sk;
	sock_hold(c->sk);
	b->channel_slot = slot;
	b->session =
		s; /* transfer caller's reference; grant is not minted yet */
	a->sock->state = a->active ? SS_CONNECTING : SS_UNCONNECTED;
	WRITE_ONCE(c->sk->sk_state, TCP_SYN_SENT);
unlock:
	spin_unlock_irqrestore(&s->lock, flags);
	spin_unlock_irqrestore(&b->lock, binding_flags);
	return ret;
}
static int sl_dynamic_attach(struct socket *sock,
			     struct sockaddr_unsized *address, int length,
			     bool active)
{
	const struct sockaddr_sparklink_dynamic *in = (void *)address;
	struct sl_connection_session *s;
	int ret;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	if (length != sizeof(*in) || in->base.family != AF_SPARKLINK ||
	    in->base.version != SPARKLINK_SOCKET_DYNAMIC_VERSION ||
	    in->base.flags ||
	    memchr_inv(in->base.reserved, 0, sizeof(in->base.reserved)) ||
	    in->reserved || in->base.local_tcid || in->base.remote_tcid ||
	    !in->base.directions ||
	    in->base.directions &
		    ~(SPARKLINK_SOCKET_TX | SPARKLINK_SOCKET_RX) ||
	    in->base.pi < 241 || in->base.pi > 250 || !in->source_port ||
	    !in->destination_port || !in->aid || !in->mtu || in->mtu > 2042 ||
	    in->mps > 2047 || in->mps < in->mtu + 5U)
		return -EINVAL;
	if (in->mode || in->base.security)
		return -EOPNOTSUPP;
	s = sparklink_native_session_get(in->base.controller,
					 in->base.generation, in->base.lifetime,
					 in->base.handle, in->base.lease, &ret);
	if (!s)
		return ret;
	{
		struct sl_dynamic_admission a = { sock, s, in, active };
		ret = sparklink_native_session_admit(s->controller,
						     s->generation, s->lifetime,
						     s->handle, s->epoch,
						     sl_dynamic_publish, &a);
	}
	if (ret)
		sl_connection_session_put(s);
	else
		sl_connection_session_kick(s);
	return ret;
}
static int sl_connect(struct socket *sock, struct sockaddr_unsized *address,
		      int length, int flags)
{
	int ret;
	if (!(flags & O_NONBLOCK))
		return -EOPNOTSUPP;
	ret = sl_dynamic_attach(sock, address, length, true);
	return ret ? ret : -EINPROGRESS;
}
static int sl_bind(struct socket *sock, struct sockaddr_unsized *address, int length)
{
	struct sl_socket_binding *binding = sl_sk(sock->sk);
	struct sockaddr_sparklink *input = (void *)address;
	struct sl_connection_session *s;
	struct sl_channel_grant grant;
	struct sl_grant_scope scope;
	int ret = 0, slot;

	if (length == sizeof(struct sockaddr_sparklink_dynamic))
		return sl_dynamic_attach(sock, address, length, false);
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	if (length != sizeof(*input) || input->family != AF_SPARKLINK || input->version != SPARKLINK_SOCKET_VERSION ||
	    input->flags || memchr_inv(input->reserved, 0, sizeof(input->reserved)))
		return -EINVAL;
	if (!input->directions || input->directions & ~(SPARKLINK_SOCKET_TX | SPARKLINK_SOCKET_RX))
		return -EINVAL;
	if (input->security > SPARKLINK_SOCKET_SECURITY_AUTHENTICATED)
		return -EOPNOTSUPP;
	slot = sl_channel_key_slot(input->local_tcid, input->remote_tcid, input->pi);
	if (slot < 0)
		return -EOPNOTSUPP;
	scope = (struct sl_grant_scope){ .controller = input->controller,
		.generation = input->generation, .lifetime = input->lifetime, .epoch = input->lease,
		.handle = input->handle, .local_tcid = input->local_tcid,
		.remote_tcid = input->remote_tcid, .pi = input->pi };
	if (!sl_grant_scope_valid(scope))
		return -EINVAL;
	grant = (struct sl_channel_grant){ .scope = scope,
					   .directions = input->directions,
					   .security = input->security };
	s = sparklink_native_session_get(input->controller, input->generation, input->lifetime, input->handle, input->lease, &ret);
	if (!s)
		return ret;
	{
		struct sl_bind_admission admission = { sock, binding, s, grant, slot };
		ret = sparklink_native_session_admit(input->controller, input->generation,
			input->lifetime, input->handle, input->lease, sl_publish_binding, &admission);
	}
	if (ret)
		sl_connection_session_put(s);
	else
		sl_connection_session_kick(s);
	return ret;
}
static int sl_can_write(struct sl_connection_session *s,
			struct sl_basic_channel *c)
{
	unsigned long flags;
	int ready;
	spin_lock_irqsave(&s->lock, flags);
	ready = !sl_channel_active(s->progress) ||
		!sl_binding_live(c->binding) ||
		sl_dynamic_status(c) == -ENOTCONN ||
		(!sl_dynamic_status(c) && !sl_permits(s, c, SL_GRANT_TX)) ||
		(s->progress.phase == SL_CH_OPEN && !sl_dynamic_status(c) &&
		 sl_binding_space(c->binding, skb_queue_len(&c->tx),
				  SL_CHANNEL_TX));
	spin_unlock_irqrestore(&s->lock, flags);
	return ready;
}
struct sl_admission { struct sl_connection_session *session; struct sl_basic_channel *channel; struct sk_buff *skb; size_t length; struct sparklink_send_constraint constraint; };
static int sl_admit(void *context, u64 security_revision)
{
	struct sl_admission *admission = context;
	struct sl_connection_session *s = admission->session;
	struct sl_basic_channel *c = admission->channel;
	struct sk_buff *skb = admission->skb;
	size_t length = admission->length;
	u64 now = ktime_get_ns();
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&s->lock, flags);
	if (sl_binding_live(c->binding) && sl_dynamic_status(c))
		ret = sl_dynamic_status(c);
	else if (sl_binding_live(c->binding) &&
		 (!sl_permits(s, c, SL_GRANT_TX) ||
		  sl_security_check(s, c, security_revision)))
		ret = -EACCES;
	else if ((ret = sl_constraint_check(s, c, &admission->constraint,
					    security_revision))) {
		/* Preserve explicit original-deadline and malformed bounds errors. */
	} else if (s->progress.phase != SL_CH_OPEN ||
		   !sl_binding_live(c->binding))
		ret = sl_channel_active(s->progress) &&
				      sl_binding_live(c->binding) ?
			      -EAGAIN :
			      -ENOTCONN;
	else if (length > c->mtu ||
		 length > sl_channel_payload_limit(s->progress, c->remote_tcid))
		ret = -EMSGSIZE;
	else {
		spin_lock(&c->tx.lock);
		if (!sl_binding_space(c->binding, c->tx.qlen, SL_CHANNEL_TX))
			ret = -EAGAIN;
		else {
			((struct sl_fragment_cursor *)skb->cb)->security_epoch =
				admission->constraint.security_epoch;
			((struct sl_fragment_cursor *)skb->cb)
				->minimum_security =
				admission->constraint.minimum;
			((struct sl_fragment_cursor *)skb->cb)
				->intent_deadline_ns =
				admission->constraint.deadline_monotonic_ns;
			((struct sl_fragment_cursor *)skb->cb)->deadline =
				jiffies +
				(admission->constraint.security_epoch ?
					 min_t(unsigned long,
					       msecs_to_jiffies(5000),
					       nsecs_to_jiffies(
						       admission->constraint
							       .deadline_monotonic_ns -
						       now) +
						       1) :
					 msecs_to_jiffies(5000));
			((struct sl_fragment_cursor *)skb->cb)->observation =
				++s->admission_sequence;
			__skb_queue_tail(&c->tx, skb);
			trace_sparklink_session_queue(
				s->controller, s->generation, s->lifetime,
				s->epoch,
				((struct sl_fragment_cursor *)skb->cb)
					->observation,
				c - s->channels, skb->len,
				((struct sl_fragment_cursor *)skb->cb)->deadline,
				0);
			admission->skb = NULL;
			ret = 0;
		}
		spin_unlock(&c->tx.lock);
	}
	spin_unlock_irqrestore(&s->lock, flags);
	return ret;
}
/* Early permission check prevents a receive-only fd from allocating/copying
 * sender memory or waiting for negotiation. Final queue admission rechecks. */
static int sl_tx_access(void *context, u64 security_revision)
{
	struct sl_admission *admission = context;
	struct sl_connection_session *s = admission->session;
	struct sl_basic_channel *c = admission->channel;
	unsigned long flags;
	int ret;
	spin_lock_irqsave(&s->lock, flags);
	ret = !sl_binding_live(c->binding) ? -ENOTCONN :
	      sl_dynamic_status(c)	   ? sl_dynamic_status(c) :
	      (!sl_permits(s, c, SL_GRANT_TX) ||
	       sl_security_check(s, c, security_revision)) ?
				     -EACCES :
				     0;
	if (!ret)
		ret = sl_constraint_check(s, c, &admission->constraint,
					  security_revision);
	spin_unlock_irqrestore(&s->lock, flags);
	return ret;
}
/* Socket core has copied/converted ancillary input into kernel memory. This
 * parser has one exact record and no allocation or policy side effects. */
static int sl_send_control(struct msghdr *msg,
			   struct sparklink_send_constraint *out)
{
	struct sparklink_send_constraint value;
	const struct cmsghdr *cm;
	if (!msg->msg_controllen) {
		memset(out, 0, sizeof(*out));
		return 0;
	}
	cm = CMSG_FIRSTHDR(msg);
	if (!cm || cm->cmsg_len < CMSG_LEN(0) ||
	    cm->cmsg_len > msg->msg_controllen)
		return -EINVAL;
	if (cm->cmsg_level != SOL_SPARKLINK ||
	    cm->cmsg_type != SPARKLINK_SCM_TX_CONSTRAINT)
		return -EOPNOTSUPP;
	if (msg->msg_controllen != CMSG_SPACE(sizeof(value)) ||
	    cm->cmsg_len != CMSG_LEN(sizeof(value)))
		return -EINVAL;
	memcpy(&value, CMSG_DATA(cm), sizeof(value));
	if (!sl_send_constraint_valid(&value))
		return -EINVAL;
	*out = value;
	return 0;
}
static int sl_sendmsg(struct socket *sock, struct msghdr *msg, size_t length)
{
	struct sl_connection_session *s = sl_binding_session(sock->sk);
	struct sl_basic_channel *c = s ? sl_bound_channel(sock->sk, s) : NULL;
	struct sk_buff *skb = NULL;
	struct sl_admission access = { .session = s, .channel = c };
	size_t header;
	u8 *p;
	int ret;
	long timeout = sock_sndtimeo(sock->sk, msg->msg_flags & MSG_DONTWAIT);

	if (!s)
		return -ENOTCONN;
	ret = sl_send_control(msg, &access.constraint);
	if (ret)
		goto put;
	ret = sparklink_native_session_admit(s->controller, s->generation,
					     s->lifetime, s->handle, s->epoch,
					     sl_tx_access, &access);
	if (ret)
		goto put;
	if (msg->msg_name || msg->msg_flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL)) {
		ret = -EOPNOTSUPP;
		goto put;
	}
	if (length > sl_channel_payload_limit(sl_snapshot(s), c->remote_tcid)) {
		ret = -EMSGSIZE;
		goto put;
	}
	while (!sl_can_write(s, c)) {
		long wait = timeout, left;
		u64 now = ktime_get_ns();
		if (access.constraint.security_epoch) {
			if (!sl_send_constraint_timely(
				    access.constraint.deadline_monotonic_ns,
				    now)) {
				ret = -ETIMEDOUT;
				goto put;
			}
			wait = min_t(
				long, timeout,
				nsecs_to_jiffies(
					access.constraint.deadline_monotonic_ns -
					now) +
					1);
		}
		if (!wait) {
			ret = -EAGAIN;
			goto put;
		}
		left = wait_event_interruptible_timeout(
			*sk_sleep(sock->sk), sl_can_write(s, c), wait);
		if (left < 0) {
			ret = left;
			goto put;
		}
		if (timeout != MAX_SCHEDULE_TIMEOUT)
			timeout -= wait - left;
	}
	header = c->remote_tcid <= 0x1d ? 4 : 5;
	skb = alloc_skb(length + header, GFP_KERNEL);
	if (!skb) {
		ret = -ENOMEM;
		goto put;
	}
	memset(skb->cb, 0, sizeof(skb->cb));
	p = skb_put(skb, length + header);
	p[0] = c->remote_tcid;
	p[1] = 0;
	p[2] = (length + header - 4) & 255;
	p[3] = (length + header - 4) >> 8;
	if (header == 5)
		p[4] = c->pi;
	ret = memcpy_from_msg(p + header, msg, length);
	if (ret)
		goto put;
    {
        struct sl_admission admission = { .session=s, .channel=c, .skb=skb, .length=length, .constraint=access.constraint };
        ret = sparklink_native_session_admit(s->controller, s->generation, s->lifetime,
            s->handle, s->epoch, sl_admit, &admission);
        skb = admission.skb;
        if (!ret) {
            sl_connection_session_kick(s); /* Host/data/gate admission has returned */
            ret = length;
        }
    }
put:
	kfree_skb(skb);
	sl_connection_session_put(s);
	return ret;
}
struct sl_receive {
	struct sl_connection_session *session;
	struct sl_basic_channel *channel;
	struct sock *sk;
	struct sk_buff *skb, *last;
	int flags;
	struct sparklink_message_security security;
};
/* Runtime holds Host/data/gate: RX admission linearizes at peek reference or
 * unlink under Session/RX locks. No allocation, wait or user copy here. PEEK
 * holds a reference, including zero-sized datagrams; SO_PEEK_OFF is unsupported.
 * Revocation after this point does not revoke an already admitted user copy. */
static int sl_take(void *context, u64 security_revision)
{
	struct sl_receive *receive = context;
	struct sl_connection_session *s = receive->session;
	struct sl_basic_channel *c = receive->channel;
	unsigned long irq_flags;
	int ret, level;

	spin_lock_irqsave(&s->lock, irq_flags);
	ret = sock_error(receive->sk);
	if (ret)
		goto unlock;
	if (!sl_channel_active(s->progress) || !sl_binding_live(c->binding) ||
	    c->sk != receive->sk) {
		ret = -ENOTCONN;
		goto unlock;
	}
	if (sl_dynamic_status(c) && !c->peer_closed) {
		ret = sl_dynamic_status(c);
		goto unlock;
	}
	if (!sl_permits(s, c, SL_GRANT_RX) ||
	    sl_security_check(s, c, security_revision)) {
		ret = -EACCES;
		goto unlock;
	}
	level = sl_security_owner_level_rust(s->security, security_revision);
	spin_lock(&c->rx.lock);
	receive->last = c->rx.prev;
	receive->skb = skb_peek(&c->rx);
	if (!receive->skb) {
		ret = c->peer_closed ? -ENOTCONN : -EAGAIN;
	} else {
		const struct sparklink_message_security *original =
			(const void *)receive->skb->cb;
		receive->security = *original;
		receive->security.flags = sl_message_receipt_dequeue_flags(
			original, security_revision, level);
		if (receive->flags & MSG_PEEK)
			skb_get(receive->skb);
		else
			__skb_unlink(receive->skb, &c->rx);
		ret = 0;
	}
	spin_unlock(&c->rx.lock);
unlock:
	spin_unlock_irqrestore(&s->lock, irq_flags);
	return ret;
}
static int sl_recvmsg(struct socket *sock, struct msghdr *msg, size_t length,
		      int flags)
{
	struct sl_connection_session *s = sl_binding_session(sock->sk);
	struct sl_basic_channel *c = s ? sl_bound_channel(sock->sk, s) : NULL;
	struct sl_receive receive = {
		.session = s, .channel = c, .sk = sock->sk, .flags = flags
	};
	struct sk_buff *skb;
	long timeout = sock_rcvtimeo(sock->sk, flags & MSG_DONTWAIT);
	int error, copied;

	if (!s)
		return -ENOTCONN;
	if (flags & ~(MSG_DONTWAIT | MSG_PEEK | MSG_TRUNC | MSG_CMSG_COMPAT)) {
		copied = -EOPNOTSUPP;
		goto put;
	}
	for (;;) {
		receive.last = NULL;
		receive.skb = NULL;
		error = sparklink_native_session_admit(
			s->controller, s->generation, s->lifetime, s->handle,
			s->epoch, sl_take, &receive);
		if (!error)
			break;
		if (error != -EAGAIN || !timeout || !receive.last) {
			copied = error;
			goto put;
		}
		/* Stock wait registers first and compares the saved queue tail.
		 * Every normal wake retries actual locked authorization/dequeue. */
		if (__skb_wait_for_more_packets(sock->sk, &c->rx, &error,
						&timeout, receive.last)) {
			int status = sparklink_native_session_status(
				s->controller, s->generation, s->lifetime,
				s->handle, s->epoch);
			copied = status ? status : (error ? error : -ENOTCONN);
			goto put;
		}
	}
	skb = receive.skb;
	copied = min_t(size_t, length, skb->len);
	if ((size_t)copied < skb->len)
		msg->msg_flags |= MSG_TRUNC;
	error = skb_copy_datagram_msg(skb, 0, msg, copied);
	if (!error) {
		put_cmsg(msg, SOL_SPARKLINK, SPARKLINK_SCM_RX_SECURITY,
			 sizeof(receive.security), &receive.security);
	}
	if (!error && flags & MSG_TRUNC)
		copied = skb->len;
	skb_free_datagram(sock->sk, skb);
	if (error)
		copied = error;
put:
	sl_connection_session_put(s);
	return copied;
}
struct sl_poll_read {
	struct socket *sock;
	struct sl_connection_session *session;
	__poll_t mask;
};
static int sl_poll_admit(void *context, u64 security_revision)
{
	struct sl_poll_read *read = context;
	struct socket *sock = read->sock;
	struct sl_connection_session *s = read->session;
	struct sl_basic_channel *c = sl_bound_channel(sock->sk, s);
	unsigned long flags;
	__poll_t mask = 0;
	spin_lock_irqsave(&s->lock, flags);
	if (sl_security_check(s, c, security_revision)) {
		mask = EPOLLERR | EPOLLHUP;
		goto unlock;
	}
	if (sl_channel_active(s->progress) && sl_binding_live(c->binding) &&
	    c->peer_closed) {
		mask = EPOLLHUP;
		if (READ_ONCE(sock->sk->sk_err))
			mask |= EPOLLERR;
		if (sl_permits(s, c, SL_GRANT_RX) && !skb_queue_empty(&c->rx))
			mask |= EPOLLIN | EPOLLRDNORM;
	} else if (!sl_channel_active(s->progress) ||
		   !sl_binding_live(c->binding) ||
		   sl_dynamic_status(c) == -ENOTCONN ||
		   (!sl_dynamic_status(c) && !sl_permits(s, c, SL_GRANT_TX) &&
		    !sl_permits(s, c, SL_GRANT_RX)))
		mask = EPOLLERR | EPOLLHUP;
	else {
		if (sl_permits(s, c, SL_GRANT_RX) && !skb_queue_empty(&c->rx))
			mask |= EPOLLIN | EPOLLRDNORM;
		if (sl_permits(s, c, SL_GRANT_TX) &&
		    s->progress.phase == SL_CH_OPEN &&
		    sl_binding_space(c->binding, skb_queue_len(&c->tx),
				     SL_CHANNEL_TX))
			mask |= EPOLLOUT | EPOLLWRNORM;
	}
unlock:
	spin_unlock_irqrestore(&s->lock, flags);
	read->mask = mask;
	return 0;
}
static __poll_t sl_poll(struct file *file, struct socket *sock,
			poll_table *wait)
{
	struct sl_connection_session *s;
	struct sl_poll_read read;
	int ret;
	sock_poll_wait(file, sock, wait);
	s = sl_binding_session(sock->sk);
	if (!s)
		return EPOLLERR | EPOLLHUP;
	read = (struct sl_poll_read){ .sock = sock, .session = s };
	ret = sparklink_native_session_admit(s->controller, s->generation,
					     s->lifetime, s->handle, s->epoch,
					     sl_poll_admit, &read);
	sl_connection_session_put(s);
	return ret ? EPOLLERR | EPOLLHUP : read.mask;
}

struct sl_info_read {
	struct sl_connection_session *session;
	struct sl_basic_channel *channel;
	struct sock *sk;
	struct sparklink_channel_info value;
};
/* Runtime Host/data/gate -> Session: validate the fd's exact grant and copy one
 * capability snapshot. No user memory, wait, credit mutation or RX consumption.
 */
static int sl_view_access(struct sl_connection_session *s,
			  struct sl_basic_channel *c, struct sock *sk,
			  u64 security_revision)
{
	if (!sl_channel_active(s->progress) || !sl_binding_live(c->binding) ||
	    c->sk != sk)
		return -ENOTCONN;
	if (sl_dynamic_status(c))
		return sl_dynamic_status(c);
	if ((!sl_permits(s, c, SL_GRANT_TX) &&
	     !sl_permits(s, c, SL_GRANT_RX)) ||
	    sl_security_check(s, c, security_revision))
		return -EACCES;
	return s->progress.phase == SL_CH_OPEN ? 0 : -EAGAIN;
}
static int sl_read_info(void *context, u64 security_revision)
{
	struct sl_info_read *read = context;
	struct sl_connection_session *s = read->session;
	struct sl_basic_channel *c = read->channel;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&s->lock, flags);
	ret = sl_view_access(s, c, read->sk, security_revision);
	if (!ret)
		read->value = (struct sparklink_channel_info) {
			.version = SPARKLINK_CHANNEL_INFO_VERSION, .size = sizeof(read->value),
			.controller = s->controller, .handle = s->handle,
			.generation = s->generation, .lifetime = s->lifetime,
			.mtu = c->mtu, .mps = c->mps,
			.local_tcid = c->local_tcid, .remote_tcid = c->remote_tcid,
			.pi = c->pi, .mode = SPARKLINK_CHANNEL_MODE_BASIC,
			.directions = sl_sk(read->sk)->grant.directions,
		};
	spin_unlock_irqrestore(&s->lock, flags);
	return ret;
}
struct sl_tx_status_read {
    struct sl_connection_session *session;
    struct sl_basic_channel *channel;
    struct sock *sk;
    struct sparklink_channel_tx_status value;
};
/* Runtime holds Host/data/gate and this callback adds Session lock. No pointer
 * escapes; copy_to_user happens after all locks, withdrawal may follow it. */
static int sl_read_tx_status(const struct sparklink_credit_snapshot *credit,
			     u64 security_revision, void *context)
{
    struct sl_tx_status_read *read=context;
    struct sl_connection_session *s=read->session;
    struct sl_basic_channel *c=read->channel;
    unsigned long flags;
    int ret;
    spin_lock_irqsave(&s->lock,flags);
    ret = sl_view_access(s, c, read->sk, security_revision);
    if (!ret) {
        read->value=(struct sparklink_channel_tx_status){
            .version=SPARKLINK_CHANNEL_TX_STATUS_VERSION,.size=sizeof(read->value),
            .controller=s->controller,.handle=s->handle,.generation=s->generation,.lifetime=s->lifetime,
            .packet_maximum=credit->maximum,.capacity=credit->capacity,
            .outstanding=credit->outstanding,.connection_debt=credit->connection_debt,
            .peak_reserved=credit->peak_reserved,.queued=skb_queue_len(&c->tx),
            .queue_limit=SL_CHANNEL_TX,.busy=c->binding.busy,.pool_exhaustions=credit->pool_exhaustions,
        };
        if (s->tx_inflight && s->fragment_slot==c-s->channels) {
            struct sl_fragment_cursor *cursor=(void *)s->tx_inflight->cb;
            read->value.active_pdu_bytes=s->tx_inflight->len;
            read->value.active_pdu_offset=cursor->offset;
            read->value.flags=SPARKLINK_CHANNEL_TX_ACTIVE |
                (s->tx_started ? SPARKLINK_CHANNEL_TX_BEGUN : 0);
        }
    }
    spin_unlock_irqrestore(&s->lock,flags);
    return ret;
}

struct sl_session_status_read {
	struct sl_connection_session *session;
	struct sl_basic_channel *channel;
	struct sock *sk;
	struct sparklink_session_tx_status value;
};

/*
 * Host/data/gate -> Session -> one TX queue at a time. Worker-only state is
 * published by service_running under this lock; never read it while running.
 * Concurrent purge can only reduce the conservatively summed queue count.
 */
static int
sl_read_session_status(const struct sparklink_credit_snapshot *credit,
		       u64 security_revision, void *context)
{
	struct sl_session_status_read *read = context;
	struct sl_connection_session *s = read->session;
	struct sparklink_session_tx_status *v = &read->value;
	unsigned long flags;
	unsigned int i;
	int ret;

	spin_lock_irqsave(&s->lock, flags);
	ret = sl_view_access(s, read->channel, read->sk, security_revision);
	if (ret)
		goto out;
	*v = (struct sparklink_session_tx_status){
		.version = SPARKLINK_SESSION_TX_STATUS_VERSION,
		.size = sizeof(*v),
		.controller = s->controller,
		.handle = s->handle,
		.generation = s->generation,
		.lifetime = s->lifetime,
		.capacity = credit->capacity,
		.outstanding = credit->outstanding,
		.connection_debt = credit->connection_debt,
		.active_pdus = !!s->tx_inflight,
	};
	if (s->service_running)
		v->flags |= SPARKLINK_SESSION_WORK_RUNNING;
	else if (s->response_pending || s->rejection_count)
		v->flags |= SPARKLINK_SESSION_BASE_PENDING;
	/* Pending execution includes the original timeout hint, not a promise
	 * that a workqueue reference exists or callbacks have drained.
	 */
	if (delayed_work_pending(&s->work) || hrtimer_active(&s->wake_timer))
		v->flags |= SPARKLINK_SESSION_WORK_QUEUED;
	for (i = 0; i < SL_SESSION_CHANNELS; i++) {
		struct sl_basic_channel *c = &s->channels[i];

		spin_lock(&c->tx.lock);
		v->queued += skb_queue_len(&c->tx);
		spin_unlock(&c->tx.lock);
		if (!c->dynamic)
			continue;
		v->dynamic_allocated++;
		switch (c->negotiation.phase) {
		case SL_DYN_OPEN:
			v->dynamic_open++;
			break;
		case SL_DYN_RETIRED:
			v->dynamic_retired++;
			break;
		case SL_DYN_FAILED:
			v->dynamic_failed++;
			break;
		case SL_DYN_LISTEN:
		case SL_DYN_CONNECT:
		case SL_DYN_CONNECT_SENT:
		case SL_DYN_ABANDONED:
		case SL_DYN_RESPONSE:
		case SL_DYN_REJECT:
		case SL_DYN_CLOSE:
		case SL_DYN_CLOSE_SENT:
		case SL_DYN_CLOSE_RESPONSE:
			v->dynamic_pending++;
			break;
		default:
			v->dynamic_pending++;
			v->flags |= SPARKLINK_SESSION_STATE_UNKNOWN;
		}
	}
out:
	spin_unlock_irqrestore(&s->lock, flags);
	return ret;
}
struct sl_prepare_read {
	struct sl_connection_session *session;
	struct sl_basic_channel *channel;
	struct sparklink_send_constraint value;
};
static int sl_prepare_tx(void *context, u64 revision)
{
	struct sl_prepare_read *r = context;
	struct sl_connection_session *s = r->session;
	struct sl_basic_channel *c = r->channel;
	unsigned long flags;
	int ret;
	spin_lock_irqsave(&s->lock, flags);
	if (!sl_binding_live(c->binding) || !sl_channel_active(s->progress))
		ret = -ENOTCONN;
	else if (sl_dynamic_status(c))
		ret = sl_dynamic_status(c);
	else if (!sl_permits(s, c, SL_GRANT_TX) ||
		 sl_security_check(s, c, revision))
		ret = -EACCES;
	else if (s->progress.phase != SL_CH_OPEN)
		ret = -EAGAIN;
	else {
		r->value.generation = s->generation;
		r->value.lifetime = s->lifetime;
		r->value.controller = s->controller;
		r->value.handle = s->handle;
		r->value.local_tcid = c->local_tcid;
		r->value.remote_tcid = c->remote_tcid;
		r->value.pi = c->pi;
		r->value.security_epoch = revision;
		ret = sl_constraint_check(s, c, &r->value, revision);
	}
	spin_unlock_irqrestore(&s->lock, flags);
	return ret;
}
static int sl_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sl_connection_session *s;
	struct sl_info_read read;
	struct sl_tx_status_read tx_read;
	struct sl_session_status_read session_read;
	int ret;

	if (cmd != SPARKLINK_CHANNEL_INFO &&
	    cmd != SPARKLINK_CHANNEL_TX_STATUS &&
	    cmd != SPARKLINK_SESSION_TX_STATUS &&
	    cmd != SPARKLINK_CHANNEL_PREPARE_TX)
		return -ENOIOCTLCMD;
	s = sl_binding_session(sock->sk);
	if (!s)
		return -ENOTCONN;
	if (cmd == SPARKLINK_CHANNEL_PREPARE_TX) {
		struct sl_prepare_read prepared = {
			.session = s, .channel = sl_bound_channel(sock->sk, s)
		};
		if (copy_from_user(&prepared.value, (void __user *)arg,
				   sizeof(prepared.value))) {
			ret = -EFAULT;
			goto done;
		}
		if (prepared.value.version != 1 || prepared.value.size != 48 ||
		    prepared.value.minimum > 2 ||
		    !prepared.value.deadline_monotonic_ns ||
		    prepared.value.reserved || prepared.value.generation ||
		    prepared.value.lifetime || prepared.value.security_epoch ||
		    prepared.value.controller || prepared.value.handle ||
		    prepared.value.local_tcid || prepared.value.remote_tcid ||
		    prepared.value.pi) {
			ret = -EINVAL;
			goto done;
		}
		ret = sparklink_native_session_admit(s->controller,
						     s->generation, s->lifetime,
						     s->handle, s->epoch,
						     sl_prepare_tx, &prepared);
		if (!ret && copy_to_user((void __user *)arg, &prepared.value,
					 sizeof(prepared.value)))
			ret = -EFAULT;
	} else if (cmd == SPARKLINK_CHANNEL_INFO) {
		read = (struct sl_info_read){ .session = s,
					      .channel = sl_bound_channel(
						      sock->sk, s),
					      .sk = sock->sk };
		ret = sparklink_native_session_admit(s->controller,
						     s->generation, s->lifetime,
						     s->handle, s->epoch,
						     sl_read_info, &read);
		if (!ret && copy_to_user((void __user *)arg, &read.value,
					 sizeof(read.value)))
			ret = -EFAULT;
	} else if (cmd == SPARKLINK_CHANNEL_TX_STATUS) {
		tx_read = (struct sl_tx_status_read){
			.session = s,
			.channel = sl_bound_channel(sock->sk, s),
			.sk = sock->sk
		};
		ret = sparklink_native_session_inspect(
			s->controller, s->generation, s->lifetime, s->handle,
			s->epoch, sl_read_tx_status, &tx_read);
		if (!ret && copy_to_user((void __user *)arg, &tx_read.value,
					 sizeof(tx_read.value)))
			ret = -EFAULT;
	} else {
		session_read = (struct sl_session_status_read){
			.session = s,
			.channel = sl_bound_channel(sock->sk, s),
			.sk = sock->sk
		};
		ret = sparklink_native_session_inspect(
			s->controller, s->generation, s->lifetime, s->handle,
			s->epoch, sl_read_session_status, &session_read);
		if (!ret &&
		    copy_to_user((void __user *)arg, &session_read.value,
				 sizeof(session_read.value)))
			ret = -EFAULT;
	}
done:
	sl_connection_session_put(s);
	return ret;
}
#ifdef CONFIG_COMPAT
static int sl_compat_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	return sl_ioctl(sock, cmd, (unsigned long)compat_ptr(arg));
}
#endif
static int sl_drained(struct sl_connection_session *s, struct sl_basic_channel *c)
{
	unsigned long flags;
	int drained;
	spin_lock_irqsave(&s->lock, flags);
	drained = !sl_channel_active(s->progress) || (skb_queue_empty(&c->tx) && !c->binding.busy);
	spin_unlock_irqrestore(&s->lock, flags);
	return drained;
}
static int sl_release(struct socket *sock)
{
	unsigned long flags, binding_flags;
	struct sock *sk = sock->sk, *held = NULL;
	struct sl_socket_binding *binding;
	struct sl_connection_session *s;
	struct sl_basic_channel *c;

	if (!sk)
		return 0;
	binding = sl_sk(sk);
	s = sl_binding_session(sk);
	c = s ? sl_bound_channel(sk, s) : NULL;
	if (s && sock_flag(sk, SOCK_LINGER) && sk->sk_lingertime)
		wait_event_interruptible_timeout(*sk_sleep(sk), sl_drained(s, c), min_t(long, sk->sk_lingertime, msecs_to_jiffies(5000)));
	spin_lock_irqsave(&binding->lock, binding_flags);
	binding->session = NULL;
	if (s) {
		spin_lock_irqsave(&s->lock, flags);
		if (c->sk == sk) {
			held = c->sk;
			c->sk = NULL;
			sl_binding_retire(&c->binding);
			if (c->dynamic) {
				sl_dynamic_detach(&c->negotiation);
				sl_dynamic_closing(s, c);
			}
		}
		spin_unlock_irqrestore(&s->lock, flags);
	}
	spin_unlock_irqrestore(&binding->lock, binding_flags);
	if (s) {
		sl_purge_tx(s, c);
		skb_queue_purge(&c->rx);
		if (held)
			sock_put(held);
		sl_connection_session_kick(s); /* dynamic close or begun physical PDU */
		sl_connection_session_put(s); /* binding ownership */
		sl_connection_session_put(s); /* temporary operation reference */
	}
	sock_orphan(sk);
	sock->sk = NULL;
	sock_put(sk);
	return 0;
}
static const struct proto_ops sl_channel_ops = {
	.family = PF_SPARKLINK,
	.owner = THIS_MODULE,
	.release = sl_release,
	.bind = sl_bind,
	.connect = sl_connect,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.getname = sock_no_getname,
	.poll = sl_poll,
	.ioctl = sl_ioctl,
	.listen = sock_no_listen,
	.shutdown = sock_no_shutdown,
#ifdef CONFIG_COMPAT
	.compat_ioctl = sl_compat_ioctl,
#endif
	.sendmsg = sl_sendmsg,
	.recvmsg = sl_recvmsg,
	.mmap = sock_no_mmap,
};
static struct proto sl_channel_proto = {
	.name = "SPARKLINK", .owner = THIS_MODULE, .obj_size = sizeof(struct sl_socket_binding),
};
static int sl_create(struct net *net, struct socket *sock, int protocol, int kern)
{
	struct sock *sk;
	struct sl_socket_binding *binding;
	if (!net_eq(net, &init_net))
		return -EAFNOSUPPORT;
	if (sock->type != SOCK_DGRAM || protocol)
		return -EPROTONOSUPPORT;
	sk = sk_alloc(net, PF_SPARKLINK, GFP_KERNEL, &sl_channel_proto, kern);
	if (!sk)
		return -ENOMEM;
	sock_init_data(sock, sk);
	sock->ops = &sl_channel_ops;
	binding = sl_sk(sk);
	spin_lock_init(&binding->lock);
	binding->session = NULL;
	return 0;
}
static const struct net_proto_family sl_family = {
	.family = PF_SPARKLINK, .create = sl_create, .owner = THIS_MODULE,
};
int sl_channel_socket_init(void)
{
	int ret = proto_register(&sl_channel_proto, 0);
	if (ret)
		return ret;
	ret = sock_register(&sl_family);
	if (ret)
		proto_unregister(&sl_channel_proto);
	return ret;
}
void sl_channel_socket_exit(void)
{
	sock_unregister(PF_SPARKLINK);
	proto_unregister(&sl_channel_proto);
}
