// SPDX-License-Identifier: GPL-2.0-only
/* Runtime-owned connection session, bounded fixed channels, fd bindings. Dynamic
 * TCIDs/reliable modes and same-lifetime rebinding require protocol support. */
#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/kref.h>
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
#include "sle_channel_table.h"
#include "sle_fragment_cursor.h"
#include "sle_security_relay.h"

_Static_assert(SL_SESSION_CHANNELS == 2 && SL_CHANNEL_USER_SLOT == 0 && SL_CHANNEL_SMTC_SLOT == 1, "fixed channel table bounds");
_Static_assert(SL_GRANT_TX == SPARKLINK_SOCKET_TX && SL_GRANT_RX == SPARKLINK_SOCKET_RX, "grant direction UAPI mismatch");

#define SL_CHANNEL_TX 8
#define SL_CHANNEL_RX 16

struct sl_basic_channel {
	u8 local_tcid, remote_tcid, pi;
	unsigned int mtu, mps;
	struct sl_binding_progress binding;
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
	struct sl_basic_channel channels[SL_SESSION_CHANNELS];
	unsigned int tx_next; /* serialized worker-only round-robin start */
	u16 acb_maximum; /* controller packet size, distinct from DTAP MTU */
	int fragment_slot; /* worker-only; -1 or sole unfinished connection PDU */
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
struct sl_submit_scope { struct sl_connection_session *session; struct sl_basic_channel *channel; };
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

	return c->sk && sl_grant_permits(&sl_sk(c->sk)->grant, scope, direction);
}
static void sl_session_destroy(struct kref *refs)
{
	struct sl_connection_session *s = container_of(refs, struct sl_connection_session, refs);
	unsigned int i;

	WARN_ON(delayed_work_pending(&s->work));
	for (i = 0; i < SL_SESSION_CHANNELS; i++) {
		WARN_ON(s->channels[i].sk);
		skb_queue_purge(&s->channels[i].tx);
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
static void sl_schedule(struct sl_connection_session *s)
{
	unsigned long flags;
	spin_lock_irqsave(&s->lock, flags);
	if (sl_channel_active(s->progress)) {
		sl_connection_session_get(s);
		if (!queue_delayed_work(system_unbound_wq, &s->work, msecs_to_jiffies(10)))
			sl_connection_session_put(s);
	}
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
static void sl_progress_event(struct sl_connection_session *s, unsigned int event, unsigned int mtu)
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
	case 2: sl_channel_peer_capability(&s->progress, mtu, expired); break;
	case 3: sl_channel_response_submitted(&s->progress, expired); break;
	default: sl_channel_tick(&s->progress, expired); break;
	}
	after = s->progress.phase;
	if (after == SL_CH_OPEN) {
		for (i = 0; i < SL_SESSION_CHANNELS; i++) {
			s->channels[i].mtu = s->progress.mtu;
			s->channels[i].mps = s->progress.mtu;
		}
	}
	spin_unlock_irqrestore(&s->lock, flags);
	if (before == SL_CH_NEGOTIATING && after == SL_CH_FAILED)
		sl_fault(s, -ETIMEDOUT);
	else if (before != SL_CH_OPEN && after == SL_CH_OPEN)
		sl_wake(s);
}

/* Invoked inside actual Runtime Host/data/gate commit. Order is those locks
 * then session lock. No caller holds session lock over any Runtime API/wait.
 * Last-fd detach and actual USB queueing therefore have one linearization. */
static int sl_session_submit(void *scope, int (*submit)(void *), void *context)
{
	struct sl_submit_scope *permission = scope;
	struct sl_connection_session *s = permission->session;
	int ret;

	spin_lock(&s->lock); /* Runtime commit has IRQs disabled */
	if (!sl_channel_active(s->progress) ||
	    (permission->channel && !sl_binding_live(permission->channel->binding)))
		ret = -ECANCELED;
	else if (permission->channel && !sl_permits(s, permission->channel, SL_GRANT_TX))
		ret = -EACCES;
	else
		ret = submit(context); /* atomic queue only; no wait or protocol reentry */
	spin_unlock(&s->lock);
	return ret;
}
static int sl_send(struct sl_connection_session *s, struct sl_basic_channel *c, const u8 *data, size_t length)
{
	struct sl_submit_scope permission = { s, c };

	return sparklink_native_acb_send_guarded(s->controller, s->generation, s->lifetime,
		s->handle, data, length, s->epoch, sl_session_submit, &permission);
}

/* Exactly one session worker consumes the connection's ACB queue. Decode once,
 * route CMTC to session state, then route DTAP by local TCID/PI to channel RX. */
static void sl_route(struct sl_connection_session *s, const u8 *bytes, size_t length)
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
		if (sl_channel_cap_decode(frame.data, frame.length, &code, &identifier, &mask, &cap))
			return;
		if (code == 1) {
			if (s->response_id && s->response_id != identifier) {
				sl_fault(s, -EPROTO);
				return;
			}
			s->response_id = identifier;
			s->response_mask = mask;
		} else if (identifier == 1 && sl_snapshot(s).request_submitted) {
			struct sl_channel_progress view = sl_snapshot(s);
			sl_progress_event(s, 2, min_t(unsigned int, view.maximum, min(cap.mtu, cap.mps)));
		}
		return;
	}
	slot = sl_channel_rx_slot(frame.tcid, frame.pi);
	if (slot < 0)
		return;
	c = &s->channels[slot];
	skb = alloc_skb(frame.length, GFP_KERNEL);
	if (!skb)
		return;
	memcpy(skb_put(skb, frame.length), frame.data, frame.length);
	spin_lock_irqsave(&s->lock, flags);
	if (s->progress.phase == SL_CH_OPEN && sl_binding_live(c->binding) &&
	    sl_permits(s, c, SL_GRANT_RX) && frame.tcid == c->local_tcid && frame.pi == c->pi &&
	    frame.length <= c->mtu) {
		spin_lock(&c->rx.lock);
		if (c->rx.qlen < SL_CHANNEL_RX &&
            atomic_read(&c->sk->sk_rmem_alloc) < READ_ONCE(c->sk->sk_rcvbuf) &&
            sk_rmem_schedule(c->sk, skb, skb->truesize)) {
            skb_set_owner_r(skb, c->sk);
			__skb_queue_tail(&c->rx, skb);
			skb = NULL;
			sk = c->sk;
			sock_hold(sk);
		}
		spin_unlock(&c->rx.lock);
	}
	if (skb)
		c->rx_dropped++;
	spin_unlock_irqrestore(&s->lock, flags);
	kfree_skb(skb);
	if (sk) {
		sk->sk_data_ready(sk);
		sock_put(sk);
	}
}
static int sl_transmit_channel(struct sl_connection_session *s, struct sl_basic_channel *c)
{
	unsigned long flags;
	struct sk_buff *skb = NULL;
	struct sl_fragment_cursor *cursor;
	struct sl_submit_scope permission = { s, c };
	unsigned int length, boundary;
	int slot = c - s->channels, ret = 0;

	if (s->fragment_slot >= 0 && s->fragment_slot != slot)
		return 0; /* DLI PB has no TCID; do not interleave connection PDUs. */
	spin_lock_irqsave(&s->lock, flags);
	if (s->progress.phase == SL_CH_OPEN && sl_binding_live(c->binding) && sl_permits(s, c, SL_GRANT_TX) && !c->binding.busy) {
		skb = skb_dequeue(&c->tx);
		if (skb)
			sl_binding_start_tx(&c->binding);
	}
	spin_unlock_irqrestore(&s->lock, flags);
	if (!skb)
		return s->fragment_slot == slot ? -ECANCELED : 0;
	cursor = (void *)skb->cb;
	if (!cursor->deadline)
		cursor->deadline = jiffies + msecs_to_jiffies(5000);
	if (time_after_eq(jiffies, cursor->deadline))
		ret = -ETIMEDOUT;
	else if (!sl_fragment_next(skb->len, cursor->offset, s->acb_maximum, &length, &boundary))
		ret = -EPROTO;
	else {
		ret = sparklink_native_acb_fragment_guarded(s->controller, s->generation,
			s->lifetime, s->handle, boundary, skb->data + cursor->offset, length,
			s->epoch, sl_session_submit, &permission);
		if (!ret && !sl_fragment_advance(cursor, skb->len, length))
			ret = -EPROTO;
	}
	spin_lock_irqsave(&s->lock, flags);
	sl_binding_finish_tx(&c->binding);
	if ((ret == -EAGAIN || (!ret && cursor->offset < skb->len)) &&
	    sl_binding_live(c->binding) && sl_permits(s, c, SL_GRANT_TX)) {
		/* A blocked first submit permits other PDUs. A committed prefix owns
		 * the entire connection stream until its final fragment is submitted. */
		if (cursor->offset)
			s->fragment_slot = slot;
		skb_queue_head(&c->tx, skb);
		skb = NULL;
	} else {
		if ((!ret || ret == -EAGAIN || ret == -ECANCELED) && cursor->offset && cursor->offset < skb->len)
			ret = -ECONNABORTED; /* no qualified partial-PDU discard barrier */
		s->fragment_slot = -1;
	}
	spin_unlock_irqrestore(&s->lock, flags);
	kfree_skb(skb);
	sl_wake(s);
	return ret == -EAGAIN || ret == -ECANCELED ? 0 : ret;
}
static void sl_work(struct work_struct *work)
{
	struct sl_connection_session *s = container_of(to_delayed_work(work), struct sl_connection_session, work);
	u8 signal[16], wire[24];
	size_t size;
	int ret, n;
	unsigned int i;

	if (!sl_channel_active(sl_snapshot(s)))
		goto put;
	ret = sparklink_native_session_status(s->controller, s->generation, s->lifetime, s->handle, s->epoch);
	if (ret == -EAGAIN) {
		/* Unknown physical state is bounded independently of CMTC deadline. */
		sl_progress_event(s, 0, 0);
		if (!s->unknown_deadline)
			s->unknown_deadline = jiffies + msecs_to_jiffies(5000);
		if (time_after_eq(jiffies, s->unknown_deadline))
			sl_fault(s, -ETIMEDOUT);
		goto again;
	}
	s->unknown_deadline = 0;
	if (ret) { sl_fault(s, ret); goto put; }
	sl_progress_event(s, 0, 0);
	if (!sl_channel_active(sl_snapshot(s)))
		goto put;
	if (!sl_snapshot(s).request_submitted) {
		n = sl_channel_cap_request(signal, sizeof(signal), 1);
		if (n >= 0)
			n = sl_channel_frame_encode(wire, sizeof(wire), SL_CHANNEL_CMTC, 0, signal, n);
		if (n < 0) { sl_fault(s, n); goto put; }
		ret = sl_send(s, NULL, wire, n);
		if (ret == -EAGAIN)
			goto again;
		if (ret) { sl_fault(s, ret); goto put; }
		sl_progress_event(s, 1, 0);
	}
	for (i = 0; i < 16 && sl_channel_active(sl_snapshot(s)); i++) {
		ret = sparklink_native_acb_take(s->controller, s->generation, s->lifetime,
			s->handle, s->rx_buffer, sizeof(s->rx_buffer), &size);
		if (ret == -EAGAIN)
			break;
		if (ret) { sl_fault(s, ret); break; }
		sl_route(s, s->rx_buffer, size);
	}
	if (!sl_channel_active(sl_snapshot(s)))
		goto put;
	if (s->response_id && s->fragment_slot < 0) {
		n = sl_channel_cap_response(signal, sizeof(signal), s->response_id, s->response_mask, sl_snapshot(s).maximum);
		if (n >= 0)
			n = sl_channel_frame_encode(wire, sizeof(wire), SL_CHANNEL_CMTC, 0, signal, n);
		if (n < 0) { sl_fault(s, n); goto put; }
		ret = sl_send(s, NULL, wire, n);
		if (ret == -EAGAIN)
			goto again;
		if (ret) { sl_fault(s, ret); goto put; }
		s->response_id = 0;
		sl_progress_event(s, 3, 0);
	}
	for (i = 0; i < SL_SESSION_CHANNELS; i++) {
		unsigned int slot = (s->tx_next + i) % SL_SESSION_CHANNELS;
		ret = sl_transmit_channel(s, &s->channels[slot]);
		if (ret) { sl_fault(s, ret); goto put; }
	}
	s->tx_next = (s->tx_next + 1) % SL_SESSION_CHANNELS;
again:
	sl_progress_event(s, 0, 0);
	if (sl_channel_active(sl_snapshot(s)))
		sl_schedule(s);
put:
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
	for (i = 0; i < SL_SESSION_CHANNELS; i++) {
		struct sl_basic_channel *c = &s->channels[i];
		skb_queue_head_init(&c->tx);
		skb_queue_head_init(&c->rx);
		c->local_tcid = i == SL_CHANNEL_USER_SLOT ? SL_CHANNEL_CUTC : SL_CHANNEL_SMTC;
		c->remote_tcid = c->local_tcid;
		c->pi = i == SL_CHANNEL_USER_SLOT ? SPARKLINK_SOCKET_USER_PI : 0;
	}
	/* Physical session exists before any application fd. Start the sole CMTC
	 * negotiation at the first authorized channel binding, never at allocation
	 * or each subsequent fd open. Inactive sessions have no work/timer refs.
	 */
	s->acb_maximum = maximum;
	s->fragment_slot = -1;
	s->progress.maximum = SL_FRAGMENT_PDU_MAX - 5;
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
	if (cancel_delayed_work_sync(&s->work))
		sl_connection_session_put(s); /* queued work owned one reference */
	for (i = 0; i < SL_SESSION_CHANNELS; i++) {
		skb_queue_purge(&s->channels[i].tx);
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
static int sl_publish_binding(void *context)
{
	struct sl_bind_admission *admission = context;
	struct socket *sock = admission->sock;
	struct sl_socket_binding *binding = admission->binding;
	struct sl_connection_session *s = admission->session;
	struct sl_basic_channel *c = &s->channels[admission->channel_slot];
	unsigned long flags, binding_flags;
	int ret = 0;
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
			sl_channel_start(&s->progress, s->progress.maximum);
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
static int sl_bind(struct socket *sock, struct sockaddr_unsized *address, int length)
{
	struct sl_socket_binding *binding = sl_sk(sock->sk);
	struct sockaddr_sparklink *input = (void *)address;
	struct sl_connection_session *s;
	struct sl_channel_grant grant;
	struct sl_grant_scope scope;
	int ret = 0, slot;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	if (length != sizeof(*input) || input->family != AF_SPARKLINK || input->version != SPARKLINK_SOCKET_VERSION ||
	    input->flags || memchr_inv(input->reserved, 0, sizeof(input->reserved)))
		return -EINVAL;
	if (!input->directions || input->directions & ~(SPARKLINK_SOCKET_TX | SPARKLINK_SOCKET_RX))
		return -EINVAL;
	if (input->security)
		return -EOPNOTSUPP;
	slot = sl_channel_key_slot(input->local_tcid, input->remote_tcid, input->pi);
	if (slot < 0)
		return -EOPNOTSUPP;
	scope = (struct sl_grant_scope){ .controller = input->controller,
		.generation = input->generation, .lifetime = input->lifetime, .epoch = input->lease,
		.handle = input->handle, .local_tcid = input->local_tcid,
		.remote_tcid = input->remote_tcid, .pi = input->pi };
	if (!sl_grant_init(&grant, scope, input->directions, input->security))
		return -EINVAL;
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
		sl_schedule(s);
	return ret;
}
static int sl_can_write(struct sl_connection_session *s, struct sl_basic_channel *c)
{
	unsigned long flags;
	int ready;
	spin_lock_irqsave(&s->lock, flags);
	ready = !sl_channel_active(s->progress) || !sl_binding_live(c->binding) || !sl_permits(s, c, SL_GRANT_TX) ||
		(s->progress.phase == SL_CH_OPEN && sl_binding_space(c->binding, skb_queue_len(&c->tx), SL_CHANNEL_TX));
	spin_unlock_irqrestore(&s->lock, flags);
	return ready;
}
struct sl_admission { struct sl_connection_session *session; struct sl_basic_channel *channel; struct sk_buff *skb; size_t length; };
static int sl_admit(void *context)
{
    struct sl_admission *admission = context;
    struct sl_connection_session *s = admission->session;
    struct sl_basic_channel *c = admission->channel;
    struct sk_buff *skb = admission->skb;
    size_t length = admission->length;
    unsigned long flags;
    int ret;

	spin_lock_irqsave(&s->lock, flags);
	if (sl_binding_live(c->binding) && !sl_permits(s, c, SL_GRANT_TX))
		ret = -EACCES;
	else if (s->progress.phase != SL_CH_OPEN || !sl_binding_live(c->binding))
		ret = sl_channel_active(s->progress) && sl_binding_live(c->binding) ? -EAGAIN : -ENOTCONN;
	else if (length > c->mtu)
		ret = -EMSGSIZE;
	else {
		spin_lock(&c->tx.lock);
		if (!sl_binding_space(c->binding, c->tx.qlen, SL_CHANNEL_TX))
			ret = -EAGAIN;
		else {
			__skb_queue_tail(&c->tx, skb);
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
static int sl_tx_access(void *context)
{
	struct sl_admission *admission = context;
	struct sl_connection_session *s = admission->session;
	struct sl_basic_channel *c = admission->channel;
	unsigned long flags;
	int ret;
	spin_lock_irqsave(&s->lock, flags);
	ret = !sl_binding_live(c->binding) ? -ENOTCONN :
		!sl_permits(s, c, SL_GRANT_TX) ? -EACCES : 0;
	spin_unlock_irqrestore(&s->lock, flags);
	return ret;
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
	ret = sparklink_native_session_admit(s->controller, s->generation, s->lifetime, s->handle, s->epoch, sl_tx_access, &access);
	if (ret)
		goto put;
	if (msg->msg_name || msg->msg_flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL)) { ret = -EOPNOTSUPP; goto put; }
	if (length > sl_snapshot(s).mtu) { ret = -EMSGSIZE; goto put; }
	while (!sl_can_write(s, c)) {
		if (!timeout) { ret = -EAGAIN; goto put; }
		timeout = wait_event_interruptible_timeout(*sk_sleep(sock->sk), sl_can_write(s, c), timeout);
		if (timeout < 0) { ret = timeout; goto put; }
	}
	header = c->remote_tcid <= 0x1d ? 4 : 5;
	skb = alloc_skb(length + header, GFP_KERNEL);
	if (!skb) { ret = -ENOMEM; goto put; }
	memset(skb->cb, 0, sizeof(skb->cb));
	p = skb_put(skb, length + header);
	p[0] = c->remote_tcid; p[1] = 0;
	p[2] = (length + header - 4) & 255; p[3] = (length + header - 4) >> 8;
	if (header == 5)
		p[4] = c->pi;
	ret = memcpy_from_msg(p + header, msg, length);
	if (ret)
		goto put;
    {
        struct sl_admission admission = { s, c, skb, length };
        ret = sparklink_native_session_admit(s->controller, s->generation, s->lifetime,
            s->handle, s->epoch, sl_admit, &admission);
        skb = admission.skb;
        if (!ret)
            ret = length;
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
};
/* Runtime holds Host/data/gate: RX admission linearizes at peek reference or
 * unlink under Session/RX locks. No allocation, wait or user copy here. PEEK
 * holds a reference, including zero-sized datagrams; SO_PEEK_OFF is unsupported.
 * Revocation after this point does not revoke an already admitted user copy. */
static int sl_take(void *context)
{
	struct sl_receive *receive = context;
	struct sl_connection_session *s = receive->session;
	struct sl_basic_channel *c = receive->channel;
	unsigned long irq_flags;
	int ret;

	spin_lock_irqsave(&s->lock, irq_flags);
	ret = sock_error(receive->sk);
	if (ret)
		goto unlock;
	if (!sl_channel_active(s->progress) || !sl_binding_live(c->binding) ||
	    c->sk != receive->sk) {
		ret = -ENOTCONN;
		goto unlock;
	}
	if (!sl_permits(s, c, SL_GRANT_RX)) {
		ret = -EACCES;
		goto unlock;
	}
	spin_lock(&c->rx.lock);
	receive->last = c->rx.prev;
	receive->skb = skb_peek(&c->rx);
	if (!receive->skb) {
		ret = -EAGAIN;
	} else {
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
static int sl_recvmsg(struct socket *sock, struct msghdr *msg, size_t length, int flags)
{
	struct sl_connection_session *s = sl_binding_session(sock->sk);
	struct sl_basic_channel *c = s ? sl_bound_channel(sock->sk, s) : NULL;
	struct sl_receive receive = { .session = s, .channel = c, .sk = sock->sk, .flags = flags };
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
		error = sparklink_native_session_admit(s->controller, s->generation,
			s->lifetime, s->handle, s->epoch, sl_take, &receive);
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
			int status = sparklink_native_session_status(s->controller, s->generation,
				s->lifetime, s->handle, s->epoch);
			copied = status ? status : (error ? error : -ENOTCONN);
			goto put;
		}
	}
	skb = receive.skb;
	copied = min_t(size_t, length, skb->len);
	if ((size_t)copied < skb->len)
		msg->msg_flags |= MSG_TRUNC;
	error = skb_copy_datagram_msg(skb, 0, msg, copied);
	if (!error && flags & MSG_TRUNC)
		copied = skb->len;
	skb_free_datagram(sock->sk, skb);
	if (error)
		copied = error;
put:
	sl_connection_session_put(s);
	return copied;
}
static __poll_t sl_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	unsigned long flags;
	struct sl_connection_session *s;
	struct sl_basic_channel *c;
	__poll_t mask = 0;

	sock_poll_wait(file, sock, wait);
	s = sl_binding_session(sock->sk);
	if (!s)
		return EPOLLERR | EPOLLHUP;
	c = sl_bound_channel(sock->sk, s);
	if (sparklink_native_session_status(s->controller, s->generation, s->lifetime, s->handle, s->epoch)) {
		sl_connection_session_put(s);
		return EPOLLERR | EPOLLHUP;
	}
	spin_lock_irqsave(&s->lock, flags);
	if (!sl_channel_active(s->progress) || !sl_binding_live(c->binding) ||
	    (!sl_permits(s, c, SL_GRANT_TX) && !sl_permits(s, c, SL_GRANT_RX)))
		mask = EPOLLERR | EPOLLHUP;
	else {
		if (sl_permits(s, c, SL_GRANT_RX) && !skb_queue_empty(&c->rx))
			mask |= EPOLLIN | EPOLLRDNORM;
		if (sl_permits(s, c, SL_GRANT_TX) && s->progress.phase == SL_CH_OPEN && sl_binding_space(c->binding, skb_queue_len(&c->tx), SL_CHANNEL_TX))
			mask |= EPOLLOUT | EPOLLWRNORM;
	}
	spin_unlock_irqrestore(&s->lock, flags);
	sl_connection_session_put(s);
	return mask;
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
static int sl_read_info(void *context)
{
	struct sl_info_read *read = context;
	struct sl_connection_session *s = read->session;
	struct sl_basic_channel *c = read->channel;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&s->lock, flags);
	if (!sl_channel_active(s->progress) || !sl_binding_live(c->binding) || c->sk != read->sk)
		ret = -ENOTCONN;
	else if (!sl_permits(s, c, SL_GRANT_TX) && !sl_permits(s, c, SL_GRANT_RX))
		ret = -EACCES;
	else if (s->progress.phase != SL_CH_OPEN)
		ret = -EAGAIN;
	else
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
static int sl_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sl_connection_session *s;
	struct sl_info_read read;
	int ret;

	if (cmd != SPARKLINK_CHANNEL_INFO)
		return -ENOIOCTLCMD;
	s = sl_binding_session(sock->sk);
	if (!s)
		return -ENOTCONN;
	read = (struct sl_info_read) { .session = s, .channel = sl_bound_channel(sock->sk, s), .sk = sock->sk };
	ret = sparklink_native_session_admit(s->controller, s->generation,
		s->lifetime, s->handle, s->epoch, sl_read_info, &read);
	if (!ret && copy_to_user((void __user *)arg, &read.value, sizeof(read.value)))
		ret = -EFAULT;
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
		}
		spin_unlock_irqrestore(&s->lock, flags);
	}
	spin_unlock_irqrestore(&binding->lock, binding_flags);
	if (s) {
		skb_queue_purge(&c->tx);
		skb_queue_purge(&c->rx);
		if (held)
			sock_put(held);
		sl_connection_session_put(s); /* binding ownership */
		sl_connection_session_put(s); /* temporary operation reference */
	}
	sock_orphan(sk);
	sock->sk = NULL;
	sock_put(sk);
	return 0;
}
static const struct proto_ops sl_channel_ops = {
	.family = PF_SPARKLINK, .owner = THIS_MODULE, .release = sl_release,
	.bind = sl_bind, .connect = sock_no_connect, .socketpair = sock_no_socketpair,
	.accept = sock_no_accept, .getname = sock_no_getname, .poll = sl_poll,
	.ioctl = sl_ioctl, .listen = sock_no_listen, .shutdown = sock_no_shutdown,
#ifdef CONFIG_COMPAT
	.compat_ioctl = sl_compat_ioctl,
#endif
	.sendmsg = sl_sendmsg, .recvmsg = sl_recvmsg, .mmap = sock_no_mmap,
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
