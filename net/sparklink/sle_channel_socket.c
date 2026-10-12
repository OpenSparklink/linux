// SPDX-License-Identifier: GPL-2.0-only
/* Minimal native default unicast channel. SSAP/dynamic/reliable modes are not
 * advertised. Each socket binds an immutable controller/connection lifetime.
 */
#include <linux/capability.h>
#include <linux/errno.h>
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

#define SL_CHANNEL_QUEUE 8
struct sl_channel_sock {
	struct sock sk;
	struct sockaddr_sparklink address;
	struct delayed_work work;
	struct sk_buff_head tx;
	struct list_head entry;
	bool bound, dead, ready, request_sent, response_sent;
	u8 response_id;
	u32 response_mask;
	u16 maximum, mtu;
	unsigned long deadline;
};
static LIST_HEAD(sl_channel_sockets);
static DEFINE_MUTEX(sl_channel_registry);
static unsigned int sl_channel_count;
static struct proto sl_channel_proto;

static struct sl_channel_sock *sl_sk(struct sock *sk)
{
	return container_of(sk, struct sl_channel_sock, sk);
}

static void sl_schedule(struct sl_channel_sock *ss)
{
	sock_hold(&ss->sk);
	if (!queue_delayed_work(system_unbound_wq, &ss->work, msecs_to_jiffies(10)))
		sock_put(&ss->sk);
}

static void sl_fault(struct sl_channel_sock *ss, int error)
{
	WRITE_ONCE(ss->dead, true);
	WRITE_ONCE(ss->sk.sk_err, -error);
	WRITE_ONCE(ss->sk.sk_shutdown, SHUTDOWN_MASK);
	WRITE_ONCE(ss->sk.sk_state, TCP_CLOSE);
	ss->sk.sk_error_report(&ss->sk);
	ss->sk.sk_state_change(&ss->sk);
}

static int sl_send(struct sl_channel_sock *ss, const u8 *data, size_t length)
{
	if (READ_ONCE(ss->dead))
		return -ECANCELED;
	return sparklink_native_acb_send(ss->address.controller, ss->address.generation,
		ss->address.lifetime, ss->address.handle, data, length);
}

static void sl_work(struct work_struct *work)
{
	struct sl_channel_sock *ss = container_of(to_delayed_work(work), struct sl_channel_sock, work);
	struct sl_channel_frame frame;
	struct sl_channel_cap cap;
	struct sk_buff *skb;
	u8 signal[16], wire[24], *rx;
	unsigned int code, identifier, mask;
	size_t size;
	int ret, n, i;

	if (READ_ONCE(ss->dead))
		goto put;
	if (!ss->request_sent) {
		n = sl_channel_cap_request(signal, sizeof(signal), 1);
		n = sl_channel_frame_encode(wire, sizeof(wire), SL_CHANNEL_CMTC, 0, signal, n);
		ret = sl_send(ss, wire, n);
		if (ret == -EAGAIN)
			goto again;
		if (ret) { sl_fault(ss, ret); goto put; }
		ss->request_sent = true;
	}
	rx = kmalloc(2047, GFP_KERNEL);
	if (!rx) { sl_fault(ss, -ENOMEM); goto put; }
	for (i = 0; i < 16; i++) {
		ret = sparklink_native_acb_take(ss->address.controller, ss->address.generation,
			ss->address.lifetime, ss->address.handle, rx, 2047, &size);
		if (ret == -EAGAIN)
			break;
		if (ret) { sl_fault(ss, ret); break; }
		ret = sl_channel_frame_decode(rx, size, &frame);
		if (ret)
			continue; /* malformed/unsupported input never becomes successful data */
		if (frame.tcid == SL_CHANNEL_CMTC) {
			ret = sl_channel_cap_decode(frame.data, frame.length, &code, &identifier, &mask, &cap);
			if (ret)
				continue;
			if (code == 1) {
				ss->response_id = identifier;
				ss->response_mask = mask;
            } else if (identifier == 1 && ss->request_sent && !READ_ONCE(ss->ready)) {
				ss->mtu = min_t(unsigned int, ss->maximum, min(cap.mtu, cap.mps));
				WRITE_ONCE(ss->ready, true);
				ss->sk.sk_write_space(&ss->sk);
			}
		} else if (READ_ONCE(ss->ready) && frame.tcid == ss->address.local_tcid && frame.pi == ss->address.pi) {
			if (frame.length > ss->mtu)
				continue;
			skb = alloc_skb(frame.length, GFP_KERNEL);
			if (!skb)
				continue;
			memcpy(skb_put(skb, frame.length), frame.data, frame.length);
			if (sock_queue_rcv_skb(&ss->sk, skb))
				kfree_skb(skb);
		}
	}
	kfree(rx);
	if (READ_ONCE(ss->dead))
		goto put;
	if (ss->response_id) {
		n = sl_channel_cap_response(signal, sizeof(signal), ss->response_id, ss->response_mask, ss->maximum);
		n = sl_channel_frame_encode(wire, sizeof(wire), SL_CHANNEL_CMTC, 0, signal, n);
		ret = sl_send(ss, wire, n);
		if (ret == -EAGAIN)
			goto again;
		if (ret) { sl_fault(ss, ret); goto put; }
		ss->response_id = 0;
		ss->response_sent = true;
		ss->sk.sk_write_space(&ss->sk);
	}
	if (READ_ONCE(ss->ready) && ss->response_sent) {
		skb = skb_peek(&ss->tx);
		if (skb) {
			ret = sl_send(ss, skb->data, skb->len);
			if (ret == -EAGAIN)
				goto again;
			if (ret) { sl_fault(ss, ret); goto put; }
			skb = skb_dequeue(&ss->tx);
			kfree_skb(skb);
			ss->sk.sk_write_space(&ss->sk);
		}
	}
again:
	if (!READ_ONCE(ss->ready) && time_after_eq(jiffies, ss->deadline))
		sl_fault(ss, -ETIMEDOUT);
	if (!READ_ONCE(ss->dead))
		sl_schedule(ss);
put:
	sock_put(&ss->sk);
}

static int sl_bind(struct socket *sock, struct sockaddr_unsized *address, int length)
{
	struct sl_channel_sock *ss = sl_sk(sock->sk), *other;
	struct sockaddr_sparklink *input = (void *)address;
	u16 maximum;
	int ret;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	if (length != sizeof(*input) || input->family != AF_SPARKLINK || input->version != 1 ||
	    input->flags || memchr_inv(input->reserved, 0, sizeof(input->reserved)))
		return -EINVAL;
	if (input->local_tcid != SL_CHANNEL_CUTC || input->remote_tcid != SL_CHANNEL_CUTC ||
	    input->pi != SPARKLINK_SOCKET_USER_PI)
		return -EOPNOTSUPP;
	ret = sparklink_native_acb_limits(input->controller, input->generation, input->lifetime, input->handle, &maximum);
	if (ret)
		return ret;
	if (maximum <= 5)
		return -EOPNOTSUPP;
	mutex_lock(&sl_channel_registry);
	if (ss->bound) { ret = -EINVAL; goto out; }
	if (sl_channel_count >= 64) { ret = -ENOBUFS; goto out; }
	list_for_each_entry(other, &sl_channel_sockets, entry) {
		if (other->address.controller == input->controller && other->address.generation == input->generation &&
		    other->address.lifetime == input->lifetime) { ret = -EADDRINUSE; goto out; }
	}
	ss->address = *input;
	ss->maximum = min_t(unsigned int, maximum - 5, 2042);
	ss->mtu = ss->maximum;
	ss->deadline = jiffies + msecs_to_jiffies(5000);
	ss->bound = true;
	list_add(&ss->entry, &sl_channel_sockets);
	sl_channel_count++;
	sock->state = SS_CONNECTED;
	WRITE_ONCE(sock->sk->sk_state, TCP_ESTABLISHED);
	sl_schedule(ss);
	ret = 0;
out:
	mutex_unlock(&sl_channel_registry);
	return ret;
}

static int sl_sendmsg(struct socket *sock, struct msghdr *msg, size_t length)
{
	struct sl_channel_sock *ss = sl_sk(sock->sk);
	struct sk_buff *skb;
	u8 *p;
	int ret;
	long timeout = sock_sndtimeo(sock->sk, msg->msg_flags & MSG_DONTWAIT);

	if (msg->msg_name || msg->msg_flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL))
		return -EOPNOTSUPP;
	if (!ss->bound)
		return -ENOTCONN;
	if (length > READ_ONCE(ss->mtu))
		return -EMSGSIZE;
	while (!READ_ONCE(ss->dead) && (!READ_ONCE(ss->ready) || !ss->response_sent || skb_queue_len(&ss->tx) >= SL_CHANNEL_QUEUE)) {
		if (!timeout)
			return -EAGAIN;
		timeout = wait_event_interruptible_timeout(*sk_sleep(sock->sk), READ_ONCE(ss->dead) ||
			(READ_ONCE(ss->ready) && ss->response_sent && skb_queue_len(&ss->tx) < SL_CHANNEL_QUEUE), timeout);
		if (timeout < 0)
			return timeout;
	}
	if (READ_ONCE(ss->dead))
		return -ENOTCONN;
	if (length > READ_ONCE(ss->mtu))
		return -EMSGSIZE;
	skb = alloc_skb(length + 5, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	p = skb_put(skb, length + 5);
	p[0] = ss->address.remote_tcid; p[1] = 0; p[2] = (length + 1) & 255; p[3] = (length + 1) >> 8; p[4] = ss->address.pi;
	ret = memcpy_from_msg(p + 5, msg, length);
	if (ret) { kfree_skb(skb); return ret; }
	spin_lock_bh(&ss->tx.lock);
	if (READ_ONCE(ss->dead) || ss->tx.qlen >= SL_CHANNEL_QUEUE) {
		spin_unlock_bh(&ss->tx.lock); kfree_skb(skb); return -EAGAIN;
	}
	__skb_queue_tail(&ss->tx, skb);
	spin_unlock_bh(&ss->tx.lock);
	return length;
}

static int sl_recvmsg(struct socket *sock, struct msghdr *msg, size_t length, int flags)
{
	struct sk_buff *skb;
	int error, copied;

	skb = skb_recv_datagram(sock->sk, flags, &error);
	if (!skb)
		return error;
	copied = min_t(size_t, length, skb->len);
	if (copied < skb->len)
		msg->msg_flags |= MSG_TRUNC;
	error = skb_copy_datagram_msg(skb, 0, msg, copied);
	if (!error && flags & MSG_TRUNC)
		copied = skb->len;
	skb_free_datagram(sock->sk, skb);
	return error ? error : copied;
}

static __poll_t sl_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	struct sl_channel_sock *ss = sl_sk(sock->sk);
	__poll_t mask = 0;

	sock_poll_wait(file, sock, wait);
	if (READ_ONCE(ss->dead))
		return EPOLLERR | EPOLLHUP;
	if (!skb_queue_empty(&sock->sk->sk_receive_queue))
		mask |= EPOLLIN | EPOLLRDNORM;
	if (READ_ONCE(ss->ready) && ss->response_sent && skb_queue_len(&ss->tx) < SL_CHANNEL_QUEUE)
		mask |= EPOLLOUT | EPOLLWRNORM;
	return mask;
}

static int sl_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct sl_channel_sock *ss;

	if (!sk)
		return 0;
	ss = sl_sk(sk);
	/* Explicit finite linger drains admitted software TX through the real
	 * driver. It does not invent controller completion or peer delivery.
	 * Without linger (or after its bound), close discards unsent packets.
	 */
	if (ss->bound && sock_flag(sk, SOCK_LINGER) && sk->sk_lingertime &&
	    !READ_ONCE(ss->dead))
		wait_event_interruptible_timeout(*sk_sleep(sk),
			READ_ONCE(ss->dead) || skb_queue_empty(&ss->tx),
			min_t(long, sk->sk_lingertime, msecs_to_jiffies(5000)));
	mutex_lock(&sl_channel_registry);
	WRITE_ONCE(ss->dead, true);
	if (ss->bound) {
		list_del(&ss->entry);
		sl_channel_count--;
	}
	mutex_unlock(&sl_channel_registry);
	if (cancel_delayed_work_sync(&ss->work))
		sock_put(sk); /* pending worker owned one reference */
	skb_queue_purge(&ss->tx); /* unsent packets never reserved controller credit */
	skb_queue_purge(&sk->sk_receive_queue);
	sock_orphan(sk);
	sock->sk = NULL;
	sock_put(sk);
	return 0;
}

static const struct proto_ops sl_channel_ops = {
	.family = PF_SPARKLINK, .owner = THIS_MODULE, .release = sl_release,
	.bind = sl_bind, .connect = sock_no_connect, .socketpair = sock_no_socketpair,
	.accept = sock_no_accept, .getname = sock_no_getname, .poll = sl_poll,
	.ioctl = sock_no_ioctl, .listen = sock_no_listen, .shutdown = sock_no_shutdown,
	.sendmsg = sl_sendmsg, .recvmsg = sl_recvmsg, .mmap = sock_no_mmap,
};

static struct proto sl_channel_proto = {
	.name = "SPARKLINK", .owner = THIS_MODULE, .obj_size = sizeof(struct sl_channel_sock),
};

static int sl_create(struct net *net, struct socket *sock, int protocol, int kern)
{
	struct sock *sk;
	struct sl_channel_sock *ss;

	if (!net_eq(net, &init_net))
		return -EAFNOSUPPORT;
	if (sock->type != SOCK_SEQPACKET || protocol)
		return -EPROTONOSUPPORT;
	sk = sk_alloc(net, PF_SPARKLINK, GFP_KERNEL, &sl_channel_proto, kern);
	if (!sk)
		return -ENOMEM;
	sock_init_data(sock, sk);
	sock->ops = &sl_channel_ops;
	ss = sl_sk(sk);
	memset((u8 *)ss + sizeof(*sk), 0, sizeof(*ss) - sizeof(*sk));
	skb_queue_head_init(&ss->tx);
	INIT_LIST_HEAD(&ss->entry);
	INIT_DELAYED_WORK(&ss->work, sl_work);
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
