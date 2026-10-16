/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SLE_DYNAMIC_STATE_H
#define _SLE_DYNAMIC_STATE_H
/* Actual CMTC operation state. Session lock serializes it. IDs/TCIDs are not
 * reused in the physical lifetime; terminal entries remain bounded tombstones.
 * Expiry is supplied from the operation's original deadline, never refreshed
 * by a duplicate, a wakeup, or a subsequent application fd. */
enum sl_dynamic_phase {
	SL_DYN_UNUSED,
	SL_DYN_LISTEN,
	SL_DYN_CONNECT,
	SL_DYN_CONNECT_SENT,
	SL_DYN_ABANDONED,
	SL_DYN_RESPONSE,
	SL_DYN_REJECT,
	SL_DYN_OPEN,
	SL_DYN_CLOSE,
	SL_DYN_CLOSE_SENT,
	SL_DYN_CLOSE_RESPONSE,
	SL_DYN_RETIRED,
	SL_DYN_FAILED
};
struct sl_dynamic_progress {
	enum sl_dynamic_phase phase;
	unsigned int identifier, peer_identifier;
};
static inline int sl_dynamic_pending(struct sl_dynamic_progress p)
{
	return p.phase != SL_DYN_UNUSED && p.phase != SL_DYN_OPEN &&
	       p.phase != SL_DYN_RETIRED && p.phase != SL_DYN_FAILED;
}
static inline void sl_dynamic_tick(struct sl_dynamic_progress *p, int expired)
{
	if (expired && sl_dynamic_pending(*p))
		p->phase = SL_DYN_FAILED;
}
static inline void sl_dynamic_detach(struct sl_dynamic_progress *p)
{
	switch (p->phase) {
	case SL_DYN_CONNECT_SENT:
		p->phase = SL_DYN_ABANDONED;
		break;
	case SL_DYN_RESPONSE:
		p->phase = SL_DYN_REJECT;
		break;
	case SL_DYN_OPEN:
		p->phase = SL_DYN_CLOSE;
		break;
	case SL_DYN_LISTEN:
	case SL_DYN_CONNECT:
		p->phase = SL_DYN_RETIRED;
		break;
	default:
		break;
	}
}
static inline int sl_dynamic_connected(struct sl_dynamic_progress *p,
				       unsigned int identifier,
				       unsigned int result)
{
	if (identifier != p->identifier ||
	    (p->phase != SL_DYN_CONNECT_SENT && p->phase != SL_DYN_ABANDONED))
		return 0;
	p->phase = result			? SL_DYN_FAILED :
		   p->phase == SL_DYN_ABANDONED ? SL_DYN_CLOSE :
						  SL_DYN_OPEN;
	return 1;
}
static inline void sl_dynamic_submitted(struct sl_dynamic_progress *p)
{
	switch (p->phase) {
	case SL_DYN_CONNECT:
		p->phase = SL_DYN_CONNECT_SENT;
		break;
	case SL_DYN_RESPONSE:
		p->phase = SL_DYN_OPEN;
		break;
	case SL_DYN_REJECT:
	case SL_DYN_CLOSE_RESPONSE:
		p->phase = SL_DYN_RETIRED;
		break;
	case SL_DYN_CLOSE:
		p->phase = SL_DYN_CLOSE_SENT;
		break;
	default:
		break;
	}
}
#endif
