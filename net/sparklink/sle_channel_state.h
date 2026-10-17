/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SLE_CHANNEL_STATE_H
#define _SLE_CHANNEL_STATE_H
/* Production pure transitions. Socket integration serializes the entire
 * structure with state_lock; a deadline flag always uses the original timer.
 * ConnectionSession owns this state; fd detach does not restart negotiation.
 */
/* One current binding per fixed basic channel. Retirement is local: without a
 * qualified protocol close/drain barrier, reattach in this lifetime is refused.
 * busy counts a dequeued, independently owned TX in the total queue budget. */
struct sl_binding_progress { unsigned int bound, retired, busy; };
static inline int sl_binding_live(struct sl_binding_progress s)
{
    return s.bound && !s.retired;
}
static inline int sl_binding_attach(struct sl_binding_progress *s)
{
    if (s->bound || s->retired) return 0;
    s->bound = 1;
    return 1;
}
static inline int sl_binding_space(struct sl_binding_progress s, unsigned int queued, unsigned int limit)
{
    return sl_binding_live(s) && queued < limit && s.busy < limit - queued;
}
static inline int sl_binding_start_tx(struct sl_binding_progress *s)
{
    if (!sl_binding_live(*s) || s->busy) return 0;
    s->busy = 1;
    return 1;
}
static inline void sl_binding_finish_tx(struct sl_binding_progress *s)
{
    s->busy = 0;
}
static inline void sl_binding_retire(struct sl_binding_progress *s)
{
    s->bound = 0;
    s->retired = 1;
}
enum sl_channel_phase { SL_CH_UNBOUND, SL_CH_NEGOTIATING, SL_CH_OPEN,
	SL_CH_FAILED, SL_CH_CLOSED };
struct sl_channel_progress {
	enum sl_channel_phase phase;
	unsigned int maximum, maximum_mps, mtu, mps;
	unsigned int request_submitted, peer_capability, response_submitted;
};
static inline int sl_channel_active(struct sl_channel_progress s)
{
	return s.phase == SL_CH_NEGOTIATING || s.phase == SL_CH_OPEN;
}
static inline void sl_channel_start(struct sl_channel_progress *s, unsigned int maximum, unsigned int maximum_mps)
{
	if (s->phase != SL_CH_UNBOUND)
		return;
	if (!maximum || maximum > 2042 || maximum_mps < 20 || maximum_mps > 2047) {
		s->phase = SL_CH_FAILED;
		return;
	}
	*s = (struct sl_channel_progress){ .phase = SL_CH_NEGOTIATING,
		.maximum = maximum, .maximum_mps = maximum_mps, .mtu = maximum, .mps = maximum_mps };
}
static inline void sl_channel_fail(struct sl_channel_progress *s)
{
	if (s->phase != SL_CH_CLOSED)
		s->phase = SL_CH_FAILED;
}
static inline void sl_channel_close(struct sl_channel_progress *s)
{
	s->phase = SL_CH_CLOSED;
}
static inline void sl_channel_tick(struct sl_channel_progress *s, int expired)
{
	if (s->phase == SL_CH_NEGOTIATING && expired)
		s->phase = SL_CH_FAILED;
}
static inline void sl_channel_try_open(struct sl_channel_progress *s)
{
	if (s->phase == SL_CH_NEGOTIATING && s->request_submitted &&
	    s->peer_capability && s->response_submitted)
		s->phase = SL_CH_OPEN;
}
static inline void sl_channel_request_submitted(struct sl_channel_progress *s, int expired)
{
	sl_channel_tick(s, expired);
	if (s->phase == SL_CH_NEGOTIATING)
		s->request_submitted = 1;
}
static inline void sl_channel_peer_capability(struct sl_channel_progress *s,
	unsigned int mtu, unsigned int mps, int expired)
{
	sl_channel_tick(s, expired);
	if (s->phase == SL_CH_NEGOTIATING && s->request_submitted && !s->peer_capability) {
		/* The selected native capability response itself is a 20-byte PDU. */
		if (!mtu || mps < 20) { sl_channel_fail(s); return; }
		s->mtu = mtu < s->maximum ? mtu : s->maximum;
		s->mps = mps < s->maximum_mps ? mps : s->maximum_mps;
		s->peer_capability = 1;
		sl_channel_try_open(s);
	}
}
static inline void sl_channel_response_submitted(struct sl_channel_progress *s, int expired)
{
	sl_channel_tick(s, expired);
	if (s->phase == SL_CH_NEGOTIATING) {
		s->response_submitted = 1;
		sl_channel_try_open(s);
	}
}
/* SDU admission reserves the complete basic header inside the peer PDU limit.
 * Local/remote unicast dynamic TCIDs both use the five-byte basic header. */
static inline unsigned int sl_channel_payload_limit(struct sl_channel_progress s, unsigned int tcid)
{
	unsigned int header = tcid <= 0x1d ? 4 : 5;
	if (!tcid || tcid > 255 || s.mps <= header) return 0;
	return s.mtu < s.mps - header ? s.mtu : s.mps - header;
}
#endif
