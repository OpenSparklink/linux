/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SLE_CHANNEL_STATE_H
#define _SLE_CHANNEL_STATE_H
/* Production pure transitions. Socket integration serializes the entire
 * structure with state_lock; a deadline flag always uses the original timer.
 * This transitional negotiation state does not solve same-lifetime reopen.
 */
enum sl_channel_phase { SL_CH_UNBOUND, SL_CH_NEGOTIATING, SL_CH_OPEN,
	SL_CH_FAILED, SL_CH_CLOSED };
struct sl_channel_progress {
	enum sl_channel_phase phase;
	unsigned int maximum, mtu;
	unsigned int request_submitted, peer_capability, response_submitted;
};
static inline int sl_channel_active(struct sl_channel_progress s)
{
	return s.phase == SL_CH_NEGOTIATING || s.phase == SL_CH_OPEN;
}
static inline void sl_channel_start(struct sl_channel_progress *s, unsigned int maximum)
{
	if (s->phase != SL_CH_UNBOUND)
		return;
	if (!maximum || maximum > 2042) {
		s->phase = SL_CH_FAILED;
		return;
	}
	*s = (struct sl_channel_progress){ .phase = SL_CH_NEGOTIATING,
		.maximum = maximum, .mtu = maximum };
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
	unsigned int mtu, int expired)
{
	sl_channel_tick(s, expired);
	if (s->phase == SL_CH_NEGOTIATING && s->request_submitted &&
	    !s->peer_capability && mtu && mtu <= s->maximum) {
		s->mtu = mtu;
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
#endif
