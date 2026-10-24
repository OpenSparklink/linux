/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SLE_TX_POLICY_H
#define _SLE_TX_POLICY_H
#include "sle_channel_table.h"

/* Software PDU service policy, not protocol credit or a wire priority bit.
 * Independent class cursors avoid restarting dynamic round-robin at slot 2
 * after every fixed-channel burst. A begun PB sequence is owned separately.
 */
#define SL_TX_FIXED_BURST 2U
struct sl_tx_policy {
	unsigned int fixed_next, normal_next, fixed_run;
};

static inline int sl_tx_policy_choose(struct sl_tx_policy *p, unsigned int ready)
{
	unsigned int all = (1U << SL_SESSION_CHANNELS) - 1;
	unsigned int fixed = ready & ((1U << SL_FIXED_CHANNELS) - 1);
	unsigned int normal = ready & all & ~((1U << SL_FIXED_CHANNELS) - 1);
	unsigned int mask, *cursor, i;

	if (fixed && (p->fixed_run < SL_TX_FIXED_BURST || !normal)) {
		mask = fixed;
		cursor = &p->fixed_next;
	} else {
		mask = normal;
		cursor = &p->normal_next;
	}
	if (*cursor >= SL_SESSION_CHANNELS)
		return -1;
	for (i = 0; i < SL_SESSION_CHANNELS; i++) {
		unsigned int slot = (*cursor + i) % SL_SESSION_CHANNELS;

		if (mask & (1U << slot)) {
			*cursor = slot; /* retain this eligible turn across credit wait */
			return slot;
		}
	}
	return -1;
}

/* Non-credit retry may yield its selected class turn, but earns no service. */
static inline void sl_tx_policy_yield(struct sl_tx_policy *p, unsigned int slot)
{
	if (slot >= SL_SESSION_CHANNELS)
		return;
	if (slot < SL_FIXED_CHANNELS)
		p->fixed_next = (slot + 1) % SL_SESSION_CHANNELS;
	else
		p->normal_next = (slot + 1) % SL_SESSION_CHANNELS;
}

/* Call only after the last fragment of an actually submitted PDU. Neither
 * cancellation, a failed attempt nor local queue retirement is completion.
 */
static inline void sl_tx_policy_complete(struct sl_tx_policy *p, unsigned int slot)
{
	if (slot >= SL_SESSION_CHANNELS)
		return;
	sl_tx_policy_yield(p, slot);
	if (slot < SL_FIXED_CHANNELS) {
		if (p->fixed_run < SL_TX_FIXED_BURST)
			p->fixed_run++;
	} else {
		p->fixed_run = 0;
	}
}
#endif
