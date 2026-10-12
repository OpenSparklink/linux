// SPDX-License-Identifier: GPL-2.0-only
#include <assert.h>
#include "../../../../net/sparklink/sle_channel_state.h"

static void invariants(struct sl_channel_progress s)
{
	if (s.phase == SL_CH_OPEN) {
		assert(s.request_submitted && s.peer_capability && s.response_submitted);
		assert(s.mtu && s.mtu <= s.maximum && s.maximum <= 2042);
	}
}
static void trace(struct sl_channel_progress s, unsigned int depth)
{
	unsigned int event;
	invariants(s);
	if (!depth)
		return;
	for (event = 0; event < 10; event++) {
		struct sl_channel_progress next = s;
		switch (event) {
		case 0: sl_channel_request_submitted(&next, 0); break;
		case 1: sl_channel_peer_capability(&next, 128, 0); break;
		case 2: sl_channel_response_submitted(&next, 0); break;
		case 3: sl_channel_tick(&next, 1); break;
		case 4: sl_channel_close(&next); break;
		case 5: sl_channel_fail(&next); break;
		case 6: sl_channel_peer_capability(&next, 128, 1); break;
		case 7: sl_channel_response_submitted(&next, 1); break;
		case 8: sl_channel_peer_capability(&next, 250, 0); break;
		default: sl_channel_start(&next, 249); break;
		}
		if (s.phase == SL_CH_CLOSED)
			assert(next.phase == SL_CH_CLOSED);
		if (s.phase == SL_CH_FAILED)
			assert(next.phase == SL_CH_FAILED || next.phase == SL_CH_CLOSED);
		trace(next, depth - 1);
	}
}
int main(void)
{
	struct sl_channel_progress s = {0};
	struct sl_binding_progress binding = {0};
	assert(sl_binding_attach(&binding));
	assert(sl_binding_live(binding));
	assert(!sl_binding_attach(&binding));
	binding.busy = 1; /* independently owned in-flight work survives detach */
	sl_binding_retire(&binding);
	assert(!sl_binding_live(binding) && binding.busy == 1);
	assert(!sl_binding_attach(&binding)); /* same-life reattach is not invented */
	sl_binding_retire(&binding);
	assert(binding.retired && !binding.bound);

	sl_channel_start(&s, 249);
	sl_channel_request_submitted(&s, 0);
	sl_channel_peer_capability(&s, 249, 0);
	assert(s.phase == SL_CH_NEGOTIATING); /* peer reply is not complete readiness */
	sl_channel_tick(&s, 1); /* real deadline also covers blocked local response */
	assert(s.phase == SL_CH_FAILED);
	sl_channel_response_submitted(&s, 0);
	assert(s.phase == SL_CH_FAILED);
	s = (struct sl_channel_progress){0};
	sl_channel_start(&s, 249);
	trace(s, 5); /* execution support, not an unbounded formal proof */
	return 0;
}
