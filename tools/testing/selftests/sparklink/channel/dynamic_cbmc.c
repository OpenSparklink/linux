// SPDX-License-Identifier: GPL-2.0-only
/* Direct production codec and transitions. No kernel/firmware refinement. */
#include <assert.h>
#include <string.h>
#include "../../../../../net/sparklink/sle_channel_wire.h"
#include "../../../../../net/sparklink/sle_dynamic_state.h"
extern unsigned char nondet_byte(void);
extern unsigned int nondet_uint(void);
int main(void)
{
	unsigned char bytes[32];
	struct sl_channel_signal request = { .code = SL_CMTC_CONNECT_REQ,
					     .identifier = nondet_byte(),
					     .source =
						     0x80 + nondet_uint() % 96,
					     .mtu = 1 + nondet_uint() % 2042,
					     .mps = 6 + nondet_uint() % 2042,
					     .ports = 1,
					     .exclusive = 1,
					     .source_port = nondet_byte(),
					     .destination_port = nondet_byte(),
					     .aid = nondet_byte(),
					     .slqi_count = 1,
					     .slqi = { nondet_byte() } },
				 decoded, before;
	int n = sl_channel_signal_encode(bytes, sizeof(bytes), &request);
	assert(n == 22);
	if (n != 22)
		return 0;
	assert(!sl_channel_signal_decode(bytes, n, &decoded));
	assert(decoded.source == request.source &&
	       decoded.identifier == request.identifier &&
	       decoded.mtu == request.mtu && decoded.mps == request.mps &&
	       decoded.source_port == request.source_port &&
	       decoded.destination_port == request.destination_port &&
	       decoded.aid == request.aid &&
	       decoded.slqi[0] == request.slqi[0]);
	for (unsigned int i = 0; i < sizeof(bytes); i++)
		bytes[i] = nondet_byte();
	memset(&decoded, 0xa5, sizeof(decoded));
	before = decoded;
	int ret = sl_channel_signal_decode(bytes, nondet_uint() % 33, &decoded);
	if (ret)
		assert(!memcmp(&before, &decoded, sizeof(decoded)));
	struct sl_dynamic_progress p = {
		.phase = SL_DYN_CONNECT, .identifier = 1 + nondet_uint() % 255
	};
	for (unsigned int step = 0; step < 6; step++) {
		struct sl_dynamic_progress old = p;
		unsigned int event = nondet_uint() % 4, id = nondet_byte();
		int expired = nondet_uint() % 2;
		switch (event) {
		case 0:
			sl_dynamic_submitted(&p);
			break;
		case 1:
			sl_dynamic_detach(&p);
			break;
		case 2:
			sl_dynamic_tick(&p, expired);
			break;
		default:
			sl_dynamic_connected(&p, id, nondet_uint() % 5);
			break;
		}
		assert(old.phase != SL_DYN_RETIRED ||
		       p.phase == SL_DYN_RETIRED);
		assert(old.phase != SL_DYN_FAILED || p.phase == SL_DYN_FAILED);
		assert(old.phase != SL_DYN_ABANDONED || p.phase != SL_DYN_OPEN);
		assert(event != 3 || id == old.identifier ||
		       !memcmp(&old, &p, sizeof(p)));
	}
}
