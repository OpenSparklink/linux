// SPDX-License-Identifier: GPL-2.0-only
/* Production codec vectors, not socket or hardware qualification. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "../../../../net/sparklink/sle_channel_wire.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); return 1; } } while (0)
int main(void)
{
	unsigned char signal[32], frame[40];
	struct sl_channel_frame parsed;
	struct sl_channel_cap cap;
	unsigned int code, identifier, mask;
	int n;

	n = sl_channel_cap_request(signal, sizeof(signal), 7);
	CHECK(n == 8 && !memcmp(signal, (unsigned char[]){1,7,4,0,0xe2,0,0,0}, 8));
	CHECK(sl_channel_cap_decode(signal, n, &code, &identifier, &mask, &cap) == 0);
	CHECK(code == 1 && identifier == 7 && mask == 0xe2);
	n = sl_channel_cap_response(signal, sizeof(signal), 7, mask, 249);
	CHECK(n == 16 && !memcmp(signal, (unsigned char[]){2,7,12,0,0xe2,0,0,0,0,0,249,0,249,0,1,1}, 16));
	CHECK(sl_channel_cap_decode(signal, n, &code, &identifier, &mask, &cap) == 0);
	CHECK(cap.mtu == 249 && cap.mps == 249 && cap.version == 0x0101 && cap.modes == 0);
	CHECK(sl_channel_frame_encode(frame, sizeof(frame), 2, 0, signal, n) == 20);
	CHECK(sl_channel_frame_decode(frame, 20, &parsed) == 0 && parsed.tcid == 2 && parsed.pi == 0 && parsed.length == 16);
	CHECK(sl_channel_frame_encode(frame, sizeof(frame), 31, 241, (unsigned char *)"abc", 3) == 8);
	CHECK(!memcmp(frame, (unsigned char[]){31,0,4,0,241,'a','b','c'}, 8));
	CHECK(sl_channel_frame_decode(frame, 8, &parsed) == 0 && parsed.tcid == 31 && parsed.pi == 241 && parsed.length == 3);
	frame[1] = 1; CHECK(sl_channel_frame_decode(frame, 8, &parsed) == -EOPNOTSUPP); frame[1] = 0;
	CHECK(sl_channel_frame_decode(frame, 7, &parsed) == -EPROTO);
	frame[4] = 0; CHECK(sl_channel_frame_decode(frame, 8, &parsed) == -EPROTO);
	CHECK(sl_channel_frame_encode(frame, 4, 31, 241, NULL, 0) == -EMSGSIZE);
	CHECK(sl_channel_frame_encode(frame, sizeof(frame), 2, 241, NULL, 0) == -EINVAL);
	signal[1] = 0; CHECK(sl_channel_cap_decode(signal, 16, &code, &identifier, &mask, &cap) == 0 && identifier == 0); signal[1] = 7;
	signal[4] |= 1; CHECK(sl_channel_cap_decode(signal, 16, &code, &identifier, &mask, &cap) == -EOPNOTSUPP); signal[4] &= ~1;
	CHECK(sl_channel_cap_decode(signal, 15, &code, &identifier, &mask, &cap) == -EPROTO);
	/* T/XS20002-2025 7.3.3 permits the complete 8-bit identifier space.
	 * No wire identifier is an absent-operation sentinel. */
	for (unsigned int id = 0; id < 256; id++) {
		n = sl_channel_cap_request(signal, sizeof(signal), id);
		CHECK(n == 8 && sl_channel_cap_decode(signal, n, &code, &identifier, &mask, &cap) == 0 && identifier == id);
		n = sl_channel_cap_response(signal, sizeof(signal), id, mask, 2042);
		CHECK(n == 16 && sl_channel_cap_decode(signal, n, &code, &identifier, &mask, &cap) == 0 && identifier == id);
	}
	CHECK(sl_channel_cap_request(signal, sizeof(signal), 256) == -EINVAL);
	CHECK(sl_channel_cap_response(signal, sizeof(signal), 256, mask, 2042) == -EINVAL);
	puts("basic DTAP/CMTC production codec PASS (offline only)");
	return 0;
}
