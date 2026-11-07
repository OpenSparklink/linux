// SPDX-License-Identifier: GPL-2.0-only
#include <assert.h>
#include <errno.h>
#include <string.h>
#include "../../../../net/sparklink/sle_channel_wire.h"

int main(void)
{
	unsigned char bytes[32], saved[32];
	struct sl_channel_signal s = { .code = SL_CMTC_CONNECT_REQ,
				       .identifier = 1,
				       .source = 0x80,
				       .mtu = 2042,
				       .mps = 2047,
				       .exclusive = 1,
				       .ports = 1,
				       .source_port = 0x3344,
				       .destination_port = 0x1122,
				       .aid = 0x5566,
				       .slqi_count = 1,
				       .slqi = { 1 } },
				 parsed, before;
	const unsigned char golden[] = { 0x10, 1,    18,   0,	0x80, 10,
					 1,    0,    0xfa, 7,	0xff, 7,
					 1,    1,    1,	   0,	0x22, 0x11,
					 0x44, 0x33, 0x66, 0x55 };
	assert(sl_channel_signal_encode(bytes, sizeof(bytes), &s) ==
	       sizeof(golden));
	assert(!memcmp(bytes, golden, sizeof(golden)));
	assert(!sl_channel_signal_decode(bytes, sizeof(golden), &parsed));
	assert(parsed.source == 0x80 && parsed.destination_port == 0x1122 &&
	       parsed.source_port == 0x3344 && parsed.aid == 0x5566 &&
	       parsed.mtu == 2042 && parsed.mps == 2047);
	for (unsigned int code = 0x10; code <= 0x13; code++) {
		s.code = code;
		s.destination = 0x91;
		for (unsigned int id = 0; id < 256; id++) {
			s.identifier = id;
			int n = sl_channel_signal_encode(bytes, sizeof(bytes),
							 &s);
			assert(n > 0);
			assert(!sl_channel_signal_decode(bytes, n, &parsed));
			assert(parsed.code == code && parsed.identifier == id &&
			       parsed.source == 0x80);
			if (code != 0x10)
				assert(parsed.destination == 0x91);
			for (int i = 0; i < n; i++) {
				memset(&parsed, 0xa5, sizeof(parsed));
				before = parsed;
				assert(sl_channel_signal_decode(bytes, i,
								&parsed));
				assert(!memcmp(&parsed, &before,
					       sizeof(parsed)));
			}
		}
	}
	s.code = SL_CMTC_CONNECT_REQ;
	s.identifier = 0;
	s.slqi_count = 8;
	assert(sl_channel_signal_encode(bytes, sizeof(bytes), &s) == 29);
	assert(!sl_channel_signal_decode(bytes, 29, &parsed) &&
	       parsed.slqi_count == 8);
	for (unsigned int tcid = 0; tcid < 256; tcid++) {
		s.source = tcid;
		int n = sl_channel_signal_encode(bytes, sizeof(bytes), &s);
		assert((n > 0) == (tcid >= 0x80 && tcid <= 0xdf));
	}
	s.source = 0x80;
	s.slqi_count = 1;
	assert(sl_channel_signal_encode(bytes, sizeof(bytes), &s) == 22);
	memcpy(saved, bytes, 22);
	for (unsigned int kind = 0; kind < 5; kind++) {
		memcpy(bytes, saved, 22);
		if (kind == 0)
			bytes[5] = 9;
		if (kind == 1)
			bytes[6] = 0x80;
		if (kind == 2)
			bytes[7] = 3;
		if (kind == 3)
			bytes[12] = 0;
		if (kind == 4)
			bytes[14] = 4;
		memset(&parsed, 0xa5, sizeof(parsed));
		before = parsed;
		assert(sl_channel_signal_decode(bytes, 22, &parsed));
		assert(!memcmp(&parsed, &before, sizeof(parsed)));
	}
	memset(bytes, 0xa5, sizeof(bytes));
	memcpy(saved, bytes, sizeof(bytes));
	assert(sl_channel_signal_encode(bytes, 21, &s) == -EMSGSIZE);
	assert(!memcmp(bytes, saved, sizeof(bytes)));
	return 0;
}
