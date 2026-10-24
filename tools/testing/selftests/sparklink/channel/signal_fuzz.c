// SPDX-License-Identifier: GPL-2.0-only
/* Actual production parser/encoder. Valid C pointers, arbitrary bounded bytes.
 * Not a kernel callback/allocator/concurrency or physical firmware test. */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "../../../../../net/sparklink/sle_channel_wire.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t length)
{
	struct sl_channel_signal signal, before, again;
	unsigned char encoded[32];
	memset(&signal, 0xa5, sizeof(signal));
	before = signal;
	int ret = sl_channel_signal_decode(data, length, &signal);
	if (ret)
		assert(!memcmp(&signal, &before, sizeof(signal)));
	else {
		int n = sl_channel_signal_encode(encoded, sizeof(encoded),
						 &signal);
		assert(n >= 0 && (size_t)n == length &&
		       !memcmp(encoded, data, length));
		assert(!sl_channel_signal_decode(encoded, n, &again));
		assert(!memcmp(&signal, &again, sizeof(signal)));
	}
	return 0;
}
