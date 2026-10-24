// SPDX-License-Identifier: GPL-2.0-only
/* Pure production codecs linked unchanged. No USB, clock, allocator/lock stub,
 * firmware, command engine or successful transport dependencies. Callback is
 * an input-bounds observer, with a separately exercised explicit error result.
 */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../../../../../drivers/sparklink/ws73/dli.h"

static unsigned int le16(const uint8_t *p)
{
	return (unsigned int)p[0] | (unsigned int)p[1] << 8;
}

static void raw_parsers(const uint8_t *data, size_t size, unsigned int maximum)
{
	const uint8_t *payload = NULL;
	size_t length = SIZE_MAX;
	unsigned int handle = 0xfeed, boundary = 0xface;
	struct ws73_link_outcome outcome, before;
	unsigned int type = 0x12345678, message = 0x12345678;
	int ret, valid;

	(void)ws73_wire_status(data, size, &type, &message);
	(void)ws73_dli_validate_reply(data, size);
	(void)ws73_dli_validate_security_event(data, size);
	valid = ws73_dli_validate_link_event(data, size);
	memset(&outcome, 0xa5, sizeof(outcome));
	memcpy(&before, &outcome, sizeof(before));
	ret = ws73_dli_link_outcome(data, size, &outcome);
	assert(ret == valid);
	if (ret)
		assert(!memcmp(&before, &outcome, sizeof(outcome)));
	else {
		assert(size >= 9 && outcome.status == data[5]);
		assert(outcome.handle == le16(data + 6));
	}
	ret = ws73_wire_acb_fragment_decode(data, size, maximum,
					   &handle, &boundary, &payload, &length);
	if (ret) {
		assert(handle == 0xfeed && boundary == 0xface);
		assert(!payload && length == SIZE_MAX);
	} else {
		assert(size >= 6 && length == size - 5 && length <= maximum);
		assert(payload == data + 5 && handle <= 0xfff && boundary <= 3);
	}
	handle = 0xfeed;
	payload = NULL;
	length = SIZE_MAX;
	ret = ws73_wire_acb_decode(data, size, maximum, &handle, &payload, &length);
	if (ret)
		assert(handle == 0xfeed && !payload && length == SIZE_MAX);
	else
		assert(payload == data + 5 && size == length + 5 && handle <= 0xfff);
}

struct observer {
	const uint8_t *base;
	size_t size;
	unsigned int calls;
	int fail;
};

static int consume(void *context, unsigned int service, unsigned int queue,
		   const unsigned char *payload, size_t size)
{
	struct observer *o = context;
	uintptr_t begin = (uintptr_t)o->base, value = (uintptr_t)payload;

	assert(++o->calls <= WS73_WIRE_RX_SLOTS);
	assert((service == 5 && queue == 10) || (service == 10 && queue == 8));
	assert(value >= begin && value - begin <= o->size);
	assert(size <= o->size - (value - begin));
	raw_parsers(payload, size, 2047);
	return o->fail ? -ECANCELED : 0;
}

static void encoders(const uint8_t *data, size_t size)
{
	/* Caller pointers always denote valid C objects. Bad-user-address syscall
	 * fuzz belongs to a VM; this harness never manufactures caller UB.
	 */
	size_t capacity = size > 1 ? le16(data) % 2122 : size;
	unsigned int a = size > 3 ? le16(data + 2) : 0;
	unsigned int b = size > 5 ? le16(data + 4) : 0;
	uint8_t *out = malloc(capacity + 1);
	int kind, ret;
	size_t i;

	assert(out);
	for (kind = 0; kind < 5; kind++) {
		memset(out, 0xa5, capacity + 1);
		switch (kind) {
		case 0:
			ret = ws73_wire_control(out, capacity, a, a & 3, b & 511);
			break;
		case 1:
			ret = ws73_wire_customize(out, capacity, a, data, size);
			break;
		case 2:
			ret = ws73_wire_pm(out, capacity, a, data, size);
			break;
		case 3:
			ret = ws73_wire_command(out, capacity, b, a, data, size);
			break;
		default:
			ret = ws73_wire_acb_fragment(out, capacity, b, a, b & 7,
						    2047, data, size);
			break;
		}
		if (ret < 0) {
			for (i = 0; i <= capacity; i++)
				assert(out[i] == 0xa5); /* failure atomicity */
		} else {
			assert((size_t)ret <= capacity);
			for (i = ret; i <= capacity; i++)
				assert(out[i] == 0xa5); /* logical capacity, not just malloc bounds */
			if (kind == 4) {
				unsigned int handle = 0, boundary = 0;
				const uint8_t *payload = NULL;
				size_t length = 0;

				assert(!ws73_wire_acb_fragment_decode(out + 68, size + 5,
					2047, &handle, &boundary, &payload, &length));
				assert(handle == a && boundary == (b & 7) && length == size);
				assert(!memcmp(payload, data, size));
			}
		}
	}
	free(out);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	/* Same RX budget as production. Raw parser and encoder calls additionally
	 * use bounded malformed small/large values, not over-sized allocations.
	 */
	struct observer o = { .base = data, .size = size };
	uint8_t good[104] = { 2, 0, 0, 0, 104 };
	unsigned int max = size > 1 ? le16(data) : 0;
	int ret;

	if (size > WS73_WIRE_RX_MAX)
		return 0;
	raw_parsers(data, size, max);
	raw_parsers(data, size, 254);
	raw_parsers(data, size, 2047);
	ret = ws73_wire_receive(data, size, consume, &o);
	/* The first pass validates the whole aggregate before any consumer call.
	 * A pure observer never rejects, so a structural failure exposes nothing.
	 */
	if (ret)
		assert(!o.calls);
	o.calls = 0;
	o.fail = 1;
	ret = ws73_wire_receive(data, size, consume, &o);
	if (o.calls)
		assert(o.calls == 1 && ret == -ECANCELED);
	encoders(data, size);
	(void)ws73_dli_validate_command(max, data, size);
	/* Fresh valid BSLE after every malformed attempt. This checks pure parser
	 * re-entry, not a stateful USB split/concatenation or runtime recovery.
	 */
	good[12] = 12;
	good[92] = 0x50;
	good[93] = 10;
	good[94] = 8;
	good[96] = 2;
	good[98] = 4;
	good[100] = 2;
	o = (struct observer) { .base = good, .size = sizeof(good) };
	assert(!ws73_wire_receive(good, sizeof(good), consume, &o) && o.calls == 1);
	return 0;
}
