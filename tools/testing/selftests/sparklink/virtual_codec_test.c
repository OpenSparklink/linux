// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "../../../../drivers/sparklink/virtual_codec.h"

int main(void)
{
	struct sparklink_native_info info = {
		.version = { 0xff, 2, 3, 4, 5 },
		.features = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 },
		.address = { 2, 0x56, 0x49, 0x52, 9, 42 },
	};
	const u16 queries[] = { 0x0401, 0x0402, 0x0403, 0x0404, 0x0406 };
	const unsigned int lengths[] = { 2, 6, 10, 5, 6 };
	u8 out[20], type = 0;
	unsigned int checks = 0, i;

#define CHECK(expr) do { checks++; if (!(expr)) { \
	fprintf(stderr, "virtual codec check %u failed\n", checks); return 1; } } while (0)
	for (i = 0; i < 5; i++) {
		memset(out, 0xa5, sizeof(out));
		CHECK(sparklink_virtual_reply(&info, queries[i], i == 4 ? &type : NULL,
					     i == 4 ? 1 : 0, out) == 8 + (int)lengths[i]);
		CHECK(out[0] == 2 && !out[1] && out[2] == 4 + lengths[i] && !out[3]);
		CHECK(out[4] == (u8)queries[i] && out[5] == 4 && out[6] == 1 && !out[7]);
		CHECK(out[18] == 0xa5 && out[19] == 0xa5);
	}
	CHECK(!memcmp(out + 8, info.address, 6));
	CHECK(sparklink_virtual_reply(&info, 0x0403, NULL, 0, out) == 18);
	CHECK(!memcmp(out + 8, info.features, 10));
	CHECK(sparklink_virtual_reply(&info, 0x0404, NULL, 0, out) == 13);
	CHECK(!memcmp(out + 8, info.version, 5));
	CHECK(sparklink_virtual_reply(&info, 0x0402, NULL, 0, out) == 14);
	CHECK(!memcmp(out + 8, (u8[6]){}, 6));
	for (unsigned int op = 0; op <= 0xffff; op++) {
		if (op >= 0x0401 && op <= 0x0404)
			continue;
		CHECK(sparklink_virtual_validate(op, NULL, 0) ==
		      (op == 0x0406 ? -EINVAL : -EOPNOTSUPP));
	}
	for (unsigned int value = 0; value < 256; value++) {
		type = value;
		CHECK(sparklink_virtual_validate(0x0406, &type, 1) ==
		      (value == 0 || (value >= 2 && value <= 6) ? 0 : -EINVAL));
	}
	memset(out, 0xa5, sizeof(out));
	CHECK(sparklink_virtual_reply(&info, 0x0403, &type, (size_t)-1, out) == -EINVAL);
	CHECK(sparklink_virtual_reply(&info, 0x0406, NULL, 1, out) == -EINVAL);
	CHECK(sparklink_virtual_reply(&info, 0x0c05, NULL, 0, out) == -EOPNOTSUPP);
	CHECK(!memcmp(out, (u8[20]){ [0 ... 19] = 0xa5 }, 20));
	printf("VIRTUAL_CODEC_PASS checks=%u scope=actual-test-backend-codec\n", checks);
	return 0;
}
