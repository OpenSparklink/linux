// SPDX-License-Identifier: GPL-2.0-only
/* Production codec boundary tests. No controller credit or RF claim. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "../../../../drivers/sparklink/ws73/wire.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); return 1; } } while (0)

int main(void)
{
	unsigned char out[2300], data[2048];
	const unsigned char *payload;
	unsigned int handle;
	size_t size, i;
	int n;

	for (i = 0; i < sizeof(data); i++)
		data[i] = (i * 37 + 11) & 255;
	/* Known envelope, nonzero handle: catches the reference hardcoded zero. */
	n = ws73_wire_acb(out, sizeof(out), 0x12345678, 0xabc, 254, data, 7);
	CHECK(n == 128 && out[4] == 128 && out[8] == 0x78);
	CHECK(out[64] == 0xa0 && out[65] == 8 && out[66] == 12 && !out[67]);
	CHECK(out[68] == 0xa3 && out[69] == 0xbc && out[70] == 0x0a);
	CHECK(out[71] == 7 && !out[72] && !memcmp(out + 73, data, 7));
	for (i = 80; i < 128; i++)
		CHECK(out[i] == 0);
	/* Explicit 253/254/255 boundaries; controller limit includes DTAP bytes. */
	CHECK(ws73_wire_acb(out, sizeof(out), 1, 0, 254, data, 253) == 326);
	CHECK(ws73_wire_acb(out, sizeof(out), 1, 0, 254, data, 254) == 327);
	CHECK(ws73_wire_acb(out, sizeof(out), 1, 0, 254, data, 255) == -EMSGSIZE);
	CHECK(ws73_wire_acb(out, sizeof(out), 1, 0xfff, 2047, data, 2047) == 2120);
	CHECK(ws73_wire_acb_decode(out + 68, 2052, 2047, &handle, &payload, &size) == 0);
	CHECK(handle == 0xfff && size == 2047 && !memcmp(payload, data, size));
	CHECK(ws73_wire_acb_decode(out + 68, 2051, 2047, &handle, &payload, &size) == -EPROTO);
	CHECK(ws73_wire_acb_decode(out + 68, 2052, 254, &handle, &payload, &size) == -EPROTO);
	out[70] |= 0x10;
	handle = 0xdead; payload = data; size = 777;
	CHECK(ws73_wire_acb_decode(out + 68, 2052, 2047, &handle, &payload, &size) == -EOPNOTSUPP);
	CHECK(handle == 0xdead && payload == data && size == 777);
	CHECK(ws73_wire_acb(out, sizeof(out), 1, 0x1000, 254, data, 1) == -EINVAL);
	CHECK(ws73_wire_acb(out, 127, 1, 0, 254, data, 1) == -EMSGSIZE);
	CHECK(ws73_wire_acb(out, sizeof(out), 1, 0, 0, data, 1) == -EINVAL);
	CHECK(ws73_wire_acb(out, sizeof(out), 1, 0, 2048, data, 1) == -EINVAL);
	CHECK(ws73_wire_acb(out, sizeof(out), 1, 0, 254, NULL, 1) == -EINVAL);
	CHECK(ws73_wire_acb(out, sizeof(out), 1, 0, 254, data, 0) == -EINVAL);
	CHECK(ws73_wire_acb_decode(NULL, 5, 254, &handle, &payload, &size) == -EINVAL);
	puts("WS73 full-SDU ACB codec boundaries PASS (offline only)");
	return 0;
}
