// SPDX-License-Identifier: GPL-2.0-only
/* Actual codec/query. Clock, USB and notifications below are fixtures;
 * neither real kernel concurrency nor firmware/eFuse truth is proved here.
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "../../../../drivers/sparklink/ws73/bsle.h"

static unsigned int checks;
#define CHECK(x) do { assert(x); checks++; } while (0)

static void put16(unsigned char *p, unsigned int n)
{
	p[0] = n;
	p[1] = n >> 8;
}

static void put32(unsigned char *p, unsigned int n)
{
	put16(p, n);
	put16(p + 2, n >> 16);
}

struct fixture {
	unsigned long long now;
	unsigned int sends, reads;
	int mode;
	unsigned char tx[512], rx[512];
};

static unsigned long long now(void *p)
{
	return ((struct fixture *)p)->now;
}

static int send_timed(void *p, size_t size, unsigned int timeout)
{
	struct fixture *f = p;

	CHECK(f->sends < 3 && timeout > 0 && timeout <= 2000 - f->now);
	CHECK(size == 36 || size == 128);
	if (size == 128) {
		CHECK(f->tx[68] == 11 && f->tx[69] == 0);
		CHECK(f->tx[70] == 2 && f->tx[71] == 0);
		CHECK(f->tx[72] == 125 && f->tx[73] == 6);
		for (unsigned int i = 74; i < 128; i++)
			CHECK(!f->tx[i]);
	}
	f->sends++;
	if (f->mode == 12)
		return -EPIPE;
	if (f->mode == 13)
		f->now += timeout < 700 ? timeout : 700;
	return 0;
}

static int receive(void *p, unsigned int timeout)
{
	struct fixture *f = p;
	unsigned char *raw = f->rx;

	f->reads++;
	f->now += timeout;
	if (f->mode == 10)
		return -ENODEV;
	if (f->mode == 16)
		return sizeof(f->rx) + 1;
	memset(raw, 0xa5, 188);
	memset(raw, 0, 92);
	put32(raw, 2);
	put32(raw + 4, 188);
	put16(raw + 12, 96);
	raw[92] = 0x19;
	raw[93] = 9;
	put16(raw + 94, 96);
	put16(raw + 96, f->mode == 4 || f->mode == 9 ? 10 : 5);
	put16(raw + 98, 88);
	put32(raw + 100, f->mode == 2 || f->mode == 3 ? 0x80001390 : 0);
	put32(raw + 104, f->mode == 3 ? 0 : f->mode == 6 ? 7 : 6);
	memset(raw + 108, f->mode == 1 ? 0x42 : 0, 6);
	if (f->mode == 2)
		memset(raw + 108, 0xa5, 6); /* failed firmware output is not disclosed */
	if (f->mode == 5)
		put16(raw + 98, 7);
	if (f->mode == 7)
		put16(raw + 98, 8);
	if (f->mode == 8 || f->mode == 20) {
		memcpy(raw + 188, raw + 92, 96);
		if (f->mode == 20)
			put16(raw + 96, 10); /* unrelated chip reply then one eFuse reply */
		put16(raw + 14, 96);
		put32(raw + 4, 284);
		return 284;
	}
	if (f->mode == 14)
		f->now = 2000;
	if (f->mode == 18) /* SLE header with PLAT's whole-allocation length is malformed. */
		raw[92] = 0xa0;
	if (f->mode == 19)
		put32(raw + 104, 0);
	return 188;
}

static int notification(void *p, unsigned int timeout, unsigned int *bits)
{
	struct fixture *f = p;

	f->now += timeout;
	*bits = f->mode == 11 ? 1U << 6 : 0;
	if (f->mode == 15)
		f->now = 2000;
	return 0;
}

int main(void)
{
	struct fixture f = {};
	unsigned int sequence = 0;
	struct ws73_bsle_io io = {
		.context = &f, .tx = f.tx, .tx_capacity = sizeof(f.tx),
		.rx = f.rx, .rx_capacity = sizeof(f.rx), .sequence = &sequence,
		.now_ms = now, .send_timed = send_timed,
		.receive = receive, .notification = notification,
	};
	const int expected[] = {
		0, 0, 0, 0, -ETIMEDOUT, -EPROTO, -EPROTO, -EPROTO,
		-EPROTO, -ETIMEDOUT, -ENODEV, -EIO, -EPIPE, -ETIMEDOUT,
		-ETIMEDOUT, -ETIMEDOUT, -EOVERFLOW, -EOVERFLOW,
		-EPROTO, -EPROTO, 0,
	};
	struct ws73_sle_efuse_info info, original;
	unsigned char raw[32], zeros[6] = {}, nonzero[6] = { 0x42, 0x42, 0x42, 0x42, 0x42, 0x42 };
	unsigned char packet[160], before[160];

	for (unsigned int size = 0; size <= sizeof(packet); size++) {
		memset(packet, 0x77, sizeof(packet));
		memcpy(before, packet, sizeof(packet));
		CHECK(ws73_wire_sle_efuse_request(packet, size, ~0U) ==
		      (size < 128 ? -EINVAL : 128));
		if (size < 128)
			CHECK(!memcmp(packet, before, sizeof(packet)));
		else {
			CHECK(packet[68] == 11 && packet[72] == 125 && packet[73] == 6);
			CHECK(!memcmp(packet + 128, before + 128, sizeof(packet) - 128));
		}
	}
	CHECK(ws73_wire_sle_efuse_request(NULL, sizeof(packet), 0) == -EINVAL);

	for (unsigned int mode = 0; mode < sizeof(expected) / sizeof(expected[0]); mode++) {
		int ret;

		f = (struct fixture){ .mode = mode };
		if (mode == 17)
			f.now = ~0ULL - 1000;
		sequence = 0;
		memset(&info, 0x77, sizeof(info));
		original = info;
		ret = ws73_sle_efuse_query(&io, &info);
		if (ret != expected[mode])
			fprintf(stderr, "mode=%u result=%d expected=%d\n",
				mode, ret, expected[mode]);
		CHECK(ret == expected[mode]);
		if (expected[mode]) {
			CHECK(!memcmp(&info, &original, sizeof(info)));
		} else {
			CHECK(info.status == (mode == 2 || mode == 3 ? 0x80001390 : 0));
			CHECK(info.size == (mode == 3 ? 0 : 6));
			CHECK(!memcmp(info.address, mode == 1 ? nonzero : zeros, 6));
			CHECK(f.sends == 3 && sequence == 3);
		}
		if (mode != 17)
			CHECK(f.now <= 2000);
		else
			CHECK(!f.sends && !f.reads);
	}
	/* No allocation padding, truncated output, or failed-read bytes become
	 * the observation. Success with all zeros is kept, not called valid.
	 */
	for (unsigned int status = 0; status < 2; status++)
		for (unsigned int output = 0; output < 32; output++)
			for (unsigned int size = 0; size <= sizeof(raw); size++) {
				int valid = size == 32 && (output == 6 || (status && !output));

				memset(raw, 0xa5, sizeof(raw));
				put16(raw, 5); put16(raw + 2, 28);
				put32(raw + 4, status); put32(raw + 8, output);
				memset(&info, 0x77, sizeof(info)); original = info;
				CHECK(ws73_wire_sle_efuse_reply(raw, size, &info) ==
				      (valid ? 0 : -EPROTO));
				if (!valid)
					CHECK(!memcmp(&info, &original, sizeof(info)));
				else if (status)
					CHECK(!memcmp(info.address, zeros, 6));
			}
	CHECK(ws73_sle_efuse_query(NULL, &info) == -EINVAL);
	CHECK(ws73_sle_efuse_query(&io, NULL) == -EINVAL);
	printf("ws73_sle_efuse_test: %u checks PASS (USB/clock fixtures, not hardware)\n", checks);
	return 0;
}
