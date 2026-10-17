// SPDX-License-Identifier: GPL-2.0-only
/* Actual production codec/query; clock, USB and notifications are fixtures.
 * This does not establish USB concurrency, silicon or firmware qualification. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "../../../../drivers/sparklink/ws73/bsle.h"
static unsigned int checks;
#define CHECK(x)           \
	do {               \
		assert(x); \
		checks++;  \
	} while (0)
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
	unsigned char model;
};
static unsigned long long now(void *p)
{
	return ((struct fixture *)p)->now;
}
static int send_packet(void *p, size_t n)
{
	struct fixture *f = p;
	f->sends++;
	return f->mode == 1 ? -EPIPE : (n == 36 || n == 128 ? 0 : -EINVAL);
}
static void response(unsigned char *p, unsigned char model)
{
	memset(p, 0, 156);
	put32(p, 2);
	put32(p + 4, 156);
	put16(p + 12, 64);
	p[92] = 0x19;
	p[93] = 9;
	put16(p + 94, 14);
	put16(p + 96, 10);
	put16(p + 98, 10);
	put32(p + 104, 2);
	p[108] = model;
}
static unsigned char *rx;
static int receive_packet(void *p, unsigned int timeout)
{
	struct fixture *f = p;
	f->now += timeout;
	f->reads++;
	if (f->mode == 2)
		return -ETIMEDOUT;
	if (f->mode == 3)
		return -ENODEV;
	if (f->mode == 4)
		return 865;
	response(rx, f->model);
	if (f->mode == 5)
		rx[108] = 3;
	if (f->mode == 6)
		put16(rx + 96, 9);
	if (f->mode == 7)
		put16(rx + 14, 64);
	if (f->mode == 8)
		f->now = 2000;
	return 156;
}
static int notification(void *p, unsigned int timeout, unsigned int *bits)
{
	struct fixture *f = p;
	f->now += timeout;
	*bits = f->mode == 9 ? 64 : 0;
	return 0;
}
int main(void)
{
	unsigned char tx[864], incoming[864], raw[32];
	struct ws73_chip_info out;
	unsigned int sequence;
	struct fixture f;
	struct ws73_bsle_io io = { .context = &f,
				   .tx = tx,
				   .tx_capacity = sizeof(tx),
				   .rx = incoming,
				   .rx_capacity = sizeof(incoming),
				   .sequence = &sequence,
				   .now_ms = now,
				   .send = send_packet,
				   .receive = receive_packet,
				   .notification = notification };
	int expected[] = { 0,	       -EPIPE,	    -ETIMEDOUT, -ENODEV,
			   -EOVERFLOW, -EOPNOTSUPP, -ETIMEDOUT, -EPROTO,
			   -ETIMEDOUT, -EIO };
	rx = incoming;
	CHECK(ws73_wire_chip_request(tx, 128, 99) == 128);
	CHECK(tx[64] == 0x19 && tx[65] == 9 && tx[68] == 16 && tx[70] == 1 &&
	      tx[72] == 0 && tx[8] == 99);
	CHECK(ws73_wire_chip_request(tx, 127, 0) == -EINVAL);
	for (unsigned int m = 0; m < 3; m++)
		for (unsigned int b = 0; b < 3; b++) {
			memset(raw, 0xa5, sizeof(raw));
			put16(raw, 10);
			put16(raw + 2, 10);
			put32(raw + 4, 0);
			put32(raw + 8, 2);
			raw[12] = m;
			raw[13] = b;
			out = (struct ws73_chip_info){ 7, 7 };
			CHECK(ws73_wire_chip_reply(raw, sizeof(raw), &out) ==
			      0);
			CHECK(out.model == m && out.bus == b);
			for (unsigned int n = 0; n < 14; n++) {
				out = (struct ws73_chip_info){ 7, 7 };
				CHECK(ws73_wire_chip_reply(raw, n, &out) ==
				      -EPROTO);
				CHECK(out.model == 7 && out.bus == 7);
			}
		}
	for (unsigned int mode = 0; mode < 10; mode++)
		for (unsigned int model = 0; model < 3; model++) {
			f = (struct fixture){ .mode = mode, .model = model };
			sequence = 0;
			out = (struct ws73_chip_info){ 7, 7 };
			CHECK(ws73_chip_query(&io, &out) == expected[mode]);
			CHECK(f.now <= 2101);
			if (mode)
				CHECK(out.model == 7 && out.bus == 7);
			else {
				CHECK(out.model == model && out.bus == 0);
				CHECK(f.sends == 3 && sequence == 3);
			}
		}
	for (unsigned int n = 0; n < 256; n++) {
		memset(raw, 0, 32);
		put16(raw, 10);
		put16(raw + 2, 10);
		put32(raw + 8, 2);
		raw[12] = n;
		out = (struct ws73_chip_info){ 7, 7 };
		CHECK(ws73_wire_chip_reply(raw, 32, &out) ==
		      (n < 3 ? 0 : -EOPNOTSUPP));
		if (n >= 3)
			CHECK(out.model == 7);
	}
	memset(raw, 0, 32);
	put16(raw, 10);
	put16(raw + 2, 10);
	put32(raw + 8, 2);
	put32(raw + 4, 1);
	CHECK(ws73_wire_chip_reply(raw, 32, &out) == -EIO);
	put32(raw + 4, 0);
	put32(raw + 8, 1);
	CHECK(ws73_wire_chip_reply(raw, 32, &out) == -EPROTO);
	put32(raw + 8, 2);
	put16(raw + 2, 11);
	CHECK(ws73_wire_chip_reply(raw, 32, &out) == -EPROTO);
	put16(raw, 9);
	CHECK(ws73_wire_chip_reply(raw, 32, &out) == -ENOMSG);
	printf("WS73_CHIP_QUERY_OFFLINE_PASS checks=%u\n", checks);
	return 0;
}
