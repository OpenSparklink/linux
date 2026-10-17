// SPDX-License-Identifier: GPL-2.0-only
/* Synthetic wire and transport tests of the actual driver codec/sequencer.
 * No USB device, firmware, DLI query, or RF acceptance is simulated as real.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "../../../../drivers/sparklink/ws73/bsle.h"

static unsigned int checks, failures;
#define CHECK(condition) do { checks++; if (!(condition)) { \
	failures++; fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
} } while (0)

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

static unsigned int get32(const unsigned char *p)
{
	return (unsigned int)p[0] | (unsigned int)p[1] << 8 |
	       (unsigned int)p[2] << 16 | (unsigned int)p[3] << 24;
}

static void ack_packet(unsigned char *p, unsigned int type, unsigned int message)
{
	memset(p, 0, 156);
	put32(p, 2);
	put32(p + 4, 156);
	put16(p + 12, 64);
	p[92] = 0x50;
	p[93] = 10;
	put16(p + 94, 8);
	put16(p + 96, type);
	put16(p + 98, 4);
	put32(p + 100, message);
}

struct received {
	unsigned int frames, type, message;
};

static int consume(void *context, unsigned int service, unsigned int queue,
		   const unsigned char *data, size_t size)
{
	struct received *r = context;

	CHECK(service == 5 && queue == 10);
	r->frames++;
	return ws73_wire_status(data, size, &r->type, &r->message);
}

static void codec_tests(void)
{
	unsigned char tx[864], custom[140], pm[4] = { 0x15, 0x02, 0, 0 };
	unsigned char rx[220];
	struct received r;
	unsigned int i, type, message;

	for (i = 0; i < sizeof(custom); i++)
		custom[i] = i; /* synthetic data, never calibration */
	memset(tx, 0xcc, sizeof(tx));
	CHECK(ws73_wire_control(tx, sizeof(tx), 0x12345678, 1, 10) == 36);
	CHECK(get32(tx) == 3 && get32(tx + 4) == 0 && get32(tx + 8) == 0x12345678);
	CHECK(get32(tx + 12) == 1 && tx[16] == 10);
	for (i = 17; i < 36; i++)
		CHECK(tx[i] == 0);
	CHECK(tx[36] == 0xcc);
	CHECK(ws73_wire_control(tx, 35, 0, 0, 0) == -EINVAL);
	CHECK(ws73_wire_control(tx, sizeof(tx), 0, 0, 10) == -EINVAL);
	CHECK(ws73_wire_control(tx, sizeof(tx), 0, 2, 0) == -EINVAL);
	CHECK(ws73_wire_control(tx, sizeof(tx), 0, 1, 256) == -EINVAL);
	CHECK(ws73_wire_control(tx, sizeof(tx), 2, 0, 0) == 36);
	CHECK(get32(tx + 12) == 0 && tx[16] == 0);
	CHECK(ws73_wire_customize(tx, sizeof(tx), 5, custom, sizeof(custom)) == 864);
	CHECK(get32(tx) == 0 && get32(tx + 4) == 864 && get32(tx + 8) == 5);
	for (i = 12; i < 64; i++)
		CHECK(tx[i] == 0);
	CHECK(!memcmp(tx + 64, "\x50\x0a\x20\x03\x00\x00\x8c\x00", 8));
	CHECK(!memcmp(tx + 72, custom, sizeof(custom)));
	for (i = 212; i < 864; i++)
		CHECK(tx[i] == 0);
	CHECK(ws73_wire_customize(tx, 863, 0, custom, 140) == -EINVAL);
	CHECK(ws73_wire_customize(tx, 864, 0, custom, 139) == -EINVAL);
	CHECK(ws73_wire_customize(tx, 864, 0, NULL, 140) == -EINVAL);
	CHECK(ws73_wire_pm(tx, sizeof(tx), 0, pm, 4) == 128);
	CHECK(!memcmp(tx + 64, "\x19\x09\x20\x00\x00\x00\x04\x00", 8));
	CHECK(!memcmp(tx + 72, pm, 4));
	CHECK(ws73_wire_pm(tx, 127, 0, pm, 4) == -EINVAL);
	CHECK(ws73_wire_pm(tx, 864, 0, pm, 3) == -EINVAL);

	ack_packet(rx, 2, 2);
	/* Stale valid-looking headers in slot padding must not be delivered. */
	memcpy(rx + 116, rx + 92, 12);
	r = (struct received) { 0 };
	CHECK(ws73_wire_receive(rx, 156, consume, &r) == 0);
	CHECK(r.frames == 1 && r.type == 2 && r.message == 2);
	/* A second actual slot is delivered, irrespective of padding content. */
	memcpy(rx + 156, rx + 92, 64);
	put32(rx + 4, 220);
	put16(rx + 14, 64);
	put32(rx + 164, 1);
	r = (struct received) { 0 };
	CHECK(ws73_wire_receive(rx, 220, consume, &r) == 0);
	CHECK(r.frames == 2 && r.message == 1);
	/* A bad later slot must not expose the valid first acknowledgement. */
	put16(rx + 158, 65);
	r = (struct received) { 0 };
	CHECK(ws73_wire_receive(rx, 220, consume, &r) == -EPROTO);
	CHECK(r.frames == 0);
	put16(rx + 158, 8);
	rx[156] = 0x51;
	CHECK(ws73_wire_receive(rx, 220, consume, &r) == -EPROTO);
	CHECK(r.frames == 0);
	ack_packet(rx, 2, 2);
	put16(rx + 14, 64);
	CHECK(ws73_wire_receive(rx, 156, consume, &r) == -EPROTO);
	CHECK(r.frames == 0);
	put16(rx + 14, 0);
	put16(rx + 16, 64); /* hole in slot table */
	CHECK(ws73_wire_receive(rx, 156, consume, &r) == -EPROTO);
	put16(rx + 16, 0);
	put32(rx + 4, 155);
	CHECK(ws73_wire_receive(rx, 156, consume, &r) == -EPROTO);
	put32(rx + 4, 156);
	CHECK(ws73_wire_receive(rx, 155, consume, &r) == -EPROTO);
	CHECK(ws73_wire_receive(rx, 11, consume, &r) == -EINVAL);
	CHECK(ws73_wire_receive(NULL, 156, consume, &r) == -EINVAL);
	CHECK(ws73_wire_receive(rx, 156, NULL, &r) == -EINVAL);
	rx[92] = 0x10; /* different service: no blind header searching */
	r = (struct received) { 0 };
	CHECK(ws73_wire_receive(rx, 156, consume, &r) == 0);
	CHECK(r.frames == 0);
	memset(rx, 0, sizeof(rx));
	CHECK(ws73_wire_receive(rx, sizeof(rx), consume, &r) == 0);
	rx[219] = 1;
	CHECK(ws73_wire_receive(rx, sizeof(rx), consume, &r) == -EPROTO);
	ack_packet(rx, 4, 2);
	CHECK(ws73_wire_status(rx + 96, 8, &type, &message) == 0 && type == 4 && message == 2);
	CHECK(ws73_wire_status(rx + 96, 7, &type, &message) == -EPROTO);
	put16(rx + 96, 1);
	CHECK(ws73_wire_status(rx + 96, 8, &type, &message) == -ENOMSG);
	put16(rx + 98, 5);
	CHECK(ws73_wire_status(rx + 96, 8, &type, &message) == -EPROTO);
	/* BSLE has its own tag length inside an RX allocation. Nonzero HCC
	 * padding is not status data. Cover both status kinds and every padded
	 * length, including the real 32-byte allocation and 86-byte slot. */
	for (unsigned int kind = 2; kind <= 4; kind += 2) {
		ack_packet(rx, kind, 2);
		for (i = 104; i < 178; i++)
			rx[i] = i ^ 0xa5;
		for (unsigned int size = 8; size <= 82; size++) {
			CHECK(ws73_wire_status(rx + 96, size, &type, &message) == 0);
			CHECK(type == kind && message == 2);
		}
		put32(rx + 4, 178); put16(rx + 12, 86); put16(rx + 94, 32);
		r = (struct received) { 0 };
		CHECK(ws73_wire_receive(rx, 178, consume, &r) == 0);
		CHECK(r.frames == 1 && r.type == kind && r.message == 2);
		for (unsigned int length = 0; length <= 33; length++) {
			put16(rx + 98, length);
			CHECK(ws73_wire_status(rx + 96, 32, &type, &message) == (length == 4 ? 0 : -EPROTO));
		}
	}
}

enum fault {
	NORMAL, NO_BSP, NO_CUSTOM, ACTION_ONLY, PANIC, BAD_AGGREGATE,
	SEND_ERROR, OPEN_ERROR, DISCONNECTED, DEADLINE_ACK,
	DRAIN_BUSY, DRAIN_PANIC, DRAIN_OVERSIZE, DRAIN_ERROR, DRAIN_DEADLINE,
};

struct fake {
	struct ws73_bsle_io io;
	unsigned char tx[864], rx[220];
	unsigned int sequence, sends, opens, notifications, bulk_reads, boot_reads;
	unsigned int drains, closes, close_reads;
	unsigned long long now;
	enum ws73_bsle_phase phase;
	enum fault fault;
	unsigned int phase_history;
};

static unsigned long long now_ms(void *context)
{
	return ((struct fake *)context)->now;
}

static void phase(void *context, enum ws73_bsle_phase p)
{
	struct fake *f = context;

	f->phase = p;
	f->phase_history |= 1U << p;
}

static int send_data(void *context, size_t size)
{
	struct fake *f = context;
	static const unsigned int sizes[] = { 36, 36, 128, 36, 36, 864 };

	CHECK(f->sends < 6);
	CHECK(size == sizes[f->sends]);
	CHECK(get32(f->tx + 8) == f->sequence - 1);
	f->sends++;
	if (f->fault == SEND_ERROR && f->sends == 3)
		return -EREMOTEIO;
	if (f->fault == DISCONNECTED && f->sends == 5)
		return -ENODEV;
	return 0;
}

static int notification(void *context, unsigned int timeout, unsigned int *bits)
{
	struct fake *f = context;

	CHECK(timeout > 0 && timeout <= 500);
	f->notifications++;
	if (f->phase == WS73_BSLE_WAIT_BSP && f->fault != NO_BSP) {
		f->now++;
		*bits = 1;
		return 0;
	}
	if (f->fault == PANIC && f->phase == WS73_BSLE_WAIT_CUSTOMIZE) {
		*bits = 1U << 6;
		return 0;
	}
	if (f->fault == DRAIN_PANIC && f->phase == WS73_BSLE_DRAINING) {
		*bits = 1U << 6;
		return 0;
	}
	f->now += timeout;
	return -ETIMEDOUT;
}

static int receive_data(void *context, unsigned int timeout)
{
	struct fake *f = context;

	CHECK(timeout > 0 && timeout <= 500);
	f->bulk_reads++;
	f->now++;
	if (f->phase == WS73_BSLE_DRAINING) {
		f->drains++;
		if (f->fault == DRAIN_ERROR)
			return -EPIPE;
		if (f->fault == DRAIN_OVERSIZE)
			return f->io.rx_capacity + 1;
		if (f->fault == DRAIN_DEADLINE) {
			f->now += 1000;
			return -ETIMEDOUT;
		}
		/* Both a stale BOOT_FINISH and stale CLOSE must be discarded. */
		if (f->drains <= 2 || f->fault == DRAIN_BUSY) {
			ack_packet(f->rx, f->drains == 1 ? 2 : 4, f->drains == 1 ? 1 : 3);
			return 156;
		}
		f->now += timeout;
		return -ETIMEDOUT;
	}
	if (f->phase == WS73_BSLE_WAIT_CLOSE) {
		f->close_reads++;
		ack_packet(f->rx, f->close_reads == 1 ? 2 : 4,
			   f->close_reads == 1 ? 1 : f->close_reads == 2 || f->fault == ACTION_ONLY ? 2 : 3);
		return 156;
	}
	if (f->phase == WS73_BSLE_WAIT_CUSTOMIZE) {
		/* A pre-open BOOT_FINISH cannot be saved to confirm the later open. */
		ack_packet(f->rx, 2, f->fault == NO_CUSTOM ? 1 : 2);
		if (f->fault == BAD_AGGREGATE) {
			put32(f->rx + 4, 220);
			put16(f->rx + 14, 128);
			return 220;
		}
		if (f->fault == DEADLINE_ACK)
			f->now += 10000;
	} else {
		f->boot_reads++;
		/* An action acknowledgement alone must not finish boot. */
		ack_packet(f->rx, f->boot_reads == 1 || f->fault == ACTION_ONLY ? 4 : 2,
			   f->boot_reads == 1 || f->fault == ACTION_ONLY ? 2 : 1);
	}
	return 156;
}

static int open_sle(void *context)
{
	struct fake *f = context;

	CHECK(f->sends == 6);
	f->opens++;
	return f->fault == OPEN_ERROR ? -EREMOTEIO : 0;
}

static int close_sle(void *context)
{
	struct fake *f = context;

	CHECK(f->phase == WS73_BSLE_CLOSING && !f->sends && !f->opens);
	f->closes++;
	return f->fault == OPEN_ERROR ? -EREMOTEIO : 0;
}

static void init_fake(struct fake *f, enum fault fault)
{
	memset(f, 0, sizeof(*f));
	f->fault = fault;
	f->io = (struct ws73_bsle_io) {
		.context = f, .tx = f->tx, .tx_capacity = sizeof(f->tx),
		.rx = f->rx, .rx_capacity = sizeof(f->rx), .sequence = &f->sequence,
		.now_ms = now_ms, .send = send_data, .receive = receive_data,
		.notification = notification, .open = open_sle, .close = close_sle, .phase = phase,
	};
}

static void warm_tests(void)
{
	const unsigned char pm[4] = { 1 }, custom[140] = { 1 };
	struct fake a, b;
	const enum fault faults[] = { NORMAL, ACTION_ONLY, OPEN_ERROR, NO_CUSTOM, BAD_AGGREGATE,
				     PANIC, SEND_ERROR, DISCONNECTED, DEADLINE_ACK };
	const int errors[] = { 0, -ETIMEDOUT, -EREMOTEIO, -ETIMEDOUT, -EPROTO,
			      -EIO, -EREMOTEIO, -ENODEV, -ETIMEDOUT };

	for (unsigned int i = 0; i < sizeof(faults) / sizeof(faults[0]); i++) {
		init_fake(&a, faults[i]);
		CHECK(ws73_bsle_restore(&a.io, pm, 4, custom, 140) == errors[i]);
		CHECK(a.drains == 3 && a.closes == 1);
		CHECK(!(a.phase_history & (1U << WS73_BSLE_WAIT_BSP)));
		CHECK(a.now < 21000);
		if (!i) {
			CHECK(a.close_reads == 3 && a.opens == 1 && a.sends == 6 && a.sequence == 6);
			CHECK(a.phase == WS73_BSLE_TRANSPORT_OPEN);
		} else {
			CHECK(!(a.phase_history & (1U << WS73_BSLE_TRANSPORT_OPEN)));
		}
		init_fake(&b, NORMAL);
		CHECK(ws73_bsle_start(&b.io, pm, 4, custom, 140) == 0);
		CHECK(!b.closes && b.sequence == 6);
	}
	init_fake(&a, NORMAL);
	CHECK(ws73_bsle_restore(&a.io, pm, 3, custom, 140) == -EINVAL);
	CHECK(!a.drains && !a.closes && !a.sends);
	a.io.close = NULL;
	CHECK(ws73_bsle_restore(&a.io, pm, 4, custom, 140) == -EINVAL);
	CHECK(!a.drains && !a.closes);
	CHECK(ws73_bsle_restore(NULL, pm, 4, custom, 140) == -EINVAL);
	const enum fault drain_faults[] = { DRAIN_BUSY, DRAIN_PANIC, DRAIN_OVERSIZE,
					  DRAIN_ERROR, DRAIN_DEADLINE };
	const int drain_errors[] = { -ETIMEDOUT, -EIO, -EOVERFLOW, -EPIPE, -ETIMEDOUT };
	for (unsigned int i = 0; i < sizeof(drain_faults) / sizeof(drain_faults[0]); i++) {
		init_fake(&a, drain_faults[i]);
		CHECK(ws73_bsle_restore(&a.io, pm, 4, custom, 140) == drain_errors[i]);
		CHECK(!a.closes && !a.opens && !a.sends && a.drains <= 64);
		if (!i)
			CHECK(a.drains == 64);
	}
}

static void handshake_tests(void)
{
	static const int errors[] = {
		0, -ETIMEDOUT, -ETIMEDOUT, -ETIMEDOUT, -EIO, -EPROTO,
		-EREMOTEIO, -EREMOTEIO, -ENODEV, -ETIMEDOUT,
	};
	unsigned char pm[4] = { 1, 0, 0, 0 }, custom[140] = { 0x01 };
	struct fake a, b;
	unsigned int i;

	for (i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		init_fake(&a, i);
		CHECK(ws73_bsle_start(&a.io, pm, 4, custom, 140) == errors[i]);
		if (!i) {
			CHECK(a.sequence == 6 && a.sends == 6 && a.opens == 1);
			CHECK(a.phase == WS73_BSLE_TRANSPORT_OPEN && a.phase_history == 0x3f);
			CHECK(a.boot_reads == 2);
		} else {
			CHECK(!(a.phase_history & (1U << WS73_BSLE_TRANSPORT_OPEN)));
			if (i == NO_BSP || i == NO_CUSTOM || i == BAD_AGGREGATE || i == PANIC || i == DEADLINE_ACK)
				CHECK(a.opens == 0);
		}
		CHECK(a.now < 21000);
		/* Failure of one owner leaves another's sequence and phases intact. */
		init_fake(&b, NORMAL);
		CHECK(ws73_bsle_start(&b.io, pm, 4, custom, 140) == 0);
		CHECK(b.sequence == 6 && b.phase == WS73_BSLE_TRANSPORT_OPEN);
	}
	init_fake(&a, NORMAL);
	CHECK(ws73_bsle_start(&a.io, pm, 4, custom, 139) == -EINVAL);
	CHECK(a.notifications == 0 && a.sends == 0 && a.sequence == 0);
	CHECK(ws73_bsle_start(&a.io, pm, 3, custom, 140) == -EINVAL);
	CHECK(a.notifications == 0 && a.sends == 0);
	a.io.receive = NULL;
	CHECK(ws73_bsle_start(&a.io, pm, 4, custom, 140) == -EINVAL);
}

int main(void)
{
	codec_tests();
	handshake_tests();
	warm_tests();
	printf("WS73_WIRE_BSLE_TEST: %s (%u checks, %u failures; synthetic IO only)\n",
	       failures ? "FAIL" : "PASS", checks, failures);
	return failures ? 1 : 0;
}
