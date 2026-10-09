// SPDX-License-Identifier: GPL-2.0-only
/* Production native-query tests with synthetic HCC/DLI inputs. No RF claim. */
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "../../../../drivers/sparklink/ws73/dli.h"

static unsigned int checks, failures;
#define CHECK(condition) do { checks++; if (!(condition)) { \
	failures++; fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
} } while (0)

static unsigned int u16(const unsigned char *p)
{
	return (unsigned int)p[0] | (unsigned int)p[1] << 8;
}

static void put16(unsigned char *p, unsigned int value)
{
	p[0] = value;
	p[1] = value >> 8;
}

static void put32(unsigned char *p, unsigned int value)
{
	put16(p, value);
	put16(p + 2, value >> 16);
}

enum fault {
	NORMAL, ZERO_WINDOW, FINAL_ZERO, WRONG_OPCODE, STATUS_FIRST, OPCODE_EVENT,
	BAD_LENGTH, SHORT_VALUE, FAILURE_STATUS, DUPLICATE, NO_GRANT,
	SEND_ERROR, DISCONNECT, PANIC, HARDWARE_ERROR, ZERO_ADDRESS, FF_ADDRESS,
	BAD_BUFFER, HUGE_BUFFER, LATE_COMPLETE,
};

struct fake {
	struct ws73_bsle_io io;
	unsigned char tx[864], rx[220];
	unsigned int sequence, controls, commands, pending_opcode, reads, grant_reads;
	unsigned int reply_stage, credits, owner;
	unsigned long long now;
	enum fault fault;
};

static unsigned long long now_ms(void *context)
{
	return ((struct fake *)context)->now;
}

static int send_data(void *context, size_t size)
{
	struct fake *f = context;
	static const unsigned int ops[] = { 0x0404, 0x0402, 0x0403, 0x0406 };

	CHECK(u16(f->tx + 8) == f->sequence - 1);
	if (f->tx[0] == 3) {
		CHECK(size == 36 && f->controls < 2);
		CHECK(u16(f->tx + 12) == (f->controls ? 0 : 1));
		CHECK(f->tx[16] == (f->controls ? 0 : 8));
		f->controls++;
		return 0;
	}
	CHECK(f->controls == 2);
	CHECK(size == 128 && !f->tx[0]);
	CHECK(!memcmp(f->tx + 64, "\xa0\x08", 2) && f->tx[68] == 0xa1);
	CHECK(f->commands < 4 && u16(f->tx + 69) == ops[f->commands]);
	CHECK(u16(f->tx + 71) == (f->commands == 3 ? 1 : 0));
	if (f->commands == 3)
		CHECK(f->tx[73] == 0); /* explicit public-address type */
	f->commands++;
	f->pending_opcode = u16(f->tx + 69);
	f->reply_stage = 0;
	if (f->fault == SEND_ERROR && f->commands == 3)
		return -EREMOTEIO;
	return 0;
}

static void packet(struct fake *f, unsigned int event, unsigned int opcode,
		   unsigned int credit, unsigned int status,
		   const unsigned char *value, size_t length)
{
	unsigned char *p = f->rx;

	memset(p, 0, sizeof(f->rx));
	put32(p, 2);
	put32(p + 4, 156);
	put16(p + 12, 64);
	p[92] = 0xa0;
	p[93] = 8;
	put16(p + 94, opcode ? 9 + length : 8);
	p[96] = 0xa2;
	put16(p + 97, event);
	put16(p + 99, opcode ? 4 + length : 3);
	put16(p + 101, opcode);
	p[103] = credit;
	if (opcode) {
		p[104] = status;
		if (length)
			memcpy(p + 105, value, length);
	}
}

static int receive_data(void *context, unsigned int timeout)
{
	struct fake *f = context;
	unsigned char value[10] = { 0 };
	unsigned int opcode = f->pending_opcode, credit = 1;
	size_t length = 0;

	CHECK(timeout > 0 && timeout <= 500);
	f->now++;
	f->reads++;
	if (!opcode) {
		f->grant_reads++;
		packet(f, 2, 0, f->fault == NO_GRANT ? 0 : 1, 0, NULL, 0);
		return 156;
	}
	if (f->fault == DISCONNECT && f->commands == 2)
		return -ENODEV;
	if (f->fault == HARDWARE_ERROR) {
		packet(f, 0x000a, opcode, 0, 0, NULL, 0);
		return 156;
	}
	if (f->fault == WRONG_OPCODE && !f->reply_stage++) {
		packet(f, 2, 0x1888, 1, 0, NULL, 0);
		return 156;
	}
	if (f->fault == STATUS_FIRST && !f->reply_stage++) {
		packet(f, 1, opcode, 1, 0, NULL, 0);
		return 156;
	}
	if (f->fault == OPCODE_EVENT && !f->reply_stage++) {
		packet(f, opcode, opcode, 1, 0, NULL, 0);
		return 156;
	}
	if (f->fault == FAILURE_STATUS) {
		packet(f, 1, opcode, 1, 0xfe, NULL, 0);
		return 156;
	}
	switch (opcode) {
	case 0x0404:
		/* Author-attributed version return: 01 6c 00 a1 00. */
		memcpy(value, "\x01\x6c\x00\xa1\x00", 5);
		length = 5;
		break;
	case 0x0402:
		value[0] = 254;
		value[2] = f->fault == BAD_BUFFER ? 0 : 5;
		if (f->fault == HUGE_BUFFER)
			value[1] = 8;
		length = 6;
		break;
	case 0x0403:
		memset(value, f->owner, 10);
		length = 10;
		break;
	case 0x0406:
		value[0] = 2;
		value[5] = f->owner;
		if (f->fault == ZERO_ADDRESS)
			memset(value, 0, 6);
		if (f->fault == FF_ADDRESS)
			memset(value, 255, 6);
		length = 6;
		break;
	default:
		CHECK(0);
	}
	if (f->fault == ZERO_WINDOW || f->fault == NO_GRANT ||
	    (f->fault == FINAL_ZERO && opcode == 0x0406))
		credit = 0;
	packet(f, 2, opcode, credit, 0, value, f->fault == SHORT_VALUE ? length - 1 : length);
	if (f->fault == BAD_LENGTH)
		put16(f->rx + 99, 20);
	if (f->fault == DUPLICATE) {
		memcpy(f->rx + 156, f->rx + 92, 64);
		put32(f->rx + 4, 220);
		put16(f->rx + 14, 64);
		return 220;
	}
	f->pending_opcode = 0;
	if (f->fault == LATE_COMPLETE)
		f->now += 10000;
	return 156;
}

static int notification(void *context, unsigned int timeout, unsigned int *bits)
{
	struct fake *f = context;

	CHECK(timeout && timeout <= 20);
	if (f->fault == PANIC) {
		*bits = 1U << 6;
		return 0;
	}
	f->now += timeout;
	return -ETIMEDOUT;
}

static void init_fake(struct fake *f, enum fault fault, unsigned int owner)
{
	memset(f, 0, sizeof(*f));
	f->fault = fault;
	f->owner = owner;
	f->sequence = 6; /* query starts after the six BSLE packages */
	f->credits = fault == ZERO_WINDOW ? 0 : 1;
	f->io = (struct ws73_bsle_io) {
		.context = f, .tx = f->tx, .tx_capacity = sizeof(f->tx),
		.rx = f->rx, .rx_capacity = sizeof(f->rx), .sequence = &f->sequence,
		.now_ms = now_ms, .send = send_data, .receive = receive_data,
		.notification = notification,
	};
}

static void command_tests(void)
{
	unsigned char tx[328], params[255];
	unsigned int i;

	memset(params, 0x5a, sizeof(params));
	for (unsigned int op = 0x0402; op <= 0x0404; op++) {
		CHECK(ws73_dli_validate_command(op, NULL, 0) == 0);
		CHECK(ws73_dli_validate_command(op, params, 1) == -EINVAL);
	}
	CHECK(ws73_dli_validate_command(0x0406, NULL, 0) == -EINVAL);
	CHECK(ws73_dli_validate_command(0x0406, NULL, 1) == -EINVAL);
	for (i = 0; i < 256; i++) {
		params[0] = i;
		CHECK(ws73_dli_validate_command(0x0406, params, 1) == (i <= 1 ? 0 : -EINVAL));
	}
	CHECK(ws73_dli_validate_command(0x0401, NULL, 0) == -EOPNOTSUPP);
	CHECK(ws73_dli_validate_command(0x1001, params, 8) == -EOPNOTSUPP);
	CHECK(ws73_dli_validate_command(0x0c05, params, 5) == -EOPNOTSUPP);
	memset(params, 0x5a, sizeof(params));
	CHECK(ws73_wire_command(tx, sizeof(tx), 8, 0x0404, NULL, 0) == 128);
	CHECK(!memcmp(tx + 64, "\xa0\x08\x05\x00\xa1\x04\x04\x00\x00", 9));
	CHECK(ws73_wire_command(tx, sizeof(tx), 9, 0x0406, params, 1) == 128);
	CHECK(!memcmp(tx + 64, "\xa0\x08\x06\x00\xa1\x06\x04\x01\x00\x5a", 10));
	CHECK(ws73_wire_command(tx, sizeof(tx), 10, 0x0c03, params, 255) == 328);
	CHECK(u16(tx + 66) == 260 && u16(tx + 71) == 255);
	CHECK(!memcmp(tx + 73, params, 255));
	memset(tx, 0xcc, sizeof(tx));
	CHECK(ws73_wire_command(tx, 127, 0, 0x0404, NULL, 0) == -EMSGSIZE);
	for (i = 0; i < sizeof(tx); i++)
		CHECK(tx[i] == 0xcc);
	CHECK(ws73_wire_command(tx, 328, 0, 0x0404, params, 256) == -EINVAL);
	CHECK(ws73_wire_command(tx, 328, 0, 0, NULL, 0) == -EINVAL);
	CHECK(ws73_wire_command(tx, 328, 0, 65536, NULL, 0) == -EINVAL);
	CHECK(ws73_wire_command(tx, 328, 0, 0x0406, NULL, 1) == -EINVAL);
}

static void reply_tests(void)
{
	static const struct { unsigned int opcode, returns; } cases[] = {
		{ 0x0402, 6 }, { 0x0403, 10 }, { 0x0404, 5 }, { 0x0406, 6 },
		{ 0x0c02, 1 }, { 0x0c03, 0 }, { 0x0c04, 0 }, { 0x0c05, 0 },
		{ 0x1001, 0 }, { 0x1002, 0 },
	};
	unsigned char event[260] = { 0xa2, 2, 0, 4, 0, 2, 0x0c, 1, 0 };

	/* 0C02 must contain exactly the selected signed power byte. */
	CHECK(ws73_dli_validate_reply(event, 9) == -EPROTO);
	event[3] = 5;
	event[9] = 0xd6;
	CHECK(ws73_dli_validate_reply(event, 10) == 0);
	for (unsigned int i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		for (unsigned int complete = 0; complete <= 1; complete++) {
			for (unsigned int length = 0; length <= 20; length++) {
				event[1] = complete ? 2 : 1;
				event[3] = length;
				event[5] = cases[i].opcode;
				event[6] = cases[i].opcode >> 8;
				for (unsigned int status = 0; status < 256; status++) {
					int expected;

					event[8] = status;
					expected = complete ? (length >= 4 &&
						(status || length == 4 + cases[i].returns) ? 0 : -EPROTO) :
						(length == 4 ? 0 : -EPROTO);
					CHECK(ws73_dli_validate_reply(event, length + 5) == expected);
				}
			}
		}
	}
	/* Unknown return data is opaque; it does not add command support. */
	event[1] = 2;
	event[3] = 244;
	event[5] = 0xfe;
	event[6] = 0xfc;
	event[8] = 0;
	CHECK(ws73_dli_validate_reply(event, 249) == 0);
	CHECK(ws73_dli_validate_reply(event, 248) == -EPROTO);
	CHECK(ws73_dli_validate_reply(event, 250) == -EPROTO);
	CHECK(ws73_dli_validate_reply(event, (size_t)-1) == -EPROTO);
	event[5] = event[6] = 0;
	for (unsigned int event_code = 0; event_code <= 3; event_code++) {
		event[1] = event_code;
		for (unsigned int length = 0; length <= 5; length++) {
			event[3] = length;
			CHECK(ws73_dli_validate_reply(event, 5 + length) ==
			      ((event_code == 1 || event_code == 2) && length == 3 ? 0 : -EPROTO));
		}
	}
	event[0] = 0xa1;
	CHECK(ws73_dli_validate_reply(event, 8) == -EPROTO);
	CHECK(ws73_dli_validate_reply(NULL, 8) == -EINVAL);
	for (unsigned int length = 0; length < 5; length++)
		CHECK(ws73_dli_validate_reply(event, length) == -EPROTO);
}

static void query_tests(void)
{
	static const int expected[] = {
		0, 0, 0, 0, 0, 0, -EPROTO, -EPROTO, -EREMOTEIO, -EPROTO,
		-ETIMEDOUT, -EREMOTEIO, -ENODEV, -EIO, -EIO, -EPROTO, -EPROTO,
		-EPROTO, -EPROTO, -ETIMEDOUT,
	};
	struct fake a, b;
	struct ws73_dli_info info, before, other;
	struct ws73_dli_result result;
	unsigned int i;

	for (i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
		init_fake(&a, i, 0x11);
		memset(&info, 0xa5, sizeof(info));
		before = info;
		CHECK(ws73_dli_query(&a.io, &a.credits, &info, &result) == expected[i]);
		if (expected[i]) {
			CHECK(!memcmp(&info, &before, sizeof(info)));
			CHECK(a.commands <= 4 && a.now <= 11000);
			if (i == FAILURE_STATUS)
				CHECK(result.status == 0xfe && result.opcode == 0x0404);
			if (i == NO_GRANT)
				CHECK(a.commands == 1 && a.credits == 0 && result.opcode == 0x0402);
		} else {
			CHECK(a.commands == 4 && a.sequence == 12);
			CHECK(!memcmp(info.version, "\x01\x6c\x00\xa1\x00", 5));
			CHECK(info.acb_length == 254 && info.acb_count == 5);
			CHECK(info.icb_length == 0 && info.icb_count == 0);
			CHECK(info.features[0] == 0x11 && info.features[9] == 0x11);
			CHECK(info.address[0] == 2 && info.address[5] == 0x11);
			if (i == FINAL_ZERO)
				CHECK(a.credits == 0);
			if (i == ZERO_WINDOW)
				CHECK(a.grant_reads == 4);
			if (i == STATUS_FIRST || i == WRONG_OPCODE || i == OPCODE_EVENT)
				CHECK(a.reads == 8);
		}
		/* Another instance independently returns its own address/features. */
		init_fake(&b, NORMAL, 0x22);
		CHECK(ws73_dli_query(&b.io, &b.credits, &other, &result) == 0);
		CHECK(other.address[5] == 0x22 && other.features[9] == 0x22 && b.sequence == 12);
	}
	init_fake(&a, NORMAL, 0x11);
	a.credits = 256;
	CHECK(ws73_dli_query(&a.io, &a.credits, &info, &result) == -EINVAL);
	CHECK(a.controls == 0 && a.commands == 0);
}

int main(void)
{
	reply_tests();
	command_tests();
	query_tests();
	printf("WS73_NATIVE_DLI_TEST: %s (%u checks, %u failures; synthetic IO only)\n",
	       failures ? "FAIL" : "PASS", checks, failures);
	return failures ? 1 : 0;
}
