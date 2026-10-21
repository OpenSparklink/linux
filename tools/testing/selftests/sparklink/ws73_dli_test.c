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
	unsigned int reply_stage, credits, owner, rx_subtype;
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
	CHECK(u16(f->tx + 71) == 0); /* WS73 SDK 0406 has no address-type byte */
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
	p[92] = 0xa0 | f->rx_subtype;
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
		/* Hardware Error has one raw byte, not the command-echo envelope. */
		put16(f->rx + 94, 6);
		put16(f->rx + 99, 1);
		f->rx[101] = 0;
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

static void runtime_address_tests(void)
{
    unsigned char address[6] = {0xa6, 0x7b, 0x73, 0x10, 0xe0, 1};
    unsigned char params[8], event[10] = {0xa2, 2, 0, 4, 0, 5, 4, 1, 0, 0};
    unsigned short opcode;
    unsigned int i, n;

    CHECK(ws73_dli_validate_command(0x0405, address, 6) == -EOPNOTSUPP);
    CHECK(ws73_dli_validate_runtime_address(0x0405, address, 6) == 0);
    CHECK(ws73_dli_validate_runtime_address(0x0408, address, 6) == -EOPNOTSUPP);
    CHECK(ws73_dli_validate_runtime_address(0x0405, NULL, 6) == -EINVAL);
    for (n = 0; n <= 8; n++) {
        if (n != 6)
            CHECK(ws73_dli_validate_runtime_address(0x0405, address, n) == -EINVAL);
    }
    memset(address, 0, sizeof(address));
    CHECK(ws73_dli_validate_runtime_address(0x0405, address, 6) == -EINVAL);
    for (i = 0; i < 6; i++) {
        address[i] = 1;
        CHECK(ws73_dli_validate_runtime_address(0x0405, address, 6) == 0);
        address[i] = 0;
    }
    memset(params, 0xcc, sizeof(params)); opcode = 0xcccc;
    CHECK(ws73_dli_prepare_runtime_address(address, &opcode, params, sizeof(params)) == -EINVAL);
    CHECK(opcode == 0xcccc);
    for (i = 0; i < sizeof(params); i++) CHECK(params[i] == 0xcc);
    address[5] = 2;
    CHECK(ws73_dli_prepare_runtime_address(address, &opcode, params, 5) == -EINVAL);
    CHECK(opcode == 0xcccc);
    CHECK(ws73_dli_prepare_runtime_address(address, NULL, params, 8) == -EINVAL);
    CHECK(ws73_dli_prepare_runtime_address(address, &opcode, NULL, 8) == -EINVAL);
    CHECK(ws73_dli_prepare_runtime_address(address, &opcode, params, 8) == 6);
    CHECK(opcode == 0x0405 && !memcmp(params, address, 6));
    CHECK(params[6] == 0xcc && params[7] == 0xcc);
    CHECK(ws73_dli_validate_reply(event, 9) == 0);
    event[3] = 5;
    CHECK(ws73_dli_validate_reply(event, 10) == -EPROTO);
    event[8] = 15; /* Actual rejection stays a rejection,not synthetic success. */
    CHECK(ws73_dli_validate_reply(event, 10) == 0);
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
	CHECK(ws73_dli_validate_command(0x0406, NULL, 0) == 0);
	CHECK(ws73_dli_validate_command(0x0406, NULL, 1) == -EINVAL);
	for (i = 0; i < 256; i++) {
		params[0] = i;
		CHECK(ws73_dli_validate_command(0x0406, params, 1) == -EINVAL);
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
	/* Real SDK111 1812 Complete: opcode/credit/status + handle/index echo.
	 * The previous empty-return assumption retired a real Native Runtime. */
	memset(event, 0, sizeof(event));
	event[0] = 0xa2; event[1] = 2; event[3] = 8;
	event[5] = 0x12; event[6] = 0x18; event[7] = 1;
	event[11] = 0x47; event[12] = 1;
	CHECK(ws73_dli_validate_reply(event, 13) == 0);
	for (unsigned int length = 0; length <= 20; length++) {
		event[3] = length;
		CHECK(ws73_dli_validate_reply(event, length + 5) == (length == 8 ? 0 : -EPROTO));
	}
	event[3] = 8; event[10] = 0x10;
	CHECK(ws73_dli_validate_reply(event, 13) == -EPROTO);
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
			if (i == HARDWARE_ERROR)
				CHECK(result.event == 0x000a && result.hardware_error == 0 &&
				      result.status == 0x100 && result.opcode == 0x0404);
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

static void link_event_tests(void)
{
	unsigned char data[284] = { 0xa2 }, before[284];
	const unsigned int codes[] = { 0x0015, 0x1401, 0x0005, 0x1405 };
	struct ws73_link_outcome outcome, saved;
	memset(&outcome, 0xaa, sizeof(outcome)); saved = outcome;
	CHECK(ws73_dli_link_outcome(NULL, 0, &outcome) == -EINVAL);
	CHECK(!memcmp(&outcome, &saved, sizeof(outcome)));
	CHECK(ws73_dli_link_outcome(data, sizeof(data), NULL) == -EINVAL);

	CHECK(ws73_dli_validate_link_event(NULL, 0) == -EINVAL);
	for (unsigned int kind = 0; kind < 4; kind++) {
		put16(data + 1, codes[kind]);
		for (unsigned int n = 0; n <= 278; n++) {
			put16(data + 3, n);
			for (unsigned int i = 0; i < n; i++) data[5 + i] = i ^ n;
			memcpy(before, data, sizeof(data));
			CHECK(ws73_dli_validate_link_event(data, 5 + n) ==
			      ((kind < 2 ? n >= 11 : n == 4) ? 0 : -EPROTO));
			int normalized = ws73_dli_link_outcome(data, 5 + n, &outcome);
			CHECK(normalized == ((kind < 2 ? n >= 11 : n == 4) ? 0 : -EPROTO));
			if (!normalized) {
				CHECK(outcome.kind == (kind < 2 ? 1U : 2U));
				CHECK(outcome.status == data[5] && outcome.handle == u16(data + 6));
				CHECK(outcome.reserved[0] == 0 && outcome.reserved[1] == 0);
				if (kind < 2) {
					CHECK(outcome.role == data[8] && outcome.address_type == data[9]);
					CHECK(!memcmp(outcome.address, data + 10, 6));
				} else {
					CHECK(!outcome.role && !outcome.address_type);
					CHECK(!memcmp(outcome.address, (unsigned char[6]){0}, 6));
				}
			} else CHECK(!memcmp(&outcome, &saved, sizeof(outcome)));
			outcome = saved;
			CHECK(!memcmp(before, data, sizeof(data)));
			CHECK(ws73_dli_validate_link_event(data, 4 + n) == -EPROTO);
			CHECK(ws73_dli_validate_link_event(data, 6 + n) == -EPROTO);
		}
		CHECK(ws73_dli_validate_link_event(data, 3) == -EPROTO);
		CHECK(ws73_dli_validate_link_event(data, 4) == -EPROTO);
	}
	put16(data + 1, 0x0401);
	CHECK(ws73_dli_validate_link_event(data, 5) == -ENOMSG);
	put16(data + 1, 2); /* management Complete is never a link outcome */
	CHECK(ws73_dli_validate_link_event(data, 9) == -ENOMSG);
	CHECK(ws73_dli_link_outcome(data, 9, &outcome) == -ENOMSG);
	CHECK(!memcmp(&outcome, &saved, sizeof(outcome)));
	data[0] = 0xa1;
	put16(data + 1, 0x1401);
	CHECK(ws73_dli_validate_link_event(data, 16) == -ENOMSG);
	CHECK(ws73_dli_validate_link_event(data, 0) == -ENOMSG);
}

static void security_event_tests(void)
{
	unsigned char data[271] = {0xa2}, before[271];
	const unsigned int events[] = {0x0014, 0x000e, 0x0011};

	CHECK(ws73_dli_validate_security_event(NULL, 0) == -EINVAL);
	for (unsigned int kind = 0; kind < 3; kind++) {
		put16(data + 1, events[kind]);
		for (unsigned int n = 0; n <= 266; n++) {
			put16(data + 3, n);
			for (unsigned int i = 0; i < n; i++)
				data[5 + i] = (unsigned char)(i ^ n);
			/* Every possible one-byte relay length, including a zero-length
			 * opaque PDU. The protocol consumer owns opcode-specific rules.
			 */
			for (unsigned int length = 0; length <= 255; length++) {
				data[9] = length;
				memcpy(before, data, sizeof(data));
				int valid = kind == 0 ? n == 5 + length :
					(kind == 1 ? n == 2 : n == 4);
				CHECK(ws73_dli_validate_security_event(data, 5 + n) ==
				      (valid ? 0 : -EPROTO));
				CHECK(!memcmp(before, data, sizeof(data)));
			}
			CHECK(ws73_dli_validate_security_event(data, 4 + n) == -EPROTO);
			if (n < 266)
				CHECK(ws73_dli_validate_security_event(data, 6 + n) == -EPROTO);
		}
		for (unsigned int n = 0; n < 5; n++)
			CHECK(ws73_dli_validate_security_event(data, n) ==
			      (n < 3 ? -ENOMSG : -EPROTO));
	}
	/* Recognition must not steal another event or a command frame. */
	put16(data + 1, 2);
	CHECK(ws73_dli_validate_security_event(data, sizeof(data)) == -ENOMSG);
	put16(data + 1, 0x0014);
	data[0] = 0xa1;
	CHECK(ws73_dli_validate_security_event(data, sizeof(data)) == -ENOMSG);
	/* The raw channel cannot use this codec to gain mutation permission. */
	CHECK(ws73_dli_validate_command(0x1812, data, 10) == -EOPNOTSUPP);
	CHECK(ws73_dli_validate_command(0x1c03, data, 21) == -EOPNOTSUPP);
	CHECK(ws73_dli_validate_command(0x1c05, data, 20) == -EOPNOTSUPP);
}

static void relay_command_tests(void)
{
 unsigned char params[255],payload[255];unsigned short opcode, echo_index;
 memset(payload,0xa5,sizeof(payload));
 for(unsigned int n=0;n<=250;n++) {
  memset(params,0xcc,sizeof(params));opcode=0xaaaa;
  CHECK(ws73_dli_relay_prepare(0x0fff,0x0147,payload,n,&opcode,params,sizeof(params),&echo_index)==(int)n+5);
  CHECK(opcode==0x1812&&u16(params)==0x0fff&&u16(params+2)==0x01ff&&echo_index==0x01ff&&params[4]==n);
  CHECK(!memcmp(params+5,payload,n));CHECK(!ws73_dli_relay_validate(opcode,params,n+5));
  CHECK(ws73_dli_validate_command(opcode,params,n+5)==-EOPNOTSUPP);
 }
 for(unsigned int n=251;n<=255;n++) {
  memset(params,0xcc,sizeof(params));opcode=0xaaaa;
  CHECK(ws73_dli_relay_prepare(0,0x0147,payload,n,&opcode,params,sizeof(params),&echo_index)==-EMSGSIZE);
  CHECK(opcode==0xaaaa&&params[0]==0xcc&&params[254]==0xcc);
 }
 CHECK(ws73_dli_relay_prepare(0x1000,0x0147,payload,1,&opcode,params,sizeof(params),&echo_index)==-EINVAL);
 CHECK(ws73_dli_relay_prepare(0,0x0147,payload,1,&opcode,params,5,&echo_index)==-EMSGSIZE);
 CHECK(ws73_dli_relay_validate(0x1812,NULL,5)==-EINVAL);
 CHECK(ws73_dli_relay_validate(0x1812,params,256)==-EINVAL);
 CHECK(ws73_dli_relay_validate(0x1c03,params,6)==-EPROTO);
 params[0]=params[1]=0;params[4]=2;CHECK(ws73_dli_relay_validate(0x1812,params,6)==-EPROTO);
}

static void installation_intent_tests(void)
{
 unsigned char params[255], original[255]; unsigned short opcode, echo;
 for(unsigned int kind=0x1c03;kind<=0x1c05;kind+=2) {
  size_t length=kind==0x1c03?21:20;
  memset(params,0xcc,sizeof(params));
  CHECK(ws73_dli_relay_prepare(0xfff,kind,NULL,0,&opcode,params,sizeof(params),&echo)==(int)length);
  CHECK(opcode==kind&&echo==kind&&u16(params)==0xfff&&params[18]==1&&params[19]==1);
  for(unsigned int n=2;n<18;n++)CHECK(params[n]==0);
  CHECK(!ws73_dli_relay_validate(kind,params,length));
  CHECK(ws73_dli_validate_command(kind,params,length)==-EOPNOTSUPP);
  for(unsigned int n=0;n<26;n++)if(n!=length)CHECK(ws73_dli_relay_validate(kind,params,n)==-EPROTO);
  params[2]=1;CHECK(ws73_dli_relay_validate(kind,params,length)==-EPROTO);params[2]=0;
  params[18]=2;CHECK(ws73_dli_relay_validate(kind,params,length)==-EPROTO);params[18]=1;
  if(kind==0x1c03){params[20]=1;CHECK(ws73_dli_relay_validate(kind,params,length)==-EPROTO);params[20]=0;}
  memcpy(original,params,sizeof(params));
  CHECK(ws73_dli_relay_prepare(0xfff,kind,NULL,0,&opcode,params,length-1,&echo)==-EMSGSIZE);
  CHECK(!memcmp(params,original,sizeof(params)));
  CHECK(ws73_dli_relay_prepare(0xfff,kind,original,1,&opcode,params,sizeof(params),&echo)==-EINVAL);
 }
}

static void relay_index_tests(void)
{
	unsigned char wire[12] = {0xa2, 0x14, 0, 6, 0, 0xff, 0x0f, 0xff, 1, 1, 2, 0};
	unsigned char original[12], normalized[12];

	memcpy(original, wire, sizeof(wire));
	memset(normalized, 0xcc, sizeof(normalized));
	CHECK(ws73_dli_relay_normalize_rx(wire, 11, normalized, sizeof(normalized)) == 11);
	CHECK(!memcmp(wire, original, sizeof(wire)));
	CHECK(normalized[7] == 0x47 && normalized[8] == 1 && normalized[10] == 2 && normalized[11] == 0xcc);
	for (unsigned int i = 0; i < 11; i++)
		if (i != 7 && i != 8)
			CHECK(normalized[i] == wire[i]);
	for (unsigned int capacity = 0; capacity < 11; capacity++) {
		memset(normalized, 0xcc, sizeof(normalized));
		CHECK(ws73_dli_relay_normalize_rx(wire, 11, normalized, capacity) == -EMSGSIZE);
		for (unsigned int i = 0; i < sizeof(normalized); i++)
			CHECK(normalized[i] == 0xcc);
	}
	CHECK(ws73_dli_relay_normalize_rx(NULL, 11, normalized, sizeof(normalized)) == -EINVAL);
	CHECK(ws73_dli_relay_normalize_rx(wire, 11, NULL, 11) == -EMSGSIZE);
	wire[6] = 0x10;
	CHECK(ws73_dli_relay_normalize_rx(wire, 11, normalized, sizeof(normalized)) == -EPROTO);
	wire[6] = 0;
	wire[3] = 7; wire[9] = 2;
	CHECK(ws73_dli_relay_normalize_rx(wire, 12, normalized, sizeof(normalized)) == -EPROTO);
	wire[3] = 6; wire[9] = 1; wire[7] = 0x47;
	CHECK(ws73_dli_relay_normalize_rx(wire, 11, normalized, sizeof(normalized)) == 0);
	wire[7] = 0xff; wire[1] = 2;
	CHECK(ws73_dli_relay_normalize_rx(wire, 11, normalized, sizeof(normalized)) == 0);
}

static void connected_query_reply_tests(void)
{
	unsigned char wire[20] = {0xa2,2,0,0,0,0,0,1,0};
	const unsigned int opcodes[2] = {0x180c,0x1805};
	const unsigned int lengths[2] = {3,10};
	for (unsigned int i=0;i<2;i++) {
		unsigned int opcode=opcodes[i], length=lengths[i];
		put16(wire+5,opcode);put16(wire+3,4+length);wire[8]=0;
		CHECK(ws73_dli_validate_reply(wire,9+length)==0);
		put16(wire+3,3+length);
		CHECK(ws73_dli_validate_reply(wire,8+length)==-EPROTO);
		put16(wire+3,5+length);
		CHECK(ws73_dli_validate_reply(wire,10+length)==-EPROTO);
		wire[8]=0x0c;put16(wire+3,4);
		CHECK(ws73_dli_validate_reply(wire,9)==0); /* real error, no sample */
		wire[8]=0;wire[1]=1;
		CHECK(ws73_dli_validate_reply(wire,9)==0); /* accepted Status, not Complete */
		wire[1]=2;
		CHECK(ws73_dli_validate_command(opcode,NULL,0)==-EOPNOTSUPP);
	}
}

int main(void)
{
	/* SDK ignores SLE RX sub_type; all 16 still pass the full query
	 * validator and bounded HCC parser. No RX rule changes TX tags.
	 */
	for (unsigned int subtype = 0; subtype < 16; subtype++) {
		struct fake f;
		struct ws73_dli_info info;
		struct ws73_dli_result result;
		init_fake(&f, NORMAL, 0x11);
		f.rx_subtype = subtype;
		CHECK(ws73_dli_query(&f.io, &f.credits, &info, &result) == 0);
		CHECK(info.address[5] == 0x11 && info.acb_length == 254);
	}
	link_event_tests();
	security_event_tests();
	relay_command_tests();
 installation_intent_tests();
	relay_index_tests();
	reply_tests();
	connected_query_reply_tests();
	runtime_address_tests();
	command_tests();
	query_tests();
	printf("WS73_NATIVE_DLI_TEST: %s (%u checks, %u failures; synthetic IO only)\n",
	       failures ? "FAIL" : "PASS", checks, failures);
	return failures ? 1 : 0;
}
