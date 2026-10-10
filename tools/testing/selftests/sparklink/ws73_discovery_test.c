// SPDX-License-Identifier: GPL-2.0-only
/* Production WS73 profile codecs. Synthetic vectors; no RF/Ready claim. */
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "../../../../drivers/sparklink/ws73/discovery.h"
#include "../../../../drivers/sparklink/ws73/dli.h"

static unsigned int checks, failures;
#define CHECK(condition) do { checks++; if (!(condition)) { \
	failures++; fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
} } while (0)

static void adv_params_tests(void)
{
	/* Independent wire vector: every address/tail byte has a distinct value.
	 * Reserved values here exercise serialization, not controller support.
	 */
	static const unsigned char expected[49] = {
		0x12, 0x03, 0x02, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab,
		0x07, 0x06, 0x04, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x03, 0xd6, 0x01,
		0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x34, 0x12, 0x78, 0x56, 0xbc, 0x9a, 0xf0, 0xde,
		0x57, 0x13, 0x68, 0x24, 0x79, 0x35,
	};
	struct sparklink_discovery_adv_params params = {
		.handle = 0x12, .mode = 3, .gt_role = 2,
		.interval_min = 0x123456, .interval_max = 0xabcdef,
		.channel_map = 7, .own_address_type = 6, .peer_address_type = 4,
		.own_address = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15 },
		.peer_address = { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25 },
		.filter = 3, .tx_power = -42, .primary_frame = 1,
		.secondary_frame = 2, .secondary_phy = 3, .secondary_pilot = 4,
		.secondary_mcs = 5, .secondary_max_skip = 6, .sid = 7,
		.request_notification = 8, .max_requests = 9,
		.request_rx_duration = 0x1234, .conn_interval_min = 0x5678,
		.conn_interval_max = 0x9abc, .conn_max_latency = 0xdef0,
		.supervision_timeout = 0x1357, .min_event_length = 0x2468,
		.max_event_length = 0x3579,
	};
	struct field {
		size_t host_offset;
		unsigned int wire_offset, bytes, max;
	};
#define FIELD(name, offset, bytes, max) \
	{ offsetof(struct sparklink_discovery_adv_params, name), offset, bytes, max }
	static const struct field fields[] = {
		FIELD(handle, 0, 1, 0xef), FIELD(mode, 1, 1, 0xff),
		FIELD(gt_role, 2, 1, 0xff), FIELD(interval_min, 3, 3, 0xffffff),
		FIELD(interval_max, 6, 3, 0xffffff), FIELD(channel_map, 9, 1, 0xff),
		FIELD(own_address_type, 10, 1, 0xff), FIELD(peer_address_type, 11, 1, 0xff),
		FIELD(filter, 24, 1, 0xff), FIELD(primary_frame, 26, 1, 0xff),
		FIELD(secondary_frame, 27, 1, 0xff), FIELD(secondary_phy, 28, 1, 0xff),
		FIELD(secondary_pilot, 29, 1, 0xff), FIELD(secondary_mcs, 30, 1, 0xff),
		FIELD(secondary_max_skip, 31, 1, 0xff), FIELD(sid, 32, 1, 0xff),
		FIELD(request_notification, 33, 1, 0xff), FIELD(max_requests, 34, 1, 0xff),
		FIELD(request_rx_duration, 35, 2, 0xffff),
		FIELD(conn_interval_min, 37, 2, 0xffff), FIELD(conn_interval_max, 39, 2, 0xffff),
		FIELD(conn_max_latency, 41, 2, 0xffff), FIELD(supervision_timeout, 43, 2, 0xffff),
		FIELD(min_event_length, 45, 2, 0xffff), FIELD(max_event_length, 47, 2, 0xffff),
	};
#undef FIELD
	unsigned char out[64], before[64], vector[49], wire[128];
	struct sparklink_discovery_adv_params candidate;
	unsigned int slots;

	memset(out, 0xa5, sizeof(out));
	memcpy(before, out, sizeof(out));
	CHECK(ws73_discovery_adv_params(out, sizeof(out), &params) == 49);
	CHECK(!memcmp(out, expected, 49) && !memcmp(out + 49, before + 49, 15));
	CHECK(ws73_discovery_validate_command(0x0c02, out, 49) == 0);
	CHECK(ws73_wire_command(wire, sizeof(wire), 0x1234, 0x0c02, out, 49) == 128);
	CHECK(!memcmp(wire + 68, "\xa1\x02\x0c\x31\x00", 5));
	CHECK(!memcmp(wire + 73, expected, 49));
	for (unsigned int i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
		const struct field *field = fields + i;
		unsigned int values[] = { 0, 1, 0xff, 0x100, 0x1234, 0x123456,
			field->max, field->max + 1, UINT_MAX };

		for (unsigned int j = 0; j < sizeof(values) / sizeof(values[0]); j++) {
			unsigned int value = values[j];

			candidate = params;
			/* Real unsigned-int member, aligned by offsetof. */
			*(unsigned int *)((unsigned char *)&candidate + field->host_offset) = value;
			memset(out, 0xa5, sizeof(out));
			if (value > field->max) {
				CHECK(ws73_discovery_adv_params(out, sizeof(out), &candidate) == -EINVAL);
				CHECK(!memcmp(out, before, sizeof(out)));
				continue;
			}
			memcpy(vector, expected, sizeof(vector));
			for (unsigned int k = 0; k < field->bytes; k++)
				vector[field->wire_offset + k] = value >> (8 * k);
			CHECK(ws73_discovery_adv_params(out, sizeof(out), &candidate) == 49);
			CHECK(!memcmp(out, vector, 49) && !memcmp(out + 49, before + 49, 15));
		}
	}
	for (int power = -128; power <= 127; power++) {
		candidate = params;
		candidate.tx_power = power;
		memcpy(vector, expected, sizeof(vector));
		vector[25] = (unsigned char)power;
		CHECK(ws73_discovery_adv_params(out, sizeof(out), &candidate) == 49);
		CHECK(!memcmp(out, vector, 49));
	}
	for (unsigned int capacity = 0; capacity < 49; capacity++) {
		memset(out, 0xa5, sizeof(out));
		CHECK(ws73_discovery_adv_params(out, capacity, &params) == -EMSGSIZE);
		CHECK(!memcmp(out, before, sizeof(out)));
	}
	candidate = params;
	candidate.tx_power = -129;
	CHECK(ws73_discovery_adv_params(out, sizeof(out), &candidate) == -EINVAL);
	candidate.tx_power = 128;
	CHECK(ws73_discovery_adv_params(out, sizeof(out), &candidate) == -EINVAL);
	candidate.tx_power = INT_MIN;
	CHECK(ws73_discovery_adv_params(out, sizeof(out), &candidate) == -EINVAL);
	candidate.tx_power = INT_MAX;
	CHECK(ws73_discovery_adv_params(out, sizeof(out), &candidate) == -EINVAL);
	CHECK(ws73_discovery_adv_params(out, sizeof(out), NULL) == -EINVAL);
	CHECK(ws73_discovery_adv_params(NULL, sizeof(out), &params) == -EINVAL);
	CHECK(!memcmp(out, before, sizeof(out)));
	/* No implicit board, role, address, power or interval defaults. */
	memset(&candidate, 0, sizeof(candidate));
	memset(vector, 0, sizeof(vector));
	CHECK(ws73_discovery_adv_params(out, sizeof(out), &candidate) == 49);
	CHECK(!memcmp(out, vector, sizeof(vector)));
	for (unsigned int ms = 1; ms <= 8191; ms++) {
		CHECK(ws73_discovery_ms_slots(ms, 16, &slots) == 0 && slots == ms * 8);
	}
	CHECK(ws73_discovery_ms_slots(2097151, 24, &slots) == 0 && slots == 0xfffff8);
	CHECK(ws73_discovery_ms_slots(8192, 16, &slots) == -ERANGE && slots == 0xfffff8);
	CHECK(ws73_discovery_ms_slots(2097152, 24, &slots) == -ERANGE && slots == 0xfffff8);
	CHECK(ws73_discovery_ms_slots(ULLONG_MAX, 24, &slots) == -ERANGE && slots == 0xfffff8);
	CHECK(ws73_discovery_ms_slots(0, 24, &slots) == -EINVAL && slots == 0xfffff8);
	CHECK(ws73_discovery_ms_slots(1, 32, &slots) == -EINVAL && slots == 0xfffff8);
	CHECK(ws73_discovery_ms_slots(1, UINT_MAX, &slots) == -EINVAL && slots == 0xfffff8);
	CHECK(ws73_discovery_ms_slots(1, 16, NULL) == -EINVAL);
}

static void data_tests(void)
{
	/* Opaque marker starts at byte three, not behind a selection byte.
	 * This test makes no claim about its outer/inner application TLV format.
	 */
	static const unsigned char marker[] = { 5, 9, 'W', 'S', '7', '3' };
	static const unsigned char expected[] = { 0, 3, 6, 5, 9, 'W', 'S', '7', '3' };
	static const unsigned char standard[] = { 0, 3, 0, 6, 5, 9, 'W', 'S', '7', '3' };
	unsigned char out[254], payload[252], wire[328], before[254];

	CHECK(ws73_discovery_data(out, sizeof(out), 0, marker, sizeof(marker)) == sizeof(expected));
	CHECK(!memcmp(out, expected, sizeof(expected)));
	CHECK(ws73_discovery_validate_command(0x0c03, out, sizeof(expected)) == 0);
	CHECK(ws73_discovery_validate_command(0x0c03, standard, sizeof(standard)) == -EINVAL);
	for (unsigned int i = 0; i < sizeof(payload); i++)
		payload[i] = i;
	for (unsigned int length = 0; length <= 251; length++) {
		unsigned int size = length + 3;
		int total;

		CHECK(ws73_discovery_data(out, sizeof(out), 0xef, payload, length) == (int)size);
		CHECK(out[0] == 0xef && out[1] == 3 && out[2] == length);
		CHECK(!memcmp(out + 3, payload, length));
		CHECK(ws73_discovery_validate_command(0x0c03, out, size) == 0);
		CHECK(ws73_discovery_validate_command(0x0c04, out, size) == 0);
		total = ws73_wire_command(wire, sizeof(wire), 0x1234, 0x0c03, out, size);
		CHECK(total == (int)(64 + (size + 9 < 64 ? 64 : size + 9)));
		CHECK(wire[68] == 0xa1 && wire[69] == 3 && wire[70] == 0x0c);
		CHECK(wire[71] == size && wire[72] == 0 && !memcmp(wire + 73, out, size));
		CHECK(ws73_discovery_validate_command(0x0c03, out, size - 1) == -EINVAL);
		CHECK(ws73_discovery_validate_command(0x0c03, out, size + 1) == -EINVAL);
		memset(out, 0xa5, sizeof(out));
		memcpy(before, out, sizeof(out));
		CHECK(ws73_discovery_data(out, size - 1, 0, payload, length) == -EMSGSIZE);
		CHECK(!memcmp(out, before, sizeof(out)));
	}
	CHECK(ws73_discovery_data(out, sizeof(out), 0, payload, 252) == -EMSGSIZE);
	CHECK(ws73_discovery_data(out, sizeof(out), 0, payload, (size_t)-1) == -EMSGSIZE);
	CHECK(ws73_discovery_data(out, sizeof(out), 0x100, payload, 1) == -EINVAL);
	CHECK(ws73_discovery_data(out, sizeof(out), 0, NULL, 1) == -EINVAL);
	CHECK(ws73_discovery_data(NULL, sizeof(out), 0, NULL, 0) == -EINVAL);
	CHECK(!memcmp(out, before, sizeof(out)));
	CHECK(ws73_discovery_data(out, sizeof(out), 0, NULL, 0) == 3);
	CHECK(!memcmp(out, "\x00\x03\x00", 3));
	out[1] = 2;
	CHECK(ws73_discovery_validate_command(0x0c03, out, 3) == -EOPNOTSUPP);
}

static void control_tests(void)
{
	unsigned char out[49], before[49];
	static const unsigned char scan[] = { 0x06, 0, 1, 0, 0xb0, 4, 0x58, 2 };

	CHECK(ws73_discovery_scan_params(out, sizeof(out), 6, 0, 1, 0, 0x4b0, 0x258) == 8);
	CHECK(!memcmp(out, scan, sizeof(scan)));
	CHECK(ws73_discovery_validate_command(0x1001, out, 8) == 0);
	CHECK(ws73_discovery_adv_enable(out, sizeof(out), 1, 0, 0x1234, 7) == 5);
	CHECK(!memcmp(out, "\x01\x00\x34\x12\x07", 5));
	CHECK(ws73_discovery_validate_command(0x0c05, out, 5) == 0);
	CHECK(ws73_discovery_adv_enable(out, sizeof(out), 0, 0, 0, 0) == 5);
	CHECK(!memcmp(out, "\x00\x00\x00\x00\x00", 5));
	CHECK(ws73_discovery_scan_enable(out, sizeof(out), 1, 0) == 2);
	CHECK(!memcmp(out, "\x01\x00", 2));
	CHECK(ws73_discovery_validate_command(0x1002, out, 2) == 0);
	memset(out, 0xa5, sizeof(out));
	memcpy(before, out, sizeof(out));
	for (unsigned int capacity = 0; capacity < 8; capacity++) {
		CHECK(ws73_discovery_scan_params(out, capacity, 0, 0, 1, 0, 1, 1) == -EMSGSIZE);
		CHECK(!memcmp(out, before, sizeof(out)));
	}
	for (unsigned int frames = 0; frames < 128; frames++) {
		if (frames == 1)
			continue;
		CHECK(ws73_discovery_scan_params(out, sizeof(out), 0, 0, frames, 0, 1, 1) == -EOPNOTSUPP);
		CHECK(!memcmp(out, before, sizeof(out)));
	}
	CHECK(ws73_discovery_scan_params(out, sizeof(out), 0, 0, 1, 0, 0, 0) == -EINVAL);
	CHECK(ws73_discovery_scan_params(out, sizeof(out), 0, 0, 1, 0, 1, 2) == -EINVAL);
	CHECK(ws73_discovery_scan_params(out, sizeof(out), 0, 0, 1, 0, 65536, 1) == -EINVAL);
	CHECK(ws73_discovery_scan_params(out, sizeof(out), 256, 0, 1, 0, 1, 1) == -EINVAL);
	CHECK(ws73_discovery_adv_enable(out, 4, 1, 0, 0, 0) == -EMSGSIZE);
	CHECK(ws73_discovery_adv_enable(out, sizeof(out), 2, 0, 0, 0) == -EINVAL);
	CHECK(ws73_discovery_adv_enable(out, sizeof(out), 1, 0xf0, 0, 0) == -EINVAL);
	CHECK(ws73_discovery_adv_enable(out, sizeof(out), 1, 0, 65536, 0) == -EINVAL);
	CHECK(ws73_discovery_adv_enable(out, sizeof(out), 1, 0, 0, UINT_MAX) == -EINVAL);
	CHECK(ws73_discovery_scan_enable(out, 1, 1, 0) == -EMSGSIZE);
	CHECK(ws73_discovery_scan_enable(out, sizeof(out), 1, 2) == -EINVAL);
	CHECK(!memcmp(out, before, sizeof(out)));
	CHECK(ws73_discovery_validate_command(0x0c02, out, 48) == -EINVAL);
	CHECK(ws73_discovery_validate_command(0x0c02, out, 49) == 0); /* framing only */
	out[0] = 0xf0;
	CHECK(ws73_discovery_validate_command(0x0c02, out, 49) == -EINVAL);
	CHECK(ws73_discovery_validate_command(0x0c02, NULL, 49) == -EINVAL);
	CHECK(ws73_discovery_validate_command(0x0401, NULL, 0) == -EOPNOTSUPP);
	CHECK(ws73_discovery_validate_command(0x1001, scan, 7) == -EINVAL);
	CHECK(ws73_discovery_validate_command(0x1002, (const unsigned char *)"\x01", 1) == -EINVAL);
	CHECK(ws73_discovery_validate_command(0x0c05, (const unsigned char *)"\x01", 1) == -EINVAL);
	CHECK(ws73_discovery_validate_command(0x1002, (const unsigned char *)"\x02\x00", 2) == -EINVAL);
}

static void report_tests(void)
{
	/* Distinct address types, direct address, PHY bytes, vendor byte, -42dBm. */
	unsigned char params[279] = {
		0x12, 0x06, 0x02, 0x73, 1, 2, 3, 4, 0x04,
		9, 8, 7, 6, 5, 4, 1, 2, 3, 0x44, 0x55, 0xa7, 0xd6, 6,
		5, 9, 'W', 'S', '7', '3',
	};
	struct ws73_discovery_report report, before;

	CHECK(ws73_discovery_report_decode(params, 29, &report) == 0);
	CHECK(report.header == params && report.data == params + 23);
	CHECK(report.header[1] == 6 && report.header[8] == 4 && report.header[20] == 0xa7);
	CHECK(!memcmp(report.header + 2, "\x02\x73\x01\x02\x03\x04", 6));
	CHECK(!memcmp(report.header + 9, "\x09\x08\x07\x06\x05\x04", 6));
	CHECK(report.rssi == -42 && report.data_size == 6);
	CHECK(!memcmp(report.data, "\x05\x09WS73", 6));
	for (unsigned int length = 0; length < 256; length++) {
		params[22] = length;
		for (unsigned int i = 0; i < length; i++)
			params[23 + i] = i;
		CHECK(ws73_discovery_report_decode(params, 23 + length, &report) == 0);
		CHECK(report.data_size == length && report.data == params + 23);
		CHECK(!memcmp(report.header, params, 23));
		for (unsigned int i = 0; i < length; i++)
			CHECK(report.data[i] == i);
		before = report;
		CHECK(ws73_discovery_report_decode(params, 22 + length, &report) == -EPROTO);
		CHECK(!memcmp(&report, &before, sizeof(report)));
		CHECK(ws73_discovery_report_decode(params, 24 + length, &report) == -EPROTO);
		CHECK(!memcmp(&report, &before, sizeof(report)));
	}
	for (unsigned int byte = 0; byte < 256; byte++) {
		params[21] = byte;
		CHECK(ws73_discovery_report_decode(params, 278, &report) == 0);
		CHECK(report.rssi == (byte < 128 ? (int)byte : (int)byte - 256));
	}
	before = report;
	CHECK(ws73_discovery_report_decode(NULL, 278, &report) == -EINVAL);
	CHECK(ws73_discovery_report_decode(params, 278, NULL) == -EINVAL);
	CHECK(ws73_discovery_report_decode(params, (size_t)-1, &report) == -EPROTO);
	CHECK(!memcmp(&report, &before, sizeof(report)));
}

static void recipe_tests(void)
{
	struct sparklink_discovery_adv_params adv = {
		.handle = 7,
		.interval_min = 800,
		.interval_max = 800,
		.tx_power = -42,
		.own_address_type = 6,
		.peer_address_type = 4,
		.own_address = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15 },
		.peer_address = { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25 },
		.request_notification = 8,
		.max_requests = 9,
	};
	struct sparklink_discovery_scan_params scan = {
		.own_address_type = 6,
		.filter = 3,
		.frame_types = 1,
		.active = 1,
		.interval = 0x1234,
		.window = 0x567,
		.filter_duplicates = 1,
	};
	static const unsigned char scan_expected[] = { 6,    3,	   1,	 1,
						       0x34, 0x12, 0x67, 5 };
	static const unsigned char adv_enable_expected[] = { 1, 7, 0x34, 0x12,
							     0x56 };
	unsigned char data[252], response[252];
	struct sparklink_discovery_request request = {
		.operation = SPARKLINK_DISCOVERY_ADV_START,
		.advertising = &adv,
		.handle = 7,
		.duration = 0x1234,
		.max_events = 0x56,
		.data = data,
	};
	struct sparklink_discovery_plan plan, before;
	struct sparklink_discovery_request candidate;

	for (unsigned int i = 0; i < sizeof(data); i++) {
		data[i] = i;
		response[i] = 255 - i;
	}
	/* Full length range, optional empty or full response, exact sequence shape,
  * no standard data-selection byte, and cleared unused bytes/steps.
  */
	for (unsigned int len = 0; len <= 251; len++) {
		for (unsigned int present = 0; present <= 1; present++) {
			request.data_size = len;
			request.scan_response_present = present;
			request.scan_response = present ? response : NULL;
			request.scan_response_size = present ? 251 - len : 0;
			memset(&plan, 0xa5, sizeof(plan));
			CHECK(ws73_discovery_prepare(&request, &plan) == 0);
			CHECK(plan.operation == 1 &&
			      plan.count == (present ? 4U : 3U));
			CHECK(plan.steps[0].opcode == 0x0c02 &&
			      plan.steps[0].length == 49);
			CHECK(plan.steps[0].params[0] == 7 &&
			      plan.steps[0].params[25] == 0xd6);
			CHECK(plan.steps[0].params[10] == 6 &&
			      plan.steps[0].params[11] == 4);
			CHECK(!memcmp(plan.steps[0].params + 12,
				      adv.own_address, 6));
			CHECK(!memcmp(plan.steps[0].params + 18,
				      adv.peer_address, 6));
			CHECK(plan.steps[0].params[33] == 8 &&
			      plan.steps[0].params[34] == 9);
			CHECK(plan.steps[1].opcode == 0x0c03 &&
			      plan.steps[1].length == len + 3);
			CHECK(plan.steps[1].params[0] == 7 &&
			      plan.steps[1].params[1] == 3 &&
			      plan.steps[1].params[2] == len);
			CHECK(!memcmp(plan.steps[1].params + 3, data, len));
			if (present) {
				CHECK(plan.steps[2].opcode == 0x0c04 &&
				      plan.steps[2].length == 254 - len);
				CHECK(plan.steps[2].params[0] == 7 &&
				      plan.steps[2].params[1] == 3 &&
				      plan.steps[2].params[2] == 251 - len);
				CHECK(!memcmp(plan.steps[2].params + 3,
					      response, 251 - len));
			}
			CHECK(plan.steps[plan.count - 1].opcode == 0x0c05);
			CHECK(plan.steps[plan.count - 1].length == 5 &&
			      !memcmp(plan.steps[plan.count - 1].params,
				      adv_enable_expected, 5));
			for (unsigned int i = 0; i < 4; i++) {
				struct sparklink_discovery_step *part =
					&plan.steps[i];
				for (unsigned int j = part->length; j < 255;
				     j++)
					CHECK(part->params[j] == 0);
				if (i < plan.count) {
					CHECK(ws73_discovery_validate_step(
						      plan.operation, i,
						      plan.count, part->opcode,
						      part->params,
						      part->length) == 0);
					/* Preparation never broadens the raw metadata whitelist. */
					CHECK(ws73_dli_validate_command(
						      part->opcode,
						      part->params,
						      part->length) ==
					      -EOPNOTSUPP);
				} else {
					CHECK(!part->opcode && !part->length);
				}
			}
		}
	}
	/* Failure at any later encoder must leave the entire output unchanged. */
	memset(&plan, 0xa5, sizeof(plan));
	before = plan;
	request.data_size = 1;
	request.scan_response_present = 1;
	request.scan_response = response;
	request.scan_response_size = 1;
#define BAD(field, value)                                             \
	do {                                                          \
		candidate = request;                                  \
		candidate.field = (value);                            \
		CHECK(ws73_discovery_prepare(&candidate, &plan) < 0); \
		CHECK(!memcmp(&plan, &before, sizeof(plan)));         \
	} while (0)
	BAD(advertising, NULL);
	BAD(scanning, &scan);
	BAD(handle, 8);
	BAD(data, NULL);
	BAD(data_size, 252);
	BAD(data_size, UINT_MAX);
	BAD(scan_response, NULL);
	BAD(scan_response_size, 252);
	BAD(scan_response_size, UINT_MAX);
	BAD(scan_response_present, 2);
	BAD(duration, 0x10000);
	BAD(max_events, 0x100);
	BAD(operation, 0);
	BAD(operation, UINT_MAX);
#undef BAD
	adv.interval_min = 0x1000000;
	CHECK(ws73_discovery_prepare(&request, &plan) == -EINVAL);
	CHECK(!memcmp(&plan, &before, sizeof(plan)));
	adv.interval_min = 800;
	CHECK(ws73_discovery_prepare(NULL, &plan) == -EINVAL);
	CHECK(ws73_discovery_prepare(&request, NULL) == -EINVAL);
	CHECK(!memcmp(&plan, &before, sizeof(plan)));

	request = (struct sparklink_discovery_request){
		.operation = SPARKLINK_DISCOVERY_SCAN_START,
		.scanning = &scan,
	};
	CHECK(ws73_discovery_prepare(&request, &plan) == 0);
	CHECK(plan.power_step == plan.count);
	CHECK(plan.count == 2 && plan.steps[0].opcode == 0x1001 &&
	      plan.steps[0].length == 8);
	CHECK(!memcmp(plan.steps[0].params, scan_expected,
		      sizeof(scan_expected)));
	CHECK(plan.steps[1].opcode == 0x1002 && plan.steps[1].length == 2 &&
	      plan.steps[1].params[0] == 1 && plan.steps[1].params[1] == 1);
	before = plan;
	scan.filter_duplicates = 2;
	CHECK(ws73_discovery_prepare(&request, &plan) == -EINVAL);
	CHECK(!memcmp(&plan, &before, sizeof(plan)));
	scan.filter_duplicates = 1;
	scan.frame_types = 3;
	CHECK(ws73_discovery_prepare(&request, &plan) == -EOPNOTSUPP);
	CHECK(!memcmp(&plan, &before, sizeof(plan)));
	scan.frame_types = 1;
	request.operation = SPARKLINK_DISCOVERY_ADV_STOP;
	request.scanning = NULL;
	request.handle = 7;
	CHECK(ws73_discovery_prepare(&request, &plan) == 0);
	CHECK(plan.count == 1 && plan.steps[0].opcode == 0x0c05 &&
	      plan.steps[0].length == 5);
	CHECK(plan.steps[0].params[0] == 0 && plan.steps[0].params[1] == 7 &&
	      !plan.steps[0].params[2] && !plan.steps[0].params[3] &&
	      !plan.steps[0].params[4]);
	request.operation = SPARKLINK_DISCOVERY_SCAN_STOP;
	request.handle = 0;
	CHECK(ws73_discovery_prepare(&request, &plan) == 0);
	CHECK(plan.count == 1 && plan.steps[0].opcode == 0x1002 &&
	      plan.steps[0].length == 2);
	CHECK(!plan.steps[0].params[0] && !plan.steps[0].params[1]);

	/* Exhaust sequence positions/counts and wrong action/enable combinations.
  * Only the complete plan's own positions are authorized by this validator.
  */
	for (unsigned int op = 1; op <= 5; op++) {
		request =
			(struct sparklink_discovery_request){ .operation = op };
		if (op == 1 || op == 5) {
			request.advertising = &adv;
			request.handle = 7;
		}
		if (op == 2)
			request.handle = 7;
		if (op == 3)
			request.scanning = &scan;
		CHECK(ws73_discovery_prepare(&request, &plan) == 0);
		for (unsigned int i = 0; i < plan.count; i++) {
			struct sparklink_discovery_step *part = &plan.steps[i];
			CHECK(ws73_discovery_validate_step(
				      op, i, plan.count, part->opcode,
				      part->params, part->length) == 0);
			for (unsigned int count = 0; count <= 8; count++)
				for (unsigned int step = 0; step <= 8; step++) {
					/* ADV_START permits both 3/4 shapes; two common leading positions
      * can be valid in either shape, enable's terminal position changes.
      */
					int valid = count == plan.count &&
						    step == i;
					if (op == 1 && count == 4)
						valid = i < 2 ? step == i :
								step == 3;
					CHECK((ws73_discovery_validate_step(
						       op, step, count,
						       part->opcode,
						       part->params,
						       part->length) == 0) ==
					      valid);
				}
			CHECK(ws73_discovery_validate_step(
				      op, i, plan.count, 0x0401, part->params,
				      part->length) == -EINVAL);
			CHECK(ws73_discovery_validate_step(
				      op, i, plan.count, part->opcode,
				      part->params, part->length + 1) < 0);
			CHECK(ws73_discovery_validate_step(op, i, plan.count,
							   part->opcode, NULL,
							   part->length) < 0);
		}
		struct sparklink_discovery_step *last =
			&plan.steps[plan.count - 1];
		for (unsigned int enable = 0; enable < 256; enable++) {
			last->params[0] = enable;
			CHECK((ws73_discovery_validate_step(
				       op, plan.count - 1, plan.count,
				       last->opcode, last->params,
				       last->length) == 0) ==
			      (enable == (op == 1 || op == 3)));
		}
	}
	request = (struct sparklink_discovery_request){
		.operation = SPARKLINK_DISCOVERY_ADV_CONFIGURE_OFF,
		.advertising = &adv, .handle = 7,
	};
	CHECK(ws73_discovery_prepare(&request, &plan) == 0);
	CHECK(plan.count == 2 && plan.power_step == 0 &&
	      plan.steps[0].opcode == 0x0c02 && plan.steps[1].opcode == 0x0c05 &&
	      plan.steps[1].params[0] == 0);
	before = plan;
	for (unsigned int field = 0; field < 7; field++) {
		candidate = request;
		switch (field) {
		case 0: candidate.data = data; break;
		case 1: candidate.data_size = 1; break;
		case 2: candidate.duration = 1; break;
		case 3: candidate.max_events = 1; break;
		case 4: candidate.scan_response_present = 1; break;
		case 5: candidate.scanning = &scan; break;
		case 6: candidate.handle = 8; break;
		}
		CHECK(ws73_discovery_prepare(&candidate, &plan) < 0);
		CHECK(!memcmp(&plan, &before, sizeof(plan)));
	}
	/* Reject irrelevant input without changing a prior complete output. */
	for (unsigned int op = 2; op <= 4; op++) {
		request =
			(struct sparklink_discovery_request){ .operation = op };
		if (op == 2)
			request.handle = 7;
		if (op == 3)
			request.scanning = &scan;
		CHECK(ws73_discovery_prepare(&request, &plan) == 0);
		before = plan;
#define UNUSED(field, value)                                          \
	do {                                                          \
		candidate = request;                                  \
		candidate.field = (value);                            \
		CHECK(ws73_discovery_prepare(&candidate, &plan) < 0); \
		CHECK(!memcmp(&plan, &before, sizeof(plan)));         \
	} while (0)
		UNUSED(advertising, &adv);
		UNUSED(data, data);
		UNUSED(data_size, 1);
		UNUSED(scan_response, response);
		UNUSED(scan_response_size, 1);
		UNUSED(scan_response_present, 1);
		UNUSED(duration, 1);
		UNUSED(max_events, 1);
		if (op != 2) {
			UNUSED(handle, 1);
		}
		if (op != 3) {
			UNUSED(scanning, &scan);
		}
#undef UNUSED
	}
	CHECK(ws73_discovery_validate_step(0, 0, 1, 0x1002, data, 2) ==
	      -EOPNOTSUPP);
}

int main(void)
{
	adv_params_tests();
	data_tests();
	control_tests();
	report_tests();
	recipe_tests();
	printf("WS73_DISCOVERY_CODEC_TEST: %s (%u checks, %u failures; synthetic only)\n",
	       failures ? "FAIL" : "PASS", checks, failures);
	return failures ? 1 : 0;
}
