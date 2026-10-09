// SPDX-License-Identifier: GPL-2.0-only
/* Production WS73 profile codecs. Synthetic vectors; no RF/Ready claim. */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "../../../../drivers/sparklink/ws73/discovery.h"

static unsigned int checks, failures;
#define CHECK(condition) do { checks++; if (!(condition)) { \
	failures++; fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
} } while (0)

static void data_tests(void)
{
	/* A named TLV must start at byte three, not behind a selection byte. */
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

int main(void)
{
	data_tests();
	control_tests();
	report_tests();
	printf("WS73_DISCOVERY_CODEC_TEST: %s (%u checks, %u failures; synthetic only)\n",
	       failures ? "FAIL" : "PASS", checks, failures);
	return failures ? 1 : 0;
}
