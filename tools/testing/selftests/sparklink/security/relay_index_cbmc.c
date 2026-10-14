// SPDX-License-Identifier: GPL-2.0-only
/* Actual SDK111 codec, not an independent normalization implementation. */
#include <assert.h>
#include "../../../../../drivers/sparklink/ws73/dli.c"
extern unsigned int nondet_uint(void);
extern unsigned char nondet_byte(void);
int main(void)
{
	unsigned char packet[265], normalized[11], params[255], payload[255];
	unsigned int length = nondet_uint(), handle = nondet_uint(), index = nondet_uint();
	unsigned int size = nondet_uint(), capacity = nondet_uint();
	unsigned short opcode = 0xaaaa, echo = 0xbbbb;
	__CPROVER_assume(length <= sizeof(packet) && handle <= 65535 && index <= 65535);
	__CPROVER_assume(size <= sizeof(payload) && capacity <= sizeof(params));
	for (unsigned int i = 0; i < sizeof(packet); i++) packet[i] = nondet_byte();
	for (unsigned int i = 0; i < sizeof(normalized); i++) normalized[i] = 0xcc;
	for (unsigned int i = 0; i < sizeof(params); i++) { params[i] = 0xcc; payload[i] = nondet_byte(); }
	int result = ws73_dli_relay_normalize_rx(packet, length, normalized, sizeof(normalized));
	if (result > 0) {
		assert(result == 11 && length == 11);
		assert(packet[7] == 0xff && packet[8] == 1);
		assert(normalized[7] == 0x47 && normalized[8] == 1);
		for (unsigned int i = 0; i < sizeof(normalized); i++)
			if (i != 7 && i != 8) assert(normalized[i] == packet[i]);
	} else {
		for (unsigned int i = 0; i < sizeof(normalized); i++) assert(normalized[i] == 0xcc);
	}
	result = ws73_dli_relay_prepare(handle, index, payload, size, &opcode, params, capacity, &echo);
	if (result >= 0) {
		assert(result == size + 5 && size <= 250 && capacity >= size + 5);
		assert(opcode == 0x1812 && dli_u16(params) == handle);
		assert(echo == (index == 0x0147 ? 0x01ff : index));
		assert(dli_u16(params + 2) == echo && params[4] == size);
		for (unsigned int i = 0; i < size; i++) assert(params[5 + i] == payload[i]);
	} else {
		assert(opcode == 0xaaaa && echo == 0xbbbb);
		for (unsigned int i = 0; i < sizeof(params); i++) assert(params[i] == 0xcc);
	}
	return 0;
}
