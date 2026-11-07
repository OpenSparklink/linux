// SPDX-License-Identifier: GPL-2.0-only
/* Actual production codec, not USB, firmware, locks or lifetime validation.
 * cbmc ws73_sle_efuse_cbmc.c --unwind 161 --unwinding-assertions
 *      --bounds-check --pointer-check --signed-overflow-check
 *      --unsigned-overflow-check --trace
 * Packet bytes/length and output capacity/sequence are unconstrained within
 * the allocated objects below. No dependency is stubbed to succeed.
 */
#include <assert.h>
#include "../../../../drivers/sparklink/ws73/wire.c"

extern unsigned int nondet_uint(void);
extern unsigned char nondet_byte(void);

int main(void)
{
	unsigned char packet[32], request[160];
	unsigned int size = nondet_uint(), capacity = nondet_uint();
	struct ws73_sle_efuse_info info, before;
	int ret;

	__CPROVER_assume(size <= sizeof(packet));
	__CPROVER_assume(capacity <= sizeof(request));
	for (unsigned int i = 0; i < sizeof(packet); i++)
		packet[i] = nondet_byte();
	memset(&info, 0x77, sizeof(info));
	before = info;
	ret = ws73_wire_sle_efuse_reply(packet, size, &info);
	if (ret)
		assert(!memcmp(&info, &before, sizeof(info)));
	else {
		assert(size >= 12 && (info.size == 6 || (info.status && !info.size)));
		for (unsigned int i = 0; i < sizeof(info.address); i++)
			assert(info.status ? !info.address[i] : info.address[i] == packet[12 + i]);
	}
	memset(request, 0x77, sizeof(request));
	ret = ws73_wire_sle_efuse_request(request, capacity, nondet_uint());
	assert(ret == (capacity < 128 ? -EINVAL : 128));
	for (unsigned int i = capacity < 128 ? 0 : 128; i < sizeof(request); i++)
		assert(request[i] == 0x77);
	if (capacity >= 128) {
		assert(request[68] == 11 && request[69] == 0);
		assert(request[70] == 2 && request[71] == 0);
		assert(request[72] == 125 && request[73] == 6);
	}
	return 0;
}
