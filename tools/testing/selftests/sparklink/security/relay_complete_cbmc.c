// SPDX-License-Identifier: GPL-2.0-only
/* Real SDK111 counterexample regression against the production validator.
 * Bounded packet memory/shape only; no Host, USB, lifetime or firmware proof. */
#include <assert.h>
#include "../../../../../drivers/sparklink/ws73/dli.c"
extern unsigned int nondet_uint(void);
extern unsigned char nondet_byte(void);
int main(void)
{
	unsigned char packet[265];
	unsigned int length = nondet_uint();
	__CPROVER_assume(length <= sizeof(packet));
	for (unsigned int i = 0; i < sizeof(packet); i++)
		packet[i] = nondet_byte();
	assert(ws73_dli_validate_reply(NULL, length) == -EINVAL);
	int result = ws73_dli_validate_reply(packet, length);
	/* Constrain only the property selector, never a dependency to succeed.
	 * Every byte, length, status and opcode is otherwise arbitrary, and the
	 * production function also executes all its other packet branches. */
	if (length >= 9 && packet[0] == 0xa2 && packet[1] == 2 &&
	    packet[2] == 0 && packet[5] == 0x12 && packet[6] == 0x18 &&
	    packet[8] == 0) {
		if (result == 0) {
			assert(length == 13);
			assert(packet[3] == 8 && packet[4] == 0);
			assert(packet[10] < 16);
		}
		if (length == 13 && packet[3] == 8 && packet[4] == 0 && packet[10] < 16)
			assert(result == 0);
	}
	return 0;
}
