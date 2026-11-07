// SPDX-License-Identifier: GPL-2.0-only
/* Verify the actual production codec, not a second parser implementation.
 * Scope: one bounded, fully allocated packet; no USB/lifetime/security proof.
 */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "../../../../../drivers/sparklink/ws73/dli.c"

extern unsigned int nondet_uint(void);
extern unsigned char nondet_byte(void);

int main(void)
{
	unsigned int size = nondet_uint();
	unsigned char *data;
	unsigned int event, params;
	int ret;

	__CPROVER_assume(size <= 265); /* 5 outer + 5 relay + 255 payload */
	data = malloc(size ? size : 1);
	if (!data)
		return 0; /* Allocation failure is not assumed away. */
	for (unsigned int i = 0; i < size; i++)
		data[i] = nondet_byte();
	assert(ws73_dli_validate_security_event(NULL, size) == -EINVAL);
	ret = ws73_dli_validate_security_event(data, size);
	if (size < 3 || data[0] != 0xa2) {
		assert(ret == -ENOMSG);
	} else {
		event = (unsigned int)data[1] | (unsigned int)data[2] << 8;
		if (event != 0x0014 && event != 0x000e && event != 0x0011) {
			assert(ret == -ENOMSG);
		} else if (size < 5) {
			assert(ret == -EPROTO);
		} else {
			params = (unsigned int)data[3] | (unsigned int)data[4] << 8;
			if (params != size - 5) {
				assert(ret == -EPROTO);
			} else if (event == 0x0014) {
				if (params < 5)
					assert(ret == -EPROTO);
				else
					assert((ret == 0) == (params - 5 == data[9]));
			} else {
				assert((ret == 0) == (params == (event == 0x000e ? 2 : 4)));
			}
		}
	}
	free(data);
	return 0;
}
