// SPDX-License-Identifier: GPL-2.0-only
/* Actual production key map and authorization; no socket/RF claim. */
#include <assert.h>
#include <stdio.h>
#include "../../../../net/sparklink/sle_channel_table.h"
#include "../../../../net/sparklink/sle_channel_grant.h"
int main(void)
{
	unsigned int local, remote, pi;
	struct sl_grant_scope user = { .controller = 3, .handle = 0,
		.generation = 7, .lifetime = 9, .epoch = 11,
		.local_tcid = 31, .remote_tcid = 31, .pi = 241 };
	struct sl_grant_scope ssap = user;
	struct sl_channel_grant grant;
	ssap.local_tcid = ssap.remote_tcid = SL_CHANNEL_SMTC;
	ssap.pi = 0;
	assert(sl_grant_init(&grant, user, SL_GRANT_TX | SL_GRANT_RX, 0));
	assert(sl_grant_permits(&grant, user, SL_GRANT_TX));
	assert(!sl_grant_permits(&grant, ssap, SL_GRANT_TX));
	assert(sl_grant_init(&grant, ssap, SL_GRANT_TX | SL_GRANT_RX, 0));
	assert(sl_grant_permits(&grant, ssap, SL_GRANT_RX));
	assert(!sl_grant_permits(&grant, user, SL_GRANT_RX));
	for (local = 0; local < 256; local++)
		for (remote = 0; remote < 256; remote++)
			for (pi = 0; pi < 256; pi++) {
				int expected = local == 31 && remote == 31 && pi == 241 ? 0 :
					local == 10 && remote == 10 && pi == 0 ? 1 : -1;
				assert(sl_channel_key_slot(local, remote, pi) == expected);
				if (local == remote)
					assert(sl_channel_rx_slot(local, pi) == expected);
			}
	puts("FIXED_CHANNEL_TABLE_PASS: keys=16777216 slots=2 cross_grant_rejected=2 no_rf=1");
	return 0;
}
