// SPDX-License-Identifier: GPL-2.0-only
/* Actual production helpers, symbolic wire bytes and advertised length.
 * No filesystem, hash implementation, kernel locks or firmware are modeled.
 * Directory formatting is covered separately by actual sanitizer regressions.
 */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "fw_profile.h"
extern unsigned char nondet_uchar(void);
extern unsigned int nondet_uint(void);
extern size_t nondet_size(void);
extern _Bool nondet_bool(void);

void verify_profile(void)
{
	unsigned char wire[WS73_PROFILE_SIZE], digest[WS73_PROFILE_DIGEST_SIZE];
	struct ws73_fw_profile output, before, peer;
	size_t size = nondet_size();
	bool input_present = nondet_bool(), output_present = nondet_bool();
	bool valid, nonzero;
	unsigned int i, j, model = nondet_uint(), bus = nondet_uint(), file = nondet_uint();
	int result;

	_Static_assert(sizeof(output) == 161, "profile has no uninitialized padding");
	for (i = 0; i < sizeof(wire); i++)
		wire[i] = nondet_uchar();
	memset(&output, 0xa5, sizeof(output));
	before = output;
	valid = input_present && output_present && size == sizeof(wire) &&
		!memcmp(wire, "WS73P001", 8) && (wire[8] == 0 || wire[8] == 2) &&
		!wire[9] && !wire[10] && !wire[11];
	for (i = 0; i < WS73_PROFILE_FILES; i++) {
		nonzero = false;
		for (j = 0; j < WS73_PROFILE_DIGEST_SIZE; j++)
			nonzero = nonzero || wire[12+i*32+j] != 0;
		valid = valid && nonzero;
	}
	result = ws73_fw_profile_decode(input_present ? wire : NULL, size,
					output_present ? &output : NULL);
	__CPROVER_assert((result == 0) == valid, "profile.exact_admissibility");
	if (result) {
		__CPROVER_assert(!memcmp(&output, &before, sizeof(output)), "profile.failure_atomic");
	} else {
		__CPROVER_assert(output.model == wire[8], "profile.model_binding");
		__CPROVER_assert(!memcmp(output.digest, wire+12, sizeof(output.digest)), "profile.hash_order_binding");
		__CPROVER_assert((ws73_fw_profile_model(&output, model, bus) == 0) ==
				(model == output.model && bus == 0), "profile.model_bus_match");
		peer = output;
		__CPROVER_assert(!ws73_fw_profile_same(&output, &peer), "profile.same_closure");
		peer.digest[4][31] ^= 1;
		__CPROVER_assert(ws73_fw_profile_same(&output, &peer) == -ESTALE,
				"profile.changed_closure_rejected");
		/* Exhaust all five valid indices;no input value is excluded. This
		 * avoids a symbolic nested-array address in the harness itself.
		 */
		for (i = 0; i < WS73_PROFILE_FILES; i++) {
			for (j = 0; j < sizeof(digest); j++)
				digest[j] = output.digest[i][j];
			__CPROVER_assert(!ws73_fw_profile_digest(&output, i, digest), "profile.file_hash_match");
			digest[31] ^= 1;
			__CPROVER_assert(ws73_fw_profile_digest(&output, i, digest) == -EBADMSG,
					"profile.corrupt_file_hash_rejected");
		}
		if (file >= WS73_PROFILE_FILES)
			__CPROVER_assert(ws73_fw_profile_digest(&output, file, digest) == -EINVAL,
					"profile.invalid_file_index_rejected");
	}
}
