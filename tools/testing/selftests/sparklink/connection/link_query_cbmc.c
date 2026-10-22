/* SPDX-License-Identifier: GPL-2.0-only */
/* Actual production connection.c is a separate translation unit. No driver,
 * ledger, lock, allocator, clock, USB, firmware or Host stub is supplied here.
 * Scope: internal query selectors 4/5 only, arbitrary 32-bit fields, valid
 * allocated objects or NULL. Not an arbitrary-invalid-FFI-pointer proof.
 */
#include <assert.h>
#include <errno.h>
#include <string.h>
#include "connection.h"

int main(void)
{
	struct sparklink_connection_request request;
	struct guarded {
		unsigned char prefix[8];
		struct sparklink_connection_plan plan;
		unsigned char suffix[8];
	} output, before;
	_Bool phy, null_request, null_output;
	__CPROVER_havoc_object(&request);
	__CPROVER_havoc_object(&output);
	__CPROVER_havoc_object(&phy);
	__CPROVER_havoc_object(&null_request);
	__CPROVER_havoc_object(&null_output);
	request.operation = phy ? 5 : 4;
	before = output;
	const struct sparklink_connection_parameters zero = {0};
	int valid = request.handle <= 65535 && request.reason == 0 &&
		    !memcmp(&request.parameters, &zero, sizeof(zero));
	int result = ws73_connection_prepare(null_request ? NULL : &request,
					    null_output ? NULL : &output.plan);
	__CPROVER_assert(sizeof(unsigned int) == 4, "LQI_u32_model");
	__CPROVER_assert(!memcmp(output.prefix, before.prefix, 8) &&
			 !memcmp(output.suffix, before.suffix, 8), "LQI_output_guards");
	if (null_request || null_output || !valid) {
		__CPROVER_assert(result == -EINVAL, "LQI_invalid_rejected");
		__CPROVER_assert(!memcmp(&output, &before, sizeof(output)), "LQI_failure_atomic");
	} else {
		__CPROVER_assert(result == 0, "LQI_valid_accepted");
		__CPROVER_assert(output.plan.operation == request.operation &&
				 output.plan.opcode == (phy ? 0x1805 : 0x180c) &&
				 output.plan.length == 2, "LQI_typed_recipe");
		__CPROVER_assert(output.plan.params[0] == (request.handle & 255) &&
				 output.plan.params[1] == (request.handle >> 8), "LQI_LE16_handle");
		for (unsigned int n = 2; n < sizeof(output.plan.params); n++)
			__CPROVER_assert(output.plan.params[n] == 0, "LQI_unused_bytes_zero");
		__CPROVER_assert(ws73_connection_validate(output.plan.operation,
			 output.plan.opcode, output.plan.params, output.plan.length) == 0, "LQI_plan_validates");
	}
	unsigned int opcode;
	size_t size;
	_Bool null_params;
	unsigned char params[32];
	__CPROVER_havoc_object(&opcode);
	__CPROVER_havoc_object(&size);
	__CPROVER_havoc_object(&null_params);
	__CPROVER_havoc_object(params);
	int checked = ws73_connection_validate(request.operation, opcode,
					  null_params ? NULL : params, size);
	__CPROVER_assert(checked == (!null_params && size == 2 &&
		 opcode == (phy ? 0x1805 : 0x180c) ? 0 : -EINVAL), "LQI_validator_shape");
	return 0;
}
