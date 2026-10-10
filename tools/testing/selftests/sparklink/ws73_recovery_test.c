// SPDX-License-Identifier: GPL-2.0-only
/* Port-policy requirements only; integration tests prove transport lifecycle. */
#include <stdio.h>
#include <string.h>
#include "../../../../drivers/sparklink/ws73/recovery.h"

static unsigned int checks, failures;
#define CHECK(x) do { checks++; if (!(x)) { failures++; fprintf(stderr, "line %d: %s\n", __LINE__, #x); } } while (0)

int main(void)
{
	struct ws73_recovery_budget a = {}, b = {};
	unsigned int delay = 999;

	CHECK(!ws73_recovery_admit(&a, 10000, -EPROTO, &delay));
	CHECK(delay == 1000 && a.attempts == 1 && a.cause == -EPROTO);
	unsigned long long deadline = a.deadline_ms;
	CHECK(ws73_recovery_timeout(&a, deadline - 7, 3000) == 7);
	CHECK(ws73_recovery_timeout(&a, deadline, 3000) == 0);
	CHECK(ws73_recovery_timeout(&a, deadline + 1, 3000) == 0);
	/* Destroy/recreate the USB incarnation, retaining the port-owned object.
	 * A new transport/index/address has no authority to renew its deadline.
	 */
	struct ws73_recovery_budget *new_incarnation = &a;
	CHECK(!ws73_recovery_admit(new_incarnation, 11000, -ETIMEDOUT, &delay));
	CHECK(delay == 4000 && a.attempts == 2 && a.deadline_ms == deadline);
	CHECK(a.cause == -EPROTO);
	struct ws73_recovery_budget before = a;
	CHECK(!ws73_recovery_admit(&b, 12000, -ETIMEDOUT, &delay));
	CHECK(!memcmp(&a, &before, sizeof(a)));
	CHECK(ws73_recovery_admit(&a, 12000, -EPROTO, &delay) == -ETIMEDOUT);
	CHECK(a.exhausted && a.attempts == 2 && a.deadline_ms == deadline);
	for (unsigned int i = 0; i < 1000; i++) {
		CHECK(ws73_recovery_admit(&a, 13000 + i, -ETIMEDOUT, &delay) == -ETIMEDOUT);
		CHECK(a.attempts == 2 && a.deadline_ms == deadline && a.cause == -EPROTO);
	}
	/* One late Ready must not reopen a spent budget. Setup/fault restarts
	 * the stable observation interval; only a full stable period renews it.
	 */
	ws73_recovery_observe(&a, 20000, 1);
	CHECK(a.attempts == 2 && a.exhausted);
	ws73_recovery_observe(&a, 79000, 0);
	ws73_recovery_observe(&a, 80000, 1);
	ws73_recovery_observe(&a, 139999, 1);
	CHECK(a.attempts == 2 && a.exhausted);
	ws73_recovery_observe(&a, 140000, 1);
	CHECK(!a.attempts && !a.exhausted && !a.deadline_ms && !a.cause);
	CHECK(!ws73_recovery_admit(&a, 140001, -EREMOTEIO, &delay) && delay == 1000);
	CHECK(b.attempts == 1 && b.cause == -ETIMEDOUT);
	int terminal[] = {-ENODEV, -ESHUTDOWN, -ECANCELED, -EPIPE, -EIO, -EINVAL, -EOPNOTSUPP};
	for (unsigned int i = 0; i < sizeof(terminal)/sizeof(terminal[0]); i++) {
		struct ws73_recovery_budget t = {};
		CHECK(ws73_recovery_admit(&t, 1, terminal[i], &delay) == terminal[i]);
		CHECK(!t.attempts && !t.deadline_ms && t.cause == terminal[i]);
	}
	struct ws73_recovery_budget expired = { .deadline_ms = 5000 };
	CHECK(ws73_recovery_admit(&expired, 4000, -EPROTO, &delay) == -ETIMEDOUT);
	CHECK(expired.exhausted && !expired.attempts);
	struct ws73_recovery_budget overflow = {};
	CHECK(ws73_recovery_admit(&overflow, ~0ULL - 1, -EPROTO, &delay) == -EOVERFLOW);
	CHECK(overflow.exhausted && !overflow.deadline_ms && !overflow.attempts);
	struct ws73_recovery_budget backwards = { .attempts = 2, .stable_since_ms = 80000 };
	ws73_recovery_observe(&backwards, 10000, 1);
	CHECK(backwards.attempts == 2 && backwards.stable_since_ms == 10000);
	ws73_recovery_observe(&backwards, 69999, 1);
	CHECK(backwards.attempts == 2);
	ws73_recovery_observe(&backwards, 70000, 1);
	CHECK(!backwards.attempts);
	printf("WS73_RECOVERY_POLICY: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
