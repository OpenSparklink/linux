/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SPARKLINK_WS73_RECOVERY_H
#define _SPARKLINK_WS73_RECOVERY_H

#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#endif

#define WS73_RECOVERY_LIMIT 2U
#define WS73_RECOVERY_TOTAL_MS 120000ULL
#define WS73_RECOVERY_STABLE_MS 60000ULL
#define WS73_RECOVERY_UPLOAD_LIMIT 3U

/* Caller serializes this port-owned record. Reprobe must not recreate it.
 * No protocol/USB action, credit or Ready is supplied by this policy.
 */
struct ws73_recovery_budget {
	unsigned int attempts, uploads;
	unsigned long long deadline_ms, stable_since_ms;
	int cause, result;
	int exhausted;
};

static inline int ws73_recovery_retryable(int error)
{
	/* EIO may be a controller/unsupported-command error. Offline/shutdown,
	 * cancellation and pipe stalls require their own qualified recovery.
	 */
	return error == -ETIMEDOUT || error == -EPROTO || error == -EREMOTEIO;
}

static inline int ws73_recovery_admit(struct ws73_recovery_budget *b,
		unsigned long long now, int cause, unsigned int *delay_ms)
{
	if (!b->cause)
		b->cause = cause;
	b->stable_since_ms = 0;
	if (!ws73_recovery_retryable(cause)) {
		b->result = cause;
		return cause;
	}
	if (!b->deadline_ms) {
		if (now > ~0ULL - WS73_RECOVERY_TOTAL_MS) {
			b->exhausted = 1;
			b->result = -EOVERFLOW;
			return -EOVERFLOW;
		}
		b->deadline_ms = now + WS73_RECOVERY_TOTAL_MS;
	}
	if (b->exhausted || b->attempts == WS73_RECOVERY_LIMIT ||
	    now >= b->deadline_ms) {
		b->exhausted = 1;
		b->result = -ETIMEDOUT;
		return -ETIMEDOUT;
	}
	*delay_ms = b->attempts ? 4000 : 1000;
	if (b->deadline_ms - now <= *delay_ms) {
		b->exhausted = 1;
		b->result = -ETIMEDOUT;
		return -ETIMEDOUT;
	}
	b->attempts++;
	b->result = -EINPROGRESS;
	return 0;
}

static inline unsigned int ws73_recovery_timeout(const struct ws73_recovery_budget *b,
		unsigned long long now, unsigned int requested)
{
	unsigned long long remaining;

	if (!b->deadline_ms)
		return requested;
	if (now >= b->deadline_ms)
		return 0;
	remaining = b->deadline_ms - now;
	return remaining < requested ? (unsigned int)remaining : requested;
}

static inline void ws73_recovery_observe(struct ws73_recovery_budget *b,
		unsigned long long now, int ready)
{
	if (!ready) {
		b->stable_since_ms = 0;
		return;
	}
	if (!b->stable_since_ms) {
		b->stable_since_ms = now;
		return;
	}
	if (now < b->stable_since_ms) {
		b->stable_since_ms = now;
		return;
	}
	if (now - b->stable_since_ms >= WS73_RECOVERY_STABLE_MS) {
		*b = (struct ws73_recovery_budget){ .stable_since_ms = now };
	}
}

#endif
