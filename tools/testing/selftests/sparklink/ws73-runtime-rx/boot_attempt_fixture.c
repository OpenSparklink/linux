// SPDX-License-Identifier: GPL-2.0-only
/* Actual driver wrapper/getter. The sequencer, clock, logger, mutex and sysfs
 * dependencies below are explicit synchronous fixtures, not kernel/USB proof.
 */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "bsle.h"

typedef unsigned long long u64;
#define READ_ONCE(x) (x)
#define PAGE_SIZE 4096
/* @@DECLARATIONS@@ */

struct mutex { bool held; };
struct device { void *context; };
struct device_attribute { int unused; };
struct usb_interface { struct device dev; };
struct firmware { const unsigned char *data; size_t size; };
struct ws73_usb {
	struct usb_interface *intf;
	/* Explicit single-thread lock dependency,not a kernel mutex model. */
	struct mutex phase_lock;
	struct ws73_bsle_attempt_history bsle_attempts;
	enum ws73_stage stage;
	unsigned int tx_sequence;
	/* Test-controlled dependencies; none is a production replacement state. */
	u64 clock_ms, duration_ms;
	unsigned int sequence_delta, calls, logs;
	enum ws73_stage next_phase;
	int next_result;
	bool expect_restore;
};

static unsigned char pm_bytes[4], custom_bytes[140];
static const struct firmware pm = { pm_bytes, sizeof(pm_bytes) };
static const struct firmware custom = { custom_bytes, sizeof(custom_bytes) };
static const char expected_warm[] =
	"attempt=2 kind=1 phase=5 result=-110 start_ms=10100 end_ms=13100 sequence_start=0 sequence_end=1\n";

#define lockdep_assert_held(lock) assert((lock)->held)
static int mutex_trylock(struct mutex *lock)
{
	if (lock->held)
		return 0;
	lock->held = true;
	return 1;
}

static void mutex_unlock(struct mutex *lock)
{
	assert(lock->held);
	lock->held = false;
}

static void *to_usb_interface(struct device *dev) { return dev; }

static struct ws73_usb *usb_get_intfdata(void *intf)
{
	return ((struct device *)intf)->context;
}

static u64 ws73_now_ms(struct ws73_usb *ws) { return ws->clock_ms; }

static void dev_info(struct device *dev, const char *format, ...)
{
	struct ws73_usb *ws = dev->context;

	assert(ws->phase_lock.held && format);
	ws->logs++;
}

static int sysfs_emit_at(char *buf, ssize_t offset, const char *format, ...)
{
	va_list args;
	int count;

	assert(offset >= 0 && offset < PAGE_SIZE);
	va_start(args, format);
	count = vsnprintf(buf + offset, PAGE_SIZE - offset, format, args);
	va_end(args);
	assert(count >= 0 && count < PAGE_SIZE - offset);
	return count;
}

#define sysfs_emit(buf, ...) sysfs_emit_at(buf, 0, __VA_ARGS__)

static int sequence_result(struct ws73_bsle_io *io, bool restore,
			   const unsigned char *p, size_t pn,
			   const unsigned char *c, size_t cn)
{
	struct ws73_usb *ws = io->context;

	assert(ws->phase_lock.held && restore == ws->expect_restore);
	assert(p == pm_bytes && pn == 4 && c == custom_bytes && cn == 140);
	ws->clock_ms += ws->duration_ms;
	ws->tx_sequence += ws->sequence_delta;
	ws->stage = ws->next_phase;
	ws->calls++;
	return ws->next_result;
}

int ws73_bsle_start(struct ws73_bsle_io *io, const unsigned char *p, size_t pn,
		    const unsigned char *c, size_t cn)
{
	return sequence_result(io, false, p, pn, c, cn);
}

int ws73_bsle_restore(struct ws73_bsle_io *io, const unsigned char *p, size_t pn,
		      const unsigned char *c, size_t cn)
{
	return sequence_result(io, true, p, pn, c, cn);
}

/* @@ACTUAL@@ */

static int attempt(struct ws73_usb *ws, enum ws73_bsle_attempt_kind kind,
		   int result, enum ws73_stage phase, u64 duration, unsigned int advance)
{
	struct ws73_bsle_io io = { .context = ws };
	int ret;

	ws->next_result = result;
	ws->next_phase = phase;
	ws->duration_ms = duration;
	ws->sequence_delta = advance;
	ws->expect_restore = kind != WS73_BSLE_ATTEMPT_INITIAL;
	ws->phase_lock.held = true;
	ret = ws73_run_bsle_attempt(ws, &io, &pm, &custom, kind);
	assert(ret == result && ws->phase_lock.held);
	ws->phase_lock.held = false;
	assert(ws->calls == ws->logs);
	return ret;
}

int main(void)
{
	struct usb_interface ia = {}, ib = {};
	struct ws73_usb a = { .intf = &ia, .clock_ms = 100 };
	struct ws73_usb b = { .intf = &ib, .clock_ms = 200 };
	struct ws73_bsle_attempt_history empty = {}, prefix, peer;
	char buf[PAGE_SIZE + 32], again[PAGE_SIZE + 32];
	ssize_t length;

	ia.dev.context = &a;
	ib.dev.context = &b;
	memset(buf, 0xa5, sizeof(buf));
	assert(bsle_attempts_show(&ia.dev, NULL, buf) == 39);
	assert(!strcmp(buf, "version=1 count=0 capacity=8 omitted=0\n"));
	assert(!a.calls && !a.phase_lock.held);
	/* Busy read cannot expose partial fields, modify output or issue I/O. */
	memset(buf, 0xa5, sizeof(buf));
	a.phase_lock.held = true;
	assert(bsle_attempts_show(&ia.dev, NULL, buf) == -EAGAIN);
	for (unsigned int i = 0; i < sizeof(buf); i++)
		assert((unsigned char)buf[i] == 0xa5);
	assert(!a.calls && a.phase_lock.held);
	a.phase_lock.held = false;
	/* Different original return phases remain separately observable. */
	attempt(&a, WS73_BSLE_ATTEMPT_INITIAL, -ETIMEDOUT, WS73_WAIT_BSP, 10000, 0);
	attempt(&a, WS73_BSLE_ATTEMPT_WARM, -ETIMEDOUT, WS73_CONFIGURING, 3000, 1);
	attempt(&a, WS73_BSLE_ATTEMPT_PROTOCOL, -ETIMEDOUT, WS73_RECOVERY_WAIT_CLOSE, 10000, 0);
	assert(a.bsle_attempts.count == 3 && !a.bsle_attempts.omitted);
	assert(a.bsle_attempts.records[0].phase == WS73_WAIT_BSP);
	assert(a.bsle_attempts.records[1].phase == WS73_CONFIGURING);
	assert(a.bsle_attempts.records[2].phase == WS73_RECOVERY_WAIT_CLOSE);
	assert(a.bsle_attempts.records[0].start_ms == 100 &&
	       a.bsle_attempts.records[0].end_ms == 10100);
	assert(a.bsle_attempts.records[1].start_ms == 10100 &&
	       a.bsle_attempts.records[1].end_ms == 13100);
	assert(a.bsle_attempts.records[2].start_ms == 13100 &&
	       a.bsle_attempts.records[2].end_ms == 23100);
	for (unsigned int i = 0; i < 3; i++) {
		assert(a.bsle_attempts.records[i].kind == i);
		assert(a.bsle_attempts.records[i].result == -ETIMEDOUT);
	}
	assert(!a.bsle_attempts.records[0].sequence_start &&
	       !a.bsle_attempts.records[0].sequence_end);
	assert(!a.bsle_attempts.records[1].sequence_start &&
	       a.bsle_attempts.records[1].sequence_end == 1);
	assert(a.bsle_attempts.records[2].sequence_start == 1 &&
	       a.bsle_attempts.records[2].sequence_end == 1);
	assert(!memcmp(&b.bsle_attempts, &empty, sizeof(empty)));
	peer = a.bsle_attempts;
	attempt(&b, WS73_BSLE_ATTEMPT_INITIAL, 0, WS73_TRANSPORT_OPEN, 20, 6);
	assert(!memcmp(&a.bsle_attempts, &peer, sizeof(peer)));
	assert(b.bsle_attempts.count == 1 && !b.bsle_attempts.records[0].result);
	/* Snapshot reads are stable and have no sequencer/USB side effect. */
	unsigned int calls = a.calls;

	length = bsle_attempts_show(&ia.dev, NULL, buf);
	assert(length > 0 && (size_t)length == strlen(buf));
	assert(strstr(buf, expected_warm));
	assert(bsle_attempts_show(&ia.dev, NULL, again) == length && !strcmp(buf, again));
	assert(a.calls == calls && !a.phase_lock.held);
	/* Retain the finite prefix even after later successes and failures. */
	while (a.bsle_attempts.count < WS73_BSLE_ATTEMPTS_MAX)
		attempt(&a, WS73_BSLE_ATTEMPT_PROTOCOL, -EIO, WS73_WAIT_CUSTOMIZE, 1, 2);
	prefix = a.bsle_attempts;
	for (unsigned int i = 0; i < 1000; i++)
		attempt(&a, WS73_BSLE_ATTEMPT_PROTOCOL, i % 2 ? 0 : -ENODEV, WS73_WAIT_BOOT, 1, 1);
	assert(a.bsle_attempts.count == WS73_BSLE_ATTEMPTS_MAX && a.bsle_attempts.omitted == 1000);
	assert(!memcmp(a.bsle_attempts.records, prefix.records, sizeof(prefix.records)));
	a.bsle_attempts.omitted = UINT_MAX - 1;
	attempt(&a, WS73_BSLE_ATTEMPT_PROTOCOL, -EPIPE, WS73_OPENING, 0, 0);
	attempt(&a, WS73_BSLE_ATTEMPT_PROTOCOL, -ESHUTDOWN, WS73_RECOVERY_CLOSE, 0, 0);
	assert(a.bsle_attempts.omitted == UINT_MAX && a.bsle_attempts.count == 8);
	assert(!memcmp(a.bsle_attempts.records, prefix.records, sizeof(prefix.records)));
	/* Full-width formatting stays within a single sysfs page. */
	for (unsigned int i = 0; i < 8; i++) {
		a.bsle_attempts.records[i] = (struct ws73_bsle_attempt_record) {
			.start_ms = ULLONG_MAX, .end_ms = ULLONG_MAX, .kind = UINT_MAX,
			.phase = UINT_MAX, .result = INT_MIN,
			.sequence_start = UINT_MAX, .sequence_end = UINT_MAX,
		};
	}
	memset(buf, 0xa5, sizeof(buf));
	length = bsle_attempts_show(&ia.dev, NULL, buf);
	assert(length > 0 && length < PAGE_SIZE && (size_t)length == strlen(buf));
	for (unsigned int i = PAGE_SIZE; i < sizeof(buf); i++)
		assert((unsigned char)buf[i] == 0xa5);
	assert(!a.phase_lock.held);
	/* A newly allocated USB-interface context has no inherited prefix. */
	struct ws73_usb fresh = {};

	assert(!memcmp(&fresh.bsle_attempts, &empty, sizeof(empty)));
	puts("{\"status\":\"WS73_BSLE_ATTEMPT_FUNCTIONS_PASS\"}");
	return 0;
}
