// SPDX-License-Identifier: GPL-2.0-only
/* Production query and USB exact-response helper are inserted verbatim.
 * Locks, access ordering, allocation, clock and raw USB are explicit fixtures;
 * this does not execute kernel attribute/ref/callback drain or real USB.
 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int gfp_t;
#define GFP_KERNEL 0
#define USB_DIR_IN 0x80
#define USB_TYPE_CLASS 0x20
#define USB_RECIP_INTERFACE 1
#define READ_ONCE(x) (x)
#define smp_load_acquire(p) (*(p))

struct mutex { bool held; };
struct ws73_usb;
struct usb_device { struct ws73_usb *owner; };
struct ws73_usb {
	struct mutex phase_lock;
	bool metadata_valid, stopping, broken, runtime_transport, streaming;
	int native_id;
	u64 native_generation;
	struct usb_device *udev;
};
/* @@OBSERVATION@@ */

static unsigned int allocations, calls, unlocks, mutation;
static bool allocation_fail;
static int transfer_result;
static unsigned char response[4];
static u64 clock_ns;

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
	unlocks++;
}

static u64 ktime_get_ns(void)
{
	clock_ns += 1000;
	return clock_ns;
}

static void *kmalloc(size_t size, int flags)
{
	assert(size == 4 && flags == GFP_KERNEL);
	if (allocation_fail)
		return NULL;
	void *p = malloc(size);
	assert(p);
	allocations++;
	return p;
}

static void kfree(void *p)
{
	assert(p && allocations == 1);
	allocations--;
	free(p);
}

static unsigned int usb_rcvctrlpipe(struct usb_device *dev, unsigned int ep)
{
	assert(dev && ep == 0);
	return 0x80;
}

static int usb_control_msg(struct usb_device *dev, unsigned int pipe,
			   __u8 request, __u8 requesttype, __u16 value,
			   __u16 index, void *data, __u16 size, int timeout)
{
	struct ws73_usb *ws = dev->owner;

	assert(ws->phase_lock.held && allocations == 1);
	assert(pipe == 0x80 && request == 5 && requesttype == 0xa1);
	assert(value == 0 && index == 0 && size == 4 && timeout == 250);
	calls++;
	if (transfer_result > 0)
		memcpy(data, response, transfer_result < 4 ? transfer_result : 4);
	switch (mutation) {
	case 1: ws->stopping = true; break;
	case 2: ws->broken = true; break;
	case 3: ws->streaming = false; break;
	case 4: ws->metadata_valid = false; break;
	case 5: ws->native_id++; break;
	case 6: ws->native_generation++; break;
	}
	return transfer_result;
}

static unsigned int get_unaligned_le32(const void *ptr)
{
	const unsigned char *p = ptr;

	return p[0] | (unsigned int)p[1] << 8 |
		(unsigned int)p[2] << 16 | (unsigned int)p[3] << 24;
}

/* @@USB_HELPER@@ */
/* @@QUERY@@ */

static void reset(struct ws73_usb *ws, struct usb_device *dev)
{
	assert(!allocations);
	*ws = (struct ws73_usb) { .metadata_valid = true,
		.runtime_transport = true, .streaming = true, .native_id = 7,
		.native_generation = 19, .udev = dev };
	dev->owner = ws;
	calls = unlocks = mutation = 0;
	allocation_fail = false;
	transfer_result = 4;
	memcpy(response, "\x12\x34\x56\x78", 4);
	clock_ns = 5000;
}

static void rejected(struct ws73_usb *ws, int error, unsigned int expected_calls,
		     unsigned int expected_unlocks)
{
	struct ws73_hcc_memory_observation observation, before;

	memset(&observation, 0xa5, sizeof(observation));
	before = observation;
	assert(ws73_hcc_memory_query(ws, &observation) == error);
	assert(!memcmp(&observation, &before, sizeof(observation)));
	assert(calls == expected_calls && unlocks == expected_unlocks && !allocations);
}

int main(void)
{
	struct ws73_usb ws;
	struct usb_device dev;
	unsigned int cases = 0;

	for (unsigned int i = 0; i < 8; i++) {
		reset(&ws, &dev);
		if (i == 0) ws.phase_lock.held = true;
		if (i == 1) ws.stopping = true;
		if (i == 2) ws.broken = true;
		if (i == 3) ws.runtime_transport = false;
		if (i == 4) ws.metadata_valid = false;
		if (i == 5) ws.native_id = -1;
		if (i == 6) ws.streaming = false;
		if (i == 7) ws.native_generation = 0;
		rejected(&ws, i == 0 ? -EAGAIN : i < 3 ? -ENODEV :
			 i == 3 ? -EOPNOTSUPP : -ENODATA, 0, i != 0);
		cases++;
	}
	/* Exercise the actual USB core helper, not a stub claiming exact input. */
	for (int length = 0; length <= 5; length++) {
		reset(&ws, &dev);
		transfer_result = length;
		if (length != 4) {
			rejected(&ws, -EREMOTEIO, 1, 1);
		} else {
			struct ws73_hcc_memory_observation observation;

			assert(!ws73_hcc_memory_query(&ws, &observation));
			assert(observation.id == 7 && observation.generation == 19 &&
			       observation.raw_le32 == 0x78563412 &&
			       observation.start_ns == 6000 && observation.end_ns == 7000);
			assert(calls == 1 && unlocks == 1 && !allocations);
		}
		assert(!ws.phase_lock.held);
		cases++;
	}
	int errors[] = { -EPIPE, -ETIMEDOUT, -ENODEV, -EIO, -EPROTO };
	for (unsigned int i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		reset(&ws, &dev);
		transfer_result = errors[i];
		rejected(&ws, errors[i], 1, 1);
		assert(!ws.phase_lock.held && !ws.stopping && !ws.broken && ws.streaming);
		cases++;
	}
	reset(&ws, &dev);
	allocation_fail = true;
	rejected(&ws, -ENOMEM, 0, 1);
	assert(!ws.phase_lock.held);
	cases++;
	for (mutation = 1; mutation <= 6;) {
		unsigned int changed = mutation;

		reset(&ws, &dev);
		mutation = changed;
		rejected(&ws, -ESTALE, 1, 1);
		assert(!ws.phase_lock.held);
		mutation = changed + 1;
		cases++;
	}
	/* A full zero word remains raw, never an invented transport error or
	 * usable protocol credit. Counter semantics are outside this function. */
	for (unsigned int value = 0; value < 2; value++) {
		struct ws73_hcc_memory_observation observation;

		reset(&ws, &dev);
		memset(response, value ? 255 : 0, sizeof(response));
		assert(!ws73_hcc_memory_query(&ws, &observation));
		assert(observation.raw_le32 == (value ? UINT32_MAX : 0));
		assert(calls == 1 && !ws.broken && ws.streaming && !allocations);
		cases++;
	}
	printf("{\"status\":\"WS73_HCC_MEMORY_QUERY_FUNCTIONS_PASS\",\"cases\":%u}\n", cases);
	return 0;
}
