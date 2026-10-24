// SPDX-License-Identifier: GPL-2.0-only
/* Actual USB open/close/completion bodies are inserted by the runner.
 * Allocation, USB core, scheduling, Native consumer and memory accesses here
 * are explicit single-thread fixtures, not a model of kernel concurrency.
 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wire.h"

typedef uint16_t u16;
typedef uint64_t u64;
#define GFP_KERNEL 0
#define GFP_ATOMIC 1
#define BIT(n) (1U << (n))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))

struct urb {
	void *context, *buffer;
	void (*complete)(struct urb *);
	int status, actual_length;
	unsigned int pipe, length, interval;
	bool queued;
};

struct ws73_usb {
	void *udev;
	struct urb *rx_urb, *notification_urb;
	bool streaming, stopping, broken;
	int native_id;
	u64 native_generation;
	unsigned int bulk_in, int_in, int_interval;
	unsigned char *rx;
	size_t rx_size;
	unsigned char notification[8];
	/* Fixture observations, not fields added to the production object. */
	unsigned int consumer_calls, failures;
	int last_error;
};

static unsigned int allocations, alloc_calls, alloc_fail_at;
static unsigned int submissions, submit_fail_at, kills, consumers_at_submit;
static int submit_error, consumer_error;
static bool stop_in_consumer, retire_in_consumer, stop_at_failed_submit;
static struct urb *last_submitted;

static unsigned int get_unaligned_le32(const void *ptr)
{
	const unsigned char *p = ptr;

	return p[0] | (unsigned int)p[1] << 8 |
		(unsigned int)p[2] << 16 | (unsigned int)p[3] << 24;
}

static struct urb *usb_alloc_urb(int packets, int flags)
{
	struct urb *urb;

	assert(!packets && flags == GFP_KERNEL);
	if (++alloc_calls == alloc_fail_at)
		return NULL;
	urb = calloc(1, sizeof(*urb));
	assert(urb);
	allocations++;
	return urb;
}

static void usb_free_urb(struct urb *urb)
{
	if (!urb)
		return;
	assert(!urb->queued && allocations);
	allocations--;
	free(urb);
}

static unsigned int usb_rcvbulkpipe(void *device, unsigned int endpoint)
{
	assert(device && endpoint == 1);
	return 0x81;
}

static unsigned int usb_rcvintpipe(void *device, unsigned int endpoint)
{
	assert(device && endpoint == 3);
	return 0x83;
}

static void usb_fill_bulk_urb(struct urb *urb, void *device, unsigned int pipe,
			      void *buffer, unsigned int length,
			      void (*complete)(struct urb *), void *context)
{
	assert(urb && device && buffer && length && complete && context);
	urb->buffer = buffer;
	urb->length = length;
	urb->context = context;
	urb->complete = complete;
	urb->pipe = pipe;
}

static void usb_fill_int_urb(struct urb *urb, void *device, unsigned int pipe,
			     void *buffer, unsigned int length,
			     void (*complete)(struct urb *), void *context,
			     unsigned int interval)
{
	usb_fill_bulk_urb(urb, device, pipe, buffer, length, complete, context);
	urb->interval = interval;
}

static int usb_submit_urb(struct urb *urb, int flags)
{
	struct ws73_usb *ws = urb->context;

	assert(!urb->queued && ws && ws->streaming && !ws->stopping);
	assert(ws->native_id == 42 && ws->native_generation == 0x12345678);
	assert(flags == GFP_KERNEL || flags == GFP_ATOMIC);
	if (urb == ws->rx_urb)
		assert(urb->pipe == 0x81 && urb->buffer == ws->rx &&
		       urb->length == WS73_WIRE_RX_MAX);
	else
		assert(urb == ws->notification_urb && urb->pipe == 0x83 &&
		       urb->buffer == ws->notification && urb->length == 8 &&
		       urb->interval == 7);
	last_submitted = urb;
	consumers_at_submit = ws->consumer_calls;
	if (++submissions == submit_fail_at) {
		if (stop_at_failed_submit)
			ws->stopping = true;
		return submit_error;
	}
	urb->queued = true;
	return 0;
}

static void usb_kill_urb(struct urb *urb)
{
	/* Record the dependency call; real reject/use_count/waits are NOT run. */
	kills++;
	if (urb)
		urb->queued = false;
}

static void ws73_async_failure(struct ws73_usb *ws, int error)
{
	assert(error < 0);
	ws->failures++;
	ws->last_error = error;
	ws->broken = true;
	ws->streaming = false;
}

static int ws73_native_packet(void *context, unsigned int service,
			      unsigned int queue, const unsigned char *data,
			      size_t size)
{
	struct ws73_usb *ws = context;

	assert(service == WS73_WIRE_SLE_SERVICE && queue == WS73_WIRE_SLE_QUEUE);
	assert(size == 1 && data[0] == 0xa5);
	ws->consumer_calls++;
	if (stop_in_consumer)
		ws->stopping = true;
	if (retire_in_consumer)
		ws->streaming = false;
	return consumer_error;
}

/* @@PRODUCTION@@ */

static void reset(struct ws73_usb *ws, unsigned char *rx)
{
	assert(!allocations);
	alloc_calls = alloc_fail_at = submissions = submit_fail_at = kills = 0;
	consumer_error = 0;
	submit_error = -EPIPE;
	stop_in_consumer = retire_in_consumer = stop_at_failed_submit = false;
	last_submitted = NULL;
	consumers_at_submit = 0;
	memset(ws, 0, sizeof(*ws));
	memset(rx, 0, WS73_WIRE_RX_MAX);
	ws->udev = ws;
	ws->native_id = -1;
	ws->bulk_in = 1;
	ws->int_in = 3;
	ws->int_interval = 7;
	ws->rx = rx;
	ws->rx_size = WS73_WIRE_RX_MAX;
}

static void release(struct ws73_usb *ws)
{
	ws73_native_close(ws);
	usb_free_urb(ws->notification_urb);
	usb_free_urb(ws->rx_urb);
	ws->notification_urb = ws->rx_urb = NULL;
	assert(!allocations);
}

static void complete(struct urb *urb, int status, int length)
{
	assert(urb->queued);
	urb->queued = false;
	urb->status = status;
	urb->actual_length = length;
	urb->complete(urb);
}

static void put32(unsigned char *p, unsigned int word)
{
	for (unsigned int i = 0; i < 4; i++)
		p[i] = word >> (8 * i);
}

static void aggregate(unsigned char *rx)
{
	/* Independently specified one-slot HCC RX, one opaque consumer byte. */
	put32(rx, 2);
	put32(rx + 4, 97);
	rx[12] = 5;
	rx[92] = 0xa0;
	rx[93] = 8;
	rx[94] = 1;
	rx[96] = 0xa5;
}

int main(void)
{
	unsigned char rx[WS73_WIRE_RX_MAX];
	struct ws73_usb ws;
	unsigned int cases = 0;

	/* No allocation or I/O on stopped/broken or already-owned objects. */
	for (unsigned int i = 0; i < 4; i++) {
		reset(&ws, rx);
		if (i == 0) ws.stopping = true;
		if (i == 1) ws.broken = true;
		if (i == 2) ws.rx_urb = (void *)&ws;
		if (i == 3) ws.notification_urb = (void *)&ws;
		assert(ws73_native_open(&ws, 42, 0x12345678) ==
		       (i < 2 ? -ENODEV : -EBUSY));
		assert(!allocations && !alloc_calls && !submissions);
		cases++;
	}
	/* Either allocation and either initial USB submit may fail. */
	for (unsigned int i = 0; i < 4; i++) {
		reset(&ws, rx);
		if (i < 2) alloc_fail_at = i + 1;
		else submit_fail_at = i - 1;
		assert(ws73_native_open(&ws, 42, 0x12345678) ==
		       (i < 2 ? -ENOMEM : -EPIPE));
		assert(!ws.streaming && !allocations && !ws.rx_urb &&
		       !ws.notification_urb && ws.native_id == -1 && kills == 2);
		cases++;
	}
	/* Every truncated notification length rejects; exact zero and all bits
	 * except PANIC remain observations, never consumer data or credit. */
	for (unsigned int i = 0; i < 11; i++) {
		reset(&ws, rx);
		assert(!ws73_native_open(&ws, 42, 0x12345678));
		unsigned int length = i < 8 ? i : 8;
		if (i == 9) put32(ws.notification, ~(unsigned int)BIT(6));
		if (i == 10) put32(ws.notification, BIT(6));
		complete(ws.notification_urb, 0, length);
		if (i < 8 || i == 10)
			assert(ws.failures == 1 && !ws.streaming && submissions == 2 &&
			       ws.last_error == (i == 10 ? -EIO : -EPROTO));
		else
			assert(!ws.failures && submissions == 3 &&
			       last_submitted == ws.notification_urb && ws.streaming);
		assert(!ws.consumer_calls);
		release(&ws);
		cases++;
	}
	/* Status errors, zero bulk, valid aggregate, invalid late slot,
	 * retired generation, consumer failure and a stop during consumption. */
	for (unsigned int i = 0; i < 10; i++) {
		reset(&ws, rx);
		assert(!ws73_native_open(&ws, 42, 0x12345678));
		aggregate(rx);
		if (i == 3) rx[14] = 255; /* bad second slot: no first consumer */
		if (i == 4) consumer_error = -ENODEV;
		if (i == 5) consumer_error = -ENOBUFS;
		if (i == 6) stop_in_consumer = true;
		if (i == 7) retire_in_consumer = true;
		if (i >= 8) { submit_fail_at = 3; stop_at_failed_submit = i == 9; }
		complete(ws.rx_urb, i == 0 ? -EILSEQ : 0, i == 1 ? 0 : 97);
		if (i == 0 || i == 3 || i == 5 || i == 8)
			assert(ws.failures == 1 && !ws.streaming &&
			       ws.last_error == (i == 0 ? -EILSEQ : i == 3 ?
					 -EPROTO : i == 5 ? -ENOBUFS : -EPIPE));
		else
			assert(!ws.failures);
		assert(ws.consumer_calls == (i == 0 || i == 1 || i == 3 ? 0 : 1));
		assert(submissions == (i == 1 || i == 2 || i >= 8 ? 3 : 2));
		if (i == 2)
			assert(last_submitted == ws.rx_urb && consumers_at_submit == 1);
		if (i == 4 || i == 7) assert(!ws.streaming);
		release(&ws);
		cases++;
	}
	/* Stopping/closed callbacks consume nothing; another object's state is
	 * unchanged. This checks fixture object isolation, not actual devices. */
	for (unsigned int i = 0; i < 4; i++) {
		reset(&ws, rx);
		assert(!ws73_native_open(&ws, 42, 0x12345678));
		struct ws73_usb survivor = { .streaming = true, .native_id = 19,
			.native_generation = 23 };
		if (i < 2) ws.streaming = false;
		else ws.stopping = true;
		complete(i % 2 ? ws.notification_urb : ws.rx_urb, -ESHUTDOWN, 0);
		assert(!ws.failures && !ws.consumer_calls && submissions == 2);
		assert(survivor.streaming && survivor.native_id == 19 &&
		       survivor.native_generation == 23 && !survivor.failures);
		release(&ws);
		cases++;
	}
	printf("{\"status\":\"WS73_RUNTIME_RX_FUNCTIONS_PASS\",\"cases\":%u}\n", cases);
	return 0;
}
