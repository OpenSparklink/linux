/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SPARKLINK_WS73_BSLE_H
#define _SPARKLINK_WS73_BSLE_H

#include "wire.h"

enum ws73_bsle_phase {
	WS73_BSLE_WAIT_BSP,
	WS73_BSLE_CONFIGURING,
	WS73_BSLE_WAIT_CUSTOMIZE,
	WS73_BSLE_OPENING,
	WS73_BSLE_WAIT_BOOT,
	WS73_BSLE_TRANSPORT_OPEN,
};

/* Buffers and sequence belong to one USB interface. Transport callbacks
 * return exact lengths, zero for send success, or a negative errno. now_ms
 * must be monotonic. No callback may fabricate a controller acknowledgement.
 */
struct ws73_bsle_io {
	void *context;
	unsigned char *tx;
	size_t tx_capacity;
	unsigned char *rx;
	size_t rx_capacity;
	unsigned int *sequence;
	unsigned long long (*now_ms)(void *context);
	int (*send)(void *context, size_t size);
	int (*receive)(void *context, unsigned int timeout_ms);
	int (*notification)(void *context, unsigned int timeout_ms, unsigned int *bits);
	int (*open)(void *context);
	void (*phase)(void *context, enum ws73_bsle_phase phase);
};

/* The PM word and 140-byte customization are deployment inputs, not guesses.
 * Success only opens the vendor transport; DLI queries are still mandatory.
 */
int ws73_bsle_start(struct ws73_bsle_io *io, const unsigned char *pm, size_t pm_size,
		    const unsigned char *custom, size_t custom_size);

#endif
