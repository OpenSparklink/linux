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
	WS73_BSLE_DRAINING,
	WS73_BSLE_CLOSING,
	WS73_BSLE_WAIT_CLOSE,
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
	/* Query-only bounded write; timeout is remaining original budget. */
	int (*send_timed)(void *context, size_t size, unsigned int timeout_ms);
	int (*receive)(void *context, unsigned int timeout_ms);
	int (*notification)(void *context, unsigned int timeout_ms, unsigned int *bits);
	int (*open)(void *context);
	int (*close)(void *context);
	void (*phase)(void *context, enum ws73_bsle_phase phase);
};

/* Exclusive pre-registration transport owner only, after BSLE open. One
 * request, original bounded deadline, no DLI command/data credit consumed.
 */
int ws73_chip_query(struct ws73_bsle_io *io, struct ws73_chip_info *info);

/* The PM word and 140-byte customization are deployment inputs, not guesses.
 * Success only opens the vendor transport; DLI queries are still mandatory.
 */
int ws73_bsle_start(struct ws73_bsle_io *io, const unsigned char *pm, size_t pm_size,
		    const unsigned char *custom, size_t custom_size);

/* Adopt a warm device only after the owner has no live protocol/USB workers.
 * No synthetic BSP_READY: drain, actual CLOSE action, reconfigure, actual
 * BOOT_FINISH. The caller owns retry admission/budget; this makes one attempt.
 */
int ws73_bsle_restore(struct ws73_bsle_io *io, const unsigned char *pm, size_t pm_size,
		      const unsigned char *custom, size_t custom_size);

#endif
