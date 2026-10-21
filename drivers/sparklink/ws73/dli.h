/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SPARKLINK_WS73_DLI_H
#define _SPARKLINK_WS73_DLI_H

#include "bsle.h"

struct ws73_dli_info {
	unsigned char version[5];
	unsigned char features[10];
	unsigned char address[6];
	unsigned int acb_length;
	unsigned int acb_count;
	unsigned int icb_length;
	unsigned int icb_count;
};

struct ws73_dli_result {
	unsigned int opcode;
	unsigned int status; /* exact controller status; not an errno alias */
	unsigned int event; /* last observed bootstrap DLI event */
	unsigned int hardware_error; /* raw Hardware Error byte; 0x100 = absent */
};

/* Raw admission stays metadata-query only. Typed discovery has its separate
 * validated Host path; no native raw mutation permission is inferred here.
 */
int ws73_dli_validate_command(unsigned int opcode, const unsigned char *params,
			      size_t size);

/* Setup-only typed volatile address path. This does not expand the raw query
 * whitelist or authorize storage writes. Core must retain the frozen ticket,
 * original deadline and independent 0406 readback before using the identity.
 */
int ws73_dli_validate_runtime_address(unsigned int opcode,
		const unsigned char *params, size_t size);
int ws73_dli_prepare_runtime_address(const unsigned char *address,
		unsigned short *opcode, unsigned char *params, size_t capacity);

/* Validate one A2 management event slot, not an HCC aggregate. WS73 owns the
 * successful Complete return schemas (including 0C02's selected TX power).
 * Unknown opcode returns remain opaque; Status, credit-only and framing are
 * still checked. A rejected reply must never release a Host transaction.
 */
int ws73_dli_validate_reply(const unsigned char *data, size_t size);

/* SDK111 controller-data (0014), encryption-parameter request (000e) and
 * encryption-change (0011) envelopes. Explicit wire offsets, not C layouts.
 * Unknown data indices/status/handles remain opaque. Validation establishes
 * neither session ownership nor authenticated/encrypted state. Other events
 * return -ENOMSG; malformed recognized events return -EPROTO.
 */
int ws73_dli_validate_security_event(const unsigned char *data, size_t size);

/* Recognize WS73 connection/disconnection outcomes, including the controller's
 * opcode-block event numbers. Validate framing and the known prefix only;
 * connection extension bytes, status, role and address type remain opaque.
 * No command completion, connection ownership or Ready state is inferred.
 * Returns -ENOMSG for another event kind, -EPROTO for a malformed outcome.
 */
int ws73_dli_validate_link_event(const unsigned char *data, size_t size);

/* Driver-owned dialect normalization. Does not interpret successful command
 * Status as a physical link. Errors leave output intact. Connection extension
 * bytes are not projected; the caller retains/logs the complete original body.
 */
struct ws73_link_outcome {
    unsigned int kind, status, handle, role, address_type;
    unsigned char address[6], reserved[2];
};
int ws73_dli_link_outcome(const unsigned char *data, size_t size,
                         struct ws73_link_outcome *out);

/* Fresh BSLE-open instance only. The caller provides its initial probe
 * window (one); every subsequent grant is an absolute controller credit.
 * Do not call again after an uncertain send/timeout. Publish info only on
 * full success; this still does not register a Runtime or advertise Ready.
 */
int ws73_dli_query(struct ws73_bsle_io *io, unsigned int *credits,
		   struct ws73_dli_info *info, struct ws73_dli_result *result);


/* Typed relay prepare returns exact parameter bytes, no I/O or truncation. */
int ws73_dli_relay_prepare(unsigned int handle, unsigned int index,
    const unsigned char *payload, size_t size, unsigned short *opcode,
    unsigned char *params, size_t capacity, unsigned short *echo_index);
/* SDK111 wire failure1ff -> canonical147; original packet is never changed. */
int ws73_dli_relay_normalize_rx(const unsigned char *data, size_t size,
    unsigned char *out, size_t capacity);
int ws73_dli_relay_validate(unsigned int opcode, const unsigned char *params, size_t size);

#endif
