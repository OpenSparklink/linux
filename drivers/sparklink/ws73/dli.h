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

/* Runtime support policy: metadata queries only until the discovery Host
 * transaction and report route are implemented. No I/O or state mutation.
 */
int ws73_dli_validate_command(unsigned int opcode, const unsigned char *params,
			      size_t size);

/* Validate one A2 management event slot, not an HCC aggregate. WS73 owns the
 * successful Complete return schemas (including 0C02's selected TX power).
 * Unknown opcode returns remain opaque; Status, credit-only and framing are
 * still checked. A rejected reply must never release a Host transaction.
 */
int ws73_dli_validate_reply(const unsigned char *data, size_t size);

/* Recognize WS73 connection/disconnection outcomes, including the controller's
 * opcode-block event numbers. Validate framing and the known prefix only;
 * connection extension bytes, status, role and address type remain opaque.
 * No command completion, connection ownership or Ready state is inferred.
 * Returns -ENOMSG for another event kind, -EPROTO for a malformed outcome.
 */
int ws73_dli_validate_link_event(const unsigned char *data, size_t size);

/* Fresh BSLE-open instance only. The caller provides its initial probe
 * window (one); every subsequent grant is an absolute controller credit.
 * Do not call again after an uncertain send/timeout. Publish info only on
 * full success; this still does not register a Runtime or advertise Ready.
 */
int ws73_dli_query(struct ws73_bsle_io *io, unsigned int *credits,
		   struct ws73_dli_info *info, struct ws73_dli_result *result);

#endif
