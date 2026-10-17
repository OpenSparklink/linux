/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SPARKLINK_VIRTUAL_TEST_H
#define _SPARKLINK_VIRTUAL_TEST_H

/* Private test-device control, not the public SparkLink socket/UAPI.
 * Opening this device creates one TEST-bus, standard-DLI query controller;
 * final control-file close removes it. No RF, connection or data capability.
 */
#include <linux/types.h>
#include <linux/ioctl.h>

struct sparklink_virtual_control {
	__u32 delay_ms, drop_next, fail_next, reserved;
};

struct sparklink_virtual_status {
	/* submitted counts driver attempts, delivered counts ingress attempts;
	 * delivered covers delayed command replies, not injected hardware errors.
	 * Neither means Host resolution, controller completion or peer delivery.
	 */
	__u64 generation, submitted, delivered, dropped, failed;
	__u32 id, live, pending, reserved;
};

#define SPARKLINK_VIRTUAL_CONFIG _IOW('V', 0, struct sparklink_virtual_control)
#define SPARKLINK_VIRTUAL_STATUS _IOR('V', 1, struct sparklink_virtual_status)
/* Explicit TEST backend only: one well-framed standard hardware-error event.
 * The input is a u32 in [0,255]. No production Native ioctl injection exists.
 */
#define SPARKLINK_VIRTUAL_HARDWARE_ERROR _IOW('V', 2, __u32)

#endif
