/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPARKLINK_NATIVE_OPEN_FIXTURE_H
#define SPARKLINK_NATIVE_OPEN_FIXTURE_H
#include <linux/types.h>
#include <linux/ioctl.h>

/* Guest-only test device, not SparkLink UAPI or a transport for deployment. */
struct native_open_probe {
	__u32 slot;
	__u32 mode; /* 0: blocked success; 1: blocked -EIO; 2: immediate success */
	__u64 generation;
	__u32 id;
	__u32 flags; /* entered=1, released=2, registered=4, retiring=8, retired=16 */
	__s32 result;
	__u32 gets;
	__u32 puts;
	__u32 closes;
	__u32 sends;
	__u32 reserved;
};
#define NATIVE_OPEN_START _IOWR('N', 1, struct native_open_probe)
#define NATIVE_OPEN_QUERY _IOWR('N', 2, struct native_open_probe)
#define NATIVE_OPEN_RELEASE _IOWR('N', 3, struct native_open_probe)
#define NATIVE_OPEN_RETIRE _IOWR('N', 4, struct native_open_probe)
#define NATIVE_OPEN_STALE _IOWR('N', 5, struct native_open_probe)
#endif
