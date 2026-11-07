/* SPDX-License-Identifier: GPL-2.0-only */
/* Historical read/copy tests only. Current kernels reject these interfaces. */
#ifndef SPARKLINK_RETIRED_READ_ABI_H
#define SPARKLINK_RETIRED_READ_ABI_H
struct sle_wire_event { __u8 event_type, payload_len, payload[40], _pad[2]; };
struct sle_event_stats { __u32 pending, _pad; __u64 total_enqueued, total_dropped, total_delivered; };
#define SL_IOCTL_EVENT_COUNT _IO(SL_MAGIC, 0x70)
#define SL_IOCTL_EVENT_STATS _IOR(SL_MAGIC, 0x71, struct sle_event_stats)
#endif
