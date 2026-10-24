/* SPDX-License-Identifier: GPL-2.0-only */
/* Historical test encodings only. No definition is exported by current UAPI.
 * Positive legacy tests require their recorded old kernel; current kernels
 * reject this number with ENOTTY. Never use this in a production driver. */
#ifndef SPARKLINK_RETIRED_EVENT_ABI_H
#define SPARKLINK_RETIRED_EVENT_ABI_H
struct sle_dli_event {
	__u8 event_type, status;
	__u16 handle, opcode, data_len;
	__u8 data[240], addr[6], _pad[2];
};
#define SL_IOCTL_DLI_POLL_EVENT _IOR(SL_MAGIC, 0x82, struct sle_dli_event)
#endif
