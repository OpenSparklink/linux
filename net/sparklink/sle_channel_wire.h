/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SLE_CHANNEL_WIRE_H
#define _SLE_CHANNEL_WIRE_H
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#endif

#define SL_CHANNEL_CMTC 2U
#define SL_CHANNEL_CUTC 31U
#define SL_CHANNEL_CAP_IDENTIFIER 0U /* valid identifier; independent of pending state */
#define SL_CHANNEL_CAP_QUERY 0xe2U /* basic only, MTU/MPS/version */
struct sl_channel_frame {
	unsigned int tcid, pi;
	const unsigned char *data;
	size_t length;
};
struct sl_channel_cap {
	unsigned int mtu, mps, version, modes;
};
int sl_channel_frame_decode(const unsigned char *data, size_t length,
			    struct sl_channel_frame *out);
int sl_channel_frame_encode(unsigned char *out, size_t capacity,
			    unsigned int remote_tcid, unsigned int pi,
			    const unsigned char *data, size_t length);
int sl_channel_cap_request(unsigned char *out, size_t capacity, unsigned int identifier);
int sl_channel_cap_response(unsigned char *out, size_t capacity, unsigned int identifier,
			    unsigned int requested, unsigned int maximum);
int sl_channel_cap_decode(const unsigned char *data, size_t length,
			  unsigned int *code, unsigned int *identifier,
			  unsigned int *requested, struct sl_channel_cap *cap);
#endif
