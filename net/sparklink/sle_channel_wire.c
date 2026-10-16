// SPDX-License-Identifier: GPL-2.0-only
/* Independently implemented T/XS20002 basic DTAP/CMTC subset.
 * No optional transport mode, dynamic channel, relay or security claim.
 */
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif
#include "sle_channel_wire.h"

static unsigned int get16(const unsigned char *p) { return p[0] | p[1] << 8; }
static unsigned int get32(const unsigned char *p) { return get16(p) | get16(p + 2) << 16; }
static void put16(unsigned char *p, unsigned int v) { p[0] = v; p[1] = v >> 8; }
static void put32(unsigned char *p, unsigned int v) { put16(p, v); put16(p + 2, v >> 16); }

int sl_channel_frame_decode(const unsigned char *data, size_t length,
			    struct sl_channel_frame *out)
{
	struct sl_channel_frame frame;
	size_t header;

	if (!data || !out || length < 4 || !data[0] || get16(data + 2) != length - 4)
		return -EPROTO;
	if (data[1])
		return -EOPNOTSUPP;
	header = data[0] <= 0x1d ? 4 : 5;
	if (length < header)
		return -EPROTO;
	frame.tcid = data[0];
	frame.pi = header == 5 ? data[4] : 0;
	if (header == 5 && !frame.pi)
		return -EPROTO;
	frame.data = data + header;
	frame.length = length - header;
	*out = frame;
	return 0;
}

int sl_channel_frame_encode(unsigned char *out, size_t capacity,
			    unsigned int remote_tcid, unsigned int pi,
			    const unsigned char *data, size_t length)
{
	size_t header = remote_tcid <= 0x1d ? 4 : 5;

	if (!out || !remote_tcid || remote_tcid > 255 || length > 65534 ||
	    (length && !data) || (header == 4 && pi) || (header == 5 && (!pi || pi > 255)))
		return -EINVAL;
	if (capacity < header + length)
		return -EMSGSIZE;
	out[0] = remote_tcid; out[1] = 0;
	put16(out + 2, length + header - 4);
	if (header == 5)
		out[4] = pi;
	if (length)
		memcpy(out + header, data, length);
	return header + length;
}

int sl_channel_cap_request(unsigned char *out, size_t capacity, unsigned int identifier)
{
	if (!out || identifier > 255 || capacity < 8)
		return -EINVAL;
	out[0] = 1; out[1] = identifier; put16(out + 2, 4);
	put32(out + 4, SL_CHANNEL_CAP_QUERY);
	return 8;
}

int sl_channel_cap_response(unsigned char *out, size_t capacity, unsigned int identifier,
			    unsigned int requested, unsigned int maximum)
{
	unsigned int accepted = requested & SL_CHANNEL_CAP_QUERY;
	size_t n = 8;

	if (!out || identifier > 255 || !maximum || maximum > 2042 || capacity < 16)
		return -EINVAL;
	out[0] = 2; out[1] = identifier; put32(out + 4, accepted);
	if (accepted & 2) { put16(out + n, 0); n += 2; } /* no optional modes */
	if (accepted & 0x20) { put16(out + n, maximum); n += 2; }
	if (accepted & 0x40) { put16(out + n, maximum); n += 2; }
	if (accepted & 0x80) { put16(out + n, 0x0101); n += 2; }
	put16(out + 2, n - 4);
	return n;
}

int sl_channel_cap_decode(const unsigned char *data, size_t length,
			  unsigned int *code, unsigned int *identifier,
			  unsigned int *requested, struct sl_channel_cap *cap)
{
	struct sl_channel_cap value = {0};
	unsigned int mask;
	size_t n = 8;

	if (!data || !code || !identifier || !requested || !cap || length < 8 ||
	    get16(data + 2) != length - 4)
		return -EPROTO;
	mask = get32(data + 4);
	if (data[0] == 1) {
		if (length != 8 || mask & ~0x1ffU)
			return -EPROTO;
	} else if (data[0] == 2) {
		if (mask & ~SL_CHANNEL_CAP_QUERY || (mask & 0x60) != 0x60)
			return -EOPNOTSUPP;
#define READ_CAP(bit, field) do { if (mask & (bit)) { if (n + 2 > length) return -EPROTO; value.field = get16(data + n); n += 2; } } while (0)
		READ_CAP(2, modes); READ_CAP(0x20, mtu); READ_CAP(0x40, mps); READ_CAP(0x80, version);
#undef READ_CAP
		if (n != length || !value.mtu || !value.mps || value.modes & ~7U)
			return -EPROTO;
	} else {
		return -EOPNOTSUPP;
	}
	*code = data[0]; *identifier = data[1]; *requested = mask; *cap = value;
	return 0;
}
