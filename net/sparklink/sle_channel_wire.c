// SPDX-License-Identifier: GPL-2.0-only
/* Independently implemented T/XS20002 basic DTAP/CMTC subset.
 * Basic unicast dynamic signaling codec; no optional mode/relay/security claim.
 */
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif
#include "sle_channel_wire.h"

static unsigned int get16(const unsigned char *p)
{
	return p[0] | p[1] << 8;
}
static unsigned int get32(const unsigned char *p)
{
	return get16(p) | get16(p + 2) << 16;
}
static void put16(unsigned char *p, unsigned int v)
{
	p[0] = v;
	p[1] = v >> 8;
}
static void put32(unsigned char *p, unsigned int v)
{
	put16(p, v);
	put16(p + 2, v >> 16);
}

int sl_channel_frame_decode(const unsigned char *data, size_t length,
			    struct sl_channel_frame *out)
{
	struct sl_channel_frame frame;
	size_t header;

	if (!data || !out || length < 4 || !data[0] ||
	    get16(data + 2) != length - 4)
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
	    (length && !data) || (header == 4 && pi) ||
	    (header == 5 && (!pi || pi > 255)))
		return -EINVAL;
	if (capacity < header + length)
		return -EMSGSIZE;
	out[0] = remote_tcid;
	out[1] = 0;
	put16(out + 2, length + header - 4);
	if (header == 5)
		out[4] = pi;
	if (length)
		memcpy(out + header, data, length);
	return header + length;
}

int sl_channel_cap_request(unsigned char *out, size_t capacity,
			   unsigned int identifier)
{
	if (!out || identifier > 255 || capacity < 8)
		return -EINVAL;
	out[0] = 1;
	out[1] = identifier;
	put16(out + 2, 4);
	put32(out + 4, SL_CHANNEL_CAP_QUERY);
	return 8;
}

int sl_channel_cap_response(unsigned char *out, size_t capacity,
			    unsigned int identifier, unsigned int requested,
			    unsigned int maximum, unsigned int maximum_mps)
{
	unsigned int accepted = requested & SL_CHANNEL_CAP_QUERY;
	size_t n = 8;

	if (!out || identifier > 255 || !maximum || maximum > 2042 ||
	    maximum_mps < 20 || maximum_mps > 2047 || capacity < 16)
		return -EINVAL;
	out[0] = 2;
	out[1] = identifier;
	put32(out + 4, accepted);
	if (accepted & 2) {
		put16(out + n, 0);
		n += 2;
	} /* no optional modes */
	if (accepted & 0x20) {
		put16(out + n, maximum);
		n += 2;
	}
	if (accepted & 0x40) {
		put16(out + n, maximum_mps);
		n += 2;
	}
	if (accepted & 0x80) {
		put16(out + n, 0x0101);
		n += 2;
	}
	put16(out + 2, n - 4);
	return n;
}

int sl_channel_cap_decode(const unsigned char *data, size_t length,
			  unsigned int *code, unsigned int *identifier,
			  unsigned int *requested, struct sl_channel_cap *cap)
{
	struct sl_channel_cap value = { 0 };
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
#define READ_CAP(bit, field)                           \
	do {                                           \
		if (mask & (bit)) {                    \
			if (n + 2 > length)            \
				return -EPROTO;        \
			value.field = get16(data + n); \
			n += 2;                        \
		}                                      \
	} while (0)
		READ_CAP(2, modes);
		READ_CAP(0x20, mtu);
		READ_CAP(0x40, mps);
		READ_CAP(0x80, version);
#undef READ_CAP
		if (n != length || !value.mtu || !value.mps ||
		    value.modes & ~7U)
			return -EPROTO;
	} else {
		return -EOPNOTSUPP;
	}
	*code = data[0];
	*identifier = data[1];
	*requested = mask;
	*cap = value;
	return 0;
}

static int unicast_tcid(unsigned int tcid)
{
	return tcid >= 0x80 && tcid <= 0xdf;
}

int sl_channel_signal_decode(const unsigned char *bytes, size_t length,
			     struct sl_channel_signal *out)
{
	struct sl_channel_signal s = { 0 };
	size_t offset, n;

	if (!bytes || !out || length < 4 || length > 32 ||
	    get16(bytes + 2) != length - 4)
		return -EPROTO;
	s.code = bytes[0];
	s.identifier = bytes[1];
	if (s.code == SL_CMTC_CONNECT_REQ) {
		if (length < 14 || !unicast_tcid(bytes[4]) || bytes[6] & ~3U)
			return -EPROTO;
		if (bytes[7])
			return -EOPNOTSUPP; /* basic mode only */
		s.source = bytes[4];
		s.exclusive = bytes[6] & 1;
		s.measurement = (bytes[6] >> 1) & 1;
		s.mtu = get16(bytes + 8);
		s.mps = get16(bytes + 10);
		s.slqi_count = bytes[12];
		if (!s.mtu || !s.mps || !s.slqi_count || s.slqi_count > 8 ||
		    13 + s.slqi_count > length)
			return -EPROTO;
		memcpy(s.slqi, bytes + 13, s.slqi_count);
		n = 13 + s.slqi_count;
		offset = bytes[5] ? (size_t)bytes[5] + 4 : length;
		if (offset != n)
			return -EPROTO;
		if (bytes[5]) {
			if (length - n != 8)
				return -EPROTO;
			if (get16(bytes + n) != 1)
				return -EOPNOTSUPP; /* no LC/MC or unknown extensions */
			s.ports = 1;
			s.destination_port = get16(bytes + n + 2);
			s.source_port = get16(bytes + n + 4);
			s.aid = get16(bytes + n + 6);
		}
	} else if (s.code == SL_CMTC_CONNECT_RSP) {
		if (length != 8 || !unicast_tcid(bytes[4]) || bytes[6] > 4)
			return -EPROTO;
		if (bytes[7])
			return -EOPNOTSUPP;
		s.source = bytes[4];
		s.destination = bytes[5];
		s.result = bytes[6];
		if ((!s.result && !unicast_tcid(s.destination)) ||
		    (s.result && s.destination && !unicast_tcid(s.destination)))
			return -EPROTO;
	} else if (s.code == SL_CMTC_CLOSE_REQ || s.code == SL_CMTC_CLOSE_RSP) {
		if (length != (s.code == SL_CMTC_CLOSE_REQ ? 6U : 7U) ||
		    !unicast_tcid(bytes[4]) || !unicast_tcid(bytes[5]))
			return -EPROTO;
		s.source = bytes[4];
		s.destination = bytes[5];
		if (s.code == SL_CMTC_CLOSE_RSP && bytes[6])
			return -EPROTO; /* only success is defined on wire */
	} else {
		return -EOPNOTSUPP;
	}
	*out = s;
	return 0;
}

int sl_channel_signal_encode(unsigned char *bytes, size_t capacity,
			     const struct sl_channel_signal *s)
{
	unsigned char wire[32] = { 0 };
	size_t n;
	struct sl_channel_signal checked;

	if (!bytes || !s || s->identifier > 255 || !unicast_tcid(s->source))
		return -EINVAL;
	wire[0] = s->code;
	wire[1] = s->identifier;
	wire[4] = s->source;
	if (s->code == SL_CMTC_CONNECT_REQ) {
		if (!s->mtu || s->mtu > 65535 || !s->mps || s->mps > 65535 ||
		    s->exclusive > 1 || s->measurement > 1 || s->ports > 1 ||
		    !s->slqi_count || s->slqi_count > 8 ||
		    s->source_port > 65535 || s->destination_port > 65535 ||
		    s->aid > 65535)
			return -EINVAL;
		wire[6] = s->exclusive | (s->measurement << 1);
		put16(wire + 8, s->mtu);
		put16(wire + 10, s->mps);
		wire[12] = s->slqi_count;
		memcpy(wire + 13, s->slqi, s->slqi_count);
		n = 13 + s->slqi_count;
		if (s->ports) {
			wire[5] = n - 4;
			put16(wire + n, 1);
			put16(wire + n + 2, s->destination_port);
			put16(wire + n + 4, s->source_port);
			put16(wire + n + 6, s->aid);
			n += 8;
		}
	} else if (s->code == SL_CMTC_CONNECT_RSP) {
		if (s->destination > 255 || s->result > 4)
			return -EINVAL;
		wire[5] = s->destination;
		wire[6] = s->result;
		n = 8;
	} else if (s->code == SL_CMTC_CLOSE_REQ ||
		   s->code == SL_CMTC_CLOSE_RSP) {
		if (!unicast_tcid(s->destination) || s->result)
			return -EINVAL;
		wire[5] = s->destination;
		n = s->code == SL_CMTC_CLOSE_REQ ? 6 : 7;
	} else {
		return -EOPNOTSUPP;
	}
	put16(wire + 2, n - 4);
	if (sl_channel_signal_decode(wire, n, &checked))
		return -EINVAL;
	if (capacity < n)
		return -EMSGSIZE;
	memcpy(bytes, wire, n);
	return n;
}
