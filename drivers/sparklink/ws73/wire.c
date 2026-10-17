// SPDX-License-Identifier: GPL-2.0-only
/*
 * WS73 USB/HCC wire codec, independently implemented from the SDK layouts in
 * hcc_usb_host.h, hcc_comm.h and customize_bsle_ext.h. libws73-usb's wire
 * observations are additional evidence, not hardware validation of this code.
 */
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

#include "wire.h"

static unsigned int wire_u16(const unsigned char *data)
{
	return (unsigned int)data[0] | (unsigned int)data[1] << 8;
}

static unsigned int wire_u32(const unsigned char *data)
{
	return wire_u16(data) | wire_u16(data + 2) << 16;
}

static void wire_put32(unsigned char *data, unsigned int value)
{
	unsigned int i;

	for (i = 0; i < 4; i++)
		data[i] = value >> (i * 8);
}

static void wire_package(unsigned char *out, size_t size, unsigned int sequence)
{
	memset(out, 0, size);
	wire_put32(out + 4, size);
	wire_put32(out + 8, sequence);
}

int ws73_wire_control(unsigned char *out, size_t capacity,
		      unsigned int sequence, unsigned int descriptor,
		      unsigned int queue)
{
	if (!out || capacity < WS73_WIRE_CONTROL_SIZE || descriptor > 1 ||
	    queue > 255 || (!descriptor && queue))
		return -EINVAL;
	wire_package(out, WS73_WIRE_CONTROL_SIZE, sequence);
	wire_put32(out, 3); /* USB_HCC_CONTROL_MSG */
	wire_put32(out + 4, 0);
	wire_put32(out + 12, descriptor);
	out[16] = queue;
	return WS73_WIRE_CONTROL_SIZE;
}

int ws73_wire_customize(unsigned char *out, size_t capacity,
			unsigned int sequence, const unsigned char *data,
			size_t size)
{
	if (!out || !data || capacity < WS73_WIRE_CUSTOM_SIZE ||
	    size != WS73_WIRE_CUSTOM_DATA_SIZE)
		return -EINVAL;
	wire_package(out, WS73_WIRE_CUSTOM_SIZE, sequence);
	/* The vendor's TX BSLE allocation is 800 bytes, including its HCC
	 * header; hcc_tx_data stamps this allocation size in pay_len. This
	 * TX quirk is not used when interpreting device RX payload lengths.
	 */
	out[64] = 0x50;
	out[65] = WS73_WIRE_BSLE_QUEUE;
	out[66] = 0x20;
	out[67] = 0x03;
	out[70] = size; /* CUSTOMIZE_DATA tag: type=0, len=140 */
	memcpy(out + 72, data, size);
	return WS73_WIRE_CUSTOM_SIZE;
}

int ws73_wire_pm(unsigned char *out, size_t capacity, unsigned int sequence,
		 const unsigned char *data, size_t size)
{
	if (!out || !data || capacity < 128 || size != 4)
		return -EINVAL;
	wire_package(out, 128, sequence);
	out[64] = 0x19; /* OAM service, platform-config sub-type */
	out[65] = 9;
	out[66] = 32; /* Vendor TX netbuf padded to 32 bytes */
	out[70] = 4; /* PM_INI message id=0, length=4 */
	memcpy(out + 72, data, size);
	return 128;
}

int ws73_wire_chip_request(unsigned char *out, size_t capacity,
			   unsigned int sequence)
{
	if (!out || capacity < 128)
		return -EINVAL;
	wire_package(out, 128, sequence);
	out[64] = 0x19; /* OAM / PLAT_MSG_TRANSFER */
	out[65] = WS73_WIRE_PLAT_QUEUE;
	out[66] = 32;
	out[68] = 16; /* H2D_PLAT_CFG_MSG_GET_CHIP_TYPE */
	out[70] = 1;  /* SDK input_data = one zero byte */
	return 128;
}

int ws73_wire_chip_reply(const unsigned char *data, size_t size,
			 struct ws73_chip_info *info)
{
	/* plat_hcc_srv + plat_misc: msg_id/len, result u32, output_len u32,
	 * then two output bytes. HCC allocation padding is not output data.
	 * Commit only a completely validated reply; unknown is never U.
	 */
	if (!data || !info || size < 4)
		return -EPROTO;
	if (wire_u16(data) != 10) /* D2H_*_GET_CHIP_TYPE_COMPLETE */
		return -ENOMSG;
	if (wire_u16(data + 2) < 10 || wire_u16(data + 2) > size - 4 || size < 14 ||
	    wire_u32(data + 8) != 2)
		return -EPROTO;
	if (wire_u32(data + 4))
		return -EIO;
	if (data[12] > 2 || data[13] > 2)
		return -EOPNOTSUPP;
	*info = (struct ws73_chip_info) { .model = data[12], .bus = data[13] };
	return 0;
}

int ws73_wire_command(unsigned char *out, size_t capacity, unsigned int sequence,
		      unsigned int opcode, const unsigned char *params, size_t size)
{
	size_t slot, total;

	/* The bootstrap profile only uses short commands. Keep the known
	 * 255-byte baseline rather than pretending 0x0401 negotiates a limit:
	 * that opcode means SetEventMask on this WS73 dialect.
	 */
	if (!out || !opcode || opcode > 65535 || size > 255 || (size && !params))
		return -EINVAL;
	slot = 9 + size;
	if (slot < 64)
		slot = 64;
	total = 64 + slot;
	if (capacity < total)
		return -EMSGSIZE;
	wire_package(out, total, sequence);
	out[64] = 0xa0;
	out[65] = WS73_WIRE_SLE_QUEUE;
	out[66] = (5 + size) & 255;
	out[67] = (5 + size) >> 8;
	out[68] = 0xa1;
	out[69] = opcode;
	out[70] = opcode >> 8;
	out[71] = size;
	out[72] = size >> 8;
	if (size)
		memcpy(out + 73, params, size);
	return total;
}

int ws73_wire_acb_fragment(unsigned char *out, size_t capacity, unsigned int sequence,
		  unsigned int handle, unsigned int boundary, unsigned int maximum,
		  const unsigned char *payload, size_t size)
{
	size_t slot, total;

	/* SDK111/HCC carries standard A3 followed by handle/flags and length.
	 * Typed PB, low priority, reserved bit zero; one physical packet credit.
	 * Never copy the reference single-link builder's hardcoded handle 0.
	 */
	if (!out || handle > 0x0fff || boundary > 3 || !maximum || maximum > 2047 ||
	    !size || !payload)
		return -EINVAL;
	if (size > maximum)
		return -EMSGSIZE;
	slot = 9 + size;
	if (slot < 64)
		slot = 64;
	total = 64 + slot;
	if (capacity < total)
		return -EMSGSIZE;
	wire_package(out, total, sequence);
	out[64] = 0xa0;
	out[65] = WS73_WIRE_SLE_QUEUE;
	out[66] = (5 + size) & 255;
	out[67] = (5 + size) >> 8;
	out[68] = 0xa3;
	out[69] = handle;
	out[70] = (handle >> 8) | (boundary << 4);
	out[71] = size;
	out[72] = size >> 8;
	memcpy(out + 73, payload, size);
	return total;
}

int ws73_wire_acb(unsigned char *out, size_t capacity, unsigned int sequence,
                  unsigned int handle, unsigned int maximum,
                  const unsigned char *payload, size_t size)
{
    return ws73_wire_acb_fragment(out, capacity, sequence, handle, 0, maximum, payload, size);
}

int ws73_wire_acb_fragment_decode(const unsigned char *data, size_t size,
			unsigned int maximum, unsigned int *handle,
			unsigned int *boundary, const unsigned char **payload, size_t *payload_size)
{
	unsigned int length, identity;

	if (!data || !handle || !boundary || !payload || !payload_size ||
	    !maximum || maximum > 2047)
		return -EINVAL;
	if (size < 5 || data[0] != 0xa3)
		return -EPROTO;
	length = wire_u16(data + 3);
	identity = wire_u16(data + 1);
	if (!length || length != size - 5 || length > maximum)
		return -EPROTO;
	/* Bit 14 is reserved; PB and priority are independent of the handle.
	 * Core reassembles PB fragments, never treats them as complete SDUs.
	 */
	if (identity & 0x4000)
		return -EOPNOTSUPP;
	*handle = identity & 0x0fff;
	*boundary = (identity >> 12) & 3;
	*payload = data + 5;
	*payload_size = length;
	return 0;
}

int ws73_wire_acb_decode(const unsigned char *data, size_t size,
			unsigned int maximum, unsigned int *handle,
			const unsigned char **payload, size_t *payload_size)
{
	unsigned int identity, boundary;
	const unsigned char *bytes;
	size_t count;
	int ret;

	if (!handle || !payload || !payload_size)
		return -EINVAL;
	ret = ws73_wire_acb_fragment_decode(data, size, maximum, &identity, &boundary, &bytes, &count);
	if (ret)
		return ret;
	if (boundary)
		return -EOPNOTSUPP;
	*handle = identity;
	*payload = bytes;
	*payload_size = count;
	return 0;
}

int ws73_wire_receive(const unsigned char *data, size_t size,
		      ws73_wire_consumer consumer, void *context)
{
	size_t offset;
	unsigned int i, count = 0;

	if (!data || !consumer || size < 12 || size > WS73_WIRE_RX_MAX)
		return -EINVAL;
	/* The SDK permits an empty USB notification. Reject nonzero tails. */
	if (!wire_u32(data) && !wire_u32(data + 4)) {
		for (offset = 0; offset < size; offset++)
			if (data[offset])
				return -EPROTO;
		return 0;
	}
	if (size < WS73_WIRE_RX_HEADER_SIZE || wire_u32(data) != 2 ||
	    wire_u32(data + 4) != size)
		return -EPROTO;

	/* Pass one validates all slot boundaries, including unknown services.
	 * Nothing from a malformed aggregate may advance the handshake.
	 */
	offset = WS73_WIRE_RX_HEADER_SIZE;
	for (i = 0; i < WS73_WIRE_RX_SLOTS; i++) {
		size_t slot = wire_u16(data + 12 + i * 2);

		if (!slot) {
			unsigned int j;

			for (j = i + 1; j < WS73_WIRE_RX_SLOTS; j++)
				if (wire_u16(data + 12 + j * 2))
					return -EPROTO;
			break;
		}
		if (slot < 4 || slot > size - offset)
			return -EPROTO;
		/* SDK110 OAM/platform RX advertises the whole allocation,
		 * including its four-byte HCC header (real E GET_CHIP_TYPE:
		 * slot=96, pay_len=96, platform len=88). This is confined to
		 * the exact platform route; never relax SLE/ACB bounds. */
		if (wire_u16(data + offset + 2) > slot - 4 &&
		    !(data[offset] == 0x19 && data[offset + 1] == WS73_WIRE_PLAT_QUEUE &&
		      wire_u16(data + offset + 2) == slot))
			return -EPROTO;
		/* SDK SLE RX routes by service/queue and ignores sub_type.
		 * Real 1.10.111 buffer Complete has tag a1, not a0. Keep
		 * the distinct BSLE message profile's reserved subtype check.
		 */
		if ((data[offset] >> 4 == WS73_WIRE_BSLE_SERVICE &&
		     data[offset + 1] == WS73_WIRE_BSLE_QUEUE) &&
		    (data[offset] & 0x0f))
			return -EPROTO;
		if (data[offset] >> 4 == WS73_WIRE_PLAT_SERVICE &&
		    data[offset + 1] == WS73_WIRE_PLAT_QUEUE &&
		    (data[offset] & 0x0f) != 9)
			return -EPROTO;
		offset += slot;
		count++;
	}
	if (offset != size)
		return -EPROTO;

	offset = WS73_WIRE_RX_HEADER_SIZE;
	for (i = 0; i < count; i++) {
		const unsigned char *netbuf = data + offset;
		unsigned int service = netbuf[0] >> 4;
		unsigned int queue = netbuf[1];
		size_t payload = wire_u16(netbuf + 2);
		int ret;

		if (netbuf[0] == 0x19 && queue == WS73_WIRE_PLAT_QUEUE &&
		    payload == wire_u16(data + 12 + i * 2))
			payload -= 4;

		if ((service == WS73_WIRE_BSLE_SERVICE && queue == WS73_WIRE_BSLE_QUEUE) ||
		    (service == WS73_WIRE_SLE_SERVICE && queue == WS73_WIRE_SLE_QUEUE) ||
		    (service == WS73_WIRE_PLAT_SERVICE && queue == WS73_WIRE_PLAT_QUEUE)) {
			ret = consumer(context, service, queue, netbuf + 4,
				       payload);
			if (ret)
				return ret;
		}
		offset += wire_u16(data + 12 + i * 2);
	}
	return 0;
}

int ws73_wire_status(const unsigned char *data, size_t size,
		     unsigned int *type, unsigned int *message)
{
	if (!data || !type || !message || size < 4 || wire_u16(data + 2) > size - 4)
		return -EPROTO;
	*type = wire_u16(data);
	if (*type != 2 && *type != 4)
		return -ENOMSG;
	/* RX HCC pay_len can include allocation padding. Real customize ACKs
	 * advertise 32 bytes while the BSLE tag declares a four-byte message.
	 * Consume only that declared message; padding is not another status and
	 * need not be zero. Aggregate bounds were validated by wire_receive.
	 */
	if (wire_u16(data + 2) != 4 || size < 8)
		return -EPROTO;
	*message = wire_u32(data + 4);
	return 0;
}
