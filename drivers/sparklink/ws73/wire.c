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
		if (slot < 4 || slot > size - offset ||
		    wire_u16(data + offset + 2) > slot - 4)
			return -EPROTO;
		if (((data[offset] >> 4 == WS73_WIRE_BSLE_SERVICE &&
		      data[offset + 1] == WS73_WIRE_BSLE_QUEUE) ||
		     (data[offset] >> 4 == WS73_WIRE_SLE_SERVICE &&
		      data[offset + 1] == WS73_WIRE_SLE_QUEUE)) &&
		    (data[offset] & 0x0f))
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
		int ret;

		if ((service == WS73_WIRE_BSLE_SERVICE && queue == WS73_WIRE_BSLE_QUEUE) ||
		    (service == WS73_WIRE_SLE_SERVICE && queue == WS73_WIRE_SLE_QUEUE)) {
			ret = consumer(context, service, queue, netbuf + 4,
				       wire_u16(netbuf + 2));
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
	if (!data || !type || !message || size < 4 || wire_u16(data + 2) != size - 4)
		return -EPROTO;
	*type = wire_u16(data);
	if (*type != 2 && *type != 4)
		return -ENOMSG;
	if (size != 8)
		return -EPROTO;
	*message = wire_u32(data + 4);
	return 0;
}
