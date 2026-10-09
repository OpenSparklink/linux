// SPDX-License-Identifier: GPL-2.0-only
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

#include "discovery.h"

static unsigned int disc_u16(const unsigned char *p)
{
	return (unsigned int)p[0] | (unsigned int)p[1] << 8;
}

static void disc_put16(unsigned char *p, unsigned int value)
{
	p[0] = value;
	p[1] = value >> 8;
}

int ws73_discovery_validate_command(unsigned int opcode, const unsigned char *params,
				    size_t size)
{
	if (size && !params)
		return -EINVAL;
	switch (opcode) {
	case 0x0c02:
		/* Structural size only. Parameter capability/range errors belong
		 * to the controller; no standard address enum is imposed on WS73.
		 */
		return size == WS73_DISC_ADV_PARAM_SIZE ? 0 : -EINVAL;
	case 0x0c03:
	case 0x0c04:
		if (size < WS73_DISC_ADV_DATA_HEADER || params[0] > 0xef ||
		    params[2] > WS73_DISC_ADV_DATA_MAX ||
		    size != WS73_DISC_ADV_DATA_HEADER + params[2])
			return -EINVAL;
		return params[1] == 3 ? 0 : -EOPNOTSUPP;
	case 0x0c05:
		return size == WS73_DISC_ADV_ENABLE_SIZE && params[0] <= 1 &&
		       params[1] <= 0xef ? 0 : -EINVAL;
	case 0x1001:
		if (size != WS73_DISC_SCAN_PARAM_SIZE || params[1] > 3 || params[3] > 1)
			return -EINVAL;
		/* Exactly frame type 1, never choose/drop one of several PHYs. */
		if (params[2] != 1)
			return -EOPNOTSUPP;
		return disc_u16(params + 4) && disc_u16(params + 6) &&
		       disc_u16(params + 6) <= disc_u16(params + 4) ? 0 : -EINVAL;
	case 0x1002:
		return size == WS73_DISC_SCAN_ENABLE_SIZE && params[0] <= 1 &&
		       params[1] <= 1 ? 0 : -EINVAL;
	default:
		return -EOPNOTSUPP;
	}
}

int ws73_discovery_data(unsigned char *out, size_t capacity, unsigned int handle,
			const unsigned char *data, size_t size)
{
	if (!out || (size && !data) || handle > 0xef)
		return -EINVAL;
	if (size > WS73_DISC_ADV_DATA_MAX || capacity < WS73_DISC_ADV_DATA_HEADER + size)
		return -EMSGSIZE;
	out[0] = handle;
	out[1] = 3; /* complete, no standard selection byte */
	out[2] = size;
	if (size)
		memcpy(out + WS73_DISC_ADV_DATA_HEADER, data, size);
	return WS73_DISC_ADV_DATA_HEADER + size;
}

int ws73_discovery_adv_enable(unsigned char *out, size_t capacity, unsigned int enable,
			      unsigned int handle, unsigned int duration,
			      unsigned int max_events)
{
	if (!out || enable > 1 || handle > 0xef || duration > 0xffff || max_events > 0xff)
		return -EINVAL;
	if (capacity < WS73_DISC_ADV_ENABLE_SIZE)
		return -EMSGSIZE;
	out[0] = enable;
	out[1] = handle;
	disc_put16(out + 2, duration);
	out[4] = max_events;
	return WS73_DISC_ADV_ENABLE_SIZE;
}

int ws73_discovery_scan_params(unsigned char *out, size_t capacity,
			       unsigned int own_address_type, unsigned int filter,
			       unsigned int frame_types, unsigned int active,
			       unsigned int interval, unsigned int window)
{
	if (!out || own_address_type > 0xff || filter > 3 || active > 1 ||
	    !interval || interval > 0xffff || !window || window > interval)
		return -EINVAL;
	if (frame_types != 1)
		return -EOPNOTSUPP;
	if (capacity < WS73_DISC_SCAN_PARAM_SIZE)
		return -EMSGSIZE;
	out[0] = own_address_type;
	out[1] = filter;
	out[2] = frame_types;
	out[3] = active;
	disc_put16(out + 4, interval);
	disc_put16(out + 6, window);
	return WS73_DISC_SCAN_PARAM_SIZE;
}

int ws73_discovery_scan_enable(unsigned char *out, size_t capacity,
			       unsigned int enable, unsigned int filter_duplicates)
{
	if (!out || enable > 1 || filter_duplicates > 1)
		return -EINVAL;
	if (capacity < WS73_DISC_SCAN_ENABLE_SIZE)
		return -EMSGSIZE;
	out[0] = enable;
	out[1] = filter_duplicates;
	return WS73_DISC_SCAN_ENABLE_SIZE;
}

int ws73_discovery_report_decode(const unsigned char *params, size_t size,
				 struct ws73_discovery_report *report)
{
	unsigned int length;

	if (!params || !report)
		return -EINVAL;
	if (size < WS73_DISC_REPORT_HEADER || size > WS73_DISC_REPORT_MAX)
		return -EPROTO;
	length = params[22];
	if (size != WS73_DISC_REPORT_HEADER + length)
		return -EPROTO;
	report->header = params;
	report->data = params + WS73_DISC_REPORT_HEADER;
	report->data_size = length;
	/* Explicit conversion is independent of the compiler's char signedness. */
	report->rssi = params[21] < 128 ? params[21] : (int)params[21] - 256;
	return 0;
}
