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

int ws73_discovery_ms_slots(unsigned long long ms, unsigned int bits,
			    unsigned int *slots)
{
	unsigned int max;

	if (!slots || (bits != 16 && bits != 24) || !ms)
		return -EINVAL;
	max = (1U << bits) - 1;
	if (ms > max / 8U)
		return -ERANGE;
	*slots = ms * 8U;
	return 0;
}

int ws73_discovery_adv_params(unsigned char *out, size_t capacity,
			      const struct sparklink_discovery_adv_params *p)
{
	if (!out || !p || p->handle > 0xef || p->mode > 0xff ||
	    p->gt_role > 0xff || p->interval_min > 0xffffff ||
	    p->interval_max > 0xffffff || p->channel_map > 0xff ||
	    p->own_address_type > 0xff || p->peer_address_type > 0xff ||
	    p->filter > 0xff || p->tx_power < -128 || p->tx_power > 127 ||
	    p->primary_frame > 0xff || p->secondary_frame > 0xff ||
	    p->secondary_phy > 0xff || p->secondary_pilot > 0xff ||
	    p->secondary_mcs > 0xff || p->secondary_max_skip > 0xff ||
	    p->sid > 0xff || p->request_notification > 0xff ||
	    p->max_requests > 0xff || p->request_rx_duration > 0xffff ||
	    p->conn_interval_min > 0xffff || p->conn_interval_max > 0xffff ||
	    p->conn_max_latency > 0xffff || p->supervision_timeout > 0xffff ||
	    p->min_event_length > 0xffff || p->max_event_length > 0xffff)
		return -EINVAL;
	if (capacity < WS73_DISC_ADV_PARAM_SIZE)
		return -EMSGSIZE;

	out[0] = p->handle;
	out[1] = p->mode;
	out[2] = p->gt_role;
	out[3] = p->interval_min;
	out[4] = p->interval_min >> 8;
	out[5] = p->interval_min >> 16;
	out[6] = p->interval_max;
	out[7] = p->interval_max >> 8;
	out[8] = p->interval_max >> 16;
	out[9] = p->channel_map;
	out[10] = p->own_address_type;
	out[11] = p->peer_address_type;
	memcpy(out + 12, p->own_address, sizeof(p->own_address));
	memcpy(out + 18, p->peer_address, sizeof(p->peer_address));
	out[24] = p->filter;
	out[25] = (unsigned char)p->tx_power;
	out[26] = p->primary_frame;
	out[27] = p->secondary_frame;
	out[28] = p->secondary_phy;
	out[29] = p->secondary_pilot;
	out[30] = p->secondary_mcs;
	out[31] = p->secondary_max_skip;
	out[32] = p->sid;
	out[33] = p->request_notification;
	out[34] = p->max_requests;
	disc_put16(out + 35, p->request_rx_duration);
	disc_put16(out + 37, p->conn_interval_min);
	disc_put16(out + 39, p->conn_interval_max);
	disc_put16(out + 41, p->conn_max_latency);
	disc_put16(out + 43, p->supervision_timeout);
	disc_put16(out + 45, p->min_event_length);
	disc_put16(out + 47, p->max_event_length);
	return WS73_DISC_ADV_PARAM_SIZE;
}

int ws73_discovery_validate_command(unsigned int opcode, const unsigned char *params,
				    size_t size)
{
	if (size && !params)
		return -EINVAL;
	switch (opcode) {
	case 0x0c02:
		/* Structural size and handle. Parameter capability/range errors belong
		 * to the controller; no standard address enum is imposed on WS73.
		 */
		return size == WS73_DISC_ADV_PARAM_SIZE && params[0] <= 0xef ? 0 : -EINVAL;
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

/* Validate the typed sequence shape independently at transfer time. Raw DLI
 * still uses its metadata-only whitelist. A recipe tag is kernel-owned and
 * cannot be supplied by the raw command ioctl.
 */
int ws73_discovery_validate_step(unsigned int operation, unsigned int step,
				 unsigned int count, unsigned int opcode,
				 const unsigned char *params, size_t size)
{
	unsigned int expected;
	int enable = -1;

	if (step >= count)
		return -EINVAL;
	switch (operation) {
	case SPARKLINK_DISCOVERY_ADV_START:
		if (count != 3 && count != 4)
			return -EINVAL;
		if (step == 0)
			expected = 0x0c02;
		else if (step == 1)
			expected = 0x0c03;
		else if (step == count - 1)
			expected = 0x0c05;
		else
			expected = 0x0c04;
		if (step == count - 1)
			enable = 1;
		break;
	case SPARKLINK_DISCOVERY_ADV_CONFIGURE_OFF:
		if (count != 2)
			return -EINVAL;
		expected = step == 0 ? 0x0c02 : 0x0c05;
		if (step == 1)
			enable = 0;
		break;
	case SPARKLINK_DISCOVERY_ADV_STOP:
		if (count != 1)
			return -EINVAL;
		expected = 0x0c05;
		enable = 0;
		break;
	case SPARKLINK_DISCOVERY_SCAN_INITIALIZE_OFF:
		if (count != 3)
			return -EINVAL;
		expected = step == 0 ? 0x1001 : 0x1002;
		if (step != 0)
			enable = step == 1;
		break;
	case SPARKLINK_DISCOVERY_SCAN_START:
		if (count != 2)
			return -EINVAL;
		expected = step == 0 ? 0x1001 : 0x1002;
		if (step == 1)
			enable = operation == SPARKLINK_DISCOVERY_SCAN_START;
		break;
	case SPARKLINK_DISCOVERY_SCAN_STOP:
		if (count != 1)
			return -EINVAL;
		expected = 0x1002;
		enable = 0;
		break;
	default:
		return -EOPNOTSUPP;
	}
	if (opcode != expected)
		return -EINVAL;
	if (enable >= 0 && (!params || !size || params[0] != enable))
		return -EINVAL;
	if (operation == SPARKLINK_DISCOVERY_SCAN_INITIALIZE_OFF &&
	    ((step == 0 && (size != 8 || !params || params[3])) ||
	     (step != 0 && (size != 2 || !params || params[1]))))
		return -EINVAL;
	return ws73_discovery_validate_command(opcode, params, size);
}

/* Called twice: preflight into one small scratch buffer, then encode directly
 * into the caller's (normally heap) plan. No 1KB plan temporary or allocation
 * is needed. Immutable/disjoint input is an internal interface precondition.
 */
static int ws73_discovery_build(const struct sparklink_discovery_request *r,
				struct sparklink_discovery_plan *out)
{
	unsigned char scratch[SPARKLINK_DISCOVERY_PARAMS_MAX];
	unsigned char *p;
	unsigned int count, step = 0, opcode;
	int ret;
	const struct sparklink_discovery_scan_params *scan = r->scanning;

#define PART(code, expression)                               \
	do {                                                 \
		opcode = (code);                             \
		p = out ? out->steps[step].params : scratch; \
		ret = (expression);                          \
		if (ret < 0)                                 \
			return ret;                          \
		if (out) {                                   \
			out->steps[step].opcode = opcode;    \
			out->steps[step].length = ret;       \
		}                                            \
		step++;                                      \
	} while (0)
	switch (r->operation) {
	case SPARKLINK_DISCOVERY_ADV_START:
		count = r->scan_response_present ? 4 : 3;
		PART(0x0c02, ws73_discovery_adv_params(p, sizeof(scratch),
						       r->advertising));
		PART(0x0c03, ws73_discovery_data(p, sizeof(scratch), r->handle,
						 r->data, r->data_size));
		if (r->scan_response_present)
			PART(0x0c04,
			     ws73_discovery_data(p, sizeof(scratch), r->handle,
						 r->scan_response,
						 r->scan_response_size));
		PART(0x0c05,
		     ws73_discovery_adv_enable(p, sizeof(scratch), 1, r->handle,
					       r->duration, r->max_events));
		break;
	case SPARKLINK_DISCOVERY_ADV_CONFIGURE_OFF:
		count = 2;
		PART(0x0c02, ws73_discovery_adv_params(p, sizeof(scratch),
						       r->advertising));
		PART(0x0c05, ws73_discovery_adv_enable(p, sizeof(scratch), 0,
						       r->handle, 0, 0));
		break;
	case SPARKLINK_DISCOVERY_ADV_STOP:
		count = 1;
		PART(0x0c05, ws73_discovery_adv_enable(p, sizeof(scratch), 0,
						       r->handle, 0, 0));
		break;
	case SPARKLINK_DISCOVERY_SCAN_START:
	case SPARKLINK_DISCOVERY_SCAN_INITIALIZE_OFF:
		count = r->operation == SPARKLINK_DISCOVERY_SCAN_INITIALIZE_OFF ? 3 : 2;
		PART(0x1001,
		     ws73_discovery_scan_params(
			     p, sizeof(scratch), scan->own_address_type,
			     scan->filter, scan->frame_types, scan->active,
			     scan->interval, scan->window));
		PART(0x1002, ws73_discovery_scan_enable(p, sizeof(scratch), 1,
						       scan->filter_duplicates));
		if (r->operation == SPARKLINK_DISCOVERY_SCAN_INITIALIZE_OFF)
			PART(0x1002, ws73_discovery_scan_enable(p, sizeof(scratch), 0, 0));
		break;
	case SPARKLINK_DISCOVERY_SCAN_STOP:
		count = 1;
		PART(0x1002,
		     ws73_discovery_scan_enable(p, sizeof(scratch), 0, 0));
		break;
	default:
		return -EOPNOTSUPP;
	}
#undef PART
	if (out) {
		out->operation = r->operation;
		out->count = count;
		out->power_step = (r->operation == SPARKLINK_DISCOVERY_ADV_START ||
				   r->operation == SPARKLINK_DISCOVERY_ADV_CONFIGURE_OFF) ? 0 : count;
	}
	return 0;
}

int ws73_discovery_prepare(const struct sparklink_discovery_request *r,
			   struct sparklink_discovery_plan *out)
{
	int ret;

	if (!r || !out || r->scan_response_present > 1 ||
	    (!r->scan_response_present &&
	     (r->scan_response || r->scan_response_size)))
		return -EINVAL;
	switch (r->operation) {
	case SPARKLINK_DISCOVERY_ADV_START:
	case SPARKLINK_DISCOVERY_ADV_CONFIGURE_OFF:
		if (!r->advertising || r->scanning ||
		    r->advertising->handle != r->handle)
			return -EINVAL;
		break;
	case SPARKLINK_DISCOVERY_SCAN_START:
	case SPARKLINK_DISCOVERY_SCAN_INITIALIZE_OFF:
		if (!r->scanning || r->advertising || r->scanning->filter_duplicates > 1 ||
		    (r->operation == SPARKLINK_DISCOVERY_SCAN_INITIALIZE_OFF &&
		     (r->scanning->active || r->scanning->filter_duplicates)))
			return -EINVAL;
		break;
	case SPARKLINK_DISCOVERY_ADV_STOP:
	case SPARKLINK_DISCOVERY_SCAN_STOP:
		if (r->advertising || r->scanning)
			return -EINVAL;
		break;
	default:
		return -EOPNOTSUPP;
	}
	if (r->operation != SPARKLINK_DISCOVERY_ADV_START) {
		if (r->data || r->data_size || r->scan_response_present ||
		    r->duration || r->max_events)
			return -EINVAL;
		if (r->operation != SPARKLINK_DISCOVERY_ADV_STOP &&
		    r->operation != SPARKLINK_DISCOVERY_ADV_CONFIGURE_OFF && r->handle)
			return -EINVAL;
	}
	ret = ws73_discovery_build(r, NULL);
	if (ret)
		return ret;
	memset(out, 0, sizeof(*out));
	return ws73_discovery_build(r, out);
}
