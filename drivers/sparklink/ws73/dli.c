// SPDX-License-Identifier: GPL-2.0-only
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

#include "dli.h"

#define WS73_QUERY_MS 10000U

int ws73_dli_validate_command(unsigned int opcode, const unsigned char *params,
			      size_t size)
{
	if (size && !params)
		return -EINVAL;
	switch (opcode) {
	case 0x0402:
	case 0x0403:
	case 0x0404:
	case 0x0406:
		return size ? -EINVAL : 0;
	default:
		/* WS73 0401 is SetEventMask, not standard ReadCmdLen. */
		return -EOPNOTSUPP;
	}
}

struct ws73_query {
	unsigned int opcode;
	unsigned int *credits;
	struct ws73_dli_result *result;
	size_t size;
	unsigned char data[10];
	int complete;
};

int ws73_dli_prepare_runtime_address(const unsigned char *address,
		unsigned short *opcode, unsigned char *params, size_t capacity)
{
	int ret;

	if (!opcode || !params || capacity < 6)
		return -EINVAL;
	ret = ws73_dli_validate_runtime_address(0x0405, address, 6);
	if (ret)
		return ret;
	memcpy(params, address, 6);
	*opcode = 0x0405;
	return 6;
}

int ws73_dli_validate_runtime_address(unsigned int opcode,
		const unsigned char *params, size_t size)
{
	size_t i;

	if (opcode != 0x0405)
		return -EOPNOTSUPP;
	if (!params || size != 6)
		return -EINVAL;
	/* SDK110 E 4009b0 -> 40f322 rejects exactly the all-zero value.
	 * Handler 40f40a copies six bytes to its volatile global only after
	 * that check. No Wi-Fi/Bluetooth bit rules or official allocation
	 * claims follow; the actual controller may still reject the command.
	 */
	for (i = 0; i < size; i++)
		if (params[i])
			return 0;
	return -EINVAL;
}

static unsigned int dli_u16(const unsigned char *p)
{
	return (unsigned int)p[0] | (unsigned int)p[1] << 8;
}

int ws73_dli_validate_security_event(const unsigned char *data, size_t size)
{
	unsigned int event;
	size_t params;

	if (!data)
		return -EINVAL;
	if (size < 3 || data[0] != 0xa2)
		return -ENOMSG;
	event = dli_u16(data + 1);
	if (event != 0x0014 && event != 0x000e && event != 0x0011)
		return -ENOMSG;
	if (size < 5)
		return -EPROTO;
	params = dli_u16(data + 3);
	if (params != size - 5)
		return -EPROTO;
	/* NearLink Host f0872df DLI_ControllerDataEvt and DLI_EncryptChangeEvt,
	 * cross-checked with libws73-usb f4d85d0 SDK111 captures. A host C
	 * structure may include padding; the relay header on wire is five bytes.
	 * Legacy three-byte encryption outcomes are not this firmware's schema.
	 */
	switch (event) {
	case 0x0014:
		return params >= 5 && params - 5 == data[9] ? 0 : -EPROTO;
	case 0x000e:
		return params == 2 ? 0 : -EPROTO;
	default: /* 0011: status, handle LE16, opaque encryption-change byte */
		return params == 4 ? 0 : -EPROTO;
	}
}

int ws73_dli_validate_link_event(const unsigned char *data, size_t size)
{
	unsigned int event;
	size_t params;

	if (!data)
		return -EINVAL;
	if (size < 3 || data[0] != 0xa2)
		return -ENOMSG;
	event = dli_u16(data + 1);
	if (event != 0x0015 && event != 0x1401 &&
	    event != 0x0005 && event != 0x1405)
		return -ENOMSG;
	if (size < 5)
		return -EPROTO;
	params = dli_u16(data + 3);
	if (params != size - 5)
		return -EPROTO;
	/* Connection: status, handle, role, peer type and six address bytes.
	 * The standard's longer body and vendor extensions stay in the record.
	 * Disconnection has an exact status/handle/reason body.
	 * Facts checked against T/XS 10003-2025 9.1.14/9.1.5 and the independent
	 * libws73-usb f4d85d0 connection reference; no source is incorporated.
	 */
	if (event == 0x0005 || event == 0x1405)
		return params == 4 ? 0 : -EPROTO;
	return params >= 11 ? 0 : -EPROTO;
}

int ws73_dli_link_outcome(const unsigned char *data, size_t size,
                         struct ws73_link_outcome *out)
{
    struct ws73_link_outcome candidate = {0};
    unsigned int event;
    int ret;

    if (!out)
        return -EINVAL;
    ret = ws73_dli_validate_link_event(data, size);
    if (ret)
        return ret;
    event = dli_u16(data + 1);
    candidate.kind = event == 0x0015 || event == 0x1401 ? 1 : 2;
    candidate.status = data[5];
    candidate.handle = dli_u16(data + 6);
    if (candidate.kind == 1) {
        candidate.role = data[8];
        candidate.address_type = data[9];
        memcpy(candidate.address, data + 10, sizeof(candidate.address));
    }
    *out = candidate;
    return 0;
}

int ws73_dli_validate_reply(const unsigned char *data, size_t size)
{
	unsigned int event, opcode, expected;
	size_t params;

	if (!data)
		return -EINVAL;
	if (size < 5 || data[0] != 0xa2)
		return -EPROTO;
	event = dli_u16(data + 1);
	params = dli_u16(data + 3);
	if (params != size - 5 || (event != 1 && event != 2) || params < 3)
		return -EPROTO;
	opcode = dli_u16(data + 5);
	if (!opcode)
		return params == 3 ? 0 : -EPROTO;
	if (params < 4 || (event == 1 && params != 4))
		return -EPROTO;
	/* Status acceptance is not terminal. Failure returns are retained, not
	 * mapped to the host's enum or interpreted as successful result data.
	 */
	if (event == 1 || data[8])
		return 0;
	switch (opcode) {
	case 0x180c: /* Read RSSI: echoed handle LE16 and signed RSSI byte */
		expected = 3;
		break;
	case 0x1805: /* Read PHY: handle LE16 and eight wire fields */
		expected = 10;
		break;
	case 0x0402:
	case 0x0406:
		expected = 6;
		break;
	case 0x0403:
		expected = 10;
		break;
	case 0x0404:
		expected = 5;
		break;
	case 0x0c02:
		expected = 1; /* selected TX power, not another command status */
		break;
	case 0x0c03:
	case 0x0c04:
	case 0x0c05:
	case 0x1001:
	case 0x1002:
	case 0x0405: /* SDK110 volatile address setter: status only */
	case 0x1804: /* SDK110 link payload preference: status, not effective MTU */
		expected = 0;
		break;
	case 0x1812:
		/* SDK111 real capture: success echoes handle LE16 and SMP index
		 * LE16. Host matches both to its frozen submission; this is not
		 * a generation/lifetime token or raw-command authorization. */
		return params == 8 && dli_u16(data + 9) <= 0x0fff ? 0 : -EPROTO;
	default:
		return 0; /* no capability or command authorization inferred */
	}
	return params == 4 + expected ? 0 : -EPROTO;
}

static int ws73_query_receive(void *context, unsigned int service, unsigned int queue,
			      const unsigned char *data, size_t size)
{
	struct ws73_query *query = context;
	unsigned int event, opcode, status;
	size_t params;

	if (service != WS73_WIRE_SLE_SERVICE || queue != WS73_WIRE_SLE_QUEUE)
		return 0;
	if (!size)
		return -EPROTO;
	/* Async data is not a command reply. Host command echo is rejected. */
	if (data[0] >= 0xa3 && data[0] <= 0xa5)
		return 0;
	if (size < 5 || data[0] != 0xa2)
		return -EPROTO;
	event = dli_u16(data + 1);
	params = dli_u16(data + 3);
	if (params != size - 5)
		return -EPROTO;
	query->result->event = event;
	if (event == 0x000a) {
		if (params != 1)
			return -EPROTO;
		query->result->hardware_error = data[5];
		return -EIO;
	}
	if (event != 1 && event != 2)
		return 0;
	if (ws73_dli_validate_reply(data, size))
		return -EPROTO;
	if (params < 3)
		return -EPROTO;
	opcode = dli_u16(data + 5);
	if (!opcode) {
		if (params != 3)
			return -EPROTO;
		*query->credits = data[7];
		return 0; /* unsolicited credit-only event never resolves a query */
	}
	if (params < 4)
		return -EPROTO;
	status = data[8];
	*query->credits = data[7];
	if (!query->opcode || opcode != query->opcode)
		return 0;
	query->result->status = status;
	if (status)
		return -EREMOTEIO;
	if (event == 1)
		return params == 4 ? 0 : -EPROTO; /* acceptance is not Complete */
	if (query->complete || params - 4 != query->size)
		return -EPROTO;
	memcpy(query->data, data + 9, query->size);
	query->complete = 1;
	return 0;
}

static int ws73_query_poll(struct ws73_bsle_io *io, struct ws73_query *query,
			   int grant)
{
	unsigned long long deadline = io->now_ms(io->context) + WS73_QUERY_MS;

	for (;;) {
		unsigned long long now = io->now_ms(io->context);
		unsigned int timeout, bits = 0;
		int ret;

		if (now >= deadline)
			return -ETIMEDOUT;
		timeout = deadline - now;
		if (timeout > 500)
			timeout = 500;
		ret = io->receive(io->context, timeout);
		if (ret < 0 && ret != -ETIMEDOUT)
			return ret;
		if (ret > 0) {
			if ((size_t)ret > io->rx_capacity)
				return -EOVERFLOW;
			ret = ws73_wire_receive(io->rx, ret, ws73_query_receive, query);
			if (ret)
				return ret;
		}
		now = io->now_ms(io->context);
		if (now >= deadline)
			return -ETIMEDOUT;
		timeout = deadline - now;
		if (timeout > 20)
			timeout = 20;
		ret = io->notification(io->context, timeout, &bits);
		if (ret < 0 && ret != -ETIMEDOUT)
			return ret;
		if (!ret && (bits & (1U << 6)))
			return -EIO;
		if (io->now_ms(io->context) >= deadline)
			return -ETIMEDOUT;
		if (grant ? *query->credits != 0 : query->complete)
			return 0;
	}
}

static int ws73_query_one(struct ws73_bsle_io *io, unsigned int *credits,
			  unsigned int opcode, const unsigned char *params,
			  size_t size, unsigned char *out, size_t out_size,
			  struct ws73_dli_result *result)
{
	struct ws73_query query = {
		.credits = credits, .result = result, .size = out_size,
	};
	int ret;

	result->opcode = opcode;
	result->status = 0x100; /* no controller status received */
	result->event = 0;
	result->hardware_error = 0x100; /* no Hardware Error event received */
	if (!*credits) {
		ret = ws73_query_poll(io, &query, 1);
		if (ret)
			return ret;
	}
	query.opcode = opcode;
	ret = ws73_wire_command(io->tx, io->tx_capacity, *io->sequence, opcode, params, size);
	if (ret < 0)
		return ret;
	(*io->sequence)++;
	(*credits)--;
	ret = io->send(io->context, ret);
	if (ret)
		return ret;
	ret = ws73_query_poll(io, &query, 0);
	if (!ret)
		memcpy(out, query.data, out_size);
	return ret;
}

int ws73_dli_query(struct ws73_bsle_io *io, unsigned int *credits,
		   struct ws73_dli_info *info, struct ws73_dli_result *result)
{
	struct ws73_dli_info candidate = {};
	unsigned char buffer[6];
	unsigned int i;
	int ret;

	if (!io || !credits || *credits > 255 || !info || !result || !io->tx ||
	    !io->rx || !io->sequence || !io->now_ms || !io->send || !io->receive ||
	    !io->notification || io->tx_capacity < 128 ||
	    io->rx_capacity < WS73_WIRE_RX_HEADER_SIZE || io->rx_capacity > WS73_WIRE_RX_MAX)
		return -EINVAL;
	/* Select SLE queue only after BSLE boot; no global queue or sequence. */
	for (i = 0; i < 2; i++) {
		ret = ws73_wire_control(io->tx, io->tx_capacity, *io->sequence, i ? 0 : 1,
					i ? 0 : WS73_WIRE_SLE_QUEUE);
		if (ret < 0)
			return ret;
		(*io->sequence)++;
		ret = io->send(io->context, ret);
		if (ret)
			return ret;
	}
	/* Never send 0x0401 as ReadCmdLen on the WS73 event-mask dialect. */
	ret = ws73_query_one(io, credits, 0x0404, NULL, 0, candidate.version, 5, result);
	if (ret)
		return ret;
	ret = ws73_query_one(io, credits, 0x0402, NULL, 0, buffer, 6, result);
	if (ret)
		return ret;
	candidate.acb_length = dli_u16(buffer);
	candidate.acb_count = buffer[2];
	candidate.icb_length = dli_u16(buffer + 3);
	candidate.icb_count = buffer[5];
	if (candidate.acb_length > 2047 || candidate.icb_length > 2047 ||
	    (!candidate.acb_length != !candidate.acb_count) ||
	    (!candidate.icb_length != !candidate.icb_count))
		return -EPROTO;
	ret = ws73_query_one(io, credits, 0x0403, NULL, 0, candidate.features, 10, result);
	if (ret)
		return ret;
	/* WS73 SDK ARM shared and static host libraries both send 0406 with
	 * no parameters. This differs from standard DLI's address-type byte.
	 * Keep the quirk here, not in the standard Host command schema; failure
	 * never falls back to a synthesized/cached public address.
	 */
	ret = ws73_query_one(io, credits, 0x0406, NULL, 0, candidate.address, 6, result);
	if (ret)
		return ret;
	for (i = 0; i < 6 && !candidate.address[i]; i++)
		;
	if (i == 6)
		return -EPROTO;
	for (i = 0; i < 6 && candidate.address[i] == 255; i++)
		;
	if (i == 6)
		return -EPROTO;
	*info = candidate;
	return 0;
}

int ws73_dli_relay_validate(unsigned int opcode, const unsigned char *params, size_t size)
{
    if (!params)
        return -EINVAL;
    if (opcode == 0x1c03 || opcode == 0x1c05) {
        size_t expected = opcode == 0x1c03 ? 21 : 20;
        if (size != expected || dli_u16(params) > 0x0fff ||
            params[18] != 1 || params[19] != 1 ||
            (opcode == 0x1c03 && params[20] != 0))
            return -EPROTO;
        /* Queue/prepare contains NO key. The retained final ticket copies the
         * verified Session key directly into the driver's temporary frame. */
        return memcmp(params + 2, (const unsigned char[16]){0}, 16) ? -EPROTO : 0;
    }
    if (size < 5 || size > 255)
        return -EINVAL;
    if (opcode != 0x1812)
        return -EOPNOTSUPP;
    if (dli_u16(params) > 0x0fff || (size_t)params[4] + 5 != size)
        return -EPROTO;
    return 0;
}
int ws73_dli_relay_prepare(unsigned int handle, unsigned int index,
    const unsigned char *payload, size_t size, unsigned short *opcode,
    unsigned char *params, size_t capacity, unsigned short *echo_index)
{
    unsigned int wire_index = index == 0x0147 ? 0x01ff : index;

    if (!opcode || !params || !echo_index || handle > 0x0fff || index > 65535 || (size && !payload))
        return -EINVAL;
    /* Reserved internal installation intents, never on-wire SMP indices or
     * raw UAPI commands. Only the physical Session can construct these. */
    if (index == 0x1c03 || index == 0x1c05) {
        size_t length = index == 0x1c03 ? 21 : 20;
        if (size) return -EINVAL;
        if (capacity < length) return -EMSGSIZE;
        memset(params, 0, length);
        params[0] = handle & 0xff; params[1] = handle >> 8;
        params[18] = 1; params[19] = 1;
        *opcode = index; *echo_index = index;
        return length;
    }
    /* Confirmed command budget includes the relay envelope. RX255 does not
     * establish TX255; current negotiated SM messages fit, oversize rejects. */
    if (size > 250 || capacity < size + 5)
        return -EMSGSIZE;
    params[0] = handle & 0xff; params[1] = handle >> 8;
    /* SDK111 gle_sm_cmd_list[26] uses1ff/1byte, unlike standard147.
     * Keep canonical policy in Host and correlate Complete with raw wire. */
    params[2] = wire_index & 0xff; params[3] = wire_index >> 8;
    params[4] = size;
    if (size) memcpy(params + 5, payload, size);
    *opcode = 0x1812;
    *echo_index = wire_index;
    return size + 5;
}

int ws73_dli_relay_normalize_rx(const unsigned char *data, size_t size,
    unsigned char *out, size_t capacity)
{
    int ret;

    if (!data)
        return -EINVAL;
    if (size < 3 || data[0] != 0xa2 || dli_u16(data + 1) != 0x0014)
        return 0;
    ret = ws73_dli_validate_security_event(data, size);
    if (ret)
        return ret;
    if (dli_u16(data + 7) != 0x01ff)
        return 0;
    /* The SDK111 failure entry has exactly one reason byte. No truncation,
     * fabricated reply or change to the original snoop/USB packet. */
    if (size != 11 || dli_u16(data + 5) > 0x0fff)
        return -EPROTO;
    if (!out || capacity < size)
        return -EMSGSIZE;
    memcpy(out, data, size);
    out[7] = 0x47;
    out[8] = 0x01;
    return size;
}
