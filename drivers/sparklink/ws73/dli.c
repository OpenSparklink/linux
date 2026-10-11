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

static unsigned int dli_u16(const unsigned char *p)
{
	return (unsigned int)p[0] | (unsigned int)p[1] << 8;
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
		expected = 0;
		break;
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
