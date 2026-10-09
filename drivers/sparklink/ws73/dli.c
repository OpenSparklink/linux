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
	if (event == 0x000a)
		return -EIO;
	if (event != 1 && event != 2)
		return 0;
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
	unsigned char buffer[6], address_type = 0;
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
	/* Address read carries the explicit address-type byte (§8.1.6).
	 * This command's availability on the WS73 firmware must be verified;
	 * failure never falls back to a synthesized/cached public address.
	 */
	ret = ws73_query_one(io, credits, 0x0406, &address_type, 1, candidate.address, 6, result);
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
