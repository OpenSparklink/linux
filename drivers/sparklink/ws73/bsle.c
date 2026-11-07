// SPDX-License-Identifier: GPL-2.0-only
#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#endif

#include "bsle.h"

#define WS73_BSLE_STAGE_MS 10000U
#define WS73_BSLE_POLL_MS 500U
#define WS73_BSLE_PANIC (1U << 6)

struct ws73_ack {
	unsigned int type;
	unsigned int message;
	int found;
};

static int ws73_ack_receive(void *context, unsigned int service, unsigned int queue,
			    const unsigned char *data, size_t size)
{
	struct ws73_ack *ack = context;
	unsigned int type, message;
	int ret;

	if (service != WS73_WIRE_BSLE_SERVICE || queue != WS73_WIRE_BSLE_QUEUE)
		return 0;
	ret = ws73_wire_status(data, size, &type, &message);
	if (ret == -ENOMSG)
		return 0;
	if (ret)
		return ret;
	if (type == ack->type && message == ack->message)
		ack->found = 1;
	return 0;
}

static int ws73_wait(struct ws73_bsle_io *io, int bsp, unsigned int type, unsigned int message)
{
	unsigned long long deadline = io->now_ms(io->context) + WS73_BSLE_STAGE_MS;
	struct ws73_ack ack = { .type = type, .message = message };

	for (;;) {
		unsigned long long now = io->now_ms(io->context);
		unsigned int timeout, bits = 0;
		int ret;

		if (now >= deadline)
			return -ETIMEDOUT;
		timeout = deadline - now;
		if (timeout > WS73_BSLE_POLL_MS)
			timeout = WS73_BSLE_POLL_MS;
		if (!bsp) {
			ret = io->receive(io->context, timeout);
			if (ret < 0 && ret != -ETIMEDOUT)
				return ret;
			if (ret > 0) {
				if ((size_t)ret > io->rx_capacity)
					return -EOVERFLOW;
				ret = ws73_wire_receive(io->rx, ret, ws73_ack_receive, &ack);
				if (ret)
					return ret;
			}
			/* Check panic even under continuous bulk traffic. */
			now = io->now_ms(io->context);
			if (now >= deadline)
				return -ETIMEDOUT;
			timeout = deadline - now;
			if (timeout > 20)
				timeout = 20;
		}
		ret = io->notification(io->context, timeout, &bits);
		if (ret < 0 && ret != -ETIMEDOUT)
			return ret;
		if (!ret && bits & WS73_BSLE_PANIC)
			return -EIO;
		if (io->now_ms(io->context) >= deadline)
			return -ETIMEDOUT;
		if ((bsp && !ret && (bits & 1)) || (!bsp && ack.found))
			return 0;
	}
}

static int ws73_send_control(struct ws73_bsle_io *io, unsigned int descriptor,
			     unsigned int queue)
{
	int ret = ws73_wire_control(io->tx, io->tx_capacity, *io->sequence,
				    descriptor, queue);

	if (ret < 0)
		return ret;
	(*io->sequence)++;
	return io->send(io->context, ret);
}

enum ws73_platform_query {
	WS73_QUERY_CHIP,
	WS73_QUERY_SLE_EFUSE,
};

struct ws73_platform_query_state {
	enum ws73_platform_query operation;
	union {
		struct ws73_chip_info chip;
		struct ws73_sle_efuse_info efuse;
	} info;
	int complete;
};

static int ws73_platform_receive(void *context, unsigned int service,
			     unsigned int queue, const unsigned char *data, size_t size)
{
	struct ws73_platform_query_state *state = context;
	struct ws73_platform_query_state candidate = {};
	int ret;

	if (service != WS73_WIRE_PLAT_SERVICE || queue != WS73_WIRE_PLAT_QUEUE)
		return 0;
	ret = state->operation == WS73_QUERY_CHIP ?
		ws73_wire_chip_reply(data, size, &candidate.info.chip) :
		ws73_wire_sle_efuse_reply(data, size, &candidate.info.efuse);
	if (ret == -ENOMSG)
		return 0;
	if (ret)
		return ret;
	if (state->complete)
		return -EPROTO; /* no ambiguous duplicate response */
	state->info = candidate.info;
	state->complete = 1;
	return 0;
}

static int ws73_platform_query(struct ws73_bsle_io *io,
			       struct ws73_platform_query_state *state)
{
	unsigned long long deadline, now;
	unsigned int step;
	int ret;

	if (!io || !state || !io->tx || !io->rx || !io->sequence ||
	    !io->now_ms || !io->send_timed || !io->receive || !io->notification ||
	    io->rx_capacity < WS73_WIRE_RX_HEADER_SIZE || io->rx_capacity > WS73_WIRE_RX_MAX)
		return -EINVAL;
	/* Includes TX and all unrelated/empty replies. No retry renews it. */
	now = io->now_ms(io->context);
	if (now > ~0ULL - 2000)
		return -EOVERFLOW;
	deadline = now + 2000;
	for (step = 0; step < 3; step++) {
		if (step != 2)
			ret = ws73_wire_control(io->tx, io->tx_capacity, *io->sequence,
					       step == 0, step == 0 ? WS73_WIRE_PLAT_QUEUE : 0);
		else if (state->operation == WS73_QUERY_CHIP)
			ret = ws73_wire_chip_request(io->tx, io->tx_capacity, *io->sequence);
		else
			ret = ws73_wire_sle_efuse_request(io->tx, io->tx_capacity, *io->sequence);
		if (ret < 0)
			return ret;
		now = io->now_ms(io->context);
		if (now >= deadline)
			return -ETIMEDOUT;
		(*io->sequence)++;
		ret = io->send_timed(io->context, ret, deadline - now);
		if (ret)
			return ret;
	}
	for (;;) {
		unsigned int timeout, bits = 0;

		now = io->now_ms(io->context);
		if (now >= deadline)
			return -ETIMEDOUT;
		timeout = deadline - now;
		if (timeout > 100)
			timeout = 100;
		ret = io->receive(io->context, timeout);
		if (ret < 0 && ret != -ETIMEDOUT)
			return ret;
		if (ret > 0) {
			if ((size_t)ret > io->rx_capacity)
				return -EOVERFLOW;
			ret = ws73_wire_receive(io->rx, ret, ws73_platform_receive, state);
			if (ret)
				return ret;
		}
		if (io->now_ms(io->context) >= deadline)
			return -ETIMEDOUT;
		ret = io->notification(io->context, 1, &bits);
		if (ret < 0 && ret != -ETIMEDOUT)
			return ret;
		if (!ret && (bits & WS73_BSLE_PANIC))
			return -EIO;
		if (io->now_ms(io->context) >= deadline)
			return -ETIMEDOUT;
		if (state->complete)
			return 0;
	}
}

int ws73_chip_query(struct ws73_bsle_io *io, struct ws73_chip_info *info)
{
	struct ws73_platform_query_state state = { .operation = WS73_QUERY_CHIP };
	int ret;

	if (!info)
		return -EINVAL;
	ret = ws73_platform_query(io, &state);
	if (!ret)
		*info = state.info.chip;
	return ret;
}

int ws73_sle_efuse_query(struct ws73_bsle_io *io, struct ws73_sle_efuse_info *info)
{
	struct ws73_platform_query_state state = { .operation = WS73_QUERY_SLE_EFUSE };
	int ret;

	if (!info)
		return -EINVAL;
	ret = ws73_platform_query(io, &state);
	if (!ret)
		*info = state.info.efuse;
	return ret;
}

static int ws73_bsle_validate(struct ws73_bsle_io *io, const unsigned char *pm, size_t pm_size,
			      const unsigned char *custom, size_t custom_size)
{
	if (!io || !io->tx || !io->rx || !io->sequence || !io->now_ms ||
	    !io->send || !io->receive || !io->notification || !io->open || !io->phase ||
	    io->tx_capacity < WS73_WIRE_CUSTOM_SIZE || io->rx_capacity < WS73_WIRE_RX_HEADER_SIZE ||
	    io->rx_capacity > WS73_WIRE_RX_MAX || !pm || pm_size != 4 ||
	    !custom || custom_size != WS73_WIRE_CUSTOM_DATA_SIZE)
		return -EINVAL;
	return 0;
}

static int ws73_bsle_configure_open(struct ws73_bsle_io *io,
				  const unsigned char *pm, size_t pm_size,
				  const unsigned char *custom, size_t custom_size)
{
	int ret;

	io->phase(io->context, WS73_BSLE_CONFIGURING);
	ret = ws73_send_control(io, 1, 9);
	if (ret)
		return ret;
	ret = ws73_send_control(io, 0, 0);
	if (ret)
		return ret;
	ret = ws73_wire_pm(io->tx, io->tx_capacity, *io->sequence, pm, pm_size);
	if (ret < 0)
		return ret;
	(*io->sequence)++;
	ret = io->send(io->context, ret);
	if (ret)
		return ret;
	ret = ws73_send_control(io, 1, WS73_WIRE_BSLE_QUEUE);
	if (ret)
		return ret;
	ret = ws73_send_control(io, 0, 0);
	if (ret)
		return ret;
	ret = ws73_wire_customize(io->tx, io->tx_capacity, *io->sequence, custom, custom_size);
	if (ret < 0)
		return ret;
	(*io->sequence)++;
	ret = io->send(io->context, ret);
	if (ret)
		return ret;

	io->phase(io->context, WS73_BSLE_WAIT_CUSTOMIZE);
	ret = ws73_wait(io, 0, 2, 2);
	if (ret)
		return ret;
	io->phase(io->context, WS73_BSLE_OPENING);
	ret = io->open(io->context);
	if (ret)
		return ret;
	io->phase(io->context, WS73_BSLE_WAIT_BOOT);
	/* DEVICE_ACTION_STATUS(SLE_OPEN) is not BOOT_FINISH. */
	ret = ws73_wait(io, 0, 2, 1);
	if (!ret)
		io->phase(io->context, WS73_BSLE_TRANSPORT_OPEN);
	return ret;
}

int ws73_bsle_start(struct ws73_bsle_io *io, const unsigned char *pm, size_t pm_size,
		    const unsigned char *custom, size_t custom_size)
{
	int ret = ws73_bsle_validate(io, pm, pm_size, custom, custom_size);

	if (ret)
		return ret;
	io->phase(io->context, WS73_BSLE_WAIT_BSP);
	ret = ws73_wait(io, 1, 2, 0);
	return ret ? ret : ws73_bsle_configure_open(io, pm, pm_size, custom, custom_size);
}

int ws73_bsle_restore(struct ws73_bsle_io *io, const unsigned char *pm, size_t pm_size,
		      const unsigned char *custom, size_t custom_size)
{
	unsigned long long deadline;
	int ret = ws73_bsle_validate(io, pm, pm_size, custom, custom_size);

	if (ret || !io->close)
		return ret ? ret : -EINVAL;
	io->phase(io->context, WS73_BSLE_DRAINING);
	deadline = io->now_ms(io->context) + 1000;
	/* Discard bounded stale packets before CLOSE; none supplies state/credit.
	 * A continuously busy input fails instead of draining without a bound.
	 */
	for (unsigned int packets = 0; packets < 64; packets++) {
		unsigned int bits = 0;

		if (io->now_ms(io->context) >= deadline)
			return -ETIMEDOUT;
		ret = io->receive(io->context, 20);
		if (ret < 0 && ret != -ETIMEDOUT)
			return ret;
		if (ret > 0 && (size_t)ret > io->rx_capacity)
			return -EOVERFLOW;
		if (!ret || ret == -ETIMEDOUT) {
			ret = io->notification(io->context, 20, &bits);
			if (ret < 0 && ret != -ETIMEDOUT)
				return ret;
			if (!ret && bits & WS73_BSLE_PANIC)
				return -EIO;
			if (io->now_ms(io->context) >= deadline)
				return -ETIMEDOUT;
			io->phase(io->context, WS73_BSLE_CLOSING);
			ret = io->close(io->context);
			if (ret)
				return ret;
			io->phase(io->context, WS73_BSLE_WAIT_CLOSE);
			/* SDK action enum: SLE_OPEN=2, SLE_CLOSE=3. Neither a
			 * status/open ACK nor an old BOOT_FINISH confirms CLOSE.
			 */
			ret = ws73_wait(io, 0, 4, 3);
			return ret ? ret : ws73_bsle_configure_open(io, pm, pm_size, custom, custom_size);
		}
	}
	return -ETIMEDOUT;
}
