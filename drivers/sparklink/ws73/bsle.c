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

struct ws73_chip_query_state {
	struct ws73_chip_info info;
	int complete;
};

static int ws73_chip_receive(void *context, unsigned int service,
			     unsigned int queue, const unsigned char *data, size_t size)
{
	struct ws73_chip_query_state *state = context;
	struct ws73_chip_info candidate;
	int ret;

	if (service != WS73_WIRE_PLAT_SERVICE || queue != WS73_WIRE_PLAT_QUEUE)
		return 0;
	ret = ws73_wire_chip_reply(data, size, &candidate);
	if (ret == -ENOMSG)
		return 0;
	if (ret)
		return ret;
	if (state->complete)
		return -EPROTO; /* no ambiguous duplicate response */
	state->info = candidate;
	state->complete = 1;
	return 0;
}

int ws73_chip_query(struct ws73_bsle_io *io, struct ws73_chip_info *info)
{
	struct ws73_chip_query_state state = {};
	unsigned long long deadline;
	int ret;

	if (!io || !info || !io->tx || !io->rx || !io->sequence ||
	    !io->now_ms || !io->send || !io->receive || !io->notification ||
	    io->rx_capacity < WS73_WIRE_RX_HEADER_SIZE || io->rx_capacity > WS73_WIRE_RX_MAX)
		return -EINVAL;
	/* Includes TX and all unrelated/empty replies. No retry renews it. */
	deadline = io->now_ms(io->context) + 2000;
	ret = ws73_send_control(io, 1, WS73_WIRE_PLAT_QUEUE);
	if (!ret)
		ret = ws73_send_control(io, 0, 0);
	if (ret)
		return ret;
	ret = ws73_wire_chip_request(io->tx, io->tx_capacity, *io->sequence);
	if (ret < 0)
		return ret;
	(*io->sequence)++;
	ret = io->send(io->context, ret);
	if (ret)
		return ret;
	for (;;) {
		unsigned long long now = io->now_ms(io->context);
		unsigned int timeout, bits = 0;

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
			ret = ws73_wire_receive(io->rx, ret, ws73_chip_receive, &state);
			if (ret)
				return ret;
		}
		ret = io->notification(io->context, 1, &bits);
		if (ret < 0 && ret != -ETIMEDOUT)
			return ret;
		if (!ret && (bits & WS73_BSLE_PANIC))
			return -EIO;
		if (io->now_ms(io->context) >= deadline)
			return -ETIMEDOUT;
		if (state.complete) {
			*info = state.info;
			return 0;
		}
	}
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
