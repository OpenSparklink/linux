/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SLE_TX_BUDGET_H
#define _SLE_TX_BUDGET_H
/* Software service budget only, never protocol credit. A failed attempt still
 * consumes this quantum. The original PDU deadline is a separate authority.
 * Unsigned nanosecond subtraction is intentionally modulo (monotonic clock). */
#define SL_TX_QUANTUM_PACKETS 8U
#define SL_TX_QUANTUM_BYTES 4096U
#define SL_TX_QUANTUM_NS 2000000ULL

enum sl_tx_budget_stop {
	SL_TX_BUDGET_NONE,
	SL_TX_BUDGET_PACKETS,
	SL_TX_BUDGET_BYTES,
	SL_TX_BUDGET_ELAPSED,
};
struct sl_tx_budget {
	u64 start_ns;
	unsigned int packets, bytes;
	enum sl_tx_budget_stop stop;
};
static inline struct sl_tx_budget sl_tx_budget_begin(u64 now)
{
	return (struct sl_tx_budget){ .start_ns = now };
}
static inline bool sl_tx_budget_charge(struct sl_tx_budget *b,
				     unsigned int length, u64 now)
{
	if (b->stop != SL_TX_BUDGET_NONE)
		return false;
	if (b->packets >= SL_TX_QUANTUM_PACKETS)
		b->stop = SL_TX_BUDGET_PACKETS;
	else if (!length || b->bytes > SL_TX_QUANTUM_BYTES ||
		 length > SL_TX_QUANTUM_BYTES - b->bytes)
		b->stop = SL_TX_BUDGET_BYTES;
	else if (now - b->start_ns >= SL_TX_QUANTUM_NS)
		b->stop = SL_TX_BUDGET_ELAPSED;
	else {
		b->packets++;
		b->bytes += length;
		return true;
	}
	return false;
}
#endif
