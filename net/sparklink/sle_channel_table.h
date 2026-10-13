/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SLE_CHANNEL_TABLE_H
#define _SLE_CHANNEL_TABLE_H
/* Current bounded fixed-channel table. Dynamic TCIDs and reliable modes are
 * still unsupported. Match RX by local TCID/PI, never by the consuming fd. */
#define SL_SESSION_CHANNELS 2U
#define SL_CHANNEL_USER_SLOT 0U
#define SL_CHANNEL_SMTC_SLOT 1U
#define SL_CHANNEL_SMTC 10U
static inline int sl_channel_key_slot(unsigned int local, unsigned int remote, unsigned int pi)
{
	if (local == 31 && remote == 31 && pi == 241)
		return SL_CHANNEL_USER_SLOT;
	if (local == SL_CHANNEL_SMTC && remote == SL_CHANNEL_SMTC && !pi)
		return SL_CHANNEL_SMTC_SLOT;
	return -1;
}
static inline int sl_channel_rx_slot(unsigned int local, unsigned int pi)
{
	return sl_channel_key_slot(local, local, pi);
}
#endif
