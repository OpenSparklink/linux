/* SPDX-License-Identifier: GPL-2.0-only */
/* Retired unqualified handle-only/H4 bulk framing, source1d6b. Test-only history. */
int sle_usb_dev_send_data_locked(struct sle_usb_dev *d, u16 handle, const u8 *data, int len)
{
	u8 *pkt;
	int total;
	int actual_len;
	unsigned int pipe;
	u16 link_id_seg;
	u16 data_len_field;
	int ret;


	if (!d->active || !d->udev)
		return -ENODEV;

	if (len <= 0 || !data || handle > 0x0fff)
		return -EINVAL;
	if (len > 511)
		return -EMSGSIZE;

	total = 5 + len;
	pkt = kmalloc(total, GFP_KERNEL);
	if (!pkt)
		return -ENOMEM;

	/* Build DLI async unicast data packet */
	link_id_seg = ((handle & 0x0FFF) << 4);
	data_len_field = (u16)(len & 0x01FF);

	pkt[0] = DLI_PKT_ASYNC_DATA;
	pkt[1] = (u8)(link_id_seg & 0xFF);
	pkt[2] = (u8)(link_id_seg >> 8);
	pkt[3] = (u8)(data_len_field & 0xFF);
	pkt[4] = (u8)(data_len_field >> 8);
	if (len > 0 && data)
		memcpy(&pkt[5], data, len);

	pipe = usb_sndbulkpipe(d->udev, d->ep_bulk_out);
	ret = usb_bulk_msg(d->udev, pipe, pkt, total,
			   &actual_len, SLE_CMD_TIMEOUT_MS);
	kfree(pkt);
	if (!ret && actual_len != total)
		return -EIO;
	return ret;
}
