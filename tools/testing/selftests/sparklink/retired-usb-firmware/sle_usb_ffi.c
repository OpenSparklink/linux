/* SPDX-License-Identifier: GPL-2.0-only */
/* Retired experimental protocol, source1d6b3195484f. Never built into production.
 * Historical bounds/failure regressions only, not standard USB/firmware proof. */
#define SLE_USB_MAX_DEVS 16
#define DLI_PKT_COMMAND    0xA1
#define SLE_EVT_CMD_COMPLETE      0x0002
#define SLE_INIT_TIMEOUT_MS       3000
#define SLE_FW_DATA_MARKER   0xA5
#define SLE_FW_CHUNK_HDR     7     /* marker + offset(4) + len(2) */
#define SLE_OP_FW_DL_START   0xF810
#define SLE_OP_FW_DL_DONE    0xF811
#define SLE_FW_DEFAULT_CHUNK 240   /* legacy fallback, not a device capability */
#define SLE_FW_MAX_SIZE     (4 * 1024 * 1024) /* matches Rust loader budget */
#define SLE_FW_DL_TIMEOUT_MS 10000
int sle_usb_send_cmd_sync(struct sle_usb_dev *d, u16 opcode,
				 const u8 *params, int plen, u8 *resp, int resp_size, int *resp_len)
{
	u8 *cmd;
	u8 *rbuf;
	int actual_len;
	unsigned int pipe_out, pipe_in;
	int ret;

	if (plen < 0 || plen > 65535 || (plen && !params) ||
	    !resp || !resp_len || resp_size <= 0)
		return -EINVAL;
	cmd = kmalloc(5 + plen, GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd[0] = DLI_PKT_COMMAND;
	cmd[1] = (u8)(opcode & 0xFF);
	cmd[2] = (u8)(opcode >> 8);
	cmd[3] = (u8)plen;
	cmd[4] = (u8)(plen >> 8);
	if (plen)
		memcpy(cmd + 5, params, plen);

	pipe_out = usb_sndbulkpipe(d->udev, d->ep_bulk_out);
	ret = usb_bulk_msg(d->udev, pipe_out, cmd, 5 + plen,
			   &actual_len, SLE_INIT_TIMEOUT_MS);
	kfree(cmd);
	if (ret)
		return ret;
	if (actual_len != 5 + plen)
		return -EIO;

	/* Read response from bulk IN using heap buffer */
	rbuf = kmalloc(resp_size, GFP_KERNEL);
	if (!rbuf)
		return -ENOMEM;

	pipe_in = usb_rcvbulkpipe(d->udev, d->ep_bulk_in);
	ret = usb_bulk_msg(d->udev, pipe_in, rbuf, resp_size,
			   resp_len, SLE_INIT_TIMEOUT_MS);
	if (!ret) {
		if (*resp_len < 0 || *resp_len > resp_size)
			ret = -EPROTO;
		else if (*resp_len > 0)
			memcpy(resp, rbuf, *resp_len);
	}
	kfree(rbuf);
	return ret;
}
int sle_usb_validate_init_reply(const u8 *resp, int len,
				       u16 opcode, int return_size)
{
	if (len != 8 + return_size ||
	    get_unaligned_le16(resp) != SLE_EVT_CMD_COMPLETE ||
	    get_unaligned_le16(resp + 2) != 4 + return_size ||
	    get_unaligned_le16(resp + 4) != opcode)
		return -EPROTO;
	if (resp[7])
		return -EREMOTEIO;
	return 0;
}
int sle_usb_dev_download_fw_locked(struct sle_usb_dev *d, const u8 *data, int size,
			    int chunk_size)
{
	unsigned int pipe;
	int offset = 0;
	int actual_len;
	int ret;
	u8 *pkt;
	int pkt_size;
	u8 start_params[4];
	u8 resp[32];
	int resp_len = 0;

	if (!data || size <= 0)
		return -EINVAL;
	if (size > SLE_FW_MAX_SIZE)
		return -EFBIG;
	if (chunk_size < 0)
		return -EINVAL;

	if (!d->active || !d->udev)
		return -ENODEV;

	if (!chunk_size)
		chunk_size = d->ep_bulk_in_size > SLE_FW_CHUNK_HDR ?
			     d->ep_bulk_in_size - SLE_FW_CHUNK_HDR :
			     SLE_FW_DEFAULT_CHUNK;
	/* The chunk header has a 16-bit length. This also bounds pkt_size
	 * before integer addition and allocation, including explicit sizes.
	 */
	if (chunk_size <= 0 || chunk_size > 0xffff)
		return -EMSGSIZE;

	pkt_size = SLE_FW_CHUNK_HDR + chunk_size;
	pkt = kmalloc(pkt_size, GFP_KERNEL);
	if (!pkt)
		return -ENOMEM;

	/* Step 1: Send FW_DOWNLOAD_START with total size */
	start_params[0] = (u8)(size & 0xFF);
	start_params[1] = (u8)((size >> 8) & 0xFF);
	start_params[2] = (u8)((size >> 16) & 0xFF);
	start_params[3] = (u8)((size >> 24) & 0xFF);

	ret = sle_usb_dev_send_cmd_locked(d, SLE_OP_FW_DL_START,
				   start_params, 4);
	if (ret) {
		pr_err("sparklink-usb: fw download start failed: %d\n", ret);
		goto out;
	}

	/* Step 2: Send firmware in chunks via bulk OUT */
	pipe = usb_sndbulkpipe(d->udev, d->ep_bulk_out);

	while (offset < size) {
		int chunk = min(chunk_size, size - offset);
		int total = SLE_FW_CHUNK_HDR + chunk;

		pkt[0] = SLE_FW_DATA_MARKER;
		pkt[1] = (u8)(offset & 0xFF);
		pkt[2] = (u8)((offset >> 8) & 0xFF);
		pkt[3] = (u8)((offset >> 16) & 0xFF);
		pkt[4] = (u8)((offset >> 24) & 0xFF);
		pkt[5] = (u8)(chunk & 0xFF);
		pkt[6] = (u8)((chunk >> 8) & 0xFF);
		memcpy(&pkt[SLE_FW_CHUNK_HDR], data + offset, chunk);

		ret = usb_bulk_msg(d->udev, pipe, pkt, total,
				   &actual_len, SLE_FW_DL_TIMEOUT_MS);
		if (ret) {
			pr_err("sparklink-usb: fw chunk at offset %d failed: %d\n",
			       offset, ret);
			goto out;
		}
		if (actual_len != total) {
			ret = -EIO;
			pr_err("sparklink-usb: short fw chunk at offset %d: %d/%d\n",
			       offset, actual_len, total);
			goto out;
		}

		offset += chunk;
	}

	/* Step 3: Send FW_DOWNLOAD_DONE and wait for ACK */
	ret = sle_usb_send_cmd_sync(d, SLE_OP_FW_DL_DONE, NULL, 0,
				    resp, sizeof(resp), &resp_len);
	if (!ret)
		ret = sle_usb_validate_init_reply(resp, resp_len, SLE_OP_FW_DL_DONE, 0);
	if (ret)
		pr_err("sparklink-usb: fw download done cmd failed: %d\n", ret);
	else
		pr_info("sparklink-usb: firmware downloaded (%d bytes)\n", size);

out:
	kfree(pkt);
	return ret;
}
