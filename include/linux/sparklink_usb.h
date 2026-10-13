/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_SPARKLINK_USB_H
#define _LINUX_SPARKLINK_USB_H
#include <linux/types.h>
/* Internal process-context interface. Caller owns a context reference for the
 * full operation. Identity/USB references are immutable. Retirement serializes
 * with I/O, closes admission and joins RX before return; put releases ownership.
 * get/put do not revive a retired allocation or redirect to another index.
 */
struct sle_usb_dev;
/* Internal queried standard metadata, not a public UAPI or policy capability.
 * A zero buffer pair means absent. Features remain the full 80-bit wire value.
 */
struct sle_usb_capabilities {
	u16 command_max;
	u16 acb_length;
	u16 icb_length;
	u8 acb_count;
	u8 icb_count;
	u8 features[10];
};
/* One io_lock observation. Valid only after the whole bootstrap transaction;
 * no policy/Ready assertion and no separately mixed version/capability reads.
 */
struct sle_usb_metadata {
	struct sle_usb_capabilities capabilities;
	u8 version[5];
	u8 address[6];
	u8 command_credits;
};
int sle_usb_dev_register(int id, void *interface, u64 generation, struct sle_usb_dev **output);
void sle_usb_dev_get(struct sle_usb_dev *context);
void sle_usb_dev_put(struct sle_usb_dev *context);
void sle_usb_dev_unregister(struct sle_usb_dev *context);
int sle_usb_dev_send_cmd(struct sle_usb_dev *context, u16 opcode, const u8 *params, int length);
int sle_usb_dev_send_data(struct sle_usb_dev *context, u16 handle, const u8 *data, int length);
int sle_usb_dev_start_evt(struct sle_usb_dev *context);
void sle_usb_dev_stop_evt(struct sle_usb_dev *context);
int sle_usb_dev_start_data(struct sle_usb_dev *context);
void sle_usb_dev_stop_data(struct sle_usb_dev *context);
int sle_usb_dev_init_controller(struct sle_usb_dev *context);
u8 sle_usb_dev_get_command_credits(struct sle_usb_dev *context);
u32 sle_usb_dev_get_fw_version(struct sle_usb_dev *context);
int sle_usb_dev_get_metadata(struct sle_usb_dev *context, struct sle_usb_metadata *out);
int sle_usb_dev_get_mac(struct sle_usb_dev *context, u8 *mac);
int sle_usb_dev_download_fw(struct sle_usb_dev *context, const u8 *data, int size, int chunk_size);
int sle_usb_dev_suspend(struct sle_usb_dev *context);
int sle_usb_dev_resume(struct sle_usb_dev *context);
#endif
