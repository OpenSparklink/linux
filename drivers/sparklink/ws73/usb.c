// SPDX-License-Identifier: GPL-2.0-only
/*
 * WS73 USB boot transport. Protocol facts were checked against the WS73 SDK
 * and libws73-usb; this implementation uses the kernel USB/firmware/SHA APIs.
 * Runtime USB enumeration is not equivalent to SLE controller readiness.
 */
#include <crypto/sha2.h>
#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/hex.h>
#include <linux/ktime.h>
#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/sparklink_native.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/usb.h>
#include <linux/unaligned.h>
#include <linux/workqueue.h>

#include "bsle.h"
#include "dli.h"
#include "discovery.h"

#define WS73_VID		0xffff
#define WS73_PID		0x3733
#define WS73_FW_HEADER	64
#define WS73_FW_MAX	204736
#define WS73_FW_CHUNK	32768
#define WS73_TX_TIMEOUT	3000
#define WS73_RX_TIMEOUT	2000

enum ws73_stage {
	WS73_BOOT,
	WS73_LOADING,
	WS73_REENUMERATING,
	WS73_RUNTIME,
	WS73_WAIT_BSP,
	WS73_CONFIGURING,
	WS73_WAIT_CUSTOMIZE,
	WS73_OPENING,
	WS73_WAIT_BOOT,
	WS73_TRANSPORT_OPEN,
	WS73_QUERYING,
	WS73_METADATA_VALID,
	WS73_NATIVE_SETUP,
	WS73_FAILED,
	WS73_REMOVING,
};

struct ws73_usb {
	struct usb_device *udev;
	struct usb_interface *intf;
	struct work_struct boot_work;
	struct work_struct runtime_work;
	struct work_struct fault_work;
	struct kref references;
	struct mutex phase_lock;
	struct mutex tx_lock;
	struct urb *rx_urb;
	struct urb *notification_urb;
	bool streaming;
	bool broken;
	int native_id;
	u64 native_generation;
	int asynchronous_error;
	atomic_t unsupported_rx;
	u16 last_unsupported_event;
	u16 controller_error;
	u8 int_interval;
	enum ws73_stage stage;
	int last_error;
	bool stopping;
	u8 bulk_in;
	u8 bulk_out;
	u8 int_in;
	u8 reg_in;
	u8 reg_out;
	/* usb_bulk_msg() needs DMA-safe buffers, not firmware or stack memory. */
	u8 *tx;
	u8 *rx;
	size_t rx_size;
	u8 notification[8];
	u32 tx_sequence;
	bool runtime_transport;
	bool metadata_valid;
	unsigned int command_credits;
	struct ws73_dli_info info;
	struct ws73_dli_result dli_result;
};

static const struct {
	const char *name;
	u32 address;
} ws73_images[] = {
	{ "sparklink/ws73/ws73.bin", 0x400000 },
	{ "sparklink/ws73/wifi_cali.bin", 0x430000 },
	{ "sparklink/ws73/btc_cali.bin", 0x440000 },
};

static const struct {
	u32 address;
	u32 value;
} ws73_cali_banks[] = {
	{ 0x40017750, 51 },
	{ 0x40017790, 0 },
	{ 0x40017794, 0 },
	{ 0x4001775c, 0x430000 },
	{ 0x40017760, 0x438000 },
	{ 0x40017750, 63 },
	{ 0x40017750, 47 },
	{ 0x40017798, 0 },
	{ 0x40017764, 0x440000 },
	{ 0x40017750, 63 },
};

static int ws73_write(struct ws73_usb *ws, const void *data, size_t len)
{
	int ret, actual;

	if (READ_ONCE(ws->stopping) || READ_ONCE(ws->broken))
		return -ENODEV;
	if (!len || len > WS73_FW_CHUNK)
		return -EINVAL;
	if (data != ws->tx)
		memcpy(ws->tx, data, len);
	ret = usb_bulk_msg(ws->udev,
			   usb_sndbulkpipe(ws->udev, ws->bulk_out),
			   ws->tx, len, &actual, WS73_TX_TIMEOUT);
	if (ret)
		return ret;
	return actual == len ? 0 : -EREMOTEIO;
}

static int ws73_read(struct ws73_usb *ws, size_t len)
{
	int ret, actual;

	if (READ_ONCE(ws->stopping) || READ_ONCE(ws->broken))
		return -ENODEV;
	ret = usb_bulk_msg(ws->udev,
			   usb_rcvbulkpipe(ws->udev, ws->bulk_in),
			   ws->rx, len, &actual, WS73_RX_TIMEOUT);
	return ret ? ret : actual;
}

static int ws73_command(struct ws73_usb *ws, const char *command,
			const char *reply)
{
	size_t len = strlen(command);
	int ret;

	/* The boot ROM token delimiter is a space, not newline or NUL. */
	if (len + 1 > 128)
		return -EINVAL;
	memcpy(ws->tx, command, len);
	ws->tx[len++] = ' ';
	ret = ws73_write(ws, ws->tx, len);
	if (ret || !reply)
		return ret;
	ret = ws73_read(ws, 512);
	if (ret < 0)
		return ret;
	if (ret < strlen(reply) || memcmp(ws->rx, reply, strlen(reply)))
		return -EPROTO;
	return 0;
}

static int ws73_validate_image(const struct firmware *fw)
{
	u8 expected[SHA256_DIGEST_SIZE], actual[SHA256_DIGEST_SIZE];
	size_t i;

	if (fw->size <= WS73_FW_HEADER ||
	    fw->size > WS73_FW_HEADER + WS73_FW_MAX)
		return -EINVAL;
	/* SDK headers contain exactly 64 lowercase ASCII hex bytes. */
	for (i = 0; i < WS73_FW_HEADER; i++) {
		u8 c = fw->data[i];

		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
			return -EBADMSG;
	}
	if (hex2bin(expected, fw->data, sizeof(expected)))
		return -EBADMSG;
	sha256(fw->data + WS73_FW_HEADER, fw->size - WS73_FW_HEADER, actual);
	return memcmp(expected, actual, sizeof(actual)) ? -EBADMSG : 0;
}

static int ws73_download_image(struct ws73_usb *ws, const struct firmware *fw,
			       u32 address)
{
	size_t size = fw->size - WS73_FW_HEADER;
	size_t offset = 0;
	char command[128];
	int ret;

	while (offset < size) {
		size_t len = min_t(size_t, WS73_FW_CHUNK, size - offset);
		unsigned int state;

		if (size <= WS73_FW_CHUNK)
			state = 3;
		else if (!offset)
			state = 0;
		else if (offset + len == size)
			state = 2;
		else
			state = 1;
		snprintf(command, sizeof(command), "FILES 1 0x%x 0x%zx 0x%x",
			 address + (u32)offset, len, state);
		ret = ws73_command(ws, command, "READY");
		if (ret)
			return ret;
		usleep_range(5000, 6000);
		ret = ws73_write(ws, fw->data + WS73_FW_HEADER + offset, len);
		if (ret)
			return ret;
		ret = ws73_read(ws, 512);
		if (ret < 0)
			return ret;
		if (ret < 8 || memcmp(ws->rx, "FILES OK", 8))
			return -EPROTO;
		offset += len;
	}
	return 0;
}

static void ws73_boot_work(struct work_struct *work)
{
	struct ws73_usb *ws = container_of(work, struct ws73_usb, boot_work);
	const struct firmware *images[ARRAY_SIZE(ws73_images)] = {};
	char command[128];
	size_t i;
	int ret = 0;

	WRITE_ONCE(ws->stage, WS73_LOADING);
	/* Validate all images before the first device write. */
	for (i = 0; i < ARRAY_SIZE(images); i++) {
		ret = request_firmware(&images[i], ws73_images[i].name,
				       &ws->intf->dev);
		if (ret)
			goto out;
		ret = ws73_validate_image(images[i]);
		if (ret) {
			dev_err(&ws->intf->dev, "invalid firmware %s: %d\n",
				ws73_images[i].name, ret);
			goto out;
		}
	}

	ret = ws73_command(ws, "READM 0x40019380 4", NULL);
	if (ret)
		goto out;
	ret = ws73_read(ws, 4);
	if (ret != 4) {
		ret = ret < 0 ? ret : -EPROTO;
		goto out;
	}
	for (i = 0; i < ARRAY_SIZE(ws73_cali_banks); i++) {
		snprintf(command, sizeof(command), "WRITEM 4 0x%x %u",
			 ws73_cali_banks[i].address, ws73_cali_banks[i].value);
		ret = ws73_command(ws, command, "WRITEM OK");
		if (ret)
			goto out;
	}
	ret = ws73_command(ws, "WRITEM 4 0x40019408 0x3c08", "WRITEM OK");
	if (ret)
		goto out;
	for (i = 0; i < ARRAY_SIZE(images); i++) {
		ret = ws73_download_image(ws, images[i], ws73_images[i].address);
		if (ret)
			goto out;
		dev_info(&ws->intf->dev, "downloaded %s (%zu bytes)\n",
			 ws73_images[i].name, images[i]->size - WS73_FW_HEADER);
	}
	WRITE_ONCE(ws->stage, WS73_REENUMERATING);
	ret = ws73_command(ws, "QUIT", NULL);
	if (!ret)
		dev_info(&ws->intf->dev, "firmware sent; awaiting USB re-enumeration\n");
out:
	for (i = 0; i < ARRAY_SIZE(images); i++)
		release_firmware(images[i]);
	if (ret && !READ_ONCE(ws->stopping)) {
		WRITE_ONCE(ws->last_error, ret);
		WRITE_ONCE(ws->stage, WS73_FAILED);
		dev_err(&ws->intf->dev, "boot failed: %d\n", ret);
	}
}

static unsigned long long ws73_now_ms(void *context)
{
	return ktime_to_ms(ktime_get());
}

static int ws73_runtime_send(void *context, size_t size)
{
	struct ws73_usb *ws = context;

	return ws73_write(ws, ws->tx, size);
}

static int ws73_runtime_receive(void *context, unsigned int timeout_ms)
{
	struct ws73_usb *ws = context;
	int ret, actual;

	if (READ_ONCE(ws->stopping) || READ_ONCE(ws->broken))
		return -ENODEV;
	ret = usb_bulk_msg(ws->udev, usb_rcvbulkpipe(ws->udev, ws->bulk_in),
			   ws->rx, ws->rx_size, &actual, timeout_ms);
	return ret ? ret : actual;
}

static int ws73_notification(void *context, unsigned int timeout_ms, unsigned int *bits)
{
	struct ws73_usb *ws = context;
	int ret, actual;

	if (READ_ONCE(ws->stopping) || READ_ONCE(ws->broken))
		return -ENODEV;
	ret = usb_interrupt_msg(ws->udev, usb_rcvintpipe(ws->udev, ws->int_in),
				ws->notification, sizeof(ws->notification), &actual, timeout_ms);
	if (ret)
		return ret;
	if (actual != sizeof(ws->notification))
		return -EPROTO;
	*bits = get_unaligned_le32(ws->notification);
	return 0;
}

static int ws73_open_sle(void *context)
{
	struct ws73_usb *ws = context;
	int ret;

	if (READ_ONCE(ws->stopping) || READ_ONCE(ws->broken))
		return -ENODEV;
	/* H2D_MSG_SLE_OPEN is the ordinal 29, not a bit mask. */
	put_unaligned_le32(29, ws->tx);
	ret = usb_control_msg(ws->udev, usb_sndctrlpipe(ws->udev, 0), 0,
			      USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
			      0, 0, ws->tx, 4, WS73_TX_TIMEOUT);
	return ret < 0 ? ret : ret == 4 ? 0 : -EREMOTEIO;
}

static void ws73_runtime_phase(void *context, enum ws73_bsle_phase phase)
{
	struct ws73_usb *ws = context;
	static const enum ws73_stage stages[] = {
		WS73_WAIT_BSP, WS73_CONFIGURING, WS73_WAIT_CUSTOMIZE,
		WS73_OPENING, WS73_WAIT_BOOT, WS73_TRANSPORT_OPEN,
	};

	if (!READ_ONCE(ws->stopping)) {
		WRITE_ONCE(ws->stage, stages[phase]);
		dev_info(&ws->intf->dev, "BSLE phase %u\n", phase);
	}
}

static void ws73_release(struct kref *reference)
{
	struct ws73_usb *ws = container_of(reference, struct ws73_usb, references);

	usb_free_urb(ws->notification_urb);
	usb_free_urb(ws->rx_urb);
	usb_put_dev(ws->udev);
	kfree(ws->rx);
	kfree(ws->tx);
	kfree(ws);
}

static void ws73_native_get(void *context)
{
	struct ws73_usb *ws = context;

	kref_get(&ws->references);
}

static void ws73_native_put(void *context)
{
	struct ws73_usb *ws = context;

	kref_put(&ws->references, ws73_release);
}

static void ws73_native_close(void *context)
{
	struct ws73_usb *ws = context;

	WRITE_ONCE(ws->streaming, false);
	usb_kill_urb(ws->notification_urb);
	usb_kill_urb(ws->rx_urb);
}

static void ws73_fault_work(struct work_struct *work)
{
	struct ws73_usb *ws = container_of(work, struct ws73_usb, fault_work);

	/* Serialize with the bootstrap's registration, never unregister in IRQ. */
	mutex_lock(&ws->phase_lock);
	if (!READ_ONCE(ws->stopping)) {
		if (ws->native_id >= 0) {
			sparklink_native_unregister(ws->native_id, ws->native_generation);
			WRITE_ONCE(ws->native_id, -1);
		}
		WRITE_ONCE(ws->last_error, READ_ONCE(ws->asynchronous_error));
		WRITE_ONCE(ws->stage, WS73_FAILED);
		dev_err(&ws->intf->dev, "native RX stopped: %d\n", ws->last_error);
	}
	mutex_unlock(&ws->phase_lock);
}

static void ws73_async_failure(struct ws73_usb *ws, int error)
{
	WRITE_ONCE(ws->broken, true);
	WRITE_ONCE(ws->streaming, false);
	if (cmpxchg(&ws->asynchronous_error, 0, error))
		return; /* retain first transport failure */
	if (!READ_ONCE(ws->stopping))
		schedule_work(&ws->fault_work);
}

static int ws73_native_packet(void *context, unsigned int service, unsigned int queue,
			      const unsigned char *data, size_t size)
{
	struct ws73_usb *ws = context;
	int ret;

	if (service != WS73_WIRE_SLE_SERVICE || queue != WS73_WIRE_SLE_QUEUE)
		return 0;
	if (size >= 5 && data[0] == 0xa2 && get_unaligned_le16(data + 1) == WS73_DISC_REPORT_EVENT) {
		struct ws73_discovery_report report;

		if (get_unaligned_le16(data + 3) != size - 5)
			return -EPROTO;
		ret = ws73_discovery_report_decode(data + 5, size - 5, &report);
		if (ret)
			return ret;
		return sparklink_native_event(ws->native_id, ws->native_generation,
					      SPARKLINK_NATIVE_WS73_HCC, WS73_DISC_REPORT_EVENT,
					      report.header, size - 5);
	}
	ret = sparklink_native_receive(ws->native_id, ws->native_generation, data, size);
	if (ret == -EOPNOTSUPP) {
		atomic_inc(&ws->unsupported_rx);
		if (size >= 5 && data[0] == 0xa2)
			WRITE_ONCE(ws->last_unsupported_event, get_unaligned_le16(data + 1));
		return 0; /* no fabricated domain event or completion */
	}
	if (!ret && size == 6 && data[0] == 0xa2 && get_unaligned_le16(data + 1) == 0x000a) {
		WRITE_ONCE(ws->controller_error, data[5]);
		ws73_async_failure(ws, -EIO);
	}
	return ret;
}

static void ws73_native_rx_complete(struct urb *urb)
{
	struct ws73_usb *ws = urb->context;
	int ret;

	if (!READ_ONCE(ws->streaming) || READ_ONCE(ws->stopping))
		return;
	if (urb->status) {
		ws73_async_failure(ws, urb->status);
		return;
	}
	if (urb == ws->notification_urb) {
		if (urb->actual_length != sizeof(ws->notification))
			ret = -EPROTO;
		else if (get_unaligned_le32(ws->notification) & BIT(6))
			ret = -EIO;
		else
			ret = 0;
	} else {
		ret = ws73_wire_receive(ws->rx, urb->actual_length, ws73_native_packet, ws);
	}
	if (ret == -ENODEV) {
		WRITE_ONCE(ws->streaming, false); /* retired generation, not another owner */
		return;
	}
	if (ret) {
		ws73_async_failure(ws, ret);
		return;
	}
	if (!READ_ONCE(ws->streaming) || READ_ONCE(ws->stopping))
		return;
	ret = usb_submit_urb(urb, GFP_ATOMIC);
	if (ret && READ_ONCE(ws->streaming) && !READ_ONCE(ws->stopping))
		ws73_async_failure(ws, ret);
}

static int ws73_native_open(void *context, u16 id, u64 generation)
{
	struct ws73_usb *ws = context;
	int ret;

	if (READ_ONCE(ws->stopping) || READ_ONCE(ws->broken))
		return -ENODEV;
	if (ws->rx_urb || ws->notification_urb)
		return -EBUSY;
	ws->rx_urb = usb_alloc_urb(0, GFP_KERNEL);
	ws->notification_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!ws->rx_urb || !ws->notification_urb) {
		ret = -ENOMEM;
		goto fail;
	}
	ws->native_id = id;
	ws->native_generation = generation;
	usb_fill_bulk_urb(ws->rx_urb, ws->udev, usb_rcvbulkpipe(ws->udev, ws->bulk_in),
			  ws->rx, ws->rx_size, ws73_native_rx_complete, ws);
	usb_fill_int_urb(ws->notification_urb, ws->udev,
			 usb_rcvintpipe(ws->udev, ws->int_in), ws->notification,
			 sizeof(ws->notification), ws73_native_rx_complete, ws, ws->int_interval);
	WRITE_ONCE(ws->streaming, true);
	ret = usb_submit_urb(ws->rx_urb, GFP_KERNEL);
	if (ret)
		goto fail;
	ret = usb_submit_urb(ws->notification_urb, GFP_KERNEL);
	if (!ret)
		return 0;
fail:
	ws73_native_close(ws);
	usb_free_urb(ws->notification_urb);
	usb_free_urb(ws->rx_urb);
	ws->notification_urb = NULL;
	ws->rx_urb = NULL;
	ws->native_id = -1;
	return ret;
}

static int ws73_native_validate(void *context, u16 opcode, const u8 *params, size_t length)
{
	return ws73_dli_validate_command(opcode, params, length);
}

static int ws73_native_command(void *context, u16 opcode, const u8 *params, size_t length)
{
	struct ws73_usb *ws = context;
	int ret;

	mutex_lock(&ws->tx_lock);
	if (READ_ONCE(ws->stopping) || READ_ONCE(ws->broken) || !READ_ONCE(ws->streaming)) {
		ret = -ENODEV;
		goto out;
	}
	ret = ws73_wire_command(ws->tx, WS73_FW_CHUNK, ws->tx_sequence, opcode, params, length);
	if (ret < 0)
		goto out;
	ws->tx_sequence++;
	ret = ws73_write(ws, ws->tx, ret);
	if (ret && !READ_ONCE(ws->stopping))
		ws73_async_failure(ws, ret);
out:
	mutex_unlock(&ws->tx_lock);
	return ret;
}

static const struct sparklink_native_ops ws73_native_ops = {
	.owner = THIS_MODULE,
	.get = ws73_native_get,
	.put = ws73_native_put,
	.open = ws73_native_open,
	.close = ws73_native_close,
	.validate_command = ws73_native_validate,
	.send_command = ws73_native_command,
};

static void ws73_runtime_work(struct work_struct *work)
{
	struct ws73_usb *ws = container_of(work, struct ws73_usb, runtime_work);
	const struct firmware *custom = NULL, *pm = NULL;
	struct ws73_bsle_io io = {
		.context = ws,
		.tx = ws->tx,
		.tx_capacity = WS73_FW_CHUNK,
		.rx = ws->rx,
		.rx_capacity = ws->rx_size,
		.sequence = &ws->tx_sequence,
		.now_ms = ws73_now_ms,
		.send = ws73_runtime_send,
		.receive = ws73_runtime_receive,
		.notification = ws73_notification,
		.open = ws73_open_sle,
		.phase = ws73_runtime_phase,
	};
	u8 digest[SHA256_DIGEST_SIZE];
	struct sparklink_native_info native_info = {};
	struct sparklink_native_identity identity;
	unsigned int credits = 1; /* one probe window after fresh BSLE open */
	int ret;

	mutex_lock(&ws->phase_lock);
	/* Board configuration is supplied by deployment, never guessed from
	 * another dongle or synthesized as an all-zero calibration block.
	 * Validate both inputs before sending any runtime command.
	 */
	ret = request_firmware(&custom, "sparklink/ws73/bsle_custom.bin", &ws->intf->dev);
	if (ret)
		goto out;
	ret = request_firmware(&pm, "sparklink/ws73/pm_config.bin", &ws->intf->dev);
	if (ret)
		goto out;
	if (custom->size != WS73_WIRE_CUSTOM_DATA_SIZE || pm->size != 4) {
		ret = -EINVAL;
		goto out;
	}
	sha256(custom->data, custom->size, digest);
	dev_info(&ws->intf->dev, "BSLE customize SHA256=%*phN\n", (int)sizeof(digest), digest);
	sha256(pm->data, pm->size, digest);
	dev_info(&ws->intf->dev, "PM config SHA256=%*phN\n", (int)sizeof(digest), digest);
	ret = ws73_bsle_start(&io, pm->data, pm->size, custom->data, custom->size);
	if (ret)
		goto out;
	WRITE_ONCE(ws->stage, WS73_QUERYING);
	ws->dli_result.status = 0x100;
	ret = ws73_dli_query(&io, &credits, &ws->info, &ws->dli_result);
	if (ret)
		goto out;
	if (READ_ONCE(ws->stopping)) {
		ret = -ENODEV;
		goto out;
	}
	ws->command_credits = credits;
	/* info is immutable after this release publication until disconnect. */
	smp_store_release(&ws->metadata_valid, true);
	WRITE_ONCE(ws->stage, WS73_METADATA_VALID);
	dev_info(&ws->intf->dev,
		 "DLI metadata verified: version=%5phN features=%10phN address=%pM credits=%u\n",
		 ws->info.version, ws->info.features, ws->info.address, credits);
	native_info.profile = SPARKLINK_NATIVE_WS73_HCC;
	memcpy(native_info.version, ws->info.version, sizeof(native_info.version));
	memcpy(native_info.features, ws->info.features, sizeof(native_info.features));
	memcpy(native_info.address, ws->info.address, sizeof(native_info.address));
	native_info.acb_length = ws->info.acb_length;
	native_info.acb_count = ws->info.acb_count;
	native_info.icb_length = ws->info.icb_length;
	native_info.icb_count = ws->info.icb_count;
	native_info.command_credits = credits;
	ret = sparklink_native_register(&native_info, &ws73_native_ops, ws, &identity);
	if (ret)
		goto out;
	WRITE_ONCE(ws->stage, WS73_NATIVE_SETUP);
	dev_info(&ws->intf->dev, "native Runtime sle%u generation=%llu SETUP, not Ready\n",
		 identity.id, identity.generation);
out:
	release_firmware(pm);
	release_firmware(custom);
	if (ret && !READ_ONCE(ws->stopping)) {
		WRITE_ONCE(ws->last_error, ret);
		WRITE_ONCE(ws->stage, WS73_FAILED);
		dev_err(&ws->intf->dev, "runtime bring-up failed: %d\n", ret);
		if (ws->dli_result.opcode)
			dev_err(&ws->intf->dev, "DLI query opcode=%04x controller_status=%x\n",
				ws->dli_result.opcode, ws->dli_result.status);
	}
	mutex_unlock(&ws->phase_lock);
}

static ssize_t boot_stage_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct ws73_usb *ws = usb_get_intfdata(to_usb_interface(dev));
	static const char * const names[] = {
		"boot", "loading", "reenumerating", "runtime-awaiting-sle",
		"bsle-wait-bsp", "bsle-configuring", "bsle-wait-customize",
		"bsle-opening", "bsle-wait-boot", "sle-awaiting-dli",
		"dli-querying", "dli-awaiting-runtime", "native-runtime-setup",
		"failed", "removing",
	};

	return sysfs_emit(buf, "%s\n", names[READ_ONCE(ws->stage)]);
}
static DEVICE_ATTR_RO(boot_stage);

static ssize_t boot_error_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct ws73_usb *ws = usb_get_intfdata(to_usb_interface(dev));

	return sysfs_emit(buf, "%d\n", READ_ONCE(ws->last_error));
}
static DEVICE_ATTR_RO(boot_error);

static ssize_t runtime_transport_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	struct ws73_usb *ws = usb_get_intfdata(to_usb_interface(dev));

	/* Descriptor validation only; this is explicitly not Ready. */
	return sysfs_emit(buf, "%u\n", ws->runtime_transport);
}
static DEVICE_ATTR_RO(runtime_transport);

static ssize_t metadata_valid_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct ws73_usb *ws = usb_get_intfdata(to_usb_interface(dev));

	return sysfs_emit(buf, "%u\n", READ_ONCE(ws->metadata_valid));
}
static DEVICE_ATTR_RO(metadata_valid);

static ssize_t controller_information_show(struct device *dev,
					   struct device_attribute *attr, char *buf)
{
	struct ws73_usb *ws = usb_get_intfdata(to_usb_interface(dev));

	/* Paired with runtime_work's release publication of immutable info. */
	if (!smp_load_acquire(&ws->metadata_valid))
		return -ENODATA;
	return sysfs_emit(buf,
			  "version=%5phN features=%10phN address=%pM acb=%u/%u icb=%u/%u bootstrap_credits=%u\n",
			  ws->info.version, ws->info.features, ws->info.address,
			  ws->info.acb_length, ws->info.acb_count,
			  ws->info.icb_length, ws->info.icb_count, ws->command_credits);
}
static DEVICE_ATTR_RO(controller_information);

static ssize_t native_runtime_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct ws73_usb *ws = usb_get_intfdata(to_usb_interface(dev));

	return sysfs_emit(buf,
			 "id=%d generation=%llu streaming=%u broken=%u unsupported=%d last_event=%04x controller_error=%x\n",
			 READ_ONCE(ws->native_id), READ_ONCE(ws->native_generation),
			 READ_ONCE(ws->streaming), READ_ONCE(ws->broken),
			 atomic_read(&ws->unsupported_rx), READ_ONCE(ws->last_unsupported_event),
			 READ_ONCE(ws->controller_error));
}
static DEVICE_ATTR_RO(native_runtime);

static struct attribute *ws73_attrs[] = {
	&dev_attr_boot_stage.attr,
	&dev_attr_boot_error.attr,
	&dev_attr_runtime_transport.attr,
	&dev_attr_metadata_valid.attr,
	&dev_attr_native_runtime.attr,
	&dev_attr_controller_information.attr,
	NULL,
};
ATTRIBUTE_GROUPS(ws73);

static int ws73_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
	struct usb_host_interface *alt = intf->cur_altsetting;
	struct ws73_usb *ws;
	unsigned int i;
	u8 eps;

	if (alt->desc.bInterfaceNumber ||
	    alt->desc.bInterfaceClass != 0xe0 ||
	    alt->desc.bInterfaceSubClass != 0x02 ||
	    alt->desc.bInterfaceProtocol != 0x02)
		return -ENODEV;
	eps = alt->desc.bNumEndpoints;
	if (eps != 2 && eps != 5)
		return -ENODEV;

	ws = kzalloc_obj(*ws);
	if (!ws)
		return -ENOMEM;
	/* Validate the known roles by address and transfer type, not ordering. */
	for (i = 0; i < eps; i++) {
		const struct usb_endpoint_descriptor *ep = &alt->endpoint[i].desc;

		if (usb_endpoint_is_bulk_in(ep) && ep->bEndpointAddress == 0x81)
			ws->bulk_in = ep->bEndpointAddress;
		else if (usb_endpoint_is_bulk_out(ep) && ep->bEndpointAddress == 0x01)
			ws->bulk_out = ep->bEndpointAddress;
		else if (usb_endpoint_is_int_in(ep) && ep->bEndpointAddress == 0x83) {
			ws->int_in = ep->bEndpointAddress;
			ws->int_interval = ep->bInterval;
		} else if (usb_endpoint_is_bulk_in(ep) && ep->bEndpointAddress == 0x82)
			ws->reg_in = ep->bEndpointAddress;
		else if (usb_endpoint_is_bulk_out(ep) && ep->bEndpointAddress == 0x02)
			ws->reg_out = ep->bEndpointAddress;
		else
			goto unsupported;
	}
	if (!ws->bulk_in || !ws->bulk_out ||
	    (eps == 5 && (!ws->int_in || !ws->int_interval || !ws->reg_in || !ws->reg_out)))
		goto unsupported;
	ws->tx = kmalloc(WS73_FW_CHUNK, GFP_KERNEL);
	ws->rx_size = eps == 5 ? WS73_WIRE_RX_MAX : 512;
	ws->rx = kmalloc(ws->rx_size, GFP_KERNEL);
	if (!ws->tx || !ws->rx) {
		kfree(ws->rx);
		kfree(ws->tx);
		kfree(ws);
		return -ENOMEM;
	}
	kref_init(&ws->references);
	mutex_init(&ws->phase_lock);
	mutex_init(&ws->tx_lock);
	ws->native_id = -1;
	ws->controller_error = 0x100; /* no controller error byte observed */
	atomic_set(&ws->unsupported_rx, 0);
	ws->udev = usb_get_dev(interface_to_usbdev(intf));
	ws->intf = intf;
	ws->stage = eps == 2 ? WS73_BOOT : WS73_RUNTIME;
	ws->runtime_transport = eps == 5;
	INIT_WORK(&ws->boot_work, ws73_boot_work);
	INIT_WORK(&ws->runtime_work, ws73_runtime_work);
	INIT_WORK(&ws->fault_work, ws73_fault_work);
	usb_set_intfdata(intf, ws);
	dev_info(&intf->dev, "WS73 %s interface (%u endpoints)\n",
		 eps == 2 ? "boot" : "runtime", eps);
	if (eps == 2)
		schedule_work(&ws->boot_work);
	else
		schedule_work(&ws->runtime_work);
	return 0;
unsupported:
	kfree(ws);
	return -ENODEV;
}

static void ws73_disconnect(struct usb_interface *intf)
{
	struct ws73_usb *ws = usb_get_intfdata(intf);

	WRITE_ONCE(ws->stopping, true);
	cancel_work_sync(&ws->boot_work);
	cancel_work_sync(&ws->runtime_work);
	cancel_work_sync(&ws->fault_work);
	if (ws->native_id >= 0) {
		sparklink_native_unregister(ws->native_id, ws->native_generation);
		ws->native_id = -1;
	}
	ws73_native_close(ws);
	WRITE_ONCE(ws->stage, WS73_REMOVING);
	usb_set_intfdata(intf, NULL);
	kref_put(&ws->references, ws73_release);
}

static const struct usb_device_id ws73_ids[] = {
	{ USB_DEVICE(WS73_VID, WS73_PID) },
	{},
};
MODULE_DEVICE_TABLE(usb, ws73_ids);

static struct usb_driver ws73_driver = {
	.name = "sparklink_ws73_usb",
	.probe = ws73_probe,
	.disconnect = ws73_disconnect,
	.id_table = ws73_ids,
	.dev_groups = ws73_groups,
};
module_usb_driver(ws73_driver);

MODULE_DESCRIPTION("WS73 USB firmware, BSLE and native Runtime transport for SparkLink");
MODULE_LICENSE("GPL");
MODULE_FIRMWARE("sparklink/ws73/ws73.bin");
MODULE_FIRMWARE("sparklink/ws73/wifi_cali.bin");
MODULE_FIRMWARE("sparklink/ws73/btc_cali.bin");
MODULE_FIRMWARE("sparklink/ws73/bsle_custom.bin");
MODULE_FIRMWARE("sparklink/ws73/pm_config.bin");
