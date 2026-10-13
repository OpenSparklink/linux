// SPDX-License-Identifier: GPL-2.0
/*
 * SparkLink USB transport FFI helpers.
 *
 * Provides thin C wrappers around the kernel USB URB API for consumption
 * by the Rust sle_usb module. The wrappers handle the unsafe parts of
 * URB lifecycle management (allocation, fill, submit, complete) and
 * expose a minimal, type-safe surface to Rust.
 *
 * Actual ownership: UsbDevice retains a per-probe context. C owns the two RX
 * URBs; registered callbacks carry immutable id/generation into Runtime ingress.
 * Low-level RX helpers are private implementation details, not a second Rust API.
 */

#include <linux/usb.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/sparklink_usb.h>
#include <linux/sparklink_backend.h>
#include <linux/unaligned.h>

/* -----------------------------------------------------------------------
 * Rust-side completion callback declaration
 * -----------------------------------------------------------------------
 * Rust provides this function via #[no_mangle]. It receives:
 *   dev_id/generation — immutable registration identity of the RX allocation
 *   data     — pointer to the transfer buffer
 *   length   — actual number of bytes transferred
 *   status   — URB completion status (0 = success, negative = error)
 */
extern void sparklink_usb_registered_complete(u32 dev_id, u64 generation,
					      const u8 *data, int length, u8 lane,
					      int status);

/* Private RX lifecycle helpers. */
static struct sle_urb_ctx *sle_usb_alloc_ctx(int buf_size);
static void sle_usb_free_ctx(struct sle_urb_ctx *ctx);
static int sle_usb_submit_bulk_in(struct sle_urb_ctx *ctx,
			   struct usb_device *udev, u8 ep);
static int sle_usb_submit_intr_in(struct sle_urb_ctx *ctx,
			   struct usb_device *udev, u8 ep, int interval);
static void sle_usb_kill_ctx(struct sle_urb_ctx *ctx);

/* -----------------------------------------------------------------------
 * URB context: bookkeeping for in-flight transfers
 * -----------------------------------------------------------------------
 */
struct sle_urb_ctx {
	struct urb *urb;
	u8 *buf;
	int buf_size;
	/* Immutable after registration, before first submit. USB kill/join
	 * precedes free; identity belongs to this URB allocation, not its slot.
	 */
	u32 registration_id;
	u64 registration_generation;
};

/* -----------------------------------------------------------------------
 * Completion handler: called by USB core when transfer finishes
 * -----------------------------------------------------------------------
 */
static void sle_usb_receive_complete(struct sle_urb_ctx *ctx, struct urb *urb, u8 lane)
{
	/* All live RX URBs belong to a registered immutable identity. */
	sparklink_usb_registered_complete(ctx->registration_id,
					  ctx->registration_generation,
					  ctx->buf, urb->actual_length, lane,
					  urb->status);
}

/* Bulk IN (data) callback with auto-resubmit for continuous reception */
static void sle_usb_bulk_in_cb(struct urb *urb)
{
	struct sle_urb_ctx *ctx = urb->context;

	sle_usb_receive_complete(ctx, urb, 2);

	/* Auto-resubmit unless cancelled or device disconnected */
	if (urb->status == 0 || urb->status == -EOVERFLOW) {
		int ret = usb_submit_urb(urb, GFP_ATOMIC);
		if (ret)
			pr_err("sparklink-usb: bulk-in resubmit failed: %d\n",
			       ret);
	}
}

static void sle_usb_intr_cb(struct urb *urb)
{
	struct sle_urb_ctx *ctx = urb->context;

	sle_usb_receive_complete(ctx, urb, 1);

	/* For interrupt IN endpoints: auto-resubmit unless cancelled */
	if (urb->status == 0 || urb->status == -EOVERFLOW) {
		int ret = usb_submit_urb(urb, GFP_ATOMIC);
		if (ret)
			pr_err("sparklink-usb: intr resubmit failed: %d\n",
			       ret);
	}
}

/* -----------------------------------------------------------------------
 * Private RX allocation and submission helpers
 * -----------------------------------------------------------------------
 */

/**
 * sle_usb_alloc_ctx - Allocate a URB context for SparkLink transfers.
 * @buf_size: size of the transfer buffer
 *
 * Returns NULL on allocation failure.
 */
static struct sle_urb_ctx *sle_usb_alloc_ctx(int buf_size)
{
	struct sle_urb_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	ctx->urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!ctx->urb) {
		kfree(ctx);
		return NULL;
	}

	ctx->buf = kmalloc(buf_size, GFP_KERNEL);
	if (!ctx->buf) {
		usb_free_urb(ctx->urb);
		kfree(ctx);
		return NULL;
	}

	ctx->buf_size = buf_size;
	return ctx;
}

/**
 * sle_usb_free_ctx - Free a URB context and its resources.
 * @ctx: context allocated by sle_usb_alloc_ctx
 */
static void sle_usb_free_ctx(struct sle_urb_ctx *ctx)
{
	if (!ctx)
		return;
	usb_free_urb(ctx->urb);
	kfree(ctx->buf);
	kfree(ctx);
}



/**
 * sle_usb_submit_bulk_in - Submit a bulk IN transfer (device to host).
 * @ctx:       URB context
 * @udev:      USB device
 * @ep:        endpoint address (e.g. 0x92)
 *
 * Returns 0 on success, negative errno on failure.
 */
static int sle_usb_submit_bulk_in(struct sle_urb_ctx *ctx,
			   struct usb_device *udev, u8 ep)
{
	unsigned int pipe;

	if (!ctx || !udev)
		return -EINVAL;

	pipe = usb_rcvbulkpipe(udev, ep);

	usb_fill_bulk_urb(ctx->urb, udev, pipe,
			  ctx->buf, ctx->buf_size,
			  sle_usb_bulk_in_cb, ctx);

	return usb_submit_urb(ctx->urb, GFP_KERNEL);
}

/**
 * sle_usb_submit_intr_in - Submit an interrupt IN transfer (events).
 * @ctx:       URB context
 * @udev:      USB device
 * @ep:        endpoint address (e.g. 0x91)
 * @interval:  polling interval (from endpoint descriptor)
 *
 * Returns 0 on success, negative errno on failure.
 * The URB auto-resubmits on successful completion.
 */
static int sle_usb_submit_intr_in(struct sle_urb_ctx *ctx,
			   struct usb_device *udev, u8 ep, int interval)
{
	unsigned int pipe;

	if (!ctx || !udev)
		return -EINVAL;

	pipe = usb_rcvintpipe(udev, ep);

	usb_fill_int_urb(ctx->urb, udev, pipe,
			 ctx->buf, ctx->buf_size,
			 sle_usb_intr_cb, ctx, interval);

	return usb_submit_urb(ctx->urb, GFP_KERNEL);
}

/**
 * sle_usb_kill_ctx - Cancel a pending URB.
 * @ctx: URB context
 */
static void sle_usb_kill_ctx(struct sle_urb_ctx *ctx)
{
	if (ctx && ctx->urb)
		usb_kill_urb(ctx->urb);
}





/* =======================================================================
 * Per-probe USB context ownership
 *
 * References pin one allocation and immutable registration identity. No
 * operation resolves a reusable registry index to transport resources.
 * ======================================================================= */

#define SLE_USB_MAX_DEVS 16
#define SLE_USB_EVENT_MAX 65539 /* four-byte header + u16 event parameters */

/* USB types are implicit in EP0, interrupt and bulk endpoint lanes. */

/* Timeout for synchronous command transfers (ms) */
#define SLE_CMD_TIMEOUT_MS 5000

struct sle_usb_dev {
	refcount_t references;
	struct mutex io_lock;
	u16 id;
	u64 generation;
	bool active;
	bool suspended;
	struct usb_interface *intf;
	struct usb_device *udev;
	struct sle_urb_ctx *evt_urb;  /* interrupt IN for events */
	struct sle_urb_ctx *rx_urb;   /* bulk IN for data */
	/* Discovered endpoint addresses (from endpoint descriptors) */
	u8 ep_bulk_in;                /* 0x92 per T/XS 10003 */
	u8 ep_bulk_out;               /* 0x12 per T/XS 10003 */
	u8 ep_intr_in;                /* 0x91 per T/XS 10003 */
	u16 ep_bulk_in_size;          /* wMaxPacketSize */
	u16 ep_intr_in_size;
	u8 command_request_type;
	u16 command_index;
	u8 ep_intr_in_interval;       /* bInterval */
	/* Read-back from controller during init */
	u8 mac_addr[6];
	u32 fw_version;
	u8 version[5];
	struct sle_usb_capabilities capabilities;
	bool metadata_valid;
	u8 command_credits;
};

/* One allocation per probe. Identity and USB references never change. Every
 * caller owns a reference; process I/O and retirement serialize on io_lock.
 * URBs are killed/joined before release, callbacks carry immutable identity.
 */
static void sle_usb_dev_release(struct sle_usb_dev *d)
{
	if (d->evt_urb) { sle_usb_kill_ctx(d->evt_urb); sle_usb_free_ctx(d->evt_urb); }
	if (d->rx_urb) { sle_usb_kill_ctx(d->rx_urb); sle_usb_free_ctx(d->rx_urb); }
	usb_put_intf(d->intf);
	usb_put_dev(d->udev);
	kfree(d);
}

void sle_usb_dev_get(struct sle_usb_dev *d) { refcount_inc(&d->references); }
void sle_usb_dev_put(struct sle_usb_dev *d)
{
	if (refcount_dec_and_test(&d->references)) sle_usb_dev_release(d);
}

/**
 * sle_usb_dev_register - Register a USB device for I/O by dev_id.
 * @dev_id:   reserved pending identity index
 * @intf_ptr: raw struct usb_interface pointer (from Rust probe)
 * @generation: nonzero registration generation allocated by the registry
 *
 * Extracts the usb_device, allocates URB contexts for event and data
 * reception. Returns 0 on success.
 */
int sle_usb_dev_register(int dev_id, void *intf_ptr, u64 generation,
			 struct sle_usb_dev **output)
{
	struct sle_usb_dev *d;
	struct usb_interface *intf;
	struct usb_endpoint_descriptor *bulk_in, *bulk_out, *int_in;
	struct sle_urb_ctx *evt_urb, *rx_urb;
	int ret;

	if (dev_id < 0 || dev_id >= SLE_USB_MAX_DEVS || !intf_ptr || !generation || !output)
		return -EINVAL;

	intf = (struct usb_interface *)intf_ptr;

	/* A missing descriptor is not a test controller. Discover and allocate
	 * privately; return the owning allocation only after preparation succeeds.
	 */
	ret = usb_find_common_endpoints(intf->cur_altsetting,
					&bulk_in, &bulk_out, &int_in, NULL);
	if (ret)
		return ret;
	if (!usb_endpoint_maxp(bulk_in) || !usb_endpoint_maxp(bulk_out) ||
	    !usb_endpoint_maxp(int_in) || !int_in->bInterval)
		return -EPROTO;

	evt_urb = sle_usb_alloc_ctx(SLE_USB_EVENT_MAX);
	if (!evt_urb)
		return -ENOMEM;
	rx_urb = sle_usb_alloc_ctx(usb_endpoint_maxp(bulk_in));
	if (!rx_urb) {
		sle_usb_free_ctx(evt_urb);
		return -ENOMEM;
	}

	d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (!d) {
		sle_usb_free_ctx(rx_urb);
		sle_usb_free_ctx(evt_urb);
		return -ENOMEM;
	}
	refcount_set(&d->references, 1);
	mutex_init(&d->io_lock);
	d->id = dev_id;
	d->generation = generation;
	d->intf = usb_get_intf(intf);
	d->udev = usb_get_dev(interface_to_usbdev(intf));
	/* Standard section6.2.2: device recipient for a single DLI function,
	 * interface recipient otherwise; addressing is immutable per binding.
	 */
	if (d->udev->descriptor.bDeviceClass == 0xe0 &&
	    d->udev->descriptor.bDeviceSubClass == 0x01 &&
	    d->udev->descriptor.bDeviceProtocol == 0x05) {
		d->command_request_type = USB_TYPE_CLASS | USB_RECIP_DEVICE;
		d->command_index = 0;
	} else {
		d->command_request_type = USB_TYPE_CLASS | USB_RECIP_INTERFACE;
		d->command_index = intf->cur_altsetting->desc.bInterfaceNumber;
	}
	d->ep_bulk_in = bulk_in->bEndpointAddress;
	d->ep_bulk_out = bulk_out->bEndpointAddress;
	d->ep_intr_in = int_in->bEndpointAddress;
	d->ep_bulk_in_size = usb_endpoint_maxp(bulk_in);
	d->ep_intr_in_size = usb_endpoint_maxp(int_in);
	d->ep_intr_in_interval = int_in->bInterval;
	d->evt_urb = evt_urb;
	d->rx_urb = rx_urb;
	d->suspended = false;
	d->command_credits = 0;

	memset(d->mac_addr, 0, 6);
	d->fw_version = 0;
	memset(d->version, 0, sizeof(d->version));
	d->metadata_valid = false;
	d->evt_urb->registration_id = dev_id;
	d->evt_urb->registration_generation = generation;
	d->rx_urb->registration_id = dev_id;
	d->rx_urb->registration_generation = generation;
	d->active = true;
	*output = d;
	return 0;
}

/**
 * sle_usb_dev_unregister - Remove a device from the USB I/O table.
 * @d: retained USB context
 *
 * Cancels pending URBs and frees resources.
 */
void sle_usb_dev_unregister(struct sle_usb_dev *d)
{


	if (!d) return;
	mutex_lock(&d->io_lock);
	if (!d->active) { mutex_unlock(&d->io_lock); return; }
	d->active = false;

	if (d->evt_urb) {
		sle_usb_kill_ctx(d->evt_urb);
		sle_usb_free_ctx(d->evt_urb);
		d->evt_urb = NULL;
	}
	if (d->rx_urb) {
		sle_usb_kill_ctx(d->rx_urb);
		sle_usb_free_ctx(d->rx_urb);
		d->rx_urb = NULL;
	}

	mutex_unlock(&d->io_lock);
}

/**
 * sle_usb_dev_send_cmd - Send a standard DLI command via USB EP0.
 * @d: retained USB context
 * @opcode: DLI opcode (host byte order)
 * @params: parameter bytes
 * @plen:   parameter length
 *
 * Builds a DLI command packet and sends synchronously.
 * Returns 0 on success, negative errno on failure.
 */
/* Standard USB has no UART/H4 packet marker. One complete DLI command
 * uses EP0, bRequest/wValue zero and the binding's descriptor-selected target.
 * wLength is u16 including the four-byte DLI header, not the parameter limit.
 */
static int sle_usb_write_command_locked(struct sle_usb_dev *d, u16 opcode,
				 const u8 *params, int plen, int timeout)
{
	u8 *pkt;
	int total, ret;

	if (!d->active || !d->udev)
		return -ENODEV;
	if (plen < 0 || (plen && !params))
		return -EINVAL;
	if (plen > 65531)
		return -EMSGSIZE;
	total = 4 + plen;
	pkt = kmalloc(total, GFP_KERNEL);
	if (!pkt)
		return -ENOMEM;
	put_unaligned_le16(opcode, pkt);
	put_unaligned_le16(plen, pkt + 2);
	if (plen)
		memcpy(pkt + 4, params, plen);
	ret = usb_control_msg(d->udev, usb_sndctrlpipe(d->udev, 0),
		0, d->command_request_type, 0, d->command_index,
		pkt, total, timeout);
	kfree(pkt);
	if (ret < 0)
		return ret;
	return ret == total ? 0 : -EREMOTEIO;
}

static int sle_usb_dev_send_cmd_locked(struct sle_usb_dev *d, u16 opcode,
				     const u8 *params, int plen)
{
	/* Current Host queue supports255 parameter bytes. A codec bound is not
	 * an advertised controller limit or permission to mutate its state.
	 */
	if (plen > 255)
		return -EMSGSIZE;
	return sle_usb_write_command_locked(d, opcode, params, plen, SLE_CMD_TIMEOUT_MS);
}

/**
 * sle_usb_dev_send_data - Send a DLI async data packet via USB bulk OUT.
 * @d: retained USB context
 * @handle: link handle
 * @data:   payload bytes
 * @len:    payload length
 *
 * Returns 0 on success, negative errno on failure.
 */
static int sle_usb_dev_send_data_locked(struct sle_usb_dev *d, u16 handle,
				       const u8 *data, int len)
{
	/* No qualified standard Session/ticket/credit path yet. */
	(void)handle;
	(void)data;
	(void)len;
	return d->active ? -EOPNOTSUPP : -ENODEV;
}

/**
 * sle_usb_dev_start_evt - Start listening for events on interrupt IN.
 * @d: retained USB context
 *
 * Submits the event interrupt URB which auto-resubmits on completion.
 */
static int sle_usb_dev_start_evt_locked(struct sle_usb_dev *d)
{
	int ret;


	if (!d->active || !d->udev || !d->evt_urb)
		return -ENODEV;

	ret = sle_usb_submit_intr_in(d->evt_urb, d->udev,
				      d->ep_intr_in,
				      d->ep_intr_in_interval);
	return ret;
}

/**
 * sle_usb_dev_stop_evt - Stop listening for events.
 * @d: retained USB context
 */
static void sle_usb_dev_stop_evt_locked(struct sle_usb_dev *d)
{


	if (d->evt_urb)
		sle_usb_kill_ctx(d->evt_urb);
}

/**
 * sle_usb_dev_start_data - Start listening for async data on bulk IN.
 * @d: retained USB context
 *
 * Submits the bulk IN URB which auto-resubmits on completion.
 */
static int sle_usb_dev_start_data_locked(struct sle_usb_dev *d)
{


	if (!d->active || !d->udev || !d->rx_urb)
		return -ENODEV;

	return sle_usb_submit_bulk_in(d->rx_urb, d->udev,
				      d->ep_bulk_in);
}

/**
 * sle_usb_dev_stop_data - Stop listening for async data.
 * @d: retained USB context
 */
static void sle_usb_dev_stop_data_locked(struct sle_usb_dev *d)
{


	if (d->rx_urb)
		sle_usb_kill_ctx(d->rx_urb);
}

/* -----------------------------------------------------------------------
 * Device initialisation sequence
 *
 * Performs the standard SLE controller bring-up over USB:
 *   1. Send Reset command (opcode 0x0408)
 *   2. Send ReadLocalVersion (opcode 0x0404) → extract fw_version
 *   3. Send ReadMacAddr (opcode 0x0406) → extract MAC address
 *
 * The responses are received synchronously via the bulk IN endpoint.
 * On success, fw_version and mac_addr fields of the device table entry
 * are populated.
 *
 * DLI command packet format (T/XS 10003-2025):
 *   [0]    = 0xA1 (Command)
 *   [1..2] = opcode (LE16)
 *   [3..4] = param_len (LE16)
 *   [5..N] = params
 *
 * DLI event packet format:
 *   [0..1] = event_code (LE16) — expect CmdComplete 0x0002
 *   [2..3] = param_len (LE16)
 *   [4..5] = opcode echo (LE16)
 *   [6]    = command credits
 *   [7]    = status (0 = success)
 *   [8..N] = remaining return params
 * ----------------------------------------------------------------------- */

/* DLI opcodes from T/XS 10003-2025 */
#define SLE_OP_READ_CMD_LENGTH    0x0401
#define SLE_OP_READ_BUFFER        0x0402
#define SLE_OP_READ_FEATURES      0x0403
#define SLE_OP_READ_LOCAL_VERSION 0x0404
#define SLE_OP_READ_MAC_ADDR      0x0406
#define SLE_OP_RESET              0x0408

/* DLI event: CommandComplete */
#define SLE_EVT_CMD_COMPLETE      0x0002

/* How long to wait for a command response (ms) */
#define SLE_INIT_TIMEOUT_MS       3000

static int sle_usb_send_cmd_sync(struct sle_usb_dev *d, u16 opcode,
				 const u8 *params, int plen, u8 *resp,
				 int resp_size, int *resp_len)
{
	u8 *buffer;
	int ret;

	if (!resp || !resp_len || resp_size <= 0)
		return -EINVAL;
	ret = sle_usb_write_command_locked(d, opcode, params, plen, SLE_INIT_TIMEOUT_MS);
	if (ret)
		return ret;
	buffer = kmalloc(resp_size, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;
	/* Events use interrupt IN; never steal ACB data from bulk IN. Probe
	 * bootstrap runs before the asynchronous event listener starts.
	 */
	ret = usb_interrupt_msg(d->udev, usb_rcvintpipe(d->udev, d->ep_intr_in),
		buffer, resp_size, resp_len, SLE_INIT_TIMEOUT_MS);
	if (!ret) {
		if (*resp_len < 0 || *resp_len > resp_size)
			ret = -EPROTO;
		else if (*resp_len)
			memcpy(resp, buffer, *resp_len);
	}
	kfree(buffer);
	return ret;
}

/* A transport write or an unrelated/truncated reply is not query success. */
static int sle_usb_validate_init_reply(const u8 *resp, int len,
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

/* Bootstrap uses standard T/XS 10003-2025 sections 8.1.1--8.1.6.
 * WS73's zero-parameter 0x0406 and 0x0401 dialect belong to its own driver.
 * Strictly query all metadata before publishing any of it. Each next command
 * requires the previous real Complete's command credit, not USB write success.
 */
static int sle_usb_dev_init_controller_locked(struct sle_usb_dev *d)
{
	static const struct { u16 opcode; int result_size; } queries[] = {
		{ SLE_OP_RESET, 0 },
		{ SLE_OP_READ_LOCAL_VERSION, 5 },
		{ SLE_OP_READ_CMD_LENGTH, 2 },
		{ SLE_OP_READ_BUFFER, 6 },
		{ SLE_OP_READ_FEATURES, 10 },
		{ SLE_OP_READ_MAC_ADDR, 6 },
	};
	struct sle_usb_capabilities capabilities = {};
	u8 resp[64], version[5], mac_addr[6];
	const u8 address_type = 0; /* alliance-assigned identifier */
	int resp_len, ret;
	size_t i;

	if (!d->active || !d->udev)
		return -ENODEV;
	d->metadata_valid = false;
	for (i = 0; i < ARRAY_SIZE(queries); i++) {
		const u8 *params = queries[i].opcode == SLE_OP_READ_MAC_ADDR ?
			&address_type : NULL;

		ret = sle_usb_send_cmd_sync(d, queries[i].opcode, params,
			params ? 1 : 0, resp, sizeof(resp), &resp_len);
		if (ret)
			return ret;
		ret = sle_usb_validate_init_reply(resp, resp_len,
			queries[i].opcode, queries[i].result_size);
		if (ret)
			return ret;
		if (i + 1 < ARRAY_SIZE(queries) && !resp[6])
			return -EAGAIN;
		switch (queries[i].opcode) {
		case SLE_OP_READ_LOCAL_VERSION:
			memcpy(version, resp + 8, sizeof(version));
			break;
		case SLE_OP_READ_CMD_LENGTH:
			capabilities.command_max = get_unaligned_le16(resp + 8);
			if (capabilities.command_max < 255)
				return -EPROTO;
			break;
		case SLE_OP_READ_BUFFER:
			capabilities.acb_length = get_unaligned_le16(resp + 8);
			capabilities.acb_count = resp[10];
			capabilities.icb_length = get_unaligned_le16(resp + 11);
			capabilities.icb_count = resp[13];
			if (capabilities.acb_length > 2047 || capabilities.icb_length > 2047 ||
			    (!capabilities.acb_length != !capabilities.acb_count) ||
			    (!capabilities.icb_length != !capabilities.icb_count))
				return -EPROTO;
			break;
		case SLE_OP_READ_FEATURES:
			memcpy(capabilities.features, resp + 8, sizeof(capabilities.features));
			break;
		case SLE_OP_READ_MAC_ADDR:
			memcpy(mac_addr, resp + 8, sizeof(mac_addr));
			if (!memchr_inv(mac_addr, 0, sizeof(mac_addr)) ||
			    !memchr_inv(mac_addr, 0xff, sizeof(mac_addr)))
				return -EPROTO;
			break;
		}
	}
	/* io_lock protects the complete observation and its validity bit. */
	d->fw_version = get_unaligned_le32(version); /* legacy projection only */
	memcpy(d->version, version, sizeof(d->version));
	d->capabilities = capabilities;
	d->command_credits = resp[6];
	memcpy(d->mac_addr, mac_addr, sizeof(mac_addr));
	d->metadata_valid = true;
	return 0;
}

static u8 sle_usb_dev_get_command_credits_locked(struct sle_usb_dev *d)
{
    if (!d->active)
        return 0;
    return d->command_credits;
}

/**
 * sle_usb_dev_get_fw_version - Read back the firmware version.
 * @d: retained USB context
 *
 * Returns the firmware version obtained during init, or 0.
 */
static u32 sle_usb_dev_get_fw_version_locked(struct sle_usb_dev *d)
{
	if (!d->active)
		return 0;
	return d->fw_version;
}

/**
 * sle_usb_dev_get_mac - Read back the MAC address.
 * @d: retained USB context
 * @mac:    output buffer (6 bytes)
 *
 * Returns 0 on success.
 */
static int sle_usb_dev_get_mac_locked(struct sle_usb_dev *d, u8 *mac)
{
	if (!mac)
		return -EINVAL;
	if (!d->active)
		return -ENODEV;
	memcpy(mac, d->mac_addr, 6);
	return 0;
}

/* -----------------------------------------------------------------------
 * Power management: suspend / resume
 *
 * suspend: Kill all in-flight URBs so the host controller can power down.
 * resume:  Re-submit the event interrupt URB and optionally re-init the
 *          controller if the device was reset during suspend.
 * ----------------------------------------------------------------------- */

/**
 * sle_usb_dev_suspend - Quiesce the device for system/runtime suspend.
 * @d: retained USB context
 *
 * Kills the event (interrupt IN) and data (bulk IN) URBs so no further
 * transfers are pending when the host controller suspends.
 */
static int sle_usb_dev_suspend_locked(struct sle_usb_dev *d)
{


	if (!d->active)
		return -ENODEV;

	if (d->suspended)
		return 0;

	/* Kill outstanding URBs */
	if (d->evt_urb)
		sle_usb_kill_ctx(d->evt_urb);
	if (d->rx_urb)
		sle_usb_kill_ctx(d->rx_urb);

	d->suspended = true;
	pr_debug("sparklink-usb: dev %d suspended\n", d->id);
	return 0;
}

/**
 * sle_usb_dev_resume - Re-activate the device after suspend.
 * @d: retained USB context
 *
 * Re-submits the event interrupt URB so the driver resumes receiving
 * asynchronous events from the controller.
 */
static int sle_usb_dev_resume_locked(struct sle_usb_dev *d)
{
	int ret;


	if (!d->active)
		return -ENODEV;

	if (!d->suspended)
		return 0;

	d->suspended = false;

	/* Re-submit event URB */
	if (d->evt_urb && d->udev) {
		ret = sle_usb_submit_intr_in(d->evt_urb, d->udev,
					     d->ep_intr_in,
					     d->ep_intr_in_interval);
		if (ret) {
			pr_err("sparklink-usb: dev %d resume evt URB failed: %d\n",
			       d->id, ret);
			return ret;
		}
	}

	/* Re-submit bulk IN data URB */
	if (d->rx_urb && d->udev) {
		ret = sle_usb_submit_bulk_in(d->rx_urb, d->udev,
					     d->ep_bulk_in);
		if (ret)
			pr_err("sparklink-usb: dev %d resume data URB failed: %d\n",
			       d->id, ret);
	}

	pr_debug("sparklink-usb: dev %d resumed\n", d->id);
	return 0;
}

/* Retained process-context operations, never identity-index lookup. */
int sle_usb_dev_send_cmd(struct sle_usb_dev *d, u16 opcode, const u8 *params, int plen)
{
	int result;
	if (!d) return -EINVAL;
	mutex_lock(&d->io_lock);
	result = !d->active ? -ENODEV : d->suspended ? -EHOSTDOWN :
		sle_usb_dev_send_cmd_locked(d, opcode, params, plen);
	mutex_unlock(&d->io_lock);
	return result;
}

int sle_usb_dev_send_data(struct sle_usb_dev *d, u16 handle, const u8 *data, int len)
{
	int result;
	if (!d) return -EINVAL;
	mutex_lock(&d->io_lock);
	result = d->active ? sle_usb_dev_send_data_locked(d, handle, data, len) : -ENODEV;
	mutex_unlock(&d->io_lock);
	return result;
}

int sle_usb_dev_start_evt(struct sle_usb_dev *d)
{
	int result;
	if (!d) return -EINVAL;
	mutex_lock(&d->io_lock);
	result = d->active ? sle_usb_dev_start_evt_locked(d) : -ENODEV;
	mutex_unlock(&d->io_lock);
	return result;
}

void sle_usb_dev_stop_evt(struct sle_usb_dev *d)
{
	if (!d) return;
	mutex_lock(&d->io_lock);
	sle_usb_dev_stop_evt_locked(d);
	mutex_unlock(&d->io_lock);
}

int sle_usb_dev_start_data(struct sle_usb_dev *d)
{
	int result;
	if (!d) return -EINVAL;
	mutex_lock(&d->io_lock);
	result = d->active ? sle_usb_dev_start_data_locked(d) : -ENODEV;
	mutex_unlock(&d->io_lock);
	return result;
}

void sle_usb_dev_stop_data(struct sle_usb_dev *d)
{
	if (!d) return;
	mutex_lock(&d->io_lock);
	sle_usb_dev_stop_data_locked(d);
	mutex_unlock(&d->io_lock);
}

int sle_usb_dev_init_controller(struct sle_usb_dev *d)
{
	int result;
	if (!d) return -EINVAL;
	mutex_lock(&d->io_lock);
	result = d->active ? sle_usb_dev_init_controller_locked(d) : -ENODEV;
	mutex_unlock(&d->io_lock);
	return result;
}

u8 sle_usb_dev_get_command_credits(struct sle_usb_dev *d)
{
	u8 result;
	if (!d) return 0;
	mutex_lock(&d->io_lock);
	result = d->active ? sle_usb_dev_get_command_credits_locked(d) : 0;
	mutex_unlock(&d->io_lock);
	return result;
}

u32 sle_usb_dev_get_fw_version(struct sle_usb_dev *d)
{
	u32 result;
	if (!d) return 0;
	mutex_lock(&d->io_lock);
	result = d->active ? sle_usb_dev_get_fw_version_locked(d) : 0;
	mutex_unlock(&d->io_lock);
	return result;
}

int sle_usb_dev_get_metadata(struct sle_usb_dev *d, struct sle_usb_metadata *out)
{
	int ret = 0;

	if (!d || !out)
		return -EINVAL;
	mutex_lock(&d->io_lock);
	if (!d->active)
		ret = -ENODEV;
	else if (!d->metadata_valid)
		ret = -ENODATA;
	else {
		out->capabilities = d->capabilities;
		memcpy(out->version, d->version, sizeof(out->version));
		memcpy(out->address, d->mac_addr, sizeof(out->address));
		out->command_credits = d->command_credits;
	}
	mutex_unlock(&d->io_lock);
	return ret;
}

int sle_usb_dev_get_mac(struct sle_usb_dev *d, u8 *mac)
{
	int result;
	if (!d) return -EINVAL;
	mutex_lock(&d->io_lock);
	result = d->active ? sle_usb_dev_get_mac_locked(d, mac) : -ENODEV;
	mutex_unlock(&d->io_lock);
	return result;
}

int sle_usb_dev_suspend(struct sle_usb_dev *d)
{
	int result;
	if (!d) return -EINVAL;
	mutex_lock(&d->io_lock);
	result = d->active ? sle_usb_dev_suspend_locked(d) : -ENODEV;
	mutex_unlock(&d->io_lock);
	return result;
}

int sle_usb_dev_resume(struct sle_usb_dev *d)
{
	int result;
	if (!d) return -EINVAL;
	mutex_lock(&d->io_lock);
	result = d->active ? sle_usb_dev_resume_locked(d) : -ENODEV;
	mutex_unlock(&d->io_lock);
	return result;
}

/* Standard provider adapter: no registry index resolves transport resources.
 * Pure query validation is independent of mutable context state. Physical send
 * serializes against retire/PM; Core retains the context and Host obligations.
 */
static void sle_usb_provider_get(void *context) { sle_usb_dev_get(context); }
static void sle_usb_provider_put(void *context) { sle_usb_dev_put(context); }
static int sle_usb_provider_validate(void *context, u16 opcode,
				     const u8 *params, size_t length)
{
	(void)context;
	if (length > 255 || (length && !params))
		return -EINVAL;
	switch (opcode) {
	case 0x0401: case 0x0402: case 0x0403: case 0x0404:
		return length ? -EINVAL : 0;
	case 0x0406:
		if (length != 1)
			return -EINVAL;
		return params[0] == 0 || (params[0] >= 2 && params[0] <= 6) ? 0 : -EINVAL;
	default:
		return -EOPNOTSUPP;
	}
}
static int sle_usb_provider_send(void *context, u16 opcode,
				 const u8 *params, size_t length)
{
	int ret = sle_usb_provider_validate(context, opcode, params, length);

	if (ret)
		return ret;
	return sle_usb_dev_send_cmd(context, opcode, params, length);
}
static int sle_usb_provider_open(void *context, u16 id, u64 generation)
{
	struct sle_usb_dev *d = context;
	int ret;

	mutex_lock(&d->io_lock);
	if (!d->active || d->id != id || d->generation != generation)
		ret = -ENODEV;
	else if (d->suspended)
		ret = -EAGAIN;
	else {
		ret = sle_usb_dev_start_evt_locked(d);
		if (!ret) {
			ret = sle_usb_dev_start_data_locked(d);
			if (ret)
				sle_usb_dev_stop_evt_locked(d);
		}
	}
	mutex_unlock(&d->io_lock);
	return ret;
}
static void sle_usb_provider_close(void *context)
{
	struct sle_usb_dev *d = context;

	mutex_lock(&d->io_lock);
	sle_usb_dev_stop_evt_locked(d);
	sle_usb_dev_stop_data_locked(d);
	mutex_unlock(&d->io_lock);
}
static const struct sparklink_native_ops sle_usb_provider_ops = {
	.owner = THIS_MODULE,
	.get = sle_usb_provider_get,
	.put = sle_usb_provider_put,
	.open = sle_usb_provider_open,
	.close = sle_usb_provider_close,
	.validate_command = sle_usb_provider_validate,
	.send_command = sle_usb_provider_send,
};

int sle_usb_dev_install_provider(struct sle_usb_dev *d)
{
	struct sle_usb_metadata metadata;
	struct sparklink_native_identity reserved, output;
	struct sparklink_backend_descriptor descriptor = {
		.version = SPARKLINK_BACKEND_VERSION,
		.size = sizeof(descriptor),
		.bus = SPARKLINK_BACKEND_USB,
		.capabilities = 0,
		.ops = &sle_usb_provider_ops,
		.context = d,
	};
	int ret = sle_usb_dev_get_metadata(d, &metadata);

	if (ret)
		return ret;
	reserved.id = d->id;
	reserved.generation = d->generation;
	descriptor.info.profile = SPARKLINK_NATIVE_STANDARD_DLI;
	memcpy(descriptor.info.version, metadata.version, sizeof(metadata.version));
	memcpy(descriptor.info.features, metadata.capabilities.features, sizeof(descriptor.info.features));
	memcpy(descriptor.info.address, metadata.address, sizeof(metadata.address));
	descriptor.info.command_credits = metadata.command_credits;
	descriptor.info.acb_length = metadata.capabilities.acb_length;
	descriptor.info.icb_length = metadata.capabilities.icb_length;
	descriptor.info.acb_count = metadata.capabilities.acb_count;
	descriptor.info.icb_count = metadata.capabilities.icb_count;
	ret = sparklink_backend_register_reserved(&descriptor, &reserved, &output);
	if (ret)
		return ret;
	/* Never follow a malformed callback result into another owner's cleanup. */
	return output.id == reserved.id && output.generation == reserved.generation ? 0 : -EPROTO;
}
