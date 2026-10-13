// SPDX-License-Identifier: GPL-2.0
/*
 * SparkLink USB transport FFI helpers.
 *
 * Provides thin C wrappers around the kernel USB URB API for consumption
 * by the Rust sle_usb module. The wrappers handle the unsafe parts of
 * URB lifecycle management (allocation, fill, submit, complete) and
 * expose a minimal, type-safe surface to Rust.
 *
 * Architecture:
 *
 *   Rust (sle_usb.rs)         C (sle_usb_ffi.c)        kernel USB core
 *   ─────────────────         ─────────────────         ──────────────
 *   sle_usb_alloc()      ──► sle_usb_alloc_urb()  ──► usb_alloc_urb()
 *   sle_usb_submit_bulk()──► sle_usb_submit_bulk()──► usb_fill_bulk_urb()
 *                                                  ──► usb_submit_urb()
 *   <completion callback> ◄── sle_usb_bulk_out_cb()   ◄── USB core IRQ
 *   sle_usb_kill()        ──► sle_usb_kill_urb()  ──► usb_kill_urb()
 *   sle_usb_free()        ──► sle_usb_free_urb()  ──► usb_free_urb()
 */

#include <linux/usb.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/sparklink_usb.h>
#include <linux/unaligned.h>

/* -----------------------------------------------------------------------
 * Rust-side completion callback declaration
 * -----------------------------------------------------------------------
 * Rust provides this function via #[no_mangle]. It receives:
 *   ctx      — opaque pointer passed during submit (Rust uses this to
 *              identify which URB completed)
 *   data     — pointer to the transfer buffer
 *   length   — actual number of bytes transferred
 *   status   — URB completion status (0 = success, negative = error)
 */
extern void sparklink_usb_complete(void *ctx, const u8 *data,
				   int length, int status);
extern void sparklink_usb_registered_complete(u32 dev_id, u64 generation,
					      const u8 *data, int length,
					      int status);

/* Forward declarations for exported FFI functions */
struct sle_urb_ctx *sle_usb_alloc_ctx(int buf_size);
void sle_usb_free_ctx(struct sle_urb_ctx *ctx);
int sle_usb_submit_bulk_out(struct sle_urb_ctx *ctx,
			    struct usb_device *udev, u8 ep,
			    const u8 *data, int len,
			    void *rust_ctx, int timeout_ms);
int sle_usb_submit_bulk_in(struct sle_urb_ctx *ctx,
			   struct usb_device *udev, u8 ep,
			   void *rust_ctx);
int sle_usb_submit_intr_in(struct sle_urb_ctx *ctx,
			   struct usb_device *udev, u8 ep,
			   void *rust_ctx, int interval);
void sle_usb_kill_ctx(struct sle_urb_ctx *ctx);
int sle_usb_sync_bulk_out(struct usb_device *udev, u8 ep,
			  const u8 *data, int len, int timeout_ms);
int sle_usb_sync_bulk_in(struct usb_device *udev, u8 ep,
			 u8 *buf, int size, int timeout_ms);

/* -----------------------------------------------------------------------
 * URB context: bookkeeping for in-flight transfers
 * -----------------------------------------------------------------------
 */
struct sle_urb_ctx {
	struct urb *urb;
	u8 *buf;
	int buf_size;
	void *rust_ctx;  /* opaque pointer handed back to Rust on completion */
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
static void sle_usb_bulk_out_cb(struct urb *urb)
{
	struct sle_urb_ctx *ctx = urb->context;

	/* Preserve transport status without feeding the transmitted bytes into RX. */
	sparklink_usb_complete(ctx->rust_ctx, NULL, 0, urb->status);
}

static void sle_usb_receive_complete(struct sle_urb_ctx *ctx, struct urb *urb)
{
	if (ctx->registration_generation)
		sparklink_usb_registered_complete(ctx->registration_id,
						  ctx->registration_generation,
						  ctx->buf, urb->actual_length,
						  urb->status);
	else
		sparklink_usb_complete(ctx->rust_ctx, ctx->buf,
				       urb->actual_length, urb->status);
}

/* Bulk IN (data) callback with auto-resubmit for continuous reception */
static void sle_usb_bulk_in_cb(struct urb *urb)
{
	struct sle_urb_ctx *ctx = urb->context;

	sle_usb_receive_complete(ctx, urb);

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

	sle_usb_receive_complete(ctx, urb);

	/* For interrupt IN endpoints: auto-resubmit unless cancelled */
	if (urb->status == 0 || urb->status == -EOVERFLOW) {
		int ret = usb_submit_urb(urb, GFP_ATOMIC);
		if (ret)
			pr_err("sparklink-usb: intr resubmit failed: %d\n",
			       ret);
	}
}

/* -----------------------------------------------------------------------
 * Exported FFI functions
 * -----------------------------------------------------------------------
 */

/**
 * sle_usb_alloc_ctx - Allocate a URB context for SparkLink transfers.
 * @buf_size: size of the transfer buffer
 *
 * Returns NULL on allocation failure.
 */
struct sle_urb_ctx *sle_usb_alloc_ctx(int buf_size)
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
	ctx->rust_ctx = NULL;
	return ctx;
}

/**
 * sle_usb_free_ctx - Free a URB context and its resources.
 * @ctx: context allocated by sle_usb_alloc_ctx
 */
void sle_usb_free_ctx(struct sle_urb_ctx *ctx)
{
	if (!ctx)
		return;
	usb_free_urb(ctx->urb);
	kfree(ctx->buf);
	kfree(ctx);
}

/**
 * sle_usb_submit_bulk_out - Submit a bulk OUT transfer (host to device).
 * @ctx:       URB context
 * @udev:      USB device
 * @ep:        endpoint address (e.g. 0x12)
 * @data:      payload to send
 * @len:       payload length
 * @rust_ctx:  opaque pointer passed to completion callback
 * @timeout_ms: 0 for async, > 0 for synchronous timeout
 *
 * Returns 0 on success, negative errno on failure.
 */
int sle_usb_submit_bulk_out(struct sle_urb_ctx *ctx,
			    struct usb_device *udev, u8 ep,
			    const u8 *data, int len,
			    void *rust_ctx, int timeout_ms)
{
	unsigned int pipe;
	int actual_len;

	if (!ctx || !udev || len > ctx->buf_size)
		return -EINVAL;

	if (timeout_ms > 0) {
		/* Synchronous: use usb_bulk_msg */
		memcpy(ctx->buf, data, len);
		pipe = usb_sndbulkpipe(udev, ep);
		return usb_bulk_msg(udev, pipe, ctx->buf, len,
				    &actual_len, timeout_ms);
	}

	/* Asynchronous: fill and submit URB */
	memcpy(ctx->buf, data, len);
	ctx->rust_ctx = rust_ctx;
	pipe = usb_sndbulkpipe(udev, ep);

	usb_fill_bulk_urb(ctx->urb, udev, pipe,
			  ctx->buf, len,
			  sle_usb_bulk_out_cb, ctx);

	return usb_submit_urb(ctx->urb, GFP_KERNEL);
}

/**
 * sle_usb_submit_bulk_in - Submit a bulk IN transfer (device to host).
 * @ctx:       URB context
 * @udev:      USB device
 * @ep:        endpoint address (e.g. 0x92)
 * @rust_ctx:  opaque pointer passed to completion callback
 *
 * Returns 0 on success, negative errno on failure.
 */
int sle_usb_submit_bulk_in(struct sle_urb_ctx *ctx,
			   struct usb_device *udev, u8 ep,
			   void *rust_ctx)
{
	unsigned int pipe;

	if (!ctx || !udev)
		return -EINVAL;

	ctx->rust_ctx = rust_ctx;
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
 * @rust_ctx:  opaque pointer passed to completion callback
 * @interval:  polling interval (from endpoint descriptor)
 *
 * Returns 0 on success, negative errno on failure.
 * The URB auto-resubmits on successful completion.
 */
int sle_usb_submit_intr_in(struct sle_urb_ctx *ctx,
			   struct usb_device *udev, u8 ep,
			   void *rust_ctx, int interval)
{
	unsigned int pipe;

	if (!ctx || !udev)
		return -EINVAL;

	ctx->rust_ctx = rust_ctx;
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
void sle_usb_kill_ctx(struct sle_urb_ctx *ctx)
{
	if (ctx && ctx->urb)
		usb_kill_urb(ctx->urb);
}

/**
 * sle_usb_sync_bulk_out - Blocking bulk OUT transfer.
 * @udev:      USB device
 * @ep:        endpoint address
 * @data:      payload
 * @len:       payload length
 * @timeout_ms: timeout in milliseconds
 *
 * Uses a kmalloc'd bounce buffer to avoid DMA from stack memory.
 * Returns actual bytes transferred on success, negative errno on failure.
 */
int sle_usb_sync_bulk_out(struct usb_device *udev, u8 ep,
			  const u8 *data, int len, int timeout_ms)
{
	int actual_len = 0;
	int ret;
	unsigned int pipe = usb_sndbulkpipe(udev, ep);
	u8 *bounce;

	bounce = kmalloc(len, GFP_KERNEL);
	if (!bounce)
		return -ENOMEM;
	memcpy(bounce, data, len);

	ret = usb_bulk_msg(udev, pipe, bounce, len,
			   &actual_len, timeout_ms);
	kfree(bounce);
	return ret ? ret : actual_len;
}

/**
 * sle_usb_sync_bulk_in - Blocking bulk IN transfer.
 * @udev:  USB device
 * @ep:    endpoint address
 * @buf:   receive buffer
 * @size:  buffer capacity
 * @timeout_ms: timeout in milliseconds
 *
 * Uses a kmalloc'd bounce buffer to avoid DMA from stack memory.
 * Returns actual bytes received on success, negative errno on failure.
 */
int sle_usb_sync_bulk_in(struct usb_device *udev, u8 ep,
			 u8 *buf, int size, int timeout_ms)
{
	int actual_len = 0;
	int ret;
	unsigned int pipe = usb_rcvbulkpipe(udev, ep);
	u8 *bounce;

	bounce = kmalloc(size, GFP_KERNEL);
	if (!bounce)
		return -ENOMEM;

	ret = usb_bulk_msg(udev, pipe, bounce, size,
			   &actual_len, timeout_ms);
	if (!ret)
		memcpy(buf, bounce, actual_len);
	kfree(bounce);
	return ret ? ret : actual_len;
}

/* =======================================================================
 * Per-probe USB context ownership
 *
 * References pin one allocation and immutable registration identity. No
 * operation resolves a reusable registry index to transport resources.
 * ======================================================================= */

#define SLE_USB_MAX_DEVS 16

/* DLI packet type bytes (T/XS 10003-2025 section 5.2) */
#define DLI_PKT_COMMAND    0xA1
#define DLI_PKT_ASYNC_DATA 0xA3

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
	u8 ep_intr_in_interval;       /* bInterval */
	/* Read-back from controller during init */
	u8 mac_addr[6];
	u32 fw_version;
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
	 * privately; publish the table entry only after preparation succeeds.
	 */
	ret = usb_find_common_endpoints(intf->cur_altsetting,
					&bulk_in, &bulk_out, &int_in, NULL);
	if (ret)
		return ret;
	if (!usb_endpoint_maxp(bulk_in) || !usb_endpoint_maxp(bulk_out) ||
	    !usb_endpoint_maxp(int_in) || !int_in->bInterval)
		return -EPROTO;

	evt_urb = sle_usb_alloc_ctx(usb_endpoint_maxp(int_in));
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
 * sle_usb_dev_send_cmd - Send a DLI command via USB bulk OUT.
 * @d: retained USB context
 * @opcode: DLI opcode (host byte order)
 * @params: parameter bytes
 * @plen:   parameter length
 *
 * Builds a DLI command packet and sends synchronously.
 * Returns 0 on success, negative errno on failure.
 */
static int sle_usb_dev_send_cmd_locked(struct sle_usb_dev *d, u16 opcode, const u8 *params, int plen)
{
	u8 *pkt;
	int total;
	int actual_len;
	unsigned int pipe;
	int ret;


	if (!d->active || !d->udev)
		return -ENODEV;

	if (plen < 0) return -EINVAL;
	if (plen > 255) return -EMSGSIZE;

	if (plen > 0 && !params)
		return -EINVAL;

	total = 5 + plen;
	pkt = kmalloc(total, GFP_KERNEL);
	if (!pkt)
		return -ENOMEM;

	/* Build DLI command packet: [type:1][opcode:2][param_len:2][params...] */
	pkt[0] = DLI_PKT_COMMAND;
	pkt[1] = (u8)(opcode & 0xFF);
	pkt[2] = (u8)(opcode >> 8);
	pkt[3] = (u8)(plen & 0xFF);
	pkt[4] = (u8)(plen >> 8);
	if (plen > 0 && params)
		memcpy(&pkt[5], params, plen);

	pipe = usb_sndbulkpipe(d->udev, d->ep_bulk_out);
	ret = usb_bulk_msg(d->udev, pipe, pkt, total,
			   &actual_len, SLE_CMD_TIMEOUT_MS);
	kfree(pkt);
	if (ret)
		return ret;
	return actual_len == total ? 0 : -EREMOTEIO;
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
static int sle_usb_dev_send_data_locked(struct sle_usb_dev *d, u16 handle, const u8 *data, int len)
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
				      NULL,
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
				      d->ep_bulk_in,
				      NULL);
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
#define SLE_OP_READ_LOCAL_VERSION 0x0404
#define SLE_OP_READ_MAC_ADDR      0x0406
#define SLE_OP_RESET              0x0408

/* DLI event: CommandComplete */
#define SLE_EVT_CMD_COMPLETE      0x0002

/* How long to wait for a command response (ms) */
#define SLE_INIT_TIMEOUT_MS       3000

static int sle_usb_send_cmd_sync(struct sle_usb_dev *d, u16 opcode,
				 u8 *resp, int resp_size, int *resp_len)
{
	u8 *cmd;
	u8 *rbuf;
	int actual_len;
	unsigned int pipe_out, pipe_in;
	int ret;

	cmd = kmalloc(5, GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd[0] = DLI_PKT_COMMAND;
	cmd[1] = (u8)(opcode & 0xFF);
	cmd[2] = (u8)(opcode >> 8);
	cmd[3] = 0; /* param_len low */
	cmd[4] = 0; /* param_len high */

	pipe_out = usb_sndbulkpipe(d->udev, d->ep_bulk_out);
	ret = usb_bulk_msg(d->udev, pipe_out, cmd, 5,
			   &actual_len, SLE_INIT_TIMEOUT_MS);
	kfree(cmd);
	if (ret)
		return ret;
	if (actual_len != 5)
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

/**
 * sle_usb_dev_init_controller - Run the SLE controller init sequence.
 * @d: retained USB context
 *
 * Sends Reset, ReadLocalVersion, ReadMacAddr commands and stores the
 * results only after all three matching CommandComplete replies succeed.
 * The driver rolls back probe on transport, framing or controller errors.
 *
 * Returns 0 on full success. Negative errno if any command fails.
 */
static int sle_usb_dev_init_controller_locked(struct sle_usb_dev *d)
{
	u8 resp[64];
	int resp_len = 0;
	int ret;
	u32 fw_version;
	u8 mac_addr[6];


	if (!d->active || !d->udev)
		return -ENODEV;

	/* Step 1: Reset controller */
	ret = sle_usb_send_cmd_sync(d, SLE_OP_RESET, resp, sizeof(resp),
				    &resp_len);
	if (ret)
		return ret;
	ret = sle_usb_validate_init_reply(resp, resp_len, SLE_OP_RESET, 0);
	if (ret)
		return ret;
	/* Bootstrap has no asynchronous credit waiter yet: fail closed rather
	 * than send a query when the controller advertises zero capacity.
	 */
	if (!resp[6])
		return -EAGAIN;
	pr_info("sparklink-usb: controller reset OK\n");

	/* Step 2: ReadLocalVersion
	 * CmdComplete wire format:
	 *   [0..1] evt_code  (0x0002)
	 *   [2..3] param_len (LE16)
	 *   [4..5] opcode    (LE16)
	 *   [6]    command credits
	 *   [7]    status
	 *   [8] protocol version, [9..10] company id, [11..12] sub-version
	 *   (T/XS 10003-2025 section 8.1.4: 1 + 2 + 2 bytes)
	 */
	ret = sle_usb_send_cmd_sync(d, SLE_OP_READ_LOCAL_VERSION,
				    resp, sizeof(resp), &resp_len);
	if (ret)
		return ret;
	ret = sle_usb_validate_init_reply(resp, resp_len, SLE_OP_READ_LOCAL_VERSION, 5);
	if (ret)
		return ret;
	if (!resp[6])
		return -EAGAIN;
	/* Preserve the old u32 metadata projection for the legacy ABI. It is not
	 * a complete standards version tuple; raw DLI queries return all 5 bytes.
	 */
	fw_version = get_unaligned_le32(resp + 8);

	/* Step 3: ReadMacAddr
	 * CmdComplete: [0..7] header, opcode, credit, status; [8..13] MAC.
	 */
	ret = sle_usb_send_cmd_sync(d, SLE_OP_READ_MAC_ADDR,
				    resp, sizeof(resp), &resp_len);
	if (ret)
		return ret;
	ret = sle_usb_validate_init_reply(resp, resp_len, SLE_OP_READ_MAC_ADDR, 6);
	if (ret)
		return ret;
	memcpy(mac_addr, resp + 8, sizeof(mac_addr));
	if (!memchr_inv(mac_addr, 0, sizeof(mac_addr)))
		return -EPROTO;
	/* Commit metadata together, never a partial/default successful bootstrap. */
	d->fw_version = fw_version;
	d->command_credits = resp[6];
	memcpy(d->mac_addr, mac_addr, sizeof(mac_addr));

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
 * Firmware download over USB bulk OUT
 *
 * Protocol (modeled after BT HCI firmware download):
 *   1. Host sends FW_DOWNLOAD_START command (opcode 0xF810, param = total size)
 *   2. Host sends firmware data in chunks via bulk OUT, prefixed with
 *      a FW_DATA header byte 0xA5
 *   3. After all chunks: host sends FW_DOWNLOAD_DONE (opcode 0xF811)
 *   4. Controller ACKs with CommandComplete
 *
 * Chunk wire format:
 *   [0]      0xA5 (FW_DATA marker)
 *   [1..4]   offset (LE32)
 *   [5..6]   chunk_len (LE16)
 *   [7..N]   firmware data
 * ----------------------------------------------------------------------- */

#define SLE_FW_DATA_MARKER   0xA5
#define SLE_FW_CHUNK_HDR     7     /* marker + offset(4) + len(2) */
#define SLE_OP_FW_DL_START   0xF810
#define SLE_OP_FW_DL_DONE    0xF811
#define SLE_FW_DEFAULT_CHUNK 240   /* legacy fallback, not a device capability */
#define SLE_FW_MAX_SIZE     (4 * 1024 * 1024) /* matches Rust loader budget */
#define SLE_FW_DL_TIMEOUT_MS 10000

/**
 * sle_usb_dev_download_fw - Download firmware to controller in chunks.
 * @dev_id:     device id
 * @data:       firmware blob from request_firmware()
 * @size:       firmware size in bytes
 * @chunk_size: max payload per transfer (0 = auto from endpoint size)
 *
 * Returns 0 on success, negative errno on failure.
 */
static int sle_usb_dev_download_fw_locked(struct sle_usb_dev *d, const u8 *data, int size,
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
	ret = sle_usb_send_cmd_sync(d, SLE_OP_FW_DL_DONE,
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
					     NULL,
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
					     d->ep_bulk_in,
					     NULL);
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
	result = d->active ? sle_usb_dev_send_cmd_locked(d, opcode, params, plen) : -ENODEV;
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

int sle_usb_dev_get_mac(struct sle_usb_dev *d, u8 *mac)
{
	int result;
	if (!d) return -EINVAL;
	mutex_lock(&d->io_lock);
	result = d->active ? sle_usb_dev_get_mac_locked(d, mac) : -ENODEV;
	mutex_unlock(&d->io_lock);
	return result;
}

int sle_usb_dev_download_fw(struct sle_usb_dev *d, const u8 *data, int size, int chunk_size)
{
	int result;
	if (!d) return -EINVAL;
	mutex_lock(&d->io_lock);
	result = d->active ? sle_usb_dev_download_fw_locked(d, data, size, chunk_size) : -ENODEV;
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
