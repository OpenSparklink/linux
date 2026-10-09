// SPDX-License-Identifier: GPL-2.0-only
/* Synthetic runtime-only WS73 USB fixture. No ROM, firmware execution or RF.
 * Exercises the production HCC/BSLE/bootstrap/URB/native Runtime path.
 * All addresses, features, configuration acknowledgements and replies are fake.
 */
#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "hw/qdev-properties.h"
#include "hw/usb.h"
#include "hw/usb/desc.h"
#include "qom/object.h"

#define TYPE_USB_WS73_TEST "usb-ws73-test"
OBJECT_DECLARE_SIMPLE_TYPE(USBWs73Test, USB_WS73_TEST)

struct USBWs73Test {
    USBDevice parent_obj;
    uint8_t packets[64][384];
    unsigned int packet_size[64];
    int64_t ready_at[64];
    QEMUTimer *wake;
    bool in_flight;
    unsigned int head, count, sequence, commands, serial;
    uint8_t runtime_status;
    uint8_t runtime_fault;
    uint8_t runtime_reports;
    bool reports_emitted;
    bool bsp, pm, custom, opened, failed_once;
};

static unsigned int instances;

static const USBDescStrings strings = {
    [1] = "OpenSparklink synthetic test",
    [2] = "WS73 runtime fixture (NO RF)",
    [3] = "WS73-TEST",
};

static const USBDescIface iface = {
    .bInterfaceNumber = 0, .bNumEndpoints = 5,
    .bInterfaceClass = 0xe0, .bInterfaceSubClass = 2, .bInterfaceProtocol = 2,
    .eps = (USBDescEndpoint[]) {
        { .bEndpointAddress = 0x81, .bmAttributes = USB_ENDPOINT_XFER_BULK, .wMaxPacketSize = 512 },
        { .bEndpointAddress = 0x01, .bmAttributes = USB_ENDPOINT_XFER_BULK, .wMaxPacketSize = 512 },
        { .bEndpointAddress = 0x83, .bmAttributes = USB_ENDPOINT_XFER_INT, .wMaxPacketSize = 8, .bInterval = 4 },
        { .bEndpointAddress = 0x82, .bmAttributes = USB_ENDPOINT_XFER_BULK, .wMaxPacketSize = 512 },
        { .bEndpointAddress = 0x02, .bmAttributes = USB_ENDPOINT_XFER_BULK, .wMaxPacketSize = 512 },
    },
};

static const USBDescIface full_iface = {
    .bInterfaceNumber = 0, .bNumEndpoints = 5,
    .bInterfaceClass = 0xe0, .bInterfaceSubClass = 2, .bInterfaceProtocol = 2,
    .eps = (USBDescEndpoint[]) {
        { .bEndpointAddress = 0x81, .bmAttributes = USB_ENDPOINT_XFER_BULK, .wMaxPacketSize = 64 },
        { .bEndpointAddress = 0x01, .bmAttributes = USB_ENDPOINT_XFER_BULK, .wMaxPacketSize = 64 },
        { .bEndpointAddress = 0x83, .bmAttributes = USB_ENDPOINT_XFER_INT, .wMaxPacketSize = 8, .bInterval = 4 },
        { .bEndpointAddress = 0x82, .bmAttributes = USB_ENDPOINT_XFER_BULK, .wMaxPacketSize = 64 },
        { .bEndpointAddress = 0x02, .bmAttributes = USB_ENDPOINT_XFER_BULK, .wMaxPacketSize = 64 },
    },
};

static const USBDescDevice full_device = {
    .bcdUSB = 0x0200, .bMaxPacketSize0 = 64, .bNumConfigurations = 1,
    .confs = (USBDescConfig[]) {
        { .bNumInterfaces = 1, .bConfigurationValue = 1, .bmAttributes = USB_CFG_ATT_ONE,
          .bMaxPower = 50, .nif = 1, .ifs = &full_iface },
    },
};

static const USBDescDevice device = {
    .bcdUSB = 0x0200, .bMaxPacketSize0 = 64, .bNumConfigurations = 1,
    .confs = (USBDescConfig[]) {
        { .bNumInterfaces = 1, .bConfigurationValue = 1, .bmAttributes = USB_CFG_ATT_ONE,
          .bMaxPower = 50, .nif = 1, .ifs = &iface },
    },
};

static const USBDesc descriptor = {
    .id = { .idVendor = 0xffff, .idProduct = 0x3733, .bcdDevice = 0x0100,
            .iManufacturer = 1, .iProduct = 2, .iSerialNumber = 3 },
    .full = &full_device, .high = &device, .str = strings,
};

static unsigned int le16(const uint8_t *p) { return p[0] | p[1] << 8; }
static unsigned int le32(const uint8_t *p) { return le16(p) | le16(p + 2) << 16; }
static void put16(uint8_t *p, unsigned int v) { p[0] = v; p[1] = v >> 8; }
static void put32(uint8_t *p, unsigned int v) { put16(p, v); put16(p + 2, v >> 16); }

static void queue_frame(USBWs73Test *s, uint8_t service, uint8_t queue,
                        const uint8_t *data, size_t length)
{
    uint8_t *p;

    g_assert(s->count < 64 && length <= 283);
    unsigned int slot = MAX(64, ROUND_UP(length + 4, 32));
    unsigned int tail = (s->head + s->count++) % 64;
    p = s->packets[tail];
    s->ready_at[tail] = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
    memset(p, 0, sizeof(s->packets[tail]));
    s->packet_size[tail] = 92 + slot;
    put32(p, 2); put32(p + 4, 92 + slot); put16(p + 12, slot);
    p[92] = service << 4; p[93] = queue; put16(p + 94, length);
    memcpy(p + 96, data, length);
}

static void bsle_ack(USBWs73Test *s, unsigned int message)
{
    uint8_t data[8] = { 2, 0, 4, 0 };
    put32(data + 4, message);
    queue_frame(s, 5, 10, data, sizeof(data));
}

static void command_event(USBWs73Test *s, unsigned int event, unsigned int opcode,
                          unsigned int credit, unsigned int status,
                          const uint8_t *value, size_t length)
{
    uint8_t data[32] = { 0xa2 };
    put16(data + 1, event); put16(data + 3, opcode ? 4 + length : 3);
    put16(data + 5, opcode); data[7] = credit;
    if (opcode) { data[8] = status; if (length) { memcpy(data + 9, value, length); } }
    queue_frame(s, 10, 8, data, opcode ? 9 + length : 8);
    if (opcode && event == 2) {
        s->ready_at[(s->head + s->count - 1) % 64] += 25;
    }
}

static void report_events(USBWs73Test *s)
{
    /* Synthetic unsolicited maximum-length reports; not RF or a scanner.
     * Forty records intentionally overrun the production 32-entry log.
     */
    for (unsigned int ordinal = 1; ordinal <= s->runtime_reports; ordinal++) {
        uint8_t data[283] = { 0xa2 };
        uint8_t *body = data + 5;
        put16(data + 1, 0x180b); put16(data + 3, 278);
        body[0] = 3; body[1] = 6;
        memcpy(body + 2, "\xaa\xbb\xcc\xdd\xee", 5); body[7] = s->serial;
        body[8] = 4; memcpy(body + 9, "\x09\x08\x07\x06\x05\x04", 6);
        body[15] = 1; body[16] = 2; body[17] = 3;
        body[18] = 0x44; body[19] = 0x55; body[20] = 0xa7;
        body[21] = 0xd6; body[22] = 255;
        for (unsigned int i = 0; i < 255; i++) { body[23 + i] = i ^ ordinal; }
        queue_frame(s, 10, 8, data, sizeof(data));
    }
}

static bool command(USBWs73Test *s, const uint8_t *p, size_t length)
{
    uint8_t value[10] = { 0 };
    unsigned int op, n;
    size_t size = 0;

    if (s->in_flight || !s->opened || length < 5 || p[0] != 0xa1) { return false; }
    op = le16(p + 1); n = le16(p + 3);
    if (n != length - 5) { return false; }
    switch (op) {
    case 0x0404:
        if (n) { return false; }
        memcpy(value, "\x02\x01\x00\x01\x20", 5); size = 5;
        break;
    case 0x0402:
        if (n) { return false; }
        value[0] = 254; value[2] = 5; size = 6;
        break;
    case 0x0403:
        if (n) { return false; }
        memset(value, s->serial, 10); size = 10;
        break;
    case 0x0406:
        if (n != 1 || p[5]) { return false; }
        memcpy(value, "\x02\x73\x00\x00\x00", 5); value[5] = s->serial; size = 6;
        break;
    default: return false; /* especially do not accept 0x0401 as ReadCmdLen */
    }
    s->commands++;
    if (s->commands > 4 && s->runtime_fault && !s->failed_once) {
        uint8_t malformed[8] = { 0xa2, 2, 0, 3, 0, 0, 0, 1 };
        s->failed_once = true;
        if (s->runtime_fault == 1) {
            queue_frame(s, 10, 8, malformed, sizeof(malformed));
            /* Production HCC validation rejects the inconsistent aggregate. */
            put32(s->packets[(s->head + s->count - 1) % 64] + 4, 155);
        } else {
            /* Valid HCC and declared DLI framing, wrong successful return
             * length. Only the driver's reply schema can reject this before
             * the Host publishes a result or advances another command.
             */
            assert(size > 0 && size < sizeof(value));
            s->in_flight = true;
            command_event(s, 1, op, 1, 0, NULL, 0);
            command_event(s, 2, op, 1, 0, value,
                          s->runtime_fault == 2 ? size - 1 : size + 1);
        }
        return true;
    }
    if (s->commands > 4 && s->runtime_status && !s->failed_once) {
        s->failed_once = true;
        command_event(s, 1, op, 1, s->runtime_status, NULL, 0);
        return true;
    }
    s->in_flight = true;
    command_event(s, 1, op, 1, 0, NULL, 0); /* acceptance, not completion */
    command_event(s, 2, op, 0, 0, value, size); /* zero window */
    command_event(s, 2, 0, 1, 0, NULL, 0); /* genuine unsolicited grant */
    if (s->commands > 4 && op == 0x0404 && s->runtime_reports && !s->reports_emitted) {
        s->reports_emitted = true;
        report_events(s);
    }
    return true;
}

static bool outgoing(USBWs73Test *s, const uint8_t *p, size_t n)
{
    unsigned int length;

    if (n < 36 || le32(p + 8) != s->sequence++) { return false; }
    if (le32(p) == 3) {
        return n == 36 && !le32(p + 4) && le32(p + 12) <= 1;
    }
    if (le32(p) || n < 128 || le32(p + 4) != n) { return false; }
    if (p[64] == 0x19 && p[65] == 9) {
        if (n != 128 || le16(p + 66) != 32 || le16(p + 68) || le16(p + 70) != 4) { return false; }
        s->pm = true;
        return true;
    }
    if (p[64] == 0x50 && p[65] == 10) {
        if (!s->pm || n != 864 || le16(p + 66) != 800 || le16(p + 68) || le16(p + 70) != 140) { return false; }
        s->custom = true; bsle_ack(s, 2);
        return true;
    }
    length = le16(p + 66);
    if (p[64] != 0xa0 || p[65] != 8 || length > n - 68) { return false; }
    return command(s, p + 68, length);
}

static void reset(USBDevice *dev)
{
    USBWs73Test *s = USB_WS73_TEST(dev);
    s->head = s->count = s->sequence = s->commands = 0;
    s->bsp = true; s->pm = s->custom = s->opened = s->failed_once = s->in_flight = false;
    s->reports_emitted = false;
    if (s->wake) { timer_del(s->wake); }
}

static void wakeup(void *opaque)
{
    USBWs73Test *s = opaque;
    usb_wakeup(usb_ep_get(&s->parent_obj, USB_TOKEN_IN, 1), 0);
}

static void realize(USBDevice *dev, Error **errp)
{
    USBWs73Test *s = USB_WS73_TEST(dev);
    usb_desc_create_serial(dev); usb_desc_init(dev);
    s->wake = timer_new_ms(QEMU_CLOCK_VIRTUAL, wakeup, s);
    s->serial = ++instances;
    g_assert(s->serial < 255);
    g_assert(s->runtime_reports <= 40);
    reset(dev);
}

static void control(USBDevice *dev, USBPacket *p, int request, int value,
                    int index, int length, uint8_t *data)
{
    USBWs73Test *s = USB_WS73_TEST(dev);
    if (usb_desc_handle_control(dev, p, request, value, index, length, data) >= 0) { return; }
    if (request == 0x2100 && !value && !index && length == 4 && le32(data) == 29 && s->custom) {
        s->opened = true; bsle_ack(s, 1);
        usb_wakeup(usb_ep_get(dev, USB_TOKEN_IN, 1), 0); return;
    }
    p->status = USB_RET_STALL;
}

static void transfer(USBDevice *dev, USBPacket *p)
{
    USBWs73Test *s = USB_WS73_TEST(dev);
    uint8_t out[1024];
    size_t n = p->iov.size;

    if (p->pid == USB_TOKEN_IN && p->ep->nr == 3) {
        uint8_t bits[8] = { 0 };
        if (!s->bsp) { p->status = USB_RET_NAK; return; }
        if (n < 8) { p->status = USB_RET_STALL; return; }
        bits[0] = 1; s->bsp = false; usb_packet_copy(p, bits, 8);
    } else if (p->pid == USB_TOKEN_IN && p->ep->nr == 1) {
        if (!s->count) { p->status = USB_RET_NAK; return; }
        if (n < s->packet_size[s->head]) { p->status = USB_RET_STALL; return; }
        if (qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) < s->ready_at[s->head]) {
            timer_mod(s->wake, s->ready_at[s->head]); p->status = USB_RET_NAK; return;
        }
        if (s->packets[s->head][96] == 0xa2 && le16(s->packets[s->head] + 97) == 2
            && le16(s->packets[s->head] + 101)) { s->in_flight = false; }
        usb_packet_copy(p, s->packets[s->head], s->packet_size[s->head]);
        s->head = (s->head + 1) % 64; s->count--;
    } else if (p->pid == USB_TOKEN_OUT && p->ep->nr == 1 && n <= sizeof(out)) {
        usb_packet_copy(p, out, n);
        if (!outgoing(s, out, n)) { p->status = USB_RET_STALL; }
        else { usb_wakeup(usb_ep_get(dev, USB_TOKEN_IN, 1), 0); }
    } else { p->status = USB_RET_STALL; }
}

static Property properties[] = {
    DEFINE_PROP_UINT8("runtime-status", USBWs73Test, runtime_status, 0),
    DEFINE_PROP_UINT8("runtime-fault", USBWs73Test, runtime_fault, 0),
    DEFINE_PROP_UINT8("runtime-reports", USBWs73Test, runtime_reports, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static void unrealize(USBDevice *dev)
{
    USBWs73Test *s = USB_WS73_TEST(dev);
    timer_free(s->wake); s->wake = NULL;
}

static void class_init(ObjectClass *klass, void *data)
{
    USBDeviceClass *uc = USB_DEVICE_CLASS(klass);
    uc->realize = realize; uc->unrealize = unrealize; uc->usb_desc = &descriptor;
    uc->product_desc = "Synthetic WS73 runtime (NO RF)";
    uc->handle_reset = reset; uc->handle_control = control; uc->handle_data = transfer;
    device_class_set_props(DEVICE_CLASS(klass), properties);
}

static const TypeInfo type = {
    .name = TYPE_USB_WS73_TEST, .parent = TYPE_USB_DEVICE,
    .instance_size = sizeof(USBWs73Test), .class_init = class_init,
};

static void register_type(void) { type_register_static(&type); }
type_init(register_type);
