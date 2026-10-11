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
#include "qapi/error.h"

#define TYPE_USB_WS73_TEST "usb-ws73-test"
OBJECT_DECLARE_SIMPLE_TYPE(USBWs73Test, USB_WS73_TEST)

struct USBWs73Test {
    USBDevice parent_obj;
    uint8_t packets[64][384];
    unsigned int packet_size[64];
    int64_t ready_at[64];
    QEMUTimer *wake;
    QEMUTimer *out_timer;
    USBPacket *out_packet;
    uint32_t runtime_out_delay_ms;
    uint8_t runtime_out_result;
    bool out_delayed, out_replied;
    bool in_flight;
    unsigned int head, count, sequence, commands, serial;
    uint8_t runtime_status;
    uint8_t runtime_fault;
    bool runtime_fault_repeat;
    uint8_t runtime_reports;
    bool runtime_link_events;
    bool runtime_policy, runtime_fresh_advertiser, advertiser_created, runtime_sle_subtypes;
    bool runtime_zlp;
    bool runtime_warm;
    bool runtime_idle_scan_stop;
    uint8_t runtime_medium;
    uint8_t adv_data[251];
    unsigned int adv_data_len;
    bool runtime_discovery, advertising, scanning, fail_stop;
    unsigned int adv_phase, scan_phase, adv_handle, fail_step;
    bool timeout_enable;
    bool reports_emitted;
    bool bsp, pm, custom, opened, failed_once;
    /* Test model only: retain the next terminal frame at the queue head.
     * This is not a successful host/libusb IN transfer or real RF evidence.
     * One budget per object, including reset; all controls default disabled.
     */
    QEMUTimer *model_hold_timer;
    bool model_hold_once, model_held;
    uint64_t model_holds, model_releases, model_bounded_releases, model_drops;
};

static unsigned int instances;
static USBWs73Test *medium_devices[256];

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
    if (service == 10 && s->runtime_sle_subtypes) { p[92] |= (s->commands - 1) & 15; }
    memcpy(p + 96, data, length);
}

static void bsle_ack(USBWs73Test *s, unsigned int message)
{
    uint8_t data[32] = { 2, 0, 4, 0 };
    /* Model the independently captured RX allocation padding, using an
     * explicitly synthetic nonzero pattern rather than device memory. */
    for (unsigned int i = 8; i < sizeof(data); i++) data[i] = i ^ 0xa5;
    put32(data + 4, message);
    queue_frame(s, 5, 10, data, sizeof(data));
}

static void bsle_close_ack(USBWs73Test *s)
{
    uint8_t data[8] = { 4, 0, 4, 0, 3, 0, 0, 0 };
    queue_frame(s, 5, 10, data, sizeof(data));
}

static void queue_zlp(USBWs73Test *s)
{
    unsigned int tail;

    g_assert(s->count < 64);
    tail = (s->head + s->count++) % 64;
    memset(s->packets[tail], 0, sizeof(s->packets[tail]));
    s->packet_size[tail] = 0;
    s->ready_at[tail] = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
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
        if (s->runtime_link_events) {
            static const unsigned int codes[] = { 0x0015, 0x1401, 0x0005, 0x1405 };
            static const unsigned int sizes[] = { 32, 11, 4, 4 };
            unsigned int kind = (ordinal - 1) % 4, size = sizes[kind];
            put16(data + 1, codes[kind]); put16(data + 3, size);
            body[0] = ordinal % 3 ? 0xfe : 0;
            body[1] = ordinal; body[2] = s->serial;
            body[3] = 0xff; /* raw role or reason, never normalize */
            if (kind < 2) {
                body[4] = 0xa6;
                for (unsigned int i = 5; i < size; i++) { body[i] = i ^ ordinal; }
            }
            queue_frame(s, 10, 8, data, 5 + size);
            continue;
        }
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

/* Explicit synthetic medium, never an air capture. Only a different live
 * policy-enabled controller in the same group can supply a scan report. */
static void medium_report(USBWs73Test *rx, USBWs73Test *tx)
{
    uint8_t data[5 + 23 + 251] = { 0xa2 };
    uint8_t *body = data + 5;
    g_assert(rx != tx && rx->runtime_policy && tx->runtime_policy);
    put16(data + 1, 0x180b); put16(data + 3, 23 + tx->adv_data_len);
    body[1] = 0;
    memcpy(body + 2, "\x02\x73\x00\x00\x00", 5); body[7] = tx->serial;
    body[16] = 1; body[21] = 0xd6; body[22] = tx->adv_data_len;
    memcpy(body + 23, tx->adv_data, tx->adv_data_len);
    queue_frame(rx, 10, 8, data, 28 + tx->adv_data_len);
    usb_wakeup(usb_ep_get(&rx->parent_obj, USB_TOKEN_IN, 1), 0);
}
static void medium_discover(USBWs73Test *changed)
{
    if (!changed->runtime_policy || !changed->runtime_medium) { return; }
    for (unsigned int i = 1; i < ARRAY_SIZE(medium_devices); i++) {
        USBWs73Test *peer = medium_devices[i];
        if (!peer || peer == changed || !peer->runtime_policy ||
            peer->runtime_medium != changed->runtime_medium) { continue; }
        if (changed->scanning && peer->advertising) { medium_report(changed, peer); }
        if (changed->advertising && peer->scanning) { medium_report(peer, changed); }
    }
}
static bool basic_parameters(USBWs73Test *s, const uint8_t *p)
{
    uint8_t expected[49] = { 0 };
    expected[2] = 2; put16(expected + 3, 1200); put16(expected + 6, 1200);
    expected[9] = 7; expected[25] = 127; expected[43] = 200;
    memcpy(expected + 12, "\x02\x73\x00\x00\x00", 5); expected[17] = s->serial;
    return !memcmp(p, expected, sizeof(expected));
}
static bool basic_data(const uint8_t *p, size_t size)
{
    const uint8_t prefix[] = { 255, 41, 1, 1, 1, 11, 36, 's', 'l', 'k', '-' };
    if (size != 43 || memcmp(p, prefix, sizeof(prefix))) { return false; }
    for (size_t i = sizeof(prefix); i < size; i++) {
        if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f'))) { return false; }
    }
    return true;
}

static bool command(USBWs73Test *s, const uint8_t *p, size_t length)
{
    uint8_t value[10] = { 0 };
    unsigned int op, n;
    size_t size = 0;
    unsigned int typed_status = 0;
    bool typed = false, timeout = false;

    if (s->runtime_discovery) { g_assert(!s->in_flight); }
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
        if (n) { return false; } /* WS73 SDK dialect, not standard DLI */
        memcpy(value, "\x02\x73\x00\x00\x00", 5); value[5] = s->serial; size = 6;
        break;
    case 0x0c02:
        if (!s->runtime_discovery || n != 49 || s->advertising || s->scanning || p[5] > 0xef) { return false; }
        if (s->runtime_policy) {
            if (!basic_parameters(s, p + 5)) { return false; }
        } else if (p[5] != 7 || le16(p + 8) != 800 || p[10] || le16(p + 11) != 800 || p[13]
            || memcmp(p + 17, "\x02\x73\x00\x00\x00", 5) || p[22] != s->serial
            || p[30] != 0 || p[31] != 1) { return false; }
        typed = true; s->adv_handle = p[5]; s->adv_phase = 1;
        s->fail_step = p[6] >= 0xf0 && p[6] <= 0xf3 ? p[6] - 0xf0 : 255;
        s->fail_stop = p[6] == 0xee; s->timeout_enable = p[6] == 0xed;
        typed_status = s->fail_step == 0 ? 0xfd : 0;
        if (!typed_status) { s->advertiser_created = true; }
        value[0] = 0xd6; size = 1; /* selected -42, independent of requested power */
        break;
    case 0x0c03:
    case 0x0c04:
        if (!s->runtime_discovery || n < 3 || p[5] != s->adv_handle || p[6] != 3 || n != 3 + p[7]) { return false; }
        if (s->runtime_policy) {
            if (op != 0x0c03 || !basic_data(p + 8, p[7])) { return false; }
            memcpy(s->adv_data, p + 8, p[7]); s->adv_data_len = p[7];
        } else if (p[7] != 6 || memcmp(p + 8, op == 0x0c03 ? "\x05\x09WS73" : "\x05\x09RSP!", 6)) { return false; }
        g_assert(s->adv_phase == (op == 0x0c03 ? 1 : 2));
        typed = true; s->adv_phase++;
        typed_status = s->fail_step == (op == 0x0c03 ? 1 : 2) ? 0xfd : 0;
        break;
    case 0x0c05:
        if (!s->runtime_discovery || n != 5 || p[5] > 1 || p[6] > 0xef) { return false; }
        typed = true;
        if (p[5]) {
            g_assert(s->adv_phase == 2 || s->adv_phase == 3);
            g_assert(p[6] == s->adv_handle);
            typed_status = s->fail_step == 3 ? 0xfd : 0;
            timeout = s->timeout_enable;
            if (!typed_status && !timeout) { s->advertising = true; }
        } else if (s->runtime_fresh_advertiser &&
                   (!s->advertiser_created || p[6] != s->adv_handle)) {
            typed_status = 0x1e; /* real fresh-controller unknown advertiser */
        } else if (s->fail_stop) {
            s->fail_stop = false; typed_status = 0xfd;
        } else { s->advertising = false; }
        s->adv_phase = 0;
        break;
    case 0x1001:
        if (!s->runtime_discovery || n != 8 || p[7] != 1 || p[8] > 1
            || !le16(p + 9) || !le16(p + 11) || le16(p + 11) > le16(p + 9)
            || le16(p + 9) != (s->runtime_policy ? 1600 : 800)
            || le16(p + 11) != (s->runtime_policy ? 800 : 400) || s->advertising || s->scanning) { return false; }
        if (s->runtime_policy && (p[5] || p[6] || p[8])) { return false; }
        typed = true; s->scan_phase = 1;
        break;
    case 0x1002:
        if (!s->runtime_discovery || n != 2 || p[5] > 1 || p[6] > 1) { return false; }
        typed = true;
        if (p[5]) { g_assert(s->scan_phase == 1); s->scanning = true; }
        else if (s->runtime_idle_scan_stop && !s->scanning) {
            typed_status = 0x0b; /* idle OFF is CommandDisallowed, matching the observed real111 failure */
        } else { s->scanning = false; }
        s->scan_phase = 0;
        break;
    default: return false; /* especially do not accept 0x0401 as ReadCmdLen */
    }
    s->commands++;
    /* Only after bootstrap queries: exercise the production asynchronous
     * bulk URB, including initialization stops and in-flight commands.
     * This has no HCC payload and must not clear command ownership.
     */
    if (s->commands > 4 && s->runtime_zlp) { queue_zlp(s); }
    if (typed) {
        if (typed_status) { s->adv_phase = 0; size = 0; }
        s->in_flight = true;
        command_event(s, 1, op, 1, 0, NULL, 0);
        if (timeout) { return true; } /* accepted, missing terminal result */
        command_event(s, 2, op, 0, typed_status, value, size);
        command_event(s, 2, 0, 1, 0, NULL, 0);
        if (!typed_status && (op == 0x0c05 || op == 0x1002)) { medium_discover(s); }
        return true;
    }
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
    if (s->model_hold_timer) { timer_del(s->model_hold_timer); }
    if (s->model_held) { s->model_drops++; }
    s->model_hold_once = s->model_held = false;
    s->head = s->count = s->sequence = s->commands = 0;
    s->advertising = s->scanning = s->fail_stop = s->timeout_enable = false;
    s->advertiser_created = false;
    s->adv_phase = s->scan_phase = 0; s->fail_step = 255;
    s->bsp = true; s->pm = s->custom = s->opened = s->failed_once = s->in_flight = false;
    if (s->runtime_warm) {
        s->bsp = false; s->pm = s->custom = s->opened = true;
        bsle_ack(s, 1); bsle_close_ack(s); /* stale, not fresh session evidence */
    }
    s->reports_emitted = false;
    s->adv_data_len = 0;
    if (s->wake) { timer_del(s->wake); }
    if (s->out_timer) { timer_del(s->out_timer); }
    s->out_packet = NULL;
    s->out_delayed = s->out_replied = false;
}

static void out_complete(void *opaque)
{
    USBWs73Test *s = opaque;
    USBPacket *p = s->out_packet;

    g_assert(p);
    s->out_packet = NULL; /* completion can reenter the device */
    p->status = s->runtime_out_result == 1 ? USB_RET_STALL : USB_RET_SUCCESS;
    if (s->runtime_out_result == 1) {
        p->actual_length = 0;
    } else if (s->runtime_out_result == 2) {
        g_assert(p->actual_length > 0);
        p->actual_length--;
    }
    fprintf(stderr, "WS73_TEST_OUT_%s: serial=%u\n",
            s->runtime_out_result == 1 ? "ERROR" :
            s->runtime_out_result == 2 ? "SHORT" : "COMPLETE", s->serial);
    usb_packet_complete(&s->parent_obj, p);
}

static void cancel_packet(USBDevice *dev, USBPacket *p)
{
    USBWs73Test *s = USB_WS73_TEST(dev);

    if (s->out_packet == p) {
        timer_del(s->out_timer);
        s->out_packet = NULL;
        fprintf(stderr, "WS73_TEST_OUT_CANCEL: serial=%u\n", s->serial);
    }
}

static bool out_pending(Object *obj, Error **errp)
{
    return USB_WS73_TEST(obj)->out_packet != NULL;
}

static bool out_replied(Object *obj, Error **errp)
{
    return USB_WS73_TEST(obj)->out_replied;
}

static void wakeup(void *opaque)
{
    USBWs73Test *s = opaque;
    usb_wakeup(usb_ep_get(&s->parent_obj, USB_TOKEN_IN, 1), 0);
}

static void model_release(USBWs73Test *s, bool bounded)
{
    g_assert(s->model_held && s->count);
    char *digest = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
                                               s->packets[s->head],
                                               s->packet_size[s->head]);
    timer_del(s->model_hold_timer);
    s->model_held = false;
    if (bounded) { s->model_bounded_releases++; }
    else { s->model_releases++; }
    fprintf(stderr, "WS73_MODEL_TERMINAL_RELEASE: serial=%u bytes=%u bounded=%u sha256=%s\n",
            s->serial, s->packet_size[s->head], bounded, digest);
    g_free(digest);
    usb_wakeup(usb_ep_get(&s->parent_obj, USB_TOKEN_IN, 1), 0);
}

static void model_bounded_release(void *opaque)
{
    USBWs73Test *s = opaque;
    if (s->model_held) { model_release(s, true); }
}

static bool model_arm_get(Object *obj, Error **errp)
{
    return USB_WS73_TEST(obj)->model_hold_once;
}

static void model_arm_set(Object *obj, bool value, Error **errp)
{
    USBWs73Test *s = USB_WS73_TEST(obj);
    if (!value) { s->model_hold_once = false; return; }
    if (!s->opened || !s->runtime_discovery || s->count || s->in_flight
        || s->model_hold_once || s->model_held || s->model_holds) {
        error_setg(errp, "model hold requires idle opened discovery fixture and unused object budget");
        return;
    }
    s->model_hold_once = true;
}

static bool model_held_get(Object *obj, Error **errp)
{
    return USB_WS73_TEST(obj)->model_held;
}

static bool model_armable_get(Object *obj, Error **errp)
{
    USBWs73Test *s = USB_WS73_TEST(obj);
    return s->opened && s->runtime_discovery && !s->count && !s->in_flight
        && !s->model_hold_once && !s->model_held && !s->model_holds;
}

static bool model_release_get(Object *obj, Error **errp)
{
    return false; /* pulse, never a stored success */
}

static void model_release_set(Object *obj, bool value, Error **errp)
{
    USBWs73Test *s = USB_WS73_TEST(obj);
    if (!value) { return; }
    if (!s->model_held || !s->count) {
        error_setg(errp, "no actual model terminal frame retained");
        return;
    }
    model_release(s, false);
}

static bool model_retain_terminal(USBWs73Test *s)
{
    if (s->model_held) { return true; }
    uint8_t *frame = s->packets[s->head];
    if (!s->model_hold_once || s->packet_size[s->head] < 105
        || frame[96] != 0xa2 || le16(frame + 97) != 2 || !le16(frame + 101)) {
        return false;
    }
    g_assert(s->model_holds == 0);
    s->model_hold_once = false; s->model_held = true; s->model_holds++;
    char *digest = g_compute_checksum_for_data(G_CHECKSUM_SHA256, frame,
                                               s->packet_size[s->head]);
    fprintf(stderr, "WS73_MODEL_TERMINAL_HOLD: serial=%u bytes=%u sha256=%s\n",
            s->serial, s->packet_size[s->head], digest);
    g_free(digest);
    timer_mod(s->model_hold_timer, qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + 2000);
    return true;
}

static void realize(USBDevice *dev, Error **errp)
{
    USBWs73Test *s = USB_WS73_TEST(dev);
    usb_desc_create_serial(dev); usb_desc_init(dev);
    s->wake = timer_new_ms(QEMU_CLOCK_VIRTUAL, wakeup, s);
    s->out_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, out_complete, s);
    s->model_hold_timer = timer_new_ms(QEMU_CLOCK_REALTIME, model_bounded_release, s);
    s->serial = ++instances;
    g_assert(s->serial < 255);
    g_assert(s->runtime_reports <= 40);
    g_assert(s->runtime_out_delay_ms <= 2000);
    g_assert(s->runtime_out_result <= 2);
    g_assert(!s->runtime_out_result || s->runtime_out_delay_ms);
    g_assert(!s->runtime_policy || s->runtime_discovery);
    medium_devices[s->serial] = s;
    reset(dev);
}

static void control(USBDevice *dev, USBPacket *p, int request, int value,
                    int index, int length, uint8_t *data)
{
    USBWs73Test *s = USB_WS73_TEST(dev);
    if (usb_desc_handle_control(dev, p, request, value, index, length, data) >= 0) { return; }
    if (request == 0x2100 && !value && !index && length == 4 && le32(data) == 30) {
        s->opened = s->pm = s->custom = false;
        s->advertising = s->scanning = false; s->advertiser_created = false;
        if (s->runtime_fault_repeat) { s->failed_once = false; }
        bsle_close_ack(s);
        fprintf(stderr, "WS73_TEST_CLOSE: serial=%u\n", s->serial);
        usb_wakeup(usb_ep_get(dev, USB_TOKEN_IN, 1), 0); return;
    }
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
        if (model_retain_terminal(s)) { p->status = USB_RET_NAK; return; }
        if (s->packet_size[s->head] >= 105 && s->packets[s->head][96] == 0xa2 && le16(s->packets[s->head] + 97) == 2
            && le16(s->packets[s->head] + 101)) { s->in_flight = false; }
        if (s->out_packet && s->packet_size[s->head] >= 105 &&
            s->packets[s->head][96] == 0xa2 &&
            le16(s->packets[s->head] + 97) == 2 &&
            le16(s->packets[s->head] + 101) == 0x0403) {
            s->out_replied = true;
            fprintf(stderr, "WS73_TEST_EARLY_REPLY: serial=%u\n", s->serial);
        }
        usb_packet_copy(p, s->packets[s->head], s->packet_size[s->head]);
        s->head = (s->head + 1) % 64; s->count--;
    } else if (p->pid == USB_TOKEN_OUT && p->ep->nr == 1 && n <= sizeof(out)) {
        usb_packet_copy(p, out, n);
        if (!outgoing(s, out, n)) { p->status = USB_RET_STALL; }
        else {
            if (s->runtime_out_delay_ms && !s->out_delayed && s->commands > 4 &&
                n >= 73 && out[64] == 0xa0 && out[65] == 8 &&
                out[68] == 0xa1 && le16(out + 69) == 0x0403) {
                g_assert(!s->out_packet);
                s->out_delayed = true;
                s->out_packet = p;
                p->status = USB_RET_ASYNC;
                timer_mod(s->out_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + s->runtime_out_delay_ms);
                fprintf(stderr, "WS73_TEST_OUT_PENDING: serial=%u delay=%u\n",
                        s->serial, s->runtime_out_delay_ms);
            }
            usb_wakeup(usb_ep_get(dev, USB_TOKEN_IN, 1), 0);
        }
    } else { p->status = USB_RET_STALL; }
}

static Property properties[] = {
    DEFINE_PROP_BOOL("runtime-policy", USBWs73Test, runtime_policy, false),
    DEFINE_PROP_BOOL("runtime-warm", USBWs73Test, runtime_warm, false),
    DEFINE_PROP_BOOL("runtime-idle-scan-stop", USBWs73Test, runtime_idle_scan_stop, false),
    DEFINE_PROP_BOOL("runtime-sle-subtypes", USBWs73Test, runtime_sle_subtypes, false),
    DEFINE_PROP_BOOL("runtime-fresh-advertiser", USBWs73Test, runtime_fresh_advertiser, false),
    DEFINE_PROP_UINT32("runtime-out-delay-ms", USBWs73Test, runtime_out_delay_ms, 0),
    DEFINE_PROP_UINT8("runtime-out-result", USBWs73Test, runtime_out_result, 0),
    DEFINE_PROP_BOOL("runtime-zlp", USBWs73Test, runtime_zlp, false),
    DEFINE_PROP_UINT8("runtime-medium", USBWs73Test, runtime_medium, 0),
    DEFINE_PROP_BOOL("runtime-discovery", USBWs73Test, runtime_discovery, false),
    DEFINE_PROP_UINT8("runtime-status", USBWs73Test, runtime_status, 0),
    DEFINE_PROP_UINT8("runtime-fault", USBWs73Test, runtime_fault, 0),
    DEFINE_PROP_BOOL("runtime-fault-repeat", USBWs73Test, runtime_fault_repeat, false),
    DEFINE_PROP_UINT8("runtime-reports", USBWs73Test, runtime_reports, 0),
    DEFINE_PROP_BOOL("runtime-link-events", USBWs73Test, runtime_link_events, false),
    DEFINE_PROP_END_OF_LIST(),
};

static void unrealize(USBDevice *dev)
{
    USBWs73Test *s = USB_WS73_TEST(dev);
    medium_devices[s->serial] = NULL;
    timer_free(s->wake); s->wake = NULL;
    g_assert(!s->out_packet);
    timer_free(s->out_timer); s->out_timer = NULL;
    if (s->model_held) { s->model_drops++; }
    s->model_hold_once = s->model_held = false;
    timer_free(s->model_hold_timer); s->model_hold_timer = NULL;
}

static void class_init(ObjectClass *klass, void *data)
{
    USBDeviceClass *uc = USB_DEVICE_CLASS(klass);
    uc->realize = realize; uc->unrealize = unrealize; uc->usb_desc = &descriptor;
    uc->product_desc = "Synthetic WS73 runtime (NO RF)";
    uc->handle_reset = reset; uc->handle_control = control; uc->handle_data = transfer;
    uc->cancel_packet = cancel_packet;
    object_class_property_add_bool(klass, "runtime-out-pending", out_pending, NULL);
    object_class_property_add_bool(klass, "runtime-out-replied", out_replied, NULL);
    object_class_property_add_bool(klass, "model-terminal-hold-once", model_arm_get, model_arm_set);
    object_class_property_add_bool(klass, "model-terminal-held", model_held_get, NULL);
    object_class_property_add_bool(klass, "model-terminal-armable", model_armable_get, NULL);
    object_class_property_add_bool(klass, "model-terminal-release", model_release_get, model_release_set);
    device_class_set_props(DEVICE_CLASS(klass), properties);
}

static void instance_init(Object *obj)
{
    USBWs73Test *s = USB_WS73_TEST(obj);
    object_property_add_uint64_ptr(obj, "model-terminal-holds", &s->model_holds, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "model-terminal-releases", &s->model_releases, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "model-terminal-bounded-releases", &s->model_bounded_releases, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "model-terminal-drops", &s->model_drops, OBJ_PROP_FLAG_READ);
}

static const TypeInfo type = {
    .name = TYPE_USB_WS73_TEST, .parent = TYPE_USB_DEVICE,
    .instance_size = sizeof(USBWs73Test), .class_init = class_init, .instance_init = instance_init,
};

static void register_type(void) { type_register_static(&type); }
type_init(register_type);
