// SPDX-License-Identifier: GPL-2.0-only
/* Synthetic production-USB terminal races. No firmware execution or RF. */
#define main ws73_native_lifecycle_main
#include "ws73_native_runtime_test.c"
#undef main

static int retired_raw(int fd, unsigned long long generation)
{
    struct sle_dli_event event = { 0 };
    struct sle_dli_cmd command = { .opcode = 0x0403 };
    struct sle_controller_snapshot snapshot = { .version = 1, .generation = generation };
    if (stale(fd)) return -1;
    errno = 0;
    if (ioctl(fd, SL_IOCTL_DLI_POLL_EVENT, &event) != -1 || errno != ENODEV)
        return fail("retired raw result must stay ENODEV");
    errno = 0;
    if (ioctl(fd, SL_IOCTL_DLI_SEND_CMD, &command) != -1 || errno != ENODEV)
        return fail("retired raw admission must stay ENODEV");
    errno = 0;
    if (ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &snapshot) != -1 || errno != ENODEV)
        return fail("retired snapshot must stay ENODEV");
    return 0;
}

static int no_success_until_retired(int control, int a, double *elapsed)
{
    double started = now(), deadline = started + 4;
    do {
        struct sle_dli_event event = { 0 };
        uint16_t mask = 0;
        int ret = ioctl(a, SL_IOCTL_DLI_POLL_EVENT, &event);
        if (!ret && event.opcode == 0x0403 && event.event_type == 1 && !event.status)
            return fail("early Complete leaked through failed/cancelled OUT");
        if (ret && errno != EAGAIN && errno != ENODEV)
            return fail("terminal-race raw poll");
        if (ioctl(control, SL_IOCTL_DEV_LIST, &mask)) return fail("terminal-race inventory");
        if (mask == 2) { *elapsed = now() - started; return 0; }
        if (mask != 3) return fail("survivor disappeared during retirement");
        usleep(1000);
    } while (now() < deadline);
    return fail("in-flight retirement exceeded four seconds");
}

static int failed_transport(int expected)
{
    double deadline = now() + 2;
    do {
        DIR *dir = opendir("/sys/bus/usb/drivers/sparklink_ws73_usb");
        struct dirent *entry;
        int count = 0;
        if (!dir) return fail("terminal-race driver inventory");
        while ((entry = readdir(dir))) {
            char path[512], stage[64];
            int error = 0;
            FILE *file;
            if (!strchr(entry->d_name, ':')) continue;
            snprintf(path, sizeof(path), "/sys/bus/usb/drivers/sparklink_ws73_usb/%s/boot_error", entry->d_name);
            file = fopen(path, "r");
            if (!file) continue;
            int parsed = fscanf(file, "%d", &error);
            fclose(file);
            if (parsed != 1 || error != -expected) continue;
            snprintf(path, sizeof(path), "/sys/bus/usb/drivers/sparklink_ws73_usb/%s/boot_stage", entry->d_name);
            file = fopen(path, "r");
            if (!file) continue;
            parsed = fscanf(file, "%63s", stage);
            fclose(file);
            if (parsed == 1 && !strcmp(stage, "failed")) count++;
        }
        closedir(dir);
        if (count == 1) return 0;
        usleep(1000);
    } while (now() < deadline);
    return fail("first OUT failure not retained in driver");
}

int main(int argc, char **argv)
{
    int unplug = argc == 2 && !strcmp(argv[1], "unplug");
    int expected = argc == 2 && !strcmp(argv[1], "out-error") ? EPIPE :
                   argc == 2 && !strcmp(argv[1], "short-out") ? EREMOTEIO : 0;
    if (!unplug && !expected) return 2;
    int control = -1, a = -1, b = -1, observer = -1, replacement = -1, complete = 0;
    struct sci_dev_info ai, bi, ri, oi;
    unsigned long long ag, bg, rg, og;
    double elapsed;
    setvbuf(stdout, NULL, _IOLBF, 0);
    control = open("/dev/sparklink", O_RDWR | O_NONBLOCK);
    if (control < 0 || mask_wait(control, 1)) goto out;
    a = bind_owner(0, &ai, &ag);
    if (a < 0 || query(a, &ai, 0x0406, 0xfe)) goto out;
    puts("NATIVE_ADD_SECOND");
    if (mask_wait(control, 3)) goto out;
    b = bind_owner(1, &bi, &bg);
    observer = bind_owner(0, &oi, &og);
    if (b < 0 || observer < 0 || og != ag || events_subscribe(observer, ag) ||
        tx_barrier_pending(a, ag, b, &bi)) goto out;
    if (unplug) puts("NATIVE_REMOVE_FIRST");
    else puts("NATIVE_TX_WAIT_FAULT");
    if (no_success_until_retired(control, a, &elapsed) || retired_raw(a, ag) ||
        events_retired(observer, ag) || same(b, &bi, bg) || query(b, &bi, 0x0406, 0)) goto out;
    if (!unplug && failed_transport(expected)) goto out;
    if (exercise(b, &bi)) goto out;
    if (!unplug && failed_transport(expected)) goto out;
    printf("NATIVE_TX_RETIRE: mode=%s early_success=0 old_raw=ENODEV event_hup=1 survivor=1 driver_error=%s error_checks=%u elapsed_ms=%.3f\n",
           argv[1], unplug ? "removed" : expected == EPIPE ? "pipe" : "short",
           unplug ? 0U : 2U, elapsed * 1000);
    if (!unplug) puts("NATIVE_REMOVE_FIRST");
    if (wait_interfaces(1)) goto out;
    puts("NATIVE_READD_FIRST");
    if (mask_wait(control, 3)) goto out;
    replacement = bind_owner(0, &ri, &rg);
    if (replacement < 0 || rg <= ag || rg == bg || !memcmp(ai.addr, ri.addr, 6) ||
        query(replacement, &ri, 0x0403, 0) || retired_raw(a, ag) ||
        events_retired(observer, ag) || same(b, &bi, bg)) goto out;
    /* Cross the cancelled fixture's original deadline with old fds retained. */
    double guard_start = now();
    while (now() - guard_start < 2.2) usleep(1000);
    double guard_ms = (now() - guard_start) * 1000;
    if (retired_raw(a, ag) || events_retired(observer, ag) || same(b, &bi, bg) ||
        query(b, &bi, 0x0406, 0) || query(replacement, &ri, 0x0403, 0)) goto out;
    printf("NATIVE_TX_REPLUG: old=%llu new=%llu unaffected=%llu features=10 old_raw=ENODEV late_guard_ms=%.3f\n",
           ag, rg, bg, guard_ms);
    puts("NATIVE_TX_TERMINAL: PASS");
    complete = 1;
out:
    if (!complete && !failed) fail("terminal race ended before completion");
    if (replacement >= 0) close(replacement);
    if (observer >= 0) close(observer);
    if (b >= 0) close(b);
    if (a >= 0) close(a);
    if (control >= 0) close(control);
    return complete && !failed ? 0 : 1;
}
