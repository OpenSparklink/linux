// SPDX-License-Identifier: GPL-2.0-only
/* Historical unpublished commands must remain absent. Run only in the test VM.
 * Frozen x86/Linux ioctl encodings from 167f468c00f7, not a compatibility API.
 * Both ordinary and privileged opens must reject before touching the argument.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>
static const struct { unsigned long command; const char *name; } retired[] = {
    { 0x00005350UL, "SL_IOCTL_SSAP_REGISTER_SVC" },
    { 0x80105351UL, "SL_IOCTL_SSAP_INFO" },
    { 0xc1005352UL, "SL_IOCTL_SSAP_READ" },
    { 0x41005353UL, "SL_IOCTL_SSAP_WRITE" },
    { 0x807c5354UL, "SL_IOCTL_SSAP_FIND_SVC" },
    { 0x40025355UL, "SL_IOCTL_SSAP_NOTIFY" },
    { 0x81005356UL, "SL_IOCTL_SSAP_DEQUEUE_NTF" },
    { 0xc01c5357UL, "SL_IOCTL_SSAP_ADD_SVC" },
    { 0xc1005358UL, "SL_IOCTL_SSAP_ADD_PROP" },
    { 0x40025359UL, "SL_IOCTL_SSAP_REMOVE_SVC" },
    { 0x4004535aUL, "SL_IOCTL_SSAP_EXCHANGE_INFO" },
    { 0xc008535bUL, "SL_IOCTL_SSAP_REMOTE_DISCOVER" },
    { 0xc100535cUL, "SL_IOCTL_SSAP_REMOTE_READ" },
    { 0x4100535dUL, "SL_IOCTL_SSAP_REMOTE_WRITE" },
    { 0x8100535eUL, "SL_IOCTL_SSAP_REMOTE_EVENT" },
    { 0xc100535fUL, "SL_IOCTL_SSAP_CALL_METHOD" },
    { 0xc100536fUL, "SL_IOCTL_SSAP_FIND_BY_UUID" },
    { 0xc1005372UL, "SL_IOCTL_SSAP_READ_BY_UUID" },
};
int main(void)
{
    int fd = open("/dev/sparklink", O_RDWR | O_CLOEXEC);
    if (fd < 0) { perror("open"); return 4; }
    for (unsigned int i = 0; i < sizeof(retired)/sizeof(retired[0]); i++) {
        for (unsigned int null_arg = 0; null_arg < 2; null_arg++) {
            errno = 0;
            if (ioctl(fd, retired[i].command, null_arg ? NULL : (void *)1) != -1 || errno != ENOTTY) {
                fprintf(stderr, "%s: expected ENOTTY, got errno %d\n", retired[i].name, errno);
                close(fd); return 1;
            }
        }
    }
    close(fd);
    puts("SSAP_REMOVED_UAPI_PASS commands=18 pointer_variants=2");
    return 0;
}
