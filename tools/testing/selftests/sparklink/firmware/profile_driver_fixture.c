// SPDX-License-Identifier: GPL-2.0-only
/* Actual WS73 selection/file-validation/boot bodies. Dependencies below are
 * explicit: filesystem, SHA implementation, allocator, mutexes, clock and USB.
 * This is not kernel concurrency, callback/drain or physical firmware proof.
 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "fw_profile.h"
#include "recovery.h"
#ifdef NDEBUG
#error "assertions required"
#endif
typedef uint8_t u8;
typedef uint32_t u32;
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define SHA256_DIGEST_SIZE 32
#define WS73_WIRE_CUSTOM_DATA_SIZE 140
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define WRITE_ONCE(p, v) ((p) = (v))
#define READ_ONCE(p) (p)
#define dev_err(...) ((void)0)
#define dev_info(...) ((void)0)
#define ktime_get() 100ULL
#define ktime_to_ms(t) (t)
/* @@DEFINES@@ */
/* @@STAGES@@ */
struct work_struct { int unused; };
struct device { unsigned int slot; };
struct interface { struct device dev; };
struct firmware { const u8 *data; size_t size; };
struct ws73_port {
	struct ws73_recovery_budget budget;
	bool rom_profile_pending;
	struct ws73_fw_profile rom_profile;
};
struct ws73_usb {
	struct work_struct boot_work;
	struct interface *intf;
	struct ws73_port *port;
	int phase_lock;
	char profile_directory[WS73_PROFILE_DIRECTORY_SIZE];
	struct ws73_fw_profile input_profile;
	bool profile_loaded, stopping, recovery_io;
	u8 profile_checked;
	unsigned int stage, failure_stage;
	unsigned long long boot_deadline_ms, failure_ms;
	int failure_error, last_error;
};
static int ws73_ports_lock;
static struct interface interfaces[2];
static struct ws73_port ports[2];
static struct ws73_usb devices[2];
static u8 blobs[2][6][256];
static size_t sizes[2][6];
static int missing, allocate_fail, allocations, live_files, io_count, io_fail, reads_return;
static unsigned int cases;
static void mutex_lock(int *lock) { assert(!*lock); *lock = 1; }
static void mutex_unlock(int *lock) { assert(*lock == 1); *lock = 0; }
static void sha256(const u8 *p, size_t n, u8 *out) { assert(SHA256(p, n, out)); }
static int hex2bin(u8 *out, const u8 *p, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) {
		unsigned int a = p[2*i] <= '9' ? p[2*i]-'0' : p[2*i]-'a'+10;
		unsigned int b = p[2*i+1] <= '9' ? p[2*i+1]-'0' : p[2*i+1]-'a'+10;
		out[i] = a * 16 + b;
	}
	return 0;
}
/* @@TABLES@@ */
static int request_firmware_direct(const struct firmware **out, const char *name,
				   struct device *device)
{
	const char *file = strrchr(name, '/');
	struct ws73_usb *ws = &devices[device->slot];
	struct firmware *fw;
	unsigned int i;

	assert(ws->phase_lock && !ws73_ports_lock && file);
	assert((size_t)(file-name) == strlen(ws->profile_directory));
	assert(!memcmp(name, ws->profile_directory, (size_t)(file-name)));
	for (i = 0; i < WS73_PROFILE_FILES; i++)
		if (!strcmp(file+1, ws73_profile_names[i]))
			break;
	if (i == WS73_PROFILE_FILES)
		assert(!strcmp(file+1, "profile.bin"));
	if ((int)i == missing)
		return -ENOENT;
	allocations++;
	if (allocations == allocate_fail)
		return -ENOMEM;
	fw = malloc(sizeof(*fw));
	assert(fw);
	*fw = (struct firmware) { blobs[device->slot][i], sizes[device->slot][i] };
	*out = fw;
	live_files++;
	return 0;
}
static void release_firmware(const struct firmware *file)
{
	if (file) { assert(live_files > 0); live_files--; free((void *)file); }
}
static int ws73_command(struct ws73_usb *ws, const char *command, const char *reply)
{
	(void)command; (void)reply;
	assert(!ws73_ports_lock && !ws->phase_lock && ws->port->rom_profile_pending);
	assert(ws->profile_checked == 7);
	assert(!ws73_fw_profile_same(&ws->port->rom_profile, &ws->input_profile));
	return ++io_count == io_fail ? -ETIMEDOUT : 0;
}
static int ws73_read(struct ws73_usb *ws, int size)
{
	assert(size == 4 && !ws->phase_lock);
	return reads_return;
}
static int ws73_download_image(struct ws73_usb *ws, const struct firmware *image, u32 address)
{
	unsigned int i;
	assert(!ws73_ports_lock && !ws->phase_lock && ws->profile_checked == 7);
	for (i = 0; i < ARRAY_SIZE(ws73_images); i++)
		if (ws73_images[i].address == address)
			break;
	assert(i < ARRAY_SIZE(ws73_images));
	assert(image->data == blobs[ws->intf->dev.slot][i]);
	return ++io_count == io_fail ? -EIO : 0;
}
static void ws73_pending_status(struct ws73_usb *ws, unsigned int stage, int ret)
{
	(void)ws; (void)stage; (void)ret;
}
/* @@ACTUAL@@ */
static void reset(void)
{
	unsigned int s, i, j;
	u8 hash[32];
	assert(!live_files && !ws73_ports_lock);
	memset(devices, 0, sizeof(devices)); memset(ports, 0, sizeof(ports));
	memset(blobs, 0, sizeof(blobs));
	missing = -1; allocate_fail = allocations = io_count = io_fail = 0;
	reads_return = 4;
	for (s = 0; s < 2; s++) {
		interfaces[s].dev.slot = s;
		devices[s].intf = &interfaces[s]; devices[s].port = &ports[s];
		assert(!ws73_fw_profile_directory(devices[s].profile_directory,
			sizeof(devices[s].profile_directory), "0000:00:02.0", s ? "2" : "1"));
		for (i = 0; i < 3; i++) {
			memset(blobs[s][i]+64, (int)(i+1+s*8), 4); sizes[s][i] = 68;
			sha256(blobs[s][i]+64, 4, hash);
			for (j = 0; j < 32; j++)
				snprintf((char *)blobs[s][i]+j*2, 3, "%02x", hash[j]);
			/* snprintf's terminator must not overwrite the actual payload. */
			blobs[s][i][64] = (u8)(i+1+s*8);
		}
		sizes[s][3] = 140; sizes[s][4] = 4; sizes[s][5] = WS73_PROFILE_SIZE;
		memcpy(blobs[s][5], "WS73P001", 8); blobs[s][5][8] = s ? 2 : 0;
		for (i = 0; i < 5; i++)
			sha256(blobs[s][i], sizes[s][i], blobs[s][5]+12+i*32);
	}
}
static void boot_failure(int error)
{
	struct ws73_usb *ws = &devices[0];
	ws73_boot_work(&ws->boot_work);
	assert(ws->stage == WS73_FAILED && ws->last_error == error);
	assert(!ws->boot_deadline_ms && !ws->recovery_io && !live_files && !ws->phase_lock);
	cases++;
}
int main(void)
{
	unsigned int i, normal_io;
	struct ws73_usb peer;
	const struct firmware *file;

	reset(); peer = devices[1]; ws73_boot_work(&devices[0].boot_work);
	assert(devices[0].stage == WS73_REENUMERATING && !live_files && io_count);
	assert(!memcmp(&peer, &devices[1], sizeof(peer)) && !ports[1].rom_profile_pending);
	normal_io = (unsigned int)io_count; cases++;
	ws73_boot_work(&devices[1].boot_work);
	assert(ports[0].rom_profile.model == 0 && ports[1].rom_profile.model == 2);
	assert(!live_files); cases++;
	for (i = 0; i < 4; i++) {
		reset(); missing = i == 3 ? 5 : (int)i;
		boot_failure(-ENOENT); assert(!io_count && !ports[0].rom_profile_pending);
		reset(); allocate_fail = (int)i+1;
		boot_failure(-ENOMEM); assert(!io_count && !ports[0].rom_profile_pending);
	}
	for (i = 0; i < 3; i++) {
		reset(); blobs[0][i][67] ^= 1;
		boot_failure(-EBADMSG); assert(!io_count && !ports[0].rom_profile_pending);
	}
	reset(); blobs[0][5][9] = 1; boot_failure(-EINVAL); assert(!io_count);
	reset(); ports[0].rom_profile_pending = true;
	assert(!ws73_fw_profile_decode(blobs[1][5], WS73_PROFILE_SIZE, &ports[0].rom_profile));
	boot_failure(-ESTALE); assert(!io_count);
	for (i = 1; i <= normal_io; i++) {
		reset(); io_fail = (int)i;
		ws73_boot_work(&devices[0].boot_work);
		assert(devices[0].stage == WS73_FAILED && devices[0].last_error < 0);
		assert(!live_files && !devices[0].boot_deadline_ms && ports[0].rom_profile_pending);
		cases++;
	}
	reset(); reads_return = 3; boot_failure(-EPROTO);
	reset(); ports[0].budget.uploads = WS73_RECOVERY_UPLOAD_LIMIT;
	boot_failure(-ELOOP); assert(!io_count && !allocations);
	reset(); mutex_lock(&devices[0].phase_lock);
	assert(!ws73_profile_load(&devices[0]));
	assert(!ws73_profile_file(&devices[0], WS73_PROFILE_CUSTOM, &file));
	release_firmware(file); assert(devices[0].profile_checked == (1U << WS73_PROFILE_CUSTOM));
	blobs[0][3][0] ^= 1; file = (const struct firmware *)1;
	assert(ws73_profile_file(&devices[0], WS73_PROFILE_CUSTOM, &file) == -EBADMSG && !file);
	assert(!devices[0].profile_checked && !live_files);
	blobs[0][3][0] ^= 1;
	assert(!ws73_profile_file(&devices[0], WS73_PROFILE_CUSTOM, &file));
	release_firmware(file);
	blobs[0][4][0] ^= 1; file = (const struct firmware *)1;
	assert(ws73_profile_file(&devices[0], WS73_PROFILE_PM, &file) == -EBADMSG && !file);
	assert(devices[0].profile_checked == (1U << WS73_PROFILE_CUSTOM) && !live_files);
	blobs[0][5][12] ^= 1;
	assert(ws73_profile_load(&devices[0]) == -ESTALE);
	assert(!devices[0].profile_checked && !live_files);
	mutex_unlock(&devices[0].phase_lock); cases++;
	printf("WS73 actual profile/boot fault fixture: %u cases passed;all references released\n", cases);
	return 0;
}
