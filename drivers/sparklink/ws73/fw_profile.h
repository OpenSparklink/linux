/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef WS73_FW_PROFILE_H
#define WS73_FW_PROFILE_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#endif

#define WS73_PROFILE_FILES 5
#define WS73_PROFILE_DIGEST_SIZE 32
#define WS73_PROFILE_SIZE (12 + WS73_PROFILE_FILES * WS73_PROFILE_DIGEST_SIZE)
#define WS73_PROFILE_DIRECTORY_SIZE 128
#define WS73_PROFILE_PATH_SIZE 160

enum ws73_profile_file {
	WS73_PROFILE_MAIN,
	WS73_PROFILE_WIFI,
	WS73_PROFILE_BTC,
	WS73_PROFILE_CUSTOM,
	WS73_PROFILE_PM,
};

/* Selected OS inputs only; never an assertion about silicon or running RAM. */
struct ws73_fw_profile {
	unsigned char model;
	unsigned char digest[WS73_PROFILE_FILES][WS73_PROFILE_DIGEST_SIZE];
};

int ws73_fw_profile_decode(const unsigned char *data, size_t size,
			   struct ws73_fw_profile *profile);
int ws73_fw_profile_digest(const struct ws73_fw_profile *profile,
			   unsigned int file, const unsigned char *digest);
int ws73_fw_profile_model(const struct ws73_fw_profile *profile,
			  unsigned int model, unsigned int bus);
int ws73_fw_profile_same(const struct ws73_fw_profile *left,
			 const struct ws73_fw_profile *right);
/* Names must be readable up to their terminator or the 64/16-byte limits.
 * The caller provides the actual controller name and physical USB2 devpath.
 * USB device numbers and firmware-provided strings are not selectors.
 */
int ws73_fw_profile_directory(char *out, size_t capacity,
			      const char *controller, const char *route);

#endif
