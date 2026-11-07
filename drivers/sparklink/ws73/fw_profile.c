// SPDX-License-Identifier: GPL-2.0-only
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <stdio.h>
#include <string.h>
#endif

#include "fw_profile.h"

int ws73_fw_profile_decode(const unsigned char *data, size_t size,
			   struct ws73_fw_profile *profile)
{
	struct ws73_fw_profile value;
	unsigned int i, j;
	unsigned char nonzero;

	if (!data || !profile || size != WS73_PROFILE_SIZE)
		return -EINVAL;
	if (memcmp(data, "WS73P001", 8) || (data[8] != 0 && data[8] != 2) ||
	    data[9] || data[10] || data[11])
		return -EINVAL;
	value.model = data[8];
	memcpy(value.digest, data + 12, sizeof(value.digest));
	for (i = 0; i < WS73_PROFILE_FILES; i++) {
		nonzero = 0;
		for (j = 0; j < WS73_PROFILE_DIGEST_SIZE; j++)
			nonzero |= value.digest[i][j];
		if (!nonzero)
			return -EINVAL;
	}
	*profile = value;
	return 0;
}

int ws73_fw_profile_digest(const struct ws73_fw_profile *profile,
			   unsigned int file, const unsigned char *digest)
{
	if (!profile || !digest || file >= WS73_PROFILE_FILES)
		return -EINVAL;
	return memcmp(profile->digest[file], digest, WS73_PROFILE_DIGEST_SIZE) ?
		-EBADMSG : 0;
}

int ws73_fw_profile_model(const struct ws73_fw_profile *profile,
			  unsigned int model, unsigned int bus)
{
	if (!profile || (profile->model != 0 && profile->model != 2))
		return -EINVAL;
	return model == profile->model && !bus ? 0 : -EPROTO;
}

int ws73_fw_profile_same(const struct ws73_fw_profile *left,
			 const struct ws73_fw_profile *right)
{
	if (!left || !right || (left->model != 0 && left->model != 2) ||
	    (right->model != 0 && right->model != 2))
		return -EINVAL;
	return left->model == right->model &&
	       !memcmp(left->digest, right->digest, sizeof(left->digest)) ?
		0 : -ESTALE;
}

int ws73_fw_profile_directory(char *out, size_t capacity,
			      const char *controller, const char *route)
{
	static const char prefix[] = "sparklink/ws73/by-path/";
	size_t n, length, digits = 0;
	unsigned int port = 0;
	unsigned char c;

	if (!out || !controller || !route)
		return -EINVAL;
	for (n = 0; n < 64 && controller[n]; n++) {
		c = controller[n];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
		      (c >= 'A' && c <= 'Z') || c == ':' || c == '.' ||
		      c == '-' || c == '_'))
			return -EINVAL;
	}
	if (!n || n == 64)
		return -ENAMETOOLONG;
	length = sizeof(prefix) - 1 + n + sizeof("-usb2-") - 1;
	for (n = 0; n < 16 && route[n]; n++) {
		c = route[n];
		if (c == '.') {
			if (!digits)
				return -EINVAL;
			digits = 0;
			port = 0;
		} else if (c >= '0' && c <= '9') {
			if ((!digits && c == '0') || ++digits > 3)
				return -EINVAL;
			port = port * 10 + c - '0';
			if (port > 255)
				return -EINVAL;
		} else {
			return -EINVAL;
		}
	}
	if (!n || n == 16)
		return -ENAMETOOLONG;
	if (!digits)
		return -EINVAL;
	length += n;
	if (length >= capacity)
		return -ENAMETOOLONG;
	snprintf(out, capacity, "%s%s-usb2-%s", prefix, controller, route);
	return 0;
}
