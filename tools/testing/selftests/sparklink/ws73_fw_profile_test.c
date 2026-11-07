// SPDX-License-Identifier: GPL-2.0-only
/* Actual production input codec; no firmware, USB or scheduler substitutes. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifdef NDEBUG
#error "assertions must remain enabled in this selftest"
#endif

#include "../../../../drivers/sparklink/ws73/fw_profile.h"

static unsigned int checks;
#define CHECK(condition) do { assert(condition); checks++; } while (0)

static void unchanged(const unsigned char *raw, size_t size)
{
	struct ws73_fw_profile result, before;

	memset(&result, 0xa5, sizeof(result));
	before = result;
	CHECK(ws73_fw_profile_decode(raw, size, &result) < 0);
	CHECK(!memcmp(&result, &before, sizeof(result)));
}

static int decode_file(const char *name)
{
	unsigned char raw[WS73_PROFILE_SIZE + 1];
	struct ws73_fw_profile profile;
	unsigned int i, j;
	FILE *file = fopen(name, "rb");
	size_t size;

	if (!file)
		return 1;
	size = fread(raw, 1, sizeof(raw), file);
	if (ferror(file) || fclose(file) ||
	    ws73_fw_profile_decode(raw, size, &profile))
		return 1;
	printf("%u", profile.model);
	for (i = 0; i < WS73_PROFILE_FILES; i++) {
		putchar(' ');
		for (j = 0; j < WS73_PROFILE_DIGEST_SIZE; j++)
			printf("%02x", profile.digest[i][j]);
	}
	putchar('\n');
	return 0;
}

int main(int argc, char **argv)
{
	unsigned char raw[WS73_PROFILE_SIZE] = "WS73P001";
	unsigned char bad[sizeof(raw)], digest[WS73_PROFILE_DIGEST_SIZE];
	struct ws73_fw_profile profile, other;
	char out[WS73_PROFILE_DIRECTORY_SIZE], before[sizeof(out)];
	char controller[65], route[17];
	const char *invalid[] = { "", "0", "01", "1.0", "1..2", "1.",
		"256", "1/2", "../1", "1-2", "1000" };
	unsigned int i;
	size_t length;

	if (argc == 2)
		return decode_file(argv[1]);
	if (argc != 1)
		return 1;
	for (i = 0; i < WS73_PROFILE_FILES; i++)
		raw[12 + i * WS73_PROFILE_DIGEST_SIZE] = i + 1;
	for (i = 0; i < sizeof(raw); i++)
		unchanged(raw, i);
	unchanged(NULL, sizeof(raw));
	CHECK(ws73_fw_profile_decode(raw, sizeof(raw), NULL) == -EINVAL);
	CHECK(!ws73_fw_profile_decode(raw, sizeof(raw), &profile));
	CHECK(!profile.model);
	raw[8] = 2;
	CHECK(!ws73_fw_profile_decode(raw, sizeof(raw), &profile));
	CHECK(profile.model == 2);
	for (i = 0; i < 12; i++) {
		memcpy(bad, raw, sizeof(raw));
		bad[i] ^= 1;
		unchanged(bad, sizeof(bad));
	}
	for (i = 0; i < WS73_PROFILE_FILES; i++) {
		memcpy(bad, raw, sizeof(raw));
		memset(bad + 12 + i * WS73_PROFILE_DIGEST_SIZE, 0, WS73_PROFILE_DIGEST_SIZE);
		unchanged(bad, sizeof(bad));
		memcpy(digest, profile.digest[i], sizeof(digest));
		CHECK(!ws73_fw_profile_digest(&profile, i, digest));
		digest[31] ^= 1;
		CHECK(ws73_fw_profile_digest(&profile, i, digest) == -EBADMSG);
	}
	CHECK(ws73_fw_profile_digest(&profile, WS73_PROFILE_FILES, digest) == -EINVAL);
	CHECK(ws73_fw_profile_digest(NULL, 0, digest) == -EINVAL);
	CHECK(ws73_fw_profile_digest(&profile, 0, NULL) == -EINVAL);
	CHECK(!ws73_fw_profile_model(&profile, 2, 0));
	CHECK(ws73_fw_profile_model(&profile, 0, 0) == -EPROTO);
	CHECK(ws73_fw_profile_model(&profile, 2, 2) == -EPROTO);
	other = profile;
	CHECK(!ws73_fw_profile_same(&profile, &other));
	other.digest[4][31] ^= 1;
	CHECK(ws73_fw_profile_same(&profile, &other) == -ESTALE);
	other = profile;
	other.model = 0;
	CHECK(ws73_fw_profile_same(&profile, &other) == -ESTALE);
	other.model = 1;
	CHECK(ws73_fw_profile_same(&profile, &other) == -EINVAL);
	CHECK(ws73_fw_profile_same(NULL, &profile) == -EINVAL);
	/* Retain the symbolic nested-index counterexample as a concrete native
	 * regression:copying/mutating a peer must not alter the source closure.
	 */
	memset(raw, 0xa5, sizeof(raw));
	memcpy(raw, "WS73P001", 8);
	memset(raw + 8, 0, 4);
	raw[30] = 0xe5;
	CHECK(!ws73_fw_profile_decode(raw, sizeof(raw), &profile));
	other = profile;
	other.digest[4][31] ^= 1;
	CHECK(ws73_fw_profile_same(&profile, &other) == -ESTALE);
	for (i = 0; i < WS73_PROFILE_FILES; i++) {
		memcpy(digest, profile.digest[i], sizeof(digest));
		CHECK(!ws73_fw_profile_digest(&profile, i, digest));
	}
	CHECK(!ws73_fw_profile_directory(out, sizeof(out), "0000:c5:00.3", "2.1.1"));
	CHECK(!strcmp(out, "sparklink/ws73/by-path/0000:c5:00.3-usb2-2.1.1"));
	length = strlen(out);
	CHECK(!ws73_fw_profile_directory(out, length + 1, "0000:c5:00.3", "2.1.1"));
	memset(out, 0xa5, sizeof(out));
	memcpy(before, out, sizeof(out));
	CHECK(ws73_fw_profile_directory(out, length, "0000:c5:00.3", "2.1.1") == -ENAMETOOLONG);
	CHECK(!memcmp(out, before, sizeof(out)));
	for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		CHECK(ws73_fw_profile_directory(out, sizeof(out), "pci", invalid[i]) < 0);
		CHECK(!memcmp(out, before, sizeof(out)));
	}
	CHECK(ws73_fw_profile_directory(out, sizeof(out), "../pci", "1") == -EINVAL);
	CHECK(!memcmp(out, before, sizeof(out)));
	memset(controller, 'x', sizeof(controller));
	controller[64] = 0;
	CHECK(ws73_fw_profile_directory(out, sizeof(out), controller, "1") == -ENAMETOOLONG);
	controller[63] = 0;
	CHECK(!ws73_fw_profile_directory(out, sizeof(out), controller, "255.255.255.255"));
	memset(route, '1', sizeof(route));
	route[16] = 0;
	CHECK(ws73_fw_profile_directory(out, sizeof(out), "pci", route) < 0);
	printf("WS73 actual profile codec: %u checks passed\n", checks);
	return 0;
}
