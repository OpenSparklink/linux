/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SPARKLINK_PAIR_MATERIAL_H
#define _SPARKLINK_PAIR_MATERIAL_H
#include <linux/types.h>
struct sl_pair_material;
int sl_pair_material_create(u8 role, const u8 *local, const u8 *remote,
			    struct sl_pair_material **out);
void sl_pair_material_destroy(struct sl_pair_material *material);
int sl_pair_material_public(struct sl_pair_material *material, u8 *out);
int sl_pair_material_peer(struct sl_pair_material *material, const u8 *peer);
int sl_pair_material_confirm(struct sl_pair_material *material, u8 *out);
int sl_pair_material_nonce(struct sl_pair_material *material, u8 *out);
int sl_pair_material_derive(struct sl_pair_material *material, const u8 *nonce,
			    const u8 *confirm, u8 *out);
int sl_pair_material_verify(struct sl_pair_material *material, const u8 *proof,
			    u8 *out);
#endif
