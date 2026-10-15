// SPDX-License-Identifier: GPL-2.0-only
/* Per-Session, nonexported candidate material. Only the relay Session decides
 * protocol order, policy and lifetime. No trusted state or key install here.
 * All crypto may sleep: caller must be outside IRQ/Host/gate locks, then
 * revalidate the original job identity/deadline before admitting its output.
 */
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/string.h>
#include <crypto/algapi.h>
#include "sle_pair_material.h"

int sle_ecdh_generate(u8 *private_key, u8 *public_key);
int sle_ecdh_shared_secret(const u8 *private_key, const u8 *remote_public_key,
			  u8 *secret);
int sle_aes_cmac(const u8 *key, const u8 *data, u32 length, u8 *out);

struct sl_pair_material {
	u8 private[32], public[64], peer[64], shared[32], nonce[16];
	u8 g_address[6], t_address[6], own_proof[16], peer_proof[16];
	u8 candidate_link_key[16];
	u8 role;
	bool peer_valid, derived, verified;
};

/* SDK111 scalar/point/PRF byte order is an explicit dialect boundary. Public
 * coordinates are individually LE32; the KPP interface uses BE coordinates.
 * The PRF reverses key, entire message and result, not each message field.
 */
static void point_order(u8 point[64])
{
	unsigned int coordinate, byte;

	for (coordinate = 0; coordinate < 64; coordinate += 32)
		for (byte = 0; byte < 16; byte++)
			swap(point[coordinate + byte], point[coordinate + 31 - byte]);
}

static int dialect_mac(const u8 key[16], const u8 *message, u32 length, u8 *out)
{
	u8 encoded_key[16], encoded_message[128], digest[16];
	unsigned int i;
	int error;

	if (length > sizeof(encoded_message))
		return -EMSGSIZE;
	for (i = 0; i < 16; i++)
		encoded_key[i] = key[15 - i];
	for (i = 0; i < length; i++)
		encoded_message[i] = message[length - 1 - i];
	error = sle_aes_cmac(encoded_key, encoded_message, length, digest);
	if (!error)
		for (i = 0; i < 16; i++)
			out[i] = digest[15 - i];
	memzero_explicit(encoded_key, sizeof(encoded_key));
	memzero_explicit(encoded_message, sizeof(encoded_message));
	memzero_explicit(digest, sizeof(digest));
	return error;
}

int sl_pair_material_create(u8 role, const u8 *local, const u8 *remote,
			    struct sl_pair_material **out)
{
	struct sl_pair_material *m;
	int error;

	if (role > 1 || !local || !remote || !out)
		return -EINVAL;
	if (!rng_is_initialized())
		return -EAGAIN;
	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return -ENOMEM;
	m->role = role;
	memcpy(m->g_address, role ? remote : local, 6);
	memcpy(m->t_address, role ? local : remote, 6);
	error = sle_ecdh_generate(m->private, m->public);
	if (error) {
		kfree_sensitive(m);
		return error;
	}
	point_order(m->public);
	get_random_bytes(m->nonce, sizeof(m->nonce));
	*out = m;
	return 0;
}

void sl_pair_material_destroy(struct sl_pair_material *m)
{
	kfree_sensitive(m);
}

int sl_pair_material_public(struct sl_pair_material *m, u8 *out)
{
	if (!m || !out || m->verified)
		return -EINVAL;
	memcpy(out, m->public, 64);
	return 0;
}

int sl_pair_material_peer(struct sl_pair_material *m, const u8 *peer)
{
	u8 point[64], shared[32];
	int error;

	if (!m || !peer || m->verified)
		return -EINVAL;
	if (m->peer_valid)
		return -EALREADY;
	memcpy(point, peer, sizeof(point));
	point_order(point);
	error = sle_ecdh_shared_secret(m->private, point, shared);
	if (!error) {
		memcpy(m->peer, peer, 64);
		memcpy(m->shared, shared, 32);
		m->peer_valid = true;
	}
	memzero_explicit(point, sizeof(point));
	memzero_explicit(shared, sizeof(shared));
	return error;
}

static int confirm_for(struct sl_pair_material *m, const u8 nonce[16], u8 *out)
{
	u8 message[128];
	int error;

	memcpy(message, m->role ? m->peer : m->public, 64);
	memcpy(message + 64, m->role ? m->public : m->peer, 64);
	error = dialect_mac(nonce, message, sizeof(message), out);
	memzero_explicit(message, sizeof(message));
	return error;
}

int sl_pair_material_confirm(struct sl_pair_material *m, u8 *out)
{
	if (!m || !out || m->role != 1 || !m->peer_valid || m->verified)
		return -EINVAL;
	return confirm_for(m, m->nonce, out);
}

int sl_pair_material_nonce(struct sl_pair_material *m, u8 *out)
{
	if (!m || !out || !m->peer_valid || m->verified)
		return -EINVAL;
	memcpy(out, m->nonce, 16);
	return 0;
}

/* Method1 is explicitly no-entry/no-MITM, no Bond: its protocol salt is zero.
 * This is not a zero random nonce or a fallback credential. All nonces/private
 * scalars are fresh. IO/OOB/algorithm inputs must match the sole known offer.
 */
static int proof_for(struct sl_pair_material *m, const u8 key[16],
		     const u8 nonce[16], u8 *out)
{
	u8 message[53] = {0};
	int error;

	memcpy(message, nonce, 16);
	message[32] = 3; message[33] = 3; message[34] = 1;
	memset(message + 35, 2, 4);
	memcpy(message + 41, m->g_address, 6);
	memcpy(message + 47, m->t_address, 6);
	error = dialect_mac(key, message, sizeof(message), out);
	memzero_explicit(message, sizeof(message));
	return error;
}

int sl_pair_material_derive(struct sl_pair_material *m, const u8 *nonce,
			    const u8 *confirm, u8 *out)
{
	u8 message[46], key[16], link[16], check_key[16];
	u8 own[16], peer[16], expected[16];
	unsigned int i;
	int error;

	if (!m || !nonce || !out || !m->peer_valid || m->derived || m->verified ||
	    (!m->role && !confirm) || (m->role && confirm))
		return -EINVAL;
	if (!m->role) {
		error = confirm_for(m, nonce, expected);
		if (error)
			goto out;
		if (crypto_memneq(expected, confirm, 16)) {
			error = -EKEYREJECTED;
			goto out;
		}
	}
	/* Low half of BE shared X becomes the first16 bytes of LE shared X. */
	for (i = 0; i < 16; i++)
		key[i] = m->shared[31 - i];
	message[0] = 'k'; message[1] = 'l';
	memcpy(message + 2, m->role ? nonce : m->nonce, 16);
	memcpy(message + 18, m->role ? m->nonce : nonce, 16);
	memcpy(message + 34, m->g_address, 6);
	memcpy(message + 40, m->t_address, 6);
	error = dialect_mac(key, message, sizeof(message), link);
	if (error)
		goto out;
	message[1] = 'd';
	error = dialect_mac(key, message, sizeof(message), check_key);
	if (error)
		goto out;
	error = proof_for(m, check_key, m->nonce, own);
	if (error)
		goto out;
	error = proof_for(m, check_key, nonce, peer);
	if (!error) {
		memcpy(m->candidate_link_key, link, 16);
		memcpy(m->own_proof, own, 16);
		memcpy(m->peer_proof, peer, 16);
		m->derived = true;
		memcpy(out, own, 16);
	}
out:
	memzero_explicit(message, sizeof(message));
	memzero_explicit(key, sizeof(key));
	memzero_explicit(link, sizeof(link));
	memzero_explicit(check_key, sizeof(check_key));
	memzero_explicit(own, sizeof(own));
	memzero_explicit(peer, sizeof(peer));
	memzero_explicit(expected, sizeof(expected));
	return error;
}

int sl_pair_material_verify(struct sl_pair_material *m, const u8 *proof, u8 *out)
{
	if (!m || !proof || !out || !m->derived || m->verified)
		return -EINVAL;
	if (crypto_memneq(m->peer_proof, proof, 16))
		return -EKEYREJECTED;
	memcpy(out, m->own_proof, 16);
	/* Keep only an uninstalled candidate key for the physical Session. No
	 * key export/install or trusted state exists in this bounded slice. */
	memzero_explicit(m->private, sizeof(m->private));
	memzero_explicit(m->shared, sizeof(m->shared));
	memzero_explicit(m->nonce, sizeof(m->nonce));
	memzero_explicit(m->own_proof, sizeof(m->own_proof));
	memzero_explicit(m->peer_proof, sizeof(m->peer_proof));
	m->verified = true;
	return 0;
}

/* Non-sleeping, kernel-private installation dependency. The physical Session
 * checks policy/ticket/lifetime first; no user-provided key or export ioctl.
 * Output is atomic on error and only the role-exact prepared16-byte slot. */
int sl_pair_material_install(struct sl_pair_material *m, u8 role, u8 *out)
{
    if (!m || !out || role > 1 || role != m->role || !m->verified)
        return -EINVAL;
    memcpy(out, m->candidate_link_key, 16);
    return 0;
}
