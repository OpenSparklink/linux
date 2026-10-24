// SPDX-License-Identifier: GPL-2.0
/* Shared P-256/AES-CMAC primitives. Default per-Session security and dedicated
 * regression modules compile this same source; no legacy SM3/SM4 facade.
 */
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/kpp.h>
#include <crypto/ecdh.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/random.h>
#define ECDH_P256_KEY_SIZE 32
#define ECDH_P256_PUB_SIZE 64
int sle_aes_cmac(const u8 *key, const u8 *data, u32 data_len, u8 *digest);
int sle_ecdh_generate(u8 *private_key, u8 *public_key);
int sle_ecdh_shared_secret(const u8 *private_key, const u8 *remote_public_key, u8 *secret);

/*
 * sle_ecdh_generate - Generate an ECDH-P256 key pair.
 * @private_key:   Output buffer for the 32-byte private key.
 * @public_key:    Output buffer for the 64-byte public key (X || Y).
 *
 * Generates a random private key and the corresponding public key on
 * the NIST P-256 curve.
 *
 * Returns 0 on success, negative errno on failure.
 */
int sle_ecdh_generate(u8 *private_key, u8 *public_key)
{
    struct crypto_kpp *tfm;
    struct kpp_request *req = NULL;
    struct ecdh parameters;
    struct scatterlist destination;
    DECLARE_CRYPTO_WAIT(wait);
    u8 candidate_private[ECDH_P256_KEY_SIZE];
    u8 candidate_public[ECDH_P256_PUB_SIZE];
    u8 *encoded = NULL;
    unsigned int encoded_len, attempt;
    int result;

    if (!private_key || !public_key)
        return -EINVAL;
    tfm = crypto_alloc_kpp("ecdh-nist-p256", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);
    parameters.key = (char *)candidate_private;
    parameters.key_size = sizeof(candidate_private);
    encoded_len = crypto_ecdh_key_len(&parameters);
    encoded = kmalloc(encoded_len, GFP_KERNEL);
    if (!encoded) {
        result = -ENOMEM;
        goto out;
    }
    /* Do not wait for entropy under a future session's original deadline.
     * Readiness is monotonic; reject rather than use uninitialized randomness. */
    if (!rng_is_initialized()) {
        result = -EAGAIN;
        goto out;
    }
    for (attempt = 0; attempt < 8; attempt++) {
        get_random_bytes(candidate_private, sizeof(candidate_private));
        result = crypto_ecdh_encode_key(encoded, encoded_len, &parameters);
        if (result)
            goto out;
        result = crypto_kpp_set_secret(tfm, encoded, encoded_len);
        if (result != -EINVAL)
            break;
    }
    if (result)
        goto out;
    req = kpp_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        result = -ENOMEM;
        goto out;
    }
    sg_init_one(&destination, candidate_public, sizeof(candidate_public));
    kpp_request_set_input(req, NULL, 0);
    kpp_request_set_output(req, &destination, sizeof(candidate_public));
    kpp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                            crypto_req_done, &wait);
    result = crypto_wait_req(crypto_kpp_generate_public_key(req), &wait);
    if (!result) {
        memcpy(private_key, candidate_private, sizeof(candidate_private));
        memcpy(public_key, candidate_public, sizeof(candidate_public));
    }
out:
    if (req)
        kpp_request_free(req);
    kfree_sensitive(encoded);
    memzero_explicit(candidate_private, sizeof(candidate_private));
    memzero_explicit(candidate_public, sizeof(candidate_public));
    crypto_free_kpp(tfm);
    return result;
}

/*
 * sle_ecdh_shared_secret - Compute ECDH-P256 shared secret.
 * @private_key:        Local 32-byte private key.
 * @remote_public_key:  Remote 64-byte public key (X || Y).
 * @secret:             Output buffer for 32-byte shared secret.
 *
 * Computes the ECDH shared secret using the local private key and the
 * remote peer's public key on NIST P-256.
 *
 * Returns 0 on success, negative errno on failure.
 */
int sle_ecdh_shared_secret(const u8 *private_key,
			   const u8 *remote_public_key, u8 *secret)
{
	struct crypto_kpp *tfm;
	struct kpp_request *req;
	struct ecdh p = {0};
	struct scatterlist src, dst;
	DECLARE_CRYPTO_WAIT(wait);
	u8 *buf;
	u8 candidate[ECDH_P256_KEY_SIZE];
	unsigned int buf_len;
	int err;

	if (!private_key || !remote_public_key || !secret)
		return -EINVAL;
	tfm = crypto_alloc_kpp("ecdh-nist-p256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	/* Set the local private key */
	p.key = (char *)private_key;
	p.key_size = ECDH_P256_KEY_SIZE;
	buf_len = crypto_ecdh_key_len(&p);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		goto out_tfm;
	}

	err = crypto_ecdh_encode_key(buf, buf_len, &p);
	if (err)
		goto out_buf;

	err = crypto_kpp_set_secret(tfm, buf, buf_len);
	if (err)
		goto out_buf;

	req = kpp_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		err = -ENOMEM;
		goto out_buf;
	}

	sg_init_one(&src, remote_public_key, ECDH_P256_PUB_SIZE);
	sg_init_one(&dst, candidate, ECDH_P256_KEY_SIZE);
	kpp_request_set_input(req, &src, ECDH_P256_PUB_SIZE);
	kpp_request_set_output(req, &dst, ECDH_P256_KEY_SIZE);
	kpp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				 crypto_req_done, &wait);

	err = crypto_kpp_compute_shared_secret(req);
	err = crypto_wait_req(err, &wait);
	if (!err)
		memcpy(secret, candidate, sizeof(candidate));

	kpp_request_free(req);
out_buf:
	kfree_sensitive(buf);
out_tfm:
	memzero_explicit(candidate, sizeof(candidate));
	crypto_free_kpp(tfm);
	return err;
}

/* Process-context AES-CMAC mechanism for HA2. No protocol/trust state changes.
 * Bound matches the reviewed WS73 pairing PRF inputs; failures are atomic.
 */
int sle_aes_cmac(const u8 *key, const u8 *data, u32 data_len, u8 *digest)
{
    struct crypto_shash *tfm;
    struct shash_desc *description;
    u8 candidate[16], empty = 0;
    int result;

    if (!key || !digest || (data_len && !data))
        return -EINVAL;
    if (data_len > 160)
        return -EMSGSIZE;
    tfm = crypto_alloc_shash("cmac(aes)", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);
    description = kmalloc(sizeof(*description) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!description) {
        result = -ENOMEM;
        goto out;
    }
    description->tfm = tfm;
    result = crypto_shash_setkey(tfm, key, 16);
    if (!result)
        result = crypto_shash_digest(description, data_len ? data : &empty, data_len, candidate);
    if (!result)
        memcpy(digest, candidate, sizeof(candidate));
    kfree_sensitive(description);
out:
    memzero_explicit(candidate, sizeof(candidate));
    crypto_free_shash(tfm);
    return result;
}
