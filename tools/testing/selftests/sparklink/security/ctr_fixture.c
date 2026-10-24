/* SPDX-License-Identifier: GPL-2.0-only */
/* Mock crypto dependencies; production CTR body is inserted verbatim by runner. */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint32_t u32;
#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE 16
#define GFP_KERNEL 0
#define CRYPTO_TFM_REQ_MAY_BACKLOG 0
#define DECLARE_CRYPTO_WAIT(name) int name = 0
#define IS_ERR(p) ((intptr_t)(p) < 0)
#define PTR_ERR(p) ((int)(intptr_t)(p))
struct crypto_skcipher { int dummy; };
struct scatterlist { u8 *data; size_t size; };
struct skcipher_request { struct scatterlist *sg; u8 *iv; };
static struct crypto_skcipher tfm;
static int fault, tfm_live, req_live, scratch_live, requests;
static void *crypto_alloc_skcipher(const char *name, int a, int b) {
    assert(!strcmp(name, "ctr(sm4)")); (void)a; (void)b;
    if (fault == 1) return (void *)(intptr_t)-ENOENT;
    tfm_live++; return &tfm;
}
static int crypto_skcipher_setkey(void *p, const u8 *key, int size) {
    assert(p == &tfm && key && size == 16); return fault == 2 ? -EINVAL : 0;
}
static void crypto_free_skcipher(void *p) { assert(p == &tfm); tfm_live--; }
static struct skcipher_request *skcipher_request_alloc(void *p, int flags) {
    assert(p == &tfm); (void)flags; if (fault == 3) return NULL;
    req_live++; return calloc(1, sizeof(struct skcipher_request));
}
static void skcipher_request_free(void *p) { req_live--; free(p); }
static void *kmemdup(const void *p, size_t len, int flags) {
    (void)flags; if (fault == 4) return NULL;
    void *v = malloc(len); assert(v); memcpy(v, p, len); scratch_live++; return v;
}
static void kfree_sensitive(void *p) { scratch_live--; free(p); }
static void memzero_explicit(void *p, size_t n) { memset(p, 0, n); }
static void sg_init_one(struct scatterlist *sg, void *p, size_t n) { sg->data = p; sg->size = n; }
static void crypto_req_done(void) { }
static void skcipher_request_set_callback(void *p, int flags, void (*cb)(void), void *wait) {
    (void)p; (void)flags; (void)cb; (void)wait;
}
static void skcipher_request_set_crypt(struct skcipher_request *req, struct scatterlist *a,
                                     struct scatterlist *b, size_t size, u8 *iv) {
    assert(a == b && a->size == size); req->sg = a; req->iv = iv;
}
static int crypto_skcipher_encrypt(struct skcipher_request *req) {
    requests++; memset(req->sg->data, 0xa5, req->sg->size); memset(req->iv, 0xb6, 16);
    // Partial destination/IV mutation then error models an asynchronous failure.
    return fault == 5 ? -EIO : 0;
}
static int crypto_wait_req(int ret, void *wait) { (void)wait; return ret; }
@@PRODUCTION_CTR@@
int main(void) {
    u8 key[16] = {0}, iv[16], data[33];
    const int errors[] = {0, -ENOENT, -EINVAL, -ENOMEM, -ENOMEM, -EIO};
    for (fault = 0; fault <= 5; fault++) {
        memset(iv, 0x22, sizeof(iv)); memset(data, 0x33, sizeof(data)); requests = 0;
        assert(sle_sm4_ctr_crypt(key, iv, data, sizeof(data)) == errors[fault]);
        for (size_t i = 0; i < sizeof(data); i++) assert(data[i] == (fault ? 0x33 : 0xa5));
        for (size_t i = 0; i < sizeof(iv); i++) assert(iv[i] == (fault ? 0x22 : 0xb6));
        assert(tfm_live == 0 && req_live == 0 && scratch_live == 0);
        assert(requests == (fault == 0 || fault == 5));
    }
    assert(sle_sm4_ctr_crypt(key, iv, data, 0) == 0);
    assert(tfm_live == 0 && req_live == 0 && scratch_live == 0);
    return 0;
}
