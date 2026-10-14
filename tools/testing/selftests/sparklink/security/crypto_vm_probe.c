// SPDX-License-Identifier: GPL-2.0-only
/* Dedicated VM module, never loaded on the host. Includes the actual retained
 * mechanism source, not a second crypto implementation or synthetic backend.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>
#include "../../../../../net/sparklink/sle_crypto_ffi.c"

static int __init security_crypto_probe_init(void)
{
    /* RFC4493 public AES-CMAC vectors. Fixtures are confined to this test. */
    static const u8 key[16]={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    static const u8 message[16]={0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
    static const u8 empty_mac[16]={0xbb,0x1d,0x69,0x29,0xe9,0x59,0x37,0x28,0x7f,0xa3,0x7d,0x12,0x9b,0x75,0x67,0x46};
    static const u8 block_mac[16]={0x07,0x0a,0x16,0xb4,0x6b,0x4d,0x41,0x44,0xf7,0x9b,0xdd,0x9d,0xd0,0x4a,0x28,0x7c};
    u8 digest[16], before[32], a_private[32], b_private[32], a_public[64], b_public[64], a_secret[32], b_secret[32], invalid[64]={0};
    int result, iteration;
    result=sle_aes_cmac(key,NULL,0,digest);
    if(result || memcmp(digest,empty_mac,16)){result=result?:-EILSEQ;goto out;}
    result=sle_aes_cmac(key,message,16,digest);
    if(result || memcmp(digest,block_mac,16)){result=result?:-EILSEQ;goto out;}
    memset(digest,0xa5,sizeof(digest));
    result=sle_aes_cmac(key,message,161,digest);
    if(result!=-EMSGSIZE || memchr_inv(digest,0xa5,sizeof(digest))){result=-EILSEQ;goto out;}
    result=sle_aes_cmac(NULL,message,16,digest);
    if(result!=-EINVAL || memchr_inv(digest,0xa5,sizeof(digest))){result=-EILSEQ;goto out;}
    for(iteration=0;iteration<8;iteration++){
        result=sle_ecdh_generate(a_private,a_public);if(result)goto out;
        result=sle_ecdh_generate(b_private,b_public);if(result)goto out;
        if(!memcmp(a_private,b_private,32)||!memcmp(a_public,b_public,64)){result=-EILSEQ;goto out;}
        result=sle_ecdh_shared_secret(a_private,b_public,a_secret);if(result)goto out;
        result=sle_ecdh_shared_secret(b_private,a_public,b_secret);if(result)goto out;
        if(memcmp(a_secret,b_secret,32)||!memchr_inv(a_secret,0,32)){result=-EILSEQ;goto out;}
        memset(a_secret,0xa5,sizeof(a_secret));memcpy(before,a_secret,sizeof(before));
        result=sle_ecdh_shared_secret(a_private,invalid,a_secret);
        if(result>=0 || memcmp(a_secret,before,32)){result=-EILSEQ;goto out;}
        memset(a_private,0,sizeof(a_private));
        result=sle_ecdh_shared_secret(a_private,b_public,a_secret);
        if(result>=0 || memcmp(a_secret,before,32)){result=-EILSEQ;goto out;}
    }
    result=0;
out:
    memzero_explicit(digest,sizeof(digest));memzero_explicit(before,sizeof(before));
    memzero_explicit(a_private,sizeof(a_private));memzero_explicit(b_private,sizeof(b_private));
    memzero_explicit(a_secret,sizeof(a_secret));memzero_explicit(b_secret,sizeof(b_secret));
    memzero_explicit(a_public,sizeof(a_public));memzero_explicit(b_public,sizeof(b_public));
    if(result)pr_err("SPARKLINK_SECURITY_CRYPTO_VM_FAIL: errno=%d\n",result);
    else pr_info("SPARKLINK_SECURITY_CRYPTO_VM_PASS: RFC4493 empty/block;8 random P256 pair agreements;invalid-peer/zero-key atomic refusal;bounded CMAC. No pairing/auth/encryption claim.\n");
    return result;
}
static void __exit security_crypto_probe_exit(void){}
module_init(security_crypto_probe_init);
module_exit(security_crypto_probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("VM-only SparkLink actual kernel crypto mechanism tests");
