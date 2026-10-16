// SPDX-License-Identifier: GPL-2.0-only
/* Dedicated VM module, never loaded on the host. Includes the actual retained
 * mechanism source, not a second crypto implementation or synthetic backend.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>
#include "../../../../../net/sparklink/sle_crypto_ffi.c"
#include "../../../../../net/sparklink/sle_pair_material.c"

static int pair_material_vectors(void)
{
	/* Toy data, independently evaluated with OpenSSL3.5.9 CMAC. This direct
	 * fixture state validates byte order/KDF/commit, not ECDH point validity
	 * or a standard pairing vector. Never present in the production object.
	 */
	static const u8 confirmation[16]={0xfd,0x93,0x4d,0xdf,0x1b,0x7a,0x4e,0x1a,0xe9,0x7e,0x1b,0xc5,0x72,0xbd,0x2c,0x2d};
	static const u8 link[16]={0x6b,0xd8,0x4d,0x76,0xc3,0xc2,0xad,0x8d,0x88,0x7f,0x15,0x42,0x98,0xfe,0x6b,0xdc};
	static const u8 gp[16]={0xa9,0x9f,0x50,0x22,0xc3,0x52,0x85,0x8e,0x06,0x8d,0x61,0x4c,0x23,0x7a,0x31,0x78};
	static const u8 tp[16]={0xe7,0x8f,0x1a,0x29,0xbe,0x12,0x90,0x05,0xee,0x74,0xd7,0x0b,0x6a,0x6f,0x97,0xde};
	struct sl_pair_material m={.role=0,.method=1,.peer_valid=true};
	u8 nonce[16], out[16], bad[16];unsigned int i;int result=-EILSEQ;
	for(i=0;i<32;i++)m.shared[i]=i;
	for(i=0;i<16;i++){m.nonce[i]=16+i;nonce[i]=32+i;}
	for(i=0;i<64;i++){m.public[i]=1+i;m.peer[i]=129+i;}
	for(i=0;i<6;i++){m.g_address[i]=1+i;m.t_address[i]=11+i;}
	memcpy(bad,confirmation,16);bad[0]^=1;memset(out,0xa5,16);
	if(sl_pair_material_derive(&m,nonce,bad,out)!=-EKEYREJECTED || m.derived || memchr_inv(out,0xa5,16))goto out;
	if(sl_pair_material_derive(&m,nonce,confirmation,out) || memcmp(out,gp,16) || memcmp(m.candidate_link_key,link,16) || memcmp(m.peer_proof,tp,16))goto out;
	memcpy(bad,tp,16);bad[0]^=1;memset(out,0xa5,16);
	if(sl_pair_material_install(&m,0,out)!=-EINVAL || memchr_inv(out,0xa5,16))goto out;
	if(sl_pair_material_verify(&m,bad,out)!=-EKEYREJECTED || m.verified || memchr_inv(out,0xa5,16))goto out;
	if(sl_pair_material_verify(&m,tp,out) || memcmp(out,gp,16) || !m.verified || memchr_inv(m.shared,0,32) || memchr_inv(m.nonce,0,16) || memchr_inv(m.own_proof,0,16))goto out;
	memset(out,0xa5,16);
	if(sl_pair_material_install(&m,1,out)!=-EINVAL || memchr_inv(out,0xa5,16))goto out;
	if(sl_pair_material_install(&m,0,out) || memcmp(out,link,16))goto out;
	result=0;
out:
	memzero_explicit(&m,sizeof(m));memzero_explicit(nonce,sizeof(nonce));memzero_explicit(out,sizeof(out));memzero_explicit(bad,sizeof(bad));return result;
}

static int numeric_public_vector(void)
{
    struct sl_pair_material m={.role=0,.method=0,.derived=true};
    u32 number=1000001;unsigned int i;int error;
    for(i=0;i<64;i++){m.public[i]=1+i;m.peer[i]=129+i;}
    for(i=0;i<16;i++){m.nonce[i]=16+i;m.peer_nonce[i]=32+i;}
    error=sl_pair_material_numeric(&m,&number);
    if(error || number!=759201)return -EILSEQ;
    m.method=1;number=1000001;
    if(sl_pair_material_numeric(&m,&number)!=-EINVAL || number!=1000001)return -EILSEQ;
    m.method=0;m.derived=false;
    if(sl_pair_material_numeric(&m,&number)!=-EINVAL || number!=1000001)return -EILSEQ;
    memzero_explicit(&m,sizeof(m));return 0;
}

static int pair_material_fresh(u8 method)
{
	static const u8 ga[6]={1,2,3,4,5,6},ta[6]={11,12,13,14,15,16};
	struct sl_pair_material *g=NULL,*t=NULL,*other=NULL;
	u8 gpub[64],tpub[64],again[64],invalid[64]={0},gn[16],tn[16],cfm[16],gp[16],tp[16],out[16];u32 gc=1000001,tc=1000001;int result;
	result=sl_pair_material_create(0,method,ga,ta,&g);if(result)goto out;
	result=sl_pair_material_create(1,method,ta,ga,&t);if(result)goto out;
	result=sl_pair_material_create(0,method,ga,ta,&other);if(result)goto out;
	result=-EILSEQ;
	if(sl_pair_material_public(g,gpub)||sl_pair_material_public(t,tpub)||sl_pair_material_public(other,again)||!memcmp(gpub,tpub,64)||!memcmp(gpub,again,64))goto out;
	if(sl_pair_material_peer(g,invalid)>=0 || g->peer_valid)goto out;
	if(sl_pair_material_peer(g,tpub)||sl_pair_material_peer(t,gpub)||sl_pair_material_peer(g,tpub)!=-EALREADY)goto out;
	if(sl_pair_material_nonce(g,gn)||sl_pair_material_nonce(t,tn)||!memcmp(gn,tn,16)||sl_pair_material_confirm(t,cfm))goto out;
	if(sl_pair_material_derive(g,tn,cfm,gp)||sl_pair_material_derive(t,gn,NULL,tp)||memcmp(g->candidate_link_key,t->candidate_link_key,16))goto out;
    if(!method && (sl_pair_material_numeric(g,&gc)||sl_pair_material_numeric(t,&tc)||gc!=tc||gc>=1000000))goto out;
    if(method && (sl_pair_material_numeric(g,&gc)!=-EINVAL||gc!=1000001))goto out;
	memset(out,0xa5,16);invalid[0]=gp[0]^1;memcpy(invalid+1,gp+1,15);
	if(sl_pair_material_verify(t,invalid,out)!=-EKEYREJECTED||memchr_inv(out,0xa5,16))goto out;
	if(sl_pair_material_verify(t,gp,out)||memcmp(out,tp,16)||sl_pair_material_verify(g,tp,out)||memcmp(out,gp,16))goto out;
	if(!g->verified||!t->verified||memchr_inv(g->private,0,32)||memchr_inv(t->private,0,32)||memchr_inv(g->nonce,0,16)||memchr_inv(t->nonce,0,16))goto out;
	result=0;
out:
	sl_pair_material_destroy(g);sl_pair_material_destroy(t);sl_pair_material_destroy(other);
	memzero_explicit(gn,sizeof(gn));memzero_explicit(tn,sizeof(tn));memzero_explicit(gp,sizeof(gp));memzero_explicit(tp,sizeof(tp));memzero_explicit(out,sizeof(out));return result;
}

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
    result=pair_material_vectors();if(result)goto out;
    for(iteration=0;iteration<8;iteration++){result=numeric_public_vector();if(result)goto out;
    result=pair_material_fresh(0);if(result)goto out;
    result=pair_material_fresh(1);if(result)goto out;}
    result=0;
out:
    memzero_explicit(digest,sizeof(digest));memzero_explicit(before,sizeof(before));
    memzero_explicit(a_private,sizeof(a_private));memzero_explicit(b_private,sizeof(b_private));
    memzero_explicit(a_secret,sizeof(a_secret));memzero_explicit(b_secret,sizeof(b_secret));
    memzero_explicit(a_public,sizeof(a_public));memzero_explicit(b_public,sizeof(b_public));
    if(result)pr_err("SPARKLINK_SECURITY_CRYPTO_VM_FAIL: errno=%d\n",result);
    else pr_info("SPARKLINK_SECURITY_CRYPTO_VM_PASS: RFC4493;8 random P256 agreements;OpenSSL toy dialect KDF/confirm/proof vectors;8 fresh material pairs and tamper/zeroization. No RF/pairing/auth/install/encryption qualification.\n");
    return result;
}
static void __exit security_crypto_probe_exit(void){}
module_init(security_crypto_probe_init);
module_exit(security_crypto_probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("VM-only SparkLink actual kernel crypto mechanism tests");
