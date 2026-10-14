/* SPDX-License-Identifier: GPL-2.0-only */
/* Fault dependencies only; retained production bodies inserted verbatim. */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
#define ECDH_P256_KEY_SIZE 32
#define ECDH_P256_PUB_SIZE 64
#define GFP_KERNEL 0
#define CRYPTO_TFM_REQ_MAY_BACKLOG 0
#define DECLARE_CRYPTO_WAIT(v) int v=0
#define IS_ERR(p) ((uintptr_t)(p)>=(UINTPTR_MAX-4094))
#define PTR_ERR(p) ((int)(intptr_t)(p))
struct crypto_kpp { int unused; };
struct scatterlist { u8 *data; unsigned int length; };
struct ecdh { char *key; unsigned short key_size; };
struct kpp_request { struct scatterlist *destination; };
static struct crypto_kpp context;
static int fault, contexts, allocations, requests, random_calls, set_calls, allocator_failed;
static struct crypto_kpp *crypto_alloc_kpp(const char *name,int a,int b){assert(!strcmp(name,"ecdh-nist-p256"));(void)a;(void)b;if(fault==1)return(void *)(intptr_t)-ENOENT;contexts++;return &context;}
static void crypto_free_kpp(void *p){assert(p==&context);contexts--;}
static unsigned int crypto_ecdh_key_len(const struct ecdh *p){assert(p->key_size==32);return 36;}
static void *kmalloc(unsigned int n,int flags){(void)flags;if(fault==2)return NULL;void *p=malloc(n);if(!p){allocator_failed=1;return NULL;}allocations++;return p;}
static void kfree_sensitive(void *p){if(p){allocations--;free(p);}}
static void memzero_explicit(void *p,size_t n){memset(p,0,n);}
static int rng_is_initialized(void){return fault!=3;}
static void get_random_bytes(void *p,size_t n){random_calls++;memset(p,0x44,n);}
static int crypto_ecdh_encode_key(void *out,unsigned int len,const struct ecdh *p){assert(len==36 && p->key_size==32);memcpy(out,p->key,32);return fault==4?-EINVAL:0;}
static int crypto_kpp_set_secret(void *p,const void *key,unsigned int n){assert(p==&context && key && n==36);set_calls++;if(fault==5)return-EIO;if(fault==6)return-EINVAL;return 0;}
static struct kpp_request *kpp_request_alloc(void *p,int flags){assert(p==&context);(void)flags;if(fault==7)return NULL;struct kpp_request *r=calloc(1,sizeof(*r));if(!r){allocator_failed=1;return NULL;}requests++;return r;}
static void kpp_request_free(void *p){assert(p);requests--;free(p);}
static void sg_init_one(struct scatterlist *s,const void *p,unsigned int n){s->data=(u8 *)p;s->length=n;}
static void kpp_request_set_input(void *r,struct scatterlist *s,unsigned int n){assert(r);assert(!s?n==0:s->length==n);}
static void kpp_request_set_output(struct kpp_request *r,struct scatterlist *s,unsigned int n){assert(s->length==n);r->destination=s;}
static void crypto_req_done(void){}
static void kpp_request_set_callback(void *r,int flags,void (*callback)(void),void *wait){assert(r && wait);(void)flags;(void)callback;}
static int crypto_kpp_generate_public_key(struct kpp_request *r){assert(r->destination->length==64);memset(r->destination->data,0xdd,64);return fault==8?-EIO:0;}
static int crypto_kpp_compute_shared_secret(struct kpp_request *r){assert(r->destination->length==32);memset(r->destination->data,0xee,32);return fault==8?-EIO:0;}
static int crypto_wait_req(int result,void *wait){assert(wait);return result;}
@@PRODUCTION_GENERATE@@
@@PRODUCTION_SHARED@@
int main(void){
 u8 private_key[32],public_key[64],secret[32],saved_private[32],saved_public[64],saved_secret[32],input[32]={1},peer[64]={2};
 int mode;
 assert(IS_ERR((void *)(intptr_t)-1));
 assert(!IS_ERR((void *)(uintptr_t)0xffff800000001000ULL));
 for(mode=0;mode<=8;mode++){
  fault=mode;allocator_failed=0;random_calls=set_calls=0;memset(private_key,0xa5,32);memset(public_key,0xb6,64);memcpy(saved_private,private_key,32);memcpy(saved_public,public_key,64);
  int result=sle_ecdh_generate(private_key,public_key);
  assert(!contexts && !allocations && !requests);
  if(!mode && !allocator_failed){assert(!result && random_calls==1 && set_calls==1);for(int i=0;i<32;i++)assert(private_key[i]==0x44);for(int i=0;i<64;i++)assert(public_key[i]==0xdd);}
  else{assert(result<0 && !memcmp(private_key,saved_private,32) && !memcmp(public_key,saved_public,64));if(mode==6 && !allocator_failed)assert(random_calls==8 && set_calls==8);}
  fault=mode;allocator_failed=0;memset(secret,0xc7,32);memcpy(saved_secret,secret,32);result=sle_ecdh_shared_secret(input,peer,secret);
  assert(!contexts && !allocations && !requests);
  if((mode==0 || mode==3) && !allocator_failed){assert(!result);for(int i=0;i<32;i++)assert(secret[i]==0xee);}
  else assert(result<0 && !memcmp(secret,saved_secret,32));
 }
 assert(sle_ecdh_generate(NULL,public_key)==-EINVAL);assert(sle_ecdh_shared_secret(NULL,peer,secret)==-EINVAL);
 return 0;
}
