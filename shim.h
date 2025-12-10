/*
 * Copyright (C) 2014 Space Monkey, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <openssl/core_names.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/ec.h>


/* shim  methods */
extern int X_shim_init();

/* Library methods */
extern void X_OPENSSL_free(void *ref);
extern void *X_OPENSSL_malloc(size_t size);

/* SSL macros */
extern long X_SSL_set_tlsext_host_name(SSL *ssl, const char *name);
extern const char * X_SSL_get_cipher_name(const SSL *ssl);
extern int X_SSL_new_index();

/* SSL methods */
extern int sni_cb(SSL *ssl_conn, int *ad, void *arg);
extern int X_SSL_verify_cb(int ok, X509_STORE_CTX* store);

/* SSL_CTX macros */
extern int X_SSL_CTX_new_index();
extern int X_SSL_CTX_set_min_proto_version(SSL_CTX *ctx, long version);
extern int X_SSL_CTX_set_max_proto_version(SSL_CTX *ctx, long version);
extern long X_SSL_CTX_set_mode(SSL_CTX* ctx, long modes);
extern long X_SSL_CTX_get_mode(SSL_CTX* ctx);
extern long X_SSL_CTX_set_session_cache_mode(SSL_CTX* ctx, long modes);
extern long X_SSL_CTX_sess_set_cache_size(SSL_CTX* ctx, long t);
extern long X_SSL_CTX_sess_get_cache_size(SSL_CTX* ctx);
extern int X_SSL_CTX_set1_curves(SSL_CTX *ctx, int *clist, int clistlen);
extern long X_SSL_CTX_add_extra_chain_cert(SSL_CTX* ctx, X509 *cert);
extern long X_SSL_CTX_set_tlsext_servername_callback(SSL_CTX* ctx, int (*cb)(SSL *con, int *ad, void *args));
extern int X_SSL_CTX_set1_groups_list(SSL_CTX* ctx, char *s);

/* SSL_CTX methods */
extern int X_SSL_CTX_verify_cb(int ok, X509_STORE_CTX* store);

/* BIO methods */
extern BIO *X_BIO_new_write_bio();
extern BIO *X_BIO_new_read_bio();

/* EVP_MD_CTX methods */
extern EVP_MD_CTX *X_EVP_MD_CTX_new(void);
extern void X_EVP_MD_CTX_free(EVP_MD_CTX *ctx);
extern int X_EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
extern int X_EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
extern int X_EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);

/* EVP methods */
extern const EVP_MD *X_EVP_md_null();
extern const EVP_MD *X_EVP_md5();
extern const EVP_MD *X_EVP_sha();
extern const EVP_MD *X_EVP_sha1();
extern const EVP_MD *X_EVP_dss();
extern const EVP_MD *X_EVP_dss1();
extern const EVP_MD *X_EVP_ripemd160();
extern const EVP_MD *X_EVP_sha224();
extern const EVP_MD *X_EVP_sha256();
extern const EVP_MD *X_EVP_sha384();
extern const EVP_MD *X_EVP_sha512();
extern int X_EVP_MD_size(const EVP_MD *md);
extern int X_EVP_SignInit(EVP_MD_CTX *ctx, const EVP_MD *type);
extern int X_EVP_SignUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt);
extern int X_EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
extern int X_EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen, const unsigned char *tbs, size_t tbslen);
extern EVP_PKEY *X_EVP_PKEY_new(void);
extern void X_EVP_PKEY_free(EVP_PKEY *pkey);
extern int X_EVP_PKEY_size(EVP_PKEY *pkey);
extern struct rsa_st *X_EVP_PKEY_get1_RSA(EVP_PKEY *pkey);
extern int X_EVP_PKEY_set1_RSA(EVP_PKEY *pkey, struct rsa_st *key);
extern int X_EVP_PKEY_assign_charp(EVP_PKEY *pkey, int type, char *key);
extern int X_EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s, EVP_PKEY *pkey);
extern int X_EVP_VerifyInit(EVP_MD_CTX *ctx, const EVP_MD *type);
extern int X_EVP_VerifyUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt);
extern int X_EVP_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf, unsigned int siglen, EVP_PKEY *pkey);
extern int X_EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
extern int X_EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret, size_t siglen, const unsigned char *tbs, size_t tbslen);
extern int X_EVP_CIPHER_block_size(EVP_CIPHER *c);
extern int X_EVP_CIPHER_key_length(EVP_CIPHER *c);
extern int X_EVP_CIPHER_iv_length(EVP_CIPHER *c);
extern int X_EVP_CIPHER_nid(EVP_CIPHER *c);
extern int X_EVP_CIPHER_CTX_block_size(EVP_CIPHER_CTX *ctx);
extern int X_EVP_CIPHER_CTX_key_length(EVP_CIPHER_CTX *ctx);
extern int X_EVP_CIPHER_CTX_iv_length(EVP_CIPHER_CTX *ctx);
extern void X_EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int padding);
extern const EVP_CIPHER *X_EVP_CIPHER_CTX_cipher(EVP_CIPHER_CTX *ctx);
extern int X_EVP_CIPHER_CTX_encrypting(const EVP_CIPHER_CTX *ctx);
extern int X_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid);

/* HMAC methods */
extern size_t X_HMAC_size(const HMAC_CTX *e);
extern HMAC_CTX *X_HMAC_CTX_new(void);
extern void X_HMAC_CTX_free(HMAC_CTX *ctx);
extern int X_HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl);
extern int X_HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len);
extern int X_HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);

  /* X509 methods */
extern int X_X509_add_ref(X509* x509);
extern const ASN1_TIME *X_X509_get0_notBefore(const X509 *x);
extern const ASN1_TIME *X_X509_get0_notAfter(const X509 *x);
extern int X_sk_X509_num(STACK_OF(X509) *sk);
extern X509 *X_sk_X509_value(STACK_OF(X509)* sk, int i);
extern long X_X509_get_version(const X509 *x);
extern int X_X509_set_version(X509 *x, long version);

/* Object methods */
extern int OBJ_create(const char *oid,const char *sn,const char *ln);

/* Extension helper method */
extern const unsigned char * get_extension(X509 *x, int NID, int *data_len);
extern int add_custom_ext(X509 *cert, int nid, char *value, int len);

/* BigNum macros */
extern int X_BN_num_bytes(const BIGNUM *a);

/* PEM methods */
extern int X_PEM_write_bio_PrivateKey_traditional(BIO *bio, EVP_PKEY *key, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);

extern int X_PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen, const unsigned char *salt, int saltlen, int iter, int keylen, unsigned char *out);
extern int X_PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt, int saltlen, int iter, const EVP_MD *digest, int keylen, unsigned char *out);
