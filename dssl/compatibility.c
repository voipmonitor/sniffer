#include "stdinc.h"


#if (OPENSSL_VERSION_NUMBER < 0x10100000L)

HMAC_CTX *HMAC_CTX_new(void) {
	HMAC_CTX *ctx = (HMAC_CTX*)calloc(1, sizeof(HMAC_CTX));
	HMAC_CTX_init(ctx);
	return(ctx);
}

void HMAC_CTX_free(HMAC_CTX *ctx) {
	HMAC_CTX_cleanup(ctx);
	free(ctx);
}

void EVP_MD_CTX_reset(EVP_MD_CTX *ctx) {
	EVP_MD_CTX_init(ctx);
}

struct rsa_st *EVP_PKEY_get0_RSA(EVP_PKEY *pkey) {
	return(pkey->pkey.rsa);
}

#endif
