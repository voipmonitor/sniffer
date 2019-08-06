/*
** This file is a part of DSSL library.
**
** Copyright (C) 2005-2009, Atomic Labs, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/
#include <string.h>
#include "stdinc.h"
#include "ssl_utils.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>

/**/
int ssl3_PRF( const u_char* secret, uint32_t secret_len, 
		const u_char* random1, uint32_t random1_len,
		const u_char* random2, uint32_t random2_len,
		u_char* out, uint32_t out_len )
{
	MD5_CTX md5;
	SHA_CTX sha;
	u_char buf[20];
	uint32_t off;
	u_char i;

	if( !out ) return NM_ERROR( DSSL_E_INVALID_PARAMETER );

	for( off=0, i = 1; off < out_len; off+=16, ++i )
	{
		u_char md5_buf[16];
		uint32_t cnt;
		uint32_t j;

		MD5_Init(&md5);
		SHA1_Init(&sha);

		/* salt: A, BB, CCC,  ... */
		for( j=0; j < i; j++ ) buf[j]='A' + (i-1);

		SHA1_Update( &sha, buf, i );
		if( secret ) SHA1_Update( &sha, secret, secret_len );
		SHA1_Update( &sha, random1, random1_len );
		SHA1_Update( &sha, random2, random2_len );
		SHA1_Final( buf, &sha );

		MD5_Update( &md5, secret, secret_len );
		MD5_Update( &md5, buf, 20 );
		MD5_Final( md5_buf, &md5 );

		cnt = out_len - off < 16 ? out_len - off : 16;
		memcpy( out + off, md5_buf, cnt );
	}

	return DSSL_RC_OK;
}


static void tls1_P_hash( const EVP_MD *md, const unsigned char *sec,
						int sec_len, unsigned char *seed, int seed_len,
						unsigned char *out, int olen)
{
	int chunk;
	unsigned int j;
	HMAC_CTX *ctx;
	HMAC_CTX *ctx_tmp;
	unsigned char A1[EVP_MAX_MD_SIZE*2];
	unsigned int A1_len;

	chunk=EVP_MD_size(md);

	ctx = HMAC_CTX_new();
	ctx_tmp = HMAC_CTX_new();
	HMAC_Init_ex(ctx,sec,sec_len,md, NULL);
	HMAC_Init_ex(ctx_tmp,sec,sec_len,md, NULL);
	HMAC_Update(ctx,seed,seed_len);
	HMAC_Final(ctx,A1,&A1_len);

	for (;;)
	{
		HMAC_Init_ex(ctx,NULL,0,NULL,NULL); /* re-init */
		HMAC_Init_ex(ctx_tmp,NULL,0,NULL,NULL); /* re-init */
		HMAC_Update(ctx,A1,A1_len);
		HMAC_Update(ctx_tmp,A1,A1_len);
		HMAC_Update(ctx,seed,seed_len);

		if (olen > chunk)
		{
			HMAC_Final(ctx,out,&j);
			out+=j;
			olen-=j;
			HMAC_Final(ctx_tmp,A1,&A1_len); /* calc the next A1 value */
		}
		else	/* last one */
		{
			HMAC_Final(ctx,A1,&A1_len);
			memcpy(out,A1,olen);
			break;
		}
	}
	HMAC_CTX_free(ctx);
	HMAC_CTX_free(ctx_tmp);
	OPENSSL_cleanse(A1,sizeof(A1));
}

int tls12_PRF( const EVP_MD *md, const u_char* secret, uint32_t secret_len, const char* label, 
		u_char* random1, uint32_t random1_len, u_char* random2, uint32_t random2_len,
		u_char *out, uint32_t out_len )
{
	uint32_t i;
	u_char* out_tmp;
	u_char* seed;
	uint32_t seed_len;
	u_char* p;

	if( !label || !out || out_len == 0 ) { _ASSERT( FALSE); return NM_ERROR( DSSL_E_INVALID_PARAMETER ); }
	
	/* 'sha256' is the default for TLS 1.2.
	 * also, do not allow anything less secure...
	 */
	if ( !md )
		md = EVP_sha256();
	else if ( EVP_MD_size( md ) < EVP_MD_size( EVP_sha256() ) )
		md = EVP_sha256();

	/* allocate a temporary buffer for second output stream */
	out_tmp = (u_char*) malloc( out_len );
	if( !out_tmp ) return NM_ERROR( DSSL_E_OUT_OF_MEMORY );

	/* allocate and initialize the seed */
	seed_len = (uint32_t)strlen( label ) + random1_len + random2_len;
	seed = (u_char*) malloc( seed_len );
	if( !seed ) 
	{
		free( out_tmp );
		return NM_ERROR( DSSL_E_OUT_OF_MEMORY );
	}

	p = seed;
	memcpy( p, label, strlen( label ) ); p+= strlen( label );
	memcpy( p, random1, random1_len ); p+= random1_len;
	memcpy( p, random2, random2_len );

	DEBUG_TRACE_BUF("secret", secret, secret_len);
	DEBUG_TRACE_BUF("seed", seed, seed_len);
	tls1_P_hash( md, secret, secret_len, seed, seed_len, out_tmp, out_len );
	DEBUG_TRACE_BUF("result", out_tmp, out_len);
	
	DEBUG_TRACE3( "\nsecret(%d) + seed(%u)=out(%u)\n", secret_len, seed_len, out_len);

	for( i=0; i < out_len; i++ ) out[i] = out_tmp[i];

	free( seed );
	free( out_tmp );

	return DSSL_RC_OK;
}

int tls1_PRF( const u_char* secret, uint32_t secret_len, const char* label, 
		u_char* random1, uint32_t random1_len, u_char* random2, uint32_t random2_len,
		u_char *out, uint32_t out_len )
{
	uint32_t len;
	uint32_t i;
	const u_char *S1,*S2;
	u_char* out_tmp;
	u_char* seed;
	uint32_t seed_len;
	u_char* p;

	if( !label || !out || out_len == 0 ) { _ASSERT( FALSE); return NM_ERROR( DSSL_E_INVALID_PARAMETER ); }

	/* allocate a temporary buffer for second output stream */
	out_tmp = (u_char*) malloc( out_len );
	if( !out_tmp ) return NM_ERROR( DSSL_E_OUT_OF_MEMORY );

	/* allocate and initialize the seed */
	seed_len = (uint32_t)strlen( label ) + random1_len + random2_len;
	seed = (u_char*) malloc( seed_len );
	if( !seed ) 
	{
		free( out_tmp );
		return NM_ERROR( DSSL_E_OUT_OF_MEMORY );
	}

	p = seed;
	memcpy( p, label, strlen( label ) ); p+= strlen( label );
	memcpy( p, random1, random1_len ); p+= random1_len;
	memcpy( p, random2, random2_len );

	/* split the secret into halves */
	len = (secret_len / 2) + (secret_len % 2);
	S1 = secret;
	S2 = secret + secret_len - len;

	DEBUG_TRACE_BUF("secret", secret, secret_len);
	DEBUG_TRACE_BUF("seed", seed, seed_len);
	tls1_P_hash( EVP_md5(), S1, len, seed, seed_len, out, out_len );
	tls1_P_hash( EVP_sha1(), S2, len, seed, seed_len, out_tmp, out_len );

	for( i=0; i < out_len; i++ ) out[i] ^= out_tmp[i];

	DEBUG_TRACE_BUF("result", out, out_len);

	free( seed );
	free( out_tmp );

	return DSSL_RC_OK;
}


#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
int ssl2_PRF( const u_char* secret, uint32_t secret_len,
		const u_char* challenge, uint32_t challenge_len, 
		const u_char* conn_id, uint32_t conn_id_len,
		u_char* out, uint32_t out_len )
{
	u_char c= '0';
	int repeat = 0;
	int i = 0;
	const EVP_MD *md5 = NULL;
	EVP_MD_CTX *ctx;

	md5 = EVP_md5();

	if( !out ) return NM_ERROR( DSSL_E_INVALID_PARAMETER );
	if( out_len % EVP_MD_size(md5) != 0 ) { return NM_ERROR( DSSL_E_INVALID_PARAMETER ); }

	repeat = out_len / EVP_MD_size(md5);
	ctx = EVP_MD_CTX_create();
	EVP_MD_CTX_init( ctx );
	for( i = 0; i < repeat; i++ )
	{
		EVP_DigestInit_ex( ctx, md5, NULL );
		EVP_DigestUpdate( ctx, secret, secret_len );
		EVP_DigestUpdate( ctx, &c, 1);
		c++; /* '0', '1', etc. */
		EVP_DigestUpdate( ctx, challenge, challenge_len );
		EVP_DigestUpdate( ctx, conn_id, conn_id_len );
		EVP_DigestFinal_ex( ctx, out, NULL );
		out += EVP_MD_size( md5 );
	}

	EVP_MD_CTX_destroy( ctx );
	return DSSL_RC_OK;
}
#endif //(OPENSSL_VERSION_NUMBER < 0x10100000L)
