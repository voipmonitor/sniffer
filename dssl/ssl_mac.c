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
#include "decoder_stack.h"
#include "ssl_session.h"
#include "ssl_utils.h"
#include "ciphersuites.h"


static void fmt_seq( uint64_t n, u_char* buf )
{
	buf[7] = (u_char)(n & 0xff);
	buf[6] = (u_char)(( n >> 8)& 0xff );
	buf[5] = (u_char)(( n >> 16)& 0xff );
	buf[4] = (u_char)(( n >> 24)& 0xff );
	buf[3] = (u_char)(( n >> 32)& 0xff );
	buf[2] = (u_char)(( n >> 40)& 0xff );
	buf[1] = (u_char)(( n >> 48)& 0xff );
	buf[0] = (u_char)(( n >> 56)& 0xff );
}

static u_char ssl3_pad_1[48]={
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 };

static u_char ssl3_pad_2[48]={
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c };


int ssl3_calculate_mac( dssl_decoder_stack* stack, u_char type, 
						 u_char* data, uint32_t len, u_char* mac )
{
	uint32_t mac_size = 0, pad_size = 0;
	const EVP_MD* md = stack->md;
	EVP_MD_CTX	*md_ctx;
	u_char hdr[3];
	u_char seq_buf[8];

	_ASSERT( stack->md != NULL );
	//_ASSERT_STATIC( sizeof(stack->seq_num) == 8 );

	mac_size = EVP_MD_size( md );
	pad_size = (48/mac_size)*mac_size;

	hdr[0] = type; 
	hdr[1] = (u_char)(len >> 8);
	hdr[2] = (u_char)(len &0xff);

	fmt_seq( stack->seq_num, seq_buf );
	++stack->seq_num;

	md_ctx = EVP_MD_CTX_create();
	EVP_MD_CTX_init( md_ctx );
	EVP_DigestInit_ex( md_ctx, md, NULL );

	EVP_DigestUpdate( md_ctx, stack->mac_key, mac_size );
	EVP_DigestUpdate( md_ctx, ssl3_pad_1, pad_size );
	EVP_DigestUpdate( md_ctx, seq_buf, 8 );
	EVP_DigestUpdate( md_ctx, hdr, sizeof(hdr) );
	EVP_DigestUpdate( md_ctx, data, len );
	EVP_DigestFinal_ex( md_ctx, mac, NULL );

	EVP_DigestInit_ex( md_ctx, md, NULL);
	EVP_DigestUpdate( md_ctx, stack->mac_key, mac_size );
	EVP_DigestUpdate( md_ctx, ssl3_pad_2, pad_size );
	EVP_DigestUpdate( md_ctx, mac, mac_size );
	EVP_DigestFinal_ex( md_ctx, mac, NULL );

	EVP_MD_CTX_destroy(md_ctx);

	return DSSL_RC_OK;
}


static int ssl3_calculate_handshake_hash( DSSL_Session* sess, NM_PacketDir dir, 
										 EVP_MD_CTX* ctx, u_char* out)
{
	EVP_MD_CTX *md_ctx;
	uint32_t md_size = 0, pad_size = 0;
	u_char* sender; uint32_t sender_len;
	static u_char sender_c[] = "\x43\x4c\x4e\x54";
	static u_char sender_s[] = "\x53\x52\x56\x52";
	const EVP_MD* md = EVP_MD_CTX_md( ctx );

	_ASSERT( dir == ePacketDirFromClient || dir == ePacketDirFromServer );

	md_size = EVP_MD_size( md );
	pad_size = (48/md_size)*md_size;

	sender = ( dir == ePacketDirFromClient ) ? sender_c : sender_s;
	sender_len = 4;

	md_ctx = EVP_MD_CTX_create();
	EVP_MD_CTX_init( md_ctx );
	EVP_MD_CTX_copy_ex( md_ctx, ctx );

	EVP_DigestUpdate( md_ctx, sender, sender_len );
	EVP_DigestUpdate( md_ctx, sess->master_secret, sizeof( sess->master_secret ) );
	EVP_DigestUpdate( md_ctx, ssl3_pad_1, pad_size );
	EVP_DigestFinal_ex( md_ctx, out, NULL );

	EVP_DigestInit_ex( md_ctx, md, NULL);
	EVP_DigestUpdate( md_ctx, sess->master_secret, sizeof( sess->master_secret ) );
	EVP_DigestUpdate( md_ctx, ssl3_pad_2, pad_size );
	EVP_DigestUpdate( md_ctx, out, md_size );

	EVP_DigestFinal_ex( md_ctx, out, &md_size );

	EVP_MD_CTX_destroy( md_ctx );

	return md_size;
}


int ssl3_decode_finished( DSSL_Session* sess, NM_PacketDir dir, u_char* data, uint32_t len )
{
	u_char hash[EVP_MAX_MD_SIZE*2];
	uint32_t md5_hash_len = 0, sha_hash_len=0;
	int rc = DSSL_RC_OK;

	md5_hash_len = ssl3_calculate_handshake_hash( sess, dir, 
			sess->handshake_digest_md5, hash );
	
	sha_hash_len = ssl3_calculate_handshake_hash( sess, dir, 
		sess->handshake_digest_sha, hash + md5_hash_len );
	
	if( len != sha_hash_len + md5_hash_len ) rc = NM_ERROR( DSSL_E_SSL_BAD_FINISHED_DIGEST );

	if( rc == DSSL_RC_OK && memcmp( hash, data, len ) != 0 )
	{
		rc = NM_ERROR( DSSL_E_SSL_BAD_FINISHED_DIGEST );
	}

	return rc;
}


int tls1_calculate_mac( dssl_decoder_stack* stack, u_char type, 
						 u_char* data, uint32_t len, u_char* mac )
{
	HMAC_CTX *hmac;
	uint32_t mac_size = 0;
	const EVP_MD* md = stack->md;
	u_char seq_buf[8];
	u_char hdr[5];

	_ASSERT( stack->md != NULL );
	//_ASSERT_STATIC( sizeof(stack->seq_num) == 8 );

	if( md == NULL ) return NM_ERROR( DSSL_E_INVALID_PARAMETER );

	mac_size = EVP_MD_size( md );
	hmac = HMAC_CTX_new();
	HMAC_Init_ex( hmac, stack->mac_key, mac_size, md , NULL );

	fmt_seq( stack->seq_num, seq_buf );
	++stack->seq_num;

	HMAC_Update( hmac, seq_buf, 8 );

	hdr[0] = type; 
	hdr[1] = (u_char)(stack->sess->version >> 8);
	hdr[2] = (u_char)(stack->sess->version & 0xff);
	hdr[3] = (u_char)((len & 0x0000ff00) >> 8);
	hdr[4] = (u_char)(len & 0xff);

	HMAC_Update( hmac, hdr, sizeof(hdr) );
	HMAC_Update( hmac, data, len );
	HMAC_Final( hmac, mac, &mac_size );
	HMAC_CTX_free( hmac );
	
	DEBUG_TRACE_BUF("mac", mac, mac_size);

	return DSSL_RC_OK;
}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
int ssl2_calculate_mac( dssl_decoder_stack* stack, u_char type, 
						 u_char* data, uint32_t len, u_char* mac )
{
	uint32_t seq = (uint32_t) stack->seq_num;

	++seq;
	stack->seq_num = seq;

	/* TODO */
	//type; data; len; mac;
	return NM_ERROR( DSSL_E_NOT_IMPL );
}
#endif //(OPENSSL_VERSION_NUMBER < 0x10100000L)


int tls1_decode_finished( DSSL_Session* sess, NM_PacketDir dir, u_char* data, uint32_t len )
{
	u_char buf[TLS_MD_MAX_CONST_SIZE + MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH];
	u_char* cur_ptr = NULL;
	u_char prf_out[12];
	EVP_MD_CTX *digest;
	uint32_t sz = 0;
	const char* label;
	int rc = DSSL_RC_OK;

	_ASSERT( sess->version >= TLS1_VERSION );
	if( len != 12 ) return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );

	label = (dir == ePacketDirFromClient) ? TLS_MD_CLIENT_FINISH_CONST : TLS_MD_SERVER_FINISH_CONST;
	
	digest = EVP_MD_CTX_create();
	EVP_MD_CTX_init( digest );

	if ( sess->version >= TLS1_2_VERSION )
	{
		EVP_MD_CTX_copy_ex(digest, sess->handshake_digest );

		cur_ptr = buf;
		EVP_DigestFinal_ex( digest, cur_ptr, &sz );
		cur_ptr += sz;
	}
	else
	{
		EVP_MD_CTX_copy_ex(digest, sess->handshake_digest_md5 );

		cur_ptr = buf;
		EVP_DigestFinal_ex( digest, cur_ptr, &sz );
		cur_ptr += sz;

		EVP_MD_CTX_copy_ex(digest, sess->handshake_digest_sha );
		EVP_DigestFinal_ex( digest, cur_ptr, &sz );
		cur_ptr += sz;
	}

	EVP_MD_CTX_destroy( digest );

	if ( sess->version == TLS1_2_VERSION )
		rc = tls12_PRF( EVP_get_digestbyname( sess->dssl_cipher_suite->digest ), sess->master_secret, sizeof( sess->master_secret ),
			label, 
			buf, (uint32_t)(cur_ptr - buf),
			NULL, 0, 
			prf_out, sizeof( prf_out) );
	else
		rc = tls1_PRF( sess->master_secret, sizeof( sess->master_secret ),
			label, 
			buf, (uint32_t)(cur_ptr - buf),
			NULL, 0, 
			prf_out, sizeof( prf_out) );

	if( rc != DSSL_RC_OK ) return rc;

	if( memcmp( data, prf_out, 12 ) != 0 && !sess->ignore_error_bad_finished_digest ) return NM_ERROR( DSSL_E_SSL_BAD_FINISHED_DIGEST );

	return DSSL_RC_OK;
}
