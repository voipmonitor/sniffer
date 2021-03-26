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
#include "session.h"
#include "ssl_session.h"
#include "ssl_decode_hs.h"
#include "ssl_utils.h"
#include "ssl_mac.h"
#include "ciphersuites.h"
#include "ssl_sessionkey_table.h"
#include "tls_ticket_table.h"
#include "compression.h"
#include <openssl/evp.h>
#include <gcrypt.h>

#include "../config.h"

#include "tls-ext.h"

void DSSL_SessionInit( DSSL_Env* env, DSSL_Session* s, DSSL_ServerInfo* si )
{
	_ASSERT( s );

#ifdef NM_TRACE_SSL_SESSIONS
	DEBUG_TRACE0( "DSSL_SessionInit\n" );
#endif
	memset( s, 0, sizeof(*s) );

	s->ssl_si = si;
	s->env = env;

	dssl_decoder_stack_init( &s->c_dec );
	dssl_decoder_stack_init( &s->s_dec );

	s->handshake_digest_md5 = EVP_MD_CTX_create();
	EVP_MD_CTX_init( s->handshake_digest_md5 );
	s->handshake_digest_sha = EVP_MD_CTX_create();
	EVP_MD_CTX_init( s->handshake_digest_sha );
	s->handshake_digest = EVP_MD_CTX_create();
	EVP_MD_CTX_init( s->handshake_digest );
}


void DSSL_SessionDeInit( DSSL_Session* s )
{
#ifdef NM_TRACE_SSL_SESSIONS
	DEBUG_TRACE0( "DSSL_SessionDeInit\n" );
#endif

	if( s->env ) DSSL_EnvOnSessionClosing( s->env, s );

	dssl_decoder_stack_deinit( &s->c_dec );
	dssl_decoder_stack_deinit( &s->s_dec );

	ssls_free_extension_data(s);

	EVP_MD_CTX_destroy( s->handshake_digest_md5 );
	EVP_MD_CTX_destroy( s->handshake_digest_sha );
	EVP_MD_CTX_destroy( s->handshake_digest );
	
	ssls_handshake_data_free(s);
	ssls_handshake_queue_free(s);
	
	if(s->tls_session)
	{
		tls_destroy_session(s);
	}
}


void DSSL_SessionSetCallback( DSSL_Session* sess, DataCallbackProc data_callback, 
							ErrorCallbackProc error_callback, void* user_data )
{
	_ASSERT( sess );
	
	sess->data_callback = data_callback;
	sess->error_callback = error_callback;
	sess->user_data = user_data;
}


void DSSL_SessionSetEventCallback(DSSL_Session* sess, EventCallbackProc event_callback)
{
	_ASSERT( sess );
	sess->event_callback = event_callback;
}


int DSSL_SessionProcessData( DSSL_Session* sess, NM_PacketDir dir, u_char* data, uint32_t len )
{
	int rc = DSSL_RC_OK;
	dssl_decoder_stack* dec = NULL;

	if( dir == ePacketDirInvalid ) return NM_ERROR( DSSL_E_INVALID_PARAMETER );

	dec = (dir == ePacketDirFromClient) ? &sess->c_dec : &sess->s_dec;

	if( !sslc_is_decoder_stack_set( dec ) )
	{
		uint16_t ver = 0;

		if( dir == ePacketDirFromClient )
		{
			rc = ssl_detect_client_hello_version( data, len, &ver );
		}
		else
		{
			rc = ssl_detect_server_hello_version( data, len, &ver );
			/* update the client decoder after the server have declared the actual version 
			of the session */
			if( rc == DSSL_RC_OK && sess->version != ver )
			{
				rc = dssl_decoder_stack_set( &sess->c_dec, sess, ver );
			}
			ssls_set_session_version( sess, ver );
		}

		if( rc == DSSL_RC_OK ) 
		{
			rc = dssl_decoder_stack_set( dec, sess, ver );
		}
	}

	if( rc == DSSL_RC_OK ) rc = dssl_decoder_stack_process( dec, dir, data, len );

	/* check if a session with a first-time automapped key failed */
	if( NM_IS_FAILED( rc ) && sess->flags & SSF_TEST_SSL_KEY )
	{
		if(sess->event_callback)
		{
			(*sess->event_callback)( sess->user_data, eSslMappedKeyFailed, sess->ssl_si );
		}
		DSSL_MoveServerToMissingKeyList( sess->env, sess->ssl_si );
		sess->ssl_si = NULL;
	}

	if( NM_IS_FAILED( rc ) && sess->error_callback && rc != DSSL_E_SSL_SERVER_KEY_UNKNOWN )
	{
		sess->error_callback( sess->user_data, rc );
	}

	return rc;
}


EVP_PKEY* ssls_get_session_private_key( DSSL_Session* sess )
{
	if( sess->ssl_si == NULL ) return NULL;
	return sess->ssl_si->pkey;
}

/* convert SSL v2 CHALLENGE to SSL v3+ CLIENT_RANDOM */
static void ssls_convert_v2challenge(DSSL_Session* sess)
{
	u_char buff[SSL3_RANDOM_SIZE];

	_ASSERT(sess->flags & SSF_SSLV2_CHALLENGE);
	_ASSERT(sess->client_challenge_len != 0);

	memset(buff, 0, sizeof(buff));
	memcpy(buff, sess->client_random, sess->client_challenge_len);

	memset(sess->client_random, 0, SSL3_RANDOM_SIZE);
	memcpy(sess->client_random + SSL3_RANDOM_SIZE - sess->client_challenge_len, 
		buff, sess->client_challenge_len);

	sess->flags &= ~SSF_SSLV2_CHALLENGE;

}

int ssls_set_session_version( DSSL_Session* sess, uint16_t ver )
{
	int rc = DSSL_RC_OK;

	sess->version = ver;

	switch( ver )
	{
	case SSL3_VERSION:
		sess->decode_finished_proc = ssl3_decode_finished;
		sess->caclulate_mac_proc  = ssl3_calculate_mac;
		/* convert SSL v2 CHALLENGE to SSL v3+ CLIENT_RANDOM */
		if(sess->flags & SSF_SSLV2_CHALLENGE) 
			ssls_convert_v2challenge(sess);
		break;

	case TLS1_1_VERSION:
	case TLS1_2_VERSION:
	case TLS1_VERSION:
		sess->decode_finished_proc = tls1_decode_finished;
		sess->caclulate_mac_proc = tls1_calculate_mac;
		/* convert SSL v2 CHALLENGE to SSL v3+ CLIENT_RANDOM */
		if(sess->flags & SSF_SSLV2_CHALLENGE) 
			ssls_convert_v2challenge(sess);
		break;

	#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	case SSL2_VERSION:
		sess->decode_finished_proc = NULL;
		sess->caclulate_mac_proc = ssl2_calculate_mac;
		break;
	#endif //(OPENSSL_VERSION_NUMBER < 0x10100000L)

	default:
		rc = NM_ERROR( DSSL_E_SSL_UNKNOWN_VERSION );
		break;
	}

	return rc;
}


int ssls_decode_master_secret( DSSL_Session* sess )
{
	DSSL_CipherSuite* suite = NULL;
	#ifdef HAVE_LIBGNUTLS
	int rc;
	gcry_md_hd_t gcry_h;
	int gcry_algo;
	unsigned int gcry_len;
	void *gcry_data;
	#endif

	switch( sess->version )
	{
	case SSL3_VERSION:
		return ssl3_PRF( sess->PMS, SSL_MAX_MASTER_KEY_LENGTH, 
					sess->client_random, SSL3_RANDOM_SIZE, 
					sess->server_random, SSL3_RANDOM_SIZE,
					sess->master_secret, sizeof( sess->master_secret ) );

	case TLS1_1_VERSION:
	case TLS1_VERSION:
		return tls1_PRF( sess->PMS, SSL_MAX_MASTER_KEY_LENGTH, 
					TLS_MD_MASTER_SECRET_CONST, 
					sess->client_random, SSL3_RANDOM_SIZE, 
					sess->server_random, SSL3_RANDOM_SIZE,
					sess->master_secret, sizeof( sess->master_secret ) );
	case TLS1_2_VERSION:
		suite = sess->dssl_cipher_suite;
		if ( !suite )
			suite = DSSL_GetSSL3CipherSuite( sess->cipher_suite );
		if( !suite ) return NM_ERROR( DSSL_E_SSL_CANNOT_DECRYPT );
		
		#ifdef HAVE_LIBGNUTLS
		if((sess->flags & (SSF_TLS_SERVER_EXTENDED_MASTER_SECRET|SSF_TLS_CLIENT_EXTENDED_MASTER_SECRET)) == (SSF_TLS_SERVER_EXTENDED_MASTER_SECRET|SSF_TLS_CLIENT_EXTENDED_MASTER_SECRET) &&
		   sess->handshake_data) {
			gcry_md_open(&gcry_h, !strcmp(suite->digest, LN_sha384) ? GCRY_MD_SHA384 : GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
			gcry_md_write(gcry_h, sess->handshake_data, sess->handshake_data_size);
			gcry_algo = gcry_md_get_algo(gcry_h);
			gcry_len = gcry_md_get_algo_dlen(gcry_algo);
			gcry_data = malloc(gcry_len);
			memcpy(gcry_data, gcry_md_read(gcry_h,  gcry_algo), gcry_len);
			gcry_md_close(gcry_h);
			rc = tls12_PRF( EVP_get_digestbyname( suite->digest ), sess->PMS, SSL_MAX_MASTER_KEY_LENGTH, 
						"extended " TLS_MD_MASTER_SECRET_CONST,
						gcry_data, gcry_len, 
						NULL, 0,
						sess->master_secret, sizeof( sess->master_secret ) );
			free(gcry_data);
			return(rc);
		} else 
		#endif
		{
			return tls12_PRF( EVP_get_digestbyname( suite->digest ), sess->PMS, SSL_MAX_MASTER_KEY_LENGTH, 
						TLS_MD_MASTER_SECRET_CONST, 
						sess->client_random, SSL3_RANDOM_SIZE, 
						sess->server_random, SSL3_RANDOM_SIZE,
						sess->master_secret, sizeof( sess->master_secret ) );
		}

	default:
		return NM_ERROR( DSSL_E_NOT_IMPL );
	}
}

/*
static void ssl3_generate_export_iv( u_char* random1, u_char* random2, u_char* out )
{
    MD5_CTX md5;
    
    MD5_Init( &md5 );
	MD5_Update( &md5, random1, SSL3_RANDOM_SIZE );
	MD5_Update( &md5, random2, SSL3_RANDOM_SIZE );
    MD5_Final( out, &md5 );
}
*/

/* generate read/write keys for SSL v3+ session */
#define TLS_MAX_KEYBLOCK_LEN ((EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH + EVP_MAX_MD_SIZE*2)*2)
int ssls_generate_keys( DSSL_Session* sess )
{
	DSSL_CipherSuite* suite = NULL;
	const EVP_CIPHER* c = NULL;
	const EVP_MD* digest = NULL;
	u_char* c_mac = NULL;
	u_char* c_wk = NULL;
	u_char* c_iv = NULL;
	u_char* s_mac = NULL;
	u_char* s_wk = NULL;
	u_char* s_iv = NULL;
	u_char export_iv_block[EVP_MAX_IV_LENGTH*2];

	u_char c_iv_buf[EVP_MAX_IV_LENGTH];
	u_char s_iv_buf[EVP_MAX_IV_LENGTH];
	u_char export_c_wk[EVP_MAX_KEY_LENGTH];
	u_char export_s_wk[EVP_MAX_KEY_LENGTH];
	
	u_char keyblock[ TLS_MAX_KEYBLOCK_LEN ];
	uint32_t keyblock_len = 0;

	uint32_t iv_len = 0;
	uint32_t wk_len = 0;
	uint32_t digest_len = 0;

	EVP_CIPHER_CTX* c_cipher = NULL;
	EVP_CIPHER_CTX* s_cipher = NULL;

	int rc = DSSL_RC_OK;

	_ASSERT( sess->c_dec.compression_data_new == NULL );
	_ASSERT( sess->s_dec.compression_data_new == NULL );
	_ASSERT( sess->c_dec.compression_method_new == 0 );
	_ASSERT( sess->s_dec.compression_method_new == 0 );

	memset(c_iv_buf, 0, sizeof(c_iv_buf));
	memset(s_iv_buf, 0, sizeof(s_iv_buf));

	/* set new compression algorithm */
	if( sess->compression_method != 0 )
	{
		sess->s_dec.compression_method_new = sess->compression_method;
		sess->c_dec.compression_method_new = sess->compression_method;

		dssl_compr_init( sess->s_dec.compression_method_new, &sess->s_dec.compression_data_new );
		dssl_compr_init( sess->c_dec.compression_method_new, &sess->c_dec.compression_data_new );
	}

	if( sess->c_dec.cipher_new != NULL )
	{
/*		_ASSERT( FALSE ); */
		EVP_CIPHER_CTX_cleanup( sess->c_dec.cipher_new );
		EVP_CIPHER_CTX_free( sess->c_dec.cipher_new );
		sess->c_dec.cipher_new = NULL;
	}

	if( sess->s_dec.cipher_new != NULL )
	{
/*		_ASSERT( FALSE ); */
		EVP_CIPHER_CTX_cleanup( sess->s_dec.cipher_new );
		EVP_CIPHER_CTX_free( sess->s_dec.cipher_new );
		sess->s_dec.cipher_new = NULL;
	}

	suite = DSSL_GetSSL3CipherSuite( sess->cipher_suite );

	if( !suite ) return NM_ERROR( DSSL_E_SSL_CANNOT_DECRYPT );

	sess->dssl_cipher_suite = suite;
	c = EVP_get_cipherbyname( suite->enc );
	digest = EVP_get_digestbyname( suite->digest );

	/* calculate key length and IV length */
	if( c != NULL ) 
	{
		sess->cipher_mode = EVP_CIPHER_mode(c);
		if( DSSL_CipherSuiteExportable( suite ) )
		{ wk_len = suite->export_key_bits / 8; }
		else 
		{ wk_len = EVP_CIPHER_key_length( c ); }

		iv_len = EVP_CIPHER_iv_length( c );
		/* GCM ciphers' IV is constructed from 4-byte salt and 8-byte nonce_explicit */
		if ( EVP_CIPH_GCM_MODE == sess->cipher_mode )
			iv_len = EVP_GCM_TLS_FIXED_IV_LEN;
		
		DEBUG_TRACE3( "\ncipher '%s' has %sIV length %u\n", suite->enc, ((EVP_CIPH_GCM_MODE == sess->cipher_mode)?"fixed ":""), iv_len);
	}
	if( digest != NULL ) digest_len = EVP_MD_size( digest );

	/* calculate total keyblock length */
	keyblock_len = (wk_len + digest_len + iv_len)*2;
	DEBUG_TRACE4( "\nkey material = (%u+%u+%u)*2 = %u\n", wk_len, digest_len, iv_len, keyblock_len);
	if( !keyblock_len ) return DSSL_RC_OK;

	if( sess->version >= TLS1_2_VERSION)
	{
		rc = tls12_PRF( digest, sess->master_secret, sizeof( sess->master_secret ), 
					TLS_MD_KEY_EXPANSION_CONST, 
					sess->server_random, SSL3_RANDOM_SIZE,
					sess->client_random, SSL3_RANDOM_SIZE,
					keyblock, keyblock_len );
	}
	else if( sess->version >= TLS1_VERSION)
	{
		rc = tls1_PRF( sess->master_secret, sizeof( sess->master_secret ), 
					TLS_MD_KEY_EXPANSION_CONST, 
					sess->server_random, SSL3_RANDOM_SIZE,
					sess->client_random, SSL3_RANDOM_SIZE,
					keyblock, keyblock_len );
	}
	else
	{
		rc = ssl3_PRF( sess->master_secret, sizeof( sess->master_secret ),
					sess->server_random, SSL3_RANDOM_SIZE,
					sess->client_random, SSL3_RANDOM_SIZE,
					keyblock, keyblock_len );
	}

	/* init keying material pointers */
	if( rc == DSSL_RC_OK )
	{
		u_char* p = keyblock;

		/* AEAD ciphers don't use MAC */
		if( digest_len && !(EVP_CIPH_GCM_MODE == sess->cipher_mode || EVP_CIPH_CCM_MODE == sess->cipher_mode ) )
		{
			c_mac = p; p+= digest_len;
			s_mac = p; p+= digest_len;
		}

		if( c != NULL )
		{
			c_wk = p; p+= wk_len;
			s_wk = p; p+= wk_len;

			/* generate final server and client write keys for exportable ciphers */
			if( DSSL_CipherSuiteExportable( suite ) && ( sess->version < TLS1_2_VERSION) )
			{
				int final_wk_len =  EVP_CIPHER_key_length( c );
				if( sess->version >= TLS1_VERSION)
				{
					tls1_PRF( c_wk, wk_len, TLS_MD_CLIENT_WRITE_KEY_CONST, 
							sess->client_random, SSL3_RANDOM_SIZE,
							sess->server_random, SSL3_RANDOM_SIZE,
							export_c_wk, final_wk_len );
					
					tls1_PRF( s_wk, wk_len, TLS_MD_SERVER_WRITE_KEY_CONST, 
							sess->client_random, SSL3_RANDOM_SIZE,
							sess->server_random, SSL3_RANDOM_SIZE,
							export_s_wk, final_wk_len );
				}
				else
				{
					MD5_CTX md5;

					_ASSERT( sess->version == SSL3_VERSION );
					MD5_Init( &md5 );
					MD5_Update( &md5, c_wk, wk_len );
					MD5_Update( &md5, sess->client_random, SSL3_RANDOM_SIZE );
					MD5_Update( &md5, sess->server_random, SSL3_RANDOM_SIZE );
					MD5_Final( export_c_wk, &md5 );

					MD5_Init( &md5 );
					MD5_Update( &md5, s_wk, wk_len );
					MD5_Update( &md5, sess->server_random, SSL3_RANDOM_SIZE );
					MD5_Update( &md5, sess->client_random, SSL3_RANDOM_SIZE );
					MD5_Final( export_s_wk, &md5 );

				}
				c_wk = export_c_wk;
				s_wk = export_s_wk;
				wk_len = final_wk_len;
			}
		}
		
		if( iv_len )
		{
			if( DSSL_CipherSuiteExportable( suite ) && ( sess->version < TLS1_2_VERSION) )
			{
				if( sess->version >= TLS1_VERSION)
				{
					tls1_PRF( NULL, 0, TLS_MD_IV_BLOCK_CONST,
							sess->client_random, SSL3_RANDOM_SIZE, 
							sess->server_random, SSL3_RANDOM_SIZE,
							export_iv_block, iv_len*2 );
				}
				else
				{
					MD5_CTX md5;

					_ASSERT( sess->version == SSL3_VERSION );

					MD5_Init( &md5 );
					MD5_Update( &md5, sess->client_random, SSL3_RANDOM_SIZE );
					MD5_Update( &md5, sess->server_random, SSL3_RANDOM_SIZE );
					MD5_Final( export_iv_block, &md5 );

					MD5_Init( &md5 );
					MD5_Update( &md5, sess->server_random, SSL3_RANDOM_SIZE );
					MD5_Update( &md5, sess->client_random, SSL3_RANDOM_SIZE );
					MD5_Final( export_iv_block + iv_len, &md5 );
				}
				c_iv = export_iv_block;
				s_iv = export_iv_block + iv_len;
			}
			else
			{
				c_iv = memcpy(c_iv_buf, p, iv_len); p+= iv_len;
				s_iv = memcpy(s_iv_buf, p, iv_len); p+= iv_len;
			}
		}
		else
		{
			c_iv = s_iv = NULL;
		}
		
		DEBUG_TRACE_BUF("keyblock", keyblock, keyblock_len);
		DEBUG_TRACE_BUF("c_mac", c_mac, digest_len);
		DEBUG_TRACE_BUF("s_mac", s_mac, digest_len);
		DEBUG_TRACE_BUF("c_wk", c_wk, wk_len);
		DEBUG_TRACE_BUF("s_wk", s_wk, wk_len);
		DEBUG_TRACE_BUF("c_iv", c_iv, iv_len);
		DEBUG_TRACE_BUF("s_iv", s_iv, iv_len);
	}

	/* create ciphers */
	if(  c != NULL && rc == DSSL_RC_OK )
	{
		c_cipher = EVP_CIPHER_CTX_new();
		s_cipher = EVP_CIPHER_CTX_new();

		if( !c_cipher || !s_cipher ) 
		{
			rc = NM_ERROR( DSSL_E_OUT_OF_MEMORY );
		}
	}

	/* init ciphers */
	if( c != NULL && rc == DSSL_RC_OK )
	{
		EVP_CIPHER_CTX_init( c_cipher );
		EVP_CipherInit( c_cipher, c, c_wk, c_iv, 0 );
		EVP_CIPHER_CTX_ctrl(c_cipher, EVP_CTRL_GCM_SET_IV_FIXED, -1, c_iv);

		EVP_CIPHER_CTX_init( s_cipher );
		EVP_CipherInit( s_cipher, c, s_wk, s_iv, 0 );
		EVP_CIPHER_CTX_ctrl(s_cipher, EVP_CTRL_GCM_SET_IV_FIXED, -1, s_iv);
	}

	/* set session data */
	if( rc == DSSL_RC_OK )
	{
		_ASSERT( sess->c_dec.cipher_new == NULL );
		_ASSERT( sess->s_dec.cipher_new == NULL );

		sess->c_dec.cipher_new = c_cipher; c_cipher = NULL;
		sess->s_dec.cipher_new = s_cipher; s_cipher = NULL;

		if( digest )
		{
			_ASSERT( EVP_MD_size( digest ) == (int)digest_len );
			sess->c_dec.md_new = digest;
			sess->s_dec.md_new = digest;
			if (c_mac)
				memcpy( sess->c_dec.mac_key_new, c_mac, digest_len );
			if (s_mac)
				memcpy( sess->s_dec.mac_key_new, s_mac, digest_len );
		}
	}

	/* cleanup */
	OPENSSL_cleanse( keyblock, keyblock_len );

	if( c_cipher )
	{
		EVP_CIPHER_CTX_free( c_cipher );
		c_cipher = NULL;
	}

	if( s_cipher )
	{
		EVP_CIPHER_CTX_free( c_cipher );
		c_cipher = NULL;
	}

	return rc;
}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#define SSL2_MAX_KEYBLOCK_LEN	48
/* generate read/write keys for SSL v2 session */
int ssls2_generate_keys( DSSL_Session* sess, u_char* keyArg, uint32_t keyArgLen )
{
	DSSL_CipherSuite* suite = NULL;
	const EVP_CIPHER* c = NULL;
	const EVP_MD* digest = NULL;
	int rc = DSSL_RC_OK;
	uint32_t iv_len = 0;
	EVP_CIPHER_CTX* c_cipher = NULL;
	EVP_CIPHER_CTX* s_cipher = NULL;
	int keyLen = 0;
	u_char keydata[SSL2_MAX_KEYBLOCK_LEN];

	if(keyArgLen > SSL2_KEYARG_MAX_LEN)
	{
		return NM_ERROR(DSSL_E_SSL_PROTOCOL_ERROR);
	}

	if( sess->c_dec.cipher_new != NULL )
	{
		_ASSERT( FALSE );
		EVP_CIPHER_CTX_cleanup( sess->c_dec.cipher_new );
		EVP_CIPHER_CTX_free( sess->c_dec.cipher_new );
		sess->c_dec.cipher_new = NULL;
	}

	if( sess->s_dec.cipher_new != NULL )
	{
		_ASSERT( FALSE );
		EVP_CIPHER_CTX_cleanup( sess->s_dec.cipher_new );
		EVP_CIPHER_CTX_free( sess->s_dec.cipher_new );
		sess->s_dec.cipher_new = NULL;
	}

	suite = DSSL_GetSSL2CipherSuite( sess->cipher_suite );
	if( !suite ) return NM_ERROR( DSSL_E_SSL_CANNOT_DECRYPT );

	c = EVP_get_cipherbyname( suite->enc );
	if( c == NULL )
	{ 
		_ASSERT( FALSE );
		return NM_ERROR( DSSL_E_UNSPECIFIED_ERROR );
	}

	digest = EVP_get_digestbyname( suite->digest );

	iv_len = EVP_CIPHER_iv_length( c );
	if( iv_len && iv_len != keyArgLen )
	{
		return NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );
	}

	keyLen = EVP_CIPHER_key_length( c );

	_ASSERT( keyLen*2 <= sizeof(keydata) );

	if( rc == DSSL_RC_OK )
	{
		rc = ssl2_PRF( sess->master_secret, sess->master_key_len, sess->client_random, sess->client_challenge_len,
				sess->server_random, sess->server_connection_id_len, keydata, keyLen * 2 );
	}

	/* create ciphers */
	if( rc == DSSL_RC_OK )
	{
		c_cipher = EVP_CIPHER_CTX_new();
		s_cipher = EVP_CIPHER_CTX_new();


		if( !c_cipher || !s_cipher ) 
		{
			rc = NM_ERROR( DSSL_E_OUT_OF_MEMORY );
		}

		EVP_CIPHER_CTX_init( c_cipher );
		EVP_CIPHER_CTX_init( s_cipher );
	}

	if( rc == DSSL_RC_OK )
	{
		EVP_DecryptInit_ex( s_cipher, c, NULL, keydata, keyArg );
		EVP_DecryptInit_ex( c_cipher, c, NULL, keydata + keyLen, keyArg );

		sess->c_dec.cipher_new = c_cipher; c_cipher = NULL;
		sess->s_dec.cipher_new = s_cipher; s_cipher = NULL;

		sess->c_dec.md_new = digest;
		sess->s_dec.md_new = digest;
	}

	if( rc != DSSL_RC_OK )
	{
		if( c_cipher ) { EVP_CIPHER_CTX_free( c_cipher ); c_cipher = NULL; }
		if( s_cipher ) { EVP_CIPHER_CTX_free( s_cipher ); s_cipher = NULL; }
	}

	/* store KEY-ARG data for session cache */
	if( rc == DSSL_RC_OK)
	{
		memset(sess->ssl2_key_arg, 0, SSL2_KEYARG_MAX_LEN);
		memcpy(sess->ssl2_key_arg, keyArg, keyArgLen);
		sess->ssl2_key_arg_len = keyArgLen;
	}

	return rc;
}
#endif //(OPENSSL_VERSION_NUMBER < 0x10100000L)


int ssls_lookup_session( DSSL_Session* sess )
{
	DSSL_SessionKeyData* sess_data = NULL;

	_ASSERT( sess );
	_ASSERT( sess->env );
	
	if( sess->env->session_cache )
	{
		sess_data = dssl_SessionKT_Find( sess->env->session_cache, sess->session_id );
	}

	if( !sess_data ) return NM_ERROR( DSSL_E_SSL_SESSION_NOT_IN_CACHE );

	dssl_SessionKT_AddRef( sess_data );
	memcpy( sess->master_secret, sess_data->master_secret, SSL3_MASTER_SECRET_SIZE );
	sess->master_key_len = sess_data->master_secret_len;

	#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	if(sess->version == SSL2_VERSION)
	{
		memcpy(sess->ssl2_key_arg, sess_data->ssl2_key_arg, SSL2_KEYARG_MAX_LEN );
		sess->ssl2_key_arg_len = sess_data->ssl2_key_arg_length;
		sess->cipher_suite = sess_data->ssl2_cipher_suite;
	}
	#endif //(OPENSSL_VERSION_NUMBER < 0x10100000L)

	return DSSL_RC_OK;
}

void ssls_store_session( DSSL_Session* sess )
{
	DSSL_SessionKeyData* sess_data = NULL;

	_ASSERT( sess );
	_ASSERT( sess->env );
	if( !sess->env->session_cache ) return;

	sess_data = dssl_SessionKT_Find( sess->env->session_cache, sess->session_id );

	if( sess_data )
	{
		memcpy( sess_data->master_secret, sess->master_secret, SSL3_MASTER_SECRET_SIZE );
		sess_data->master_secret_len = sess->master_key_len;
	}
	else
	{
		dssl_SessionKT_Add( sess->env->session_cache, sess );
	}
}


#ifdef NM_MULTI_THREADED_SSL
	#error "Multithreading is not implemented for SSL session decode buffer!"
#else
int ssls_get_decrypt_buffer( DSSL_Session* sess, u_char** data, uint32_t len )
{
	if(!data || !len ) return NM_ERROR( DSSL_E_INVALID_PARAMETER );

	if( len > sizeof(sess->env->decrypt_buffer))
	{
		_ASSERT( FALSE ); /*decrypt_buffer is supposed to fit the biggest possible SSL record!*/
		return NM_ERROR( DSSL_E_OUT_OF_MEMORY );
	}

	(*data) = sess->env->decrypt_buffer;
	return DSSL_RC_OK;
}

void ssls_release_decrypt_buffer( DSSL_Session* sess )
{
	/* no-op in a single threaded mode */
	//sess;
}

int ssls_get_decompress_buffer( DSSL_Session* sess, u_char** data, uint32_t len )
{
	if(!data || !len ) return NM_ERROR( DSSL_E_INVALID_PARAMETER );

	if( len > sizeof(sess->env->decompress_buffer))
	{
		_ASSERT( FALSE ); /*decompressed record can not exceed 2^14 + 1024 bytes !*/
		return NM_ERROR( DSSL_E_OUT_OF_MEMORY );
	}

	(*data) = sess->env->decompress_buffer;
	return DSSL_RC_OK;
}

void ssls_release_decompress_buffer( DSSL_Session* sess )
{
	/* no-op in a single threaded mode */
	//sess;
}

EVP_PKEY* ssls_try_ssl_keys( DSSL_Session* sess, u_char* data, uint32_t len)
{
	DSSL_Env* env = NULL;
	int i = 0;
	EVP_PKEY *pk = NULL;
	u_char	pms_buff[1024];
	_ASSERT(sess);

	env = sess->env;
	_ASSERT(env);

	for(i = 0; i < env->key_count; i++)
	{
		int idx = (i + env->keys_try_index) % env->key_count;

		int pms_len = RSA_private_decrypt( len, data, pms_buff, 
				EVP_PKEY_get0_RSA( env->keys[idx] ), RSA_PKCS1_PADDING );

		if( pms_len != -1 )
		{
			pk = env->keys[idx];
			break;
		}
	}

	/* increment the 'start from' index */
	++env->keys_try_index;
	if(env->keys_try_index >= env->key_count) env->keys_try_index = 0;

	return pk;

}

static EVP_PKEY* ssls_dup_PrivateRSA_ENV_PKEY( EVP_PKEY* src )
{
	EVP_PKEY* pDupKey = EVP_PKEY_new();
	RSA* pRSA = EVP_PKEY_get1_RSA(src);
	RSA* pRSADupKey = RSAPrivateKey_dup(pRSA);
	RSA_free(pRSA);
	EVP_PKEY_set1_RSA(pDupKey, pRSADupKey);
	RSA_free(pRSADupKey);
	return(pDupKey);
}


int ssls_register_ssl_key( DSSL_Session* sess,EVP_PKEY* pk )
{
	struct in_addr server_ip = sess->last_packet->ip_header->ip_dst;
	uint16_t server_port = ntohs(sess->last_packet->tcp_header->th_dport);
	EVP_PKEY* dup_key = ssls_dup_PrivateRSA_ENV_PKEY( pk );
	int rc = DSSL_RC_OK;

#if !defined(__APPLE__)
	/* MacOS uses OpenSSL v 0.9.7 that doesn't have EVP_PKEY_cmp */
	_ASSERT( EVP_PKEY_cmp(pk, dup_key) == 1);
#endif

	rc = DSSL_EnvSetServerInfoWithKey(sess->env, &server_ip, server_port, dup_key);
	if( rc == DSSL_RC_OK)
	{
		sess->flags |= SSF_TEST_SSL_KEY; /* set a flag to watch this key until it's proven to work */
		sess->ssl_si = DSSL_EnvFindServerInfo( sess->env, server_ip, server_port);
		_ASSERT(sess->ssl_si);
	}
	else
	{
		EVP_PKEY_free(dup_key);
		dup_key = NULL;
	}

	return rc;
}

void ssls_register_missing_key_server(DSSL_Session* sess)
{
	struct in_addr server_ip = sess->last_packet->ip_header->ip_dst;
	uint16_t server_port = ntohs(sess->last_packet->tcp_header->th_dport);

	_ASSERT( sess );
	_ASSERT( sess->env );

	if(DSSL_EnvIsMissingKeyServer( sess->env, server_ip, server_port) == NULL )
	{
		DSSL_EnvAddMissingKeyServer( sess->env, server_ip, server_port );

		if(sess->event_callback)
		{
			DSSL_ServerInfo* si = DSSL_EnvIsMissingKeyServer( sess->env, server_ip, server_port);
			_ASSERT(si);
			(*sess->event_callback)( sess->user_data, eSslMissingServerKey, si );
		}
	}
}

#endif

/* reset all SSL/TLS extension data */
void ssls_free_extension_data(DSSL_Session* sess)
{
	_ASSERT(sess);

	sess->flags &= ~SSF_TLS_SESSION_TICKET_SET;
	/* free TLS session ticket */
	if(sess->session_ticket) { 
		free(sess->session_ticket); 
	}
	sess->session_ticket = 0;
	sess->session_ticket_len = 0;
}


int ssls_init_from_tls_ticket( DSSL_Session* sess )
{
	DSSL_SessionTicketData* ticket_data = NULL;

	_ASSERT( sess );
	_ASSERT( sess->env );
	
	if( sess->env->ticket_cache )
	{
		ticket_data = dssl_SessionTicketTable_Find( sess->env->ticket_cache, 
			sess->session_ticket, sess->session_ticket_len );
	}

	if( !ticket_data ) return NM_ERROR( DSSL_E_SSL_SESSION_TICKET_NOT_CACHED );

	memcpy( sess->master_secret, ticket_data->master_secret, SSL3_MASTER_SECRET_SIZE );
	sess->master_key_len = SSL3_MASTER_SECRET_SIZE;
	sess->cipher_suite = ticket_data->cipher_suite;
	sess->version = ticket_data->protocol_version;
	sess->compression_method = ticket_data->compression_method;

	return DSSL_RC_OK;
}

int ssls_store_new_ticket(DSSL_Session* sess, u_char* ticket, uint32_t len)
{
	_ASSERT(sess && ticket && len);

	if( sess->env->ticket_cache )
	{
		return dssl_SessionTicketTable_Add( sess->env->ticket_cache, sess, ticket, len );
	}
	else
	{
		_ASSERT( FALSE );
		return NM_ERROR( DSSL_E_UNSPECIFIED_ERROR );
	}
}

void ssls_handshake_data_append(DSSL_Session* sess, u_char* data, uint32_t len)
{
	void *handshake_data_new;

	if(sess->handshake_data)
	{
		handshake_data_new = malloc(sess->handshake_data_size + len);
		memcpy(handshake_data_new, sess->handshake_data, sess->handshake_data_size);
		memcpy(handshake_data_new + sess->handshake_data_size, data, len);
		free(sess->handshake_data);
		sess->handshake_data = handshake_data_new;
		sess->handshake_data_size += len;
	} 
	else
	{
		sess->handshake_data = malloc(len);
		memcpy(sess->handshake_data, data, len);
		sess->handshake_data_size = len;
	}
}

void ssls_handshake_data_free(DSSL_Session* sess)
{
	if(sess->handshake_data)
	{
		free(sess->handshake_data);
		sess->handshake_data = NULL;
	}
	sess->handshake_data_size = 0;
}

void ssls_handshake_queue_free(DSSL_Session* sess)
{
	if(sess->handshake_queue) {
		DSSL_handshake_buffer *q = NULL, *next;
		for (q = sess->handshake_queue; q != NULL; q = next)
		{
			next = q->next;
			free ( q->data );
			free ( q );
		}
		sess->handshake_queue = NULL;
	}
	
}
