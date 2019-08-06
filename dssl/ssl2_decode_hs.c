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

#include "stdinc.h"

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)

#include "string.h"
#include "ssl_session.h"
#include "ssl2_decode_hs.h"
#include "ssl_decode_hs.h"
#include "decoder_stack.h"
#include "ciphersuites.h"
#include "packet.h"

#define SSL20_CLIENT_HELLO_MIN_LEN			8
#define SSL20_CLIENT_MASTER_KEY_MIN_LEN		9

/*
======== Utility functions and Local Prototypes
*/

#ifdef NM_TRACE_SSL_HANDSHAKE
static const char* SSL2_HandshakeTypeToString( int hs_type )
{
	static const char* HandshakeCodes[] = 
	{
		"ERROR", "CLIENT-HELLO", "CLIENT-MASTER-KEY", "CLIENT-FINISHED",
		"SERVER-HELLO", "SERVER-VERIFY", "SERVER-FINISHED", 
		"REQUEST-CERTIFICATE", "CLIENT-CERTIFICATE"
	};

	if( hs_type >= 0 && hs_type < sizeof( HandshakeCodes ) / sizeof(HandshakeCodes[0] ) )
	{
		return HandshakeCodes[hs_type];
	}
	else
	{
		return "INVALID";
	}
}
#endif


int ssl2_handshake_record_decode_wrapper( dssl_decoder_stack* stack, NM_PacketDir dir,
								 u_char* data, uint32_t len, uint32_t* processed )
{
	return ssl2_decode_handshake( stack->sess, dir, data, len, processed );
}

/*
 ========== SSL 2.0 Handshake Protocol Message Handlers 
*/

/* ========== CLIENT-HELLO ========== */
static int ssl2_decode_client_hello( DSSL_Session* sess, u_char* data, uint32_t len, uint32_t* processed )
{
	int rc = DSSL_RC_OK;
	uint32_t sessionIdLen = 0, challengeLen = 0, cipherSpecLen = 0;

	_ASSERT( processed && data && sess );

	/* record the handshake start time */
	sess->handshake_start = sess->last_packet->pcap_header.ts;

	if( len < SSL20_CLIENT_HELLO_MIN_LEN ) return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH ); 

	if( data[0] == 0 && data[1] == 2 )
	{
		sess->client_version = SSL2_VERSION;
		rc = ssls_set_session_version( sess, SSL2_VERSION );
	}
	else if( data[0] == 3 ) 
	{
		/* SSLv3 or TLS1 in a v2 header */
		sess->client_version = MAKE_UINT16(data[0], data[1]);
		rc = ssls_set_session_version( sess, MAKE_UINT16(data[0], data[1]) );
	}
	else
	{
		rc = NM_ERROR( DSSL_E_SSL_UNKNOWN_VERSION );
	}

	/*	validate the record format */
	if( rc == DSSL_RC_OK )
	{
		/* CIPHER-SPECS-LENGTH */
		cipherSpecLen = MAKE_UINT16( data[2], data[3] );
		/* SESSION-ID-LENGTH */
		sessionIdLen = MAKE_UINT16( data[4], data[5] ); 
		/* CHALLENGE-LENGTH */
		challengeLen = MAKE_UINT16( data[6], data[7] ); 

		if( challengeLen + sessionIdLen + cipherSpecLen + SSL20_CLIENT_HELLO_MIN_LEN != len ) 
		{
			rc = NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
		}
	}

	/* validate and set the session ID */
	
	if( rc == DSSL_RC_OK )
	{
		if( sessionIdLen == 16 )
		{
			u_char* sessionId = data + SSL20_CLIENT_HELLO_MIN_LEN + cipherSpecLen;

			_ASSERT( sessionIdLen <= sizeof( sess->session_id ) );
			memset( sess->session_id, 0, sizeof( sess->session_id ) );
			memcpy( sess->session_id, sessionId, sessionIdLen );
			sess->flags |= SSF_CLIENT_SESSION_ID_SET;

		}
		else
		{
			sess->flags &= ~SSF_CLIENT_SESSION_ID_SET;
			if (sessionIdLen != 0 )
			{
				/* session ID length must be either 16 or 0 for SSL v2 */
				rc = NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );
			}
		}
	}

	/* validate and set the client random aka Challenge */
	if( rc == DSSL_RC_OK )
	{
		if( challengeLen < 16 || challengeLen > 32 )
		{
			rc = NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );
		}
		else
		{
			u_char* challenge = data + SSL20_CLIENT_HELLO_MIN_LEN + cipherSpecLen + sessionIdLen;
			_ASSERT( challengeLen <= sizeof( sess->client_random ) );
			memset( sess->client_random, 0, sizeof( sess->client_random ) );
			memcpy( sess->client_random,  challenge, challengeLen );
			sess->client_challenge_len = challengeLen;
			/* may need this flag later to convert CHALLENGE to SSL v3 CLIENT_RANDOM */
			sess->flags |= SSF_SSLV2_CHALLENGE;
		}
	}

	if( rc == DSSL_RC_OK ) { *processed = len; }

	return rc;
}

/* ========== SERVER-HELLO ========== */
static int ssl2_decode_server_hello( DSSL_Session* sess, u_char* data, uint32_t len, uint32_t* processed )
{
	int rc = DSSL_RC_OK;
	uint16_t certLen = 0;
	uint16_t cipherSpecLen = 0;
	uint16_t connectionIdLen = 0;
	int session_id_hit = 0;

	_ASSERT( processed && data && sess );

	if( len < SSL20_SERVER_HELLO_MIN_LEN ) { return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH ); }

	/* check SESSION-ID-HIT */
	session_id_hit = data[0];

	/* decode CERTIFICATE-TYPE */
	if( rc == DSSL_RC_OK && (data[1] && data[1] != SSL2_CT_X509_CERTIFICATE) ) 
	{
		rc = NM_ERROR( DSSL_E_SSL2_INVALID_CERTIFICATE_TYPE ); 
	}

	/* SERVER-VERSION*/	 /* TODO: add server version check */

	/* CERTIFICATE-LENGTH, CIPHER-SPECS-LENGTH, CONNECTION-ID-LENGTH */
	if( rc == DSSL_RC_OK )
	{
		certLen = MAKE_UINT16( data[4], data[5] );
		cipherSpecLen = MAKE_UINT16( data[6], data[7] );
		connectionIdLen = MAKE_UINT16( data[8], data[9] );

		if( (uint32_t)certLen + cipherSpecLen + connectionIdLen + SSL20_SERVER_HELLO_MIN_LEN != len )
		{
			rc = NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
		}
		else if( connectionIdLen < 16 || connectionIdLen > 32 )
		{
			rc = NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );
		}

		if( rc == DSSL_RC_OK ) 
		{
			u_char* connIdData = data + SSL20_SERVER_HELLO_MIN_LEN + certLen + cipherSpecLen;
			sess->server_connection_id_len = connectionIdLen; 
			memset( sess->server_random, 0, sizeof(sess->server_random) );
			memcpy( sess->server_random, connIdData, connectionIdLen );
		}
	}

	/* TODO: Check the certificate to match what DSSL has been initialized with */
	if( rc == DSSL_RC_OK )
	{
	}

	if( session_id_hit )
	{
		if( sess->flags & SSF_CLIENT_SESSION_ID_SET )
		{
			rc = ssls_lookup_session( sess );
			/* re-generate the session keys and turn on ciphers right away */
			if( rc == DSSL_RC_OK)
			{
				rc = ssls2_generate_keys( sess, sess->ssl2_key_arg, sess->ssl2_key_arg_len );
			}
			/* turn on new ciphers */
			if( rc == DSSL_RC_OK ) 
			{
				rc = dssl_decoder_stack_flip_cipher( &sess->c_dec );
				if (rc == DSSL_RC_OK ) { rc = dssl_decoder_stack_flip_cipher( &sess->s_dec ); }
			}
		}
		else
		{
			/* client didn't send the session id */
			rc = NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );
		}
	}


	if( rc == DSSL_RC_OK )
	{
		*processed = certLen + cipherSpecLen + connectionIdLen + SSL20_SERVER_HELLO_MIN_LEN;
	}

	return rc;
}

/* ========== CLIENT-MASTER-KEY ========== */
static int ssl2_decode_client_master_key(  DSSL_Session* sess, u_char* data, uint32_t len, uint32_t* processed )
{
	int rc = DSSL_RC_OK;
	uint16_t clearKeyLen = 0;
	uint16_t encKeyLen = 0;
	uint16_t keyArgLen = 0;
	u_char* pClearKey = NULL;
	u_char* pEncKey = NULL;
	u_char* pKeyArg = NULL;

	_ASSERT( processed && data && sess );
	if( len < SSL20_CLIENT_MASTER_KEY_MIN_LEN ) { return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH ); }

	/* CIPHER-KIND - convert to 2 byte DSSL_Session::cipher_suite */
	rc = DSSL_ConvertSSL2CipherSuite( data, &sess->cipher_suite );

	/* CLEAR-KEY-LENGTH, ENCRYPTED-KEY-LENGTH, KEY-ARG-LENGTH */
	if( rc == DSSL_RC_OK )
	{
		clearKeyLen = MAKE_UINT16( data[3], data[4] );
		encKeyLen = MAKE_UINT16( data[5], data[6] );
		keyArgLen = MAKE_UINT16( data[7], data[8] );

		if( len != (uint32_t)clearKeyLen + encKeyLen + keyArgLen + SSL20_CLIENT_MASTER_KEY_MIN_LEN )
		{
			rc = NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
		}

		*processed = len;

	}
	
	/* reconstitute the master secret */
	if( rc == DSSL_RC_OK )
	{
		EVP_PKEY *pk = NULL;

		pClearKey = data + SSL20_CLIENT_MASTER_KEY_MIN_LEN;
		pEncKey = pClearKey + clearKeyLen;
		pKeyArg = pEncKey + encKeyLen;

		if( clearKeyLen ) { memcpy( sess->master_secret, pClearKey, clearKeyLen ); }

		pk = ssls_get_session_private_key( sess );
		
		/* if SSL server key is not found, try to find a matching one from the key pool */
		if(pk == NULL) 
		{
			u_char buff[1024];
			_ASSERT( sess->last_packet);

			memcpy(buff, pEncKey, encKeyLen);
			pk = ssls_try_ssl_keys( sess, pEncKey, encKeyLen );

			/* if a matching key found, register it with the server IP:port */
			if(pk != NULL)
			{
				if( ssls_register_ssl_key( sess, pk ) == DSSL_RC_OK)
				{
					/* ssls_register_ssl_key clones the key, query the key back */
					/* pk = ssls_get_session_private_key( sess ); */
				}
				else
				{
					pk = NULL;
				}
			}
		}

		if( pk )
		{
			uint32_t encLen2 = RSA_private_decrypt( encKeyLen, pEncKey, 
					sess->master_secret + clearKeyLen, EVP_PKEY_get0_RSA( pk ), RSA_PKCS1_PADDING );

			if( clearKeyLen + encLen2 >= sizeof( sess->master_secret ) )
			{
				rc = NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );
			}

			sess->master_key_len = clearKeyLen + encLen2;
		}
		else
		{
			rc = NM_ERROR( DSSL_E_SSL_SERVER_KEY_UNKNOWN );
			ssls_register_missing_key_server( sess );
		}
	}

	/* generate session keys */
	if( rc == DSSL_RC_OK )
	{
		rc = ssls2_generate_keys( sess, pKeyArg, keyArgLen );
	}

	/* turn on new ciphers */
	if( rc == DSSL_RC_OK ) 
	{
		rc = dssl_decoder_stack_flip_cipher( &sess->c_dec );
		if (rc == DSSL_RC_OK ) { rc = dssl_decoder_stack_flip_cipher( &sess->s_dec ); }
	}

	return rc;
}


/* ========== CLIENT-FINISHED ========== */
static int ssl2_decode_client_finished(  DSSL_Session* sess, u_char* data, uint32_t len, uint32_t* processed )
{
	_ASSERT( processed && data && sess );

	if( len != sess->server_connection_id_len ) { return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH ); }

	if( memcmp( data, sess->server_random, sess->server_connection_id_len ) != 0 )
	{
		return NM_ERROR( DSSL_E_SSL2_BAD_CLIENT_FINISHED ); 
	}

	*processed = len;

	return DSSL_RC_OK;
}


/* ========== SERVER-VERIFY ========== */
static int ssl2_decode_server_verify(  DSSL_Session* sess, u_char* data, uint32_t len, uint32_t* processed )
{	
	_ASSERT( processed && data && sess );

	if( len != sess->client_challenge_len ) { return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH ); }

	if( memcmp( data, sess->client_random, sess->client_challenge_len ) != 0 )
	{
		return NM_ERROR( DSSL_E_SSL2_BAD_SERVER_VERIFY ); 
	}

	*processed = len;

	return DSSL_RC_OK;
}

/* ========== SERVER-FINISHED ========== */
static int ssl2_decode_server_finished(  DSSL_Session* sess, u_char* data, uint32_t len, uint32_t* processed )
{
	_ASSERT( processed && data && sess );

	if( len > sizeof( sess->session_id ) ) { return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH ); }

	/* set new session ID and add the session to the session cache */
	memset( sess->session_id, 0, sizeof(sess->session_id ) );
	memcpy( sess->session_id, data, len );
	ssls_store_session( sess );

	/* handshake is over, time to switch to application data protocol */
	sess->c_dec.state = SS_Established;
	sess->s_dec.state = SS_Established;
	ssls_handshake_done( sess );

	*processed = len;

	return DSSL_RC_OK;
}

/* ========== SERVER-FINISHED ========== */
static int ssl2_decode_error(  DSSL_Session* sess, u_char* data, uint32_t len, uint32_t* processed )
{
	//data; /*unused */
	/*TODO: error handling - store the error code */
	sess->flags |= SSF_FATAL_ALERT_RECEIVED;

	*processed = len;
	return DSSL_RC_OK;
}


/* ========== SSL 2 Handshake Protocol Decoder ========== */
int ssl2_decode_handshake( DSSL_Session* sess, NM_PacketDir dir, 
		u_char* data, uint32_t len, uint32_t* processed )
{
	int rc = DSSL_RC_OK;
	int hs_type = 0;

	_ASSERT( processed );
	_ASSERT( data );

	if( len < 1 ) { return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH ); }
	hs_type = data[0];
	data += 1;
	len -= 1;

#ifdef NM_TRACE_SSL_HANDSHAKE
	DEBUG_TRACE1( "\n===>Decoding SSL v2 handshake message: %s", SSL2_HandshakeTypeToString( hs_type ) );
#endif

	/* check the packet direction */
	switch(hs_type)
	{
	case SSL2_MT_CLIENT_HELLO:
	case SSL2_MT_CLIENT_MASTER_KEY:
	case SSL2_MT_CLIENT_FINISHED:
	case SSL2_MT_CLIENT_CERTIFICATE:
		if( dir != ePacketDirFromClient ) { rc = NM_ERROR( DSSL_E_SSL_UNEXPECTED_TRANSMISSION ); }
		break;

	case SSL2_MT_SERVER_HELLO:
	case SSL2_MT_SERVER_VERIFY:
	case SSL2_MT_SERVER_FINISHED:
		if( dir != ePacketDirFromServer ) { rc = NM_ERROR( DSSL_E_SSL_UNEXPECTED_TRANSMISSION ); }
		break;
	}

	if( rc == DSSL_RC_OK )
	{
		switch( hs_type )
		{
		case SSL2_MT_ERROR:
			rc = ssl2_decode_error( sess, data, len, processed );
			break;

		case SSL2_MT_CLIENT_HELLO:
			rc = ssl2_decode_client_hello( sess, data, len, processed );
			break;

		case SSL2_MT_SERVER_HELLO:
			sess->s_dec.state = SS_SeenServerHello;
			rc = ssl2_decode_server_hello( sess, data, len, processed );
			break;

		case SSL2_MT_CLIENT_MASTER_KEY:
			rc = ssl2_decode_client_master_key( sess, data, len, processed );
			break;

		case SSL2_MT_CLIENT_FINISHED:
			rc = ssl2_decode_client_finished( sess, data, len, processed );
			break;

		case SSL2_MT_SERVER_VERIFY:
			rc = ssl2_decode_server_verify( sess, data, len, processed );
			break;

		case SSL2_MT_SERVER_FINISHED:
			rc = ssl2_decode_server_finished( sess, data, len, processed );
			break;

		case SSL2_MT_CLIENT_CERTIFICATE:
		case SSL2_MT_REQUEST_CERTIFICATE:
			/*just eat it */
			*processed = len;
			rc = DSSL_RC_OK;
			break;

		default:
			rc = NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );
			break;
		}

		if( rc == DSSL_RC_OK )
		{
			*processed += 1;
		}
	}

	return rc;
}

#endif //(OPENSSL_VERSION_NUMBER < 0x10100000L)
