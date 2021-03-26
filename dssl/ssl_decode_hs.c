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
#include <string.h>
#include "ssl_session.h"
#include "ssl_decode_hs.h"
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#include "ssl2_decode_hs.h"
#endif //(OPENSSL_VERSION_NUMBER < 0x10100000L)
#include "decoder_stack.h"
#include "packet.h"
#include "ciphersuites.h"

#include "tls-ext.h"

#ifndef SSL3_MT_NEWSESSION_TICKET
	#define	SSL3_MT_NEWSESSION_TICKET		4
#endif

#ifdef NM_TRACE_SSL_HANDSHAKE
static const char* SSL3_HandshakeTypeToString( int hs_type )
{
	switch(hs_type) {
		case SSL3_MT_HELLO_REQUEST: return "HelloRequest"; 
		case SSL3_MT_CLIENT_HELLO: return "ClientHello";
		case SSL3_MT_SERVER_HELLO: return "ServerHello";
		case SSL3_MT_NEWSESSION_TICKET: return "NewSessionTicket (unsupported!)";
		case SSL3_MT_CERTIFICATE: return "Certificate";
		case SSL3_MT_SERVER_KEY_EXCHANGE: return "ServerKeyExchange";
		case SSL3_MT_CERTIFICATE_REQUEST: return "CertificateRequest";
		case SSL3_MT_SERVER_DONE: return "ServerHelloDone";
		case SSL3_MT_CERTIFICATE_VERIFY: return "CertificateVerify";
		case SSL3_MT_CLIENT_KEY_EXCHANGE: return "ClientKeyExchange";
		case SSL3_MT_FINISHED: return "Finished";
		case SSL3_MT_CERTIFICATE_STATUS: return "CertificateStatus";
		case DTLS1_MT_HELLO_VERIFY_REQUEST: return "HelloVerifyRequest";
		default: return "Unknown";
	}
}

static const char* SSL3_ExtensionTypeToString( int ext_type )
{
	static char buff[64];
	switch(ext_type) {
		case 0x0000: return "server_name"; 
		case 0x000a: return "elliptic_curves";
		case 0x000b: return "ec_point_format";
		case 0x0023: return "Session Ticket TLS";
		case 0x002b: return "supported_versions";
		default:
			sprintf(buff, "Unknown (%x)", ext_type);
			return buff;
	}
}

#endif

static int ssl3_decode_client_hello( DSSL_Session* sess, u_char* data, uint32_t len )
{
	u_char* org_data = data;
	int t_len = 0;

	/* record the handshake start time */
	sess->handshake_start = sess->last_packet->pcap_header.ts;

	if( data[0] != 3 || data[1] > 3) return NM_ERROR( DSSL_E_SSL_UNKNOWN_VERSION );

	/* 2 bytes client version */
	sess->client_version = MAKE_UINT16( data[0], data[1] );
	ssls_set_session_version( sess, MAKE_UINT16( data[0], data[1] ) );

	data+= 2;

	/* make sure */
	if( data + 32 > org_data + len ) return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );

	/* 32 bytes ClientRandom */
	memcpy( sess->client_random, data, 32 );
	data+= 32;
	DEBUG_TRACE_BUF("client_random", sess->client_random, 32);
	
	if( !sess->ssl_si->pkey && sess->get_keys_fce )
	{
		sess->get_keys_fce(sess->client_random, &sess->get_keys_rslt_data, sess);
		if(sess->get_keys_rslt_data.set && sess->version != TLS1_3_VERSION && sess->get_keys_rslt_data.client_random.key[0]) 
		{
			memcpy(sess->master_secret, sess->get_keys_rslt_data.client_random.key, sess->get_keys_rslt_data.client_random.length);
		}
	}

	/* check session ID length */
	if( data[0] > 32 ) return NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );

	if( data[0] > 0 )
	{
		/* Session ID set */
		if( data + data[0] > org_data + len ) 
			return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );

		memcpy( sess->session_id, data+1, data[0] );
		sess->flags |= SSF_CLIENT_SESSION_ID_SET;

		data += data[0] + 1;
	}
	else
	{
		/* no Session ID */
		sess->flags &= ~SSF_CLIENT_SESSION_ID_SET;
		++data;
	}

	/* Cypher Suites */
	if(data + 1 >= org_data + len) return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
	t_len = MAKE_UINT16(data[0], data[1]) + 2; /* cypher suites + cypher sute length size */

	data += t_len; /* skip cypher suites */

	/* Compression Method */
	if(data >= org_data + len) return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
	if(data + data[0] + 1 > org_data + len) return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
	t_len = data[0] + 1;

	data += t_len; /* skip compression methods */

	/* Extensions */

	/* clear all previous extension fields */
	ssls_free_extension_data(sess);

	if(data >= org_data + len) return DSSL_RC_OK;

	if(data + 2 > org_data + len) return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
	t_len = MAKE_UINT16(data[0], data[1]);

	data += 2; /* positon at the beginning of the first extension record, if any*/

	while(t_len >= 4)
	{
		int ext_type = MAKE_UINT16(data[0], data[1]); /* extension type */
		int ext_len = MAKE_UINT16(data[2], data[3]);
		#ifdef NM_TRACE_SSL_HANDSHAKE
			DEBUG_TRACE2( "\nSSL extension: %s len: %d", SSL3_ExtensionTypeToString( ext_type ), ext_len );
		#endif

		/* TLS Session Ticket */
		if( ext_type == 0x0023)
		{
			/* non empty ticket passed, store it */
			if(ext_len > 0)
			{
				sess->flags |= SSF_TLS_SESSION_TICKET_SET;
				sess->session_ticket = (u_char*) malloc(ext_len);
				if(sess->session_ticket == NULL) return NM_ERROR(DSSL_E_OUT_OF_MEMORY);
				memcpy(sess->session_ticket, data+4, ext_len);
				sess->session_ticket_len = ext_len;
			}
		}
		if( ext_type == 0x0017)
		{ 	sess->flags |= SSF_TLS_CLIENT_EXTENDED_MASTER_SECRET;
		}

		data += ext_len + 4;
		if(data > org_data + len) return NM_ERROR(DSSL_E_SSL_INVALID_RECORD_LENGTH);
		t_len -= ext_len + 4;
	}

	return DSSL_RC_OK;
}


static int ssl3_decode_server_hello( DSSL_Session* sess, u_char* data, uint32_t len )
{
	uint16_t server_version = 0;
	u_char* org_data = data;
	uint16_t session_id_len = 0;
	int session_id_match = 0;

	if( data[0] != 3 || data[1] > 3) return NM_ERROR( DSSL_E_SSL_UNKNOWN_VERSION );
	if( len < SSL3_SERVER_HELLO_MIN_LEN ) return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );

	/* Server Version */
	server_version = MAKE_UINT16( data[0], data[1] );
	if( sess->version == 0 || server_version < sess->version )
	{
		ssls_set_session_version( sess, server_version );
	}
	data+= 2;

	/* ServerRandom */
	//_ASSERT_STATIC( sizeof(sess->server_random) == 32 );

	memcpy( sess->server_random, data, sizeof( sess->server_random ) );
	data+= 32;
	DEBUG_TRACE_BUF("server_random", sess->server_random, 32);


	/* session ID */
	//_ASSERT_STATIC( sizeof(sess->session_id) == 32 );
	session_id_len = data[0];
	data++;

	if( session_id_len > 0 )
	{
		if ( session_id_len > 32 ) return NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );

		if( !IS_ENOUGH_LENGTH( org_data, len, data, session_id_len ) ) 
		{
			return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
		}

		if( sess->flags & SSF_CLIENT_SESSION_ID_SET 
			&& memcmp( sess->session_id, data, session_id_len ) == 0 )
		{
			session_id_match = 1;
		}
		else
		{
			sess->flags &= ~SSF_CLIENT_SESSION_ID_SET;
			memcpy( sess->session_id, data, session_id_len );
		}

		data += session_id_len;
	}

	/* Cipher Suite and Compression */
	if( !IS_ENOUGH_LENGTH( org_data, len, data, 3 ) ) 
	{
		return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
	}

	sess->cipher_suite = MAKE_UINT16( data[0], data[1] );
	sess->compression_method = data[2];

	data += 3;
	sess->flags &= ~SSF_TLS_SERVER_SESSION_TICKET; /* clear server side TLS Session Ticket flag */
	/* Process SSL Extensions, if present */
	if(IS_ENOUGH_LENGTH( org_data, len, data, 2 )) 
	{
		int t_len = MAKE_UINT16(data[0], data[1]);
		data += 2;
		if(!IS_ENOUGH_LENGTH( org_data, len, data, t_len)) 
			return NM_ERROR(DSSL_E_SSL_INVALID_RECORD_LENGTH);

		/* cycle through extension records */
		while(t_len >= 4)
		{
			int ext_type = MAKE_UINT16(data[0], data[1]); /* extension type */
			int ext_len = MAKE_UINT16(data[2], data[3]);
			#ifdef NM_TRACE_SSL_HANDSHAKE
				DEBUG_TRACE2( "\nSSL extension: %s len: %d", SSL3_ExtensionTypeToString( ext_type ), ext_len );
			#endif

			/* TLS Session Ticket extension found, set the flag */
			if( ext_type == 0x0023)
			{
				sess->flags |= SSF_TLS_SERVER_SESSION_TICKET;
			}
			if( ext_type == 0x0017)
			{ 	sess->flags |= SSF_TLS_SERVER_EXTENDED_MASTER_SECRET;
			}
			if( ext_type == 0x002b)
			{	if(ext_len == 2 && sess->version == TLS1_2_VERSION && MAKE_UINT16(data[4], data[5]) == TLS1_3_VERSION)
					sess->version = TLS1_3_VERSION;
			}
			data += ext_len + 4;
			if(data > org_data + len) return NM_ERROR(DSSL_E_SSL_INVALID_RECORD_LENGTH);
			t_len -= ext_len + 4;
		}
	}

	if( session_id_match )
	{
		if( sess->flags & SSF_TLS_SESSION_TICKET_SET)
		{
			int rc = ssls_init_from_tls_ticket( sess );
			if( NM_IS_FAILED( rc ) ) 
				return rc;
		}
		else
		{
			/* lookup session from the cache for stateful SSL renegotiation */
			int rc = ssls_lookup_session( sess );
			if( rc != DSSL_E_SSL_SESSION_NOT_IN_CACHE && NM_IS_FAILED( rc ) ) 
				return rc;
		}
	}
	else
	{
		if( sess->flags & SSF_TLS_SESSION_TICKET_SET )
		{
			if( ssls_init_from_tls_ticket( sess ) == DSSL_RC_OK &&
			    ssls_generate_keys( sess ) == DSSL_RC_OK )
			{
				return DSSL_RC_OK;
			}
		}
	}

	if( sess->flags & SSF_CLIENT_SESSION_ID_SET || sess->get_keys_rslt_data.set )
	{
		if( sess->version == TLS1_3_VERSION )
		{
			if( !sess->get_keys_rslt_data.set || !tls_generate_keys(sess, 0) )
			{
				return DSSL_E_TLS_GENERATE_KEYS;
			}
		}
		else
		{
			int rc = ssls_generate_keys( sess );
			if( NM_IS_FAILED( rc ) ) return rc;
		}
	}

	return DSSL_RC_OK;
}


/* First client_hello is a special case, because of SSL v2 compatibility */
int ssl_decode_first_client_hello( DSSL_Session* sess, u_char* data, uint32_t len, uint32_t* processed )
{
	int rc = DSSL_RC_OK;
	
	#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	if( data[0] & 0x80 && len >= 3 && data[2] == SSL2_MT_CLIENT_HELLO )
	{
		int hdrLen = SSL20_CLIENT_HELLO_HDR_LEN;
		uint32_t recLen = len - hdrLen;

		rc = ssl2_decode_handshake( sess, ePacketDirFromClient, data + hdrLen, recLen, processed );

		if( rc == DSSL_RC_OK )
		{
			if( sess->version >= SSL3_VERSION && sess->version <= TLS1_2_VERSION )
			{
				ssl3_init_handshake_digests( sess );
				ssl3_update_handshake_digests( sess, data + hdrLen, recLen );
			}

			*processed += hdrLen;
		}
	}
	else 
	#endif //(OPENSSL_VERSION_NUMBER < 0x10100000L)
	if( data[0] == SSL3_RT_HANDSHAKE && len > 6 && 
		data[1] == SSL3_VERSION_MAJOR && data[5] == SSL3_MT_CLIENT_HELLO )
	{
		uint32_t recLen = 0;
		u_char* org_data;

		data += SSL3_HEADER_LEN;
		recLen = (((int32_t)data[1]) << 16) | (((int32_t)data[2]) << 8) | data[3];
		org_data = data;

		data += SSL3_HANDSHAKE_HEADER_LEN;
		len -= SSL3_HANDSHAKE_HEADER_LEN;
		
		rc = ssl3_decode_client_hello( sess, data, recLen );
		if( rc == DSSL_RC_OK )
		{
			*processed = recLen + SSL3_HANDSHAKE_HEADER_LEN + SSL3_HEADER_LEN;
			ssl3_init_handshake_digests( sess );
			ssl3_update_handshake_digests( sess, org_data, recLen + SSL3_HANDSHAKE_HEADER_LEN );
		}
	}
	else
	{
		rc = NM_ERROR( DSSL_E_SSL_UNKNOWN_VERSION );
	}

	return rc;
}


int ssl_detect_client_hello_version( u_char* data, uint32_t len, uint16_t* ver )
{
	int rc = DSSL_RC_OK;

	_ASSERT( ver != NULL );
	_ASSERT( data != NULL );

	/* SSL v2 header can be sent even by never clients */
	if( data[0] & 0x80 && len >= 3 && data[2] == SSL2_MT_CLIENT_HELLO )
	{
		*ver = MAKE_UINT16( data[3], data[4] );
	}
	else if ( data[0] == SSL3_RT_HANDSHAKE && len > 11 && 
		data[1] == SSL3_VERSION_MAJOR && data[5] == SSL3_MT_CLIENT_HELLO )
	{
		uint16_t client_hello_ver = MAKE_UINT16( data[9], data[10] );
		*ver = MAKE_UINT16( data[1], data[2] );

		if( *ver > client_hello_ver ) rc = NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );
	}
	else
	{
		rc = NM_ERROR( DSSL_E_SSL_UNKNOWN_VERSION );
	}

	return rc;
}


int ssl_detect_server_hello_version( u_char* data, uint32_t len, uint16_t* ver )
{
	int rc = DSSL_RC_OK;

	_ASSERT( ver != NULL );
	_ASSERT( data != NULL );
	
	#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	if( data[0] & 0x80 && len >= SSL20_SERVER_HELLO_MIN_LEN && data[2] == SSL2_MT_SERVER_HELLO )
	{
		*ver = MAKE_UINT16( data[5], data[6] );
	}
	else 
	#endif //(OPENSSL_VERSION_NUMBER < 0x10100000L)
	if( data[0] == SSL3_RT_HANDSHAKE && len > 11 && 
		data[1] == SSL3_VERSION_MAJOR && data[5] == SSL3_MT_SERVER_HELLO )
	{
		uint16_t sever_hello_ver = MAKE_UINT16( data[9], data[10] );
		*ver = MAKE_UINT16( data[1], data[2] );

		if( *ver > sever_hello_ver ) rc = NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );
	}
	else if( data[0] == SSL3_RT_ALERT && len == 7 && data[1] == SSL3_VERSION_MAJOR &&
			MAKE_UINT16( data[3], data[4] ) == 2 )
	{
		/* this is an SSL3 Alert message - the server didn't like this session */
		*ver = MAKE_UINT16( data[1], data[2] );
	}
	else
	{
		rc = NM_ERROR( DSSL_E_SSL_UNKNOWN_VERSION );
	}

	return rc;
}


/* ========= ClientKeyExchange ========= */
int ssl3_decode_client_key_exchange( DSSL_Session* sess, u_char* data, uint32_t len )
{
	EVP_PKEY *pk = NULL;
	u_char* org_data = data;
	uint32_t org_len = len;
	int pms_len = 0;
	int rc = DSSL_RC_OK;

	if( sess->version < SSL3_VERSION || sess->version > TLS1_2_VERSION )
	{
		return NM_ERROR( DSSL_E_SSL_UNKNOWN_VERSION );
	}

	/* 
	TLS is different as it sends the record length, while SSL3 implementaions don't
	(due to a bug in Netscape implementation)
	*/
	
	if( !sess->master_secret[0] )
	{
		if( sess->version > SSL3_VERSION )
		{
			uint16_t recLen = 0;
			if( !IS_ENOUGH_LENGTH( org_data, org_len, data, 2 ) ) 
			{
				return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
			}

			recLen = MAKE_UINT16( data[0], data[1] );
			if( len != (uint32_t)recLen + 2 )
			{
				/*TODO: set an option to tolerate this bug?*/
				return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
			}

			/* advance */
			data += len - recLen;
			len = recLen;
		}

		if( !IS_ENOUGH_LENGTH( org_data, org_len, data, SSL_MAX_MASTER_KEY_LENGTH ) )
		{
			return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
		}
	}
	
	if( sess->ssl_si->pkey && !sess->master_secret[0] )
	{
		pk = ssls_get_session_private_key( sess );

		/* if SSL server key is not found, try to find a matching one from the key pool */
		if(pk == NULL) 
		{
			_ASSERT( sess->last_packet);
			pk = ssls_try_ssl_keys( sess, data, len );

			/* if a matching key found, register it with the server IP:port */
			if(pk != NULL)
			{
				if( ssls_register_ssl_key( sess, pk ) == DSSL_RC_OK)
				{
					/* ssls_register_ssl_key clones the key, query the key back */
					pk = ssls_get_session_private_key( sess );
				}
				else
				{
					pk = NULL;
				}
			}
		}

		if(!pk) 
		{
			ssls_register_missing_key_server( sess );
			return NM_ERROR( DSSL_E_SSL_SERVER_KEY_UNKNOWN );
		}

		if(EVP_PKEY_id( pk ) != EVP_PKEY_RSA) return NM_ERROR( DSSL_E_SSL_CANNOT_DECRYPT_NON_RSA );

		pms_len = RSA_private_decrypt( len, data, sess->PMS, EVP_PKEY_get0_RSA( pk ), RSA_PKCS1_PADDING );

		if( pms_len != SSL_MAX_MASTER_KEY_LENGTH )
		{
			return NM_ERROR( DSSL_E_SSL_CORRUPTED_PMS );
		}

		if( MAKE_UINT16( sess->PMS[0], sess->PMS[1] ) != sess->client_version )
		{
			return NM_ERROR( DSSL_E_SSL_PMS_VERSION_ROLLBACK );
		}

		rc = ssls_decode_master_secret( sess );
		OPENSSL_cleanse(sess->PMS, sizeof(sess->PMS) );
	}

	if( rc != DSSL_RC_OK ) return rc;

	rc = ssls_generate_keys( sess );
	if( rc == DSSL_RC_OK )
	{
		ssls_store_session( sess );
	}
	return rc;
}


static int ssl3_decode_dummy( DSSL_Session* sess, u_char* data, uint32_t len )
{
	//UNUSED_PARAM( sess );
	//UNUSED_PARAM( data );
	//UNUSED_PARAM( len );

	return DSSL_RC_OK;
}


/* ========== Server Certificate ========== */
static int ssl3_decode_server_certificate( DSSL_Session* sess, u_char* data, uint32_t len )
{
	X509 *x=NULL;
	uint32_t llen = 0;
	int rc = DSSL_RC_OK;

	if( !sess ) return NM_ERROR( DSSL_E_INVALID_PARAMETER );

	/* TBD: skip server certificate check if SSL key has not yet been mapped for this server */
	if( !sess->ssl_si ) return DSSL_RC_OK;

	if( !sess->ssl_si->pkey && !sess->master_secret[0]) return NM_ERROR( DSSL_E_UNINITIALIZED_ARGUMENT );

	if( len < 3 ) return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
	
	llen = MAKE_UINT24( data[0], data[1], data[2] );
	data+=3;
	if( llen + 3 != len || llen < 3 ) return NM_ERROR( DSSL_E_SSL_INVALID_CERTIFICATE_RECORD );

	llen = MAKE_UINT24( data[0], data[1], data[2] );
	data+=3;
	if( llen > len ) return NM_ERROR( DSSL_E_SSL_INVALID_CERTIFICATE_LENGTH );

	if( sess->ssl_si->pkey && !sess->master_secret[0] )
	{
		x = d2i_X509( NULL, (const u_char**)&data, llen );
		if( !x ) 
		{
			rc = NM_ERROR( DSSL_E_SSL_BAD_CERTIFICATE );
		}

		if( rc == DSSL_RC_OK && !X509_check_private_key(x, ssls_get_session_private_key( sess )) )
		{
			rc = NM_ERROR( DSSL_E_SSL_CERTIFICATE_KEY_MISMATCH );
		}

		if( x ) X509_free( x );
	}

	return rc;
}

static int ssl3_decode_new_session_ticket(DSSL_Session* sess, u_char* data, uint32_t len )
{
	uint16_t sz = 0;
	if(len < 6) return NM_ERROR(DSSL_E_SSL_INVALID_RECORD_LENGTH);

	sz = MAKE_UINT16(data[4], data[5]);

	if(len != sz + 6) return NM_ERROR(DSSL_E_SSL_PROTOCOL_ERROR);

	return ssls_store_new_ticket( sess, data + 6, sz );
}

/* ========== Finished, handshake digest routines ========== */
void ssl3_init_handshake_digests( DSSL_Session* sess )
{
	EVP_DigestInit_ex( sess->handshake_digest_md5, EVP_md5(), NULL );
	EVP_DigestInit_ex( sess->handshake_digest_sha, EVP_sha1(), NULL );

	if ( sess->version >= TLS1_2_VERSION )
	{
		EVP_MD* digest = NULL;
		DSSL_CipherSuite* suite = sess->dssl_cipher_suite;
		if ( !suite )
			suite = DSSL_GetSSL3CipherSuite( sess->cipher_suite );
		digest = (EVP_MD*)EVP_get_digestbyname( suite->digest );
		/* 'sha256' is the default for TLS 1.2 */
		if ( !digest )
			digest = (EVP_MD*)EVP_sha256();

		if ( digest )
			EVP_DigestInit_ex( sess->handshake_digest, digest, NULL );
	}
}

int ssl3_update_handshake_digests( DSSL_Session* sess, u_char* data, uint32_t len )
{
	DSSL_handshake_buffer *q = NULL, *next;

	/* sanity check in case client hello is not received */
	if( EVP_MD_CTX_md( sess->handshake_digest_md5 ) == NULL
		|| EVP_MD_CTX_md( sess->handshake_digest_sha ) == NULL)
	{
		ssl3_init_handshake_digests( sess );
	}
	EVP_DigestUpdate( sess->handshake_digest_md5, data, len );
	EVP_DigestUpdate( sess->handshake_digest_sha, data, len );
	
	if ( sess->version >= TLS1_2_VERSION )
	{
		/* if digest is still unknown, then queue the packets.
		 * we'll calculate the handshake hash once we determine which digest we should use.
		 */
		EVP_MD* digest = NULL;
		DSSL_CipherSuite* suite = sess->dssl_cipher_suite;
		if ( !suite ) {
			suite = DSSL_GetSSL3CipherSuite( sess->cipher_suite );
			if( !suite ) 
			{
				if( sess->version == TLS1_3_VERSION && sess->get_keys_rslt_data.set)
				{
					return DSSL_RC_OK;
				}
				else 
				{
					return DSSL_E_UNKNOWN_CIPHER_SUITE;
				}
			}
		}
		digest = (EVP_MD*)EVP_get_digestbyname( suite->digest );
		/* 'sha256' is the default for TLS 1.2, and can be replaced with a different (but stronger) hash */
		if ( !digest ) 
		{
			q = (DSSL_handshake_buffer*) malloc( sizeof(DSSL_handshake_buffer) );
			q->next = NULL;
			q->data = (u_char*) malloc( len );
			memcpy(q->data, data, len);
			q->len = len;
			
			if (NULL == sess->handshake_queue)
				sess->handshake_queue = q;
			else
				sess->handshake_queue->next = q;
			
			DEBUG_TRACE3( "Queue handshake packet %p (%u @ %p)", q, q->len, q->data );
		}
		else if ( digest != EVP_MD_CTX_md( sess->handshake_digest ) && EVP_MD_size( digest ) >= EVP_MD_size( EVP_MD_CTX_md( sess->handshake_digest ) ) ) 
		{
			/* specified digest is different than the default.
			 * re-init and re-hash all queued packets.
			 */
			EVP_MD_CTX_reset( sess->handshake_digest );
			EVP_DigestInit_ex( sess->handshake_digest, digest, NULL );
			for (q = sess->handshake_queue; q != NULL; q = next)
			{
				DEBUG_TRACE3( "Re-hash handshake packet %p (%u @ %p)", q, q->len, q->data );
				EVP_DigestUpdate( sess->handshake_digest, q->data, q->len );
				next = q->next;
				free ( q->data );
				free ( q );
			}
			sess->handshake_queue = NULL;
		}
		else 
		{
			/* specified digest is identical to the default.
			 * throw away all the queued packets.
			 */
			for (q = sess->handshake_queue; q != NULL; q = next)
			{
				DEBUG_TRACE3( "discard handshake packet %p (%u @ %p)", q, q->len, q->data );
				next = q->next;
				free ( q->data );
				free ( q );
			}
			sess->handshake_queue = NULL;
		}
		
		if ( EVP_MD_CTX_md( sess->handshake_digest ) )
			EVP_DigestUpdate( sess->handshake_digest, data, len );
	}
	return(DSSL_RC_OK);
}


/* ========== Handshake decoding function ========== */
int ssl3_decode_handshake_record( dssl_decoder_stack* stack, NM_PacketDir dir,
								 u_char* data, uint32_t len, uint32_t* processed )
{
	int rc = DSSL_E_UNSPECIFIED_ERROR;
	uint32_t recLen = 0;
	u_char hs_type = 0;
	u_char* org_data = data;
	DSSL_Session* sess = stack->sess;
	_ASSERT( processed != NULL );
	_ASSERT((sess->flags & SSF_SSLV2_CHALLENGE) == 0);

	if( sess->version == 0 )
	{
		return ssl_decode_first_client_hello( sess, data, len, processed );
	}

	if( len < SSL3_HANDSHAKE_HEADER_LEN ) return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );

	DEBUG_TRACE_BUF("handshake", data, len);
	recLen = (((int32_t)data[1]) << 16) | (((int32_t)data[2]) << 8) | data[3];
	hs_type = data[0];
	
	if(!recLen && !hs_type) {
		*processed = len;
		return DSSL_RC_OK;
	}

	data += SSL3_HANDSHAKE_HEADER_LEN;
	len -= SSL3_HANDSHAKE_HEADER_LEN;

	if( len < recLen )return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );

#ifdef NM_TRACE_SSL_HANDSHAKE
	DEBUG_TRACE2( "===>Decoding SSL v3 handshake: %s len: %d...", SSL3_HandshakeTypeToString( hs_type ), (int) recLen );
#endif

	if(stack->sess->handshake_data && 
	   (stack->sess->flags & (SSF_TLS_CLIENT_EXTENDED_MASTER_SECRET|SSF_TLS_SERVER_EXTENDED_MASTER_SECRET)) &&
	   hs_type != SSL3_MT_CERTIFICATE_VERIFY)
	{
		ssls_handshake_data_append(sess, data - SSL3_HANDSHAKE_HEADER_LEN, recLen + SSL3_HANDSHAKE_HEADER_LEN);
	}

	switch( hs_type )
	{
	case SSL3_MT_HELLO_REQUEST:
		rc = ssl3_decode_dummy( sess, data, recLen );
		break;

	case SSL3_MT_CLIENT_HELLO:
		rc = ssl3_decode_client_hello( sess, data, recLen );
		break;

	case SSL3_MT_SERVER_HELLO:
		stack->state = SS_SeenServerHello;
		rc = ssl3_decode_server_hello( sess, data, recLen );
		break;

	case SSL3_MT_CERTIFICATE:
		if( sess->version == TLS1_3_VERSION && sess->get_keys_rslt_data.set )
		{
			rc = ssl3_decode_dummy( sess, data, recLen );
		}
		else if( dir == ePacketDirFromServer )
		{
			rc = ssl3_decode_server_certificate( sess, data, recLen );
		}
		else
		{
			rc = ssl3_decode_dummy( sess, data, recLen );
		}
		break;

	case SSL3_MT_SERVER_DONE:
		rc = ssl3_decode_dummy( sess, data, recLen );
		break;

	case SSL3_MT_CLIENT_KEY_EXCHANGE:
		if( sess->version == TLS1_3_VERSION && sess->get_keys_rslt_data.set )
		{
			rc = ssl3_decode_dummy( sess, data, recLen );
		} 
		else
		{
			rc = ssl3_decode_client_key_exchange( sess, data, recLen );
		}
		break;

	case SSL3_MT_FINISHED:
		rc = (*sess->decode_finished_proc)( sess, dir, data, recLen );
		if( rc == DSSL_RC_OK ) {
			stack->state = SS_Established;
			ssls_handshake_done( sess );
		}
		break;
		
	case SSL3_MT_CERTIFICATE_STATUS:
		rc = ssl3_decode_dummy( sess, data, recLen );
		break;
	
	case SSL3_MT_SERVER_KEY_EXCHANGE:
		/*at this point it is clear that the session is not decryptable due to ephemeral keys usage.*/
		if( sess->master_secret[0] || (sess->version == TLS1_3_VERSION && sess->get_keys_rslt_data.set) ) 
		{
			rc = ssl3_decode_dummy( sess, data, recLen );
		}
		else
		{
			rc = NM_ERROR( DSSL_E_SSL_CANNOT_DECRYPT_EPHEMERAL );
		}
		break;

	case SSL3_MT_CERTIFICATE_REQUEST:
		/* TODO: track CertificateRequest- client certificate / certificate verify */
		rc = ssl3_decode_dummy( sess, data, recLen );
		break;

	case SSL3_MT_CERTIFICATE_VERIFY:
		/* TODO: track CertificateRequest- client certificate / certificate verify */
		rc = ssl3_decode_dummy( sess, data, recLen );
		break;

	case SSL3_MT_NEWSESSION_TICKET:
		rc = ssl3_decode_new_session_ticket( sess, data, recLen );
		break;

	default:
		rc = NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );
		break;
	}

	if( rc == DSSL_RC_OK )
	{
		*processed = recLen + SSL3_HANDSHAKE_HEADER_LEN;

		if( hs_type == SSL3_MT_CLIENT_HELLO ) 
		{
			ssl3_init_handshake_digests( sess );
		}

		if( hs_type != SSL3_MT_HELLO_REQUEST )
		{
			rc = ssl3_update_handshake_digests( sess, org_data, *processed );
		}
	}

#ifdef NM_TRACE_SSL_HANDSHAKE
	if( rc == DSSL_RC_OK )
	{
		DEBUG_TRACE0( "OK\n" );
	}
	else
	{
		DEBUG_TRACE1( "Error! (%d)\n", (int)rc );
	}
#endif

	return rc;
}

void ssls_handshake_done( DSSL_Session* sess )
{
	/*  at this point we can safely conclude that the SSL key 
	is working fine, so clear the 'test key' flag, if set  */
	if(sess->flags & SSF_TEST_SSL_KEY && sess->c_dec.state == SS_Established 
		&& sess->s_dec.state == SS_Established)
	{
		sess->flags &= ~SSF_TEST_SSL_KEY;
		_ASSERT(sess->ssl_si);
		if(sess->event_callback && sess->ssl_si)
		{
			(*sess->event_callback)( sess->user_data, eSslMappingDiscovered, sess->ssl_si );
		}
	}

	if( sess->event_callback && sess->c_dec.state == SS_Established && sess->s_dec.state == SS_Established )
	{
		struct timeval t = sess->last_packet->pcap_header.ts;

		t.tv_sec -= sess->handshake_start.tv_sec;

		if(t.tv_usec < sess->handshake_start.tv_usec)
		{
			--t.tv_sec;
			t.tv_usec = t.tv_usec  + 1000000 - sess->handshake_start.tv_usec;
		}
		else
		{
			t.tv_usec -= sess->handshake_start.tv_usec;
		}
		(*sess->event_callback)( sess->user_data, eSslHandshakeComplete, &t );
	}
	
	if(sess->handshake_data)
	{
		ssls_handshake_data_free(sess);
	}
}
