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
#ifndef __DSSL_SSL_SESSION_H__
#define __DSSL_SSL_SESSION_H__

#include "ssl_ctx.h"
#include "decoder_stack.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct DSSL_handshake_buffer_
{
	DSSL_handshake_buffer*	next;
	
	u_char*					data;
	uint32_t				len;
};

/* session flags */
/* SSF_CLIENT_SESSION_ID_SET means that ClientHello message contained non-null session id field */
#define SSF_CLIENT_SESSION_ID_SET		0x0001
#define SSF_CLOSE_NOTIFY_RECEIVED		0x0002		
#define SSF_FATAL_ALERT_RECEIVED		0x0004
/* this session uses auto-mapped SSL key */
#define SSF_TEST_SSL_KEY				0x0008
/* this session has SSL v2 CLIENT-HELLO message */
#define SSF_SSLV2_CHALLENGE				0x0010
/* RFC 5077 TLS Session Ticket */
#define SSF_TLS_SESSION_TICKET_SET		0x0020
#define SSF_TLS_SERVER_SESSION_TICKET	0x0040

#define SSF_TLS_CLIENT_EXTENDED_MASTER_SECRET	0x0100
#define SSF_TLS_SERVER_EXTENDED_MASTER_SECRET	0x0200


struct DSSL_Session_get_keys_data_item
{	u_char 				key[SSL3_MASTER_SECRET_SIZE];
	unsigned 			length;
};

struct DSSL_Session_get_keys_data
{
	struct DSSL_Session_get_keys_data_item client_random;
	struct DSSL_Session_get_keys_data_item client_handshake_traffic_secret;
	struct DSSL_Session_get_keys_data_item server_handshake_traffic_secret;
	struct DSSL_Session_get_keys_data_item exporter_secret;
	struct DSSL_Session_get_keys_data_item client_traffic_secret_0;
	struct DSSL_Session_get_keys_data_item server_traffic_secret_0;
	int 				set;
};

struct DSSL_Session_
{
	DSSL_Env*			env;

	uint16_t			version;		/* negotiated session version */
	uint16_t			client_version; /* actual client version */
	
	/* decoders */
	dssl_decoder_stack	c_dec; /* client-to-server stream decoder*/
	dssl_decoder_stack	s_dec; /* server-to-client stream decoder */

	u_char				client_random[SSL3_RANDOM_SIZE]; /* challenge for SSL 2*/
	u_char				server_random[SSL3_RANDOM_SIZE]; /* connection-id for SSL 2 */

	u_char				PMS[SSL_MAX_MASTER_KEY_LENGTH];
	u_char				master_secret[SSL3_MASTER_SECRET_SIZE];

	#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	u_char				ssl2_key_arg[SSL2_KEYARG_MAX_LEN];
	#endif //(OPENSSL_VERSION_NUMBER < 0x10100000L)

	u_char				session_id[DSSL_SESSION_ID_SIZE];
	uint32_t			flags;
	
	DSSL_ServerInfo*	ssl_si;

	uint16_t			cipher_suite;
	
	#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	uint16_t			ssl2_key_arg_len;
	#endif //(OPENSSL_VERSION_NUMBER < 0x10100000L)

	u_char				compression_method;

	EVP_MD_CTX			*handshake_digest_sha;
	EVP_MD_CTX			*handshake_digest_md5;
	EVP_MD_CTX			*handshake_digest;

	int (*decode_finished_proc)( struct DSSL_Session_* sess, NM_PacketDir dir, u_char* data, uint32_t len );
	int (*caclulate_mac_proc)( dssl_decoder_stack* stack, u_char type, u_char* data, 
								uint32_t len, u_char* mac );

	/* callbacks and user-defined state */
	DataCallbackProc	data_callback;
	ErrorCallbackProc	error_callback;
	EventCallbackProc	event_callback;
	void*				user_data;

	/* SSL 2.0 specific data */
	uint32_t			client_challenge_len; /* CHALLENGE-LENGTH */
	uint32_t			server_connection_id_len; /* CONNECTION-ID-LENGTH */
	uint32_t			master_key_len;

	/* metrics */
	struct timeval		handshake_start;

	/* last packet being processed (passed from TCP layer) */
	DSSL_Pkt*			last_packet;

	u_char*				session_ticket; /* TLS session ticket */
	uint32_t			session_ticket_len; /* TLS session ticket length */
	
	DSSL_CipherSuite*	dssl_cipher_suite;
	int					cipher_mode;
	
	DSSL_handshake_buffer* handshake_queue;
	
	void 			*handshake_data;
	uint32_t		handshake_data_size;
	
	int (*get_keys_fce)(u_char *client_random, struct DSSL_Session_get_keys_data *get_keys_data, DSSL_Session *session);
	void *get_keys_fce_call_data[2];
	struct DSSL_Session_get_keys_data get_keys_rslt_data;
	
	int ignore_error_invalid_mac;
	int ignore_error_bad_finished_digest;
	
	void *tls_session;
	uint64_t tls_session_server_seq;
	uint64_t tls_session_client_seq;
	
};


void DSSL_SessionInit( DSSL_Env* env, DSSL_Session* s, DSSL_ServerInfo* si );
void DSSL_SessionDeInit( DSSL_Session* s );

void DSSL_SessionSetCallback( DSSL_Session* sess, DataCallbackProc data_callback, 
		ErrorCallbackProc error_callback, void* user_data );

void DSSL_SessionSetEventCallback(DSSL_Session* sess, EventCallbackProc proc);

/**
	DSSL_SessionProcessData:  Decodes captured network SSL session data
	dir - data (stream) direction
	{data, len} input should be a chunk of the reassembled TCP stream data.

	Deciphered SSL payload will be returned through the session data callback
	routine (see DSSL_SessionSetCallback)
*/
int DSSL_SessionProcessData( DSSL_Session* sess, NM_PacketDir dir, u_char* data, uint32_t len );

/* TODO: move to ssl_session_priv.h */
/* Internal routines */

EVP_PKEY* ssls_get_session_private_key( DSSL_Session* sess );
int ssls_decode_master_secret( DSSL_Session* sess );
int ssls_generate_keys( DSSL_Session* sess );
int ssls2_generate_keys( DSSL_Session* sess, u_char* keyArg, uint32_t keyArgLen );
int ssls_set_session_version( DSSL_Session* sess, uint16_t ver );

int ssls_get_decrypt_buffer( DSSL_Session* sess, u_char** data, uint32_t len );
void ssls_release_decrypt_buffer( DSSL_Session* sess );

int ssls_get_decompress_buffer( DSSL_Session* sess, u_char** data, uint32_t len );
void ssls_release_decompress_buffer( DSSL_Session* sess );

int ssls_lookup_session( DSSL_Session* sess );
void ssls_store_session( DSSL_Session* sess );
void ssls_handshake_done( DSSL_Session* sess );
EVP_PKEY* ssls_try_ssl_keys( DSSL_Session* sess, u_char* data, uint32_t len);
int ssls_register_ssl_key( DSSL_Session* sess,EVP_PKEY* pk );
void ssls_register_missing_key_server(DSSL_Session* sess);

void ssls_free_extension_data(DSSL_Session* sess);

int ssls_init_from_tls_ticket( DSSL_Session* sess );
int ssls_store_new_ticket(DSSL_Session* sess, u_char* ticket, uint32_t len);

void ssls_handshake_data_append(DSSL_Session* sess, u_char* data, uint32_t len);
void ssls_handshake_data_free(DSSL_Session* sess);
void ssls_handshake_queue_free(DSSL_Session* sess);

#ifdef  __cplusplus
}
#endif

#endif
