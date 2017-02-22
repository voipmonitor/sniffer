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
#include "capenv.h"
#include "decode.h"
#include "ssl_ctx.h"
#include "ssl_sessionkey_table.h"

int CapEnvIsSSLPacket( const CapEnv* env, const DSSL_Pkt* pkt )
{
	uint16_t port = PKT_TCP_DPORT( pkt );

	/* check if the destination ip:port is in the SSL server list */
	if( CapEnvFindDSSL_ServerInfo( env, &pkt->ip_header->ip_dst, port ) ) 
		return 1;
	
	/* check if the source ip:port is in the SSL server list */
	port = PKT_TCP_SPORT( pkt );
	if( CapEnvFindDSSL_ServerInfo( env, &pkt->ip_header->ip_src, port ) ) 
		return 1;

	return 0;
}

int CapEnvIsMissingKeyServerPacket( const CapEnv* env, const DSSL_Pkt* pkt )
{
	uint16_t port = PKT_TCP_DPORT( pkt );

	if(env->ssl_env == NULL) return 0;

	/* check if the destination ip:port is in the SSL server black list */
	if( DSSL_EnvIsMissingKeyServer( env->ssl_env, pkt->ip_header->ip_dst, port ) ) 
		return 1;
	
	/* check if the source ip:port is in the SSL server black list */
	port = PKT_TCP_SPORT( pkt );
	if( DSSL_EnvIsMissingKeyServer( env->ssl_env, pkt->ip_header->ip_src, port ) ) 
		return 1;

	return 0;
}

/* TODO: make it configurable */
NM_SessionType _CaptureEnv_ForReassemble( struct CapEnv_* env, struct DSSL_Pkt_* pkt )
{
	if( CapEnvIsSSLPacket( env, pkt ) ) return eSessionTypeSSL;

	if( CapEnvIsMissingKeyServerPacket( env, pkt )) return eSessionTypeSSL;

	return eSessionTypeTBD;
}


CapEnv* CapEnvCreate( pcap_t* adapter, int sessionTableSize, uint32_t key_timeout_interval, uint32_t tcp_timeout_interval, uint32_t cleanup_interval)
{
	CapEnv* env;

	if( key_timeout_interval == 0 ) key_timeout_interval = 60*60;
	if( tcp_timeout_interval == 0 ) tcp_timeout_interval = 180;
	if( cleanup_interval == 0 ) cleanup_interval = 300;

	env = (CapEnv*) malloc( sizeof(CapEnv) );
	memset( env, 0, sizeof(*env) );

	env->pcap_adapter = adapter;

#ifndef DSSL_NO_PCAP
	if( env->pcap_adapter != NULL )
	{
		env->handler = GetPcapHandler( env->pcap_adapter );
	}
#else
	_ASSERT( env->pcap_adapter == NULL );
#endif

	env->ForReassemble = _CaptureEnv_ForReassemble;
    
	env->sessions = CreateSessionTable( sessionTableSize, tcp_timeout_interval, cleanup_interval );
	env->sessions->env = env;
	env->session_callback = NULL;
	env->env_user_data = NULL;

	env->ssl_env = DSSL_EnvCreate( sessionTableSize, key_timeout_interval );

	return env;
}


void CapEnvDestroy( CapEnv* env )
{
	DestroySessionTable( env->sessions );

	if( env->ssl_env ) 
	{
		DSSL_EnvDestroy( env->ssl_env );
		env->ssl_env = NULL;
	}

	free( env );
}

#ifndef DSSL_NO_PCAP
/* run pcap_loop on environment's pcap adapter */
int CapEnvCapture( CapEnv* env )
{
	if( env->pcap_adapter == NULL || env->handler == NULL ) return -1;
    return pcap_loop( env->pcap_adapter, -1, env->handler, (u_char*) env );
}
#endif

static int NewSessionPacket( const DSSL_Pkt* pkt, NM_SessionType s_type )
{
	switch( s_type )
	{
	case eSessionTypeTcp:
	case eSessionTypeSSL:
	case eSessionTypeTBD:
		return IsNewTcpSessionPacket( pkt );
	case eSessionTypeNull:
		return 0;
	}

	_ASSERT( 0 ); 
	return 0;
}

/* Packet processing routine*/
void CapEnvProcessPacket( CapEnv* env, DSSL_Pkt* pkt )
{
	NM_SessionType s_type = env->ForReassemble( env, pkt );

	/* Check if this packet is to be reassembled / decoded*/
	if( s_type == eSessionTypeNull ) return;

	/* Lookup an existing session */
	pkt->session = env->sessions->FindSession( env->sessions, pkt );

	/* No session found, try creaing a new one */
	if( !pkt->session && NewSessionPacket( pkt, s_type ) ) 
	{
		pkt->session = env->sessions->CreateSession( env->sessions, pkt, s_type );
	}
	if( pkt->session ) SessionProcessPacket( env, pkt );
}

void CapEnvProcessDatagram( CapEnv* env, const uint8_t* data, uint32_t len, DSSL_Pkt* pkt )
{
	if(env->datagram_callback ) { env->datagram_callback( env, data, len, pkt ); }
}

int CapEnvSetSSL_ServerInfo( CapEnv* env, const struct in_addr* ip_address, uint16_t port, 
			const char* keyfile, const char* password )
{
	if( env->ssl_env == NULL ) return NM_ERROR( DSSL_E_UNINITIALIZED_ARGUMENT );

	return DSSL_EnvSetServerInfo( env->ssl_env, ip_address, port, keyfile, password );
}


int CapEnvSetSSL_ServerInfoWithKey( CapEnv* env, const struct in_addr* ip_address, uint16_t port, 
			EVP_PKEY *pkey )
{
	if( env->ssl_env == NULL ) return NM_ERROR( DSSL_E_UNINITIALIZED_ARGUMENT );

	return DSSL_EnvSetServerInfoWithKey( env->ssl_env, ip_address, port, pkey );
}


void CapEnvSetSessionCallback( CapEnv* env, CapEnvSessionCallback callback, void* user_data )
{
	_ASSERT( env );
	
	env->session_callback = callback;
	env->env_user_data = user_data;
}

void CapEnvSetDatagramCallback( CapEnv* env, CapEnvDatagramCallback callback )
{
	_ASSERT( env );

	env->datagram_callback = callback;
}

void* CapEnvGetUserData( CapEnv* env )
{
	_ASSERT( env );
	return env->env_user_data;
}


DSSL_ServerInfo* CapEnvFindDSSL_ServerInfo( const CapEnv* env, 
		const struct in_addr* server_ip, uint16_t server_port )
{
	if( env->ssl_env ) 
		return DSSL_EnvFindServerInfo( env->ssl_env, *server_ip, server_port );
	else
		return NULL;
}


void CapEnvGetMemoryUsage( const CapEnv* env, uint32_t* sess_cnt,
						  uint32_t* ssl_sess_cnt, uint32_t* packet_cache_cnt,
						  uint64_t* packet_cache_size, uint32_t* server_count,
						  uint32_t* missing_key_server_count, uint32_t* key_count)
{
	_ASSERT(env);

	if(sess_cnt) *sess_cnt = env->sessions->sessionCount;
	if(ssl_sess_cnt) *ssl_sess_cnt = env->ssl_env->session_cache->count;
	if(packet_cache_cnt) *packet_cache_cnt = env->sessions->packet_cache_count;
	if(packet_cache_size) *packet_cache_size = env->sessions->packet_cache_mem;
	if (env->ssl_env) {
		if (server_count) *server_count = env->ssl_env->server_count;
		if (missing_key_server_count) *missing_key_server_count = env->ssl_env->missing_key_server_count;
		if (key_count) *key_count = env->ssl_env->key_count;
	} else {
		if (server_count) *server_count = 0;
		if (missing_key_server_count) *missing_key_server_count = 0;
		if (key_count) *key_count = 0;
	}
}

int CapEnvAddSSLKey( CapEnv* env, EVP_PKEY* pkey )
{
	if( env->ssl_env ) 
		return DSSL_AddSSLKey( env->ssl_env, pkey );
	else
		return NM_ERROR(DSSL_E_NOT_IMPL);
}

int CapEnvGetMaxSessionCount( const CapEnv* env )
{
	_ASSERT(env && env->sessions);
	return env->sessions->maxSessionCount;
}

void CapEnvSetMaxSessionCount( CapEnv* env, int cnt)
{
	_ASSERT(env && env->sessions);
	_ASSERT( cnt >= 0);

	env->sessions->maxSessionCount = cnt;
}

int CapEnvGetMaxReassemblyPacketCount( const CapEnv* env )
{
	_ASSERT(env && env->sessions);
	return env->sessions->maxCachedPacketCount;
}

void CapEnvSetMaxReassemblyPacketCount( CapEnv* env, int cnt )
{
	_ASSERT(env && env->sessions);
	_ASSERT( cnt >= 0);

	env->sessions->maxCachedPacketCount = cnt;
}
