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
#ifndef __DSSL_CAPENV_H__
#define __DSSL_CAPENV_H__

#include "session_table.h"
#include "ssl_ctx.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct CapEnv_;

/**
	CapEnvSessionCallback: a callback interface for TCP session events (new session / session closure)
*/
#define DSSL_EVENT_NEW_SESSION			0
#define DSSL_EVENT_SESSION_CLOSING		1
#define DSSL_EVENT_SESSION_LIMIT		2

typedef void (*CapEnvSessionCallback)( struct CapEnv_* env, TcpSession* sess, char event );

/**
	CapEnvDatagramCallback: a callback interface for UDP packets
*/
typedef void (*CapEnvDatagramCallback)( struct CapEnv_* env, const u_char* data, uint32_t len, DSSL_Pkt* pkt );

/* Packet capture environment */
struct CapEnv_
{
	pcap_t*				pcap_adapter;
    pcap_handler        handler;
	
	dssl_SessionTable*	sessions;
	DSSL_Env*			ssl_env;

/*  
	ForReassemble: return on of NM_SessionType constants. 
	eSessionTypeNull tells DSSL to ignore the packet
	Note: pkt->tcp_header must be initialized before calling this function!
*/
	NM_SessionType (*ForReassemble)( struct CapEnv_* env, DSSL_Pkt* pkt );
	
	/* called when a new session is created before it is added to the session table */
	CapEnvSessionCallback	session_callback;

	/* called for UDP datagrams when UPD packet processing is enabled */
	CapEnvDatagramCallback	datagram_callback;
	void* env_user_data;
#ifdef NM_TRACE_FRAME_COUNT
	uint32_t				frame_cnt; /* frame count; for debugging */
#endif
};


CapEnv* CapEnvCreate( pcap_t* adapter, int sessionTableSize, uint32_t key_timeout_interval, uint32_t tcp_timeout_interval, uint32_t cleanup_interval);
void CapEnvDestroy( CapEnv* env );

/* TODO: add the default session data callback that will be used when no OnNewSession callback is set */
void CapEnvSetSessionCallback( CapEnv* env, CapEnvSessionCallback callback, void* user_data );

/* CapEnvSetDatagramCallback - enables UDP packets processing and sets UDP callback routine */
void CapEnvSetDatagramCallback( CapEnv* env, CapEnvDatagramCallback callback );

void* CapEnvGetUserData( CapEnv* env );

#ifndef DSSL_NO_PCAP
/* run pcap_loop on environment's pcap adapter; return value is the same as for pcap_loop call */
int CapEnvCapture( CapEnv* env );
#endif

/* Single-server version of setting up the DSSL_ServerInfo table struct for given CapEnv. 
	Returns 0 if successful, non-zero error code (DSSL_E_OUT_OF_MEMORY) otherwise. */
int CapEnvSetSSL_ServerInfo( CapEnv* env, const struct in_addr* ip_address, uint16_t port, 
			const char* keyfile, const char* password );

/* Single-server version of setting up the DSSL_ServerInfo table struct for given CapEnv. 
	Returns 0 if successful, non-zero error code (DSSL_E_OUT_OF_MEMORY) otherwise.
	This function "steals" the pkey pointer to an existing private key. */
int CapEnvSetSSL_ServerInfoWithKey( CapEnv* env, const struct in_addr* ip_address, uint16_t port, 
			EVP_PKEY *pkey );

/* Add a known private key */
int CapEnvAddSSLKey( CapEnv* env, EVP_PKEY* pkey);

DSSL_ServerInfo* CapEnvFindDSSL_ServerInfo( const CapEnv* env, const struct in_addr* server_ip, uint16_t server_port );

/**
CapEnvIsSSLPacket: return 1 if there is an SSL server registered at packet's src or dst address/port; 
				   0 otherwise 
*/
int CapEnvIsSSLPacket( const CapEnv* env, const DSSL_Pkt* pkt );

/** CapEnvProcessPacket: main (TCP) packet processing routine*/
void CapEnvProcessPacket( CapEnv* env, DSSL_Pkt* pkt );

/** CapEnvProcessDatagram: main (UDP) packet processing routine */
void CapEnvProcessDatagram( CapEnv* env, const uint8_t* data, uint32_t len, DSSL_Pkt* pkt );

/** CapEnvGetMemoryUsage: reports memory usage 
	@param sess_cnt: count of TCP sessions currently in the session table
	@param ssl_sess_cnt: count of SSL session keys stored in SSL session cache
	@param packet_cache_cnt: number of TCP packets in TCP reassembly 
	@param packet_cache_size: total size of TCP data payload (in bytes) that TCP reassembly cache carries
	@param server_count: total number of SSL servers for which decryption was successful
	@param missing_key_server_count: total number of SSL servers with missing RSA keys
	@param key_count: total number of SSL keys
*/
void CapEnvGetMemoryUsage( const CapEnv* env, uint32_t* sess_cnt,
	uint32_t* ssl_sess_cnt, uint32_t* packet_cache_cnt, uint64_t* packet_cache_size,
	uint32_t* server_count, uint32_t* missing_key_server_count, uint32_t* key_count);

/**
 CapEnvGetMaxSessionCount: returns max TCP session count, or 0 if unlimited
*/
int CapEnvGetMaxSessionCount( const CapEnv* env );

/**
	CapEnvSetMaxSessionCount: sets a limit of concurrently opened TCP sessions
	@param cnt: max number of concurrent TCP sessions, or 0 if unlimited
*/
void CapEnvSetMaxSessionCount( CapEnv* env, int cnt);

/**
CapEnvGetMaxReassemblyPacketCount: returns the max number of packets in all sessions' reassembly queues, or 0 if unlimited
*/
int CapEnvGetMaxReassemblyPacketCount( const CapEnv* env );

/* CapEnvSetMaxReassemblyPacketCount: sets max number of packets in all sessions' reassembly queues, or 0 if unlimited */
void CapEnvSetMaxReassemblyPacketCount( CapEnv* env, int cnt );
#ifdef  __cplusplus
}
#endif

#endif
