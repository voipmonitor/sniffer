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
#ifndef __DSSL_SESSION_H__
#define __DSSL_SESSION_H__

#include "dssl_defs.h"
#include "stream.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* TCP Session object */
struct _TcpSession
{
	/* Session type - TCP/SSL/Null */
	NM_SessionType		type;
	/* session TCP stream objects */
	TcpStream			clientStream;
	TcpStream			serverStream;
	/* next session in chain (used in session hash table)*/
	struct _TcpSession*	next;
	/* session closure flag */
	int					closing;
	/* callback routines for data and error processing */
	DataCallbackProc	data_callback;
	ErrorCallbackProc	error_callback;
	EventCallbackProc	event_callback;
	void*				user_data;
	/* current packet timestamp (taken from the packet's header) */
	struct timeval		packet_time;		
	/* last session activity time */
	time_t				last_update_time; 
	/* reassembled packet callback */
	int (*OnNewPacket)( struct _TcpStream* stream, DSSL_Pkt* pkt );
	/* corresponding SSL session struct (SSL session type only) */
	struct DSSL_Session_*	ssl_session;
	/* parent capture environment */
	CapEnv*				env;
	/* missing packets handling */
	int							missing_packet_timeout; /**/
	uint32_t					missing_packet_count;
	MissingPacketCallbackProc	missing_callback;
	/* packet callback */
	PacketCallbackProc		packet_callback;
};

/* formats an ip:port parameters as a string into buff */
void AddressToString( uint32_t ip, uint16_t port, char* buff );

/* formats the session as a "ip:port<->ip:port" string */
const char* SessionToString( TcpSession* sess, char* buff );

/* Init/Free session */
int SessionInit( CapEnv* env, TcpSession* s, DSSL_Pkt* pkt, NM_SessionType s_type );
void SessionFree( TcpSession* s );

NM_PacketDir SessionGetPacketDirection(const TcpSession* sess, const DSSL_Pkt* pkt );

/* packet processing entry point */
void SessionProcessPacket( struct CapEnv_* env, DSSL_Pkt* pkt );

/* updates the last activity time (set it to current time) */
void TouchSession( TcpSession* s );

/*Get/Set session callbacks, user data */
void SessionSetCallback( TcpSession* sess, DataCallbackProc data_callback, 
			ErrorCallbackProc error_callback, PacketCallbackProc packet_callback, void* user_data );

void SessionSetMissingPacketCallback( TcpSession* sess, MissingPacketCallbackProc missing_callback,
			int missing_packet_count, int timeout_sec );

void SessionSetEventCallback( TcpSession* sess, EventCallbackProc event_callback );

void SessionSetUserData( TcpSession* sess, void* data );
void* SessionGetUserData( const TcpSession* sess );

/* */
void SessionFlushPacketQueue( TcpSession* sess );

int IsNewTcpSessionPacket( const DSSL_Pkt* pkt );

#ifdef  __cplusplus
}
#endif

#endif
