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
#include "capenv.h"
#include "fnv_hash.h"
#include "ssl_session.h"
#include "ssl_decode_hs.h"

/* Local prototypes */
static int OnNewPlainTextPacket( TcpStream* stream, DSSL_Pkt* pkt );
static int OnNewSSLPacket( TcpStream* stream, DSSL_Pkt* pkt );
static void SessionInitDecoders( TcpSession* sess, DSSL_Pkt* pkt );
static int DetectSessionTypeCallback(struct _TcpStream* stream, DSSL_Pkt* pkt );

void AddressToString( uint32_t ip_addr, uint16_t port, char* buff )
{
	uint32_t ip = ntohl(ip_addr);
	sprintf( buff, "%d.%d.%d.%d:%d",
		((ip >> 24)), ((ip >> 16) & 0xFF),
		((ip >> 8) & 0xFF), (ip & 0xFF),
		(int) port );
}

const char* SessionToString( TcpSession* sess, char* buff )
{
	char addr1[32], addr2[32];

	addr1[0] = 0;
	addr2[0] = 0;

	AddressToString( sess->serverStream.ip_addr, sess->serverStream.port, addr1 );
	AddressToString( sess->clientStream.ip_addr, sess->clientStream.port, addr2 );

	sprintf( buff, "%s<->%s", addr1, addr2 );
	return buff;
}

NM_PacketDir SessionGetPacketDirection( const TcpSession* sess,  const DSSL_Pkt* pkt)
{
	uint32_t ip1, ip2;
	uint16_t port1, port2;

	_ASSERT( sess );
	_ASSERT( pkt );

	_ASSERT( pkt->ip_header );
	_ASSERT( pkt->tcp_header );

	ip1 = INADDR_IP( pkt->ip_header->ip_src );
	ip2 = INADDR_IP( pkt->ip_header->ip_dst );

	port1 = PKT_TCP_SPORT( pkt );
	port2 = PKT_TCP_DPORT( pkt );

	if( sess->clientStream.ip_addr == ip1 && sess->serverStream.ip_addr == ip2 && 
		sess->clientStream.port == port1 && sess->serverStream.port == port2 )
	{
		return ePacketDirFromClient;
	} 
	else if( sess->clientStream.ip_addr == ip2 && sess->serverStream.ip_addr == ip1 &&
			sess->clientStream.port == port2 && sess->serverStream.port == port1 )
	{
		return ePacketDirFromServer;
	}
	else
	{
		return ePacketDirInvalid;
	}
}


int SessionInit( CapEnv* env, TcpSession* sess, DSSL_Pkt* pkt, NM_SessionType s_type )
{
	//int is_server = 0;
	_ASSERT( pkt );

	/* zero init first */
	memset( sess, 0, sizeof(*sess) );

	/* init session's last update timestamp */
	TouchSession(sess);

	sess->type = s_type;
	if( s_type != eSessionTypeSSL && s_type != eSessionTypeTcp
		&& s_type != eSessionTypeTBD ) return NM_ERROR( DSSL_E_INVALID_PARAMETER );

	sess->env = env;

	/* init session's TCP streams */
	switch( pkt->tcp_header->th_flags & ~(TH_ECNECHO | TH_CWR) )
	{
	case TH_SYN:
		StreamInit( &sess->clientStream, sess,
			INADDR_IP( pkt->ip_header->ip_src ), PKT_TCP_SPORT( pkt ) );
		StreamInit( &sess->serverStream, sess, 
			INADDR_IP( pkt->ip_header->ip_dst ), PKT_TCP_DPORT( pkt ) );

		//is_server = 0;
		break;

	case TH_SYN | TH_ACK:
		StreamInit( &sess->serverStream, sess, 
			INADDR_IP( pkt->ip_header->ip_src ), PKT_TCP_SPORT( pkt ) );
		StreamInit( &sess->clientStream, sess,
			INADDR_IP( pkt->ip_header->ip_dst ), PKT_TCP_DPORT( pkt ) );

		//is_server = 1;
		break;

	default:
		StreamInit( &sess->serverStream, sess, 
			INADDR_IP( pkt->ip_header->ip_src ), PKT_TCP_SPORT( pkt ) );
		StreamInit( &sess->clientStream, sess, 
			INADDR_IP( pkt->ip_header->ip_dst ), PKT_TCP_DPORT( pkt ) );

		/* 
		This connection has already been established. Can't reassemble the SSL session from the middle,
		hence ignore this session.
		*/
		if( sess->type == eSessionTypeSSL ) 
		{
#ifdef NM_TRACE_SSL_SESSIONS
			char _trace_buff[1024];
			DEBUG_TRACE1( "\n==>Can't reassemble the SSL session from the middle, dropping: %s", SessionToString(sess, _trace_buff) );
#endif
			sess->type = eSessionTypeNull;
		}
		break;
	}

	/* set up the decoders */
	SessionInitDecoders( sess, pkt );

	return DSSL_RC_OK;
}


static void SessionInitDecoders( TcpSession* sess, DSSL_Pkt* pkt )
{
	CapEnv* env = NULL;
	_ASSERT(sess && sess->env);
	env = sess->env;

	switch( sess->type )
	{
	case eSessionTypeTBD:
		sess->OnNewPacket = DetectSessionTypeCallback;
		break;

	case eSessionTypeTcp:
		sess->OnNewPacket = OnNewPlainTextPacket;
		break;

	case eSessionTypeSSL:
		/* create SSL session */
		if( env->ssl_env != NULL ) 
		{
			/* first try dst IP:port as the server address */
			sess->ssl_session = DSSL_EnvCreateSession( env->ssl_env, 
					pkt->ip_header->ip_dst, PKT_TCP_DPORT( pkt ),
					pkt->ip_header->ip_src, PKT_TCP_SPORT( pkt ));
		}
		else
		{
			sess->ssl_session = NULL;
		}

		/* set packet callback */
		if( sess->ssl_session != NULL )
		{
			sess->OnNewPacket = OnNewSSLPacket;
			DSSL_SessionSetCallback( sess->ssl_session, sess->data_callback, 
					sess->error_callback, sess->user_data );
			DSSL_SessionSetEventCallback( sess->ssl_session, sess->event_callback );
		}
		else
		{
			sess->type = eSessionTypeNull; /* TODO: report error? */
		}
		break;

	case eSessionTypeNull:
		break;

	default:
		_ASSERT( FALSE );
		break;
	}
}

/* can be called multiple times; preserve state */
static void SessionDeInit( TcpSession* sess )
{
	_ASSERT( sess );

	if( sess->ssl_session )
	{
		DSSL_SessionDeInit( sess->ssl_session );
		free( sess->ssl_session );
		sess->ssl_session = NULL;
	}

	StreamFreeData( &sess->clientStream );
	StreamFreeData( &sess->serverStream );

	sess->type = eSessionTypeNull;
}


void SessionFree( TcpSession* sess )
{
	SessionDeInit( sess );
	free( sess );
}

static void SessionOnError( TcpSession* sess, int error_code )
{
	if( sess->error_callback )
	{
		sess->error_callback( sess->user_data, error_code );
	}
}

static int SessionDecodable( const TcpSession* sess )
{
	return sess->type != eSessionTypeNull;
}

static TcpStream* GetPacketStream( const DSSL_Pkt* pkt )
{
	TcpStream* retval = NULL;
	const TcpSession* sess;
	int dir = 0;

	sess = pkt->session;
	_ASSERT(sess);

	dir = SessionGetPacketDirection( sess, pkt );
	switch( dir )
	{
	case ePacketDirFromClient:
		retval = &pkt->session->clientStream;
		break;
	case ePacketDirFromServer:
		retval = &pkt->session->serverStream;
		break;

	default:
		_ASSERT( FALSE ); /* this packet does not belong to this session? */
		retval = NULL;
		break;
	}

	return retval;
}

void SessionProcessPacket( CapEnv* env, DSSL_Pkt* pkt )
{
	TcpStream* stream = NULL;
	int rc = DSSL_RC_OK;
	int new_packets = 0;

	_ASSERT( pkt );
	_ASSERT( pkt->session );

	/* update session's last activity timestamp */
	TouchSession( pkt->session );

	/* call packet callback first */
	if ( pkt->session->packet_callback ) {
		pkt->session->packet_callback( pkt->session->user_data, pkt );
	}

	if( !SessionDecodable( pkt->session ) ) return;

	stream = GetPacketStream( pkt );
	if( stream == NULL ) { _ASSERT( stream ); return; }

	rc = StreamProcessPacket( stream, pkt, &new_packets );
	/* tbd: for now, assume every packet potentially triggers 
		new packet event for the peer stream */
	new_packets=1;
	while( new_packets && rc == DSSL_RC_OK)
	{
		if(new_packets) { stream = StreamGetPeer(stream); }
		new_packets = 0;
		rc = StreamPollPackets( stream, &new_packets );
	}

	if( rc != DSSL_RC_OK && rc != DSSL_E_SSL_SERVER_KEY_UNKNOWN )
	{
		SessionOnError( pkt->session, rc );
	}

	if( rc != DSSL_RC_OK || pkt->session->closing)
	{
		if (rc == DSSL_RC_OK)
			SessionFlushPacketQueue( pkt->session );
		else if ( pkt->session->type == eSessionTypeSSL ) 
			pkt->session->type = eSessionTypeTcp; /* session is not decodable as SSL anymore */

		if (pkt->session->closing)
			env->sessions->DestroySession( env->sessions, pkt->session );
	}
}



void SessionSetCallback( TcpSession* sess, DataCallbackProc data_callback, ErrorCallbackProc error_callback,
						PacketCallbackProc packet_callback, void* user_data )
{
	_ASSERT( sess );

	sess->data_callback = data_callback;
	sess->error_callback = error_callback;
	sess->packet_callback = packet_callback;
	sess->user_data = user_data;
	
	if( sess->ssl_session != NULL )
	{
		DSSL_SessionSetCallback( sess->ssl_session, data_callback, error_callback, user_data );
	}
}

void SessionSetMissingPacketCallback( TcpSession* sess, MissingPacketCallbackProc missing_callback,
		int missing_packet_count, int timeout_sec )
{
	_ASSERT( sess );
	sess->missing_callback = missing_callback;
	sess->missing_packet_count = missing_packet_count;
	sess->missing_packet_timeout = timeout_sec;
}

void SessionSetEventCallback( TcpSession* sess, EventCallbackProc event_callback )
{
	_ASSERT( sess );

	sess->event_callback = event_callback;
	
	if( sess->ssl_session != NULL )
	{
		DSSL_SessionSetEventCallback( sess->ssl_session, event_callback );
	}
}

/* TCP reassembler callback that auto-detects SSL traffic and 
	sets the session type accordingly */
static int DetectSessionTypeCallback(struct _TcpStream* stream, DSSL_Pkt* pkt )
{
	TcpSession* sess = NULL; 
	NM_PacketDir dir = ePacketDirInvalid;
	int is_ssl = 0;

	_ASSERT(stream);
	_ASSERT(pkt);

	sess = stream->session;
	_ASSERT(sess && sess->type == eSessionTypeTBD);

	dir = SessionGetPacketDirection(sess, pkt);
	if(dir == ePacketDirFromClient)
	{
		uint16_t ver = 0;
		u_char* data = PKT_TCP_PAYLOAD( pkt );
		uint32_t len = pkt->data_len;
		int rc = ssl_detect_client_hello_version(data, len, &ver);
		is_ssl = (rc == DSSL_RC_OK);
	}
	else if(dir == ePacketDirFromServer)
	{
		is_ssl = 0; /* SSL servers don't talk first*/
	}
	else
	{
		_ASSERT(SessionGetPacketDirection(sess, pkt) != ePacketDirInvalid);
		return NM_ERROR(DSSL_E_INVALID_PARAMETER);
	}

#ifdef NM_TRACE_TCP_SESSIONS
	DEBUG_TRACE1( "\nTCP Session Type detected: %s", is_ssl ? "SSL" : "PlainText" ); 
#endif

	/* set the actual session type based on whether
		the first packet was recognized as SSL ClientHello */
	sess->type = is_ssl ? eSessionTypeSSL : eSessionTypeTcp;
	/* initialize session type specific data */
	SessionInitDecoders( sess, pkt);
	/* run this packet again throught the actual data callback */
	if(sess->type != eSessionTypeNull)
		return sess->OnNewPacket( stream, pkt );
	else
		return DSSL_RC_OK; /* TBD: return error? */
}

/* Plain text TCP reassembler callback */
static int OnNewPlainTextPacket( struct _TcpStream* stream, DSSL_Pkt* pkt )
{
	TcpSession* sess;

	_ASSERT( stream );
	_ASSERT( pkt );

	sess = stream->session;
	_ASSERT( sess );

	if ( sess->data_callback )
	{
		sess->data_callback( SessionGetPacketDirection( sess, pkt ),
			sess->user_data, PKT_TCP_PAYLOAD( pkt ), pkt->data_len, pkt );
	}

	return 0;
}

/* TCP reassembler callback function for SSL sessions */
static int OnNewSSLPacket( struct _TcpStream* stream, DSSL_Pkt* pkt )
{
	TcpSession* sess = NULL;
	DSSL_Session* ssl_sess = NULL;
	u_char* data = NULL;
	uint32_t len = 0;
	NM_PacketDir dir = ePacketDirInvalid;
	int rc = DSSL_RC_OK;

	_ASSERT( stream );
	_ASSERT( pkt );

	sess = stream->session;
	_ASSERT( sess );

	ssl_sess = sess->ssl_session;
	if( !ssl_sess )
	{
		_ASSERT( FALSE );
		return NM_ERROR( DSSL_E_UNSPECIFIED_ERROR );
	}

	ssl_sess->last_packet = pkt;
	data = PKT_TCP_PAYLOAD( pkt );
	len = pkt->data_len;
	dir = SessionGetPacketDirection( sess, pkt );

	if( sess->type == eSessionTypeSSL )
		rc = DSSL_SessionProcessData( ssl_sess, dir, data, len );

	if( ssl_sess->flags & ( SSF_CLOSE_NOTIFY_RECEIVED | SSF_FATAL_ALERT_RECEIVED ) )
	{
		sess->closing = 1;
	}

	return rc;
}


void SessionSetUserData( TcpSession* sess, void* data )
{
	_ASSERT( sess );
	sess->user_data = data;
}


void* SessionGetUserData( const TcpSession* sess )
{
	_ASSERT( sess );
	return sess->user_data;
}

void TouchSession( TcpSession* sess )
{
	_ASSERT( sess );
	sess->last_update_time = time(NULL);
}

void SessionFlushPacketQueue( TcpSession* sess )
{
	TcpStream* stream = NULL;
	if(sess->type != eSessionTypeTcp || sess->missing_callback == NULL ) return;

	/* pick a stream with the missing packet, if any */
	if(sess->clientStream.pktHead && !sess->serverStream.pktHead) {
		/*only client stream has packets */
		stream = &sess->clientStream;
	} else if(sess->serverStream.pktHead && !sess->clientStream.pktHead) {
		/*only server stream has packets */
		stream = &sess->serverStream;
	} else if(sess->serverStream.pktHead && sess->clientStream.pktHead) {
		stream = &sess->clientStream;
		if(PKT_TCP_SEQ( stream->pktHead ) - stream->nextSeqExpected == 0 )
			stream = StreamGetPeer(stream);

		if(PKT_TCP_SEQ( stream->pktHead ) - stream->nextSeqExpected == 0)
			stream = NULL; /*no missing packets */
		
		/* both streams have packets, pick the oldest */
		if(stream == NULL) {
			stream = PktCompareTimes( sess->serverStream.pktHead, sess->clientStream.pktHead ) > 0 ?
				&sess->clientStream : &sess->serverStream;
		}
	} else {
		return; /* both streams are empty */
	}

	while( sess->clientStream.pktHead || sess->serverStream.pktHead )
	{
		uint32_t len;
		if( stream->pktHead == NULL )
		{
			stream = StreamGetPeer( stream );
			continue;
		}

		if (PKT_TCP_SEQ( stream->pktHead ) > stream->nextSeqExpected) {
			len = PKT_TCP_SEQ( stream->pktHead ) - stream->nextSeqExpected;
		} else {
			len = 0;
		}
		if( len == 0 || sess->missing_callback( SessionGetPacketDirection(sess, stream->pktHead), SessionGetUserData(sess),
				PKT_TCP_SEQ(stream->pktHead), len) != 0)
		{
			int new_ack = 0; TcpStream* str = stream;

			int rc = StreamConsumeHead( str, &new_ack );
			if(rc == DSSL_RC_OK ) rc = StreamPollPackets( str, &new_ack );

			while( new_ack && rc == DSSL_RC_OK )
			{
				str = StreamGetPeer(str);
				new_ack = 0;
				rc = StreamPollPackets( str, &new_ack );
			}

			if( rc != DSSL_RC_OK ) break;
		}
		else
		{
			break;
		}

		stream = StreamGetPeer(stream);
	}
}

int IsNewTcpSessionPacket( const DSSL_Pkt* pkt )
{
	return pkt->tcp_header->th_flags & TH_SYN ? 1 : 0;
}
