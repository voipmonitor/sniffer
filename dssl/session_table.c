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
#ifdef _WIN32
  #define _CRT_SECURE_NO_WARNINGS 
#endif

#include <string.h>
#include "stdinc.h"
#include "capenv.h"
#include "fnv_hash.h"

extern int StreamHasMissingPacket(TcpStream* stream, DSSL_Pkt* pkt);

/* Calculates a hash key for a (ip1, port1)<->(ip2, port2) tcp session */
static uint32_t getTcpSessionHash( uint32_t ip1, uint16_t port1, uint32_t ip2, uint16_t port2 )
{
	uint32_t hash;

	if( ip1 < ip2 )
	{
		hash = fnv_32_buf( &ip1, sizeof(ip1), FNV1_32_INIT );
		hash = fnv_32_buf( &port1, sizeof(port1), hash );
		hash = fnv_32_buf( &ip2, sizeof(ip2), hash );
		hash = fnv_32_buf( &port2, sizeof(port2), hash );
	}
	else 
	{
		hash = fnv_32_buf( &ip2, sizeof(ip2), FNV1_32_INIT );
		hash = fnv_32_buf( &port2, sizeof(port2), hash );
		hash = fnv_32_buf( &ip1, sizeof(ip1), hash );
		hash = fnv_32_buf( &port1, sizeof(port1), hash );
	}
	return hash;
}


/* Calculates a TcpSession hash key from packet's src and dest {ip, port} pairs */
static uint32_t getPktSessionHash( const DSSL_Pkt* pkt )
{
	uint32_t ip1, ip2;
	uint16_t port1, port2;

	_ASSERT( pkt );
	_ASSERT( pkt->ip_header );
	_ASSERT( pkt->tcp_header );

	/* use the smaller ip number as "ip1"
		(if source and dest IPs are the same,
		port1 is the smallest port)
	*/
	
	if( INADDR_IP( pkt->ip_header->ip_src ) < INADDR_IP( pkt->ip_header->ip_dst ) )
	{
		ip1 = INADDR_IP( pkt->ip_header->ip_src );
		ip2 = INADDR_IP( pkt->ip_header->ip_dst );
		port1 = PKT_TCP_SPORT( pkt );
		port2 = PKT_TCP_DPORT( pkt );
	}
	else if( INADDR_IP( pkt->ip_header->ip_src ) > INADDR_IP( pkt->ip_header->ip_dst ) )
	{
		ip2 = INADDR_IP( pkt->ip_header->ip_src );
		ip1 = INADDR_IP( pkt->ip_header->ip_dst );
		port2 = PKT_TCP_SPORT( pkt );
		port1 = PKT_TCP_DPORT( pkt );
	}
	else
	{
		ip1 = ip2 = INADDR_IP( pkt->ip_header->ip_src );

		if( PKT_TCP_SPORT( pkt ) < PKT_TCP_DPORT( pkt ) )
		{
			port1 = PKT_TCP_SPORT( pkt );
			port2 = PKT_TCP_DPORT( pkt );
		}
		else
		{
			port2 = PKT_TCP_SPORT( pkt );
			port1 = PKT_TCP_DPORT( pkt );
		}
	}

	return getTcpSessionHash( ip1, port1, ip2, port2 );
}


/* Calculate TcpSession's hash key */
static uint32_t getSessionHash( TcpSession* sess )
{
	uint32_t ip1, ip2;
	uint16_t port1, port2;

	_ASSERT( sess );

	if( sess->clientStream.ip_addr < sess->serverStream.ip_addr )
	{
		ip1 = sess->clientStream.ip_addr;
		ip2 = sess->serverStream.ip_addr;

		port1 = sess->clientStream.port;
		port2 = sess->serverStream.port;
	}
	else if( sess->clientStream.ip_addr > sess->serverStream.ip_addr )
	{
		ip2 = sess->clientStream.ip_addr;
		ip1 = sess->serverStream.ip_addr;

		port2 = sess->clientStream.port;
		port1 = sess->serverStream.port;
	}
	else
	{
		ip1 = ip2 = sess->clientStream.ip_addr;
		
		if( sess->clientStream.port < sess->serverStream.port )
		{
			port1 = sess->clientStream.port;
			port2 = sess->serverStream.port;
		}
		else
		{
			port2 = sess->clientStream.port;
			port1 = sess->serverStream.port;
		}
	}

	return getTcpSessionHash( ip1, port1, ip2, port2 );
}


static const TcpStream* GetStream(const DSSL_Pkt* pkt, const TcpSession* sess )
{
	NM_PacketDir dir = SessionGetPacketDirection( sess, pkt );

	_ASSERT( dir != ePacketDirInvalid );
	return (dir == ePacketDirFromClient) ? & sess->clientStream : &sess->serverStream;
}

/*
static const TcpStream* GetPeerStream(const DSSL_Pkt* pkt, const TcpSession* sess )
{
	NM_PacketDir dir = SessionGetPacketDirection( sess, pkt );

	_ASSERT( dir != ePacketDirInvalid );
	return (dir == ePacketDirFromClient) ? & sess->clientStream : &sess->serverStream;
}
*/

/* check if packet matches session streams IP/ports; also test for handshake state */
static int PacketSessionMatch( const TcpSession* sess, const DSSL_Pkt* pkt )
{
	if( (SessionGetPacketDirection( sess, pkt ) != ePacketDirInvalid)) {
		if(IsNewTcpSessionPacket(pkt)) {
			const TcpStream* stream = GetStream( pkt, sess );
			if( stream ) {
				uint32_t seq = PKT_TCP_SEQ(pkt);
				return ((stream->flags & DSSL_TCPSTREAM_SENT_SYN) == 0) || (seq == stream->initial_seq);
			} else {
				return 0;
			}
		} else {
			return 1;
		}
	} else {
		return 0;
	}
}

/* see how many sessions are in the cache that potentiall match that packet */
static int GetSessionCountForPacket( const dssl_SessionTable* tbl, const DSSL_Pkt* pkt, 
									TcpSession** psess )
{
	/* calculate hash index */
	uint32_t hash = getPktSessionHash( pkt ) % tbl->tableSize;
	TcpSession* sess;
	int cnt = 0;

	if(psess) { *psess = NULL; }

	/* find the session in the table */
	sess = tbl->table[hash];

	while( sess ) {
		if(PacketSessionMatch(sess, pkt)) {
			++ cnt;
			if(psess) { *psess = sess; }
		}
		sess = sess->next;
	}
	return cnt;
}

static TcpSession* FindBestSessionForPacket( const dssl_SessionTable* tbl, const DSSL_Pkt* pkt,
											int cnt )
{
	TcpSession** sessions = (TcpSession**) alloca( sizeof(TcpSession*)*cnt );
	uint32_t hash = 0; int i = 0;
	TcpSession* sess = NULL;
	uint32_t pktSeq = PKT_TCP_SEQ(pkt);
	uint32_t* offsets = (uint32_t*) alloca(sizeof(uint32_t)*cnt);
	int best_sess_idx = 0;

	memset( sessions, 0, sizeof(TcpSession*)*cnt );
	memset( offsets, 0, sizeof(uint32_t)*cnt );

	/* calculate hash index */
	hash = getPktSessionHash( pkt ) % tbl->tableSize;

	/* grab all the sessions into array */
	sess = tbl->table[hash];
	i = 0;
	while( sess ) {
		if(PacketSessionMatch(sess, pkt)) {
			_ASSERT( i < cnt );
			sessions[i] = sess;
			++ i;
		}
		sess = sess->next;
	}

	_ASSERT( i == cnt );

	/* first pass - check for perfect match */
	for(i = 0; i < cnt; ++i) {
		TcpSession* s = sessions[i];
		const TcpStream* stream = GetStream( pkt, s);
		if( !stream ) { _ASSERT(FALSE); continue; }
		if( stream->nextSeqExpected == pktSeq ) return s;
		if( stream->pktTail && PktNextTcpSeqExpected(stream->pktTail) == pktSeq) return s;
	}

	/* second pass - try to find the best fitting TCP sequence range */
	for(i = 0; i < cnt; ++i) {
		TcpSession* s = sessions[i];
		const TcpStream* stream = GetStream( pkt, s);
		uint32_t seqBegin = 0; 
		uint32_t seqEnd = 0;

		if( !stream ) { _ASSERT(FALSE); continue; }

		seqBegin = stream->initial_seq;
		seqEnd = stream->pktTail ? PktNextTcpSeqExpected(stream->pktTail) : stream->nextSeqExpected;

		if(seqBegin <= seqEnd ) {
			if( pktSeq >= seqBegin && pktSeq <= seqEnd ) 
				return s;
			if( seqBegin && pktSeq >= seqEnd ) offsets[i] = pktSeq - seqEnd;
		} else { /* TCP sequence wrap over */
			if( pktSeq > seqBegin || pktSeq <= seqEnd ) 
				return s;
			if( seqBegin && pktSeq < seqBegin && pktSeq >= seqEnd ) offsets[i] = pktSeq - seqEnd;
		}
	}

	/* see which sessions's last seen sequence is closer to this packet */
	best_sess_idx = 0;
#ifdef NM_TRACE_TCP_SESSIONS
	DEBUG_TRACE1("\n[**]? TCP Session ambiguity: choosing between %d sessions:", cnt );
	for(i=0; i < cnt; i++) {
		char buff[128];
		SessionToString(sessions[i], buff);
		DEBUG_TRACE2("\n\t%s at %p", buff, sessions[i] );
	}
#endif

	for(i=0; i < cnt;i++) {
		if( offsets[i] && offsets[i] < offsets[best_sess_idx] ) 
			best_sess_idx = i;
	}
	#ifdef NM_TRACE_TCP_SESSIONS
		DEBUG_TRACE2("\nbest offset is %d for %d", offsets[best_sess_idx], best_sess_idx );
	#endif

	return sessions[best_sess_idx];
}

static TcpSession* _SessionTable_FindSession( dssl_SessionTable* tbl, DSSL_Pkt* pkt )
{
	TcpSession* sess = NULL;
	int existingSessionCnt = 0;
	_ASSERT( pkt->ip_header );
	_ASSERT( pkt->tcp_header );

	/* first, see how many TCP sessions between srcIP:srcPort<->trgtIP:trgtPort exist */
	existingSessionCnt = GetSessionCountForPacket( tbl, pkt, &sess );

	/* nothing found, return */
	if( existingSessionCnt == 0 ) {
		return NULL;
	}

	if( existingSessionCnt == 1 ) { /* single session - simple case */
		_ASSERT( sess ); /* should be returned by GetSessionCountForPacket */
		//sess;
	} else {  /* multiple sessions */
		sess = FindBestSessionForPacket( tbl, pkt, existingSessionCnt );
	}

	return sess;
}


static void _SessionTable_addSession( dssl_SessionTable* tbl, TcpSession* sess )
{
	uint32_t hash;
	TcpSession** prevSession;

	_ASSERT( tbl );
	_ASSERT( sess );

#ifdef NM_TRACE_TCP_SESSIONS
	{
		char _trace_buff[512];
		DEBUG_TRACE2( "\n-->New  TCP Session: type: %d %s", (int)sess->type, SessionToString(sess, _trace_buff) );
	}
#endif
	sess->next = NULL;
	hash = getSessionHash( sess ) % tbl->tableSize;

	prevSession = &tbl->table[hash];

	while( (*prevSession) != NULL ) prevSession = &(*prevSession)->next;

	(*prevSession) = sess;
}


static TcpSession* _SessionTable_CreateSession( dssl_SessionTable* tbl, DSSL_Pkt* pkt, NM_SessionType s_type )
{
	TcpSession* sess = NULL;

	_ASSERT( tbl );	_ASSERT( pkt );

	if( s_type == eSessionTypeNull )
	{
		_ASSERT( s_type != eSessionTypeNull );
		return NULL;
	}

	/* check if a cleanup is needed */
	if( tbl->timeout_interval != 0 && 
		time( NULL ) - tbl->last_cleanup_time > tbl->cleanup_interval )
	{
		tbl->Cleanup( tbl );
	}

	/* check if the session limit is reached, then force a cleanup and check again */
	if( tbl->maxSessionCount > 0 && tbl->sessionCount >= tbl->maxSessionCount )
	{
		tbl->Cleanup( tbl );
	}

	/* check if the session limit is reached */
	if( tbl->maxSessionCount > 0 && tbl->sessionCount >= tbl->maxSessionCount )
	{
		if( tbl->env && tbl->env->session_callback )
		{
			tbl->env->session_callback( tbl->env, NULL, DSSL_EVENT_SESSION_LIMIT );
		}
		return NULL;
	}

	sess = (TcpSession*) malloc( sizeof(*sess) );

	/* TODO: handle low memory condition */
	if( sess == NULL ) return NULL;

	if( SessionInit( tbl->env, sess, pkt, s_type ) != DSSL_RC_OK )
	{
		free( sess );
		return NULL;
	}

	sess->packet_time = pkt->pcap_header.ts;

	if( sess && sess->type != eSessionTypeNull && tbl->env && tbl->env->session_callback )
	{
		tbl->env->session_callback( tbl->env, sess, DSSL_EVENT_NEW_SESSION );
	}

	_SessionTable_addSession( tbl, sess );

	++ tbl->sessionCount;

	return sess;
}


static void SessionTableFreeSession( dssl_SessionTable* tbl, TcpSession* sess )
{
#ifdef NM_TRACE_TCP_SESSIONS
	{
		char _trace_buff[512];
		DEBUG_TRACE2( "\n-->Free TCP Session: type: %d %s", (int)sess->type, SessionToString(sess, _trace_buff) );
	}
#endif

	if( tbl->env && tbl->env->session_callback )
	{
		tbl->env->session_callback( tbl->env, sess, DSSL_EVENT_SESSION_CLOSING );
	}
	SessionFree( sess );
}


static void _SessionTable_DestroySession( dssl_SessionTable* tbl, TcpSession* sess )
{
	uint32_t hash;
	TcpSession** s;
	_ASSERT( tbl ); _ASSERT( sess );

	hash = getSessionHash( sess ) % tbl->tableSize;
	s = &tbl->table[hash];

	while( (*s) &&  (*s) != sess ) 
		s = &(*s)->next;

	if( *s )
	{
		(*s) = (*s)->next;
		SessionTableFreeSession( tbl, sess );
		-- tbl->sessionCount;
	}
	else
	{
		_ASSERT( FALSE ); /* session not found in the session table */
	}
}


static void _SessionTable_RemoveAll( dssl_SessionTable* tbl )
{
	int i;
	_ASSERT( tbl );

	for( i=0; i < tbl->tableSize; ++i )
	{
		TcpSession* s = tbl->table[i];
		while( s )
		{
			TcpSession* ss = s;
			s = s->next;
			SessionFlushPacketQueue( ss );
			SessionTableFreeSession( tbl, ss );
		}
	}

	memset( tbl->table, 0, sizeof(tbl->table[0])*tbl->tableSize );
	tbl->sessionCount = 0;
}

static void _SessionTable_Cleanup( dssl_SessionTable* tbl )
{
	int i;
	time_t cur_time = time( NULL );
	DSSL_Pkt pkt;
	_ASSERT( tbl );

	/* dummy packet for missing-packet tests */
	memset(&pkt, 0, sizeof(pkt));
	pkt.pcap_header.ts.tv_sec = cur_time;
	for( i=0; i < tbl->tableSize && tbl->sessionCount > 0; ++i )
	{
		TcpSession** s = &tbl->table[i];
		while( *s )
		{
			if(((*s)->last_update_time != 0 && 
				cur_time - (*s)->last_update_time > tbl->timeout_interval) ||
				/* check for missing packet timeout in streams */
				StreamHasMissingPacket(&(*s)->clientStream, &pkt) ||
				StreamHasMissingPacket(&(*s)->serverStream, &pkt))
			{
				TcpSession* sess = *s;
				(*s) = (*s)->next;
				#ifdef NM_TRACE_TCP_SESSIONS
				{
					char _trace_buff[512];
					DEBUG_TRACE2( "\n-->TCP Session cleanup: type: %d %s", (int)sess->type, SessionToString(sess, _trace_buff) );
				}
				#endif
				SessionFlushPacketQueue( sess );
				SessionTableFreeSession( tbl, sess );
				-- tbl->sessionCount;
			}
			else
			{
				s = &(*s)->next;
			}
		}
	}

	tbl->last_cleanup_time = cur_time;
}


/* dssl_SessionTable "constructor" routine */
dssl_SessionTable* CreateSessionTable( int tableSize, uint32_t timeout_int, uint32_t cleanup_interval )
{
	dssl_SessionTable* tbl;

	_ASSERT( tableSize > 0 );

	tbl = (dssl_SessionTable*) malloc( sizeof(dssl_SessionTable) );
	memset( tbl, 0, sizeof(*tbl) );

	tbl->FindSession = _SessionTable_FindSession;
	tbl->CreateSession = _SessionTable_CreateSession;
	tbl->DestroySession = _SessionTable_DestroySession;
	tbl->RemoveAll = _SessionTable_RemoveAll;
	tbl->Cleanup = _SessionTable_Cleanup;

	tbl->table = (TcpSession**) malloc( sizeof(tbl->table[0])*tableSize );
	memset( tbl->table, 0, sizeof(tbl->table[0])*tableSize );

	tbl->tableSize = tableSize;
	tbl->timeout_interval = timeout_int;
	tbl->cleanup_interval = cleanup_interval;
	tbl->last_cleanup_time = time( NULL );
	tbl->maxSessionCount = 0;
	tbl->maxCachedPacketCount = 0;

	return tbl;
}


void DestroySessionTable( dssl_SessionTable* tbl )
{
#ifdef NM_TRACE_TCP_SESSIONS
	{
		DEBUG_TRACE1( "\n-->Destroying TCP Session Table, remaining session count %d", (int)tbl->sessionCount);
	}
#endif

	tbl->RemoveAll( tbl );
	free( tbl->table );
	free( tbl );
}

