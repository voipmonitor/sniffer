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
#ifndef __DSSL_SESSION_TABLE_H__
#define __DSSL_SESSION_TABLE_H__

#include "session.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* TODO_DEF_MOVE */
#define DSSL_SESSION_CLEANUP_INTERVAL	300

struct CapEnv_;

struct dssl_SessionTable_
{
	/* session hash table */
	TcpSession**			table;
	/* hash table size */
	int						tableSize;
	/* current session count */
	volatile int			sessionCount;
	/* parent CapEnv structure */
	struct CapEnv_*			env;
	/* time in seconds sessions are kept in cache */
	time_t					timeout_interval;
	/* time in seconds between table cleanups */
	time_t					cleanup_interval;
	/* last session table cleanup time stamp */
	time_t					last_cleanup_time;

	volatile int			packet_cache_count; /* count of cached packets for all sessions */
	volatile uint64_t		packet_cache_mem;	/* packet reassembly cache memory usage */

	int						maxSessionCount; /* max number of TCP sessions or 0 if unlimited */
	int						maxCachedPacketCount; /* max number of packets cached in sessions' reassembly queues */
/* "Member" functions ----------------- */
	/* Lookup a session */
	TcpSession*	(*FindSession)( struct dssl_SessionTable_* tbl, DSSL_Pkt* pkt );
	/* Create a new session */
	TcpSession*	(*CreateSession)( struct dssl_SessionTable_* tbl, DSSL_Pkt* pkt, NM_SessionType s_type );
	/* Remove the session from the table; free session object */
	void		(*DestroySession)( struct dssl_SessionTable_* tbl, TcpSession* sess );
	/* Remove all sessions; free session objects */
	void		(*RemoveAll)( struct dssl_SessionTable_* tbl );
	/* Pefrorm cleanup */
	void		(*Cleanup)(struct dssl_SessionTable_* tbl );
};

dssl_SessionTable* CreateSessionTable( int tableSize, uint32_t timeout_int, uint32_t cleanup_interval );
void DestroySessionTable( dssl_SessionTable* tbl );

#ifdef  __cplusplus
}
#endif

#endif
