/*
** This file is a part of DSSL library.
**
** Copyright (C) 2010, Atomic Labs, Inc.
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
#include "tls_ticket_table.h"
#include "fnv_hash.h"
#include "ssl_session.h"


DSSL_SessionTicketTable* dssl_SessionTicketTable_Create( int table_size, uint32_t timeout_int )
{
	DSSL_SessionTicketTable* retval = NULL;

	if( table_size < 111 ) table_size = 111;

	retval = (DSSL_SessionTicketTable*) malloc( sizeof( DSSL_SessionTicketTable ) );
	if(! retval ) return NULL;

	memset(retval, 0, sizeof(*retval) );

	retval->timeout_interval = timeout_int;
	retval->last_cleanup_time = time( NULL );

	retval->table = (DSSL_SessionTicketData**) malloc( sizeof(DSSL_SessionTicketData*) * table_size );
	if( !retval->table )
	{
		free( retval );
		return NULL;
	}

	memset( retval->table, 0, sizeof(DSSL_SessionTicketData*) * table_size );
	retval->table_size = table_size;
	retval->count = 0;

	return retval;
}


void dssl_SessionTicketTable_Destroy( DSSL_SessionTicketTable* tbl )
{
	dssl_SessionTicketTable_RemoveAll( tbl );
	free( tbl->table );
	free( tbl );
}

static uint32_t GetSessionIDCache( const u_char* ticket, int len )
{
	_ASSERT(ticket);
	return fnv_32_buf( ticket, len, FNV1_32_INIT );
}


DSSL_SessionTicketData* dssl_SessionTicketTable_Find( DSSL_SessionTicketTable* tbl, const u_char* ticket, uint32_t len )
{
	DSSL_SessionTicketData* ticket_data = NULL;
	uint32_t hash = 0;
	
	_ASSERT( ticket );
	_ASSERT( tbl );
	_ASSERT( len > 0 );

	hash = GetSessionIDCache( ticket, len ) % tbl->table_size;
	ticket_data = tbl->table[hash];

	while( ticket_data && (ticket_data->ticket_size != len ||
		memcmp( ticket_data->ticket, ticket, len ) != 0) ) 
	{
		ticket_data = ticket_data->next;
	}
	return ticket_data;
}


static DSSL_SessionTicketData* CreateSessionTicketData( DSSL_Session* sess, const u_char* ticket, uint32_t len )
{
	DSSL_SessionTicketData* new_data;

	_ASSERT( sess && ticket && len );

	if(ticket == NULL || len == 0 ) return NULL;

	new_data = (DSSL_SessionTicketData*) malloc( sizeof(DSSL_SessionTicketData) );
	if(!new_data) return NULL;

	new_data->ticket = (u_char*) malloc( len );
	if(!new_data->ticket) {
		free(new_data);
		return NULL;
	}
	memcpy( new_data->ticket, ticket, len );
	new_data->ticket_size = len;

	//_ASSERT_STATIC( sizeof(new_data->master_secret) == sizeof(->master_secret ) );
	memcpy( new_data->master_secret, sess->master_secret, sizeof(new_data->master_secret) );

	new_data->cipher_suite = sess->cipher_suite;
	new_data->compression_method = sess->compression_method;
	new_data->protocol_version = sess->version;
	
	time(&new_data->timestamp);
	new_data->next = NULL;
	return new_data;
}

static void DestroySessionTicketData( DSSL_SessionTicketData* td )
{
	_ASSERT( td && td->ticket);
	free(td->ticket);
	free(td);
}

static void SessionTicketTable_RemoveKey( DSSL_SessionTicketTable* tbl, DSSL_SessionTicketData** key )
{
	DSSL_SessionTicketData* temp = (*key);
	(*key) = (*key)->next;
	
	DestroySessionTicketData( temp );
	-- tbl->count;
}


int dssl_SessionTicketTable_Add( DSSL_SessionTicketTable* tbl, DSSL_Session* sess, const u_char* ticket, uint32_t len)
{
	uint32_t hash;
	DSSL_SessionTicketData* new_data;

	_ASSERT( tbl );
	_ASSERT( sess );

	if( tbl->timeout_interval != 0 && 
		time( NULL ) - tbl->last_cleanup_time > DSSL_CACHE_CLEANUP_INTERVAL )
	{
		dssl_SessionTicketTable_CleanSessionCache( tbl );
	}

	new_data = CreateSessionTicketData( sess, ticket, len );
	if( !new_data )
	{
		return NM_ERROR(DSSL_E_OUT_OF_MEMORY);
	}

	hash = GetSessionIDCache( new_data->ticket, new_data->ticket_size ) % tbl->table_size;
	new_data->next = tbl->table[hash];
	tbl->table[hash] = new_data;
	++ tbl->count;

	return DSSL_RC_OK;
}

void dssl_SessionTicketTable_Remove( DSSL_SessionTicketTable* tbl, const u_char* ticket, uint32_t len )
{
	uint32_t hash;
	DSSL_SessionTicketData** s;
	_ASSERT( tbl ); _ASSERT( ticket && len );

	hash = GetSessionIDCache( ticket, len ) % tbl->table_size;
	s = &tbl->table[hash];

	while( (*s) && ((*s)->ticket_size != len || memcmp((*s)->ticket, ticket, len ) != 0) )
	{
		s = &(*s)->next;
	}

	if( *s )
	{
		SessionTicketTable_RemoveKey( tbl, s );
	}
}

void dssl_SessionTicketTable_RemoveAll( DSSL_SessionTicketTable* tbl )
{
	int i;
	for( i=0; i < tbl->table_size; ++i )
	{
		DSSL_SessionTicketData* d = tbl->table[i];
		while( d )
		{
			DSSL_SessionTicketData* dd = d;
			d = d->next;
			DestroySessionTicketData( dd );
		}
	}

	memset( tbl->table, 0, sizeof(tbl->table[0])*tbl->table_size );
	tbl->count = 0;
}


void dssl_SessionTicketTable_CleanSessionCache( DSSL_SessionTicketTable* tbl )
{
	int i;
	time_t cur_time = tbl->last_cleanup_time = time( NULL );

	for( i=0; i < tbl->table_size; ++i )
	{
		DSSL_SessionTicketData** d = &tbl->table[i];
		while( *d )
		{
			if( (*d)->timestamp != 0 && 
				cur_time - (*d)->timestamp > tbl->timeout_interval )
			{
				SessionTicketTable_RemoveKey( tbl, d );
			}
			else
			{
				d = &(*d)->next;
			}
		}
	}
}
