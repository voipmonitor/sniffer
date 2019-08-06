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
#include "ssl_sessionkey_table.h"
#include "fnv_hash.h"
#include "ssl_session.h"


dssl_SessionKeyTable* dssl_SessionKT_Create( int table_size, uint32_t timeout_int )
{
	dssl_SessionKeyTable* retval = NULL;

	if( table_size < 111 ) table_size = 111;

	retval = (dssl_SessionKeyTable*) malloc( sizeof( dssl_SessionKeyTable ) );
	if(! retval ) return NULL;

	memset(retval, 0, sizeof(*retval) );

	retval->timeout_interval = timeout_int;
	retval->last_cleanup_time = time( NULL );

	retval->table = (DSSL_SessionKeyData**) malloc( sizeof(DSSL_SessionKeyData*) * table_size );
	if( !retval->table )
	{
		free( retval );
		return NULL;
	}

	memset( retval->table, 0, sizeof(DSSL_SessionKeyData*) * table_size );
	retval->table_size = table_size;
	retval->count = 0;

	return retval;
}


void dssl_SessionKT_Destroy( dssl_SessionKeyTable* tbl )
{
	dssl_SessionKT_RemoveAll( tbl );
	free( tbl->table );
	free( tbl );
}


static uint32_t GetSessionIDCache( u_char* session_id )
{
	return fnv_32_buf( session_id, DSSL_SESSION_ID_SIZE, FNV1_32_INIT );
}


DSSL_SessionKeyData* dssl_SessionKT_Find( dssl_SessionKeyTable* tbl, u_char* session_id )
{
	DSSL_SessionKeyData* key = NULL;
	uint32_t hash = 0;
	
	_ASSERT( session_id );
	_ASSERT( tbl );

	hash = GetSessionIDCache( session_id ) % tbl->table_size;
	key = tbl->table[hash];

	while( key && memcmp( key->id, session_id, sizeof(key->id) ) != 0 ) key = key->next;

	return key;
}


static DSSL_SessionKeyData* CreateSessionKeyData( DSSL_Session* sess )
{
	DSSL_SessionKeyData* new_data;

	_ASSERT( sess );

	new_data = (DSSL_SessionKeyData*) malloc( sizeof(DSSL_SessionKeyData) );
	if(!new_data) return NULL;

	//_ASSERT_STATIC( sizeof(new_data->id) == sizeof(sess->session_id ) );
	memcpy( new_data->id, sess->session_id, sizeof(new_data->id) );

	//_ASSERT_STATIC( sizeof(new_data->master_secret) == sizeof(sess->master_secret ) );
	memcpy( new_data->master_secret, sess->master_secret, sizeof(new_data->master_secret) );
	new_data->master_secret_len = sess->master_key_len;

	#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	memcpy(new_data->ssl2_key_arg, sess->ssl2_key_arg, SSL2_KEYARG_MAX_LEN);
	new_data->ssl2_key_arg_length = sess->ssl2_key_arg_len;
	new_data->ssl2_cipher_suite = sess->cipher_suite;
	#endif //(OPENSSL_VERSION_NUMBER < 0x10100000L)

	new_data->refcount = 1;
	new_data->next = NULL;
	new_data->released_time = 0;
	return new_data;
}


static void SessionKT_RemoveKey( dssl_SessionKeyTable* tbl, DSSL_SessionKeyData** key )
{
	DSSL_SessionKeyData* temp = (*key);
	(*key) = (*key)->next;
	
	free( temp );
	-- tbl->count;
}


void dssl_SessionKT_CleanSessionCache( dssl_SessionKeyTable* tbl )
{
	int i;
	time_t cur_time;
	
	_ASSERT( tbl );

	if( tbl->count == 0 ) return;

	cur_time = tbl->last_cleanup_time = time( NULL );

	for( i=0; i < tbl->table_size; ++i )
	{
		DSSL_SessionKeyData** d = &tbl->table[i];
		while( *d )
		{
			if( (*d)->released_time != 0 && 
				cur_time - (*d)->released_time > tbl->timeout_interval )
			{
				SessionKT_RemoveKey( tbl, d );
			}
			else
			{
				d = &(*d)->next;
			}
		}
	}
}


void dssl_SessionKT_Add( dssl_SessionKeyTable* tbl, DSSL_Session* sess )
{
	uint32_t hash;
	DSSL_SessionKeyData* new_data;

	_ASSERT( tbl );
	_ASSERT( sess );

	if( tbl->timeout_interval != 0 && 
		time( NULL ) - tbl->last_cleanup_time > DSSL_CACHE_CLEANUP_INTERVAL )
	{
		dssl_SessionKT_CleanSessionCache( tbl );
	}

	new_data = CreateSessionKeyData( sess );
	if( !new_data )
	{
		/* TODO: log */
		return;
	}

	hash = GetSessionIDCache( new_data->id ) % tbl->table_size;
	new_data->next = tbl->table[hash];
	tbl->table[hash] = new_data;
	++ tbl->count;
}

void dssl_SessionKT_Remove( dssl_SessionKeyTable* tbl, u_char* session_id )
{
	uint32_t hash;
	DSSL_SessionKeyData** s;
	_ASSERT( tbl ); _ASSERT( session_id );

	hash = GetSessionIDCache( session_id ) % tbl->table_size;
	s = &tbl->table[hash];

	while( (*s) &&  memcmp((*s)->id, session_id, sizeof((*s)->id) ) != 0 )
	{
		s = &(*s)->next;
	}

	if( *s )
	{
		SessionKT_RemoveKey( tbl, s );
	}
}

void dssl_SessionKT_RemoveAll( dssl_SessionKeyTable* tbl )
{
	int i;
	for( i=0; i < tbl->table_size; ++i )
	{
		DSSL_SessionKeyData* d = tbl->table[i];
		while( d )
		{
			DSSL_SessionKeyData* dd = d;
			d = d->next;
			free( dd );
		}
	}

	memset( tbl->table, 0, sizeof(tbl->table[0])*tbl->table_size );
	tbl->count = 0;
}

#ifdef NM_MULTI_THREADED_SSL
	#error "Multithreading is not implemented for SSL session cache!"
#else
void dssl_SessionKT_AddRef( DSSL_SessionKeyData* sess_data )
{
	sess_data->refcount++;
}

void dssl_SessionKT_Release( dssl_SessionKeyTable* tbl, u_char* session_id )
{
	DSSL_SessionKeyData* sess_data = dssl_SessionKT_Find( tbl, session_id );

	if( sess_data )
	{
		sess_data->refcount--;
		if(sess_data->refcount == 0 )
		{
			time( &sess_data->released_time );
		}
	}
}
#endif
