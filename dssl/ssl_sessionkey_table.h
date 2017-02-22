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
#ifndef __DSSL_SSL_SESSIONKEY_TABLE_H__
#define __DSSL_SSL_SESSIONKEY_TABLE_H__

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct _DSSL_SessionKeyData
{
	u_char							id[DSSL_SESSION_ID_SIZE];
	u_char							master_secret[SSL3_MASTER_SECRET_SIZE];
	uint32_t						master_secret_len; /*SSL v2 only */
	u_char							ssl2_key_arg[SSL2_KEYARG_MAX_LEN];/* SSL v2 only */
	uint16_t						ssl2_key_arg_length;/* SSL v2 only */
	uint16_t						ssl2_cipher_suite;/* SSL v2 only */
	volatile uint32_t				refcount;
	time_t							released_time;
	struct _DSSL_SessionKeyData*	next;
} DSSL_SessionKeyData;

struct dssl_SessionKeyTable_
{
	DSSL_SessionKeyData**	table;
	volatile int			count;
	int						table_size;
	time_t					timeout_interval;	/* in seconds */
	time_t					last_cleanup_time;
};

dssl_SessionKeyTable* dssl_SessionKT_Create( int table_size, uint32_t timeout_int );
void dssl_SessionKT_Destroy( dssl_SessionKeyTable* tbl );

void dssl_SessionKT_AddRef( DSSL_SessionKeyData* sess_data );
void dssl_SessionKT_Release( dssl_SessionKeyTable* tbl, u_char* session_id );
void dssl_SessionKT_CleanSessionCache( dssl_SessionKeyTable* tbl );

DSSL_SessionKeyData* dssl_SessionKT_Find( dssl_SessionKeyTable* tbl, u_char* session_id );
void dssl_SessionKT_Add( dssl_SessionKeyTable* tbl, DSSL_Session* sess );
void dssl_SessionKT_Remove( dssl_SessionKeyTable* tbl, u_char* session_id );
void dssl_SessionKT_RemoveAll( dssl_SessionKeyTable* tbl );

#ifdef  __cplusplus
}
#endif

#endif
