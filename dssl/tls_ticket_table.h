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

#ifndef __DSSL_TLS_TICKET_TABLE_H__
#define __DSSL_TLS_TICKET_TABLE_H__

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct _DSSL_SessionTicketData
{
	u_char*							ticket;
	uint32_t						ticket_size;

	uint16_t						protocol_version;
	uint16_t						cipher_suite;
	u_char							compression_method;
	u_char							master_secret[SSL3_MASTER_SECRET_SIZE];
	time_t							timestamp;
	struct _DSSL_SessionTicketData*	next;
} DSSL_SessionTicketData;

struct _DSSL_SessionTicketTable
{
	DSSL_SessionTicketData**	table;
	volatile int				count;
	int							table_size;
	time_t						timeout_interval;	/* in seconds */
	time_t						last_cleanup_time;
};

DSSL_SessionTicketTable* dssl_SessionTicketTable_Create( int table_size, uint32_t timeout_int );
void dssl_SessionTicketTable_Destroy( DSSL_SessionTicketTable* tbl );
void dssl_SessionTicketTable_RemoveAll( DSSL_SessionTicketTable* tbl );

DSSL_SessionTicketData* dssl_SessionTicketTable_Find( DSSL_SessionTicketTable* tbl, const u_char* ticket, uint32_t len );
int dssl_SessionTicketTable_Add( DSSL_SessionTicketTable* tbl, DSSL_Session* sess, const u_char* ticket, uint32_t len);
void dssl_SessionTicketTable_Remove( DSSL_SessionTicketTable* tbl, const u_char* ticket, uint32_t len );
void dssl_SessionTicketTable_CleanSessionCache( DSSL_SessionTicketTable* tbl );


#ifdef  __cplusplus
}
#endif

#endif
