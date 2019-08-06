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
#include "decoder.h"


void dssl_decoder_init( dssl_decoder* decoder, sslc_decode_proc handler, void* handler_data )
{
	_ASSERT( decoder );

	#if __GNUC__ >= 8
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wsizeof-pointer-memaccess"
	#endif
	memset( decoder, 0, sizeof(*decoder) );
	#if __GNUC__ >= 8
	#pragma GCC diagnostic pop
	#endif
	decoder->handler = handler;
	decoder->handler_data = handler_data;
}


void dssl_decoder_deinit( dssl_decoder* d )
{
	_ASSERT( d );

	if( d->buff ) free( d->buff );

	d->buff = NULL;
	d->buff_len = 0;
	d->buff_used_len = 0;
}


static int realloc_buffer( dssl_decoder* d, uint32_t new_len )
{
	/* TODO: add CapEnv-scope buffer management */
	u_char* new_buff = NULL;

	_ASSERT( new_len > 0 );
	_ASSERT( d->buff_len == 0 || new_len > d->buff_len );

	if( d->buff != NULL )
		new_buff = (u_char*) realloc( d->buff, new_len );
	else
		new_buff = (u_char*) malloc( new_len );

	if( new_buff == NULL ) return NM_ERROR( DSSL_E_OUT_OF_MEMORY );

	d->buff_len = new_len;
	d->buff = new_buff;

	return DSSL_RC_OK;
}

int dssl_decoder_add_to_buffer( dssl_decoder* d, u_char* data, uint32_t len )
{
	int rc = DSSL_RC_OK;

	if( d->buff_len < d->buff_used_len + len )
	{
		rc = realloc_buffer( d, d->buff_used_len + len );
	}

	if( rc == DSSL_RC_OK )
	{
		_ASSERT( d->buff_len >= d->buff_used_len + len );

		memcpy( d->buff + d->buff_used_len, data, len );
		d->buff_used_len += len;
	}

	return rc;
}

int dssl_decoder_shift_buffer( dssl_decoder* d, uint32_t processed_len )
{
	_ASSERT( d->buff );
	_ASSERT( d->buff_used_len >= processed_len );

	if( d->buff_used_len > processed_len )
	{
		memmove( d->buff, d->buff + processed_len, d->buff_used_len - processed_len );
	}

	d->buff_used_len -= processed_len;

	return DSSL_RC_OK;
}

int dssl_decoder_process( dssl_decoder* d, NM_PacketDir dir, u_char* data, uint32_t len )
{
	uint32_t processed = 0;
	int rc = DSSL_RC_OK;

	if( !d->handler ) return NM_ERROR( DSSL_E_NOT_IMPL );

	if( d->buff_used_len > 0 ) 
	{
		rc = dssl_decoder_add_to_buffer( d, data, len );

		if( rc == DSSL_RC_OK )
		{
			data = d->buff;
			len = d->buff_used_len; 
		}
	}

	while( rc == DSSL_RC_OK && processed < len )
	{
		uint32_t p = 0;
		rc = d->handler( d->handler_data, dir, data + processed, len - processed, &p );
		processed += p;

		/* can't be all ok and no data processed */
		if( p == 0 && rc == DSSL_RC_OK ) { rc = NM_ERROR( DSSL_E_UNSPECIFIED_ERROR ); }
	}

	if( !NM_IS_FAILED( rc ) )
	{
		if( d->buff_used_len > 0 )
		{
			rc = dssl_decoder_shift_buffer( d, processed );
		}
		else if( processed < len )
		{
			rc = dssl_decoder_add_to_buffer( d, data + processed, len - processed );
		}
	}

	return rc;
}
