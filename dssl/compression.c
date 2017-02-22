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
#include "compression.h"
#include "errors.h"

#include <zlib.h>

#define COMPRESSION_DEFLATE		1

int dssl_compr_init( u_char compr_method, void** compr_state )
{
	int rc = DSSL_RC_OK;

	switch( compr_method )
	{
	case 0: break;
	case COMPRESSION_DEFLATE:
		{
			z_stream * zs = (z_stream*) malloc( sizeof(z_stream) );
			int err = Z_OK;

			zs->zalloc = Z_NULL;
			zs->zfree = Z_NULL;
			zs->opaque = Z_NULL;
			zs->next_in = Z_NULL;
			zs->next_out = Z_NULL;
			zs->avail_in = 0;
			zs->avail_out = 0;
			err = inflateInit(zs);

			if( err != Z_OK ) 
			{
				free( zs );
				rc = NM_ERROR( DSSL_E_DECOMPRESSION_ERROR );
			}
			else
			{
				rc = DSSL_RC_OK;
				(*compr_state) = zs;
			}
		}
		break;

	default:
		rc = NM_ERROR( DSSL_E_UNSUPPORTED_COMPRESSION ); /* unknown compression method */
		break;
	}

	return rc;
}


void dssl_compr_deinit( u_char compr_method, void* compr_state )
{
	if( compr_state == NULL ) return;

	switch( compr_method )
	{
	case 0: break;
	case COMPRESSION_DEFLATE:
		{
			z_stream* zs = (z_stream*) compr_state;
			_ASSERT( zs );

			inflateEnd( zs );
			free( zs );
		}
		break;

	default:
		_ASSERT( FALSE ); /* unknown compression method */
		break;
	}
}

int dssl_decompress( u_char compr_method, void* compr_state, u_char* in_data, uint32_t in_len,
					u_char* out_data, uint32_t* out_len )
{
	int rc = DSSL_RC_OK;
	z_stream * zs = (z_stream*) compr_state;
	/* right now only DEFLATE method is supported */
	if( compr_method != COMPRESSION_DEFLATE ) return NM_ERROR( DSSL_E_UNSUPPORTED_COMPRESSION );

	_ASSERT( zs );

	zs->next_in = in_data;
	zs->avail_in = in_len;
	zs->next_out = out_data;
	zs->avail_out = *out_len;

	if( in_len > 0 )
	{
		int zlib_rc = inflate( zs, Z_SYNC_FLUSH );
		if( zlib_rc != Z_OK ) { rc = NM_ERROR( DSSL_E_DECOMPRESSION_ERROR ); }
	}

	if( rc == DSSL_RC_OK )
	{
		(*out_len) = (*out_len) - zs->avail_out;
	}

	return rc;

}