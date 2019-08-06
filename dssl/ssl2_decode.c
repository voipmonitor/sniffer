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

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)

#include "ssl_session.h"
#include "ssl2_decode.h"
#include "session.h"
#include "decoder_stack.h"

static int ssl_decrypt_record( dssl_decoder_stack* stack, u_char* data, uint32_t len, 
					  u_char** out, int *buffer_aquired )
{
	u_char* buf = NULL;
	uint32_t buf_len = len;
	int rc = DSSL_RC_OK;
	int block_size;
	const EVP_CIPHER* c = NULL;


	_ASSERT( stack );
	_ASSERT( stack->sess );
	_ASSERT( stack->cipher );

	rc = ssls_get_decrypt_buffer( stack->sess, &buf, buf_len );
	if( rc != DSSL_RC_OK ) return rc;

	*buffer_aquired = 1;

	c = EVP_CIPHER_CTX_cipher( stack->cipher );
	block_size = EVP_CIPHER_block_size( c );

	if( block_size != 1 )
	{
		if( len == 0 || (len % block_size) != 0 )
		{
			return NM_ERROR( DSSL_E_SSL_DECRYPTION_ERROR );
		}
	}

	EVP_Cipher(stack->cipher, buf, data, len );

	*out = buf;

	return DSSL_RC_OK;
}


int ssl2_record_layer_decoder( void* decoder_stack, NM_PacketDir dir, 
		u_char* data, uint32_t len, uint32_t* processed )
{
	int rc = DSSL_RC_OK;
	uint32_t recLen = 0;
	uint32_t totalRecLen = 0;
	uint32_t hdrLen = 0;
	uint32_t padding = 0;
	dssl_decoder_stack* stack = (dssl_decoder_stack*) decoder_stack;
	dssl_decoder* next_decoder = NULL;
	int decrypt_buffer_aquired = 0;

	//dir; /* unused */

	_ASSERT( stack );
	_ASSERT( processed );
	_ASSERT( stack->sess );

/* TODO add session state check */

	if( len < 2 ) { return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH ); }

	if( data[0] & 0x80 )
	{
		/* 2 byte record header format */
		hdrLen = 2;
		recLen = ((data[0] & 0x7f) << 8) | data[1];
		padding = 0;
	}
	else
	{
		/* 3 byte record header format */ 
		hdrLen = 3;
		if (len < 3 ) { return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH ); }
		recLen = ((data[0] & 0x3f) << 8) | data[1];
		padding = data[2];
		/* TODO add IS-ESCAPE handling */
	}

	totalRecLen = recLen; /* save the outer record length */

#ifdef NM_TRACE_SSL_RECORD
	DEBUG_TRACE1( "\n==>Decoding SSL v2 Record; len: %d\n{", (int) recLen );
#endif

	if( len < recLen ) { rc = DSSL_RC_WOULD_BLOCK; }
	/* advance to the actual record */
	data += hdrLen; 

	/* TODO: calculate the MAC, subtract the padding */

	/* decrypt the data */
	if( rc == DSSL_RC_OK && stack->cipher )
	{
		rc = ssl_decrypt_record( stack, data, recLen, &data, &decrypt_buffer_aquired );
	}

	/* calculate and verify the MAC */
	if( rc == DSSL_RC_OK && stack->md )
	{
		/* TODO: calculate the MAC */
		data += EVP_MD_size( stack->md );
		recLen -= EVP_MD_size( stack->md );
	}

	/* strip the padding */
	if( rc == DSSL_RC_OK && padding )
	{
		if( padding >= recLen ) 
		{
			rc = NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
		}
		else
		{
			recLen -= padding;
		}
	}

	if( rc == DSSL_RC_OK )
	{
		switch( stack->state )
		{
		case SS_Initial:
		case SS_SeenClientHello:
		case SS_SeenServerHello:
			next_decoder = &stack->dhandshake;
			break;
		case SS_Established:
			next_decoder = &stack->dappdata;
			break;

		default:
			rc = NM_ERROR( DSSL_E_SSL_UNEXPECTED_TRANSMISSION );
			break;
		}
	}

	if( rc == DSSL_RC_OK )
	{
		_ASSERT( next_decoder != NULL );
		rc = dssl_decoder_process( next_decoder, dir, data, recLen );
	}

	if( rc == DSSL_RC_OK )
	{
		*processed = totalRecLen + hdrLen;
	}

#ifdef NM_TRACE_SSL_RECORD
	DEBUG_TRACE1( "\n} rc: %d\n", (int) rc);
#endif

	if( decrypt_buffer_aquired )
	{
		ssls_release_decrypt_buffer( stack->sess );
	}

	return rc;

}

#endif //(OPENSSL_VERSION_NUMBER < 0x10100000L)
