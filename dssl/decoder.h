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
#ifndef __NM_DECODER_H__
#define __NM_DECODER_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include "dssl_defs.h"

typedef int (*sslc_decode_proc)( void* state,
		NM_PacketDir dir, u_char* data, uint32_t len, uint32_t* processed );

struct dssl_decoder_
{
	void*				handler_data; /* SSL session, etc. */
	sslc_decode_proc	handler;
	/* decoding buffer */
	uint32_t			buff_len;
	uint32_t			buff_used_len;
	u_char*				buff;
};

void dssl_decoder_init( dssl_decoder* decoder, sslc_decode_proc handler, void* handler_data );
void dssl_decoder_deinit( dssl_decoder* decoder );

int dssl_decoder_process( dssl_decoder* decoder, NM_PacketDir dir, u_char* data, uint32_t len );

int dssl_decoder_add_to_buffer( dssl_decoder* decoder, u_char* data, uint32_t len );
int dssl_decoder_shift_buffer( dssl_decoder* decoder, uint32_t processed_len );

#ifdef  __cplusplus
}
#endif

#endif
