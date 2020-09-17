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
#ifndef __DSSL_SSL_DECODE_HS_H__
#define __DSSL_SSL_DECODE_HS_H__

#ifdef  __cplusplus
extern "C" {
#endif


int ssl3_decode_handshake_record( dssl_decoder_stack* stack, NM_PacketDir dir, 
		u_char* data, uint32_t len, uint32_t* processed );

int ssl_decode_first_client_hello( DSSL_Session* sess, u_char* data, 
		uint32_t len, uint32_t* processed );

int ssl_detect_client_hello_version( u_char* data, uint32_t len, uint16_t* ver );

int ssl_detect_server_hello_version( u_char* data, uint32_t len, uint16_t* ver );

void ssl3_init_handshake_digests( DSSL_Session* sess );
int ssl3_update_handshake_digests( DSSL_Session* sess, u_char* data, uint32_t len );

#ifdef  __cplusplus
}
#endif

#endif
