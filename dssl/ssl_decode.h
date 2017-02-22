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
#ifndef __DSSL_SSL_DECODE_H__
#define __DSSL_SSL_DECODE_H__

/* 
This file contain function prototypes for various SSL 3.0 / TLS 1.0 protocol decoders 
*/

#include "decoder.h"

#ifdef  __cplusplus
extern "C" {
#endif

int ssl3_record_layer_decoder( void* decoder_stack, NM_PacketDir dir, 
		u_char* data, uint32_t len, uint32_t* processed );

int ssl3_change_cipher_spec_decoder( void* decoder_stack, NM_PacketDir dir,
		u_char* data, uint32_t len, uint32_t* processed );

int ssl_application_data_decoder( void* decoder_stack, NM_PacketDir dir,
		u_char* data, uint32_t len, uint32_t* processed );

int ssl3_alert_decoder( void* decoder_stack, NM_PacketDir dir,
		u_char* data, uint32_t len, uint32_t* processed );

#ifdef  __cplusplus
}
#endif

#endif
