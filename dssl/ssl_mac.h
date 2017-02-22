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
#ifndef __DSSL_SSL_MAC_H__
#define __DSSL_SSL_MAC_H__

int ssl3_calculate_mac( dssl_decoder_stack* stack, u_char type, 
						 u_char* data, uint32_t len, u_char* mac );

int tls1_calculate_mac( dssl_decoder_stack* stack, u_char type, 
						 u_char* data, uint32_t len, u_char* mac );

int ssl2_calculate_mac( dssl_decoder_stack* stack, u_char type,
						u_char* data, uint32_t len, u_char* mac );

int tls1_decode_finished( DSSL_Session* sess, NM_PacketDir dir, u_char* data, uint32_t len );
int ssl3_decode_finished( DSSL_Session* sess, NM_PacketDir dir, u_char* data, uint32_t len );

#endif
