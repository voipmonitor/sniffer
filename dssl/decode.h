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
#ifndef __DSSL_DECODE_H__
#define __DSSL_DECODE_H__

#include "packet.h"
#include "capenv.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* *******************************************************
	decode.h: Contains prototypes for protocol decoder
	routines.
*/

#ifndef DSSL_NO_PCAP
/* Returns a pcap callback handler for given adapter */
pcap_handler GetPcapHandler( pcap_t* p );
#endif

void DecodeIpPacket( CapEnv* env, DSSL_Pkt* pkt, const uint8_t* data, const int len );
void DecodeTcpPacket( CapEnv* env, DSSL_Pkt* pkt, const uint8_t* data, const int len );
void DecodeUdpPacket( CapEnv* env, DSSL_Pkt* pkt, const uint8_t* data, const int len );

#ifdef  __cplusplus
}
#endif

#endif
