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
#ifndef __DSSL_SSL_UTILS_H__
#define __DSSL_SSL_UTILS_H__

#ifdef  __cplusplus
extern "C" {
#endif

int ssl3_PRF( const u_char* secret, uint32_t secret_len, 
		const u_char* random1, uint32_t random1_len,
		const u_char* random2, uint32_t random2_len,
		u_char* out, uint32_t out_len );

int tls12_PRF( const EVP_MD *md, const u_char* secret, uint32_t secret_len,
		const char* label, u_char* random1, uint32_t random1_len,
		u_char* random2, uint32_t random2_len,
		u_char *out, uint32_t out_len );

int tls1_PRF( const u_char* secret, uint32_t secret_len,
		const char* label, u_char* random1, uint32_t random1_len,
		u_char* random2, uint32_t random2_len,
		u_char *out, uint32_t out_len );

int ssl2_PRF( const u_char* secret, uint32_t secret_len,
		const u_char* challenge, uint32_t challenge_len, 
		const u_char* conn_id, uint32_t conn_id_len,
		u_char* out, uint32_t out_len );

#ifdef  __cplusplus
}
#endif

#endif
