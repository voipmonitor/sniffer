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
#ifndef __DSSL_COMPRESSION_H__
#define __DSSL_COMPRESSION_H__

/* generic routines to init/deinit compression state */
int dssl_compr_init( u_char compr_method, void** compr_state );
void dssl_compr_deinit( u_char compr_method, void* compr_state );

int dssl_decompress( u_char compr_method, void* compr_state, u_char* in_data, uint32_t in_len,
					u_char* out_data, uint32_t* out_len );
#endif
