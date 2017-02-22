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
#ifndef __DSSL_PTYPES_H__
#define __DSSL_PTYPES_H__

#ifdef _WIN32
typedef unsigned char		uint8_t;
typedef short				int16_t;
typedef unsigned short		uint16_t;
typedef int					int32_t;
typedef unsigned int		uint32_t;
typedef __int64				int64_t;
typedef unsigned __int64	uint64_t;
#else
#include <inttypes.h>
#endif

#define MAKE_UINT16( high, low ) ((((uint16_t)high) << 8) | (low))
#define MAKE_UINT24( b1, b2, b3 ) ( (((uint32_t)(b1)) << 16) | (((uint32_t)(b2)) << 8) | ((uint32_t)(b3)) )
#endif
