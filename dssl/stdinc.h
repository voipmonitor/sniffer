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
#ifndef __DSSL_STDINC_H__
#define __DSSL_STDINC_H__

#include "../common.h"
//#define _DEBUG true

#ifdef _WIN32
  #define _CRT_SECURE_NO_WARNINGS 
  #ifdef _WIN32_WINNT
  #undef _WIN32_WINNT
  #endif
  #define _WIN32_WINNT 0x0501  // Specifies that the minimum required platform is Windows XP.
#endif

#if defined(_WIN32)
  #ifdef _DEBUG
    #define _CRTDBG_MAP_ALLOC
    #include <stdlib.h>
    #include <crtdbg.h>
  #else
    #define _ASSERT( exp ) ((void)0)
  #endif
  #define DSSL_STRDUP(x) _strdup(x)

#else
  #include <stdlib.h>
  #ifdef _DEBUG
    #include <assert.h>
    #define FALSE 0
    #define _ASSERT( exp ) assert( exp )
  #else
    #define _ASSERT( exp ) ((void)0)
  #endif
  #define DSSL_STRDUP(x) strdup(x)
#endif

#ifdef FREEBSD
  #include <stdlib.h>
/* workaround, I don't how to fix better */
  #define s6_addr32 __u6_addr.__u6_addr32
#else
  #ifndef WIN32
    #include <alloca.h>
  #else
    #include <malloc.h>
  #endif
#endif

#include "ptypes.h"

#ifdef _WIN32
#pragma warning(push, 3)
#include <pcap.h>
#pragma warning(pop)
#include <ws2ipdef.h>
#else
#include <pcap.h>
#endif

#include "log.h"
#include "errors.h"

#ifndef FIELD_OFFSET
#define FIELD_OFFSET( t, f ) ((int) &(((t*)NULL)->f))
#endif

#include <openssl/ssl.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "dssl_defs.h"
#include "netdefs.h"


#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
HMAC_CTX *HMAC_CTX_new(void);
void HMAC_CTX_free(HMAC_CTX *ctx);
void EVP_MD_CTX_reset(EVP_MD_CTX *ctx);
struct rsa_st *EVP_PKEY_get0_RSA(EVP_PKEY *pkey);
#endif


#endif
