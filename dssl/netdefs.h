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
#ifndef __DSSL_NETDEFS_H__
#define __DSSL_NETDEFS_H__

#if defined( _WIN32)
  #include "win32/include/netinet/ether.h"
  #include "win32/include/netinet/ethertype.h"
  #include "win32/include/netinet/ip.h"
  #include "win32/include/netinet/tcp.h"
  #include "win32/include/netinet/udp.h"

#elif defined(__linux)
  #include <features.h>
  #define __FAVOR_BSD
  #include <netinet/ether.h>

#elif defined(__FreeBSD__) || defined(__APPLE__)
  #include <netinet/in_systm.h>
  #include <netinet/in.h>
  #include <net/ethernet.h>

#ifndef s6_addr32
#define	s6_addr32	__u6_addr.__u6_addr32
#endif

#elif defined(__SunOS_5_10)
  #include <strings.h>		/* the ip_compat.h conflics bcopy->memmove */
  #include <netinet/ip_compat.h>
  #include <netinet/if_ether.h>

#elif defined(__SunOS_5_8) || defined(__SunOS_5_9) || ( defined(__GNUC__) && defined(__sun__) )
  #include <sys/socket.h>
  #include <sys/ethernet.h>
  #include <netinet/in_systm.h>

#elif defined(_AIX)
  #include <netinet/if_ether.h>

#elif defined(__hpux)
  #include <netinet/in_systm.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <net/if_arp.h>
  #include <netinet/if_ether.h>

#else
  #include <netinet/ether.h>

#endif

#if !defined( _WIN32)
  #include <netinet/ip.h>
  #include <netinet/tcp.h>
  #include <netinet/udp.h>
  #include <netinet/ip6.h>
  #ifndef ETHERTYPE_IPV6
    #define ETHERTYPE_IPV6  0x86dd
  #endif
  #ifndef ETHER_HDRLEN
    #define ETHER_HDRLEN  14
  #endif
  #ifndef TH_ECNECHO
    #define TH_ECNECHO    0x40  /* ECN Echo */
  #endif
  #ifndef TH_CWR
    #define TH_CWR        0x80  /* ECN Cwnd Reduced */
  #endif
#endif

#define MAKE_IP( b1, b2, b3, b4 ) ((uint32_t)(b1 | ((uint32_t)b2 << 8) | ((uint32_t)b3 << 16) | ((uint32_t)b4 << 24 )))

#if !defined(_WIN32)
  #ifndef INADDR_IP
    #define INADDR_IP( _inaddr ) ((_inaddr).s_addr)
  #endif
  #ifndef NM_TCP_HDR_LEN
    #define NM_TCP_HDR_LEN( hdr ) (((u_char)(hdr)->th_off ) << 2 )
  #endif
  #ifndef IP_V
    #define IP_V(ip ) ((ip)->ip_v)
  #endif
  #ifndef IP_HL
    #define IP_HL(ip) ((ip)->ip_hl)
  #endif
#else
  #define INADDR_IP( _inaddr ) ((_inaddr).S_un.S_addr)
  #define NM_TCP_HDR_LEN( hdr ) (((hdr)->th_offx2 & 0xF0 ) >> 2 )
#endif

#endif
