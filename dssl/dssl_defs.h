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
#ifndef __DSSL_DSSL_DEFS_H__
#define __DSSL_DSSL_DEFS_H__

#ifdef  __cplusplus
extern "C" {
#endif

#define DSSL_VERSION_MAJOR		1
#define DSSL_VERSION_MINOR		73
#define DSSL_VERSION_STRING		"1.7.3"

typedef enum NM_SessionType_
{
	eSessionTypeNull = 0,
	eSessionTypeTcp = 1,
	eSessionTypeSSL = 2,
	eSessionTypeTBD = 3
} NM_SessionType;

typedef enum NM_PacketDir_
{
	ePacketDirInvalid,
	ePacketDirFromClient,
	ePacketDirFromServer
} NM_PacketDir;

typedef enum NM_SessionEvents_
{
	eNull,					/* null event */
	eSslHandshakeComplete,	/* SSL handshake complete: event_data contains handshake time in srtuct timeval */
	eSslMappedKeyFailed,	/* SSL auto-mapped key failed: event data contains session's DSSL_ServerInfo* */
	eSslMappingDiscovered,  /* SSL server has been found and RSA private key mapped to its IP:port 
									event data contains session's DSSL_ServerInfo*  */
	eSslMissingServerKey	/* SSL traffic has been detected on this ip:port, but no matching RSA private key was found 
									event data contains DSSL_ServerInfo* with ip and port fields filled */
} NM_SessionEvents;

/* Forward declarations */

struct DSSL_Pkt_;
typedef struct DSSL_Pkt_ DSSL_Pkt;

struct DSSL_handshake_buffer_;
typedef struct DSSL_handshake_buffer_ DSSL_handshake_buffer;

struct DSSL_Session_;
typedef struct DSSL_Session_ DSSL_Session;

struct DSSL_ServerInfo_;
typedef struct DSSL_ServerInfo_ DSSL_ServerInfo;

struct dssl_SessionKeyTable_;
typedef struct dssl_SessionKeyTable_ dssl_SessionKeyTable;

typedef struct dssl_SessionTable_ dssl_SessionTable;

struct  _DSSL_SessionTicketTable;
typedef struct _DSSL_SessionTicketTable  DSSL_SessionTicketTable;

struct _TcpSession;
typedef struct _TcpSession TcpSession;

struct CapEnv_;
typedef struct CapEnv_ CapEnv;

struct _TcpStream;
typedef struct _TcpStream TcpStream;

struct _DSSL_CipherSuite;
typedef struct _DSSL_CipherSuite DSSL_CipherSuite;

struct dssl_decoder_;
typedef struct dssl_decoder_ dssl_decoder;

struct dssl_decoder_stack_;
typedef struct dssl_decoder_stack_ dssl_decoder_stack;

/* TCP or SSL decoder callback */
typedef void (*DataCallbackProc)( NM_PacketDir dir, void* user_data, u_char* data, uint32_t len, DSSL_Pkt* pkt );
typedef void (*ErrorCallbackProc)( void* user_data, int error_code );
typedef void (*PacketCallbackProc)( void* user_data, DSSL_Pkt* pkt );

/**
MissingPacketCallbackProc routine:
@param dir - packet direction
@param user_data - TCP session's user_data field
@param seq - TCP sequence
@param len - missing segment length
@return 0 - terminate the session; 1 - skip the missing segment and continue
*/
typedef int (*MissingPacketCallbackProc)( NM_PacketDir dir, void* user_data, uint32_t seq, uint32_t len );

/**EventCAallbackProc: callback function for TCP session events
@param user_data - TCP session's user_data field
@param event_code - event code as defined in NM_SessionEvents enum
@param event_data - event specific data 
@see NM_SessionEvents
*/
typedef void (*EventCallbackProc)(void* user_data, int event_code, const void* event_data);

#define IS_ENOUGH_LENGTH( org_data, org_len, cur_data, size_needed ) ( (org_data) + (org_len) >= (cur_data) + (size_needed) )
#define _ASSERT_STATIC(e) 1/(e)
#define UNUSED_PARAM( p ) (p)


/*TODO: remove to a separate file */
#define SSL3_HEADER_LEN		5
#define SSL20_CLIENT_HELLO_HDR_LEN		2
#define SSL20_SERVER_HELLO_MIN_LEN		10
#define SSL3_SERVER_HELLO_MIN_LEN		38
#define SSL3_HANDSHAKE_HEADER_LEN		4
#define SSL2_KEYARG_MAX_LEN 8

#define DSSL_SESSION_ID_SIZE	32

#define RFC_2246_MAX_RECORD_LENGTH	16384

#ifdef DSSL_NO_COMPRESSION
	#define RFC_2246_MAX_COMPRESSED_LENGTH	RFC_2246_MAX_RECORD_LENGTH
#else
	#define RFC_2246_MAX_COMPRESSED_LENGTH	(RFC_2246_MAX_RECORD_LENGTH + 1024)
#endif

#define DSSL_MAX_RECORD_LENGTH	32767
#define DSSL_MAX_COMPRESSED_LENGTH (DSSL_MAX_RECORD_LENGTH	+ 1024)

#define DSSL_DEFAULT_MISSING_PACKET_COUNT		100
#define DSSL_DEFAULT_MISSING_PACKET_TIMEOUT		180

/*
#define NM_MULTI_THREADED_SSL
*/

/* SSL session cache cleanup interval */
#define DSSL_CACHE_CLEANUP_INTERVAL		180

#ifdef  __cplusplus
}
#endif

#endif
