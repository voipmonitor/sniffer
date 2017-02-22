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
#ifndef __DSSL_SSL_CTX_H__
#define __DSSL_SSL_CTX_H__

/* Network definition includes needed for "struct in_addr" */
#include "netdefs.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* DSSL_ServerInfo - maps server ip:port to SSL certificate, RSA private key file 
	and key file password */

struct DSSL_ServerInfo_
{
	struct in_addr	server_ip;
	uint16_t		port;
	EVP_PKEY*		pkey;
};


typedef struct _DSSL_Env
{
	DSSL_ServerInfo**		servers;
	int						server_count;

	DSSL_ServerInfo**		missing_key_servers;
	int						missing_key_server_count;

	dssl_SessionKeyTable*		session_cache;
	DSSL_SessionTicketTable*	ticket_cache;

	EVP_PKEY**				keys;
	int						key_count;
	int						keys_try_index; /* round-robin index of the first key to try */

#ifndef NM_MULTI_THREADED_SSL
	u_char			decompress_buffer[DSSL_MAX_RECORD_LENGTH];
	u_char			decrypt_buffer[DSSL_MAX_COMPRESSED_LENGTH];
#else
	#error "Multi-threading is not implemented for DSSL_Env"
#endif

} DSSL_Env;


DSSL_Env* DSSL_EnvCreate( int session_cache_size, uint32_t cache_timeout_interval );
void DSSL_EnvDestroy( DSSL_Env* env );


/* SSL Server info */
int DSSL_EnvSetServerInfoWithKey( DSSL_Env* env, const struct in_addr* ip_address,
	uint16_t port, EVP_PKEY *pkey );

int DSSL_EnvSetServerInfo( DSSL_Env* env, const struct in_addr* ip_address, uint16_t port, 
			const char* keyfile, const char* password );

/* looks up the server in the server list, and, if found, moves it to the missing 
key server list. Return 1 if found, 0 otherwise */
int DSSL_MoveServerToMissingKeyList( DSSL_Env* env, DSSL_ServerInfo* si );
			
DSSL_ServerInfo* DSSL_EnvFindServerInfo( const DSSL_Env* env, struct in_addr server_ip, uint16_t port );

/* Session mgmt */
DSSL_Session* DSSL_EnvCreateSession( DSSL_Env* env, struct in_addr dst_ip, uint16_t dst_port,
									struct in_addr src_ip, uint16_t src_port );
void DSSL_EnvOnSessionClosing( DSSL_Env* env, DSSL_Session* sess );


/*========= DSSL_ServerInfo =========*/
/* Free a DSSL_ServerInfo structure */
void DSSL_ServerInfoFree( DSSL_ServerInfo* si );

/* Add a RSA key to a known key list. 
NOte: DSSL_Env takes over the memory management of pkey parameter */
int DSSL_AddSSLKey(DSSL_Env* env, EVP_PKEY* pkey);

/* add a server to a list of servers for which there is no PK information available. 
CapEnv will check new sessions against this list and ignore these servers' future traffic */
int DSSL_EnvAddMissingKeyServer( DSSL_Env* env, const struct in_addr server_ip, uint16_t port );

/* returns not null DSSL_Info pointer if the server_ip:port entry is found in the missing SSL key server list, NULL otherwise */
DSSL_ServerInfo* DSSL_EnvIsMissingKeyServer( DSSL_Env* env, const struct in_addr server_ip, uint16_t port );
#ifdef  __cplusplus
}
#endif

#endif /*__DSSL_SSL_CTX_H__*/
