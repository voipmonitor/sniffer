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
#include "stdinc.h"
#include <string.h>
#include "ssl_ctx.h"
#include "ssl_session.h"
#include "ssl_sessionkey_table.h"
#include "tls_ticket_table.h"

/* Free an array of DSSL_ServerInfo structures */

void DSSL_ServerInfoFree( DSSL_ServerInfo* si )
{
	if( si == NULL ) return;

	if( si->pkey != NULL )
	{
		EVP_PKEY_free( si->pkey );
		si->pkey = NULL;
	}

	free( si );
}


static void DSSL_ServerInfoFreeArray( DSSL_ServerInfo** si, int size )
{
	int i;
	_ASSERT( si );
	_ASSERT( size > 0 );

	for( i = 0; i < size; i++ ) 
	{
		DSSL_ServerInfoFree( si[i] );
	}

	free( si );
}


/* simple password callback function to use with openssl certificate / private key API */
static int password_cb_direct( char *buf, int size, int rwflag, void *userdata )
{
	char* pwd = (char*) userdata;
	int len = (int) strlen( pwd );

	//rwflag;

	strncpy( buf, pwd, size );
	return len;
}


static int ServerInfo_LoadPrivateKey( EVP_PKEY **pkey, const char *keyfile, const char *pwd )
{
	FILE* f = NULL;
	int rc = DSSL_RC_OK;

	f = fopen( keyfile, "r" );
	if( !f ) return NM_ERROR( DSSL_E_SSL_PRIVATE_KEY_FILE_OPEN );

	if( rc == DSSL_RC_OK && PEM_read_PrivateKey( f, pkey, password_cb_direct, (void*)pwd ) == NULL )
	{
		rc = NM_ERROR( DSSL_E_SSL_LOAD_PRIVATE_KEY );
	}

	fclose( f );

	return rc;
}


DSSL_Session* DSSL_EnvCreateSession( DSSL_Env* env, struct in_addr dst_ip, uint16_t dst_port,
									struct in_addr src_ip, uint16_t src_port)
{
	/* first try destination address as the first packet in a session usually 
	comes from a client */
	DSSL_ServerInfo* si = DSSL_EnvFindServerInfo( env, dst_ip, dst_port );
	DSSL_Session* sess = NULL;
	
	/* no SSL server found at dst ip:port, try source ip:port before leaving si to be NULL,
	which triggers SSL key auto-discover */
	if(!si) si = DSSL_EnvFindServerInfo( env, src_ip, src_port );
	
	sess = malloc( sizeof( DSSL_Session) );
	DSSL_SessionInit( env, sess, si );

	return sess;
}


void DSSL_EnvOnSessionClosing( DSSL_Env* env, DSSL_Session* s )
{
	_ASSERT( env );
	_ASSERT( s );

	if( env->session_cache )
	{
		dssl_SessionKT_Release( env->session_cache, s->session_id );
	}
}


DSSL_Env* DSSL_EnvCreate( int session_cache_size, uint32_t cache_timeout_interval )
{
	DSSL_Env* env = (DSSL_Env*) malloc( sizeof( DSSL_Env ) );
	if( !env ) return NULL;

	memset( env, 0, sizeof( *env ) );

	env->session_cache = dssl_SessionKT_Create( session_cache_size, cache_timeout_interval );
	env->ticket_cache = dssl_SessionTicketTable_Create( session_cache_size, cache_timeout_interval );

	return env;
}


void DSSL_EnvDestroy( DSSL_Env* env )
{
	if( env->servers ) 
	{
		_ASSERT( env->server_count > 0 );
		DSSL_ServerInfoFreeArray( env->servers, env->server_count );
		env->server_count = 0;
		env->servers = NULL;
	}

	if( env->missing_key_servers )
	{
		_ASSERT( env->missing_key_server_count > 0 );
		DSSL_ServerInfoFreeArray( env->missing_key_servers, env->missing_key_server_count );
		env->missing_key_server_count = 0;
		env->missing_key_servers = NULL;
	}

	if( env->session_cache )
	{
		dssl_SessionKT_Destroy( env->session_cache );
	}

	if( env->ticket_cache )
	{
		dssl_SessionTicketTable_Destroy( env->ticket_cache );
	}

	if( env->keys )
	{
		int i = 0;
		_ASSERT( env->key_count > 0 );
		for(i = 0; i < env->key_count; i++)
		{
			EVP_PKEY_free( env->keys[i] );
		}

		free( env->keys);
		env->keys = NULL; env->key_count = 0;
	}

	free( env );
}

int DSSL_EnvAddServer( DSSL_Env* env, DSSL_ServerInfo* server )
{
	DSSL_ServerInfo** new_servers = NULL;
	int i = 0;

	/* sanity check if server already exists in the list */
	for(i = 0; i < env->server_count; i++)
	{
		_ASSERT( env->servers && env->servers[i]);
		if(env->servers[i]->port == server->port && INADDR_IP(env->servers[i]->server_ip) == INADDR_IP(server->server_ip))
			return NM_ERROR( DSSL_E_SSL_DUPLICATE_SERVER );
	}

	new_servers = realloc( env->servers, (env->server_count + 1)*sizeof(*env->servers) );

	if( new_servers == NULL ) return NM_ERROR( DSSL_E_OUT_OF_MEMORY );

	new_servers[env->server_count] = server;
	env->servers = new_servers;
	env->server_count++;

	return DSSL_RC_OK;
}


int DSSL_EnvAddMissingKeyServerInfo( DSSL_Env* env, DSSL_ServerInfo* server )
{
	DSSL_ServerInfo** new_servers = NULL;
	int i = 0;

	/* sanity check if server already exists in the list */
	for(i = 0; i < env->missing_key_server_count; i++)
	{
		_ASSERT( env->missing_key_servers && env->missing_key_servers[i]);
		if(env->missing_key_servers[i]->port == server->port && INADDR_IP(env->missing_key_servers[i]->server_ip) == INADDR_IP(server->server_ip))
			return NM_ERROR( DSSL_E_SSL_DUPLICATE_SERVER );
	}

	new_servers = realloc( env->missing_key_servers, (env->missing_key_server_count + 1)*sizeof(*env->missing_key_servers) );
	if( new_servers == NULL ) return NM_ERROR( DSSL_E_OUT_OF_MEMORY );

	new_servers[env->missing_key_server_count] = server;
	env->missing_key_servers = new_servers;
	env->missing_key_server_count++;
	return DSSL_RC_OK;
}


int DSSL_EnvAddMissingKeyServer( DSSL_Env* env, const struct in_addr server_ip, uint16_t port )
{
	DSSL_ServerInfo* server = (DSSL_ServerInfo*)malloc(sizeof(DSSL_ServerInfo));

	if(!server) return NM_ERROR( DSSL_E_OUT_OF_MEMORY );

	memset( server, 0, sizeof(DSSL_ServerInfo));
	server->port = port;
	server->server_ip = server_ip;
	server->pkey = NULL;


	return DSSL_EnvAddMissingKeyServerInfo( env, server );
}


int DSSL_EnvSetServerInfoWithKey( DSSL_Env* env, const struct in_addr* ip_address,
	uint16_t port, EVP_PKEY *pkey )
{
	DSSL_ServerInfo* server = NULL;
	int rc = DSSL_RC_OK;

	if( !pkey ) return NM_ERROR( DSSL_E_INVALID_PARAMETER );

	server = (DSSL_ServerInfo*) calloc( 1, sizeof( DSSL_ServerInfo ) );
	
	if( !server ) return NM_ERROR( DSSL_E_OUT_OF_MEMORY );

	memcpy( &server->server_ip,  ip_address, sizeof(server->server_ip) ) ;
	server->port = port;
	server->pkey = pkey;

	rc = DSSL_EnvAddServer( env, server );

	if( rc != DSSL_RC_OK )
	{
		DSSL_ServerInfoFree( server );
	}

	return DSSL_RC_OK;
}


int DSSL_EnvSetServerInfo( DSSL_Env* env, const struct in_addr* ip_address, uint16_t port, 
			const char* keyfile, const char* password )
{
	int rc = DSSL_RC_OK;
	EVP_PKEY *pkey = NULL;

	if ( !keyfile )
		return NM_ERROR( DSSL_E_INVALID_PARAMETER );

	if ( !password )
		password = "";

	rc = ServerInfo_LoadPrivateKey( &pkey, keyfile, password );
	if( rc != DSSL_RC_OK ) 
	{
		return rc;
	}

	rc = DSSL_EnvSetServerInfoWithKey( env, ip_address, port, pkey );
	return rc;
}


/* find DSSL_ServerInfo in a table by ip:port */
DSSL_ServerInfo* DSSL_EnvFindServerInfo( const DSSL_Env* env, struct in_addr ip_address, uint16_t port )
{
	int i;
	for( i = 0; i < env->server_count; i++ )
	{
		DSSL_ServerInfo* si = env->servers[i];

		if( INADDR_IP( si->server_ip ) == INADDR_IP( ip_address ) &&
			port == si->port ) return si;
	}

	return NULL;
}

/* shallow key check by pointer comparision only */
int DSSL_GetSSLKeyIndex( const DSSL_Env* env, EVP_PKEY* pkey)
{
	int i = 0;

	for(i = 0; i < env->key_count; i++)
	{
		if( pkey == env->keys[i] ) return i;
	}

	return -1;
}

int DSSL_AddSSLKey(DSSL_Env* env, EVP_PKEY* pkey)
{
	/* check if the key already exist*/
	int i = DSSL_GetSSLKeyIndex(env, pkey);
	EVP_PKEY** new_keys = NULL;
	_ASSERT(env && pkey);

	if(i != -1) return DSSL_RC_OK;
	
	new_keys = realloc(env->keys, (env->key_count+1)*sizeof(*env->keys));
	if(new_keys == NULL) return NM_ERROR(DSSL_E_OUT_OF_MEMORY);	

	new_keys[env->key_count] = pkey;
	env->keys = new_keys;
	++env->key_count;

	return DSSL_RC_OK;
}

int DSSL_MoveServerToMissingKeyList( DSSL_Env* env, DSSL_ServerInfo* si )
{
	DSSL_ServerInfo** new_servers = NULL;
	int i = 0; int ni = 0;
	int found = 0;
	_ASSERT( env );

	if( env->server_count > 1 )
		new_servers = (DSSL_ServerInfo**) malloc( (env->server_count - 1)*sizeof(*env->servers) );

	for(i = 0, ni = 0; i < env->server_count; i++)
	{
		if(!found && env->servers[i] == si)
		{
			DSSL_EnvAddMissingKeyServerInfo( env, si );
			found = 1;
		}
		else if(new_servers && ni < (env->server_count - 1))
		{
			new_servers[ni] = env->servers[i];
			++ni;
		}
	}

	if(found)
	{
		free(env->servers);
		env->servers = new_servers;
		--env->server_count;
	}
	else if(new_servers)
	{
		free(new_servers);
		new_servers = NULL;
	}

	return found;
}

DSSL_ServerInfo* DSSL_EnvIsMissingKeyServer( DSSL_Env* env, const struct in_addr server_ip, uint16_t port )
{
	int i = 0;
	_ASSERT( env );

	for(i = 0; i < env->missing_key_server_count; i++)
	{
		_ASSERT( env->missing_key_servers && env->missing_key_servers[i]);
		if(env->missing_key_servers[i]->port == port && INADDR_IP(env->missing_key_servers[i]->server_ip) == INADDR_IP(server_ip))
			return env->missing_key_servers[i];
	}

	return NULL;
}
