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
#ifndef __DSSL_ERRORS_H__
#define __DSSL_ERRORS_H__

#define NM_IS_FAILED( rc ) ((rc) < 0) 

#define DSSL_RC_WOULD_BLOCK						1
#define DSSL_RC_OK								0
#define DSSL_E_OUT_OF_MEMORY					(-1)
/*#define DSSL_E_SSL_LOAD_CERTIFICATE				(-3) */
#define DSSL_E_SSL_LOAD_PRIVATE_KEY				(-4)
#define DSSL_E_SSL_UNKNOWN_VERSION				(-5)
#define DSSL_E_INVALID_PARAMETER				(-6)
#define DSSL_E_SSL_PROTOCOL_ERROR				(-7)
#define DSSL_E_SSL_INVALID_RECORD_LENGTH 		(-8)
#define DSSL_E_UNSPECIFIED_ERROR				(-9)
#define DSSL_E_NOT_IMPL							(-10)
#define DSSL_E_SSL_SERVER_KEY_UNKNOWN			(-11)
/* SSL: An undecryptable ciphersuite has been chosen */
#define DSSL_E_SSL_CANNOT_DECRYPT				(-12)
/* SSL: Invalid Pre Master Secret */
#define DSSL_E_SSL_CORRUPTED_PMS				(-13)
/* SSL: Protocol version rollback detected (SSL attack?) */
#define DSSL_E_SSL_PMS_VERSION_ROLLBACK			(-14)
/* SSL: Generic decrytion error */
#define DSSL_E_SSL_DECRYPTION_ERROR				(-15)
/* SSL Protocol error: Bad Finished message digest */
#define DSSL_E_SSL_BAD_FINISHED_DIGEST			(-16)
/* TCP reassembly error */
#define DSSL_E_TCP_CANT_REASSEMBLE				(-17)
/* Unexpected transmission - session is already closed or aborted */
#define DSSL_E_SSL_UNEXPECTED_TRANSMISSION		(-18)
/* Message Authentification Code check failed */
#define DSSL_E_SSL_INVALID_MAC					(-19)
/* Session renegotiation detected, but the previous 
session data is not cached - decryption impossible */
#define DSSL_E_SSL_SESSION_NOT_IN_CACHE			(-20)
/* Failed to open the private key file */
#define DSSL_E_SSL_PRIVATE_KEY_FILE_OPEN		(-21)
/* SSL Protocol error: invalid certificate list length */
#define DSSL_E_SSL_INVALID_CERTIFICATE_RECORD	(-22)
/* SSL Protocol error: invalid certificate length */
#define DSSL_E_SSL_INVALID_CERTIFICATE_LENGTH	(-23)
/* Bad server certificate detected */
#define DSSL_E_SSL_BAD_CERTIFICATE				(-24)
/* Function argument is not initialized properly */
#define DSSL_E_UNINITIALIZED_ARGUMENT			(-25)
/* SSL: ephemeral keys cannot be decrypted */
#define DSSL_E_SSL_CANNOT_DECRYPT_EPHEMERAL		(-26)
/* SSL: Only RSA keys can be used with DSSL */
#define DSSL_E_SSL_CANNOT_DECRYPT_NON_RSA		(-27)
/* SSL: Server's certificate is signed with the key different
than the one passed to CapEnvSetSSL_ServerInfo or 
DSSL_EnvSetServerInfo */
#define DSSL_E_SSL_CERTIFICATE_KEY_MISMATCH		(-28)
#define DSSL_E_UNSUPPORTED_COMPRESSION			(-29)
#define DSSL_E_DECOMPRESSION_ERROR				(-30)
#define DSSL_E_SSL2_INVALID_CERTIFICATE_TYPE    (-31)
#define DSSL_E_SSL2_UNKNOWN_CIPHER_KIND		    (-32)
/* Incorrect SERVER-VERIFY - the data doesn't match the client-sent CHALLENGE */
#define DSSL_E_SSL2_BAD_SERVER_VERIFY		    (-33)
/* Incorrect CLIENT-FINISHED - the data doesn't match the server-sent CONNECTION-ID */
#define DSSL_E_SSL2_BAD_CLIENT_FINISHED		    (-34)
/* Reached the maximum number of out-of-order packts in TCP stream's reassembly queue */
#define DSSL_E_TCP_REASSEMBLY_QUEUE_FULL		(-35)
/* Missing packet detected and user-defined callback code decided to abort the session */
#define DSSL_E_TCP_MISSING_PACKET_DETECTED		(-36)
/* TLS Session Ticket is not cached */
#define DSSL_E_SSL_SESSION_TICKET_NOT_CACHED	(-37)
/* Duplicate SSL server entry */
#define DSSL_E_SSL_DUPLICATE_SERVER				(-38)
/* Duplicate SSL server entry */
#define DSSL_E_TCP_GLOBAL_REASSEMBLY_QUEUE_LIMIT (-39)

#define DSSL_E_UNKNOWN_CIPHER_SUITE		(-40)

#define DSSL_E_TLS_GENERATE_KEYS		(-41)
#define DSSL_E_TLS_DECRYPT_RECORD		(-42)

#ifdef _DEBUG
	int NmDebugCatchError( int rc, int line, const char* file );
	#define NM_ERROR( rc ) NmDebugCatchError( rc, __LINE__, __FILE__ )
#else
	#define NM_ERROR( rc ) ( rc )
#endif
#ifdef  __cplusplus
extern "C" {
#endif
void NmDebugCatchError_disable_log();
void NmDebugCatchError_enable_log();
#ifdef  __cplusplus
}
#endif
#define NM_ERROR_DISABLE_LOG NmDebugCatchError_disable_log()
#define NM_ERROR_ENABLE_LOG NmDebugCatchError_enable_log()

#endif
