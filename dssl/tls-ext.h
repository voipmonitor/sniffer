#ifndef __DSSL_TLS_EXT_H__
#define __DSSL_TLS_EXT_H__


#include <openssl/ssl.h>

#ifndef TLS1_3_VERSION
#define TLS1_3_VERSION 0x0304
#endif

#include <sys/types.h>

u_int8_t tls_13_generate_keys(void* dssl_sess, u_int8_t restore_session);
u_int8_t tls_12_generate_keys(void* dssl_sess, u_int8_t restore_session);
void tls_destroy_session(void* dssl_sess);
u_int8_t tls_decrypt_record(void* dssl_sess, u_char* data, u_int32_t len, 
			    u_int8_t record_type, u_int16_t record_version, u_int8_t is_from_server, 
			    u_char* rslt, u_int32_t rslt_max_len, u_int32_t *rslt_len);


#endif
