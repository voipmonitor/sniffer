#ifndef _GNU_SOURCE
#define _GNU_SOURCE // for RTLD_NEXT
#endif


#ifndef HAVE_WOLFSSL

#include <openssl/ssl.h>

#ifndef LIBSSL_SONAME
#define LIBSSL_SONAME "libssl.so"
#endif

#else

#include <wolfssl/ssl.h>
typedef WOLFSSL SSL;
typedef WOLFSSL_CTX SSL_CTX;
typedef WOLFSSL_SESSION SSL_SESSION;
#define SSL_MAX_MASTER_KEY_LENGTH WOLFSSL_MAX_MASTER_KEY_LENGTH
#define SSL3_RANDOM_SIZE 32

#ifndef LIBSSL_SONAME
#define LIBSSL_SONAME "libwolfssl.so"
#endif

#endif


#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <syslog.h>
#include <pthread.h>
#include <string>

#ifdef SSLKEYLOG_TCP
#include "cloud_router_base.h"
#endif


#define BOTH_METHODS 0

#if not defined HAVE_WOLFSSL and OPENSSL_VERSION_NUMBER >= 0x10101000L and not BOTH_METHODS
#define ONLY_KEYLOG_CALLBACK 1
#endif

#define WRITE_THREAD 1

#define DEBUG 1
#define DEBUG_PREFIX "\n * SSL KEYLOG : "
#define DEBUG_TO_SYSLOG 0
//#define DEBUG_TO_FILE "/tmp/sslkeylog.log"

#define ABORT_IF_FAILURE false
#define EXIT_IF_FAILURE false

#define min(a, b) (a < b ? a : b)

#define _SYNC_LOCK(vint) while(__sync_lock_test_and_set(&vint, 1)) {};
#define _SYNC_LOCK_USLEEP(vint, us_sleep) while(__sync_lock_test_and_set(&vint, 1)) { if(us_sleep) { usleep(us_sleep); } }
#define _SYNC_UNLOCK(vint) __sync_lock_release(&vint);


extern "C" {
typedef SSL *(*SSL_new_type)(SSL_CTX *ctx);
typedef void (*SSL_CTX_set_keylog_callback_type)(SSL_CTX *ctx, void (*)(const SSL *ssl, const char *line));
typedef int (*SSL_connect_type)(SSL *ssl);
typedef int (*SSL_do_handshake_type)(SSL *ssl);
typedef int (*SSL_accept_type)(SSL *ssl);
typedef int (*SSL_read_type)(SSL *ssl, void *buf, int num);
typedef int (*SSL_write_type)(SSL *ssl, const void *buf, int num);
typedef SSL_SESSION *(*SSL_get_session_type)(const SSL *ssl);
typedef size_t (*SSL_get_client_random_type)(const SSL *ssl, unsigned char *out, size_t outlen);
typedef size_t (*SSL_SESSION_get_master_key_type)(const SSL_SESSION *session, unsigned char *out, size_t outlen);
#ifdef HAVE_WOLFSSL
typedef void (*SSL_KeepArrays_type)(SSL *ssl);
#endif
}

u_int64_t rdtsc_by_250ms = 0;

#ifdef SSLKEYLOG_TCP
static void keylog_tcp_socket_close();
#endif
static void write_keylog_to_dest(const char *key);

#ifdef SSLKEYLOG_TCP
static char keylog_tcp_dest_host[100];
static int keylog_tcp_dest_port = 0;
static cSocketBlock *keylog_tcp_socket = NULL;
#endif

static char keylog_ip_port[100];
static u_int32_t keylog_socket_ipn;
static int keylog_socket_port = 0;
static int keylog_socket_handle = -1;

static char keylog_filename[200];
static int keylog_file_fd = -1;

static bool syslog_open = false;
static FILE *filelog = NULL;

struct sKeyQueueItem {
	sKeyQueueItem(const char *key) {
		this->key = new char[strlen(key) + 1];
		strcpy(this->key, key);
		next = NULL;
	}
	~sKeyQueueItem() {
		delete [] key;
	}
	char *key;
	sKeyQueueItem *next;
};
static sKeyQueueItem *key_queue_first;
static sKeyQueueItem *key_queue_last;
volatile int key_queue_sync;

struct sPerCallerOrig {
	void resolve(void *lib_handle);
	void *caller_addr;
	sPerCallerOrig *next;
	SSL_new_type ssl_new;
	SSL_CTX_set_keylog_callback_type set_keylog_cb;
	SSL_connect_type ssl_connect;
	SSL_do_handshake_type ssl_do_handshake;
	SSL_accept_type ssl_accept;
	SSL_read_type ssl_read;
	SSL_write_type ssl_write;
	SSL_get_session_type ssl_get_session;
	SSL_get_client_random_type ssl_get_client_random;
	SSL_SESSION_get_master_key_type ssl_session_get_master_key;
	#ifdef HAVE_WOLFSSL
	SSL_KeepArrays_type ssl_keep_arrays;
	#endif
};
static sPerCallerOrig default_orig;
static sPerCallerOrig * volatile per_caller_orig;


static void debug_printf(const char* fmt, ...) {
	#if DEBUG
	va_list ap;
	va_start(ap, fmt);
	#if defined DEBUG_TO_FILE
		if(!filelog) {
			filelog = fopen(DEBUG_TO_FILE, "a");
		}
		fprintf(filelog, DEBUG_PREFIX);
		vfprintf(filelog, fmt, ap);
	#elif DEBUG_TO_SYSLOG
		if(!syslog_open) {
			openlog("SSL KEYLOG", LOG_PID, LOG_DAEMON);
			syslog_open = true;
		}
		char log_buffer[1000];
		vsnprintf(log_buffer, sizeof(log_buffer), fmt, ap);
		syslog(LOG_NOTICE, "%s", log_buffer);
	#else
		fprintf(stdout, DEBUG_PREFIX);
		vfprintf(stdout, fmt, ap);
	#endif
	va_end(ap);
	#endif
}


static void ucharToHex(unsigned char *data, unsigned datalen, char *rslt) {
	for(unsigned i = 0; i < datalen; i++) {
		sprintf(rslt + i * 2, "%.2x", data[i]);
	}
}


void exit_failure() {
	#if ABORT_IF_FAILURE
	abort();
	#endif
	#if EXIT_IF_FAILURE
	exit(EXIT_FAILURE);
	#endif
}


struct sMasterKey {
	sMasterKey(SSL *ssl, sPerCallerOrig *orig) {
		memset(this, 0, sizeof(*this));
		const SSL_SESSION *session = orig->ssl_get_session ? orig->ssl_get_session(ssl) : NULL;
		if(session) {
			if(orig->ssl_session_get_master_key) {
				master_key_length = orig->ssl_session_get_master_key(session, master_key, SSL_MAX_MASTER_KEY_LENGTH);
				//debug_printf("\n %lx - %i - %i", session, master_key_length, master_key[10]);
			} else {
				#ifndef HAVE_WOLFSSL
				#if OPENSSL_VERSION_NUMBER < 0x10100000L
				if(session->master_key_length > 0) {
					master_key_length = session->master_key_length;
					memcpy(master_key, session->master_key, session->master_key_length);
				}
				#endif
				#endif
			}
		}
	}
	char *completeKey(SSL *ssl, char *complete_key, sPerCallerOrig *orig) {
		unsigned char client_random[SSL3_RANDOM_SIZE];
		bool client_random_ok = false;
		if(orig->ssl_get_client_random) {
			client_random_ok = orig->ssl_get_client_random(ssl, client_random, SSL3_RANDOM_SIZE) > 0;
		} else {
			#ifndef HAVE_WOLFSSL
			#if OPENSSL_VERSION_NUMBER < 0x10100000L
			if(ssl->s3) {
				memcpy(client_random, ssl->s3->client_random, SSL3_RANDOM_SIZE);
				client_random_ok = true;
			}
			#endif
			#endif
		}
		if(!client_random_ok) {
			return(NULL);
		}
		strcpy(complete_key, "CLIENT_RANDOM ");
		ucharToHex(client_random, SSL3_RANDOM_SIZE, complete_key + strlen(complete_key));
		strcat(complete_key, " ");
		ucharToHex(master_key, master_key_length, complete_key + strlen(complete_key));
		return(complete_key);
	}
	int master_key_length;
	unsigned char master_key[SSL_MAX_MASTER_KEY_LENGTH];
	friend bool operator != (const sMasterKey &mk1, const sMasterKey &mk2) {
		return(mk1.master_key_length != mk2.master_key_length ||
		       memcmp(mk1.master_key, mk2.master_key, min(mk1.master_key_length, mk2.master_key_length)));
	}
};


#ifdef SSLKEYLOG_TCP
static int keylog_tcp_socket_open() {
	if(keylog_tcp_socket)
		return 2;
	if(keylog_tcp_dest_host[0] && keylog_tcp_dest_port) {
		keylog_tcp_socket = new cSocketBlock("ssl key logger", true);
		keylog_tcp_socket->setBlockHeaderString("ssl_key_socket_block");
		keylog_tcp_socket->setHostPort(keylog_tcp_dest_host, keylog_tcp_dest_port);
		if(!keylog_tcp_socket->connect()) {
			debug_printf("FAILED connect to : %s:%i / %s", keylog_tcp_dest_host, keylog_tcp_dest_port, keylog_tcp_socket->getError().c_str());
			keylog_tcp_socket_close();
			return(0);
		}
		debug_printf("OK connect to : %s:%i / %s", keylog_tcp_dest_host, keylog_tcp_dest_port, keylog_tcp_socket->getError().c_str());
		keylog_tcp_socket->generate_rsa_keys(1024);
		JsonExport json_rsa_key;
		json_rsa_key.add("rsa_key", keylog_tcp_socket->get_rsa_pub_key());
		if(!keylog_tcp_socket->writeBlock(json_rsa_key.getJson())) {
			debug_printf("FAILED send rsa key");
			keylog_tcp_socket_close();
			return(0);
		}
		string rsltAesKeys;
		if(!keylog_tcp_socket->readBlock(&rsltAesKeys, cSocket::_te_rsa) || rsltAesKeys.find("aes_ckey") == string::npos) {
			debug_printf("FAILED read aes keys");
			keylog_tcp_socket_close();
			return(0);
		}
		JsonItem jsonAesKeys;
		jsonAesKeys.parse(rsltAesKeys);
		string aes_ckey = jsonAesKeys.getValue("aes_ckey");
		string aes_ivec = jsonAesKeys.getValue("aes_ivec");
		keylog_tcp_socket->set_aes_keys(aes_ckey, aes_ivec);
		if(!keylog_tcp_socket->writeBlock("OK", cSocket::_te_aes)) {
			debug_printf("FAILED send OK");
			keylog_tcp_socket_close();
			return(0);
		}
		return(1);
	}
	return(0);
}

static void keylog_tcp_socket_close() {
	if(keylog_tcp_socket) {
		delete keylog_tcp_socket;
		keylog_tcp_socket = NULL;
	}
}

static void keylog_tcp_socket_write(u_char *data, size_t datalen) {
	if(!(keylog_tcp_dest_host[0] && keylog_tcp_dest_port)) {
		return;
	}
	bool ok = false;
	unsigned pass = 0;
	unsigned max_pass = 10;
	while(pass < max_pass) {
		if(!keylog_tcp_socket) {
			keylog_tcp_socket_open();
		}
		if(keylog_tcp_socket && keylog_tcp_socket->writeBlock(data, datalen, cSocket::_te_aes)) {
			ok = true;
			break;
		} else {
			keylog_tcp_socket_close();
			if(pass + 1 < max_pass) {
				usleep(100000 * pass);
			}
		}
		++pass;
	}
	if(!ok) {
		debug_printf("failed sent key: %s", string((char*)data, datalen).c_str());
	}
}
#endif

static int keylog_udp_socket_open() {
	if(keylog_socket_handle >= 0)
		return 2;
	if(keylog_socket_ipn && keylog_socket_port) {
		keylog_socket_handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if(keylog_socket_handle >= 0) {
			debug_printf("OK create socket : %i", keylog_socket_handle);
			sockaddr_in addr;
			memset(&addr, 0, sizeof(sockaddr_in));
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = keylog_socket_ipn;
			addr.sin_port = htons(keylog_socket_port);
			for (unsigned pass = 0; pass < 10; pass++) {
				if(connect(keylog_socket_handle, (const sockaddr*)&addr, sizeof(sockaddr_in)) == 0) {
					debug_printf("OK connect to : %s", keylog_ip_port);
					return(1);
				} else {
					debug_printf("FAILED connect to : %s / %s", keylog_ip_port, strerror(errno));
					sleep(1);
				}
			}
		    
		}
	}
	if(keylog_socket_handle >= 0) {
		close(keylog_socket_handle);
		keylog_socket_handle = -1;
	}
	return(0);
}

static void keylog_udp_socket_close() {
	if(keylog_socket_handle >= 0) {
		close(keylog_socket_handle);
		keylog_socket_handle = -1;
	}
}

static void keylog_udp_socket_write(u_char *data, size_t datalen) {
	if(!(keylog_socket_ipn && keylog_socket_port)) {
		return;
	}
	bool ok = false;
	size_t datalenSent = 0;
	unsigned pass = 0;
	unsigned max_pass = 10;
	while(pass < max_pass) {
		if(keylog_socket_handle < 0) {
			keylog_udp_socket_open();
		}
		ssize_t _datalenSent = -1;
		if(keylog_socket_handle >= 0) {
			_datalenSent = send(keylog_socket_handle, (u_char*)data + datalenSent, datalen - datalenSent, 0);
		}
		debug_printf("sent %i bytes", _datalenSent);
		if(_datalenSent > 0) {
			datalenSent += _datalenSent;
			if(datalenSent >= datalen) {
				ok = true;
				break;
			}
		} else {
			keylog_udp_socket_close();
			if(pass + 1 < max_pass) {
				usleep(100000 * pass);
			}
			++pass;
		}
	}
	if(!ok) {
		debug_printf("failed sent key: %s", std::string((char*)data, datalen).c_str());
	}
}

static int keylog_file_open(void) {
	if(keylog_file_fd >= 0) 
		return 2;
	if(keylog_filename[0]) {
		keylog_file_fd = open(keylog_filename, O_WRONLY | O_APPEND | O_CREAT, 0644);
		if(keylog_file_fd >= 0) {
			debug_printf("OK open : %s", keylog_filename);
			return(1);
		} else {
			debug_printf("FAILED open : %s / %s", keylog_filename, strerror(errno));
		}
	}
	if(keylog_file_fd >= 0) {
		close(keylog_file_fd);
		keylog_file_fd = -1;
	}
	return(0);
}

static void keylog_file_close()	{
	if(keylog_file_fd >= 0) {
		close(keylog_file_fd);
		keylog_file_fd = -1;
	}
}

static int init_keylog(void) {
	if(
	   #ifdef SSLKEYLOG_TCP
	   (keylog_tcp_dest_host[0] && keylog_tcp_dest_port) ||
	   #endif
	   (keylog_socket_ipn && keylog_socket_port) ||
	   keylog_filename[0]) {
		return(2);
	}
	#ifdef SSLKEYLOG_TCP
	const char *host_port = getenv("SSLKEYLOG_TCP");
	if(host_port) {
		char *port_separator = (char*)strchr(host_port, ':');
		if(port_separator) {
			*port_separator = 0;
			strcpy(keylog_tcp_dest_host, host_port);
			keylog_tcp_dest_port = atoi(port_separator + 1);
			*port_separator = ':';
		}
	}
	#endif
	const char *ip_port = getenv("SSLKEYLOG_UDP");
	if(ip_port) {
		strcpy(keylog_ip_port, ip_port);
		char *port_separator = (char*)strchr(ip_port, ':');
		if(port_separator) {
			*port_separator = 0;
			inet_pton(AF_INET, ip_port, &keylog_socket_ipn);
			keylog_socket_port = atoi(port_separator + 1);
			*port_separator = ':';
			if(keylog_socket_ipn && keylog_socket_port) {
				debug_printf("log to : %s", keylog_ip_port);
			}
		}
	}
	const char *filename = getenv("SSLKEYLOG_FILE");
	if(filename) {
		strcpy(keylog_filename, filename);
		if(keylog_filename[0]) {
			debug_printf("log to : %s", keylog_filename);
		}
	}
	return(
	       #ifdef SSLKEYLOG_TCP
	       (keylog_tcp_dest_host[0] && keylog_tcp_dest_port) ||
	       #endif
	       (keylog_socket_ipn && keylog_socket_port) ||
	       keylog_filename[0]);
}

#if WRITE_THREAD
static void *write_thread(void *arg) {
	while(true) {
		if(key_queue_first) {
			sKeyQueueItem *kqi = NULL;
			_SYNC_LOCK_USLEEP(key_queue_sync, 100);
			if(key_queue_first) {
				kqi = key_queue_first;
				if(kqi->next) {
					key_queue_first = kqi->next;
				} else {
					key_queue_first = NULL;
					key_queue_last = NULL;
				}
			}
			_SYNC_UNLOCK(key_queue_sync);
			if(kqi) {
				write_keylog_to_dest(kqi->key);
				delete kqi;
			}
		} else {
			usleep(1000);
		}
	}
}

static bool write_thread_created;
static void create_write_thread() {
	if(!write_thread_created) {
		write_thread_created = true;
		pthread_t thread;
		pthread_create(&thread, NULL, write_thread, NULL);
	}
}

static void write_keylog_to_queue(const char *key) {
	_SYNC_LOCK_USLEEP(key_queue_sync, 100);
	create_write_thread();
	sKeyQueueItem *kqi = new sKeyQueueItem(key);
	if(key_queue_last) {
		key_queue_last->next = kqi;
		key_queue_last = kqi;
	} else {
		key_queue_first = kqi;
		key_queue_last = kqi;
	}
	_SYNC_UNLOCK(key_queue_sync);
}
#endif

static void write_keylog(const SSL *ssl, const char *key) {
	if(!ssl || !key) {
		return;
	}
	const char *keys_types[] = {
		"CLIENT_RANDOM ",
		"CLIENT_HANDSHAKE_TRAFFIC_SECRET ",
		"SERVER_HANDSHAKE_TRAFFIC_SECRET ",
		"EXPORTER_SECRET ",
		"CLIENT_TRAFFIC_SECRET_0 ",
		"SERVER_TRAFFIC_SECRET_0 "
	};
	bool key_ok = false;
	for(unsigned i = 0; i < sizeof(keys_types) / sizeof(keys_types[0]); i++) {
		const char *p = strcasestr(key, keys_types[i]);
		if(p) {
			key = p;
			key_ok = true;
			break;
		}
	}
	if(!key_ok) {
		return;
	}
	#if WRITE_THREAD
		write_keylog_to_queue(key);
	#else
		write_keylog_to_dest(key);
	#endif
}

static void write_keylog_to_dest(const char *key) {
	debug_printf("send key : %s (size: %i)", key, strlen(key));
	#ifdef SSLKEYLOG_TCP
	keylog_tcp_socket_write((u_char*)key, strlen(key));
	#endif
	keylog_udp_socket_write((u_char*)key, strlen(key));
	if(keylog_filename[0]) {
		if(keylog_file_fd < 0) {
			keylog_file_open();
		}
		if(keylog_file_fd >= 0) {
			write(keylog_file_fd, key, strlen(key));
			write(keylog_file_fd, "\n", 1);
		}
	}
}

static void *lookup_symbol(const char *sym, void *lib_handle) {
	char sym_mod[256] = "";
	#ifdef HAVE_WOLFSSL
	strcpy(sym_mod, "wolf");
	#endif
	strcat(sym_mod, sym);
	return(dlsym(lib_handle, sym_mod));
}

static void *dlopen_ssl_lib(void *scope_handle, Dl_info *lib_info) {
	void *ssl_new = lookup_symbol("SSL_new", scope_handle);
	if(!ssl_new || !dladdr(ssl_new, lib_info) || !lib_info->dli_fname || !lib_info->dli_fname[0]) {
		return(NULL);
	}
	return(dlopen(lib_info->dli_fname, RTLD_NOW | RTLD_NOLOAD));
}

void sPerCallerOrig::resolve(void *lib_handle) {
	ssl_new = (SSL_new_type)lookup_symbol("SSL_new", lib_handle);
	set_keylog_cb = (SSL_CTX_set_keylog_callback_type)lookup_symbol("SSL_CTX_set_keylog_callback", lib_handle);
	#if not ONLY_KEYLOG_CALLBACK or BOTH_METHODS
	ssl_connect = (SSL_connect_type)lookup_symbol("SSL_connect", lib_handle);
	ssl_do_handshake = (SSL_do_handshake_type)lookup_symbol("SSL_do_handshake", lib_handle);
	ssl_accept = (SSL_accept_type)lookup_symbol("SSL_accept", lib_handle);
	ssl_read = (SSL_read_type)lookup_symbol("SSL_read", lib_handle);
	ssl_write = (SSL_write_type)lookup_symbol("SSL_write", lib_handle);
	ssl_get_session = (SSL_get_session_type)lookup_symbol("SSL_get_session", lib_handle);
	ssl_get_client_random = (SSL_get_client_random_type)lookup_symbol("SSL_get_client_random", lib_handle);
	ssl_session_get_master_key = (SSL_SESSION_get_master_key_type)lookup_symbol("SSL_SESSION_get_master_key", lib_handle);
	#ifdef HAVE_WOLFSSL
	ssl_keep_arrays = (SSL_KeepArrays_type)lookup_symbol("SSL_KeepArrays", lib_handle);
	#endif
	#endif
}

static sPerCallerOrig *resolve_orig_for_caller(void *caller_addr) {
	sPerCallerOrig *orig = per_caller_orig;
	while(orig && orig->caller_addr != caller_addr) {
		orig = orig->next;
	}
	if(!orig) {
		Dl_info caller_info;
		if(!caller_addr || !dladdr(caller_addr, &caller_info) || !caller_info.dli_fname || !caller_info.dli_fname[0]) {
			return(&default_orig);
		}
		orig = new sPerCallerOrig();
		orig->caller_addr = caller_addr;
		void *caller_handle = dlopen(caller_info.dli_fname, RTLD_NOW | RTLD_NOLOAD);
		if(caller_handle) {
			Dl_info lib_info;
			void *lib_handle = dlopen_ssl_lib(caller_handle, &lib_info);
			if(lib_handle) {
				orig->resolve(lib_handle);
				debug_printf("Per-caller resolve OK for '%s' (0x%lx) : %s / SSL_new 0x%lx", caller_info.dli_fname, (unsigned long)caller_addr, lib_info.dli_fname, (unsigned long)orig->ssl_new);
				dlclose(lib_handle);
			}
			dlclose(caller_handle);
		}
		if(!orig->ssl_new) {
			debug_printf("Per-caller resolve FAILED for '%s' (0x%lx) - will use default binding", caller_info.dli_fname, (unsigned long)caller_addr);
		}
		do {
			orig->next = per_caller_orig;
		} while(!__sync_bool_compare_and_swap(&per_caller_orig, orig->next, orig));
	}
	return(orig->ssl_new ? orig : &default_orig);
}

SSL *
#ifndef HAVE_WOLFSSL
SSL_new
#else
wolfSSL_new
#endif
(SSL_CTX *ctx) {
	sPerCallerOrig *orig = resolve_orig_for_caller(__builtin_return_address(0));
	if(orig->set_keylog_cb) {
		orig->set_keylog_cb(ctx, write_keylog);
	}
	SSL *ssl = orig->ssl_new(ctx);
	#ifdef HAVE_WOLFSSL
	if(ssl && orig->ssl_keep_arrays && (BOTH_METHODS || !orig->set_keylog_cb)) {
		orig->ssl_keep_arrays(ssl);
	}
	#endif
	return(ssl);
}

#if not ONLY_KEYLOG_CALLBACK
int 
#ifndef HAVE_WOLFSSL
SSL_connect
#else
wolfSSL_connect
#endif
(SSL *ssl) {
	sPerCallerOrig *orig = resolve_orig_for_caller(__builtin_return_address(0));
	#if not BOTH_METHODS
	if(orig->set_keylog_cb) {
		return(orig->ssl_connect(ssl));
	}
	#endif
	//debug_printf("SSL_connect 1");
	sMasterKey mk1(ssl, orig);
	int rslt = orig->ssl_connect(ssl);
	sMasterKey mk2(ssl, orig);
	if(mk1 != mk2) {
		//debug_printf("SSL_connect changekey");
		char complete_key[1000];
		write_keylog(ssl, mk2.completeKey(ssl, complete_key, orig));
	}
	//debug_printf("SSL_connect 2");
	return(rslt);
}

int 
#ifndef HAVE_WOLFSSL
SSL_do_handshake
#else
wolfSSL_do_handshake
#endif
(SSL *ssl) {
	sPerCallerOrig *orig = resolve_orig_for_caller(__builtin_return_address(0));
	#if not BOTH_METHODS
	if(orig->set_keylog_cb) {
		return(orig->ssl_do_handshake(ssl));
	}
	#endif
	//debug_printf("SSL_do_handshake_orig 1");
	sMasterKey mk1(ssl, orig);
	int rslt = orig->ssl_do_handshake(ssl);
	sMasterKey mk2(ssl, orig);
	if(mk1 != mk2) {
		//debug_printf("SSL_do_handshake changekey");
		char complete_key[1000];
		write_keylog(ssl, mk2.completeKey(ssl, complete_key, orig));
	}
	//debug_printf("SSL_do_handshake_orig 2");
	return(rslt);
}

int 
#ifndef HAVE_WOLFSSL
SSL_accept
#else
wolfSSL_accept
#endif
(SSL *ssl) {
	sPerCallerOrig *orig = resolve_orig_for_caller(__builtin_return_address(0));
	#if not BOTH_METHODS
	if(orig->set_keylog_cb) {
		return(orig->ssl_accept(ssl));
	}
	#endif
	//debug_printf("SSL_accept 1");
	sMasterKey mk1(ssl, orig);
	int rslt = orig->ssl_accept(ssl);
	sMasterKey mk2(ssl, orig);
	if(mk1 != mk2) {
		//debug_printf("SSL_accept changekey");
		char complete_key[1000];
		write_keylog(ssl, mk2.completeKey(ssl, complete_key, orig));
	}
	//debug_printf("SSL_accept 2");
	return(rslt);
}

int 
#ifndef HAVE_WOLFSSL
SSL_read
#else
wolfSSL_read
#endif
(SSL *ssl, void *buf, int num) {
	sPerCallerOrig *orig = resolve_orig_for_caller(__builtin_return_address(0));
	#if not BOTH_METHODS
	if(orig->set_keylog_cb) {
		return(orig->ssl_read(ssl, buf, num));
	}
	#endif
	//debug_printf("SSL_read 1");
	sMasterKey mk1(ssl, orig);
	int rslt = orig->ssl_read(ssl, buf, num);
	sMasterKey mk2(ssl, orig);
	if(mk1 != mk2) {
		//debug_printf("SSL_read changekey");
		char complete_key[1000];
		write_keylog(ssl, mk2.completeKey(ssl, complete_key, orig));
	}
	//debug_printf("SSL_read 2");
	return(rslt);
}

int 
#ifndef HAVE_WOLFSSL
SSL_write
#else
wolfSSL_write
#endif
(SSL *ssl, const void *buf, int num) {
	sPerCallerOrig *orig = resolve_orig_for_caller(__builtin_return_address(0));
	#if not BOTH_METHODS
	if(orig->set_keylog_cb) {
		return(orig->ssl_write(ssl, buf, num));
	}
	#endif
	//debug_printf("SSL_write 1");
	sMasterKey mk1(ssl, orig);
	int rslt = orig->ssl_write(ssl, buf, num);
	sMasterKey mk2(ssl, orig);
	if(mk1 != mk2) {
		//debug_printf("SSL_write changekey");
		char complete_key[1000];
		write_keylog(ssl, mk2.completeKey(ssl, complete_key, orig));
	}
	//debug_printf("SSL_write 2");
	return(rslt);
}
#endif

__attribute__((constructor)) static void setup(void) {
	Dl_info lib_info;
	void *lib_handle = dlopen_ssl_lib(RTLD_NEXT, &lib_info);
	if(!lib_handle) {
		lib_handle = dlopen(LIBSSL_SONAME, RTLD_LAZY);
	}
	if(lib_handle) {
		default_orig.resolve(lib_handle);
		dlclose(lib_handle);
		if(!dladdr((void*)default_orig.ssl_new, &lib_info)) {
			memset(&default_orig, 0, sizeof(default_orig));
		}
	}
	if(!init_keylog()) {
		debug_printf("FAILED init_keylog - exit!");
		exit_failure();
		return;
	}
	if(default_orig.ssl_new) {
		debug_printf("OK detect pointer to function SSL_new : 0x%lx", default_orig.ssl_new);
	} else {
		debug_printf("FAILED detect pointer to function SSL_new - keys will be logged only with per-caller binding");
		return;
	}
	if(default_orig.set_keylog_cb) {
		debug_printf("OK detect pointer to function SSL_CTX_set_keylog_callback : 0x%lx", default_orig.set_keylog_cb);
	}
	#if ONLY_KEYLOG_CALLBACK
	if(!default_orig.set_keylog_cb) {
		debug_printf("FAILED detect pointer to function SSL_CTX_set_keylog_callback - keys will be logged only with per-caller binding");
		return;
	}
	#endif
	#if not ONLY_KEYLOG_CALLBACK or BOTH_METHODS
	if(default_orig.ssl_connect) {
		debug_printf("OK detect pointer to function SSL_connect : 0x%lx", default_orig.ssl_connect);
	}
	if(default_orig.ssl_do_handshake) {
		debug_printf("OK detect pointer to function SSL_do_handshake : 0x%lx", default_orig.ssl_do_handshake);
	}
	if(default_orig.ssl_accept) {
		debug_printf("OK detect pointer to function SSL_accept : 0x%lx", default_orig.ssl_accept);
	}
	if(default_orig.ssl_read) {
		debug_printf("OK detect pointer to function SSL_read : 0x%lx", default_orig.ssl_read);
	}
	if(default_orig.ssl_write) {
		debug_printf("OK detect pointer to function SSL_write : 0x%lx", default_orig.ssl_write);
	}
	if(default_orig.ssl_get_session) {
		debug_printf("OK detect pointer to function SSL_get_session : 0x%lx", default_orig.ssl_get_session);
	}
	if(default_orig.ssl_get_client_random) {
		debug_printf("OK detect pointer to function SSL_get_client_random : 0x%lx", default_orig.ssl_get_client_random);
	}
	if(default_orig.ssl_session_get_master_key) {
		debug_printf("OK detect pointer to function SSL_SESSION_get_master_key : 0x%lx", default_orig.ssl_session_get_master_key);
	}
	if(!default_orig.set_keylog_cb && !default_orig.ssl_connect) {
		debug_printf("FAILED detect pointer to function SSL_CTX_set_keylog_callback and SSL_connect - keys will be logged only with per-caller binding");
		return;
	}
	#endif
}


#ifdef SSLKEYLOG_TCP
cResolver resolver;
bool opt_socket_use_poll = true;
bool useIPv6 = true;

sCloudRouterVerbose& CR_VERBOSE() {
	static sCloudRouterVerbose cr_verbose;
	static bool cr_verbose_init = false;
	if(!cr_verbose_init) {
		memset(&cr_verbose, 0, sizeof(cr_verbose));
		cr_verbose_init = false;
	}
	return(cr_verbose);
}

bool CR_TERMINATE() {
	return(false);
}
#endif
