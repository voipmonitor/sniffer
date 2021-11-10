#ifndef _GNU_SOURCE
#define _GNU_SOURCE // for RTLD_NEXT
#endif

#include <dlfcn.h>
#include <openssl/ssl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <syslog.h>
#include <pthread.h>

#ifdef SSLKEYLOG_TCP
#include "cloud_router_base.h"
#else

#endif


#ifndef OPENSSL_SONAME
#define OPENSSL_SONAME "libssl.so"
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
#define ONLY_OPENSSL_111_SUPPORT 1
#endif

#define WRITE_THREAD 1

#define DEBUG 1
#define DEBUG_PREFIX "\n * SSL KEYLOG : "
#define DEBUG_TO_SYSLOG 0

#define min(a, b) (a < b ? a : b)

#define __SYNC_LOCK(vint) while(__sync_lock_test_and_set(&vint, 1)) {};
#define __SYNC_LOCK_USLEEP(vint, us_sleep) while(__sync_lock_test_and_set(&vint, 1)) { if(us_sleep) { usleep(us_sleep); } }
#define __SYNC_UNLOCK(vint) __sync_lock_release(&vint);


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
}

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

extern "C" {
static SSL_new_type SSL_new_orig;
static SSL_CTX_set_keylog_callback_type SSL_CTX_set_keylog_callback_orig;
static SSL_connect_type SSL_connect_orig;
static SSL_do_handshake_type SSL_do_handshake_orig;
static SSL_accept_type SSL_accept_orig;
static SSL_read_type SSL_read_orig;
static SSL_write_type SSL_write_orig;
static SSL_get_session_type SSL_get_session_orig;
static SSL_get_client_random_type SSL_get_client_random_orig;
static SSL_SESSION_get_master_key_type SSL_SESSION_get_master_key_orig;
}


static void debug_printf(const char* fmt, ...) {
	#if DEBUG
	va_list ap;
	va_start(ap, fmt);
	#if DEBUG_TO_SYSLOG
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


struct sMasterKey {
	sMasterKey(SSL *ssl) {
		memset(this, 0, sizeof(*this));
		const SSL_SESSION *session = SSL_get_session_orig(ssl);
		if(session) {
			if(SSL_SESSION_get_master_key_orig) {
				master_key_length = SSL_SESSION_get_master_key_orig(session, master_key, SSL_MAX_MASTER_KEY_LENGTH);
				//debug_printf("\n %lx - %i - %i", session, master_key_length, master_key[10]);
			} else {
				#if OPENSSL_VERSION_NUMBER < 0x10100000L
				if(session->master_key_length > 0) {
					master_key_length = session->master_key_length;
					memcpy(master_key, session->master_key, session->master_key_length);
				}
				#endif
			}
		}
	}
	char *completeKey(SSL *ssl, char *complete_key) {
		unsigned char client_random[SSL3_RANDOM_SIZE];
		if(SSL_get_client_random_orig) {
			SSL_get_client_random_orig(ssl, client_random, SSL3_RANDOM_SIZE);
		} else {
			#if OPENSSL_VERSION_NUMBER < 0x10100000L
			if(ssl->s3) {
				memcpy(client_random, ssl->s3->client_random, SSL3_RANDOM_SIZE);
			}
			#endif
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
	if(!keylog_tcp_socket)
		return;
	unsigned pass = 0;
	while(pass < 3) {
		if(keylog_tcp_socket->writeBlock(data, datalen, cSocket::_te_aes)) {
			return;
		} else {
			keylog_tcp_socket_close();
			if(!keylog_tcp_socket_open()) {
				break;
			}
		}
		++pass;
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
	if(keylog_socket_handle < 0)
		return;
	size_t datalenSent = 0;
	unsigned pass = 0;
	while(datalenSent < datalen) {
		ssize_t _datalenSent = send(keylog_socket_handle, (u_char*)data + datalenSent, datalen - datalenSent, 0);
		debug_printf("sent %i bytes", _datalenSent);
		if(_datalenSent == -1) {
			if(pass > 10)
				break;
			if(pass > 2) {
				keylog_udp_socket_close();
				if(!keylog_udp_socket_open()) {
					break;
				}
			}
		} else {
			datalenSent += _datalenSent;
		}
		++pass;
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
			__SYNC_LOCK_USLEEP(key_queue_sync, 100);
			if(key_queue_first) {
				kqi = key_queue_first;
				if(kqi->next) {
					key_queue_first = kqi->next;
				} else {
					key_queue_first = NULL;
					key_queue_last = NULL;
				}
			}
			__SYNC_UNLOCK(key_queue_sync);
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
	__SYNC_LOCK_USLEEP(key_queue_sync, 100);
	create_write_thread();
	sKeyQueueItem *kqi = new sKeyQueueItem(key);
	if(key_queue_last) {
		key_queue_last->next = kqi;
		key_queue_last = kqi;
	} else {
		key_queue_first = kqi;
		key_queue_last = kqi;
	}
	__SYNC_UNLOCK(key_queue_sync);
}
#endif

static void write_keylog(const SSL *ssl, const char *key) {
	if(!ssl || !key) {
		return;
	}
	#if WRITE_THREAD
		write_keylog_to_queue(key);
	#else
		write_keylog_to_dest(key);
	#endif
}

static void write_keylog_to_dest(const char *key) {
	if(
	   #ifdef SSLKEYLOG_TCP
	   !keylog_tcp_socket && 
	   #endif
	   keylog_socket_handle < 0 && keylog_file_fd < 0) {
		#ifdef SSLKEYLOG_TCP
		keylog_tcp_socket_open();
		#endif
		keylog_udp_socket_open();
		keylog_file_open();
	}
	debug_printf("send key : %s (size: %i)", key, strlen(key));
	#ifdef SSLKEYLOG_TCP
	if(keylog_tcp_socket) {
		keylog_tcp_socket_write((u_char*)key, strlen(key));
	}
	#endif
	if(keylog_socket_handle >= 0) {
		keylog_udp_socket_write((u_char*)key, strlen(key));
	}
	if(keylog_file_fd >= 0) {
		write(keylog_file_fd, key, strlen(key));
		write(keylog_file_fd, "\n", 1);
	}
}

static void *lookup_symbol(const char *sym, const char *lib_soname) {
	void *func = dlsym(RTLD_NEXT, sym);
	if(!func) {
		void *handle = dlopen(lib_soname, RTLD_LAZY);
		if(handle) {
			func = dlsym(handle, sym);
			dlclose(handle);
		}
	}
	return(func);
}

SSL *SSL_new(SSL_CTX *ctx) {
	if(SSL_CTX_set_keylog_callback_orig) {
		SSL_CTX_set_keylog_callback_orig(ctx, write_keylog);
	}
	return SSL_new_orig(ctx);
}

#if not(defined(ONLY_OPENSSL_111_SUPPORT)) or not(ONLY_OPENSSL_111_SUPPORT)
int SSL_connect(SSL *ssl) {
	if(SSL_CTX_set_keylog_callback_orig) {
		return(SSL_connect_orig(ssl));
	}
	//debug_printf("SSL_connect 1");
	sMasterKey mk1(ssl);
	int rslt = SSL_connect_orig(ssl);
	sMasterKey mk2(ssl);
	if(mk1 != mk2) {
		//debug_printf("SSL_connect changekey");
		char complete_key[1000];
		write_keylog(ssl, mk2.completeKey(ssl, complete_key));
	}
	//debug_printf("SSL_connect 2");
	return(rslt);
}

int SSL_do_handshake(SSL *ssl) {
	if(SSL_CTX_set_keylog_callback_orig) {
		return(SSL_do_handshake_orig(ssl));
	}
	//debug_printf("SSL_do_handshake_orig 1");
	sMasterKey mk1(ssl);
	int rslt = SSL_do_handshake_orig(ssl);
	sMasterKey mk2(ssl);
	if(mk1 != mk2) {
		//debug_printf("SSL_do_handshake changekey");
		char complete_key[1000];
		write_keylog(ssl, mk2.completeKey(ssl, complete_key));
	}
	//debug_printf("SSL_do_handshake_orig 2");
	return(rslt);
}

int SSL_accept(SSL *ssl) {
	if(SSL_CTX_set_keylog_callback_orig) {
		return(SSL_accept_orig(ssl));
	}
	//debug_printf("SSL_accept 1");
	sMasterKey mk1(ssl);
	int rslt = SSL_accept_orig(ssl);
	sMasterKey mk2(ssl);
	if(mk1 != mk2) {
		//debug_printf("SSL_accept changekey");
		char complete_key[1000];
		write_keylog(ssl, mk2.completeKey(ssl, complete_key));
	}
	//debug_printf("SSL_accept 2");
	return(rslt);
}

int SSL_read(SSL *ssl, void *buf, int num) {
	if(SSL_CTX_set_keylog_callback_orig) {
		return(SSL_read_orig(ssl, buf, num));
	}
	//debug_printf("SSL_read 1");
	sMasterKey mk1(ssl);
	int rslt = SSL_read_orig(ssl, buf, num);
	sMasterKey mk2(ssl);
	if(mk1 != mk2) {
		//debug_printf("SSL_read changekey");
		char complete_key[1000];
		write_keylog(ssl, mk2.completeKey(ssl, complete_key));
	}
	//debug_printf("SSL_read 2");
	return(rslt);
}

int SSL_write(SSL *ssl, const void *buf, int num) {
	if(SSL_CTX_set_keylog_callback_orig) {
		return(SSL_write_orig(ssl, buf, num));
	}
	//debug_printf("SSL_write 1");
	sMasterKey mk1(ssl);
	int rslt = SSL_write_orig(ssl, buf, num);
	sMasterKey mk2(ssl);
	if(mk1 != mk2) {
		//debug_printf("SSL_write changekey");
		char complete_key[1000];
		write_keylog(ssl, mk2.completeKey(ssl, complete_key));
	}
	//debug_printf("SSL_write 2");
	return(rslt);
}
#endif

__attribute__((constructor)) static void setup(void) {
	SSL_new_orig = (SSL_new_type)lookup_symbol("SSL_new", OPENSSL_SONAME);
	if(SSL_new_orig) {
		debug_printf("OK detect pointer to function SSL_new : 0x%lx", SSL_new_orig);
	} else {
		debug_printf("FAILED detect pointer to function SSL_new - abort!");
		abort();
	}
	SSL_CTX_set_keylog_callback_orig = (SSL_CTX_set_keylog_callback_type)lookup_symbol("SSL_CTX_set_keylog_callback", OPENSSL_SONAME);
	if(SSL_CTX_set_keylog_callback_orig) {
		debug_printf("OK detect pointer to function SSL_CTX_set_keylog_callback : 0x%lx", SSL_CTX_set_keylog_callback_orig);
	}
	#if ONLY_OPENSSL_111_SUPPORT
	if(!SSL_CTX_set_keylog_callback_orig) {
		debug_printf("FAILED detect pointer to function SSL_CTX_set_keylog_callback - abort!");
		abort();
	}
	#else
	SSL_connect_orig = (SSL_connect_type)lookup_symbol("SSL_connect", OPENSSL_SONAME);
	if(SSL_connect_orig) {
		debug_printf("OK detect pointer to function SSL_connect : 0x%lx", SSL_connect_orig);
	}
	SSL_do_handshake_orig = (SSL_do_handshake_type)lookup_symbol("SSL_do_handshake", OPENSSL_SONAME);
	if(SSL_do_handshake_orig) {
		debug_printf("OK detect pointer to function SSL_do_handshake : 0x%lx", SSL_do_handshake_orig);
	}
	SSL_accept_orig = (SSL_accept_type)lookup_symbol("SSL_accept", OPENSSL_SONAME);
	if(SSL_accept_orig) {
		debug_printf("OK detect pointer to function SSL_accept : 0x%lx", SSL_accept_orig);
	}
	SSL_read_orig = (SSL_read_type)lookup_symbol("SSL_read", OPENSSL_SONAME);
	if(SSL_read_orig) {
		debug_printf("OK detect pointer to function SSL_read : 0x%lx", SSL_read_orig);
	}
	SSL_write_orig = (SSL_write_type)lookup_symbol("SSL_write", OPENSSL_SONAME);
	if(SSL_write_orig) {
		debug_printf("OK detect pointer to function SSL_write : 0x%lx", SSL_write_orig);
	}
	SSL_get_session_orig = (SSL_get_session_type)lookup_symbol("SSL_get_session", OPENSSL_SONAME);
	if(SSL_get_session_orig) {
		debug_printf("OK detect pointer to function SSL_get_session : 0x%lx", SSL_get_session_orig);
	}
	SSL_get_client_random_orig = (SSL_get_client_random_type)lookup_symbol("SSL_get_client_random", OPENSSL_SONAME);
	if(SSL_get_client_random_orig) {
		debug_printf("OK detect pointer to function SSL_get_client_random : 0x%lx", SSL_get_client_random_orig);
	}
	SSL_SESSION_get_master_key_orig = (SSL_SESSION_get_master_key_type)lookup_symbol("SSL_SESSION_get_master_key", OPENSSL_SONAME);
	if(SSL_SESSION_get_master_key_orig) {
		debug_printf("OK detect pointer to function SSL_SESSION_get_master_key : 0x%lx", SSL_SESSION_get_master_key_orig);
	}
	if(!SSL_CTX_set_keylog_callback_orig && !SSL_connect_orig) {
		debug_printf("FAILED detect pointer to function SSL_CTX_set_keylog_callback and SSL_connect - abort!");
		abort();
	}
	#endif
	if(!init_keylog()) {
		debug_printf("FAILED init_keylog - abort!");
		abort();
	}
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
