#define _GNU_SOURCE // for RTLD_NEXT
#include <dlfcn.h>
#include <openssl/ssl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>


#ifndef OPENSSL_SONAME
#define OPENSSL_SONAME "libssl.so"
#endif

#define DEBUG 1
#define DEBUG_PREFIX "\n * SSL KEYLOG : "


static char keylog_filename[200];
static int keylog_file_fd = -1;
static char keylog_ip_port[100];
static u_int32_t keylog_socket_ipn;
static int keylog_socket_port = 0;
static int keylog_socket_handle = -1;

static SSL *(*SSL_new_orig)(SSL_CTX *ctx);
static void (*SSL_CTX_set_keylog_callback_orig)();


static void debug_printf(const char* fmt, ...) {
	#if DEBUG
	va_list ap;
	va_start(ap, fmt);
	fprintf(stdout, DEBUG_PREFIX);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	#endif
}

static int keylog_udp_socket_open() {
	if(keylog_socket_handle >= 0)
		return 2;
	if(keylog_socket_ipn && keylog_socket_port) {
		keylog_socket_handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if(keylog_socket_handle >= 0) {
			debug_printf("OK create socket : %i", keylog_socket_handle);
			struct sockaddr_in addr;
			memset(&addr, 0, sizeof(struct sockaddr_in));
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = keylog_socket_ipn;
			addr.sin_port = htons(keylog_socket_port);
			for (unsigned pass = 0; pass < 10; pass++) {
				if(connect(keylog_socket_handle, &addr, sizeof(struct sockaddr_in)) == 0) {
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
	if((keylog_socket_ipn && keylog_socket_port) ||
	   keylog_filename[0]) {
		return(2);
	}
	const char *ip_port = getenv("SSLKEYLOG_UDP");
	if(ip_port) {
		strcpy(keylog_ip_port, ip_port);
		char *port_separator = strchr(ip_port, ':');
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
	return((keylog_socket_ipn && keylog_socket_port) ||
	       keylog_filename[0]);
}

static void write_keylog(const SSL *ssl, const char *line) {
	if(keylog_socket_handle < 0 && keylog_file_fd < 0) {
		keylog_udp_socket_open();
		keylog_file_open();
	}
	debug_printf("send key : %s (size: %i)", line, strlen(line));
	if(keylog_socket_handle >= 0) {
		keylog_udp_socket_write((u_char*)line, strlen(line));
	}
	if(keylog_file_fd >= 0) {
		write(keylog_file_fd, line, strlen(line));
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

SSL *SSL_new(SSL_CTX *ctx){
	if(SSL_CTX_set_keylog_callback_orig) {
		SSL_CTX_set_keylog_callback_orig(ctx, write_keylog);
	}
	return SSL_new_orig(ctx);
}

__attribute__((constructor)) static void setup(void) {
	SSL_new_orig = lookup_symbol("SSL_new", OPENSSL_SONAME);
	if(SSL_new_orig) {
		debug_printf("OK detect pointer to function SSL_new : 0x%lx", SSL_new_orig);
	} else {
		debug_printf("FAILED detect pointer to function SSL_new - abort!");
		abort();
	}
	SSL_CTX_set_keylog_callback_orig = lookup_symbol("SSL_CTX_set_keylog_callback", OPENSSL_SONAME);
	if(SSL_new_orig) {
		debug_printf("OK detect pointer to function SSL_CTX_set_keylog_callback : 0x%lx", SSL_CTX_set_keylog_callback);
	} else {
		debug_printf("FAILED detect pointer to function SSL_CTX_set_keylog_callback - abort!", SSL_CTX_set_keylog_callback);
		abort();
	}
	if(!init_keylog()) {
		debug_printf("FAILED init_keylog - abort!");
		abort();
	}
}
