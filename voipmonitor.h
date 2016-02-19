#include <sys/types.h>
#include <string>
#include <netdb.h>
#include "config.h"
#include "common.h"
#include "heap_safe.h"

#ifndef VOIPMONITOR_H
#define VOIPMONITOR_H

#define RTPSENSOR_VERSION "15.3"
#define NAT

#define FORMAT_WAV	1
#define FORMAT_OGG	2
#define REGISTER_CLEAN_PERIOD 60	// clean register table for expired items every 60 seconds

#define TYPE_SIP 1
#define TYPE_RTP 2
#define TYPE_RTCP 3
#define TYPE_SKINNY 4

#define STORE_PROC_ID_CDR_1 11
#define STORE_PROC_ID_MESSAGE_1 21
#define STORE_PROC_ID_CLEANSPOOL 41
#define STORE_PROC_ID_CLEANSPOOL_SERVICE 42
#define STORE_PROC_ID_REGISTER_1 51
#define STORE_PROC_ID_SAVE_PACKET_SQL 61
#define STORE_PROC_ID_HTTP_1 71
#define STORE_PROC_ID_WEBRTC_1 81
#define STORE_PROC_ID_CACHE_NUMBERS_LOCATIONS 91
#define STORE_PROC_ID_FRAUD_ALERT_INFO 92
#define STORE_PROC_ID_IPACC_1 101
#define STORE_PROC_ID_IPACC_AGR_INTERVAL 111
#define STORE_PROC_ID_IPACC_AGR_HOUR 112
#define STORE_PROC_ID_IPACC_AGR_DAY 113
#define STORE_PROC_ID_IPACC_AGR2_HOUR_1 121

#define GRAPH_DELIMITER 4294967295
#define GRAPH_VERSION 4294967293
#define GRAPH_MARK 4294967293 
#define GRAPH_MOS 4294967292
#define GRAPH_SILENCE 4294967291
#define GRAPH_EVENT 4294967290

#define SNIFFER_INLINE_FUNCTIONS true

#define SYNC_PCAP_BLOCK_STORE true
#define SYNC_CALL_RTP true

#define TAR_PROF false

#define MAX_PREPROCESS_PACKET_THREADS 3
#define MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS 3
#define MAX_PROCESS_RTP_PACKET_THREADS 3

#define TAR_MODULO_SECONDS 60


/* choose what method wil be used to synchronize threads. NONBLOCK is the fastest. Do not enable both at once */
// this is now defined in Makefile 

/* if you want to see all new calls in syslog enable DEBUG_INVITE */
//#define DEBUG_INVITE

using namespace std;

void reload_config(const char *jsonConfig = NULL);
void hot_restart();
void hot_restart_with_json_config(const char *jsonConfig);
void set_request_for_reload_capture_rules();
void reload_capture_rules();

void terminate_packetbuffer();

/* For compatibility with Linux definitions... */

#if ( defined( __FreeBSD__ ) || defined ( __NetBSD__ ) )
# ifndef FREEBSD
#  define FREEBSD
# endif
#endif

#ifdef FREEBSD
# include <sys/endian.h>
# define __BYTE_ORDER _BYTE_ORDER
# define __BIG_ENDIAN _BIG_ENDIAN
# define __LITTLE_ENDIAN _LITTLE_ENDIAN
#else
# include <endian.h>
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
# ifndef __BIG_ENDIAN_BITFIELD
#  define __BIG_ENDIAN_BITFIELD
# endif
#else
# ifndef __LITTLE_ENDIAN_BITFIELD
#  define __LITTLE_ENDIAN_BITFIELD
# endif
#endif
#if defined(__BIG_ENDIAN_BITFIELD) && defined(__LITTLE_ENDIAN_BITFIELD)
# error Cannot define both __BIG_ENDIAN_BITFIELD and __LITTLE_ENDIAN_BITFIELD
#endif


#ifndef ulong 
#define ulong unsigned long 
#endif

struct tcphdr2
  {
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t res1:4;
    u_int16_t doff:4;
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff:4;
    u_int16_t res1:4;
    u_int16_t res2:2;
    u_int16_t urg:1;
    u_int16_t ack:1;
    u_int16_t psh:1;
    u_int16_t rst:1;
    u_int16_t syn:1;
    u_int16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};

#ifndef GLOBAL_DECLARATION
extern 
#endif
sVerbose sverb;

void vm_terminate();
void vm_terminate_error(const char *terminate_error);
inline void set_terminating() {
	extern int terminating;
	++terminating;
}
inline void clear_terminating() {
	extern int terminating;
	terminating = 0;
}
inline int is_terminating() {
	extern int terminating;
	return(terminating);
}
bool is_terminating_without_error();

bool is_read_from_file();
bool is_read_from_file_simple();
bool is_read_from_file_by_pb();
bool is_enable_packetbuffer();
bool is_enable_rtp_threads();
bool is_enable_cleanspool();
bool is_receiver();
bool is_sender();
int check_set_rtp_threads(int num_rtp_threads);
u_int32_t gethostbyname_lock(const char *name);

enum eSnifferMode {
	snifferMode_na,
	snifferMode_read_from_interface,
	snifferMode_read_from_files,
	snifferMode_sender
};

#define snifferMode_read_from_interface_str string("1")
#define snifferMode_read_from_files_str string("2")
#define snifferMode_sender_str string("3")

#endif
