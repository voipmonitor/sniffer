#include <sys/types.h>
#include <string>

#ifndef VOIPMONITOR_H
#define VOIPMONITOR_H

#define RTPSENSOR_VERSION "10.1.14"
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
#define GRAPH_VERSION 4294967294 
#define GRAPH_MARK 4294967293 

#define SNIFFER_INLINE_FUNCTIONS true
#define TCPREPLAY_WORKARROUND false


/* choose what method wil be used to synchronize threads. NONBLOCK is the fastest. Do not enable both at once */
// this is now defined in Makefile 
//#define QUEUE_NONBLOCK 
//#define QUEUE_MUTEX 

/* if you want to see all new calls in syslog enable DEBUG_INVITE */
//#define DEBUG_INVITE

using namespace std;

void reload_config();
void reload_capture_rules();
void set_context_config();
void convert_filesindex();

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

struct sVerbose {
	int process_rtp;
	int read_rtp;
	int check_is_caller_called;
	int disable_threads_rtp;
	int packet_lost;
	int rrd_info;
	int http;
	int webrtc;
	int sip_packets;
	int set_ua;
	int dscp;
	int store_process_query;
	int call_listening;
	int skinny;
	int fraud;
};

#ifndef GLOBAL_DECLARATION
extern 
#endif
sVerbose sverb;

#endif
