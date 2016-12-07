#include <sys/types.h>
#include <string>
#include <netdb.h>
#include "config.h"
#include "common.h"
#include "heap_safe.h"

#ifndef VOIPMONITOR_H
#define VOIPMONITOR_H

#include "voipmonitor_define.h"


/* choose what method wil be used to synchronize threads. NONBLOCK is the fastest. Do not enable both at once */
// this is now defined in Makefile 

/* if you want to see all new calls in syslog enable DEBUG_INVITE */
//#define DEBUG_INVITE

using namespace std;

void reload_config(const char *jsonConfig = NULL);
bool cloud_register();
bool cloud_activecheck_send();
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

inline void set_readend() {
	extern int readend;
	readend = 1;
}
inline void clear_readend() {
	extern int readend;
	readend = 0;
}
inline bool is_readend() {
	extern int readend;
	return(readend);
}

bool is_read_from_file();
bool is_read_from_file_simple();
bool is_read_from_file_by_pb();
inline bool no_sip_reassembly() { 
	extern bool opt_read_from_file_no_sip_reassembly;
	return(opt_read_from_file_no_sip_reassembly);
}
bool is_enable_packetbuffer();
bool is_enable_rtp_threads();
bool is_enable_cleanspool();
bool is_receiver();
bool is_sender();
int check_set_rtp_threads(int num_rtp_threads);
u_int32_t gethostbyname_lock(const char *name);

bool use_mysql_2();
bool use_mysql_2_http();
void *sqlStore_http();

enum eSnifferMode {
	snifferMode_na,
	snifferMode_read_from_interface,
	snifferMode_read_from_files,
	snifferMode_sender
};

enum eTypeSpoolFile {
	tsf_na,
	tsf_main = 1,
	tsf_sip = 1,
	tsf_rtp,
	tsf_graph,
	tsf_audio,
	tsf_all,
	tsf_reg,
	tsf_skinny
};

#define MAX_TYPE_SPOOL_FILE (int)tsf_skinny
#define MAX_SPOOL_INDEX 1
#define MAX_COUNT_TYPE_SPOOL_FILE (MAX_TYPE_SPOOL_FILE + 1)
#define MAX_COUNT_SPOOL_INDEX (MAX_SPOOL_INDEX + 1)

inline bool isSetSpoolDir2() {
	extern char opt_spooldir_2_main[1024];
	return(opt_spooldir_2_main[0]);
}
inline bool isSetSpoolDir(int spoolIndex) {
	return(spoolIndex == 0 || isSetSpoolDir2());
}
inline const char *getSpoolDir(eTypeSpoolFile typeSpoolFile, const char *main, const char *rtp, const char *graph, const char *audio) {
	if(typeSpoolFile == tsf_rtp && rtp && rtp[0]) {
		return(rtp);
	} else if(typeSpoolFile == tsf_graph && graph && graph[0]) {
		return(graph);
	} else if(typeSpoolFile == tsf_audio && audio && audio[0]) {
		return(audio);
	}
	return(main);
}
inline const char *getSpoolDir(eTypeSpoolFile typeSpoolFile, int spoolIndex) {
	extern char opt_spooldir_main[1024];
	extern char opt_spooldir_rtp[1024];
	extern char opt_spooldir_graph[1024];
	extern char opt_spooldir_audio[1024];
	extern char opt_spooldir_2_main[1024];
	extern char opt_spooldir_2_rtp[1024];
	extern char opt_spooldir_2_graph[1024];
	extern char opt_spooldir_2_audio[1024];
	if(spoolIndex == 1 && opt_spooldir_2_main[0]) {
		return(getSpoolDir(typeSpoolFile, opt_spooldir_2_main, opt_spooldir_2_rtp, opt_spooldir_2_graph, opt_spooldir_2_audio));
	} else {
		return(getSpoolDir(typeSpoolFile, opt_spooldir_main, opt_spooldir_rtp, opt_spooldir_graph, opt_spooldir_audio));
	}
}
inline const char *skipSpoolDir(eTypeSpoolFile typeSpoolFile, int spoolIndex, const char *spoolDirFile) {
	const char *spoolDir = getSpoolDir(typeSpoolFile, spoolIndex);
	unsigned spoolDirLength = strlen(spoolDir);
	if(spoolDir[0] != spoolDirFile[0] ||
	   strncmp(spoolDirFile, spoolDir, spoolDirLength)) {
		return(spoolDirFile);
	}
	spoolDirFile += spoolDirLength;
	while(*spoolDirFile == '/') {
		++spoolDirFile;
	}
	return(spoolDirFile);
}

inline const char *getRrdDir() {
	extern char opt_spooldir_main[1024];
	return(opt_spooldir_main);
}
inline const char *getPcapdumpDir() {
	extern char opt_spooldir_main[1024];
	return(opt_spooldir_main);
}
inline const char *getQueryCacheDir() {
	extern char opt_spooldir_main[1024];
	return(opt_spooldir_main);
}
inline const char *getSqlVmExportDir() {
	extern char opt_spooldir_main[1024];
	return(opt_spooldir_main);
}

void vmChdir() {
	extern char opt_spooldir_main[1024];
	chdir(opt_spooldir_main);
}

const char *getSpoolTypeDir(eTypeSpoolFile typeSpoolFile) {
	return(typeSpoolFile == tsf_sip ? "SIP" :
	       typeSpoolFile == tsf_rtp ? "RTP" :
	       typeSpoolFile == tsf_graph ? "GRAPH" :
	       typeSpoolFile == tsf_audio ? "AUDIO" : 
	       typeSpoolFile == tsf_all ? "ALL" : 
	       typeSpoolFile == tsf_reg ? "REG" : 
	       typeSpoolFile == tsf_skinny ? "SKINNY" : 
	       NULL);
}
const char *getSpoolTypeFilesIndex(eTypeSpoolFile typeSpoolFile) {
	return(typeSpoolFile == tsf_sip ? "sip" :
	       typeSpoolFile == tsf_rtp ? "rtp" :
	       typeSpoolFile == tsf_graph ? "graph" :
	       typeSpoolFile == tsf_audio ? "audio" : 
	       NULL);
}
eTypeSpoolFile getTypeSpoolFile(const char *filePathName);
eTypeSpoolFile findTypeSpoolFile(unsigned int spool_index, const char *filePathName);

#define snifferMode_read_from_interface_str string("1")
#define snifferMode_read_from_files_str string("2")
#define snifferMode_sender_str string("3")

#endif
