/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

#include <queue>
#include <climits>
// stevek - it could be smarter if sys/inotyfy.h available then use it otherwise use linux/inotify.h. I will do it later
#define GLOBAL_DECLARATION true
#include "voipmonitor.h"

#ifndef FREEBSD
#include <sys/inotify.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>

#ifdef FREEBSD
#include <sys/endian.h>
#else
#include <endian.h>
#endif

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <pthread.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/resource.h>
#include <semaphore.h>
#include <signal.h>
#include <execinfo.h>
#include <sstream>
#include <dirent.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <pcap.h>

#include "rtp.h"
#include "calltable.h"
#include "sniff.h"
#include "simpleini/SimpleIni.h"
#include "manager.h"
#include "filter_mysql.h"
#include "sql_db.h"
#include "tools.h"
#include "mirrorip.h"
#include "ipaccount.h"
#include "pcap_queue.h"
#include "generator.h"
#include "tcpreassembly.h"
#include "http.h"
#include "ip_frag.h"
#include "cleanspool.h"
#include "regcache.h"
#include "config_mysql.h"
#include "fraud.h"
#include "rrd.h"

#if defined(QUEUE_MUTEX) || defined(QUEUE_NONBLOCK)
extern "C" {
#include "liblfds.6/inc/liblfds.h"
}
#endif

#ifndef FREEBSD
#define BACKTRACE 1
#endif

#ifdef BACKTRACE
/* Since kernel version 2.2 the undocumented parameter to the signal handler has been declared
obsolete in adherence with POSIX.1b. A more correct way to retrieve additional information is
to use the SA_SIGINFO option when setting the handler */
#undef USE_SIGCONTEXT

#ifndef USE_SIGCONTEXT
/* get REG_EIP / REG_RIP from ucontext.h */
#include <ucontext.h>

        #ifndef EIP
        #define EIP     14
        #endif

        #if (defined (__x86_64__))
                #ifndef REG_RIP
                #define REG_RIP REG_INDEX(rip) /* seems to be 16 */
                #endif
        #endif

#endif

typedef struct { char name[10]; int id; char description[40]; } signal_def;

signal_def signal_data[] =
{
        { "SIGHUP", SIGHUP, "Hangup (POSIX)" },
        { "SIGINT", SIGINT, "Interrupt (ANSI)" },
        { "SIGQUIT", SIGQUIT, "Quit (POSIX)" },
        { "SIGILL", SIGILL, "Illegal instruction (ANSI)" },
        { "SIGTRAP", SIGTRAP, "Trace trap (POSIX)" },
        { "SIGABRT", SIGABRT, "Abort (ANSI)" },
        { "SIGIOT", SIGIOT, "IOT trap (4.2 BSD)" },
        { "SIGBUS", SIGBUS, "BUS error (4.2 BSD)" },
        { "SIGFPE", SIGFPE, "Floating-point exception (ANSI)" },
        { "SIGKILL", SIGKILL, "Kill, unblockable (POSIX)" },
        { "SIGUSR1", SIGUSR1, "User-defined signal 1 (POSIX)" },
        { "SIGSEGV", SIGSEGV, "Segmentation violation (ANSI)" },
        { "SIGUSR2", SIGUSR2, "User-defined signal 2 (POSIX)" },
        { "SIGPIPE", SIGPIPE, "Broken pipe (POSIX)" },
        { "SIGALRM", SIGALRM, "Alarm clock (POSIX)" },
        { "SIGTERM", SIGTERM, "Termination (ANSI)" },
        { "SIGSTKFLT", SIGSTKFLT, "Stack fault" },
        { "SIGCHLD", SIGCHLD, "Child status has changed (POSIX)" },
        { "SIGCLD", SIGCLD, "Same as SIGCHLD (System V)" },
        { "SIGCONT", SIGCONT, "Continue (POSIX)" },
        { "SIGSTOP", SIGSTOP, "Stop, unblockable (POSIX)" },
        { "SIGTSTP", SIGTSTP, "Keyboard stop (POSIX)" },
        { "SIGTTIN", SIGTTIN, "Background read from tty (POSIX)" },
        { "SIGTTOU", SIGTTOU, "Background write to tty (POSIX)" },
        { "SIGURG", SIGURG, "Urgent condition on socket (4.2 BSD)" },
        { "SIGXCPU", SIGXCPU, "CPU limit exceeded (4.2 BSD)" },
        { "SIGXFSZ", SIGXFSZ, "File size limit exceeded (4.2 BSD)" },
        { "SIGVTALRM", SIGVTALRM, "Virtual alarm clock (4.2 BSD)" },
        { "SIGPROF", SIGPROF, "Profiling alarm clock (4.2 BSD)" },
        { "SIGWINCH", SIGWINCH, "Window size change (4.3 BSD, Sun)" },
        { "SIGIO", SIGIO, "I/O now possible (4.2 BSD)" },
        { "SIGPOLL", SIGPOLL, "Pollable event occurred (System V)" },
        { "SIGPWR", SIGPWR, "Power failure restart (System V)" },
        { "SIGSYS", SIGSYS, "Bad system call" },
};
#endif

using namespace std;

int debugclean = 0;


/* global variables */

extern Calltable *calltable;
extern volatile int calls_counter;
extern volatile int calls_cdr_save_counter;
extern volatile int calls_message_save_counter;
unsigned int opt_openfile_max = 65535;
int opt_packetbuffered = 0;	// Make .pcap files writing ‘‘packet-buffered’’ 
				// more slow method, but you can use partitialy 
				// writen file anytime, it will be consistent.
	
int opt_disableplc = 0 ;	// On or Off packet loss concealment			
int opt_rrd = 1;
int opt_remotepartyid = 0;	//Rewrite caller? If sip invite contain header Remote-Party-ID, caller num/name is overwritten by its values.
int opt_fork = 1;		// fork or run foreground 
int opt_saveSIP = 0;		// save SIP packets to pcap file?
int opt_saveRTP = 0;		// save RTP packets to pcap file?
int opt_onlyRTPheader = 0;	// do not save RTP payload, only RTP header
int opt_saveRTCP = 0;		// save RTCP packets to pcap file?
int opt_saveudptl = 0;		// if = 1 all UDPTL packets will be saved (T.38 fax)
int opt_saveRAW = 0;		// save RTP packets to pcap file?
int opt_saveWAV = 0;		// save RTP packets to pcap file?
int opt_saveGRAPH = 0;		// save GRAPH data to *.graph file? 
int opt_gzipGRAPH = 0;		// compress GRAPH data ? 
int opt_saverfc2833 = 0;
int opt_dbdtmf = 0;
int opt_rtcp = 1;		// pair RTP+1 port to RTCP and save it. 
int opt_nocdr = 0;		// do not save cdr?
int opt_only_cdr_next = 0;
int opt_gzipPCAP = 0;		// compress PCAP data ? 
int opt_mos_g729 = 0;		// calculate MOS for G729 codec
int verbosity = 0;		// debug level
int verbosityE = 0;		// debug extended level
int opt_rtp_firstleg = 0;	// if == 1 then save RTP stream only for first INVITE leg in case you are 
				// sniffing on SIP proxy where voipmonitor see both SIP leg. 
int opt_rtp_check_timestamp = 0;
int opt_jitterbuffer_f1 = 1;		// turns off/on jitterbuffer simulator to compute MOS score mos_f1
int opt_jitterbuffer_f2 = 1;		// turns off/on jitterbuffer simulator to compute MOS score mos_f2
int opt_jitterbuffer_adapt = 1;		// turns off/on jitterbuffer simulator to compute MOS score mos_adapt
int opt_ringbuffer = 10;	// ring buffer in MB 
int opt_sip_register = 0;	// if == 1 save REGISTER messages
int opt_audio_format = FORMAT_WAV;	// define format for audio writing (if -W option)
int opt_manager_port = 5029;	// manager api TCP port
char opt_manager_ip[32] = "127.0.0.1";	// manager api listen IP address
int opt_pcap_threaded = 0;	// run reading packets from pcap in one thread and process packets in another thread via queue
int opt_rtpsave_threaded = 1;
int opt_norecord_header = 0;	// if = 1 SIP call with X-VoipMonitor-norecord header will be not saved although global configuration says to record. 
int opt_rtpnosip = 0;		// if = 1 RTP stream will be saved into calls regardless on SIP signalizatoin (handy if you need extract RTP without SIP)
int opt_norecord_dtmf = 0;	// if = 1 SIP call with dtmf == *0 sequence (in SIP INFO) will stop recording
int opt_savewav_force = 0;	// if = 1 WAV will be generated no matter on filter rules
int opt_sipoverlap = 1;		
int opt_id_sensor = -1;		
int opt_id_sensor_cleanspool = -1;		
int readend = 0;
int opt_dup_check = 0;
int opt_dup_check_ipheader = 1;
int rtptimeout = 300;
int sipwithoutrtptimeout = 3600;
int absolute_timeout = 4 * 3600;
int opt_destination_number_mode = 1;
int opt_update_dstnum_onanswer = 0;
int opt_cleanspool_interval = 0; // number of seconds between cleaning spool directory. 0 = disabled
int opt_cleanspool_sizeMB = 0; // number of MB to keep in spooldir
int opt_domainport = 0;
int request_iptelnum_reload = 0;
int opt_mirrorip = 0;
int opt_mirrorall = 0;
int opt_mirroronly = 0;
char opt_mirrorip_src[20];
char opt_mirrorip_dst[20];
int opt_printinsertid = 0;
int opt_ipaccount = 0;
int opt_ipacc_interval = 300;
bool opt_ipacc_sniffer_agregate = false;
bool opt_ipacc_agregate_only_customers_on_main_side = true;
bool opt_ipacc_agregate_only_customers_on_any_side = true;
int opt_udpfrag = 1;
MirrorIP *mirrorip = NULL;
int opt_cdronlyanswered = 0;
int opt_cdronlyrtp = 0;
int opt_pcap_split = 1;
int opt_newdir = 1;
char opt_clientmanager[1024] = "";
int opt_clientmanagerport = 9999;
int opt_callslimit = 0;
char opt_silencedmtfseq[16] = "";
char opt_keycheck[1024] = "";
char opt_convert_char[64] = "";
int opt_skinny = 0;
int opt_read_from_file = 0;
char opt_pb_read_from_file[256] = "";
int opt_dscp = 0;
int opt_cdrproxy = 1;
int opt_enable_http_enum_tables = 0;
int opt_generator = 0;
int opt_generator_channels = 1;
int opt_skipdefault = 0;
int opt_filesclean = 1;
int opt_enable_tcpreassembly = 0;
int opt_tcpreassembly_pb_lock = 0;
int opt_tcpreassembly_thread = 1;
char opt_tcpreassembly_log[1024];
int opt_allow_zerossrc = 0;
int opt_convert_dlt_sll_to_en10 = 0;
int opt_mysqlcompress = 1;
int opt_cdr_ua_enable = 1;
unsigned long long cachedirtransfered = 0;
unsigned int opt_maxpcapsize_mb = 0;
int opt_mosmin_f2 = 1;
char opt_database_backup_from_date[20];
char opt_database_backup_from_mysql_host[256] = "";
char opt_database_backup_from_mysql_database[256] = "";
char opt_database_backup_from_mysql_user[256] = "";
char opt_database_backup_from_mysql_password[256] = "";
int opt_database_backup_pause = 300;
int opt_database_backup_insert_threads = 1;
int opt_database_backup_use_federated = 0;
string opt_mos_lqo_bin = "pesq";
string opt_mos_lqo_ref = "/usr/local/share/voipmonitor/audio/mos_lqe_original.wav";
string opt_mos_lqo_ref16 = "/usr/local/share/voipmonitor/audio/mos_lqe_original_16khz.wav";
regcache *regfailedcache;
int opt_onewaytimeout = 15;
int opt_saveaudio_reversestereo = 0;
float opt_saveaudio_oggquality = 0.4;
int opt_saveaudio_stereo = 1;
int opt_register_timeout = 5;
unsigned int opt_maxpoolsize = 0;
unsigned int opt_maxpooldays = 0;
unsigned int opt_maxpoolsipsize = 0;
unsigned int opt_maxpoolsipdays = 0;
unsigned int opt_maxpoolrtpsize = 0;
unsigned int opt_maxpoolrtpdays = 0;
unsigned int opt_maxpoolgraphsize = 0;
unsigned int opt_maxpoolgraphdays = 0;
unsigned int opt_maxpoolaudiosize = 0;
unsigned int opt_maxpoolaudiodays = 0;
int opt_maxpool_clean_obsolete = 0;
int opt_autocleanspool = 1;
int opt_autocleanspoolminpercent = 1;
int opt_autocleanmingb = 5;
int opt_mysqlloadconfig = 1;
int opt_last_rtp_from_end = 1;
int opt_pcap_dump_bufflength = 8194;
int opt_pcap_dump_asyncwrite = 1;
int opt_pcap_dump_zip = 1;
int opt_pcap_dump_ziplevel = Z_DEFAULT_COMPRESSION;
int opt_pcap_dump_writethreads = 1;
int opt_pcap_dump_writethreads_max = 32;
int opt_pcap_dump_asyncwrite_maxsize = 100; //MB
int opt_defer_create_spooldir = 1;

int opt_sdp_multiplication = 3;

char opt_php_path[1024];

struct pcap_stat pcapstat;

extern int opt_pcap_queue;
extern u_int opt_pcap_queue_block_max_time_ms;
extern size_t opt_pcap_queue_block_max_size;
extern u_int opt_pcap_queue_file_store_max_time_ms;
extern size_t opt_pcap_queue_file_store_max_size;
extern uint64_t opt_pcap_queue_store_queue_max_memory_size;
extern uint64_t opt_pcap_queue_store_queue_max_disk_size;
extern uint64_t opt_pcap_queue_bypass_max_size;
extern bool opt_pcap_queue_compress;
extern string opt_pcap_queue_disk_folder;
extern ip_port opt_pcap_queue_send_to_ip_port;
extern ip_port opt_pcap_queue_receive_from_ip_port;
extern int opt_pcap_queue_receive_dlt;
extern int opt_pcap_queue_iface_separate_threads;
extern int opt_pcap_queue_iface_dedup_separate_threads;
extern int opt_pcap_queue_iface_dedup_separate_threads_extend;
extern int opt_pcap_queue_dequeu_window_length;
extern int opt_pcap_queue_dequeu_method;
extern int sql_noerror;
int opt_cleandatabase_cdr = 0;
int opt_cleandatabase_http_enum = 0;
int opt_cleandatabase_register_state = 0;
int opt_cleandatabase_register_failed = 0;
unsigned int graph_delimiter = GRAPH_DELIMITER;
unsigned int graph_version = GRAPH_VERSION;
unsigned int graph_mark = GRAPH_MARK;
int opt_mos_lqo = 0;

bool opt_cdr_partition = 1;
bool opt_cdr_sipport = 0;
bool opt_cdr_rtpport = 0;
int opt_create_old_partitions = 0;
bool opt_disable_partition_operations = 0;
vector<dstring> opt_custom_headers_cdr;
vector<dstring> opt_custom_headers_message;
int opt_custom_headers_last_value = 1;

char configfile[1024] = "";	// config file name

string insert_funcname = "__insert";

char sql_driver[256] = "mysql";
char sql_cdr_table[256] = "cdr";
char sql_cdr_table_last30d[256] = "";
char sql_cdr_table_last7d[256] = "";
char sql_cdr_table_last1d[256] = "";
char sql_cdr_next_table[256] = "cdr_next";
char sql_cdr_ua_table[256] = "cdr_ua";
char sql_cdr_sip_response_table[256] = "cdr_sip_response";

char mysql_host[256] = "127.0.0.1";
char mysql_host_orig[256] = "";
char mysql_database[256] = "voipmonitor";
char mysql_table[256] = "cdr";
char mysql_user[256] = "root";
char mysql_password[256] = "";
int opt_mysql_port = 0; // 0 menas use standard port 
int opt_skiprtpdata = 0;

char opt_match_header[128] = "";
char opt_callidmerge_header[128] = "";
char opt_callidmerge_secret[128] = "";

char odbc_dsn[256] = "voipmonitor";
char odbc_user[256];
char odbc_password[256];
char odbc_driver[256];

char cloud_host[256] = "";

char cloud_url[1024] = "";
char cloud_token[256] = "";

char ssh_host[1024] = "";
int ssh_port = 22;
char ssh_username[256] = "";
char ssh_password[256] = "";
char ssh_remote_listenhost[1024] = "localhost";
unsigned int ssh_remote_listenport = 5029;

char get_customer_by_ip_sql_driver[256] = "odbc";
char get_customer_by_ip_odbc_dsn[256];
char get_customer_by_ip_odbc_user[256];
char get_customer_by_ip_odbc_password[256];
char get_customer_by_ip_odbc_driver[256];
char get_customer_by_ip_query[1024];
char get_customers_ip_query[1024];
char get_customers_radius_name_query[1024];

char get_customer_by_pn_sql_driver[256] = "odbc";
char get_customer_by_pn_odbc_dsn[256];
char get_customer_by_pn_odbc_user[256];
char get_customer_by_pn_odbc_password[256];
char get_customer_by_pn_odbc_driver[256];
char get_customers_pn_query[1024];
vector<string> opt_national_prefix;

char get_radius_ip_driver[256];
char get_radius_ip_host[256];
char get_radius_ip_db[256];
char get_radius_ip_user[256];
char get_radius_ip_password[256];
char get_radius_ip_query[1024];
char get_radius_ip_query_where[1024];
int get_customer_by_ip_flush_period = 1;

char opt_pidfile[4098] = "/var/run/voipmonitor.pid";

char user_filter[1024*20] = "";
char ifname[1024];	// Specifies the name of the network device to use for 
			// the network lookup, for example, eth0
char opt_scanpcapdir[2048] = "";	// Specifies the name of the network device to use for 
#ifndef FREEBSD
uint32_t opt_scanpcapmethod = IN_CLOSE_WRITE; // Specifies how to watch for new files in opt_scanpcapdir
#endif
int opt_promisc = 1;	// put interface to promisc mode?
char pcapcommand[4092] = "";
char filtercommand[4092] = "";

int rtp_threaded = 0; // do not enable this until it will be reworked to be thread safe
int num_threads = 0; // this has to be 1 for now
unsigned int rtpthreadbuffer = 20;	// default 20MB
unsigned int gthread_num = 0;

int opt_pcapdump = 0;

int opt_callend = 1; //if true, cdr.called is saved
char opt_chdir[1024];
char opt_cachedir[1024];

int opt_upgrade_try_http_if_https_fail = 0;

IPfilter *ipfilter = NULL;		// IP filter based on MYSQL 
IPfilter *ipfilter_reload = NULL;	// IP filter based on MYSQL for reload purpose
int ipfilter_reload_do = 0;	// for reload in main thread

TELNUMfilter *telnumfilter = NULL;		// TELNUM filter based on MYSQL 
TELNUMfilter *telnumfilter_reload = NULL;	// TELNUM filter based on MYSQL for reload purpose
int telnumfilter_reload_do = 0;	// for reload in main thread

DOMAINfilter *domainfilter = NULL;		// DOMAIN filter based on MYSQL 
DOMAINfilter *domainfilter_reload = NULL;	// DOMAIN filter based on MYSQL for reload purpose
int domainfilter_reload_do = 0;	// for reload in main thread

pthread_t call_thread;		// ID of worker storing CDR thread 
//pthread_t destroy_calls_thread;
pthread_t readdump_libpcap_thread;
pthread_t manager_thread = 0;	// ID of worker manager thread 
pthread_t manager_client_thread;	// ID of worker manager thread 
pthread_t manager_ssh_thread;	
pthread_t cachedir_thread;	// ID of worker cachedir thread 
pthread_t database_backup_thread;	// ID of worker backup thread 
int terminating;		// if set to 1, worker thread will terminate
int terminating2;		// if set to 1, worker thread will terminate
char *sipportmatrix;		// matrix of sip ports to monitor
char *httpportmatrix;		// matrix of http ports to monitor
char *ipaccountportmatrix;
vector<u_int32_t> httpip;
vector<d_u_int32_t> httpnet;

uint8_t opt_sdp_reverse_ipport = 0;

volatile unsigned int readit = 0;
volatile unsigned int writeit = 0;
int global_livesniffer = 0;
int global_livesniffer_all = 0;
unsigned int qringmax = 12500;
#if defined(QUEUE_MUTEX) || defined(QUEUE_NONBLOCK) || defined(QUEUE_NONBLOCK2)
pcap_packet *qring;
#endif

pcap_t *global_pcap_handle = NULL;		// pcap handler 
pcap_t *global_pcap_handle_dead_EN10MB = NULL;

read_thread *threads;

int manager_socket_server = 0;

pthread_mutex_t mysqlconnect_lock;
pthread_mutex_t rdd_lock;

pthread_t pcap_read_thread;
#ifdef QUEUE_MUTEX
pthread_mutex_t readpacket_thread_queue_lock;
sem_t readpacket_thread_semaphore;
#endif

#ifdef QUEUE_NONBLOCK
struct queue_state *qs_readpacket_thread_queue = NULL;
#endif

nat_aliases_t nat_aliases;	// net_aliases[local_ip] = extern_ip

MySqlStore *sqlStore = NULL;

char mac[32] = "";

PcapQueue *pcapQueueStatInterface;

TcpReassembly *tcpReassembly;
HttpData *httpData;

vm_atomic<string> storingCdrLastWriteAt;

time_t startTime;

sem_t *globalSemaphore;

bool opt_loadsqlconfig = true;

int opt_mysqlstore_concat_limit = 0;
int opt_mysqlstore_concat_limit_cdr = 0;
int opt_mysqlstore_concat_limit_message = 0;
int opt_mysqlstore_concat_limit_register = 0;
int opt_mysqlstore_concat_limit_http = 0;
int opt_mysqlstore_concat_limit_ipacc = 0;
int opt_mysqlstore_max_threads_cdr = 1;
int opt_mysqlstore_max_threads_message = 1;
int opt_mysqlstore_max_threads_register = 1;
int opt_mysqlstore_max_threads_http = 1;
int opt_mysqlstore_max_threads_ipacc_base = 3;
int opt_mysqlstore_max_threads_ipacc_agreg2 = 3;
int opt_mysqlstore_limit_queue_register = 1000000;

char opt_curlproxy[256] = "";
int opt_enable_fraud = 1;
char opt_local_country_code[10] = "local";

map<string, string> hosts;

ip_port sipSendSocket_ip_port;
SocketSimpleBufferWrite *sipSendSocket = NULL;
int opt_sip_send_before_packetbuffer = 0;

int opt_enable_jitterbuffer_asserts = 0;
int opt_hide_message_content = 0;
char opt_hide_message_content_secret[1024] = "";

char opt_bogus_dumper_path[1204];
BogusDumper *bogusDumper;


#include <stdio.h>
#include <pthread.h>
#include <openssl/err.h>
 
#define MUTEX_TYPE       pthread_mutex_t
#define MUTEX_SETUP(x)   pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x)    pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x)  pthread_mutex_unlock(&(x))
#define THREAD_ID        pthread_self(  )
 
 
void handle_error(const char *file, int lineno, const char *msg){
     fprintf(stderr, "** %s:%d %s\n", file, lineno, msg);
     ERR_print_errors_fp(stderr);
     /* exit(-1); */ 
 }
 
/* This array will store all of the mutexes available to OpenSSL. */ 
static MUTEX_TYPE *mutex_buf= NULL;
 
 
static void locking_function(int mode, int n, const char * file, int line)
{
  if (mode & CRYPTO_LOCK)
    MUTEX_LOCK(mutex_buf[n]);
  else
    MUTEX_UNLOCK(mutex_buf[n]);
}
 
static unsigned long id_function(void)
{
  return ((unsigned long)THREAD_ID);
}
 
int thread_setup(void)
{
  int i;
 
  mutex_buf = (MUTEX_TYPE *)malloc(CRYPTO_num_locks(  ) * sizeof(MUTEX_TYPE));
  if (!mutex_buf)
    return 0;
  for (i = 0;  i < CRYPTO_num_locks(  );  i++)
    MUTEX_SETUP(mutex_buf[i]);
  CRYPTO_set_id_callback(id_function);
  CRYPTO_set_locking_callback(locking_function);
  return 1;
}
 
int thread_cleanup(void)
{
  int i;
 
  if (!mutex_buf)
    return 0;
  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  for (i = 0;  i < CRYPTO_num_locks(  );  i++)
    MUTEX_CLEANUP(mutex_buf[i]);
  free(mutex_buf);
  mutex_buf = NULL;
  return 1;
}



#define ENABLE_SEMAPHOR_FORK_MODE 0
#if ENABLE_SEMAPHOR_FORK_MODE
string SEMAPHOR_FORK_MODE_NAME() {
 	char forkModeName[1024] = "";
	if(!forkModeName[0]) {
		strcpy(forkModeName, configfile[0] ? configfile : "voipmonitor_fork_mode");
		if(configfile[0]) {
			char *point = forkModeName;
			while(*point) {
				if(!isdigit(*point) && !isalpha(*point)) {
					*point = '_';
				}
				++point;
			}
		}
	}
	return(forkModeName);
}
#endif

void terminate2() {
	terminating = 1;
}

#if ENABLE_SEMAPHOR_FORK_MODE
void exit_handler_fork_mode()
{
	if(opt_fork) {
		sem_unlink(SEMAPHOR_FORK_MODE_NAME().c_str());
		if(globalSemaphore) {
			sem_close(globalSemaphore);
		}
	}
}
#endif

/* handler for INTERRUPT signal */
void sigint_handler(int param)
{
	syslog(LOG_ERR, "SIGINT received, terminating\n");
	terminate2();
	#if ENABLE_SEMAPHOR_FORK_MODE
	exit_handler_fork_mode();
	#endif
}

/* handler for TERMINATE signal */
void sigterm_handler(int param)
{
	syslog(LOG_ERR, "SIGTERM received, terminating\n");
	terminate2();
	#if ENABLE_SEMAPHOR_FORK_MODE
	exit_handler_fork_mode();
	#endif
}

void *database_backup(void *dummy) {
	if(!isSqlDriver("mysql")) {
		syslog(LOG_ERR, "database_backup is only for mysql driver!");
		return(NULL);
	}
	if(!opt_cdr_partition) {
		syslog(LOG_ERR, "database_backup need enable partitions!");
		return(NULL);
	}
	time_t createPartitionAt = 0;
	time_t dropPartitionAt = 0;
	SqlDb *sqlDb = createSqlObject();
	if(!sqlDb->connect()) {
		delete sqlDb;
		return NULL;
	}
	SqlDb_mysql *sqlDb_mysql = dynamic_cast<SqlDb_mysql*>(sqlDb);
	sqlStore = new MySqlStore(mysql_host, mysql_user, mysql_password, mysql_database);
	for(int i = 1; i <= 10; i++) {
		sqlStore->setIgnoreTerminating(i, true);
	}
	while(!terminating) {
		syslog(LOG_NOTICE, "-- START BACKUP PROCESS");
		time_t actTime = time(NULL);
		if(actTime - createPartitionAt > 12 * 3600) {
			createMysqlPartitionsCdr();
			createPartitionAt = actTime;
		}
		if(actTime - dropPartitionAt > 12 * 3600) {
			dropMysqlPartitionsCdr();
			dropPartitionAt = actTime;
		}
		if(opt_database_backup_use_federated) {
			sqlDb_mysql->dropFederatedTables();
			sqlDb->createSchema(opt_database_backup_from_mysql_host, 
					    opt_database_backup_from_mysql_database,
					    opt_database_backup_from_mysql_user,
					    opt_database_backup_from_mysql_password);
			if(sqlDb_mysql->checkFederatedTables()) {
				sqlDb_mysql->copyFromFederatedTables();
			}
		} else {
			SqlDb *sqlDbSrc = new SqlDb_mysql();
			sqlDbSrc->setConnectParameters(opt_database_backup_from_mysql_host, 
						       opt_database_backup_from_mysql_user,
						       opt_database_backup_from_mysql_password,
						       opt_database_backup_from_mysql_database);
			if(sqlDbSrc->connect()) {
				SqlDb_mysql *sqlDbSrc_mysql = dynamic_cast<SqlDb_mysql*>(sqlDbSrc);
				if(sqlDbSrc_mysql->checkSourceTables()) {
					sqlDb_mysql->copyFromSourceTables(sqlDbSrc_mysql);
				}
			}
			delete sqlDbSrc;
		}
		syslog(LOG_NOTICE, "-- END BACKUP PROCESS");
		for(int i = 0; i < opt_database_backup_pause && !terminating; i++) {
			sleep(1);
		}
	}
	while(sqlStore->getAllSize()) {
		syslog(LOG_NOTICE, "flush sqlStore");
		sleep(1);
	}
	for(int i = 1; i <= 10; i++) {
		sqlStore->setIgnoreTerminating(i, false);
	}
	delete sqlDb;
	delete sqlStore;
	return NULL;
}

/* cycle files_queue and move it to spool dir */
void *moving_cache( void *dummy ) {
	string file;
	char src_c[1024];
	char dst_c[1024];
	unsigned long long counter[2] = { 0, 0 };
	while(1) {
		u_int32_t mindatehour = 0;
		int year, month, mday, hour;
		while (1) {
			calltable->lock_files_queue();
			if(calltable->files_queue.size() == 0) {
				calltable->unlock_files_queue();
				break;
			}
			file = calltable->files_queue.front();
			calltable->files_queue.pop();
			calltable->unlock_files_queue();
			
			sscanf(file.c_str(), "%d-%d-%d/%d", &year, &month, &mday, &hour);
			u_int32_t datehour = year * 1000000 + month * 10000 + mday * 100 + hour;
			if(!mindatehour || datehour < mindatehour) {
				 mindatehour = datehour;
			}

			string src;
			src.append(opt_cachedir);
			src.append("/");
			src.append(file);

			string dst;
			dst.append(opt_chdir);
			dst.append("/");
			dst.append(file);

			strncpy(src_c, (char*)src.c_str(), sizeof(src_c));
			strncpy(dst_c, (char*)dst.c_str(), sizeof(dst_c));

			if(verbosity > 2) syslog(LOG_ERR, "rename([%s] -> [%s])\n", src_c, dst_c);
			cachedirtransfered += move_file(src_c, dst_c);
			//TODO: error handling
			//perror ("The following error occurred");
		}
		if(terminating2) {
			break;
		} else {
			++counter[0];
			if(mindatehour && counter[0] > counter[1] + 300) {
				DIR* dp = opendir(opt_cachedir);
				struct tm mindatehour_t;
				memset(&mindatehour_t, 0, sizeof(mindatehour_t));
				mindatehour_t.tm_year = mindatehour / 1000000 - 1900;
				mindatehour_t.tm_mon = mindatehour / 10000 % 100 - 1;  
				mindatehour_t.tm_mday = mindatehour / 100 % 100;
				mindatehour_t.tm_hour = mindatehour % 100; 
				if(dp) {
					dirent* de;
					while(true) {
						de = readdir(dp);
						if(de == NULL) break;
						if(string(de->d_name) == ".." or string(de->d_name) == ".") continue;
						if(de->d_type == DT_DIR && de->d_name[0] == '2') {
							int year, month, mday;
							sscanf(de->d_name, "%d-%d-%d", &year, &month, &mday);
							bool moveHourDir = false;
							for(int hour = 0; hour < 24; hour ++) {
								struct tm dirdatehour_t;
								memset(&dirdatehour_t, 0, sizeof(dirdatehour_t));
								dirdatehour_t.tm_year = year - 1900;
								dirdatehour_t.tm_mon = month - 1;  
								dirdatehour_t.tm_mday = mday;
								dirdatehour_t.tm_hour = hour; 
								if(difftime(mktime(&mindatehour_t), mktime(&dirdatehour_t)) > 8 * 60 * 60) {
									char hour_str[10];
									sprintf(hour_str, "%02i", hour);
									if(file_exists((char*)(string(opt_cachedir) + "/" + de->d_name + "/" + hour_str).c_str())) {
										mkdir_r((string(opt_chdir) + "/" + de->d_name + "/" + hour_str).c_str(), 0777);
										mv_r((string(opt_cachedir) + "/" + de->d_name + "/" + hour_str).c_str(), (string(opt_chdir) + "/" + de->d_name + "/" + hour_str).c_str());
										rmdir((string(opt_cachedir) + "/" + de->d_name + "/" + hour_str).c_str());
										moveHourDir = true;
									}
								}
							}
							if(moveHourDir) {
								rmdir((string(opt_cachedir) + "/" + de->d_name).c_str());
							}
						}
					}
					closedir(dp);
				}
				counter[1] = counter[0];
			}
		}
		sleep(1);
	}
	return NULL;
}

/* cycle calls_queue and save it to MySQL */
void *storing_cdr( void *dummy ) {
	Call *call;
	time_t createPartitionAt = 0;
	time_t dropPartitionAt = 0;
	time_t createPartitionIpaccAt = 0;
	time_t createPartitionBillingAgregationAt = 0;
	time_t checkDiskFreeAt = 0;
	while(1) {
		if(!opt_nocdr and opt_cdr_partition and !opt_disable_partition_operations and isSqlDriver("mysql")) {
			time_t actTime = time(NULL);
			if(actTime - createPartitionAt > 12 * 3600) {
				createMysqlPartitionsCdr();
				createPartitionAt = actTime;
			}
			if(actTime - dropPartitionAt > 12 * 3600) {
				dropMysqlPartitionsCdr();
				dropPartitionAt = actTime;
			}
		}
		
		if(!opt_nocdr and opt_ipaccount and !opt_disable_partition_operations and isSqlDriver("mysql")) {
			time_t actTime = time(NULL);
			if(actTime - createPartitionIpaccAt > 12 * 3600) {
				createMysqlPartitionsIpacc();
				createPartitionIpaccAt = actTime;
			}
		}
		
		if(!opt_nocdr and !opt_disable_partition_operations and isSqlDriver("mysql")) {
			time_t actTime = time(NULL);
			if(actTime - createPartitionBillingAgregationAt > 12 * 3600) {
				createMysqlPartitionsBillingAgregation();
				createPartitionBillingAgregationAt = actTime;
			}
		}
		
		if(opt_autocleanspool &&
		   isSqlDriver("mysql") &&
		   !(opt_pcap_queue && 
		     !opt_pcap_queue_receive_from_ip_port &&
		     opt_pcap_queue_send_to_ip_port)) {
			time_t actTime = time(NULL);
			if(!checkDiskFreeAt) {
				checkDiskFreeAt = actTime;
			} else if(actTime - checkDiskFreeAt > 5 * 60) {
				run_check_disk_free_thread();
				checkDiskFreeAt = actTime;
			}
		}
		
		if(request_iptelnum_reload == 1) { reload_capture_rules(); request_iptelnum_reload = 0;};
		
		if(verbosity > 0 && !opt_pcap_queue) { 
			ostringstream outStr;
			outStr << "calls[" << calls_counter << "]";
			if(opt_ipaccount) {
				outStr << " ipacc_buffer[" << lengthIpaccBuffer() << "]";
			}
			#ifdef QUEUE_NONBLOCK2
			if(!opt_pcap_queue) {
				outStr << " qring[" << (writeit >= readit ? writeit - readit : writeit + qringmax - readit)
				       << " (w" << writeit << ",r" << readit << ")]";
			}
			#endif
			syslog(LOG_NOTICE, outStr.str().c_str());
		}
		while (1) {

			if(request_iptelnum_reload == 1) { reload_capture_rules(); request_iptelnum_reload = 0;};

			calltable->lock_calls_queue();
			if(calltable->calls_queue.size() == 0) {
				calltable->unlock_calls_queue();
				break;
			}
			call = calltable->calls_queue.front();
			calltable->calls_queue.pop_front();
			calltable->unlock_calls_queue();
	
			call->closeRawFiles();
			if( (opt_savewav_force || (call->flags & FLAG_SAVEWAV)) && (call->type == INVITE || call->type == SKINNY_NEW) &&
			    call->getAllReceivedRtpPackets()) {
				if(verbosity > 0) printf("converting RAW file to WAV Queue[%d]\n", (int)calltable->calls_queue.size());
				call->convertRawToWav();
			}

			regfailedcache->prunecheck(call->first_packet_time);
			if(!opt_nocdr) {
				if(call->type == INVITE or call->type == SKINNY_NEW) {
					call->saveToDb(1);
				} else if(call->type == REGISTER){
					call->saveRegisterToDb();
				} else if(call->type == MESSAGE){
					call->saveMessageToDb();
				}
			}
			// Close SIP and SIP+RTP dump files ASAP to save file handles
			call->getPcap()->close();
			call->getPcapSip()->close();

			/* if we delete call here directly, destructors and another cleaning functions can be
			 * called in the middle of working with call or another structures inside main thread
			 * so put it in deletequeue and delete it in the main thread. Another way can be locking
			 * call structure for every case in main thread but it can slow down thinks for each 
			 * processing packet.
			*/
			calltable->lock_calls_deletequeue();
			calltable->calls_deletequeue.push_back(call);
			calltable->unlock_calls_deletequeue();
			storingCdrLastWriteAt = getActDateTimeF();
		}

		if(terminating) {
			break;
		}
	
		sleep(1);
	}
	return NULL;
}

/*
void *destroy_calls( void *dummy ) {
	while(1) {
		calltable->destroyCallsIfPcapsClosed();
		
		if(terminating) {
			break;
		}
	
		sleep(2);
	}
	return NULL;
}
*/

char daemonizeErrorTempFileName[L_tmpnam+1];
pthread_mutex_t daemonizeErrorTempFileLock;

static void daemonize(void)
{
 
	tmpnam(daemonizeErrorTempFileName);
	pthread_mutex_init(&daemonizeErrorTempFileLock, NULL);
 
	pid_t pid;

	pid = fork();
	if (pid) {
		// parent
		sleep(5);
		FILE *daemonizeErrorFile = fopen(daemonizeErrorTempFileName, "r");
		if(daemonizeErrorFile) {
			char buff[1024];
			while(fgets(buff, sizeof(buff), daemonizeErrorFile)) {
				cout << buff;
			}
			unlink(daemonizeErrorTempFileName);
		}
		opt_fork = 0;
		exit(0);
	} else {
		// child
		FILE* f;
		pid_t vmon_pid;

		setsid();

		// write pid file to opt_pidfile
		vmon_pid = getpid();
		f = fopen(opt_pidfile, "w");
		if (f) {
		       fprintf(f, "%ld\n", (long)vmon_pid);
		       fclose(f);
		} else {
		       syslog(LOG_ERR,"Error occurs while writing pid file to %s\n", opt_pidfile);
		}

		// close std descriptors (otherwise problems detaching ssh)
		close(0); open("/dev/null", O_RDONLY);
		close(1); open("/dev/null", O_WRONLY);
		close(2); open("/dev/null", O_WRONLY);
	}
}

void daemonizeOutput(string error) {
	pthread_mutex_lock(&daemonizeErrorTempFileLock);
	ofstream daemonizeErrorStream(daemonizeErrorTempFileName, ofstream::out | ofstream::app);
	daemonizeErrorStream << error << endl;
	daemonizeErrorStream.close();
	pthread_mutex_unlock(&daemonizeErrorTempFileLock);
}

int yesno(const char *arg) {
	if(arg[0] == 'y' or arg[0] == 'Y' or arg[0] == '1') 
		return 1;
	else
		return 0;
}


int eval_config(string inistr) {
	CSimpleIniA ini;
	ini.SetUnicode();
	ini.SetMultiKey(true);
	int rc = ini.LoadData(inistr);			//load ini from passed string
	if (rc != 0) {
		return 1;
	}
 	const char *value;
	const char *value2;
	CSimpleIniA::TNamesDepend values;

	// sip ports
	if (ini.GetAllValues("general", "sipport", values)) {
		CSimpleIni::TNamesDepend::const_iterator i = values.begin();
		// reset default port 
		sipportmatrix[5060] = 0;
		for (; i != values.end(); ++i) {
			sipportmatrix[atoi(i->pItem)] = 1;
		}
	}

	// http ports
	if (ini.GetAllValues("general", "httpport", values)) {
		CSimpleIni::TNamesDepend::const_iterator i = values.begin();
		// reset default port 
		for (; i != values.end(); ++i) {
			httpportmatrix[atoi(i->pItem)] = 1;
		}
	}
	
	// http ip
	if (ini.GetAllValues("general", "httpip", values)) {
		CSimpleIni::TNamesDepend::const_iterator i = values.begin();
		for (; i != values.end(); ++i) {
			u_int32_t ip;
			int lengthMask = 32;
			char *pointToSeparatorLengthMask = strchr((char*)i->pItem, '/');
			if(pointToSeparatorLengthMask) {
				*pointToSeparatorLengthMask = 0;
				ip = htonl(inet_addr(i->pItem));
				lengthMask = atoi(pointToSeparatorLengthMask + 1);
			} else {
				ip = htonl(inet_addr(i->pItem));
			}
			if(lengthMask < 32) {
				ip = ip >> (32 - lengthMask) << (32 - lengthMask);
			}
			if(ip) {
				if(lengthMask < 32) {
					httpnet.push_back(d_u_int32_t(ip, lengthMask));
				} else {
					httpip.push_back(ip);
				}
			}
		}
		if(httpip.size() > 1) {
			std::sort(httpip.begin(), httpip.end());
		}
	}

	// ipacc ports
	if (ini.GetAllValues("general", "ipaccountport", values)) {
		CSimpleIni::TNamesDepend::const_iterator i = values.begin();
		// reset default port 
		for (; i != values.end(); ++i) {
			if(!ipaccountportmatrix) {
				ipaccountportmatrix = (char*)calloc(1, sizeof(char) * 65537);
			}
			ipaccountportmatrix[atoi(i->pItem)] = 1;
		}
	}

	// nat aliases
	if (ini.GetAllValues("general", "natalias", values)) {
		char local_ip[30], extern_ip[30];
		in_addr_t nlocal_ip, nextern_ip;
		int len, j = 0, i;
		char *s = local_ip;
		CSimpleIni::TNamesDepend::const_iterator it = values.begin();

		for (; it != values.end(); ++it) {
			s = local_ip;
			j = 0;
			for(i = 0; i < 30; i++) {
				local_ip[i] = '\0';
				extern_ip[i] = '\0';
			}

			len = strlen(it->pItem);
			for(int i = 0; i < len; i++) {
				if(it->pItem[i] == ' ' or it->pItem[i] == ':' or it->pItem[i] == '=' or it->pItem[i] == ' ') {
					// moving s to b pointer (write to b ip
					s = extern_ip;
					j = 0;
				} else {
					s[j] = it->pItem[i];
					j++;
				}
			}
			if ((int32_t)(nlocal_ip = inet_addr(local_ip)) != -1 && (int32_t)(nextern_ip = inet_addr(extern_ip)) != -1 ){
				nat_aliases[nlocal_ip] = nextern_ip;
				if(verbosity > 3) printf("adding local_ip[%s][%u] = extern_ip[%s][%u]\n", local_ip, nlocal_ip, extern_ip, nextern_ip);
			}
		}
	}

	if((value = ini.GetValue("general", "interface", NULL))) {
		strncpy(ifname, value, sizeof(ifname));
	}
	if((value = ini.GetValue("general", "cleandatabase", NULL))) {
		opt_cleandatabase_cdr = atoi(value);
		opt_cleandatabase_http_enum = opt_cleandatabase_cdr;
		opt_cleandatabase_register_state = opt_cleandatabase_cdr;
		opt_cleandatabase_register_failed = opt_cleandatabase_cdr;
	}
	if((value = ini.GetValue("general", "plcdisable", NULL))) {
		opt_disableplc = yesno(value);
	}
	if((value = ini.GetValue("general", "rrd", NULL))) {
		opt_rrd = yesno(value);
	}
	if((value = ini.GetValue("general", "remotepartyid", NULL))) {
		opt_remotepartyid = yesno(value);
	}
	if((value = ini.GetValue("general", "cleandatabase_cdr", NULL))) {
		opt_cleandatabase_cdr = atoi(value);
		opt_cleandatabase_http_enum = opt_cleandatabase_cdr;
	}
	if((value = ini.GetValue("general", "cleandatabase_http_enum", NULL))) {
		opt_cleandatabase_http_enum = atoi(value);
	}
	if((value = ini.GetValue("general", "cleandatabase_register_state", NULL))) {
		opt_cleandatabase_register_state = atoi(value);
	}
	if((value = ini.GetValue("general", "cleandatabase_register_failed", NULL))) {
		opt_cleandatabase_register_failed = atoi(value);
	}
	if((value = ini.GetValue("general", "cleanspool_interval", NULL))) {
		opt_cleanspool_interval = atoi(value);
	}
	if((value = ini.GetValue("general", "cleanspool_size", NULL))) {
		opt_cleanspool_sizeMB = atoi(value);
	}
	if((value = ini.GetValue("general", "maxpoolsize", NULL))) {
		opt_maxpoolsize = atoi(value);
	}
	if((value = ini.GetValue("general", "maxpooldays", NULL))) {
		opt_maxpooldays = atoi(value);
	}
	if((value = ini.GetValue("general", "maxpoolsipsize", NULL))) {
		opt_maxpoolsipsize = atoi(value);
	}
	if((value = ini.GetValue("general", "maxpoolsipdays", NULL))) {
		opt_maxpoolsipdays = atoi(value);
	}
	if((value = ini.GetValue("general", "maxpoolrtpsize", NULL))) {
		opt_maxpoolrtpsize = atoi(value);
	}
	if((value = ini.GetValue("general", "maxpoolrtpdays", NULL))) {
		opt_maxpoolrtpdays = atoi(value);
	}
	if((value = ini.GetValue("general", "maxpoolgraphsize", NULL))) {
		opt_maxpoolgraphsize = atoi(value);
	}
	if((value = ini.GetValue("general", "maxpoolgraphdays", NULL))) {
		opt_maxpoolgraphdays = atoi(value);
	}
	if((value = ini.GetValue("general", "maxpoolaudiosize", NULL))) {
		opt_maxpoolaudiosize = atoi(value);
	}
	if((value = ini.GetValue("general", "maxpoolaudiodays", NULL))) {
		opt_maxpoolaudiodays = atoi(value);
	}
	if((value = ini.GetValue("general", "maxpool_clean_obsolete", NULL))) {
		opt_maxpool_clean_obsolete = yesno(value);
	}
	if((value = ini.GetValue("general", "autocleanspool", NULL))) {
		opt_autocleanspool = yesno(value);
	}
	if((value = ini.GetValue("general", "autocleanspoolminpercent", NULL))) {
		opt_autocleanspoolminpercent = atoi(value);
	}
	if((value = ini.GetValue("general", "autocleanmingb", NULL))) {
		opt_autocleanmingb = atoi(value);
	}
	if((value = ini.GetValue("general", "id_sensor", NULL))) {
		opt_id_sensor = atoi(value);
		opt_id_sensor_cleanspool = opt_id_sensor;
		insert_funcname = "__insert_";
		insert_funcname.append(value);
	}
	if((value = ini.GetValue("general", "pcapcommand", NULL))) {
		strncpy(pcapcommand, value, sizeof(pcapcommand));
	}
	if((value = ini.GetValue("general", "filtercommand", NULL))) {
		strncpy(filtercommand, value, sizeof(filtercommand));
	}
	if((value = ini.GetValue("general", "ringbuffer", NULL))) {
		opt_ringbuffer = MIN(atoi(value), 2000);
	}
	if((value = ini.GetValue("general", "rtpthreads", NULL))) {
		num_threads = atoi(value);
	}
	if((value = ini.GetValue("general", "rtptimeout", NULL))) {
		rtptimeout = atoi(value);
	}
	if((value = ini.GetValue("general", "sipwithoutrtptimeout", NULL))) {
		sipwithoutrtptimeout = atoi(value);
	}
	if((value = ini.GetValue("general", "absolute_timeout", NULL))) {
		absolute_timeout = atoi(value);
	}
	if((value = ini.GetValue("general", "rtpthread-buffer", NULL))) {
		rtpthreadbuffer = atoi(value);
	}
	if((value = ini.GetValue("general", "rtp-firstleg", NULL))) {
		opt_rtp_firstleg = yesno(value);
	}
	if((value = ini.GetValue("general", "rtp-check-timestamp", NULL))) {
		opt_rtp_check_timestamp = yesno(value);
	}
	if((value = ini.GetValue("general", "allow-zerossrc", NULL))) {
		opt_allow_zerossrc = yesno(value);
	}
	if((value = ini.GetValue("general", "sip-register", NULL))) {
		opt_sip_register = yesno(value);
	}
	if((value = ini.GetValue("general", "sip-register-timeout", NULL))) {
		opt_register_timeout = atoi(value);
	}
	if((value = ini.GetValue("general", "deduplicate", NULL))) {
		opt_dup_check = yesno(value);
	}
	if((value = ini.GetValue("general", "deduplicate_ipheader", NULL))) {
		opt_dup_check_ipheader = yesno(value);
	}
	if((value = ini.GetValue("general", "dscp", NULL))) {
		opt_dscp = yesno(value);
	}
	if((value = ini.GetValue("general", "cdrproxy", NULL))) {
		opt_cdrproxy = yesno(value);
	}
	if((value = ini.GetValue("general", "mos_g729", NULL))) {
		opt_mos_g729 = yesno(value);
	}
	if((value = ini.GetValue("general", "nocdr", NULL))) {
		opt_nocdr = yesno(value);
	}
	if((value = ini.GetValue("general", "only_cdr_next", NULL))) {
		opt_only_cdr_next = yesno(value);
	}
	if((value = ini.GetValue("general", "skipdefault", NULL))) {
		opt_skipdefault = yesno(value);
	}
	if((value = ini.GetValue("general", "skinny", NULL))) {
		opt_skinny = yesno(value);
	}
	if((value = ini.GetValue("general", "cdr_partition", NULL))) {
		opt_cdr_partition = yesno(value);
	}
	if((value = ini.GetValue("general", "cdr_sipport", NULL))) {
		opt_cdr_sipport = yesno(value);
	}
	if((value = ini.GetValue("general", "cdr_rtpport", NULL))) {
		opt_cdr_rtpport = yesno(value);
	}
	if((value = ini.GetValue("general", "create_old_partitions", NULL))) {
		opt_create_old_partitions = atoi(value);
	} else if((value = ini.GetValue("general", "create_old_partitions_from", NULL))) {
		opt_create_old_partitions = getNumberOfDayToNow(value);
	} else if((value = ini.GetValue("general", "database_backup_from_date", NULL))) {
		opt_create_old_partitions = getNumberOfDayToNow(value);
		strncpy(opt_database_backup_from_date, value, sizeof(opt_database_backup_from_date));
	}
	if((value = ini.GetValue("general", "disable_partition_operations", NULL))) {
		opt_disable_partition_operations = yesno(value);
	}
	if((value = ini.GetValue("general", "cdr_ua_enable", NULL))) {
		opt_cdr_ua_enable = yesno(value);
	}
	for(int i = 0; i < 2; i++) {
		if(i == 0 ?
			(value = ini.GetValue("general", "custom_headers_cdr", NULL)) ||
			(value = ini.GetValue("general", "custom_headers", NULL)) :
			(value = ini.GetValue("general", "custom_headers_message", NULL)) != NULL) {
			char *pos = (char*)value;
			while(pos && *pos) {
				char *posSep = strchr(pos, ';');
				if(posSep) {
					*posSep = 0;
				}
				string custom_header = pos;
				custom_header.erase(custom_header.begin(), std::find_if(custom_header.begin(), custom_header.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
				custom_header.erase(std::find_if(custom_header.rbegin(), custom_header.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), custom_header.end());
				string custom_header_field = "custom_header__" + custom_header;
				std::replace(custom_header_field.begin(), custom_header_field.end(), ' ', '_');
				if(i == 0) {
					opt_custom_headers_cdr.push_back(dstring(custom_header, custom_header_field));
				} else {
					opt_custom_headers_message.push_back(dstring(custom_header, custom_header_field));
				}
				pos = posSep ? posSep + 1 : NULL;
			}
		}
	}
	if((value = ini.GetValue("general", "custom_headers_last_value", NULL))) {
		opt_custom_headers_last_value = yesno(value);
	}
	if((value = ini.GetValue("general", "savesip", NULL))) {
		opt_saveSIP = yesno(value);
	}
	if((value = ini.GetValue("general", "savertp", NULL))) {
		switch(value[0]) {
		case 'y':
		case 'Y':
		case '1':
			opt_saveRTP = 1;
			break;
		case 'h':
		case 'H':
			opt_onlyRTPheader = 1;
			break;
		}
	}
	if((value = ini.GetValue("general", "saverfc2833", NULL))) {
		opt_saverfc2833 = yesno(value);
	}
	if((value = ini.GetValue("general", "dtmf2db", NULL))) {
		opt_dbdtmf = yesno(value);
	}
	if((value = ini.GetValue("general", "saveudptl", NULL))) {
		opt_saveudptl = yesno(value);
	}
	if((value = ini.GetValue("general", "savertp-threaded", NULL))) {
		opt_rtpsave_threaded = yesno(value);
	}
	if((value = ini.GetValue("general", "norecord-header", NULL))) {
		opt_norecord_header = yesno(value);
	}
	if((value = ini.GetValue("general", "norecord-dtmf", NULL))) {
		opt_norecord_dtmf = yesno(value);
	}
	if((value = ini.GetValue("general", "vmbuffer", NULL))) {
		qringmax = (unsigned int)((unsigned int)MIN(atoi(value), 4000) * 1024 * 1024 / (unsigned int)sizeof(pcap_packet));
	}
	if((value = ini.GetValue("general", "matchheader", NULL))) {
		snprintf(opt_match_header, sizeof(opt_match_header), "\n%s:", value);
	}
	//for compatibility 
	if((value = ini.GetValue("general", "match_header", NULL))) {
		snprintf(opt_match_header, sizeof(opt_match_header), "\n%s:", value);
	}
	if((value = ini.GetValue("general", "callidmerge_header", NULL))) {
		snprintf(opt_callidmerge_header, sizeof(opt_callidmerge_header), "\n%s:", value);
	}
	if((value = ini.GetValue("general", "callidmerge_secret", NULL))) {
		strncpy(opt_callidmerge_secret, value, sizeof(opt_callidmerge_secret));
	}
	if((value = ini.GetValue("general", "domainport", NULL))) {
		opt_domainport = atoi(value);
	}
	if((value = ini.GetValue("general", "managerport", NULL))) {
		opt_manager_port = atoi(value);
	}
	if((value = ini.GetValue("general", "managerip", NULL))) {
		strncpy(opt_manager_ip, value, sizeof(opt_manager_ip));
	}
	if((value = ini.GetValue("general", "managerclient", NULL))) {
		strncpy(opt_clientmanager, value, sizeof(opt_clientmanager) - 1);
	}
	if((value = ini.GetValue("general", "managerclientport", NULL))) {
		opt_clientmanagerport = atoi(value);
	}
	if((value = ini.GetValue("general", "savertcp", NULL))) {
		opt_saveRTCP = yesno(value);
	}
	if((value = ini.GetValue("general", "saveaudio", NULL))) {
		switch(value[0]) {
		case 'y':
		case '1':
		case 'w':
			opt_saveWAV = 1;
			opt_audio_format = FORMAT_WAV;
			break;
		case 'o':
			opt_saveWAV = 1;
			opt_audio_format = FORMAT_OGG;
			break;
		}
	}
	if((value = ini.GetValue("general", "savegraph", NULL))) {
		switch(value[0]) {
		case 'y':
		case '1':
		case 'p':
			opt_saveGRAPH = 1;
			break;
		case 'g':
			opt_saveGRAPH = 1;
			opt_gzipGRAPH = 1;
			break;
		}
	}
	if((value = ini.GetValue("general", "filter", NULL))) {
		strncpy(user_filter, value, sizeof(user_filter));
	}
	if((value = ini.GetValue("general", "cachedir", NULL))) {
		strncpy(opt_cachedir, value, sizeof(opt_cachedir));
		mkdir_r(opt_cachedir, 0777);
	}
	if((value = ini.GetValue("general", "spooldir", NULL))) {
		strncpy(opt_chdir, value, sizeof(opt_chdir));
		mkdir_r(opt_chdir, 0777);
	}
	if((value = ini.GetValue("general", "spooldiroldschema", NULL))) {
		opt_newdir = !yesno(value);
	}
	if((value = ini.GetValue("general", "pcapsplit", NULL))) {
		opt_pcap_split = yesno(value);
	}
	if((value = ini.GetValue("general", "scanpcapdir", NULL))) {
		strncpy(opt_scanpcapdir, value, sizeof(opt_scanpcapdir));
	}
#ifndef FREEBSD
	if((value = ini.GetValue("general", "scanpcapmethod", NULL))) {
		opt_scanpcapmethod = (value[0] == 'r') ? IN_MOVED_TO : IN_CLOSE_WRITE;
	}
#endif
	if((value = ini.GetValue("general", "promisc", NULL))) {
		opt_promisc = yesno(value);
	}
	if((value = ini.GetValue("general", "sqldriver", NULL))) {
		strncpy(sql_driver, value, sizeof(sql_driver));
	}
	if((value = ini.GetValue("general", "sqlcdrtable", NULL))) {
		strncpy(sql_cdr_table, value, sizeof(sql_cdr_table));
	}
	if((value = ini.GetValue("general", "sqlcdrtable_last30d", NULL))) {
		strncpy(sql_cdr_table_last30d, value, sizeof(sql_cdr_table_last30d));
	}
	if((value = ini.GetValue("general", "sqlcdrtable_last7d", NULL))) {
		strncpy(sql_cdr_table_last7d, value, sizeof(sql_cdr_table_last1d));
	}
	if((value = ini.GetValue("general", "sqlcdrtable_last1d", NULL))) {
		strncpy(sql_cdr_table_last7d, value, sizeof(sql_cdr_table_last1d));
	}
	if((value = ini.GetValue("general", "sqlcdrnexttable", NULL)) ||
	   (value = ini.GetValue("general", "sqlcdr_next_table", NULL))) {
		strncpy(sql_cdr_next_table, value, sizeof(sql_cdr_next_table));
	}
	if((value = ini.GetValue("general", "sqlcdruatable", NULL)) ||
	   (value = ini.GetValue("general", "sqlcdr_ua_table", NULL))) {
		strncpy(sql_cdr_ua_table, value, sizeof(sql_cdr_ua_table));
	}
	if((value = ini.GetValue("general", "sqlcdrsipresptable", NULL)) ||
	   (value = ini.GetValue("general", "sqlcdr_sipresp_table", NULL))) {
		strncpy(sql_cdr_sip_response_table, value, sizeof(sql_cdr_sip_response_table));
	}
	if((value = ini.GetValue("general", "mysqlcompress", NULL))) {
		opt_mysqlcompress = yesno(value);
	}
	if((value = ini.GetValue("general", "mysqlhost", NULL))) {
		strncpy(mysql_host, value, sizeof(mysql_host));
	}
	if((value = ini.GetValue("general", "mysqlport", NULL))) {
		opt_mysql_port = atoi(value);
	}
	if((value = ini.GetValue("general", "myqslhost", NULL))) {
		printf("You have old version of config file! there were typo in myqslhost instead of mysqlhost! Fix your config! exiting...\n");
		syslog(LOG_ERR, "You have old version of config file! there were typo in myqslhost instead of mysqlhost! Fix your config! exiting...\n");
		exit(1);
	}
	if((value = ini.GetValue("general", "mysqldb", NULL))) {
		strncpy(mysql_database, value, sizeof(mysql_database));
	}
	if((value = ini.GetValue("general", "mysqltable", NULL))) {
		strncpy(mysql_table, value, sizeof(mysql_table));
	}
	if((value = ini.GetValue("general", "mysqlusername", NULL))) {
		strncpy(mysql_user, value, sizeof(mysql_user));
	}
	if((value = ini.GetValue("general", "mysqlpassword", NULL))) {
		strncpy(mysql_password, value, sizeof(mysql_password));
	}
	if((value = ini.GetValue("general", "odbcdsn", NULL))) {
		strncpy(odbc_dsn, value, sizeof(odbc_dsn));
	}
	if((value = ini.GetValue("general", "odbcuser", NULL))) {
		strncpy(odbc_user, value, sizeof(odbc_user));
	}
	if((value = ini.GetValue("general", "odbcpass", NULL))) {
		strncpy(odbc_password, value, sizeof(odbc_password));
	}
	if((value = ini.GetValue("general", "odbcdriver", NULL))) {
		strncpy(odbc_driver, value, sizeof(odbc_driver));
	}
	if((value = ini.GetValue("general", "cloud_host", NULL))) {
		strncpy(cloud_host, value, sizeof(cloud_host));
	}
	if((value = ini.GetValue("general", "cloud_url", NULL))) {
		strncpy(cloud_url, value, sizeof(cloud_url));
	}
	if((value = ini.GetValue("general", "cloud_token", NULL))) {
		strncpy(cloud_token, value, sizeof(cloud_token));
	}
	if((value = ini.GetValue("general", "database_backup_from_mysqlhost", NULL))) {
		strncpy(opt_database_backup_from_mysql_host, value, sizeof(opt_database_backup_from_mysql_host));
	}
	if((value = ini.GetValue("general", "database_backup_from_mysqldb", NULL))) {
		strncpy(opt_database_backup_from_mysql_database, value, sizeof(opt_database_backup_from_mysql_database));
	}
	if((value = ini.GetValue("general", "database_backup_from_mysqlusername", NULL))) {
		strncpy(opt_database_backup_from_mysql_user, value, sizeof(opt_database_backup_from_mysql_user));
	}
	if((value = ini.GetValue("general", "database_backup_from_mysqlpassword", NULL))) {
		strncpy(opt_database_backup_from_mysql_password, value, sizeof(opt_database_backup_from_mysql_password));
	}
	if((value = ini.GetValue("general", "database_backup_pause", NULL))) {
		opt_database_backup_pause = atoi(value);
	}
	if((value = ini.GetValue("general", "database_backup_insert_threads", NULL))) {
		opt_database_backup_insert_threads = atoi(value);
	}
	if((value = ini.GetValue("general", "get_customer_by_ip_sql_driver", NULL))) {
		strncpy(get_customer_by_ip_sql_driver, value, sizeof(get_customer_by_ip_sql_driver));
	}
	if((value = ini.GetValue("general", "get_customer_by_ip_odbc_dsn", NULL))) {
		strncpy(get_customer_by_ip_odbc_dsn, value, sizeof(get_customer_by_ip_odbc_dsn));
	}
	if((value = ini.GetValue("general", "get_customer_by_ip_odbc_user", NULL))) {
		strncpy(get_customer_by_ip_odbc_user, value, sizeof(get_customer_by_ip_odbc_user));
	}
	if((value = ini.GetValue("general", "get_customer_by_ip_odbc_password", NULL))) {
		strncpy(get_customer_by_ip_odbc_password, value, sizeof(get_customer_by_ip_odbc_password));
	}
	if((value = ini.GetValue("general", "get_customer_by_ip_odbc_driver", NULL))) {
		strncpy(get_customer_by_ip_odbc_driver, value, sizeof(get_customer_by_ip_odbc_driver));
	}
	if((value = ini.GetValue("general", "get_customer_by_ip_query", NULL))) {
		strncpy(get_customer_by_ip_query, value, sizeof(get_customer_by_ip_query));
	}
	if((value = ini.GetValue("general", "get_customers_ip_query", NULL))) {
		strncpy(get_customers_ip_query, value, sizeof(get_customers_ip_query));
	}
	if((value = ini.GetValue("general", "get_customers_radius_name_query", NULL))) {
		strncpy(get_customers_radius_name_query, value, sizeof(get_customers_radius_name_query));
	}
	if((value = ini.GetValue("general", "get_customer_by_pn_sql_driver", NULL))) {
		strncpy(get_customer_by_pn_sql_driver, value, sizeof(get_customer_by_pn_sql_driver));
	}
	if((value = ini.GetValue("general", "get_customer_by_pn_odbc_dsn", NULL))) {
		strncpy(get_customer_by_pn_odbc_dsn, value, sizeof(get_customer_by_pn_odbc_dsn));
	}
	if((value = ini.GetValue("general", "get_customer_by_pn_odbc_user", NULL))) {
		strncpy(get_customer_by_pn_odbc_user, value, sizeof(get_customer_by_pn_odbc_user));
	}
	if((value = ini.GetValue("general", "get_customer_by_pn_odbc_password", NULL))) {
		strncpy(get_customer_by_pn_odbc_password, value, sizeof(get_customer_by_pn_odbc_password));
	}
	if((value = ini.GetValue("general", "get_customer_by_pn_odbc_driver", NULL))) {
		strncpy(get_customer_by_pn_odbc_driver, value, sizeof(get_customer_by_pn_odbc_driver));
	}
	if((value = ini.GetValue("general", "get_customers_pn_query", NULL))) {
		strncpy(get_customers_pn_query, value, sizeof(get_customers_pn_query));
	}
	if((value = ini.GetValue("general", "national_prefix", NULL))) {
		char *pos = (char*)value;
		while(pos && *pos) {
			char *posSep = strchr(pos, ';');
			if(posSep) {
				*posSep = 0;
			}
			opt_national_prefix.push_back(pos);
			pos = posSep ? posSep + 1 : NULL;
		}
	}
	if((value = ini.GetValue("general", "get_radius_ip_driver", NULL))) {
		strncpy(get_radius_ip_driver, value, sizeof(get_radius_ip_driver));
	}
	if((value = ini.GetValue("general", "get_radius_ip_host", NULL))) {
		strncpy(get_radius_ip_host, value, sizeof(get_radius_ip_host));
	}
	if((value = ini.GetValue("general", "get_radius_ip_db", NULL))) {
		strncpy(get_radius_ip_db, value, sizeof(get_radius_ip_db));
	}
	if((value = ini.GetValue("general", "get_radius_ip_user", NULL))) {
		strncpy(get_radius_ip_user, value, sizeof(get_radius_ip_user));
	}
	if((value = ini.GetValue("general", "get_radius_ip_password", NULL))) {
		strncpy(get_radius_ip_password, value, sizeof(get_radius_ip_password));
	}
	if((value = ini.GetValue("general", "get_radius_ip_query", NULL))) {
		strncpy(get_radius_ip_query, value, sizeof(get_radius_ip_query));
	}
	if((value = ini.GetValue("general", "get_radius_ip_query_where", NULL))) {
		strncpy(get_radius_ip_query_where, value, sizeof(get_radius_ip_query_where));
	}
	if((value = ini.GetValue("general", "get_customer_by_ip_flush_period", NULL))) {
		get_customer_by_ip_flush_period = atoi(value);
	}
	if((value = ini.GetValue("general", "sipoverlap", NULL))) {
		opt_sipoverlap = yesno(value);
	}
	if((value = ini.GetValue("general", "dumpallpackets", NULL))) {
		opt_pcapdump = yesno(value);
	}
	if((value = ini.GetValue("general", "jitterbuffer_f1", NULL))) {
		switch(value[0]) {
		case 'Y':
		case 'y':
		case '1':
			opt_jitterbuffer_f1 = 1;
			break;
		default: 
			opt_jitterbuffer_f1 = 0;
			break;
		}
	}
	if((value = ini.GetValue("general", "jitterbuffer_f2", NULL))) {
		switch(value[0]) {
		case 'Y':
		case 'y':
		case '1':
			opt_jitterbuffer_f2 = 1;
			break;
		default: 
			opt_jitterbuffer_f2 = 0;
			break;
		}
	}
	if((value = ini.GetValue("general", "jitterbuffer_adapt", NULL))) {
		switch(value[0]) {
		case 'Y':
		case 'y':
		case '1':
			opt_jitterbuffer_adapt = 1;
			break;
		default: 
			opt_jitterbuffer_adapt = 0;
			break;
		}
	}
	if((value = ini.GetValue("general", "sqlcallend", NULL))) {
		opt_callend = yesno(value);
	}
	if((value = ini.GetValue("general", "destination_number_mode", NULL))) {
		opt_destination_number_mode = atoi(value);
	}
	if((value = ini.GetValue("general", "update_dstnum_onanswer", NULL))) {
		opt_update_dstnum_onanswer = yesno(value);
	}
	if((value = ini.GetValue("general", "mirrorip", NULL))) {
		opt_mirrorip = yesno(value);
	}
	if((value = ini.GetValue("general", "mirrorall", NULL))) {
		opt_mirrorall = yesno(value);
	}
	if((value = ini.GetValue("general", "mirroronly", NULL))) {
		opt_mirroronly = yesno(value);
	}
	if((value = ini.GetValue("general", "mirroripsrc", NULL))) {
		strncpy(opt_mirrorip_src, value, sizeof(opt_mirrorip_src));
	}
	if((value = ini.GetValue("general", "mirroripdst", NULL))) {
		strncpy(opt_mirrorip_dst, value, sizeof(opt_mirrorip_dst));
	}
	if((value = ini.GetValue("general", "printinsertid", NULL))) {
		opt_printinsertid = yesno(value);
	}
	if((value = ini.GetValue("general", "ipaccount", NULL))) {
		opt_ipaccount = yesno(value);
	}
	if((value = ini.GetValue("general", "ipaccount_interval", NULL))) {
		opt_ipacc_interval = atoi(value);
	}
	if((value = ini.GetValue("general", "ipaccount_sniffer_agregate", NULL))) {
		opt_ipacc_sniffer_agregate = yesno(value);
	}
	if((value = ini.GetValue("general", "ipaccount_agregate_only_customers_on_main_side", NULL))) {
		opt_ipacc_agregate_only_customers_on_main_side = yesno(value);
	}
	if((value = ini.GetValue("general", "ipaccount_agregate_only_customers_on_any_side", NULL))) {
		opt_ipacc_agregate_only_customers_on_any_side = yesno(value);
	}
	if((value = ini.GetValue("general", "cdronlyanswered", NULL))) {
		opt_cdronlyanswered = yesno(value);
	}
	if((value = ini.GetValue("general", "cdronlyrtp", NULL))) {
		opt_cdronlyrtp = yesno(value);
	}
	if((value = ini.GetValue("general", "callslimit", NULL))) {
		opt_callslimit = atoi(value);
	}
	if((value = ini.GetValue("general", "pauserecordingdtmf", NULL))) {
		strncpy(opt_silencedmtfseq, value, 15);
	}
	if((value = ini.GetValue("general", "keycheck", NULL))) {
		strncpy(opt_keycheck, value, 1024);
	}
	if((value = ini.GetValue("general", "convertchar", NULL))) {
		strncpy(opt_convert_char, value, sizeof(opt_convert_char));
	}
	if((value = ini.GetValue("general", "openfile_max", NULL))) {
                opt_openfile_max = atoi(value);
        }
	if((value = ini.GetValue("general", "enable_lua_tables", NULL)) ||
	   (value = ini.GetValue("general", "enable_http_enum_tables", NULL))
	) {
		opt_enable_http_enum_tables = yesno(value);
	}

	if((value = ini.GetValue("general", "packetbuffer_enable", NULL))) {
		opt_pcap_queue = yesno(value);
	}
	//EXPERT VALUES
	if((value = ini.GetValue("general", "packetbuffer_block_maxsize", NULL))) {
		opt_pcap_queue_block_max_size = atol(value) * 1024;
	}
	if((value = ini.GetValue("general", "packetbuffer_block_maxtime", NULL))) {
		opt_pcap_queue_block_max_time_ms = atoi(value);
	}
	//
	if((value = ini.GetValue("general", "packetbuffer_total_maxheap", NULL))) {
		opt_pcap_queue_store_queue_max_memory_size = atol(value) * 1024 *1024;
	}
	/*
	INDIRECT VALUE
	if((value = ini.GetValue("general", "packetbuffer_thread_maxheap", NULL))) {
		opt_pcap_queue_bypass_max_size = atol(value) * 1024 *1024;
	}
	*/
	if((value = ini.GetValue("general", "packetbuffer_file_totalmaxsize", NULL))) {
		opt_pcap_queue_store_queue_max_disk_size = atol(value) * 1024 *1024;
	}
	if((value = ini.GetValue("general", "packetbuffer_file_path", NULL))) {
		opt_pcap_queue_disk_folder = value;
	}
	/*
	DEFAULT VALUES
	if((value = ini.GetValue("general", "packetbuffer_file_maxfilesize", NULL))) {
		opt_pcap_queue_file_store_max_size = atol(value) * 1024 *1024;
	}
	if((value = ini.GetValue("general", "packetbuffer_file_maxtime", NULL))) {
		opt_pcap_queue_file_store_max_time_ms = atoi(value);
	}
	*/
	if((value = ini.GetValue("general", "packetbuffer_compress", NULL))) {
		opt_pcap_queue_compress = yesno(value);
	}
	if((value = ini.GetValue("general", "mirror_destination_ip", NULL)) &&
	   (value2 = ini.GetValue("general", "mirror_destination_port", NULL))) {
		opt_pcap_queue_send_to_ip_port.set_ip(value);
		opt_pcap_queue_send_to_ip_port.set_port(atoi(value2));
		opt_nocdr = 1;
	}
	if((value = ini.GetValue("general", "mirror_destination", NULL))) {
		char *pointToPortSeparator = (char*)strchr(value, ':');
		if(pointToPortSeparator) {
			opt_nocdr = 1;
			*pointToPortSeparator = 0;
			int port = atoi(pointToPortSeparator + 1);
			if(*value && port) {
				opt_pcap_queue_send_to_ip_port.set_ip(value);
				opt_pcap_queue_send_to_ip_port.set_port(port);
			}
		}
	}
	if((value = ini.GetValue("general", "mirror_bind_ip", NULL)) &&
	   (value2 = ini.GetValue("general", "mirror_bind_port", NULL))) {
		opt_pcap_queue_receive_from_ip_port.set_ip(value);
		opt_pcap_queue_receive_from_ip_port.set_port(atoi(value2));
	}
	if((value = ini.GetValue("general", "mirror_bind", NULL))) {
		char *pointToPortSeparator = (char*)strchr(value, ':');
		if(pointToPortSeparator) {
			*pointToPortSeparator = 0;
			int port = atoi(pointToPortSeparator + 1);
			if(*value && port) {
				opt_pcap_queue_receive_from_ip_port.set_ip(value);
				opt_pcap_queue_receive_from_ip_port.set_port(port);
			}
		}
	}
	if((value = ini.GetValue("general", "mirror_bind_dlt", NULL))) {
		opt_pcap_queue_receive_dlt = atoi(value);
	}
	
	if((value = ini.GetValue("general", "tcpreassembly", NULL))) {
		opt_enable_tcpreassembly = strcmp(value, "only") ? yesno(value) : 2;
	}
	if((value = ini.GetValue("general", "tcpreassembly_log", NULL))) {
		strncpy(opt_tcpreassembly_log, value, sizeof(opt_tcpreassembly_log));
	}
	
	if((value = ini.GetValue("general", "convert_dlt_sll2en10", NULL))) {
		opt_convert_dlt_sll_to_en10 = yesno(value);
	}
	if((value = ini.GetValue("general", "threading_mod", NULL))) {
		switch(atoi(value)) {
		case 2:
			opt_pcap_queue_iface_separate_threads = 1;
			break;
		case 3:
			opt_pcap_queue_iface_separate_threads = 1;
			opt_pcap_queue_iface_dedup_separate_threads = 1;
			break;
		case 4:
			opt_pcap_queue_iface_separate_threads = 1;
			opt_pcap_queue_iface_dedup_separate_threads = 1;
			opt_pcap_queue_iface_dedup_separate_threads_extend = 1;
			break;
		}
	}
	if((value = ini.GetValue("general", "pcap_queue_dequeu_window_length", NULL))) {
		opt_pcap_queue_dequeu_window_length = atoi(value);
	}
	if((value = ini.GetValue("general", "pcap_queue_dequeu_method", NULL))) {
		opt_pcap_queue_dequeu_method = atoi(value);
	}
	if((value = ini.GetValue("general", "maxpcapsize", NULL))) {
		opt_maxpcapsize_mb = atoi(value);
	}
	if((value = ini.GetValue("general", "upgrade_try_http_if_https_fail", NULL))) {
		opt_upgrade_try_http_if_https_fail = yesno(value);
	}
	if((value = ini.GetValue("general", "sdp_reverse_ipport", NULL))) {
		opt_sdp_reverse_ipport = yesno(value);
	}
	if((value = ini.GetValue("general", "mos_lqo", NULL))) {
		opt_mos_lqo = yesno(value);
	}
	if((value = ini.GetValue("general", "mos_lqo_bin", NULL))) {
		opt_mos_lqo_bin = value;
	}
	if((value = ini.GetValue("general", "mos_lqo_ref", NULL))) {
		opt_mos_lqo_ref = value;
	}
	if((value = ini.GetValue("general", "mos_lqo_ref16", NULL))) {
		opt_mos_lqo_ref16 = value;
	}
	if((value = ini.GetValue("general", "php_path", NULL))) {
		strncpy(opt_php_path, value, sizeof(opt_php_path));
	}
	if((value = ini.GetValue("general", "onewaytimeout", NULL))) {
		opt_onewaytimeout = atoi(value);
	}
	if((value = ini.GetValue("general", "saveaudio_stereo", NULL))) {
		opt_saveaudio_stereo = yesno(value);
	}
	if((value = ini.GetValue("general", "saveaudio_reversestereo", NULL))) {
		opt_saveaudio_reversestereo = yesno(value);
	}
	if((value = ini.GetValue("general", "ogg_quality", NULL))) {
		opt_saveaudio_oggquality = atof(value);
	}
	if((value = ini.GetValue("general", "mysqlloadconfig", NULL))) {
		opt_mysqlloadconfig = yesno(value);
	}
	
	if((value = ini.GetValue("general", "mysqlstore_concat_limit", NULL))) {
		opt_mysqlstore_concat_limit = atoi(value);
	}
	if((value = ini.GetValue("general", "mysqlstore_concat_limit_cdr", NULL))) {
		opt_mysqlstore_concat_limit_cdr = atoi(value);
	}
	if((value = ini.GetValue("general", "mysqlstore_concat_limit_message", NULL))) {
		opt_mysqlstore_concat_limit_message = atoi(value);
	}
	if((value = ini.GetValue("general", "mysqlstore_concat_limit_register", NULL))) {
		opt_mysqlstore_concat_limit_register = atoi(value);
	}
	if((value = ini.GetValue("general", "mysqlstore_concat_limit_http", NULL))) {
		opt_mysqlstore_concat_limit_http = atoi(value);
	}
	if((value = ini.GetValue("general", "mysqlstore_concat_limit_ipacc", NULL))) {
		opt_mysqlstore_concat_limit_ipacc = atoi(value);
	}
	
	if((value = ini.GetValue("general", "mysqlstore_max_threads_cdr", NULL))) {
		opt_mysqlstore_max_threads_cdr = max(min(atoi(value), 9), 1);
	}
	if((value = ini.GetValue("general", "mysqlstore_max_threads_message", NULL))) {
		opt_mysqlstore_max_threads_message = max(min(atoi(value), 9), 1);
	}
	if((value = ini.GetValue("general", "mysqlstore_max_threads_register", NULL))) {
		opt_mysqlstore_max_threads_register = max(min(atoi(value), 9), 1);
	}
	if((value = ini.GetValue("general", "mysqlstore_max_threads_http", NULL))) {
		opt_mysqlstore_max_threads_http = max(min(atoi(value), 9), 1);
	}
	if((value = ini.GetValue("general", "mysqlstore_max_threads_ipacc_base", NULL))) {
		opt_mysqlstore_max_threads_ipacc_base = max(min(atoi(value), 9), 1);
	}
	if((value = ini.GetValue("general", "mysqlstore_max_threads_ipacc_agreg2", NULL))) {
		opt_mysqlstore_max_threads_ipacc_agreg2 = max(min(atoi(value), 9), 1);
	}
	
	if((value = ini.GetValue("general", "mysqlstore_limit_queue_register", NULL))) {
		opt_mysqlstore_limit_queue_register = atoi(value);
	}
	
	if((value = ini.GetValue("general", "curlproxy", NULL))) {
		strncpy(opt_curlproxy, value, sizeof(opt_curlproxy));
	}
	
	if((value = ini.GetValue("general", "enable_fraud", NULL))) {
		opt_enable_fraud = yesno(value);
	}
	if((value = ini.GetValue("general", "local_country_code", NULL))) {
		strncpy(opt_local_country_code, value, sizeof(opt_local_country_code));
	}
	if((value = ini.GetValue("general", "pcap_dump_bufflength", NULL))) {
		opt_pcap_dump_bufflength = atoi(value);
	}
	if((value = ini.GetValue("general", "pcap_dump_asyncwrite", NULL))) {
		opt_pcap_dump_asyncwrite = yesno(value);
	}
	if((value = ini.GetValue("general", "pcap_dump_zip", NULL))) {
		opt_pcap_dump_zip = yesno(value);
	}
	if((value = ini.GetValue("general", "pcap_dump_ziplevel", NULL))) {
		opt_pcap_dump_ziplevel = atoi(value);
	}
	if((value = ini.GetValue("general", "pcap_dump_writethreads", NULL))) {
		opt_pcap_dump_writethreads = atoi(value);
	}
	if((value = ini.GetValue("general", "pcap_dump_writethreads_max", NULL))) {
		opt_pcap_dump_writethreads_max = atoi(value);
	}
	if((value = ini.GetValue("general", "pcap_dump_asyncwrite_maxsize", NULL)) ||
	   (value = ini.GetValue("general", "pcap_dump_asyncbuffer", NULL))) {
		opt_pcap_dump_asyncwrite_maxsize = atoi(value);
	}
	if((value = ini.GetValue("general", "defer_create_spooldir", NULL))) {
		opt_defer_create_spooldir = yesno(value);
	}
	if((value = ini.GetValue("general", "sip_send_ip", NULL)) &&
	   (value2 = ini.GetValue("general", "sip_send_port", NULL))) {
		sipSendSocket_ip_port.set_ip(value);
		sipSendSocket_ip_port.set_port(atoi(value2));
	}
	if((value = ini.GetValue("general", "sip_send", NULL))) {
		char *pointToPortSeparator = (char*)strchr(value, ':');
		if(pointToPortSeparator) {
			opt_nocdr = 1;
			*pointToPortSeparator = 0;
			int port = atoi(pointToPortSeparator + 1);
			if(*value && port) {
				sipSendSocket_ip_port.set_ip(value);
				sipSendSocket_ip_port.set_port(port);
			}
		}
	}
	if((value = ini.GetValue("general", "sip_send_before_packetbuffer", NULL))) {
		opt_sip_send_before_packetbuffer = yesno(value);
	}
	if((value = ini.GetValue("general", "manager_sshhost", NULL))) {
		strncpy(ssh_host, value, sizeof(ssh_host));
	}
	if((value = ini.GetValue("general", "manager_sshport", NULL))) {
		ssh_port = atoi(value);
	}
	if((value = ini.GetValue("general", "manager_sshusername", NULL))) {
		strncpy(ssh_username, value, sizeof(ssh_username));
	}
	if((value = ini.GetValue("general", "manager_sshpassword", NULL))) {
		strncpy(ssh_password, value, sizeof(ssh_password));
	}
	if((value = ini.GetValue("general", "manager_sshremoteip", NULL))) {
		strncpy(ssh_remote_listenhost, value, sizeof(ssh_remote_listenhost));
	}
	if((value = ini.GetValue("general", "manager_sshremoteport", NULL))) {
		ssh_remote_listenport = atoi(value);
	}
	if((value = ini.GetValue("general", "sdp_multiplication", NULL))) {
		opt_sdp_multiplication = atoi(value);
	}
	
	if((value = ini.GetValue("general", "enable_jitterbuffer_asserts", NULL))) {
		opt_enable_jitterbuffer_asserts = yesno(value);
	}
	
	if((value = ini.GetValue("general", "hide_message_content", NULL))) {
		opt_hide_message_content = yesno(value);
	}
	if((value = ini.GetValue("general", "hide_message_content_secret", NULL))) {
		strncpy(opt_hide_message_content_secret, value, sizeof(opt_hide_message_content_secret));
	}

	if((value = ini.GetValue("general", "bogus_dumper_path", NULL))) {
		strncpy(opt_bogus_dumper_path, value, sizeof(opt_bogus_dumper_path));
	}

	/*
	
	packetbuffer default configuration
	
	packetbuffer_enable		= no
	packetbuffer_block_maxsize	= 500	#kB
	packetbuffer_block_maxtime	= 500	#ms
	packetbuffer_total_maxheap	= 500	#MB
	packetbuffer_thread_maxheap	= 500	#MB
	packetbuffer_file_totalmaxsize	= 20000	#MB
	packetbuffer_file_path		= /var/spool/voipmonitor/packetbuffer
	packetbuffer_file_maxfilesize	= 1000	#MB
	packetbuffer_file_maxtime	= 5000	#ms
	packetbuffer_compress		= yes
	#mirror_destination_ip		=
	#mirror_destination_port	=
	#mirror_source_ip		=
	#mirror_source_port		=
	*/

	#ifdef QUEUE_NONBLOCK2
		if(opt_scanpcapdir[0] != '\0') {
			opt_pcap_queue = 0;
		}
	#else
		opt_pcap_queue = 0;
	#endif

	if(opt_pcap_queue) {
		if(!opt_pcap_queue_disk_folder.length() || !opt_pcap_queue_store_queue_max_disk_size) {
			// disable disc save
			if(opt_pcap_queue_compress) {
				// enable compress - maximum thread0 buffer = 100MB, minimum = 50MB
				opt_pcap_queue_bypass_max_size = opt_pcap_queue_store_queue_max_memory_size / 8;
				if(opt_pcap_queue_bypass_max_size > 100 * 1024 * 1024) {
					opt_pcap_queue_bypass_max_size = 100 * 1024 * 1024;
				} else if(opt_pcap_queue_bypass_max_size < 50 * 1024 * 1024) {
					opt_pcap_queue_bypass_max_size = 50 * 1024 * 1024;
				}
			} else {
				// disable compress - thread0 buffer = 50MB
				opt_pcap_queue_bypass_max_size = 50 * 1024 * 1024;
			}
		} else {
			// disable disc save - maximum thread0 buffer = 500MB
			opt_pcap_queue_bypass_max_size = opt_pcap_queue_store_queue_max_memory_size / 4;
			if(opt_pcap_queue_bypass_max_size > 500 * 1024 * 1024) {
				opt_pcap_queue_bypass_max_size = 500 * 1024 * 1024;
			}
		}
		if(opt_pcap_queue_store_queue_max_memory_size < opt_pcap_queue_bypass_max_size * 2) {
			opt_pcap_queue_store_queue_max_memory_size = opt_pcap_queue_bypass_max_size * 2;
		} else {
			opt_pcap_queue_store_queue_max_memory_size -= opt_pcap_queue_bypass_max_size;
		}
		
		if(opt_pcap_queue_receive_from_ip_port) {
			opt_id_sensor_cleanspool = -1;
		}
	}
	
	if(!opt_pcap_split || opt_scanpcapdir[0] != '\0') {
		opt_rtpsave_threaded = 0;
	}
	
	if(opt_enable_tcpreassembly) {
		opt_enable_http_enum_tables = true;
	}
	return 0;
}

int load_config(char *fname) {
	int res = 0;

	if(!FileExists(fname)) {
		return 1;
	}

	CSimpleIniA ini;
	int rc = 0;
	string inistr;

	//Is it really file or directory?
	if(!DirExists(fname)) {
		printf("Loading configuration from file %s ", fname);
		ini.SetUnicode();
		ini.SetMultiKey(true);
		rc = ini.LoadFile(fname);
		if (rc != 0) {
			printf("ERROR\n");
			syslog(LOG_ERR, "Loading config from file %s FAILED!", fname );
			return 1;
		}
		rc = ini.Save(inistr);
		if (rc != 0) {
			printf("ERROR\n");
			syslog(LOG_ERR, "Preparing config from file %s FAILED!", fname );
			return 1;
		}
		rc = eval_config(inistr);
		if (rc != 0) {
			printf("ERROR\n");
			syslog(LOG_ERR, "Evaluating config from file %s FAILED!", fname );
			return 1;
		}
		printf("OK\n");

	} else {
		DIR *dir;
		ini.SetUnicode();
		ini.SetMultiKey(true);
		if ((dir = opendir (fname)) != NULL) {
			struct dirent *ent;
			FILE * fp = NULL;
			unsigned char isFile =0x8;

			while ((ent = readdir (dir)) != NULL) {
									//each directory inside conf.d directory is omitted
				if ( ent->d_type != isFile) {
					continue;
				}
									//its a file lets load it
				char fullname[500];
				fullname[0] = 0;    //reset string data
				strcat (fullname, "/etc/voipmonitor/conf.d/");
				strcat (fullname, ent->d_name);
				if (verbosity>1) syslog(LOG_NOTICE, "Loading configuration from file %s", fullname );
				printf("Loading configuration from file %s ", fullname);
				fp = fopen(fullname, "rb");
				if (!fp) {
					printf("ERROR\n");
					syslog(LOG_ERR, "Cannot access config file %s!", ent->d_name );
					return 1;
				}
				int retval = fseek(fp, 0, SEEK_END);
				if (retval == -1) {
					printf("ERROR\n");
					fclose(fp);
					syslog(LOG_ERR, "Cannot access config file %s!", ent->d_name );
					return 1;							//Problem accessing file
				}

				long lSize = ftell(fp);
				if (lSize == 0) {
					printf("is empty\n");
					fclose(fp);
					return 0;
				}
				char * pData = new char[lSize + 10];	//adding "[general]\n" on top
				if (!pData) {
					fclose(fp);
					printf("ERROR\n");
					syslog(LOG_ERR, "Cannot alloc memory for config file %s!", ent->d_name );
					return 1;							//nomem for alloc
				}
				pData[0] = 0;							//resetting string
				strcat(pData, "[general]\n");
				fseek(fp, 0, SEEK_SET);
				size_t uRead = fread(&pData[10], sizeof(char), lSize, fp);
				if (uRead != (size_t) lSize) {
					fclose(fp);
					printf("ERROR\n");
					delete[] pData;
					syslog(LOG_ERR, "Cannot read data from config file %s!", ent->d_name );
					return 2;							//problem while reading
				}
				fclose(fp);
				rc = ini.LoadData(pData, uRead + 10);	//with "[general]\n" thats not included in uRead
				if (rc != 0) {
					printf("ERROR\n");
					syslog(LOG_ERR, "Loading config from file %s FAILED!", ent->d_name );
					return 1;
				}
				delete[] pData;
				rc = ini.Save(inistr);
				if (rc != 0) {
					printf("ERROR\n");
					syslog(LOG_ERR, "Preparing config from file %s FAILED!", ent->d_name );
					return 1;
				}
				rc = eval_config(inistr);
				if (rc != 0) {
					printf("ERROR\n");
					syslog(LOG_ERR, "Evaluating config from file %s FAILED!", ent->d_name );
					return 1;
				}
				printf("OK\n");
			}
			closedir (dir);
		} else {
	  /* could not open directory */
			syslog(LOG_ERR, "Cannot access directory file %s!", fname );
			return EXIT_FAILURE;
		}
	}
	return res;
}

void reload_config() {
	load_config(configfile);
	load_config((char*)"/etc/voipmonitor/conf.d/");
	request_iptelnum_reload = 1;
}

void reload_capture_rules() {

	if(ipfilter_reload) {
		delete ipfilter_reload;
	}

	ipfilter_reload = new IPfilter;
	ipfilter_reload->load();
	ipfilter_reload_do = 1;

	if(telnumfilter_reload) {
		delete telnumfilter_reload;
	}

	telnumfilter_reload = new TELNUMfilter;
	telnumfilter_reload->load();
	telnumfilter_reload_do = 1;

	if(domainfilter_reload) {
		delete domainfilter_reload;
	}

	domainfilter_reload = new DOMAINfilter;
	domainfilter_reload->load();
	domainfilter_reload_do = 1;
}

#ifdef BACKTRACE
#ifndef USE_SIGCONTEXT
void bt_sighandler(int sig, siginfo_t *info, void *secret)
#else
void bt_sighandler(int sig, struct sigcontext ctx)
#endif
{

        void *trace[16];
        char **messages = (char **)NULL;
        int i, trace_size = 0;

        signal_def *d = NULL;
        for (i = 0; i < (int)(sizeof(signal_data) / sizeof(signal_def)); i++)
                if (sig == signal_data[i].id)
                        { d = &signal_data[i]; break; }
        if (d) 
                syslog(LOG_ERR, "Got signal 0x%02X (%s): %s\n", sig, signal_data[i].name, signal_data[i].description);
        else   
                syslog(LOG_ERR, "Got signal 0x%02X\n", sig);

        #ifndef USE_SIGCONTEXT

                void *pnt = NULL;
                #if defined(__x86_64__)
                        ucontext_t* uc = (ucontext_t*) secret;
                        pnt = (void*) uc->uc_mcontext.gregs[REG_RIP] ;
                #elif defined(__hppa__)
                        ucontext_t* uc = (ucontext_t*) secret;
                        pnt = (void*) uc->uc_mcontext.sc_iaoq[0] & ~0×3UL ;
                #elif (defined (__ppc__)) || (defined (__powerpc__))
                        ucontext_t* uc = (ucontext_t*) secret;
                        pnt = (void*) uc->uc_mcontext.regs->nip ;
                #elif defined(__sparc__)
                struct sigcontext* sc = (struct sigcontext*) secret;
                        #if __WORDSIZE == 64
                                pnt = (void*) scp->sigc_regs.tpc ;
                        #else  
                                pnt = (void*) scp->si_regs.pc ;
                        #endif
                #elif defined(__i386__)
                        ucontext_t* uc = (ucontext_t*) secret;
                        pnt = (void*) uc->uc_mcontext.gregs[REG_EIP] ;
                #endif
        /* potentially correct for other archs:
         * alpha: ucp->m_context.sc_pc
         * arm: ucp->m_context.ctx.arm_pc
         * ia64: ucp->m_context.sc_ip & ~0×3UL
         * mips: ucp->m_context.sc_pc
         * s390: ucp->m_context.sregs->regs.psw.addr
         */

        if (sig == SIGSEGV)
                syslog(LOG_ERR,"Faulty address is %p, called from %p\n", info->si_addr, pnt);

        /* The first two entries in the stack frame chain when you
         * get into the signal handler contain, respectively, a
         * return address inside your signal handler and one inside
         * sigaction() in libc. The stack frame of the last function
         * called before the signal (which, in case of fault signals,
         * also is the one that supposedly caused the problem) is lost.
         */

        /* the third parameter to the signal handler points to an
         * ucontext_t structure that contains the values of the CPU
         * registers when the signal was raised.
         */
        trace_size = backtrace(trace, 16);
        /* overwrite sigaction with caller's address */
        trace[1] = pnt;

        #else

        if (sig == SIGSEGV)
                syslog(LOG_ERR("Faulty address is %p, called from %p\n",
                        ctx.cr2, ctx.eip);

        /* An undocumented parameter of type sigcontext that is passed
         * to the signal handler (see the UNDOCUMENTED section in man
         * sigaction) and contains, among other things, the value of EIP
         * when the signal was raised. Declared obsolete in adherence
         * with POSIX.1b since kernel version 2.2
         */

        trace_size = backtrace(trace, 16);
        /* overwrite sigaction with caller's address */
        trace[1] = (void *)ctx.eip;
        #endif

        messages = backtrace_symbols(trace, trace_size);
        /* skip first stack frame (points here) */
        syslog(LOG_ERR, "[bt] Execution path:\n");
        for (i=1; i<trace_size; ++i)
                syslog(LOG_ERR, "[bt] %s\n", messages[i]);

	/* those two lines causes core dump generation */
	signal(sig, SIG_DFL);
	kill(getpid(), sig);
}
#endif

int opt_test = 0;
char opt_test_str[1024];
void *readdump_libpcap_thread_fce(void *handle);
void test();

int main(int argc, char *argv[]) {
 
	printf("voipmonitor version %s\n", RTPSENSOR_VERSION);
	syslog(LOG_NOTICE, "start voipmonitor version %s", RTPSENSOR_VERSION);
 
	time(&startTime);

	regfailedcache = new regcache;

	base64_init();

/*
	if(mysql_library_init(0, NULL, NULL)) {
		fprintf(stderr, "could not initialize MySQL library\n");
		exit(1);
	}
*/

#ifdef BACKTRACE

	pcapstat.ps_drop = 0;
	pcapstat.ps_ifdrop = 0;

        /* Install our signal handler */
        struct sigaction sa;

        sa.sa_sigaction = bt_sighandler;
        sigemptyset (&sa.sa_mask);
        sa.sa_flags = SA_RESTART | SA_SIGINFO;

        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);
        sigaction(SIGILL, &sa, NULL);
        sigaction(SIGFPE, &sa, NULL);
//        sigaction(SIGUSR1, &sa, NULL);
//        sigaction(SIGUSR2, &sa, NULL);
	
#endif
	
	signal(SIGPIPE, SIG_IGN);

	/* parse arguments */

	char fname[1024] = "";	// pcap file to read on 
	ifname[0] = '\0';
	opt_mirrorip_src[0] = '\0';
	opt_mirrorip_dst[0] = '\0';
	strcpy(opt_chdir, "/var/spool/voipmonitor");
	strcpy(opt_cachedir, "");
	sipportmatrix = (char*)calloc(1, sizeof(char) * 65537);
	// set default SIP port to 5060
	sipportmatrix[5060] = 1;
	httpportmatrix = (char*)calloc(1, sizeof(char) * 65537);

	pthread_mutex_init(&mysqlconnect_lock, NULL);
	pthread_mutex_init(&rdd_lock, NULL);

	// if the system has more than one CPU enable threading
	opt_pcap_threaded = sysconf( _SC_NPROCESSORS_ONLN ) > 1; 
	opt_pcap_threaded = 1; // TODO: this must be enabled for now. 
	num_threads = sysconf( _SC_NPROCESSORS_ONLN ) - 1;
	set_mac();

	thread_setup();
	int option_index = 0;
	static struct option long_options[] = {
	    {"gzip-graph", 0, 0, '1'},
	    {"gzip-pcap", 0, 0, '2'},
	    {"deduplicate", 0, 0, 'L'},
	    {"dump-allpackets", 0, 0, 'M'},
	    {"save-sip", 0, 0, 'S'},
	    {"save-rtp", 0, 0, 'R'},
	    {"skip-rtppayload", 0, 0, 'o'},
	    {"save-udptl", 0, 0, 'D'},
	    {"save-rtcp", 0, 0, '9'},
	    {"save-raw", 0, 0, 'A'},
	    {"save-audio", 0, 0, 'W'},
	    {"no-cdr", 0, 0, 'c'},
	    {"save-graph", 2, 0, 'G'},
	    {"mysql-server", 1, 0, 'h'},
	    {"mysql-port", 1, 0, 'O'},
	    {"mysql-database", 1, 0, 'b'},
	    {"mysql-username", 1, 0, 'u'},
	    {"mysql-password", 1, 0, 'p'},
	    {"mysql-table", 1, 0, 't'},
	    {"pid-file", 1, 0, 'P'},
	    {"rtp-timeout", 1, 0, 'm'},
	    {"rtp-firstleg", 0, 0, '3'},
	    {"sip-register", 0, 0, '4'},
	    {"audio-format", 1, 0, '5'},
	    {"ring-buffer", 1, 0, '6'},
	    {"vm-buffer", 1, 0, 'T'},
	    {"rtp-threads", 1, 0, 'e'},
	    {"rtpthread-buffer", 1, 0, 'E'},
	    {"config-file", 1, 0, '7'},
	    {"manager-port", 1, 0, '8'},
	    {"pcap-command", 1, 0, 'a'},
	    {"norecord-header", 0, 0, 'N'},
	    {"norecord-dtmf", 0, 0, 'K'},
	    {"rtp-nosig", 0, 0, 'I'},
	    {"cachedir", 1, 0, 'C'},
	    {"id-sensor", 1, 0, 's'},
	    {"ipaccount", 0, 0, 'x'},
	    {"pcapscan-dir", 1, 0, '0'},
	    {"pcapscan-method", 1, 0, 900},
	    {"keycheck", 1, 0, 'Z'},
	    {"pcapfilter", 1, 0, 'f'},
	    {"plc-disable", 0, 0, 'l'},
	    {"interface", 1, 0, 'i'},
	    {"read", 1, 0, 'r'},
	    {"spooldir", 1, 0, 'd'},
	    {"verbose", 1, 0, 'v'},
	    {"nodaemon", 0, 0, 'k'},
	    {"promisc", 0, 0, 'n'},
	    {"pcapbuffered", 0, 0, 'U'},
	    {"test", 0, 0, 'X'},
	    {"allsipports", 0, 0, 'y'},
	    {"sipports", 1, 0, 'Y'},
	    {"skinny", 0, 0, 200},
/*
	    {"maxpoolsize", 1, 0, NULL},
	    {"maxpooldays", 1, 0, NULL},
	    {"maxpoolsipsize", 1, 0, NULL},
	    {"maxpoolsipdays", 1, 0, NULL},
	    {"maxpoolrtpsize", 1, 0, NULL},
	    {"maxpoolrtpdays", 1, 0, NULL},
	    {"maxpoolgraphsize", 1, 0, NULL},
	    {"maxpoolgraphdays", 1, 0, NULL},
*/
	    {0, 0, 0, 0}
	};

	terminating = 0;
	terminating2 = 0;

	umask(0000);

	openlog("voipmonitor", LOG_CONS | LOG_PERROR | LOG_PID, LOG_DAEMON);

	/* command line arguments overrides configuration in voipmonitor.conf file */
	while(1) {
		int c;
		c = getopt_long(argc, argv, "C:f:i:r:d:v:O:h:b:t:u:p:P:s:T:D:e:E:m:X:lLkncUSRoAWGNIKy4Mx", long_options, &option_index);
		//"i:r:d:v:h:b:u:p:fnU", NULL, NULL);
		if (c == -1)
			break;

		switch (c) {
			/*
			case 0:
				printf ("option %s\n", long_options[option_index].name);
				break;
			*/
			case 200:
				opt_skinny = 1;
				break;
			case 'x':
				opt_ipaccount = 1;
				break;
			case 'y':
				for(int i = 5060; i < 5099; i++) {
					sipportmatrix[i] = 1;
				}
				sipportmatrix[443] = 1;
				sipportmatrix[80] = 1;
				break;
			case 'Y':
				{
					vector<string> result = explode(optarg, ',');
					for (size_t tier = 0; tier < result.size(); tier++) {
						sipportmatrix[atoi(result[tier].c_str())] = 1;
					}
				}
				break;
			case 'm':
				rtptimeout = atoi(optarg);
				break;
			case 'M':
				opt_pcapdump = 1;
				break;
			case 'e':
				num_threads = atoi(optarg);
				break;
			case 'E':
				rtpthreadbuffer = atoi(optarg);
				break;
			case 'T':
				qringmax = (unsigned int)((unsigned int)MIN(atoi(optarg), 4000) * 1024 * 1024 / (unsigned int)sizeof(pcap_packet));
				break;
			case 's':
				opt_id_sensor = atoi(optarg);
				insert_funcname = "__insert_";
				insert_funcname.append(optarg);
				break;
			case 'Z':
				strncpy(opt_keycheck, optarg, sizeof(opt_keycheck));
				break;
			case '0':
				strncpy(opt_scanpcapdir, optarg, sizeof(opt_scanpcapdir));
				break;
#ifndef FREEBSD
			case 900: // pcapscan-method
				opt_scanpcapmethod = (optarg[0] == 'r') ? IN_MOVED_TO : IN_CLOSE_WRITE;
				break;
#endif
			case 'a':
				strncpy(pcapcommand, optarg, sizeof(pcapcommand));
				break;
			case 'I':
				opt_rtpnosip = 1;
				break;
			case 'l':
				opt_disableplc = 1;
				break;
			case 'L':
				opt_dup_check = 1;
				break;
			case 'K':
				opt_norecord_dtmf = 1;
				break;
			case 'N':
				opt_norecord_header = 1;
				break;
			case '1':
				opt_gzipGRAPH = 1;
				break;
			case '2':
				opt_gzipPCAP = 1;
				break;
			case '3':
				opt_rtp_firstleg = 1;
				break;
			case '4':
				opt_sip_register = 1;
				break;
			case '5':
				if(optarg[0] == 'o') {
					opt_audio_format = FORMAT_OGG;
				} else {
					opt_audio_format = FORMAT_WAV;
				}
				break;
			case '6':
				opt_ringbuffer = MIN(atoi(optarg), 2000);
				break;
			case '7':
				strncpy(configfile, optarg, sizeof(configfile));
				load_config(configfile);
				load_config((char*)"/etc/voipmonitor/conf.d/");
				break;
			case '8':
				opt_manager_port = atoi(optarg);
				if(char *pointToSeparator = strchr(optarg,'/')) {
					strncpy(opt_manager_ip, pointToSeparator+1, sizeof(opt_manager_ip));
				}
				break;
			case '9':
				opt_saveRTCP = 1;
				break;
			case 'i':
				strncpy(ifname, optarg, sizeof(ifname));
				break;
			case 'v':
				{
				vector<string> verbparams = split(optarg, ',');
				for(size_t i = 0; i < verbparams.size(); i++) {
					if(isdigit(verbparams[i][0])) {
						verbosity = atoi(optarg);
						if(char *pointToSeparator = strchr(optarg, '/')) {
							verbosityE = atoi(pointToSeparator + 1);
						} 
					} else {
						if(verbparams[i] == "process_rtp")			sverb.process_rtp = 1;
						else if(verbparams[i] == "read_rtp")			sverb.read_rtp = 1;
						else if(verbparams[i] == "check_is_caller_called")	sverb.check_is_caller_called = 1;
						else if(verbparams[i] == "disable_threads_rtp")		sverb.disable_threads_rtp = 1;
						else if(verbparams[i] == "packet_lost")			sverb.packet_lost = 1;
					}
				} }
				break;
			case 'r':
				if(!strncmp(optarg, "pb:", 3)) {
					strcpy(opt_pb_read_from_file, optarg + 3);
				} else {
					strcpy(fname, optarg);
					opt_read_from_file = 1;
					opt_scanpcapdir[0] = '\0';
					//opt_cachedir[0] = '\0';
					opt_pcap_queue = 0;
				}
				break;
			case 'c':
				opt_nocdr = 1;
				break;
			case 'C':
				strncpy(opt_cachedir, optarg, sizeof(opt_cachedir));
				break;
			case 'd':
				strncpy(opt_chdir, optarg, sizeof(opt_chdir));
				mkdir_r(opt_chdir, 0777);
				break;
			case 'k':
				opt_fork = 0;
				break;
			case 'n':
				opt_promisc = 0;
				break;
			case 'U':
				opt_packetbuffered=1;
				break;
			case 'h':
				strncpy(mysql_host, optarg, sizeof(mysql_host));
				break;
			case 'O':
				opt_mysql_port = atoi(optarg);
				break;
			case 'b':
				strncpy(mysql_database, optarg, sizeof(mysql_database));
				break;
			case 't':
				strncpy(mysql_table, optarg, sizeof(mysql_table));
				break;
			case 'u':
				strncpy(mysql_user, optarg, sizeof(mysql_user));
				break;
			case 'p':
				strncpy(mysql_password, optarg, sizeof(mysql_password));
				break;
			case 'P':
				strncpy(opt_pidfile, optarg, sizeof(opt_pidfile));
				break;
			case 'f':
				strncpy(user_filter, optarg, sizeof(user_filter));
				break;
			case 'S':
				opt_saveSIP = 1;
				break;
			case 'R':
				opt_saveRTP = 1;
				break;
			case 'D':
				opt_saveudptl = 1;
				break;
			case 'o':
				opt_onlyRTPheader = 1;
				break;
			case 'A':
				opt_saveRAW = 1;
				break;
			case 'W':
				opt_saveWAV = 1;
				opt_savewav_force = 1;
				break;
			case 'G':
				opt_saveGRAPH = 1;
				if(optarg && optarg[0] == 'g') {
					opt_gzipGRAPH = 1;
				}
				break;
			case 'X':
				strcpy(opt_test_str, optarg);
				opt_test = atoi(optarg);
				if(!opt_test) {
					opt_test = 1;
				}
				break;
		}
	}
	if(opt_ipaccount) {
		initIpacc();
	}
	if ((fname[0] == '\0') && (ifname[0] == '\0') && opt_scanpcapdir[0] == '\0'){
                        /* Ruler to assist with keeping help description to max. 80 chars wide:
                                  1         2         3         4         5         6         7         8
                         12345678901234567890123456789012345678901234567890123456789012345678901234567890
                        */
                printf("\nvoipmonitor version %s\n"
                        "\nUsage: voipmonitor [OPTIONS]\n"
                        "\n"
                        " -A, --save-raw\n"
                        "      Save RTP payload to RAW format. Default is disabled.\n"
                        "\n"
                        " -b <database>, --mysql-database=<database>\n"
                        "      mysql database, default voipmonitor\n"
                        "\n"
                        " -C <dir>, --cachedir=<dir>\n"
                        "      Store pcap file to <dir> and move it after call ends to spool directory.\n"
                        "      Moving all files are guaranteed to be serialized which solves slow\n"
                        "      random write I/O on magnetic or other media.  Typical cache directory\n"
                        "      is /dev/shm/voipmonitor which is in RAM and grows automatically or\n"
                        "      /mnt/ssd/voipmonitor which is mounted to SSD disk or some very fast\n"
                        "      SAS/SATA disk where spool can be network storage or raid5 etc.\n"
                        "      Wav files are not implemented yet\n"
                        "\n"
                        " -c, --no-cdr\n"
                        "      Do no save CDR to MySQL database.\n"
                        "\n"
                        " -D, --save-udptl\n"
                        "      Save UDPTL packets (T.38).  If savertp = yes the UDPTL packets are saved\n"
                        "      automatically.  If savertp = no and you want to save only udptl packets\n"
                        "      enable saveudptl = yes and savertp = no\n"
                        "\n"
                        " -d <dir>\n"
                        "      Where to store pcap files.  Default is /var/spool/voipmonitor\n"
                        "\n"
                        " -E <n>, --rtpthread-buffer=<n>\n"
                        "      Size of rtp thread ring buffer in MB. Default is 20MB per thread.\n"
                        "\n"
                        " -e <n>, --rtp-threads=<n>\n"
                        "      Number of threads to process RTP packets. If not specified it will be\n"
                        "      number of available CPUs.  If equel to zero RTP threading will be turned\n"
                        "      off.  Each thread allocates default 20MB for buffers.  This buffer can be\n"
                        "      controlled with --rtpthread-buffer.  For < 150 concurrent calls you can\n"
                        "      turn it off.\n"
                        "\n"
                        " -f <filter>\n"
                        "      Pcap filter.  If you will use only UDP, set to udp.  WARNING: If you set\n"
                        "      protocol to 'udp' pcap discards VLAN packets.  Maximum size is 2040\n"
                        "      characters.\n"
                        "\n"
                        " -G [plain|gzip], --save-graph=[plain|gzip]\n"
                        "      Save GRAPH data to graph file.  Default is disabled.  If enabled without\n"
                        "      a value, 'plain' is used.\n"
                        "\n"
                        " -h <hostname>, --mysql-server=<hostname>\n"
                        "      mysql server - default localhost\n"
                        "\n"
                        " -i <interface>\n"
                        "      Interface on which to listen.  Example: eth0\n"
                        "\n"
                        " -k   Do not fork or detach from controlling terminal.\n"
                        "\n"
                        " -L, --deduplicate\n"
                        "      Duplicate check do md5 sum for each packet and if md5 is same as previous\n"
                        "      packet it will discard it.  WARNING: md5 is expensive function (slows\n"
                        "      voipmonitor 3 times) so use it only if you have enough CPU or for pcap\n"
                        "      conversion only.\n"
                        "\n"
                        " -M, --dump-allpackets\n"
                        "      Dump all packets to /tmp/voipmonitor-[UNIX_TIMESTAMP].pcap\n"
                        "\n"
                        " -m <n>, --rtp-timeout=<n>\n"
                        "      rtptimeout is important value which specifies how much seconds from the\n"
                        "      last SIP packet or RTP packet is call closed and writen to database. It\n"
                        "      means that if you need to monitor ONLY SIP you have to set this to at\n"
                        "      least 2 hours = 7200 assuming your calls is not longer than 2 hours. Take\n"
                        "      in mind that seting this to very large value will cause to keep call in\n"
                        "      memory in case the call lost BYE and can consume all memory and slows\n"
                        "      down the sniffer - so do not set it to very high numbers.\n"
                        "      Default is 300 seconds. \n"
                        "\n"
                        " -n   Do not put the interface into promiscuous mode.\n"
                        "\n"
                        " -O <port>, --mysql-port=<port>\n"
                        "      mysql server - default localhost\n"
                        "\n"
                        " -o, --skip-rtppayload\n"
                        "      Skip RTP payload and save only RTP headers.\n"
                        "\n"
                        " -P <pid-file>, --pid-file=<pid-file>\n"
                        "      pid file, default /var/run/voipmonitor.pid\n"
                        "\n"
                        " -p <password>, --mysql-password=<password>\n"
                        "      mysql password, default is empty\n"
                        "\n"
                        " -R, --save-rtp\n"
                        "      Save RTP packets to pcap file. Default is disabled. Whan enabled RTCP\n"
                        "      packets will be saved too.\n"
                        "\n"
                        " -r <pcap-file>\n"
                        "      Read packets from <pcap-file>.\n"
                        "\n"
                        " -S, --save-sip\n"
                        "      Save SIP packets to pcap file.  Default is disabled.\n"
                        "\n"
                        " -s <num>, --id-sensor=<num>\n"
                        "      If set the number is saved to sql cdr.id_sensor.  Used to uniquely\n"
                        "      identify a copy of voipmonitor where many servers with voipmonitor are\n"
                        "      writing to a common database.\n"
                        "\n"
                        " -t <table>, --mysql-table=<table>\n"
                        "      mysql table, default cdr\n"
                        "\n"
                        " -U   Make .pcap files writing packet-buffered - more slow method, but you can\n"
                        "      use partialy writen file anytime, it will be consistent.\n"
                        "\n"
                        " -u <username>, --mysql-username=<username>\n"
                        "      mysql username, default voipmonitor\n"
                        "\n"
                        " -v <level-number>\n"
                        "      Set verbosity level (higher number is more verbose).\n"
                        "\n"
                        " -W, --save-audio\n"
                        "      Save RTP packets and covert it to one WAV file. Default is disabled.\n"
                        "\n"
                        " -y   Listen to SIP protocol on ports 5060 - 5099\n"
                        "\n"
                        " --audio-format=<wav|ogg>\n"
                        "      Save to WAV or OGG audio format. Default is WAV.\n"
                        "\n"
                        " --config-file=<filename>\n"
                        "      Specify configuration file full path.  Suggest /etc/voipmonitor.conf\n"
                        "\n"
                        " --manager-port=<port-number>\n"
                        "      TCP port top which manager interface should bind.  Default is 5029.\n"
                        "\n"
                        " --norecord-header\n"
                        "      If any of SIP message during the call contains header\n"
                        "      X-VoipMonitor-norecord call will be not converted to wav and pcap file\n"
                        "      will be deleted.\n"
                        "\n"
                        " --plc-disable\n"
                        "      This option disable voipmonitor's PLC\n"
                        "      (voipmonitor will not mask effect of packet loss, when playing files).\n"
                        "\n"
                        " --ring-buffer=<n>\n"
                        "      Set ring buffer in MB (feature of newer >= 2.6.31 kernels and\n"
                        "      libpcap >= 1.0.0).  If you see voipmonitor dropping packets in syslog\n"
                        "      upgrade to newer kernel and increase --ring-buffer to higher MB.\n"
                        "      Ring-buffer is between kernel and pcap library.  The top reason why\n"
                        "      voipmonitor drops packets is waiting for I/O operations or it consumes\n"
                        "      100%% CPU.\n"
                        "\n"
                        " --rtp-firstleg\n"
                        "      This is important option if voipmonitor is sniffing on SIP proxy and see\n"
                        "      both RTP leg of CALL.  In that case use this option.  It will analyze RTP\n"
                        "      only for the first LEG and not each 4 RTP streams which will confuse\n"
                        "      voipmonitor. Drawback of this switch is that voipmonitor will analyze\n"
                        "      SDP only for SIP packets which have the same IP and port of the first\n"
                        "      INVITE source IP and port.  It means it will not work in case where phone\n"
                        "      sends INVITE from a.b.c.d:1024 and SIP proxy replies to a.b.c.d:5060.  If\n"
                        "      you have better idea how to solve this problem better please contact\n"
                        "      support@voipmonitor.org\n"
                        "\n"
                        " --rtp-nosig\n"
                        "      Analyze calls based on RTP only - handy if you want extract call which\n"
                        "      does not have signalization (or H323 calls which voipmonitor does not\n"
                        "      know yet).\n"
                        "\n"
                        " --save-rtcp\n"
                        "      Save RTCP packets to pcap file.  You can enable SIP signalization + only\n"
                        "      RTCP packets and not RTP packets.\n"
                        "\n"
                        " --sip-messages\n"
                        "      Save REGISTER messages.\n"
                        "\n"
                        " --sip-register\n"
                        "      Save SIP register requests to cdr.register table and to pcap file.\n"
                        "\n"
                        " --skinny\n"
                        "      analyze SKINNY VoIP protocol on TCP port 2000\n"
                        "\n"
                        " --update-schema\n"
                        "      Create or upgrade the database schema, and then exit.  Forces -k option\n"
                        "      and will use 'root' user to perform operations, so supply root's password\n"
                        "      with the -p option.  For safety, this is not compatible with the\n"
                        "      --config-file option.\n"
                        "\n"
                        " --vm-buffer=<n>\n"
                        "      vmbuffer is user space buffers in MB which is used in case there is more\n"
                        "      than 1 CPU and the sniffer run two threads - one for reading data from\n"
                        "      libpcap and writing to vmbuffer and second reads data from vmbuffer and\n"
                        "      processes it.  For very high network loads set this to very high number.\n"
                        "      In case the system is droping packets (which is logged to syslog)\n"
                        "      increase this value.  Default is 20 MB\n"
                        "\n"
                        "One of <-i interface> or <-r pcap-file> must be specified, otherwise you may\n"
                        "set interface in configuration file.\n\n"
                        , RTPSENSOR_VERSION);
                        /*        1         2         3         4         5         6         7         8
                         12345678901234567890123456789012345678901234567890123456789012345678901234567890
                           Ruler to assist with keeping help description to max. 80 chars wide:
                        */

		return 1;
	}
	if(opt_rrd && opt_read_from_file) {
		//disable update of rrd statistics when reading packets from file
		opt_rrd = 0;
	}

	if(opt_rrd && opt_read_from_file) {
          //disable update of rrd statistics when reading packets from file
          opt_rrd = 0; 
	}

	if(cloud_url[0] != '\0') {
		for(int pass = 0; pass < 5; pass++) {
			vector<dstring> postData;
			postData.push_back(dstring("securitytoken", cloud_token));
			char id_sensor_str[10];
			sprintf(id_sensor_str, "%i", opt_id_sensor);
			postData.push_back(dstring("id_sensor", id_sensor_str));
			SimpleBuffer responseBuffer;
			string error;
			syslog(LOG_NOTICE, "connecting to %s", cloud_url);
			get_url_response(cloud_url, &responseBuffer, &postData, &error);
			if(error.empty()) {
				if(!responseBuffer.empty()) {
					if(responseBuffer.isJsonObject()) {
						JsonItem jsonData;
						jsonData.parse((char*)responseBuffer);
						int res_num = atoi(jsonData.getValue("res_num").c_str());
						string res_text = jsonData.getValue("res_text");
						if(res_num != 0) {
							syslog(LOG_ERR, "cloud registration error: %s", res_text.c_str());
							exit(1);
						}
						
						//ssh 
						strcpy(ssh_host, jsonData.getValue("ssh_host").c_str());
						ssh_port = atol(jsonData.getValue("ssh_port").c_str());
						strcpy(ssh_username, jsonData.getValue("ssh_user").c_str());
						strcpy(ssh_password, jsonData.getValue("ssh_password").c_str());
						strcpy(ssh_remote_listenhost, jsonData.getValue("ssh_rhost").c_str());
						ssh_remote_listenport = atol(jsonData.getValue("ssh_rport").c_str());

						//sqlurl
						strcpy(cloud_host, jsonData.getValue("sqlurl").c_str());
						break;
					} else {
						syslog(LOG_ERR, "cloud registration error: bad response - %s", (char*)responseBuffer);
					}
				} else {
					syslog(LOG_ERR, "cloud registration error: response is empty");
				}
				sleep(5);
			} else {
				syslog(LOG_ERR, "cloud registration error: %s", error.c_str());
			}
			sleep(1);
		}
	}
	
	if(opt_cachedir[0]) {
		opt_defer_create_spooldir = false;
	}

	if(!opt_pcap_queue_iface_separate_threads && strchr(ifname, ',')) {
		opt_pcap_queue_iface_separate_threads = 1;
	}
	if(opt_pcap_queue_dequeu_window_length < 0) {
		if(opt_pcap_queue_receive_from_ip_port) {
			 opt_pcap_queue_dequeu_window_length = 2000;
		} else if(strchr(ifname, ',')) {
			 opt_pcap_queue_dequeu_window_length = 1000;
		}
	}

	extern ParsePacket _parse_packet;
	_parse_packet.setStdParse();

	if(!opt_nocdr && isSqlDriver("mysql") && mysql_host[0]) {
		strcpy(mysql_host_orig, mysql_host);
		if(!reg_match(mysql_host, "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")) {
			hostent *conn_server_record = gethostbyname(mysql_host);
			if(conn_server_record == NULL) {
				syslog(LOG_ERR, "mysql host [%s] failed to resolve to IP address", mysql_host);
				exit(1);
			}
			in_addr *conn_server_address = (in_addr*)conn_server_record->h_addr;
			strcpy(mysql_host, inet_ntoa(*conn_server_address));
			syslog(LOG_NOTICE, "mysql host [%s] resolved to [%s]", mysql_host_orig, mysql_host);
		}
	}
	
	if(opt_fork || !opt_nocdr) {
		const char *hostnames[] = {
			"voipmonitor.org",
			"www.voipmonitor.org",
			"download.voipmonitor.org",
			"cloud.voipmonitor.org",
			"cloud2.voipmonitor.org",
			"cloud3.voipmonitor.org"
		};
		for(unsigned int i = 0; i < sizeof(hostnames) / sizeof(hostnames[0]); i++) {
			hostent *conn_server_record = gethostbyname(hostnames[i]);
			if(conn_server_record == NULL) {
				syslog(LOG_ERR, "host [%s] failed to resolve to IP address", hostnames[i]);
				continue;
			}
			in_addr *conn_server_address = (in_addr*)conn_server_record->h_addr;
			hosts[hostnames[i]] = inet_ntoa(*conn_server_address);
		}
	}

	if(opt_fork && !opt_read_from_file) {
		#if ENABLE_SEMAPHOR_FORK_MODE
		for(int pass = 0; pass < 2; pass ++) {
			globalSemaphore = sem_open(SEMAPHOR_FORK_MODE_NAME().c_str(), O_CREAT | O_EXCL);
			if(globalSemaphore == SEM_FAILED) {
				if(errno != EEXIST) {
					syslog(LOG_ERR, "sem_open failed: %s", strerror(errno));
					return 1;
				}
				if(pass == 0) {
		#endif
					bool findOwnPid = false;
					bool findOtherPid = false;
					char *appName = strrchr(argv[0], '/');
					if(appName) {
						++appName;
					} else {
						appName = argv[0];
					}
					string pgrepCmdAll = string("pgrep ") + appName;
					string rsltAll = pexec((char*)pgrepCmdAll.c_str());
					vector<int> allVoipmonitorPid;
					if(rsltAll != "ERROR") {
						char *point = (char*)rsltAll.c_str();
						while(*point) {
							while(*point && !isdigit(*point)) {
								++point;
							}
							if(*point && isdigit(*point)) {
								allVoipmonitorPid.push_back(atoi(point));
							}
							while(*point && isdigit(*point)) {
								++point;
							}
						}
					}
					if(allVoipmonitorPid.size()) {
						string pgrepCmd = string("pgrep -f ") + appName;
						if(configfile[0]) {
							pgrepCmd += string(".*") + configfile;
						}
						string rslt = pexec((char*)pgrepCmd.c_str());
						if(rslt != "ERROR") {
							int ownPid = getpid();
							char *point = (char*)rslt.c_str();
							while(*point) {
								while(*point && !isdigit(*point)) {
									++point;
								}
								if(*point && isdigit(*point)) {
									int checkPid = atoi(point);
									bool findInAll = false;
									for(size_t i = 0; i < allVoipmonitorPid.size(); i++) {
										if(allVoipmonitorPid[i] == checkPid) {
											findInAll = true;
											break;
										}
									}
									if(findInAll) {
										if(checkPid == ownPid) {
										       findOwnPid = true;
										} else {
										       findOtherPid =  true;
										}
									}
								}
								while(*point && isdigit(*point)) {
									++point;
								}
							}
						}
					}
		#if ENABLE_SEMAPHOR_FORK_MODE
					if(findOwnPid && !findOtherPid) {
						if(sem_unlink(SEMAPHOR_FORK_MODE_NAME().c_str())) {
							syslog(LOG_ERR, "sem_unlink failed: %s", strerror(errno));
							return 1;
						}
					} else {
						pass = 1;
					}
				}
				if(pass == 1) {
					syslog(LOG_ERR, "another voipmonitor instance with the same configuration file is running");
					return 1;
				}
			} else {
				break;
			}
		}
		atexit(exit_handler_fork_mode);
		#else
		if(findOwnPid && findOtherPid) {
			syslog(LOG_ERR, "another voipmonitor instance with the same configuration file is running");
			return 1;
		}
		#endif
	}

	if(opt_generator) {
		opt_generator_channels = 2;
		pthread_t *genthreads = (pthread_t*)malloc(opt_generator_channels * sizeof(pthread_t));		// ID of worker storing CDR thread 
		for(int i = 0; i < opt_generator_channels; i++) {
			pthread_create(&genthreads[i], NULL, gensiprtp, NULL);
		}
		syslog(LOG_ERR, "Traffic generated");
		sleep(10000);
		return 0;
	}

	cout << "SQL DRIVER: " << sql_driver << endl;
	if(!opt_nocdr &&
	   !(opt_pcap_threaded && opt_pcap_queue && 
	     !opt_pcap_queue_receive_from_ip_port &&
	     opt_pcap_queue_send_to_ip_port)) {
		SqlDb *sqlDb = createSqlObject();
		for(int pass = 0; pass < 2; pass++) {
			if(sqlDb->connect(true, true)) {
				break;
			}
			sleep(1);
		}
		if(sqlDb->connected()) {
			if(isSqlDriver("mysql")) {
				sql_noerror = 1;
				sqlDb->query("repair table mysql.proc");
				sql_noerror = 0;
			}
			sqlDb->checkDbMode();
			sqlDb->createSchema();
			sqlDb->checkSchema();
		} else {
			syslog(LOG_ERR, "Can't connect to MySQL server - exit!");
			return 1;
		}
		delete sqlDb;
	}
	if(isSqlDriver("mysql")) {
		sqlStore = new MySqlStore(mysql_host, mysql_user, mysql_password, mysql_database, cloud_host, cloud_token);	
		if(!opt_nocdr) {
			sqlStore->connect(STORE_PROC_ID_CDR_1);
			sqlStore->connect(STORE_PROC_ID_MESSAGE_1);
		}
		if(opt_mysqlloadconfig && 
		   !opt_nocdr &&
		   !(opt_pcap_threaded && opt_pcap_queue && 
		     !opt_pcap_queue_receive_from_ip_port &&
		     opt_pcap_queue_send_to_ip_port)) {
			config_load_mysql();
		}
		if(opt_mysqlstore_concat_limit) {
			 sqlStore->setDefaultConcatLimit(opt_mysqlstore_concat_limit);
		}
		if(opt_mysqlstore_concat_limit_cdr) {
			for(int i = 0; i < opt_mysqlstore_max_threads_cdr; i++) {
				sqlStore->setConcatLimit(STORE_PROC_ID_CDR_1 + i, opt_mysqlstore_concat_limit_cdr);
				if(i) {
					sqlStore->setEnableAutoDisconnect(STORE_PROC_ID_CDR_1 + i);
				}
			}
		}
		if(opt_mysqlstore_concat_limit_message) {
			for(int i = 0; i < opt_mysqlstore_max_threads_message; i++) {
				sqlStore->setConcatLimit(STORE_PROC_ID_MESSAGE_1 + i, opt_mysqlstore_concat_limit_message);
				if(i) {
					sqlStore->setEnableAutoDisconnect(STORE_PROC_ID_MESSAGE_1 + i);
				}
			}
		}
		if(opt_mysqlstore_concat_limit_register) {
			for(int i = 0; i < opt_mysqlstore_max_threads_register; i++) {
				sqlStore->setConcatLimit(STORE_PROC_ID_REGISTER_1 + i, opt_mysqlstore_concat_limit_register);
				if(i) {
					sqlStore->setEnableAutoDisconnect(STORE_PROC_ID_REGISTER_1 + i);
				}
			}
		}
		if(opt_mysqlstore_concat_limit_http) {
			for(int i = 0; i < opt_mysqlstore_max_threads_http; i++) {
				sqlStore->setConcatLimit(STORE_PROC_ID_HTTP_1 + i, opt_mysqlstore_concat_limit_http);
				if(i) {
					sqlStore->setEnableAutoDisconnect(STORE_PROC_ID_HTTP_1 + i);
				}
			}
		}
		if(opt_mysqlstore_concat_limit_ipacc) {
			for(int i = 0; i < opt_mysqlstore_max_threads_ipacc_base; i++) {
				sqlStore->setConcatLimit(STORE_PROC_ID_IPACC_1 + i, opt_mysqlstore_concat_limit_ipacc);
			}
			for(int i = STORE_PROC_ID_IPACC_AGR_INTERVAL; i <= STORE_PROC_ID_IPACC_AGR_DAY; i++) {
				sqlStore->setConcatLimit(i, opt_mysqlstore_concat_limit_ipacc);
			}
			for(int i = 0; i < opt_mysqlstore_max_threads_ipacc_agreg2; i++) {
				sqlStore->setConcatLimit(STORE_PROC_ID_IPACC_AGR2_HOUR_1 + i, opt_mysqlstore_concat_limit_ipacc);
			}
		}
	}
	
	signal(SIGINT,sigint_handler);
	signal(SIGTERM,sigterm_handler);

	if(!opt_test &&
	   opt_database_backup_from_date[0] != '\0' &&
	   opt_database_backup_from_mysql_host[0] != '\0' &&
	   opt_database_backup_from_mysql_database[0] != '\0' &&
	   opt_database_backup_from_mysql_user[0] != '\0') {
		if (opt_fork){
			daemonize();
		}
		pthread_create(&database_backup_thread, NULL, database_backup, NULL);
		pthread_join(database_backup_thread, NULL);
		return(0);
	}

	calltable = new Calltable;
	
	// preparing pcap reading and pcap filters 
	
	bpf_u_int32 mask;		// Holds the subnet mask associated with device.
	char errbuf[PCAP_ERRBUF_SIZE];	// Returns error text and is only set when the pcap_lookupnet subroutine fails.
	
	if(opt_test) {
		ipfilter = new IPfilter;
		telnumfilter = new TELNUMfilter;
		domainfilter =  new DOMAINfilter;
		test();
		if(sqlStore) {
			delete sqlStore;
		}
		return(0);
	}
	rtp_threaded = num_threads > 0;

	// check if sniffer will be reading pcap files from dir and if not if it reads from eth interface or read only one file
	if(opt_scanpcapdir[0] == '\0') {
		if (fname[0] == '\0' && ifname[0] != '\0'){
			if(!opt_pcap_queue) {
				bpf_u_int32 net;

				printf("Capturing on interface: %s\n", ifname);
				// Find the properties for interface 
				if (pcap_lookupnet(ifname, &net, &mask, errbuf) == -1) {
					// if not available, use default
					mask = PCAP_NETMASK_UNKNOWN;
				}
				/*
				global_pcap_handle = pcap_open_live(ifname, 1600, opt_promisc, 1000, errbuf);
				if (global_pcap_handle == NULL) {
					fprintf(stderr, "Couldn't open inteface '%s': %s\n", ifname, errbuf);
					return(2);
				}
				*/

				/* to set own pcap_set_buffer_size it must be this way and not useing pcap_lookupnet */

				int status = 0;
				if((global_pcap_handle = pcap_create(ifname, errbuf)) == NULL) {
					fprintf(stderr, "pcap_create failed on iface '%s': %s\n", ifname, errbuf);
					return(2);
				}
				if((status = pcap_set_snaplen(global_pcap_handle, 3200)) != 0) {
					fprintf(stderr, "error pcap_set_snaplen\n");
					return(2);
				}
				if((status = pcap_set_promisc(global_pcap_handle, opt_promisc)) != 0) {
					fprintf(stderr, "error pcap_set_promisc\n");
					return(2);
				}
				if((status = pcap_set_timeout(global_pcap_handle, 1000)) != 0) {
					fprintf(stderr, "error pcap_set_timeout\n");
					return(2);
				}

				/* this is not possible for libpcap older than 1.0.0 so now voipmonitor requires libpcap > 1.0.0
					set ring buffer size to 5M to prevent packet drops whan CPU goes high or on very high traffic 
					- default is 2MB for libpcap > 1.0.0
					- for libpcap < 1.0.0 it is controled by /proc/sys/net/core/rmem_default which is very low 
				*/
				if((status = pcap_set_buffer_size(global_pcap_handle, opt_ringbuffer * 1024 * 1024)) != 0) {
					fprintf(stderr, "error pcap_set_buffer_size\n");
					return(2);
				}

				if((status = pcap_activate(global_pcap_handle)) != 0) {
					fprintf(stderr, "libpcap error: [%s]\n", pcap_geterr(global_pcap_handle));
					return(2);
				}
			}
			if(opt_convert_dlt_sll_to_en10) {
				global_pcap_handle_dead_EN10MB = pcap_open_dead(DLT_EN10MB, 65535);
			}
		} else {
			// if reading file
			rtp_threaded = 0;
			opt_mirrorip = 0; // disable mirroring packets when reading pcap files from file
//			opt_cachedir[0] = '\0'; //disabling cache if reading from file 
			opt_pcap_threaded = 0; //disable threading because it is useless while reading packets from file
			//opt_cleanspool_interval = 0; // disable cleaning spooldir when reading from file 
			opt_maxpoolsize = 0;
			opt_maxpooldays = 0;
			opt_maxpoolsipsize = 0;
			opt_maxpoolsipdays = 0;
			opt_maxpoolrtpsize = 0;
			opt_maxpoolrtpdays = 0;
			opt_maxpoolgraphsize = 0;
			opt_maxpoolgraphdays = 0;
			opt_maxpoolaudiosize = 0;
			opt_maxpoolaudiodays = 0;
			
			opt_manager_port = 0; // disable cleaning spooldir when reading from file 
			printf("Reading file: %s\n", fname);
			mask = PCAP_NETMASK_UNKNOWN;
			global_pcap_handle = pcap_open_offline_zip(fname, errbuf);
			if(global_pcap_handle == NULL) {
				fprintf(stderr, "Couldn't open pcap file '%s': %s\n", fname, errbuf);
				return(2);
			}
		}
		
		if(!opt_pcap_queue) {
			if(opt_mirrorip) {
				if(opt_mirrorip_dst[0] == '\0') {
					syslog(LOG_ERR, "Mirroring SIP packets disabled because mirroripdst was not set");
					opt_mirrorip = 0;
				} else {
					syslog(LOG_NOTICE, "Starting SIP mirroring [%s]->[%s]", opt_mirrorip_src, opt_mirrorip_dst);
					mirrorip = new MirrorIP(opt_mirrorip_src, opt_mirrorip_dst);
				}
			}

			char filter_exp[2048] = "";		// The filter expression
			struct bpf_program fp;		// The compiled filter 

			if(*user_filter != '\0') {
				snprintf(filter_exp, sizeof(filter_exp), "%s", user_filter);

				// Compile and apply the filter
				if (pcap_compile(global_pcap_handle, &fp, filter_exp, 0, mask) == -1) {
					fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(global_pcap_handle));
					return(2);
				}
				if (pcap_setfilter(global_pcap_handle, &fp) == -1) {
					fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(global_pcap_handle));
					return(2);
				}
			}
		}
	}
	//opt_pcap_threaded = 0; //disable threading because it is useless while reading packets from file
	
	chdir(opt_chdir);

	mkdir_r("filesindex/sipsize", 0777);
	mkdir_r("filesindex/rtpsize", 0777);
	mkdir_r("filesindex/graphsize", 0777);
	mkdir_r("filesindex/audiosize", 0777);
	mkdir_r("filesindex/regsize", 0777);

	// set maximum open files 
	struct rlimit rlp;
        rlp.rlim_cur = opt_openfile_max;
        rlp.rlim_max = opt_openfile_max;
        setrlimit(RLIMIT_NOFILE, &rlp);
        getrlimit(RLIMIT_NOFILE, &rlp);
        if(opt_fork and rlp.rlim_cur < 65535) {
                printf("Warning, max open files is: %d consider raise this to 65535 with ulimit -n 65535 and set it in config file\n", (int)rlp.rlim_cur);
        }
	// set core file dump to unlimited size
	rlp.rlim_cur = UINT_MAX;
	rlp.rlim_max = UINT_MAX;
	setrlimit(RLIMIT_CORE, &rlp);

	ipfilter = new IPfilter;
	telnumfilter = new TELNUMfilter;
	domainfilter = new DOMAINfilter;
	if(!opt_nocdr &&
	   !(opt_pcap_threaded && opt_pcap_queue && 
	     !opt_pcap_queue_receive_from_ip_port &&
	     opt_pcap_queue_send_to_ip_port)) {
		ipfilter->load();
		telnumfilter->load();
		domainfilter->load();
	}
//	ipfilter->dump();
//	telnumfilter->dump();
//	domainfilter->dump();

	if(opt_ipaccount and !ipaccountportmatrix) {
		ipaccountportmatrix = (char*)calloc(1, sizeof(char) * 65537);
	}

	// filters are ok, we can daemonize 
	if (opt_fork && !opt_read_from_file){
		daemonize();
	}
	
	if(opt_enable_fraud) {
		initFraud();
	}

	extern AsyncClose asyncClose;
	asyncClose.startThreads(opt_pcap_dump_writethreads, opt_pcap_dump_writethreads_max);
	
	if(!opt_nocdr &&
	   isSqlDriver("mysql") &&
	   !(opt_pcap_queue && 
	     !opt_pcap_queue_receive_from_ip_port &&
	     opt_pcap_queue_send_to_ip_port) &&
	   isSetCleanspoolParameters()) {
		runCleanSpoolThread();
	}
	
	// start thread processing queued cdr and sql queue - supressed if run as sender
	if(!(opt_pcap_threaded && opt_pcap_queue && 
	     !opt_pcap_queue_receive_from_ip_port &&
	     opt_pcap_queue_send_to_ip_port)) {
		pthread_create(&call_thread, NULL, storing_cdr, NULL);
		/*
		pthread_create(&destroy_calls_thread, NULL, destroy_calls, NULL);
		*/
	}

	if(opt_cachedir[0] != '\0') {
		mv_r(opt_cachedir, opt_chdir);
		pthread_create(&cachedir_thread, NULL, moving_cache, NULL);
	}

	// start manager thread 	
	if(opt_manager_port > 0) {
		pthread_create(&manager_thread, NULL, manager_server, NULL);
		// start reversed manager thread
		if(opt_clientmanager[0] != '\0') {
			pthread_create(&manager_client_thread, NULL, manager_client, NULL);
		}
	};

	if(ssh_host[0] != '\0') {
		pthread_create(&manager_ssh_thread, NULL, manager_ssh, NULL);
	}

	// start reading threads
	if(rtp_threaded &&
	   !(opt_pcap_threaded && opt_pcap_queue && 
	     !opt_pcap_queue_receive_from_ip_port &&
	     opt_pcap_queue_send_to_ip_port)) {
		threads = new read_thread[num_threads];
		for(int i = 0; i < num_threads; i++) {
#ifdef QUEUE_MUTEX
			pthread_mutex_init(&(threads[i].qlock), NULL);
			sem_init(&(threads[i].semaphore), 0, 0);
#endif

#ifdef QUEUE_NONBLOCK
			threads[i].pqueue = NULL;
			queue_new(&(threads[i].pqueue), 10000);
#endif

#ifdef QUEUE_NONBLOCK2
			threads[i].vmbuffermax = rtpthreadbuffer * 1024 * 1024 / sizeof(rtp_packet);
			threads[i].writeit = 0;
			threads[i].readit = 0;
			if(!opt_pcap_queue) {
				threads[i].vmbuffer = (rtp_packet*)malloc(sizeof(rtp_packet) * (threads[i].vmbuffermax + 1));
				for(int j = 0; j < threads[i].vmbuffermax + 1; j++) {
					threads[i].vmbuffer[j].free = 1;
				}
			}
#endif

			pthread_create(&(threads[i].thread), NULL, rtp_read_thread_func, (void*)&threads[i]);
		}
	}
	if(opt_pcap_threaded) {
#ifdef QUEUE_MUTEX
		pthread_mutex_init(&readpacket_thread_queue_lock, NULL);
		sem_init(&readpacket_thread_semaphore, 0, 0);
#endif

#ifdef QUEUE_NONBLOCK
		queue_new(&qs_readpacket_thread_queue, 100000);
		pthread_create(&pcap_read_thread, NULL, pcap_read_thread_func, NULL);
#endif

#ifdef QUEUE_NONBLOCK2
		if(!opt_pcap_queue) {
			qring = (pcap_packet*)malloc((size_t)((unsigned int)sizeof(pcap_packet) * (qringmax + 1)));
			for(unsigned int i = 0; i < qringmax + 1; i++) {
				qring[i].free = 1;
			}
			pthread_create(&pcap_read_thread, NULL, pcap_read_thread_func, NULL);
		}
#endif 
	}

	if(opt_enable_tcpreassembly) {
		bool setHttpPorts = false;
		for(int i = 0; i < 65537; i++) {
			if(httpportmatrix[i]) {
				setHttpPorts = true;
			}
		}
		if(setHttpPorts) {
			tcpReassembly = new TcpReassembly;
			tcpReassembly->setEnableHttpForceInit();
			tcpReassembly->setEnableCrazySequence();
			httpData = new HttpData;
			tcpReassembly->setDataCallback(httpData);
		}
	}
	
	if(sipSendSocket_ip_port) {
		sipSendSocket = new SocketSimpleBufferWrite("send sip", sipSendSocket_ip_port);
		sipSendSocket->startWriteThread();
	}
	
	if(opt_bogus_dumper_path[0]) {
		bogusDumper = new BogusDumper(opt_bogus_dumper_path);
	}

#ifndef FREEBSD
	if(opt_scanpcapdir[0] != '\0') {
		// scan directory opt_scanpcapdir (typically /dev/shm/voipmonitor
		char filename[1024];
		char filter_exp[2048] = "";		// The filter expression
		struct bpf_program fp;		// The compiled filter 
		pcap_t *scanhandle = NULL;		// pcap handler
		struct inotify_event *event;
		char buff[1024];
		int i=0, fd, wd, len=0;
		fd = inotify_init();
		/*checking for error*/
		if(fd < 0) perror( "inotify_init" );
		wd = inotify_add_watch(fd, opt_scanpcapdir, opt_scanpcapmethod);
		while(1 and terminating == 0) {
			i = 0;
			len = read(fd, buff, 1024);
			while(i < len) {
				event = (struct inotify_event *) &buff[i];
				if (event->mask & opt_scanpcapmethod) { // this will prevent opening files which is still open for writes
				    snprintf(filename, sizeof(filename), "%s/%s", opt_scanpcapdir, event->name);
				    int close = 1;
				    //printf("File [%s]\n", filename);
				    if(!file_exists(filename)) { 
				        i += sizeof(struct inotify_event) + event->len;
					continue;
				    }
				    // if reading file
				    //printf("Reading file: %s\n", filename);
				    mask = PCAP_NETMASK_UNKNOWN;
				    scanhandle = pcap_open_offline(filename, errbuf);
				    if(!global_pcap_handle) {
					    // keep the first handle as global handle and do not change it because it is not threadsafe to close/open it while the other parts are using it
					    global_pcap_handle = scanhandle;
					    close = 0;
				    } else {
					    close = 1;
				    }
				    if(scanhandle == NULL) {
					    syslog(LOG_ERR, "Couldn't open pcap file '%s': %s\n", filename, errbuf);
					    i += sizeof(struct inotify_event) + event->len;
					    continue;
				    }
				    if(*user_filter != '\0') {
					    snprintf(filter_exp, sizeof(filter_exp), "%s", user_filter);

					    // Compile and apply the filter
					    if (pcap_compile(scanhandle, &fp, filter_exp, 0, mask) == -1) {
						    syslog(LOG_ERR, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(scanhandle));
						    inotify_rm_watch(fd, wd);
						    return(2);
					    }
					    if (pcap_setfilter(scanhandle, &fp) == -1) {
						    syslog(LOG_ERR, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(scanhandle));
						    inotify_rm_watch(fd, wd);
						    return(2);
					    }
				    }
				    readdump_libpcap(scanhandle);
				    unlink(filename);
				    if(*user_filter != '\0') {
					    pcap_freecode(&fp);
				    }
				    if(close) {
					    pcap_close(scanhandle);
				    }
				}
				i += sizeof(struct inotify_event) + event->len;
			}
			//readend = 1;
		}
		inotify_rm_watch(fd, wd);
		if(global_pcap_handle) pcap_close(global_pcap_handle);
	} else {
#else 
	{
#endif
		// start reading packets
		//readdump_libnids(handle);
	 
		if((opt_read_from_file || opt_pb_read_from_file[0]) && !opt_nocdr) {
			for(int i = 0; i < opt_mysqlstore_max_threads_cdr; i++) {
				sqlStore->setIgnoreTerminating(STORE_PROC_ID_CDR_1 + i, true);
			}
			for(int i = 0; i < opt_mysqlstore_max_threads_message; i++) {
				sqlStore->setIgnoreTerminating(STORE_PROC_ID_MESSAGE_1 + i, true);
			}
		}

		if(opt_pcap_threaded) {
			if(opt_pcap_queue) {
				
				if(opt_pcap_queue_receive_from_ip_port) {
					
					PcapQueue_readFromFifo *pcapQueueR = new PcapQueue_readFromFifo("receive", opt_pcap_queue_disk_folder.c_str());
					pcapQueueR->setEnableAutoTerminate(false);
					pcapQueueR->setPacketServer(opt_pcap_queue_receive_from_ip_port, PcapQueue_readFromFifo::directionRead);
					pcapQueueStatInterface = pcapQueueR;
					
					pcapQueueR->start();
					
					uint64_t _counter = 0;
					while(!terminating) {
						if(_counter && (verbosityE > 0 || !(_counter % 10))) {
							pcapQueueR->pcapStat(verbosityE > 0 ? 1 : 10);
						}
						sleep(1);
						++_counter;
					}
					
					pcapQueueR->terminate();
					sleep(1);
					
					delete pcapQueueR;
					
				} else {
				 
					if(opt_pb_read_from_file[0] && opt_enable_tcpreassembly) {
						for(int i = 0; i < opt_mysqlstore_max_threads_http; i++) {
							sqlStore->setIgnoreTerminating(STORE_PROC_ID_HTTP_1 + i, true);
						}
						if(opt_tcpreassembly_thread) {
							tcpReassembly->setIgnoreTerminating(true);
						}
					}
				
					PcapQueue_readFromInterface *pcapQueueI = new PcapQueue_readFromInterface("interface");
					pcapQueueI->setInterfaceName(ifname);
					pcapQueueI->setEnableAutoTerminate(false);
					
					PcapQueue_readFromFifo *pcapQueueQ = new PcapQueue_readFromFifo("queue", opt_pcap_queue_disk_folder.c_str());
					pcapQueueQ->setInstancePcapHandle(pcapQueueI);
					pcapQueueQ->setEnableAutoTerminate(false);
					if(opt_pcap_queue_send_to_ip_port) {
						pcapQueueQ->setPacketServer(opt_pcap_queue_send_to_ip_port, PcapQueue_readFromFifo::directionWrite);
					}
					pcapQueueStatInterface = pcapQueueQ;
					
					pcapQueueQ->start();
					pcapQueueI->start();
					
					uint64_t _counter = 0;
					while(!terminating) {
						if(_counter && (verbosityE > 0 || !(_counter % 10))) {
							pcapQueueQ->pcapStat(verbosityE > 0 ? 1 : 10);
							if(tcpReassembly) {
								tcpReassembly->setDoPrintContent();
							}
						}
						sleep(1);
						++_counter;
					}
					
					pcapQueueI->terminate();
					sleep(opt_pb_read_from_file[0] && opt_enable_tcpreassembly ? 10 : 1);
					if(opt_pb_read_from_file[0] && opt_enable_tcpreassembly && opt_tcpreassembly_thread) {
						tcpReassembly->setIgnoreTerminating(false);
						sleep(2);
					}
					pcapQueueQ->terminate();
					sleep(1);
					
					if(tcpReassembly) {
						delete tcpReassembly;
						tcpReassembly = NULL;
					}
					if(httpData) {
						delete httpData;
						httpData = NULL;
					}
					
					delete pcapQueueI;
					delete pcapQueueQ;
					
					if(opt_pb_read_from_file[0] && opt_enable_tcpreassembly) {
						sleep(2);
						for(int i = 0; i < opt_mysqlstore_max_threads_http; i++) {
							sqlStore->setIgnoreTerminating(STORE_PROC_ID_HTTP_1 + i, false);
						}
						sleep(2);
					}
					
				}
				
			} else {
				pthread_create(&readdump_libpcap_thread, NULL, readdump_libpcap_thread_fce, global_pcap_handle);
				pthread_join(readdump_libpcap_thread, NULL);
			}
		} else {
			readdump_libpcap(global_pcap_handle);
		}
	}

	readend = 1;

	//wait for manager to properly terminate 
	if(opt_manager_port && manager_thread > 0) {
		int res;
		res = shutdown(manager_socket_server, SHUT_RDWR);	// break accept syscall in manager thread
		if(res == -1) {
			// if shutdown failed it can happen when reding very short pcap file and the bind socket was not created in manager
			usleep(10000); 
			res = shutdown(manager_socket_server, SHUT_RDWR);	// break accept syscall in manager thread
		}
		struct timespec ts;
		ts.tv_sec = 1;
		ts.tv_nsec = 0;
		// wait for thread max 1 sec
#ifndef FREEBSD	
		//TODO: solve it for freebsd
		pthread_timedjoin_np(manager_thread, NULL, &ts);
#endif
	}

#ifdef QUEUE_NONBLOCK2
	if(opt_pcap_threaded && !opt_pcap_queue) {
		pthread_join(pcap_read_thread, NULL);
	}
#endif

	// wait for RTP threads
	if(rtp_threaded &&
	   !(opt_pcap_threaded && opt_pcap_queue && 
	     !opt_pcap_queue_receive_from_ip_port &&
	     opt_pcap_queue_send_to_ip_port)) {
		for(int i = 0; i < num_threads; i++) {
			pthread_join((threads[i].thread), NULL);
#ifdef QUEUE_NONBLOCK2
			if(!opt_pcap_queue) {
				free(threads[i].vmbuffer);
			}
#endif
		}
		delete [] threads;
	}

	// close handler
	if(opt_scanpcapdir[0] == '\0') {
		if(!opt_pcap_queue) {
			pcap_close(global_pcap_handle);
		}
		if(global_pcap_handle_dead_EN10MB) {
			pcap_close(global_pcap_handle_dead_EN10MB);
		}
	}
	
	// flush all queues

	Call *call;
	calltable->cleanup(0);
	if((opt_read_from_file || opt_pb_read_from_file[0]) && !opt_nocdr) {
		for(int i = 0; i < 20; i++) {
			if(calls_cdr_save_counter > 0 || calls_message_save_counter > 0) {
				usleep(100000);
			} else {
				break;
			}
		}
		if(opt_enable_fraud &&
		   sqlStore->getSize(STORE_PROC_ID_FRAUD_ALERT_INFO)) {
			sleep(2);
		}
		for(int i = 0; i < opt_mysqlstore_max_threads_cdr; i++) {
			sqlStore->setIgnoreTerminating(STORE_PROC_ID_CDR_1 + i, false);
		}
		for(int i = 0; i < opt_mysqlstore_max_threads_message; i++) {
			sqlStore->setIgnoreTerminating(STORE_PROC_ID_MESSAGE_1 + i, false);
		}
	}
	terminating = 1;
	if(!(opt_pcap_threaded && opt_pcap_queue && 
	     !opt_pcap_queue_receive_from_ip_port &&
	     opt_pcap_queue_send_to_ip_port)) {
		pthread_join(call_thread, NULL);
	}
	while(calltable->calls_queue.size() != 0) {
			call = calltable->calls_queue.front();
			calltable->calls_queue.pop_front();
			delete call;
			calls_counter--;
	}
	while(calltable->calls_deletequeue.size() != 0) {
			call = calltable->calls_deletequeue.front();
			calltable->calls_deletequeue.pop_front();
			call->atFinish();
			delete call;
			calls_counter--;
	}

	regfailedcache->prune(0);
	
	if(tcpReassembly) {
		delete tcpReassembly;
	}
	if(httpData) {
		delete httpData;
	}
	
	if(sipSendSocket) {
		delete sipSendSocket;
	}

	/* obsolete ?
	if(!opt_nocdr) {
		int size = 0;
		int msgs = 50;
                int _counterIpacc = 0;
		string queryqueue = "";
		pthread_mutex_lock(&mysqlquery_lock);
		int mysqlQuerySize = mysqlquery.size();
		SqlDb *sqlDb = createSqlObject();
		while(1) {
			if(mysqlquery.size() == 0) {
				if(queryqueue != "") {
					// send the rest 
					sqlDb->query("drop procedure if exists " + insert_funcname);
					sqlDb->query("create procedure " + insert_funcname + "()\nbegin\n" + queryqueue + "\nend");
					sqlDb->query("call " + insert_funcname + "();");
					//sqlDb->query(queryqueue);
					queryqueue = "";
				}
				break;
			}
			string query = mysqlquery.front();
			mysqlquery.pop();
			--mysqlQuerySize;
			queryqueue.append(query + "; ");
			if(verbosity > 0) {
				if(query.find("ipacc ") != string::npos) {
					++_counterIpacc;
				}
			}
			if(size < msgs) {
				size++;
			} else {
				sqlDb->query("drop procedure if exists " + insert_funcname);
				sqlDb->query("create procedure " + insert_funcname + "()\nbegin\n" + queryqueue + "\nend");
				sqlDb->query("call " + insert_funcname + "();");
				//sqlDb->query(queryqueue);
				queryqueue = "";
				size = 0;
			}
			usleep(100);
		}
		delete sqlDb;
		pthread_mutex_unlock(&mysqlquery_lock);
	}
	*/

	free(sipportmatrix);
	free(httpportmatrix);
	if(opt_ipaccount) {
		free(ipaccountportmatrix);
	}

	if(opt_cachedir[0] != '\0') {
		terminating2 = 1;
		pthread_join(cachedir_thread, NULL);
	}
	delete calltable;
	
	if(ipfilter) {
		delete ipfilter;
		ipfilter = NULL;
	}
	if(telnumfilter) {
		delete telnumfilter;
		telnumfilter = NULL;
	}
	if(domainfilter) {
		delete domainfilter;
		domainfilter = NULL;
	}
	
	if(opt_enable_fraud) {
		termFraud();
	}
	if(SafeAsyncQueue_base::isRunTimerThread()) {
		SafeAsyncQueue_base::stopTimerThread(true);
	}
	
	extern SqlDb *sqlDbSaveCall;
	if(sqlDbSaveCall) {
		delete sqlDbSaveCall;
	}
	extern SqlDb *sqlDbSaveIpacc;
	if(sqlDbSaveIpacc) {
		delete sqlDbSaveIpacc;
	}
	extern SqlDb *sqlDbSaveHttp;
	if(sqlDbSaveHttp) {
		delete sqlDbSaveHttp;
	}
	extern SqlDb_mysql *sqlDbEscape;
	if(sqlDbEscape) {
		delete sqlDbEscape;
	}
	extern SqlDb_mysql *sqlDbCleanspool;
	if(sqlDbCleanspool) {
		delete sqlDbCleanspool;
	}
	
	if(mirrorip) {
		delete mirrorip;
	}

	if (opt_fork){
		unlink(opt_pidfile);
	}
	pthread_mutex_destroy(&mysqlconnect_lock);
	extern TcpReassemblySip tcpReassemblySip;
	tcpReassemblySip.clean();
	ipfrag_prune(0, 1);
	freeMemIpacc();
	delete regfailedcache;
	if(opt_read_from_file) {
		extern AsyncClose asyncClose;
		asyncClose.processAll();
	}
//	mysql_library_end();

	if(sqlStore) {
		delete sqlStore;
	}
	
	if(opt_bogus_dumper_path[0]) {
		delete bogusDumper;
	}
	
	thread_cleanup();
}

void *readdump_libpcap_thread_fce(void *handle) {
	readdump_libpcap((pcap_t*)handle);
	return(NULL);
}


#include "rqueue.h"
#include "fraud.h"
#include <regex.h>

struct XX {
	XX(int a = 0, int b = 0) {
		this->a = a;
		this->b = b;
	}
	int a;
	int b;
};

void test_search_country_by_number() {
	CheckInternational *ci = new CheckInternational();
	ci->setInternationalMinLength(9);
	CountryPrefixes *cp = new CountryPrefixes();
	cp->load();
	vector<string> countries;
	cout << cp->getCountry("00039123456789", &countries, ci) << endl;
	for(size_t i = 0; i < countries.size(); i++) {
		cout << countries[i] << endl;
	}
	delete cp;
	delete ci;
	cout << "-" << endl;
}

void test_geoip() {
	GeoIP_country *ipc = new GeoIP_country();
	ipc->load();
	in_addr ips;
	inet_aton("152.251.11.109", &ips);
	cout << ipc->getCountry(htonl(ips.s_addr)) << endl;
	delete ipc;
}

void test_filebuffer() {
	int maxFiles = 1000;
	int bufferLength = 8000;
	FILE *file[maxFiles];
	char *fbuffer[maxFiles];
	
	for(int i = 0; i < maxFiles; i++) {
		char filename[100];
		sprintf(filename, "/dev/shm/test/%i", i);
		file[i] = fopen(filename, "w");
		
		setbuf(file[i], NULL);
		
		fbuffer[i] = new char[bufferLength];
		
	}
	
	printf("%d\n", BUFSIZ);
	
	char writebuffer[1000];
	memset(writebuffer, 1, 1000);
	
	for(int i = 0; i < maxFiles; i++) {
		fwrite(writebuffer, 1000, 1, file[i]);
		fclose(file[i]);
		char filename[100];
		sprintf(filename, "/dev/shm/test/%i", i);
		file[i] = fopen(filename, "a");
		
		fflush(file[i]);
		setvbuf(file[i], fbuffer[i], _IOFBF, bufferLength);
	}
	
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv, &tz);
	
	cout << "---" << endl;
	u_int64_t _start = tv.tv_sec * 1000000ull + tv.tv_usec;
	
	
	for(int p = 0; p < 5; p++)
	for(int i = 0; i < maxFiles; i++) {
		fwrite(writebuffer, 1000, 1, file[i]);
	}
	
	cout << "---" << endl;
	gettimeofday(&tv, &tz);
	u_int64_t _end = tv.tv_sec * 1000000ull + tv.tv_usec;
	cout << (_end - _start) << endl;
}

void test_safeasyncqueue() {
	SafeAsyncQueue<XX> testSAQ;
	XX xx(1,2);
	testSAQ.push(xx);
	XX yy;
	sleep(1);
	if(testSAQ.pop(&yy)) {
		cout << "y" << endl;
		cout << yy.a << "/" << yy.b << endl;
	} else {
		cout << "n" << endl;
	}
}

void test_parsepacket() {
	ParsePacket pp;
	pp.setStdParse();
 
	char *str = (char*)"";
	cout << pp.parseData(str, strlen(str), true) << endl;
	
	pp.debugData();
}
	
void test_parsepacket2() {
	ParsePacket pp;
	pp.addNode("test1");
	pp.addNode("test2");
	pp.addNode("test3");
	
	//pp.getContent("test1")->content = "1";
	//pp.getContent("test2")->content = "2";
	//pp.getContent("test3")->content = "3";
	
	char *str = (char*)"test1abc\ncontent-length: 20 \rxx\r\n\r\ntEst2def\rtest3ghi\n";
	//          12345678 90123456789012345678 901 2 3 4 567890123456789012
	//                    1         2          3             4         5
	
	pp.parseData(str, strlen(str), true);
	
	cout << pp.getContent("test1")->content << "   L: " << pp.getContent("test1")->length << endl;
	cout << pp.getContent("test2")->content << "   L: " << pp.getContent("test2")->length << endl;
	cout << pp.getContent("test3")->content << "   L: " << pp.getContent("test3")->length << endl;
}

void test_reg() {
	cout << reg_match("123456789", "456") << endl;
	cout << reg_replace("123456789", "(.*)(456)(.*)", "$1-$2-$3") << endl;
}

void test_escape() {
	char checkbuff[2] = " ";
	for(int i = 0; i < 256; i++) {
		checkbuff[0] = i;
		string escapePacket1 = sqlEscapeString(checkbuff, 1);
		string escapePacket2 = _sqlEscapeString(checkbuff, 1, "mysql");
		if(escapePacket1 != escapePacket2) {
			cout << i << endl;
			cout << escapePacket1 << endl;
			cout << escapePacket2 << endl;
			break;
		}
	}
}

void test() {
 
	switch(opt_test) {
	 
	case 1: {
		//test_search_country_by_number();
		test_geoip();
		cout << "---------" << endl;
	} break;
	case 2: {
		for(int i = 0; i < 10; i++) {
			sleep(1);
			cout << "." << flush;
		}
		cout << endl;
		SqlDb *sqlDb = createSqlObject();
		sqlDb->connect();
		for(int i = 0; i < 10; i++) {
			sleep(1);
			cout << "." << flush;
		}
		cout << endl;
		sqlDb->query("drop procedure if exists __insert_test");
	 
	} break;
	case 3: {
		char *pointToSepOptTest = strchr(opt_test_str, '/');
		if(pointToSepOptTest) {
			initFraud();
			extern GeoIP_country *geoIP_country;
			cout << geoIP_country->getCountry(pointToSepOptTest + 1) << endl;
		}
	} break;
	case 4: {
		vm_atomic<string> astr(string("000"));
		cout << astr << endl;
		astr = string("abc");
		cout << astr << endl;
		astr = "def";
		cout << astr << endl;
		
		vm_atomic<string> astr2 = astr;
		cout << astr2 << endl;
		astr2 = astr;
		cout << astr2 << endl;
		
	} break;
	case 10:
		{
		SqlDb *sqlDb = createSqlObject();
		if(!sqlDb->connect()) {
			delete sqlDb;
		}
		SqlDb_mysql *sqlDb_mysql = dynamic_cast<SqlDb_mysql*>(sqlDb);
		SqlDb *sqlDbSrc = new SqlDb_mysql();
		sqlDbSrc->setConnectParameters(opt_database_backup_from_mysql_host, 
					       opt_database_backup_from_mysql_user,
					       opt_database_backup_from_mysql_password,
					       opt_database_backup_from_mysql_database);
		if(sqlDbSrc->connect()) {
			SqlDb_mysql *sqlDbSrc_mysql = dynamic_cast<SqlDb_mysql*>(sqlDbSrc);
			sqlDb_mysql->copyFromSourceGuiTables(sqlDbSrc_mysql);
		}
		delete sqlDbSrc;
		delete sqlDb;
		}
		return;
	case 95:
		chdir(opt_chdir);
		check_filesindex();
		terminating = 1;
		break;
	case 96:
		{
		union {
			uint32_t i;
			char c[4];
		} e = { 0x01000000 };
		cout << "real endian : " << (e.c[0] ? "big" : "little") << endl;
		cout << "endian by cmp __BYTE_ORDER == __BIG_ENDIAN : ";
		#if __BYTE_ORDER == __BIG_ENDIAN
			cout << "big" << endl;
		#else
			cout << "little" << endl;
		#endif
		#ifdef __BYTE_ORDER
			cout << "__BYTE_ORDER value (1234 is little, 4321 is big) : " << __BYTE_ORDER << endl;
		#else
			cout << "undefined __BYTE_ORDER" << endl;
		#endif
		#ifdef BYTE_ORDER
			cout << "BYTE_ORDER value (1234 is little, 4321 is big) : " << BYTE_ORDER << endl;
		#else
			cout << "undefined BYTE_ORDER" << endl;
		#endif
		}
		break;
	case 97:
		{
		SqlDb *sqlDb = createSqlObject();
		SqlDb_mysql *sqlDb_mysql = dynamic_cast<SqlDb_mysql*>(sqlDb);
		
		sqlDb_mysql->dropFederatedTables();
		sqlDb->createSchema("127.0.0.1", "voipmonitor", "root");
		
		
		if(sqlDb_mysql->checkFederatedTables()) {
			sqlDb_mysql->copyFromFederatedTables();
		}
		
		//sqlDb_mysql->dropFederatedTables();
		
		}
		return;
	case 98:
		{
		RestartUpgrade restart(true, 
				       "8.4RC15",
				       "http://www.voipmonitor.org/senzor/download/8.4RC15",
				       "cf9c2b266204be6cef845003e713e6df",
				       "58e8ae1668b596cec20fd38aa7a83e23");
		restart.runUpgrade();
		cout << restart.getRsltString();
		}
		return;
	case 99:
		char *pointToSepOptTest = strchr(opt_test_str, '/');
		check_spooldir_filesindex(NULL, pointToSepOptTest ? pointToSepOptTest + 1 : NULL);
		return;
	}
 
	/*
	sqlDb->disconnect();
	sqlDb->connect();
	
	for(int pass = 0; pass < 3000; pass++) {
		cout << "pass " << (pass + 1) << endl;
		sqlDb->query("select * from cdr order by ID DESC");
		SqlDb_row row;
		row = sqlDb->fetchRow();
		cout << row["ID"] << " : " << row["calldate"] << endl;
		sleep(1);
	}
	*/
	
	/*
	if(opt_test >= 11 && opt_test <= 13) {
		rqueue<int> test;
		switch(opt_test) {
		case 11:
			test.push(1);
			test._test();
			break;
		case 12:
			test._testPerf(true);
			break;
		case 13:
			test._testPerf(false);
			break;
		}
		return;
	}
	*/

	/*
	int pipeFh[2];
	pipe(pipeFh);
	cout << pipeFh[0] << " / " << pipeFh[1] << endl;
	
	cout << "write" << endl;
	cout << "writed " << write(pipeFh[1], "1234" , 4) << endl;
	
	cout << "read" << endl;
	char buff[10];
	memset(buff, 0, 10);
	cout << "readed " << read(pipeFh[0], buff , 4) << endl;
	cout << buff;
	
	return;
	*/
	
	/*
	char filePathName[100];
	sprintf(filePathName, "/__test/store_%010u", 1);
	cout << filePathName << endl;
	remove(filePathName);
	int fileHandleWrite = open(filePathName, O_WRONLY | O_CREAT, 0666);
	cout << "write handle: " << fileHandleWrite << endl;
	//write(fileHandleWrite, "1234", 4);
	//close(fileHandleWrite);
	
	int fileHandleRead = open(filePathName, O_RDONLY);
	cout << "read handle: " << fileHandleRead << endl;
	cout << errno << endl;
	return;
	*/

	/*
	int port = 9001;
	
	PcapQueue_readFromInterface *pcapQueue0;
	PcapQueue_readFromFifo *pcapQueue1;
	PcapQueue_readFromFifo *pcapQueue2;
	
	if(opt_test == 1 || opt_test == 3) {
		pcapQueue0 = new PcapQueue_readFromInterface("thread0");
		pcapQueue0->setInterfaceName(ifname);
		//pcapQueue0->setFifoFileForWrite("/tmp/vm_fifo0");
		//pcapQueue0->setFifoWriteHandle(pipeFh[1]);
		pcapQueue0->setEnableAutoTerminate(false);
		
		pcapQueue1 = new PcapQueue_readFromFifo("thread1", "/__test");
		//pcapQueue1->setFifoFileForRead("/tmp/vm_fifo0");
		pcapQueue1->setInstancePcapHandle(pcapQueue0);
		//pcapQueue1->setFifoReadHandle(pipeFh[0]);
		pcapQueue1->setEnableAutoTerminate(false);
		//pcapQueue1->setPacketServer("127.0.0.1", port, PcapQueue_readFromFifo::directionWrite);
		
		pcapQueue0->start();
		pcapQueue1->start();
	}
	if(opt_test == 2 || opt_test == 3) {
		pcapQueue2 = new PcapQueue_readFromFifo("server", "/__test/2");
		pcapQueue2->setEnableAutoTerminate(false);
		pcapQueue2->setPacketServer("127.0.0.1", port, PcapQueue_readFromFifo::directionRead);
		
		pcapQueue2->start();
	}
	
	while(!terminating) {
		if(opt_test == 1 || opt_test == 3) {
			pcapQueue1->pcapStat();
		}
		if(opt_test == 2 || opt_test == 3) {
			pcapQueue2->pcapStat();
		}
		sleep(1);
	}
	
	if(opt_test == 1 || opt_test == 3) {
		pcapQueue0->terminate();
		sleep(1);
		pcapQueue1->terminate();
		sleep(1);
		
		delete pcapQueue0;
		delete pcapQueue1;
	}
	if(opt_test == 2 || opt_test == 3) {
		pcapQueue2->terminate();
		sleep(1);
		
		delete pcapQueue2;
	}
	return;
	*/
	
	/*
	sqlDb->disconnect();
	sqlDb->connect();
	
	sqlDb->query("select * from cdr order by ID DESC limit 2");
	SqlDb_row row1;
	while((row1 = sqlDb->fetchRow())) {
		cout << row1["ID"] << " : " << row1["calldate"] << endl;
	}
	
	return;
	*/

	/*
	cout << "db major version: " << sqlDb->getDbMajorVersion() << endl
	     << "db minor version: " << sqlDb->getDbMinorVersion() << endl
	     << "db minor version: " << sqlDb->getDbMinorVersion(1) << endl;
	*/
	
	/*
	initIpacc();
	extern CustPhoneNumberCache *custPnCache;
	cust_reseller cr;
	cr = custPnCache->getCustomerByPhoneNumber("0352307212");
	cout << cr.cust_id << " - " << cr.reseller_id << endl;
	*/
	
	/*
	extern CustIpCache *custIpCache;
	custIpCache->fetchAllIpQueryFromDb();
	*/
	
	/*
	for(int i = 1; i <= 10; i++) {
	sqlStore->lock(i);
	sqlStore->query("insert into _test set test = 1", i);
	sqlStore->query("insert into _test set test = 2", i);
	sqlStore->query("insert into _test set test = 3", i);
	sqlStore->query("insert into _test set test = 4", i);
	sqlStore->unlock(i);
	}
	terminating = true;
	//sleep(2);
	*/
	
	/*
	octects_live_t a;
	a.setFilter(string("192.168.1.2,192.168.1.1").c_str());
	cout << (a.isIpInFilter(inet_addr("192.168.1.1")) ? "find" : "----") << endl;
	cout << (a.isIpInFilter(inet_addr("192.168.1.3")) ? "find" : "----") << endl;
	cout << (a.isIpInFilter(inet_addr("192.168.1.2")) ? "find" : "----") << endl;
	cout << (a.isIpInFilter(inet_addr("192.168.1.3")) ? "find" : "----") << endl;
	*/
	
	/*
	extern void ipacc_add_octets(time_t timestamp, unsigned int saddr, unsigned int daddr, int port, int proto, int packetlen, int voippacket);
	extern void ipacc_save(unsigned int interval_time_limit = 0);

	//for(int i = 0; i < 100000; i++) {
	//	ipacc_add_octets(1, rand()%5000, rand()%5000, rand()%4, rand()%3, rand(), rand()%100);
	//}
	
	ipacc_add_octets(1, 1, 2, 3, 4, 5, 6);
	ipacc_add_octets(1, 1, 2, 3, 4, 5, 6);
	
	ipacc_save();
	
	freeMemIpacc();
	*/
	
	/*
	CustIpCache *custIpCache = new CustIpCache;
	custIpCache->setConnectParams(
		get_customer_by_ip_sql_driver, 
		get_customer_by_ip_odbc_dsn, 
		get_customer_by_ip_odbc_user, 
		get_customer_by_ip_odbc_password, 
		get_customer_by_ip_odbc_driver);
	custIpCache->setQueryes(
		get_customer_by_ip_query, 
		get_customers_ip_query);
	
	unsigned int cust_id = custIpCache->getCustByIp(inet_addr("192.168.1.241"));
	cout << cust_id << endl;
	
	return;
	
	cout << endl << endl;
	for(int i = 0; i < 20; i++) {
		cout << "iter:" << (i+1) << endl;
		unsigned int cust_id = custIpCache->getCustByIp(inet_addr("1.2.3.4"));
		cout << cust_id << endl;
		cust_id = custIpCache->getCustByIp(inet_addr("2.3.4.5"));
		cout << cust_id << endl;
		sleep(1);
	}
	
	return;
	*/
	
	/*
	ipfilter = new IPfilter;
	ipfilter->load();
	ipfilter->dump();

	telnumfilter = new TELNUMfilter;
	telnumfilter->load();
	telnumfilter->dump();
	*/
	
	/*
	sqlDb->query("select _LC_[UNIX_TIMESTAMP('1970-01-01') = 0] as eee;");
	SqlDb_row row = sqlDb->fetchRow();
	cout << row["eee"] << endl;
	*/
	
	/*
	// výmaz - příprava
	sqlDb->query("delete from cdr_sip_response where id > 0");
	cout << sqlDb->getLastErrorString() << endl;
	
	// čtení
	SqlDb_row row1;
	sqlDb->query("select * from cdr order by ID DESC");
	while((row1 = sqlDb->fetchRow())) {
		cout << row1["ID"] << " : " << row1["calldate"] << endl;
	}
	cout << sqlDb->getLastErrorString() << endl;
	
	// zápis
	SqlDb_row row2;
	row2.add("122 wrrrrrrrr", "lastSIPresponse");
	cout << sqlDb->insert("cdr_sip_response", row2) << endl;

	// unique zápis
	SqlDb_row row3;
	row3.add("123 wrrrrrrrr", "lastSIPresponse");
	cout << sqlDb->getIdOrInsert("cdr_sip_response", "id", "lastSIPresponse", row3) << endl;
	
	cout << sqlDb->getLastErrorString() << endl;
	cout << endl << "--------------" << endl;
	*/
	
	//exit(0);
}
