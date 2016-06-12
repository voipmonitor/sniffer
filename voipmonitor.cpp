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
#include <iomanip>
#include <sys/wait.h>

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
#include "sniff_proc_class.h"
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
#include "webrtc.h"
#include "ssldata.h"
#include "sip_tcp_data.h"
#include "ip_frag.h"
#include "cleanspool.h"
#include "regcache.h"
#include "fraud.h"
#include "rrd.h"
#include "heap_safe.h"
#include "tar.h"
#include "codec_alaw.h"
#include "codec_ulaw.h"
#include "send_call_info.h"
#include "config_param.h"

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

#ifdef HAVE_LIBGNUTLS
extern void ssl_init();
extern void ssl_clean();
#endif

using namespace std;

int debugclean = 0;


/* global variables */

extern Calltable *calltable;
extern volatile int calls_counter;
extern volatile int registers_counter;
unsigned int opt_openfile_max = 65535;
int opt_disable_dbupgradecheck = 0; // When voipmonitor started this disable mysql db check/upgrade (if set to 1)
int opt_packetbuffered = 0;	// Make .pcap files writing ‘‘packet-buffered’’ 
				// more slow method, but you can use partitialy 
				// writen file anytime, it will be consistent.
	
int opt_disableplc = 0 ;	// On or Off packet loss concealment			
int opt_rrd = 1;
int opt_silencethreshold = 512; //values range from 1 to 32767 default 512
int opt_passertedidentity = 0;	//Rewrite caller? If sip invite contain P-Asserted-Identity, caller num/name is overwritten by its values.
int opt_ppreferredidentity = 0;	//Rewrite caller? If sip invite contain P-Preferred-Identity, caller num/name is overwritten by its values.
int opt_remotepartyid = 0;	//Rewrite caller? If sip invite contain header Remote-Party-ID, caller num/name is overwritten by its values.
int opt_remotepartypriority = 0;//Defines rewrite caller order. If both headers are set/found and activated ( P-Preferred-Identity,Remote-Party-ID ), rewrite caller primary from Remote-Party-ID header (if set to 1). 
int opt_fork = 1;		// fork or run foreground 
int opt_saveSIP = 0;		// save SIP packets to pcap file?
int opt_saveRTP = 0;		// save RTP packets to pcap file?
int opt_onlyRTPheader = 0;	// do not save RTP payload, only RTP header
int opt_saveRTCP = 0;		// save RTCP packets to pcap file?
int opt_saveudptl = 0;		// if = 1 all UDPTL packets will be saved (T.38 fax)
int opt_faxt30detect = 0;	// if = 1 all sdp is activated (can take a lot of cpu)
int opt_saveRAW = 0;		// save RTP packets to pcap file?
int opt_saveWAV = 0;		// save RTP packets to pcap file?
int opt_saveGRAPH = 0;		// save GRAPH data to *.graph file? 
FileZipHandler::eTypeCompress opt_gzipGRAPH = FileZipHandler::lzo;
int opt_saverfc2833 = 0;
int opt_silencedetect = 0;
int opt_clippingdetect = 0;
int opt_dbdtmf = 0;
int opt_inbanddtmf = 0;
int opt_rtcp = 1;		// pair RTP+1 port to RTCP and save it. 
int opt_nocdr = 0;		// do not save cdr?
char opt_nocdr_for_last_responses[1024];
int nocdr_for_last_responses[100];
int nocdr_for_last_responses_length[100];
int nocdr_for_last_responses_count;
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
int opt_manager_nonblock_mode = 0;
int opt_rtpsave_threaded = 1;
int opt_norecord_header = 0;	// if = 1 SIP call with X-VoipMonitor-norecord header will be not saved although global configuration says to record. 
int opt_rtpnosip = 0;		// if = 1 RTP stream will be saved into calls regardless on SIP signalizatoin (handy if you need extract RTP without SIP)
int opt_norecord_dtmf = 0;	// if = 1 SIP call with dtmf == *0 sequence (in SIP INFO) will stop recording
int opt_savewav_force = 0;	// if = 1 WAV will be generated no matter on filter rules
int opt_sipoverlap = 1;		
int opt_id_sensor = -1;		
int opt_id_sensor_cleanspool = -1;		
char opt_name_sensor[256] = "";
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
int opt_ipacc_only_agregation = 0;
bool opt_ipacc_sniffer_agregate = false;
bool opt_ipacc_agregate_only_customers_on_main_side = true;
bool opt_ipacc_agregate_only_customers_on_any_side = true;
int opt_udpfrag = 1;
MirrorIP *mirrorip = NULL;
int opt_cdronlyanswered = 0;
int opt_cdronlyrtp = 0;
int opt_pcap_split = 1;
int opt_newdir = 1;
int opt_spooldir_by_sensor = 0;
int opt_spooldir_by_sensorname = 0;
char opt_clientmanager[1024] = "";
int opt_clientmanagerport = 9999;
int opt_callslimit = 0;
char opt_silencedtmfseq[16] = "";
char opt_silenceheader[128] = "";
int opt_pauserecordingdtmf_timeout = 4;
int opt_182queuedpauserecording = 0;
int opt_vlan_siprtpsame = 0;
char opt_keycheck[1024] = "";
char opt_convert_char[64] = "";
int opt_skinny = 0;
unsigned int opt_skinny_ignore_rtpip = 0;
int opt_read_from_file = 0;
char opt_read_from_file_fname[1024] = "";
bool opt_read_from_file_no_sip_reassembly = false;
char opt_pb_read_from_file[256] = "";
double opt_pb_read_from_file_speed = 0;
int opt_pb_read_from_file_acttime = 0;
unsigned int opt_pb_read_from_file_max_packets = 0;
int opt_dscp = 0;
int opt_cdrproxy = 1;
int opt_enable_http_enum_tables = 0;
int opt_enable_webrtc_table = 0;
int opt_generator = 0;
int opt_generator_channels = 1;
int opt_skipdefault = 0;
int opt_filesclean = 1;
int opt_enable_preprocess_packet = -1;
int opt_enable_process_rtp_packet = 1;
int process_rtp_packets_distribute_threads_use = 0;
int opt_process_rtp_packets_hash_next_thread = 1;
int opt_process_rtp_packets_hash_next_thread_sem_sync = 2;
unsigned int opt_preprocess_packets_qring_length = 2000;
unsigned int opt_preprocess_packets_qring_usleep = 10;
unsigned int opt_process_rtp_packets_qring_length = 2000;
unsigned int opt_process_rtp_packets_qring_usleep = 10;
int opt_enable_http = 0;
int opt_enable_webrtc = 0;
int opt_enable_ssl = 0;
unsigned int opt_ssl_link_timeout = 5 * 60;
int opt_tcpreassembly_thread = 1;
char opt_tcpreassembly_log[1024];
int opt_allow_zerossrc = 0;
int opt_convert_dlt_sll_to_en10 = 0;
int opt_mysqlcompress = 1;
int opt_mysql_enable_transactions = 0;
int opt_mysql_enable_transactions_cdr = 0;
int opt_mysql_enable_transactions_message = 0;
int opt_mysql_enable_transactions_register = 0;
int opt_mysql_enable_transactions_http = 0;
int opt_mysql_enable_transactions_webrtc = 0;
int opt_cdr_ua_enable = 1;
vector<string> opt_cdr_ua_reg_remove;
unsigned long long cachedirtransfered = 0;
unsigned int opt_maxpcapsize_mb = 0;
int opt_mosmin_f2 = 1;
bool opt_database_backup = false;
char opt_database_backup_from_date[20];
char opt_database_backup_from_mysql_host[256] = "";
char opt_database_backup_from_mysql_database[256] = "";
char opt_database_backup_from_mysql_user[256] = "";
char opt_database_backup_from_mysql_password[256] = "";
unsigned int opt_database_backup_from_mysql_port = 0;
int opt_database_backup_pause = 300;
int opt_database_backup_insert_threads = 1;
char opt_mos_lqo_bin[1024] = "pesq";
char opt_mos_lqo_ref[1024] = "/usr/local/share/voipmonitor/audio/mos_lqe_original.wav";
char opt_mos_lqo_ref16[1024] = "/usr/local/share/voipmonitor/audio/mos_lqe_original_16khz.wav";
regcache *regfailedcache;
int opt_onewaytimeout = 15;
int opt_saveaudio_reversestereo = 0;
float opt_saveaudio_oggquality = 0.4;
int opt_audioqueue_threads_max = 10;
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
int opt_autocleanspoolminpercent = 1;
int opt_autocleanmingb = 5;
int opt_cleanspool_enable_run_hour_from = -1;
int opt_cleanspool_enable_run_hour_to = -1;
int opt_mysqlloadconfig = 1;
int opt_last_rtp_from_end = 1;
int opt_pcap_dump_bufflength = 8192;
int opt_pcap_dump_asyncwrite = 1;
FileZipHandler::eTypeCompress opt_pcap_dump_zip_sip = FileZipHandler::compress_na;
FileZipHandler::eTypeCompress opt_pcap_dump_zip_rtp = 
	#ifdef HAVE_LIBLZO
		FileZipHandler::lzo;
	#else
		FileZipHandler::gzip;
	#endif //HAVE_LIBLZO
int opt_pcap_dump_ziplevel_sip = Z_DEFAULT_COMPRESSION;
int opt_pcap_dump_ziplevel_rtp = 1;
int opt_pcap_dump_ziplevel_graph = 1;
int opt_pcap_dump_writethreads = 1;
int opt_pcap_dump_writethreads_max = 32;
int opt_pcap_dump_asyncwrite_maxsize = 100; //MB
int opt_pcap_dump_tar = 1;
int opt_pcap_dump_tar_threads = 8;
int opt_pcap_dump_tar_compress_sip = 1; //0 off, 1 gzip, 2 lzma
int opt_pcap_dump_tar_sip_level = 6;
int opt_pcap_dump_tar_sip_use_pos = 0;
int opt_pcap_dump_tar_compress_rtp = 0;
int opt_pcap_dump_tar_rtp_level = 1;
int opt_pcap_dump_tar_rtp_use_pos = 0;
int opt_pcap_dump_tar_compress_graph = 0;
int opt_pcap_dump_tar_graph_level = 1;
int opt_pcap_dump_tar_graph_use_pos = 0;
CompressStream::eTypeCompress opt_pcap_dump_tar_internalcompress_sip = CompressStream::compress_na;
CompressStream::eTypeCompress opt_pcap_dump_tar_internalcompress_rtp = CompressStream::compress_na;
CompressStream::eTypeCompress opt_pcap_dump_tar_internalcompress_graph = CompressStream::compress_na;
int opt_pcap_dump_tar_internal_gzip_sip_level = Z_DEFAULT_COMPRESSION;
int opt_pcap_dump_tar_internal_gzip_rtp_level = Z_DEFAULT_COMPRESSION;
int opt_pcap_dump_tar_internal_gzip_graph_level = Z_DEFAULT_COMPRESSION;
int opt_defer_create_spooldir = 1;

int opt_sdp_multiplication = 3;
string opt_save_sip_history;
bool _save_sip_history;
bool _save_sip_history_request_types[1000];
bool _save_sip_history_all_requests;
bool _save_sip_history_all_responses;
bool opt_cdr_sipresp = false;
bool opt_rtpmap_by_callerd = false;
bool opt_disable_rtp_warning = false;

char opt_php_path[1024];

struct pcap_stat pcapstat;

extern u_int opt_pcap_queue_block_max_time_ms;
extern size_t opt_pcap_queue_block_max_size;
extern u_int opt_pcap_queue_file_store_max_time_ms;
extern size_t opt_pcap_queue_file_store_max_size;
extern uint64_t opt_pcap_queue_store_queue_max_memory_size;
extern uint64_t opt_pcap_queue_store_queue_max_disk_size;
extern uint64_t opt_pcap_queue_bypass_max_size;
extern int opt_pcap_queue_compress;
extern pcap_block_store::compress_method opt_pcap_queue_compress_method;
extern string opt_pcap_queue_disk_folder;
extern ip_port opt_pcap_queue_send_to_ip_port;
extern ip_port opt_pcap_queue_receive_from_ip_port;
extern int opt_pcap_queue_receive_dlt;
extern int opt_pcap_queue_iface_qring_size;
extern int opt_pcap_queue_dequeu_window_length;
extern int opt_pcap_queue_dequeu_need_blocks;
extern int opt_pcap_queue_dequeu_method;
extern int opt_pcap_queue_use_blocks;
extern int opt_pcap_queue_suppress_t1_thread;
extern bool opt_pcap_queues_mirror_nonblock_mode;
extern int opt_pcap_dispatch;
extern int sql_noerror;
int opt_cleandatabase_cdr = 0;
int opt_cleandatabase_http_enum = 0;
int opt_cleandatabase_webrtc = 0;
int opt_cleandatabase_register_state = 0;
int opt_cleandatabase_register_failed = 0;
int opt_cleandatabase_rtp_stat = 2;
unsigned int graph_delimiter = GRAPH_DELIMITER;
unsigned int graph_version = GRAPH_VERSION;
unsigned int graph_mark = GRAPH_MARK;
unsigned int graph_mos = GRAPH_MOS;
unsigned int graph_silence = GRAPH_SILENCE;
unsigned int graph_event = GRAPH_EVENT;
int opt_mos_lqo = 0;

bool opt_cdr_partition = 1;
bool opt_cdr_sipport = 0;
bool opt_cdr_rtpport = 0;
bool opt_cdr_rtpsrcport  = 0;
bool opt_cdr_check_exists_callid = 0;
bool opt_cdr_check_duplicity_callid_in_next_pass_insert = 0;
bool opt_message_check_duplicity_callid_in_next_pass_insert = 0;
int opt_create_old_partitions = 0;
char opt_create_old_partitions_from[20];
bool opt_disable_partition_operations = 0;
bool opt_partition_operations_in_thread = 1;
bool opt_autoload_from_sqlvmexport = 0;
vector<dstring> opt_custom_headers_cdr;
vector<dstring> opt_custom_headers_message;
CustomHeaders *custom_headers_cdr;
CustomHeaders *custom_headers_message;
int opt_custom_headers_last_value = 1;
bool opt_sql_time_utc = false;

char configfile[1024] = "";	// config file name

char sql_driver[256] = "mysql";
char sql_cdr_table[256] = "cdr";
char sql_cdr_table_last30d[256] = "";
char sql_cdr_table_last7d[256] = "";
char sql_cdr_table_last1d[256] = "";
char sql_cdr_next_table[256] = "cdr_next";
char sql_cdr_ua_table[256] = "cdr_ua";
char sql_cdr_sip_response_table[256] = "cdr_sip_response";
char sql_cdr_sip_request_table[256] = "cdr_sip_request";
char sql_cdr_reason_table[256] = "cdr_reason";

char mysql_host[256] = "127.0.0.1";
char mysql_host_orig[256] = "";
char mysql_database[256] = "voipmonitor";
char mysql_user[256] = "root";
char mysql_password[256] = "";
int opt_mysql_port = 0; // 0 menas use standard port 

char mysql_2_host[256] = "";
char mysql_2_host_orig[256] = "";
char mysql_2_database[256] = "voipmonitor";
char mysql_2_user[256] = "root";
char mysql_2_password[256] = "";
int opt_mysql_2_port = 0; // 0 menas use standard port 
bool opt_mysql_2_http = false;

char opt_mysql_timezone[256] = "";
int opt_mysql_client_compress = 0;
char opt_timezone[256] = "";
int opt_skiprtpdata = 0;

char opt_fbasename_header[128] = "";
char opt_match_header[128] = "";
char opt_callidmerge_header[128] = "";
char opt_callidmerge_secret[128] = "";

char odbc_dsn[256] = "voipmonitor";
char odbc_user[256];
char odbc_password[256];
char odbc_driver[256];

char cloud_url_activecheck[1024] = "https://cloud.voipmonitor.org/reg/check_active.php";	//option in voipmonitor.conf cloud_url_activecheck
int opt_cloud_activecheck_period = 60;				//0 = disable, how often to check if cloud tunnel is passable in [sec.]
int cloud_activecheck_timeout = 5;				//2sec by default, how long to wait for response until restart of a cloud tunnel
volatile bool cloud_activecheck_inprogress = false;		//is currently checking in progress?
volatile bool cloud_activecheck_sshclose = false;		//is forced close/re-open of ssh forward thread?
timeval cloud_last_activecheck;					//Time of a last check request sent

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
bool get_radius_ip_disable_secure_auth = false;
char get_radius_ip_query[1024];
char get_radius_ip_query_where[1024];
int get_customer_by_ip_flush_period = 1;

char opt_pidfile[4098] = "/var/run/voipmonitor.pid";

char user_filter[1024*20] = "";
eSnifferMode sniffer_mode = snifferMode_read_from_interface;
char ifname[1024];	// Specifies the name of the network device to use for 
			// the network lookup, for example, eth0
char opt_scanpcapdir[2048] = "";	// Specifies the name of the network device to use for 
bool opt_scanpcapdir_disable_inotify = false;
#ifndef FREEBSD
uint32_t opt_scanpcapmethod = IN_CLOSE_WRITE; // Specifies how to watch for new files in opt_scanpcapdir
#endif
int opt_promisc = 1;	// put interface to promisc mode?
int opt_use_oneshot_buffer = 1;
char pcapcommand[4092] = "";
char filtercommand[4092] = "";

int rtp_threaded = 0;
int num_threads_set = 0;
int num_threads_max = 0;
volatile int num_threads_active = 0;
unsigned int rtpthreadbuffer = 20;	// default 20MB
unsigned int rtp_qring_length = 0;
unsigned int rtp_qring_usleep = 100;
int rtp_qring_quick = 1;
unsigned int gthread_num = 0;

int opt_pcapdump = 0;
int opt_pcapdump_all = 0;
char opt_pcapdump_all_path[1024];

int opt_callend = 1; //if true, cdr.called is saved
char opt_chdir[1024];
char opt_cachedir[1024];

int opt_upgrade_try_http_if_https_fail = 0;

IPfilter *ipfilter = NULL;				// IP filter based on MYSQL 
IPfilter *ipfilter_reload = NULL;			// IP filter based on MYSQL for reload purpose
volatile int ipfilter_reload_do = 0;			// for reload in main thread

TELNUMfilter *telnumfilter = NULL;			// TELNUM filter based on MYSQL 
TELNUMfilter *telnumfilter_reload = NULL;		// TELNUM filter based on MYSQL for reload purpose
volatile int telnumfilter_reload_do = 0;		// for reload in main thread

DOMAINfilter *domainfilter = NULL;			// DOMAIN filter based on MYSQL 
DOMAINfilter *domainfilter_reload = NULL;		// DOMAIN filter based on MYSQL for reload purpose
volatile int domainfilter_reload_do = 0;		// for reload in main thread

SIP_HEADERfilter *sipheaderfilter = NULL;		// SIP_HEADER filter based on MYSQL 
SIP_HEADERfilter *sipheaderfilter_reload = NULL;	// SIP_HEADER filter based on MYSQL for reload purpose
volatile int sipheaderfilter_reload_do = 0;		// for reload in main thread

pthread_t storing_cdr_thread;		// ID of worker storing CDR thread 
pthread_t storing_registers_thread;	// ID of worker storing CDR thread 
pthread_t activechecking_cloud_thread; 
pthread_t scanpcapdir_thread;
pthread_t defered_service_fork_thread;
//pthread_t destroy_calls_thread;
pthread_t manager_thread = 0;	// ID of worker manager thread 
pthread_t manager_client_thread;	// ID of worker manager thread 
pthread_t manager_ssh_thread;	
pthread_t cachedir_thread;	// ID of worker cachedir thread 
pthread_t database_backup_thread;	// ID of worker backup thread 
pthread_t tarqueuethread;	// ID of worker manager thread 
int terminating;		// if set to 1, sniffer will terminate
int terminating_moving_cache;	// if set to 1, worker thread will terminate
int terminating_storing_cdr;	// if set to 1, worker thread will terminate
int terminating_storing_registers;
int terminated_call_cleanup;
int terminated_async;
int terminated_tar_flush_queue;
int terminated_tar;
int hot_restarting;
string hot_restarting_json_config;
vm_atomic<string> terminating_error;
char *sipportmatrix;		// matrix of sip ports to monitor
char *httpportmatrix;		// matrix of http ports to monitor
char *webrtcportmatrix;		// matrix of webrtc ports to monitor
char *ipaccountportmatrix;
map<d_u_int32_t, string> ssl_ipport;
vector<u_int32_t> httpip;
vector<d_u_int32_t> httpnet;
vector<u_int32_t> webrtcip;
vector<d_u_int32_t> webrtcnet;

int opt_sdp_reverse_ipport = 0;

volatile unsigned int pcap_readit = 0;
volatile unsigned int pcap_writeit = 0;
int global_livesniffer = 0;

pcap_t *global_pcap_handle = NULL;		// pcap handler 
u_int16_t global_pcap_handle_index = 0;
pcap_t *global_pcap_handle_dead_EN10MB = NULL;
u_int16_t global_pcap_handle_dead_EN10MB_index = 0;

rtp_read_thread *rtp_threads;

int manager_socket_server = 0;

pthread_mutex_t mysqlconnect_lock;
pthread_mutex_t vm_rrd_lock;
pthread_mutex_t hostbyname_lock;

pthread_t pcap_read_thread;

nat_aliases_t nat_aliases;	// net_aliases[local_ip] = extern_ip

MySqlStore *sqlStore = NULL;
MySqlStore *sqlStore_2 = NULL;
MySqlStore *loadFromQFiles = NULL;

char mac[32] = "";

PcapQueue_readFromInterface *pcapQueueInterface;
PcapQueue *pcapQueueStatInterface;

PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end];
ProcessRtpPacket *processRtpPacketHash;
ProcessRtpPacket *processRtpPacketDistribute[MAX_PROCESS_RTP_PACKET_THREADS];

TcpReassembly *tcpReassemblyHttp;
TcpReassembly *tcpReassemblyWebrtc;
TcpReassembly *tcpReassemblySsl;
TcpReassembly *tcpReassemblySipExt;
HttpData *httpData;
WebrtcData *webrtcData;
SslData *sslData;
SipTcpData *sipTcpData;

vm_atomic<string> storingCdrLastWriteAt;
vm_atomic<string> storingRegisterLastWriteAt;

time_t startTime;

sem_t *globalSemaphore;

bool opt_loadsqlconfig = true;

int opt_mysqlstore_concat_limit = 0;
int opt_mysqlstore_concat_limit_cdr = 0;
int opt_mysqlstore_concat_limit_message = 0;
int opt_mysqlstore_concat_limit_register = 0;
int opt_mysqlstore_concat_limit_http = 0;
int opt_mysqlstore_concat_limit_webrtc = 0;
int opt_mysqlstore_concat_limit_ipacc = 0;
int opt_mysqlstore_max_threads_cdr = 1;
int opt_mysqlstore_max_threads_message = 1;
int opt_mysqlstore_max_threads_register = 1;
int opt_mysqlstore_max_threads_http = 1;
int opt_mysqlstore_max_threads_webrtc = 1;
int opt_mysqlstore_max_threads_ipacc_base = 3;
int opt_mysqlstore_max_threads_ipacc_agreg2 = 3;
int opt_mysqlstore_limit_queue_register = 1000000;

char opt_curlproxy[256] = "";
int opt_enable_fraud = 1;
char opt_local_country_code[10] = "local";

map<string, string> hosts;

ip_port sipSendSocket_ip_port;
SocketSimpleBufferWrite *sipSendSocket = NULL;
int opt_sip_send_udp;
int opt_sip_send_before_packetbuffer = 0;

int opt_enable_jitterbuffer_asserts = 0;
int opt_hide_message_content = 0;
char opt_hide_message_content_secret[1024] = "";

char opt_bogus_dumper_path[1204];
BogusDumper *bogusDumper;

char opt_syslog_string[256];
int opt_cpu_limit_warning_t0 = 60;
int opt_cpu_limit_new_thread = 50;
int opt_cpu_limit_delete_thread = 5;
int opt_cpu_limit_delete_t2sip_thread = 17;

extern pthread_mutex_t tartimemaplock;

TarQueue *tarQueue = NULL;

pthread_mutex_t terminate_packetbuffer_lock;

extern ParsePacket _parse_packet_global_process_packet;

cBuffersControl buffersControl;

u_int64_t rdtsc_by_100ms;

char opt_git_folder[1024];
bool opt_upgrade_by_git;

bool opt_save_query_to_files;
char opt_save_query_to_files_directory[1024];
int opt_save_query_to_files_period;
int opt_query_cache_speed;

int opt_load_query_from_files;
char opt_load_query_from_files_directory[1024];
int opt_load_query_from_files_period;
bool opt_load_query_from_files_inotify;

bool opt_virtualudppacket = false;
bool opt_sip_tcp_reassembly_ext = false;

int opt_test = 0;

char *opt_untar_gui_params = NULL;
char *opt_unlzo_gui_params = NULL;
char *opt_waveform_gui_params = NULL;
char *opt_spectrogram_gui_params = NULL;
char opt_test_str[1024];

map<int, string> command_line_data;
cConfig CONFIG;
bool useNewCONFIG = 0;
bool printConfigStruct = false;
bool updateSchema = false;

SensorsMap sensorsMap;


#include <stdio.h>
#include <pthread.h>
#include <openssl/err.h>
 
#define MUTEX_TYPE       pthread_mutex_t
#define MUTEX_SETUP(x)   pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x)    pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x)  pthread_mutex_unlock(&(x))
#define THREAD_ID        pthread_self(  )


static void parse_command_line_arguments(int argc, char *argv[]);
static void get_command_line_arguments();
static void set_context_config();
static bool check_complete_parameters();
static void dns_lookup_common_hostnames();
static void parse_opt_nocdr_for_last_responses();
 
 
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
 
  mutex_buf = new FILE_LINE MUTEX_TYPE[CRYPTO_num_locks()];
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
  delete [] mutex_buf;
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

void vm_terminate() {
	set_terminating();
}

void vm_terminate_error(const char *terminate_error) {
	terminating_error = terminate_error;
	set_terminating();
}

bool is_terminating_without_error() {
	string _terminate_error = terminating_error;
	return(is_terminating() &&
	       (!useNewCONFIG || _terminate_error.empty()));
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
	vm_terminate();
	#if ENABLE_SEMAPHOR_FORK_MODE
	exit_handler_fork_mode();
	#endif
}

/* handler for TERMINATE signal */
void sigterm_handler(int param)
{
	syslog(LOG_ERR, "SIGTERM received, terminating\n");
	vm_terminate();
	#if ENABLE_SEMAPHOR_FORK_MODE
	exit_handler_fork_mode();
	#endif
}

#define childPidsExit_max 10
struct sPidInfo { 
	sPidInfo(pid_t pid = 0, int exitCode = 0) { this->pid = pid, this->exitCode = exitCode; }
	volatile pid_t pid; volatile int exitCode; 
};
volatile unsigned childPidsExit_count;
sPidInfo childPidsExit[childPidsExit_max];
void sigchld_handler(int param)
{
	pid_t childpid;
	int status;
	while((childpid = waitpid(-1, &status, WNOHANG)) > 0) {
		for(unsigned i = 0; i < childPidsExit_max - 1; i++) {
			childPidsExit[i].exitCode = childPidsExit[i + 1].exitCode;
			childPidsExit[i].pid = childPidsExit[i + 1].pid;
		}
		childPidsExit[childPidsExit_max - 1].exitCode = WEXITSTATUS(status);
		childPidsExit[childPidsExit_max - 1].pid = childpid;
	}
}
bool isChildPidExit(unsigned pid) {
	for(unsigned i = 0; i < childPidsExit_max; i++) {
		if((unsigned)childPidsExit[i].pid == pid) {
			return(true);
		}
	}
	return(false);
}
int getChildPidExitCode(unsigned pid) {
	for(unsigned i = 0; i < childPidsExit_max; i++) {
		if((unsigned)childPidsExit[i].pid == pid) {
			return(childPidsExit[i].exitCode);
		}
	}
	return(-1);
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
	sqlStore = new FILE_LINE MySqlStore(mysql_host, mysql_user, mysql_password, mysql_database, opt_mysql_port);
	bool callCreateSchema = false;
	while(!is_terminating()) {
		syslog(LOG_NOTICE, "-- START BACKUP PROCESS");
		
		SqlDb *sqlDbSrc = new FILE_LINE SqlDb_mysql();
		sqlDbSrc->setConnectParameters(opt_database_backup_from_mysql_host, 
					       opt_database_backup_from_mysql_user,
					       opt_database_backup_from_mysql_password,
					       opt_database_backup_from_mysql_database,
					       opt_database_backup_from_mysql_port);
		if(sqlDbSrc->connect()) {
			SqlDb_mysql *sqlDbSrc_mysql = dynamic_cast<SqlDb_mysql*>(sqlDbSrc);
			if(sqlDbSrc_mysql->checkSourceTables()) {
			 
				if(!callCreateSchema) {
					sqlDb->createSchema();
					sqlDb->checkSchema();
					callCreateSchema = true;
				}
				
				sqlDb_mysql->copyFromSourceTablesMinor(sqlDbSrc_mysql);
			
				if(custom_headers_cdr) {
					custom_headers_cdr->refresh(sqlDbSrc);
					custom_headers_cdr->createColumnsForFixedHeaders(sqlDb);
					custom_headers_cdr->createTablesIfNotExists(sqlDb);
				}
				if(custom_headers_message) {
					custom_headers_message->refresh(sqlDbSrc);
					custom_headers_message->createColumnsForFixedHeaders(sqlDb);
					custom_headers_message->createTablesIfNotExists(sqlDb);
				}
			
				time_t actTime = time(NULL);
				if(actTime - createPartitionAt > 12 * 3600) {
					createMysqlPartitionsCdr();
					createPartitionAt = actTime;
				}
				if(actTime - dropPartitionAt > 12 * 3600) {
					dropMysqlPartitionsCdr();
					dropPartitionAt = actTime;
				}
			 
				sqlDb_mysql->copyFromSourceTablesMain(sqlDbSrc_mysql);
			}
		}
		delete sqlDbSrc;
		
		while(is_terminating() < 2 && sqlStore->getAllSize()) {
			syslog(LOG_NOTICE, "flush sqlStore");
			sleep(1);
		}
		
		syslog(LOG_NOTICE, "-- END BACKUP PROCESS");
		
		if(sverb.memory_stat_log) {
			printMemoryStat();
		}
		
		for(int i = 0; i < opt_database_backup_pause && !is_terminating(); i++) {
			sleep(1);
		}
	}
	sqlStore->setEnableTerminatingIfSqlError(0, true);
	while(is_terminating() < 2 && sqlStore->getAllSize()) {
		syslog(LOG_NOTICE, "flush sqlStore");
		sleep(1);
	}
	sqlStore->setEnableTerminatingIfEmpty(0, true);
	delete sqlDb;
	delete sqlStore;
	sqlStore = NULL;
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
		if(terminating_moving_cache) {
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

class sCreatePartitions {
public:
	sCreatePartitions() {
		init();
	}
	void init() {
		createCdr = false;
		dropCdr = false;
		createRtpStat = false;
		dropRtpStat = false;
		createIpacc = false;
		createBilling = false;
		_runInThread = false;
	}
	bool isSet() {
		return(createCdr || dropCdr || 
		       createRtpStat || dropRtpStat ||
		       createIpacc || createBilling);
	}
	void createPartitions(bool inThread = false) {
		if(isSet()) {
			bool successStartThread = false;
			if(inThread) {
				sCreatePartitions *createPartitionsData = new FILE_LINE sCreatePartitions;
				*createPartitionsData = *this;
				createPartitionsData->_runInThread = true;
				pthread_t thread;
				successStartThread = vm_pthread_create_autodestroy("create partitions",
										   &thread, NULL, _createPartitions, createPartitionsData, __FILE__, __LINE__) == 0;
			}
			if(!inThread || !successStartThread) {
				this->_runInThread = false;
				_createPartitions(this);
			}
		}
	}
	static void *_createPartitions(void *arg);
public:
	bool createCdr;
	bool dropCdr;
	bool createRtpStat;
	bool dropRtpStat;
	bool createIpacc;
	bool createBilling;
	bool _runInThread;
} createPartitions;

void *sCreatePartitions::_createPartitions(void *arg) {
	sCreatePartitions *createPartitionsData = (sCreatePartitions*)arg;
	if(createPartitionsData->createCdr) {
		createMysqlPartitionsCdr();
	}
	if(createPartitionsData->dropCdr) {
		dropMysqlPartitionsCdr();
	}
	if(createPartitionsData->createRtpStat) {
		createMysqlPartitionsRtpStat();
	}
	if(createPartitionsData->dropRtpStat) {
		dropMysqlPartitionsRtpStat();
	}
	if(createPartitionsData->createIpacc) {
		createMysqlPartitionsIpacc();
	}
	if(createPartitionsData->createBilling) {
		createMysqlPartitionsBillingAgregation();
	}
	if(createPartitionsData->_runInThread) {
		delete createPartitionsData;
	}
	return(NULL);
}

class sCheckIdCdrChildTables {
public:
	sCheckIdCdrChildTables() {
		init();
	}
	void init() {
		check = false;
	}
	bool isSet() {
		return(check);
	}
	void checkIdCdrChildTables(bool inThread = false) {
		if(isSet()) {
			if(inThread) {
				pthread_t thread;
				vm_pthread_create_autodestroy("check child cdr id",
							      &thread, NULL, _checkIdCdrChildTables, this, __FILE__, __LINE__);
			} else {
				_checkIdCdrChildTables(this);
			}
		}
	}
	static void *_checkIdCdrChildTables(void *arg);
public:
	bool check;
} checkIdCdrChildTables;

void *sCheckIdCdrChildTables::_checkIdCdrChildTables(void *arg) {
	sCheckIdCdrChildTables *checkIdCdrChildTables = (sCheckIdCdrChildTables*)arg;
	if(checkIdCdrChildTables->check) {
		checkMysqlIdCdrChildTables();
	}
	return(NULL);
}

void *defered_service_fork(void *) {
	dns_lookup_common_hostnames();
	return(NULL);
}

/* cycle calls_queue and save it to MySQL */
void *storing_cdr( void *dummy ) {
	Call *call;
	time_t createPartitionAt = 0;
	time_t dropPartitionAt = 0;
	time_t createPartitionRtpStatAt = 0;
	time_t dropPartitionRtpStatAt = 0;
	time_t createPartitionIpaccAt = 0;
	time_t createPartitionBillingAgregationAt = 0;
	time_t checkMysqlIdCdrChildTablesAt = 0;
	bool firstIter = true;
	while(1) {
		createPartitions.init();
		if(!opt_nocdr and opt_cdr_partition and !opt_disable_partition_operations and isSqlDriver("mysql")) {
			time_t actTime = time(NULL);
			if(actTime - createPartitionAt > 12 * 3600) {
				createPartitions.createCdr = true;
				createPartitionAt = actTime;
			}
			if(actTime - dropPartitionAt > 12 * 3600) {
				createPartitions.dropCdr = true;
				dropPartitionAt = actTime;
			}
		}
		if(!opt_nocdr and !opt_disable_partition_operations and isSqlDriver("mysql")) {
			time_t actTime = time(NULL);
			if(actTime - createPartitionRtpStatAt > 12 * 3600) {
				createPartitions.createRtpStat = true;
				createPartitionRtpStatAt = actTime;
			}
			if(actTime - dropPartitionRtpStatAt > 12 * 3600) {
				createPartitions.dropRtpStat = true;
				dropPartitionRtpStatAt = actTime;
			}
		}
		if(!opt_nocdr and opt_ipaccount and !opt_disable_partition_operations and isSqlDriver("mysql")) {
			time_t actTime = time(NULL);
			if(actTime - createPartitionIpaccAt > 12 * 3600) {
				createPartitions.createIpacc = true;
				createPartitionIpaccAt = actTime;
			}
		}
		if(!opt_nocdr and !opt_disable_partition_operations and isSqlDriver("mysql")) {
			time_t actTime = time(NULL);
			if(actTime - createPartitionBillingAgregationAt > 12 * 3600) {
				createPartitions.createBilling = true;
				createPartitionBillingAgregationAt = actTime;
			}
		}
		if(createPartitions.isSet()) {
			createPartitions.createPartitions(!firstIter && opt_partition_operations_in_thread);
		}
		checkIdCdrChildTables.init();
		if(!opt_nocdr and opt_cdr_partition and !opt_disable_partition_operations) {
			time_t actTime = time(NULL);
			if(actTime - checkMysqlIdCdrChildTablesAt > 1 * 3600) {
				checkIdCdrChildTables.check = true;
				checkMysqlIdCdrChildTablesAt = actTime;
			}
		}
		if(checkIdCdrChildTables.isSet()) {
			checkIdCdrChildTables.checkIdCdrChildTables(!firstIter && opt_partition_operations_in_thread);
		}
		firstIter = false;
		
		if(request_iptelnum_reload == 1) { reload_capture_rules(); request_iptelnum_reload = 0;}
		
		if(verbosity > 0 && is_read_from_file_simple()) { 
			ostringstream outStr;
			outStr << "calls[" << calls_counter << ",r:" << registers_counter << "]";
		}
		
		size_t calls_queue_size = 0;
		
		for(int pass  = 0; pass < 10; pass++) {
		
			calltable->lock_calls_queue();
			calls_queue_size = calltable->calls_queue.size();
			size_t calls_queue_position = 0;
			
			while(calls_queue_position < calls_queue_size) {

				call = calltable->calls_queue[calls_queue_position];
				
				calltable->unlock_calls_queue();
				
				// Close SIP and SIP+RTP dump files ASAP to save file handles
				call->getPcap()->close();
				call->getPcapSip()->close();
				
				if(call->isReadyForWriteCdr()) {
				
					bool needConvertToWavInThread = false;
					call->closeRawFiles();
					if( (opt_savewav_force || (call->flags & FLAG_SAVEAUDIO)) && (call->type == INVITE || call->type == SKINNY_NEW) &&
					    call->getAllReceivedRtpPackets()) {
						if(is_read_from_file()) {
							if(verbosity > 0) printf("converting RAW file to WAV Queue[%d]\n", (int)calltable->calls_queue.size());
							call->convertRawToWav();
						} else {
							needConvertToWavInThread = true;
						}
					}

					regfailedcache->prunecheck(call->first_packet_time);
					if(!opt_nocdr) {
						if(call->type == INVITE or call->type == SKINNY_NEW) {
							call->saveToDb(!is_read_from_file_simple());
						} else if(call->type == MESSAGE){
							call->saveMessageToDb();
						}
					}

					/* if we delete call here directly, destructors and another cleaning functions can be
					 * called in the middle of working with call or another structures inside main thread
					 * so put it in deletequeue and delete it in the main thread. Another way can be locking
					 * call structure for every case in main thread but it can slow down thinks for each 
					 * processing packet.
					*/
					calltable->lock_calls_queue();
					calltable->calls_queue.erase(calltable->calls_queue.begin() + calls_queue_position);
					--calls_queue_size;
					
					if(needConvertToWavInThread) {
						calltable->lock_calls_audioqueue();
						calltable->audio_queue.push_back(call);
						calltable->processCallsInAudioQueue(false);
						calltable->unlock_calls_audioqueue();
					} else {
						calltable->lock_calls_deletequeue();
						calltable->calls_deletequeue.push_back(call);
						calltable->unlock_calls_deletequeue();
					}
					storingCdrLastWriteAt = getActDateTimeF();
				} else {
					calltable->lock_calls_queue();
				}
				
				++calls_queue_position;
				
			}
			
			calltable->unlock_calls_queue();

			if(terminating_storing_cdr && (!calls_queue_size || terminating > 1)) {
				break;
			}
		
			usleep(100000);
		}
		
		calltable->lock_calls_queue();
		calls_queue_size = calltable->calls_queue.size();
		if(terminating_storing_cdr && (!calls_queue_size || terminating > 1)) {
			calltable->unlock_calls_queue();
			break;
		}
		calltable->unlock_calls_queue();
	}
	if(verbosity && !opt_nocdr) {
		syslog(LOG_NOTICE, "terminated - storing cdr / message / register");
	}
	if(terminating < 2) {
		int _terminating = terminating;
		while(terminating == _terminating) {
			calltable->lock_calls_audioqueue();
			size_t callsInAudioQueue = calltable->audio_queue.size();
			calltable->unlock_calls_audioqueue();
			if(!callsInAudioQueue) {
				break;
			}
			syslog(LOG_NOTICE, "wait for convert audio for %lu calls (or next terminating)", callsInAudioQueue);
			for(int i = 0; i < 10 && terminating == _terminating; i++) {
				usleep(100000);
			}
		}
	}
	calltable->setAudioQueueTerminating();
	while(true) {
		calltable->lock_calls_audioqueue();
		size_t audioQueueThreads = calltable->getCountAudioQueueThreads();
		calltable->unlock_calls_audioqueue();
		if(!audioQueueThreads) {
			break;
		}
		usleep(100000);
	}
	
	return NULL;
}

void *storing_registers( void *dummy ) {
	Call *call;
	while(1) {
		
		size_t registers_queue_size = 0;
		
		for(int pass  = 0; pass < 10; pass++) {
		
			calltable->lock_registers_queue();
			registers_queue_size = calltable->registers_queue.size();
			size_t registers_queue_position = 0;
			
			while(registers_queue_position < registers_queue_size) {

				call = calltable->registers_queue[registers_queue_position];
				
				calltable->unlock_registers_queue();
				
				// Close SIP and SIP+RTP dump files ASAP to save file handles
				call->getPcap()->close();
				call->getPcapSip()->close();
				
				if(call->isReadyForWriteCdr()) {
				
					regfailedcache->prunecheck(call->first_packet_time);
					if(!opt_nocdr) {
						if(call->type == REGISTER){
							call->saveRegisterToDb();
						}
					}

					calltable->lock_registers_queue();
					calltable->registers_queue.erase(calltable->registers_queue.begin() + registers_queue_position);
					--registers_queue_size;
					
					calltable->lock_registers_deletequeue();
					calltable->registers_deletequeue.push_back(call);
					calltable->unlock_registers_deletequeue();
				
					storingRegisterLastWriteAt = getActDateTimeF();
				} else {
					calltable->lock_registers_queue();
				}
				
				++registers_queue_position;
				
			}
			
			calltable->unlock_registers_queue();

			if(terminating_storing_registers && (!registers_queue_size || terminating > 1)) {
				break;
			}
		
			usleep(100000);
		}
		
		calltable->lock_registers_queue();
		registers_queue_size = calltable->registers_queue.size();
		if(terminating_storing_registers && (!registers_queue_size || terminating > 1)) {
			calltable->unlock_registers_queue();
			break;
		}
		calltable->unlock_registers_queue();
	}
	if(verbosity && !opt_nocdr) {
		syslog(LOG_NOTICE, "terminated - storing register");
	}
	
	return NULL;
}

void cloud_initial_register( void ) {
	if (verbosity) syslog(LOG_NOTICE, "activechecking cloud initial register");
	do {
		if (cloud_register()) break;
		sleep(2);
	} while (terminating == 0);
}

void *activechecking_cloud( void *dummy ) {
	if (verbosity) syslog(LOG_NOTICE, "start - activechecking cloud thread");
	cloud_activecheck_set();

	do {
		if (cloud_now_timeout()) {				//no reply in timeout? (re-register, recreate ssh)
			if (!cloud_register()){
				syslog(LOG_WARNING, "Repeating send cloud registration request");
				sleep(2);				//what to do if unable to register to a cloud?
				continue;
			}
			cloud_activecheck_sshclose = true;		//we need ssh tunnel recreation - after obtained new data from register
									//now we need for flag get back to false - we know then that we are ready for activechecks
			do {
				if (terminating) break;
				sleep(2);
			} while (cloud_activecheck_sshclose);

			cloud_activecheck_start();
			do {
				if (cloud_activecheck_send()||terminating) break;
				syslog(LOG_WARNING, "Repeating send activecheck request");
				sleep(2);				//what to do if unable to send check request to a cloud [repeat undefinitely]
				continue;
			} while (terminating == 0);
			cloud_activecheck_set();
		}

		if (cloud_now_activecheck()) {				//is time to start activecheck?
			cloud_activecheck_start();
			if (verbosity) syslog(LOG_DEBUG, "Sending cloud activecheck request");
			do {
				if(cloud_activecheck_send()||terminating) break;
				syslog(LOG_WARNING, "Repeating activecheck request");
				sleep(2);				//what to do if unable to send check request to a cloud [repeat undefinitely]
			} while (terminating == 0);
			cloud_activecheck_set();
		}
		sleep(1);
        } while (terminating == 0);
	if(verbosity) syslog(LOG_NOTICE, "terminated - cloud activecheck thread");
	return NULL;
}

void *scanpcapdir( void *dummy ) {
 
#ifndef FREEBSD
 
	while(!pcapQueueInterface && !is_terminating()) {
		usleep(100000);
	}
	if(is_terminating()) {
		return(NULL);
	}
	sleep(1);
	
	char filename[1024];
	struct inotify_event *event;
	char buff[4096];
	int i = 0, fd = 0, wd = 0, len = 0;
	queue<string> fileList;

	if(opt_scanpcapdir_disable_inotify == false) {
		fd = inotify_init();
		//checking for error
		if(fd < 0) perror( "inotify_init" );
		wd = inotify_add_watch(fd, opt_scanpcapdir, opt_scanpcapmethod);
	}

	// pre-populate the fileList with anything pre-existing in the directory
	fileList = listFilesDir(opt_scanpcapdir);

	while(!is_terminating()) {

		if (fileList.empty()) {
			// queue is empty, time to wait on inotify for some work
			if(opt_scanpcapdir_disable_inotify == false) {
				i = 0;
				len = read(fd, buff, 4096);

				if (len==4096) {
					syslog(LOG_NOTICE, "Warning: inotify events filled whole buffer.");
				}

				while (( i < len ) and !is_terminating()) {
					event = (struct inotify_event *) &buff[i];
					i += sizeof(struct inotify_event) + event->len;
					if (event->mask & opt_scanpcapmethod) { // this will prevent opening files which is still open for writes
						// add filename to end of queue
						snprintf(filename, sizeof(filename), "%s/%s", opt_scanpcapdir, event->name);
						fileList.push(filename);
					}
				}
			} else {
				fileList = listFilesDir(opt_scanpcapdir);
			}
			if (fileList.empty()) {
				usleep(10000);
				continue;
			}
		}
		// grab the next file in line to be processed
		strncpy(filename, fileList.front().c_str(), sizeof(filename));
		fileList.pop();

		//printf("File [%s]\n", filename);
		if(!file_exists(filename)) {
			continue;
		}
		
		if(verbosity > 1 || sverb.scanpcapdir) {
			syslog(LOG_NOTICE, "scanpcapdir: %s", filename);
		}
		
		if(!pcapQueueInterface->openPcap(filename)) {
			abort();
		}
		while(!is_terminating() && !pcapQueueInterface->isPcapEnd()) {
			usleep(10000);
		}
		
		if(!is_terminating()) {
			unlink(filename);
		}
	}
	
	if(opt_scanpcapdir_disable_inotify == false) {
		inotify_rm_watch(fd, wd);
	}

#endif

	return(NULL);
}

/*
void *destroy_calls( void *dummy ) {
	while(1) {
		calltable->destroyCallsIfPcapsClosed();
		
		if(is_terminating()) {
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

void reload_config(const char *jsonConfig) {
	if(useNewCONFIG) {
		CONFIG.clearToDefaultValues();
		if(configfile[0]) {
			CONFIG.loadFromConfigFileOrDirectory(configfile);
			CONFIG.loadFromConfigFileOrDirectory("/etc/voipmonitor/conf.d/");
		}
	} else {
		int load_config(char *fname);
		load_config(configfile);
		load_config((char*)"/etc/voipmonitor/conf.d/");
	}
	if(!opt_nocdr && isSqlDriver("mysql") && opt_mysqlloadconfig) {
		if(useNewCONFIG) {
			CONFIG.setFromMysql();
		}
	}
	if(useNewCONFIG && jsonConfig) {
		CONFIG.setFromJson(jsonConfig);
	}
	get_command_line_arguments();
	set_context_config();
	request_iptelnum_reload = 1;
}

void hot_restart() {
	hot_restarting = 1;
	set_terminating();
}

void hot_restart_with_json_config(const char *jsonConfig) {
	hot_restarting = 1;
	hot_restarting_json_config = jsonConfig;
	set_terminating();
}

void set_request_for_reload_capture_rules() {
	request_iptelnum_reload = 1;
}

void reload_capture_rules() {

	ipfilter_reload_do = 0;
	IPfilter::lock_sync();
	if(ipfilter_reload) {
		delete ipfilter_reload;
	}
	ipfilter_reload = new FILE_LINE IPfilter;
	ipfilter_reload->load();
	ipfilter_reload_do = 1;
	IPfilter::unlock_sync();

	telnumfilter_reload_do = 0;
	TELNUMfilter::lock_sync();
	if(telnumfilter_reload) {
		delete telnumfilter_reload;
	}
	telnumfilter_reload = new FILE_LINE TELNUMfilter;
	telnumfilter_reload->load();
	telnumfilter_reload_do = 1;
	TELNUMfilter::unlock_sync();

	domainfilter_reload_do = 0;
	DOMAINfilter::lock_sync();
	if(domainfilter_reload) {
		delete domainfilter_reload;
	}
	domainfilter_reload = new FILE_LINE DOMAINfilter;
	domainfilter_reload->load();
	domainfilter_reload_do = 1;
	DOMAINfilter::unlock_sync();

	sipheaderfilter_reload_do = 0;
	SIP_HEADERfilter::lock_sync();
	if(sipheaderfilter_reload) {
		delete sipheaderfilter_reload;
	}
	sipheaderfilter_reload = new FILE_LINE SIP_HEADERfilter;
	sipheaderfilter_reload->load();
	sipheaderfilter_reload_do = 1;
	SIP_HEADERfilter::unlock_sync();

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

void resetTerminating() {
	clear_terminating();
	terminating_moving_cache = 0;
	terminating_storing_cdr = 0;
	terminating_storing_registers = 0;
	terminated_call_cleanup = 0;
	terminated_async = 0;
	terminated_tar_flush_queue = 0;
	terminated_tar = 0;
}


void test();

PcapQueue_readFromFifo *pcapQueueR;
PcapQueue_readFromInterface *pcapQueueI;
PcapQueue_readFromFifo *pcapQueueQ;
PcapQueue_outputThread *pcapQueueQ_outThread_defrag;

void set_global_vars();
int main_init_read();
void main_term_read();
void main_init_sqlstore();

int main(int argc, char *argv[]) {
	extern unsigned int HeapSafeCheck;
	extern unsigned int HeapChunk;
	bool memoryStatInArg = false;
	bool memoryStatExInArg = false;
	for(int i = 0; i < argc; i++) {
		if(strstr(argv[i], "memory_stat")) {
			memoryStatInArg = true;
			if(strstr(argv[i], "memory_stat_ex")) {
				memoryStatExInArg = true;
			}
		}
	}
	for(int i = 0; i < argc; i++) {
		if(strstr(argv[i], "heapchunk")) {
			HeapChunk = true;
		}
		if(strstr(argv[i], "heapreserve")) {
			HeapSafeCheck = _HeapSafeSafeReserve;
		} else if(strstr(argv[i], "heapsafe")) {
			HeapSafeCheck = _HeapSafeErrorNotEnoughMemory |
					_HeapSafeErrorBeginEnd |
					_HeapSafeErrorFreed |
					_HeapSafeErrorInAllocFce |
					_HeapSafeErrorAllocReserve;
			if(strstr(argv[i], "heapsafeplus")) {
				HeapSafeCheck |= _HeapSafePlus;
			}
		} else if(strstr(argv[i], "HEAPSAFE")) {
			HeapSafeCheck = _HeapSafeErrorNotEnoughMemory |
					_HeapSafeErrorBeginEnd |
					_HeapSafeErrorFreed |
					_HeapSafeErrorInAllocFce |
					_HeapSafeErrorAllocReserve |
					_HeapSafeErrorFillFF;
			if(strstr(argv[i], "HEAPSAFEPLUS")) {
				HeapSafeCheck |= _HeapSafePlus;
			}
		}
		if((HeapSafeCheck & _HeapSafeErrorBeginEnd) && memoryStatInArg) {
			if(memoryStatExInArg) {
				HeapSafeCheck |= _HeapSafeStack;
			}
			sverb.memory_stat = true;
		}
	}
	
	set_global_vars();

	if(file_exists("/etc/localtime")) {
		setenv("TZ", "/etc/localtime", 1);
	}
 
	time(&startTime);

	regfailedcache = new FILE_LINE regcache;

	base64_init();

/*
	if(mysql_library_init(0, NULL, NULL)) {
		fprintf(stderr, "could not initialize MySQL library\n");
		exit(1);
	}
*/

	pcapstat.ps_drop = 0;
	pcapstat.ps_ifdrop = 0;

	signal(SIGPIPE, SIG_IGN);

	/* parse arguments */

	ifname[0] = '\0';
	opt_mirrorip_src[0] = '\0';
	opt_mirrorip_dst[0] = '\0';
	strcpy(opt_chdir, "/var/spool/voipmonitor");
	strcpy(opt_cachedir, "");
	sipportmatrix = new FILE_LINE char[65537];
	memset(sipportmatrix, 0, 65537);
	// set default SIP port to 5060
	sipportmatrix[5060] = 1;
	httpportmatrix = new FILE_LINE char[65537];
	memset(httpportmatrix, 0, 65537);
	webrtcportmatrix = new FILE_LINE char[65537];
	memset(webrtcportmatrix, 0, 65537);

	pthread_mutex_init(&mysqlconnect_lock, NULL);
	pthread_mutex_init(&vm_rrd_lock, NULL);
	pthread_mutex_init(&hostbyname_lock, NULL);
	pthread_mutex_init(&tartimemaplock, NULL);
	pthread_mutex_init(&terminate_packetbuffer_lock, NULL);

	set_mac();

	umask(0000);

	openlog("voipmonitor", LOG_CONS | LOG_PERROR | LOG_PID, LOG_DAEMON);

	/*
	string args;
	for(int i = 0; i < argc; i++) {
		args += string(argv[i]) + " ";
	}
	syslog(LOG_NOTICE, args.c_str());
	*/
	
	parse_command_line_arguments(argc, argv);
	get_command_line_arguments();
	if(useNewCONFIG || printConfigStruct) {
		CONFIG.addConfigItems();
	}
	if(configfile[0]) {
		if(useNewCONFIG) {
			CONFIG.loadFromConfigFileOrDirectory(configfile);
			CONFIG.loadFromConfigFileOrDirectory("/etc/voipmonitor/conf.d/");
		} else {
			int load_config(char *fname);
			load_config(configfile);
			load_config((char*)"/etc/voipmonitor/conf.d/");
		}
	}
	if(!opt_nocdr && 
	   !opt_untar_gui_params && !opt_unlzo_gui_params && !opt_waveform_gui_params && !opt_spectrogram_gui_params &&
	   !printConfigStruct &&
	   isSqlDriver("mysql") && opt_mysqlloadconfig) {
		if(useNewCONFIG) {
			CONFIG.setFromMysql(true);
		}
	}
	get_command_line_arguments();
	set_context_config();

	if(!check_complete_parameters()) {
		return 1;
	}
	
	if(!is_read_from_file_simple() && 
	   !opt_untar_gui_params && !opt_unlzo_gui_params && !opt_waveform_gui_params && !opt_spectrogram_gui_params &&
	   command_line_data.size()) {
		printf("voipmonitor version %s\n", RTPSENSOR_VERSION);
		syslog(LOG_NOTICE, "start voipmonitor version %s", RTPSENSOR_VERSION);
		
		string localActTime = sqlDateTimeString(time(NULL));
		printf("local time %s\n", localActTime.c_str());
		syslog(LOG_NOTICE, "local time %s", localActTime.c_str());
	}

	if(opt_untar_gui_params) {
		chdir(opt_chdir);
		int rslt = untar_gui(opt_untar_gui_params);
		delete [] opt_untar_gui_params;
		return(rslt);
	}
	if(opt_unlzo_gui_params) {
		chdir(opt_chdir);
		int rslt = unlzo_gui(opt_unlzo_gui_params);
		delete [] opt_unlzo_gui_params;
		return(rslt);
	}
	if(opt_waveform_gui_params) {
		chdir(opt_chdir);
		char inputRaw[1024];
		char outputWaveform[2][1024];
		unsigned sampleRate;
		unsigned msPerPixel;
		unsigned channels;
		if(sscanf(opt_waveform_gui_params, "%s %u %u %i %s %s", 
			  inputRaw, &sampleRate, &msPerPixel, &channels, 
			  outputWaveform[0], outputWaveform[1]) < 5) {
			cerr << "waveform: bad arguments" << endl;
			delete [] opt_waveform_gui_params;
			return(1);
		}
		delete [] opt_waveform_gui_params;
		return(!create_waveform_from_raw(inputRaw,
						 sampleRate, msPerPixel, channels,
						 outputWaveform));
	}
	if(opt_spectrogram_gui_params) {
		chdir(opt_chdir);
		char inputRaw[1024];
		char outputSpectrogramPng[2][1024];
		unsigned sampleRate;
		unsigned msPerPixel;
		unsigned channels;
		if(sscanf(opt_spectrogram_gui_params, "%s %u %u %i %s %s", 
			  inputRaw, &sampleRate, &msPerPixel, &channels, 
			  outputSpectrogramPng[0], outputSpectrogramPng[1]) < 5) {
			cerr << "spectrogram: bad arguments" << endl;
			delete [] opt_spectrogram_gui_params;
			return(1);
		}
		delete [] opt_spectrogram_gui_params;
		return(!create_spectrogram_from_raw(inputRaw,
						    sampleRate, msPerPixel, 0, channels,
						    outputSpectrogramPng));
	}
	
	if(printConfigStruct) {
		cout << "configuration: ";
		cout << CONFIG.getJson();
		cout << endl;
		return(0);
	}

	signal(SIGINT,sigint_handler);
	signal(SIGTERM,sigterm_handler);
	signal(SIGCHLD,sigchld_handler);
#ifdef BACKTRACE
	if(sverb.enable_bt_sighandler) {
		/* Install our signal handler */
		struct sigaction sa;

		sa.sa_sigaction = bt_sighandler;
		sigemptyset (&sa.sa_mask);
		sa.sa_flags = SA_RESTART | SA_SIGINFO;

		sigaction(SIGSEGV, &sa, NULL);
		sigaction(SIGBUS, &sa, NULL);
		sigaction(SIGILL, &sa, NULL);
		sigaction(SIGFPE, &sa, NULL);
		//sigaction(SIGUSR1, &sa, NULL);
		//sigaction(SIGUSR2, &sa, NULL);
	}
#endif
	
	// BEGIN RELOAD LOOP
	int reloadLoopCounter = -1;
	while(1) {
	 
	++reloadLoopCounter;
	resetTerminating();
	if(reloadLoopCounter) {
		reload_config(hot_restarting_json_config.c_str());
		hot_restarting = 0;
		hot_restarting_json_config = "";
		terminating_error = "";
	}
	
	// init
	alaw_init();
	ulaw_init();
	dsp_init();
 
	#if defined(__i386__) or  defined(__x86_64__)
	u_int64_t _rdtsc_1 = rdtsc();
	usleep(100000);
	u_int64_t _rdtsc_2 = rdtsc();
	rdtsc_by_100ms = _rdtsc_2 - _rdtsc_1;
	#endif
	
	thread_setup();
	// end init

	if(opt_rrd && is_read_from_file()) {
		//disable update of rrd statistics when reading packets from file
		opt_rrd = 0;
	}

	//cloud REGISTER has been moved to cloud_activecheck thread , if activecheck is disabled thread will end after registering and opening ssh
	if(cloud_url[0] != '\0') {
		//vm_pthread_create(&activechecking_cloud_thread, NULL, activechecking_cloud, NULL, __FILE__, __LINE__);
		cloud_initial_register();

		//Override query_cache option in /etc/voipmonitor.conf  settings while in cloud mode always on:
                opt_save_query_to_files = true;
                opt_load_query_from_files = 1;
                opt_load_query_from_files_inotify = true;
	}
	checkRrdVersion();

	
/* resolve is disabled since 27.3.2015 
	if(!opt_nocdr && isSqlDriver("mysql") && mysql_host[0]) {
		strcpy(mysql_host_orig, mysql_host);
		if(!reg_match(mysql_host, "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+", __FILE__, __LINE__)) {
			hostent *conn_server_record = gethostbyname_lock(mysql_host);
			if(conn_server_record == NULL) {
				syslog(LOG_ERR, "mysql host [%s] failed to resolve to IP address", mysql_host);
				exit(1);
			}
			in_addr *conn_server_address = (in_addr*)conn_server_record->h_addr;
			strcpy(mysql_host, inet_ntoa(*conn_server_address));
			syslog(LOG_NOTICE, "mysql host [%s] resolved to [%s]", mysql_host_orig, mysql_host);
		}
	}
*/
	
	if(opt_fork && !is_read_from_file() && reloadLoopCounter == 0) {
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
		
		daemonize();
	}

	if(opt_generator) {
		opt_generator_channels = 2;
		pthread_t *genthreads = new FILE_LINE pthread_t[opt_generator_channels];		// ID of worker storing CDR thread 
		for(int i = 0; i < opt_generator_channels; i++) {
			vm_pthread_create("generator sip/rtp",
					  &genthreads[i], NULL, gensiprtp, NULL, __FILE__, __LINE__);
		}
		syslog(LOG_ERR, "Traffic generated");
		sleep(10000);
		return 0;
	}

	// start manager thread 	
	if(opt_manager_port > 0 && !is_read_from_file_simple()) {
		vm_pthread_create("manager server",
				  &manager_thread, NULL, manager_server, NULL, __FILE__, __LINE__);
		// start reversed manager thread
		if(opt_clientmanager[0] != '\0') {
			vm_pthread_create("manager client",
					  &manager_client_thread, NULL, manager_client, NULL, __FILE__, __LINE__);
		}
	};

	//cout << "SQL DRIVER: " << sql_driver << endl;
	if(!opt_nocdr && !is_sender()/* && cloud_url[0] == '\0'*/) {
		bool connectError = false;
		string connectErrorString;
		for(int connectId = 0; connectId < (use_mysql_2() ? 2 : 1); connectId++) {
			SqlDb *sqlDb = createSqlObject(connectId);
			bool rsltConnect = false;
			for(int pass = 0; pass < 2; pass++) {
				if((rsltConnect = sqlDb->connect(true, true))) {
					break;
				}
				sleep(1);
			}
			if(rsltConnect && sqlDb->connected()) {
				if(isSqlDriver("mysql")) {
					sql_noerror = 1;
					sqlDb->query("repair table mysql.proc");
					sql_noerror = 0;
				}
				sqlDb->checkDbMode();
				if(!opt_database_backup) {
					if (!opt_disable_dbupgradecheck) {
						if(sqlDb->createSchema(connectId)) {
							sqlDb->checkSchema(connectId);
						} else {
							connectError = true;
							connectErrorString = sqlDb->getLastErrorString();
						}
					} else {
						sqlDb->checkSchema(connectId, true);
					}
				}
				sensorsMap.fillSensors();
			} else {
				connectError = true;
				connectErrorString = sqlDb->getLastErrorString();
			}
			delete sqlDb;
		}
		if(connectError) {
			if(useNewCONFIG && !is_read_from_file()) {
				vm_terminate_error(connectErrorString.c_str());
			} else {
				syslog(LOG_ERR, (connectErrorString + " - exit!").c_str());
				return 1;
			}
		}
	}
	
	if(updateSchema) {
		return 0;
	}

	if(!is_terminating()) {
	
		if(opt_test) {
			ipfilter = new FILE_LINE IPfilter;
			telnumfilter = new FILE_LINE TELNUMfilter;
			domainfilter =  new FILE_LINE DOMAINfilter;
			sipheaderfilter =  new FILE_LINE SIP_HEADERfilter;
			_parse_packet_global_process_packet.setStdParse();
			test();
			if(sqlStore) {
				delete sqlStore;
			}
			return(0);
		}
		
		if(!opt_database_backup && opt_load_query_from_files != 2) {
			main_init_sqlstore();
			int rslt_main_init_read = main_init_read();
			if(rslt_main_init_read) {
				return(rslt_main_init_read);
			}
			main_term_read();
		} else {
			if(opt_database_backup) {
				sqlStore = new FILE_LINE MySqlStore(mysql_host, mysql_user, mysql_password, mysql_database, opt_mysql_port, 
								    cloud_host, cloud_token);
				custom_headers_cdr = new FILE_LINE CustomHeaders(CustomHeaders::cdr);
				custom_headers_message = new FILE_LINE CustomHeaders(CustomHeaders::message);
				vm_pthread_create("database backup",
						  &database_backup_thread, NULL, database_backup, NULL, __FILE__, __LINE__);
				pthread_join(database_backup_thread, NULL);
			} else if(opt_load_query_from_files == 2) {
				main_init_sqlstore();
				loadFromQFiles->loadFromQFiles_start();
				unsigned int counter = 0;
				while(!is_terminating()) {
					sleep(1);
					if(!(++counter % 10) && verbosity) {
						string stat = loadFromQFiles->getLoadFromQFilesStat();
						syslog(LOG_NOTICE, "SQLf: [%s]", stat.c_str());
					}
				}
			}
			if(sqlStore) {
				delete sqlStore;
				sqlStore = NULL;
			}
			if(sqlStore_2) {
				delete sqlStore_2;
				sqlStore_2 = NULL;
			}
			if(loadFromQFiles) {
				delete loadFromQFiles;
				loadFromQFiles = NULL;
			}
			if(custom_headers_cdr) {
				delete custom_headers_cdr;
				custom_headers_cdr = NULL;
			}
			if(custom_headers_message) {
				delete custom_headers_message;
				custom_headers_message = NULL;
			}
		}
	
	}
	
	bool _break = false;
	
	if(useNewCONFIG && !is_read_from_file()) {
		string _terminating_error = terminating_error;
		if(!hot_restarting && _terminating_error.empty()) {
			_break = true;
		}
		if(!_terminating_error.empty()) {
			clear_terminating();
			while(!is_terminating()) {
				syslog(LOG_NOTICE, "%s - wait for terminating or hot restarting", _terminating_error.c_str());
				for(int i = 0; i < 10 && !is_terminating(); i++) {
					sleep(1);
				}
			}
			if(!hot_restarting) {
				_break = true;
			}
		}
		terminating_error = "";
	} else {
		_break = true;
	}
	
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
	
	if(_break) {
		break;
	}

	}
	// END RELOAD LOOP
	
	_parse_packet_global_process_packet.free();
	
	delete [] sipportmatrix;
	delete [] httpportmatrix;
	delete [] webrtcportmatrix;
	
	delete regfailedcache;
	
#ifdef HAVE_LIBGNUTLS
	ssl_clean();
#endif
	
	if(sverb.memory_stat) {
		cout << "memory stat at end" << endl;
		printMemoryStat(true);
	}
	if (opt_fork){
		unlink(opt_pidfile);
	}
	
	return(0);
}

bool cloud_register() {
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
				strcpy(ssh_username, jsonData.getValue("ssh_user").c_str());                                                                                                                                                                                 strcpy(ssh_password, jsonData.getValue("ssh_password").c_str());                                                                                                                                                                             strcpy(ssh_remote_listenhost, jsonData.getValue("ssh_rhost").c_str());                                                                                                                                                                       ssh_remote_listenport = atol(jsonData.getValue("ssh_rport").c_str());

				//sqlurl
				strcpy(cloud_host, jsonData.getValue("sqlurl").c_str());
				return true;
			} else {
				syslog(LOG_ERR, "cloud registration error: bad response - %s", (char*)responseBuffer);
			}
		} else {
			syslog(LOG_ERR, "cloud registration error: response is empty");
		}
	} else {
		syslog(LOG_ERR, "cloud registration error: %s", error.c_str());
	}
	return(false);
}

bool cloud_activecheck_send() {
	vector<dstring> postData;
	postData.push_back(dstring("ssh_rhost", ssh_remote_listenhost));
	char str_port[10];
	sprintf(str_port, "%i", ssh_remote_listenport);
	postData.push_back(dstring("ssh_rport", str_port));
	SimpleBuffer responseBuffer;
	string error;
	syslog(LOG_NOTICE, "connecting to %s", cloud_url_activecheck);
	get_url_response(cloud_url_activecheck, &responseBuffer, &postData, &error);
	if(error.empty()) {
		if(!responseBuffer.empty()) {
			if(responseBuffer.isJsonObject()) {
				JsonItem jsonData;
				jsonData.parse((char*)responseBuffer);
				int res_num = atoi(jsonData.getValue("res_num").c_str());
				string res_text = jsonData.getValue("res_text");
				if(res_num != 0) {
					syslog(LOG_ERR, "cloud tunnel check request error: %s", res_text.c_str());
					return(false);
				}
				return true;
			} else {
				syslog(LOG_ERR, "cloud tunnel check: bad response - %s", (char*)responseBuffer);
			}
		} else {
			syslog(LOG_ERR, "cloud tunnel check error: response is empty");
		}
	} else {
		syslog(LOG_ERR, "cloud tunnel check error: %s", error.c_str());
	}
	return(false);
}


void set_global_vars() {
	opt_save_sip_history = "bye";
}

int main_init_read() {
	calltable = new FILE_LINE Calltable;
	
	// if the system has more than one CPU enable threading
	if(opt_rtpsave_threaded) {
		if(num_threads_set > 0) {
			num_threads_max = num_threads_set;
			num_threads_active = 1;
		} else {
			num_threads_max = sysconf( _SC_NPROCESSORS_ONLN ) - 1;
			if(num_threads_max <= 0) num_threads_max = 1;
			num_threads_active = 1;
		}
	} else {
		num_threads_max = 0;
		num_threads_active = 0;
	}
	rtp_threaded = num_threads_max > 0 && num_threads_active > 0;

	// check if sniffer will be reading pcap files from dir and if not if it reads from eth interface or read only one file
	if(is_read_from_file_simple()) {
		// if reading file
		rtp_threaded = 0;
		opt_mirrorip = 0; // disable mirroring packets when reading pcap files from file
//			opt_cachedir[0] = '\0'; //disabling cache if reading from file 
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
		printf("Reading file: %s\n", opt_read_from_file_fname);
		char errbuf[PCAP_ERRBUF_SIZE];
		global_pcap_handle = pcap_open_offline_zip(opt_read_from_file_fname, errbuf);
		if(global_pcap_handle == NULL) {
			fprintf(stderr, "Couldn't open pcap file '%s': %s\n", opt_read_from_file_fname, errbuf);
			return(2);
		}
		global_pcap_handle_index = register_pcap_handle(global_pcap_handle);
	}
	
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
	rlp.rlim_cur = RLIM_INFINITY;
	rlp.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_CORE, &rlp) < 0)
		fprintf(stderr, "setrlimit: %s\nWarning: core dumps may be truncated or non-existant\n", strerror(errno));

	if(!opt_nocdr) {
		custom_headers_cdr = new FILE_LINE CustomHeaders(CustomHeaders::cdr);
		custom_headers_cdr->createTablesIfNotExists();
		custom_headers_message = new FILE_LINE CustomHeaders(CustomHeaders::message);
		custom_headers_message->createTablesIfNotExists();
	}

	ipfilter = new FILE_LINE IPfilter;
	telnumfilter = new FILE_LINE TELNUMfilter;
	domainfilter = new FILE_LINE DOMAINfilter;
	sipheaderfilter = new FILE_LINE SIP_HEADERfilter;
	if(!opt_nocdr &&
	   !is_sender()) {
		ipfilter->load();
		telnumfilter->load();
		domainfilter->load();
		sipheaderfilter->load();
	}
//	ipfilter->dump();
//	telnumfilter->dump();
//	domainfilter->dump();
//	sipheaderfilter->dump();

	_parse_packet_global_process_packet.setStdParse();

	if(opt_ipaccount && !opt_test) {
		initIpacc();
	}
	
	if(opt_ipaccount and !ipaccountportmatrix) {
		ipaccountportmatrix = new FILE_LINE char[65537];
		memset(ipaccountportmatrix, 0, 65537);
	}

	if(opt_save_query_to_files) {
		sqlStore->queryToFiles_start();
		if(sqlStore_2) {
			sqlStore_2->queryToFiles_start();
		}
	}
	if(opt_load_query_from_files) {
		loadFromQFiles->loadFromQFiles_start();
	}

	if(opt_pcap_dump_tar) {
		tarQueue = new FILE_LINE TarQueue;
	}
	
	if(opt_enable_fraud) {
		initFraud();
	}
	initSendCallInfo();
	
	if(opt_ipaccount) {
		ipaccStartThread();
	}

	if(opt_pcap_dump_asyncwrite) {
		extern AsyncClose *asyncClose;
		asyncClose = new FILE_LINE AsyncClose;
		asyncClose->startThreads(opt_pcap_dump_writethreads, opt_pcap_dump_writethreads_max);
	}
	
	if(is_enable_cleanspool() &&
	   isSetCleanspoolParameters()) {
		runCleanSpoolThread();
	}
	
	if(opt_fork) {
		vm_pthread_create("defered service",
				  &defered_service_fork_thread, NULL, defered_service_fork, NULL, __FILE__, __LINE__);
	}
	
	// start thread processing queued cdr and sql queue - supressed if run as sender
	if(!is_sender()) {
		vm_pthread_create("storing cdr",
				  &storing_cdr_thread, NULL, storing_cdr, NULL, __FILE__, __LINE__);
		vm_pthread_create("storing register",
				  &storing_registers_thread, NULL, storing_registers, NULL, __FILE__, __LINE__);
		/*
		vm_pthread_create(&destroy_calls_thread, NULL, destroy_calls, NULL, __FILE__, __LINE__);
		*/
	}

	// start activechecking cloud thread if in cloud mode and no zero activecheck_period
	if(cloud_url[0] != '\0') {
		if (!opt_cloud_activecheck_period) {
			if(verbosity) syslog(LOG_NOTICE, "notice - activechecking is disabled by config");
		} else {
			vm_pthread_create("checking cloud",
					  &activechecking_cloud_thread, NULL, activechecking_cloud, NULL, __FILE__, __LINE__);
		}
	}

	if(opt_cachedir[0] != '\0') {
		mv_r(opt_cachedir, opt_chdir);
		vm_pthread_create("moving cache",
				  &cachedir_thread, NULL, moving_cache, NULL, __FILE__, __LINE__);
	}

	// start tar dumper
	if(opt_pcap_dump_tar) {
		vm_pthread_create("tar queue",
				  &tarqueuethread, NULL, TarQueueThread, NULL, __FILE__, __LINE__);
	}

#ifdef HAVE_LIBSSH
	if(cloud_url[0] != '\0') {
		vm_pthread_create("manager ssh",
				  &manager_ssh_thread, NULL, manager_ssh, NULL, __FILE__, __LINE__);
	}
#endif

	// start reading threads
	if(is_enable_rtp_threads()) {
		rtp_threads = new FILE_LINE rtp_read_thread[num_threads_max];
		for(int i = 0; i < num_threads_max; i++) {
			size_t _rtp_qring_length = rtp_qring_length ? 
							rtp_qring_length :
							rtpthreadbuffer * 1024 * 1024 / sizeof(rtp_packet_pcap_queue);
			if(rtp_qring_quick == 2) {
				rtp_threads[i].rtpp_queue_quick_boost = new FILE_LINE rqueue_quick_boost<rtp_packet_pcap_queue>(
										100, rtp_qring_usleep,
										&terminating,
										__FILE__, __LINE__);
			} else if(rtp_qring_quick) {
				rtp_threads[i].rtpp_queue_quick = new FILE_LINE rqueue_quick<rtp_packet_pcap_queue>(
									_rtp_qring_length,
									100, rtp_qring_usleep,
									&terminating, true,
									__FILE__, __LINE__);
			} else {
				rtp_threads[i].rtpp_queue = new FILE_LINE rqueue<rtp_packet_pcap_queue>(_rtp_qring_length / 2, _rtp_qring_length / 5, _rtp_qring_length * 1.5);
				char rtpp_queue_name[20];
				sprintf(rtpp_queue_name, "rtp thread %i", i + 1);
				rtp_threads[i].rtpp_queue->setName(rtpp_queue_name);
			}
			rtp_threads[i].threadId = 0;
			memset(rtp_threads[i].threadPstatData, 0, sizeof(rtp_threads[i].threadPstatData));
			rtp_threads[i].remove_flag = 0;
			rtp_threads[i].last_use_time_s = 0;
			rtp_threads[i].calls = 0;
			if(i < num_threads_active) {
				vm_pthread_create_autodestroy("rtp read",
							      &(rtp_threads[i].thread), NULL, rtp_read_thread_func, (void*)&rtp_threads[i], __FILE__, __LINE__);
			}
		}
	}
	
	for(int i = 0; i < PreProcessPacket::ppt_end; i++) {
		preProcessPacket[i] = new FILE_LINE PreProcessPacket((PreProcessPacket::eTypePreProcessThread)i);
	}
	if(!is_read_from_file_simple()) {
		for(int i = 0; i < max(1, min(opt_enable_preprocess_packet, (int)PreProcessPacket::ppt_end)); i++) {
			preProcessPacket[i]->startOutThread();
		}
	}
	
	//autostart for fork mode if t2cpu > 50%
	if(!opt_fork &&
	   opt_enable_process_rtp_packet && opt_pcap_split &&
	   !is_read_from_file_simple()) {
		process_rtp_packets_distribute_threads_use = opt_enable_process_rtp_packet;
		processRtpPacketHash = new FILE_LINE ProcessRtpPacket(ProcessRtpPacket::hash, 0);
		for(int i = 0; i < opt_enable_process_rtp_packet; i++) {
			processRtpPacketDistribute[i] = new FILE_LINE ProcessRtpPacket(ProcessRtpPacket::distribute, i);
		}
	}

	if(opt_enable_http) {
		bool setHttpPorts = false;
		for(int i = 0; i < 65537; i++) {
			if(httpportmatrix[i]) {
				setHttpPorts = true;
			}
		}
		if(setHttpPorts) {
			tcpReassemblyHttp = new FILE_LINE TcpReassembly(TcpReassembly::http);
			tcpReassemblyHttp->setEnableHttpForceInit();
			tcpReassemblyHttp->setEnableCrazySequence();
			tcpReassemblyHttp->setEnableValidateDataViaCheckData();
			tcpReassemblyHttp->setEnableCleanupThread();
			tcpReassemblyHttp->setEnablePacketThread();
			httpData = new FILE_LINE HttpData;
			tcpReassemblyHttp->setDataCallback(httpData);
		}
	}
	if(opt_enable_webrtc) {
		bool setWebrtcPorts = false;
		for(int i = 0; i < 65537; i++) {
			if(webrtcportmatrix[i]) {
				setWebrtcPorts = true;
			}
		}
		if(setWebrtcPorts) {
			tcpReassemblyWebrtc = new FILE_LINE TcpReassembly(TcpReassembly::webrtc);
			tcpReassemblyWebrtc->setEnableIgnorePairReqResp();
			tcpReassemblyWebrtc->setEnableWildLink();
			tcpReassemblyWebrtc->setEnableDestroyStreamsInComplete();
			tcpReassemblyWebrtc->setEnableAllCompleteAfterZerodataAck();
			tcpReassemblyWebrtc->setIgnorePshInCheckOkData();
			tcpReassemblyWebrtc->setEnablePacketThread();
			webrtcData = new FILE_LINE WebrtcData;
			tcpReassemblyWebrtc->setDataCallback(webrtcData);
		}
	}
	if(opt_enable_ssl && ssl_ipport.size()) {
		tcpReassemblySsl = new FILE_LINE TcpReassembly(TcpReassembly::ssl);
		tcpReassemblySsl->setEnableIgnorePairReqResp();
		tcpReassemblySsl->setEnableDestroyStreamsInComplete();
		tcpReassemblySsl->setEnableAllCompleteAfterZerodataAck();
		tcpReassemblySsl->setIgnorePshInCheckOkData();
		sslData = new FILE_LINE SslData;
		tcpReassemblySsl->setDataCallback(sslData);
		tcpReassemblySsl->setLinkTimeout(opt_ssl_link_timeout);
		tcpReassemblySsl->setEnableWildLink();
	}
	if(opt_sip_tcp_reassembly_ext) {
		tcpReassemblySipExt = new FILE_LINE TcpReassembly(TcpReassembly::sip);
		tcpReassemblySipExt->setEnableIgnorePairReqResp();
		tcpReassemblySipExt->setEnableDestroyStreamsInComplete();
		tcpReassemblySipExt->setEnableStrictValidateDataViaCheckData();
		tcpReassemblySipExt->setNeedValidateDataViaCheckData();
		tcpReassemblySipExt->setSimpleByAck();
		tcpReassemblySipExt->setIgnorePshInCheckOkData();
		sipTcpData = new FILE_LINE SipTcpData;
		tcpReassemblySipExt->setDataCallback(sipTcpData);
		tcpReassemblySipExt->setLinkTimeout(10);
		tcpReassemblySipExt->setEnableWildLink();
	}
	
	if(sipSendSocket_ip_port) {
		sipSendSocket = new FILE_LINE SocketSimpleBufferWrite("send sip", sipSendSocket_ip_port, opt_sip_send_udp);
		sipSendSocket->startWriteThread();
	}
	
	if(opt_bogus_dumper_path[0]) {
		bogusDumper = new FILE_LINE BogusDumper(opt_bogus_dumper_path);
	}
	
	if(opt_pcap_dump_tar && opt_fork) {
		string maxSpoolDate = getMaxSpoolDate();
		if(maxSpoolDate.length()) {
			syslog(LOG_NOTICE, "run reindex date %s", maxSpoolDate.c_str());
			reindex_date(maxSpoolDate);
			syslog(LOG_NOTICE, "reindex date %s completed", maxSpoolDate.c_str());
		}
	}
	
	readend = 0;

	if(is_enable_packetbuffer()) {
		PcapQueue_init();
		
		if(is_read_from_file_by_pb() && opt_tcpreassembly_thread) {
			if(tcpReassemblyHttp) {
				tcpReassemblyHttp->setIgnoreTerminating(true);
			}
			if(tcpReassemblyWebrtc) {
				tcpReassemblyWebrtc->setIgnoreTerminating(true);
			}
			if(tcpReassemblySsl) {
				tcpReassemblySsl->setIgnoreTerminating(true);
			}
			if(tcpReassemblySipExt) {
				tcpReassemblySipExt->setIgnoreTerminating(true);
			}
		}
	
		if(ifname[0] || is_read_from_file_by_pb()) {
			pcapQueueI = new FILE_LINE PcapQueue_readFromInterface("interface");
			pcapQueueI->setInterfaceName(ifname);
			pcapQueueI->setEnableAutoTerminate(false);
		}
		
		pcapQueueQ = new FILE_LINE PcapQueue_readFromFifo("queue", opt_pcap_queue_disk_folder.c_str());
		if(pcapQueueI) {
			pcapQueueQ->setInstancePcapHandle(pcapQueueI);
			pcapQueueI->setInstancePcapFifo(pcapQueueQ);
		}
		pcapQueueQ->setEnableAutoTerminate(false);
		
		if(opt_pcap_queue_receive_from_ip_port) {
			pcapQueueQ->setPacketServer(opt_pcap_queue_receive_from_ip_port, PcapQueue_readFromFifo::directionRead);
		} else if(opt_pcap_queue_send_to_ip_port) {
			pcapQueueQ->setPacketServer(opt_pcap_queue_send_to_ip_port, PcapQueue_readFromFifo::directionWrite);
		}
		
		if(opt_pcap_queue_use_blocks && opt_udpfrag) {
			pcapQueueQ_outThread_defrag = new PcapQueue_outputThread(PcapQueue_outputThread::defrag, pcapQueueQ);
			pcapQueueQ_outThread_defrag->start();
		}
		
		pcapQueueQ->start();
		if(pcapQueueI) {
			pcapQueueI->start();
			pcapQueueInterface = pcapQueueI;
		}
		pcapQueueStatInterface = pcapQueueQ;
		
		if(opt_scanpcapdir[0] != '\0') {
			vm_pthread_create("scan pcap dir",
					  &scanpcapdir_thread, NULL, scanpcapdir, NULL, __FILE__, __LINE__);
		}
		
		uint64_t _counter = 0;
		if(!sverb.pcap_stat_period) {
			sverb.pcap_stat_period = verbosityE > 0 ? 1 : 10;
		}
		while(!is_terminating()) {
			long timeProcessStatMS = 0;
			if(_counter) {
				u_long startTimeMS = getTimeMS();
				pthread_mutex_lock(&terminate_packetbuffer_lock);
				pcapQueueQ->pcapStat(verbosityE > 0 ? 1 : sverb.pcap_stat_period);
				pthread_mutex_unlock(&terminate_packetbuffer_lock);
				if(sverb.memory_stat_log) {
					printMemoryStat();
				}
				if(tcpReassemblyHttp) {
					tcpReassemblyHttp->setDoPrintContent();
				}
				if(tcpReassemblyWebrtc) {
					tcpReassemblyWebrtc->setDoPrintContent();
				}
				u_long endTimeMS = getTimeMS();
				if(endTimeMS > startTimeMS) {
					timeProcessStatMS = endTimeMS - startTimeMS;
				}
			}
			for(long i = 0; i < ((sverb.pcap_stat_period * 100) - timeProcessStatMS / 10) && !is_terminating(); i++) {
				usleep(10000);
			}
			++_counter;
		}
		
		if(opt_scanpcapdir[0] != '\0') {
			//pthread_join(scanpcapdir_thread, NULL); // failed - stop at: scanpcapdir::'len = read(fd, buff, 4096);'
			sleep(2);
		}
		
		terminate_packetbuffer();
		
		if(is_read_from_file_by_pb() && (opt_enable_http || opt_enable_webrtc || opt_enable_ssl || opt_sip_tcp_reassembly_ext)) {
			sleep(2);
		}
		
		PcapQueue_term();
	} else {
		readdump_libpcap(global_pcap_handle, global_pcap_handle_index);
	}
	
	return(0);
}

void main_term_read() {
	readend = 1;

	// wait for RTP threads
	if(rtp_threads) {
		for(int i = 0; i < num_threads_max; i++) {
			if(i < num_threads_active) {
				while(rtp_threads[i].threadId) {
					usleep(100000);
				}
			}
			if(rtp_threads[i].rtpp_queue_quick) {
				delete rtp_threads[i].rtpp_queue_quick;
			} else {
				delete rtp_threads[i].rtpp_queue;
			}
		}
		delete [] rtp_threads;
		rtp_threads = NULL;
	}

	if(is_read_from_file_simple() && global_pcap_handle) {
		pcap_close(global_pcap_handle);
	}
	if(global_pcap_handle_dead_EN10MB) {
		pcap_close(global_pcap_handle_dead_EN10MB);
	}
	
	// flush all queues

	Call *call;
	calltable->cleanup_calls(0);
	calltable->cleanup_registers(0);

	set_terminating();

	regfailedcache->prune(0);
	
	if(tcpReassemblyHttp) {
		delete tcpReassemblyHttp;
		tcpReassemblyHttp = NULL;
	}
	if(httpData) {
		delete httpData;
	}
	if(tcpReassemblyWebrtc) {
		delete tcpReassemblyWebrtc;
		tcpReassemblyWebrtc = NULL;
	}
	if(webrtcData) {
		delete webrtcData;
	}
	if(tcpReassemblySsl) {
		delete tcpReassemblySsl;
		tcpReassemblySsl = NULL;
	}
	if(sslData) {
		delete sslData;
		sslData = NULL;
	}
	if(tcpReassemblySipExt) {
		delete tcpReassemblySipExt;
		tcpReassemblySipExt = NULL;
	}
	if(sipTcpData) {
		delete sipTcpData;
		sipTcpData = NULL;
	}
	
	if(processRtpPacketHash) {
		processRtpPacketHash->terminate();
		delete processRtpPacketHash;
		processRtpPacketHash = NULL;
	}
	for(int i = 0; i < MAX_PROCESS_RTP_PACKET_THREADS; i++) {
		if(processRtpPacketDistribute[i]) {
			processRtpPacketDistribute[i]->terminate();
			delete processRtpPacketDistribute[i];
			processRtpPacketDistribute[i] = NULL;
		}
	}
	
	for(int i = 0; i < PreProcessPacket::ppt_end; i++) {
		if(preProcessPacket[i]) {
			preProcessPacket[i]->terminate();
			delete preProcessPacket[i];
			preProcessPacket[i] = NULL;
		}
	}
	
	if(sipSendSocket) {
		delete sipSendSocket;
		sipSendSocket = NULL;
	}

	if(ipaccountportmatrix) {
		delete [] ipaccountportmatrix;
		ipaccountportmatrix = NULL;
	}

	if(opt_cachedir[0] != '\0') {
		terminating_moving_cache = 1;
		pthread_join(cachedir_thread, NULL);
	}
	
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
	if(sipheaderfilter) {
		delete sipheaderfilter;
		sipheaderfilter = NULL;
	}
	
	if(opt_enable_fraud) {
		termFraud();
	}
	termSendCallInfo();
	if(SafeAsyncQueue_base::isRunTimerThread()) {
		SafeAsyncQueue_base::stopTimerThread(true);
	}
	
	if(mirrorip) {
		delete mirrorip;
		mirrorip = NULL;
	}

	pthread_mutex_destroy(&tartimemaplock);
	pthread_mutex_unlock(&terminate_packetbuffer_lock);
	pthread_mutex_destroy(&terminate_packetbuffer_lock);

	extern TcpReassemblySip tcpReassemblySip;
	tcpReassemblySip.clean();

	if(opt_pcap_dump_asyncwrite) {
		extern AsyncClose *asyncClose;
		if(asyncClose) {
			asyncClose->safeTerminate();
			delete asyncClose;
			asyncClose = NULL;
		}
	}
	
	if(opt_pcap_dump_tar) {
		if(sverb.chunk_buffer > 1) { 
			cout << "start destroy tar queue" << endl << flush;
		}
		pthread_join(tarqueuethread, NULL);
		delete tarQueue;
		tarQueue = NULL;
		if(sverb.chunk_buffer > 1) { 
			cout << "end destroy tar queue" << endl << flush;
		}
	}

	if(storing_cdr_thread) {
		terminating_storing_cdr = 1;
		pthread_join(storing_cdr_thread, NULL);
	}
	if(storing_registers_thread) {
		terminating_storing_registers = 1;
		pthread_join(storing_registers_thread, NULL);
	}
	while(calltable->calls_queue.size() != 0) {
			call = calltable->calls_queue.front();
			calltable->calls_queue.pop_front();
			delete call;
			calls_counter--;
	}
	while(calltable->audio_queue.size() != 0) {
			call = calltable->audio_queue.front();
			calltable->audio_queue.pop_front();
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
	while(calltable->registers_queue.size() != 0) {
			call = calltable->registers_queue.front();
			calltable->registers_queue.pop_front();
			delete call;
			registers_counter--;
	}
	while(calltable->registers_deletequeue.size() != 0) {
			call = calltable->registers_deletequeue.front();
			calltable->registers_deletequeue.pop_front();
			call->atFinish();
			delete call;
			registers_counter--;
	}
	delete calltable;
	calltable = NULL;
	
	termCleanSpoolThread();

	pthread_mutex_destroy(&mysqlconnect_lock);
	extern SqlDb *sqlDbSaveCall;
	if(sqlDbSaveCall) {
		delete sqlDbSaveCall;
		sqlDbSaveCall = NULL;
	}
	extern SqlDb *sqlDbSaveHttp;
	if(sqlDbSaveHttp) {
		delete sqlDbSaveHttp;
		sqlDbSaveHttp = NULL;
	}
	extern SqlDb *sqlDbSaveWebrtc;
	if(sqlDbSaveWebrtc) {
		delete sqlDbSaveWebrtc;
		sqlDbSaveWebrtc = NULL;
	}
	extern SqlDb_mysql *sqlDbEscape;
	if(sqlDbEscape) {
		delete sqlDbEscape;
		sqlDbEscape = NULL;
	}
	extern SqlDb_mysql *sqlDbCleanspool;
	if(sqlDbCleanspool) {
		delete sqlDbCleanspool;
		sqlDbCleanspool = NULL;
	}
	
	if(sqlStore) {
		sqlStore->setEnableTerminatingIfEmpty(0, true);
		sqlStore->setEnableTerminatingIfSqlError(0, true);
		regfailedcache->prune(0);
		delete sqlStore;
		sqlStore = NULL;
	}
	if(sqlStore_2) {
		sqlStore_2->setEnableTerminatingIfEmpty(0, true);
		sqlStore_2->setEnableTerminatingIfSqlError(0, true);
		delete sqlStore_2;
		sqlStore_2 = NULL;
	}
	if(loadFromQFiles) {
		delete loadFromQFiles;
		loadFromQFiles = NULL;
	}
	
	if(custom_headers_cdr) {
		delete custom_headers_cdr;
		custom_headers_cdr = NULL;
	}
	if(custom_headers_message) {
		delete custom_headers_message;
		custom_headers_message = NULL;
	}
	
	termIpacc();
	
	if(opt_bogus_dumper_path[0]) {
		delete bogusDumper;
		bogusDumper = NULL;
	}
	
	thread_cleanup();
}

void main_init_sqlstore() {
	if(isSqlDriver("mysql")) {
		if(opt_load_query_from_files != 2) {
			sqlStore = new FILE_LINE MySqlStore(mysql_host, mysql_user, mysql_password, mysql_database, opt_mysql_port,
							    cloud_host, cloud_token);
			if(opt_save_query_to_files) {
				sqlStore->queryToFiles(opt_save_query_to_files, opt_save_query_to_files_directory, opt_save_query_to_files_period);
			}
			if(use_mysql_2()) {
				sqlStore_2 = new FILE_LINE MySqlStore(mysql_2_host, mysql_2_user, mysql_2_password, mysql_2_database, opt_mysql_2_port);
				if(opt_save_query_to_files) {
					sqlStore_2->queryToFiles(opt_save_query_to_files, opt_save_query_to_files_directory, opt_save_query_to_files_period);
				}
			}
		}
		if(opt_load_query_from_files) {
			loadFromQFiles = new FILE_LINE MySqlStore(mysql_host, mysql_user, mysql_password, mysql_database, opt_mysql_port,
								  cloud_host, cloud_token);
			loadFromQFiles->loadFromQFiles(opt_load_query_from_files, opt_load_query_from_files_directory, opt_load_query_from_files_period);
		}
		if(opt_load_query_from_files != 2) {
			if(!opt_nocdr) {
				sqlStore->connect(STORE_PROC_ID_CDR_1);
				sqlStore->connect(STORE_PROC_ID_MESSAGE_1);
			}
			if(opt_mysqlstore_concat_limit) {
				sqlStore->setDefaultConcatLimit(opt_mysqlstore_concat_limit);
				if(sqlStore_2) {
					sqlStore_2->setDefaultConcatLimit(opt_mysqlstore_concat_limit);
				}
			}
			for(int i = 0; i < opt_mysqlstore_max_threads_cdr; i++) {
				if(opt_mysqlstore_concat_limit_cdr) {
					sqlStore->setConcatLimit(STORE_PROC_ID_CDR_1 + i, opt_mysqlstore_concat_limit_cdr);
				}
				if(i) {
					sqlStore->setEnableAutoDisconnect(STORE_PROC_ID_CDR_1 + i);
				}
				if(opt_mysql_enable_transactions_cdr) {
					sqlStore->setEnableTransaction(STORE_PROC_ID_CDR_1 + i);
				}
				if(opt_cdr_check_duplicity_callid_in_next_pass_insert) {
					sqlStore->setEnableFixDeadlock(STORE_PROC_ID_CDR_1 + i);
				}
			}
			for(int i = 0; i < opt_mysqlstore_max_threads_message; i++) {
				if(opt_mysqlstore_concat_limit_message) {
					sqlStore->setConcatLimit(STORE_PROC_ID_MESSAGE_1 + i, opt_mysqlstore_concat_limit_message);
				}
				if(i) {
					sqlStore->setEnableAutoDisconnect(STORE_PROC_ID_MESSAGE_1 + i);
				}
				if(opt_mysql_enable_transactions_message) {
					sqlStore->setEnableTransaction(STORE_PROC_ID_MESSAGE_1 + i);
				}
				if(opt_message_check_duplicity_callid_in_next_pass_insert) {
					sqlStore->setEnableFixDeadlock(STORE_PROC_ID_MESSAGE_1 + i);
				}
			}
			for(int i = 0; i < opt_mysqlstore_max_threads_register; i++) {
				if(opt_mysqlstore_concat_limit_register) {
					sqlStore->setConcatLimit(STORE_PROC_ID_REGISTER_1 + i, opt_mysqlstore_concat_limit_register);
				}
				if(i) {
					sqlStore->setEnableAutoDisconnect(STORE_PROC_ID_REGISTER_1 + i);
				}
				if(opt_mysql_enable_transactions_register) {
					sqlStore->setEnableTransaction(STORE_PROC_ID_REGISTER_1 + i);
				}
			}
			MySqlStore *sqlStoreHttp = (MySqlStore*)sqlStore_http();
			for(int i = 0; i < opt_mysqlstore_max_threads_http; i++) {
				if(opt_mysqlstore_concat_limit_http) {
					sqlStoreHttp->setConcatLimit(STORE_PROC_ID_HTTP_1 + i, opt_mysqlstore_concat_limit_http);
				}
				if(i) {
					sqlStoreHttp->setEnableAutoDisconnect(STORE_PROC_ID_HTTP_1 + i);
				}
				if(opt_mysql_enable_transactions_http) {
					sqlStoreHttp->setEnableTransaction(STORE_PROC_ID_HTTP_1 + i);
				}
			}
			for(int i = 0; i < opt_mysqlstore_max_threads_webrtc; i++) {
				if(opt_mysqlstore_concat_limit_webrtc) {
					sqlStore->setConcatLimit(STORE_PROC_ID_WEBRTC_1 + i, opt_mysqlstore_concat_limit_webrtc);
				}
				if(i) {
					sqlStore->setEnableAutoDisconnect(STORE_PROC_ID_WEBRTC_1 + i);
				}
				if(opt_mysql_enable_transactions_webrtc) {
					sqlStore->setEnableTransaction(STORE_PROC_ID_WEBRTC_1 + i);
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
			if(!opt_nocdr && opt_autoload_from_sqlvmexport) {
				sqlStore->autoloadFromSqlVmExport();
				if(sqlStore_2) {
					sqlStore_2->autoloadFromSqlVmExport();
				}
			}
		}
	}
}

void terminate_packetbuffer() {
	if(is_enable_packetbuffer()) {
		pthread_mutex_lock(&terminate_packetbuffer_lock);
		extern bool pstat_quietly_errors;
		pstat_quietly_errors = true;
		
		if(pcapQueueI) {
			pcapQueueI->terminate();
		}
		sleep(1);
		if(is_read_from_file_by_pb() && opt_tcpreassembly_thread) {
			if(tcpReassemblyHttp) {
				tcpReassemblyHttp->setIgnoreTerminating(false);
			}
			if(tcpReassemblyWebrtc) {
				tcpReassemblyWebrtc->setIgnoreTerminating(false);
			}
			if(tcpReassemblySsl) {
				tcpReassemblySsl->setIgnoreTerminating(false);
			}
			if(tcpReassemblySipExt) {
				tcpReassemblySipExt->setIgnoreTerminating(false);
			}
			sleep(2);
		}
		if(pcapQueueQ) {
			pcapQueueQ->terminate();
		}
		sleep(1);
		
		if(tcpReassemblyHttp) {
			delete tcpReassemblyHttp;
			tcpReassemblyHttp = NULL;
		}
		if(httpData) {
			delete httpData;
			httpData = NULL;
		}
		if(tcpReassemblyWebrtc) {
			delete tcpReassemblyWebrtc;
			tcpReassemblyWebrtc = NULL;
		}
		if(webrtcData) {
			delete webrtcData;
			webrtcData = NULL;
		}
		if(tcpReassemblySsl) {
			delete tcpReassemblySsl;
			tcpReassemblySsl = NULL;
		}
		if(sslData) {
			delete sslData;
			sslData = NULL;
		}
		if(tcpReassemblySipExt) {
			delete tcpReassemblySipExt;
			tcpReassemblySipExt = NULL;
		}
		if(sipTcpData) {
			delete sipTcpData;
			sipTcpData = NULL;
		}
		
		if(pcapQueueI) {
			delete pcapQueueI;
			pcapQueueI = NULL;
		}
		if(pcapQueueQ_outThread_defrag) {
			delete pcapQueueQ_outThread_defrag;
			pcapQueueQ_outThread_defrag = NULL;
		}
		if(pcapQueueQ) {
			delete pcapQueueQ;
			pcapQueueQ = NULL;
		}
	}
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
	CheckInternational *ci = new FILE_LINE CheckInternational();
	ci->setInternationalMinLength(9);
	CountryPrefixes *cp = new FILE_LINE CountryPrefixes();
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
	GeoIP_country *ipc = new FILE_LINE GeoIP_country();
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
		
		fbuffer[i] = new FILE_LINE char[bufferLength];
		
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
 
	char *str = (char*)"INVITE sip:800123456@sip.odorik.cz SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.12:5061;rport;branch=z9hG4bK354557323\r\nFrom: <sip:706912@sip.odorik.cz>;tag=1645803335\r\nTo: <sip:800123456@sip.odorik.cz>\r\nCall-ID: 1781060762\r\nCSeq: 20 INVITE\r\nContact: <sip:jumbox@93.91.52.46>\r\nContent-Type: application/sdp\r\nAllow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\nMax-Forwards: 70\r\nUser-Agent: Linphone/3.6.1 (eXosip2/3.6.0)\r\nSubject: Phone call\r\nContent-Length: 453\r\n\r\nv=0\r\no=706912 1477 2440 IN IP4 93.91.52.46\r\ns=Talk\r\nc=IN IP4 93.91.52.46\r\nt=0 0\r\nm=audio 7078 RTP/AVP 125 112 111 110 96 3 0 8 101\r\na=rtpmap:125 opus/48000\r\na=fmtp:125 useinbandfec=1; usedtx=1\r\na=rtpmap:112 speex/32000\r\na=fmtp:112 vbr=on\r\na=rtpmap:111 speex/16000\r\na=fmtp:111 vbr=on\r\na=rtpmap:110 speex/8000\r\na=fmtp:110 vbr=on\r\na=rtpmap:96 GSM/11025\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-11\r\nm=video 9078 RTP/AVP 103\r\na=rtpmap:103 VP8/90000\r\n\177\026\221V";
	
	ParsePacket::ppContentsX contents(&pp);
	pp.parseData(str, strlen(str), &contents);
	
	pp.debugData(&contents);
}
	
void test_parsepacket2() {
	ParsePacket pp;
	pp.addNode("test1", ParsePacket::typeNode_std);
	pp.addNode("test2", ParsePacket::typeNode_std);
	pp.addNode("test3", ParsePacket::typeNode_std);
	
	char *str = (char*)"test1abc\ntEst2def\ntest3ghi";
	
	ParsePacket::ppContentsX contents(&pp);
	pp.parseData(str, strlen(str), &contents);
	
	cout << "test1: " << contents.getContentString("test1") << endl;
	cout << "test2: " << contents.getContentString("test2") << endl;
	cout << "test3: " << contents.getContentString("test3") << endl;
	
	pp.debugData(&contents);
}

void test_reg() {
	cout << reg_match("123456789", "456", __FILE__, __LINE__) << endl;
	cout << reg_replace("123456789", "(.*)(456)(.*)", "$1-$2-$3", __FILE__, __LINE__) << endl;
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

void test_alloc_speed() {
	extern unsigned int HeapSafeCheck;
	uint32_t ii = 1000000;
	cout << "HeapSafeCheck: " << HeapSafeCheck << endl;
	for(int p = 0; p < 10; p++) {
		char **pointers = new FILE_LINE char*[ii];
		for(u_int32_t i = 0; i < ii; i++) {
			pointers[i] = new FILE_LINE char[1000];
		}
		for(u_int32_t i = 0; i < ii; i++) {
			delete [] pointers[i];
		}
		delete pointers;
	}
}

void test_alloc_speed_malloc() {
	extern unsigned int HeapSafeCheck;
	uint32_t ii = 1000000;
	cout << "HeapSafeCheck: " << HeapSafeCheck << endl;
	for(int p = 0; p < 10; p++) {
		char **pointers = new FILE_LINE char*[ii];
		for(u_int32_t i = 0; i < ii; i++) {
			pointers[i] = (char*)malloc(1000);
		}
		for(u_int32_t i = 0; i < ii; i++) {
			free(pointers[i]);
		}
		delete pointers;
	}
}

#ifdef HAVE_LIBTCMALLOC
#if HAVE_LIBTCMALLOC
extern "C" {
void* tc_malloc(size_t size);
void tc_free(void*);
}
void test_alloc_speed_tc() {
	extern unsigned int HeapSafeCheck;
	uint32_t ii = 1000000;
	cout << "HeapSafeCheck: " << HeapSafeCheck << endl;
	for(int p = 0; p < 10; p++) {
		char **pointers = new FILE_LINE char*[ii];
		for(u_int32_t i = 0; i < ii; i++) {
			pointers[i] = (char*)tc_malloc(1000);
		}
		for(u_int32_t i = 0; i < ii; i++) {
			tc_free(pointers[i]);
		}
		delete pointers;
	}
}
#endif
#endif

void test_untar() {
	Tar tar;
	tar.tar_open("/var/spool/voipmonitor_local/2015-01-30/19/26/SIP/sip_2015-01-30-19-26.tar", O_RDONLY);
	tar.tar_read("1309960312.pcap.*", "1309960312.pcap", 659493, "cdr");
}

void test_http_dumper() {
	HttpPacketsDumper dumper;
	dumper.setPcapName("/tmp/testhttp.pcap");
	//dumper.setTemplatePcapName();
	string timestamp_from = "2013-09-22 15:48:51";
	string timestamp_to = "2013-09-24 01:48:51";
	string ids = "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20";
	dumper.dumpData(timestamp_from.c_str(), timestamp_to.c_str(), ids.c_str());
}

void test_pexec() {
	const char *cmdLine = "rrdtool graph - -w 582 -h 232 -a PNG --start \"now-3606s\" --end \"now-6s\" --font DEFAULT:0:Courier --title \"CPU usage\" --watermark \"`date`\" --disable-rrdtool-tag --vertical-label \"percent[%]\" --lower-limit 0 --units-exponent 0 --full-size-mode -c BACK#e9e9e9 -c SHADEA#e9e9e9 -c SHADEB#e9e9e9 DEF:t0=/var/spool/voipmonitor_local/rrd/db-tCPU.rrd:tCPU-t0:MAX DEF:t1=/var/spool/voipmonitor_local/rrd/db-tCPU.rrd:tCPU-t1:MAX DEF:t2=/var/spool/voipmonitor_local/rrd/db-tCPU.rrd:tCPU-t2:MAX LINE1:t0#0000FF:\"t0 CPU Usage %\\l\" COMMENT:\"\\u\" GPRINT:t0:LAST:\"Cur\\: %5.2lf\" GPRINT:t0:AVERAGE:\"Avg\\: %5.2lf\" GPRINT:t0:MAX:\"Max\\: %5.2lf\" GPRINT:t0:MIN:\"Min\\: %5.2lf\\r\" LINE1:t1#00FF00:\"t1 CPU Usage %\\l\" COMMENT:\"\\u\" GPRINT:t1:LAST:\"Cur\\: %5.2lf\" GPRINT:t1:AVERAGE:\"Avg\\: %5.2lf\" GPRINT:t1:MAX:\"Max\\: %5.2lf\" GPRINT:t1:MIN:\"Min\\: %5.2lf\\r\" LINE1:t2#FF0000:\"t2 CPU Usage %\\l\" COMMENT:\"\\u\" GPRINT:t2:LAST:\"Cur\\: %5.2lf\" GPRINT:t2:AVERAGE:\"Avg\\: %5.2lf\" GPRINT:t2:MAX:\"Max\\: %5.2lf\" GPRINT:t2:MIN:\"Min\\: %5.2lf\\r\"";
	//cmdLine = "sh -c 'cd /;make;'";
	
	SimpleBuffer out;
	SimpleBuffer err;
	int exitCode;
	cout << "vm_pexec rslt:" << vm_pexec(cmdLine, &out, &err, &exitCode) << endl;
	cout << "OUT SIZE:" << out.size() << endl;
	cout << "OUT:" << (char*)out << endl;
	cout << "ERR SIZE:" << err.size() << endl;
	cout << "ERR:" << (char*)err << endl;
	cout << "exit code:" << exitCode << endl;
}

bool save_packet(const char *binaryPacketFile, const char *rsltPcapFile, int length, time_t sec, suseconds_t usec) {
	FILE *file = fopen(binaryPacketFile, "rb");
	u_char *packet = new FILE_LINE u_char[length];
	if(file) {
		fread(packet, length, 1, file);
		fclose(file);
	} else {
		cerr << "failed open file: " << binaryPacketFile << endl;
		delete [] packet;
		return(false);
	}
	pcap_pkthdr header;
	memset(&header, 0, sizeof(header));
	header.caplen = length;
	header.len = length;
	header.ts.tv_sec = sec;
	header.ts.tv_usec = usec;
	PcapDumper *dumper = new FILE_LINE PcapDumper(PcapDumper::na, NULL);
	dumper->setEnableAsyncWrite(false);
	dumper->setTypeCompress(FileZipHandler::compress_na);
	bool rslt;
	if(dumper->open(rsltPcapFile, 1)) {
		dumper->dump(&header, packet, 1, true);
		rslt = true;
	} else {
		cerr << "failed write file: " << rsltPcapFile << endl;
		rslt = false;
	}
	delete dumper;
	delete [] packet;
	return(rslt);
}

class cTestCompress : public CompressStream {
public:
	cTestCompress(CompressStream::eTypeCompress typeCompress)
	 : CompressStream(typeCompress, 1024 * 8, 0) {
	}
	bool compress_ev(char *data, u_int32_t len, u_int32_t decompress_len, bool format_data = false) {
		fwrite(data, 1, len, fileO);
		return(true);
	}
	bool decompress_ev(char *data, u_int32_t len) { 
		fwrite(data, 1, len, fileO);
		return(true); 
	}
	void testCompress() {
		fileI = fopen("/tmp/tc1.pcap", "rb");
		if(!fileI) {
			return;
		}
		fileO = fopen("/tmp/tc1_c.pcap", "wb");
		if(!fileO) {
			return;
		}
		char buff[5000];
		size_t readSize;
		while((readSize = fread(buff, 1, sizeof(buff), fileI))) {
			this->compress(buff, readSize, false, this);
		}
		fclose(fileI);
		fclose(fileO);
	}
	void testDecompress() {
		fileI = fopen("/tmp/tc1_c.pcap", "rb");
		if(!fileI) {
			return;
		}
		fileO = fopen("/tmp/tc1_d.pcap", "wb");
		if(!fileO) {
			return;
		}
		char buff[5000];
		size_t readSize;
		while((readSize = fread(buff, 1, sizeof(buff), fileI))) {
			this->decompress(buff, readSize, readSize * 10, false, this);
		}
		fclose(fileI);
		fclose(fileO);
	}
private:
	FILE *fileI;
	FILE *fileO;
};

void test_time_cache() {
	cout << "-----------------" << endl;
	time_t now;
	time(&now);
	for(int i = 0; i <= 4 * 60 * 6; i++) {
		cout << "-- " << i << endl;
		cout << "local " << time_r_str(&now, "local") << endl;
		cout << "gmt   " << time_r_str(&now, "GMT") << endl;
		cout << "EST   " << time_r_str(&now, "EST") << endl;
		cout << "NY    " << time_r_str(&now, "America/New_York") << endl;
		cout << "LA    " << time_r_str(&now, "America/Los_Angeles") << endl;
		cout << "NF    " << time_r_str(&now, "Canada/Newfoundland") << endl;
		now += 10;
	}
	cout << "-----------------" << endl;
}

void test_ip_groups() {
	/*
	GroupsIP gip;
	gip.load();
	GroupIP *gr = gip.getGroup("192.168.3.5");
	if(gr) {
		cout << gr->getDescr() << endl;
	}
	*/
}

#ifdef HEAP_CHUNK_ENABLE
#include "heap_chunk.h"
void test_heapchunk() {
	void **testP = new FILE_LINE void*[1000000];
	for(int pass = 0; pass < 2; pass++) {
		u_int64_t startTime = getTimeNS();
		unsigned allocSize = 1000;
		for(int j = 0; j < 10; j++) {
			for(int i = 0; i < 100000; i++) {
				testP[i] = pass == 0 ?
					    ChunkMAlloc(allocSize) :
					    malloc(allocSize);
			}
			for(int i = 0; i < 100000 / 2; i++) {
				if(pass == 0) {
					ChunkFree(testP[i]);
				} else {
					free(testP[i]);
				}
			}
		}
		u_int64_t endTime = getTimeNS();
		cout << endTime - startTime << endl;
	}
}
#endif //HEAP_CHUNK_ENABLE

void test_filezip_handler() {
	FileZipHandler *fzh = new FILE_LINE FileZipHandler(8 * 1024, 0, FileZipHandler::gzip);
	fzh->open("/home/jumbox/Plocha/test.gz");
	for(int i = 0; i < 1000; i++) {
		char buff[1000];
		sprintf(buff, "abcd %80s %i\n", "x", i + 1);
		fzh->write(buff, strlen(buff));
	}
	fzh->write((char*)"eof", 3);
	fzh->close();
	delete fzh;
	fzh = new FILE_LINE FileZipHandler(8 * 1024, 0, FileZipHandler::gzip);
	fzh->open("/home/jumbox/Plocha/test.gz");
	while(!fzh->is_eof() && fzh->is_ok_decompress() && fzh->read(2)) {
		string line;
		while(fzh->getLineFromReadBuffer(&line)) {
			cout << line;
		}
	}
	cout << "|" << endl;
	delete fzh;
}

void test() {
 
	switch(opt_test) {
	 
	case 21 : {
		for(int pass = 0; pass < 1000; pass++) {
		cTestCompress *testCompress = new FILE_LINE cTestCompress(CompressStream::lzo);
		testCompress->testCompress();
		//testCompress->testDecompress();
		delete testCompress;
		}
	} break;
	case 22 : {
		for(int pass = 0; pass < 1000; pass++) {
		cTestCompress *testCompress = new FILE_LINE cTestCompress(CompressStream::snappy);
		testCompress->testCompress();
		//testCompress->testDecompress();
		delete testCompress;
		}
	} break;
	case 23 : {
		for(int pass = 0; pass < 1000; pass++) {
		cTestCompress *testCompress = new FILE_LINE cTestCompress(CompressStream::gzip);
		testCompress->setZipLevel(1);
		testCompress->testCompress();
		//testCompress->testDecompress();
		delete testCompress;
		}
	} break;
	
	case 31: {
	 
		if(opt_callidmerge_secret[0] != '\0') {
			// header is encoded - decode it 
		 
			char *s2 = new FILE_LINE char[1024];
			strcpy(s2, opt_test_str + 2);
			int l2 = strlen(s2);
			unsigned char buf[1024];
		 
			char c;
			c = s2[l2];
			s2[l2] = '\0';
			int enclen = base64decode(buf, (const char*)s2, l2);
			static int keysize = strlen(opt_callidmerge_secret);
			s2[l2] = c;
			for(int i = 0; i < enclen; i++) {
				buf[i] = buf[i] ^ opt_callidmerge_secret[i % keysize];
			}
			// s2 is now decrypted call-id
			s2 = (char*)buf;
			l2 = enclen;
			cout << string(s2, l2) << endl;
			
		} else {
			cout << "missing callidmerge_secret" << endl;
		}
		
	} break;
	 
	case 1: {
	 
		test_filezip_handler();
		break;
	 
		cout << getSystemTimezone() << endl;
		cout << getSystemTimezone(1) << endl;
		cout << getSystemTimezone(2) << endl;
		cout << getSystemTimezone(3) << endl;
	 
		//test_time_cache();
		//test_parsepacket();
		break;
	 
		//test_search_country_by_number();
	 
		map<int, string> testmap;
		testmap[1] = "aaa";
		testmap[2] = "bbb";
		
		map<int, string>::iterator iter = testmap.begin();
		
		cout << testmap[1] << testmap[2] << iter->second << endl;
	 
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
	case 51:
		test_alloc_speed();
		break;
	case 52:
		test_alloc_speed_malloc();
		break;
	case 53:
		#ifdef HAVE_LIBTCMALLOC
		test_alloc_speed_tc();
		#else
		cout << "tcmalloc not exists" << endl;
		#endif
		break;
	case 6:
		test_untar();
		break;
	case 7: 
		test_http_dumper(); 
		break;
	case 8: 
		test_pexec();
		break;
	case 9: {
		vector<string> param;
		char *pointToSepOptTest = strchr(opt_test_str, '/');
		if(pointToSepOptTest) {
			param = split(pointToSepOptTest + 1, ',');
		}
		if(param.size() < 5) {
			cout << "missing parameters" << endl
			     << "example: -X9/packet.bin,packet.pcap,214,4655546,54565" << endl
			     << "description: -X9/binary source,output pcap file,length,sec,usec" << endl;
		} else {
			save_packet(param[0].c_str(), param[1].c_str(), atoi(param[2].c_str()),
				    atoi(param[3].c_str()), atoi(param[4].c_str()));
		}
	} break;
	case 10:
		{
		SqlDb *sqlDb = createSqlObject();
		if(!sqlDb->connect()) {
			delete sqlDb;
		}
		SqlDb_mysql *sqlDb_mysql = dynamic_cast<SqlDb_mysql*>(sqlDb);
		SqlDb *sqlDbSrc = new FILE_LINE SqlDb_mysql();
		sqlDbSrc->setConnectParameters(opt_database_backup_from_mysql_host, 
					       opt_database_backup_from_mysql_user,
					       opt_database_backup_from_mysql_password,
					       opt_database_backup_from_mysql_database,
					       opt_database_backup_from_mysql_port);
		if(sqlDbSrc->connect()) {
			SqlDb_mysql *sqlDbSrc_mysql = dynamic_cast<SqlDb_mysql*>(sqlDbSrc);
			sqlDb_mysql->copyFromSourceGuiTables(sqlDbSrc_mysql);
		}
		delete sqlDbSrc;
		delete sqlDb;
		}
		return;
	case 90:
		{
		vector<string> param;
		char *pointToSepOptTest = strchr(opt_test_str, '/');
		if(pointToSepOptTest) {
			param = split(pointToSepOptTest + 1, ',');
		}
		if(param.size() < 1) {
			cout << "missing parameters" << endl
			     << "example: -X90/coredump,outfile" << endl;
		} else {
			parse_heapsafeplus_coredump(param[0].c_str(), param.size() > 1 ? param[1].c_str() : NULL);
		}
		}
		break;
	case 95:
		chdir(opt_chdir);
		check_filesindex();
		set_terminating();
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
		{
		char *pointToSepOptTest = strchr(opt_test_str, '/');
		check_spooldir_filesindex(NULL, pointToSepOptTest ? pointToSepOptTest + 1 : NULL);
		}
		return;
		
	case 11: 
		{
		cConfig config;
		config.addConfigItems();
		config.loadFromConfigFile(configfile);
		cout << "***" << endl;
		cout << config.getContentConfig(true); 
		cout << "***" << endl;
		string jsonStr = config.getJson(true); 
		cout << jsonStr << endl;
		cout << "***" << endl;
		config.setFromJson(jsonStr.c_str(), true);
		cout << "***" << endl;
		config.putToMysql();
		}
		break;
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
		pcapQueue0 = new FILE_LINE PcapQueue_readFromInterface("thread0");
		pcapQueue0->setInterfaceName(ifname);
		//pcapQueue0->setFifoFileForWrite("/tmp/vm_fifo0");
		//pcapQueue0->setFifoWriteHandle(pipeFh[1]);
		pcapQueue0->setEnableAutoTerminate(false);
		
		pcapQueue1 = new FILE_LINE PcapQueue_readFromFifo("thread1", "/__test");
		//pcapQueue1->setFifoFileForRead("/tmp/vm_fifo0");
		pcapQueue1->setInstancePcapHandle(pcapQueue0);
		//pcapQueue1->setFifoReadHandle(pipeFh[0]);
		pcapQueue1->setEnableAutoTerminate(false);
		//pcapQueue1->setPacketServer("127.0.0.1", port, PcapQueue_readFromFifo::directionWrite);
		
		pcapQueue0->start();
		pcapQueue1->start();
	}
	if(opt_test == 2 || opt_test == 3) {
		pcapQueue2 = new FILE_LINE PcapQueue_readFromFifo("server", "/__test/2");
		pcapQueue2->setEnableAutoTerminate(false);
		pcapQueue2->setPacketServer("127.0.0.1", port, PcapQueue_readFromFifo::directionRead);
		
		pcapQueue2->start();
	}
	
	while(!is_terminating()) {
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
	set_terminating();
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
	CustIpCache *custIpCache = new FILE_LINE CustIpCache;
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
	ipfilter = new FILE_LINE IPfilter;
	ipfilter->load();
	ipfilter->dump();

	telnumfilter = new FILE_LINE TELNUMfilter;
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


extern "C"{
void __cyg_profile_func_enter(void *this_fn, void *call_site) __attribute__((no_instrument_function));
void __cyg_profile_func_enter(void *this_fn, void *call_site) {
	extern unsigned int HeapSafeCheck;
	if(!MCB_STACK ||
	   this_fn == syscall || this_fn == get_unix_tid) {
		return;
	}
	unsigned tid = get_unix_tid();
	extern void* threadStack[65536][10];
	extern u_int16_t threadStackSize[65536];
	if(threadStackSize[tid] < 10) {
		threadStack[tid][threadStackSize[tid]] = call_site;
	}
	++threadStackSize[tid];
}
void __cyg_profile_func_exit(void *this_fn, void *call_site) __attribute__((no_instrument_function));
void __cyg_profile_func_exit(void *this_fn, void *call_site) {
	extern unsigned int HeapSafeCheck;
	if(!MCB_STACK ||
	   this_fn == syscall || this_fn == get_unix_tid) {
		return;
	}
	unsigned tid = get_unix_tid();
	extern u_int16_t threadStackSize[65536];
	--threadStackSize[tid];
}
}


//#define HAVE_LIBJEMALLOC

#ifdef HAVE_LIBJEMALLOC
#include <jemalloc/jemalloc.h>
#endif //HAVE_LIBJEMALLOC

string jeMallocStat(bool full) {
	string rslt;
#ifdef HAVE_LIBJEMALLOC
	char tempFileName[L_tmpnam+1];
	tmpnam(tempFileName);
	char *tempFileNamePointer = tempFileName;
	mallctl("prof.dump", NULL, NULL, &tempFileNamePointer, sizeof(char*));
	FILE *jeout = fopen(tempFileName, "rt");
	if(jeout) {
		char *buff = new FILE_LINE char[10000];
		while(fgets(buff, 10000, jeout)) {
			if(full) {
				rslt += buff;
			} else {
				if(reg_match(buff, "MAPPED_LIBRARIES", __FILE__, __LINE__)) {
					break;
				}
				if(*buff) {
					if(reg_match(buff, "^[0-9]+: [0-9]+", __FILE__, __LINE__)) {
						char *pointerToSizeSeparator = strchr(buff, ':');
						if(pointerToSizeSeparator &&
						   atoll(buff) * atoll(pointerToSizeSeparator + 2) > sverb.memory_stat_ignore_limit) {
							rslt += buff;
						}
					} else {
						rslt += buff;
					}
				}
			}
		}
		delete [] buff;
		fclose(jeout);
	}
	unlink(tempFileName);
#else
	rslt = "voipmonitor build without library jemalloc\n";
#endif //HAVE_LIBJEMALLOC
	return(rslt);
}


// CONFIGURATION

void cConfig::addConfigItems() {
 
	// TODO
	// what is ?
	//  - destroy_call_at_bye
	//  - sip-register-active-nologbin
 
	group("sql");
		subgroup("read only");
			addConfigItem((new FILE_LINE cConfigItem_string("sqldriver", sql_driver, sizeof(sql_driver)))
				->setReadOnly());
			addConfigItem((new FILE_LINE cConfigItem_string("mysqlhost", mysql_host, sizeof(mysql_host)))
				->setReadOnly());
			addConfigItem((new FILE_LINE cConfigItem_integer("mysqlport",  &opt_mysql_port))
				->setSubtype("port")
				->setReadOnly());
			addConfigItem((new FILE_LINE cConfigItem_string("mysqlusername", mysql_user, sizeof(mysql_user)))
				->setReadOnly());
			addConfigItem((new FILE_LINE cConfigItem_string("mysqlpassword", mysql_password, sizeof(mysql_password)))
				->setPassword()
				->setReadOnly()
				->setMinor());
			advanced();
				addConfigItem((new FILE_LINE cConfigItem_string("mysqlhost_2", mysql_2_host, sizeof(mysql_2_host)))
					->setReadOnly());
				addConfigItem((new FILE_LINE cConfigItem_integer("mysqlport_2",  &opt_mysql_2_port))
					->setSubtype("port")
					->setReadOnly());
				addConfigItem((new FILE_LINE cConfigItem_string("mysqlusername_2", mysql_2_user, sizeof(mysql_2_user)))
					->setReadOnly());
				addConfigItem((new FILE_LINE cConfigItem_string("mysqlpassword_2", mysql_2_password, sizeof(mysql_2_password)))
					->setPassword()
					->setReadOnly()
					->setMinor());
				addConfigItem(new FILE_LINE cConfigItem_yesno("mysql_2_http",  &opt_mysql_2_http));
		subgroup("main");
			addConfigItem((new FILE_LINE cConfigItem_yesno("query_cache"))
				->setDefaultValueStr("no"));
			advanced();
				addConfigItem(new FILE_LINE cConfigItem_yesno("query_cache_speed", &opt_query_cache_speed));
				normal();
			addConfigItem((new FILE_LINE cConfigItem_yesno("utc", &opt_sql_time_utc))
				->addAlias("sql_time_utc"));
			advanced();
				addConfigItem(new FILE_LINE cConfigItem_yesno("disable_dbupgradecheck", &opt_disable_dbupgradecheck));
				addConfigItem(new FILE_LINE cConfigItem_yesno("only_cdr_next", &opt_only_cdr_next));
				addConfigItem(new FILE_LINE cConfigItem_yesno("check_duplicity_callid_in_next_pass_insert", &opt_cdr_check_duplicity_callid_in_next_pass_insert));
				addConfigItem(new FILE_LINE cConfigItem_yesno("cdr_check_duplicity_callid_in_next_pass_insert", &opt_cdr_check_duplicity_callid_in_next_pass_insert));
				addConfigItem(new FILE_LINE cConfigItem_yesno("message_check_duplicity_callid_in_next_pass_insert", &opt_message_check_duplicity_callid_in_next_pass_insert));
				addConfigItem(new FILE_LINE cConfigItem_string("mysql_timezone", opt_mysql_timezone, sizeof(opt_mysql_timezone)));
				addConfigItem(new FILE_LINE cConfigItem_yesno("autoload_from_sqlvmexport", &opt_autoload_from_sqlvmexport));
				expert();
					addConfigItem(new FILE_LINE cConfigItem_yesno("mysqlcompress", &opt_mysqlcompress));
					addConfigItem(new FILE_LINE cConfigItem_yesno("sqlcallend", &opt_callend));
		subgroup("partitions");
			addConfigItem(new FILE_LINE cConfigItem_yesno("disable_partition_operations", &opt_disable_partition_operations));
			advanced();
				addConfigItem(new FILE_LINE cConfigItem_yesno("partition_operations_in_thread", &opt_partition_operations_in_thread));
				expert();
					addConfigItem(new FILE_LINE cConfigItem_integer("create_old_partitions", &opt_create_old_partitions));
					addConfigItem(new FILE_LINE cConfigItem_string("create_old_partitions_from", opt_create_old_partitions_from, sizeof(opt_create_old_partitions_from)));
		subgroup("scale");
				advanced();
				addConfigItem(new FILE_LINE cConfigItem_integer("mysqlstore_concat_limit", &opt_mysqlstore_concat_limit));
				addConfigItem(new FILE_LINE cConfigItem_integer("mysqlstore_concat_limit_cdr", &opt_mysqlstore_concat_limit_cdr));
				addConfigItem(new FILE_LINE cConfigItem_integer("mysqlstore_concat_limit_message", &opt_mysqlstore_concat_limit_message));
				addConfigItem(new FILE_LINE cConfigItem_integer("mysqlstore_concat_limit_register", &opt_mysqlstore_concat_limit_register));
				addConfigItem(new FILE_LINE cConfigItem_integer("mysqlstore_concat_limit_http", &opt_mysqlstore_concat_limit_http));
				addConfigItem(new FILE_LINE cConfigItem_integer("mysqlstore_concat_limit_webrtc", &opt_mysqlstore_concat_limit_webrtc));
				addConfigItem(new FILE_LINE cConfigItem_integer("mysqlstore_concat_limit_ipacc", &opt_mysqlstore_concat_limit_ipacc));
				addConfigItem((new FILE_LINE cConfigItem_integer("mysqlstore_max_threads_cdr", &opt_mysqlstore_max_threads_cdr))
					->setMaximum(9)->setMinimum(1));
				addConfigItem((new FILE_LINE cConfigItem_integer("mysqlstore_max_threads_message", &opt_mysqlstore_max_threads_message))
					->setMaximum(9)->setMinimum(1));
				addConfigItem((new FILE_LINE cConfigItem_integer("mysqlstore_max_threads_register", &opt_mysqlstore_max_threads_register))
					->setMaximum(9)->setMinimum(1));
				addConfigItem((new FILE_LINE cConfigItem_integer("mysqlstore_max_threads_http", &opt_mysqlstore_max_threads_http))
					->setMaximum(9)->setMinimum(1));
				addConfigItem((new FILE_LINE cConfigItem_integer("mysqlstore_max_threads_webrtc", &opt_mysqlstore_max_threads_webrtc))
					->setMaximum(9)->setMinimum(1));
				addConfigItem((new FILE_LINE cConfigItem_integer("mysqlstore_max_threads_ipacc_base", &opt_mysqlstore_max_threads_ipacc_base))
					->setMaximum(9)->setMinimum(1));
				addConfigItem((new FILE_LINE cConfigItem_integer("mysqlstore_max_threads_ipacc_agreg2", &opt_mysqlstore_max_threads_ipacc_agreg2))
					->setMaximum(9)->setMinimum(1));
				addConfigItem(new FILE_LINE cConfigItem_integer("mysqlstore_limit_queue_register", &opt_mysqlstore_limit_queue_register));
				addConfigItem(new FILE_LINE cConfigItem_yesno("mysqltransactions", &opt_mysql_enable_transactions));
				addConfigItem(new FILE_LINE cConfigItem_yesno("mysqltransactions_cdr", &opt_mysql_enable_transactions_cdr));
				addConfigItem(new FILE_LINE cConfigItem_yesno("mysqltransactions_message", &opt_mysql_enable_transactions_message));
				addConfigItem(new FILE_LINE cConfigItem_yesno("mysqltransactions_register", &opt_mysql_enable_transactions_register));
				addConfigItem(new FILE_LINE cConfigItem_yesno("mysqltransactions_http", &opt_mysql_enable_transactions_http));
				addConfigItem(new FILE_LINE cConfigItem_yesno("mysqltransactions_webrtc", &opt_mysql_enable_transactions_webrtc));
		subgroup("cleaning");
			addConfigItem(new FILE_LINE cConfigItem_integer("cleandatabase"));
			addConfigItem(new FILE_LINE cConfigItem_integer("cleandatabase_cdr", &opt_cleandatabase_cdr));
			addConfigItem(new FILE_LINE cConfigItem_integer("cleandatabase_http_enum", &opt_cleandatabase_http_enum));
			addConfigItem(new FILE_LINE cConfigItem_integer("cleandatabase_webrtc", &opt_cleandatabase_webrtc));
			addConfigItem(new FILE_LINE cConfigItem_integer("cleandatabase_register_state", &opt_cleandatabase_register_state));
			addConfigItem(new FILE_LINE cConfigItem_integer("cleandatabase_register_failed", &opt_cleandatabase_register_failed));
			addConfigItem(new FILE_LINE cConfigItem_integer("cleandatabase_rtp_stat", &opt_cleandatabase_rtp_stat));
		subgroup("backup");
				advanced();
				addConfigItem(new FILE_LINE cConfigItem_string("database_backup_from_date", opt_database_backup_from_date, sizeof(opt_database_backup_from_date)));
				addConfigItem(new FILE_LINE cConfigItem_string("database_backup_from_mysqlhost", opt_database_backup_from_mysql_host, sizeof(opt_database_backup_from_mysql_host)));
				addConfigItem(new FILE_LINE cConfigItem_string("database_backup_from_mysqldb", opt_database_backup_from_mysql_database, sizeof(opt_database_backup_from_mysql_database)));
				addConfigItem(new FILE_LINE cConfigItem_string("database_backup_from_mysqlusername", opt_database_backup_from_mysql_user, sizeof(opt_database_backup_from_mysql_user)));
				addConfigItem(new FILE_LINE cConfigItem_string("database_backup_from_mysqlpassword", opt_database_backup_from_mysql_password, sizeof(opt_database_backup_from_mysql_password)));
				addConfigItem(new FILE_LINE cConfigItem_integer("database_backup_from_mysqlport", &opt_database_backup_from_mysql_port));
				addConfigItem(new FILE_LINE cConfigItem_integer("database_backup_pause", &opt_database_backup_pause));
				addConfigItem(new FILE_LINE cConfigItem_integer("database_backup_insert_threads", &opt_database_backup_insert_threads));
	group("sniffer mode");
		// SNIFFER MODE
		subgroup("main");
			cConfigItem_integer *snifferMode = new FILE_LINE cConfigItem_integer("sniffer_mode", (int*)&sniffer_mode);
			snifferMode
				->setMenuValue()
				->setOnlyMenu()
				->addValues("reading from interfaces or receive from mirrors:1|read from files:2|mirror packets to another sniffer:3")
				->setDefaultValueStr(snifferMode_read_from_interface_str.c_str())
				->setAlwaysShow();
			addConfigItem(snifferMode);
			setDisableIfBegin("sniffer_mode!" + snifferMode_read_from_interface_str);
			addConfigItem(new FILE_LINE cConfigItem_string("interface", ifname, sizeof(ifname)));
				addConfigItem(new FILE_LINE cConfigItem_yesno("use_oneshot_buffer", &opt_use_oneshot_buffer));
				advanced();
			normal();
			addConfigItem(new FILE_LINE cConfigItem_yesno("promisc", &opt_promisc));
			addConfigItem(new FILE_LINE cConfigItem_string("filter", user_filter, sizeof(user_filter)));
			addConfigItem(new FILE_LINE cConfigItem_ip_port("mirror_bind", &opt_pcap_queue_receive_from_ip_port));
			addConfigItem((new FILE_LINE cConfigItem_string("mirror_bind_ip"))
				->setNaDefaultValueStr()
				->setMinor());
			addConfigItem((new FILE_LINE cConfigItem_integer("mirror_bind_port"))
				->setNaDefaultValueStr()
				->setSubtype("port")
				->setMinor());
					expert();
					addConfigItem(new FILE_LINE cConfigItem_integer("mirror_bind_dlt", &opt_pcap_queue_receive_dlt));
			normal();
			setDisableIfBegin("sniffer_mode!" + snifferMode_read_from_files_str);
			addConfigItem(new FILE_LINE cConfigItem_string("scanpcapdir", opt_scanpcapdir, sizeof(opt_scanpcapdir)));
			setDisableIfBegin("sniffer_mode!" + snifferMode_sender_str);
			addConfigItem(new FILE_LINE cConfigItem_ip_port("mirror_destination", &opt_pcap_queue_send_to_ip_port));
			addConfigItem((new FILE_LINE cConfigItem_string("mirror_destination_ip"))
				->setNaDefaultValueStr()
				->setMinor());
			addConfigItem((new FILE_LINE cConfigItem_integer("mirror_destination_port"))
				->setNaDefaultValueStr()
				->setMinor());
			setDisableIfBegin("sniffer_mode=" + snifferMode_read_from_files_str);
			addConfigItem(new FILE_LINE cConfigItem_yesno("mirror_nonblock_mode", &opt_pcap_queues_mirror_nonblock_mode));
			setDisableIfEnd();
		subgroup("scaling");
			setDisableIfBegin("sniffer_mode!" + snifferMode_read_from_interface_str);
			addConfigItem((new FILE_LINE cConfigItem_yesno("threading_mod"))
				->disableNo()
				->addValues("1:1|2:2|3:3|4:4")
				->setDefaultValueStr("4"));
				advanced();
				addConfigItem((new FILE_LINE cConfigItem_integer("preprocess_rtp_threads", &opt_enable_process_rtp_packet))
					->setMaximum(MAX_PROCESS_RTP_PACKET_THREADS)
					->addValues("yes:1|y:1|no:0|n:0")
					->addAlias("enable_process_rtp_packet"));
					expert();
					addConfigItem((new FILE_LINE cConfigItem_integer("process_rtp_packets_hash_next_thread", &opt_process_rtp_packets_hash_next_thread))
						->setMaximum(MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS)
						->addValues("yes:1|y:1|no:0|n:0"));
					addConfigItem((new FILE_LINE cConfigItem_yesno("process_rtp_packets_hash_next_thread_sem_sync", &opt_process_rtp_packets_hash_next_thread_sem_sync))
						->addValues("2:2"));
					addConfigItem(new FILE_LINE cConfigItem_integer("process_rtp_packets_qring_length", &opt_process_rtp_packets_qring_length));
					addConfigItem(new FILE_LINE cConfigItem_integer("process_rtp_packets_qring_usleep", &opt_process_rtp_packets_qring_usleep));
						obsolete();
						addConfigItem((new FILE_LINE cConfigItem_yesno("enable_preprocess_packet", &opt_enable_preprocess_packet))
							->addValues("sip:2|extend:3|auto:-1"));
						addConfigItem(new FILE_LINE cConfigItem_integer("preprocess_packets_qring_length", &opt_preprocess_packets_qring_length));
						addConfigItem(new FILE_LINE cConfigItem_integer("preprocess_packets_qring_usleep", &opt_preprocess_packets_qring_usleep));
						minorEnd();
			setDisableIfEnd();
	group("manager");
		addConfigItem(new FILE_LINE cConfigItem_string("managerip", opt_manager_ip, sizeof(opt_manager_ip)));
		addConfigItem(new FILE_LINE cConfigItem_integer("managerport", &opt_manager_port));
	group("buffers and memory usage");
		subgroup("main");
			addConfigItem((new FILE_LINE cConfigItem_integer("max_buffer_mem"))
				->setNaDefaultValueStr());
			addConfigItem((new FILE_LINE cConfigItem_integer("ringbuffer", &opt_ringbuffer))
				->setMaximum(2000));
		subgroup("scaling");
				advanced();
				addConfigItem((new FILE_LINE cConfigItem_integer("rtpthreads", &num_threads_set))
					->setIfZeroOrNegative(max(sysconf(_SC_NPROCESSORS_ONLN) - 1, 1l)));
					expert();
					addConfigItem(new FILE_LINE cConfigItem_yesno("savertp-threaded", &opt_rtpsave_threaded));
				addConfigItem(new FILE_LINE cConfigItem_yesno("packetbuffer_compress", &opt_pcap_queue_compress));
				addConfigItem(new FILE_LINE cConfigItem_integer("pcap_queue_dequeu_window_length", &opt_pcap_queue_dequeu_window_length));
				addConfigItem(new FILE_LINE cConfigItem_integer("pcap_queue_dequeu_need_blocks", &opt_pcap_queue_dequeu_need_blocks));
				addConfigItem(new FILE_LINE cConfigItem_integer("pcap_queue_iface_qring_size", &opt_pcap_queue_iface_qring_size));
					expert();
					addConfigItem(new FILE_LINE cConfigItem_integer("pcap_queue_dequeu_method", &opt_pcap_queue_dequeu_method));
					addConfigItem(new FILE_LINE cConfigItem_integer("pcap_queue_use_blocks", &opt_pcap_queue_use_blocks));
					addConfigItem((new FILE_LINE cConfigItem_integer("packetbuffer_block_maxsize", &opt_pcap_queue_block_max_size))
						->setMultiple(1024));
					addConfigItem(new FILE_LINE cConfigItem_integer("packetbuffer_block_maxtime", &opt_pcap_queue_block_max_time_ms));
		subgroup("file cache");
					expert();
					addConfigItem((new FILE_LINE cConfigItem_integer("packetbuffer_file_totalmaxsize", &opt_pcap_queue_store_queue_max_disk_size))
						->setMultiple(1024 * 1024));
					addConfigItem(new FILE_LINE cConfigItem_string("packetbuffer_file_path", &opt_pcap_queue_disk_folder));
	group("data storing");
		setDisableIfBegin("sniffer_mode=" + snifferMode_sender_str);
		subgroup("main");
			addConfigItem(new FILE_LINE cConfigItem_string("spooldir", opt_chdir, sizeof(opt_chdir)));
			addConfigItem(new FILE_LINE cConfigItem_yesno("tar", &opt_pcap_dump_tar));
				advanced();
				addConfigItem(new FILE_LINE cConfigItem_string("convertchar", opt_convert_char, sizeof(opt_convert_char)));
				addConfigItem(new FILE_LINE cConfigItem_string("cachedir", opt_cachedir, sizeof(opt_cachedir)));
					expert();
					addConfigItem(new FILE_LINE cConfigItem_yesno("convert_dlt_sll2en10", &opt_convert_dlt_sll_to_en10));
					addConfigItem(new FILE_LINE cConfigItem_yesno("dumpallpackets", &opt_pcapdump));
					addConfigItem((new FILE_LINE cConfigItem_integer("dumpallallpackets", &opt_pcapdump_all))
						->setYes(1000));
					addConfigItem(new FILE_LINE cConfigItem_string("dumpallallpackets_path", opt_pcapdump_all_path, sizeof(opt_pcapdump_all_path)));
					addConfigItem(new FILE_LINE cConfigItem_string("bogus_dumper_path", opt_bogus_dumper_path, sizeof(opt_bogus_dumper_path)));
		subgroup("scaling");
			addConfigItem(new FILE_LINE cConfigItem_integer("tar_maxthreads", &opt_pcap_dump_tar_threads));
				advanced();
				addConfigItem(new FILE_LINE cConfigItem_integer("maxpcapsize", &opt_maxpcapsize_mb));
					expert();
					addConfigItem(new FILE_LINE cConfigItem_integer("pcap_dump_bufflength", &opt_pcap_dump_bufflength));
					addConfigItem(new FILE_LINE cConfigItem_integer("pcap_dump_writethreads", &opt_pcap_dump_writethreads));
					addConfigItem(new FILE_LINE cConfigItem_yesno("pcap_dump_asyncwrite", &opt_pcap_dump_asyncwrite));
					addConfigItem(new FILE_LINE cConfigItem_yesno("defer_create_spooldir", &opt_defer_create_spooldir));
		subgroup("SIP");
			addConfigItem(new FILE_LINE cConfigItem_yesno("savesip", &opt_saveSIP));
					expert();
					addConfigItem(new FILE_LINE cConfigItem_type_compress("pcap_dump_zip_sip", &opt_pcap_dump_zip_sip));
					addConfigItem(new FILE_LINE cConfigItem_integer("pcap_dump_ziplevel_sip", &opt_pcap_dump_ziplevel_sip));
					addConfigItem((new FILE_LINE cConfigItem_yesno("tar_compress_sip", &opt_pcap_dump_tar_compress_sip))
						->addValues("zip:1|z:1|gzip:1|g:1|lz4:2|l:2|no:0|n:0|0:0"));
					addConfigItem(new FILE_LINE cConfigItem_integer("tar_sip_level", &opt_pcap_dump_tar_sip_level));
					addConfigItem(new FILE_LINE cConfigItem_type_compress("tar_internalcompress_sip", &opt_pcap_dump_tar_internalcompress_sip));
					addConfigItem(new FILE_LINE cConfigItem_integer("tar_internal_sip_level", &opt_pcap_dump_tar_internal_gzip_sip_level));
		subgroup("RTP/RTCP/UDPTL");
			addConfigItem((new FILE_LINE cConfigItem_yesno("savertp"))
				->addValues("header:-1|h:-1")
				->setDefaultValueStr("no"));
			addConfigItem(new FILE_LINE cConfigItem_yesno("savertcp", &opt_saveRTCP));
			addConfigItem(new FILE_LINE cConfigItem_yesno("saveudptl", &opt_saveudptl));
					expert();
					addConfigItem(new FILE_LINE cConfigItem_type_compress("pcap_dump_zip_rtp", &opt_pcap_dump_zip_rtp));
					addConfigItem(new FILE_LINE cConfigItem_integer("pcap_dump_ziplevel_rtp", &opt_pcap_dump_ziplevel_rtp));
					addConfigItem((new FILE_LINE cConfigItem_yesno("tar_compress_rtp", &opt_pcap_dump_tar_compress_rtp))
						->addValues("zip:1|z:1|gzip:1|g:1|lz4:2|l:2|no:0|n:0|0:0"));
					addConfigItem(new FILE_LINE cConfigItem_integer("tar_rtp_level", &opt_pcap_dump_tar_rtp_level));
					addConfigItem(new FILE_LINE cConfigItem_type_compress("tar_internalcompress_rtp", &opt_pcap_dump_tar_internalcompress_rtp));
					addConfigItem(new FILE_LINE cConfigItem_integer("tar_internal_rtp_level", &opt_pcap_dump_tar_internal_gzip_rtp_level));
		subgroup("GRAPH");
			addConfigItem((new FILE_LINE cConfigItem_yesno("savegraph"))
				->addValues("plain:1|p:1|gzip:2|g:2")
				->setDefaultValueStr("no"));
					expert();
					addConfigItem(new FILE_LINE cConfigItem_type_compress("pcap_dump_zip_graph", &opt_gzipGRAPH));
					addConfigItem(new FILE_LINE cConfigItem_integer("pcap_dump_ziplevel_graph", &opt_pcap_dump_ziplevel_graph));
					addConfigItem((new FILE_LINE cConfigItem_yesno("tar_compress_graph", &opt_pcap_dump_tar_compress_graph))
						->addValues("zip:1|z:1|gzip:1|g:1|lz4:2|l:2|no:0|n:0|0:0"));
					addConfigItem(new FILE_LINE cConfigItem_integer("tar_graph_level", &opt_pcap_dump_tar_graph_level));
					addConfigItem(new FILE_LINE cConfigItem_type_compress("tar_internalcompress_graph", &opt_pcap_dump_tar_internalcompress_graph));
					addConfigItem(new FILE_LINE cConfigItem_integer("tar_internal_graph_level", &opt_pcap_dump_tar_internal_gzip_graph_level));
		subgroup("AUDIO");
			addConfigItem((new FILE_LINE cConfigItem_yesno("saveaudio"))
				->addValues("wav:1|w:1|ogg:2|o:2")
				->setDefaultValueStr("no"));
				advanced();
				addConfigItem(new FILE_LINE cConfigItem_yesno("saveaudio_stereo", &opt_saveaudio_stereo));
				addConfigItem(new FILE_LINE cConfigItem_yesno("saveaudio_reversestereo", &opt_saveaudio_reversestereo));
				addConfigItem(new FILE_LINE cConfigItem_float("ogg_quality", &opt_saveaudio_oggquality));
				addConfigItem(new FILE_LINE cConfigItem_integer("audioqueue_threads_max", &opt_audioqueue_threads_max));
					expert();
					addConfigItem(new FILE_LINE cConfigItem_yesno("plcdisable", &opt_disableplc));
		setDisableIfEnd();
	group("data spool directory cleaning");
		setDisableIfBegin("sniffer_mode=" + snifferMode_sender_str);
			advanced();
			addConfigItem(new FILE_LINE cConfigItem_integer("cleanspool_interval", &opt_cleanspool_interval));
		normal();
		addConfigItem(new FILE_LINE cConfigItem_hour_interval("cleanspool_enable_fromto", &opt_cleanspool_enable_run_hour_from, &opt_cleanspool_enable_run_hour_to));
		addConfigItem(new FILE_LINE cConfigItem_integer("maxpoolsize", &opt_maxpoolsize));
		addConfigItem(new FILE_LINE cConfigItem_integer("maxpooldays", &opt_maxpooldays));
		addConfigItem(new FILE_LINE cConfigItem_integer("maxpoolsipsize", &opt_maxpoolsipsize));
		addConfigItem(new FILE_LINE cConfigItem_integer("maxpoolsipdays", &opt_maxpoolsipdays));
		addConfigItem(new FILE_LINE cConfigItem_integer("maxpoolrtpsize", &opt_maxpoolrtpsize));
		addConfigItem(new FILE_LINE cConfigItem_integer("maxpoolrtpdays", &opt_maxpoolrtpdays));
		addConfigItem(new FILE_LINE cConfigItem_integer("maxpoolgraphsize", &opt_maxpoolgraphsize));
		addConfigItem(new FILE_LINE cConfigItem_integer("maxpoolgraphdays", &opt_maxpoolgraphdays));
		addConfigItem(new FILE_LINE cConfigItem_integer("maxpoolaudiosize", &opt_maxpoolaudiosize));
		addConfigItem(new FILE_LINE cConfigItem_integer("maxpoolaudiodays", &opt_maxpoolaudiodays));
			advanced();
			addConfigItem(new FILE_LINE cConfigItem_yesno("maxpool_clean_obsolete", &opt_maxpool_clean_obsolete));
			addConfigItem(new FILE_LINE cConfigItem_integer("autocleanspoolminpercent", &opt_autocleanspoolminpercent));
			addConfigItem((new FILE_LINE cConfigItem_integer("autocleanmingb", &opt_autocleanmingb))
				->addAlias("autocleanspoolmingb"));
		setDisableIfEnd();
	group("IP protocol");
		addConfigItem(new FILE_LINE cConfigItem_yesno("deduplicate", &opt_dup_check));
		addConfigItem(new FILE_LINE cConfigItem_yesno("deduplicate_ipheader", &opt_dup_check_ipheader));
		addConfigItem(new FILE_LINE cConfigItem_yesno("udpfrag", &opt_udpfrag));
		addConfigItem(new FILE_LINE cConfigItem_yesno("dscp", &opt_dscp));
				expert();
				addConfigItem(new FILE_LINE cConfigItem_string("tcpreassembly_log", opt_tcpreassembly_log, sizeof(opt_tcpreassembly_log)));
	group("SSL");
		setDisableIfBegin("sniffer_mode=" + snifferMode_sender_str);
		addConfigItem((new FILE_LINE cConfigItem_yesno("ssl", &opt_enable_ssl))
			->addValue("only", 2));
		addConfigItem(new FILE_LINE cConfigItem_ip_port_str_map("ssl_ipport", &ssl_ipport));
		addConfigItem(new FILE_LINE cConfigItem_integer("ssl_link_timeout", &opt_ssl_link_timeout));
		setDisableIfEnd();
	group("SKINNY");
		setDisableIfBegin("sniffer_mode=" + snifferMode_sender_str);
		addConfigItem(new FILE_LINE cConfigItem_yesno("skinny", &opt_skinny));
		addConfigItem((new FILE_LINE cConfigItem_integer("skinny_ignore_rtpip", &opt_skinny_ignore_rtpip))
			->setIp());
		setDisableIfEnd();
	group("CDR");
		setDisableIfBegin("sniffer_mode=" + snifferMode_sender_str);
			advanced();
			addConfigItem(new FILE_LINE cConfigItem_integer("absolute_timeout", &absolute_timeout));
			addConfigItem(new FILE_LINE cConfigItem_integer("onewaytimeout", &opt_onewaytimeout));
			addConfigItem(new FILE_LINE cConfigItem_yesno("nocdr", &opt_nocdr));
			addConfigItem((new FILE_LINE cConfigItem_string("cdr_ignore_response", opt_nocdr_for_last_responses, sizeof(opt_nocdr_for_last_responses)))
				->addAlias("nocdr_for_last_responses"));
			addConfigItem(new FILE_LINE cConfigItem_yesno("skipdefault", &opt_skipdefault));
			addConfigItem(new FILE_LINE cConfigItem_yesno("cdronlyanswered", &opt_cdronlyanswered));
			addConfigItem(new FILE_LINE cConfigItem_yesno("cdr_check_exists_callid", &opt_cdr_check_exists_callid));
			addConfigItem(new FILE_LINE cConfigItem_yesno("cdronlyrtp", &opt_cdronlyrtp));
			addConfigItem(new FILE_LINE cConfigItem_integer("callslimit", &opt_callslimit));
			addConfigItem(new FILE_LINE cConfigItem_yesno("cdrproxy", &opt_cdrproxy));
		setDisableIfEnd();
	group("SIP protocol / headers");
		setDisableIfBegin("sniffer_mode=" + snifferMode_sender_str);
		subgroup("main");
			addConfigItem(new FILE_LINE cConfigItem_ports("sipport", sipportmatrix));
			addConfigItem(new FILE_LINE cConfigItem_yesno("cdr_sipport", &opt_cdr_sipport));
			addConfigItem(new FILE_LINE cConfigItem_integer("domainport", &opt_domainport));
			addConfigItem((new FILE_LINE cConfigItem_string("fbasenameheader", opt_fbasename_header, sizeof(opt_fbasename_header)))
				->setPrefix("\n")
				->addAlias("fbasename_header"));
			addConfigItem((new FILE_LINE cConfigItem_string("matchheader", opt_match_header, sizeof(opt_match_header)))
				->setPrefix("\n")
				->addAlias("match_header"));
			addConfigItem((new FILE_LINE cConfigItem_string("callidmerge_header", opt_callidmerge_header, sizeof(opt_callidmerge_header)))
				->setPrefix("\n"));
			addConfigItem(new FILE_LINE cConfigItem_string("callidmerge_secret", opt_callidmerge_secret, sizeof(opt_callidmerge_secret)));
				advanced();
				addConfigItem(new FILE_LINE cConfigItem_yesno("custom_headers_last_value", &opt_custom_headers_last_value));
				addConfigItem(new FILE_LINE cConfigItem_yesno("remotepartyid", &opt_remotepartyid));
				addConfigItem(new FILE_LINE cConfigItem_yesno("passertedidentity", &opt_passertedidentity));
				addConfigItem(new FILE_LINE cConfigItem_yesno("ppreferredidentity", &opt_ppreferredidentity));
				addConfigItem(new FILE_LINE cConfigItem_yesno("remotepartypriority", &opt_remotepartypriority));
				addConfigItem(new FILE_LINE cConfigItem_integer("destination_number_mode", &opt_destination_number_mode));
				addConfigItem(new FILE_LINE cConfigItem_yesno("cdr_ua_enable", &opt_cdr_ua_enable));
				addConfigItem(new FILE_LINE cConfigItem_string("cdr_ua_reg_remove", &opt_cdr_ua_reg_remove));
				addConfigItem(new FILE_LINE cConfigItem_yesno("sipoverlap", &opt_sipoverlap));
				addConfigItem(new FILE_LINE cConfigItem_yesno("update_dstnum_onanswer", &opt_update_dstnum_onanswer));
				addConfigItem(new FILE_LINE cConfigItem_integer("sdp_multiplication", &opt_sdp_multiplication));
				addConfigItem(new FILE_LINE cConfigItem_yesno("save_sip_responses", &opt_cdr_sipresp));
				addConfigItem((new FILE_LINE cConfigItem_string("save_sip_history", &opt_save_sip_history))
					->addStringItems("invite|bye|cancel|register|message|info|subscribe|options|notify|ack|prack|publish|refer|update|REQUESTS|RESPONSES|ALL"));
		subgroup("REGISTER");
			addConfigItem(new FILE_LINE cConfigItem_yesno("sip-register", &opt_sip_register));
			addConfigItem(new FILE_LINE cConfigItem_integer("sip-register-timeout", &opt_register_timeout));
		subgroup("MESSAGE");
			addConfigItem(new FILE_LINE cConfigItem_yesno("hide_message_content", &opt_hide_message_content));
			addConfigItem(new FILE_LINE cConfigItem_string("hide_message_content_secret", opt_hide_message_content_secret, sizeof(opt_hide_message_content_secret)));
		subgroup("SIP send");
				advanced();
				addConfigItem(new FILE_LINE cConfigItem_ip_port("sip_send", &sipSendSocket_ip_port));
				addConfigItem((new FILE_LINE cConfigItem_string("sip_send_ip"))
					->setNaDefaultValueStr()
					->setMinor());
				addConfigItem((new FILE_LINE cConfigItem_integer("sip_send_port"))
					->setNaDefaultValueStr()
					->setMinor());
				addConfigItem(new FILE_LINE cConfigItem_yesno("sip_send_udp", &opt_sip_send_udp));
				addConfigItem(new FILE_LINE cConfigItem_yesno("sip_send_before_packetbuffer", &opt_sip_send_before_packetbuffer));
		setDisableIfEnd();
	group("RTP / DTMF / FAX options");
		setDisableIfBegin("sniffer_mode=" + snifferMode_sender_str);
		subgroup("main");
			addConfigItem(new FILE_LINE cConfigItem_integer("rtptimeout", &rtptimeout));
			addConfigItem(new FILE_LINE cConfigItem_yesno("cdr_rtpport", &opt_cdr_rtpport));
			addConfigItem(new FILE_LINE cConfigItem_yesno("cdr_rtpsrcport ", &opt_cdr_rtpsrcport ));
			addConfigItem(new FILE_LINE cConfigItem_integer("sipwithoutrtptimeout", &sipwithoutrtptimeout));
			addConfigItem(new FILE_LINE cConfigItem_yesno("allow-zerossrc", &opt_allow_zerossrc));
			addConfigItem(new FILE_LINE cConfigItem_yesno("rtp-check-timestamp", &opt_rtp_check_timestamp));
			addConfigItem(new FILE_LINE cConfigItem_yesno("rtp-firstleg", &opt_rtp_firstleg));
			addConfigItem(new FILE_LINE cConfigItem_yesno("saverfc2833", &opt_saverfc2833));
			addConfigItem(new FILE_LINE cConfigItem_yesno("dtmf2db", &opt_dbdtmf));
			addConfigItem(new FILE_LINE cConfigItem_yesno("inbanddtmf", &opt_inbanddtmf));
			addConfigItem(new FILE_LINE cConfigItem_integer("silencethreshold", &opt_silencethreshold));
			addConfigItem(new FILE_LINE cConfigItem_yesno("silencedetect", &opt_silencedetect));
			addConfigItem(new FILE_LINE cConfigItem_yesno("clippingdetect", &opt_clippingdetect));
			addConfigItem(new FILE_LINE cConfigItem_yesno("norecord-header", &opt_norecord_header));
			addConfigItem(new FILE_LINE cConfigItem_yesno("norecord-dtmf", &opt_norecord_dtmf));
			addConfigItem(new FILE_LINE cConfigItem_string("pauserecordingdtmf", opt_silencedtmfseq, sizeof(opt_silencedtmfseq)));
			addConfigItem(new FILE_LINE cConfigItem_string("pauserecordingheader", opt_silenceheader, sizeof(opt_silenceheader)));
			addConfigItem(new FILE_LINE cConfigItem_integer("pauserecordingdtmf_timeout", &opt_pauserecordingdtmf_timeout));
			addConfigItem(new FILE_LINE cConfigItem_yesno("182queuedpauserecording", &opt_182queuedpauserecording));
			addConfigItem(new FILE_LINE cConfigItem_yesno("vlan_siprtpsame", &opt_vlan_siprtpsame));
				advanced();
				addConfigItem(new FILE_LINE cConfigItem_yesno("rtpmap_by_callerd", &opt_rtpmap_by_callerd));
				addConfigItem(new FILE_LINE cConfigItem_yesno("disable_rtp_warning", &opt_disable_rtp_warning));
		subgroup("NAT");
			addConfigItem(new FILE_LINE cConfigItem_nat_aliases("natalias", &nat_aliases));
			addConfigItem(new FILE_LINE cConfigItem_yesno("sdp_reverse_ipport", &opt_sdp_reverse_ipport));
		subgroup("MOS");
			addConfigItem(new FILE_LINE cConfigItem_yesno("mos_g729", &opt_mos_g729));
			addConfigItem(new FILE_LINE cConfigItem_yesno("mos_lqo", &opt_mos_lqo));
			addConfigItem(new FILE_LINE cConfigItem_string("mos_lqo_bin", opt_mos_lqo_bin, sizeof(opt_mos_lqo_bin)));
			addConfigItem(new FILE_LINE cConfigItem_string("mos_lqo_ref", opt_mos_lqo_ref, sizeof(opt_mos_lqo_ref)));
			addConfigItem(new FILE_LINE cConfigItem_string("mos_lqo_ref16", opt_mos_lqo_ref16, sizeof(opt_mos_lqo_ref16)));
		subgroup("FAX");
			addConfigItem(new FILE_LINE cConfigItem_yesno("faxdetect", &opt_faxt30detect));
		subgroup("jitterbufer");
			addConfigItem(new FILE_LINE cConfigItem_yesno("jitterbuffer_f1", &opt_jitterbuffer_f1));
			addConfigItem(new FILE_LINE cConfigItem_yesno("jitterbuffer_f2", &opt_jitterbuffer_f2));
			addConfigItem(new FILE_LINE cConfigItem_yesno("jitterbuffer_adapt", &opt_jitterbuffer_adapt));
			addConfigItem(new FILE_LINE cConfigItem_yesno("enable_jitterbuffer_asserts", &opt_enable_jitterbuffer_asserts));
		setDisableIfEnd();
	group("system");
		addConfigItem(new FILE_LINE cConfigItem_string("pcapcommand", pcapcommand, sizeof(pcapcommand)));
		addConfigItem(new FILE_LINE cConfigItem_string("filtercommand", filtercommand, sizeof(filtercommand)));
		addConfigItem(new FILE_LINE cConfigItem_integer("openfile_max", &opt_openfile_max));
		addConfigItem(new FILE_LINE cConfigItem_yesno("rrd", &opt_rrd));
		addConfigItem(new FILE_LINE cConfigItem_string("php_path", opt_php_path, sizeof(opt_php_path)));
		addConfigItem(new FILE_LINE cConfigItem_string("syslog_string", opt_syslog_string, sizeof(opt_syslog_string)));
		addConfigItem(new FILE_LINE cConfigItem_integer("cpu_limit_new_thread", &opt_cpu_limit_new_thread));
		addConfigItem(new FILE_LINE cConfigItem_integer("cpu_limit_delete_thread", &opt_cpu_limit_delete_thread));
		addConfigItem(new FILE_LINE cConfigItem_integer("cpu_limit_delete_t2sip_thread", &opt_cpu_limit_delete_t2sip_thread));
	group("upgrade");
		addConfigItem(new FILE_LINE cConfigItem_yesno("upgrade_try_http_if_https_fail", &opt_upgrade_try_http_if_https_fail));
		addConfigItem(new FILE_LINE cConfigItem_string("curlproxy", opt_curlproxy, sizeof(opt_curlproxy)));
		addConfigItem(new FILE_LINE cConfigItem_yesno("upgrade_by_git", &opt_upgrade_by_git));
		addConfigItem(new FILE_LINE cConfigItem_string("git_folder", opt_git_folder, sizeof(opt_git_folder)));
	group("locale");
		addConfigItem(new FILE_LINE cConfigItem_string("local_country_code", opt_local_country_code, sizeof(opt_local_country_code)));
		addConfigItem(new FILE_LINE cConfigItem_string("timezone", opt_timezone, sizeof(opt_timezone)));
	group("ipaccount");
			advanced();
			addConfigItem(new FILE_LINE cConfigItem_yesno("ipaccount", &opt_ipaccount));
			addConfigItem(new FILE_LINE cConfigItem_ports("ipaccountport", ipaccountportmatrix));
			addConfigItem(new FILE_LINE cConfigItem_integer("ipaccount_interval", &opt_ipacc_interval));
			addConfigItem(new FILE_LINE cConfigItem_integer("ipaccount_only_agregation", &opt_ipacc_only_agregation));
				expert();
				addConfigItem(new FILE_LINE cConfigItem_yesno("ipaccount_sniffer_agregate", &opt_ipacc_sniffer_agregate));
				addConfigItem(new FILE_LINE cConfigItem_yesno("ipaccount_agregate_only_customers_on_main_side", &opt_ipacc_agregate_only_customers_on_main_side));
				addConfigItem(new FILE_LINE cConfigItem_yesno("ipaccount_agregate_only_customers_on_any_side", &opt_ipacc_agregate_only_customers_on_any_side));

	minorGroupIfNotSetBegin();
	group("http");
			advanced();
			addConfigItem((new FILE_LINE cConfigItem_yesno("http", &opt_enable_http))
				->addValue("only", 2)
				->addAlias("tcpreassembly"));
			addConfigItem(new FILE_LINE cConfigItem_ports("httpport", httpportmatrix));
			addConfigItem(new FILE_LINE cConfigItem_hosts("httpip", &httpip, &httpnet));
				expert();
				addConfigItem((new FILE_LINE cConfigItem_yesno("enable_http_enum_tables", &opt_enable_http_enum_tables))
					->addAlias("enable_lua_tables"));
	group("webrtc");
			advanced();
			addConfigItem((new FILE_LINE cConfigItem_yesno("webrtc", &opt_enable_webrtc))
				->addValue("only", 2));
			addConfigItem(new FILE_LINE cConfigItem_ports("webrtcport", webrtcportmatrix));
			addConfigItem(new FILE_LINE cConfigItem_hosts("webrtcip", &webrtcip, &webrtcnet));
				expert();
				addConfigItem(new FILE_LINE cConfigItem_yesno("enable_webrtc_table", &opt_enable_webrtc_table));
	group("ipaccount extended");
				expert();
				addConfigItem(new FILE_LINE cConfigItem_string("get_customer_by_ip_sql_driver", get_customer_by_ip_sql_driver, sizeof(get_customer_by_ip_sql_driver)));
				addConfigItem(new FILE_LINE cConfigItem_string("get_customer_by_ip_odbc_dsn", get_customer_by_ip_odbc_dsn, sizeof(get_customer_by_ip_odbc_dsn)));
				addConfigItem(new FILE_LINE cConfigItem_string("get_customer_by_ip_odbc_user", get_customer_by_ip_odbc_user, sizeof(get_customer_by_ip_odbc_user)));
				addConfigItem(new FILE_LINE cConfigItem_string("get_customer_by_ip_odbc_password", get_customer_by_ip_odbc_password, sizeof(get_customer_by_ip_odbc_password)));
				addConfigItem(new FILE_LINE cConfigItem_string("get_customer_by_ip_odbc_driver", get_customer_by_ip_odbc_driver, sizeof(get_customer_by_ip_odbc_driver)));
				addConfigItem(new FILE_LINE cConfigItem_string("get_customer_by_ip_query", get_customer_by_ip_query, sizeof(get_customer_by_ip_query)));
				addConfigItem(new FILE_LINE cConfigItem_string("get_customers_ip_query", get_customers_ip_query, sizeof(get_customers_ip_query)));
				addConfigItem(new FILE_LINE cConfigItem_string("get_customers_radius_name_query", get_customers_radius_name_query, sizeof(get_customers_radius_name_query)));
				addConfigItem(new FILE_LINE cConfigItem_string("get_customer_by_pn_sql_driver", get_customer_by_pn_sql_driver, sizeof(get_customer_by_pn_sql_driver)));
				addConfigItem(new FILE_LINE cConfigItem_string("get_customer_by_pn_odbc_dsn", get_customer_by_pn_odbc_dsn, sizeof(get_customer_by_pn_odbc_dsn)));
				addConfigItem(new FILE_LINE cConfigItem_string("get_customer_by_pn_odbc_user", get_customer_by_pn_odbc_user, sizeof(get_customer_by_pn_odbc_user)));
				addConfigItem(new FILE_LINE cConfigItem_string("get_customer_by_pn_odbc_password", get_customer_by_pn_odbc_password, sizeof(get_customer_by_pn_odbc_password)));
				addConfigItem(new FILE_LINE cConfigItem_string("get_customer_by_pn_odbc_driver", get_customer_by_pn_odbc_driver, sizeof(get_customer_by_pn_odbc_driver)));
				addConfigItem(new FILE_LINE cConfigItem_string("get_customers_pn_query", get_customers_pn_query, sizeof(get_customers_pn_query)));
				addConfigItem(new FILE_LINE cConfigItem_string("national_prefix", &opt_national_prefix));
				addConfigItem(new FILE_LINE cConfigItem_string("get_radius_ip_driver", get_radius_ip_driver, sizeof(get_radius_ip_driver)));
				addConfigItem(new FILE_LINE cConfigItem_string("get_radius_ip_host", get_radius_ip_host, sizeof(get_radius_ip_host)));
				addConfigItem(new FILE_LINE cConfigItem_string("get_radius_ip_db", get_radius_ip_db, sizeof(get_radius_ip_db)));
				addConfigItem(new FILE_LINE cConfigItem_string("get_radius_ip_user", get_radius_ip_user, sizeof(get_radius_ip_user)));
				addConfigItem(new FILE_LINE cConfigItem_string("get_radius_ip_password", get_radius_ip_password, sizeof(get_radius_ip_password)));
				addConfigItem(new FILE_LINE cConfigItem_yesno("get_radius_ip_disable_secure_auth", &get_radius_ip_disable_secure_auth));
				addConfigItem(new FILE_LINE cConfigItem_string("get_radius_ip_query", get_radius_ip_query, sizeof(get_radius_ip_query)));
				addConfigItem(new FILE_LINE cConfigItem_string("get_radius_ip_query_where", get_radius_ip_query_where, sizeof(get_radius_ip_query_where)));
				addConfigItem(new FILE_LINE cConfigItem_integer("get_customer_by_ip_flush_period", &get_customer_by_ip_flush_period));
	minorGroupIfNotSetEnd();

	minorBegin();
	group("other");
		subgroup("sensor id");
			addConfigItem((new FILE_LINE cConfigItem_integer("id_sensor", &opt_id_sensor))
				->setReadOnly());
			addConfigItem(new FILE_LINE cConfigItem_string("name_sensor", opt_name_sensor, sizeof(opt_name_sensor)));
				advanced();
				addConfigItem(new FILE_LINE cConfigItem_yesno("spooldir_by_sensor", &opt_spooldir_by_sensor));
					expert();
					addConfigItem(new FILE_LINE cConfigItem_yesno("spooldir_by_sensorname", &opt_spooldir_by_sensorname));
		subgroup("sql");
			addConfigItem(new FILE_LINE cConfigItem_string("mysqldb", mysql_database, sizeof(mysql_database)));
				advanced();
				addConfigItem(new FILE_LINE cConfigItem_string("mysqldb_2", mysql_2_database, sizeof(mysql_2_database)));
				addConfigItem(new FILE_LINE cConfigItem_yesno("mysql_client_compress", &opt_mysql_client_compress));
					expert();
					addConfigItem(new FILE_LINE cConfigItem_string("odbcdsn", odbc_dsn, sizeof(odbc_dsn)));
					addConfigItem(new FILE_LINE cConfigItem_string("odbcuser", odbc_user, sizeof(odbc_user)));
					addConfigItem(new FILE_LINE cConfigItem_string("odbcpass", odbc_password, sizeof(odbc_password)));
					addConfigItem(new FILE_LINE cConfigItem_string("odbcdriver", odbc_driver, sizeof(odbc_driver)));
					addConfigItem(new FILE_LINE cConfigItem_yesno("cdr_partition", &opt_cdr_partition));
					addConfigItem(new FILE_LINE cConfigItem_yesno("save_query_to_files", &opt_save_query_to_files));
					addConfigItem(new FILE_LINE cConfigItem_string("save_query_to_files_directory", opt_save_query_to_files_directory, sizeof(opt_save_query_to_files_directory)));
					addConfigItem(new FILE_LINE cConfigItem_integer("save_query_to_files_period", &opt_save_query_to_files_period));
					addConfigItem((new FILE_LINE cConfigItem_yesno("load_query_from_files", &opt_load_query_from_files))
						->addValue("only", 2));
					addConfigItem(new FILE_LINE cConfigItem_string("load_query_from_files_directory", opt_load_query_from_files_directory, sizeof(opt_load_query_from_files_directory)));
					addConfigItem(new FILE_LINE cConfigItem_integer("load_query_from_files_period", &opt_load_query_from_files_period));
					addConfigItem(new FILE_LINE cConfigItem_yesno("load_query_from_files_inotify", &opt_load_query_from_files_inotify));
					addConfigItem(new FILE_LINE cConfigItem_yesno("mysqlloadconfig", &opt_mysqlloadconfig));
						obsolete();
						addConfigItem((new FILE_LINE cConfigItem_custom_headers("custom_headers_cdr", &opt_custom_headers_cdr))
							->addAlias("custom_headers"));
						addConfigItem(new FILE_LINE cConfigItem_custom_headers("custom_headers_message", &opt_custom_headers_message));
						addConfigItem(new FILE_LINE cConfigItem_string("sqlcdrtable", sql_cdr_table, sizeof(sql_cdr_table)));
						addConfigItem(new FILE_LINE cConfigItem_string("sqlcdrtable_last30d", sql_cdr_table_last30d, sizeof(sql_cdr_table_last30d)));
						addConfigItem(new FILE_LINE cConfigItem_string("sqlcdrtable_last7d", sql_cdr_table_last7d, sizeof(sql_cdr_table_last1d)));
						addConfigItem(new FILE_LINE cConfigItem_string("sqlcdrtable_last1d", sql_cdr_table_last7d, sizeof(sql_cdr_table_last1d)));
						addConfigItem((new FILE_LINE cConfigItem_string("sqlcdrnexttable", sql_cdr_next_table, sizeof(sql_cdr_next_table)))
							->addAlias("sqlcdr_next_table"));
						addConfigItem((new FILE_LINE cConfigItem_string("sqlcdruatable", sql_cdr_ua_table, sizeof(sql_cdr_ua_table)))
							->addAlias("sqlcdr_ua_table"));
						addConfigItem((new FILE_LINE cConfigItem_string("sqlcdrsipresptable", sql_cdr_sip_response_table, sizeof(sql_cdr_sip_response_table)))
							->addAlias("sqlcdr_sipresp_table"));
		subgroup("interface - read packets");
					expert();
					addConfigItem(new FILE_LINE cConfigItem_integer("rtp_qring_length", &rtp_qring_length));
					addConfigItem(new FILE_LINE cConfigItem_integer("rtp_qring_usleep", &rtp_qring_usleep));
					addConfigItem((new FILE_LINE cConfigItem_yesno("rtp_qring_quick", &rtp_qring_quick))
						->addValue("boost", 2));
		subgroup("mirroring");
					expert();
					addConfigItem(new FILE_LINE cConfigItem_yesno("mirrorip", &opt_mirrorip));
					addConfigItem(new FILE_LINE cConfigItem_yesno("mirrorall", &opt_mirrorall));
					addConfigItem(new FILE_LINE cConfigItem_yesno("mirroronly", &opt_mirroronly));
					addConfigItem(new FILE_LINE cConfigItem_string("mirroripsrc", opt_mirrorip_src, sizeof(opt_mirrorip_src)));
					addConfigItem(new FILE_LINE cConfigItem_string("mirroripdst", opt_mirrorip_dst, sizeof(opt_mirrorip_dst)));
		subgroup("scanpcapdir");
				advanced();
				char scanpcapmethod_values[100];
				sprintf(scanpcapmethod_values, "close:%i|moved:%i|r:%i", IN_CLOSE_WRITE, IN_MOVED_TO, IN_MOVED_TO);
				addConfigItem((new FILE_LINE cConfigItem_yesno("scanpcapmethod"))
					->disableYes()
					->disableNo()
					->addValues(scanpcapmethod_values));
				addConfigItem(new FILE_LINE cConfigItem_yesno("scanpcapdir_disable_inotify", &opt_scanpcapdir_disable_inotify));
		subgroup("manager");
				advanced();
				addConfigItem(new FILE_LINE cConfigItem_string("managerclient", opt_clientmanager, sizeof(opt_clientmanager)));
				addConfigItem(new FILE_LINE cConfigItem_integer("managerclientport", &opt_clientmanagerport));
				addConfigItem(new FILE_LINE cConfigItem_yesno("manager_nonblock_mode", &opt_manager_nonblock_mode));
					expert();
					addConfigItem(new FILE_LINE cConfigItem_string("manager_sshhost", ssh_host, sizeof(ssh_host)));
					addConfigItem(new FILE_LINE cConfigItem_integer("manager_sshport", &ssh_port));
					addConfigItem(new FILE_LINE cConfigItem_string("manager_sshusername", ssh_username, sizeof(ssh_username)));
					addConfigItem(new FILE_LINE cConfigItem_string("manager_sshpassword", ssh_password, sizeof(ssh_password)));
					addConfigItem(new FILE_LINE cConfigItem_string("manager_sshremoteip", ssh_remote_listenhost, sizeof(ssh_remote_listenhost)));
					addConfigItem(new FILE_LINE cConfigItem_integer("manager_sshremoteport", &ssh_remote_listenport));
		subgroup("spool - cleaning");
						 obsolete();
						 addConfigItem(new FILE_LINE cConfigItem_integer("cleanspool_size", &opt_cleanspool_sizeMB));
		subgroup("packetbuffer & memory");
					expert();
					addConfigItem((new FILE_LINE cConfigItem_integer("packetbuffer_total_maxheap", &opt_pcap_queue_store_queue_max_memory_size))
						->setMultiple(1024 * 1024));
					addConfigItem((new FILE_LINE cConfigItem_yesno("packetbuffer_compress_method"))
						->addValues("snappy:1|s:1|lz4:2|l:2")
						->setDefaultValueStr("no"));
						obsolete();
						addConfigItem(new FILE_LINE cConfigItem_yesno("pcap_dispatch", &opt_pcap_dispatch));
		subgroup("storing packets into pcap files, graph, audio");
					expert();
					addConfigItem(new FILE_LINE cConfigItem_type_compress("pcap_dump_zip", (FileZipHandler::eTypeCompress*)NULL));
					addConfigItem(new FILE_LINE cConfigItem_type_compress("pcap_dump_zip_all", (FileZipHandler::eTypeCompress*)NULL));
					addConfigItem(new FILE_LINE cConfigItem_integer("pcap_dump_ziplevel"));
					addConfigItem(new FILE_LINE cConfigItem_integer("pcap_dump_writethreads_max", &opt_pcap_dump_writethreads_max));
					addConfigItem(new FILE_LINE cConfigItem_yesno("pcapsplit", &opt_pcap_split));
					addConfigItem((new FILE_LINE cConfigItem_yesno("spooldiroldschema", &opt_newdir))
						->setNeg());
					addConfigItem((new FILE_LINE cConfigItem_integer("pcap_dump_asyncwrite_maxsize", &opt_pcap_dump_asyncwrite_maxsize))
						->addAlias("pcap_dump_asyncbuffer"));
		subgroup("cloud");
			addConfigItem(new FILE_LINE cConfigItem_string("cloud_host", cloud_host, sizeof(cloud_host)));
			addConfigItem(new FILE_LINE cConfigItem_string("cloud_url", cloud_url, sizeof(cloud_url)));
			addConfigItem(new FILE_LINE cConfigItem_string("cloud_token", cloud_token, sizeof(cloud_token)));
			addConfigItem(new FILE_LINE cConfigItem_integer("cloud_activecheck_period", &opt_cloud_activecheck_period));
			addConfigItem(new FILE_LINE cConfigItem_string("cloud_url_activecheck", cloud_url_activecheck, sizeof(cloud_url_activecheck)));
		subgroup("other");
			addConfigItem(new FILE_LINE cConfigItem_string("keycheck", opt_keycheck, sizeof(opt_keycheck)));
				advanced();
				addConfigItem(new FILE_LINE cConfigItem_yesno("printinsertid", &opt_printinsertid));
				addConfigItem(new FILE_LINE cConfigItem_yesno("virtualudppacket", &opt_virtualudppacket));
				addConfigItem(new FILE_LINE cConfigItem_yesno("sip_tcp_reassembly_ext", &opt_sip_tcp_reassembly_ext));
					expert();
					addConfigItem(new FILE_LINE cConfigItem_integer("rtpthread-buffer",  &rtpthreadbuffer));
						obsolete();
						addConfigItem(new FILE_LINE cConfigItem_yesno("enable_fraud", &opt_enable_fraud));
	minorEnd();
	
	setDefaultValues();
	
	const char *descriptionsHelpTable[][3] = {
		{ "sqldriver", "SQL driver", "SQL driver - test help text" }
	};
	for(unsigned i = 0; i < sizeof(descriptionsHelpTable) / sizeof(descriptionsHelpTable[0]); i++) {
		if(descriptionsHelpTable[i][1]) {
			setDescription(descriptionsHelpTable[i][0], descriptionsHelpTable[i][1]);
		}
		if(descriptionsHelpTable[i][2]) {
			setHelp(descriptionsHelpTable[i][0], descriptionsHelpTable[i][2]);
		}
	}
}

void cConfig::evSetConfigItem(cConfigItem *configItem) {
	if(configItem->config_name == "ssl_ipport") {
		#ifdef HAVE_LIBGNUTLS
			ssl_init();
		#endif
	}
	if(configItem->config_name == "cleandatabase") {
		opt_cleandatabase_cdr =
		opt_cleandatabase_http_enum =
		opt_cleandatabase_webrtc =
		opt_cleandatabase_register_state =
		opt_cleandatabase_register_failed = configItem->getValueInt();
	}
	if(configItem->config_name == "cleandatabase_cdr") {
		opt_cleandatabase_http_enum =
		opt_cleandatabase_webrtc = opt_cleandatabase_cdr;
	}
	if(configItem->config_name == "id_sensor") {
		opt_id_sensor_cleanspool = opt_id_sensor;
	}
	if(configItem->config_name == "check_duplicity_callid_in_next_pass_insert") {
		opt_message_check_duplicity_callid_in_next_pass_insert = opt_cdr_check_duplicity_callid_in_next_pass_insert;
	}
	if(configItem->config_name == "create_old_partitions_from") {
		opt_create_old_partitions = getNumberOfDayToNow(opt_create_old_partitions_from);
	}
	if(configItem->config_name == "database_backup_from_date") {
		opt_create_old_partitions = getNumberOfDayToNow(opt_database_backup_from_date);
	}
	if(configItem->config_name == "cachedir") {
		mkdir_r(opt_cachedir, 0777);
	}
	if(configItem->config_name == "spooldir") {
		mkdir_r(opt_chdir, 0777);
	}
	if(configItem->config_name == "timezone") {
		if(opt_timezone[0]) {
			setenv("TZ", opt_timezone, 1);
		}
	}
	if(configItem->config_name == "pcap_dump_ziplevel") {
		opt_pcap_dump_ziplevel_sip =
		opt_pcap_dump_ziplevel_rtp =
		opt_pcap_dump_ziplevel_graph = configItem->getValueInt();
	}
	if(configItem->config_name == "savertp") {
		switch(configItem->getValueInt()) {
		case 0:
			opt_saveRTP = 0;
			opt_onlyRTPheader = 0;
			break;
		case 1:
			opt_saveRTP = 1;
			opt_onlyRTPheader = 0;
			break;
		case -1:
			opt_onlyRTPheader = 1;
			opt_saveRTP = 0;
			break;
		}
	}
	if(configItem->config_name == "saveaudio") {
		switch(configItem->getValueInt()) {
		case 0:
			opt_saveWAV = 0;
			opt_audio_format = 0;
			break;
		case 1:
			opt_saveWAV = 1;
			opt_audio_format = FORMAT_WAV;
			break;
		case 2:
			opt_saveWAV = 1;
			opt_audio_format = FORMAT_OGG;
			break;
		}
	}
	if(configItem->config_name == "savegraph") {
		switch(configItem->getValueInt()) {
		case 0:
			opt_saveGRAPH = 0;
			opt_gzipGRAPH = FileZipHandler::compress_na;
			break;
		case 1:
			opt_saveGRAPH = 1;
			opt_gzipGRAPH = FileZipHandler::compress_na;
			break;
		case 2:
			opt_saveGRAPH = 1;
			opt_gzipGRAPH = FileZipHandler::gzip;
			break;
		}
	}
	if(configItem->config_name == "scanpcapmethod") {
		opt_scanpcapmethod = !configItem->getValueStr().empty() && configItem->getValueStr()[0] == 'r' ? IN_MOVED_TO : IN_CLOSE_WRITE;
	}
	if(configItem->config_name == "packetbuffer_compress_method") {
		switch(configItem->getValueInt()) {
		case 0:
			opt_pcap_queue_compress_method = pcap_block_store::compress_method_default;
			break;
		case 1:
			opt_pcap_queue_compress_method = pcap_block_store::snappy;
			break;
		case 2:
			opt_pcap_queue_compress_method = pcap_block_store::lz4;
			break;
		}
	}
	if((configItem->config_name == "mirror_destination" && ((cConfigItem_ip_port*)configItem)->getValue()) || 
	   (configItem->config_name == "mirror_destination_ip" && !configItem->getValueStr().empty())) {
		opt_nocdr = 1;
	}
	if(configItem->config_name == "mirror_destination_ip") {
		opt_pcap_queue_send_to_ip_port.set_ip(configItem->getValueStr());
	}
	if(configItem->config_name == "mirror_destination_port") {
		opt_pcap_queue_send_to_ip_port.set_port(configItem->getValueInt());
	}
	if(configItem->config_name == "mirror_bind_ip") {
		opt_pcap_queue_receive_from_ip_port.set_ip(configItem->getValueStr());
	}
	if(configItem->config_name == "mirror_bind_port") {
		opt_pcap_queue_receive_from_ip_port.set_port(configItem->getValueInt());
	}
	if(configItem->config_name == "threading_mod") {
		setThreadingMode(configItem->getValueInt());
	}
	if(configItem->config_name == "pcap_dump_zip") {
		opt_pcap_dump_zip_sip = 
		opt_pcap_dump_zip_rtp = (FileZipHandler::eTypeCompress)configItem->getValueInt();
	}
	if(configItem->config_name == "pcap_dump_zip_all") {
		opt_pcap_dump_zip_sip =
		opt_pcap_dump_zip_rtp = 
		opt_gzipGRAPH = (FileZipHandler::eTypeCompress)configItem->getValueInt();;
	}
	if(configItem->config_name == "sip_send_ip") {
		sipSendSocket_ip_port.set_ip(configItem->getValueStr());
	}
	if(configItem->config_name == "sip_send_port") {
		sipSendSocket_ip_port.set_port(configItem->getValueInt());
	}
	if(configItem->config_name == "max_buffer_mem") {
		buffersControl.setMaxBufferMem(configItem->getValueInt() * 1024 * 1024, true);
	}
	if(configItem->config_name == "query_cache") {
		if(configItem->getValueInt()) {
			opt_save_query_to_files = true;
			opt_load_query_from_files = 1;
			opt_load_query_from_files_inotify = true;
		}
	}
	if(configItem->config_name == "cdr_ignore_response") {
		parse_opt_nocdr_for_last_responses();
	}
	if(configItem->config_name == "cdr_ua_reg_remove") {
		for(unsigned i = 0; i < opt_cdr_ua_reg_remove.size(); i++) {
			if(!check_regexp(opt_cdr_ua_reg_remove[i].c_str())) {
				syslog(LOG_WARNING, "invalid regexp %s for cdr_ua_reg_remove", opt_cdr_ua_reg_remove[i].c_str());
				opt_cdr_ua_reg_remove.erase(opt_cdr_ua_reg_remove.begin() + i);
				--i;
			}
		}
	}
}

void parse_command_line_arguments(int argc, char *argv[]) {
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
	    {"mono", 0, 0, 201},
	    {"untar-gui", 1, 0, 202},
	    {"unlzo-gui", 1, 0, 205},
	    {"waveform-gui", 1, 0, 206},
	    {"spectrogram-gui", 1, 0, 207},
	    {"update-schema", 0, 0, 208},
	    {"new-config", 0, 0, 203},
	    {"print-config-struct", 0, 0, 204},
	    {"max-packets", 1, 0, 301},
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

	while(1) {
		int c;
		c = getopt_long(argc, argv, "C:f:i:r:d:v:O:h:b:t:u:p:P:s:T:D:e:E:m:X:lLkncUSRoAWGNIKy4Mx", long_options, &option_index);
		if (c == -1)
			break;
		command_line_data[c] = optarg ? optarg : "";
	}
}

void get_command_line_arguments() {
	for(map<int, string>::iterator iter = command_line_data.begin(); iter != command_line_data.end(); iter++) {
		int c = iter->first;
		char *optarg = NULL;
		if(iter->second.length()) {
			optarg = new FILE_LINE char[iter->second.length() + 10];
			strcpy(optarg, iter->second.c_str());
		}
		switch (c) {
			/*
			case 0:
				printf ("option %s\n", long_options[option_index].name);
				break;
			*/
			case 200:
				opt_skinny = 1;
				break;
			case 201:
				opt_saveaudio_stereo = 0;
				break;
			case 202:
				if(!opt_untar_gui_params) {
					opt_untar_gui_params = new FILE_LINE char[strlen(optarg) + 1];
					strcpy(opt_untar_gui_params, optarg);
				}
				break;
			case 205:
				if(!opt_unlzo_gui_params) {
					opt_unlzo_gui_params = new FILE_LINE char[strlen(optarg) + 1];
					strcpy(opt_unlzo_gui_params, optarg);
				}
				break;
			case 206:
				if(!opt_waveform_gui_params) {
					opt_waveform_gui_params =  new FILE_LINE char[strlen(optarg) + 1];
					strcpy(opt_waveform_gui_params, optarg);
				}
				break;
			case 207:
				if(!opt_spectrogram_gui_params) {
					opt_spectrogram_gui_params =  new FILE_LINE char[strlen(optarg) + 1];
					strcpy(opt_spectrogram_gui_params, optarg);
				}
				break;
			case 208:
				updateSchema = true;
				break;
			case 203:
				useNewCONFIG = true;
				break;
			case 204:
				printConfigStruct = true;
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
				num_threads_set = check_set_rtp_threads(atoi(optarg));
				break;
			case 'E':
				rtpthreadbuffer = atoi(optarg);
				break;
			case 's':
				opt_id_sensor = atoi(optarg);
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
				opt_gzipGRAPH = FileZipHandler::gzip;
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
						else if(verbparams[i] == "graph")			sverb.graph = 1;
						else if(verbparams[i] == "read_rtp")			sverb.read_rtp = 1;
						else if(verbparams[i] == "rtp_set_base_seq")		sverb.rtp_set_base_seq = 1;
						else if(verbparams[i] == "check_is_caller_called")	sverb.check_is_caller_called = 1;
						else if(verbparams[i] == "disable_threads_rtp")		sverb.disable_threads_rtp = 1;
						else if(verbparams[i] == "packet_lost")			sverb.packet_lost = 1;
						else if(verbparams[i] == "rrd_info")			sverb.rrd_info = 1;
						else if(verbparams[i] == "http")			sverb.http = 1;
						else if(verbparams[i] == "webrtc")			sverb.webrtc = 1;
						else if(verbparams[i] == "ssl")				sverb.ssl = 1;
						else if(verbparams[i] == "sip")				sverb.sip = 1;
						else if(verbparams[i] == "ssldecode")			sverb.ssldecode = 1;
						else if(verbparams[i] == "ssldecode_debug")		sverb.ssldecode_debug = 1;
						else if(verbparams[i] == "sip_packets")			sverb.sip_packets = 1;
						else if(verbparams[i] == "set_ua")			sverb.set_ua = 1;
						else if(verbparams[i] == "dscp")			sverb.dscp = 1;
						else if(verbparams[i] == "store_process_query")		sverb.store_process_query = 1;
						else if(verbparams[i] == "call_listening")		sverb.call_listening = 1;
						else if(verbparams[i] == "skinny")			sverb.skinny = 1;
						else if(verbparams[i] == "fraud")			sverb.fraud = 1;
						else if(verbparams[i] == "enable_bt_sighandler")	sverb.enable_bt_sighandler = 1;
						else if(verbparams[i].substr(0, 4) == "tar=")
													sverb.tar = atoi(verbparams[i].c_str() + 4);
						else if(verbparams[i] == "tar")				sverb.tar = 1;
						else if(verbparams[i].substr(0, 13) == "chunk_buffer=")
													sverb.chunk_buffer = atoi(verbparams[i].c_str() + 13);
						else if(verbparams[i] == "chunk_buffer")		sverb.chunk_buffer = 1;
						else if(verbparams[i].substr(0, 15) == "tcp_debug_port=")
													sverb.tcp_debug_port = atoi(verbparams[i].c_str() + 15);
						else if(verbparams[i].substr(0, 5) == "ssrc=")          sverb.ssrc = strtol(verbparams[i].c_str() + 5, NULL, 16);
						else if(verbparams[i] == "jitter")			sverb.jitter = 1;
						else if(verbparams[i] == "jitter_na")			opt_jitterbuffer_adapt = 0;
						else if(verbparams[i] == "jitter_nf1")			opt_jitterbuffer_f1 = 0;
						else if(verbparams[i] == "jitter_nf2")			opt_jitterbuffer_f2 = 0;
						else if(verbparams[i] == "noaudiounlink")		sverb.noaudiounlink = 1;
						else if(verbparams[i] == "capture_filter")		sverb.capture_filter = 1;
						else if(verbparams[i].substr(0, 17) == "pcap_stat_period=")
													sverb.pcap_stat_period = atoi(verbparams[i].c_str() + 17);
						else if(verbparams[i] == "memory_stat" ||
							verbparams[i] == "memory_stat_ex")		sverb.memory_stat = 1;
						else if(verbparams[i] == "memory_stat_log" ||
							verbparams[i] == "memory_stat_ex_log")		{sverb.memory_stat = 1; sverb.memory_stat_log = 1;}
						else if(verbparams[i].substr(0, 25) == "memory_stat_ignore_limit=")
													sverb.memory_stat_ignore_limit = atoi(verbparams[i].c_str() + 25);
						else if(verbparams[i] == "qring_stat")			sverb.qring_stat = 1;
						else if(verbparams[i] == "alloc_stat")			sverb.alloc_stat = 1;
						else if(verbparams[i] == "qfiles")			sverb.qfiles = 1;
						else if(verbparams[i] == "query_error")			sverb.query_error = 1;
						else if(verbparams[i] == "dump_sip")			sverb.dump_sip = 1;
						else if(verbparams[i] == "dump_sip_line")		{ sverb.dump_sip = 1; sverb.dump_sip_line = 1; }
						else if(verbparams[i] == "dump_sip_without_counter")	{ sverb.dump_sip = 1; sverb.dump_sip_without_counter = 1; }
						else if(verbparams[i] == "manager")			sverb.manager = 1;
						else if(verbparams[i] == "scanpcapdir")			sverb.scanpcapdir = 1;
						else if(verbparams[i] == "debug_rtcp")			sverb.debug_rtcp = 1;
						else if(verbparams[i] == "defrag")			sverb.defrag = 1;
						else if(verbparams[i] == "dedup")			sverb.dedup = 1;
						else if(verbparams[i] == "reassembly_sip")		sverb.reassembly_sip = 1;
						else if(verbparams[i] == "reassembly_sip_output")	sverb.reassembly_sip_output = 1;
						else if(verbparams[i] == "log_manager_cmd")		sverb.log_manager_cmd = 1;
						else if(verbparams[i] == "rtp_extend_stat")		sverb.rtp_extend_stat = 1;
						else if(verbparams[i] == "disable_process_packet_in_packetbuffer")
													sverb.disable_process_packet_in_packetbuffer = 1;
						else if(verbparams[i] == "disable_push_to_t2_in_packetbuffer")
													sverb.disable_push_to_t2_in_packetbuffer = 1;
						else if(verbparams[i] == "disable_save_packet")		sverb.disable_save_packet = 1;
						else if(verbparams[i] == "thread_create")		sverb.thread_create = 1;
						else if(verbparams[i] == "timezones")			sverb.timezones = 1;
						else if(verbparams[i] == "tcpreplay")			sverb.tcpreplay = 1;
						else if(verbparams[i] == "abort_if_heap_full")		sverb.abort_if_heap_full = 1;
						else if(verbparams[i] == "dtmf")			sverb.dtmf = 1;
						//
						else if(verbparams[i] == "debug1")			sverb._debug1 = 1;
						else if(verbparams[i] == "debug2")			sverb._debug2 = 1;
						else if(verbparams[i] == "debug2")			sverb._debug3 = 1;
					}
				} }
				break;
			case 'r':
				if(!strncmp(optarg, "s:", 2)) {
					opt_read_from_file = true;
					strcpy(opt_read_from_file_fname, optarg + 2);
					opt_read_from_file_no_sip_reassembly = true;
				} else if(!strncmp(optarg, "pb:", 3) ||
					  !strncmp(optarg, "pba:", 4)) {
					bool acttime = !strncmp(optarg, "pba:", 4);
					strcpy(opt_pb_read_from_file, optarg + (acttime ? 4 : 3));
					opt_pb_read_from_file_acttime = acttime;
					opt_scanpcapdir[0] = '\0';
				} else if((!strncmp(optarg, "pbs", 3) ||
					   !strncmp(optarg, "pbsa", 4)) &&
					  strchr(optarg, ':')) {
					bool acttime = !strncmp(optarg, "pbsa", 4);
					opt_pb_read_from_file_speed = atof(optarg + (acttime ? 4 : 3));
					strcpy(opt_pb_read_from_file, strchr(optarg, ':') + 1);
					opt_pb_read_from_file_acttime = acttime;
					opt_scanpcapdir[0] = '\0';
				} else {
					strcpy(opt_read_from_file_fname, optarg);
					opt_read_from_file = 1;
					opt_scanpcapdir[0] = '\0';
					//opt_cachedir[0] = '\0';
					opt_enable_preprocess_packet = 0;
					opt_enable_process_rtp_packet = 0;
				}
				break;
			case 301:
				opt_pb_read_from_file_max_packets = atol(optarg);
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
					opt_gzipGRAPH = FileZipHandler::gzip;
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
		if(optarg) {
			delete [] optarg;
		}
	}
}

void set_context_config() {
 
	if(opt_scanpcapdir[0]) {
		sniffer_mode = snifferMode_read_from_files;
	} else if(opt_pcap_queue_send_to_ip_port) {
		sniffer_mode = snifferMode_sender;
	} else {
		sniffer_mode = snifferMode_read_from_interface;
	}

	if(opt_pcap_queue_receive_from_ip_port || opt_pcap_queue_send_to_ip_port) {
		if(opt_pcap_queue_compress == -1) {
			opt_pcap_queue_compress = 1;
		}
	} else {
		opt_pcap_queue_compress = 0;
	}
	
	if(!is_read_from_file_simple() && 
	   !opt_untar_gui_params && !opt_unlzo_gui_params && !opt_waveform_gui_params && !opt_spectrogram_gui_params &&
	   command_line_data.size()) {
		// restore orig values
		buffersControl.restoreMaxBufferMemFromOrig();
		static u_int64_t opt_pcap_queue_store_queue_max_memory_size_orig = 0;
		if(!opt_pcap_queue_store_queue_max_memory_size_orig) {
			opt_pcap_queue_store_queue_max_memory_size_orig = opt_pcap_queue_store_queue_max_memory_size;
		} else {
			opt_pcap_queue_store_queue_max_memory_size = opt_pcap_queue_store_queue_max_memory_size_orig;
		}
		//
		for(int pass = 0; pass < (buffersControl.isSetOrig() ? 1 : 2); pass++) {
			if(buffersControl.getMaxBufferMem()) {
				u_int64_t totalMemory = getTotalMemory();
				if(buffersControl.getMaxBufferMem() > totalMemory / 2) {
					buffersControl.setMaxBufferMem(totalMemory / 2);
					syslog(LOG_NOTICE, "set buffer memory limit to %lu", totalMemory / 2);
				} else if(pass) {
					break;
				}
			}
			// prepare for old buffer size calculate
			if(buffersControl.getMaxBufferMem()) {
				opt_pcap_queue_store_queue_max_memory_size = buffersControl.getMaxBufferMem() * 0.9;
			}
			// old buffer size calculate &&  set size opt_pcap_queue_bypass_max_size
			if(!opt_pcap_queue_disk_folder.length() || !opt_pcap_queue_store_queue_max_disk_size) {
				// disable disc save
				if(opt_pcap_queue_compress || !opt_pcap_queue_suppress_t1_thread) {
					// enable compress or not suppress t1 thread - maximum thread0 buffer = 100MB, minimum = 50MB
					opt_pcap_queue_bypass_max_size = opt_pcap_queue_store_queue_max_memory_size / 8;
					if(opt_pcap_queue_bypass_max_size > 100 * 1024 * 1024) {
						opt_pcap_queue_bypass_max_size = 100 * 1024 * 1024;
					} else if(opt_pcap_queue_bypass_max_size < 50 * 1024 * 1024) {
						opt_pcap_queue_bypass_max_size = 50 * 1024 * 1024;
					}
				} else {
					// disable compress and suppress t1 thread - thread0 buffer not need
					opt_pcap_queue_bypass_max_size = 0;
				}
			} else {
				// enable disc save - maximum thread0 buffer = 500MB
				opt_pcap_queue_bypass_max_size = opt_pcap_queue_store_queue_max_memory_size / 4;
				if(opt_pcap_queue_bypass_max_size > 500 * 1024 * 1024) {
					opt_pcap_queue_bypass_max_size = 500 * 1024 * 1024;
				}
			}
			// set old buffer size via opt_pcap_queue_bypass_max_size
			if(opt_pcap_queue_store_queue_max_memory_size < opt_pcap_queue_bypass_max_size * 2) {
				opt_pcap_queue_store_queue_max_memory_size = opt_pcap_queue_bypass_max_size * 2;
			} else {
				opt_pcap_queue_store_queue_max_memory_size -= opt_pcap_queue_bypass_max_size;
			}
			// set new buffer size via opt_pcap_queue_bypass_max_size
			if(buffersControl.getMaxBufferMem()) {
				if(buffersControl.getMaxBufferMem() < opt_pcap_queue_bypass_max_size * 2) {
					buffersControl.setMaxBufferMem(opt_pcap_queue_bypass_max_size * 2);
				} else {
					buffersControl.setMaxBufferMem(buffersControl.getMaxBufferMem() - opt_pcap_queue_bypass_max_size);
				}
			} else {
				buffersControl.setMaxBufferMem(opt_pcap_queue_store_queue_max_memory_size + opt_pcap_dump_asyncwrite_maxsize * 1024ull * 1024ull);
			}
		}
		
		if(opt_pcap_queue_receive_from_ip_port) {
			opt_id_sensor_cleanspool = -1;
		}
	}
	
	if(!opt_pcap_split) {
		opt_rtpsave_threaded = 0;
	}
	
	if(opt_enable_http) {
		opt_enable_http_enum_tables = true;
	}
	if(opt_enable_webrtc) {
		opt_enable_webrtc_table = true;
	}
	
	if(rtp_qring_quick == 0 && opt_enable_process_rtp_packet > 1) {
		rtp_qring_quick = 1;
	}
	
	if(opt_read_from_file) {
		opt_enable_preprocess_packet = 0;
		opt_enable_process_rtp_packet = 0;
		opt_enable_http = 0;
		opt_enable_webrtc = 0;
		opt_enable_ssl = 0;
		opt_sip_tcp_reassembly_ext = 0;
		opt_pcap_dump_tar = 0;
		if(opt_pcap_dump_zip_sip == FileZipHandler::compress_default ||
		   opt_pcap_dump_zip_sip == FileZipHandler::lzo) {
			opt_pcap_dump_zip_sip = FileZipHandler::gzip;
		}
		if(opt_pcap_dump_zip_rtp == FileZipHandler::compress_default ||
		   opt_pcap_dump_zip_rtp == FileZipHandler::lzo) {
			opt_pcap_dump_zip_rtp = FileZipHandler::gzip;
		}
		if(opt_gzipGRAPH == FileZipHandler::compress_default ||
		   opt_gzipGRAPH == FileZipHandler::lzo) {
			opt_gzipGRAPH = FileZipHandler::gzip;
		}
		opt_pcap_dump_asyncwrite = 0;
		opt_save_query_to_files = false;
		opt_load_query_from_files = 0;
	}
	
	if(is_read_from_file()) {
		if(is_receiver()) {
			opt_pcap_queue_receive_from_ip_port.clear();
		}
		if(is_read_from_file_simple()) {
			setThreadingMode(1);
		}
		opt_pcap_queue_dequeu_method = 0;
	}
	
	if(opt_pcap_dump_tar) {
		opt_cachedir[0] = '\0';
		if(opt_pcap_dump_tar_compress_sip) {
			opt_pcap_dump_zip_sip = FileZipHandler::compress_na;
		}
		if(opt_pcap_dump_tar_compress_rtp) {
			opt_pcap_dump_zip_rtp = FileZipHandler::compress_na;
		}
		if(opt_pcap_dump_tar_compress_graph) {
			opt_gzipGRAPH = FileZipHandler::compress_na;
		}
	}
	
	if(!opt_newdir && opt_pcap_dump_tar) {
		opt_pcap_dump_tar = 0;
	}
	
	opt_pcap_dump_tar_sip_use_pos = opt_pcap_dump_tar && !opt_pcap_dump_tar_compress_sip;
	opt_pcap_dump_tar_rtp_use_pos = opt_pcap_dump_tar && !opt_pcap_dump_tar_compress_rtp;
	opt_pcap_dump_tar_graph_use_pos = opt_pcap_dump_tar && !opt_pcap_dump_tar_compress_graph;
	
	if(opt_save_query_to_files || opt_load_query_from_files) {
		opt_autoload_from_sqlvmexport = false;
	}
	
	opt_database_backup = !opt_test &&
			      opt_database_backup_from_date[0] != '\0' &&
			      opt_database_backup_from_mysql_host[0] != '\0' &&
			      opt_database_backup_from_mysql_database[0] != '\0' &&
			      opt_database_backup_from_mysql_user[0] != '\0';
		
	
	if(opt_cachedir[0]) {
		opt_defer_create_spooldir = false;
	}
	
	vector<string> ifnamev = split(ifname, split(",|;| |\t|\r|\n", "|"), true);
	if(getThreadingMode() < 2 && ifnamev.size() > 1) {
		setThreadingMode(2);
	}
	
	if(opt_pcap_queue_dequeu_window_length < 0) {
		if(opt_pcap_queue_receive_from_ip_port) {
			 opt_pcap_queue_dequeu_window_length = 2000;
		} else if(ifnamev.size() > 1) {
			 opt_pcap_queue_dequeu_window_length = 1000;
		}
	}
	
	_save_sip_history = false;
	memset(_save_sip_history_request_types, 0, sizeof(_save_sip_history_request_types));
	_save_sip_history_all_requests = false;
	_save_sip_history_all_responses = false;
	if(!opt_save_sip_history.empty()) {
		vector<string> opt_save_sip_history_vector = split(opt_save_sip_history.c_str(), split(",|;", '|'), true);
		for(size_t i = 0; i < opt_save_sip_history_vector.size(); i++) {
			string item = opt_save_sip_history_vector[i];
			std::transform(item.begin(), item.end(),item.begin(), ::toupper);
			if(item == "ALL") {
				_save_sip_history_all_requests = true;
				_save_sip_history_all_responses = true;
				_save_sip_history = true;
			} else if(item == "REQUESTS") {
				_save_sip_history_all_requests = true;
				_save_sip_history = true;
			} else if(item == "RESPONSES") {
				_save_sip_history_all_responses = true;
				_save_sip_history = true;
			} else {
				int requestCode = sip_request_name_to_int(item.c_str());
				if(requestCode) {
					_save_sip_history_request_types[requestCode] = true;
					_save_sip_history = true;
				}
			}
		}
	}
}

bool check_complete_parameters() {
	if (!is_read_from_file() && ifname[0] == '\0' && opt_scanpcapdir[0] == '\0' && 
	    !opt_untar_gui_params && !opt_unlzo_gui_params && !opt_waveform_gui_params && !opt_spectrogram_gui_params &&
	    !printConfigStruct && !is_receiver() &&
	    !opt_test){
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

		return false;
	}
	return true;
}


// OBSOLETE

int eval_config(string inistr) {
 
	if(opt_test == 11) {
		return(0);
	}
 
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
	
	// webrtc ports
	if (ini.GetAllValues("general", "webrtcport", values)) {
		CSimpleIni::TNamesDepend::const_iterator i = values.begin();
		// reset default port 
		for (; i != values.end(); ++i) {
			webrtcportmatrix[atoi(i->pItem)] = 1;
		}
	}
	
	// ssl ip/ports
	if (ini.GetAllValues("general", "ssl_ipport", values)) {
		CSimpleIni::TNamesDepend::const_iterator i = values.begin();
		// reset default port 
		for (; i != values.end(); ++i) {
			u_int32_t ip = 0;
			u_int32_t port = 0;
			string key;
			char *pointToSeparator = strchr((char*)i->pItem, ':');
			if(pointToSeparator) {
				*pointToSeparator = 0;
				ip = htonl(inet_addr(i->pItem));
				++pointToSeparator;
				while(*pointToSeparator == ' ') {
					++pointToSeparator;
				}
				port = atoi(pointToSeparator);
				while(*pointToSeparator != ' ') {
					++pointToSeparator;
				}
				while(*pointToSeparator == ' ') {
					++pointToSeparator;
				}
				key = pointToSeparator;
			}
			if(ip && port) {
				ssl_ipport[d_u_int32_t(ip, port)] = key;
			}
		}
		if(ssl_ipport.size()) {
#ifdef HAVE_LIBGNUTLS
			ssl_init();
#endif
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

	// webrtc ip
	if (ini.GetAllValues("general", "webrtcip", values)) {
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
					webrtcnet.push_back(d_u_int32_t(ip, lengthMask));
				} else {
					webrtcip.push_back(ip);
				}
			}
		}
		if(webrtcip.size() > 1) {
			std::sort(webrtcip.begin(), webrtcip.end());
		}
	}

	// ipacc ports
	if (ini.GetAllValues("general", "ipaccountport", values)) {
		CSimpleIni::TNamesDepend::const_iterator i = values.begin();
		// reset default port 
		for (; i != values.end(); ++i) {
			if(!ipaccountportmatrix) {
				ipaccountportmatrix = new FILE_LINE char[65537];
				memset(ipaccountportmatrix, 0, 65537);
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
		opt_cleandatabase_cdr =
		opt_cleandatabase_http_enum =
		opt_cleandatabase_webrtc =
		opt_cleandatabase_register_state =
		opt_cleandatabase_register_failed = atoi(value);
	}
	if((value = ini.GetValue("general", "plcdisable", NULL))) {
		opt_disableplc = yesno(value);
	}
	if((value = ini.GetValue("general", "rrd", NULL))) {
		opt_rrd = yesno(value);
	}
	if((value = ini.GetValue("general", "remotepartypriority", NULL))) {
		opt_remotepartypriority = yesno(value);
	}
	if((value = ini.GetValue("general", "remotepartyid", NULL))) {
		opt_remotepartyid = yesno(value);
	}
	if((value = ini.GetValue("general", "ppreferredidentity", NULL))) {
		opt_ppreferredidentity = yesno(value);
	}
	if((value = ini.GetValue("general", "passertedidentity", NULL))) {
		opt_passertedidentity = yesno(value);
	}
	if((value = ini.GetValue("general", "cleandatabase_cdr", NULL))) {
		opt_cleandatabase_cdr =
		opt_cleandatabase_http_enum =
		opt_cleandatabase_webrtc = atoi(value);
	}
	if((value = ini.GetValue("general", "cleandatabase_http_enum", NULL))) {
		opt_cleandatabase_http_enum = atoi(value);
	}
	if((value = ini.GetValue("general", "cleandatabase_webrtc", NULL))) {
		opt_cleandatabase_webrtc = atoi(value);
	}
	if((value = ini.GetValue("general", "cleandatabase_register_state", NULL))) {
		opt_cleandatabase_register_state = atoi(value);
	}
	if((value = ini.GetValue("general", "cleandatabase_register_failed", NULL))) {
		opt_cleandatabase_register_failed = atoi(value);
	}
	if((value = ini.GetValue("general", "cleandatabase_rtp_stat", NULL))) {
		opt_cleandatabase_rtp_stat = atoi(value);
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
	if((value = ini.GetValue("general", "autocleanspoolminpercent", NULL))) {
		opt_autocleanspoolminpercent = atoi(value);
	}
	if((value = ini.GetValue("general", "autocleanmingb", NULL)) ||
	   (value = ini.GetValue("general", "autocleanspoolmingb", NULL))) {
		opt_autocleanmingb = atoi(value);
	}
	if((value = ini.GetValue("general", "cleanspool_enable_fromto", NULL))) {
		string fromTo = reg_replace(value, "([0-9]+)[- ]*([0-9]+)", "$1-$2", __FILE__, __LINE__);
		if(fromTo.empty()) {
			int h = atoi(value);
			if(h >= 0 && h < 24) {
				opt_cleanspool_enable_run_hour_from = h;
				opt_cleanspool_enable_run_hour_to = h;
			}
		} else {
			sscanf(fromTo.c_str(), "%i-%i", &opt_cleanspool_enable_run_hour_from, &opt_cleanspool_enable_run_hour_to);
			if(opt_cleanspool_enable_run_hour_from < 0 ||
			   opt_cleanspool_enable_run_hour_from > 23 ||
			   opt_cleanspool_enable_run_hour_to < 0 ||
			   opt_cleanspool_enable_run_hour_to > 23) {
				opt_cleanspool_enable_run_hour_from = -1;
				opt_cleanspool_enable_run_hour_to = -1;
			}
		}
	}
	if((value = ini.GetValue("general", "id_sensor", NULL))) {
		opt_id_sensor = atoi(value);
		opt_id_sensor_cleanspool = opt_id_sensor;
	}
	if((value = ini.GetValue("general", "name_sensor", NULL))) {
		strncpy(opt_name_sensor, value, sizeof(opt_name_sensor));
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
		num_threads_set = check_set_rtp_threads(atoi(value));
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
		if(!opt_nocdr) {
			opt_nocdr = yesno(value);
		}
	}
	if((value = ini.GetValue("general", "cdr_ignore_response", NULL)) ||
	   (value = ini.GetValue("general", "nocdr_for_last_responses", NULL))) {
		strncpy(opt_nocdr_for_last_responses, value, sizeof(opt_nocdr_for_last_responses));
		parse_opt_nocdr_for_last_responses();
	}
	if((value = ini.GetValue("general", "disable_dbupgradecheck", NULL))) {
		opt_disable_dbupgradecheck  = yesno(value);
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
	if((value = ini.GetValue("general", "skinny_ignore_rtpip", NULL))) {
		struct sockaddr_in sa;
		inet_pton(AF_INET, value, &(sa.sin_addr));
		opt_skinny_ignore_rtpip = (unsigned int)(sa.sin_addr.s_addr);
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
	if((value = ini.GetValue("general", "cdr_rtpsrcport", NULL))) {
		opt_cdr_rtpsrcport  = yesno(value);
	}
	if((value = ini.GetValue("general", "cdr_check_exists_callid", NULL))) {
		opt_cdr_check_exists_callid = yesno(value);
	}
	if((value = ini.GetValue("general", "check_duplicity_callid_in_next_pass_insert", NULL))) {
		opt_cdr_check_duplicity_callid_in_next_pass_insert = 
		opt_message_check_duplicity_callid_in_next_pass_insert = yesno(value);
	}
	if((value = ini.GetValue("general", "cdr_check_duplicity_callid_in_next_pass_insert", NULL))) {
		opt_cdr_check_duplicity_callid_in_next_pass_insert = yesno(value);
	}
	if((value = ini.GetValue("general", "message_check_duplicity_callid_in_next_pass_insert", NULL))) {
		opt_message_check_duplicity_callid_in_next_pass_insert = yesno(value);
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
	if((value = ini.GetValue("general", "partition_operations_in_thread", NULL))) {
		opt_partition_operations_in_thread = yesno(value);
	}
	if((value = ini.GetValue("general", "autoload_from_sqlvmexport", NULL))) {
		opt_autoload_from_sqlvmexport = yesno(value);
	}
	if((value = ini.GetValue("general", "cdr_ua_enable", NULL))) {
		opt_cdr_ua_enable = yesno(value);
	}
	if (ini.GetAllValues("general", "cdr_ua_reg_remove", values)) {
		CSimpleIni::TNamesDepend::const_iterator i = values.begin();
		for (; i != values.end(); ++i) {
			if(!check_regexp(i->pItem)) {
				syslog(LOG_WARNING, "invalid regexp %s for cdr_ua_reg_remove", i->pItem);
			} else {
				opt_cdr_ua_reg_remove.push_back(i->pItem);
			}
		}
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
			opt_onlyRTPheader = 0;
			opt_saveRTP = 1;
			break;
		case 'h':
		case 'H':
			opt_onlyRTPheader = 1;
			opt_saveRTP = 0;
			break;
		case 'n':
		case 'N':
		case '0':
			opt_onlyRTPheader = 0;
			opt_saveRTP = 0;
			break;
		}
	}
	if((value = ini.GetValue("general", "silencethreshold", NULL))) {
		opt_silencethreshold = atoi(value);
	}
	if((value = ini.GetValue("general", "silencedetect", NULL))) {
		opt_silencedetect = yesno(value);
	}
	if((value = ini.GetValue("general", "clippingdetect", NULL))) {
		opt_clippingdetect = yesno(value);
	}
	if((value = ini.GetValue("general", "saverfc2833", NULL))) {
		opt_saverfc2833 = yesno(value);
	}
	if((value = ini.GetValue("general", "dtmf2db", NULL))) {
		opt_dbdtmf = yesno(value);
	}
	if((value = ini.GetValue("general", "inbanddtmf", NULL))) {
		opt_inbanddtmf = yesno(value);
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
	if((value = ini.GetValue("general", "fbasenameheader", NULL))) {
		snprintf(opt_fbasename_header, sizeof(opt_fbasename_header), "\n%s:", value);
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
	if((value = ini.GetValue("general", "manager_nonblock_mode", NULL))) {
		opt_manager_nonblock_mode = yesno(value);
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
		case 'n':
		case 'N':
		case '0':
			opt_saveWAV = 0;
			opt_audio_format = 0;
			break;
		}
	}
	if((value = ini.GetValue("general", "savegraph", NULL))) {
		switch(value[0]) {
		case 'y':
		case '1':
		case 'p':
			opt_saveGRAPH = 1;
			opt_gzipGRAPH = FileZipHandler::compress_na;
			break;
		case 'g':
			opt_saveGRAPH = 1;
			opt_gzipGRAPH = FileZipHandler::gzip;
			break;
		case 'n':
		case 'N':
		case '0':
			opt_saveGRAPH = 0;
			opt_gzipGRAPH = FileZipHandler::compress_na;
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
	if((value = ini.GetValue("general", "spooldir_by_sensor", NULL))) {
		opt_spooldir_by_sensor = yesno(value);
	}
	if((value = ini.GetValue("general", "spooldir_by_sensorname", NULL))) {
		opt_spooldir_by_sensorname = yesno(value);
	}
	if((value = ini.GetValue("general", "pcapsplit", NULL))) {
		opt_pcap_split = yesno(value);
	}
	if((value = ini.GetValue("general", "scanpcapdir", NULL))) {
		strncpy(opt_scanpcapdir, value, sizeof(opt_scanpcapdir));
	}
	if((value = ini.GetValue("general", "scanpcapdir_disable_inotify", NULL))) {
		      opt_scanpcapdir_disable_inotify = yesno(value);
	}
#ifndef FREEBSD
	if((value = ini.GetValue("general", "scanpcapmethod", NULL))) {
		opt_scanpcapmethod = (value[0] == 'r') ? IN_MOVED_TO : IN_CLOSE_WRITE;
	}
#endif
	if((value = ini.GetValue("general", "use_oneshot_buffer", NULL))) {
		opt_use_oneshot_buffer = yesno(value);
	}
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
	if((value = ini.GetValue("general", "mysqltransactions", NULL))) {
		opt_mysql_enable_transactions = yesno(value);
	}
	if((value = ini.GetValue("general", "mysqltransactions_cdr", NULL))) {
		opt_mysql_enable_transactions_cdr = yesno(value);
	}
	if((value = ini.GetValue("general", "mysqltransactions_message", NULL))) {
		opt_mysql_enable_transactions_message = yesno(value);
	}
	if((value = ini.GetValue("general", "mysqltransactions_register", NULL))) {
		opt_mysql_enable_transactions_register = yesno(value);
	}
	if((value = ini.GetValue("general", "mysqltransactions_http", NULL))) {
		opt_mysql_enable_transactions_http = yesno(value);
	}
	if((value = ini.GetValue("general", "mysqltransactions_webrtc", NULL))) {
		opt_mysql_enable_transactions_webrtc = yesno(value);
	}
	if((value = ini.GetValue("general", "mysqlhost", NULL))) {
		strncpy(mysql_host, value, sizeof(mysql_host));
	}
	if((value = ini.GetValue("general", "mysqlport", NULL))) {
		opt_mysql_port = atoi(value);
	}
	if((value = ini.GetValue("general", "mysqlhost_2", NULL))) {
		strncpy(mysql_2_host, value, sizeof(mysql_2_host));
	}
	if((value = ini.GetValue("general", "mysqlport_2", NULL))) {
		opt_mysql_2_port = atoi(value);
	}
	if((value = ini.GetValue("general", "mysql_timezone", NULL))) {
		strncpy(opt_mysql_timezone, value, sizeof(opt_mysql_timezone));
	}
	if((value = ini.GetValue("general", "timezone", NULL))) {
		setenv("TZ", value, 1);
	}
	if((value = ini.GetValue("general", "myqslhost", NULL))) {
		printf("You have old version of config file! there were typo in myqslhost instead of mysqlhost! Fix your config! exiting...\n");
		syslog(LOG_ERR, "You have old version of config file! there were typo in myqslhost instead of mysqlhost! Fix your config! exiting...\n");
		exit(1);
	}
	if((value = ini.GetValue("general", "mysqldb", NULL))) {
		strncpy(mysql_database, value, sizeof(mysql_database));
	}
	if((value = ini.GetValue("general", "mysqlusername", NULL))) {
		strncpy(mysql_user, value, sizeof(mysql_user));
	}
	if((value = ini.GetValue("general", "mysqlpassword", NULL))) {
		strncpy(mysql_password, value, sizeof(mysql_password));
	}
	if((value = ini.GetValue("general", "mysqldb_2", NULL))) {
		strncpy(mysql_2_database, value, sizeof(mysql_2_database));
	}
	if((value = ini.GetValue("general", "mysqlusername_2", NULL))) {
		strncpy(mysql_2_user, value, sizeof(mysql_2_user));
	}
	if((value = ini.GetValue("general", "mysqlpassword_2", NULL))) {
		strncpy(mysql_2_password, value, sizeof(mysql_2_password));
	}
	if((value = ini.GetValue("general", "mysql_2_http", NULL))) {
		opt_mysql_2_http = yesno(value);
	}
	if((value = ini.GetValue("general", "mysql_client_compress", NULL))) {
		opt_mysql_client_compress = yesno(value);
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
	if((value = ini.GetValue("general", "cloud_url_activecheck", NULL))) {
		strncpy(cloud_url_activecheck, value, sizeof(cloud_url_activecheck));
	}
	if((value = ini.GetValue("general", "cloud_token", NULL))) {
		strncpy(cloud_token, value, sizeof(cloud_token));
	}
	if((value = ini.GetValue("general", "cloud_activecheck_period", NULL))) {
		opt_cloud_activecheck_period = atoi(value);
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
	if((value = ini.GetValue("general", "database_backup_from_mysqlport", NULL))) {
		opt_database_backup_from_mysql_port = atol(value);
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
	if((value = ini.GetValue("general", "get_radius_ip_disable_secure_auth", NULL))) {
		get_radius_ip_disable_secure_auth = yesno(value);
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
	if((value = ini.GetValue("general", "dumpallallpackets", NULL))) {
		opt_pcapdump_all = atol(value) ? atol(value) : 
				   yesno(value) ? 1000 : 0;
	}
	if((value = ini.GetValue("general", "dumpallallpackets_path", NULL))) {
		strncpy(opt_pcapdump_all_path, value, sizeof(opt_pcapdump_all_path));
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
	if((value = ini.GetValue("general", "ipaccount_only_agregation", NULL))) {
		opt_ipacc_only_agregation = atoi(value);
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
		strncpy(opt_silencedtmfseq, value, 15);
	}
	if((value = ini.GetValue("general", "pauserecordingheader", NULL))) {
		snprintf(opt_silenceheader, sizeof(opt_silenceheader), "\n%s:", value);
	}
	if((value = ini.GetValue("general", "pauserecordingdtmf_timeout", NULL))) {
		opt_pauserecordingdtmf_timeout = atoi(value);
	}
	if((value = ini.GetValue("general", "182queuedpauserecording", NULL))) {
		opt_182queuedpauserecording = yesno(value);
	}
	if((value = ini.GetValue("general", "vlan_siprtpsame", NULL))) {
		opt_vlan_siprtpsame = yesno(value);
	}
	if((value = ini.GetValue("general", "rtpmap_by_callerd", NULL))) {
		opt_rtpmap_by_callerd = yesno(value);
	}
	if((value = ini.GetValue("general", "disable_rtp_warning", NULL))) {
		opt_disable_rtp_warning = yesno(value);
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
	   (value = ini.GetValue("general", "enable_http_enum_tables", NULL))) {
		opt_enable_http_enum_tables = yesno(value);
	}
	if((value = ini.GetValue("general", "enable_webrtc_table", NULL))) {
		opt_enable_webrtc_table = yesno(value);
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
		opt_pcap_queue_store_queue_max_memory_size = atol(value) * 1024ull *1024ull;
	}
	/*
	INDIRECT VALUE
	if((value = ini.GetValue("general", "packetbuffer_thread_maxheap", NULL))) {
		opt_pcap_queue_bypass_max_size = atol(value) * 1024 *1024;
	}
	*/
	if((value = ini.GetValue("general", "packetbuffer_file_totalmaxsize", NULL))) {
		opt_pcap_queue_store_queue_max_disk_size = atol(value) * 1024ull *1024ull;
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
	if((value = ini.GetValue("general", "packetbuffer_compress_method", NULL))) {
		char _opt_pcap_queue_compress_method[10];
		strncpy(_opt_pcap_queue_compress_method, value, sizeof(_opt_pcap_queue_compress_method));
		strlwr(_opt_pcap_queue_compress_method, sizeof(_opt_pcap_queue_compress_method));
		if(!strcmp(_opt_pcap_queue_compress_method, "snappy")) {
			opt_pcap_queue_compress_method = pcap_block_store::snappy;
		} else if(!strcmp(_opt_pcap_queue_compress_method, "lz4")) {
			opt_pcap_queue_compress_method = pcap_block_store::lz4;
		}
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
	if((value = ini.GetValue("general", "mirror_nonblock_mode", NULL))) {
		opt_pcap_queues_mirror_nonblock_mode = yesno(value);
	}
	
	if((value = ini.GetValue("general", "enable_preprocess_packet", NULL))) {
		opt_enable_preprocess_packet = !strcmp(value, "auto") ? -1 :
					       !strcmp(value, "extend") ? PreProcessPacket::ppt_end :
					       !strcmp(value, "sip") ? 3 : 
					       yesno(value);
	}
	if((value = ini.GetValue("general", "enable_process_rtp_packet", NULL)) ||
	   (value = ini.GetValue("general", "preprocess_rtp_threads", NULL))) {
		opt_enable_process_rtp_packet = atoi(value) > 1 ? min(atoi(value), MAX_PROCESS_RTP_PACKET_THREADS) : yesno(value);
	}
	if((value = ini.GetValue("general", "process_rtp_packets_hash_next_thread", NULL))) {
		opt_process_rtp_packets_hash_next_thread = atoi(value) > 1 ? min(atoi(value), MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS) : yesno(value);
	}
	if((value = ini.GetValue("general", "process_rtp_packets_hash_next_thread_sem_sync", NULL))) {
		opt_process_rtp_packets_hash_next_thread_sem_sync = atoi(value) == 2 ? 2 :yesno(value);
	}
	
	if((value = ini.GetValue("general", "tcpreassembly", NULL)) ||
	   (value = ini.GetValue("general", "http", NULL))) {
		opt_enable_http = strcmp(value, "only") ? yesno(value) : 2;
	}
	if((value = ini.GetValue("general", "webrtc", NULL))) {
		opt_enable_webrtc = strcmp(value, "only") ? yesno(value) : 2;
	}
	if((value = ini.GetValue("general", "ssl", NULL))) {
		opt_enable_ssl = strcmp(value, "only") ? yesno(value) : 2;
	}
	if((value = ini.GetValue("general", "ssl_link_timeout", NULL))) {
		opt_ssl_link_timeout = atol(value);
	}
	if((value = ini.GetValue("general", "tcpreassembly_log", NULL))) {
		strncpy(opt_tcpreassembly_log, value, sizeof(opt_tcpreassembly_log));
	}
	
	if((value = ini.GetValue("general", "convert_dlt_sll2en10", NULL))) {
		opt_convert_dlt_sll_to_en10 = yesno(value);
	}
	if((value = ini.GetValue("general", "threading_mod", NULL))) {
		setThreadingMode(atoi(value));
	}
	if((value = ini.GetValue("general", "pcap_queue_dequeu_window_length", NULL))) {
		opt_pcap_queue_dequeu_window_length = atoi(value);
	}
	if((value = ini.GetValue("general", "pcap_queue_dequeu_need_blocks", NULL))) {
		opt_pcap_queue_dequeu_need_blocks = atoi(value);
	}
	if((value = ini.GetValue("general", "pcap_queue_iface_qring_size", NULL))) {
		opt_pcap_queue_iface_qring_size = atoi(value);
	}
	if((value = ini.GetValue("general", "pcap_queue_dequeu_method", NULL))) {
		opt_pcap_queue_dequeu_method = atoi(value);
	}
	if((value = ini.GetValue("general", "pcap_queue_use_blocks", NULL))) {
		opt_pcap_queue_use_blocks = yesno(value);
	}
	if((value = ini.GetValue("general", "pcap_dispatch", NULL))) {
		opt_pcap_dispatch = yesno(value);
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
		strncpy(opt_mos_lqo_bin, value, sizeof(opt_mos_lqo_bin));
	}
	if((value = ini.GetValue("general", "mos_lqo_ref", NULL))) {
		strncpy(opt_mos_lqo_ref, value, sizeof(opt_mos_lqo_ref));
	}
	if((value = ini.GetValue("general", "mos_lqo_ref16", NULL))) {
		strncpy(opt_mos_lqo_ref16, value, sizeof(opt_mos_lqo_ref16));
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
	if((value = ini.GetValue("general", "audioqueue_threads_max", NULL))) {
		opt_audioqueue_threads_max = atoi(value);
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
	if((value = ini.GetValue("general", "mysqlstore_concat_limit_webrtc", NULL))) {
		opt_mysqlstore_concat_limit_webrtc = atoi(value);
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
	if((value = ini.GetValue("general", "mysqlstore_max_threads_webrtc", NULL))) {
		opt_mysqlstore_max_threads_webrtc = max(min(atoi(value), 9), 1);
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
		strlwr((char*)value);
		opt_pcap_dump_zip_sip = 
		opt_pcap_dump_zip_rtp = FileZipHandler::convTypeCompress(value);
	}
	if((value = ini.GetValue("general", "pcap_dump_zip_all", NULL))) {
		strlwr((char*)value);
		opt_pcap_dump_zip_sip = 
		opt_pcap_dump_zip_rtp = 
		opt_gzipGRAPH = FileZipHandler::convTypeCompress(value);
	}
	if((value = ini.GetValue("general", "pcap_dump_zip_sip", NULL))) {
		strlwr((char*)value);
		opt_pcap_dump_zip_sip = FileZipHandler::convTypeCompress(value);
	}
	if((value = ini.GetValue("general", "pcap_dump_zip_rtp", NULL))) {
		strlwr((char*)value);
		opt_pcap_dump_zip_rtp = FileZipHandler::convTypeCompress(value);
	}
	if((value = ini.GetValue("general", "pcap_dump_zip_graph", NULL))) {
		strlwr((char*)value);
		opt_gzipGRAPH = FileZipHandler::convTypeCompress(value);
	}
	if((value = ini.GetValue("general", "pcap_dump_ziplevel", NULL))) {
		opt_pcap_dump_ziplevel_sip = 
		opt_pcap_dump_ziplevel_rtp = 
		opt_pcap_dump_ziplevel_graph = atoi(value);
	}
	if((value = ini.GetValue("general", "pcap_dump_ziplevel_sip", NULL))) {
		opt_pcap_dump_ziplevel_sip = atoi(value);
	}
	if((value = ini.GetValue("general", "pcap_dump_ziplevel_rtp", NULL))) {
		opt_pcap_dump_ziplevel_rtp = atoi(value);
	}
	if((value = ini.GetValue("general", "pcap_dump_ziplevel_graph", NULL))) {
		opt_pcap_dump_ziplevel_graph = atoi(value);
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
	if((value = ini.GetValue("general", "tar", NULL))) {
		opt_pcap_dump_tar = yesno(value);
	}
	if((value = ini.GetValue("general", "tar_maxthreads", NULL))) {
		opt_pcap_dump_tar_threads = atoi(value);
	}
	if((value = ini.GetValue("general", "tar_compress_sip", NULL))) {
		switch(value[0]) {
		case 'z':
		case 'Z':
		case 'g':
		case 'G':
			opt_pcap_dump_tar_compress_sip = 1; // gzip
			break;
		case 'l':
		case 'L':
			opt_pcap_dump_tar_compress_sip = 2; // lzma
			break;
		case '0':
		case 'n':
		case 'N':
			opt_pcap_dump_tar_compress_sip = 0; // na
			break;
		}
	}
	if((value = ini.GetValue("general", "tar_compress_rtp", NULL))) {
		switch(value[0]) {
		case 'z':
		case 'Z':
		case 'g':
		case 'G':
			opt_pcap_dump_tar_compress_rtp = 1; // gzip
			break;
		case 'l':
		case 'L':
			opt_pcap_dump_tar_compress_rtp = 2; // lzma
			break;
		case '0':
		case 'n':
		case 'N':
			opt_pcap_dump_tar_compress_rtp = 0; // na
			break;
		}
	}
	if((value = ini.GetValue("general", "tar_compress_graph", NULL))) {
		switch(value[0]) {
		case 'z':
		case 'Z':
		case 'g':
		case 'G':
			opt_pcap_dump_tar_compress_graph = 1; // gzip
			break;
		case 'l':
		case 'L':
			opt_pcap_dump_tar_compress_graph = 2; // lzma
			break;
		case '0':
		case 'n':
		case 'N':
			opt_pcap_dump_tar_compress_graph = 0; // na
			break;
		}
	}
	if((value = ini.GetValue("general", "tar_sip_level", NULL))) {
		opt_pcap_dump_tar_sip_level = atoi(value);
	}
	if((value = ini.GetValue("general", "tar_rtp_level", NULL))) {
		opt_pcap_dump_tar_rtp_level = atoi(value);
	}
	if((value = ini.GetValue("general", "tar_graph_level", NULL))) {
		opt_pcap_dump_tar_graph_level = atoi(value);
	}
	if((value = ini.GetValue("general", "tar_internalcompress_sip", NULL))) {
		opt_pcap_dump_tar_internalcompress_sip = CompressStream::convTypeCompress(value);
	}
	if((value = ini.GetValue("general", "tar_internalcompress_rtp", NULL))) {
		opt_pcap_dump_tar_internalcompress_rtp = CompressStream::convTypeCompress(value);
	}
	if((value = ini.GetValue("general", "tar_internalcompress_graph", NULL))) {
		opt_pcap_dump_tar_internalcompress_graph = CompressStream::convTypeCompress(value);
	}
	if((value = ini.GetValue("general", "tar_internal_sip_level", NULL))) {
		opt_pcap_dump_tar_internal_gzip_sip_level = atoi(value);
	}
	if((value = ini.GetValue("general", "tar_internal_rtp_level", NULL))) {
		opt_pcap_dump_tar_internal_gzip_rtp_level = atoi(value);
	}
	if((value = ini.GetValue("general", "tar_internal_graph_level", NULL))) {
		opt_pcap_dump_tar_internal_gzip_graph_level = atoi(value);
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
			*pointToPortSeparator = 0;
			int port = atoi(pointToPortSeparator + 1);
			if(*value && port) {
				sipSendSocket_ip_port.set_ip(value);
				sipSendSocket_ip_port.set_port(port);
			}
		}
	}
	if((value = ini.GetValue("general", "sip_send_udp", NULL))) {
		opt_sip_send_udp = yesno(value);
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
	if((value = ini.GetValue("general", "save_sip_responses", NULL))) {
		opt_cdr_sipresp = value;
	}
	if((value = ini.GetValue("general", "save_sip_history", NULL))) {
		opt_save_sip_history = value;
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

	if((value = ini.GetValue("general", "syslog_string", NULL))) {
		strncpy(opt_syslog_string, value, sizeof(opt_syslog_string));
	}
	
	if((value = ini.GetValue("general", "cpu_limit_new_thread", NULL))) {
		opt_cpu_limit_new_thread = atoi(value);
	}
	if((value = ini.GetValue("general", "cpu_limit_delete_thread", NULL))) {
		opt_cpu_limit_delete_thread = atoi(value);
	}
	if((value = ini.GetValue("general", "cpu_limit_delete_t2sip_thread", NULL))) {
		opt_cpu_limit_delete_t2sip_thread = atoi(value);
	}

	if((value = ini.GetValue("general", "preprocess_packets_qring_length", NULL))) {
		opt_preprocess_packets_qring_length = atol(value);
	}
	if((value = ini.GetValue("general", "preprocess_packets_qring_usleep", NULL))) {
		opt_preprocess_packets_qring_usleep = atol(value);
	}
	if((value = ini.GetValue("general", "process_rtp_packets_qring_length", NULL))) {
		opt_process_rtp_packets_qring_length = atol(value);
	}
	if((value = ini.GetValue("general", "process_rtp_packets_qring_usleep", NULL))) {
		opt_process_rtp_packets_qring_usleep = atol(value);
	}

	if((value = ini.GetValue("general", "rtp_qring_length", NULL))) {
		rtp_qring_length = atol(value);
	}
	if((value = ini.GetValue("general", "rtp_qring_usleep", NULL))) {
		rtp_qring_usleep = atol(value);
	}
	if((value = ini.GetValue("general", "rtp_qring_quick", NULL))) {
		rtp_qring_quick = strcmp(value, "boost") ? yesno(value) : 2;
	}
	if((value = ini.GetValue("general", "udpfrag", NULL))) {
		opt_udpfrag = yesno(value);
	}
	if((value = ini.GetValue("general", "faxdetect", NULL))) {
		opt_faxt30detect = yesno(value);
	}
	
	if((value = ini.GetValue("general", "max_buffer_mem", NULL))) {
		buffersControl.setMaxBufferMem(atol(value) * 1024 * 1024, true);
	}
	
	if((value = ini.GetValue("general", "git_folder", NULL))) {
		strncpy(opt_git_folder, value, sizeof(opt_git_folder));
	}
	if((value = ini.GetValue("general", "upgrade_by_git", NULL))) {
		opt_upgrade_by_git = yesno(value);
	}
	
	if((value = ini.GetValue("general", "query_cache", NULL)) && yesno(value)) {
		opt_save_query_to_files = true;
		opt_load_query_from_files = 1;
		opt_load_query_from_files_inotify = true;
	}
	if((value = ini.GetValue("general", "query_cache_speed", NULL))) {
		opt_query_cache_speed = yesno(value);
	}
	if((value = ini.GetValue("general", "utc", NULL)) ||
	   (value = ini.GetValue("general", "sql_time_utc", NULL))) {
		opt_sql_time_utc = yesno(value);
	}
	
	if((value = ini.GetValue("general", "save_query_to_files", NULL))) {
		opt_save_query_to_files = yesno(value);
	}
	if((value = ini.GetValue("general", "save_query_to_files_directory", NULL))) {
		strncpy(opt_save_query_to_files_directory, value, sizeof(opt_save_query_to_files_directory));
	}
	if((value = ini.GetValue("general", "save_query_to_files_period", NULL))) {
		opt_save_query_to_files_period = atoi(value);
	}
	
	if((value = ini.GetValue("general", "load_query_from_files", NULL))) {
		opt_load_query_from_files = !strcmp(value, "only") ? 2 : yesno(value);
	}
	if((value = ini.GetValue("general", "load_query_from_files_directory", NULL))) {
		strncpy(opt_load_query_from_files_directory, value, sizeof(opt_load_query_from_files_directory));
	}
	if((value = ini.GetValue("general", "load_query_from_files_period", NULL))) {
		opt_load_query_from_files_period = atoi(value);
	}
	if((value = ini.GetValue("general", "load_query_from_files_inotify", NULL))) {
		opt_load_query_from_files_inotify = yesno(value);
	}
	
	if((value = ini.GetValue("general", "virtualudppacket", NULL))) {
		opt_virtualudppacket = yesno(value);
	}
	if((value = ini.GetValue("general", "sip_tcp_reassembly_ext", NULL))) {
		opt_sip_tcp_reassembly_ext = yesno(value);
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
	
	set_context_config();

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
				char * pData = new FILE_LINE char[lSize + 10];	//adding "[general]\n" on top
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


bool is_read_from_file() {
       return(is_read_from_file_simple() ||
	      is_read_from_file_by_pb());
}

bool is_read_from_file_simple() {
       return(opt_read_from_file);
}

bool is_read_from_file_by_pb() {
       return(opt_pb_read_from_file[0]);
}

bool is_enable_packetbuffer() {
	return(!is_read_from_file_simple());
}

bool is_enable_rtp_threads() {
	return(is_enable_packetbuffer() &&
	       rtp_threaded &&
	       !is_sender());
}

bool is_enable_cleanspool() {
	return(!opt_nocdr &&
	       isSqlDriver("mysql") &&
	       !is_read_from_file() &&
	       !is_sender());
}

bool is_receiver() {
	return(opt_pcap_queue_receive_from_ip_port);
}

bool is_sender() {
	return(!opt_pcap_queue_receive_from_ip_port &&
	       opt_pcap_queue_send_to_ip_port);
}

int check_set_rtp_threads(int num_rtp_threads) {
	if(num_rtp_threads <= 0) num_rtp_threads = sysconf( _SC_NPROCESSORS_ONLN ) - 1;
	if(num_rtp_threads <= 0) num_rtp_threads = 1;
	return(num_rtp_threads);
}

void dns_lookup_common_hostnames() {
	const char *hostnames[] = {
		"voipmonitor.org",
		"www.voipmonitor.org",
		"download.voipmonitor.org",
		"cloud.voipmonitor.org",
		"cloud2.voipmonitor.org",
		"cloud3.voipmonitor.org"
	};
	for(unsigned int i = 0; i < sizeof(hostnames) / sizeof(hostnames[0]) && !terminating; i++) {
		u_int32_t ipl = gethostbyname_lock(hostnames[i]);
		if(!ipl) {
			syslog(LOG_ERR, "host [%s] failed to resolve to IP address", hostnames[i]);
			continue;
		}
		hosts[hostnames[i]] = inet_ntostring(htonl(ipl));
	}
}

u_int32_t gethostbyname_lock(const char *name) {
	u_int32_t rslt_ipl = 0;
	pthread_mutex_lock(&hostbyname_lock);
	hostent *rslt_hostent = gethostbyname(name);
	if(rslt_hostent) {
		rslt_ipl = ((in_addr*)rslt_hostent->h_addr)->s_addr;
	}
	pthread_mutex_unlock(&hostbyname_lock);
	return(rslt_ipl);
}

bool _use_mysql_2() {
	return(!opt_database_backup &&
	       !cloud_host[0] &&
	       mysql_2_host[0] && mysql_2_user[0] && mysql_2_database[0]);
}

bool use_mysql_2() {
	return(use_mysql_2_http());
}

bool use_mysql_2_http() {
	return(_use_mysql_2() && opt_enable_http_enum_tables && opt_mysql_2_http);
}

void* sqlStore_http() {
	if(use_mysql_2_http()) {
		return(sqlStore_2);
	}
	return(sqlStore);
}

void parse_opt_nocdr_for_last_responses() {
	nocdr_for_last_responses_count = 0;
	vector<string> responses = split(opt_nocdr_for_last_responses, split(",|;", "|"), true);
	for(unsigned i = 0; i < min(responses.size(), sizeof(nocdr_for_last_responses) / sizeof(nocdr_for_last_responses[0])); i++) {
		nocdr_for_last_responses[nocdr_for_last_responses_count] = atoi(responses[i].c_str());
		if(nocdr_for_last_responses[nocdr_for_last_responses_count]) {
			nocdr_for_last_responses_length[nocdr_for_last_responses_count] = log10(nocdr_for_last_responses[nocdr_for_last_responses_count]) + 1;
			nocdr_for_last_responses_count++;
		}
	}
}
