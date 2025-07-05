/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

#include <queue>
#include <climits>
// stevek - it could be smarter if sys/inotyfy.h available then use it otherwise use linux/inotify.h. I will do it later
#define GLOBAL_DECLARATION true
#include "voipmonitor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>
#include <iomanip>
#include <sys/wait.h>
#include <curl/curl.h>

#ifdef FREEBSD
#include <sys/endian.h>
#else
#include <endian.h>
#include <sys/inotify.h>
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
#include <pwd.h>
#include <grp.h>

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
#include "diameter.h"
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
#include "register.h"
#include "options.h"
#include "tools_fifo_buffer.h"
#include "country_detect.h"
#include "ssl_dssl.h"
#include "server.h"
#include "billing.h"
#include "audio_convert.h"
#include "tcmalloc_hugetables.h"
#include "log_buffer.h"
#include "heap_chunk.h"
#include "charts.h"
#include "ipfix.h"
#include "hep.h"
#include "separate_processing.h"
#include "crc.h"
#include "transcribe.h"

#if HAVE_LIBTCMALLOC_HEAPPROF
#include <gperftools/heap-profiler.h>
#endif

#if HAVE_LIBJEMALLOC
#include <jemalloc/jemalloc.h>
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

#ifdef HAVE_LIBGNUTLS
extern void ssl_init();
extern void ssl_clean();
#endif


using namespace std;


/* global variables */

extern Calltable *calltable;
#if DEBUG_ASYNC_TAR_WRITE
extern cDestroyCallsInfo *destroy_calls_info;
#endif
extern volatile int calls_counter;
extern volatile int calls_for_store_counter;
extern volatile int registers_counter;
unsigned int opt_openfile_max = 65535;
int opt_disable_dbupgradecheck = 0; // When voipmonitor started this disable mysql db check/upgrade (if set to 1)
int opt_packetbuffered = 0;	// Make .pcap files writing ‘‘packet-buffered’’ 
				// more slow method, but you can use partitialy 
				// writen file anytime, it will be consistent.
	
int opt_disableplc = 0 ;	// On or Off packet loss concealment			
int opt_fix_packetization_in_create_audio = 0;
int opt_rrd = 1;
char *rrd_last_cmd_global = NULL;
int opt_silencethreshold = 512; //values range from 1 to 32767 default 512
int opt_passertedidentity = 0;	//Rewrite caller? If sip invite contain P-Asserted-Identity, caller num/name is overwritten by its values.
int opt_ppreferredidentity = 0;	//Rewrite caller? If sip invite contain P-Preferred-Identity, caller num/name is overwritten by its values.
int opt_remotepartyid = 0;	//Rewrite caller? If sip invite contain header Remote-Party-ID, caller num/name is overwritten by its values.
int opt_remotepartypriority = 0;//Defines rewrite caller order. If both headers are set/found and activated ( P-Preferred-Identity,Remote-Party-ID ), rewrite caller primary from Remote-Party-ID header (if set to 1). 
char opt_remoteparty_caller[1024];
char opt_remoteparty_called[1024];
vector<string> opt_remoteparty_caller_v;
vector<string> opt_remoteparty_called_v;
int opt_fork = 1;		// fork or run foreground 
int opt_saveSIP = 0;		// save SIP packets to pcap file?
int opt_saveRTP = 0;		// save RTP packets to pcap file?
int opt_onlyRTPheader = 0;	// do not save RTP payload, only RTP header
int opt_saveRTPvideo = 0;
int opt_saveRTPvideo_only_header = 0;
int opt_processingRTPvideo = 0;
int opt_saveMRCP = 0;
int opt_saveRTCP = 0;		// save RTCP packets to pcap file?
bool opt_null_rtppayload = false;
bool opt_srtp_rtp_decrypt = false;
bool opt_srtp_rtp_dtls_decrypt = true;
bool opt_srtp_rtp_audio_decrypt = false;
bool opt_srtp_rtp_dtmf_decrypt = false;
bool opt_srtp_rtcp_decrypt = true;
bool opt_srtp_rtp_local_instances = true;
bool opt_srtp_use_all_keys = false;
int opt_use_libsrtp = 0;
bool opt_check_diff_ssrc_on_same_ip_port = true;
bool opt_save_all_rtp_streams_to_db = false;
unsigned int opt_ignoreRTCPjitter = 0;	// ignore RTCP over this value (0 = disabled)
int opt_saveudptl = 0;		// if = 1 all UDPTL packets will be saved (T.38 fax)
int opt_rtpip_find_endpoints = 1;
bool opt_save_energylevels = false;
bool opt_save_energylevels_check_seq = true;
bool opt_save_energylevels_via_jb = true;
int opt_faxt30detect = 0;	// if = 1 all sdp is activated (can take a lot of cpu)
int opt_saveRAW = 0;		// save RTP packets to pcap file?
int opt_saveWAV = 0;		// save RTP packets to pcap file?
int opt_saveGRAPH = 0;		// save GRAPH data to *.graph file? 
FileZipHandler::eTypeCompress opt_gzipGRAPH = FileZipHandler::compress_na;
int opt_audio_transcribe = 0;
int opt_audio_transcribe_connect_duration_min = 10;
int opt_audio_transcribe_threads = 2;
int opt_audio_transcribe_queue_length_max = 100;
bool opt_audio_transcribe_parallel_channel_processing = false;
string opt_audio_transcribe_progress_file;
string opt_audio_transcribe_control_file;
bool opt_whisper_native = false;
string opt_whisper_model = "";
string opt_whisper_rest_api_url = "";

string opt_whisper_language = "auto";
int opt_whisper_timeout = 5 * 60;
bool opt_whisper_deterministic_mode = true;
string opt_whisper_python;
int opt_whisper_threads = 2;
string opt_whisper_native_lib;
int opt_save_audiograph;
int opt_audiograph_ms_per_pixel = 0;
int opt_audiograph_spectrogram_height = 32;
int opt_audiograph_spectrogram_jpeg_quality = 10;
bool opt_fftw_multithread_mode = false;
bool opt_fftw_fork_mode = false;
FileZipHandler::eTypeCompress opt_gzip_audiograph = FileZipHandler::compress_na;
int opt_save_sdp_ipport = 1;
int opt_save_ip_from_encaps_ipheader = 0;
int opt_save_ip_from_encaps_ipheader_only_gre = 0;
int opt_saverfc2833 = 0;
int opt_silencedetect = 0;
int opt_clippingdetect = 0;
int opt_dbdtmf = 0;
int opt_pcapdtmf = 1;
int opt_inbanddtmf = 0;
int opt_fasdetect = 0;
bool opt_sipalg_detect = false;
int opt_rtcp = 1;		// pair RTP+1 port to RTCP and save it. 
int opt_nocdr = 0;		// do not save cdr?
char opt_nocdr_for_last_responses[1024];
NoStoreCdrRules nocdr_rules;
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
int opt_jitterbuffer_f1_jbsize = 0;
int opt_jitterbuffer_f1_resync_threshold = 0;
int opt_jitterbuffer_f2_jbsize = 0;
int opt_jitterbuffer_f2_resync_threshold = 0;
int opt_jitterbuffer_adapt_jbsize = 0;
int opt_jitterbuffer_adapt_resync_threshold = 0;
int opt_jitterbuffer_adapt_ooo_limit = 0;

int opt_max_buffer_mem = 0;
int opt_ringbuffer = 50;	// ring buffer in MB 
bool opt_sip_message = true;
int opt_sip_register = 0;	// if == 1 save REGISTER messages, if == 2, use old registers
int opt_sip_options = 0;
int opt_sip_subscribe = 0;
int opt_sip_notify = 0;
int opt_save_sip_options = 0;
int opt_save_sip_subscribe = 0;
int opt_save_sip_notify = 0;
int opt_save_sip_register = 0;
bool opt_sip_msg_compare_ip_src = true;
bool opt_sip_msg_compare_ip_dst = true;
bool opt_sip_msg_compare_port_src = true;
bool opt_sip_msg_compare_port_dst = false;
bool opt_sip_msg_compare_number_src = true;
bool opt_sip_msg_compare_number_dst = true;
bool opt_sip_msg_compare_domain_src = true;
bool opt_sip_msg_compare_domain_dst = true;
bool opt_sip_msg_compare_vlan = false;
bool opt_sip_msg_save_ua = false;

int opt_audio_format = FORMAT_WAV;	// define format for audio writing (if -W option)
int opt_manager_port = 5029;	// manager api TCP port
char opt_manager_ip[32] = "127.0.0.1";	// manager api listen IP address
string opt_manager_socket;
string opt_manager_socket_run_via_manager;
int opt_manager_nonblock_mode = 0;
string opt_manager_aes_key;
string opt_manager_aes_iv;
int opt_rtpsave_threaded = 1;
int opt_norecord_header = 0;	// if = 1 SIP call with X-VoipMonitor-norecord header will be not saved although global configuration says to record. 
int opt_rtpnosip = 0;		// if = 1 RTP stream will be saved into calls regardless on SIP signalizatoin (handy if you need extract RTP without SIP)
int opt_norecord_dtmf = 0;	// if = 1 SIP call with dtmf == *0 sequence (in SIP INFO) will stop recording
int opt_savewav_force = 0;	// if = 1 WAV will be generated no matter on filter rules
int opt_sipoverlap = 1;		
int opt_last_dest_number = 0;
int opt_id_sensor = -1;		
char opt_id_sensor_str[10];
char opt_sensor_string[128];
int opt_id_sensor_cleanspool = -1;	
bool opt_use_id_sensor_for_receiver_in_files = false;
char opt_name_sensor[256] = "";
volatile int readend = 0;
int opt_dup_check_type = _dedup_na;
int opt_dup_check_check_type = cPacketDuplBuffer::_simple;
int opt_dup_check_hashtable_lifetime = 10;
bool opt_dup_check_collision_test = false;
int opt_dup_check_ipheader = 1;
int opt_dup_check_ipheader_ignore_ttl = 1;
int opt_dup_check_udpheader_ignore_checksum = 1;
int opt_fax_dup_seq_check = 0;
int opt_fax_create_udptl_streams = 0;
int rtptimeout = 300;
int sipwithoutrtptimeout = 3600;
int absolute_timeout = 4 * 3600;
int opt_destination_number_mode = 1;
int opt_update_dstnum_onanswer = 0;
bool opt_get_reason_from_bye_cancel = true;
bool opt_cleanspool = true;
bool opt_cleanspool_use_files = true;
int opt_cleanspool_interval = 0; // number of seconds between cleaning spool directory. 0 = disabled
int opt_cleanspool_sizeMB = 0; // number of MB to keep in spooldir
int opt_domainport = 0;
int opt_mirrorip = 0;
int opt_mirrorall = 0;
int opt_mirroronly = 0;
char opt_mirrorip_src[20];
char opt_mirrorip_dst[20];
int opt_printinsertid = 0;
int opt_ipaccount = 0;
int opt_ipacc_interval = 300;
int opt_ipacc_only_agregation = 0;
int opt_ipacc_enable_agregation_both_sides = 1;
int opt_ipacc_limit_agregation_both_sides = 0;
bool opt_ipacc_sniffer_agregate = true;
bool opt_ipacc_agregate_only_customers_on_main_side = false;
bool opt_ipacc_agregate_only_customers_on_any_side = false;
int opt_udpfrag = 1;
MirrorIP *mirrorip = NULL;
int opt_cdronlyanswered = 0;
int opt_cdronlyrtp = 0;
int opt_pcap_split = 1;
int opt_newdir = 1;
int opt_spooldir_by_sensor = 0;
int opt_spooldir_by_sensorname = 0;
int opt_callslimit = 0;
char opt_silencedtmfseq[16] = "";
char opt_silenceheader[128] = "";
int opt_pauserecordingdtmf_timeout = 4;
int opt_182queuedpauserecording = 0;
char opt_energylevelheader[128] = "";
int opt_vlan_siprtpsame = 0;
int opt_rtpfromsdp_onlysip = 0;
int opt_rtpfromsdp_onlysip_skinny = 1;
int opt_rtp_streams_max_in_call = 1000;
int opt_rtp_check_both_sides_by_sdp = 0;
char opt_keycheck[1024] = "";
char opt_vmcodecs_path[1024] = "";
int opt_cdr_stat_values = 3;
bool opt_cdr_stat_sources = false;
int opt_cdr_stat_interval = 15;
int opt_cdr_problems = 0;
bool opt_cdr_problems_by_ip = false;
bool opt_cdr_problems_by_number = false;
bool opt_cdr_problems_by_comb = false;
int opt_cdr_problems_interval = 15;
int opt_cdr_problems_list_ip_refresh_interval = 900;
bool opt_charts_cache = false;
int opt_charts_cache_max_threads = 3;
bool opt_charts_cache_store = false;
bool opt_charts_cache_ip_boost = false;
int opt_charts_cache_queue_limit = 100000;
int opt_charts_cache_remote_queue_limit = 1000;
int opt_charts_cache_remote_concat_limit = 1000;
char opt_convert_char[64] = "";
int opt_skinny = 0;
int opt_mgcp = 0;
vmIP opt_skinny_ignore_rtpip;
unsigned int opt_skinny_call_info_message_decode_type = 2;
bool opt_read_from_file = false;
char opt_read_from_file_fname[1024] = "";
char opt_process_pcap_fname[1024] = "";
bool opt_read_from_file_no_sip_reassembly = false;
char opt_pb_read_from_file[256] = "";
double opt_pb_read_from_file_speed = 0;
int opt_pb_read_from_file_acttime = 0;
int opt_pb_read_from_file_acttime_diff_days = 0;
int opt_pb_read_from_file_acttime_diff_secs = 0;
int64_t opt_pb_read_from_file_time_adjustment = 0;
unsigned int opt_pb_read_from_file_max_packets = 0;
bool opt_continue_after_read = false;
bool opt_suppress_cleanup_after_read = false;
bool opt_nonstop_read = false;
bool opt_unlimited_read = false;
bool opt_nonstop_read_quick = false;
int opt_time_to_terminate = 0;
bool opt_receiver_check_id_sensor = true;
int opt_dscp = 0;
int opt_cdrproxy = 1;
int opt_messageproxy = 1;
int opt_cdr_country_code = 1;
int opt_message_country_code = 1;
int opt_quick_save_cdr = 0;
int opt_enable_http_enum_tables = 0;
int opt_enable_webrtc_table = 0;
int opt_generator = 0;
int opt_generator_channels = 1;
int opt_skipdefault = 0;
int opt_filesclean = 1;
int opt_enable_preprocess_packet = -1;
int opt_enable_process_rtp_packet = 1;
int opt_enable_process_rtp_packet_max = -1;
volatile int process_rtp_packets_distribute_threads_use = 0;
int opt_pre_process_packets_next_thread = -1;
int opt_pre_process_packets_next_thread_find_call = -1;
int opt_pre_process_packets_next_thread_process_call = -1;
int opt_pre_process_packets_next_thread_detach = -1;
int opt_pre_process_packets_next_thread_detach2 = -1;
int opt_pre_process_packets_next_thread_defrag = -1;
int opt_pre_process_packets_next_thread_max = 2;
int opt_process_rtp_packets_hash_next_thread = 1;
int opt_process_rtp_packets_hash_next_thread_max = -1;
int opt_pre_process_packets_next_thread_sem_sync = 2;
int opt_process_rtp_packets_hash_next_thread_sem_sync = 2;
unsigned int opt_preprocess_packets_qring_length = 2000;
unsigned int opt_preprocess_packets_qring_item_length = 0;
unsigned int opt_preprocess_packets_qring_usleep = 10;
unsigned int opt_preprocess_packets_qring_push_usleep = 10;
bool opt_preprocess_packets_qring_force_push = true;
unsigned int opt_process_rtp_packets_qring_length = 2000;
unsigned int opt_process_rtp_packets_qring_item_length = 0;
unsigned int opt_process_rtp_packets_qring_usleep = 10;
unsigned int opt_process_rtp_packets_qring_push_usleep = 10;
unsigned int opt_push_batch_limit_ms = 100;
unsigned int opt_push_batch_limit_for_traffic_lt_mb_s = 0;
bool use_push_batch_limit_ms = true;
unsigned int opt_batch_length_sip_high_traffic = 5000;
unsigned int opt_batch_length_rtp_high_traffic = 40000;
bool batch_length_high_traffic_need = false;
bool opt_usleep_stats = false;
bool opt_usleep_progressive = true;
double opt_usleep_progressive_index = 0;
bool opt_usleep_mod_enable = false;
unsigned opt_usleep_mod_pause_spin_limit = 100;
unsigned opt_usleep_mod_sched_yield_spin_limit = 100;
unsigned int opt_lock_calls_hash_usleep = 10;
unsigned int opt_sip_batch_usleep = 10;
unsigned int opt_rtp_batch_usleep = 10;
unsigned int opt_lock_calls_usleep = 10;
unsigned int opt_usleep_force = 0;
unsigned int opt_usleep_minimal = 0;
bool opt_sniffer_threads_ext = false;
int opt_cleanup_calls_period = 10;
int opt_destroy_calls_period = 2;
int opt_safe_cleanup_calls = 1;
bool opt_destroy_calls_in_storing_cdr = false;
int opt_enable_ss7 = 0;
bool opt_ss7_use_sam_subsequent_number = true;
int opt_ss7_type_callid = 1;
int opt_ss7timeout_rlc = 10;
int opt_ss7timeout_rel = 60;
int opt_ss7timeout = 3600;
vector<string> opt_ws_params;
bool opt_enable_diameter;
bool opt_diameter_ignore_domain;
bool opt_diameter_ignore_prefix;
int opt_diameter_time_overlap = 10;
bool opt_diameter_reassymbly_all_complete_after_zerodata_ack = false;
int opt_enable_http = 0;
bool opt_http_cleanup_ext = false;
int opt_enable_webrtc = 0;
int opt_enable_ssl = 0;
unsigned int opt_ssl_link_timeout = 5 * 60;
bool opt_ssl_ignore_tcp_handshake = true;
bool opt_ssl_log_errors = false;
bool opt_ssl_find_valid_mac = true;
bool opt_ssl_ignore_error_invalid_mac = true;
bool opt_ssl_ignore_error_bad_finished_digest = true;
int opt_ssl_tls_12_sessionkey_mode = 1;
bool opt_ssl_unlimited_reassembly_attempts = false;
bool opt_ssl_destroy_tcp_link_on_rst = false;
bool opt_ssl_destroy_ssl_session_on_rst = false;
int opt_ssl_store_sessions = 2;
int opt_ssl_store_sessions_expiration_hours = 12;
int opt_ssl_aead_try_seq_backward = 0;
int opt_ssl_aead_try_seq_forward = 0;
int opt_ssl_enable_dtls_queue = 1;
int opt_ssl_dtls_queue_expiration_s = 10;
int opt_ssl_dtls_queue_expiration_count = 20;
bool opt_ssl_dtls_queue_keep = false;
int opt_ssl_dtls_handshake_safe = false;
bool opt_ssl_dtls_find_by_server_side = true;
bool opt_ssl_dtls_find_by_client_side = false;
int opt_ssl_dtls_boost = true;
bool opt_ssl_reassembly_all_complete_after_zerodata_ack = false;
bool opt_ssl_reassembly_ipport_reverse_enable = true;
bool opt_ssl_enable_redirection_unencrypted_sip_content = false;
int opt_tcpreassembly_thread = 1;
char opt_tcpreassembly_http_log[1024];
char opt_tcpreassembly_webrtc_log[1024];
char opt_tcpreassembly_ssl_log[1024];
char opt_tcpreassembly_sip_log[1024];
char opt_tcpreassembly_diameter_log[1024];
int opt_allow_zerossrc = 0;
int opt_convert_dlt_sll_to_en10 = 0;
unsigned int opt_mysql_connect_timeout = 60;
bool opt_mysql_reconnect = true;
int opt_mysqlcompress = 1;
char opt_mysqlcompress_type[256];
int opt_mysql_enable_transactions = 0;
int opt_mysql_enable_transactions_cdr = 0;
int opt_mysql_enable_transactions_message = 0;
int opt_mysql_enable_transactions_sip_msg = 0;
int opt_mysql_enable_transactions_register = 0;
int opt_mysql_enable_transactions_http = 0;
int opt_mysql_enable_transactions_webrtc = 0;
int opt_mysql_enable_multiple_rows_insert = 1;
int opt_mysql_max_multiple_rows_insert = 20;
int opt_mysql_enable_new_store = 0;
bool opt_mysql_enable_set_id = false;
bool opt_csv_store_format = false;
bool opt_mysql_mysql_redirect_cdr_queue = false;
int opt_cdr_sip_response_number_max_length = 0;
vector<string> opt_cdr_sip_response_reg_remove;
bool opt_cdr_sip_response_normalisation = false;
bool opt_cdr_sip_response_load_normalisation = false;
int opt_cdr_reason_string_enable = 1;
vector<string> opt_cdr_reason_reg_remove;
bool opt_cdr_reason_normalisation = true;
bool opt_cdr_reason_load_normalisation = false;
int opt_cdr_ua_enable = 1;
vector<string> opt_cdr_ua_reg_remove;
vector<string> opt_cdr_ua_reg_whitelist;
bool opt_cdr_ua_normalisation = false;
bool opt_cdr_ua_load_normalisation = false;
unsigned long long cachedirtransfered = 0;
unsigned int opt_maxpcapsize_mb = 0;
int opt_mosmin_f2 = 1;
bool opt_database_backup = false;
char opt_database_backup_from_date[20];
char opt_database_backup_to_date[20];
char opt_database_backup_from_mysql_host[256] = "";
char opt_database_backup_from_mysql_database[256] = "";
char opt_database_backup_from_mysql_user[256] = "";
char opt_database_backup_from_mysql_password[256] = "";
unsigned int opt_database_backup_from_mysql_port = 0;
char opt_database_backup_from_mysql_socket[256] = "";
mysqlSSLOptions optMySSLBackup;
int opt_database_backup_pause = 300;
int opt_database_backup_insert_threads = 1;
bool opt_database_backup_cleandatabase = false;
int opt_database_backup_pass_rows = 0;
bool opt_database_backup_desc_dir = false;
bool opt_database_backup_skip_register = false;
bool opt_database_backup_check_src_tables = false;
bool opt_database_backup_merge_reference_tables = false;
int opt_database_backup_slave_record_safe_gap = 100;
char opt_mos_lqo_bin[1024] = "pesq";
char opt_mos_lqo_ref[1024] = "/usr/local/share/voipmonitor/audio/mos_lqe_original.wav";
char opt_mos_lqo_ref16[1024] = "/usr/local/share/voipmonitor/audio/mos_lqe_original_16khz.wav";
int opt_ignore_mos_degradation_for_contiguous_packet_loss_greater_than = 1024;
int opt_ignore_mos_degradation_in_rtp_pause_without_seq_gap = 1000;
regcache *regfailedcache;
int opt_onewaytimeout = 15;
int opt_bye_timeout = 20 * 60;
int opt_bye_confirmed_timeout = 10 * 60;
int opt_redirect_response_300_timeout = 5 * 60;
int opt_response_default_timeout = 5;
bool opt_ignore_rtp_after_bye_confirmed = true;
bool opt_ignore_rtp_after_bye = false;
bool opt_ignore_duration_after_bye_confirmed = true;
bool opt_ignore_rtp_after_cancel_confirmed = false;
bool opt_ignore_rtp_after_auth_failed = true;
bool opt_ignore_rtp_after_response = false;
vector<int> opt_ignore_rtp_after_response_list;
int opt_saveaudio_reversestereo = 0;
bool opt_saveaudio_adaptive_jitterbuffer = false;
bool opt_saveaudio_resync_jitterbuffer = false;
int opt_saveaudio_jitterbuffer_jbsize = 0;
int opt_saveaudio_jitterbuffer_resync_threshold = 0;
float opt_saveaudio_oggquality = 0.4;
int opt_saveaudio_mp3quality = 5;
int opt_audioqueue_threads_max = 10;
bool opt_saveaudio_answeronly = false;
bool opt_saveaudio_filteripbysipip = false;
bool opt_saveaudio_filter_ext = true;
bool opt_saveaudio_wav_mix = true;
bool opt_saveaudio_from_first_invite = true;
bool opt_saveaudio_afterconnect = false;
bool opt_saveaudio_from_rtp = false;
int opt_saveaudio_stereo = 1;
int opt_saveaudio_dedup_seq = 0;
int opt_liveaudio = 1;
int opt_register_timeout = 5;
int opt_register_timeout_disable_save_failed = 0;
int opt_register_max_registers = 4;
int opt_register_max_messages = 20;
int opt_register_ignore_res_401 = 0;
int opt_register_ignore_res_401_nonce_has_changed = 0;
bool opt_sip_register_compare_sipcallerip = false;
bool opt_sip_register_compare_sipcalledip = false;
bool opt_sip_register_compare_sipcallerip_encaps = false;
bool opt_sip_register_compare_sipcalledip_encaps = false;
bool opt_sip_register_compare_sipcallerport = false;
bool opt_sip_register_compare_sipcalledport = false;
bool opt_sip_register_compare_to_domain = true;
bool opt_sip_register_compare_vlan = false;
bool opt_sip_register_state_compare_from_num = false;
bool opt_sip_register_state_compare_from_name = false;
bool opt_sip_register_state_compare_from_domain = false;
bool opt_sip_register_state_compare_contact_num = true;
bool opt_sip_register_state_compare_contact_domain = true;
bool opt_sip_register_state_compare_digest_realm = false;
bool opt_sip_register_state_compare_ua = false;
bool opt_sip_register_state_compare_sipalg = false;
bool opt_sip_register_state_compare_vlan = false;
bool opt_sip_register_save_all = false;
int opt_sip_register_state_timeout = 10 * 60;
bool opt_sip_register_save_eq_states_time = false;
int opt_sip_register_failed_max_details_per_minute = 1000;
bool opt_sip_register_deferred_save = false;
int opt_sip_register_advanced = 0;
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
unsigned int opt_maxpoolaudiographsize = 0;
unsigned int opt_maxpoolaudiographdays = 0;
unsigned int opt_maxpoolsize_2 = 0;
unsigned int opt_maxpooldays_2 = 0;
unsigned int opt_maxpoolsipsize_2 = 0;
unsigned int opt_maxpoolsipdays_2 = 0;
unsigned int opt_maxpoolrtpsize_2 = 0;
unsigned int opt_maxpoolrtpdays_2 = 0;
unsigned int opt_maxpoolgraphsize_2 = 0;
unsigned int opt_maxpoolgraphdays_2 = 0;
unsigned int opt_maxpoolaudiosize_2 = 0;
unsigned int opt_maxpoolaudiodays_2 = 0;
unsigned int opt_maxpoolaudiographsize_2 = 0;
unsigned int opt_maxpoolaudiographdays_2 = 0;
int opt_maxpool_clean_obsolete = 0;
int opt_autocleanspoolminpercent = 1;
int opt_autocleanmingb = 5;
int opt_cleanspool_enable_run_hour_from = -1;
int opt_cleanspool_enable_run_hour_to = -1;
int opt_mysqlloadconfig = 1;
bool opt_last_rtp_from_end = true;
int opt_pcap_dump_bufflength = 8192;
int opt_pcap_dump_asyncwrite = 1;
unsigned opt_pcap_dump_asyncwrite_batch_limit = 0;
FileZipHandler::eTypeCompress opt_pcap_dump_zip_sip = FileZipHandler::compress_na;
FileZipHandler::eTypeCompress opt_pcap_dump_zip_rtp = 
	#ifdef HAVE_LIBLZO
		FileZipHandler::lzo;
	#elif HAVE_LIBZSTD
		FileZipHandler::zstd;
	#else
		FileZipHandler::gzip;
	#endif //HAVE_LIBLZO
int opt_pcap_dump_compresslevel_sip = INT_MIN;
int opt_pcap_dump_compresslevel_rtp = INT_MIN;
int opt_pcap_dump_compresslevel_graph = INT_MIN;
int opt_pcap_dump_compresslevel_audiograph = INT_MIN;
int opt_pcap_dump_compresslevel_sip_gzip = 1;
int opt_pcap_dump_compresslevel_sip_lzma = 1;
int opt_pcap_dump_compresslevel_sip_zstd = 1;
int opt_pcap_dump_compresslevel_rtp_gzip = 1;
int opt_pcap_dump_compresslevel_rtp_lzma = 1;
int opt_pcap_dump_compresslevel_rtp_zstd = 1;
int opt_pcap_dump_compresslevel_graph_gzip = 1;
int opt_pcap_dump_compresslevel_graph_lzma = 1;
int opt_pcap_dump_compresslevel_graph_zstd = 1;
int opt_pcap_dump_compresslevel_audiograph_gzip = 1;
int opt_pcap_dump_compresslevel_audiograph_lzma = 1;
int opt_pcap_dump_compresslevel_audiograph_zstd = 1;
int opt_pcap_dump_compress_sip_zstdstrategy = INT_MIN;
int opt_pcap_dump_compress_rtp_zstdstrategy = INT_MIN;
int opt_pcap_dump_compress_graph_zstdstrategy = INT_MIN;
int opt_pcap_dump_compress_audiograph_zstdstrategy = INT_MIN;
int opt_pcap_dump_writethreads = 1;
int opt_pcap_dump_writethreads_max = 32;
int opt_pcap_dump_asyncwrite_maxsize = 100; //MB
int opt_pcap_dump_tar = 1;
bool opt_pcap_dump_tar_use_hash_instead_of_long_callid = 1;
int opt_pcap_dump_tar_threads = 8;
int opt_pcap_dump_tar_compress_sip =
	#if HAVE_LIBZSTD
		Tar::_zstd;
	#else
		Tar::_gzip_force;
	#endif
int opt_pcap_dump_tar_sip_level_gzip = 6;
int opt_pcap_dump_tar_sip_level_lzma = 5;
int opt_pcap_dump_tar_sip_level_zstd = 1;
int opt_pcap_dump_tar_sip_zstdstrategy = INT_MIN;
int opt_pcap_dump_tar_sip_use_pos = 0;
int opt_pcap_dump_tar_compress_rtp = Tar::_no_compress;
int opt_pcap_dump_tar_rtp_level_gzip = 1;
int opt_pcap_dump_tar_rtp_level_lzma = 1;
int opt_pcap_dump_tar_rtp_level_zstd = 1;
int opt_pcap_dump_tar_rtp_zstdstrategy = INT_MIN;
int opt_pcap_dump_tar_rtp_use_pos = 0;
int opt_pcap_dump_tar_compress_graph =
	#if HAVE_LIBZSTD
		Tar::_zstd;
	#else
		Tar::_gzip_force;
	#endif
int opt_pcap_dump_tar_graph_level_gzip = 6;
int opt_pcap_dump_tar_graph_level_lzma = 5;
int opt_pcap_dump_tar_graph_level_zstd = 1;
int opt_pcap_dump_tar_graph_zstdstrategy = INT_MIN;
int opt_pcap_dump_tar_graph_use_pos = 0;
int opt_pcap_dump_tar_compress_audiograph =
	#if HAVE_LIBZSTD
		Tar::_zstd;
	#else
		Tar::_gzip_force;
	#endif
int opt_pcap_dump_tar_audiograph_level_gzip = 6;
int opt_pcap_dump_tar_audiograph_level_lzma = 5;
int opt_pcap_dump_tar_audiograph_level_zstd = 1;
int opt_pcap_dump_tar_audiograph_zstdstrategy = INT_MIN;
int opt_pcap_dump_tar_audiograph_use_pos = 0;
CompressStream::eTypeCompress opt_pcap_dump_tar_internalcompress_sip = CompressStream::compress_na;
CompressStream::eTypeCompress opt_pcap_dump_tar_internalcompress_rtp = CompressStream::compress_na;
CompressStream::eTypeCompress opt_pcap_dump_tar_internalcompress_graph = CompressStream::compress_na;
CompressStream::eTypeCompress opt_pcap_dump_tar_internalcompress_audiograph = CompressStream::compress_na;
int opt_pcap_dump_tar_internal_gzip_sip_level = -1;
int opt_pcap_dump_tar_internal_gzip_rtp_level = -1;
int opt_pcap_dump_tar_internal_gzip_graph_level = -1;
int opt_pcap_dump_tar_internal_gzip_audiograph_level = -1;
int opt_pcap_ifdrop_limit = 20;
int opt_pcap_dpdk_ifdrop_limit = 0;
int swapDelayCount = 0;
int swapMysqlDelayCount = 0;

int opt_sdp_multiplication = 3;
bool opt_both_side_for_check_direction = true;
vector<vmIPport> opt_sdp_ignore_ip_port;
vector<vmIP> opt_sdp_ignore_ip;
vector<vmIPmask> opt_sdp_ignore_net;
string opt_save_sip_history;
bool _save_sip_history;
bool _save_sip_history_request_types[1000];
bool _save_sip_history_all_requests;
bool _save_sip_history_all_responses;
bool opt_active_call_info;
bool opt_disable_sdp_multiplication_warning = false;
bool opt_enable_content_type_application_csta_xml = false;
bool opt_cdr_sipresp = false;
bool opt_rtpmap_by_callerd = false;
bool opt_rtpmap_combination = true;
bool opt_rtpmap_indirect = true;
int opt_jitter_forcemark_transit_threshold = 10;
int opt_jitter_forcemark_delta_threshold = 500;
bool opt_disable_rtp_warning = false;
bool opt_disable_rtp_seq_probation = false;
bool opt_disable_rtp_seq_check = false;
bool opt_rtp_seq_dupl_skip_ext = false;
int opt_hash_modify_queue_length_ms = 0;
int opt_hash_modify_queue_length_ms_high_traffic = 100;
int hash_modify_queue_length_ms;
bool opt_disable_process_sdp = false;

bool opt_conference_processing = false;
vector<string> opt_conference_uri;
vector<string> opt_mo_mt_identification_prefix;
int opt_separate_storage_ipv6_ipv4_address;
int opt_cdr_flag_bit;
vector<string> opt_srvcc_numbers;
int opt_srvcc_compare_number_length = 9;
bool srvcc_set;
ListCheckString *srvcc_numbers;
bool opt_srvcc_processing_only;
bool opt_save_srvcc_cdr = true;
bool opt_srvcc_correlation;

char opt_php_path[1024];

struct pcap_stat pcapstat;

bool rightPSversion = true;
bool bashPresent = true;

extern bool opt_pcap_queue_disable;
extern u_int opt_pcap_queue_block_max_time_ms;
extern size_t opt_pcap_queue_block_max_size;
extern u_int opt_pcap_queue_file_store_max_time_ms;
extern size_t opt_pcap_queue_file_store_max_size;
uint64_t opt_pcap_queue_store_queue_max_memory_size;
extern uint64_t opt_pcap_queue_store_queue_max_disk_size;
extern uint64_t opt_pcap_queue_bypass_max_size;
extern int opt_pcap_queue_compress;
extern pcap_block_store::compress_method opt_pcap_queue_compress_method;
extern int opt_pcap_queue_compress_ratio;
extern string opt_pcap_queue_disk_folder;
extern ip_port opt_pcap_queue_send_to_ip_port;
extern ip_port opt_pcap_queue_receive_from_ip_port;
extern int opt_pcap_queue_receive_dlt;
bool opt_pcap_queue_receive_sensor_id_by_sender;
bool opt_pcap_queue_receive_sensor_id_by_sender_set;
extern int opt_pcap_queue_iface_qring_size;
extern int opt_pcap_queue_dequeu_window_length;
extern int opt_pcap_queue_dequeu_need_blocks;
extern int opt_pcap_queue_dequeu_method;
extern int opt_pcap_queue_use_blocks;
extern int opt_pcap_queue_use_blocks_auto_enable;
extern int opt_pcap_queue_use_blocks_read_check;
extern int opt_pcap_queue_suppress_t1_thread;
extern int opt_pcap_queue_block_timeout;
extern bool opt_pcap_queue_pcap_stat_per_one_interface;
extern bool opt_pcap_queues_mirror_nonblock_mode;
extern bool opt_pcap_queues_mirror_require_confirmation;
extern bool opt_pcap_queues_mirror_use_checksum;
extern int opt_pcap_dispatch;
extern int sql_disable_next_attempt_if_error;
int opt_cleandatabase_cdr = 0;
int opt_cleandatabase_cdr_rtp_energylevels = 0;
int opt_cleandatabase_ss7 = 0;
int opt_cleandatabase_http_enum = 0;
int opt_cleandatabase_webrtc = 0;
int opt_cleandatabase_register_state = 0;
int opt_cleandatabase_register_failed = 0;
int opt_cleandatabase_register_time_info = 0;
int opt_cleandatabase_sip_msg = 0;
int opt_cleandatabase_cdr_stat = 71;
int opt_cleandatabase_cdr_problems = 71;
int opt_cleandatabase_rtp_stat = 2;
int opt_cleandatabase_log_sensor = 30;
int opt_cleandatabase_size = 0;
int opt_cleandatabase_min_free_size = 0;
int opt_cleandatabase_cdr_size = 0;
int opt_cleandatabase_cdr_rtp_energylevels_size = 0;
int opt_cleandatabase_ss7_size = 0;
int opt_cleandatabase_http_enum_size = 0;
int opt_cleandatabase_webrtc_size = 0;
int opt_cleandatabase_register_state_size = 0;
int opt_cleandatabase_register_failed_size = 0;
int opt_cleandatabase_register_time_info_size = 0;
int opt_cleandatabase_sip_msg_size = 0;
int opt_cleandatabase_cdr_stat_size = 0;
int opt_cleandatabase_cdr_problems_size = 0;
int opt_cleandatabase_rtp_stat_size = 0;
int opt_cleandatabase_log_sensor_size = 0;
int opt_cleandatabase_size_period = 10 * 60;
bool opt_cleandatabase_size_force = false;
unsigned int graph_delimiter = GRAPH_DELIMITER;
unsigned int graph_version = GRAPH_VERSION;
unsigned int graph_mark = GRAPH_MARK;
unsigned int graph_mos = GRAPH_MOS;
unsigned int graph_silence = GRAPH_SILENCE;
unsigned int graph_event = GRAPH_EVENT;
int opt_mos_lqo = 0;
char opt_capture_rules_telnum_file[1024];
char opt_capture_rules_sip_header_file[1024];
bool opt_detect_alone_bye = false;
bool opt_time_precision_in_ms = false;
bool opt_cdr_partition = 1;
bool opt_cdr_partition_by_hours = 0;
bool opt_cdr_force_primary_index_in_all_tables = 0;
bool opt_cdr_sipport = 0;
bool opt_cdr_rtpport = 0;
bool opt_cdr_rtpsrcport = 0;
int opt_cdr_check_exists_callid = 0;
string opt_cdr_check_unique_callid_in_sensors;
set<int> opt_cdr_check_unique_callid_in_sensors_list;
unsigned opt_cdr_check_exists_callid_cache_max_size = 0;
bool opt_cdr_check_duplicity_callid_in_next_pass_insert = 0;
bool opt_message_check_duplicity_callid_in_next_pass_insert = 0;
int opt_create_old_partitions = 0;
char opt_create_old_partitions_from[20];
bool opt_disable_partition_operations = 0;
int opt_partition_operations_enable_run_hour_from = 1;
int opt_partition_operations_enable_run_hour_to = 5;
bool opt_partition_operations_in_thread = 1;
bool opt_partition_operations_drop_first = 0;
bool opt_autoload_from_sqlvmexport = 0;
vector<dstring> opt_custom_headers_cdr;
vector<dstring> opt_custom_headers_message;
vector<dstring> opt_custom_headers_sip_msg;
CustomHeaders *custom_headers_cdr;
CustomHeaders *custom_headers_message;
CustomHeaders *custom_headers_sip_msg;
NoHashMessageRules *no_hash_message_rules;
bool opt_callernum_numberonly = true;
int opt_custom_headers_last_value = 1;
int opt_custom_headers_max_size = 0;
bool opt_sql_time_utc = false;
bool opt_socket_use_poll = true;
bool opt_interrupts_counters = true;

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
int opt_mysql_port = 0; // 0 means use standard port
char mysql_socket[256] = "";
string mysql_datadir;
mysqlSSLOptions optMySsl;

char mysql_2_host[256] = "";
char mysql_2_host_orig[256] = "";
char mysql_2_database[256] = "voipmonitor";
char mysql_2_user[256] = "root";
char mysql_2_password[256] = "";
int opt_mysql_2_port = 0; // 0 means use standard port
char mysql_2_socket[256] = "";
mysqlSSLOptions optMySsl_2;

bool opt_mysql_2_http = false;

int opt_alter_rows_limit = 100000;
bool opt_mysql_security_invoker_routines = true;

char opt_mysql_timezone[256] = "";
int opt_mysql_client_compress = 0;
char opt_timezone[256] = "";
int opt_skiprtpdata = 0;

bool opt_call_branches = false;
bool opt_call_branches_find_by_called_number = true;
bool opt_call_branches_find_by_called_domain = false;
bool opt_call_branches_find_smart = true;

char opt_call_id_alternative[256] = "";
vector<string> opt_call_id_alternative_v;
char opt_fbasename_header[128] = "";
char opt_match_header[128] = "";
char opt_callidmerge_header[128] = "";
char opt_callidmerge_secret[128] = "";
bool opt_callidmerge_force_separate_branches = false;

char odbc_dsn[256] = "voipmonitor";
char odbc_user[256];
char odbc_password[256];
char odbc_driver[256];

bool opt_sql_log_all_errors = false;
string opt_sql_errors_log_file;
char opt_sql_errors_skip[1024];

int opt_cloud_activecheck_period = 60;				//0 = disable, how often to check if cloud tunnel is passable in [sec.]
int cloud_activecheck_timeout = 5;				//2sec by default, how long to wait for response until restart of a cloud tunnel
volatile bool cloud_activecheck_inprogress = false;		//is currently checking in progress?
volatile bool cloud_activecheck_sshclose = false;		//is forced close/re-open of ssh forward thread?
timeval cloud_last_activecheck;					//Time of a last check request sent

char cloud_host[256] = "cloud.voipmonitor.org";
char cloud_token[256] = "";
bool cloud_router = true;
unsigned cloud_router_port = 60023;
string cloud_db_version;

cCR_Receiver_service *cloud_receiver = NULL;
cCR_ResponseSender *cloud_response_sender = NULL;

extern sSnifferServerOptions snifferServerOptions;
extern sSnifferServerClientOptions snifferServerClientOptions;

sSnifferClientOptions snifferClientOptions;
sSnifferClientOptions snifferClientOptions_charts_cache;
cSnifferClientService *snifferClientService;
cSnifferClientService **snifferClientNextServices;
cSnifferClientService *snifferClientService_charts_cache;

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
vector<dstring> ifname_libpcap_filter;
vector<vmIP> if_filter_ip;
vector<vmIPmask> if_filter_net;
bool opt_if_filter_ip_quick = true;
bool opt_ifaces_optimize = true;
int opt_eth_max_channels = 8;
bool opt_use_dpdk = false;
int opt_dpdk_init = 1;
int opt_dpdk_read_thread = 2;
int opt_dpdk_worker_thread = 2;
bool opt_dpdk_worker_slave_thread = false;
int opt_dpdk_worker2_thread = 0;
int opt_dpdk_iterations_per_call = 1000;
int opt_dpdk_read_usleep_if_no_packet = 1;
int opt_dpdk_read_usleep_type = 0;
int opt_dpdk_worker_usleep_if_no_packet = 1;
int opt_dpdk_worker_usleep_type = 0;
int opt_dpdk_nb_rx = 4096;
int opt_dpdk_nb_rxq = 2;
bool opt_dpdk_nb_rxq_rss = true;
int opt_dpdk_nb_tx = 1024;
int opt_dpdk_nb_mbufs = 1024;
bool opt_dpdk_nb_mbufs_strictly = false;
int opt_dpdk_pkt_burst = 128;
int opt_dpdk_ring_size = 0;
int opt_dpdk_mempool_cache_size = 512;
int opt_dpdk_zc = 0;
int opt_dpdk_mbufs_in_packetbuffer = 0;
int opt_dpdk_prealloc_packetbuffer = 0;
int opt_dpdk_defer_send_packetbuffer = 0;
int opt_dpdk_rotate_packetbuffer = 1;
int opt_dpdk_rotate_packetbuffer_pool_max_perc = 25;
int opt_dpdk_copy_packetbuffer = 1;
int opt_dpdk_batch_read = 0;
string opt_dpdk_cpu_cores;
string opt_dpdk_cpu_cores_map;
int opt_dpdk_main_thread_lcore = -1;
string opt_dpdk_read_thread_lcore;
string opt_dpdk_worker_thread_lcore;
string opt_dpdk_worker2_thread_lcore;
int opt_dpdk_memory_channels = 4;
string opt_dpdk_pci_device;
int opt_dpdk_force_max_simd_bitwidth = 0;
string opt_cpu_cores;
bool opt_thread_affinity_ht = true;
bool opt_other_thread_affinity_check = true;
bool opt_other_thread_affinity_set = false;
int opt_dpdk_timer_reset_interval = 60;
int opt_dpdk_mtu = 0;
vector<string> opt_dpdk_vdev;

char opt_scanpcapdir[2048] = "";	// Specifies the name of the network device to use for 
bool opt_scanpcapdir_disable_inotify = false;
#ifndef FREEBSD
int opt_scanpcapmethod = IN_CLOSE_WRITE; // Specifies how to watch for new files in opt_scanpcapdir
#endif
int opt_promisc = 1;	// put interface to promisc mode?
int opt_use_oneshot_buffer = 1;
int opt_snaplen = 0;
bool opt_libpcap_immediate_mode = false;
bool opt_libpcap_nonblock_mode = false;
char pcapcommand[4092] = "";
char filtercommand[4092] = "";

int rtp_threaded = 0;
int num_threads_set = 0;
int num_threads_start = 0;
int num_threads_max = 0;
volatile int num_threads_active = 0;
unsigned int rtpthreadbuffer = 20;	// default 20MB
unsigned int rtp_qring_length = 0;
unsigned int rtp_qring_usleep = 10;
unsigned int rtp_qring_batch_length = 1000;
unsigned int gthread_num = 0;

int opt_pcapdump = 0;

int opt_callend = 1; //if true, cdr.called is saved
bool opt_disable_cdr_fields_rtp;
bool opt_disable_cdr_indexes_rtp;
int opt_t2_boost = true;
int opt_t2_boost_direct_rtp = false;
int opt_t2_boost_direct_rtp_delay_queue_ms = 0;
int opt_t2_boost_direct_rtp_max_queue_length_ms = 0;
int opt_t2_boost_call_find_threads = false;
int opt_t2_boost_call_threads = 3;
int opt_t2_boost_pb_detach_thread = 0;
bool opt_t2_boost_pcap_dispatch = false;
int opt_t2_boost_high_traffic_limit = 1000;
int opt_storing_cdr_max_next_threads = 3;
bool opt_processing_limitations = false;
int opt_processing_limitations_heap_high_limit = 50;
int opt_processing_limitations_heap_low_limit = 25;
bool opt_processing_limitations_active_calls_cache = false;
int opt_processing_limitations_active_calls_cache_type = 2;
int opt_processing_limitations_active_calls_cache_timeout_min = 0;
int opt_processing_limitations_active_calls_cache_timeout_max = 0;
char opt_spooldir_main[1024];
char opt_spooldir_rtp[1024];
char opt_spooldir_graph[1024];
char opt_spooldir_audio[1024];
char opt_spooldir_audiograph[1024];
char opt_spooldir_2_main[1024];
char opt_spooldir_2_rtp[1024];
char opt_spooldir_2_graph[1024];
char opt_spooldir_2_audio[1024];
char opt_spooldir_2_audiograph[1024];
char opt_spooldir_file_permission[10];
unsigned opt_spooldir_file_permission_int = 0666;
char opt_spooldir_dir_permission[10];
unsigned opt_spooldir_dir_permission_int = 0777;
char opt_spooldir_owner[100];
unsigned opt_spooldir_owner_id;
char opt_spooldir_group[100];
unsigned opt_spooldir_group_id;
char opt_cachedir[1024];

int opt_tar_move = 0;
string opt_tar_move_destination_path;
string opt_tar_move_source_trim_path;
int opt_tar_move_max_threads = 2;

int opt_upgrade_try_http_if_https_fail = 0;

pthread_t storing_cdr_thread;		// ID of worker storing CDR thread 
int storing_cdr_tid;
pstat_data storing_cdr_thread_pstat_data[2][2];
struct sStoringCdrNextThreads {
	sStoringCdrNextThreads() {
		memset(this, 0, sizeof(*this));
	}
	pthread_t thread;
	int tid;
	pstat_data pstat[2][2];
	sem_t sem[2];
	bool init;
	list<Call*> *calls;
} *storing_cdr_next_threads;
volatile int storing_cdr_next_threads_count;
volatile int storing_cdr_next_threads_count_mod;
volatile int storing_cdr_next_threads_count_mod_request;
volatile int storing_cdr_next_threads_count_sync;
unsigned storing_cdr_next_threads_count_last_change;
int opt_storing_cdr_maximum_cdr_per_iteration = 50000;

pthread_t storing_registers_thread;	// ID of worker storing CDR thread 

#if EXPERIMENTAL_SEPARATE_PROCESSSING
pthread_t cleanup_calls_separate_processing_thread;
int cleanup_calls_separate_processing_tid;
bool cleanup_calls_separate_processing_terminating;
#endif

pthread_t scanpcapdir_thread;
pthread_t defered_service_fork_thread;
pthread_t check_activity_or_crash_thread;
//pthread_t destroy_calls_thread;
pthread_t manager_thread = 0;	// ID of worker manager thread 
pthread_t manager_file_thread = 0;
bool manager_file_terminating = false;
pthread_t cachedir_thread;	// ID of worker cachedir thread 
pthread_t database_backup_thread;	// ID of worker backup thread 
pthread_t tarqueuethread[2];	// ID of worker manager thread 
volatile int terminating;	// if set to 1, sniffer will terminate
int terminating_moving_cache;	// if set to 1, worker thread will terminate
int terminating_storing_cdr;	// if set to 1, worker thread will terminate
int terminating_storing_registers;
int terminating_charts_cache;
int terminated_call_cleanup;
int terminated_async;
int terminated_tar_flush_queue[2];
int terminated_tar[2];
int hot_restarting;
string hot_restarting_json_config;
vm_atomic<string> terminating_error;
char *sipportmatrix;		// matrix of sip ports to monitor
char *httpportmatrix;		// matrix of http ports to monitor
char *webrtcportmatrix;		// matrix of webrtc ports to monitor
char *skinnyportmatrix;		// matrix of skinny ports to monitor
char *ipaccountportmatrix;
char *ss7portmatrix;
char *ss7_rudp_portmatrix;
char *diameter_tcp_portmatrix;
char *diameter_udp_portmatrix;
char *ssl_portmatrix;
char *mgcp_gateway_tcp_portmatrix;
char *mgcp_gateway_udp_portmatrix;
char *mgcp_callagent_tcp_portmatrix;
char *mgcp_callagent_udp_portmatrix;
vector<vmIP> httpip;
vector<vmIPmask> httpnet;
vector<vmIP> webrtcip;
vector<vmIPmask> webrtcnet;
bool opt_sip_only_tcp = false;
unsigned opt_max_sip_packets_in_call = 20000;
unsigned opt_max_invite_packets_in_call = 10000;
int opt_enable_semicolon_in_number = false;
bool opt_response_time_from_first_invite = false;
bool opt_redirect_publish_to_call = true;
bool opt_remove_rtp_streams_after_resp3xx = false;
map<vmIPport, string> ssl_ipport;
map<vmIPmask_port, string> ssl_netport;
bool opt_ssl_ipport_reverse_enable;
bool ssl_client_random_enable = false;
char *ssl_client_random_portmatrix;
bool ssl_client_random_portmatrix_set = false;
bool ssl_client_random_tcp_set = false;
vector<vmIP> ssl_client_random_ip;
vector<vmIPmask> ssl_client_random_net;
string ssl_client_random_tcp_host;
int ssl_client_random_tcp_port;
int ssl_client_random_maxwait_ms = 0;
char ssl_master_secret_file[1024];
bool ssl_client_random_keep = true;
bool ssl_client_random_use = false;

int opt_sdp_reverse_ipport = 0;
bool opt_sdp_check_direction_ext = true;
bool opt_rtp_count_all_sequencegap_as_loss = false;

volatile unsigned int pcap_readit = 0;
volatile unsigned int pcap_writeit = 0;
int global_livesniffer = 0;

pcap_t *global_pcap_handle = NULL;		// pcap handler 
u_int16_t global_pcap_handle_index = 0;
pcap_t *global_pcap_handle_dead_EN10MB = NULL;
u_int16_t global_pcap_handle_index_dead_EN10MB = 0;

rtp_read_thread *rtp_threads;

int manager_socket_server = 0;
int manager_socket_file_server = 0;

pthread_mutex_t mysqlconnect_lock;
pthread_mutex_t hostbyname_lock;
pthread_mutex_t commmand_type_counter_sync;

pthread_t pcap_read_thread;

nat_aliases_t nat_aliases;	// net_aliases[local_ip] = extern_ip

MySqlStore *sqlStore = NULL;
MySqlStore *sqlStore_2 = NULL;
MySqlStore *loadFromQFiles = NULL;

char mac[32] = "";

PcapQueue_readFromInterface *pcapQueueInterface;
PcapQueue *pcapQueueStatInterface;

PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
PreProcessPacket **preProcessPacketCallX;
PreProcessPacket **preProcessPacketCallFindX;
int preProcessPacketCallX_count;
ProcessRtpPacket *processRtpPacketHash;
ProcessRtpPacket *processRtpPacketDistribute[MAX_PROCESS_RTP_PACKET_THREADS];
volatile PreProcessPacket::eCallX_state preProcessPacketCallX_state = PreProcessPacket::callx_na;

TcpReassembly *tcpReassemblyHttp;
TcpReassembly *tcpReassemblyWebrtc;
TcpReassembly *tcpReassemblySsl;
TcpReassembly *tcpReassemblySipExt;
TcpReassembly *tcpReassemblyDiameter;
HttpData *httpData;
WebrtcData *webrtcData;
SslData *sslData;
SipTcpData *sipTcpData;
DiameterTcpData *diameterTcpData;

vm_atomic<string> storingCdrLastWriteAt;
vm_atomic<string> storingRegisterLastWriteAt;

time_t startTime;

bool opt_loadsqlconfig = true;

int opt_mysqlstore_concat_limit = 0;
int opt_mysqlstore_concat_limit_cdr = 0;
int opt_mysqlstore_concat_limit_message = 0;
int opt_mysqlstore_concat_limit_sip_msg = 0;
int opt_mysqlstore_concat_limit_register = 0;
int opt_mysqlstore_concat_limit_http = 0;
int opt_mysqlstore_concat_limit_webrtc = 0;
int opt_mysqlstore_concat_limit_ipacc = 0;
int opt_mysqlstore_max_threads_cdr = 3;
int opt_mysqlstore_max_threads_message = 3;
int opt_mysqlstore_max_threads_sip_msg = 3;
int opt_mysqlstore_max_threads_register = 3;
int opt_mysqlstore_max_threads_http = 1;
int opt_mysqlstore_max_threads_webrtc = 1;
int opt_mysqlstore_max_threads_ipacc_base = 3;
int opt_mysqlstore_max_threads_ipacc_agreg2 = 3;
int opt_mysqlstore_max_threads_charts_cache = 1;
bool opt_mysqlstore_max_threads_cdr_set = false;
bool opt_mysqlstore_max_threads_message_set = false;
bool opt_mysqlstore_max_threads_sip_msg_set = false;
bool opt_mysqlstore_max_threads_register_set = false;
bool opt_mysqlstore_max_threads_http_set = false;
bool opt_mysqlstore_max_threads_webrtc_set = false;
bool opt_mysqlstore_max_threads_ipacc_base_set = false;
bool opt_mysqlstore_max_threads_ipacc_agreg2_set = false;
bool opt_mysqlstore_max_threads_charts_cache_set = false;
int opt_mysqlstore_limit_queue_register = 1000000;

char opt_curlproxy[256] = "";
int opt_enable_fraud = 1;
int opt_enable_billing = 1;
char opt_local_country_code[10] = "local";

ip_port sipSendSocket_ip_port;
SocketSimpleBufferWrite *sipSendSocket = NULL;
int opt_sip_send_udp;
int opt_sip_send_before_packetbuffer = 0;

int opt_enable_jitterbuffer_asserts = 0;
int opt_hide_message_content = 0;
char opt_hide_message_content_secret[1024] = "";
vector<string> opt_message_body_url_reg;

char opt_bogus_dumper_path[1204];
BogusDumper *bogusDumper;
#if TRAFFIC_DUMPER
char opt_traffic_dumper_path[1204];
bool opt_traffic_dumper_by_interface = false;
bool opt_traffic_dumper_force_flush = false;
TrafficDumper *trafficDumper;
#endif

char opt_syslog_string[256];
int opt_cpu_limit_warning_t0 = 80;
int opt_cpu_limit_new_thread_if_heap_grows = 50;
int opt_cpu_limit_new_thread = 60;
int opt_cpu_limit_new_thread_high = 80;
int opt_cpu_limit_delete_thread = 5;
int opt_cpu_limit_delete_t2sip_thread = 15;
int opt_heap_limit_new_thread = 5;

int opt_memory_purge_interval = 60;
int opt_memory_purge_if_release_gt = 500;

CleanSpool *cleanSpool[2] = { NULL, NULL };

TarQueue *tarQueue[2] = { NULL, NULL };
TarCopy *tarCopy;

pthread_mutex_t terminate_packetbuffer_lock;

extern ParsePacket _parse_packet_global_process_packet;

cBuffersControl buffersControl;

u_int64_t rdtsc_by_250ms = 0;

char opt_git_folder[1024];
char opt_configure_param[1024];
bool opt_upgrade_by_git;

bool opt_save_query_main_to_files = true;
bool opt_save_query_charts_to_files = true;
bool opt_save_query_charts_remote_to_files = false;
char opt_save_query_to_files_directory[1024];
int opt_save_query_to_files_period;
int opt_query_cache_speed;
int opt_query_cache_check_utf;
int opt_query_cache_max_mb_utf = 0;

int opt_load_query_main_from_files = 1;
int opt_load_query_charts_from_files = 1;
int opt_load_query_charts_remote_from_files = 0;
char opt_load_query_from_files_directory[1024];
int opt_load_query_from_files_period;
bool opt_load_query_from_files_inotify = true;

bool opt_virtualudppacket = false;
int opt_sip_tcp_reassembly_stream_timeout = 10 * 60;
int opt_sip_tcp_reassembly_stream_max_attempts = 200;
int opt_sip_tcp_reassembly_stream_max_length = 0;
int opt_sip_tcp_reassembly_clean_period = 10;
bool opt_sip_tcp_reassembly_ext = true;
int opt_sip_tcp_reassembly_ext_link_timeout = 0;
int opt_sip_tcp_reassembly_ext_quick_mod = 0;
int opt_sip_tcp_reassembly_ext_complete_mod = 1;
int opt_sip_tcp_reassembly_ext_usleep = 10;

int opt_test = 0;
char opt_test_arg[1024] = "";
bool opt_check_db = false;

char *opt_untar_gui_params = NULL;
char *opt_unlzo_gui_params = NULL;
char *opt_waveform_gui_params = NULL;
char *opt_spectrogram_gui_params = NULL;
char *opt_audioconvert_params = NULL;
char *opt_audio_transcribe_params = NULL;
char *opt_rtp_stream_analysis_params = NULL;
sStreamAnalysisData *rtp_stream_analysis_data = NULL;
char *opt_check_regexp_gui_params = NULL;
char *opt_test_regexp_gui_params = NULL;
char *opt_read_pcap_gui_params = NULL;
char *opt_cmp_config_params = NULL;
char *opt_revaluation_params = NULL;
char *opt_reassign_countries_params = NULL;
bool is_gui_param = false;
char opt_test_str[1024];

map<int, string> command_line_data;
cConfig CONFIG;
bool useNewCONFIG = true;
bool useCmdLineConfig = false;

bool printConfigStruct = false;
bool printConfigFile = false;
bool printConfigFile_default = false;
bool updateSchema = false;

unsigned opt_udp_port_l2tp = 1701;
unsigned opt_udp_port_tzsp = 0x9090;
unsigned opt_udp_port_vxlan = 4789;
unsigned opt_udp_port_hperm = 7932;

bool opt_icmp_process_data = false;

bool opt_audiocodes = false;
unsigned opt_udp_port_audiocodes = 925;
unsigned opt_tcp_port_audiocodes = 925;
int opt_audiocodes_rtp = 1;
int opt_audiocodes_rtcp = 1;
map<u_int16_t, bool> opt_audiocodes_sip_ports;

bool opt_ipfix;
string opt_ipfix_bind_ip;
unsigned opt_ipfix_bind_port;
vector<int> opt_ipfix_version;
bool opt_ipfix_counter_log;
bool opt_ipfix_via_pb = true;

bool opt_hep;
string opt_hep_bind_ip;
unsigned opt_hep_bind_port;
bool opt_hep_bind_udp;
bool opt_hep_counter_log;
bool opt_hep_kamailio_protocol_id_fix = true;
bool opt_hep_via_pb = true;

bool opt_kamailio;
vmIP opt_kamailio_dstip;
vmIP opt_kamailio_srcip;
unsigned opt_kamailio_port;
bool opt_ribbonsbc;
vmIP opt_ribbonsbc_dstip;
vmIP opt_ribbonsbc_srcip;
unsigned opt_ribbonsbc_port;
bool sip_data_subst = false;

SensorsMap sensorsMap;

bool cloud_db = false;

WDT *wdt;
bool enable_wdt = true;
string wdt_run_command;
string cmdline;
string rundir;
string appname;
string binaryNameWithPath;
string binaryPath;
string configfilename;

char opt_crash_bt_filename[100];

bool useSemaphoreLock = false;
sem_t *semaphoreLock[2];
const char *anotherInstanceMessage = "another voipmonitor instance with the same configuration file is running";

int ownPidStart;
int ownPidFork;
char ownPidStart_str[10];
char ownPidFork_str[10];

cResolver resolver;
cUtfConverter utfConverter;

bool useIPv6 = false;

long int runAt;

cLogBuffer *logBuffer;

int opt_hashtable_heap_size = 0;

bool opt_hugepages_anon = false;
int opt_hugepages_max = 0;
int opt_hugepages_overcommit_max = 0;
int opt_hugepages_second_heap = 0;

int opt_numa_balancing_set = numa_balancing_set_autodisable;

int opt_mirror_connect_maximum_time_diff_s = 2;
int opt_client_server_connect_maximum_time_diff_s = 2;
int opt_receive_packetbuffer_maximum_time_diff_s = 30;
int opt_client_server_sleep_ms_if_queue_is_full = 1000;

int opt_livesniffer_timeout_s = 0;
int opt_livesniffer_tablesize_max_mb = 0;

#if EXPERIMENTAL_SEPARATE_PROCESSSING
int opt_separate_processing = 0;
#endif

int opt_abort_if_rss_gt_gb = 0;
int opt_abort_if_alloc_gt_gb = 0;
bool opt_abort_if_heap_full = false;
bool opt_exit_if_heap_full = false;
bool opt_abort_if_heap_full_and_t2cpu_is_low = true;
bool opt_exit_if_heap_full_and_t2cpu_is_low = false;
int opt_next_server_connections = 0;

string opt_coredump_filter = "0x7F";

bool heap_profiler_is_running = false;

int opt_process_pcap_type = 0;
char opt_pcap_destination[1024];
cConfigItem_net_map::t_net_map opt_anonymize_ip_map;
cConfigItem_domain_map::t_domain_map opt_anonymize_domain_map;
string opt_rtcp_params;

char opt_curl_hook_wav[256] = "";

bool opt_is_client_packetbuffer_sender = false;

cWsCalls *ws_calls;

string extract_payload;
string extract_rtp_payload;

bool opt_all_configuration_options_in_gui = false;
bool opt_all_unlink_log = false;
bool opt_bt_sighandler_enable = true;
string opt_jemalloc_stat_full_folder;

string opt_sched_pol_interface;
string opt_sched_pol_pb;
string opt_sched_pol_sip;
string opt_sched_pol_rtp_prep;
string opt_sched_pol_rtp_read;

string opt_sched_pol_auto = "prio -20";
int opt_sched_pol_auto_heap_limit = 1;
int opt_sched_pol_auto_cpu_limit = 45;

bool opt_use_thread_setname = false;

bool opt_manager_enable_unencrypted = false;

static cCreatePartitions CreatePartitions;


#include <stdio.h>
#include <pthread.h>
#ifdef HAVE_OPENSSL
#include <openssl/err.h>
#endif
 
#define MUTEX_TYPE       pthread_mutex_t
#define MUTEX_SETUP(x)   pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x)    pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x)  pthread_mutex_unlock(&(x))
#define THREAD_ID        pthread_self(  )

void set_context_config();
void dns_lookup_common_hostnames();
void daemonizeOutput(string error);

static void parse_command_line_arguments(int argc, char *argv[]);
static void get_command_line_arguments();
static void get_command_line_arguments_mysql();
static void get_command_line_arguments_json_config();
static void set_default_values();
static void check_context_config();
static void set_context_config_after_check_db_schema();
static void create_spool_dirs();
static bool check_complete_parameters();
static void final_parameters();
static void parse_opt_nocdr_for_last_responses();
static void set_cdr_check_unique_callid_in_sensors_list();

void init_management_functions(void);
 
 
void handle_error(const char *file, int lineno, const char *msg){
     fprintf(stderr, "** %s:%d %s\n", file, lineno, msg);
#ifdef HAVE_OPENSSL
     ERR_print_errors_fp(stderr);
#endif
     /* exit(-1); */ 
 }
 
/* This array will store all of the mutexes available to OpenSSL. */ 
static MUTEX_TYPE *mutex_buf= NULL;

#if __GNUC__ >= 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static void locking_function(int mode, int n, const char * /*file*/, int /*line*/)
{
#ifdef HAVE_OPENSSL
  if (mode & CRYPTO_LOCK)
    MUTEX_LOCK(mutex_buf[n]);
  else
    MUTEX_UNLOCK(mutex_buf[n]);
#endif
}
 
static unsigned long id_function(void)
{
  return ((unsigned long)THREAD_ID);
}
#if __GNUC__ >= 8
#pragma GCC diagnostic pop
#endif
 
int thread_setup(void)
{
#ifdef HAVE_OPENSSL
  int i;
  mutex_buf = new FILE_LINE(42001) MUTEX_TYPE[CRYPTO_num_locks()];
  if (!mutex_buf)
    return 0;
  for (i = 0;  i < CRYPTO_num_locks(  );  i++)
    MUTEX_SETUP(mutex_buf[i]);
  CRYPTO_set_id_callback(id_function);
  CRYPTO_set_locking_callback(locking_function);
  return 1;
#else
  return 0;
#endif
}
 
int thread_cleanup(void)
{
#ifdef HAVE_OPENSSL
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
#else
  return 0;
#endif
}

char *semaphoreLockName(int index) {
	static char semLockName[2][1024] = { "", "" };
	if(!semLockName[index][0]) {
		strcpy(semLockName[index], appname.c_str());
		strcat(semLockName[index], ("_" + intToString(index)).c_str());
		if(configfilename.length()) {
			strcat(semLockName[index], "_");
			strcat(semLockName[index], configfilename.c_str());
		}
	}
	return(semLockName[index]);
}

void semaphoreUnlink(int index = -1, bool force = false) {
	if(useSemaphoreLock && (opt_fork || force)) {
		if(index == -1) {
			for(int i = 0; i < 2; i++) {
				semaphoreUnlink(i, force);
			}
		} else {
			sem_unlink(semaphoreLockName(index));
		}
	}
}

void semaphoreClose(int index = -1, bool force = false) {
	if(useSemaphoreLock && (opt_fork || force)) {
		if(index == -1) {
			for(int i = 0; i < 2; i++) {
				semaphoreClose(i, force);
			}
		} else {
			if(semaphoreLock[index]) {
				sem_close(semaphoreLock[index]);
				semaphoreLock[index] = NULL;
			}
		}
	}
}

void vm_terminate() {
	inc_terminating();
}

void vm_terminate_error(const char *terminate_error) {
	terminating_error = terminate_error;
	set_terminating();
}

bool is_terminating_without_error() {
	string _terminate_error = terminating_error;
	return(is_terminating() && _terminate_error.empty());
}

void exit_handler_fork_mode() {
	semaphoreUnlink();
	semaphoreClose();
}

/* handler for INTERRUPT signal */
void sigint_handler(int /*param*/)
{
	syslog(LOG_ERR, "SIGINT received, terminating\n");
	vm_terminate();
}

/* handler for TERMINATE signal */
void sigterm_handler(int /*param*/)
{
	syslog(LOG_ERR, "SIGTERM received, terminating\n");
	vm_terminate();
}

#define childPidsExit_max 10
struct sPidInfo { 
	sPidInfo(pid_t pid = 0, int exitCode = 0) { this->pid = pid, this->exitCode = exitCode; }
	volatile pid_t pid; volatile int exitCode; 
};
volatile unsigned childPidsExit_count;
sPidInfo childPidsExit[childPidsExit_max];
void sigchld_handler(int /*param*/)
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

void *database_backup(void */*dummy*/) {
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
	sqlStore = new FILE_LINE(42002) MySqlStore(mysql_host, mysql_user, mysql_password, mysql_database, opt_mysql_port, mysql_socket,
						   NULL, NULL, false, &optMySsl);
	bool callCreateSchema = false;
	manager_parse_command_enable();
	while(!is_terminating()) {
		syslog(LOG_NOTICE, "-- START BACKUP PROCESS");
		
		SqlDb *sqlDbSrc = new FILE_LINE(42003) SqlDb_mysql();
		sqlDbSrc->setConnectParameters(opt_database_backup_from_mysql_host, 
					       opt_database_backup_from_mysql_user,
					       opt_database_backup_from_mysql_password,
					       opt_database_backup_from_mysql_database,
					       opt_database_backup_from_mysql_port,
					       opt_database_backup_from_mysql_socket,
					       true,
					       &optMySSLBackup);
		if(sqlDbSrc->connect()) {
			SqlDb_mysql *sqlDbSrc_mysql = dynamic_cast<SqlDb_mysql*>(sqlDbSrc);
			if(!opt_database_backup_check_src_tables ||
			   sqlDbSrc_mysql->checkSourceTables()) {
			 
				if(!callCreateSchema) {
					sqlDb->createSchema();
					sqlDb->checkSchema();
					callCreateSchema = true;
				}
				
				cSqlDbCodebooks *cb_src = NULL;
				if(opt_database_backup_merge_reference_tables) {
					cb_src = new FILE_LINE(0) cSqlDbCodebooks;
					cb_src->registerCodebooks(0, true, true);
					cb_src->loadAll(sqlDbSrc_mysql);
				}
				cSqlDbCodebooks *cb_dst = NULL;
				if(opt_database_backup_merge_reference_tables) {
					cb_dst = new FILE_LINE(0) cSqlDbCodebooks;
					cb_dst->registerCodebooks(0);
					cb_dst->loadAll(sqlDb);
				}
				
				sqlDb_mysql->copyFromSourceTablesReftabs(sqlDbSrc_mysql, cb_src, cb_dst);
			
				if(custom_headers_cdr) {
					custom_headers_cdr->refresh(sqlDbSrc, false);
					custom_headers_cdr->createColumnsForFixedHeaders(sqlDb);
					custom_headers_cdr->createTablesIfNotExists(sqlDb, true);
					custom_headers_cdr->checkTablesColumns(sqlDb);
				}
				if(custom_headers_message) {
					custom_headers_message->refresh(sqlDbSrc, false);
					custom_headers_message->createColumnsForFixedHeaders(sqlDb);
					custom_headers_message->createTablesIfNotExists(sqlDb, true);
					custom_headers_message->checkTablesColumns(sqlDb);
				}
				if(custom_headers_sip_msg) {
					custom_headers_sip_msg->refresh(sqlDbSrc, false);
					custom_headers_sip_msg->createColumnsForFixedHeaders(sqlDb);
					custom_headers_sip_msg->createTablesIfNotExists(sqlDb, true);
					custom_headers_sip_msg->checkTablesColumns(sqlDb);
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
			 
				sqlDb_mysql->copyFromSourceTablesMain(sqlDbSrc_mysql, 
								      opt_database_backup_pass_rows, 
								      opt_database_backup_desc_dir, 
								      opt_database_backup_skip_register,
								      !opt_database_backup_check_src_tables,
								      cb_src, cb_dst);
				
				if(cb_src) {
					delete cb_src;
				}
				if(cb_dst) {
					delete cb_dst;
				}
				
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
		
		extern volatile int partitionsServiceIsInProgress;
		if(!opt_nocdr && !opt_disable_partition_operations &&
		   !is_client() && 
		   isSqlDriver("mysql") &&
		   !sCreatePartitions::in_progress && !partitionsServiceIsInProgress &&
		   opt_database_backup_cleandatabase) {
			CreatePartitions.run();
		}
		
		for(int i = 0; i < opt_database_backup_pause && !is_terminating(); i++) {
			sleep(1);
		}
	}
	manager_parse_command_disable();
	sqlStore->setEnableTerminatingIfSqlError(0, 0, true);
	while(is_terminating() < 2 && sqlStore->getAllSize()) {
		syslog(LOG_NOTICE, "flush sqlStore");
		sleep(1);
	}
	sqlStore->setEnableTerminatingIfEmpty(0, 0, true);
	delete sqlDb;
	delete sqlStore;
	sqlStore = NULL;
	return NULL;
}

void SipHistorySetting (void) {
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

int SqlInitSchema(string *rsltConnectErrorString = NULL) {
	int connectOk = 1;
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
			if(!is_read_from_file() &&
			   sqlDb->getDbName() == "mysql" &&
			   sqlDb->getDbMajorVersion() >= 8) {
				if(is_support_for_mysql_new_store()) {
					if(opt_mysql_enable_new_store < 1) {
						opt_mysql_enable_new_store = true;
					}
				} else {
					if(!sqlDb->existsTable("cdr") || sqlDb->emptyTable("cdr")) {
						connectErrorString = "! mysql version 8 is not supported because it contains critical bug #92023 (https://bugs.mysql.com/bug.php?id=92023)";
						connectOk = -1;
					} else {
						cLogSensor::log(cLogSensor::critical, "Mysql version 8 contains critical bug #92023 (https://bugs.mysql.com/bug.php?id=92023). Please downgrade to version 5.7 or contact support.");
						opt_mysql_enable_new_store = false;
					}
				}
			}
			if(opt_save_energylevels &&
			   sqlDb->getDbName() == "mysql" &&
			   sqlDb->getDbVersion() < 50601) {
				cLogSensor::log(cLogSensor::critical, "The save-energylevels option is supported for mysql since version 5.6.1. Please update mysql if you require this option enabled.");
				opt_save_energylevels = false;
			}
			if(connectOk > 0) {
				if(isSqlDriver("mysql")) {
					sql_disable_next_attempt_if_error = 1;
					if(sqlDb->existsTable("mysql.proc")) {
						sqlDb->query("repair table mysql.proc");
					}
					sql_disable_next_attempt_if_error = 0;
				}
				sqlDb->checkDbMode();
				if(!opt_database_backup) {
					if(!(opt_disable_dbupgradecheck || is_read_from_file_simple() ||
					     (is_client() && 
					      ((snifferClientOptions.remote_query && snifferClientOptions.remote_store) ||
					       snifferClientOptions.packetbuffer_sender)))) {
						if(sqlDb->createSchema(connectId)) {
							sqlDb->checkSchema(connectId);
						} else {
							connectOk = 0;
							connectErrorString = sqlDb->getLastErrorString();
						}
					} else {
						sqlDb->checkSchema(connectId, true);
						if(is_read_from_file_simple()) {
							SqlDb_mysql *sqlDb_mysql = dynamic_cast<SqlDb_mysql*>(sqlDb);
							if(sqlDb_mysql) {
								sqlDb_mysql->createSchema_procedure_partition(connectId);
							}
						}
					}
					sqlDb->updateSensorState();
					set_context_config_after_check_db_schema();
				}
				sensorsMap.fillSensors(sqlDb);
				if(enable_register_engine && !opt_database_backup) {
					initRegistersDb(sqlDb);
				}
			}
		} else {
			connectOk = 0;
			connectErrorString = sqlDb->getLastErrorString();
		}
		delete sqlDb;
	}
	if(rsltConnectErrorString) {
		*rsltConnectErrorString = connectOk < 1 ? connectErrorString : "";
	}
	return(connectOk);
}

/* cycle files_queue and move it to spool dir */
void *moving_cache( void */*dummy*/ ) {
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
			dst.append(opt_spooldir_main);
			dst.append("/");
			dst.append(file);

			strcpy_null_term(src_c, (char*)src.c_str());
			strcpy_null_term(dst_c, (char*)dst.c_str());

			if(verbosity > 2) syslog(LOG_ERR, "rename([%s] -> [%s])\n", src_c, dst_c);
			int64_t _cachedirtransfered = move_file(src_c, dst_c, true);
			if(_cachedirtransfered > 0) {
				cachedirtransfered += _cachedirtransfered;
			}
			//TODO: error handling
			//perror ("The following error occurred");

			// Here we put our CURL hook
			// And use it only if cacheing is turned on
			if (opt_curl_hook_wav[0] != '\0' && opt_cachedir[0] != '\0') {
				SimpleBuffer responseBuffer;
				s_get_curl_response_params curl_params(s_get_curl_response_params::_rt_json);
				curl_params.addParam("voipmonitor", "true");
				curl_params.addParam("stereo", opt_saveaudio_stereo ? "false" : "true");
				curl_params.addParam("wav_file_name_with_path", dst_c);
				if (!get_curl_response(opt_curl_hook_wav, &responseBuffer, &curl_params)) {
					if(verbosity > 1) syslog(LOG_ERR, "FAIL: Send event to hook[%s], error[%s]\n", opt_curl_hook_wav, curl_params.error.c_str());
				} else {
					if(verbosity > 1) syslog(LOG_INFO, "SUCCESS: Send event to hook[%s], response[%s]\n", opt_curl_hook_wav, (char*)responseBuffer);
				}
			}
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
									snprintf(hour_str, sizeof(hour_str), "%02i", hour);
									if(file_exists((char*)(string(opt_cachedir) + "/" + de->d_name + "/" + hour_str).c_str())) {
										spooldir_mkdir(string(opt_spooldir_main) + "/" + de->d_name + "/" + hour_str);
										mv_r((string(opt_cachedir) + "/" + de->d_name + "/" + hour_str).c_str(), (string(opt_spooldir_main) + "/" + de->d_name + "/" + hour_str).c_str());
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


void *defered_service_fork(void *) {
	dns_lookup_common_hostnames();
	return(NULL);
}

static volatile u_int64_t last_pcap_stat_activity_at = 0;
static volatile u_int64_t call_bt_sighandler_at = 0;
void *check_activity_or_crash(void *) {
	while(!is_terminating()) {
		u_int64_t time_ms = getTimeMS_rdtsc();
		if((last_pcap_stat_activity_at && time_ms > last_pcap_stat_activity_at + 300000) ||
		   (call_bt_sighandler_at && time_ms > call_bt_sighandler_at + 10000)) {
			semaphoreUnlink();
			semaphoreClose();
			kill(getpid(), 9);
		}
		for(int i = 0; i < 10 && !is_terminating(); i++) {
			usleep(100000);
		}
	}
	return(NULL);
}


/* cycle calls_queue and save it to MySQL */
void *storing_cdr( void */*dummy*/ ) {
	bool firstIter = true;
	storing_cdr_tid = get_unix_tid();
	while(1) {
		extern volatile int partitionsServiceIsInProgress;
		if(!opt_nocdr && !opt_disable_partition_operations && 
		   !is_client() && 
		   isSqlDriver("mysql") &&
		   !sCreatePartitions::in_progress && !partitionsServiceIsInProgress) {
			CreatePartitions.run(firstIter);
		}
		
		if(verbosity > 0 && is_read_from_file_simple()) { 
			ostringstream outStr;
			outStr << "calls[" << calls_counter << ",r:" << registers_counter << "]";
		}
		
		size_t calls_queue_size = 0;
	
		for(int pass  = 0; pass < 10; pass++) {
			calltable->lock_calls_queue();
			calls_queue_size = calltable->calls_queue.size();
			calltable->unlock_calls_queue();
			size_t calls_queue_position = 0;
			list<Call*> calls_for_store;
			int _calls_for_store_counter = 0;
			__SYNC_LOCK(storing_cdr_next_threads_count_sync);
			storing_cdr_next_threads_count_mod = storing_cdr_next_threads_count_mod_request;
			storing_cdr_next_threads_count_mod_request = 0;
			if((storing_cdr_next_threads_count_mod > 0 && storing_cdr_next_threads_count == opt_storing_cdr_max_next_threads) ||
			   (storing_cdr_next_threads_count_mod < 0 && storing_cdr_next_threads_count == 0)) {
				storing_cdr_next_threads_count_mod = 0;
			}
			if(storing_cdr_next_threads_count_mod > 0) {
				syslog(LOG_NOTICE, "storing cdr - creating next thread %i", storing_cdr_next_threads_count + 1);
				if(!storing_cdr_next_threads[storing_cdr_next_threads_count].init) {
					storing_cdr_next_threads[storing_cdr_next_threads_count].calls = new FILE_LINE(0) list<Call*>;
					for(int i = 0; i < 2; i++) {
						sem_init(&storing_cdr_next_threads[storing_cdr_next_threads_count].sem[i], 0, 0);
					}
					storing_cdr_next_threads[storing_cdr_next_threads_count].init = true;
				}
				memset(storing_cdr_next_threads[storing_cdr_next_threads_count].pstat, 0, sizeof(storing_cdr_next_threads[storing_cdr_next_threads_count].pstat));
				void *storing_cdr_next_thread( void *_indexNextThread );
				vm_pthread_create(("storing cdr - next thread " + intToString(storing_cdr_next_threads_count + 1)).c_str(),
						  &storing_cdr_next_threads[storing_cdr_next_threads_count].thread, NULL, storing_cdr_next_thread, (void*)(long)(storing_cdr_next_threads_count), __FILE__, __LINE__);
				while(storing_cdr_next_threads_count_mod > 0) {
					USLEEP(100000);
				}
				++storing_cdr_next_threads_count;
				USLEEP(250000);
			}
			calltable->lock_calls_queue();
			while(calls_queue_position < calls_queue_size) {
				Call *call = calltable->calls_queue[calls_queue_position];
				calltable->unlock_calls_queue();
				if(call->closePcaps() || call->closeGraphs() ||
				   !call->isEmptyChunkBuffersCount()) {
					++calls_queue_position;
					calltable->lock_calls_queue();
					continue;
				}
				if(call->isReadyForWriteCdr()) {
					if(call->push_call_to_storing_cdr_queue) {
						syslog(LOG_WARNING,"try to duplicity push call %s / %i to storing cdr queue", call->call_id.c_str(), call->getTypeBase());
					} else {
						call->push_call_to_storing_cdr_queue = true;
						if(storing_cdr_next_threads_count) {
							int mod = _calls_for_store_counter % (storing_cdr_next_threads_count + 1);
							if(!mod) {
								calls_for_store.push_back(call);
							} else {
								storing_cdr_next_threads[mod - 1].calls->push_back(call);
							}
						} else {
							calls_for_store.push_back(call);
						}
					}
					++_calls_for_store_counter;
					calltable->lock_calls_queue();
					calltable->calls_queue.erase(calltable->calls_queue.begin() + calls_queue_position);
					--calls_queue_size;
					--calls_queue_position;
					if(opt_storing_cdr_maximum_cdr_per_iteration &&
					   _calls_for_store_counter >= opt_storing_cdr_maximum_cdr_per_iteration) {
						break;
					}
				} else {
					calltable->lock_calls_queue();
				}
				++calls_queue_position;
			}
			calltable->unlock_calls_queue();
			calls_for_store_counter = _calls_for_store_counter;
			if(_calls_for_store_counter || storing_cdr_next_threads_count_mod < 0) {
				if(storing_cdr_next_threads_count) {
					for(int i = 0; i < storing_cdr_next_threads_count; i++) {
						sem_post(&storing_cdr_next_threads[i].sem[0]);
					}
				}
				bool useConvertToWav = false;
				unsigned indikConvertToWavSize = calls_for_store.size();
				char *indikConvertToWav = new FILE_LINE(0) char[indikConvertToWavSize];
				memset(indikConvertToWav, 0, indikConvertToWavSize);
				unsigned counter = 0;
				for(list<Call*>::iterator iter_call = calls_for_store.begin(); iter_call != calls_for_store.end(); iter_call++) {
					Call *call = *iter_call;
					bool needConvertToWavInThread = false;
					call->closeRawFiles();
					if(enable_audio_any(call) &&
					   (call->typeIs(INVITE) || call->typeIs(SKINNY_NEW) || call->typeIs(MGCP)) &&
					   call->getAllReceivedRtpPackets()) {
						if(is_read_from_file_simple() ||
						   (is_read_from_file_by_pb() && !opt_continue_after_read)) {
							if(verbosity > 0) printf("converting RAW file to WAV Queue[%d]\n", (int)calltable->calls_queue.size());
							if(enable_audio_transcribe(call)) {
								Transcribe::sCall *transcribe_call = NULL;
								if(!call->convertRawToWav((void**)&transcribe_call, 0) && transcribe_call) {
									transcribeCall(transcribe_call);
								}
							} else {
								call->convertRawToWav(NULL, 0);
							}
						} else {
							needConvertToWavInThread = true;
						}
					}
					regfailedcache->prunecheck(TIME_US_TO_S(call->first_packet_time_us));
					if(!opt_nocdr) {
						if(call->typeIs(INVITE) or call->typeIs(SKINNY_NEW) or call->typeIs(MGCP)) {
							call->saveToDb(!is_read_from_file_simple() || isCloud() || is_client());
							/* debug
							call->lastSIPresponseNum = 503;
							strcpy(call->lastSIPresponse, "503 eee");
							call->saveToDb(!is_read_from_file_simple() || isCloud() || is_client());
							*/
						}
						if(call->typeIs(MESSAGE)) {
							call->saveMessageToDb();
						}
						if(call->typeIs(BYE)) {
							call->saveAloneByeToDb();
						}
					}
					if(counter < indikConvertToWavSize) {
						indikConvertToWav[counter] = needConvertToWavInThread;
					}
					if(needConvertToWavInThread) {
						useConvertToWav = true;
					}
					++counter;
				}
				if(useConvertToWav) {
					calltable->lock_calls_audioqueue();
				}
				list<Call*> calls_for_delete;
				counter = 0;
				for(list<Call*>::iterator iter_call = calls_for_store.begin(); iter_call != calls_for_store.end(); iter_call++) {
					if(useConvertToWav && counter < indikConvertToWavSize && indikConvertToWav[counter]) {
						if(!sverb.test_fftw) {
							calltable->audio_queue.push_back(*iter_call);
							calltable->processCallsInAudioQueue(false);
						} else {
							for(int x = 0; x < sysconf(_SC_NPROCESSORS_ONLN); x++) {
								calltable->audio_queue.push_back(*iter_call);
								calltable->processCallsInAudioQueue(false);
							}
						}
					} else {
						if(opt_destroy_calls_in_storing_cdr) {
							Call *call = *iter_call;
							call->destroyCall();
							delete call;
						} else {
							calls_for_delete.push_back(*iter_call);
						}
					}
					++counter;
				}
				if(useConvertToWav) {
					calltable->unlock_calls_audioqueue();
				}
				if(useChartsCacheOrCdrStatInProcessCall()) {
					calltable->lock_calls_charts_cache_queue();
					for(list<Call*>::iterator iter_call = calls_for_delete.begin(); iter_call != calls_for_delete.end(); iter_call++) {
						calltable->calls_charts_cache_queue.push_back(sChartsCallData(sChartsCallData::_call, *iter_call));
					}
					calltable->unlock_calls_charts_cache_queue();
				} else {
					calltable->lock_calls_deletequeue();
					for(list<Call*>::iterator iter_call = calls_for_delete.begin(); iter_call != calls_for_delete.end(); iter_call++) {
						calltable->calls_deletequeue.push_back(*iter_call);
					}
					calltable->unlock_calls_deletequeue();
				}
				delete [] indikConvertToWav;
				if(storing_cdr_next_threads_count) {
					for(int i = 0; i < storing_cdr_next_threads_count; i++) {
						sem_wait(&storing_cdr_next_threads[i].sem[1]);
					}
				}
				if(storing_cdr_next_threads_count_mod < 0) {
					--storing_cdr_next_threads_count;
					storing_cdr_next_threads_count_mod = 0;
				}
				storingCdrLastWriteAt = getActDateTimeF();
			}
			__SYNC_UNLOCK(storing_cdr_next_threads_count_sync);
			if(terminating_storing_cdr && (!calls_queue_size || terminating > 1)) {
				break;
			}
			USLEEP(100000);
		}
		
		calltable->lock_calls_queue();
		calls_queue_size = calltable->calls_queue.size();
		if(terminating_storing_cdr && (!calls_queue_size || terminating > 1)) {
			calltable->unlock_calls_queue();
			break;
		}
		calltable->unlock_calls_queue();
		
		firstIter = false;
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
			syslog(LOG_NOTICE, "wait for convert audio for %zd calls (or next terminating)", callsInAudioQueue);
			for(int i = 0; i < 10 && terminating == _terminating; i++) {
				USLEEP(100000);
			}
		}
	}
	calltable->setAudioQueueTerminating();
	while(calltable->getCountActiveAudioQueueThreads()) {
		USLEEP(100000);
	}
	
	terminating_storing_cdr = 2;
	
	return NULL;
}

void *storing_cdr_next_thread( void *_indexNextThread ) {
	int indexNextThread = (int)(long)_indexNextThread;
	storing_cdr_next_threads[indexNextThread].tid = get_unix_tid();
	if(storing_cdr_next_threads_count_mod > 0 &&
	   indexNextThread == storing_cdr_next_threads_count) {
		 storing_cdr_next_threads_count_mod = 0;
	}
	while(terminating_storing_cdr < 2) {
		sem_wait(&storing_cdr_next_threads[indexNextThread].sem[0]);
		if(terminating_storing_cdr == 2) {
			break;
		}
		bool useConvertToWav = false;
		unsigned indikConvertToWavSize = storing_cdr_next_threads[indexNextThread].calls->size();
		char *indikConvertToWav = new FILE_LINE(0) char[indikConvertToWavSize];
		memset(indikConvertToWav, 0, indikConvertToWavSize);
		unsigned counter = 0;
		for(list<Call*>::iterator iter_call = storing_cdr_next_threads[indexNextThread].calls->begin(); iter_call != storing_cdr_next_threads[indexNextThread].calls->end(); iter_call++) {
			Call *call = *iter_call;
			bool needConvertToWavInThread = false;
			call->closeRawFiles();
			if(enable_audio_any(call) &&
			   (call->typeIs(INVITE) || call->typeIs(SKINNY_NEW) || call->typeIs(MGCP)) &&
			   call->getAllReceivedRtpPackets()) {
				if(is_read_from_file_simple() ||
				   (is_read_from_file_by_pb() && !opt_continue_after_read)) {
					if(verbosity > 0) printf("converting RAW file to WAV Queue[%d]\n", (int)calltable->calls_queue.size());
					if(enable_audio_transcribe(call)) {
						Transcribe::sCall *transcribe_call = NULL;
						if(!call->convertRawToWav((void**)&transcribe_call, 0) && transcribe_call) {
							transcribeCall(transcribe_call);
						}
					} else {
						call->convertRawToWav(NULL, 0);
					}
				} else {
					needConvertToWavInThread = true;
				}
			}
			regfailedcache->prunecheck(TIME_US_TO_S(call->first_packet_time_us));
			if(!opt_nocdr) {
				if(call->typeIs(INVITE) or call->typeIs(SKINNY_NEW) or call->typeIs(MGCP)) {
					call->saveToDb(!is_read_from_file_simple() || isCloud() || is_client());
				}
				if(call->typeIs(MESSAGE)) {
					call->saveMessageToDb();
				}
				if(call->typeIs(BYE)) {
					call->saveAloneByeToDb();
				}
			}
			if(counter < indikConvertToWavSize) {
				indikConvertToWav[counter] = needConvertToWavInThread;
			}
			if(needConvertToWavInThread) {
				useConvertToWav = true;
			}
			++counter;
		}
		if(useConvertToWav) {
			calltable->lock_calls_audioqueue();
		}
		list<Call*> calls_for_delete;
		counter = 0;
		for(list<Call*>::iterator iter_call = storing_cdr_next_threads[indexNextThread].calls->begin(); iter_call != storing_cdr_next_threads[indexNextThread].calls->end(); iter_call++) {
			if(useConvertToWav && counter < indikConvertToWavSize && indikConvertToWav[counter]) {
				calltable->audio_queue.push_back(*iter_call);
				calltable->processCallsInAudioQueue(false);
			} else {
				if(opt_destroy_calls_in_storing_cdr) {
					Call *call = *iter_call;
					call->destroyCall();
					delete call;
				} else {
					calls_for_delete.push_back(*iter_call);
				}
			}
			++counter;
		}
		if(useConvertToWav) {
			calltable->unlock_calls_audioqueue();
		}
		if(useChartsCacheOrCdrStatInProcessCall()) {
			calltable->lock_calls_charts_cache_queue();
			for(list<Call*>::iterator iter_call = calls_for_delete.begin(); iter_call != calls_for_delete.end(); iter_call++) {
				calltable->calls_charts_cache_queue.push_back(sChartsCallData(sChartsCallData::_call, *iter_call));
			}
			calltable->unlock_calls_charts_cache_queue();
		} else {
			calltable->lock_calls_deletequeue();
			for(list<Call*>::iterator iter_call = calls_for_delete.begin(); iter_call != calls_for_delete.end(); iter_call++) {
				calltable->calls_deletequeue.push_back(*iter_call);
			}
			calltable->unlock_calls_deletequeue();
		}
		delete [] indikConvertToWav;
		storing_cdr_next_threads[indexNextThread].calls->clear();
		bool stop = false;
		if(storing_cdr_next_threads_count_mod < 0 &&
		   (indexNextThread + 1) == storing_cdr_next_threads_count) {
			stop = true;
		}
		sem_post(&storing_cdr_next_threads[indexNextThread].sem[1]);
		if(stop) {
			syslog(LOG_NOTICE, "storing cdr - stop next thread %i", indexNextThread + 1);
			break;
		}
	}
	return NULL;
}

void storing_cdr_next_thread_add() {
	if(getTimeS() > storing_cdr_next_threads_count_last_change + 60) {
		if(storing_cdr_next_threads_count < opt_storing_cdr_max_next_threads &&
		   storing_cdr_next_threads_count_mod == 0 &&
		   storing_cdr_next_threads_count_mod_request == 0) {
			storing_cdr_next_threads_count_mod_request = 1;
			storing_cdr_next_threads_count_last_change = getTimeS();
		}
	}
}

void storing_cdr_next_thread_remove() {
	if(getTimeS() > storing_cdr_next_threads_count_last_change + 120) {
		if(storing_cdr_next_threads_count > 0 &&
		   storing_cdr_next_threads_count_mod == 0 &&
		   storing_cdr_next_threads_count_mod_request == 0) {
			storing_cdr_next_threads_count_mod_request = -1;
			storing_cdr_next_threads_count_last_change = getTimeS();
		}
	}
}

string storing_cdr_getCpuUsagePerc(double *avg, int pstatDataIndex) {
	ostringstream cpuStr;
	cpuStr << fixed;
	double cpu_sum = 0;
	unsigned cpu_count = 0;
	double cpu = get_cpu_usage_perc(storing_cdr_tid, storing_cdr_thread_pstat_data[pstatDataIndex]);
	if(cpu > 0) {
		cpuStr << setprecision(1) << cpu;
		cpu_sum += cpu;
		++cpu_count;
	}
	for(int i = 0; i < storing_cdr_next_threads_count; i++) {
		double cpu = get_cpu_usage_perc(storing_cdr_next_threads[i].tid, storing_cdr_next_threads[i].pstat[pstatDataIndex]);
		if(cpu > 0) {
			cpuStr << '/' << setprecision(1) << cpu;
			cpu_sum += cpu;
			++cpu_count;
		}
	}
	if(avg) {
		*avg = cpu_count ? cpu_sum / cpu_count : 0;
	}
	return(cpuStr.str());
}

void *storing_registers( void */*dummy*/ ) {
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
				
					regfailedcache->prunecheck(TIME_US_TO_S(call->first_packet_time_us));
					if(!opt_nocdr) {
						if(call->typeIs(REGISTER) && enable_save_register_db(call)) {
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
		
			USLEEP(100000);
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

#if EXPERIMENTAL_SEPARATE_PROCESSSING
void *cleanup_calls_separate_processing(void *) {
	int period = opt_cleanup_calls_period;
	while(!cleanup_calls_separate_processing_terminating) {
		u_int64_t startTimeMS = getTimeMS_rdtsc();
		if(separate_processing() == cSeparateProcessing::_rtp) {
			calltable->cleanup_calls_separate_processing_rtp();
		}
		while(startTimeMS + period * 1000 > getTimeMS_rdtsc()) {
			USLEEP(10000);
			if(logBuffer) {
				logBuffer->apply();
			}
		}
	}
	return(NULL);
}
#endif

void stop_cloud_receiver() {
	if(cloud_response_sender) {
		cloud_response_sender->stop();
	}
	if(cloud_receiver) {
		cloud_receiver->receive_stop();
	}
	if(cloud_receiver) {
		delete cloud_receiver;
		cloud_receiver = NULL;
	}
	if(cloud_response_sender) {
		delete cloud_response_sender;
		cloud_response_sender = NULL;
	}
}

void start_cloud_receiver() {
	stop_cloud_receiver();
	cloud_response_sender = new FILE_LINE(0) cCR_ResponseSender();
	cloud_response_sender->start(cloud_host, cloud_router_port, cloud_token);
	cloud_receiver = new FILE_LINE(0) cCR_Receiver_service(cloud_token, opt_id_sensor > 0 ? opt_id_sensor : 0, opt_sensor_string, RTPSENSOR_VERSION_INT());
	cloud_receiver->setResponseSender(cloud_response_sender);
	cloud_receiver->setErrorTypeString(cSocket::_se_loss_connection, "connection to the cloud server has been lost - trying again");
	if(is_read_from_file()) {
		cloud_receiver->setEnableTermninateIfConnectFailed();
	}
	cloud_receiver->start(cloud_host, cloud_router_port);
	u_int64_t startTime = getTimeMS();
	while(!cloud_receiver->isStartOk() && !is_terminating()) {
		if(is_read_from_file_simple() && getTimeMS() > startTime + 3 * 1000) {
			vm_terminate();
			break;
		}
		USLEEP(100000);
	}
}

void stop_cloud_or_client() {
	if(isCloud()) {
		stop_cloud_receiver();
	} else if(is_client()) {
		snifferClientStop(snifferClientService);
		snifferClientService = NULL;
		if(opt_next_server_connections > 0) {
			for(int i = 0; i < opt_next_server_connections; i++) {
				snifferClientStop(snifferClientNextServices[i]);
			}
			delete [] snifferClientNextServices;
			snifferClientNextServices = NULL;
		}
		if(snifferClientService_charts_cache) {
			snifferClientStop(snifferClientService_charts_cache);
			snifferClientService_charts_cache = NULL;
		}
	}
}

void *scanpcapdir( void */*dummy*/ ) {
 
#ifndef FREEBSD
 
	while(!pcapQueueInterface && !is_terminating()) {
		USLEEP(100000);
	}
	if(is_terminating()) {
		return(NULL);
	}
	sleep(1);
	
	char filename[4096];
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
				USLEEP(10000);
				continue;
			}
		}
		// grab the next file in line to be processed
		strcpy_null_term(filename, fileList.front().c_str());
		fileList.pop();

		//printf("File [%s]\n", filename);
		if(!file_exists(filename)) {
			continue;
		}
		
		if(verbosity > 1 || sverb.scanpcapdir) {
			syslog(LOG_NOTICE, "scanpcapdir: %s", filename);
		}
		
		string tempFileName;
		if(!pcapQueueInterface->openPcap(filename, &tempFileName)) {
			continue;
		}
		while(!is_terminating() && !pcapQueueInterface->isPcapEnd()) {
			USLEEP(10000);
		}
		
		if(!tempFileName.empty()) {
			unlink(tempFileName.c_str());
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

string daemonizeErrorTempFileName;
pthread_mutex_t daemonizeErrorTempFileLock;

static void daemonize(void)
{
 
	curl_global_cleanup();
	
	daemonizeErrorTempFileName = tmpnam();
	if (daemonizeErrorTempFileName.empty()) {
		syslog(LOG_ERR, "Can't get tmp filename in daemonize.");
		exit(1);
	}
	pthread_mutex_init(&daemonizeErrorTempFileLock, NULL);
 
	pid_t pid;

	pid = fork();
	if (pid) {
		// parent
		sleep(5);
		FILE *daemonizeErrorFile = fopen(daemonizeErrorTempFileName.c_str(), "r");
		if(daemonizeErrorFile) {
			char buff[1024];
			while(fgets(buff, sizeof(buff), daemonizeErrorFile)) {
				cout << buff;
			}
			unlink(daemonizeErrorTempFileName.c_str());
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
		mode_t oldmask = umask(S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		f = fopen(opt_pidfile, "w");
		umask(oldmask);
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
		
		curl_global_init(CURL_GLOBAL_ALL);
	}
}

void daemonizeOutput(string error) {
	pthread_mutex_lock(&daemonizeErrorTempFileLock);
	ofstream daemonizeErrorStream(daemonizeErrorTempFileName.c_str(), ofstream::out | ofstream::app);
	daemonizeErrorStream << error << endl;
	daemonizeErrorStream.close();
	pthread_mutex_unlock(&daemonizeErrorTempFileLock);
}

void reload_config(const char *jsonConfig) {
	CONFIG.clearToDefaultValues();
	if(configfile[0]) {
		CONFIG.loadFromConfigFileOrDirectory(configfile[0] == '/' ? configfile : (rundir + '/' + configfile).c_str());
		CONFIG.loadFromConfigFileOrDirectory("/etc/voipmonitor/conf.d/");
	}
	if(!opt_nocdr && isSqlDriver("mysql") && opt_mysqlloadconfig) {
		CONFIG.setFromMysql();
	}
	if(jsonConfig) {
		CONFIG.setFromJson(jsonConfig);
	}
	get_command_line_arguments();
	set_default_values();
	set_context_config();
	create_spool_dirs();
	reload_capture_rules();
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

void reload_capture_rules() {
	cFilters::prepareReload();
}

#ifdef BACKTRACE
void bt_sighandler(int sig, siginfo_t */*info*/, void *secret)
{
	call_bt_sighandler_at = getTimeMS_rdtsc();
	void *crash_pnt = NULL;
	if(secret) {
		#if defined(__x86_64__)
			ucontext_t* uc = (ucontext_t*) secret;
			crash_pnt = (void*) uc->uc_mcontext.gregs[REG_RIP] ;
		#elif defined(__hppa__)
			ucontext_t* uc = (ucontext_t*) secret;
			crash_pnt = (void*) uc->uc_mcontext.sc_iaoq[0] & ~0x3UL ;
		#elif (defined (__ppc__)) || (defined (__powerpc__))
			ucontext_t* uc = (ucontext_t*) secret;
			crash_pnt = (void*) uc->uc_mcontext.regs->nip ;
		#elif defined(__sparc__)
		struct sigcontext* sc = (struct sigcontext*) secret;
			#if __WORDSIZE == 64
				crash_pnt = (void*) scp->sigc_regs.tpc ;
			#else  
				crash_pnt = (void*) scp->si_regs.pc ;
			#endif
		#elif defined(__i386__)
			ucontext_t* uc = (ucontext_t*) secret;
			crash_pnt = (void*) uc->uc_mcontext.gregs[REG_EIP] ;
		#endif
	}
	void *trace[16];
	char **messages;
	int trace_size = backtrace(trace, 16);
	messages = backtrace_symbols(trace, trace_size);
	unlink(opt_crash_bt_filename);
	int fh = open(opt_crash_bt_filename, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if(fh > 0) {
	        write(fh, RTPSENSOR_VERSION, strlen(RTPSENSOR_VERSION));
		write(fh, " sensor ", 8);
		write(fh, opt_id_sensor_str, strlen(opt_id_sensor_str));
		write(fh, " ", 1);
		#if defined(__arm__)
			write(fh, "arm", 3);
		#else
			if(sizeof(int *) == 8) {
				extern int opt_enable_ss7;
				if(opt_enable_ss7) {
					write(fh, "x86_64_ws", 9);
				} else {
					write(fh, "x86_64", 6);
				}
			} else {
				write(fh, "i686", 4);
			}
		#endif
		write(fh, " ", 1);
		if(ownPidFork) {
			write(fh, ownPidFork_str, strlen(ownPidFork_str));
		} else {
			write(fh, ownPidStart_str, strlen(ownPidStart_str));
		}
		extern bool notEnoughFreeMemory;
		if(notEnoughFreeMemory || terminating) {
			write(fh, " ", 1);
			unsigned counterFlags = 0;
			if(notEnoughFreeMemory) {
				write(fh, "nefm", 4);
				++counterFlags;
			}
			if(terminating) {
				if(counterFlags) {
					write(fh, ",", 1);
				}
				write(fh, "term", 4);
				++counterFlags;
			}
		}
		write(fh, "\n", 1);
		if(crash_pnt) {
			write(fh, "[--] [0x", 8);
			for(unsigned i = sizeof(crash_pnt); i > 0; i--) {
				char ch = *((char*)&crash_pnt + (i - 1));
				if(ch) {
					char ch1 = (ch >> 4) & 0xF;
					char ch2 = (ch & 0xF);
					ch1 = ch1 + (ch1 < 10 ? '0' : ('a' - 10));
					ch2 = ch2 + (ch2 < 10 ? '0' : ('a' - 10));
					write(fh, &ch1, 1);
					write(fh, &ch2, 1);
				}
			}
			write(fh, "]\n", 2);
		}
		for (int i = 1; i < trace_size; ++i) {
			write(fh, "[bt] ", 5);
			write(fh, messages[i], strlen(messages[i]));
			write(fh, "\n", 1);
		}
		if(rrd_last_cmd_global) {
			write(fh, "\n[--] rrd string : ", 19);
			write(fh, rrd_last_cmd_global, strlen(rrd_last_cmd_global));
			write(fh, "\n", 1);
		}
		close(fh);
	}
	semaphoreUnlink();
	semaphoreClose();
	signal(sig, SIG_DFL);
	kill(getpid(), sig);
}
#endif

void store_crash_bt_to_db() {
	if(!opt_nocdr && file_exists(opt_crash_bt_filename)) {
		FILE *crash_bt_fh = fopen(opt_crash_bt_filename, "r");
		if(!crash_bt_fh) {
			return;
		}
		char rowbuff[1000];
		int countRows = 0;
		char version[20];
		int sensor_id;
		char arch[20];
		int pid;
		char flags_str[100] = "";
		vector<string> flags;
		bool header_ok = false;
		vector<string> bt;
		vector<string> bt_gdb;
		while(fgets(rowbuff, sizeof(rowbuff), crash_bt_fh)) {
			if(!countRows) {
				if(sscanf(rowbuff, "%s sensor %i %s %i %s", version, &sensor_id, arch, &pid, flags_str) >= 4) {
					header_ok = true;
					if(flags_str[0]) {
						flags = split(flags_str, ',');
					}
				}
			} else if(!strncmp(rowbuff, "[bt]", 4) ||
				  !strncmp(rowbuff, "[--]", 4)) {
				char *lf = strchr(rowbuff, '\n');
				if(lf) {
					*lf = 0;
				}
				bt.push_back(rowbuff);
			}
			++countRows;
		}
		fclose(crash_bt_fh);
		if(header_ok && bt.size()) {
			bool version_ok = false;
			string tmpOut = tmpnam();
			if(!tmpOut.empty()) {
				system((binaryNameWithPath + " | grep version > " + tmpOut + " 2>/dev/null").c_str());
				vector<string> version_check_rows;
				char version_check[20];
				if(file_get_rows(tmpOut, &version_check_rows) &&
				   sscanf(version_check_rows[0].c_str(), "voipmonitor version %s", version_check) == 1 &&
				   !strcmp(version, version_check)) {
					version_ok = true;
				}
				if(version_ok) {
					system((string("which addr2line > ") + tmpOut + " 2>/dev/null").c_str());
					vector<string> addr2line_check_rows;
					if(file_get_rows(tmpOut, &addr2line_check_rows)) {
						for(unsigned i = 0; i < bt.size(); i++) {
							bool addr2line_ok = false;
							for(unsigned pass = 0; pass < 2 && !addr2line_ok; pass++) {
								if(pass == 0 && bt[i].find(appname) == string::npos) {
									continue;
								}
								size_t posAddr = bt[i].find(pass == 0 ? "(+0x" : "[0x");
								if(posAddr != string::npos) {
									size_t posAddrEnd = bt[i].find(pass == 0 ? ")" : "]", posAddr);
									if(posAddrEnd != string::npos) {
										string addr = bt[i].substr(posAddr + (pass == 0 ? 2 : 1), posAddrEnd - posAddr - (pass == 0 ? 2 : 1));
										system(("addr2line -e " + binaryNameWithPath + " " + addr + " > " + tmpOut + " 2>/dev/null").c_str());
										vector<string> addr2line_rows;
										if(file_get_rows(tmpOut, &addr2line_rows) &&
										   addr2line_rows[0].find("??") == string::npos) {
											bt[i] += " " + addr2line_rows[0];
											addr2line_ok = true;
										}
									}
								}
							}
						}
					} else {
						flags.push_back("missing_addr2line");
					}
					system((string("which gdb > ") + tmpOut + " 2>/dev/null").c_str());
					vector<string> gdb_check_rows;
					if(file_get_rows(tmpOut, &gdb_check_rows)) {
						vector<string> coredumps = findCoredumps(pid);
						bool pid_ok = false;
						for(unsigned i = 0; i < coredumps.size(); i++) {
							string coredump = coredumps[i];
							unlink(tmpOut.c_str());
							system(string(
							       "echo -e '"
							       "set print elements 1000\n"
							       "set print pretty on\n"
							       "set pagination off\n"
							       "set logging file " + string(tmpOut) + "\n"
							       "set logging on\n"
							       "p \"*** PID ***\"\np ownPidFork?ownPidFork:ownPidStart\n"
							       "p \"*** BT ***\"\nbt full\n"
							       "p \"*** INFO THREADS\"\ninfo threads\n"
							       "p \"*** VARIABLES ***\"\n"
							       "p \"terminating\"\np terminating\n"
							       "p \"cSslDsslSession::errorCallback\"\np cSslDsslSession::errorCallback\n"
							       "p \"*sess\"\np *sess\n"
							       "frame 1\n"
							       "p \"*sess\"\np *sess\n"
							       "p \"*** ALL THREADS BT ***\"\nthread apply all bt full\n"
							       "quit\n"
							       "' | gdb " + binaryNameWithPath + " " + coredump + " 2>&1 >/dev/null"
							       ).c_str());
							FILE *gdbOutput = fopen(tmpOut.c_str(), "r");
							if(gdbOutput) {
								char buff[10000];
								unsigned counter = 0;
								while(fgets(buff, sizeof(buff), gdbOutput)) {
									if(counter < 2) {
										if(strstr(buff, intToString(pid).c_str())) {
											pid_ok = true;
										}
									} else if(!pid_ok) {
										bt_gdb.clear();
										break;
									}
									bt_gdb.push_back(buff);
									++counter;
								}
								fclose(gdbOutput);
								if(pid_ok) {
									break;
								}
							}
						}
					} else {
						flags.push_back("missing_gdb");
					}
				}
			}
			unlink(tmpOut.c_str());
			string crash_bt_content;
			crash_bt_content = 
				string("voipmonitor version: ") + version + "\n" +
				"sensor_id: " + intToString(sensor_id) + "\n" +
				"arch: " + arch + "\n\n";
			if(flags.size()) {
				crash_bt_content += "flags:\n";
				for(unsigned i = 0; i < flags.size(); i++) {
					if(flags[i] == "nefm") {
						crash_bt_content += "not enough free memory\n";
						cLogSensor::log(cLogSensor::error, "The previous sniffer run was terminated due to insufficient allocable RAM.");
					} else if(flags[i] == "term") {
						crash_bt_content += "terminating\n";
					} else if(flags[i] == "missing_addr2line") {
						crash_bt_content += "missing addr2line\n";
					} else if(flags[i] == "missing_gdb") {
						crash_bt_content += "missing gdb\n";
					}
				}
				crash_bt_content += "\n";
			}
			for(unsigned i = 0; i < bt.size(); i++) {
				crash_bt_content += bt[i] + "\n";
			}
			if(bt_gdb.size()) {
				crash_bt_content += "\n";
				for(unsigned i = 0; i < bt_gdb.size(); i++) {
					crash_bt_content += bt_gdb[i];
				}
			}
			if(crash_bt_content.length()) {
				SqlDb *sqlDb = createSqlObject();
				if(!sqlDb->existsTable("crash_bt")) {
					sqlDb->query(
						"CREATE TABLE IF NOT EXISTS `crash_bt` (\
								`id` int NOT NULL AUTO_INCREMENT,\
								`created_at` datetime,\
								`sent_at` datetime,\
								`crash_bt` mediumblob,\
							PRIMARY KEY (`id`)\
						) ENGINE=InnoDB DEFAULT CHARSET=latin1;");
				} else {
					if(sqlDb->getTypeColumn("crash_bt", "crash_bt") == "blob") {
						sqlDb->query("ALTER TABLE crash_bt MODIFY COLUMN crash_bt mediumblob");
					}
				}
				SqlDb_row row;
				row.add(sqlDateTimeString(GetFileCreateTime(opt_crash_bt_filename)), "created_at");
				row.add(sqlEscapeString(crash_bt_content), "crash_bt");
				sqlDb->insert("crash_bt", row);
				delete sqlDb;
			}
		}
		unlink(opt_crash_bt_filename);
	}
}

void *store_crash_bt_to_db_thread_fce(void *) {
	store_crash_bt_to_db();
	return(NULL);
}

void resetTerminating() {
	clear_terminating();
	clear_readend();
	terminating_moving_cache = 0;
	terminating_storing_cdr = 0;
	terminating_storing_registers = 0;
	terminated_call_cleanup = 0;
	terminating_charts_cache = 0;
	terminated_async = 0;
	for(int i = 0; i < 2; i++) {
		terminated_tar_flush_queue[i] = 0;
		terminated_tar[i] = 0;
	}
}


void test();

PcapQueue_readFromFifo *pcapQueueR;
PcapQueue_readFromInterface *pcapQueueI;
PcapQueue_readFromFifo *pcapQueueQ;
PcapQueue_outputThread *pcapQueueQ_outThread_detach;
PcapQueue_outputThread *pcapQueueQ_outThread_defrag;
PcapQueue_outputThread *pcapQueueQ_outThread_dedup;
PcapQueue_outputThread *pcapQueueQ_outThread_detach2;

void set_global_vars();
int main_init_read();
void main_term_read();
void main_init_sqlstore();

bool is_set_gui_params() {
	return(opt_untar_gui_params ||
	       opt_unlzo_gui_params || 
	       opt_waveform_gui_params ||
	       opt_spectrogram_gui_params ||
	       opt_audioconvert_params ||
	       opt_audio_transcribe_params ||
	       opt_rtp_stream_analysis_params ||
	       opt_check_regexp_gui_params ||
	       opt_test_regexp_gui_params ||
	       opt_read_pcap_gui_params ||
	       opt_cmp_config_params ||
	       opt_revaluation_params ||
	       opt_reassign_countries_params ||
	       is_gui_param);
}


#if SEPARATE_HEAP_FOR_HUGETABLE

class cHeap_VM_HP : public cHeap {
public:
	cHeap_VM_HP();
	bool setActive();
protected:
	void *initHeapBuffer(u_int32_t *size, u_int32_t *size_reserve);
	void termHeapBuffer(void *ptr, u_int32_t size, u_int32_t size_reserve);
private:
	bool initHugepages();
private:
	int hugepage_fd;
	u_int64_t hugepage_size;
};


cHeap_VM_HP *heap_vm_hp;
bool heap_vm_hp_active;
size_t heap_vm_hp_size_call;
size_t heap_vm_hp_size_packetbuffer;


cHeap_VM_HP::cHeap_VM_HP() {
	hugepage_fd = -1;
	hugepage_size = 0;
}

bool cHeap_VM_HP::setActive() {
	if(initHugepages()) {
		return(cHeap::setActive());
	}
	return(false);
}

void *cHeap_VM_HP::initHeapBuffer(u_int32_t *size, u_int32_t *size_reserve) {
	size_t _size = 512 * 1024 * 1024;
	size_t _size_reserve = 1 * 1024 * 1024;
	size_t size_mmap;
	void *ptr = mmap_hugepage(hugepage_fd, 0, false,
				  _size + _size_reserve, &size_mmap, NULL, 
				  hugepage_size, 1,
				  false, NULL);
	if(ptr) {
		if(size_mmap > _size_reserve) {
			*size = size_mmap - _size_reserve;
			*size_reserve = _size_reserve;
		} else {
			*size = size_mmap;
			*size_reserve = 0;
		}
		return(ptr);
	}
	return(NULL);
}

void cHeap_VM_HP::termHeapBuffer(void *ptr, u_int32_t size, u_int32_t size_reserve) {
	munmap_hugepage(ptr, size + size_reserve);
}

bool cHeap_VM_HP::initHugepages() {
	return(init_hugepages(&hugepage_fd, &hugepage_size));
}

#endif //SEPARATE_HEAP_FOR_HUGETABLE


#if SEPARATE_HEAP_FOR_HASHTABLE

class cHeap_HASHTABLE : public cHeap {
public:
	cHeap_HASHTABLE(unsigned size_mb);
protected:
	void *initHeapBuffer(u_int32_t *size, u_int32_t *size_reserve);
	void termHeapBuffer(void *ptr, u_int32_t size, u_int32_t size_reserve);
private:
	unsigned size_mb;
};

cHeap *heap_hashtable;

cHeap_HASHTABLE::cHeap_HASHTABLE(unsigned size_mb) {
	this->size_mb = size_mb;
}

void *cHeap_HASHTABLE::initHeapBuffer(u_int32_t *size, u_int32_t *size_reserve) {
	size_t _size = size_mb * 1024 * 1024;
	size_t _size_reserve = 16 * 1024;
	void *ptr = calloc(1, _size + _size_reserve);
	if(ptr) {
		*size = _size;
		*size_reserve = _size_reserve;
		return(ptr);
	}
	return(NULL);
}

void cHeap_HASHTABLE::termHeapBuffer(void *ptr, u_int32_t size, u_int32_t size_reserve) {
	free(ptr);
}

#if HAVE_LIBJEMALLOC

unsigned arena_index_hashtable;

#endif //HAVE_LIBJEMALLOC

#endif //SEPARATE_HEAP_FOR_HASHTABLE


int main(int argc, char *argv[]) {
	extern unsigned int HeapSafeCheck;
	extern unsigned int MemoryStatQuick;
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
		} else if(strstr(argv[i], "heapfillff")) {
			HeapSafeCheck = _HeapSafeErrorFillFF;
		} else if(strstr(argv[i], "heapfillrand")) {
			HeapSafeCheck = _HeapSafeErrorFillRand;
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
	}
	if(memoryStatInArg) {
		if((HeapSafeCheck & _HeapSafeErrorBeginEnd)) {
			if(memoryStatExInArg) {
				HeapSafeCheck |= _HeapSafeStack;
			}
		} else {
			MemoryStatQuick = true;
		}
		sverb.memory_stat = true;
		memoryStatInit();
	}
	
	for(int i = 0; i < argc; i++) {
		if(i) {
			cmdline += ' ';
		}
		bool space = strchr(argv[i], ' ');
		bool apostrophe = strchr(argv[i], '\'');
		if(space || apostrophe) {
			cmdline += '\'';
		}
		char *parg = argv[i];
		while(*parg) {
			if(*parg == '\'') {
				cmdline += "'\\''";
			} else {
				cmdline += *parg;
			}
			++parg;
		}
		if(space || apostrophe) {
			cmdline += '\'';
		}
	}

	char exebuff[PATH_MAX];
	ssize_t exelen = ::readlink("/proc/self/exe", exebuff, sizeof(exebuff)-1);
	if (exelen != -1) {
		exebuff[exelen] = '\0';
		binaryNameWithPath = std::string(exebuff);
	} else {
		binaryNameWithPath = "/usr/local/sbin/voipmonitor";
	}
	size_t last_separator = binaryNameWithPath.rfind('/');
	if(last_separator != string::npos) {
		binaryPath = binaryNameWithPath.substr(0, last_separator);
	}
	
	char _rundir[256];
	getcwd(_rundir, sizeof(_rundir));
	rundir = _rundir;
	
	char *_appname = strrchr(argv[0], '/');
	if(!_appname) {
		_appname = argv[0];
	}
	while(*_appname == '.' || *_appname == '/') {
		++_appname;
	}
	appname = _appname;
	
	fillEscTables();
	set_global_vars();

	if(file_exists("/etc/localtime")) {
		setenv("TZ", "/etc/localtime", 1);
	}
 
	time(&startTime);

	regfailedcache = new FILE_LINE(42005) regcache;

	base64_init();
	crc64_init();

/*
	if(mysql_library_init(0, NULL, NULL)) {
		fprintf(stderr, "could not initialize MySQL library\n");
		exit(1);
	}
*/

	pcapstat.ps_drop = 0;
	pcapstat.ps_ifdrop = 0;

	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT,sigint_handler);
	signal(SIGTERM,sigterm_handler);
	signal(SIGCHLD,sigchld_handler);

	/* parse arguments */

	ifname[0] = '\0';
	opt_mirrorip_src[0] = '\0';
	opt_mirrorip_dst[0] = '\0';
	strcpy(opt_spooldir_main, "/var/spool/voipmonitor");
	strcpy(opt_cachedir, "");
	sipportmatrix = new FILE_LINE(42006) char[65537];
	memset(sipportmatrix, 0, 65537);
	httpportmatrix = new FILE_LINE(42007) char[65537];
	memset(httpportmatrix, 0, 65537);
	webrtcportmatrix = new FILE_LINE(42008) char[65537];
	memset(webrtcportmatrix, 0, 65537);
	skinnyportmatrix = new FILE_LINE(0) char[65537];
	memset(skinnyportmatrix, 0, 65537);
	ipaccountportmatrix = new FILE_LINE(42017) char[65537];
	memset(ipaccountportmatrix, 0, 65537);
	ss7portmatrix = new FILE_LINE(0) char[65537];
	memset(ss7portmatrix, 0, 65537);
	ss7_rudp_portmatrix = new FILE_LINE(0) char[65537];
	memset(ss7_rudp_portmatrix, 0, 65537);
	diameter_tcp_portmatrix = new FILE_LINE(0) char[65537];
	memset(diameter_tcp_portmatrix, 0, 65537);
	diameter_udp_portmatrix = new FILE_LINE(0) char[65537];
	memset(diameter_udp_portmatrix, 0, 65537);
	ssl_portmatrix = new FILE_LINE(0) char[65537];
	memset(ssl_portmatrix, 0, 65537);
	ssl_client_random_portmatrix = new FILE_LINE(0) char[65537];
	memset(ssl_client_random_portmatrix, 0, 65537);
	mgcp_gateway_tcp_portmatrix = new FILE_LINE(0) char[65537];
	memset(mgcp_gateway_tcp_portmatrix, 0, 65537);
	mgcp_gateway_udp_portmatrix = new FILE_LINE(0) char[65537];
	memset(mgcp_gateway_udp_portmatrix, 0, 65537);
	mgcp_callagent_tcp_portmatrix = new FILE_LINE(0) char[65537];
	memset(mgcp_callagent_tcp_portmatrix, 0, 65537);
	mgcp_callagent_udp_portmatrix = new FILE_LINE(0) char[65537];
	memset(mgcp_callagent_udp_portmatrix, 0, 65537);

	pthread_mutex_init(&mysqlconnect_lock, NULL);
	pthread_mutex_init(&hostbyname_lock, NULL);
	pthread_mutex_init(&terminate_packetbuffer_lock, NULL);
	pthread_mutex_init(&commmand_type_counter_sync, NULL);

	set_mac();

	umask(0000);

	openlog(appname.c_str(), LOG_CONS | LOG_PERROR | LOG_PID, LOG_DAEMON);

	/*
	string args;
	for(int i = 0; i < argc; i++) {
		args += string(argv[i]) + " ";
	}
	syslog(LOG_NOTICE, args.c_str());
	*/
	
	parse_command_line_arguments(argc, argv);
	get_command_line_arguments();
	
	if(!is_read_from_file() && opt_fork && !is_set_gui_params()) {
#ifndef FREEBSD
		rightPSversion = isPSrightVersion();
		if (!rightPSversion) {
			syslog(LOG_NOTICE, "Incompatible ps binary version (e.g. busybox). Please install correct version. Disabling watchdog option now.");
		}
#endif
		bashPresent = isBashPresent();
		if (!bashPresent) {
			syslog(LOG_NOTICE, "Missing bash binary. Please install. Disabling watchdog option now.");
		}
	}
	
	if(configfile[0]) {
		char *_configfilename = strrchr(configfile, '/');
		if(!_configfilename) {
			_configfilename = configfile;
		}
		while(*_configfilename == '.' || *_configfilename == '/') {
			++_configfilename;
		}
		configfilename = _configfilename;
	}
	
	cConfigMap configMap;
	CONFIG.loadConfigMapConfigFileOrDirectory(&configMap, configfile);
	CONFIG.loadConfigMapConfigFileOrDirectory(&configMap, "/etc/voipmonitor/conf.d/");
	
	#if VM_IPV6
	if(configMap.getFirstItem("ipv6", true) == "yes") {
		useIPv6 = true;
	}
	#endif
	
	if(opt_fork &&
	   configMap.getFirstItem("semaphore-lock", true) == "yes") {
		useSemaphoreLock = true;
	}
	
	ownPidStart = getpid();
	strcpy(ownPidStart_str, intToString(ownPidStart).c_str());
	
	if(opt_fork && !is_read_from_file() && configfile[0] && !is_set_gui_params()) {
		bool _existsAnotherInstance = false;
		if(useSemaphoreLock) {
			for(unsigned pass = 0; pass < 2; pass++) {
				semaphoreLock[0] = sem_open(semaphoreLockName(0), O_CREAT | O_EXCL, 0644, getpid());
				if(semaphoreLock[0] == SEM_FAILED) {
					if(errno == EEXIST) {
						if(pass == 0) {
							int semPid = 0;
							sem_t *sem = sem_open(semaphoreLockName(1), O_RDONLY);
							if(sem != SEM_FAILED) {
								sem_getvalue(sem, &semPid);
								sem_close(sem);
							}
							if((semPid && existsPidProcess(semPid)) || existsAnotherInstance()) {
								_existsAnotherInstance = true;
								break;
							} else {
								semaphoreUnlink();
								semaphoreClose();
							}
						} else {
							_existsAnotherInstance = true;
						}
					} else {
						syslog(LOG_ERR, "sem_open failed: %s", strerror(errno));
						return(1);
					}
				} else {
					break;
				}
			}
		} else {
			_existsAnotherInstance = existsAnotherInstance();
		}
		if(_existsAnotherInstance) {
			syslog(LOG_ERR, "%s", anotherInstanceMessage);
			semaphoreClose();
			return(1);
		}
	}
	
	CONFIG.addConfigItems();
	CONFIG.clearToDefaultValues();
	list<cConfig::sDiffValue> diffValuesMysqlLoadConfig;
	if(configfile[0]) {
		CONFIG.loadFromConfigFileOrDirectory(configfile);
		CONFIG.loadFromConfigFileOrDirectory("/etc/voipmonitor/conf.d/");
		if(!useCmdLineConfig && sverb.check_config) {
			cConfigMap configMap1 = CONFIG.getConfigMap();
			cConfigMap configMap2;
			CONFIG.loadConfigMapConfigFileOrDirectory(&configMap2, configfile);
			CONFIG.loadConfigMapConfigFileOrDirectory(&configMap2, "/etc/voipmonitor/conf.d/");
			string diffConfigStr = configMap1.comp(&configMap2, &CONFIG);
			if(!diffConfigStr.empty()) {
				vector<string> diff = split(diffConfigStr.c_str(), "\n");
				for(size_t i = 0; i < diff.size(); i++) {
					syslog(LOG_WARNING, "MISMATCH CONFIGURATION PARAMETER : %s", diff[i].c_str());
				}
			}
		}
		if(!opt_nocdr && !is_set_gui_params() && 
		   !printConfigStruct && !printConfigFile &&
		   isSqlDriver("mysql") && opt_mysqlloadconfig) {
			get_command_line_arguments_mysql();
			get_command_line_arguments_json_config();
			CONFIG.beginTrackDiffValues();
			CONFIG.setFromMysql(true);
			CONFIG.endTrackDiffValues(&diffValuesMysqlLoadConfig);
		}
	}
	get_command_line_arguments();

	if(is_read_from_file_simple()) {
		if(is_client()) {
			if(!is_load_pcap_via_client(opt_sensor_string)) {
				puts("Client mode does not support reading from a file.\n");
				return(0);
			}
		} else if(is_sender()) {
			puts("Mirror sender mode does not support reading from a file.\n");
			return(0);
		}
	}
	
	if(updateSchema) {
		SipHistorySetting();
		return(SqlInitSchema() > 0 ? 0 : 1);
	}

	set_default_values();
	set_context_config();
	create_spool_dirs();

	if(!check_complete_parameters()) {
		return 1;
	}
	
	final_parameters();
	
	runAt = time(NULL);
	if(!is_read_from_file() && !is_set_gui_params() && command_line_data.size()) {
		printf("voipmonitor version %s\n", getVersionWithBuild().c_str());
		string localActTime = sqlDateTimeString(runAt);
		printf("local time %s\n", localActTime.c_str());
		syslog(LOG_NOTICE, "local time %s", localActTime.c_str());
#ifndef FREEBSD
		if(opt_ifaces_optimize && !sverb.suppress_fork) {
			handleInterfaceOptions();
		}
#endif
	}
	
	check_context_config();

	if(HeapSafeCheck) {
		#if not HEAPSAFE
		syslog(LOG_ERR, "%s", "HEAPSAFE UNSUPPORTED!");
		#endif
	}
	
	if (opt_sipoverlap && opt_last_dest_number) {
		syslog(LOG_NOTICE, "You enabled last_dest_number and sipoverlap options. last_dest_number option takes precedence.");
	}

	if(opt_untar_gui_params) {
		vmChdir();
		int rslt = untar_gui(opt_untar_gui_params);
		delete [] opt_untar_gui_params;
		return(rslt);
	}
	if(opt_unlzo_gui_params) {
		vmChdir();
		int rslt = unlzo_gui(opt_unlzo_gui_params);
		delete [] opt_unlzo_gui_params;
		return(rslt);
	}
	if(opt_waveform_gui_params) {
		vmChdir();
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
		vmChdir();
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
						    outputSpectrogramPng,
						    0));
	}
	if(opt_audioconvert_params) {
		vmChdir();
		if(!strncmp(opt_audioconvert_params, "info", 4) && strlen(opt_audioconvert_params) > 5) {
			cAudioConvert info;
			info.fileName = opt_audioconvert_params + 5;
			if(info.getAudioInfo() == cAudioConvert::_rslt_ok) {
				cout << "audio-info: " << info.jsonAudioInfo() <<  endl;
				return(0);
			} else {
				cerr << "audio-convert: get info failed" << endl;
				return(1);
			}
		} else {
			char inputFileName[1024];
			char outputFormat[10];
			char outputFileName[1024];
			int sampleRate = 0;
			int channels = 0;
			int bitsPerSample = 0;
			if(sscanf(opt_audioconvert_params, "%s %s %s %i %i %i", 
				  inputFileName, outputFormat, outputFileName,
				  &sampleRate, &channels, &bitsPerSample) < 3) {
				cerr << "audio-convert: bad arguments" << endl;
				return(1);
			}
			#if not (HAVE_LIBLAME && HAVE_LIBLAME)
			if(!strcmp(outputFormat, "mp3")) {
				cerr << "audio-convert: mp3 support requires building with lame and mpg123 libraries" << endl;
				return(1);
			}
			#endif
			delete [] opt_audioconvert_params;
			cAudioConvert info;
			info.fileName = inputFileName;
			if(info.getAudioInfo() == cAudioConvert::_rslt_ok ||
			   (sampleRate && channels && bitsPerSample)) {
				cAudioConvert src;
				src.fileName = inputFileName;
				cAudioConvert dst;
				dst.formatType = !strcmp(outputFormat, "wav") ? cAudioConvert::_format_wav :
						 !strcmp(outputFormat, "ogg") ? cAudioConvert::_format_ogg :
						 #if HAVE_LIBLAME && HAVE_LIBLAME
						 !strcmp(outputFormat, "mp3") ? cAudioConvert::_format_mp3 :
						 #endif
										cAudioConvert::_format_raw;
				dst.srcDstType = cAudioConvert::_dst;
				dst.fileName = outputFileName;
				src.destAudio = &dst;
				cAudioConvert::eResult rslt;
				if(info.formatType == cAudioConvert::_format_wav) {
					rslt = src.readWav();
				} else if(info.formatType == cAudioConvert::_format_ogg) {
					rslt = src.readOgg();
				#if HAVE_LIBLAME && HAVE_LIBLAME
				} else if(info.formatType == cAudioConvert::_format_mp3) {
					rslt = src.readMp3();
				#endif
				} else {
					cAudioConvert::sAudioInfo audioInfo;
					audioInfo.sampleRate = sampleRate;
					audioInfo.channels = channels;
					audioInfo.bitsPerSample = bitsPerSample;
					rslt = src.readRaw(&audioInfo);
				}
				if(rslt == cAudioConvert::_rslt_ok) {
					cout << "convert ok" << endl;
					return(0);
				} else {
					cerr << "audio-convert: convert failed" << endl;
					return(1);
				}
			} else {
				cerr << "audio-convert: get info failed" << endl;
				return(1);			 
			}
			return(1);
		}
		cerr << "audio-convert: unknown request" << endl;
		return(1);
	}
	if(opt_audio_transcribe_params) {
		char wavFileName[1024];
		char jsonParams[1024];
		if(sscanf(opt_audio_transcribe_params, "%s %[^\n]", 
			  wavFileName, jsonParams) < 2) {
			cerr << "audio-transcribe: bad arguments" << endl;
			return(1);
		}
		Transcribe::initNativeLib();
		Transcribe *transcribe = new FILE_LINE(0) Transcribe();
		string error;
		transcribe->transcribeWav(wavFileName, jsonParams, true, NULL, NULL);
		delete transcribe;
		return(0);
	}
	if(opt_rtp_stream_analysis_params) {
		char pcapFileName[1024];
		if(sscanf(opt_rtp_stream_analysis_params, "%s", 
			  pcapFileName) < 1) {
			cerr << "rtp-stream-analysis: bad arguments" << endl;
			return(1);
		}
		alaw_init();
		ulaw_init();
		extern int rtp_stream_analysis(const char *pcap, bool onlyRtp);
		useIPv6 = true;
		opt_nocdr = true;
		opt_jitterbuffer_f1 = 1;
		opt_jitterbuffer_f2 = 1;
		opt_jitterbuffer_adapt = 1;
		opt_silencedetect = 1;
		opt_saveSIP = 0;
		opt_saveRTP = 0;
		opt_saveGRAPH = 0;
		opt_saveRAW = 0;
		opt_saveWAV = 0;
		opt_save_audiograph = 0;
		sverb.process_rtp_header = 1;
		for(int i = (opt_t2_boost_direct_rtp ? PreProcessPacket::ppt_detach_x : PreProcessPacket::ppt_detach); i < PreProcessPacket::ppt_end_base; i++) {
			preProcessPacket[i] = new FILE_LINE(0) PreProcessPacket((PreProcessPacket::eTypePreProcessThread)i);
		}
		_parse_packet_global_process_packet.setStdParse();
		calltable = new FILE_LINE(0) Calltable();
		return(rtp_stream_analysis(pcapFileName, false));
	}
	if(opt_check_regexp_gui_params) {
		bool okRegExp = check_regexp(opt_check_regexp_gui_params);
		cout << (okRegExp ? "ok" : "failed") << endl;
		return(okRegExp ? 0 : 1);
	}
	if(opt_test_regexp_gui_params) {
		vector<string> regexp_params = split(opt_test_regexp_gui_params, opt_test_regexp_gui_params[strlen(opt_test_regexp_gui_params)-1]);
		if(regexp_params.size() == 2) {
			if(check_regexp(regexp_params[0].c_str())) {
				vector<string> matches;
				int rslt = reg_match(regexp_params[1].c_str(), regexp_params[0].c_str(), &matches, false);
				cout << "rslt " << rslt << endl;
				for(unsigned i = 0; i < matches.size(); i++) {
					cout << "match " << (i+1) << " " << matches[i] << endl;
				}
				return(rslt);
			} else {
				cout << "bad regexp" << endl;
				return(-1);
			}
		} else {
			cout << "bad parameters" << endl;
			return(-2);
		}
	}
	if(opt_read_pcap_gui_params) {
		read_pcap(opt_read_pcap_gui_params);
		return(0);
	}
	if(opt_cmp_config_params) {
		cout << endl 
		     << "(cmp)" << opt_cmp_config_params << endl 
		     << "(cmp)" << configfile << endl
		     << endl;
		cConfig defaultConfig;
		defaultConfig.addConfigItems();
		cConfigMap configMap1 = CONFIG.getConfigMap();
		cConfigMap configMap2;
		CONFIG.loadConfigMapConfigFileOrDirectory(&configMap2, opt_cmp_config_params);
		string diffConfigStr = configMap2.comp(&configMap1, &CONFIG, &defaultConfig);
		if(!diffConfigStr.empty()) {
			vector<string> diff = split(diffConfigStr.c_str(), "\n");
			for(size_t i = 0; i < diff.size(); i++) {
				cout << diff[i].c_str() << endl;
			}
			cout << endl;
		}
		return(0);
	}
	if(opt_revaluation_params) {
		revaluationBilling(opt_revaluation_params);
		return(0);
	}
	if(opt_reassign_countries_params) {
		reassignCountries(opt_reassign_countries_params);
		return(0);
	}
	if(opt_process_pcap_fname[0]) {
		process_pcap(opt_process_pcap_fname, opt_pcap_destination, opt_process_pcap_type);
		return(0);
	}
	
	if(printConfigStruct) {
		cout << "configuration: ";
		cout << CONFIG.getJson();
		cout << endl;
		return(0);
	}
	if(printConfigFile) {
		cout << "configuration: ";
		cout << CONFIG.getContentConfig(true, printConfigFile_default);
		cout << endl;
		return(0);
	}

#ifdef BACKTRACE
	if(opt_bt_sighandler_enable && (opt_fork || sverb.enable_bt_sighandler) && !is_read_from_file() && !is_set_gui_params()) {
		struct sigaction sa;

		sa.sa_sigaction = bt_sighandler;
		sigemptyset (&sa.sa_mask);
		sa.sa_flags = SA_RESTART | SA_SIGINFO;

		sigaction(SIGSEGV, &sa, NULL);
		sigaction(SIGBUS, &sa, NULL);
		sigaction(SIGILL, &sa, NULL);
		sigaction(SIGFPE, &sa, NULL);
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
 
	init_rdtsc_interval();

	thread_setup();
	// end init

	if(opt_rrd && (is_read_from_file() || sverb.suppress_fork)) {
		//disable update of rrd statistics when reading packets from file
		opt_rrd = 0;
	}

	if(!opt_test) {
		snifferServerInit();
		rrd_init();
		if(opt_rrd) {
			checkRrdVersion();
			rrd_charts_init();
		}
		get_cpu_ht();
		get_cpu_count();
	}

	if(opt_fork && !is_read_from_file() && reloadLoopCounter == 0) {
		daemonize();
		ownPidFork = getpid();
		strcpy(ownPidFork_str, intToString(ownPidFork).c_str());
		bool _existsAnotherInstance = false;
		if(useSemaphoreLock) {
			semaphoreLock[1] = sem_open(semaphoreLockName(1), O_CREAT | O_EXCL, 0644, getpid());
			if(semaphoreLock[1] == SEM_FAILED) {
				if(errno == EEXIST) {
					_existsAnotherInstance = true;
				} else {
					syslog(LOG_ERR, "sem_open failed: %s", strerror(errno));
					return(1);
				}
			}
		}
		if(_existsAnotherInstance || existsAnotherInstance()) {
			syslog(LOG_ERR, "%s", anotherInstanceMessage);
			daemonizeOutput(anotherInstanceMessage);
			semaphoreClose();
			return(1);
		}
		atexit(exit_handler_fork_mode);
	}
	
	if(!opt_cpu_cores.empty()) {
		vector<int> cpu_cores;
		get_list_cores(opt_cpu_cores, cpu_cores);
		pthread_t main_thread = pthread_self();
		pthread_set_affinity(main_thread, &cpu_cores, NULL);
	}
	
	if(opt_use_dpdk) {
		cGlobalDpdkTools::clearThreadsAffinity();
		if(opt_dpdk_read_thread_lcore.empty() && opt_dpdk_worker_thread_lcore.empty() && opt_dpdk_worker2_thread_lcore.empty()) {
			cGlobalDpdkTools::setThreadsAffinity();
		}
	}
	
	if(!opt_coredump_filter.empty()) {
		SimpleBuffer content;
		string error;
		content.clear();
		content.add(opt_coredump_filter.c_str());
		if(!file_put_contents(("/proc/" + intToString(getpid()) + "/coredump_filter").c_str(), &content, &error)) {
			syslog(LOG_ERR, "%s", error.c_str());
		}
	}
	
	if(!opt_test && opt_rrd) {
		extern RrdCharts *rrd_charts;
		rrd_charts->startQueueThread();
	}
	
	if(opt_hugepages_anon || opt_hugepages_max || opt_hugepages_overcommit_max) {
		logBuffer = new FILE_LINE(0) cLogBuffer();
		#if HAVE_LIBTCMALLOC
		HugetlbSysAllocator_init();
		#else
		syslog(LOG_WARNING, "hugepages error: hugepages supported only with tcmalloc");
		#endif
	}
	
	if(opt_hugepages_second_heap) {
		#if SEPARATE_HEAP_FOR_HUGETABLE
		heap_vm_hp = new cHeap_VM_HP;
		if(heap_vm_hp->setActive()) {
			heap_vm_hp_active = true;
			if(opt_hugepages_second_heap == 1 || opt_hugepages_second_heap == 2) {
				heap_vm_hp_size_call = sizeof(Call);
			}
			if(opt_hugepages_second_heap == 1 || opt_hugepages_second_heap == 3) {
				heap_vm_hp_size_packetbuffer = opt_pcap_queue_block_max_size;
			}
		}
		#else
		syslog(LOG_ERR, "option hugepages_second_heap need recompile with #define SEPARATE_HEAP_FOR_HUGETABLE 1");
		#endif //SEPARATE_HEAP_FOR_HUGETABLE
	}
	
	#if SEPARATE_HEAP_FOR_HASHTABLE
		if(!is_client_packetbuffer_sender() && !is_sender()) {
			if(opt_hashtable_heap_size) {
				heap_hashtable = new cHeap_HASHTABLE(opt_hashtable_heap_size);
			} else {
				#if HAVE_LIBJEMALLOC
					size_t arena_index_hashtable_size = sizeof(arena_index_hashtable);
					mallctl("arenas.create", (void *)&arena_index_hashtable, &arena_index_hashtable_size, NULL, 0);
				#endif
			}
		}
	#else
		if(opt_hashtable_heap_size) {
			syslog(LOG_ERR, "option hashtable_heap_size need recompile with #define SEPARATE_HEAP_FOR_HASHTABLE 1");
		}
	#endif //SEPARATE_HEAP_FOR_HASHTABLE
	
	if(!is_read_from_file() && !is_set_gui_params() && command_line_data.size() && reloadLoopCounter == 0) {
		cLogSensor::log(cLogSensor::notice, "start voipmonitor", "version %s", getVersionWithBuild().c_str());
		if(diffValuesMysqlLoadConfig.size()) {
			cLogSensor *log = cLogSensor::begin(cLogSensor::notice, "Configuration values in mysql have a higher weight than the values in the text configuration file. (name : text config / mysql config).");
			for(list<cConfig::sDiffValue>::iterator iter = diffValuesMysqlLoadConfig.begin(); iter != diffValuesMysqlLoadConfig.end(); iter++) {
				cLogSensor::log(log, iter->format().c_str());
			}
			cLogSensor::end(log);
		}
	}

	if(!is_read_from_file() && opt_fork && enable_wdt && reloadLoopCounter == 0 && rightPSversion && bashPresent) {
		wdt = new FILE_LINE(0) WDT;
	}

	//cloud REGISTER has been moved to cloud_activecheck thread , if activecheck is disabled thread will end after registering and opening ssh
	if(isCloud()) {
		start_cloud_receiver();

		//Override query_cache option in /etc/voipmonitor.conf  settings while in cloud mode always on:
		if(opt_fork) {
			opt_save_query_main_to_files = true;
			opt_load_query_main_from_files = 1;
		}
	} else if(is_client()) {
		snifferClientService = snifferClientStart(&snifferClientOptions, NULL, snifferClientService);
		if(opt_next_server_connections > 0) {
			if(!snifferClientNextServices) {
				snifferClientNextServices = new FILE_LINE(0) cSnifferClientService*[opt_next_server_connections];
				for(int i = 0; i < opt_next_server_connections; i++) {
					snifferClientNextServices[i] = NULL;
				}
			}
			for(int i = 0; i < opt_next_server_connections; i++) {
				snifferClientNextServices[i] = snifferClientStart(&snifferClientOptions, 
										  ("next_service_" + intToString(i + 1)).c_str(),
										  snifferClientNextServices[i]);
			}
		}
		if(useChartsCacheOrCdrStatInStore() &&
		   snifferClientOptions_charts_cache.hosts.isSet()) {
			snifferClientService_charts_cache = snifferClientStart(&snifferClientOptions_charts_cache, NULL, snifferClientService_charts_cache);
		}
	} else if(is_server() && !is_read_from_file_simple()) {
		snifferServerStart();
	}
	
	if(opt_generator) {
		opt_generator_channels = 2;
		pthread_t *genthreads = new FILE_LINE(42009) pthread_t[opt_generator_channels];		// ID of worker storing CDR thread 
		for(int i = 0; i < opt_generator_channels; i++) {
			vm_pthread_create("generator sip/rtp",
					  &genthreads[i], NULL, gensiprtp, NULL, __FILE__, __LINE__);
		}
		syslog(LOG_ERR, "Traffic generated");
		sleep(10000);
		return 0;
	}
	
	// start manager threads
	if((opt_manager_port > 0 || !opt_manager_socket.empty() || is_client()) && !is_read_from_file_simple()) {
		init_management_functions();
		if(opt_manager_port > 0) {
			vm_pthread_create("manager server",
					  &manager_thread, NULL, manager_server, NULL, __FILE__, __LINE__);
		}
		if(!opt_manager_socket.empty()) {
			sManagerServerArgs *managerServerArgs = new FILE_LINE(0) sManagerServerArgs;
			managerServerArgs->file_socket = opt_manager_socket;
			managerServerArgs->non_block = true;
			managerServerArgs->timeout = 1;
			vm_pthread_create("manager socket server",
					  &manager_file_thread, NULL, manager_server, managerServerArgs, __FILE__, __LINE__);
		}
	}
	
	//cout << "SQL DRIVER: " << sql_driver << endl;
	if(!opt_nocdr && !is_sender() && !is_client_packetbuffer_sender() && !is_terminating()) {
		if(opt_fork) {
			while(!is_terminating()) {
				string connectErrorString;
				int rsltSqlInitSchema = SqlInitSchema(&connectErrorString);
				if(rsltSqlInitSchema > 0) {
					break;
				} else if(rsltSqlInitSchema < 0) {
					syslog(LOG_ERR, "%s", (connectErrorString + " - exit!").c_str());
					daemonizeOutput(connectErrorString + " - exit !");
					if(wdt) {
						delete wdt;
					}
					return 1;
				} else {
					syslog(LOG_ERR, "%s", (connectErrorString + " - trying again after 10s").c_str());
					for(int i = 0; i < 10 && !is_terminating(); i++) {
						sleep(1);
					}
				}
			}
		} else {
			string connectErrorString;
			if(SqlInitSchema(&connectErrorString) <= 0) {
				syslog(LOG_ERR, "%s", (connectErrorString + " - exit!").c_str());
				return 1;
			}
		}
	} else if(!configfile[0]) {
		useIPv6 = true;
	}
	
	if(!is_terminating()) {
	
		if(opt_test) {
			cFilters::loadActive();
			_parse_packet_global_process_packet.setStdParse();
			test();
			if(sqlStore) {
				delete sqlStore;
			}
			return(0);
		}
		
		if(!opt_database_backup && opt_load_query_main_from_files != 2) {
			bool storedRunningConfig = false;
			if(!opt_nocdr && !is_sender() && !is_read_from_file_simple() && !is_terminating()) {
				storeRunningConfig(true);
				storedRunningConfig= true;
			}
			pthread_t store_crash_bt_to_db_thread;
			vm_pthread_create_autodestroy("store_crash_bt_to_db",
						      &store_crash_bt_to_db_thread, NULL, store_crash_bt_to_db_thread_fce, NULL, __FILE__, __LINE__);
			main_init_sqlstore();
			int rslt_main_init_read = main_init_read();
			if(rslt_main_init_read) {
				return(rslt_main_init_read);
			}
			main_term_read();
			if(storedRunningConfig) {
				storeRunningConfig(false);
			}
		} else {
			if(opt_database_backup) {
				sqlStore = new FILE_LINE(42010) MySqlStore(mysql_host, mysql_user, mysql_password, mysql_database, opt_mysql_port, mysql_socket,
									   isCloud() ? cloud_host : NULL, cloud_token, cloud_router, &optMySsl);
				custom_headers_cdr = new FILE_LINE(42011) CustomHeaders(CustomHeaders::cdr);
				custom_headers_message = new FILE_LINE(42012) CustomHeaders(CustomHeaders::message);
				custom_headers_sip_msg = new FILE_LINE(0) CustomHeaders(CustomHeaders::sip_msg);
				vm_pthread_create("database backup",
						  &database_backup_thread, NULL, database_backup, NULL, __FILE__, __LINE__);
				pthread_join(database_backup_thread, NULL);
			} else if(opt_load_query_main_from_files == 2) {
				main_init_sqlstore();
				loadFromQFiles->loadFromQFiles_start();
				unsigned int counter = 0;
				manager_parse_command_enable();
				while(!is_terminating()) {
					sleep(1);
					if(!(++counter % 10) && verbosity) {
						string stat = loadFromQFiles->getLoadFromQFilesStat();
						syslog(LOG_NOTICE, "SQLf: [%s]", stat.c_str());
					}
				}
				manager_parse_command_disable();
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
			if(custom_headers_sip_msg) {
				delete custom_headers_sip_msg;
				custom_headers_sip_msg = NULL;
			}
			if(no_hash_message_rules) {
				delete no_hash_message_rules;
				no_hash_message_rules = NULL;
			}
		}
	
	}
	
	if(isCloud() || is_client()) {
		stop_cloud_or_client();
	} else if(is_server() && !is_read_from_file_simple()) {
		snifferServerStop();
	}
	
	bool _break = false;
	
	if(!is_read_from_file()) {
		string _terminating_error = terminating_error;
		if(!hot_restarting && _terminating_error.empty()) {
			_break = true;
		}
		if(!_terminating_error.empty()) {
			clear_terminating();
			clear_readend();
			manager_parse_command_enable();
			while(!is_terminating()) {
				syslog(LOG_NOTICE, "%s - wait for terminating or hot restarting", _terminating_error.c_str());
				for(int i = 0; i < 10 && !is_terminating(); i++) {
					sleep(1);
				}
			}
			manager_parse_command_disable();
			if(!hot_restarting) {
				_break = true;
			}
		}
		terminating_error = "";
	} else {
		_break = true;
	}
	
	//wait for manager to properly terminate 
#ifdef FREEBSD
	if(opt_manager_port && manager_thread != NULL) {
#else
	if(opt_manager_port && manager_thread > 0) {
#endif
		int res;
		res = shutdown(manager_socket_server, SHUT_RDWR);	// break accept syscall in manager thread
		if(res == -1) {
			// if shutdown failed it can happen when reding very short pcap file and the bind socket was not created in manager
			USLEEP(10000); 
			res = shutdown(manager_socket_server, SHUT_RDWR);	// break accept syscall in manager thread
		}
#ifndef FREEBSD
		struct timespec ts;
		ts.tv_sec = 1;
		ts.tv_nsec = 0;
		// wait for thread max 1 sec
		pthread_timedjoin_np(manager_thread, NULL, &ts);
		//TODO: solve it for freebsd
#endif
	}
	
#ifdef FREEBSD
	if(manager_file_thread != NULL) {
#else
	if(manager_file_thread > 0) {
#endif
		int res;
		res = shutdown(manager_socket_file_server, SHUT_RDWR);	// break accept syscall in manager thread
		if(res == -1) {
			// if shutdown failed it can happen when reding very short pcap file and the bind socket was not created in manager
			USLEEP(10000); 
			res = shutdown(manager_socket_file_server, SHUT_RDWR);	// break accept syscall in manager thread
		}
		pthread_join(manager_file_thread, NULL);
		manager_file_thread = 0;
	}
	
	if(opt_rrd) {
		rrd_charts_term();
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
	delete [] skinnyportmatrix;
	delete [] ipaccountportmatrix;
	delete [] ss7portmatrix;
	delete [] ss7_rudp_portmatrix;
	delete [] diameter_tcp_portmatrix;
	delete [] diameter_udp_portmatrix;
	delete [] ssl_portmatrix;
	delete [] ssl_client_random_portmatrix;
	delete [] mgcp_gateway_tcp_portmatrix;
	delete [] mgcp_gateway_udp_portmatrix;
	delete [] mgcp_callagent_tcp_portmatrix;
	delete [] mgcp_callagent_udp_portmatrix;
	
	delete regfailedcache;
	
	if(ws_calls) {
		cout << ws_calls->printUnconfirmed();
		delete ws_calls;
	}
	
	if(sverb.memory_stat) {
		cout << "memory stat at end" << endl;
		printMemoryStat(true);
	}
	if (opt_fork){
		unlink(opt_pidfile);
	}

	if(wdt) {
		delete wdt;
	}
	
	if(logBuffer) {
		delete logBuffer;
		logBuffer = NULL;
	}
	
	#if DEBUG_STORE_COUNT
	extern void out_db_cnt();
	out_db_cnt();
	#endif
	
	termTimeCacheForThread();
	
	rrd_term();
	
	snifferServerTerm();
	
	#if DEBUG_ALLOC_PACKETS
	debug_alloc_packet_list();
	#endif
	
	return(0);
}

void set_global_vars() {
	opt_save_sip_history = "bye";
}

int main_init_read() {
 
	reset_counters();
	
	extern cProcessingLimitations processing_limitations;
	processing_limitations.init();
	
	SqlDb *sqlDbInit = NULL;
	if(!opt_nocdr && !is_sender() && !is_client_packetbuffer_sender()) {
		sqlDbInit = createSqlObject();
	}
	
	dbDataInit(sqlDbInit);
	if(useCdrStatProcessThreads()) {
		cdrStatInit(sqlDbInit);
	}
	if(useCdrProblemsProcessThreads()) {
		cdrProblemsInit(sqlDbInit);
	}
	if(useChartsCacheProcessThreads()) {
		chartsCacheInit(sqlDbInit);
	}

	if(opt_t2_boost && opt_t2_boost_call_threads > 0) {
		preProcessPacketCallX_count = opt_t2_boost_call_threads;
	}
	calltable = new FILE_LINE(42013) Calltable(sqlDbInit);
	createTranscribe();
	#if DEBUG_ASYNC_TAR_WRITE
	destroy_calls_info = new FILE_LINE(0) cDestroyCallsInfo(2e6);
	#endif
	
	// if the system has more than one CPU enable threading
	if(opt_rtpsave_threaded) {
		if(num_threads_set > 0) {
			num_threads_max = num_threads_set;
		} else {
			num_threads_max = sysconf( _SC_NPROCESSORS_ONLN ) - 1;
			if(num_threads_max <= 0) num_threads_max = 1;
		}
		num_threads_active = min(num_threads_max, max(num_threads_start, 1));
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
		opt_cachedir[0] = '\0'; //disabling cache if reading from file 
		opt_cleanspool = false;
		opt_cleanspool_interval = 0; // disable cleaning spooldir when reading from file 
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
		string pcap_error;
		if(!open_global_pcap_handle(opt_read_from_file_fname, &pcap_error)) {
			fprintf(stderr, "Couldn't open pcap file '%s': %s\n", opt_read_from_file_fname, pcap_error.c_str());
			return(2);
		}
	} else if(opt_pcap_queue_disable) {
		char errbuf[PCAP_ERRBUF_SIZE];
		bpf_u_int32 interfaceNet;
		bpf_u_int32 interfaceMask;
		if(pcap_lookupnet(ifname, &interfaceNet, &interfaceMask, errbuf) == -1) {
			interfaceMask = PCAP_NETMASK_UNKNOWN;
		}
		global_pcap_handle = pcap_create(ifname, errbuf);
		if(global_pcap_handle == NULL) {
			fprintf(stderr, "pcap_create(%s) failed: '%s'\n", ifname, errbuf);
			return(2);
		}
		if(pcap_set_snaplen(global_pcap_handle, opt_snaplen ? opt_snaplen : 3200) != 0) {
			fprintf(stderr, "pcap_snaplen failed: %s", pcap_geterr(global_pcap_handle)); 
			return(2);
		}
		if(pcap_set_promisc(global_pcap_handle, opt_promisc) != 0) {
			fprintf(stderr, "pcap_set_promisc failed: %s", pcap_geterr(global_pcap_handle)); 
			return(2);
		}
		if(pcap_set_timeout(global_pcap_handle, 1000) != 0) {
			fprintf(stderr, "pcap_set_timeout failed: %s", pcap_geterr(global_pcap_handle)); 
			return(2);
		}
		if(pcap_set_buffer_size(global_pcap_handle, opt_ringbuffer * 1024 * 1024) != 0) {
			fprintf(stderr, "pcap_set_buffer_size failed: %s", pcap_geterr(global_pcap_handle)); 
			return(2);
		}
		if(pcap_activate(global_pcap_handle) != 0) {
			fprintf(stderr, "pcap_activate failed: %s", pcap_geterr(global_pcap_handle)); 
			return(2);
		}
		if(*user_filter != '\0') {
			// Compile and apply the filter
			struct bpf_program fp;
			if (pcap_compile(global_pcap_handle, &fp, user_filter, 0, interfaceMask) == -1) {
				char user_filter_err[2048];
				snprintf(user_filter_err, sizeof(user_filter_err), "%.2000s%s", user_filter, strlen(user_filter) > 2000 ? "..." : "");
				fprintf(stderr, "can not parse filter %s: %s", user_filter_err, pcap_geterr(global_pcap_handle));
				return(2);
			}
			if (pcap_setfilter(global_pcap_handle, &fp) == -1) {
				char user_filter_err[2048];
				snprintf(user_filter_err, sizeof(user_filter_err), "%.2000s%s", user_filter, strlen(user_filter) > 2000 ? "..." : "");
				fprintf(stderr, "can not install filter %s: %s", user_filter_err, pcap_geterr(global_pcap_handle));
				return(2);
			}
		}
		global_pcap_handle_index = register_pcap_handle(global_pcap_handle);
	}
	
	if(opt_convert_dlt_sll_to_en10 || opt_ipfix || opt_hep) {
		global_pcap_handle_dead_EN10MB = pcap_open_dead(DLT_EN10MB, 65535);
		global_pcap_handle_index_dead_EN10MB = register_pcap_handle(global_pcap_handle_dead_EN10MB);
	}

	vmChdir();

	// set maximum open files 
	struct rlimit rlp;
        rlp.rlim_cur = opt_openfile_max;
        rlp.rlim_max = opt_openfile_max;
        setrlimit(RLIMIT_NOFILE, &rlp);
        getrlimit(RLIMIT_NOFILE, &rlp);
        if(opt_fork and rlp.rlim_cur < opt_openfile_max) {
		printf("Warning: The maximum number of open files is currently set to %d. Consider increasing this limit to %d by running 'ulimit -n %d' and updating the configuration file. Attempting to set the limit to 65535.", (int)rlp.rlim_cur, (int)opt_openfile_max, (int)opt_openfile_max);
		// try fallback to usual maximum 65535
		rlp.rlim_cur = 65535;
		rlp.rlim_max = 65535;
		setrlimit(RLIMIT_NOFILE, &rlp);
		getrlimit(RLIMIT_NOFILE, &rlp);
		if(opt_fork and rlp.rlim_cur < 65535) {
			printf("Warning: The maximum number of open files is still only %d. Setting to 65535 failed.", (int)rlp.rlim_cur);
		}
        }
	// set core file dump to unlimited size
	rlp.rlim_cur = RLIM_INFINITY;
	rlp.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_CORE, &rlp) < 0)
		fprintf(stderr, "setrlimit: %s\nWarning: core dumps may be truncated or non-existant\n", strerror(errno));
	
	if(!opt_nocdr && !is_sender() && !is_client_packetbuffer_sender()) {
		custom_headers_cdr = new FILE_LINE(42014) CustomHeaders(CustomHeaders::cdr, sqlDbInit);
		custom_headers_cdr->createTablesIfNotExists(sqlDbInit);
		custom_headers_cdr->checkTablesColumns(sqlDbInit, opt_disable_dbupgradecheck);
		custom_headers_message = new FILE_LINE(42015) CustomHeaders(CustomHeaders::message, sqlDbInit);
		custom_headers_message->createTablesIfNotExists(sqlDbInit);
		custom_headers_message->checkTablesColumns(sqlDbInit, opt_disable_dbupgradecheck);
		custom_headers_sip_msg = new FILE_LINE(0) CustomHeaders(CustomHeaders::sip_msg, sqlDbInit);
		custom_headers_sip_msg->createTablesIfNotExists(sqlDbInit);
		custom_headers_sip_msg->checkTablesColumns(sqlDbInit, opt_disable_dbupgradecheck);
		no_hash_message_rules = new FILE_LINE(42016) NoHashMessageRules(sqlDbInit);
	}

	cFilters::loadActive(sqlDbInit);

	_parse_packet_global_process_packet.clearNodes();
	_parse_packet_global_process_packet.setStdParse();
	
	if(opt_use_dpdk) {
		cGlobalDpdkTools::setHugePages();
		cGlobalDpdkTools::clearThreadsAffinity();
		if(opt_dpdk_read_thread_lcore.empty() && opt_dpdk_worker_thread_lcore.empty() && opt_dpdk_worker2_thread_lcore.empty()) {
			cGlobalDpdkTools::setThreadsAffinity();
		}
		init_dpdk();
	}

	if(is_enable_sip_msg()) {
		initSipMsg();
	}
		
	if(opt_ipaccount && !opt_test) {
		initIpacc();
	}
	
	if(opt_save_query_main_to_files || 
	   opt_save_query_charts_to_files || 
	   opt_save_query_charts_remote_to_files) {
		sqlStore->queryToFiles_start();
		if(sqlStore_2) {
			sqlStore_2->queryToFiles_start();
		}
	}
	if(opt_load_query_main_from_files ||
	   opt_load_query_charts_from_files ||
	   opt_load_query_charts_remote_from_files) {
		loadFromQFiles->loadFromQFiles_start();
	}
	
	if(is_enable_cleanspool(true)) {
		for(int i = 0; i < 2; i++) {
			if(isSetSpoolDir(i) &&
			   CleanSpool::isSetCleanspoolParameters(i)) {
				cleanSpool[i] = new FILE_LINE(42018) CleanSpool(i);
				if(opt_pcap_dump_tar && opt_fork) {
					string maxSpoolDate = cleanSpool[i]->getMaxSpoolDate();
					if(maxSpoolDate.length()) {
						syslog(LOG_NOTICE, "run reindex date %s", maxSpoolDate.c_str());
						CleanSpool::run_reindex_date(maxSpoolDate, i);
						syslog(LOG_NOTICE, "reindex date %s completed", maxSpoolDate.c_str());
					}
				}
			}
		}
		if(cleanSpool[0] && !is_read_from_file()) {
			cleanSpool[0]->run();
		}
	}

	if(opt_pcap_dump_tar) {
		for(int i = 0; i < 2; i++) {
			if(isSetSpoolDir(i)) {
				tarQueue[i] = new FILE_LINE(42019) TarQueue(i);
			}
		}
		if(opt_tar_move && !opt_tar_move_destination_path.empty() && !is_read_from_file_simple()) {
			tarCopy = new FILE_LINE(0) TarCopy;
			tarCopy->setDestination(opt_tar_move_destination_path);
			tarCopy->setTrimSrcPath(opt_tar_move_source_trim_path);
			tarCopy->setMove(opt_tar_move == 1);
			tarCopy->setMaxThreads(opt_tar_move_max_threads);
			tarCopy->addTarsFromSpool();
			tarCopy->start_threads();
		}
	}
	
	if(!is_sender() && !is_client_packetbuffer_sender()) {
		CountryDetectInit(sqlDbInit);
		
		if(enable_register_engine) {
			initRegisters();
		}
		
		if(opt_enable_fraud) {
			initFraud(sqlDbInit);
		}
		
		if(opt_enable_billing) {
			initBilling(sqlDbInit);
		}
		
		initSendCallInfo(sqlDbInit);
	}
	
	if(sqlDbInit) {
		delete sqlDbInit;
	}
	
	if(opt_ipaccount) {
		ipaccStartThread();
	}

	if(opt_pcap_dump_asyncwrite) {
		extern AsyncClose *asyncClose;
		asyncClose = new FILE_LINE(42020) AsyncClose;
		asyncClose->startThreads(opt_pcap_dump_writethreads, opt_pcap_dump_writethreads_max);
	}
	
	if(opt_fork) {
		vm_pthread_create("defered service",
				  &defered_service_fork_thread, NULL, defered_service_fork, NULL, __FILE__, __LINE__);
		vm_pthread_create("check pcap stat activity thread",
				  &check_activity_or_crash_thread, NULL, check_activity_or_crash, NULL, __FILE__, __LINE__);
	} else if(!is_read_from_file_simple()) {
		dns_lookup_common_hostnames();
	}
	
	// start thread processing queued cdr and sql queue - supressed if run as sender
	if(!is_sender() && !is_client_packetbuffer_sender()
	   #if EXPERIMENTAL_SEPARATE_PROCESSSING
	   && separate_processing() != cSeparateProcessing::_rtp
	   #endif
	   ) {
		if(opt_storing_cdr_max_next_threads) {
			storing_cdr_next_threads = new FILE_LINE(0) sStoringCdrNextThreads[opt_storing_cdr_max_next_threads];
		}
		vm_pthread_create("storing cdr",
				  &storing_cdr_thread, NULL, storing_cdr, NULL, __FILE__, __LINE__);
		vm_pthread_create("storing register",
				  &storing_registers_thread, NULL, storing_registers, NULL, __FILE__, __LINE__);
		/*
		vm_pthread_create(&destroy_calls_thread, NULL, destroy_calls, NULL, __FILE__, __LINE__);
		*/
		if(useChartsCacheOrCdrStatProcessThreads()) {
			calltable->processCallsInChartsCache_start();
		}
	}

	if(opt_cachedir[0] != '\0') {
		mv_r(opt_cachedir, opt_spooldir_main);
		vm_pthread_create("moving cache",
				  &cachedir_thread, NULL, moving_cache, NULL, __FILE__, __LINE__);
	}

	// start tar dumper
	if(opt_pcap_dump_tar) {
		for(int i = 0; i < 2; i++) {
			if(tarQueue[i]) {
				vm_pthread_create("tar queue",
						  &tarqueuethread[i], NULL, TarQueueThread, tarQueue[i], __FILE__, __LINE__);
			}
		}
	}

	if(!is_sender() && !is_client_packetbuffer_sender()) {
		// start reading threads
		if(is_enable_rtp_threads()) {
			rtp_threads = new FILE_LINE(42021) rtp_read_thread[num_threads_max];
			for(int i = 0; i < num_threads_max; i++) {
				size_t _rtp_qring_length = rtp_qring_length ? 
								rtp_qring_length :
								rtpthreadbuffer * 1024 * 1024 / sizeof(rtp_packet_pcap_queue);
				rtp_threads[i].init(i + 1, _rtp_qring_length);
				if(i < num_threads_active) {
					rtp_threads[i].alloc_qring();
					vm_pthread_create_autodestroy("rtp read",
								      &(rtp_threads[i].thread), NULL, rtp_read_thread_func, (void*)&rtp_threads[i], __FILE__, __LINE__);
				}
			}
		}
		
		for(int i = (opt_t2_boost_direct_rtp ? PreProcessPacket::ppt_detach_x : PreProcessPacket::ppt_detach); i < PreProcessPacket::ppt_end_base; i++) {
			preProcessPacket[i] = new FILE_LINE(0) PreProcessPacket((PreProcessPacket::eTypePreProcessThread)i);
		}
		if(is_enable_packetbuffer()) {
			for(int i = (opt_t2_boost_direct_rtp ? PreProcessPacket::ppt_detach_x : PreProcessPacket::ppt_detach); i < max(1, min(opt_enable_preprocess_packet, (int)PreProcessPacket::ppt_end_base)); i++) {
				if((i != PreProcessPacket::ppt_pp_register && 
				    i != PreProcessPacket::ppt_pp_sip_other &&
				    i != PreProcessPacket::ppt_pp_diameter) ||
				   (i == PreProcessPacket::ppt_pp_register && opt_sip_register) ||
				   (i == PreProcessPacket::ppt_pp_sip_other && is_enable_sip_msg()) ||
				   (i == PreProcessPacket::ppt_pp_diameter && opt_enable_diameter)) {
					preProcessPacket[i]->startOutThread();
				}
			}
		}
		
		#if CALLX_MOD_OLDVER
		if(opt_t2_boost && opt_t2_boost_call_threads > 0) {
			bool autoStartCallX = false;
			preProcessPacketCallX = new FILE_LINE(0) PreProcessPacket*[preProcessPacketCallX_count + 1];
			for(int i = 0; i < preProcessPacketCallX_count + 1; i++) {
				preProcessPacketCallX[i] = new FILE_LINE(0) PreProcessPacket(PreProcessPacket::ppt_pp_callx, i);
				if(autoStartCallX) {
					preProcessPacketCallX[i]->startOutThread();
				}
			}
			if(autoStartCallX) {
				preProcessPacketCallX_state = PreProcessPacket::callx_process;
			}
			if(calltable->enableCallFindX()) {
				preProcessPacketCallFindX = new FILE_LINE(0) PreProcessPacket*[preProcessPacketCallX_count];
				for(int i = 0; i < preProcessPacketCallX_count; i++) {
					preProcessPacketCallFindX[i] = new FILE_LINE(0) PreProcessPacket(PreProcessPacket::ppt_pp_callfindx, i);
				}
				for(int i = 0; i < preProcessPacketCallX_count + 1; i++) {
					preProcessPacketCallX[i]->startOutThread();
				}
				for(int i = 0; i < preProcessPacketCallX_count; i++) {
					preProcessPacketCallFindX[i]->startOutThread();
				}
				preProcessPacketCallX_state = PreProcessPacket::callx_find;
			}
		}
		#endif
		
		//autostart for fork mode if t2cpu > 50%
		if(
		   #if DEBUG_DTLS_QUEUE
		   //false &&
		   #endif
		   (!opt_fork || opt_t2_boost) &&
		   opt_enable_process_rtp_packet && enable_pcap_split &&
		   is_enable_packetbuffer()) {
			process_rtp_packets_distribute_threads_use = opt_enable_process_rtp_packet;
			for(int i = 0; i < opt_enable_process_rtp_packet; i++) {
				processRtpPacketDistribute[i] = new FILE_LINE(42023) ProcessRtpPacket(ProcessRtpPacket::distribute, i);
			}
			processRtpPacketHash = new FILE_LINE(42024) ProcessRtpPacket(ProcessRtpPacket::hash, 0);
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
			tcpReassemblyHttp = new FILE_LINE(42025) TcpReassembly(TcpReassembly::http);
			tcpReassemblyHttp->setEnableHttpForceInit();
			tcpReassemblyHttp->setEnableCrazySequence();
			tcpReassemblyHttp->setEnableValidateDataViaCheckData();
			tcpReassemblyHttp->setEnableCleanupThread();
			tcpReassemblyHttp->setEnableHttpCleanupExt(opt_http_cleanup_ext);
			tcpReassemblyHttp->setEnablePacketThread();
			httpData = new FILE_LINE(42026) HttpData;
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
			tcpReassemblyWebrtc = new FILE_LINE(42027) TcpReassembly(TcpReassembly::webrtc);
			tcpReassemblyWebrtc->setEnableIgnorePairReqResp();
			tcpReassemblyWebrtc->setEnableWildLink();
			tcpReassemblyWebrtc->setEnableDestroyStreamsInComplete();
			tcpReassemblyWebrtc->setEnableAllCompleteAfterZerodataAck();
			tcpReassemblyWebrtc->setIgnorePshInCheckOkData();
			tcpReassemblyWebrtc->setEnablePacketThread();
			webrtcData = new FILE_LINE(42028) WebrtcData;
			tcpReassemblyWebrtc->setDataCallback(webrtcData);
		}
	}
	if(opt_enable_ssl) {
		if(opt_enable_ssl == 10) {
			#if defined(HAVE_LIBGNUTLS) and defined(HAVE_SSL_WS)
			ssl_init();
			#endif
		} else {
			ssl_dssl_init();
			if(ssl_master_secret_file[0]) {
				ssl_parse_client_random(ssl_master_secret_file);
			}
		}
		tcpReassemblySsl = new FILE_LINE(42029) TcpReassembly(TcpReassembly::ssl);
		tcpReassemblySsl->setEnableIgnorePairReqResp();
		tcpReassemblySsl->setEnableDestroyStreamsInComplete();
		if(opt_ssl_reassembly_all_complete_after_zerodata_ack) {
			tcpReassemblySsl->setEnableAllCompleteAfterZerodataAck();
		}
		tcpReassemblySsl->setIgnorePshInCheckOkData();
		tcpReassemblySsl->setEnableValidateLastQueueDataViaCheckData();
		if(opt_ssl_unlimited_reassembly_attempts) {
			tcpReassemblySsl->setUnlimitedReassemblyAttempts();
		}
		sslData = new FILE_LINE(42030) SslData;
		tcpReassemblySsl->setDataCallback(sslData);
		tcpReassemblySsl->setLinkTimeout(opt_ssl_link_timeout);
		if(!is_read_from_file_simple() &&
		   ssl_client_random_use && ssl_client_random_maxwait_ms > 0) {
			tcpReassemblySsl->setEnablePacketThread();
		}
		if(opt_ssl_ignore_tcp_handshake) {
			tcpReassemblySsl->setEnableWildLink();
			tcpReassemblySsl->setIgnoreTcpHandshake();
		}
	}
	if(opt_sip_tcp_reassembly_ext) {
		tcpReassemblySipExt = new FILE_LINE(42031) TcpReassembly(TcpReassembly::sip);
		tcpReassemblySipExt->setEnableIgnorePairReqResp();
		tcpReassemblySipExt->setEnableDestroyStreamsInComplete();
		tcpReassemblySipExt->setEnableStrictValidateDataViaCheckData();
		tcpReassemblySipExt->setNeedValidateDataViaCheckData();
		tcpReassemblySipExt->setSimpleByAck();
		tcpReassemblySipExt->setIgnorePshInCheckOkData();
		tcpReassemblySipExt->setSmartMaxSeq();
		//tcpReassemblySipExt->setSmartMaxSeqByPsh();
		tcpReassemblySipExt->setSkipZeroData();
		sipTcpData = new FILE_LINE(42032) SipTcpData;
		tcpReassemblySipExt->setDataCallback(sipTcpData);
		tcpReassemblySipExt->setEnableWildLink();
		tcpReassemblySipExt->setEnableSmartCompleteData();
		tcpReassemblySipExt->setEnableExtStat();
		tcpReassemblySipExt->setMaxReassemblyAttempts(opt_sip_tcp_reassembly_stream_max_attempts);
		if(opt_sip_tcp_reassembly_stream_max_length > 0) {
			tcpReassemblySipExt->setMaxStreamLength(opt_sip_tcp_reassembly_stream_max_length);
		}
		tcpReassemblySipExt->setLinkTimeout(opt_sip_tcp_reassembly_ext_link_timeout ? opt_sip_tcp_reassembly_ext_link_timeout : 10);
		if(opt_sip_tcp_reassembly_ext_quick_mod & 2) {
			if(!is_read_from_file()) {
				tcpReassemblySipExt->setEnableExtCleanupStreams(opt_sip_tcp_reassembly_stream_max_attempts, 25);
			}
			tcpReassemblySipExt->setEnableLinkLock();
			tcpReassemblySipExt->setEnableAutoCleanup(false);
			tcpReassemblySipExt->setCleanupPeriod(10);
		} else {
			if(!is_read_from_file()) {
				tcpReassemblySipExt->setEnableExtCleanupStreams(50, 25);
			}
			tcpReassemblySipExt->setEnablePushLock();
		}
		if(opt_sip_tcp_reassembly_ext_complete_mod) {
			tcpReassemblySipExt->setCompleteMod(opt_sip_tcp_reassembly_ext_complete_mod);
		}
		if(sverb.tcpreassembly_sip_dumper) {
			tcpReassemblySipExt->enableDumper(sverb.tcpreassembly_sip_dumper, sverb.tcpreassembly_sip_dumper_ports);
		}
	}
	if(opt_enable_diameter) {
		bool setDiameterTcpPorts = false;
		for(int i = 0; i < 65537; i++) {
			if(diameter_tcp_portmatrix[i]) {
				setDiameterTcpPorts = true;
			}
		}
		if(setDiameterTcpPorts) {
			tcpReassemblyDiameter = new FILE_LINE(0) TcpReassembly(TcpReassembly::diameter);
			tcpReassemblyDiameter->setEnableIgnorePairReqResp();
			tcpReassemblyDiameter->setEnableDestroyStreamsInComplete();
			if(opt_diameter_reassymbly_all_complete_after_zerodata_ack) {
				tcpReassemblyDiameter->setEnableAllCompleteAfterZerodataAck();
			}
			tcpReassemblyDiameter->setIgnorePshInCheckOkData();
			tcpReassemblyDiameter->setEnableValidateLastQueueDataViaCheckData();
			tcpReassemblyDiameter->setNeedValidateDataViaCheckData();
			// tcpReassemblyDiameter->setUnlimitedReassemblyAttempts();
			tcpReassemblyDiameter->setEnableWildLink();
			tcpReassemblyDiameter->setIgnoreTcpHandshake();
			diameterTcpData = new FILE_LINE(0) DiameterTcpData;
			tcpReassemblyDiameter->setDataCallback(diameterTcpData);
		}
	}
	
	if(sipSendSocket_ip_port) {
		sipSendSocket = new FILE_LINE(42033) SocketSimpleBufferWrite("send sip", sipSendSocket_ip_port, opt_sip_send_udp);
		sipSendSocket->startWriteThread();
	}
	
	if(opt_bogus_dumper_path[0]) {
		bogusDumper = new FILE_LINE(42034) BogusDumper(opt_bogus_dumper_path);
	}
	
	#if TRAFFIC_DUMPER
	if(opt_traffic_dumper_path[0]) {
		trafficDumper = new FILE_LINE(0) TrafficDumper(opt_traffic_dumper_path, 
							       opt_traffic_dumper_by_interface ? TrafficDumper::_byInterface : TrafficDumper::_byDlt,
							       opt_traffic_dumper_force_flush);
	}
	#endif
	
	if(!ssl_client_random_tcp_host.empty() && ssl_client_random_tcp_port) {
		clientRandomServerStart(ssl_client_random_tcp_host.c_str(), ssl_client_random_tcp_port);
	}
	
	if(opt_ipfix && !opt_ipfix_bind_ip.empty() && opt_ipfix_bind_port) {
		IPFixServerStart(opt_ipfix_bind_ip.c_str(), opt_ipfix_bind_port);
	}
	
	if(opt_hep && !opt_hep_bind_ip.empty() && opt_hep_bind_port) {
		HEP_ServerStart(opt_hep_bind_ip.c_str(), opt_hep_bind_port, opt_hep_bind_udp);
	}
	
	clear_readend();
	
	#if EXPERIMENTAL_SEPARATE_PROCESSSING
	if(separate_processing()) {
		separate_processing_init();
		separate_processing_start();
		if(separate_processing() == cSeparateProcessing::_rtp) {
			cleanup_calls_separate_processing_terminating = false;
			vm_pthread_create("cleanup calls separate processing (rtp)",
					  &cleanup_calls_separate_processing_thread, NULL, cleanup_calls_separate_processing, NULL, __FILE__, __LINE__);
		}
	}
	#endif

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
			if(tcpReassemblyDiameter) {
				tcpReassemblyDiameter->setIgnoreTerminating(true);
			}
		}
	
		if((ifname[0] && strcmp(ifname, "--")) || is_read_from_file_by_pb() || opt_scanpcapdir[0]) {
			pcapQueueI = new FILE_LINE(42035) PcapQueue_readFromInterface("interface");
			pcapQueueI->setInterfaces(ifname[0] ? 
						   ifname :
						  is_read_from_file_by_pb() ? 
						   "read_from_file" :
						   "scanpcapdir");
			if(ifname_libpcap_filter.size()) {
				pcapQueueI->setFiltersByInterface(ifname_libpcap_filter);
			}
			pcapQueueI->setEnableAutoTerminate(false);
		}
		
		pcapQueueQ = new FILE_LINE(42036) PcapQueue_readFromFifo("queue", opt_pcap_queue_disk_folder.c_str());
		if(pcapQueueI) {
			pcapQueueQ->setInstancePcapHandle(pcapQueueI);
			pcapQueueI->setInstancePcapFifo(pcapQueueQ);
		}
		pcapQueueQ->setEnableAutoTerminate(false);
		
		if(is_receiver()) {
			pcapQueueQ->setPacketServer(opt_pcap_queue_receive_from_ip_port, PcapQueue_readFromFifo::directionRead);
		} else if(is_sender()) {
			pcapQueueQ->setPacketServer(opt_pcap_queue_send_to_ip_port, PcapQueue_readFromFifo::directionWrite);
		}
		
		if(opt_pcap_queue_use_blocks && !is_sender() && !is_client_packetbuffer_sender()) {
			for(int pass = 0; pass < 2; pass++) {
				if(opt_t2_boost_pb_detach_thread && opt_t2_boost) {
					if(pass == 0) {
						pcapQueueQ_outThread_detach = new FILE_LINE(0) PcapQueue_outputThread(PcapQueue_outputThread::detach, pcapQueueQ);
					} else {
						pcapQueueQ_outThread_detach->start();
					}
				}
				if(opt_udpfrag) {
					if(pass == 0) {
						pcapQueueQ_outThread_defrag = new FILE_LINE(0) PcapQueue_outputThread(PcapQueue_outputThread::defrag, pcapQueueQ);
					} else {
						pcapQueueQ_outThread_defrag->start();
					}
				}
				if(opt_dup_check_type != _dedup_na && 
				   (is_receiver() || is_server() ?
				     !opt_receiver_check_id_sensor :
				     getCountInterfaces() > 1)) {
					if(pass == 0) {
						pcapQueueQ_outThread_dedup = new FILE_LINE(0) PcapQueue_outputThread(PcapQueue_outputThread::dedup, pcapQueueQ);
					} else {
						pcapQueueQ_outThread_dedup->start();
					}
				}
				if(opt_t2_boost_pb_detach_thread == 2 && opt_t2_boost) {
					if(pass == 0) {
						pcapQueueQ_outThread_detach2 = new FILE_LINE(0) PcapQueue_outputThread(PcapQueue_outputThread::detach2, pcapQueueQ);
					} else {
						pcapQueueQ_outThread_detach2->start();
					}
				}
			}
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
		
		uint64_t _counterLog = 0;
		uint64_t _counterCpuCheck = 0;
		if(!sverb.pcap_stat_period) {
			sverb.pcap_stat_period = verbosityE > 0 ? 1 : 10;
		}
		int logPeriodS = verbosityE > 0 ? 1 : sverb.pcap_stat_period;
		manager_parse_command_enable();
		
		if(!wdt && !is_read_from_file() && opt_fork && enable_wdt && rightPSversion && bashPresent) {
			wdt = new FILE_LINE(0) WDT;
		}

		while(!is_terminating()) {
			u_int64_t startTimeMS = getTimeMS_rdtsc();
			u_int64_t endTimeMS = startTimeMS + logPeriodS * 1000;
			if(_counterLog) {
				pthread_mutex_lock(&terminate_packetbuffer_lock);
				if(pcapQueueQ) {
					pcapQueueQ->pcapStat(PcapQueue::pcapStatLog, logPeriodS);
				}
				pthread_mutex_unlock(&terminate_packetbuffer_lock);
				if(sverb.memory_stat_log) {
					printMemoryStat();
				}
				if(sverb.threads_cpu_log) {
					extern cThreadMonitor threadMonitor;
					string log = threadMonitor.output(2, cThreadMonitor::_of_line);
					if(!log.empty()) {
						syslog(LOG_NOTICE, "threads: %s", log.c_str());
					}
				}
				#if HAVE_LIBJEMALLOC
				if(!opt_jemalloc_stat_full_folder.empty()) {
					jeMallocStat_save();
				}
				#endif
				if(tcpReassemblyHttp) {
					tcpReassemblyHttp->setDoPrintContent();
				}
				if(tcpReassemblyWebrtc) {
					tcpReassemblyWebrtc->setDoPrintContent();
				}
				if(!is_read_from_file() && !sverb.suppress_fork) {
					if (!is_client_packetbuffer_sender()) {
						if (--swapDelayCount < 0) {
							checkSwapUsage();
						}
					}
					if (!isCloud() && !is_client()) {
						if (--swapMysqlDelayCount < 0) {
							checkMysqlSwapUsage();
						}
					}
				}
				if(opt_enable_ssl) {
					if(opt_ssl_enable_dtls_queue == 1) {
						extern void dtls_queue_cleanup();
						dtls_queue_cleanup();
					}
					if(opt_ssl_dtls_handshake_safe) {
						extern void dtls_handshake_safe_links_cleanup();
						dtls_handshake_safe_links_cleanup();
					}
				}
				if(opt_use_dpdk && (opt_other_thread_affinity_check || opt_other_thread_affinity_set)) {
					dpdk_check_affinity();
				}
			}
			if(!opt_sched_pol_auto.empty() && opt_sched_pol_auto_heap_limit && opt_sched_pol_auto_cpu_limit) {
				extern cThreadMonitor threadMonitor;
				threadMonitor.setSchedPolPriority(0);
			}
			u_int64_t startTimeCpuCheck = 0;
			while(!is_terminating()) {
				u_int64_t time_ms = getTimeMS_rdtsc();
				if(time_ms >= endTimeMS) {
					break;
				}
				if(!startTimeCpuCheck ||
				   (time_ms >= startTimeCpuCheck + 1000 &&
				    time_ms + 900 < endTimeMS)) {
					startTimeCpuCheck = getTimeMS_rdtsc();
					if(_counterCpuCheck) {
						pthread_mutex_lock(&terminate_packetbuffer_lock);
						if(pcapQueueQ) {
							pcapQueueQ->pcapStat(PcapQueue::pcapStatCpuCheck, 1);
						}
						pthread_mutex_unlock(&terminate_packetbuffer_lock);
					}
					++_counterCpuCheck;
				}
				USLEEP(10000);
				if(logBuffer) {
					logBuffer->apply();
				}
			}
			++_counterLog;
			last_pcap_stat_activity_at = getTimeMS_rdtsc();

			#if DEBUG_PACKET_COUNT
			extern volatile int __xc_inv;
			extern volatile int __xc_sip;
			extern volatile int __xc_nosip;
			extern volatile int __xc_callsave;
			extern volatile int __xc_reassembly[10];
			cout << " ***" << endl 
			     << " * invite: " << __xc_inv << endl
			     << " * sip: " << __xc_sip << endl
			     << " * nosip: " << __xc_nosip << endl
			     << " * callsave: " << __xc_callsave << endl
			     << " * reassembly: " << __xc_reassembly[0] << endl
			     << " * reassembly: " << __xc_reassembly[1] << endl
			     << " ***" << endl;
			#endif
			
		}
		
		if(wdt && !hot_restarting) {
			delete wdt;
			wdt = NULL;
		}
		
		manager_parse_command_disable();
		
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
		readdump_libpcap(global_pcap_handle, global_pcap_handle_index, pcap_datalink(global_pcap_handle), NULL,
				 (is_read_from_file() ? _pp_read_file : 0) | _pp_process_calls);
	}
	
	return(0);
}

void terminate_processpacket() {
 
	#if EXPERIMENTAL_SEPARATE_PROCESSSING
	if(separate_processing()) {
		separate_processing_stop();
		separate_processing_term();
		if(cleanup_calls_separate_processing_thread) {
			cleanup_calls_separate_processing_terminating = true;
			pthread_join(cleanup_calls_separate_processing_thread, NULL);
			cleanup_calls_separate_processing_thread = 0;
			cleanup_calls_separate_processing_terminating = false;
		}
	}
	#endif
 
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
	if(opt_enable_ssl) {
		if(opt_enable_ssl == 10) {
			#if defined(HAVE_LIBGNUTLS) and defined(HAVE_SSL_WS)
			ssl_clean();
			#endif
		} else {
			ssl_dssl_clean();
		}
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
	if(tcpReassemblyDiameter) {
		delete tcpReassemblyDiameter;
		tcpReassemblyDiameter = NULL;
	}
	if(diameterTcpData) {
		delete diameterTcpData;
		diameterTcpData = NULL;
	}
	
	if(processRtpPacketHash) {
		processRtpPacketHash->terminate();
		delete processRtpPacketHash;
		processRtpPacketHash = NULL;
	}
	
	for(int termPass = 0; termPass < 2; termPass++) {
		if(preProcessPacketCallX) {
			for(int i = 0; i < preProcessPacketCallX_count + 1; i++) {
				if(preProcessPacketCallX[i]) {
					if(termPass == 0) {
						preProcessPacketCallX[i]->terminate();
					} else {
						delete preProcessPacketCallX[i];
						preProcessPacketCallX[i] = NULL;
					}
				}
			}
		}
		if(preProcessPacketCallFindX) {
			for(int i = 0; i < preProcessPacketCallX_count; i++) {
				if(preProcessPacketCallFindX[i]) {
					if(termPass == 0) {
						preProcessPacketCallFindX[i]->terminate();
					} else {
						delete preProcessPacketCallFindX[i];
						preProcessPacketCallFindX[i] = NULL;
					}
				}
			}
		}
		for(int i = 0; i < PreProcessPacket::ppt_end_base; i++) {
			if(preProcessPacket[i]) {
				if(termPass == 0) {
					preProcessPacket[i]->terminate();
				} else {
					delete preProcessPacket[i];
					preProcessPacket[i] = NULL;
				}
			}
		}
		if(termPass == 0) {
			USLEEP(100000);
		} else {
			if(preProcessPacketCallX) {
				delete [] preProcessPacketCallX;
				preProcessPacketCallX = NULL;
			}
			if(preProcessPacketCallFindX) {
				delete [] preProcessPacketCallFindX;
				preProcessPacketCallFindX = NULL;
			}
			preProcessPacketCallX_count = 0;
			preProcessPacketCallX_state = PreProcessPacket::callx_na;
		}
	}
	
	for(int termPass = 0; termPass < 2; termPass++) {
		for(int i = 0; i < MAX_PROCESS_RTP_PACKET_THREADS; i++) {
			if(processRtpPacketDistribute[i]) {
				if(termPass == 0) {
					processRtpPacketDistribute[i]->terminate();
				} else {
					delete processRtpPacketDistribute[i];
					processRtpPacketDistribute[i] = NULL;
				}
			}
		}
		if(termPass == 0) {
			USLEEP(100000);
		}
	}
	
	// wait for RTP threads
	if(rtp_threads) {
		for(int i = 0; i < num_threads_max; i++) {
			if(i < num_threads_active) {
				while(rtp_threads[i].threadId) {
					USLEEP(100000);
				}
			}
			rtp_threads[i].term();
		}
		delete [] rtp_threads;
		rtp_threads = NULL;
	}
}

void main_term_read() {
	set_readend();

	if(is_read_from_file_simple() && global_pcap_handle) {
		pcap_close(global_pcap_handle);
	}
	if(global_pcap_handle_dead_EN10MB) {
		pcap_close(global_pcap_handle_dead_EN10MB);
	}
	
	// flush all queues

	Call *call;
	Ss7 *ss7;
	calltable->cleanup_calls(true);
	calltable->cleanup_registers(true);
	calltable->cleanup_ss7(true);

	if(useCdrStatProcessThreads()) {
		cdrStatStore(true);
	}
	if(useCdrProblemsProcessThreads()) {
		cdrProblemsStore(true);
	}
	if(useChartsCacheProcessThreads()) {
		chartsCacheStore(true);
	}
	
	set_terminating();

	regfailedcache->prune(0);
	if(enable_register_engine) {
		extern Registers registers;
		registers.clean_all();
	}
	
	if(is_enable_sip_msg()) {
		termSipMsg();
	}
	
	if(!ssl_client_random_tcp_host.empty() && ssl_client_random_tcp_port) {
		clientRandomServerStop();
	}
	
	if(opt_ipfix && !opt_ipfix_bind_ip.empty() && opt_ipfix_bind_port) {
		IPFixServerStop();
	}
	
	if(opt_hep && !opt_hep_bind_ip.empty() && opt_hep_bind_port) {
		HEP_ServerStop();
	}

	terminate_processpacket();
	
	if(sipSendSocket) {
		delete sipSendSocket;
		sipSendSocket = NULL;
	}

	if(opt_cachedir[0] != '\0') {
		terminating_moving_cache = 1;
		pthread_join(cachedir_thread, NULL);
	}
	
	cFilters::freeActive();
	
	if(enable_register_engine) {
		termRegisters();
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
		for(int i = 0; i < 2; i++) {
			if(tarQueue[i]) {
				pthread_join(tarqueuethread[i], NULL);
				delete tarQueue[i];
				tarQueue[i] = NULL;
			}
			if(tarCopy) {
				delete tarCopy;
				tarCopy = NULL;
			}
		}
		if(sverb.chunk_buffer > 1) { 
			cout << "end destroy tar queue" << endl << flush;
		}
	}
	
	if(storing_cdr_thread) {
		terminating_storing_cdr = 1;
		pthread_join(storing_cdr_thread, NULL);
		if(storing_cdr_next_threads) {
			__SYNC_LOCK(storing_cdr_next_threads_count_sync);
			for(int i = 0; i < opt_storing_cdr_max_next_threads; i++) {
				if(storing_cdr_next_threads[i].init) {
					if(i < storing_cdr_next_threads_count) {
						sem_post(&storing_cdr_next_threads[i].sem[0]);
						pthread_join(storing_cdr_next_threads[i].thread, NULL);
					}
					for(int j = 0; j < 2; j++) {
						sem_destroy(&storing_cdr_next_threads[i].sem[j]);
					}
					delete storing_cdr_next_threads[i].calls;
				}
			}
			__SYNC_UNLOCK(storing_cdr_next_threads_count_sync);
			delete [] storing_cdr_next_threads;
			storing_cdr_next_threads = NULL;
		}
		storing_cdr_thread = 0;
	}
	if(storing_registers_thread) {
		terminating_storing_registers = 1;
		pthread_join(storing_registers_thread, NULL);
		storing_registers_thread = 0;
	}
	
	if(useChartsCacheOrCdrStatProcessThreads()) {
		calltable->processCallsInChartsCache_stop();
	}
	while(calltable->calls_queue.size() != 0) {
			call = calltable->calls_queue.front();
			calltable->calls_queue.pop_front();
			call->calls_counter_dec();
			delete call;
	}
	while(calltable->audio_queue.size() != 0) {
			call = calltable->audio_queue.front();
			calltable->audio_queue.pop_front();
			call->calls_counter_dec();
			delete call;
	}
	while(calltable->calls_deletequeue.size() != 0) {
			call = calltable->calls_deletequeue.front();
			calltable->calls_deletequeue.pop_front();
			call->atFinish();
			call->calls_counter_dec();
			delete call;
	}
	while(calltable->registers_queue.size() != 0) {
			call = calltable->registers_queue.front();
			calltable->registers_queue.pop_front();
			call->registers_counter_dec();
			delete call;
	}
	while(calltable->registers_deletequeue.size() != 0) {
			call = calltable->registers_deletequeue.front();
			calltable->registers_deletequeue.pop_front();
			call->atFinish();
			call->registers_counter_dec();
			delete call;
	}
	while(calltable->ss7_queue.size() != 0) {
			ss7 = calltable->ss7_queue.front();
			calltable->ss7_queue.pop_front();
			delete ss7;
	}
	delete calltable;
	calltable = NULL;
	destroyTranscribe();
	#if DEBUG_ASYNC_TAR_WRITE
	delete destroy_calls_info;
	destroy_calls_info = NULL;
	#endif
	
	extern RTPstat rtp_stat;
	rtp_stat.flush();
	
	pthread_mutex_destroy(&mysqlconnect_lock);
	extern SqlDb *sqlDbSaveCall;
	if(sqlDbSaveCall) {
		delete sqlDbSaveCall;
		sqlDbSaveCall = NULL;
	}
	extern SqlDb *sqlDbSaveSs7;
	if(sqlDbSaveSs7) {
		delete sqlDbSaveSs7;
		sqlDbSaveSs7 = NULL;
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
	
	if(sqlStore) {
		if(!isCloud() && is_server() && !is_read_from_file_simple()) {
			snifferServerSetSqlStore(NULL);
		}
		sqlStore->setEnableTerminatingIfEmpty(0, 0, true);
		sqlStore->setEnableTerminatingIfSqlError(0, 0, true);
		regfailedcache->prune(0);
		delete sqlStore;
		sqlStore = NULL;
	}
	if(sqlStore_2) {
		sqlStore_2->setEnableTerminatingIfEmpty(0, 0, true);
		sqlStore_2->setEnableTerminatingIfSqlError(0, 0, true);
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
	if(custom_headers_sip_msg) {
		delete custom_headers_sip_msg;
		custom_headers_sip_msg = NULL;
	}
	if(no_hash_message_rules) {
		delete no_hash_message_rules;
		no_hash_message_rules = NULL;
	}
	
	CountryDetectTerm();
	
	dbDataTerm();
	if(useCdrStatProcessThreads()) {
		cdrStatTerm();
	}
	if(useCdrProblemsProcessThreads()) {
		cdrProblemsTerm();
	}
	if(useChartsCacheProcessThreads()) {
		chartsCacheTerm();
	}
	
	if(opt_enable_billing) {
		termBilling();
	}
	
	for(int i = 0; i < 2; i++) {
		if(cleanSpool[i]) {
			delete cleanSpool[i];
			cleanSpool[i] = NULL;
		}
	}
	
	termIpacc();
	
	if(opt_bogus_dumper_path[0]) {
		delete bogusDumper;
		bogusDumper = NULL;
	}
	
	#if TRAFFIC_DUMPER
	if(opt_traffic_dumper_path[0]) {
		delete trafficDumper;
		trafficDumper = NULL;
	}
	#endif
	
	if(opt_use_dpdk) {
		term_dpdk();
	}
	
	thread_cleanup();
	
	fftw_multithread_term();
}

void main_init_sqlstore() {
	if(isSqlDriver("mysql")) {
		if(opt_load_query_main_from_files != 2) {
			sqlStore = new FILE_LINE(42037) MySqlStore(mysql_host, mysql_user, mysql_password, mysql_database, opt_mysql_port, mysql_socket,
								   isCloud() ? cloud_host : NULL, cloud_token, cloud_router, &optMySsl);
			if(opt_save_query_main_to_files || 
			   opt_save_query_charts_to_files || 
			   opt_save_query_charts_remote_to_files) {
				sqlStore->queryToFiles(opt_save_query_main_to_files, opt_save_query_to_files_directory, opt_save_query_to_files_period, 
						       opt_save_query_charts_to_files, opt_save_query_charts_remote_to_files);
			}
			if(use_mysql_2()) {
				sqlStore_2 = new FILE_LINE(42038) MySqlStore(mysql_2_host, mysql_2_user, mysql_2_password, mysql_2_database, opt_mysql_2_port, mysql_2_socket,
									     NULL, NULL, false, &optMySsl_2);
				if(opt_save_query_main_to_files) {
					sqlStore_2->queryToFiles(opt_save_query_main_to_files, opt_save_query_to_files_directory, opt_save_query_to_files_period);
				}
			}
		}
		if(opt_load_query_main_from_files ||
		   opt_load_query_charts_from_files ||
		   opt_load_query_charts_remote_from_files) {
			loadFromQFiles = new FILE_LINE(42039) MySqlStore(mysql_host, mysql_user, mysql_password, mysql_database, opt_mysql_port, mysql_socket,
									 isCloud() ? cloud_host : NULL, cloud_token, cloud_router, &optMySsl);
			loadFromQFiles->loadFromQFiles(opt_load_query_main_from_files, opt_load_query_from_files_directory, opt_load_query_from_files_period,
						       opt_load_query_charts_from_files, opt_load_query_charts_remote_from_files);
		}
		if(opt_load_query_main_from_files != 2) {
			if(!opt_nocdr) {
				sqlStore->connect(STORE_PROC_ID_CDR, 0);
				sqlStore->connect(STORE_PROC_ID_MESSAGE, 0);
			}
			if(opt_mysqlstore_concat_limit) {
				sqlStore->setDefaultConcatLimit(opt_mysqlstore_concat_limit);
				if(sqlStore_2) {
					sqlStore_2->setDefaultConcatLimit(opt_mysqlstore_concat_limit);
				}
			}
			for(int i = 0; i < opt_mysqlstore_max_threads_cdr; i++) {
				if(opt_mysqlstore_concat_limit_cdr) {
					sqlStore->setConcatLimit(STORE_PROC_ID_CDR, i, opt_mysqlstore_concat_limit_cdr);
					if(opt_mysql_mysql_redirect_cdr_queue) {
						sqlStore->setConcatLimit(STORE_PROC_ID_CDR_REDIRECT, i, opt_mysqlstore_concat_limit_cdr);
						if(loadFromQFiles) {
							loadFromQFiles->setConcatLimit(STORE_PROC_ID_CDR_REDIRECT, i, opt_mysqlstore_concat_limit_cdr);
						}
					}
				}
				if(i) {
					sqlStore->setEnableAutoDisconnect(STORE_PROC_ID_CDR, i);
					if(opt_mysql_mysql_redirect_cdr_queue) {
						sqlStore->setEnableAutoDisconnect(STORE_PROC_ID_CDR_REDIRECT, i);
						if(loadFromQFiles) {
							loadFromQFiles->setEnableAutoDisconnect(STORE_PROC_ID_CDR_REDIRECT, i);
						}
					}
				}
				if(opt_mysql_enable_transactions_cdr) {
					sqlStore->setEnableTransaction(STORE_PROC_ID_CDR, i);
					if(opt_mysql_mysql_redirect_cdr_queue) {
						sqlStore->setEnableTransaction(STORE_PROC_ID_CDR_REDIRECT, i);
						if(loadFromQFiles) {
							loadFromQFiles->setEnableTransaction(STORE_PROC_ID_CDR_REDIRECT, i);
						}
					}
				}
				if(opt_cdr_check_duplicity_callid_in_next_pass_insert) {
					sqlStore->setEnableFixDeadlock(STORE_PROC_ID_CDR, i);
					if(opt_mysql_mysql_redirect_cdr_queue) {
						sqlStore->setEnableFixDeadlock(STORE_PROC_ID_CDR_REDIRECT, i);
						if(loadFromQFiles) {
							loadFromQFiles->setEnableFixDeadlock(STORE_PROC_ID_CDR_REDIRECT, i);
						}
					}
				}
				if(loadFromQFiles) {
					loadFromQFiles->setQueryBuffLimit(STORE_PROC_ID_CDR_REDIRECT, i, 10000);
				}
			}
			for(int i = 0; i < opt_mysqlstore_max_threads_message; i++) {
				if(opt_mysqlstore_concat_limit_message) {
					sqlStore->setConcatLimit(STORE_PROC_ID_MESSAGE, i, opt_mysqlstore_concat_limit_message);
				}
				if(i) {
					sqlStore->setEnableAutoDisconnect(STORE_PROC_ID_MESSAGE, i);
				}
				if(opt_mysql_enable_transactions_message) {
					sqlStore->setEnableTransaction(STORE_PROC_ID_MESSAGE, i);
				}
				if(opt_message_check_duplicity_callid_in_next_pass_insert) {
					sqlStore->setEnableFixDeadlock(STORE_PROC_ID_MESSAGE, i);
				}
			}
			for(int i = 0; i < opt_mysqlstore_max_threads_sip_msg; i++) {
				if(opt_mysqlstore_concat_limit_sip_msg) {
					sqlStore->setConcatLimit(STORE_PROC_ID_SIP_MSG, i, opt_mysqlstore_concat_limit_sip_msg);
				}
				if(i) {
					sqlStore->setEnableAutoDisconnect(STORE_PROC_ID_SIP_MSG, i);
				}
				if(opt_mysql_enable_transactions_sip_msg) {
					sqlStore->setEnableTransaction(STORE_PROC_ID_SIP_MSG, i);
				}
			}
			for(int i = 0; i < opt_mysqlstore_max_threads_register; i++) {
				if(opt_mysqlstore_concat_limit_register) {
					sqlStore->setConcatLimit(STORE_PROC_ID_REGISTER, i, opt_mysqlstore_concat_limit_register);
				}
				if(i) {
					sqlStore->setEnableAutoDisconnect(STORE_PROC_ID_REGISTER, i);
				}
				if(opt_mysql_enable_transactions_register) {
					sqlStore->setEnableTransaction(STORE_PROC_ID_REGISTER, i);
				}
			}
			MySqlStore *sqlStoreHttp = (MySqlStore*)sqlStore_http();
			for(int i = 0; i < opt_mysqlstore_max_threads_http; i++) {
				if(opt_mysqlstore_concat_limit_http) {
					sqlStoreHttp->setConcatLimit(STORE_PROC_ID_HTTP, i, opt_mysqlstore_concat_limit_http);
				}
				if(i) {
					sqlStoreHttp->setEnableAutoDisconnect(STORE_PROC_ID_HTTP, i);
				}
				if(opt_mysql_enable_transactions_http) {
					sqlStoreHttp->setEnableTransaction(STORE_PROC_ID_HTTP, i);
				}
			}
			for(int i = 0; i < opt_mysqlstore_max_threads_webrtc; i++) {
				if(opt_mysqlstore_concat_limit_webrtc) {
					sqlStore->setConcatLimit(STORE_PROC_ID_WEBRTC, i, opt_mysqlstore_concat_limit_webrtc);
				}
				if(i) {
					sqlStore->setEnableAutoDisconnect(STORE_PROC_ID_WEBRTC, i);
				}
				if(opt_mysql_enable_transactions_webrtc) {
					sqlStore->setEnableTransaction(STORE_PROC_ID_WEBRTC, i);
				}
			}
			if(opt_mysqlstore_concat_limit_ipacc) {
				for(int i = 0; i < opt_mysqlstore_max_threads_ipacc_base; i++) {
					sqlStore->setConcatLimit(STORE_PROC_ID_IPACC, i, opt_mysqlstore_concat_limit_ipacc);
				}
				for(int i = STORE_PROC_ID_IPACC_AGR_INTERVAL; i <= STORE_PROC_ID_IPACC_AGR_DAY; i++) {
					sqlStore->setConcatLimit(i, 0, opt_mysqlstore_concat_limit_ipacc);
				}
				for(int i = 0; i < opt_mysqlstore_max_threads_ipacc_agreg2; i++) {
					sqlStore->setConcatLimit(STORE_PROC_ID_IPACC_AGR2_HOUR, i, opt_mysqlstore_concat_limit_ipacc);
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
	if(!isCloud() && is_server() && !is_read_from_file_simple()) {
		snifferServerSetSqlStore(sqlStore);
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
			if(tcpReassemblyDiameter) {
				tcpReassemblyDiameter->setIgnoreTerminating(false);
			}
			sleep(2);
		}
		if(pcapQueueQ) {
			pcapQueueQ->terminate();
		}
		if(pcapQueueQ_outThread_detach) {
			pcapQueueQ_outThread_detach->terminate();
		}
		if(pcapQueueQ_outThread_defrag) {
			pcapQueueQ_outThread_defrag->terminate();
		}
		if(pcapQueueQ_outThread_dedup) {
			pcapQueueQ_outThread_dedup->terminate();
		}
		if(pcapQueueQ_outThread_detach2) {
			pcapQueueQ_outThread_detach2->terminate();
		}
		sleep(1);
		
		terminate_processpacket();
		
		if(pcapQueueI) {
			delete pcapQueueI;
			pcapQueueI = NULL;
		}
		if(pcapQueueQ_outThread_detach) {
			delete pcapQueueQ_outThread_detach;
			pcapQueueQ_outThread_detach = NULL;
		}
		if(pcapQueueQ_outThread_defrag) {
			delete pcapQueueQ_outThread_defrag;
			pcapQueueQ_outThread_defrag = NULL;
		}
		if(pcapQueueQ_outThread_dedup) {
			delete pcapQueueQ_outThread_dedup;
			pcapQueueQ_outThread_dedup = NULL;
		}
		if(pcapQueueQ_outThread_detach2) {
			delete pcapQueueQ_outThread_detach2;
			pcapQueueQ_outThread_detach2 = NULL;
		}
		if(pcapQueueQ) {
			delete pcapQueueQ;
			pcapQueueQ = NULL;
		}
	}
}


#ifndef FREEBSD
extern unsigned int HeapSafeCheck;
extern "C"{
void __cyg_profile_func_enter(void *this_fn, void *call_site) __attribute__((no_instrument_function));
void __cyg_profile_func_enter(void *this_fn, void *call_site) {
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
void __cyg_profile_func_exit(void *this_fn, void */*call_site*/) {
	if(!MCB_STACK ||
	   this_fn == syscall || this_fn == get_unix_tid) {
		return;
	}
	unsigned tid = get_unix_tid();
	extern u_int16_t threadStackSize[65536];
	--threadStackSize[tid];
}
}
#endif


// CONFIGURATION

void cConfig::addConfigItems() {
	group("sql");
		subgroup("read only");
			addConfigItem((new FILE_LINE(42068) cConfigItem_string("sqldriver", sql_driver, sizeof(sql_driver)))
				->setReadOnly());
			addConfigItem((new FILE_LINE(42069) cConfigItem_string("mysqlhost", mysql_host, sizeof(mysql_host)))
				->setReadOnly());
			addConfigItem((new FILE_LINE(42070) cConfigItem_integer("mysqlport",  &opt_mysql_port))
				->setSubtype("port")
				->setReadOnly());
			addConfigItem((new FILE_LINE(0) cConfigItem_string("mysqlsocket", mysql_socket, sizeof(mysql_socket)))
				->setReadOnly());
			addConfigItem((new FILE_LINE(42071) cConfigItem_string("mysqlusername", mysql_user, sizeof(mysql_user)))
				->setReadOnly());
			addConfigItem((new FILE_LINE(42072) cConfigItem_string("mysqlpassword", mysql_password, sizeof(mysql_password)))
				->setPassword()
				->setReadOnly()
				->setMinor());
			addConfigItem((new FILE_LINE(0) cConfigItem_string("mysqlsslkey", optMySsl.key, sizeof(optMySsl.key)))
				->setReadOnly());
			addConfigItem((new FILE_LINE(0) cConfigItem_string("mysqlsslcert", optMySsl.cert, sizeof(optMySsl.cert)))
				->setReadOnly());
			addConfigItem((new FILE_LINE(0) cConfigItem_string("mysqlsslcacert", optMySsl.caCert, sizeof(optMySsl.caCert)))
				->setReadOnly());
			addConfigItem((new FILE_LINE(0) cConfigItem_string("mysqlsslcapath", optMySsl.caPath, sizeof(optMySsl.caPath)))
				->setReadOnly());
			addConfigItem((new FILE_LINE(0) cConfigItem_string("mysqlsslciphers", &optMySsl.ciphers))
				->setReadOnly());
				advanced();
				addConfigItem((new FILE_LINE(42073) cConfigItem_string("mysqlhost_2", mysql_2_host, sizeof(mysql_2_host)))
					->setReadOnly());
				addConfigItem((new FILE_LINE(42074) cConfigItem_integer("mysqlport_2",  &opt_mysql_2_port))
					->setSubtype("port")
					->setReadOnly());
				addConfigItem((new FILE_LINE(0) cConfigItem_string("mysqlsocket_2", mysql_2_socket, sizeof(mysql_2_socket)))
					->setReadOnly());
				addConfigItem((new FILE_LINE(42075) cConfigItem_string("mysqlusername_2", mysql_2_user, sizeof(mysql_2_user)))
					->setReadOnly());
				addConfigItem((new FILE_LINE(42076) cConfigItem_string("mysqlpassword_2", mysql_2_password, sizeof(mysql_2_password)))
					->setPassword()
					->setReadOnly()
					->setMinor());
				addConfigItem((new FILE_LINE(0) cConfigItem_string("mysqlsslkey_2", optMySsl_2.key, sizeof(optMySsl_2.key)))
					->setReadOnly());
				addConfigItem((new FILE_LINE(0) cConfigItem_string("mysqlsslcert_2", optMySsl_2.cert, sizeof(optMySsl_2.cert)))
					->setReadOnly());
				addConfigItem((new FILE_LINE(0) cConfigItem_string("mysqlsslcacert_2", optMySsl_2.caCert, sizeof(optMySsl_2.caCert)))
					->setReadOnly());
				addConfigItem((new FILE_LINE(0) cConfigItem_string("mysqlsslcapath_2", optMySsl_2.caPath, sizeof(optMySsl_2.caPath)))
					->setReadOnly());
				addConfigItem((new FILE_LINE(0) cConfigItem_string("mysqlsslciphers_2", &optMySsl_2.ciphers))
					->setReadOnly());
				addConfigItem(new FILE_LINE(42077) cConfigItem_yesno("mysql_2_http",  &opt_mysql_2_http));
					expert();
					addConfigItem((new FILE_LINE(0) cConfigItem_string("mysqldatadir", &mysql_datadir))
						->setReadOnly());
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("alter_rows_limit", &opt_alter_rows_limit));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("mysql_security_invoker_routines", &opt_mysql_security_invoker_routines));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sql_log_all_errors", &opt_sql_log_all_errors));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("sql_errors_log_file", &opt_sql_errors_log_file));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("sql_errors_skip", opt_sql_errors_skip, sizeof(opt_sql_errors_skip)));
		subgroup("main");
			addConfigItem((new FILE_LINE(42078) cConfigItem_yesno("query_cache"))
				->setDefaultValueStr("yes"));
				advanced();
				addConfigItem((new FILE_LINE(0) cConfigItem_yesno("query_cache_charts"))
					->setDefaultValueStr("yes"));
				addConfigItem((new FILE_LINE(0) cConfigItem_yesno("query_cache_charts_remote"))
					->setDefaultValueStr("no"));
				addConfigItem(new FILE_LINE(42079) cConfigItem_yesno("query_cache_speed", &opt_query_cache_speed));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("query_cache_check_utf", &opt_query_cache_check_utf));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("query_cache_max_mb_utf", &opt_query_cache_max_mb_utf));
			normal();
			addConfigItem((new FILE_LINE(42080) cConfigItem_yesno("utc", &opt_sql_time_utc))
				->addAlias("sql_time_utc"));
				advanced();
				addConfigItem(new FILE_LINE(42081) cConfigItem_yesno("disable_dbupgradecheck", &opt_disable_dbupgradecheck));
				addConfigItem(new FILE_LINE(42082) cConfigItem_yesno("only_cdr_next", &opt_only_cdr_next));
				addConfigItem(new FILE_LINE(42083) cConfigItem_yesno("check_duplicity_callid_in_next_pass_insert", &opt_cdr_check_duplicity_callid_in_next_pass_insert));
				addConfigItem(new FILE_LINE(42084) cConfigItem_yesno("cdr_check_duplicity_callid_in_next_pass_insert", &opt_cdr_check_duplicity_callid_in_next_pass_insert));
				addConfigItem(new FILE_LINE(42085) cConfigItem_yesno("message_check_duplicity_callid_in_next_pass_insert", &opt_message_check_duplicity_callid_in_next_pass_insert));
				addConfigItem(new FILE_LINE(42086) cConfigItem_string("mysql_timezone", opt_mysql_timezone, sizeof(opt_mysql_timezone)));
				addConfigItem(new FILE_LINE(42087) cConfigItem_yesno("autoload_from_sqlvmexport", &opt_autoload_from_sqlvmexport));
				expert();
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("mysql_connect_timeout", &opt_mysql_connect_timeout));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("mysql_reconnect", &opt_mysql_reconnect));
					addConfigItem(new FILE_LINE(42088) cConfigItem_yesno("mysqlcompress", &opt_mysqlcompress));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("mysqlcompress_type", opt_mysqlcompress_type, sizeof(opt_mysqlcompress_type)));
					addConfigItem(new FILE_LINE(42089) cConfigItem_yesno("sqlcallend", &opt_callend));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("disable_cdr_fields_rtp", &opt_disable_cdr_fields_rtp));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("disable_cdr_indexes_rtp", &opt_disable_cdr_indexes_rtp));
					addConfigItem((new FILE_LINE(42090) cConfigItem_yesno("t2_boost", &opt_t2_boost))
						->addValues("high_traffic:2")
						->addAlias("threading_expanded"));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("t2_boost_direct_rtp", &opt_t2_boost_direct_rtp));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("t2_boost_direct_rtp_delay_ms"));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("t2_boost_direct_rtp_delay_queue_ms", &opt_t2_boost_direct_rtp_delay_queue_ms));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("t2_boost_direct_rtp_max_queue_length_ms", &opt_t2_boost_direct_rtp_max_queue_length_ms));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("t2_boost_enable_call_find_threads", &opt_t2_boost_call_find_threads));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("t2_boost_max_next_call_threads", &opt_t2_boost_call_threads));
					addConfigItem((new FILE_LINE(0) cConfigItem_yesno("t2_boost_pb_detach_thread", &opt_t2_boost_pb_detach_thread))
						->addValues("two:2"));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("t2_boost_pcap_dispatch", &opt_t2_boost_pcap_dispatch));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("storing_cdr_max_next_threads", &opt_storing_cdr_max_next_threads));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("storing_cdr_maximum_cdr_per_iteration", &opt_storing_cdr_maximum_cdr_per_iteration));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("processing_limitations", &opt_processing_limitations));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("processing_limitations_heap_high_limit", &opt_processing_limitations_heap_high_limit));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("processing_limitations_heap_low_limit", &opt_processing_limitations_heap_low_limit));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("processing_limitations_active_calls_cache", &opt_processing_limitations_active_calls_cache));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("processing_limitations_active_calls_cache_type", &opt_processing_limitations_active_calls_cache_type));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("processing_limitations_active_calls_cache_timeout_min", &opt_processing_limitations_active_calls_cache_timeout_min));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("processing_limitations_active_calls_cache_timeout_max", &opt_processing_limitations_active_calls_cache_timeout_max));
		subgroup("partitions");
			addConfigItem(new FILE_LINE(42091) cConfigItem_yesno("disable_partition_operations", &opt_disable_partition_operations));
			addConfigItem(new FILE_LINE(0) cConfigItem_hour_interval("partition_operations_enable_fromto", &opt_partition_operations_enable_run_hour_from, &opt_partition_operations_enable_run_hour_to));
				advanced();
				addConfigItem(new FILE_LINE(42092) cConfigItem_yesno("partition_operations_in_thread", &opt_partition_operations_in_thread));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("partition_operations_drop_first", &opt_partition_operations_drop_first));
					expert();
					addConfigItem(new FILE_LINE(42093) cConfigItem_integer("create_old_partitions"));
					addConfigItem(new FILE_LINE(42094) cConfigItem_string("create_old_partitions_from", opt_create_old_partitions_from, sizeof(opt_create_old_partitions_from)));
		subgroup("scale");
				advanced();
				addConfigItem(new FILE_LINE(42095) cConfigItem_integer("mysqlstore_concat_limit", &opt_mysqlstore_concat_limit));
				addConfigItem(new FILE_LINE(42096) cConfigItem_integer("mysqlstore_concat_limit_cdr", &opt_mysqlstore_concat_limit_cdr));
				addConfigItem(new FILE_LINE(42097) cConfigItem_integer("mysqlstore_concat_limit_message", &opt_mysqlstore_concat_limit_message));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("mysqlstore_concat_limit_sip_msg", &opt_mysqlstore_concat_limit_sip_msg));
				addConfigItem(new FILE_LINE(42098) cConfigItem_integer("mysqlstore_concat_limit_register", &opt_mysqlstore_concat_limit_register));
				addConfigItem(new FILE_LINE(42099) cConfigItem_integer("mysqlstore_concat_limit_http", &opt_mysqlstore_concat_limit_http));
				addConfigItem(new FILE_LINE(42100) cConfigItem_integer("mysqlstore_concat_limit_webrtc", &opt_mysqlstore_concat_limit_webrtc));
				addConfigItem(new FILE_LINE(42101) cConfigItem_integer("mysqlstore_concat_limit_ipacc", &opt_mysqlstore_concat_limit_ipacc));
				addConfigItem((new FILE_LINE(42102) cConfigItem_integer("mysqlstore_max_threads_cdr", &opt_mysqlstore_max_threads_cdr))
					->setMaximum(99)->setMinimum(1));
				addConfigItem((new FILE_LINE(42103) cConfigItem_integer("mysqlstore_max_threads_message", &opt_mysqlstore_max_threads_message))
					->setMaximum(99)->setMinimum(1));
				addConfigItem((new FILE_LINE(0) cConfigItem_integer("mysqlstore_max_threads_sip_msg", &opt_mysqlstore_max_threads_sip_msg))
					->setMaximum(99)->setMinimum(1));
				addConfigItem((new FILE_LINE(42104) cConfigItem_integer("mysqlstore_max_threads_register", &opt_mysqlstore_max_threads_register))
					->setMaximum(99)->setMinimum(1));
				addConfigItem((new FILE_LINE(42105) cConfigItem_integer("mysqlstore_max_threads_http", &opt_mysqlstore_max_threads_http))
					->setMaximum(99)->setMinimum(1));
				addConfigItem((new FILE_LINE(42106) cConfigItem_integer("mysqlstore_max_threads_webrtc", &opt_mysqlstore_max_threads_webrtc))
					->setMaximum(99)->setMinimum(1));
				addConfigItem((new FILE_LINE(42107) cConfigItem_integer("mysqlstore_max_threads_ipacc_base", &opt_mysqlstore_max_threads_ipacc_base))
					->setMaximum(99)->setMinimum(1));
				addConfigItem((new FILE_LINE(42108) cConfigItem_integer("mysqlstore_max_threads_ipacc_agreg2", &opt_mysqlstore_max_threads_ipacc_agreg2))
					->setMaximum(99)->setMinimum(1));
				addConfigItem((new FILE_LINE(42108) cConfigItem_integer("mysqlstore_max_threads_charts_cache", &opt_mysqlstore_max_threads_charts_cache))
					->setMaximum(99)->setMinimum(1));
				addConfigItem(new FILE_LINE(42109) cConfigItem_integer("mysqlstore_limit_queue_register", &opt_mysqlstore_limit_queue_register));
				addConfigItem(new FILE_LINE(42110) cConfigItem_yesno("mysqltransactions", &opt_mysql_enable_transactions));
				addConfigItem(new FILE_LINE(42111) cConfigItem_yesno("mysqltransactions_cdr", &opt_mysql_enable_transactions_cdr));
				addConfigItem(new FILE_LINE(42112) cConfigItem_yesno("mysqltransactions_message", &opt_mysql_enable_transactions_message));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("mysqltransactions_sip_msg", &opt_mysql_enable_transactions_sip_msg));
				addConfigItem(new FILE_LINE(42113) cConfigItem_yesno("mysqltransactions_register", &opt_mysql_enable_transactions_register));
				addConfigItem(new FILE_LINE(42114) cConfigItem_yesno("mysqltransactions_http", &opt_mysql_enable_transactions_http));
				addConfigItem(new FILE_LINE(42115) cConfigItem_yesno("mysqltransactions_webrtc", &opt_mysql_enable_transactions_webrtc));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("mysql_enable_multiple_rows_insert", &opt_mysql_enable_multiple_rows_insert));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("mysql_max_multiple_rows_insert", &opt_mysql_max_multiple_rows_insert));
				addConfigItem((new FILE_LINE(0) cConfigItem_yesno("mysql_enable_new_store", &opt_mysql_enable_new_store))
					->addValues("per_query:2"));
					expert();
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("mysql_enable_set_id", &opt_mysql_enable_set_id));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("csv_store_format", &opt_csv_store_format));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("mysql_redirect_cdr_queue", &opt_mysql_mysql_redirect_cdr_queue));
		subgroup("cleaning");
			addConfigItem(new FILE_LINE(42116) cConfigItem_integer("cleandatabase"));
			addConfigItem(new FILE_LINE(42117) cConfigItem_integer("cleandatabase_cdr", &opt_cleandatabase_cdr));
			addConfigItem(new FILE_LINE(42117) cConfigItem_integer("cleandatabase_cdr_rtp_energylevels", &opt_cleandatabase_cdr_rtp_energylevels));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_ss7", &opt_cleandatabase_ss7));
			addConfigItem(new FILE_LINE(42118) cConfigItem_integer("cleandatabase_http_enum", &opt_cleandatabase_http_enum));
			addConfigItem(new FILE_LINE(42119) cConfigItem_integer("cleandatabase_webrtc", &opt_cleandatabase_webrtc));
			addConfigItem(new FILE_LINE(42120) cConfigItem_integer("cleandatabase_register_state", &opt_cleandatabase_register_state));
			addConfigItem(new FILE_LINE(42121) cConfigItem_integer("cleandatabase_register_failed", &opt_cleandatabase_register_failed));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_register_time_info", &opt_cleandatabase_register_time_info));
			addConfigItem(new FILE_LINE(42121) cConfigItem_integer("cleandatabase_sip_msg", &opt_cleandatabase_sip_msg));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_cdr_stat", &opt_cleandatabase_cdr_stat));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_cdr_problems", &opt_cleandatabase_cdr_problems));
			addConfigItem(new FILE_LINE(42122) cConfigItem_integer("cleandatabase_rtp_stat", &opt_cleandatabase_rtp_stat));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_log_sensor", &opt_cleandatabase_log_sensor));
				advanced();
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_size", &opt_cleandatabase_size));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_min_free_size", &opt_cleandatabase_min_free_size));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_cdr_size", &opt_cleandatabase_cdr_size));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_cdr_rtp_energylevels_size", &opt_cleandatabase_cdr_rtp_energylevels_size));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_ss7_size", &opt_cleandatabase_ss7_size));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_http_enum_size", &opt_cleandatabase_http_enum_size));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_webrtc_size", &opt_cleandatabase_webrtc_size));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_register_state_size", &opt_cleandatabase_register_state_size));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_register_failed_size", &opt_cleandatabase_register_failed_size));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_register_time_info_size", &opt_cleandatabase_register_time_info_size));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_sip_msg_size", &opt_cleandatabase_sip_msg_size));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_cdr_stat_size", &opt_cleandatabase_cdr_stat_size));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_cdr_problems_size", &opt_cleandatabase_cdr_problems_size));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_rtp_stat_size", &opt_cleandatabase_rtp_stat_size));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_log_sensor_size", &opt_cleandatabase_log_sensor_size));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleandatabase_size_period", &opt_cleandatabase_size_period));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("cleandatabase_size_force", &opt_cleandatabase_size_force));
		subgroup("backup");
				advanced();
				addConfigItem(new FILE_LINE(42123) cConfigItem_string("database_backup_from_date", opt_database_backup_from_date, sizeof(opt_database_backup_from_date)));
				addConfigItem(new FILE_LINE(42123) cConfigItem_string("database_backup_to_date", opt_database_backup_to_date, sizeof(opt_database_backup_to_date)));
				addConfigItem(new FILE_LINE(42124) cConfigItem_string("database_backup_from_mysqlhost", opt_database_backup_from_mysql_host, sizeof(opt_database_backup_from_mysql_host)));
				addConfigItem(new FILE_LINE(42125) cConfigItem_string("database_backup_from_mysqldb", opt_database_backup_from_mysql_database, sizeof(opt_database_backup_from_mysql_database)));
				addConfigItem(new FILE_LINE(42126) cConfigItem_string("database_backup_from_mysqlusername", opt_database_backup_from_mysql_user, sizeof(opt_database_backup_from_mysql_user)));
				addConfigItem(new FILE_LINE(42127) cConfigItem_string("database_backup_from_mysqlpassword", opt_database_backup_from_mysql_password, sizeof(opt_database_backup_from_mysql_password)));
				addConfigItem(new FILE_LINE(42128) cConfigItem_integer("database_backup_from_mysqlport", &opt_database_backup_from_mysql_port));
				addConfigItem(new FILE_LINE(42127) cConfigItem_string("database_backup_from_mysqlsocket", opt_database_backup_from_mysql_socket, sizeof(opt_database_backup_from_mysql_socket)));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("database_backup_from_mysqlsslkey", optMySSLBackup.key, sizeof(optMySSLBackup.key)));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("database_backup_from_mysqlsslcert", optMySSLBackup.cert, sizeof(optMySSLBackup.cert)));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("database_backup_from_mysqlsslcacert", optMySSLBackup.caCert, sizeof(optMySSLBackup.caCert)));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("database_backup_from_mysqlsslcapath", optMySSLBackup.caPath, sizeof(optMySSLBackup.caPath)));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("database_backup_from_mysqlsslciphers", &optMySSLBackup.ciphers));
				addConfigItem(new FILE_LINE(42129) cConfigItem_integer("database_backup_pause", &opt_database_backup_pause));
				addConfigItem(new FILE_LINE(42130) cConfigItem_integer("database_backup_insert_threads", &opt_database_backup_insert_threads));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("database_backup_cleandatabase", &opt_database_backup_cleandatabase));
					expert();
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("database_backup_pass_rows", &opt_database_backup_pass_rows));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("database_backup_desc_dir", &opt_database_backup_desc_dir));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("database_backup_skip_register", &opt_database_backup_skip_register));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("database_backup_check_src_tables", &opt_database_backup_check_src_tables));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("database_backup_merge_reference_tables", &opt_database_backup_merge_reference_tables));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("database_backup_slave_record_safe_gap", &opt_database_backup_slave_record_safe_gap));
	group("sniffer mode");
		// SNIFFER MODE
		subgroup("main");
			cConfigItem_integer *snifferMode = new FILE_LINE(42131) cConfigItem_integer("sniffer_mode", (int*)&sniffer_mode);
			snifferMode
				->setMenuValue()
				->setOnlyMenu()
				->addValues("reading from interfaces or receive from mirrors:1|read from files:2|mirror packets to another sniffer:3")
				->setDefaultValueStr(snifferMode_read_from_interface_str.c_str())
				->setAlwaysShow();
			addConfigItem(snifferMode);
			setDisableIfBegin("sniffer_mode!" + snifferMode_read_from_interface_str);
			addConfigItem(new FILE_LINE(42132) cConfigItem_string("interface", ifname, sizeof(ifname)));
				advanced();
				addConfigItem(new FILE_LINE(0) cConfigItem_dstrings("interface_libpcap_filter", &ifname_libpcap_filter));
				addConfigItem(new FILE_LINE(0) cConfigItem_hosts("interface_ip_filter", &if_filter_ip, &if_filter_net));
					expert();
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("interface_ip_filter_quick", &opt_if_filter_ip_quick));
				advanced();
				addConfigItem(new FILE_LINE(42133) cConfigItem_yesno("use_oneshot_buffer", &opt_use_oneshot_buffer));
				addConfigItem(new FILE_LINE(42134) cConfigItem_integer("snaplen", &opt_snaplen));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("interfaces_optimize", &opt_ifaces_optimize));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("eth_max_channels", &opt_eth_max_channels));
					expert();
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("libpcap_immediate_mode", &opt_libpcap_immediate_mode));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("libpcap_nonblock_mode", &opt_libpcap_nonblock_mode));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("dpdk", &opt_use_dpdk));
					addConfigItem((new FILE_LINE(0) cConfigItem_yesno("dpdk_init", &opt_dpdk_init))
						->disableYes()
						->disableNo()
						->addValues("main:0|separate:1|read:2")
						->setDefaultValueStr("main"));
					addConfigItem((new FILE_LINE(0) cConfigItem_yesno("dpdk_read_thread", &opt_dpdk_read_thread))
						->disableYes()
						->disableNo()
						->addValues("std:1|rte:2")
						->setDefaultValueStr("rte"));
					addConfigItem((new FILE_LINE(0) cConfigItem_yesno("dpdk_worker_thread", &opt_dpdk_worker_thread))
						->addValues("std:1|rte:2")
						->setDefaultValueStr("rte"));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("dpdk_worker_slave_thread", &opt_dpdk_worker_slave_thread));
					addConfigItem((new FILE_LINE(0) cConfigItem_yesno("dpdk_worker2_thread", &opt_dpdk_worker2_thread))
						->addValues("rte:1")
						->setDefaultValueStr("no"));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("dpdk_iterations_per_call", &opt_dpdk_iterations_per_call));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("dpdk_read_usleep_if_no_packet", &opt_dpdk_read_usleep_if_no_packet));
					addConfigItem((new FILE_LINE(0) cConfigItem_yesno("dpdk_read_usleep_type", &opt_dpdk_read_usleep_type))
						->disableYes()
						->disableNo()
						->addValues("std:0|rte:1|pause:2")
						->setDefaultValueStr("std"));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("dpdk_worker_usleep_if_no_packet", &opt_dpdk_worker_usleep_if_no_packet));
					addConfigItem((new FILE_LINE(0) cConfigItem_yesno("dpdk_worker_usleep_type", &opt_dpdk_worker_usleep_type))
						->disableYes()
						->disableNo()
						->addValues("std:0|rte:1|pause:2")
						->setDefaultValueStr("std"));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("dpdk_nb_rx", &opt_dpdk_nb_rx));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("dpdk_nb_tx", &opt_dpdk_nb_tx));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("dpdk_nb_rxq", &opt_dpdk_nb_rxq));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("dpdk_nb_rxq_rss", &opt_dpdk_nb_rxq_rss));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("dpdk_nb_mbufs", &opt_dpdk_nb_mbufs));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("dpdk_nb_mbufs_strictly", &opt_dpdk_nb_mbufs_strictly));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("dpdk_pkt_burst", &opt_dpdk_pkt_burst));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("dpdk_ring_size", &opt_dpdk_ring_size));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("dpdk_mempool_cache_size", &opt_dpdk_mempool_cache_size));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("dpdk_zc", &opt_dpdk_zc));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("dpdk_mbufs_in_packetbuffer", &opt_dpdk_mbufs_in_packetbuffer));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("dpdk_prealloc_packetbuffer", &opt_dpdk_prealloc_packetbuffer));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("dpdk_defer_send_packetbuffer", &opt_dpdk_defer_send_packetbuffer));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("dpdk_rotate_packetbuffer", &opt_dpdk_rotate_packetbuffer));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("dpdk_rotate_packetbuffer_pool_max_perc", &opt_dpdk_rotate_packetbuffer_pool_max_perc));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("dpdk_copy_packetbuffer", &opt_dpdk_copy_packetbuffer));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("dpdk_batch_read", &opt_dpdk_batch_read));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("dpdk_cpu_affinity", &opt_dpdk_cpu_cores));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("dpdk_lcores_affinity", &opt_dpdk_cpu_cores_map));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("dpdk_main_thread_cpu_affinity", &opt_dpdk_main_thread_lcore));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("dpdk_read_thread_cpu_affinity", &opt_dpdk_read_thread_lcore));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("dpdk_worker_thread_cpu_affinity", &opt_dpdk_worker_thread_lcore));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("dpdk_worker2_thread_cpu_affinity", &opt_dpdk_worker2_thread_lcore));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("dpdk_memory_channels", &opt_dpdk_memory_channels));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("dpdk_pci_device", &opt_dpdk_pci_device));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("dpdk_force_max_simd_bitwidth", &opt_dpdk_force_max_simd_bitwidth));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("thread_affinity", &opt_cpu_cores));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("thread_affinity_ht", &opt_thread_affinity_ht));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("other_thread_affinity_check", &opt_other_thread_affinity_check));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("other_thread_affinity_set", &opt_other_thread_affinity_set));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("dpdk_timer_reset_interval", &opt_dpdk_timer_reset_interval));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("dpdk_mtu", &opt_dpdk_mtu));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("dpdk_vdev", &opt_dpdk_vdev));
			normal();
			addConfigItem(new FILE_LINE(42135) cConfigItem_yesno("promisc", &opt_promisc));
			addConfigItem(new FILE_LINE(42136) cConfigItem_string("filter", user_filter, sizeof(user_filter)));
			addConfigItem(new FILE_LINE(42137) cConfigItem_ip_port("mirror_bind", &opt_pcap_queue_receive_from_ip_port));
			addConfigItem((new FILE_LINE(42138) cConfigItem_string("mirror_bind_ip"))
				->setNaDefaultValueStr()
				->setMinor());
			addConfigItem((new FILE_LINE(42139) cConfigItem_integer("mirror_bind_port"))
				->setNaDefaultValueStr()
				->setSubtype("port")
				->setMinor());
					expert();
					addConfigItem(new FILE_LINE(42140) cConfigItem_integer("mirror_bind_dlt", &opt_pcap_queue_receive_dlt));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("mirror_bind_sensor_id_by_sender", &opt_pcap_queue_receive_sensor_id_by_sender));
			normal();
			setDisableIfBegin("sniffer_mode!" + snifferMode_read_from_files_str);
			addConfigItem(new FILE_LINE(42141) cConfigItem_string("scanpcapdir", opt_scanpcapdir, sizeof(opt_scanpcapdir)));
			setDisableIfBegin("sniffer_mode!" + snifferMode_sender_str);
			addConfigItem(new FILE_LINE(42142) cConfigItem_ip_port("mirror_destination", &opt_pcap_queue_send_to_ip_port));
			addConfigItem((new FILE_LINE(42143) cConfigItem_string("mirror_destination_ip"))
				->setNaDefaultValueStr()
				->setMinor());
			addConfigItem((new FILE_LINE(42144) cConfigItem_integer("mirror_destination_port"))
				->setNaDefaultValueStr()
				->setMinor());
			setDisableIfBegin("sniffer_mode=" + snifferMode_read_from_files_str);
			addConfigItem(new FILE_LINE(42145) cConfigItem_yesno("mirror_nonblock_mode", &opt_pcap_queues_mirror_nonblock_mode));
			addConfigItem((new FILE_LINE(42146) cConfigItem_yesno("mirror_require_confirmation", &opt_pcap_queues_mirror_require_confirmation))
				->addAlias("packetbuffer_sender_require_confirmation"));
			addConfigItem(new FILE_LINE(42147) cConfigItem_yesno("mirror_use_checksum", &opt_pcap_queues_mirror_use_checksum));
			setDisableIfEnd();
				advanced();
				addConfigItem(new FILE_LINE(42148) cConfigItem_string("capture_rules_telnum_file", opt_capture_rules_telnum_file, sizeof(opt_capture_rules_telnum_file)));
				addConfigItem(new FILE_LINE(42148) cConfigItem_string("capture_rules_sip_header_file", opt_capture_rules_sip_header_file, sizeof(opt_capture_rules_sip_header_file)));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("detect_alone_bye", &opt_detect_alone_bye));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("time_precision_in_ms", &opt_time_precision_in_ms));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("mirror_connect_maximum_time_diff_s", &opt_mirror_connect_maximum_time_diff_s));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("livesniffer_timeout_s", &opt_livesniffer_timeout_s));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("livesniffer_tablesize_max_mb", &opt_livesniffer_tablesize_max_mb));
					#if EXPERIMENTAL_SEPARATE_PROCESSSING
					expert();
					addConfigItem((new FILE_LINE(0) cConfigItem_yesno("separate_processing", &opt_separate_processing))
						->addValues("sip:1|rtp:2"));
					#endif
		subgroup("scaling");
			setDisableIfBegin("sniffer_mode!" + snifferMode_read_from_interface_str);
			addConfigItem((new FILE_LINE(42149) cConfigItem_yesno("threading_mod"))
				->disableNo()
				->addValues("1:1|2:2|3:3|4:4|5:5|6:6")
				->setDefaultValueStr("4"));
				advanced();
				addConfigItem((new FILE_LINE(42150) cConfigItem_integer("preprocess_rtp_threads", &opt_enable_process_rtp_packet))
					->setMaximum(MAX_PROCESS_RTP_PACKET_THREADS)
					->addValues("yes:1|y:1|no:0|n:0")
					->addAlias("enable_process_rtp_packet"));
					expert();
					addConfigItem((new FILE_LINE(0) cConfigItem_integer("preprocess_rtp_threads_max", &opt_enable_process_rtp_packet_max))
						->setMaximum(MAX_PROCESS_RTP_PACKET_THREADS));
					addConfigItem((new FILE_LINE(42151) cConfigItem_yesno("enable_preprocess_packet", &opt_enable_preprocess_packet))
						->addValues(("sip:2|extend:"+intToString(PreProcessPacket::ppt_end_base)+"|auto:-1").c_str()));
					addConfigItem(new FILE_LINE(42152) cConfigItem_integer("preprocess_packets_qring_length", &opt_preprocess_packets_qring_length));
					addConfigItem(new FILE_LINE(42153) cConfigItem_integer("preprocess_packets_qring_item_length", &opt_preprocess_packets_qring_item_length));
					addConfigItem(new FILE_LINE(42154) cConfigItem_integer("preprocess_packets_qring_usleep", &opt_preprocess_packets_qring_usleep));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("preprocess_packets_qring_push_usleep", &opt_preprocess_packets_qring_push_usleep));
					addConfigItem(new FILE_LINE(42155) cConfigItem_yesno("preprocess_packets_qring_force_push", &opt_preprocess_packets_qring_force_push));
					addConfigItem((new FILE_LINE(0) cConfigItem_integer("pre_process_packets_next_thread", &opt_pre_process_packets_next_thread))
						->setMaximum(MAX_PRE_PROCESS_PACKET_NEXT_THREADS)
						->addValues("yes:1|y:1|no:0|n:0"));
					#if not CALLX_MOD_OLDVER
					addConfigItem((new FILE_LINE(0) cConfigItem_integer("pre_process_packets_next_thread_find_call", &opt_pre_process_packets_next_thread_find_call))
						->setMaximum(MAX_PRE_PROCESS_PACKET_NEXT_THREADS)
						->addValues("yes:1|y:1|no:0|n:0"));
					addConfigItem((new FILE_LINE(0) cConfigItem_integer("pre_process_packets_next_thread_process_call", &opt_pre_process_packets_next_thread_process_call))
						->setMaximum(MAX_PRE_PROCESS_PACKET_NEXT_THREADS)
						->addValues("yes:1|y:1|no:0|n:0"));
					#endif
					addConfigItem((new FILE_LINE(0) cConfigItem_integer("pre_process_packets_next_thread_detach", &opt_pre_process_packets_next_thread_detach))
						->setMaximum(MAX_PRE_PROCESS_PACKET_NEXT_THREADS)
						->addValues("yes:1|y:1|no:0|n:0"));
					addConfigItem((new FILE_LINE(0) cConfigItem_integer("pre_process_packets_next_thread_detach2", &opt_pre_process_packets_next_thread_detach2))
						->setMaximum(MAX_PRE_PROCESS_PACKET_NEXT_THREADS)
						->addValues("yes:1|y:1|no:0|n:0"));
					addConfigItem((new FILE_LINE(0) cConfigItem_integer("pre_process_packets_next_thread_defrag", &opt_pre_process_packets_next_thread_defrag))
						->setMaximum(MAX_PRE_PROCESS_PACKET_NEXT_THREADS)
						->addValues("yes:1|y:1|no:0|n:0"));
					addConfigItem((new FILE_LINE(0) cConfigItem_integer("pre_process_packets_next_thread_max", &opt_pre_process_packets_next_thread_max))
						->setMaximum(MAX_PRE_PROCESS_PACKET_NEXT_THREADS));
					addConfigItem((new FILE_LINE(42156) cConfigItem_integer("process_rtp_packets_hash_next_thread", &opt_process_rtp_packets_hash_next_thread))
						->setMaximum(MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS)
						->addValues("yes:1|y:1|no:0|n:0"));
					addConfigItem((new FILE_LINE(0) cConfigItem_integer("process_rtp_packets_hash_next_thread_max", &opt_process_rtp_packets_hash_next_thread_max))
						->setMaximum(MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS));
					addConfigItem((new FILE_LINE(0) cConfigItem_yesno("pre_process_packets_next_thread_sem_sync", &opt_pre_process_packets_next_thread_sem_sync))
						->addValues("2:2"));
					addConfigItem((new FILE_LINE(42157) cConfigItem_yesno("process_rtp_packets_hash_next_thread_sem_sync", &opt_process_rtp_packets_hash_next_thread_sem_sync))
						->addValues("2:2"));
					addConfigItem(new FILE_LINE(42158) cConfigItem_integer("process_rtp_packets_qring_length", &opt_process_rtp_packets_qring_length));
					addConfigItem(new FILE_LINE(42159) cConfigItem_integer("process_rtp_packets_qring_item_length", &opt_process_rtp_packets_qring_item_length));
					addConfigItem(new FILE_LINE(42160) cConfigItem_integer("process_rtp_packets_qring_usleep", &opt_process_rtp_packets_qring_usleep));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("process_rtp_packets_qring_push_usleep", &opt_process_rtp_packets_qring_push_usleep));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("push_batch_limit_ms", &opt_push_batch_limit_ms));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("push_batch_limit_for_traffic_lt_mb_s", &opt_push_batch_limit_for_traffic_lt_mb_s));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("batch_length_sip_high_traffic", &opt_batch_length_sip_high_traffic));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("batch_length_rtp_high_traffic", &opt_batch_length_rtp_high_traffic));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("cleanup_calls_period", &opt_cleanup_calls_period));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("destroy_calls_period", &opt_destroy_calls_period));
					addConfigItem((new FILE_LINE(0) cConfigItem_yesno("safe_cleanup_calls", &opt_safe_cleanup_calls))
						->addValues("ext:2"));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("destroy_calls_in_storing_cdr", &opt_destroy_calls_in_storing_cdr));
			setDisableIfEnd();
	group("manager");
		addConfigItem((new FILE_LINE(42162) cConfigItem_string("managerip", opt_manager_ip, sizeof(opt_manager_ip)))
			->setReadOnly());
		addConfigItem((new FILE_LINE(42163) cConfigItem_integer("managerport", &opt_manager_port))
			->setReadOnly());
		addConfigItem((new FILE_LINE(42163) cConfigItem_string("managersocket", &opt_manager_socket))
			->setReadOnly());
		addConfigItem((new FILE_LINE(0) cConfigItem_string("manager_aes_key", &opt_manager_aes_key))
			->setReadOnly());
		addConfigItem((new FILE_LINE(0) cConfigItem_string("manager_aes_iv", &opt_manager_aes_iv))
			->setReadOnly());
		addConfigItem((new FILE_LINE(0) cConfigItem_yesno("manager_enable_unencrypted", &opt_manager_enable_unencrypted))
			->setReadOnly());
	group("buffers and memory usage");
		subgroup("main");
			addConfigItem((new FILE_LINE(42164) cConfigItem_integer("max_buffer_mem", &opt_max_buffer_mem))
				->setNaDefaultValueStr());
			addConfigItem((new FILE_LINE(42165) cConfigItem_integer("ringbuffer", &opt_ringbuffer))
				->setMaximum(2000));
		subgroup("scaling");
				advanced();
				addConfigItem((new FILE_LINE(42166) cConfigItem_integer("rtpthreads", &num_threads_set))
					->setIfZeroOrNegative(max(sysconf(_SC_NPROCESSORS_ONLN) - 1, 1l)));
				addConfigItem(new FILE_LINE(42167) cConfigItem_integer("rtpthreads_start", &num_threads_start));
					expert();
					addConfigItem(new FILE_LINE(42168) cConfigItem_yesno("savertp-threaded", &opt_rtpsave_threaded));
				addConfigItem(new FILE_LINE(42169) cConfigItem_yesno("packetbuffer_compress", &opt_pcap_queue_compress));
				addConfigItem((new FILE_LINE(42170) cConfigItem_integer("pcap_queue_dequeu_window_length", &opt_pcap_queue_dequeu_window_length))
					->addAlias("pcap_queue_deque_window_length"));
				addConfigItem((new FILE_LINE(42171) cConfigItem_integer("pcap_queue_dequeu_need_blocks", &opt_pcap_queue_dequeu_need_blocks))
					->addAlias("pcap_queue_deque_need_blocks"));
				addConfigItem(new FILE_LINE(42172) cConfigItem_integer("pcap_queue_iface_qring_size", &opt_pcap_queue_iface_qring_size));
					expert();
					addConfigItem(new FILE_LINE(42173) cConfigItem_integer("pcap_queue_dequeu_method", &opt_pcap_queue_dequeu_method));
					addConfigItem((new FILE_LINE(42174) cConfigItem_yesno("pcap_queue_use_blocks", &opt_pcap_queue_use_blocks))
						->addAlias("use_blocks"));					
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("auto_enable_use_blocks", &opt_pcap_queue_use_blocks_auto_enable));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("pcap_queue_use_blocks_read_check", &opt_pcap_queue_use_blocks_read_check));
					addConfigItem((new FILE_LINE(42175) cConfigItem_integer("packetbuffer_block_maxsize", &opt_pcap_queue_block_max_size))
						->setMultiple(1024));
					addConfigItem(new FILE_LINE(42176) cConfigItem_integer("packetbuffer_block_maxtime", &opt_pcap_queue_block_max_time_ms));
					addConfigItem(new FILE_LINE(42177) cConfigItem_integer("packetbuffer_block_timeout", &opt_pcap_queue_block_timeout));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("packetbuffer_pcap_stat_per_one_interface", &opt_pcap_queue_pcap_stat_per_one_interface));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("packetbuffer_disable", &opt_pcap_queue_disable));
		subgroup("file cache");
					expert();
					addConfigItem((new FILE_LINE(42178) cConfigItem_integer("packetbuffer_file_totalmaxsize", &opt_pcap_queue_store_queue_max_disk_size))
						->setMultiple(1024 * 1024));
					addConfigItem(new FILE_LINE(42179) cConfigItem_string("packetbuffer_file_path", &opt_pcap_queue_disk_folder));
	group("data storing");
		setDisableIfBegin("sniffer_mode=" + snifferMode_sender_str);
		subgroup("main");
			addConfigItem((new FILE_LINE(42180) cConfigItem_string("spooldir", opt_spooldir_main, sizeof(opt_spooldir_main)))
				->setReadOnly());
			addConfigItem((new FILE_LINE(42181) cConfigItem_string("spooldir_rtp", opt_spooldir_rtp, sizeof(opt_spooldir_rtp)))
				->setReadOnly());
			addConfigItem((new FILE_LINE(42182) cConfigItem_string("spooldir_graph", opt_spooldir_graph, sizeof(opt_spooldir_graph)))
				->setReadOnly());
			addConfigItem((new FILE_LINE(42183) cConfigItem_string("spooldir_audio", opt_spooldir_audio, sizeof(opt_spooldir_audio)))
				->setReadOnly());
			addConfigItem((new FILE_LINE(0) cConfigItem_string("spooldir_audiograph", opt_spooldir_audiograph, sizeof(opt_spooldir_audiograph)))
				->setReadOnly());
			addConfigItem((new FILE_LINE(42184) cConfigItem_string("spooldir_2", opt_spooldir_2_main, sizeof(opt_spooldir_2_main)))
				->setReadOnly());
			addConfigItem((new FILE_LINE(42185) cConfigItem_string("spooldir_2_rtp", opt_spooldir_2_rtp, sizeof(opt_spooldir_2_rtp)))
				->setReadOnly());
			addConfigItem((new FILE_LINE(42186) cConfigItem_string("spooldir_2_graph", opt_spooldir_2_graph, sizeof(opt_spooldir_2_graph)))
				->setReadOnly());
			addConfigItem((new FILE_LINE(42187) cConfigItem_string("spooldir_2_audio", opt_spooldir_2_audio, sizeof(opt_spooldir_2_audio)))
				->setReadOnly());
			addConfigItem((new FILE_LINE(0) cConfigItem_string("spooldir_2_audiograph", opt_spooldir_2_audiograph, sizeof(opt_spooldir_2_audiograph)))
				->setReadOnly());
			addConfigItem(new FILE_LINE(42188) cConfigItem_yesno("tar", &opt_pcap_dump_tar));
				advanced();
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("tar_use_hash_instead_of_long_callid", &opt_pcap_dump_tar_use_hash_instead_of_long_callid));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("spooldir_file_permission", opt_spooldir_file_permission, sizeof(opt_spooldir_file_permission)));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("spooldir_dir_permission", opt_spooldir_dir_permission, sizeof(opt_spooldir_dir_permission)));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("spooldir_owner", opt_spooldir_owner, sizeof(opt_spooldir_owner)));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("spooldir_group", opt_spooldir_group, sizeof(opt_spooldir_group)));
				addConfigItem(new FILE_LINE(42189) cConfigItem_string("convertchar", opt_convert_char, sizeof(opt_convert_char)));
				addConfigItem(new FILE_LINE(42190) cConfigItem_string("cachedir", opt_cachedir, sizeof(opt_cachedir)));
				addConfigItem((new FILE_LINE(0) cConfigItem_yesno("tar_move", &opt_tar_move))
					->addValues("move:1|m:1|copy:2|c:2"));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("tar_move_destination_path", &opt_tar_move_destination_path));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("tar_move_source_trim_path", &opt_tar_move_source_trim_path));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("tar_move_max_threads", &opt_tar_move_max_threads));
					expert();
					addConfigItem(new FILE_LINE(42191) cConfigItem_yesno("convert_dlt_sll2en10", &opt_convert_dlt_sll_to_en10));
					addConfigItem(new FILE_LINE(42192) cConfigItem_yesno("dumpallpackets", &opt_pcapdump));
					addConfigItem(new FILE_LINE(42195) cConfigItem_string("bogus_dumper_path", opt_bogus_dumper_path, sizeof(opt_bogus_dumper_path)));
					#if TRAFFIC_DUMPER
					addConfigItem(new FILE_LINE(0) cConfigItem_string("traffic_dumper_path", opt_traffic_dumper_path, sizeof(opt_traffic_dumper_path)));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("traffic_dumper_by_interface", &opt_traffic_dumper_by_interface));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("traffic_dumper_force_flush", &opt_traffic_dumper_force_flush));
					#endif
		subgroup("scaling");
			addConfigItem(new FILE_LINE(42196) cConfigItem_integer("tar_maxthreads", &opt_pcap_dump_tar_threads));
				advanced();
				addConfigItem(new FILE_LINE(42197) cConfigItem_integer("maxpcapsize", &opt_maxpcapsize_mb));
					expert();
					addConfigItem(new FILE_LINE(42198) cConfigItem_integer("pcap_dump_bufflength", &opt_pcap_dump_bufflength));
					addConfigItem(new FILE_LINE(42199) cConfigItem_integer("pcap_dump_writethreads", &opt_pcap_dump_writethreads));
					addConfigItem(new FILE_LINE(42200) cConfigItem_yesno("pcap_dump_asyncwrite", &opt_pcap_dump_asyncwrite));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("pcap_dump_asyncwrite_batch_limit", &opt_pcap_dump_asyncwrite_batch_limit));
					addConfigItem(new FILE_LINE(42201) cConfigItem_integer("pcap_ifdrop_limit", &opt_pcap_ifdrop_limit));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("pcap_dpdk_ifdrop_limit", &opt_pcap_dpdk_ifdrop_limit));
		subgroup("SIP");
			addConfigItem(new FILE_LINE(42202) cConfigItem_yesno("savesip", &opt_saveSIP));
				advanced();
				addConfigItem((new FILE_LINE(0) cConfigItem_yesno("save_sdp_ipport", &opt_save_sdp_ipport))
					->addValues("last:1|all:2"));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("save_ip_from_encaps_ipheader", &opt_save_ip_from_encaps_ipheader));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("save_ip_from_encaps_ipheader_only_gre", &opt_save_ip_from_encaps_ipheader_only_gre));
					expert();
					addConfigItem(new FILE_LINE(42203) cConfigItem_type_compress("pcap_dump_zip_sip", &opt_pcap_dump_zip_sip));
					addConfigItem((new FILE_LINE(42204) cConfigItem_integer("pcap_dump_ziplevel_sip", &opt_pcap_dump_compresslevel_sip))
						->addAlias("pcap_dump_compresslevel_sip"));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("pcap_dump_compress_strategy_sip", &opt_pcap_dump_compress_sip_zstdstrategy));
					addConfigItem((new FILE_LINE(42205) cConfigItem_yesno("tar_compress_sip", &opt_pcap_dump_tar_compress_sip))
						->addValues(Tar::getTarCompressConfigValues().c_str()));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("tar_sip_level_gzip", &opt_pcap_dump_tar_sip_level_gzip));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("tar_sip_level_lzma", &opt_pcap_dump_tar_sip_level_lzma));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("tar_sip_level_zstd", &opt_pcap_dump_tar_sip_level_zstd));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("tar_sip_strategy_zstd", &opt_pcap_dump_tar_sip_zstdstrategy));
					addConfigItem(new FILE_LINE(42207) cConfigItem_type_compress("tar_internalcompress_sip", &opt_pcap_dump_tar_internalcompress_sip));
					addConfigItem(new FILE_LINE(42208) cConfigItem_integer("tar_internal_sip_level", &opt_pcap_dump_tar_internal_gzip_sip_level));
		subgroup("RTP/RTCP/UDPTL");
			addConfigItem((new FILE_LINE(42209) cConfigItem_yesno("savertp"))
				->addValues("header:-1|h:-1")
				->setDefaultValueStr("no"));
			addConfigItem((new FILE_LINE(0) cConfigItem_yesno("savertp_video"))
				->addValues("header:-1|h:-1|cdr_only:-2|c:-2")
				->setDefaultValueStr("no"));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("savemrcp", &opt_saveMRCP));
			addConfigItem(new FILE_LINE(42210) cConfigItem_yesno("savertcp", &opt_saveRTCP));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("ignorertcpjitter", &opt_ignoreRTCPjitter));
			addConfigItem(new FILE_LINE(42211) cConfigItem_yesno("saveudptl", &opt_saveudptl));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("rtpip_find_endpoints", &opt_rtpip_find_endpoints));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("save-energylevels", &opt_save_energylevels));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("save-energylevels-check-seq", &opt_save_energylevels_check_seq));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("save-energylevels-via-jb", &opt_save_energylevels_via_jb));
				advanced();
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("null_rtppayload", &opt_null_rtppayload));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("srtp_rtp", &opt_srtp_rtp_decrypt));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("srtp_rtp_dtls", &opt_srtp_rtp_dtls_decrypt));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("srtp_rtp_audio", &opt_srtp_rtp_audio_decrypt));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("srtp_rtp_dtmf", &opt_srtp_rtp_dtmf_decrypt));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("srtp_rtcp", &opt_srtp_rtcp_decrypt));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("srtp_use_all_keys", &opt_srtp_use_all_keys));
					expert();
					addConfigItem(new FILE_LINE(42212) cConfigItem_type_compress("pcap_dump_zip_rtp", &opt_pcap_dump_zip_rtp));
					addConfigItem((new FILE_LINE(42213) cConfigItem_integer("pcap_dump_ziplevel_rtp", &opt_pcap_dump_compresslevel_rtp))
						->addAlias("pcap_dump_compresslevel_rtp"));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("pcap_dump_compress_strategy_rtp", &opt_pcap_dump_compress_rtp_zstdstrategy));
					addConfigItem((new FILE_LINE(42214) cConfigItem_yesno("tar_compress_rtp", &opt_pcap_dump_tar_compress_rtp))
						->addValues(Tar::getTarCompressConfigValues().c_str()));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("tar_rtp_level_gzip", &opt_pcap_dump_tar_rtp_level_gzip));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("tar_rtp_level_lzma", &opt_pcap_dump_tar_rtp_level_lzma));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("tar_rtp_level_zstd", &opt_pcap_dump_tar_rtp_level_zstd));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("tar_rtp_strategy_zstd", &opt_pcap_dump_tar_rtp_zstdstrategy));
					addConfigItem(new FILE_LINE(42216) cConfigItem_type_compress("tar_internalcompress_rtp", &opt_pcap_dump_tar_internalcompress_rtp));
					addConfigItem(new FILE_LINE(42217) cConfigItem_integer("tar_internal_rtp_level", &opt_pcap_dump_tar_internal_gzip_rtp_level));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("srtp_rtp_local_instances", &opt_srtp_rtp_local_instances));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("libsrtp", &opt_use_libsrtp));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("check_diff_ssrc_on_same_ip_port", &opt_check_diff_ssrc_on_same_ip_port));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("save_all_rtp_streams_to_db", &opt_save_all_rtp_streams_to_db));
		subgroup("GRAPH");
			addConfigItem((new FILE_LINE(42218) cConfigItem_yesno("savegraph"))
				->addValues("plain:1|p:1|gzip:2|g:2")
				->setDefaultValueStr("no"));
					expert();
					addConfigItem(new FILE_LINE(42219) cConfigItem_type_compress("pcap_dump_zip_graph", &opt_gzipGRAPH));
					addConfigItem((new FILE_LINE(42220) cConfigItem_integer("pcap_dump_ziplevel_graph", &opt_pcap_dump_compresslevel_graph))
						->addAlias("pcap_dump_compresslevel_graph"));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("pcap_dump_compress_strategy_graph", &opt_pcap_dump_compress_graph_zstdstrategy));
					addConfigItem((new FILE_LINE(42221) cConfigItem_yesno("tar_compress_graph", &opt_pcap_dump_tar_compress_graph))
						->addValues(Tar::getTarCompressConfigValues().c_str()));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("tar_graph_level_gzip", &opt_pcap_dump_tar_graph_level_gzip));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("tar_graph_level_lzma", &opt_pcap_dump_tar_graph_level_lzma));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("tar_graph_level_zstd", &opt_pcap_dump_tar_graph_level_zstd));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("tar_graph_strategy_zstd", &opt_pcap_dump_tar_graph_zstdstrategy));
					addConfigItem(new FILE_LINE(42223) cConfigItem_type_compress("tar_internalcompress_graph", &opt_pcap_dump_tar_internalcompress_graph));
					addConfigItem(new FILE_LINE(42224) cConfigItem_integer("tar_internal_graph_level", &opt_pcap_dump_tar_internal_gzip_graph_level));
		subgroup("AUDIO");
			addConfigItem((new FILE_LINE(42225) cConfigItem_yesno("saveaudio"))
				->addValues("wav:1|w:1|ogg:2|o:2|mp3:3|m:3")
				->setDefaultValueStr("no"));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("audio_transcribe", &opt_audio_transcribe));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("liveaudio", &opt_liveaudio));
				advanced();
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("saveaudio_answeronly", &opt_saveaudio_answeronly));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("saveaudio_filteripbysipip", &opt_saveaudio_filteripbysipip));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("saveaudio_filter_ext", &opt_saveaudio_filter_ext));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("saveaudio_wav_mix", &opt_saveaudio_wav_mix));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("saveaudio_from_first_invite", &opt_saveaudio_from_first_invite));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("saveaudio_afterconnect", &opt_saveaudio_afterconnect));
				addConfigItem(new FILE_LINE(42226) cConfigItem_yesno("saveaudio_stereo", &opt_saveaudio_stereo));
				addConfigItem(new FILE_LINE(42227) cConfigItem_yesno("saveaudio_reversestereo", &opt_saveaudio_reversestereo));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("saveaudio_adaptive_jitterbuffer", &opt_saveaudio_adaptive_jitterbuffer));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("saveaudio_resync_jitterbuffer", &opt_saveaudio_resync_jitterbuffer));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("saveaudio_jitterbuffer_jbsize", &opt_saveaudio_jitterbuffer_jbsize));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("saveaudio_jitterbuffer_resync_threshold", &opt_saveaudio_jitterbuffer_resync_threshold));
				addConfigItem(new FILE_LINE(42228) cConfigItem_float("ogg_quality", &opt_saveaudio_oggquality));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("mp3_quality", &opt_saveaudio_mp3quality));
				addConfigItem(new FILE_LINE(42229) cConfigItem_integer("audioqueue_threads_max", &opt_audioqueue_threads_max));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("audio_transcribe_connect_duration_min", &opt_audio_transcribe_connect_duration_min));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("audio_transcribe_threads", &opt_audio_transcribe_threads));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("audio_transcribe_queue_length_max", &opt_audio_transcribe_queue_length_max));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("audio_transcribe_parallel_channel_processing", &opt_audio_transcribe_parallel_channel_processing));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("audio_transcribe_progress_file", &opt_audio_transcribe_progress_file));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("audio_transcribe_control_file", &opt_audio_transcribe_control_file));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("whisper_native", &opt_whisper_native));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("whisper_model", &opt_whisper_model));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("whisper_rest_api_url", &opt_whisper_rest_api_url));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("whisper_rest_api_url", &opt_whisper_rest_api_url, "", "URL for whisper REST API transcription"));

				addConfigItem(new FILE_LINE(0) cConfigItem_string("whisper_language", &opt_whisper_language));
					// auto | by_number | {language}
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("whisper_timeout", &opt_whisper_timeout));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("whisper_deterministic_mode", &opt_whisper_deterministic_mode));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("whisper_python", &opt_whisper_python));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("whisper_threads", &opt_whisper_threads));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("whisper_native_lib", &opt_whisper_native_lib));
					expert();
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("saveaudio_dedup_seq", &opt_saveaudio_dedup_seq));
					addConfigItem(new FILE_LINE(42230) cConfigItem_yesno("plcdisable", &opt_disableplc));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("fix_packetization_in_create_audio", &opt_fix_packetization_in_create_audio));
					addConfigItem(new FILE_LINE(1162) cConfigItem_string("curl_hook_wav", opt_curl_hook_wav, sizeof(opt_curl_hook_wav)));
			normal();
			addConfigItem((new FILE_LINE(0) cConfigItem_yesno("save_audiograph"))
				->addValues("plain:1|p:1|gzip:2|g:2")
				->setDefaultValueStr("no"));
				advanced();
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("audiograph_ms_per_pixel", &opt_audiograph_ms_per_pixel));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("audiograph_spectrogram_height", &opt_audiograph_spectrogram_height));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("audiograph_spectrogram_jpeg_quality", &opt_audiograph_spectrogram_jpeg_quality));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("audiograph_fftw_multithread_mode", &opt_fftw_multithread_mode));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("audiograph_fftw_fork_mode", &opt_fftw_fork_mode));
					expert();
					addConfigItem(new FILE_LINE(0) cConfigItem_type_compress("pcap_dump_zip_audiograph", &opt_gzip_audiograph));
					addConfigItem((new FILE_LINE(0) cConfigItem_integer("pcap_dump_ziplevel_audiograph", &opt_pcap_dump_compresslevel_audiograph))
						->addAlias("pcap_dump_compresslevel_audiograph"));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("pcap_dump_compress_strategy_audiograph", &opt_pcap_dump_compress_audiograph_zstdstrategy));
					addConfigItem((new FILE_LINE(0) cConfigItem_yesno("tar_compress_audiograph", &opt_pcap_dump_tar_compress_audiograph))
						->addValues(Tar::getTarCompressConfigValues().c_str()));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("tar_audiograph_level_gzip", &opt_pcap_dump_tar_audiograph_level_gzip));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("tar_audiograph_level_lzma", &opt_pcap_dump_tar_audiograph_level_lzma));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("tar_audiograph_level_zstd", &opt_pcap_dump_tar_audiograph_level_zstd));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("tar_audiograph_strategy_zstd", &opt_pcap_dump_tar_audiograph_zstdstrategy));
					addConfigItem(new FILE_LINE(0) cConfigItem_type_compress("tar_internalcompress_audiograph", &opt_pcap_dump_tar_internalcompress_audiograph));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("tar_internal_audiograph_level", &opt_pcap_dump_tar_internal_gzip_audiograph_level));
		setDisableIfEnd();
	group("data spool directory cleaning");
		setDisableIfBegin("sniffer_mode=" + snifferMode_sender_str);
		addConfigItem(new FILE_LINE(0) cConfigItem_yesno("cleanspool", &opt_cleanspool));
			advanced();
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("cleanspool_use_files", &opt_cleanspool_use_files));
			addConfigItem(new FILE_LINE(42231) cConfigItem_integer("cleanspool_interval", &opt_cleanspool_interval));
		normal();
		addConfigItem(new FILE_LINE(42232) cConfigItem_hour_interval("cleanspool_enable_fromto", &opt_cleanspool_enable_run_hour_from, &opt_cleanspool_enable_run_hour_to));
		for(int i = 0; i < 2; i++) {
			addConfigItem(new FILE_LINE(42233) cConfigItem_integer(("maxpoolsize" + string(i == 0 ? "" : "_2")).c_str(), i == 0 ? &opt_maxpoolsize : &opt_maxpoolsize_2));
			addConfigItem(new FILE_LINE(42234) cConfigItem_integer(("maxpooldays" + string(i == 0 ? "" : "_2")).c_str(), i == 0 ? &opt_maxpooldays : &opt_maxpooldays_2));
			addConfigItem(new FILE_LINE(42235) cConfigItem_integer(("maxpoolsipsize" + string(i == 0 ? "" : "_2")).c_str(), i == 0 ? &opt_maxpoolsipsize : &opt_maxpoolsipsize_2));
			addConfigItem(new FILE_LINE(42236) cConfigItem_integer(("maxpoolsipdays" + string(i == 0 ? "" : "_2")).c_str(), i == 0 ? &opt_maxpoolsipdays : &opt_maxpoolsipdays_2));
			addConfigItem(new FILE_LINE(42237) cConfigItem_integer(("maxpoolrtpsize" + string(i == 0 ? "" : "_2")).c_str(), i == 0 ? &opt_maxpoolrtpsize : &opt_maxpoolrtpsize_2));
			addConfigItem(new FILE_LINE(42238) cConfigItem_integer(("maxpoolrtpdays" + string(i == 0 ? "" : "_2")).c_str(), i == 0 ? &opt_maxpoolrtpdays : &opt_maxpoolrtpdays_2));
			addConfigItem(new FILE_LINE(42239) cConfigItem_integer(("maxpoolgraphsize" + string(i == 0 ? "" : "_2")).c_str(), i == 0 ? &opt_maxpoolgraphsize : &opt_maxpoolgraphsize_2));
			addConfigItem(new FILE_LINE(42240) cConfigItem_integer(("maxpoolgraphdays" + string(i == 0 ? "" : "_2")).c_str(), i == 0 ? &opt_maxpoolgraphdays : &opt_maxpoolgraphdays_2));
			addConfigItem(new FILE_LINE(42241) cConfigItem_integer(("maxpoolaudiosize" + string(i == 0 ? "" : "_2")).c_str(), i == 0 ? &opt_maxpoolaudiosize : &opt_maxpoolaudiosize_2));
			addConfigItem(new FILE_LINE(42242) cConfigItem_integer(("maxpoolaudiodays" + string(i == 0 ? "" : "_2")).c_str(), i == 0 ? &opt_maxpoolaudiodays : &opt_maxpoolaudiodays_2));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer(("maxpoolaudiographsize" + string(i == 0 ? "" : "_2")).c_str(), i == 0 ? &opt_maxpoolaudiographsize : &opt_maxpoolaudiographsize_2));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer(("maxpoolaudiographdays" + string(i == 0 ? "" : "_2")).c_str(), i == 0 ? &opt_maxpoolaudiographdays : &opt_maxpoolaudiographdays_2));
		}
			advanced();
			addConfigItem(new FILE_LINE(42243) cConfigItem_yesno("maxpool_clean_obsolete", &opt_maxpool_clean_obsolete));
			addConfigItem(new FILE_LINE(42244) cConfigItem_integer("autocleanspoolminpercent", &opt_autocleanspoolminpercent));
			addConfigItem((new FILE_LINE(42245) cConfigItem_integer("autocleanmingb", &opt_autocleanmingb))
				->addAlias("autocleanspoolmingb"));
		setDisableIfEnd();
	group("IP protocol");
		addConfigItem((new FILE_LINE(42246) cConfigItem_yesno("deduplicate", &opt_dup_check_type))
			->addValues(("md5:" + intToString(_dedup_md5)+ 
				     "|crc:" + intToString(_dedup_crc32_sw) +
				     "|crc32:" + intToString(_dedup_crc32_sw) +
				     "|crc64:" + intToString(_dedup_crc64)
				     #if HAVE_LIBBLAKE3
				     + "|blake3:" + intToString(_dedup_blake3) 
				     #endif
				     #if MURMUR_HASH
				     + "|murmur:" + intToString(_dedup_murmur)
				     #endif
				     ).c_str()));
				expert();
				addConfigItem((new FILE_LINE(0) cConfigItem_yesno("deduplicate_check_type", &opt_dup_check_check_type))
					->disableYes()
					->disableNo()
					->addValues(("simple:" + intToString(cPacketDuplBuffer::_simple) + 
						     "|hashtable:" + intToString(cPacketDuplBuffer::_hashtable)).c_str()));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("deduplicate_hashtable_lifetime", &opt_dup_check_hashtable_lifetime));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("deduplicate_collision_test", &opt_dup_check_collision_test));
		normal();
		addConfigItem((new FILE_LINE(0) cConfigItem_yesno("deduplicate_ipheader", &opt_dup_check_ipheader))
				->addValues("ip_only:2"));
		addConfigItem(new FILE_LINE(42248) cConfigItem_yesno("udpfrag", &opt_udpfrag));
		addConfigItem(new FILE_LINE(42249) cConfigItem_yesno("dscp", &opt_dscp));
				expert();
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("deduplicate_ipheader_ignore_ttl", &opt_dup_check_ipheader_ignore_ttl));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("deduplicate_udpheader_ignore_checksum", &opt_dup_check_udpheader_ignore_checksum));
				addConfigItem(new FILE_LINE(42250) cConfigItem_string("tcpreassembly_http_log", opt_tcpreassembly_http_log, sizeof(opt_tcpreassembly_http_log)));
				addConfigItem(new FILE_LINE(42251) cConfigItem_string("tcpreassembly_webrtc_log", opt_tcpreassembly_webrtc_log, sizeof(opt_tcpreassembly_webrtc_log)));
				addConfigItem(new FILE_LINE(42252) cConfigItem_string("tcpreassembly_ssl_log", opt_tcpreassembly_ssl_log, sizeof(opt_tcpreassembly_ssl_log)));
				addConfigItem(new FILE_LINE(42253) cConfigItem_string("tcpreassembly_sip_log", opt_tcpreassembly_sip_log, sizeof(opt_tcpreassembly_sip_log)));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("tcpreassembly_diameter_log", opt_tcpreassembly_diameter_log, sizeof(opt_tcpreassembly_diameter_log)));
	group("SSL");
		setDisableIfBegin("sniffer_mode=" + snifferMode_sender_str);
		addConfigItem((new FILE_LINE(42254) cConfigItem_yesno("ssl", &opt_enable_ssl))
			->addValues("old:10|only:2"));
		addConfigItem(new FILE_LINE(0) cConfigItem_net_port_str_map("ssl_ipport", &ssl_ipport, &ssl_netport));
		addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ssl_ipport_reverse_enable", &opt_ssl_ipport_reverse_enable));
		addConfigItem(new FILE_LINE(42256) cConfigItem_integer("ssl_link_timeout", &opt_ssl_link_timeout));
			advanced();
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ssl_sessionkey_udp", &ssl_client_random_enable));
			addConfigItem(new FILE_LINE(0) cConfigItem_ports("ssl_sessionkey_udp_port", ssl_client_random_portmatrix));
			addConfigItem(new FILE_LINE(0) cConfigItem_hosts("ssl_sessionkey_udp_ip", &ssl_client_random_ip, &ssl_client_random_net));
			addConfigItem(new FILE_LINE(0) cConfigItem_string("ssl_sessionkey_bind", &ssl_client_random_tcp_host));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("ssl_sessionkey_bind_port", &ssl_client_random_tcp_port));
			addConfigItem((new FILE_LINE(0) cConfigItem_integer("ssl_sessionkey_maxwait_ms", &ssl_client_random_maxwait_ms))
				->addAlias("ssl_sessionkey_udp_maxwait_ms"));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ssl_sessionkey_keep", &ssl_client_random_keep));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ssl_ignore_tcp_handshake", &opt_ssl_ignore_tcp_handshake));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ssl_log_errors", &opt_ssl_log_errors));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ssl_find_valid_mac", &opt_ssl_find_valid_mac));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ssl_ignore_error_invalid_mac", &opt_ssl_ignore_error_invalid_mac));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ssl_ignore_error_bad_finished_digest", &opt_ssl_ignore_error_bad_finished_digest));
			addConfigItem((new FILE_LINE(0) cConfigItem_yesno("ssl_tls_12_sessionkey_mode", &opt_ssl_tls_12_sessionkey_mode))
				->addValues("dssl:0|ws:1"));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ssl_unlimited_reassembly_attempts", &opt_ssl_unlimited_reassembly_attempts));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ssl_destroy_tcp_link_on_rst", &opt_ssl_destroy_tcp_link_on_rst));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ssl_destroy_ssl_session_on_rst", &opt_ssl_destroy_ssl_session_on_rst));
			addConfigItem((new FILE_LINE(0) cConfigItem_yesno("ssl_store_sessions", &opt_ssl_store_sessions))
				->addValues("memory:1|persistent:2"));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("ssl_store_sessions_expiration_hours", &opt_ssl_store_sessions_expiration_hours));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("ssl_aead_try_seq_backward", &opt_ssl_aead_try_seq_backward));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("ssl_aead_try_seq_forward", &opt_ssl_aead_try_seq_forward));
			addConfigItem((new FILE_LINE(0) cConfigItem_yesno("ssl_dtls_queue", &opt_ssl_enable_dtls_queue))
				->addValues("lockless:2"));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("ssl_dtls_queue_expiration", &opt_ssl_dtls_queue_expiration_s));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("ssl_dtls_queue_max_packets", &opt_ssl_dtls_queue_expiration_count));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ssl_enable_redirection_unencrypted_sip_content", &opt_ssl_enable_redirection_unencrypted_sip_content));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ssl_dtls_queue_keep", &opt_ssl_dtls_queue_keep));
			addConfigItem((new FILE_LINE(0) cConfigItem_yesno("ssl_dtls_handshake_safe", &opt_ssl_dtls_handshake_safe))
				->addValues("ext:2|only:3"));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ssl_dtls_find_by_server_side", &opt_ssl_dtls_find_by_server_side));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ssl_dtls_find_by_client_side", &opt_ssl_dtls_find_by_client_side));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ssl_dtls_boost", &opt_ssl_dtls_boost));
				expert();
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ssl_reassembly_all_complete_after_zerodata_ack", &opt_ssl_reassembly_all_complete_after_zerodata_ack));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ssl_reassembly_ipport_reverse_enable", &opt_ssl_reassembly_ipport_reverse_enable));
		setDisableIfEnd();
	group("SKINNY");
		setDisableIfBegin("sniffer_mode=" + snifferMode_sender_str);
		addConfigItem((new FILE_LINE(42257) cConfigItem_yesno("skinny", &opt_skinny))
			->setDefaultValueStr("2000")
			->setClearBeforeFirstSet());
		addConfigItem(new FILE_LINE(0) cConfigItem_ports("skinny_port", skinnyportmatrix));
		addConfigItem(new FILE_LINE(42258) cConfigItem_ip("skinny_ignore_rtpip", &opt_skinny_ignore_rtpip));
			advanced();
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("skinny_call_info_message_decode_type", &opt_skinny_call_info_message_decode_type));
		setDisableIfEnd();
	group("MGCP");
		setDisableIfBegin("sniffer_mode=" + snifferMode_sender_str);
		addConfigItem(new FILE_LINE(0) cConfigItem_yesno("mgcp", &opt_mgcp));
				expert();
				addConfigItem((new FILE_LINE(42270) cConfigItem_ports("tcp_port_mgcp_gateway", mgcp_gateway_tcp_portmatrix))
				->setDefaultValueStr("2427")
				->setClearBeforeFirstSet());
				addConfigItem((new FILE_LINE(42270) cConfigItem_ports("udp_port_mgcp_gateway", mgcp_gateway_udp_portmatrix))
				->setDefaultValueStr("2427")
				->setClearBeforeFirstSet());
				addConfigItem((new FILE_LINE(42270) cConfigItem_ports("tcp_port_mgcp_callagent", mgcp_callagent_tcp_portmatrix))
				->setDefaultValueStr("2727")
				->setClearBeforeFirstSet());
				addConfigItem((new FILE_LINE(42270) cConfigItem_ports("udp_port_mgcp_callagent", mgcp_callagent_udp_portmatrix))
				->setDefaultValueStr("2727")
				->setClearBeforeFirstSet());
		setDisableIfEnd();
	group("CDR");
		setDisableIfBegin("sniffer_mode=" + snifferMode_sender_str);
			advanced();
			addConfigItem(new FILE_LINE(42259) cConfigItem_integer("absolute_timeout", &absolute_timeout));
			addConfigItem(new FILE_LINE(42260) cConfigItem_integer("onewaytimeout", &opt_onewaytimeout));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("bye_timeout", &opt_bye_timeout));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("bye_confirmed_timeout", &opt_bye_confirmed_timeout));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("redirect_response_300_timeout", &opt_redirect_response_300_timeout));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("response_default_timeout", &opt_response_default_timeout));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ignore_rtp_after_bye_confirmed", &opt_ignore_rtp_after_bye_confirmed));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ignore_rtp_after_bye", &opt_ignore_rtp_after_bye));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ignore_duration_after_bye_confirmed", &opt_ignore_duration_after_bye_confirmed));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ignore_rtp_after_cancel_confirmed", &opt_ignore_rtp_after_cancel_confirmed));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ignore_rtp_after_auth_failed", &opt_ignore_rtp_after_auth_failed));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("ignore_rtp_after_response", &opt_ignore_rtp_after_response_list));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("get_reason_from_bye_cancel", &opt_get_reason_from_bye_cancel));
			addConfigItem(new FILE_LINE(42261) cConfigItem_yesno("nocdr", &opt_nocdr));
			addConfigItem((new FILE_LINE(42262) cConfigItem_string("cdr_ignore_response", opt_nocdr_for_last_responses, sizeof(opt_nocdr_for_last_responses)))
				->addAlias("nocdr_for_last_responses"));
			addConfigItem(new FILE_LINE(42263) cConfigItem_yesno("skipdefault", &opt_skipdefault));
			addConfigItem(new FILE_LINE(42264) cConfigItem_yesno("cdronlyanswered", &opt_cdronlyanswered));
			addConfigItem((new FILE_LINE(42265) cConfigItem_yesno("cdr_check_exists_callid", &opt_cdr_check_exists_callid))
				->addValues("lock:2"));
			addConfigItem(new FILE_LINE(0) cConfigItem_string("cdr_check_unique_callid_in_sensors", &opt_cdr_check_unique_callid_in_sensors));
				expert();
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("cdr_check_exists_callid_cache_max_size", &opt_cdr_check_exists_callid_cache_max_size));
			advanced();
			addConfigItem(new FILE_LINE(42266) cConfigItem_yesno("cdronlyrtp", &opt_cdronlyrtp));
			addConfigItem(new FILE_LINE(42267) cConfigItem_integer("callslimit", &opt_callslimit));
			addConfigItem(new FILE_LINE(42268) cConfigItem_yesno("cdrproxy", &opt_cdrproxy));
			addConfigItem(new FILE_LINE(42269) cConfigItem_yesno("messageproxy", &opt_messageproxy));
			addConfigItem((new FILE_LINE(0) cConfigItem_yesno("cdr_country_code", &opt_cdr_country_code))
				->addValues("id:2"));
			addConfigItem((new FILE_LINE(0) cConfigItem_yesno("message_country_code", &opt_message_country_code))
				->addValues("id:2"));
			addConfigItem((new FILE_LINE(0) cConfigItem_yesno("quick_save_cdr", &opt_quick_save_cdr))
				->addValues("quick:2"));
		setDisableIfEnd();
	group("SIP protocol / headers");
		setDisableIfBegin("sniffer_mode=" + snifferMode_sender_str);
		subgroup("main");
			addConfigItem((new FILE_LINE(42270) cConfigItem_ports("sipport", sipportmatrix))
				->setDefaultValueStr("5060")
				->setClearBeforeFirstSet());
			addConfigItem(new FILE_LINE(42271) cConfigItem_yesno("cdr_sipport", &opt_cdr_sipport));
			addConfigItem(new FILE_LINE(42272) cConfigItem_yesno("domainport", &opt_domainport));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("call_branches", &opt_call_branches));
				advanced();
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("call_branches_find_by_called_number", &opt_call_branches_find_by_called_number));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("call_branches_find_by_called_domain", &opt_call_branches_find_by_called_domain));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("call_branches_find_smart", &opt_call_branches_find_smart));
			normal();
			addConfigItem(new FILE_LINE(0) cConfigItem_string("call_id_alternative", opt_call_id_alternative, sizeof(opt_call_id_alternative)));
			addConfigItem((new FILE_LINE(42273) cConfigItem_string("fbasenameheader", opt_fbasename_header, sizeof(opt_fbasename_header)))
				->setPrefixSuffix("\n", ":")
				->addAlias("fbasename_header"));
			addConfigItem((new FILE_LINE(42274) cConfigItem_string("matchheader", opt_match_header, sizeof(opt_match_header)))
				->setPrefixSuffix("\n", ":")
				->addAlias("match_header"));
			addConfigItem((new FILE_LINE(42275) cConfigItem_string("callidmerge_header", opt_callidmerge_header, sizeof(opt_callidmerge_header)))
				->setPrefixSuffix("\n", ":"));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("callidmerge_force_separate_branches", &opt_callidmerge_force_separate_branches));
			addConfigItem(new FILE_LINE(42276) cConfigItem_string("callidmerge_secret", opt_callidmerge_secret, sizeof(opt_callidmerge_secret)));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("callernum_numberonly", &opt_callernum_numberonly));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-message", &opt_sip_message));
				advanced();
				addConfigItem(new FILE_LINE(42277) cConfigItem_yesno("custom_headers_last_value", &opt_custom_headers_last_value));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("custom_headers_max_size", &opt_custom_headers_max_size));
				addConfigItem(new FILE_LINE(42278) cConfigItem_yesno("remotepartyid", &opt_remotepartyid));
				addConfigItem(new FILE_LINE(42279) cConfigItem_yesno("passertedidentity", &opt_passertedidentity));
				addConfigItem(new FILE_LINE(42280) cConfigItem_yesno("ppreferredidentity", &opt_ppreferredidentity));
				addConfigItem(new FILE_LINE(42281) cConfigItem_yesno("remotepartypriority", &opt_remotepartypriority));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("remoteparty_caller", opt_remoteparty_caller, sizeof(opt_remoteparty_caller)));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("remoteparty_called", opt_remoteparty_called, sizeof(opt_remoteparty_called)));
				addConfigItem(new FILE_LINE(42282) cConfigItem_integer("destination_number_mode", &opt_destination_number_mode));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("cdr_sip_response_number_max_length", &opt_cdr_sip_response_number_max_length));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("cdr_sip_response_reg_remove", &opt_cdr_sip_response_reg_remove));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("cdr_sip_response_normalisation", &opt_cdr_sip_response_normalisation));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("cdr_sip_response_load_normalisation", &opt_cdr_sip_response_load_normalisation));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("cdr_reason_string_enable", &opt_cdr_reason_string_enable));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("cdr_reason_reg_remove", &opt_cdr_reason_reg_remove));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("cdr_reason_normalisation", &opt_cdr_reason_normalisation));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("cdr_reason_load_normalisation", &opt_cdr_reason_load_normalisation));
				addConfigItem(new FILE_LINE(42283) cConfigItem_yesno("cdr_ua_enable", &opt_cdr_ua_enable));
				addConfigItem(new FILE_LINE(42284) cConfigItem_string("cdr_ua_reg_remove", &opt_cdr_ua_reg_remove));
				addConfigItem(new FILE_LINE(42284) cConfigItem_string("cdr_ua_reg_whitelist", &opt_cdr_ua_reg_whitelist));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("cdr_ua_normalisation", &opt_cdr_ua_normalisation));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("cdr_ua_load_normalisation", &opt_cdr_ua_load_normalisation));
				addConfigItem(new FILE_LINE(42285) cConfigItem_yesno("sipoverlap", &opt_sipoverlap));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("last_dest_number", &opt_last_dest_number));
				addConfigItem(new FILE_LINE(42286) cConfigItem_yesno("update_dstnum_onanswer", &opt_update_dstnum_onanswer));
				addConfigItem(new FILE_LINE(42287) cConfigItem_integer("sdp_multiplication", &opt_sdp_multiplication));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("both_side_for_check_direction", &opt_both_side_for_check_direction));
				addConfigItem(new FILE_LINE(0) cConfigItem_ip_ports("sdp_ignore_ip_port", &opt_sdp_ignore_ip_port));
				addConfigItem(new FILE_LINE(0) cConfigItem_hosts("sdp_ignore_ip", &opt_sdp_ignore_ip, &opt_sdp_ignore_net));
				addConfigItem(new FILE_LINE(42288) cConfigItem_yesno("save_sip_responses", &opt_cdr_sipresp));
				addConfigItem((new FILE_LINE(42289) cConfigItem_string("save_sip_history", &opt_save_sip_history))
					->addStringItems("invite|bye|cancel|register|message|info|subscribe|options|notify|ack|prack|publish|refer|update|REQUESTS|RESPONSES|ALL"));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("active_call_info", &opt_active_call_info));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("disable_sdp_multiplication_warning", &opt_disable_sdp_multiplication_warning));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("enable_content_type_application_csta_xml", &opt_enable_content_type_application_csta_xml));
					expert();
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("hash_queue_length_ms", &opt_hash_modify_queue_length_ms));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("hash_queue_length_ms_high_traffic", &opt_hash_modify_queue_length_ms_high_traffic));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("disable_process_sdp", &opt_disable_process_sdp));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("conference_processing", &opt_conference_processing));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("conference_uri", &opt_conference_uri));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("mo_mt_identification_prefix", &opt_mo_mt_identification_prefix));
					addConfigItem((new FILE_LINE(0) cConfigItem_yesno("separate_storage_ipv6_ipv4_address", &opt_separate_storage_ipv6_ipv4_address))
						->addValues("confirmed:2|first:3|first_confirmed:4"));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("cdr_flag_bit", &opt_cdr_flag_bit));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("srvcc_numbers", &opt_srvcc_numbers));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("srvcc_compare_length", &opt_srvcc_compare_number_length));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("srvcc_processing_only", &opt_srvcc_processing_only));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("save_srvcc_cdr", &opt_save_srvcc_cdr));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("srvcc_correlation", &opt_srvcc_correlation));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip_only_tcp", &opt_sip_only_tcp));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("max_sip_packets_in_call", &opt_max_sip_packets_in_call));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("max_invite_packets_in_call", &opt_max_invite_packets_in_call));
					addConfigItem((new FILE_LINE(0) cConfigItem_yesno("enable_semicolon_in_number", &opt_enable_semicolon_in_number))
						->addValues("force:2"));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("response_time_from_first_invite", &opt_response_time_from_first_invite));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("redirect_publish_to_call", &opt_redirect_publish_to_call));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("remove_rtp_streams_after_resp3xx", &opt_remove_rtp_streams_after_resp3xx));
		subgroup("REGISTER");
			addConfigItem((new FILE_LINE(42290) cConfigItem_yesno("sip-register", &opt_sip_register))
				->addValues("old:2|o:2|nodb:3"));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("save-sip-register", &opt_save_sip_register));
			addConfigItem(new FILE_LINE(42291) cConfigItem_integer("sip-register-timeout", &opt_register_timeout));
			addConfigItem(new FILE_LINE(42292) cConfigItem_yesno("sip-register-timeout-disable_save_failed", &opt_register_timeout_disable_save_failed));
				advanced();
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("sip-register-max-registers", &opt_register_max_registers));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("sip-register-max-messages", &opt_register_max_messages));
				addConfigItem(new FILE_LINE(42293) cConfigItem_yesno("sip-register-ignore-res401", &opt_register_ignore_res_401));
				addConfigItem(new FILE_LINE(42294) cConfigItem_yesno("sip-register-ignore-res401-nonce-has-changed", &opt_register_ignore_res_401_nonce_has_changed));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-register-compare-sipcallerip", &opt_sip_register_compare_sipcallerip));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-register-compare-sipcalledip", &opt_sip_register_compare_sipcalledip));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-register-compare-sipcallerip-encaps", &opt_sip_register_compare_sipcallerip_encaps));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-register-compare-sipcalledip-encaps", &opt_sip_register_compare_sipcalledip_encaps));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-register-compare-sipcallerport", &opt_sip_register_compare_sipcallerport));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-register-compare-sipcalledport", &opt_sip_register_compare_sipcalledport));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-register-compare-to_domain", &opt_sip_register_compare_to_domain));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-register-compare-vlan", &opt_sip_register_compare_vlan));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-register-state-compare-from_num", &opt_sip_register_state_compare_from_num));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-register-state-compare-from_name", &opt_sip_register_state_compare_from_name));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-register-state-compare-from_domain", &opt_sip_register_state_compare_from_domain));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-register-state-compare-contact_num", &opt_sip_register_state_compare_contact_num));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-register-state-compare-contact_domain", &opt_sip_register_state_compare_contact_domain));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-register-state-compare-digest_realm", &opt_sip_register_state_compare_digest_realm));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-register-state-compare-digest_ua", &opt_sip_register_state_compare_ua));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-register-state-compare-sipalg", &opt_sip_register_state_compare_sipalg));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-register-state-compare-vlan", &opt_sip_register_state_compare_vlan));
					expert();
					addConfigItem(new FILE_LINE(42295) cConfigItem_yesno("sip-register-save-all", &opt_sip_register_save_all));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("sip-register-state-timeout", &opt_sip_register_state_timeout));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-register-save-eq-states-time", &opt_sip_register_save_eq_states_time));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("sip-register-failed-max-details-per-minute", &opt_sip_register_failed_max_details_per_minute));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-register-deferred-save", &opt_sip_register_deferred_save));
					addConfigItem((new FILE_LINE(0) cConfigItem_yesno("sip-register-advanced", &opt_sip_register_advanced))
						->addValues("ext:2|extended:2"));
		subgroup("OPTIONS / SUBSCRIBE / NOTIFY");
			addConfigItem((new FILE_LINE(0) cConfigItem_yesno("sip-options", &opt_sip_options))
				->addValues("nodb:2"));
			addConfigItem((new FILE_LINE(0) cConfigItem_yesno("sip-subscribe", &opt_sip_subscribe))
				->addValues("nodb:2"));
			addConfigItem((new FILE_LINE(0) cConfigItem_yesno("sip-notify", &opt_sip_notify))
				->addValues("nodb:2"));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("save-sip-options", &opt_save_sip_options));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("save-sip-subscribe", &opt_save_sip_subscribe));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("save-sip-notify", &opt_save_sip_notify));
				advanced();
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-msg-compare-ip-src", &opt_sip_msg_compare_ip_src));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-msg-compare-ip-dst", &opt_sip_msg_compare_ip_dst));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-msg-compare-port-src", &opt_sip_msg_compare_port_src));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-msg-compare-port-dst", &opt_sip_msg_compare_port_dst));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-msg-compare-number-src", &opt_sip_msg_compare_number_src));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-msg-compare-number-dst", &opt_sip_msg_compare_number_dst));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-msg-compare-domain-src", &opt_sip_msg_compare_domain_src));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-msg-compare-domain-dst", &opt_sip_msg_compare_domain_dst));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-msg-compare-vlan", &opt_sip_msg_compare_vlan));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip-msg-save-ua", &opt_sip_msg_save_ua));
		subgroup("MESSAGE");
			addConfigItem(new FILE_LINE(42296) cConfigItem_yesno("hide_message_content", &opt_hide_message_content));
			addConfigItem(new FILE_LINE(42297) cConfigItem_string("hide_message_content_secret", opt_hide_message_content_secret, sizeof(opt_hide_message_content_secret)));
			addConfigItem(new FILE_LINE(42298) cConfigItem_string("message_body_url_reg", &opt_message_body_url_reg));
		subgroup("SIP send");
				advanced();
				addConfigItem(new FILE_LINE(42299) cConfigItem_ip_port("sip_send", &sipSendSocket_ip_port));
				addConfigItem((new FILE_LINE(42300) cConfigItem_string("sip_send_ip"))
					->setNaDefaultValueStr()
					->setMinor());
				addConfigItem((new FILE_LINE(42301) cConfigItem_integer("sip_send_port"))
					->setNaDefaultValueStr()
					->setMinor());
				addConfigItem(new FILE_LINE(42302) cConfigItem_yesno("sip_send_udp", &opt_sip_send_udp));
				addConfigItem(new FILE_LINE(42303) cConfigItem_yesno("sip_send_before_packetbuffer", &opt_sip_send_before_packetbuffer));
		setDisableIfEnd();
	group("RTP / DTMF / FAX options");
		setDisableIfBegin("sniffer_mode=" + snifferMode_sender_str);
		subgroup("main");
			addConfigItem(new FILE_LINE(42304) cConfigItem_integer("rtptimeout", &rtptimeout));
			addConfigItem(new FILE_LINE(42305) cConfigItem_yesno("cdr_rtpport", &opt_cdr_rtpport));
			addConfigItem(new FILE_LINE(42306) cConfigItem_yesno("cdr_rtpsrcport", &opt_cdr_rtpsrcport));
			addConfigItem(new FILE_LINE(42307) cConfigItem_integer("sipwithoutrtptimeout", &sipwithoutrtptimeout));
			addConfigItem(new FILE_LINE(42308) cConfigItem_yesno("allow-zerossrc", &opt_allow_zerossrc));
			addConfigItem(new FILE_LINE(42309) cConfigItem_yesno("rtp-check-timestamp", &opt_rtp_check_timestamp));
			addConfigItem(new FILE_LINE(42310) cConfigItem_yesno("rtp-firstleg", &opt_rtp_firstleg));
			addConfigItem(new FILE_LINE(42311) cConfigItem_yesno("saverfc2833", &opt_saverfc2833));
			addConfigItem(new FILE_LINE(42312) cConfigItem_yesno("dtmf2db", &opt_dbdtmf));
			addConfigItem(new FILE_LINE(42312) cConfigItem_yesno("dtmf2pcap", &opt_pcapdtmf));
			addConfigItem(new FILE_LINE(42313) cConfigItem_yesno("inbanddtmf", &opt_inbanddtmf));
			addConfigItem(new FILE_LINE(42314) cConfigItem_integer("silencethreshold", &opt_silencethreshold));
			addConfigItem(new FILE_LINE(42315) cConfigItem_yesno("sipalg_detect", &opt_sipalg_detect));
			addConfigItem(new FILE_LINE(42315) cConfigItem_yesno("fasdetect", &opt_fasdetect));
			addConfigItem(new FILE_LINE(42315) cConfigItem_yesno("silencedetect", &opt_silencedetect));
			addConfigItem(new FILE_LINE(42316) cConfigItem_yesno("clippingdetect", &opt_clippingdetect));
			addConfigItem(new FILE_LINE(42317) cConfigItem_yesno("norecord-header", &opt_norecord_header));
			addConfigItem(new FILE_LINE(42318) cConfigItem_yesno("norecord-dtmf", &opt_norecord_dtmf));
			addConfigItem(new FILE_LINE(42319) cConfigItem_string("pauserecordingdtmf", opt_silencedtmfseq, sizeof(opt_silencedtmfseq)));
			addConfigItem((new FILE_LINE(42320) cConfigItem_string("pauserecordingheader", opt_silenceheader, sizeof(opt_silenceheader)))
				->setPrefixSuffix("\n", ":"));
			addConfigItem(new FILE_LINE(42321) cConfigItem_integer("pauserecordingdtmf_timeout", &opt_pauserecordingdtmf_timeout));
			addConfigItem(new FILE_LINE(42322) cConfigItem_yesno("182queuedpauserecording", &opt_182queuedpauserecording));
			addConfigItem((new FILE_LINE(0) cConfigItem_string("energylevelheader", opt_energylevelheader, sizeof(opt_energylevelheader)))
				->setPrefixSuffix("\n", ":"));
			addConfigItem(new FILE_LINE(42323) cConfigItem_yesno("vlan_siprtpsame", &opt_vlan_siprtpsame));
			addConfigItem(new FILE_LINE(42324) cConfigItem_yesno("rtpfromsdp_onlysip", &opt_rtpfromsdp_onlysip));
			addConfigItem(new FILE_LINE(42324) cConfigItem_yesno("rtpfromsdp_onlysip_skinny", &opt_rtpfromsdp_onlysip_skinny));
				advanced();
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("rtp_streams_max_in_call", &opt_rtp_streams_max_in_call));
				addConfigItem((new FILE_LINE(0) cConfigItem_yesno("rtp_check_both_sides_by_sdp", &opt_rtp_check_both_sides_by_sdp))
					->addValues("keep_rtp_packets:2"));
				addConfigItem(new FILE_LINE(42325) cConfigItem_yesno("rtpmap_by_callerd", &opt_rtpmap_by_callerd));
				addConfigItem(new FILE_LINE(42326) cConfigItem_yesno("rtpmap_combination", &opt_rtpmap_combination));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("rtpmap_indirect", &opt_rtpmap_indirect));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("jitter_forcemark_transit_threshold", &opt_jitter_forcemark_transit_threshold));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("jitter_forcemark_delta_threshold", &opt_jitter_forcemark_delta_threshold));
				addConfigItem(new FILE_LINE(42327) cConfigItem_yesno("disable_rtp_warning", &opt_disable_rtp_warning));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("disable_rtp_seq_probation", &opt_disable_rtp_seq_probation));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("disable_rtp_seq_check", &opt_disable_rtp_seq_check));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("rtp_seq_dupl_skip_ext", &opt_rtp_seq_dupl_skip_ext));
					expert();
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sdp_check_direction_ext", &opt_sdp_check_direction_ext));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("rtp_count_all_sequencegap_as_loss", &opt_rtp_count_all_sequencegap_as_loss));
		subgroup("NAT");
			addConfigItem(new FILE_LINE(42328) cConfigItem_nat_aliases("natalias", &nat_aliases));
			addConfigItem(new FILE_LINE(42329) cConfigItem_yesno("sdp_reverse_ipport", &opt_sdp_reverse_ipport));
		subgroup("MOS");
			addConfigItem(new FILE_LINE(42330) cConfigItem_yesno("mos_g729", &opt_mos_g729));
			addConfigItem(new FILE_LINE(42331) cConfigItem_yesno("mos_lqo", &opt_mos_lqo));
			addConfigItem(new FILE_LINE(42332) cConfigItem_string("mos_lqo_bin", opt_mos_lqo_bin, sizeof(opt_mos_lqo_bin)));
			addConfigItem(new FILE_LINE(42333) cConfigItem_string("mos_lqo_ref", opt_mos_lqo_ref, sizeof(opt_mos_lqo_ref)));
			addConfigItem(new FILE_LINE(42334) cConfigItem_string("mos_lqo_ref16", opt_mos_lqo_ref16, sizeof(opt_mos_lqo_ref16)));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("ignore_mos_degradation_for_contiguous_packet_loss_greater_than", &opt_ignore_mos_degradation_for_contiguous_packet_loss_greater_than));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("ignore_mos_degradation_in_rtp_pause_without_seq_gap", &opt_ignore_mos_degradation_in_rtp_pause_without_seq_gap));
		subgroup("FAX");
			addConfigItem(new FILE_LINE(42335) cConfigItem_yesno("faxdetect", &opt_faxt30detect));
		subgroup("jitterbufer");
			addConfigItem((new FILE_LINE(42336) cConfigItem_yesno("jitterbuffer_f1", &opt_jitterbuffer_f1))
				->addValues("null:-1"));
			addConfigItem((new FILE_LINE(42337) cConfigItem_yesno("jitterbuffer_f2", &opt_jitterbuffer_f2))
				->addValues("null:-1"));
			addConfigItem((new FILE_LINE(42338) cConfigItem_yesno("jitterbuffer_adapt", &opt_jitterbuffer_adapt))
				->addValues("null:-1"));
			addConfigItem(new FILE_LINE(42339) cConfigItem_yesno("enable_jitterbuffer_asserts", &opt_enable_jitterbuffer_asserts));
				advanced();
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("jitterbuffer_f1_jbsize", &opt_jitterbuffer_f1_jbsize));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("jitterbuffer_f1_resync_threshold", &opt_jitterbuffer_f1_resync_threshold));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("jitterbuffer_f2_jbsize", &opt_jitterbuffer_f2_jbsize));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("jitterbuffer_f2_resync_threshold", &opt_jitterbuffer_f2_resync_threshold));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("jitterbuffer_adapt_jbsize", &opt_jitterbuffer_adapt_jbsize));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("jitterbuffer_adapt_resync_threshold", &opt_jitterbuffer_adapt_resync_threshold));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("jitterbuffer_adapt_ooo_limit", &opt_jitterbuffer_adapt_ooo_limit));
		setDisableIfEnd();
	group("system");
		addConfigItem((new FILE_LINE(42340) cConfigItem_string("pcapcommand", pcapcommand, sizeof(pcapcommand)))
			->setReadOnly());
		addConfigItem((new FILE_LINE(42341) cConfigItem_string("filtercommand", filtercommand, sizeof(filtercommand)))
			->setReadOnly());
		addConfigItem(new FILE_LINE(42342) cConfigItem_integer("openfile_max", &opt_openfile_max));
		addConfigItem(new FILE_LINE(42343) cConfigItem_yesno("rrd", &opt_rrd));
		addConfigItem(new FILE_LINE(42344) cConfigItem_string("php_path", opt_php_path, sizeof(opt_php_path)));
		addConfigItem(new FILE_LINE(42345) cConfigItem_string("syslog_string", opt_syslog_string, sizeof(opt_syslog_string)));
		addConfigItem(new FILE_LINE(42346) cConfigItem_integer("cpu_limit_new_thread", &opt_cpu_limit_new_thread));
		addConfigItem(new FILE_LINE(42346) cConfigItem_integer("cpu_limit_new_thread_if_heap_grows", &opt_cpu_limit_new_thread_if_heap_grows));
		addConfigItem(new FILE_LINE(0) cConfigItem_integer("cpu_limit_new_thread_high", &opt_cpu_limit_new_thread_high));
		addConfigItem(new FILE_LINE(42347) cConfigItem_integer("cpu_limit_delete_thread", &opt_cpu_limit_delete_thread));
		addConfigItem(new FILE_LINE(42348) cConfigItem_integer("cpu_limit_delete_t2sip_thread", &opt_cpu_limit_delete_t2sip_thread));
		addConfigItem(new FILE_LINE(0) cConfigItem_integer("heap_limit_new_thread", &opt_heap_limit_new_thread));
		addConfigItem(new FILE_LINE(0) cConfigItem_integer("memory_purge_interval", &opt_memory_purge_interval));
		addConfigItem(new FILE_LINE(0) cConfigItem_integer("memory_purge_if_release_gt", &opt_memory_purge_if_release_gt));
	group("upgrade");
		addConfigItem(new FILE_LINE(42349) cConfigItem_yesno("upgrade_try_http_if_https_fail", &opt_upgrade_try_http_if_https_fail));
		addConfigItem(new FILE_LINE(42350) cConfigItem_string("curlproxy", opt_curlproxy, sizeof(opt_curlproxy)));
		addConfigItem(new FILE_LINE(42351) cConfigItem_yesno("upgrade_by_git", &opt_upgrade_by_git));
		addConfigItem(new FILE_LINE(42352) cConfigItem_string("git_folder", opt_git_folder, sizeof(opt_git_folder)));
		addConfigItem(new FILE_LINE(42352) cConfigItem_string("configure_param", opt_configure_param, sizeof(opt_configure_param)));
	group("locale");
		addConfigItem(new FILE_LINE(42353) cConfigItem_string("local_country_code", opt_local_country_code, sizeof(opt_local_country_code)));
		addConfigItem(new FILE_LINE(42354) cConfigItem_string("timezone", opt_timezone, sizeof(opt_timezone)));
	group("ipaccount");
			advanced();
			addConfigItem(new FILE_LINE(42355) cConfigItem_yesno("ipaccount", &opt_ipaccount));
			addConfigItem(new FILE_LINE(42356) cConfigItem_ports("ipaccountport", ipaccountportmatrix));
			addConfigItem(new FILE_LINE(42357) cConfigItem_integer("ipaccount_interval", &opt_ipacc_interval));
			addConfigItem(new FILE_LINE(42358) cConfigItem_integer("ipaccount_only_agregation", &opt_ipacc_only_agregation));
				expert();
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ipaccount_enable_agregation_both_sides", &opt_ipacc_enable_agregation_both_sides));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("ipaccount_limit_agregation_both_sides", &opt_ipacc_limit_agregation_both_sides));
				addConfigItem(new FILE_LINE(42359) cConfigItem_yesno("ipaccount_sniffer_agregate", &opt_ipacc_sniffer_agregate));
				addConfigItem(new FILE_LINE(42360) cConfigItem_yesno("ipaccount_agregate_only_customers_on_main_side", &opt_ipacc_agregate_only_customers_on_main_side));
				addConfigItem(new FILE_LINE(42361) cConfigItem_yesno("ipaccount_agregate_only_customers_on_any_side", &opt_ipacc_agregate_only_customers_on_any_side));
	group("ss7");
			advanced();
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ss7", &opt_enable_ss7));
				expert();
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ss7_use_sam_subsequent_number", &opt_ss7_use_sam_subsequent_number));
				addConfigItem((new FILE_LINE(0) cConfigItem_yesno("ss7callid", &opt_ss7_type_callid))
					->disableNo()
					->addValues("cic_dpc_opc:1|cic:2")
					->setDefaultValueStr("cic_dpc_opc"));
				addConfigItem(new FILE_LINE(0) cConfigItem_ports("ss7port", ss7portmatrix));
				addConfigItem(new FILE_LINE(0) cConfigItem_ports("ss7_rudp_port", ss7_rudp_portmatrix));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("ss7_rlc_timeout", &opt_ss7timeout_rlc));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("ss7_rel_timeout", &opt_ss7timeout_rel));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("ss7_timeout", &opt_ss7timeout));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("ws_param", &opt_ws_params));
	group("diameter");
			advanced();
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("diameter", &opt_enable_diameter));
			addConfigItem(new FILE_LINE(0) cConfigItem_ports("diameter_tcp_ports", diameter_tcp_portmatrix));
			addConfigItem(new FILE_LINE(0) cConfigItem_ports("diameter_udp_ports", diameter_udp_portmatrix));
				expert();
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("diameter_ignore_domain", &opt_diameter_ignore_domain));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("diameter_ignore_prefix", &opt_diameter_ignore_prefix));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("diameter_time_overlap", &opt_diameter_time_overlap));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("diameter_reassymbly_all_complete_after_zerodata_ack", &opt_diameter_reassymbly_all_complete_after_zerodata_ack));
	minorGroupIfNotSetBegin();
	group("http");
			advanced();
			addConfigItem((new FILE_LINE(42362) cConfigItem_yesno("http", &opt_enable_http))
				->addValue("only", 2)
				->addAlias("tcpreassembly"));
			addConfigItem(new FILE_LINE(42363) cConfigItem_ports("httpport", httpportmatrix));
			addConfigItem(new FILE_LINE(42364) cConfigItem_hosts("httpip", &httpip, &httpnet));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("http_cleanup_ext", &opt_http_cleanup_ext));
				expert();
				addConfigItem((new FILE_LINE(42365) cConfigItem_yesno("enable_http_enum_tables", &opt_enable_http_enum_tables))
					->addAlias("enable_lua_tables"));
	group("webrtc");
			advanced();
			addConfigItem((new FILE_LINE(42366) cConfigItem_yesno("webrtc", &opt_enable_webrtc))
				->addValue("only", 2));
			addConfigItem(new FILE_LINE(42367) cConfigItem_ports("webrtcport", webrtcportmatrix));
			addConfigItem(new FILE_LINE(42368) cConfigItem_hosts("webrtcip", &webrtcip, &webrtcnet));
				expert();
				addConfigItem(new FILE_LINE(42369) cConfigItem_yesno("enable_webrtc_table", &opt_enable_webrtc_table));
	group("ipaccount extended");
				expert();
				addConfigItem(new FILE_LINE(42370) cConfigItem_string("get_customer_by_ip_sql_driver", get_customer_by_ip_sql_driver, sizeof(get_customer_by_ip_sql_driver)));
				addConfigItem(new FILE_LINE(42371) cConfigItem_string("get_customer_by_ip_odbc_dsn", get_customer_by_ip_odbc_dsn, sizeof(get_customer_by_ip_odbc_dsn)));
				addConfigItem(new FILE_LINE(42372) cConfigItem_string("get_customer_by_ip_odbc_user", get_customer_by_ip_odbc_user, sizeof(get_customer_by_ip_odbc_user)));
				addConfigItem(new FILE_LINE(42373) cConfigItem_string("get_customer_by_ip_odbc_password", get_customer_by_ip_odbc_password, sizeof(get_customer_by_ip_odbc_password)));
				addConfigItem(new FILE_LINE(42374) cConfigItem_string("get_customer_by_ip_odbc_driver", get_customer_by_ip_odbc_driver, sizeof(get_customer_by_ip_odbc_driver)));
				addConfigItem(new FILE_LINE(42375) cConfigItem_string("get_customer_by_ip_query", get_customer_by_ip_query, sizeof(get_customer_by_ip_query)));
				addConfigItem(new FILE_LINE(42376) cConfigItem_string("get_customers_ip_query", get_customers_ip_query, sizeof(get_customers_ip_query)));
				addConfigItem(new FILE_LINE(42377) cConfigItem_string("get_customers_radius_name_query", get_customers_radius_name_query, sizeof(get_customers_radius_name_query)));
				addConfigItem(new FILE_LINE(42378) cConfigItem_string("get_customer_by_pn_sql_driver", get_customer_by_pn_sql_driver, sizeof(get_customer_by_pn_sql_driver)));
				addConfigItem(new FILE_LINE(42379) cConfigItem_string("get_customer_by_pn_odbc_dsn", get_customer_by_pn_odbc_dsn, sizeof(get_customer_by_pn_odbc_dsn)));
				addConfigItem(new FILE_LINE(42380) cConfigItem_string("get_customer_by_pn_odbc_user", get_customer_by_pn_odbc_user, sizeof(get_customer_by_pn_odbc_user)));
				addConfigItem(new FILE_LINE(42381) cConfigItem_string("get_customer_by_pn_odbc_password", get_customer_by_pn_odbc_password, sizeof(get_customer_by_pn_odbc_password)));
				addConfigItem(new FILE_LINE(42382) cConfigItem_string("get_customer_by_pn_odbc_driver", get_customer_by_pn_odbc_driver, sizeof(get_customer_by_pn_odbc_driver)));
				addConfigItem(new FILE_LINE(42383) cConfigItem_string("get_customers_pn_query", get_customers_pn_query, sizeof(get_customers_pn_query)));
				addConfigItem(new FILE_LINE(42384) cConfigItem_string("national_prefix", &opt_national_prefix));
				addConfigItem(new FILE_LINE(42385) cConfigItem_string("get_radius_ip_driver", get_radius_ip_driver, sizeof(get_radius_ip_driver)));
				addConfigItem(new FILE_LINE(42386) cConfigItem_string("get_radius_ip_host", get_radius_ip_host, sizeof(get_radius_ip_host)));
				addConfigItem(new FILE_LINE(42387) cConfigItem_string("get_radius_ip_db", get_radius_ip_db, sizeof(get_radius_ip_db)));
				addConfigItem(new FILE_LINE(42388) cConfigItem_string("get_radius_ip_user", get_radius_ip_user, sizeof(get_radius_ip_user)));
				addConfigItem(new FILE_LINE(42389) cConfigItem_string("get_radius_ip_password", get_radius_ip_password, sizeof(get_radius_ip_password)));
				addConfigItem(new FILE_LINE(42390) cConfigItem_yesno("get_radius_ip_disable_secure_auth", &get_radius_ip_disable_secure_auth));
				addConfigItem(new FILE_LINE(42391) cConfigItem_string("get_radius_ip_query", get_radius_ip_query, sizeof(get_radius_ip_query)));
				addConfigItem(new FILE_LINE(42392) cConfigItem_string("get_radius_ip_query_where", get_radius_ip_query_where, sizeof(get_radius_ip_query_where)));
				addConfigItem(new FILE_LINE(42393) cConfigItem_integer("get_customer_by_ip_flush_period", &get_customer_by_ip_flush_period));
	minorGroupIfNotSetEnd();

	minorBegin();
	group("other");
		subgroup("sensor id");
			addConfigItem((new FILE_LINE(42394) cConfigItem_integer("id_sensor", &opt_id_sensor))
				->setReadOnly());
			addConfigItem(new FILE_LINE(42395) cConfigItem_string("name_sensor", opt_name_sensor, sizeof(opt_name_sensor)));
				advanced();
				addConfigItem(new FILE_LINE(42396) cConfigItem_yesno("spooldir_by_sensor", &opt_spooldir_by_sensor));
					expert();
					addConfigItem(new FILE_LINE(42397) cConfigItem_yesno("spooldir_by_sensorname", &opt_spooldir_by_sensorname));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("use_id_sensor_for_receiver_in_files", &opt_use_id_sensor_for_receiver_in_files));
		subgroup("sql");
			addConfigItem(new FILE_LINE(42398) cConfigItem_string("mysqldb", mysql_database, sizeof(mysql_database)));
				advanced();
				addConfigItem(new FILE_LINE(42399) cConfigItem_string("mysqldb_2", mysql_2_database, sizeof(mysql_2_database)));
				addConfigItem(new FILE_LINE(42400) cConfigItem_yesno("mysql_client_compress", &opt_mysql_client_compress));
					expert();
					addConfigItem(new FILE_LINE(42401) cConfigItem_string("odbcdsn", odbc_dsn, sizeof(odbc_dsn)));
					addConfigItem(new FILE_LINE(42402) cConfigItem_string("odbcuser", odbc_user, sizeof(odbc_user)));
					addConfigItem(new FILE_LINE(42403) cConfigItem_string("odbcpass", odbc_password, sizeof(odbc_password)));
					addConfigItem(new FILE_LINE(42404) cConfigItem_string("odbcdriver", odbc_driver, sizeof(odbc_driver)));
					addConfigItem(new FILE_LINE(42405) cConfigItem_yesno("cdr_partition", &opt_cdr_partition));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("cdr_partition_by_hours", &opt_cdr_partition_by_hours));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("cdr_force_primary_index_in_all_tables", &opt_cdr_force_primary_index_in_all_tables));
					addConfigItem(new FILE_LINE(42406) cConfigItem_yesno("save_query_to_files", &opt_save_query_main_to_files));
					addConfigItem(new FILE_LINE(42407) cConfigItem_string("save_query_to_files_directory", opt_save_query_to_files_directory, sizeof(opt_save_query_to_files_directory)));
					addConfigItem(new FILE_LINE(42408) cConfigItem_integer("save_query_to_files_period", &opt_save_query_to_files_period));
					addConfigItem((new FILE_LINE(42409) cConfigItem_yesno("load_query_from_files", &opt_load_query_main_from_files))
						->addValue("only", 2));
					addConfigItem(new FILE_LINE(42410) cConfigItem_string("load_query_from_files_directory", opt_load_query_from_files_directory, sizeof(opt_load_query_from_files_directory)));
					addConfigItem(new FILE_LINE(42411) cConfigItem_integer("load_query_from_files_period", &opt_load_query_from_files_period));
					addConfigItem(new FILE_LINE(42412) cConfigItem_yesno("load_query_from_files_inotify", &opt_load_query_from_files_inotify));
					addConfigItem(new FILE_LINE(42413) cConfigItem_yesno("mysqlloadconfig", &opt_mysqlloadconfig));
						obsolete();
						addConfigItem((new FILE_LINE(42414) cConfigItem_custom_headers("custom_headers_cdr", &opt_custom_headers_cdr))
							->addAlias("custom_headers"));
						addConfigItem(new FILE_LINE(42415) cConfigItem_custom_headers("custom_headers_message", &opt_custom_headers_message));
						addConfigItem(new FILE_LINE(42416) cConfigItem_string("sqlcdrtable", sql_cdr_table, sizeof(sql_cdr_table)));
						addConfigItem(new FILE_LINE(42417) cConfigItem_string("sqlcdrtable_last30d", sql_cdr_table_last30d, sizeof(sql_cdr_table_last30d)));
						addConfigItem(new FILE_LINE(42418) cConfigItem_string("sqlcdrtable_last7d", sql_cdr_table_last7d, sizeof(sql_cdr_table_last1d)));
						addConfigItem(new FILE_LINE(42419) cConfigItem_string("sqlcdrtable_last1d", sql_cdr_table_last7d, sizeof(sql_cdr_table_last1d)));
						addConfigItem((new FILE_LINE(42420) cConfigItem_string("sqlcdrnexttable", sql_cdr_next_table, sizeof(sql_cdr_next_table)))
							->addAlias("sqlcdr_next_table"));
						addConfigItem((new FILE_LINE(42421) cConfigItem_string("sqlcdruatable", sql_cdr_ua_table, sizeof(sql_cdr_ua_table)))
							->addAlias("sqlcdr_ua_table"));
						addConfigItem((new FILE_LINE(42422) cConfigItem_string("sqlcdrsipresptable", sql_cdr_sip_response_table, sizeof(sql_cdr_sip_response_table)))
							->addAlias("sqlcdr_sipresp_table"));
		subgroup("interface - read packets");
					expert();
					addConfigItem(new FILE_LINE(42423) cConfigItem_integer("rtp_qring_length", &rtp_qring_length));
					addConfigItem(new FILE_LINE(42424) cConfigItem_integer("rtp_qring_usleep", &rtp_qring_usleep));
					addConfigItem(new FILE_LINE(42425) cConfigItem_integer("rtp_qring_batch_length", &rtp_qring_batch_length));
		subgroup("mirroring");
					expert();
					addConfigItem(new FILE_LINE(42426) cConfigItem_yesno("mirrorip", &opt_mirrorip));
					addConfigItem(new FILE_LINE(42427) cConfigItem_yesno("mirrorall", &opt_mirrorall));
					addConfigItem(new FILE_LINE(42428) cConfigItem_yesno("mirroronly", &opt_mirroronly));
					addConfigItem(new FILE_LINE(42429) cConfigItem_string("mirroripsrc", opt_mirrorip_src, sizeof(opt_mirrorip_src)));
					addConfigItem(new FILE_LINE(42430) cConfigItem_string("mirroripdst", opt_mirrorip_dst, sizeof(opt_mirrorip_dst)));
		#ifndef FREEBSD
		subgroup("scanpcapdir");
				advanced();
				char scanpcapmethod_values[100];
				snprintf(scanpcapmethod_values, sizeof(scanpcapmethod_values), "newfile:%i|close:%i|moved:%i|r:%i", IN_CLOSE_WRITE, IN_CLOSE_WRITE, IN_MOVED_TO, IN_MOVED_TO);
				addConfigItem((new FILE_LINE(42431) cConfigItem_yesno("scanpcapmethod", &opt_scanpcapmethod))
					->disableYes()
					->disableNo()
					->addValues(scanpcapmethod_values));
				addConfigItem(new FILE_LINE(42432) cConfigItem_yesno("scanpcapdir_disable_inotify", &opt_scanpcapdir_disable_inotify));
		#endif
		subgroup("manager");
				advanced();
				addConfigItem(new FILE_LINE(42435) cConfigItem_yesno("manager_nonblock_mode", &opt_manager_nonblock_mode));
					expert();
					addConfigItem(new FILE_LINE(42436) cConfigItem_string("manager_sshhost", ssh_host, sizeof(ssh_host)));
					addConfigItem(new FILE_LINE(42437) cConfigItem_integer("manager_sshport", &ssh_port));
					addConfigItem(new FILE_LINE(42438) cConfigItem_string("manager_sshusername", ssh_username, sizeof(ssh_username)));
					addConfigItem(new FILE_LINE(42439) cConfigItem_string("manager_sshpassword", ssh_password, sizeof(ssh_password)));
					addConfigItem(new FILE_LINE(42440) cConfigItem_string("manager_sshremoteip", ssh_remote_listenhost, sizeof(ssh_remote_listenhost)));
					addConfigItem(new FILE_LINE(42441) cConfigItem_integer("manager_sshremoteport", &ssh_remote_listenport));
		subgroup("spool - cleaning");
						 obsolete();
						 addConfigItem(new FILE_LINE(42442) cConfigItem_integer("cleanspool_size", &opt_cleanspool_sizeMB));
		subgroup("packetbuffer & memory");
					expert();
					addConfigItem((new FILE_LINE(42443) cConfigItem_integer("packetbuffer_total_maxheap", &opt_pcap_queue_store_queue_max_memory_size))
						->setMultiple(1024 * 1024));
					addConfigItem((new FILE_LINE(42444) cConfigItem_yesno("packetbuffer_compress_method"))
						->addValues("snappy:1|s:1|lz4:2|l:2")
						->setDefaultValueStr("no"));
					addConfigItem(new FILE_LINE(42445) cConfigItem_integer("packetbuffer_compress_ratio", &opt_pcap_queue_compress_ratio));
						obsolete();
						addConfigItem(new FILE_LINE(42446) cConfigItem_yesno("pcap_dispatch", &opt_pcap_dispatch));
		subgroup("storing packets into pcap files, graph, audio");
					expert();
					addConfigItem(new FILE_LINE(42447) cConfigItem_type_compress("pcap_dump_zip", (FileZipHandler::eTypeCompress*)NULL));
					addConfigItem(new FILE_LINE(42448) cConfigItem_type_compress("pcap_dump_zip_all", (FileZipHandler::eTypeCompress*)NULL));
					addConfigItem((new FILE_LINE(42449) cConfigItem_integer("pcap_dump_ziplevel"))
						->addAlias("pcap_dump_compresslevel"));
					addConfigItem(new FILE_LINE(42450) cConfigItem_integer("pcap_dump_writethreads_max", &opt_pcap_dump_writethreads_max));
					addConfigItem(new FILE_LINE(42451) cConfigItem_yesno("pcapsplit", &opt_pcap_split));
					addConfigItem((new FILE_LINE(42452) cConfigItem_yesno("spooldiroldschema", &opt_newdir))
						->setNeg());
					addConfigItem((new FILE_LINE(42453) cConfigItem_integer("pcap_dump_asyncwrite_maxsize", &opt_pcap_dump_asyncwrite_maxsize))
						->addAlias("pcap_dump_asyncbuffer"));
		subgroup("cloud");
			addConfigItem(new FILE_LINE(42454) cConfigItem_string("cloud_host", cloud_host, sizeof(cloud_host)));
			addConfigItem(new FILE_LINE(42456) cConfigItem_string("cloud_token", cloud_token, sizeof(cloud_token)));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("cloud_router", &cloud_router));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("cloud_router_port", &cloud_router_port));
			addConfigItem(new FILE_LINE(0) cConfigItem_string("cloud_db_version", &cloud_db_version));
			addConfigItem(new FILE_LINE(42457) cConfigItem_integer("cloud_activecheck_period", &opt_cloud_activecheck_period));
		subgroup("server / client");
			addConfigItem(new FILE_LINE(0) cConfigItem_string("server_bind", &snifferServerOptions.host));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("server_bind_port", &snifferServerOptions.port));
			addConfigItem(new FILE_LINE(0) cConfigItem_string("server_destination", &snifferClientOptions.hosts.hosts_str));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("server_destination_port", &snifferClientOptions.port));
			addConfigItem(new FILE_LINE(0) cConfigItem_string("server_destination_charts_cache", &snifferClientOptions_charts_cache.hosts.hosts_str));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("server_destination_port_charts_cache", &snifferClientOptions_charts_cache.port));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("remote_query", &snifferClientOptions.remote_query));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("remote_store", &snifferClientOptions.remote_store));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("packetbuffer_sender", &snifferClientOptions.packetbuffer_sender));
			addConfigItem((new FILE_LINE(0) cConfigItem_string("server_password", &snifferServerClientOptions.password))
				->setPassword());
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("remote_chart_server", &snifferClientOptions.remote_chart_server));
				advanced();
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("server_sql_queue_limit", &snifferServerOptions.mysql_queue_limit));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("server_sql_redirect_queue_limit", &snifferServerOptions.mysql_redirect_queue_limit));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("server_sql_concat_limit", &snifferServerOptions.mysql_concat_limit));
				addConfigItem((new FILE_LINE(0) cConfigItem_yesno("server_type_compress", (int*)&snifferServerOptions.type_compress))
					->addValues("gzip:1|zip:1|lzo:2|zstd:3")
					#ifdef HAVE_LIBZSTD
					->setDefaultValueStr("zstd")
					#else
					->setDefaultValueStr("yes")
					#endif
					);
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("server_cp_store_simple_connect_response", &snifferServerOptions.cp_store_simple_connect_response));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("client_server_connect_maximum_time_diff_s", &opt_client_server_connect_maximum_time_diff_s));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("client_server_sleep_ms_if_queue_is_full", &opt_client_server_sleep_ms_if_queue_is_full));
		subgroup("other");
			addConfigItem(new FILE_LINE(42459) cConfigItem_string("keycheck", opt_keycheck, sizeof(opt_keycheck)));
			addConfigItem(new FILE_LINE(0) cConfigItem_string("vmcodecs_path", opt_vmcodecs_path, sizeof(opt_vmcodecs_path)));
			addConfigItem((new FILE_LINE(0) cConfigItem_yesno("cdr_stat", &opt_cdr_stat_values))
				->addValues("source:1|s:1|destination:2|d:2|both:3|b:3"));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("cdr_stat_sources", &opt_cdr_stat_sources));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("cdr_stat_interval", &opt_cdr_stat_interval));
			addConfigItem((new FILE_LINE(0) cConfigItem_yesno("cdr_problems", &opt_cdr_problems))
				->addValues("source:1|s:1|destination:2|d:2|both:3|b:3"));
			addConfigItem(new FILE_LINE(0) cConfigItem_string("cdr_problems_by"));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("cdr_problems_by_ip", &opt_cdr_problems_by_ip));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("cdr_problems_by_number", &opt_cdr_problems_by_number));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("cdr_problems_by_comb", &opt_cdr_problems_by_comb));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("cdr_problems_interval", &opt_cdr_problems_interval));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("cdr_problems_list_ip_refresh_interval", &opt_cdr_problems_list_ip_refresh_interval));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("charts_cache", &opt_charts_cache));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("charts_cache_max_threads", &opt_charts_cache_max_threads));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("charts_cache_store", &opt_charts_cache_store));
			addConfigItem(new FILE_LINE(0) cConfigItem_yesno("charts_cache_ip_boost", &opt_charts_cache_ip_boost));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("charts_cache_queue_limit", &opt_charts_cache_queue_limit));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("charts_cache_remote_queue_limit", &opt_charts_cache_remote_queue_limit));
			addConfigItem(new FILE_LINE(0) cConfigItem_integer("charts_cache_remote_concat_limit", &opt_charts_cache_remote_concat_limit));
				advanced();
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("watchdog", &enable_wdt));
				addConfigItem(new FILE_LINE(0) cConfigItem_string("watchdog_run_command", &wdt_run_command));
				addConfigItem(new FILE_LINE(42460) cConfigItem_yesno("printinsertid", &opt_printinsertid));
				addConfigItem(new FILE_LINE(42461) cConfigItem_yesno("virtualudppacket", &opt_virtualudppacket));
				addConfigItem(new FILE_LINE(42462) cConfigItem_integer("sip_tcp_reassembly_stream_timeout", &opt_sip_tcp_reassembly_stream_timeout));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("sip_tcp_reassembly_stream_max_attempts", &opt_sip_tcp_reassembly_stream_max_attempts));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("sip_tcp_reassembly_stream_max_length", &opt_sip_tcp_reassembly_stream_max_length));
				addConfigItem(new FILE_LINE(42463) cConfigItem_integer("sip_tcp_reassembly_clean_period", &opt_sip_tcp_reassembly_clean_period));
				addConfigItem(new FILE_LINE(42464) cConfigItem_yesno("sip_tcp_reassembly_ext", &opt_sip_tcp_reassembly_ext));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("sip_tcp_reassembly_ext_link_timeout", &opt_sip_tcp_reassembly_ext_link_timeout));
				addConfigItem((new FILE_LINE(0) cConfigItem_yesno("sip_tcp_reassembly_ext_quick_mod", &opt_sip_tcp_reassembly_ext_quick_mod))
					->addValues("ext:2|comb_ext:3"));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sip_tcp_reassembly_ext_complete_mod", &opt_sip_tcp_reassembly_ext_complete_mod));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("sip_tcp_reassembly_ext_usleep", &opt_sip_tcp_reassembly_ext_usleep));
				addConfigItem(new FILE_LINE(0) cConfigItem_yesno("receiver_check_id_sensor", &opt_receiver_check_id_sensor));
				addConfigItem(new FILE_LINE(0) cConfigItem_integer("receive_packetbuffer_maximum_time_diff_s", &opt_receive_packetbuffer_maximum_time_diff_s));
					expert();
					addConfigItem(new FILE_LINE(42465) cConfigItem_integer("rtpthread-buffer",  &rtpthreadbuffer));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("udp_port_l2tp",  &opt_udp_port_l2tp));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("udp_port_tzsp",  &opt_udp_port_tzsp));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("udp_port_vxlan",  &opt_udp_port_vxlan));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("udp_port_hperm",  &opt_udp_port_hperm));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("icmp_process_data",  &opt_icmp_process_data));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ipfix",  &opt_ipfix));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("ipfix_bind_ip",  &opt_ipfix_bind_ip));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("ipfix_bind_port",  &opt_ipfix_bind_port));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("ipfix_version",  &opt_ipfix_version));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ipfix_counter_log",  &opt_ipfix_counter_log));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ipfix_via_pb",  &opt_ipfix_via_pb));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("hep",  &opt_hep));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("hep_bind_ip",  &opt_hep_bind_ip));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("hep_bind_port",  &opt_hep_bind_port));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("hep_bind_udp",  &opt_hep_bind_udp));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("hep_counter_log",  &opt_hep_counter_log));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("hep_kamailio_protocol_id_fix", &opt_hep_kamailio_protocol_id_fix));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("hep_via_pb",  &opt_hep_via_pb));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("audiocodes",  &opt_audiocodes));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("udp_port_audiocodes",  &opt_udp_port_audiocodes));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("tcp_port_audiocodes",  &opt_tcp_port_audiocodes));
					addConfigItem((new FILE_LINE(0) cConfigItem_yesno("audiocodes_rtp",  &opt_audiocodes_rtp))
						->addValues("only:2|only_for_audiocodes_sip:3"));
					addConfigItem((new FILE_LINE(0) cConfigItem_yesno("audiocodes_rtcp",  &opt_audiocodes_rtcp))
						->addValues("only:2|only_for_audiocodes_sip:3"));
					addConfigItem(new FILE_LINE(0) cConfigItem_ports("audiocodes_sip_ports", &opt_audiocodes_sip_ports));
					addConfigItem(new FILE_LINE(0) cConfigItem_ip("kamailio_dstip",  &opt_kamailio_dstip));
					addConfigItem(new FILE_LINE(0) cConfigItem_ip("kamailio_srcip",  &opt_kamailio_srcip));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("kamailio_port",  &opt_kamailio_port ));
					addConfigItem(new FILE_LINE(0) cConfigItem_ip("ribbonsbc_dstip",  &opt_ribbonsbc_dstip));
					addConfigItem(new FILE_LINE(0) cConfigItem_ip("ribbonsbc_srcip",  &opt_ribbonsbc_srcip));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("ribbonsbc_port",  &opt_ribbonsbc_port));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("socket_use_poll",  &opt_socket_use_poll));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("interrupts_counters",  &opt_interrupts_counters));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("ipv6", &useIPv6));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("hashtable_heap_size", &opt_hashtable_heap_size));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("hugepages_anon", &opt_hugepages_anon));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("hugepages_max", &opt_hugepages_max));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("hugepages_overcommit_max", &opt_hugepages_overcommit_max));
					addConfigItem((new FILE_LINE(0) cConfigItem_yesno("hugepages_second_heap", &opt_hugepages_second_heap))
						->addValues("all:1|call:2|packetbuffer:3")
						->setDefaultValueStr("no"));
					addConfigItem((new FILE_LINE(0) cConfigItem_yesno("numa_balancing_set", &opt_numa_balancing_set))
						->addValues(("autodisable:" + intToString(numa_balancing_set_autodisable) + "|" + 
							     "enable:" + intToString(numa_balancing_set_enable) + "|" +
							     "disable:" + intToString(numa_balancing_set_disable)).c_str()));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("abort_if_rss_gt_gb", &opt_abort_if_rss_gt_gb));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("abort_if_alloc_gt_gb", &opt_abort_if_alloc_gt_gb));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("abort_if_heap_full", &opt_abort_if_heap_full));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("exit_if_heap_full", &opt_exit_if_heap_full));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("abort_if_heap_full_and_t2cpu_is_low", &opt_abort_if_heap_full_and_t2cpu_is_low));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("exit_if_heap_full_and_t2cpu_is_low", &opt_exit_if_heap_full_and_t2cpu_is_low));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("next_server_connections", &opt_next_server_connections));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("coredump_filter", &opt_coredump_filter));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("all_configuration_options_in_gui", &opt_all_configuration_options_in_gui));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("all_unlink_log", &opt_all_unlink_log));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("bt_sighandler", &opt_bt_sighandler_enable));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("jemalloc_stat_full_folder", &opt_jemalloc_stat_full_folder));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("sched_pol_interface", &opt_sched_pol_interface));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("sched_pol_pb", &opt_sched_pol_pb));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("sched_pol_sip", &opt_sched_pol_sip));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("sched_pol_rtp_prep", &opt_sched_pol_rtp_prep));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("sched_pol_rtp_read", &opt_sched_pol_rtp_read));
					addConfigItem(new FILE_LINE(0) cConfigItem_string("sched_pol_auto", &opt_sched_pol_auto));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("sched_pol_auto_heap_limit", &opt_sched_pol_auto_heap_limit));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("sched_pol_auto_cpu_limit", &opt_sched_pol_auto_cpu_limit));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("use_thread_setname", &opt_use_thread_setname));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("usleep_progressive", &opt_usleep_progressive));
					addConfigItem(new FILE_LINE(0) cConfigItem_float("usleep_progressive_index", &opt_usleep_progressive_index));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("usleep_mod_enable", &opt_usleep_mod_enable));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("usleep_mod_pause_spin_limit", &opt_usleep_mod_pause_spin_limit));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("usleep_mod_sched_yield_spin_limit", &opt_usleep_mod_sched_yield_spin_limit));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("lock_calls_hash_usleep", &opt_lock_calls_hash_usleep));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("sip_batch_usleep", &opt_sip_batch_usleep));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("rtp_batch_usleep", &opt_rtp_batch_usleep));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("lock_calls_usleep", &opt_lock_calls_usleep));
					addConfigItem(new FILE_LINE(0) cConfigItem_integer("usleep_minimal", &opt_usleep_minimal));
					addConfigItem(new FILE_LINE(0) cConfigItem_yesno("sniffer_threads_ext", &opt_sniffer_threads_ext));
						obsolete();
						addConfigItem(new FILE_LINE(42466) cConfigItem_yesno("enable_fraud", &opt_enable_fraud));
						addConfigItem(new FILE_LINE(0) cConfigItem_yesno("enable_billing", &opt_enable_billing));
		subgroup("process pcap");
			addConfigItem((new FILE_LINE(0) cConfigItem_yesno("process_pcap_type", &opt_process_pcap_type))
				->disableYes()
				->addValues(("dedup:" + intToString(_pp_dedup) + "|" + 
					     "anonymize_ip:" + intToString(_pp_anonymize_ip) + "|" +
					     "rtcp_data:" + intToString(_pp_prepare_rtcp_data)).c_str()));
			addConfigItem(new FILE_LINE(0) cConfigItem_string("pcap_destination", opt_pcap_destination, sizeof(opt_pcap_destination)));
			addConfigItem(new FILE_LINE(0) cConfigItem_net_map("anonymize_ip", &opt_anonymize_ip_map));
			addConfigItem(new FILE_LINE(0) cConfigItem_domain_map("anonymize_sipdomain", &opt_anonymize_domain_map));
			addConfigItem(new FILE_LINE(0) cConfigItem_string("rtcp_params", &opt_rtcp_params));
	minorEnd();
	
	setDefaultValues();
	
	const char *descriptionsHelpTable[][3] = {
		// { "sqldriver", "SQL driver", "SQL driver - test help text" }
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
	if(configItem->config_name == "cleandatabase") {
		opt_cleandatabase_cdr =
		opt_cleandatabase_http_enum =
		opt_cleandatabase_webrtc =
		opt_cleandatabase_register_state =
		opt_cleandatabase_register_failed = 
		opt_cleandatabase_register_time_info = 
		opt_cleandatabase_sip_msg = configItem->getValueInt();
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
	if(configItem->config_name == "create_old_partitions") {
		opt_create_old_partitions = max(opt_create_old_partitions, (int)configItem->getValueInt());
	}
	if(configItem->config_name == "create_old_partitions_from" && opt_create_old_partitions_from[0]) {
		opt_create_old_partitions = max(opt_create_old_partitions, getNumberOfDayToNow(opt_create_old_partitions_from));
	}
	if(configItem->config_name == "database_backup_from_date" && opt_database_backup_from_date[0]) {
		opt_create_old_partitions = max(opt_create_old_partitions, getNumberOfDayToNow(opt_database_backup_from_date));
	}
	if(configItem->config_name == "cachedir" && opt_cachedir[0]) {
		spooldir_mkdir(opt_cachedir);
	}
	if(configItem->config_name == "timezone") {
		if(opt_timezone[0]) {
			setenv("TZ", opt_timezone, 1);
		}
	}
	if(configItem->config_name == "pcap_dump_ziplevel" || configItem->config_name == "pcap_dump_compress_level") {
		opt_pcap_dump_compresslevel_sip =
		opt_pcap_dump_compresslevel_rtp =
		opt_pcap_dump_compresslevel_graph = configItem->getValueInt();
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
	if(configItem->config_name == "savertp_video") {
		switch(configItem->getValueInt()) {
		case 0:
			opt_saveRTPvideo_only_header = 0;
			opt_saveRTPvideo = 0;
			opt_processingRTPvideo = 0;
			break;
		case 1:
			opt_saveRTPvideo_only_header = 0;
			opt_saveRTPvideo = 1;
			opt_processingRTPvideo = 1;
			break;
		case -1:
			opt_saveRTPvideo_only_header = 1;
			opt_saveRTPvideo = 0;
			opt_processingRTPvideo = 1;
			break;
		case -2:
			opt_saveRTPvideo_only_header = 0;
			opt_saveRTPvideo = 0;
			opt_processingRTPvideo = 1;
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
		case 3:
			opt_saveWAV = 1;
			opt_audio_format = FORMAT_MP3;
			break;
		}
	}
	if(configItem->config_name == "savegraph") {
		switch(configItem->getValueInt()) {
		case 0:
			opt_saveGRAPH = 0;
			if(!CONFIG.isSet("pcap_dump_zip_graph")) {
				opt_gzipGRAPH = FileZipHandler::compress_na;
			}
			break;
		case 1:
			opt_saveGRAPH = 1;
			if(!CONFIG.isSet("pcap_dump_zip_graph")) {
				opt_gzipGRAPH = FileZipHandler::compress_na;
			}
			break;
		case 2:
			opt_saveGRAPH = 1;
			if(!CONFIG.isSet("pcap_dump_zip_graph")) {
				opt_gzipGRAPH = FileZipHandler::gzip;
			}
			break;
		}
	}
	if(configItem->config_name == "save_audiograph") {
		switch(configItem->getValueInt()) {
		case 0:
			opt_save_audiograph = 0;
			if(!CONFIG.isSet("pcap_dump_zip_audiograph")) {
				opt_gzip_audiograph = FileZipHandler::compress_na;
			}
			break;
		case 1:
			opt_save_audiograph = 1;
			if(!CONFIG.isSet("pcap_dump_zip_audiograph")) {
				opt_gzip_audiograph = FileZipHandler::compress_na;
			}
			break;
		case 2:
			opt_save_audiograph = 1;
			if(!CONFIG.isSet("pcap_dump_zip_audiograph")) {
				opt_gzip_audiograph = FileZipHandler::gzip;
			}
			break;
		}
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
		opt_gzipGRAPH = 
		opt_gzip_audiograph = (FileZipHandler::eTypeCompress)configItem->getValueInt();
	}
	if(configItem->config_name == "sip_send_ip") {
		sipSendSocket_ip_port.set_ip(configItem->getValueStr());
	}
	if(configItem->config_name == "sip_send_port") {
		sipSendSocket_ip_port.set_port(configItem->getValueInt());
	}
	if(configItem->config_name == "query_cache") {
		if(configItem->getValueInt()) {
			opt_save_query_main_to_files = true;
			opt_load_query_main_from_files = 1;
		} else {
			opt_save_query_main_to_files = false;
			opt_load_query_main_from_files = 0;
			opt_save_query_charts_to_files = false;
			opt_load_query_charts_from_files = 0;
		}
	}
	if(configItem->config_name == "query_cache_charts") {
		if(configItem->getValueInt()) {
			opt_save_query_charts_to_files = true;
			opt_load_query_charts_from_files = 1;
		} else {
			opt_save_query_charts_to_files = false;
			opt_load_query_charts_from_files = 0;
		}
	}
	if(configItem->config_name == "query_cache_charts_remote") {
		if(configItem->getValueInt()) {
			opt_save_query_charts_remote_to_files = true;
			opt_load_query_charts_remote_from_files = 1;
		} else {
			opt_save_query_charts_remote_to_files = false;
			opt_load_query_charts_remote_from_files = 0;
		}
	}
	if(configItem->config_name == "cdr_ignore_response") {
		parse_opt_nocdr_for_last_responses();
	}
	if(configItem->config_name == "cdr_sip_response_reg_remove") {
		for(unsigned i = 0; i < opt_cdr_sip_response_reg_remove.size(); i++) {
			if(!check_regexp(opt_cdr_sip_response_reg_remove[i].c_str())) {
				syslog(LOG_WARNING, "invalid regexp %s for cdr_sip_response_reg_remove", opt_cdr_sip_response_reg_remove[i].c_str());
				opt_cdr_sip_response_reg_remove.erase(opt_cdr_sip_response_reg_remove.begin() + i);
				--i;
			}
		}
	}
	if(configItem->config_name == "cdr_reason_reg_remove") {
		for(unsigned i = 0; i < opt_cdr_reason_reg_remove.size(); i++) {
			if(!check_regexp(opt_cdr_reason_reg_remove[i].c_str())) {
				syslog(LOG_WARNING, "invalid regexp %s for cdr_reason_reg_remove", opt_cdr_reason_reg_remove[i].c_str());
				opt_cdr_reason_reg_remove.erase(opt_cdr_reason_reg_remove.begin() + i);
				--i;
			}
		}
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
	if(configItem->config_name == "cdr_ua_reg_whitelist") {
		for(unsigned i = 0; i < opt_cdr_ua_reg_whitelist.size(); i++) {
			if(!check_regexp(opt_cdr_ua_reg_whitelist[i].c_str())) {
				syslog(LOG_WARNING, "invalid regexp %s for cdr_ua_reg_whitelist", opt_cdr_ua_reg_whitelist[i].c_str());
				opt_cdr_ua_reg_whitelist.erase(opt_cdr_ua_reg_whitelist.begin() + i);
				--i;
			}
		}
	}
	if(configItem->config_name == "message_body_url_reg") {
		for(unsigned i = 0; i < opt_message_body_url_reg.size(); i++) {
			if(!check_regexp(opt_message_body_url_reg[i].c_str())) {
				syslog(LOG_WARNING, "invalid regexp %s for message_body_url_reg", opt_message_body_url_reg[i].c_str());
				opt_message_body_url_reg.erase(opt_message_body_url_reg.begin() + i);
				--i;
			}
		}
	}
	if(configItem->config_name == "t2_boost_direct_rtp_delay_ms") {
		opt_t2_boost_direct_rtp_delay_queue_ms = configItem->getValueInt();
		opt_t2_boost_direct_rtp_max_queue_length_ms = configItem->getValueInt();
	}
	if(configItem->config_name == "cdr_problems_by") {
		if(strcasestr(configItem->getValueStr().c_str(), "all")) {
			opt_cdr_problems_by_ip = true;
			opt_cdr_problems_by_number = true;
			opt_cdr_problems_by_comb = true;
		} else {
			opt_cdr_problems_by_ip = strcasestr(configItem->getValueStr().c_str(), "ip");
			opt_cdr_problems_by_number = strcasestr(configItem->getValueStr().c_str(), "number");
			opt_cdr_problems_by_comb = strcasestr(configItem->getValueStr().c_str(), "comb");
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
    	    {"cmp-config", 1, 0, _param_cmp_config},
	    {"manager-port", 1, 0, '8'},
	    {"pcap-command", 1, 0, 'a'},
	    {"norecord-header", 0, 0, 'N'},
	    {"norecord-dtmf", 0, 0, 'K'},
	    {"rtp-nosig", 0, 0, 'I'},
	    {"cachedir", 1, 0, 'C'},
	    {"id-sensor", 1, 0, 's'},
	    {"sensor-string", 1, 0, _param_sensor_string},
	    {"ipaccount", 0, 0, 'x'},
	    {"pcapscan-dir", 1, 0, '0'},
	    {"pcapscan-method", 1, 0, _param_pcapscan_method},
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
	    {"test", 1, 0, 'X'},
	    {"allsipports", 0, 0, 'y'},
	    {"sipports", 1, 0, 'Y'},
	    {"skinny", 0, 0, _param_skinny},
	    {"skinnyports", 1, 0, _param_skinnyports},
	    {"mgcp", 0, 0, _param_mgcp},
	    {"ignorertcpjitter", 1, 0, _param_ignorertcpjitter},
	    {"natalias", 1, 0, _param_natalias},
	    {"mono", 0, 0, _param_mono},
	    {"untar-gui", 1, 0, _param_untar_gui},
	    {"unlzo-gui", 1, 0, _param_unlzo_gui},
	    {"waveform-gui", 1, 0, _param_waveform_gui},
	    {"spectrogram-gui", 1, 0, _param_spectrogram_gui},
	    {"audio-convert", 1, 0, _param_audio_convert},
	    {"audio-transcribe", 1, 0, _param_audio_transcribe},
	    {"rtp-streams-analysis", 1, 0, _param_rtp_streams_analysis},
	    {"disable-rtp-seq-probation", 0, 0, _param_disable_rtp_seq_probation},
	    {"saveaudio-from-rtp", 0, 0, _param_saveaudio_from_rtp},
	    {"update-schema", 0, 0, _param_update_schema},
	    {"print-config-struct", 0, 0, _param_print_config_struct},
	    {"print-config-file", 0, 0, _param_print_config_file},
	    {"print-config-file-default", 0, 0, _param_print_config_file_default},
	    {"check-regexp", 1, 0, _param_check_regexp},
	    {"test-regexp", 1, 0, _param_test_regexp},
	    {"read-pcap", 1, 0, _param_read_pcap},
	    {"max-packets", 1, 0, _param_max_packets},
	    {"time-to-terminate", 1, 0, _param_time_to_terminate},
	    {"continue-after-read", 0, 0, _param_continue_after_read},
	    {"suppress-cleanup-after-read", 0, 0, _param_suppress_cleanup_after_read},
	    {"unlimited-read", 0, 0, _param_unlimited_read},
	    {"nonstop-read", 0, 0, _param_nonstop_read},
	    {"nonstop-read-quick", 0, 0, _param_nonstop_read_quick},
	    {"diff-days", 1, 0, _param_diff_days},
	    {"diff-secs", 1, 0, _param_diff_secs},
	    {"time-adjustment", 1, 0, _param_time_adjustment},
	    {"reindex-all", 0, 0, _param_reindex_all},
	    {"run-cleanspool", 0, 0, _param_run_cleanspool},
	    {"run-cleanspool-maxdays", 1, 0, _param_run_cleanspool_maxdays},
	    {"test-cleanspool-load", 1, 0, _param_test_cleanspool_load},
	    {"run-droppartitions-maxdays", 1, 0, _param_run_droppartitions_maxdays},
	    {"run-droppartitions-rtp_stat-maxdays", 1, 0, _param_run_droppartitions_rtp_stat_maxdays},
	    {"run-droppartitions-cdr_stat-maxdays", 1, 0, _param_run_droppartitions_cdr_stat_maxdays},
	    {"run-droppartitions-cdr_problems-maxdays", 1, 0, _param_run_droppartitions_cdr_problems_maxdays},
	    {"clean-obsolete", 0, 0, _param_clean_obsolete},
	    {"check-db", 0, 0, _param_check_db},
	    {"fax-deduplicate", 0, 0, _param_fax_deduplicate},
	    {"create-udptl-streams", 0, 0, _param_create_udptl_streams},
	    {"conv-raw-info", 1, 0, _param_conv_raw_info},
	    {"find-country-for-number", 1, 0, _param_find_country_for_number},
	    {"find-country-for-ip", 1, 0, _param_find_country_for_ip},
	    {"test-billing", 1, 0, _param_test_billing},
	    {"test-billing-json", 1, 0, _param_test_billing_json},
	    {"watchdog", 1, 0, _param_watchdog},
	    {"cloud-db", 0, 0, _param_cloud_db},
	    {"cloud-host", 1, 0, _param_cloud_host},
	    {"cloud-token", 1, 0, _param_cloud_token},
	    {"cloud-port", 1, 0, _param_cloud_port},
	    {"server-host", 1, 0, _param_server_host},
	    {"server-port", 1, 0, _param_server_port},
	    {"server-pass", 1, 0, _param_server_pass},
	    {"disable-dbupgradecheck", 0, 0, _param_disable_dbupgradecheck},
	    {"ssl-master-secret-file", 1, 0, _param_ssl_master_secret_file},
	    {"t2_boost", 0, 0, _param_t2_boost},
	    {"json_config", 1, 0, _param_json_config},
	    {"sip-msg-save", 0, 0, _param_sip_msg_save},
	    {"dedup-pcap", 1, 0, _param_dedup_pcap},
	    {"anonymize-pcap", 1, 0, _param_anonymize_pcap},
	    {"prepare_rtcp_data", 1, 0, _param_prepare_rtcp_data},
	    {"process_pcap", 1, 0, _param_process_pcap},
	    {"heap-profiler", 1, 0, _param_heap_profiler},
	    {"revaluation", 1, 0, _param_revaluation},
	    {"reassign_countries", 1, 0, _param_reassign_countries},
	    {"eval-formula", 1, 0, _param_eval_formula},
	    {"ipfix-client-emulation", 1, 0, _param_ipfix_client_emulation},
	    {"hep-client-emulation", 1, 0, _param_hep_client_emulation},
	    {"ws-calls", 1, 0, _param_ws_calls},
	    {"extract_payload", 1, 0, _param_extract_payload},
	    {"extract_rtp_payload", 1, 0, _param_extract_rtp_payload},
	    {"load-rtp-pcap", 1, 0, _param_load_rtp_pcap},
	    {"check_bad_ether_type", 1, 0, _param_check_bad_ether_type},
	    {"manager_enable_unencrypted", 0, 0, _param_manager_enable_unencrypted},
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
	string argOptions;
	string noArgOptions;
	for(unsigned i = 0; long_options[i].name; i++) {
		if(long_options[i].val >= '0' && long_options[i].val <= 'z') {
			if(long_options[i].has_arg == 1) {
				argOptions += (char)long_options[i].val;
				argOptions += ':';
			} else {
				noArgOptions += (char)long_options[i].val;
			}
		}
	}

	while(1) {
		int c;
		c = getopt_long(argc, argv, (argOptions + noArgOptions).c_str(), long_options, &option_index);
		if (c == -1)
			break;
		command_line_data[c] = optarg ? optarg : "";
	}
}

void parse_verb_param(string verbParam) {
	if(verbParam == "process_rtp")				sverb.process_rtp = 1;
	else if(verbParam == "graph")				sverb.graph = 1;
	else if(verbParam == "graph_mos")			sverb.graph_mos = 1;
	else if(verbParam == "read_rtp")			sverb.read_rtp = 1;
	else if(verbParam == "hash_rtp")			sverb.hash_rtp = 1;
	else if(verbParam == "rtp_set_base_seq")		sverb.rtp_set_base_seq = 1;
	else if(verbParam == "rtp_streams")			sverb.rtp_streams = 1;
	else if(verbParam == "forcemark")			sverb.forcemark = 1;
	else if(verbParam == "wavmix")				sverb.wavmix = 1;
	else if(verbParam == "check_is_caller_called")		sverb.check_is_caller_called = 1;
	else if(verbParam == "disable_threads_rtp")		sverb.disable_threads_rtp = 1;
	else if(verbParam == "packet_lost")			sverb.packet_lost = 1;
	else if(verbParam == "rrd_info")			sverb.rrd_info = 1;
	else if(verbParam == "tcpreassembly_http")		sverb.tcpreassembly_http = 1;
	else if(verbParam == "tcpreassembly_webrtc")		sverb.tcpreassembly_webrtc = 1;
	else if(verbParam == "tcpreassembly_ssl")		sverb.tcpreassembly_ssl = 1;
	else if(verbParam == "tls")				sverb.tls = 1;
	else if(verbParam == "ssl_sessionkey")			sverb.ssl_sessionkey = 1;
	else if(verbParam.substr(0, 23) == "ssl_sessionkey_to_file=")
								{ sverb.ssl_sessionkey_to_file = new FILE_LINE(0) char[strlen(verbParam.c_str() + 23) + 1]; strcpy(sverb.ssl_sessionkey_to_file, verbParam.c_str() + 23); }
	else if(verbParam == "tcpreassembly_sip")		sverb.tcpreassembly_sip = 1;
	else if(verbParam == "tcpreassembly_sip_cleanup")	sverb.tcpreassembly_sip_cleanup = 1;
	else if(verbParam.substr(0, 25) == "tcpreassembly_sip_dumper=")
								{ sverb.tcpreassembly_sip_dumper = new FILE_LINE(0) char[strlen(verbParam.c_str() + 25) + 1]; strcpy(sverb.tcpreassembly_sip_dumper, verbParam.c_str() + 25); }
	else if(verbParam.substr(0, 31) == "tcpreassembly_sip_dumper_ports=")
								{ sverb.tcpreassembly_sip_dumper_ports = new FILE_LINE(0) char[strlen(verbParam.c_str() + 31) + 1]; strcpy(sverb.tcpreassembly_sip_dumper_ports, verbParam.c_str() + 31); }
	else if(verbParam.substr(0, 25) == "tcpreassembly_debug_file=")
								{ sverb.tcpreassembly_debug_file = new FILE_LINE(0) char[strlen(verbParam.c_str() + 25) + 1]; strcpy(sverb.tcpreassembly_debug_file, verbParam.c_str() + 25); }
	else if(verbParam == "tcpreassembly_ext")		sverb.tcpreassembly_ext = 1;
	else if(verbParam == "ssldecode")			sverb.ssldecode = 1;
	else if(verbParam == "ssldecode_debug")			sverb.ssldecode_debug = 1;
	else if(verbParam == "ssl_stats")			sverb.ssl_stats = 1;
	else if(verbParam == "sip_packets")			sverb.sip_packets = 1;
	else if(verbParam == "set_ua")				sverb.set_ua = 1;
	else if(verbParam == "dscp")				sverb.dscp = 1;
	else if(verbParam == "store_process_query")		sverb.store_process_query = 1;
	else if(verbParam == "store_process_query_compl")	sverb.store_process_query_compl = 1;
	else if(verbParam == "store_process_query_compl_time")	sverb.store_process_query_compl_time = 1;
	else if(verbParam == "call_listening")			sverb.call_listening = 1;
	else if(verbParam == "skinny")				sverb.skinny = 1;
	else if(verbParam == "fraud")				sverb.fraud = 1;
	else if(verbParam == "fraud_file_log")			sverb.fraud_file_log = 1;
	else if(verbParam == "enable_bt_sighandler")		sverb.enable_bt_sighandler = 1;
	else if(verbParam.substr(0, 4) == "tar=")
								sverb.tar = atoi(verbParam.c_str() + 4);
	else if(verbParam == "tar")				sverb.tar = 1;
	else if(verbParam.substr(0, 13) == "chunk_buffer=")
								sverb.chunk_buffer = atoi(verbParam.c_str() + 13);
	else if(verbParam == "chunk_buffer")			sverb.chunk_buffer = 1;
	else if(verbParam.substr(0, 15) == "tcp_debug_port=")
								sverb.tcp_debug_port = atoi(verbParam.c_str() + 15);
	else if(verbParam.substr(0, 13) == "tcp_debug_ip=")	{ vmIP *tcp_debug_ip = (vmIP*)sverb.tcp_debug_ip; tcp_debug_ip->setFromString(verbParam.c_str() + 13); }
	else if(verbParam.substr(0, 5) == "ssrc=")          	sverb.ssrc = strtol(verbParam.c_str() + 5, NULL, 16);
	else if(verbParam == "jitter")				sverb.jitter = 1;
	else if(verbParam == "jitter_na")			opt_jitterbuffer_adapt = 0;
	else if(verbParam == "jitter_nf1")			opt_jitterbuffer_f1 = 0;
	else if(verbParam == "jitter_nf2")			opt_jitterbuffer_f2 = 0;
	else if(verbParam == "noaudiounlink")			sverb.noaudiounlink = 1;
	else if(verbParam == "test_fftw")			{ sverb.test_fftw = 1; sverb.noaudiounlink = 1; }
	else if(verbParam == "capture_filter")			sverb.capture_filter = 1;
	else if(verbParam.substr(0, 17) == "pcap_stat_period=")	sverb.pcap_stat_period = atoi(verbParam.c_str() + 17);
	else if(verbParam == "pcap_stat_to_stdout")		sverb.pcap_stat_to_stdout = 1;
	else if(verbParam == "memory_stat" ||
		verbParam == "memory_stat_ex")			sverb.memory_stat = 1;
	else if(verbParam == "memory_stat_log" ||
		verbParam == "memory_stat_ex_log")		{ sverb.memory_stat = 1; sverb.memory_stat_log = 1; }
	else if(verbParam.substr(0, 25) == "memory_stat_ignore_limit=")
								sverb.memory_stat_ignore_limit = atoi(verbParam.c_str() + 25);
	else if(verbParam == "sniffer_threads_ext")		sverb.sniffer_threads_ext = 1;
	else if(verbParam == "alloc_stat")			sverb.alloc_stat = 1;
	else if(verbParam == "qfiles")				sverb.qfiles = 1;
	else if(verbParam == "query_error")			sverb.query_error = 1;
	else if(verbParam.substr(0, 16) == "query_error_log=")  strcpy_null_term(sverb.query_error_log, verbParam.c_str() + 16);
	else if(verbParam.substr(0, 12) == "query_regex=")      strcpy_null_term(sverb.query_regex, verbParam.c_str() + 12);
	else if(verbParam == "new_invite")			sverb.new_invite = 1;
	else if(verbParam == "dump_sip")			sverb.dump_sip = 1;
	else if(verbParam == "dump_sip_line")			{ sverb.dump_sip = 1; sverb.dump_sip_line = 1; }
	else if(verbParam == "dump_sip_without_counter")	{ sverb.dump_sip = 1; sverb.dump_sip_without_counter = 1; }
	else if(verbParam == "reverse_invite")			sverb.reverse_invite = 1;
	else if(verbParam == "mgcp")				sverb.mgcp = 1;
	else if(verbParam == "mgcp_sdp")			sverb.mgcp_sdp = 1;
	else if(verbParam == "manager")				sverb.manager = 1;
	else if(verbParam == "scanpcapdir")			sverb.scanpcapdir = 1;
	else if(verbParam == "debug_rtcp")			sverb.debug_rtcp = 1;
	else if(verbParam == "defrag")				sverb.defrag = 1;
	else if(verbParam == "defrag_overflow")			sverb.defrag_overflow = 1;
	else if(verbParam == "dedup")				sverb.dedup = 1;
	else if(verbParam == "dedup_collision")			sverb.dedup_collision = 1;
	else if(verbParam == "dedup_counter")			sverb.dedup_counter = 1;
	else if(verbParam == "reassembly_sip")			sverb.reassembly_sip = 1;
	else if(verbParam == "reassembly_sip_output")		sverb.reassembly_sip_output = 1;
	else if(verbParam == "log_manager_cmd")			sverb.log_manager_cmd = 1;
	else if(verbParam == "rtp_extend_stat")			sverb.rtp_extend_stat = 1;
	else if(verbParam == "process_rtp_header")		sverb.process_rtp_header = 1;
	else if(verbParam == "disable_process_packet_in_packetbuffer")
								sverb.disable_process_packet_in_packetbuffer = 1;
	else if(verbParam == "disable_push_to_t2_in_packetbuffer")
								sverb.disable_push_to_t2_in_packetbuffer = 1;
	else if(verbParam == "disable_save_packet")		sverb.disable_save_packet = 1;
	else if(verbParam == "disable_save_graph")		sverb.disable_save_graph = 1;
	else if(verbParam == "disable_save_call")		sverb.disable_save_call = 1;
	else if(verbParam == "disable_save_message")		sverb.disable_save_message = 1;
	else if(verbParam == "disable_save_register")		sverb.disable_save_register = 1;
	else if(verbParam == "disable_save_sip_msg")		sverb.disable_save_sip_msg = 1;
	else if(verbParam == "disable_save_db_rec")		{ sverb.disable_save_call = 1; sverb.disable_save_message = 1; sverb.disable_save_register = 1; sverb.disable_save_sip_msg = 1; }
	else if(verbParam == "disable_save_all")		{ sverb.disable_save_call = 1; sverb.disable_save_message = 1; sverb.disable_save_register = 1; sverb.disable_save_sip_msg = 1; sverb.disable_save_packet = 1; sverb.disable_save_graph = 1; }
	else if(verbParam == "disable_read_rtp")		sverb.disable_read_rtp = 1;
	else if(verbParam == "thread_create")			sverb.thread_create = 1;
	else if(verbParam == "threads_cpu_log")			sverb.threads_cpu_log = 1;
	else if(verbParam == "timezones")			sverb.timezones = 1;
	else if(verbParam == "tcpreplay")			sverb.tcpreplay = 1;
	else if(verbParam == "abort_if_heap_full")		sverb.abort_if_heap_full = 1;
	else if(verbParam == "exit_if_heap_full")		sverb.exit_if_heap_full = 1;
	else if(verbParam == "heap_use_time")			sverb.heap_use_time = 1;
	else if(verbParam == "dtmf")				sverb.dtmf = 1;
	else if(verbParam == "dtls")				sverb.dtls = 1;
	else if(verbParam == "hep3")				sverb.hep3 = 1;
	else if(verbParam == "cleanspool")			sverb.cleanspool = 1;
	else if(verbParam == "cleanspool_disable_rm")		sverb.cleanspool_disable_rm = 1;
	else if(verbParam == "t2_destroy_all")			sverb.t2_destroy_all = 1;
	else if(verbParam == "log_profiler")			sverb.log_profiler = 1;
	else if(verbParam == "dump_packets_via_wireshark")	sverb.dump_packets_via_wireshark = 1;
	else if(verbParam == "force_log_sqlq")			sverb.force_log_sqlq = 1;
	else if(verbParam == "dump_call_flags")			sverb.dump_call_flags = 1;
	else if(verbParam == "log_srtp_callid")			sverb.log_srtp_callid = 1;
	else if(verbParam == "send_call_info")			sverb.send_call_info = 1;
	else if(verbParam == "disable_cb_cache")		sverb.disable_cb_cache = 1;
	else if(verbParam == "enable_cb_cache")			sverb.disable_cb_cache = 0;
	else if(verbParam == "system_command")			sverb.system_command = 1;
	else if(verbParam == "malloc_trim")			sverb.malloc_trim = 1;
	else if(verbParam == "socket_decode")			{ sverb.socket_decode = 1; extern sCloudRouterVerbose& CR_VERBOSE(); CR_VERBOSE().socket_decode = true; }
	else if(verbParam == "disable_load_codebooks")		sverb.disable_load_codebooks = 1;
	else if(verbParam.substr(0, 15) == "multiple_store=")	sverb.multiple_store = atoi(verbParam.c_str() + 15);
	else if(verbParam == "disable_store_rtp_stat")		sverb.disable_store_rtp_stat = 1;
	else if(verbParam == "disable_billing")			sverb.disable_billing = 1;
	else if(verbParam == "disable_custom_headers")		sverb.disable_custom_headers = 1;
	else if(verbParam == "disable_cloudshare")		sverb.disable_cloudshare = 1;
	else if(verbParam == "screen_popup")			sverb.screen_popup = 1;
	else if(verbParam == "screen_popup_syslog")		sverb.screen_popup_syslog = 1;
	else if(verbParam == "cleanup_calls")			sverb.cleanup_calls = 1;
	else if(verbParam == "cleanup_calls_log")		sverb.cleanup_calls_log = 1;
	else if(verbParam == "cleanup_calls_stat")		sverb.cleanup_calls_stat = 1;
	else if(verbParam == "charts_cache_only")		sverb.charts_cache_only = 1;
	else if(verbParam == "charts_cache_filters_eval")	sverb.charts_cache_filters_eval = 1;
	else if(verbParam == "charts_cache_filters_eval_rslt")	sverb.charts_cache_filters_eval_rslt = 1;
	else if(verbParam == "charts_cache_filters_eval_rslt_true")	
								sverb.charts_cache_filters_eval_rslt = 1;
	else if(verbParam.substr(0, 19) == "sipcallerip_filter=")
								strcpy_null_term(sverb.sipcallerip_filter, verbParam.c_str() + 19);
	else if(verbParam.substr(0, 19) == "sipcalledip_filter=")
								strcpy_null_term(sverb.sipcalledip_filter, verbParam.c_str() + 19);
	else if(verbParam == "suppress_cdr_insert")		sverb.suppress_cdr_insert = 1;
	else if(verbParam == "suppress_server_store")		sverb.suppress_server_store = 1;
	else if(verbParam == "suppress_fork")			sverb.suppress_fork = 1;
	else if(verbParam.substr(0, 11) == "trace_call=")
								{ sverb.trace_call = new FILE_LINE(0) char[strlen(verbParam.c_str() + 11) + 1]; strcpy(sverb.trace_call, verbParam.c_str() + 11); }
	else if(verbParam == "energylevels")			sverb.energylevels = 1;
	else if(verbParam == "cdr_stat_only")			sverb.cdr_stat_only = 1;
	else if(verbParam.substr(0, 24) == "cdr_stat_interval_store=")
								sverb.cdr_stat_interval_store = atoi(verbParam.c_str() + 24);
	else if(verbParam == "cdr_problems_only")		sverb.cdr_problems_only = 1;
	else if(verbParam.substr(0, 28) == "cdr_problems_interval_store=")
								sverb.cdr_problems_interval_store = atoi(verbParam.c_str() + 28);
	else if(verbParam == "disable_unlink_qfile")		sverb.disable_unlink_qfile = 1;
	else if(verbParam == "registers_save")			sverb.registers_save = 1;
	else if(verbParam == "check_config")			sverb.check_config = 1;
	else if(verbParam == "separate_processing")		sverb.separate_processing = 1;
	else if(verbParam == "suppress_auto_alter")		sverb.suppress_auto_alter = 1;
	else if(verbParam == "call_branches")			sverb.call_branches = 1;
	else if(verbParam == "diameter_dump")			sverb.diameter_dump = 1;
	else if(verbParam == "diameter_assign")			sverb.diameter_assign = 1;
	else if(verbParam == "rdtsc")				sverb.rdtsc = 1;
	else if(verbParam == "suppress_drop_partitions")	sverb.suppress_drop_partitions = 1;
	else if(verbParam == "whisper")				sverb.whisper = 1;
	else if(verbParam == "packetbuffer_send")		sverb.packetbuffer_send = 1;
	//
	else if(verbParam == "debug1")				sverb._debug1 = 1;
	else if(verbParam == "debug2")				sverb._debug2 = 1;
	else if(verbParam == "debug2")				sverb._debug3 = 1;
}

void get_command_line_arguments() {
	get_command_line_arguments_mysql();
	get_command_line_arguments_json_config();
	for(map<int, string>::iterator iter = command_line_data.begin(); iter != command_line_data.end(); iter++) {
		int c = iter->first;
		char *optarg = NULL;
		if(iter->second.length()) {
			optarg = new FILE_LINE(42467) char[iter->second.length() + 10];
			strcpy(optarg, iter->second.c_str());
		}
		switch (c) {
			/*
			case 0:
				printf ("option %s\n", long_options[option_index].name);
				break;
			*/
			case _param_ignorertcpjitter:
				opt_ignoreRTCPjitter = atoi(optarg);
				break;
			case _param_skinnyports:
				cConfigItem_ports::setPortMatrix(optarg, skinnyportmatrix, 65535);
				break;
			case _param_natalias:
				{
					vector<string> nataliases = explode(optarg, ',');
					for (size_t iter = 0; iter < nataliases.size(); iter++) {
						vector<string> ip_nat = split(nataliases[iter].c_str(), split(" |:|=", "|"), true);
						if(ip_nat.size() >= 2) {
							vmIP _ip_nat[2];
							if(_ip_nat[0].setFromString(ip_nat[0].c_str()) && _ip_nat[1].setFromString(ip_nat[1].c_str())) {
								nat_aliases[_ip_nat[0]] = _ip_nat[1];
							}
						}
					}
				}
			case _param_skinny:
				opt_skinny = 1;
				break;
			case _param_mono:
				opt_saveaudio_stereo = 0;
				break;
			case _param_mgcp:
				opt_mgcp = 1;
				break;
			case _param_untar_gui:
				if(!opt_untar_gui_params) {
					opt_untar_gui_params = new FILE_LINE(42468) char[strlen(optarg) + 1];
					strcpy(opt_untar_gui_params, optarg);
				}
				break;
			case _param_unlzo_gui:
				if(!opt_unlzo_gui_params) {
					opt_unlzo_gui_params = new FILE_LINE(42469) char[strlen(optarg) + 1];
					strcpy(opt_unlzo_gui_params, optarg);
				}
				break;
			case _param_waveform_gui:
				if(!opt_waveform_gui_params) {
					opt_waveform_gui_params =  new FILE_LINE(42470) char[strlen(optarg) + 1];
					strcpy(opt_waveform_gui_params, optarg);
				}
				break;
			case _param_spectrogram_gui:
				if(!opt_spectrogram_gui_params) {
					opt_spectrogram_gui_params =  new FILE_LINE(42471) char[strlen(optarg) + 1];
					strcpy(opt_spectrogram_gui_params, optarg);
				}
				break;
			case _param_audio_convert:
				if(!opt_audioconvert_params) {
					opt_audioconvert_params =  new FILE_LINE(0) char[strlen(optarg) + 1];
					strcpy(opt_audioconvert_params, optarg);
				}
				break;
			case _param_audio_transcribe:
				if(!opt_audio_transcribe_params) {
					opt_audio_transcribe_params =  new FILE_LINE(0) char[strlen(optarg) + 1];
					strcpy(opt_audio_transcribe_params, optarg);
				}
				break;
			case _param_rtp_streams_analysis:
				if(!opt_rtp_stream_analysis_params) {
					opt_rtp_stream_analysis_params =  new FILE_LINE(0) char[strlen(optarg) + 1];
					strcpy(opt_rtp_stream_analysis_params, optarg);
				}
				break;
			case _param_disable_rtp_seq_probation:
				opt_disable_rtp_seq_probation = true;
				break;
			case _param_saveaudio_from_rtp:
				opt_saveaudio_from_first_invite = false;
				opt_saveaudio_afterconnect = false;
				opt_saveaudio_from_rtp = true;
				break;
			case _param_update_schema:
				updateSchema = true;
				break;
			case _param_check_regexp:
				if(!opt_check_regexp_gui_params) {
					opt_check_regexp_gui_params = new FILE_LINE(42472) char[strlen(optarg) + 1];
					strcpy(opt_check_regexp_gui_params, optarg);
				}
				break;
			case _param_test_regexp:
				if(!opt_test_regexp_gui_params) {
					opt_test_regexp_gui_params = new FILE_LINE(42472) char[strlen(optarg) + 1];
					strcpy(opt_test_regexp_gui_params, optarg);
				}
				break;
			case _param_read_pcap:
				if(!opt_read_pcap_gui_params) {
					opt_read_pcap_gui_params = new FILE_LINE(42473) char[strlen(optarg) + 1];
					strcpy(opt_read_pcap_gui_params, optarg);
				}
				break;
			case _param_print_config_struct:
				printConfigStruct = true;
				break;
			case _param_print_config_file:
				printConfigFile = true;
				break;
			case _param_print_config_file_default:
				printConfigFile = true;
				printConfigFile_default = true;
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
				cConfigItem_ports::setPortMatrix(optarg, sipportmatrix, 65535);
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
			case _param_sensor_string:
				strcpy_null_term(opt_sensor_string, optarg);
				break;
			case 'Z':
				strcpy_null_term(opt_keycheck, optarg);
				break;
			case '0':
				strcpy_null_term(opt_scanpcapdir, optarg);
				break;
#ifndef FREEBSD
			case _param_pcapscan_method:
				opt_scanpcapmethod = (optarg[0] == 'r') ? IN_MOVED_TO : IN_CLOSE_WRITE;
				break;
#endif
			case 'a':
				strcpy_null_term(pcapcommand, optarg);
				break;
			case 'I':
				opt_rtpnosip = 1;
				break;
			case 'l':
				opt_disableplc = 1;
				break;
			case 'L':
				opt_dup_check_type = _dedup_md5;
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
				} else if(optarg[0] == 'm') {
					opt_audio_format = FORMAT_MP3;
				} else {
					opt_audio_format = FORMAT_WAV;
				}
				break;
			case '6':
				opt_ringbuffer = MIN(atoi(optarg), 2000);
				break;
			case '7':
				strcpy_null_term(configfile, optarg);
				break;
			case _param_cmp_config:
				if(!opt_cmp_config_params) {
					opt_cmp_config_params = new FILE_LINE(42473) char[strlen(optarg) + 1];
					strcpy(opt_cmp_config_params, optarg);
				}
				break;
			case '8':
				opt_manager_port = atoi(optarg);
				if(char *pointToSeparator = strchr(optarg,'/')) {
					strcpy_null_term(opt_manager_ip, pointToSeparator+1);
				}
				break;
			case '9':
				opt_saveRTCP = 1;
				break;
			case 'i':
				strcpy_null_term(ifname, optarg);
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
						parse_verb_param(verbparams[i]);
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
					   !strncmp(optarg, "pbsa", 4) ||
					   !strncmp(optarg, "pbas", 4)) &&
					  strchr(optarg, ':')) {
					bool acttime = !strncmp(optarg, "pbsa", 4) || !strncmp(optarg, "pbas", 4);
					opt_pb_read_from_file_speed = atof(optarg + (acttime ? 4 : 3));
					strcpy(opt_pb_read_from_file, strchr(optarg, ':') + 1);
					opt_pb_read_from_file_acttime = acttime;
					opt_scanpcapdir[0] = '\0';
				} else {
					strcpy(opt_read_from_file_fname, optarg);
					opt_read_from_file = true;
					opt_scanpcapdir[0] = '\0';
					opt_cachedir[0] = '\0';
					opt_enable_preprocess_packet = 0;
					opt_enable_process_rtp_packet = 0;
				}
				break;
			case _param_max_packets:
				opt_pb_read_from_file_max_packets = atol(optarg);
				break;
			case _param_continue_after_read:
				opt_continue_after_read = true;
				break;
			case _param_suppress_cleanup_after_read:
				opt_suppress_cleanup_after_read = true;
				break;
			case _param_unlimited_read:
				opt_unlimited_read = true;
				break;
			case _param_nonstop_read:
				opt_nonstop_read = true;
				break;
			case _param_nonstop_read_quick:
				opt_nonstop_read = true;
				opt_nonstop_read_quick = true;
				break;
			case _param_time_to_terminate:
				opt_time_to_terminate = atoi(optarg);
				break;
			case _param_diff_days:
				{
				cEvalFormula f(cEvalFormula::_est_na);
				cEvalFormula::sValue v = f.e(optarg);
				opt_pb_read_from_file_acttime_diff_days = v.getInteger();
				}
				break;
			case _param_diff_secs:
				{
				cEvalFormula f(cEvalFormula::_est_na);
				cEvalFormula::sValue v = f.e(optarg);
				opt_pb_read_from_file_acttime_diff_secs = v.getInteger();
				}
				break;
			case _param_time_adjustment:
				{
				cEvalFormula f(cEvalFormula::_est_na);
				cEvalFormula::sValue v = f.e(optarg);
				opt_pb_read_from_file_time_adjustment = v.getInteger();
				}
				break;
			case _param_reindex_all:
			case _param_run_cleanspool:
			case _param_run_cleanspool_maxdays:
			case _param_test_cleanspool_load:
			case _param_clean_obsolete:
				if(is_enable_cleanspool(true)) {
					opt_test = c;
					if(c == _param_run_cleanspool_maxdays || c == _param_test_cleanspool_load) {
						strcpy_null_term(opt_test_arg, optarg);
					}
				}
				break;
			case _param_run_droppartitions_maxdays:
			case _param_run_droppartitions_rtp_stat_maxdays:
			case _param_run_droppartitions_cdr_stat_maxdays:
			case _param_run_droppartitions_cdr_problems_maxdays:
				opt_test = c;
				strcpy_null_term(opt_test_arg, optarg);
				is_gui_param = true;
				break;
			case _param_check_db:
				opt_check_db = true;
				break;
			case _param_fax_deduplicate:
				opt_fax_dup_seq_check = 1;
				break;
			case _param_create_udptl_streams:
				opt_fax_create_udptl_streams = 1;
				break;
			case _param_conv_raw_info:
			case _param_find_country_for_number:
			case _param_find_country_for_ip:
			case _param_test_billing:
			case _param_test_billing_json:
				opt_test = c;
				if(optarg) {
					strcpy_null_term(opt_test_arg, optarg);
				}
				break;
			case _param_check_bad_ether_type:
				opt_test = c;
				if(optarg) {
					strcpy_null_term(opt_test_arg, optarg);
				}
				test();
				exit(0);
				break;
			case _param_watchdog:
				enable_wdt = yesno(optarg);
				break;
			case _param_cloud_db:
				cloud_db = true;
				break;
			case _param_cloud_host:
				strcpy_null_term(cloud_host, optarg);
				break;
			case _param_cloud_token:
				strcpy_null_term(cloud_token, optarg);
				break;
			case _param_cloud_port:
				cloud_router_port = atoi(optarg);
				break;
			case _param_server_host:
				snifferClientOptions.hosts.hosts_str = optarg;
				break;
			case _param_server_port:
				snifferClientOptions.port = atoi(optarg);
				break;
			case _param_server_pass:
				if(optarg) {
					snifferServerClientOptions.password = optarg;
				}
				break;
			case _param_disable_dbupgradecheck:
				opt_disable_dbupgradecheck = true;
				break;
			case 'c':
				opt_nocdr = 1;
				break;
			case 'C':
				strcpy_null_term(opt_cachedir, optarg);
				break;
			case 'd':
				strcpy_null_term(opt_spooldir_main, optarg);
				spooldir_mkdir(opt_spooldir_main);
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
			case 'P':
				strcpy_null_term(opt_pidfile, optarg);
				break;
			case 'f':
				strcpy_null_term(user_filter, optarg);
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
			case _param_ssl_master_secret_file:
				strcpy_null_term(ssl_master_secret_file, optarg);
				break;
			case _param_t2_boost:
				opt_t2_boost = true;
				break;
			case _param_sip_msg_save:
				opt_sip_options = true;
				opt_sip_subscribe = true;
				opt_sip_notify = true;
				opt_save_sip_options = true;
				opt_save_sip_subscribe = true;
				opt_save_sip_notify = true;
				break;
			case _param_dedup_pcap:
				if(sscanf(optarg, "%s %s", opt_process_pcap_fname, opt_pcap_destination) != 2) {
					cerr << "dedup pcap: bad arguments" << endl;
					exit(1);
				}
				opt_process_pcap_type = _pp_dedup;
				opt_dup_check_type = _dedup_md5;
				opt_dup_check_ipheader = 0;
				opt_dup_check_ipheader_ignore_ttl = 1;
				opt_dup_check_udpheader_ignore_checksum = 1;
				is_gui_param = true;
				break;
			case _param_anonymize_pcap:
				strcpy_null_term(opt_process_pcap_fname, optarg);
				opt_process_pcap_type = _pp_anonymize_ip;
				is_gui_param = true;
				break;
			case _param_prepare_rtcp_data:
				strcpy_null_term(opt_process_pcap_fname, optarg);
				opt_process_pcap_type = _pp_prepare_rtcp_data;
				is_gui_param = true;
				break;
			case _param_process_pcap:
				strcpy_null_term(opt_process_pcap_fname, optarg);
				opt_process_pcap_type = _pp_read_file;
				is_gui_param = true;
				break;
			case _param_heap_profiler:
				#if HAVE_LIBTCMALLOC_HEAPPROF
				if(!heap_profiler_is_running) {
					HeapProfilerStart(optarg && *optarg ? optarg : "voipmonitor.hprof");
					heap_profiler_is_running = true;
				}
				#else
				syslog(LOG_NOTICE, "heap profiler need build with tcmalloc (with heap profiler)");
				#endif
				break;
			case _param_revaluation:
				if(!opt_revaluation_params) {
					opt_revaluation_params =  new FILE_LINE(0) char[strlen(optarg) + 1];
					strcpy(opt_revaluation_params, optarg);
				}
				break;
			case _param_reassign_countries:
				if(!opt_reassign_countries_params) {
					opt_reassign_countries_params =  new FILE_LINE(0) char[strlen(optarg) + 1];
					strcpy(opt_reassign_countries_params, optarg);
				}
				break;
			case _param_eval_formula:
				{
				cEvalFormula f(cEvalFormula::_est_na, true);
				cEvalFormula::sSplitOperands *filter_s = new FILE_LINE(0) cEvalFormula::sSplitOperands(0);
				cEvalFormula::sValue v = f.e(optarg, 0, 0, 0, filter_s);
				while(f.e_opt(filter_s)) {
					cout << "-- opt" << endl;
				}
				cout << "== " << f.e(filter_s).getFloat() << endl;
				exit(0);
				}
				break;
			case _param_ipfix_client_emulation:
				{
				vector<string> parameters = explode(optarg, ';');
				if(parameters.size() >= 5) {
					string pcap = parameters[0];
					vmIP client_ip = str_2_vmIP(parameters[1].c_str()); 
					vmIP server_ip = str_2_vmIP(parameters[2].c_str()); 
					vmIP destination_ip = str_2_vmIP(parameters[3].c_str()); 
					u_int64_t destination_port = atoi(parameters[4].c_str());
					IPFix_client_emulation(pcap.c_str(), client_ip, server_ip, destination_ip, destination_port);
				}
				exit(0);
				}
				break;
			case _param_hep_client_emulation:
				{
				vector<string> parameters = explode(optarg, ';');
				if(parameters.size() >= 5) {
					string pcap = parameters[0];
					vmIP client_ip = str_2_vmIP(parameters[1].c_str()); 
					vmIP server_ip = str_2_vmIP(parameters[2].c_str()); 
					vmIP destination_ip = str_2_vmIP(parameters[3].c_str()); 
					u_int64_t destination_port = atoi(parameters[4].c_str());
					bool udp = false;
					if(parameters.size() >= 6) {
						udp = !strcasecmp(parameters[5].c_str(), "udp");
					}
					HEP_client_emulation(pcap.c_str(), client_ip, server_ip, destination_ip, destination_port, udp);
				}
				exit(0);
				}
				break;
			case _param_ws_calls:
				if(!ws_calls) {
					ws_calls = new FILE_LINE(0) cWsCalls();
					ws_calls->load(optarg);
				}
				break;
			case _param_extract_payload:
				extract_payload = optarg;
				break;
			case _param_extract_rtp_payload:
				extract_rtp_payload = optarg;
				break;
			case _param_load_rtp_pcap:
				opt_test = c;
				if(optarg) {
					strcpy_null_term(opt_test_arg, optarg);
				}
				break;
			case _param_manager_enable_unencrypted:
				opt_manager_enable_unencrypted = true;
				break;
		}
		if(optarg) {
			delete [] optarg;
		}
	}
}

void get_command_line_arguments_mysql() {
	for(map<int, string>::iterator iter = command_line_data.begin(); iter != command_line_data.end(); iter++) {
		switch(iter->first) {
			case 'h':
				strcpy_null_term(mysql_host, iter->second.c_str());
				{
					char *portSeparator = strrchr(mysql_host, ':');
					if(portSeparator) {
						*portSeparator = 0;
						opt_mysql_port = atoi(portSeparator + 1);
					}
				}
				break;
			case 'O':
				opt_mysql_port = atoi(iter->second.c_str());
				break;
			case 'b':
				strcpy_null_term(mysql_database, iter->second.c_str());
				break;
			case 'u':
				strcpy_null_term(mysql_user, iter->second.c_str());
				break;
			case 'p':
				strcpy_null_term(mysql_password, iter->second.c_str());
				break;
		}
	}
}

void get_command_line_arguments_json_config() {
	for(map<int, string>::iterator iter = command_line_data.begin(); iter != command_line_data.end(); iter++) {
		switch(iter->first) {
			case _param_json_config:
				if(CONFIG.isSet()) {
					CONFIG.setFromJson(iter->second.c_str(), true);
				} else {
					cConfig config;
					config.addConfigItems();
					config.setFromJson(iter->second.c_str(), true);
				}
				useCmdLineConfig = true;
				break;
		}
	}
}

void set_spool_permission() {
	if(opt_spooldir_file_permission[0]) {
		opt_spooldir_file_permission_int = strtol(opt_spooldir_file_permission, NULL, 8);
	} else {
		opt_spooldir_file_permission_int = 0666;
	}
	if(opt_spooldir_dir_permission[0]) {
		opt_spooldir_dir_permission_int = strtol(opt_spooldir_dir_permission, NULL, 8);
	} else {
		opt_spooldir_dir_permission_int = 0777;
	}
	if(opt_spooldir_owner[0]) {
		passwd *pwd = getpwnam(opt_spooldir_owner);
		if(pwd != NULL) {
			opt_spooldir_owner_id = pwd->pw_uid;
		} else {
			syslog(LOG_ERR, "unknown user '%s' in parameter spooldir_owner", opt_spooldir_owner);
		}
	} else {
		opt_spooldir_owner_id = 0;
	}
	if(opt_spooldir_group[0]) {
		group *grp = getgrnam(opt_spooldir_group);
		if(grp != NULL) {
			opt_spooldir_group_id = grp->gr_gid;
		} else {
			syslog(LOG_ERR, "unknown group '%s' in parameter spooldir_group", opt_spooldir_group);
		}
	} else {
		opt_spooldir_group_id = 0;
	}
}

void set_context_config() {
 
	if(!CONFIG.isSet("t2_boost") && sysconf(_SC_NPROCESSORS_ONLN) <= 4) {
		opt_t2_boost = 0;
	}
 
	if(opt_t2_boost_direct_rtp) {
		opt_t2_boost = 2;
	}
	
	if(opt_t2_boost == 2 && !CONFIG.isSet("t2_boost_direct_rtp_delay_ms")) {
		if(!CONFIG.isSet("t2_boost_direct_rtp_delay_queue_ms")) {
			opt_t2_boost_direct_rtp_delay_queue_ms = 2000;
		}
		if(!CONFIG.isSet("t2_boost_direct_rtp_max_queue_length_ms")) {
			opt_t2_boost_direct_rtp_max_queue_length_ms = 2000;
		}
	}
	
	if(opt_use_dpdk) {
		if(!opt_t2_boost) {
			opt_t2_boost = true;
		}
		if(!CONFIG.isSet("packetbuffer_block_maxsize")) {
			opt_pcap_queue_block_max_size = 4 * 1024 * 1024;
		}
		if(opt_dpdk_worker_slave_thread && !CONFIG.isSet("dpdk_pkt_burst")) {
			opt_dpdk_pkt_burst = 2048;
		} else if(opt_dpdk_pkt_burst >= 1024 && !CONFIG.isSet("dpdk_worker_slave_thread")) {
			opt_dpdk_worker_slave_thread = true;
		}
	}
	
	if(opt_use_dpdk || opt_t2_boost > 1) {
		opt_pcap_queue_store_queue_max_disk_size = 0;
		opt_pcap_queue_disk_folder = "";
	}
	
	if(is_read_from_file_simple() && opt_mysql_enable_set_id) {
		opt_mysql_enable_set_id = false;
	}
	
	if(!isCloud()) {
		if(is_support_for_mysql_new_store()) {
			if(opt_mysql_enable_set_id && !opt_mysql_enable_new_store) {
				opt_mysql_enable_new_store = 2;
			}
		} else {
			if(opt_mysql_enable_new_store || opt_mysql_enable_set_id) {
				opt_mysql_enable_new_store = false;
				opt_mysql_enable_set_id = false;
				syslog(LOG_ERR, "option mysql_enable_new_store and mysql_enable_set_id is not suported in your configuration");
			}
		}
	}
	
	if(opt_mysql_enable_new_store == 2 && !opt_mysql_enable_set_id) {
		opt_mysql_enable_new_store = true;
		syslog(LOG_ERR, "option mysql_enable_new_store=per_query is only supported with option mysql_enable_set_id enabled");
	}
	
	if(opt_mysql_enable_set_id) {
		static bool mysql_enable_set_id_notice = false;
		if(!mysql_enable_set_id_notice) {
			syslog(LOG_NOTICE, "!!! if the mysql_enable_set_id option is enabled, no one else can write to the database !!!");
			mysql_enable_set_id_notice = true;
		}
	}
	
	opt_mysqlstore_max_threads_cdr_set = CONFIG.isSet("mysqlstore_max_threads_cdr");
	opt_mysqlstore_max_threads_message_set = CONFIG.isSet("mysqlstore_max_threads_message");
	opt_mysqlstore_max_threads_sip_msg_set = CONFIG.isSet("mysqlstore_max_threads_sip_msg");
	opt_mysqlstore_max_threads_register_set = CONFIG.isSet("mysqlstore_max_threads_register");
	opt_mysqlstore_max_threads_http_set = CONFIG.isSet("mysqlstore_max_threads_http");
	opt_mysqlstore_max_threads_webrtc_set = CONFIG.isSet("mysqlstore_max_threads_webrtc");
	opt_mysqlstore_max_threads_ipacc_base_set = CONFIG.isSet("mysqlstore_max_threads_ipacc_base");
	opt_mysqlstore_max_threads_ipacc_agreg2_set = CONFIG.isSet("mysqlstore_max_threads_ipacc_agreg2");
	opt_mysqlstore_max_threads_charts_cache_set = CONFIG.isSet("mysqlstore_max_threads_charts_cache");
	
	if(isCloud() && opt_cdr_check_exists_callid) {
		opt_csv_store_format = true;
	}
 
	if(opt_scanpcapdir[0]) {
		sniffer_mode = snifferMode_read_from_files;
		opt_use_oneshot_buffer = 0;
	} else if(is_sender()) {
		sniffer_mode = snifferMode_sender;
		opt_nocdr = true;
	} else {
		sniffer_mode = snifferMode_read_from_interface;
	}

	if(is_receiver() || is_sender() || is_client_packetbuffer_sender()) {
		if(opt_pcap_queue_compress == -1) {
			opt_pcap_queue_compress = 1;
		}
	} else {
		opt_pcap_queue_compress = 0;
	}
	
	if(!is_read_from_file_simple() && !is_set_gui_params() && command_line_data.size()) {
		u_int32_t max_buffer_mem_mb = 0;
		if(opt_max_buffer_mem) {
			max_buffer_mem_mb = max(opt_max_buffer_mem, 10);
		} else if(opt_pcap_queue_store_queue_max_memory_size) {
			max_buffer_mem_mb = opt_pcap_queue_store_queue_max_memory_size / (1024 * 1024);
		}
		u_int32_t total_memory_mb = getTotalMemory() / (1024 * 1024);
		if(!max_buffer_mem_mb) {
			 max_buffer_mem_mb = min((u_int32_t)2000, total_memory_mb / 2);
		} else if(max_buffer_mem_mb > total_memory_mb * 3 / 4) {
			 max_buffer_mem_mb = total_memory_mb * 3 / 4;
		}
		u_int32_t thread0_buffer_mb = 0;
		if(!opt_pcap_queue_disk_folder.length() || !opt_pcap_queue_store_queue_max_disk_size) {
			// disable disc save
			if(opt_pcap_queue_compress || !opt_pcap_queue_suppress_t1_thread) {
				// enable compress or not suppress t1 thread - maximum thread0 buffer = opt_use_dpdk || opt_t2_boost > 1 ? 500MB : 100MB
				thread0_buffer_mb = max_buffer_mem_mb / 8;
				if(thread0_buffer_mb > (opt_use_dpdk || opt_t2_boost > 1 ? 500 : 100)) {
					thread0_buffer_mb = (opt_use_dpdk || opt_t2_boost > 1 ? 500 : 100);
				}
			} else {
				// disable compress and suppress t1 thread - thread0 buffer not need
				thread0_buffer_mb = 0;
			}
		} else {
			// enable disc save - maximum thread0 buffer = 500MB
			thread0_buffer_mb = max_buffer_mem_mb / 4;
			if(thread0_buffer_mb > 500) {
				thread0_buffer_mb = 500;
			}
		}
		buffersControl.setMaxBufferMemMB(max_buffer_mem_mb, thread0_buffer_mb);
		opt_pcap_queue_bypass_max_size = thread0_buffer_mb * 1024ull * 1024;
		if(buffersControl.getMaxBufferMemMB() > 1000 && 
		   !CONFIG.isSet("hashtable_heap_size") &&
		   (!is_client_packetbuffer_sender() && !is_sender())) {
			opt_hashtable_heap_size = 64;
		}
	}
	
	if(is_receiver() && !opt_use_id_sensor_for_receiver_in_files) {
		opt_id_sensor_cleanspool = -1;
	}
	
	if(opt_enable_http) {
		opt_enable_http_enum_tables = true;
	}
	if(opt_enable_webrtc) {
		opt_enable_webrtc_table = true;
	}
	
	if(is_read_from_file_simple() || (opt_process_pcap_type & _pp_prepare_rtcp_data)) {
		opt_cachedir[0] = 0;
		opt_enable_preprocess_packet = 0;
		opt_enable_process_rtp_packet = 0;
		opt_enable_http = 0;
		opt_enable_webrtc = 0;
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
		if(opt_gzip_audiograph == FileZipHandler::compress_default ||
		   opt_gzip_audiograph == FileZipHandler::lzo) {
			opt_gzip_audiograph = FileZipHandler::gzip;
		}
		opt_pcap_dump_asyncwrite = 0;
		opt_save_query_main_to_files = false;
		opt_save_query_charts_to_files = false;
		opt_save_query_charts_remote_to_files = false;
		opt_load_query_main_from_files = 0;
		opt_load_query_charts_from_files = 0;
		opt_load_query_charts_remote_from_files = 0;
		opt_t2_boost = false;
		if(opt_process_pcap_type & _pp_prepare_rtcp_data) {
			useIPv6 = true;
			opt_nocdr = true;
			opt_saveSIP = 0;
			opt_saveRTP = 0;
			opt_saveGRAPH = 0;
			opt_saveRAW = 0;
			opt_saveWAV = 0;
			opt_save_audiograph = 0;
			for(int i = (opt_t2_boost_direct_rtp ? PreProcessPacket::ppt_detach_x : PreProcessPacket::ppt_detach); i < PreProcessPacket::ppt_end_base; i++) {
				preProcessPacket[i] = new FILE_LINE(0) PreProcessPacket((PreProcessPacket::eTypePreProcessThread)i);
			}
			_parse_packet_global_process_packet.setStdParse();
			calltable = new FILE_LINE(0) Calltable();
		}
	}
	
	if(is_read_from_file_by_pb()) {
		opt_save_query_main_to_files = false;
		opt_save_query_charts_to_files = false;
		opt_save_query_charts_remote_to_files = false;
		opt_load_query_main_from_files = 0;
		opt_load_query_charts_from_files = 0;
		opt_load_query_charts_remote_from_files = 0;
	}
	
	if(is_read_from_file()) {
		if(is_receiver()) {
			opt_pcap_queue_receive_from_ip_port.clear();
		}
		if(is_read_from_file_simple()) {
			setThreadingMode(1);
		}
		if(!CONFIG.isSet("pcap_queue_dequeu_window_length") && !CONFIG.isSet("pcap_queue_dequeu_method")) {
			opt_pcap_queue_dequeu_method = 0;
		}
	}
	
	if(opt_pcap_dump_tar) {
		if(opt_cachedir[0]) {
			opt_cachedir[0] = '\0';
			syslog(LOG_ERR, "option cachedir is not supported with option 'tar = yes'");
		}
		if(opt_pcap_dump_tar_compress_sip) {
			opt_pcap_dump_zip_sip = FileZipHandler::compress_na;
		}
		if(opt_pcap_dump_zip_rtp != FileZipHandler::compress_na) {
			opt_pcap_dump_tar_compress_rtp = 0;
		}
		if(opt_pcap_dump_tar_compress_graph) {
			opt_gzipGRAPH = FileZipHandler::compress_na;
		}
		if(opt_pcap_dump_tar_compress_audiograph) {
			opt_gzip_audiograph = FileZipHandler::compress_na;
		}
	}
	
	if(opt_spooldir_2_main[0] && opt_cachedir[0]) {
		opt_cachedir[0] = '\0';
		syslog(LOG_ERR, "option cachedir is not suported with option spooldir_2");
	}
	
	if((!opt_newdir || !opt_pcap_split) && opt_pcap_dump_tar) {
		opt_pcap_dump_tar = 0;
	}
	
	opt_pcap_dump_tar_sip_use_pos = opt_pcap_dump_tar && !opt_pcap_dump_tar_compress_sip;
	opt_pcap_dump_tar_rtp_use_pos = opt_pcap_dump_tar && !opt_pcap_dump_tar_compress_rtp;
	opt_pcap_dump_tar_graph_use_pos = opt_pcap_dump_tar && !opt_pcap_dump_tar_compress_graph;
	opt_pcap_dump_tar_audiograph_use_pos = opt_pcap_dump_tar && !opt_pcap_dump_tar_compress_audiograph;
	
	if(opt_pcap_dump_tar && !CONFIG.isSet("cleanspool_use_files")) {
		opt_cleanspool_use_files = false;
	}
	
	if(opt_save_query_main_to_files || opt_load_query_main_from_files) {
		opt_autoload_from_sqlvmexport = false;
	}
	
	opt_database_backup = !opt_test &&
			      opt_database_backup_from_mysql_host[0] != '\0' &&
			      opt_database_backup_from_mysql_database[0] != '\0' &&
			      opt_database_backup_from_mysql_user[0] != '\0';
	
	if(opt_scanpcapdir[0]) {
		opt_pcap_queue_use_blocks = false;
	}
	
	if(opt_pcap_queue_dequeu_window_length < 0) {
		if(is_receiver() || is_server()) {
			opt_pcap_queue_dequeu_window_length = 2000;
		} else {
			vector<PcapQueue_readFromInterface_base::sInterface> interfaces;
			PcapQueue_readFromInterface::parseInterfaces(ifname, &ifname_libpcap_filter, &interfaces);
			if(interfaces.size() > 1) {
				opt_pcap_queue_dequeu_window_length = 1000;
			}
		}
	}

	SipHistorySetting();

	if(!enable_pcap_split && opt_t2_boost) {
		opt_t2_boost = false;
		opt_use_dpdk = false;
	}
	if(opt_t2_boost && !opt_enable_process_rtp_packet) {
		opt_enable_process_rtp_packet = 1;
	}
	if(opt_t2_boost) {
		opt_enable_preprocess_packet = PreProcessPacket::ppt_end_base;
		if(!is_sender() && !is_client_packetbuffer_sender() && !opt_scanpcapdir[0]) {
			opt_pcap_queue_use_blocks = 1;
		}
		#if DEBUG_DTLS_QUEUE
		if(opt_process_rtp_packets_hash_next_thread < 1) {
			opt_process_rtp_packets_hash_next_thread = 1;
		}
		#else
		if(opt_process_rtp_packets_hash_next_thread < 2) {
			opt_process_rtp_packets_hash_next_thread = 2;
		}
		#endif
		if(!CONFIG.isSet("pre_process_packets_next_thread_sem_sync")) {
			opt_pre_process_packets_next_thread_sem_sync = 1;
		}
		if(!CONFIG.isSet("process_rtp_packets_hash_next_thread_sem_sync")) {
			opt_process_rtp_packets_hash_next_thread_sem_sync = 1;
		}
		unsigned default_preprocess_packets_qring_item_length = 
									#if DEBUG_DTLS_QUEUE
									500;
									#else
									5000;
									#endif
		if(!CONFIG.isSet("preprocess_packets_qring_length")) {
			opt_preprocess_packets_qring_length = 3;
		}
		if(!CONFIG.isSet("preprocess_packets_qring_item_length")) {
			opt_preprocess_packets_qring_item_length = default_preprocess_packets_qring_item_length;
		}
		if(!CONFIG.isSet("process_rtp_packets_qring_length")) {
			opt_process_rtp_packets_qring_length = 4;
		}
		if(!CONFIG.isSet("process_rtp_packets_qring_item_length")) {
			opt_process_rtp_packets_qring_item_length = default_preprocess_packets_qring_item_length;
		}
	}
	
	if(opt_t2_boost == 2) {
		if(!CONFIG.isSet("t2_boost_direct_rtp")) {
			opt_t2_boost_direct_rtp = true;
		}
		if(!CONFIG.isSet("t2_boost_pb_detach_thread")) {
			opt_t2_boost_pb_detach_thread = 2;
		}
		if(!CONFIG.isSet("usleep_progressive")) {
			opt_usleep_progressive = false;
		}
	}
	
	hash_modify_queue_length_ms = opt_t2_boost == 2 && (CONFIG.isSet("hash_queue_length_ms_high_traffic") || !CONFIG.isSet("hash_queue_length_ms")) ?
					opt_hash_modify_queue_length_ms_high_traffic :
					opt_hash_modify_queue_length_ms;
	
	if(!opt_scanpcapdir[0] && !opt_pcap_queue_use_blocks && opt_pcap_queue_use_blocks_auto_enable) {
		if(opt_udpfrag) {
			if(is_receiver() || is_server()) {
				opt_pcap_queue_use_blocks = 1;
				syslog(LOG_NOTICE, "enabling pcap_queue_use_blocks because set udpfrag in server/receiver mode");
			} else if(getCountInterfaces() > 1) {
				opt_pcap_queue_use_blocks = 1;
				syslog(LOG_NOTICE, "enabling pcap_queue_use_blocks because set udpfrag in multiple interfaces");
			}
		}
		if(opt_dup_check_type != _dedup_na) {
			if(is_receiver() || is_server()) {
				opt_pcap_queue_use_blocks = 1;
				syslog(LOG_NOTICE, "enabling pcap_queue_use_blocks because set deduplicate in server/receiver mode");
			} else if(getCountInterfaces() > 1) {
				opt_pcap_queue_use_blocks = 1;
				syslog(LOG_NOTICE, "enabling pcap_queue_use_blocks because set deduplicate in multiple interfaces");
			}
		}
	}
	
	if(opt_dup_check_type != _dedup_na && opt_pcap_queue_use_blocks && (is_receiver() || is_server())) {
		opt_receiver_check_id_sensor = false;
		syslog(LOG_NOTICE, "disabling receiver_check_id_sensor because set deduplicate in server/receiver mode");
	}
	
	if(getThreadingMode() < 2 && 
	   (getCountInterfaces() > 1 || opt_pcap_queue_use_blocks)) {
		syslog(LOG_NOTICE, "set threading mode 2");
		setThreadingMode(2);
	}
	
	if(isCloud()) {
		opt_cdr_check_duplicity_callid_in_next_pass_insert = true;
		opt_message_check_duplicity_callid_in_next_pass_insert = true;
		opt_ssl_store_sessions = 2;
	}
	
	fill_ssl_portmatrix();
	
	#ifndef HAVE_OPENSSL101
	if(opt_enable_ssl == 1) {
		opt_enable_ssl = 10;
	}
	#endif //HAVE_OPENSSL101
	
	ssl_client_random_portmatrix_set = false;
	if(ssl_client_random_enable) {
		for(unsigned i = 0; i < 65537; i++) {
			if(ssl_client_random_portmatrix[i]) {
				ssl_client_random_portmatrix_set = true;
			}
		}
	}
	ssl_client_random_tcp_set = !ssl_client_random_tcp_host.empty() && ssl_client_random_tcp_port;
	ssl_client_random_use = ssl_client_random_enable || 
				(!ssl_client_random_tcp_host.empty() && ssl_client_random_tcp_port) ||
				ssl_master_secret_file[0];
	if(ssl_client_random_use) {
		if(is_read_from_file_simple()) {
			ssl_client_random_maxwait_ms = 0;
		} else if(!ssl_client_random_maxwait_ms) {
			ssl_client_random_maxwait_ms = 2000;
		}
	}
	
	extern cDtls dtls_handshake_safe_links;
	dtls_handshake_safe_links.setNeedLock(true);
	
	if(opt_ssl_dtls_boost) {
		opt_ssl_dtls_queue_expiration_s = 30;
		ssl_client_random_keep = true;
		opt_ssl_dtls_queue_keep = true;
		opt_ssl_dtls_handshake_safe = 2;
		opt_srtp_rtp_local_instances = true;
		opt_ssl_dtls_find_by_server_side = true;
		opt_ssl_dtls_find_by_client_side = true;
	}
	
	if(opt_callidmerge_header[0] && !CONFIG.isSet("rtpip_find_endpoints")) {
		opt_rtpip_find_endpoints = 1;
	}
	
	set_spool_permission();
	
	strcpy(opt_id_sensor_str, intToString(opt_id_sensor).c_str());
	
	char const *tmpPath = getenv("TMPDIR");
	if(!tmpPath) {
		tmpPath = "/tmp";
	}
	snprintf(opt_crash_bt_filename, sizeof(opt_crash_bt_filename), "%s/%s_crash_bt", tmpPath, appname.c_str());
	
	if(opt_call_id_alternative[0]) {
		opt_call_id_alternative_v = split(opt_call_id_alternative, split(",|;", '|'), true);
		for(unsigned i = 0; i < opt_call_id_alternative_v.size(); i++) {
			if(opt_call_id_alternative_v[i][opt_call_id_alternative_v[i].length() - 1] != ':') {
				opt_call_id_alternative_v[i] += ":";
			}
		}
	} else {
		opt_call_id_alternative_v.clear();
	}
	
	if(opt_remoteparty_caller[0]) {
		opt_remoteparty_caller_v = split(opt_remoteparty_caller, split(",|;", '|'), true);
	} else {
		opt_remoteparty_caller_v.clear();
	}
	
	if(opt_remoteparty_called[0]) {
		opt_remoteparty_called_v = split(opt_remoteparty_called, split(",|;", '|'), true);
	} else {
		opt_remoteparty_called_v.clear();
	}
	
	set_cdr_check_unique_callid_in_sensors_list();
	
	if(opt_numa_balancing_set == numa_balancing_set_enable ||
	   opt_numa_balancing_set == numa_balancing_set_disable) {
		SimpleBuffer content;
		string error;
		if(file_get_contents(numa_balancing_config_filename, &content, &error)) {
			if(opt_numa_balancing_set == numa_balancing_set_enable ?
			    atoi((char*)content) == 0 :
			    atoi((char*)content) != 0) {
				content.clear();
				content.add(opt_numa_balancing_set == numa_balancing_set_enable ? "1" : "0");
				if(file_put_contents(numa_balancing_config_filename, &content, &error)) {
					syslog(LOG_NOTICE, "%s set to %s", numa_balancing_config_filename, (char*)content);
				} else {
					syslog(LOG_ERR, "%s", error.c_str());
				}
			}
		} else {
			syslog(LOG_ERR, "%s", error.c_str());
		}
	}
	
	if(opt_t2_boost && opt_t2_boost_call_find_threads && opt_call_id_alternative[0]) {
		opt_t2_boost_call_find_threads = false;
		syslog(LOG_ERR, "option t2_boost_enable_call_find_threads is not suported with option call_id_alternative");
	}
	
	if(opt_sip_register_advanced) {
		if(!CONFIG.isSet("sip-register-state-timeout")) {
			opt_sip_register_state_timeout = opt_sip_register_advanced > 1 ? (2 * 60) : (5 * 60);
		}
		opt_sip_register_save_eq_states_time = true;
		if(!CONFIG.isSet("sip-register-failed-max-details-per-minute")) {
			opt_sip_register_failed_max_details_per_minute = 5000;
		}
		opt_sip_register_deferred_save = opt_sip_register_advanced > 1;
	}
	
	if(!CONFIG.isSet("ipfix")) {
		opt_ipfix = !opt_ipfix_bind_ip.empty() && opt_ipfix_bind_port;
	}
	
	if(opt_ipfix && (is_sender() || is_client_packetbuffer_sender())) {
		opt_ipfix = false;
		syslog(LOG_ERR, "the ipfix option is not supported on a client with packet buffer sending or in mirror sender mode");
	}
	
	if(!CONFIG.isSet("hep")) {
		opt_hep = !opt_hep_bind_ip.empty() && opt_hep_bind_port;
	}
	
	if(opt_hep && (is_sender() || is_client_packetbuffer_sender())) {
		opt_hep = false;
		syslog(LOG_ERR, "the hep option is not supported on a client with packet buffer sending or in mirror sender mode");
	}
	
	opt_is_client_packetbuffer_sender = is_client_packetbuffer_sender();
	if(opt_is_client_packetbuffer_sender && opt_t2_boost && !opt_pcap_queue_use_blocks_read_check) {
		opt_pcap_queue_use_blocks_read_check = 1;
	}
	
	/* ticket VS-1504 - disabling automatic default values for ignore_rtp_after_response
	if(!CONFIG.isExists("ignore_rtp_after_response")) {
		CONFIG.getItem("ignore_rtp_after_response")->setParamFromValueStr("408;480;486;487;481;600;503");
	}
	*/
	if(opt_ignore_rtp_after_response_list.size() > 1) {
		std::sort(opt_ignore_rtp_after_response_list.begin(), opt_ignore_rtp_after_response_list.end());
	}
	opt_ignore_rtp_after_response = opt_ignore_rtp_after_response_list.size() > 0;
	
	extern void dtls_queue_set_expiration_s(unsigned expiration_s);
	extern void dtls_queue_set_expiration_count(unsigned expiration_count);
	dtls_queue_set_expiration_s(opt_ssl_dtls_queue_expiration_s);
	dtls_queue_set_expiration_count(opt_ssl_dtls_queue_expiration_count);
	
	if(srvcc_numbers) {
		delete srvcc_numbers;
		srvcc_numbers = NULL;
	}
	srvcc_set = opt_srvcc_numbers.size();
	if(srvcc_set) {
		srvcc_numbers = new FILE_LINE(0) ListCheckString;
		for(unsigned i = 0; i < opt_srvcc_numbers.size(); i++) {
			srvcc_numbers->add(opt_srvcc_numbers[i].c_str());
		}
	}

	opt_kamailio = opt_kamailio_dstip.isSet();
	opt_ribbonsbc = opt_ribbonsbc_dstip.isSet();
	sip_data_subst = opt_kamailio || opt_ribbonsbc || opt_audiocodes;
	
	if(opt_dup_check_type == _dedup_murmur && opt_dup_check_ipheader == 2) {
		opt_dup_check_type = _dedup_crc64;
		syslog(LOG_ERR, "murmur type deduplication is not applicable if deduplicate_ipheader = ip_only is specified; it will be changed to crc64");
	}

	// force deduplication to crc32 always 
	#if defined(__x86_64__) or defined(__i386__)
	if(opt_dup_check_type == _dedup_crc32_sw && crc32_sse_is_available()) {
		opt_dup_check_type = _dedup_crc32_hw;
	} else if(opt_dup_check_type == _dedup_crc32_hw && !crc32_sse_is_available()) {
		opt_dup_check_type = _dedup_crc32_sw;
	}
	#endif
	
	if(is_set_cleandatabase_by_size()) {
		if(isCloud() ||
		   is_client() || is_client_packetbuffer_sender() || is_sender() || 
		   opt_nocdr || opt_disable_partition_operations || !opt_cdr_partition) {
			clean_params_cleandatabase_by_size();
		} else if(strcmp(mysql_host, "127.0.0.1") && strcmp(mysql_host, "localhost") && mysql_datadir.empty() && !opt_cleandatabase_size_force) {
			cLogSensor::log(cLogSensor::error, "The requirement to clean the database by size is that if the MySQL server is set to an address other than 127.0.0.1 or 'localhost', the 'mysqldatadir' must be specified.");
			clean_params_cleandatabase_by_size();
		} else {
			double total_MB, free_MB, free_perc, files_sum_size_MB;
			SqlDb *sqlDb = createSqlObject();
			bool stat_rslt = sqlDb->getDbDatadirStats(mysql_datadir.c_str(), NULL, &total_MB, &free_MB, &free_perc, &files_sum_size_MB);
			delete sqlDb;
			if(!stat_rslt) {
				cLogSensor::log(cLogSensor::error, "Failed to retrieve the required information for database size management. Please verify access to the database's data folder.");
				clean_params_cleandatabase_by_size();
			}
		}
	}
	
	opt_pcap_queue_receive_sensor_id_by_sender_set = CONFIG.isSet("mirror_bind_sensor_id_by_sender");
	
	if(!CONFIG.isSet("sip-msg-save-ua") && opt_cdr_ua_normalisation) {
		opt_sip_msg_save_ua = true;
	}
	
	if(opt_pre_process_packets_next_thread > 0) {
		if(!CONFIG.isSet("pre_process_packets_next_thread_find_call")) {
			opt_pre_process_packets_next_thread_find_call = opt_pre_process_packets_next_thread;
		}
		if(!CONFIG.isSet("pre_process_packets_next_thread_process_call")) {
			opt_pre_process_packets_next_thread_process_call = opt_pre_process_packets_next_thread;
		}
		if(!CONFIG.isSet("pre_process_packets_next_thread_detach")) {
			opt_pre_process_packets_next_thread_detach = opt_pre_process_packets_next_thread;
		}
		if(!CONFIG.isSet("pre_process_packets_next_thread_detach2")) {
			opt_pre_process_packets_next_thread_detach2 = opt_pre_process_packets_next_thread;
		}
		if(!CONFIG.isSet("pre_process_packets_next_thread_defrag")) {
			opt_pre_process_packets_next_thread_defrag = opt_pre_process_packets_next_thread;
		}
	}
	
	#if defined(__x86_64__)
	if(!CONFIG.isSet("usleep_minimal") && is_vmware()) {
		opt_usleep_minimal = 50;
	}
	#endif
	
	#ifndef HAVE_LIBLZO
	if(snifferServerOptions.type_compress == _cs_compress_lzo) {
		snifferServerOptions.type_compress = _cs_compress_gzip;
	}
	#endif
	#ifndef HAVE_LIBZSTD
	if(snifferServerOptions.type_compress == _cs_compress_zstd) {
		snifferServerOptions.type_compress = _cs_compress_gzip;
	}
	#endif
	
	snifferClientOptions.hosts.parse();
	snifferClientOptions_charts_cache.hosts.parse();
	
	#if not (HAVE_LIBLAME && HAVE_LIBLAME)
	if(opt_audio_format == FORMAT_MP3) {
		syslog(LOG_ERR, "MP3 support requires building with lame and mpg123 libraries. OGG format will be used.");
		opt_audio_format = FORMAT_OGG;
	}
	#endif
	
	if(!opt_cdr_problems) {
		if(opt_cdr_problems_by_ip || opt_cdr_problems_by_number || opt_cdr_problems_by_comb) {
			opt_cdr_problems = true;
		}
	} else {
		if(!opt_cdr_problems_by_ip && !opt_cdr_problems_by_number && !opt_cdr_problems_by_comb) {
			opt_cdr_problems_by_ip = true;
		}
	}
	
	if(opt_sniffer_threads_ext) {
		sverb.sniffer_threads_ext = true;
	}
}

void check_context_config() {
	#if not HAVE_LIBWIRESHARK
		if(opt_enable_ss7) {
			cLogSensor::log(cLogSensor::error, "option ss7 need voipmonitor with wireshark module");
		}
	#endif
	#if HAVE_LIBDPDK
	if(opt_use_dpdk) {
		dpdk_check_configuration();
	}
	#endif
}

void set_context_config_after_check_db_schema() {
	extern sExistsColumns existsColumns;
	if(opt_detect_alone_bye) {
		if(!existsColumns.cdr_flags) {
			syslog(LOG_ERR, "option detect_alone_bye is not suported without column cdr.flags");
			opt_detect_alone_bye = false;
		}
		if(!existsColumns.cdr_next_calldate) {
			syslog(LOG_ERR, "option detect_alone_bye is not suported without column cdr_next.calldate");
			opt_detect_alone_bye = false;
		}
	}
}

/* set default values after config and command line parrams processing if nothing is set
   - port matrixes only now */
void set_default_values() {
	portMatrixDefaultPort matrixDefaultPorts[] = {
		{sipportmatrix, 5060},
		{skinnyportmatrix, 2000},
		{mgcp_gateway_tcp_portmatrix, 2427},
		{mgcp_gateway_udp_portmatrix, 2427},
		{mgcp_callagent_tcp_portmatrix, 2727},
		{mgcp_callagent_udp_portmatrix, 2727},
		{NULL, 0}
	};
	portMatrixDefaultPort *p = matrixDefaultPorts;
	while (p->portMatrix) {
		bool found = false;
		for (int i = 0; i < 65537; i++) {
			if (p->portMatrix[i]) {
				found = true;
				break;
			}
		}
		if (!found) {
			p->portMatrix[p->defaultPort] = 1;
		}
		p++;
        }
	packet_s_process_calls_info::set_size_of();
	packet_s_process_0::set_size_of();
}

void create_spool_dirs() {
	if(opt_spooldir_main[0]) {
		spooldir_mkdir(opt_spooldir_main);
	}
	if(opt_spooldir_rtp[0]) {
		spooldir_mkdir(opt_spooldir_rtp);
	}
	if(opt_spooldir_graph[0]) {
		spooldir_mkdir(opt_spooldir_graph);
	}
	if(opt_spooldir_audio[0]) {
		spooldir_mkdir(opt_spooldir_audio);
	}
	if(opt_spooldir_audiograph[0]) {
		spooldir_mkdir(opt_spooldir_audiograph);
	}
	if(opt_spooldir_2_main[0]) {
		spooldir_mkdir(opt_spooldir_2_main);
	}
	if(opt_spooldir_2_rtp[0]) {
		spooldir_mkdir(opt_spooldir_2_rtp);
	}
	if(opt_spooldir_2_graph[0]) {
		spooldir_mkdir(opt_spooldir_2_graph);
	}
	if(opt_spooldir_2_audio[0]) {
		spooldir_mkdir(opt_spooldir_2_audio);
	}
	if(opt_spooldir_2_audiograph[0]) {
		spooldir_mkdir(opt_spooldir_2_audiograph);
	}
}


bool check_complete_parameters() {
	if (!is_read_from_file() && ifname[0] == '\0' && opt_scanpcapdir[0] == '\0' && 
	    !is_server() &&
	    !is_remote_chart_server() &&
	    !is_set_gui_params() &&
	    !printConfigStruct && !printConfigFile && !is_receiver() &&
	    !opt_database_backup &&
	    !opt_test){
                        /* Ruler to assist with keeping help description to max. 80 chars wide:
                                  1         2         3         4         5         6         7         8
                         12345678901234567890123456789012345678901234567890123456789012345678901234567890
                        */
                printf("\nvoipmonitor version %s\n"
                        "\nUsage: %s [OPTIONS]\n"
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
                        " -Y, --sipports=<ports>\n"
                        "      Listen to SIP protocol on entered ports. Separated by commas.\n"
                        "\n"
                        " --audio-format=<wav|ogg|mp3>\n"
                        "      Save to WAV or OGG or MP3 audio format. Default is WAV.\n"
                        "\n"
                        " --config-file=<filename>\n"
                        "      Specify configuration file full path.  Suggest /etc/voipmonitor.conf\n"
                        "\n"
                        " --ignorertcpjitter=<value>\n"
                        "      Ignore RTCP jitter values greater than this value. Default is zero (disabled).\n"
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
                        " --sip-register\n"
                        "      Save SIP register requests to cdr.register table and to pcap file.\n"
                        "\n"
                        " --skinny\n"
                        "      analyze SKINNY VoIP protocol. Default port is TCP port 2000\n"
                        "\n"
                        " --skinnyports=<ports>\n"
                        "      Listen to SKINNY protocol on entered ports. Separated by commas.\n"
                        "\n"
                        " --mgcp\n"
                        "      analyze MGCP VoIP protocol.\n"
                        "\n"
                        " --update-schema\n"
                        "      Create or upgrade the database schema, and then exit.  Forces -k option.\n"
                        "      Database access/name can be set via commandline parameters or in config file\n"
                        "      via --config-file option. Useful cmd paramereters are -b -p -h -O -u\n"
                        "\n"
                        " --vm-buffer=<n>\n"
                        "      vmbuffer is user space buffers in MB which is used in case there is more\n"
                        "      than 1 CPU and the sniffer run two threads - one for reading data from\n"
                        "      libpcap and writing to vmbuffer and second reads data from vmbuffer and\n"
                        "      processes it.  For very high network loads set this to very high number.\n"
                        "      In case the system is droping packets (which is logged to syslog)\n"
                        "      increase this value.  Default is 20 MB\n"
                        "\n"
                        " --reindex-all\n"
                        "      reindexes spool storage and quits\n"
                        "\n"
                        " --run-cleanspool\n"
                        "      cleans spooldir and quits\n"
                        "\n"
                        " --run-cleanspool-maxdays=<n>\n"
                        "      clean everything older than n days in spool directory\n"
                        "\n"
                        " --run-droppartitions-maxdays=<n>\n"
                        "      cleans all database partitions older than n days\n"
                        "\n"
                        " --watchdog=yes|no\n"
                        "      enable or disable watchdog script (/tmp/voipmonitor_watchdog) which will start voipmonitor if it is not running (default yes)\n"
                        "\n"
                        "One of <-i interface> or <-r pcap-file> must be specified, otherwise you may\n"
                        "set interface in configuration file.\n\n"
                        , getVersionWithBuild().c_str(), appname.c_str());
                        /*        1         2         3         4         5         6         7         8
                         12345678901234567890123456789012345678901234567890123456789012345678901234567890
                           Ruler to assist with keeping help description to max. 80 chars wide:
                        */

		return false;
	}
	return true;
}

void final_parameters() {
	u_int64_t max_buffer_mem_mb = buffersControl.getMaxBufferMemMB();
	if(max_buffer_mem_mb > 0) {
		syslog(LOG_NOTICE, "max_buffer_mem: %" int_64_format_prefix "lu MB", max_buffer_mem_mb);
	}
}

void set_cdr_check_unique_callid_in_sensors_list() {
	opt_cdr_check_unique_callid_in_sensors_list.clear();
	if(!opt_cdr_check_unique_callid_in_sensors[0]) {
		return;
	}
	vector<string> _list = split(opt_cdr_check_unique_callid_in_sensors.c_str(), split(",|;| ", '|'), true);
	for(unsigned i = 0; i < _list.size(); i++) {
		int _idSensor = atoi(_list[i].c_str());
		opt_cdr_check_unique_callid_in_sensors_list.insert(_idSensor > 0 ? _idSensor : -1);
	}
}

bool is_enable_sip_msg() {
	return(opt_sip_options || opt_sip_subscribe || opt_sip_notify);
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

bool is_read_from_file_by_pb_acttime() {
       return(opt_pb_read_from_file[0] && opt_pb_read_from_file_acttime);
}

bool is_enable_packetbuffer() {
	return(!is_read_from_file_simple() && !opt_pcap_queue_disable);
}

bool is_enable_rtp_threads() {
	return(!is_read_from_file_simple() &&
	       rtp_threaded &&
	       !is_sender() && !is_client_packetbuffer_sender());
}

bool is_enable_cleanspool(bool log) {
	if(opt_cleanspool &&
	   !opt_nocdr &&
	   isSqlDriver("mysql") &&
	   !is_read_from_file_simple() &&
	   !is_sender() && !is_client_packetbuffer_sender()) {
		if(opt_newdir) {
			return(true);
		} else if(log) {
			syslog(LOG_ERR, "%s", "cleanspol need new dir schema!!!");
		}
	}
	return(false);
}

bool is_receiver() {
	return(opt_pcap_queue_receive_from_ip_port);
}

bool is_sender() {
	return(!is_receiver() &&
	       opt_pcap_queue_send_to_ip_port);
}

bool is_server() {
	return(snifferServerOptions.isEnable());
}

bool is_client() {
	return(snifferClientOptions.isEnable());
}

bool is_client_packetbuffer_sender() {
	return(snifferClientOptions.isEnablePacketBufferSender());
}

bool enable_set_sensor_id_by_client_or_sender() {
	if(is_receiver()) {
		if(opt_pcap_queue_receive_sensor_id_by_sender_set) {
			return(opt_pcap_queue_receive_sensor_id_by_sender);
		} else {
			return(opt_id_sensor <= 0);
		}
	}
	return(true);
}

bool is_load_pcap_via_client(const char *sensor_string) {
	return(strstr(sensor_string, "load_pcap_user_id") != NULL);
}

bool is_remote_chart_server() {
	return(snifferClientOptions.remote_chart_server);
}

int check_set_rtp_threads(int num_rtp_threads) {
	if(num_rtp_threads <= 0) num_rtp_threads = sysconf( _SC_NPROCESSORS_ONLN ) - 1;
	if(num_rtp_threads <= 0) num_rtp_threads = 1;
	return(num_rtp_threads);
}

bool is_support_for_mysql_new_store() {
	return(!(opt_cdr_check_duplicity_callid_in_next_pass_insert ||
		 opt_message_check_duplicity_callid_in_next_pass_insert));
}

bool is_support_manager_aes() {
	return(!is_sender() && 
	       (!opt_nocdr || (!opt_manager_aes_key.empty() && !opt_manager_aes_iv.empty())));
}

bool is_set_cleandatabase_by_size() {
	return(opt_cleandatabase_size ||
	       opt_cleandatabase_min_free_size ||
	       opt_cleandatabase_cdr_size ||
	       opt_cleandatabase_cdr_rtp_energylevels_size ||
	       opt_cleandatabase_ss7_size ||
	       opt_cleandatabase_http_enum_size ||
	       opt_cleandatabase_webrtc_size ||
	       opt_cleandatabase_register_state_size ||
	       opt_cleandatabase_register_failed_size ||
	       opt_cleandatabase_register_time_info_size ||
	       opt_cleandatabase_sip_msg_size ||
	       opt_cleandatabase_cdr_stat_size ||
	       opt_cleandatabase_cdr_problems_size ||
	       opt_cleandatabase_rtp_stat_size ||
	       opt_cleandatabase_log_sensor_size);
}

void clean_params_cleandatabase_by_size() {
	opt_cleandatabase_size = 0;
	opt_cleandatabase_min_free_size = 0;
	opt_cleandatabase_cdr_size = 0;
	opt_cleandatabase_cdr_rtp_energylevels_size = 0;
	opt_cleandatabase_ss7_size = 0;
	opt_cleandatabase_http_enum_size = 0;
	opt_cleandatabase_webrtc_size = 0;
	opt_cleandatabase_register_state_size = 0;
	opt_cleandatabase_register_failed_size = 0;
	opt_cleandatabase_register_time_info_size = 0;
	opt_cleandatabase_sip_msg_size = 0;
	opt_cleandatabase_cdr_stat_size = 0;
	opt_cleandatabase_cdr_problems_size = 0;
	opt_cleandatabase_rtp_stat_size = 0;
	opt_cleandatabase_log_sensor_size = 0;
}

void dns_lookup_common_hostnames() {
	const char *hostnames[] = {
		"voipmonitor.org",
		"www.voipmonitor.org",
		"download.voipmonitor.org",
		"cloud.voipmonitor.org",
		"cloud2.voipmonitor.org",
		"cloud3.voipmonitor.org",
		"1.2.3.4"
	};
	vector<vmIP> ips;
	for(unsigned int i = 0; i < sizeof(hostnames) / sizeof(hostnames[0]) && !terminating; i++) {
		resolver.resolve(hostnames[i], &ips);
	}
	if(!terminating && snifferClientOptions.hosts.isSet()) {
		snifferClientOptions.hosts.resolve();
	}
}

bool _use_mysql_2() {
	return(!opt_database_backup &&
	       !isCloud() &&
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
	vector<string> responses = split(opt_nocdr_for_last_responses, split(",|;", "|"), true);
	for(unsigned i = 0; i < responses.size(); i++) {
		nocdr_rules.set(responses[i].c_str());
	}
}

extern "C" {
void fifobuff_add(void *fifo_buff, const char *data, unsigned int datalen) {
	((FifoBuffer*)fifo_buff)->add((u_char*)data, datalen);
	//cout << "fifo * " << ((FifoBuffer*)fifo_buff)->size_get() << " / time [ms] : " << getTimeMS() << endl;
}
}

eTypeSpoolFile getTypeSpoolFile(const char *filePathName) {
	for(int typeSpoolFile = tsf_sip; typeSpoolFile < tsf_all; ++typeSpoolFile) {
		const char *dir = getSpoolTypeDir((eTypeSpoolFile)typeSpoolFile);
		if(dir) {
			if(strstr(filePathName, ("/" + string(dir) + "/").c_str())) {
				return((eTypeSpoolFile)typeSpoolFile);
			}
		}
	}
	return(tsf_na);
}

eTypeSpoolFile findTypeSpoolFile(unsigned int spool_index, const char *filePathName) {
	eTypeSpoolFile type_spool_file_check;
	for(int i = 0; i < 2; i++) {
		type_spool_file_check = i == 0 ? getTypeSpoolFile(filePathName) : tsf_main;
		if(file_exists(string(getSpoolDir(type_spool_file_check, spool_index)) + '/' + filePathName) ||
		   type_spool_file_check <= tsf_sip) {
			break;
		}
	}
	return(type_spool_file_check);
}


sCloudRouterVerbose& CR_VERBOSE() {
	static sCloudRouterVerbose cr_verbose;
	return(cr_verbose);
}

bool CR_TERMINATE() {
	return(is_terminating() || is_readend());
}

void CR_SET_TERMINATE() {
	return(set_terminating());
}


int useNewStore() {
	if(isCloud() && cloud_receiver) {
		return(cloud_receiver->get_use_mysql_set_id());
	} else if(is_client()) {
		return(snifferClientOptions.mysql_new_store);
	}
	extern int opt_mysql_enable_new_store;
	extern bool opt_mysql_enable_set_id;
	return(opt_mysql_enable_new_store ? 
		opt_mysql_enable_new_store : 
		opt_mysql_enable_set_id);
}

bool useSetId() {
	if(isCloud() && cloud_receiver) {
		return(cloud_receiver->get_use_mysql_set_id());
	} else if(is_client()) {
		return(snifferClientOptions.mysql_set_id);
	}
	extern bool opt_mysql_enable_set_id;
	return(opt_mysql_enable_set_id);
}

bool useCsvStoreFormat() {
	return(useNewStore() &&
	       useSetId() && 
	       opt_mysql_enable_multiple_rows_insert &&
	       ((is_client() && snifferClientOptions.csv_store_format) ||
		opt_csv_store_format ||
		opt_cdr_check_exists_callid ||
		opt_cdr_check_unique_callid_in_sensors_list.size()));
}

bool useChartsCacheInProcessCall() {
	return(opt_charts_cache && !opt_charts_cache_store);
}

bool useChartsCacheInStore() {
	return((opt_charts_cache && opt_charts_cache_store) ||
	       (is_client() && snifferClientOptions.charts_cache_store));
}

bool useChartsCacheProcessThreads() {
	return(opt_charts_cache || snifferClientOptions.remote_chart_server);
}

bool existsChartsCacheServer() {
	return(snifferClientService_charts_cache);
}

bool useCdrStatInProcessCall() {
	return((opt_cdr_stat_values || opt_cdr_stat_sources) && !useChartsCacheInStore());
}

bool useCdrStatInStore() {
	return((opt_cdr_stat_values || opt_cdr_stat_sources) && useChartsCacheInStore());
}

bool useCdrStatProcessThreads() {
	return(opt_cdr_stat_values || opt_cdr_stat_sources);
}

bool useCdrProblemsInProcessCall() {
	return(opt_cdr_problems && !useChartsCacheInStore());
}

bool useCdrProblemsInStore() {
	return(opt_cdr_problems && useChartsCacheInStore());
}

bool useCdrProblemsProcessThreads() {
	return(opt_cdr_problems);
}

int cleanup_calls_period() {
	return(CONFIG.isSet("cleanup_calls_period") || !opt_quick_save_cdr ?
		opt_cleanup_calls_period :
		1);
}

unsigned getCountInterfaces() {
	return(PcapQueue_readFromInterface::getCountInterfaces(ifname, &ifname_libpcap_filter));
}

void set_all_ports_for_tcp() {
	for(unsigned i = 0; i < 0xFFFF; i++) {
		sipportmatrix[i] = true;
	}
}


#ifdef HAVE_LIBGNUTLS
#include <gcrypt.h>
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif
volatile int _init_lib_gcrypt_rslt = -1;
volatile int _init_lib_gcrypt_sync = 0;
bool init_lib_gcrypt() {
	if(_init_lib_gcrypt_rslt >= 0) {
		return(_init_lib_gcrypt_rslt);
	}
	__SYNC_LOCK(_init_lib_gcrypt_sync);
	if(_init_lib_gcrypt_rslt >= 0) {
		__SYNC_UNLOCK(_init_lib_gcrypt_sync);
		return(_init_lib_gcrypt_rslt);
	}
	bool rslt = false;
	#ifdef HAVE_LIBGNUTLS
	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	if(gcry_check_version(GCRYPT_VERSION)) {
		gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
		gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
		gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
		gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
		rslt = true;
	} else {
		syslog(LOG_ERR, "libgcrypt version mismatch");
	}
	#endif
	_init_lib_gcrypt_rslt = rslt;
	__SYNC_UNLOCK(_init_lib_gcrypt_sync);
	return(_init_lib_gcrypt_rslt);
}


#if HAVE_LIBSRTP
#include <srtp2/srtp.h>
volatile int _init_lib_srtp_rslt = -1;
volatile int _init_lib_srtp_sync = 0;
bool init_lib_srtp() {
	if(_init_lib_srtp_rslt >= 0) {
		return(_init_lib_srtp_rslt);
	}
	__SYNC_LOCK(_init_lib_srtp_sync);
	if(_init_lib_srtp_rslt >= 0) {
		__SYNC_UNLOCK(_init_lib_srtp_sync);
		return(_init_lib_srtp_rslt);
	}
	srtp_init();
	_init_lib_srtp_rslt = 1;
	__SYNC_UNLOCK(_init_lib_srtp_sync);
	return(_init_lib_srtp_rslt);
}
#endif


#if DEBUG_ALLOC_PACKETS

static map<const void*, string> debug_alloc_packet_map;
static volatile int debug_alloc_packet_sync = 0;

void debug_alloc_packet_alloc(const void *packet, const char *set) {
	__SYNC_LOCK(debug_alloc_packet_sync);
	if(debug_alloc_packet_map.find(packet) == debug_alloc_packet_map.end()) {
		debug_alloc_packet_map[packet] = set;
	} else {
		cout << "*** debug_alloc_packet_alloc - duplicity in list " << hex << packet << " : " << dec << debug_alloc_packet_map[packet] << endl;
	}
	__SYNC_UNLOCK(debug_alloc_packet_sync);
}

void debug_alloc_packet_free(const void *packet) {
	__SYNC_LOCK(debug_alloc_packet_sync);
	if(debug_alloc_packet_map.find(packet) != debug_alloc_packet_map.end()) {
		debug_alloc_packet_map.erase(packet);
	} else {
		cout << "*** debug_alloc_packet_free - missing in list " << hex << packet << dec << endl;
	}
	__SYNC_UNLOCK(debug_alloc_packet_sync);
}

void debug_alloc_packet_set(const void *packet, const char *set) {
	__SYNC_LOCK(debug_alloc_packet_sync);
	if(debug_alloc_packet_map.find(packet) != debug_alloc_packet_map.end()) {
		debug_alloc_packet_map[packet] = set;
	} else {
		cout << "*** debug_alloc_packet_set - missing in list " << hex << packet << dec << endl;
	}
	__SYNC_UNLOCK(debug_alloc_packet_sync);
}

void debug_alloc_packet_list() {
	__SYNC_LOCK(debug_alloc_packet_sync);
	if(debug_alloc_packet_map.size()) {
		cout << "*** debug_alloc_packet_list - leaks" << endl;
		for(map<const void*, string>::iterator iter = debug_alloc_packet_map.begin(); iter != debug_alloc_packet_map.end(); iter++) {
			cout << hex << iter->first << " : " << dec << iter->second << endl;
		}
	}
	__SYNC_UNLOCK(debug_alloc_packet_sync);
}

#endif
