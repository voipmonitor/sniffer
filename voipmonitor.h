#ifndef VOIPMONITOR_H
#define VOIPMONITOR_H

#include <climits>
#include <sys/types.h>
#include <string>
#include <netdb.h>
#include <unistd.h>
#include "config.h"
#include "common.h"
#include "proc_limit.h"
#include "heap_safe.h"
#include "sync.h"
#include "tools_global.h"

#include "voipmonitor_define.h"


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


#include "endian.h"
#include "ip.h"


#ifndef ulong 
#define ulong unsigned long 
#endif



#ifndef GLOBAL_DECLARATION
extern 
#endif
sVerbose sverb;

void vm_terminate();
void vm_terminate_error(const char *terminate_error);
inline void set_terminating() {
	extern volatile int terminating;
	terminating = 1;
}
inline void inc_terminating() {
	extern volatile int terminating;
	++terminating;
}
inline void clear_terminating() {
	extern volatile int terminating;
	terminating = 0;
}
inline int is_terminating() {
	extern volatile int terminating;
	return(terminating);
}
bool is_terminating_without_error();

inline void set_readend() {
	extern volatile int readend;
	readend = 1;
}
inline void clear_readend() {
	extern volatile int readend;
	readend = 0;
}
inline bool is_readend() {
	extern volatile int readend;
	return(readend);
}

bool is_enable_sip_msg();

bool is_read_from_file();
bool is_read_from_file_simple();
bool is_read_from_file_by_pb();
bool is_read_from_file_by_pb_acttime();
inline bool no_sip_reassembly() { 
	extern bool opt_read_from_file_no_sip_reassembly;
	return(opt_read_from_file_no_sip_reassembly);
}
bool is_enable_packetbuffer();
bool is_enable_rtp_threads();
bool is_enable_cleanspool(bool log = false);
bool is_receiver();
bool is_sender();
bool is_server();
bool is_client();
bool is_client_packetbuffer_sender();
bool enable_set_sensor_id_by_client_or_sender();
bool is_load_pcap_via_client(const char *sensor_string);
bool is_remote_chart_server();
int check_set_rtp_threads(int num_rtp_threads);
bool is_support_for_mysql_new_store();
bool is_support_manager_aes();
bool is_set_cleandatabase_by_size();
void clean_params_cleandatabase_by_size();

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
	tsf_reg,
	tsf_skinny,
	tsf_mgcp,
	tsf_ss7,
	tsf_rtp,
	tsf_graph,
	tsf_audio,
	tsf_all
};

enum eCmdLineParams {
	_param_cmp_config = 1000,
	_param_sensor_string,
	_param_pcapscan_method,
	_param_skinny,
	_param_skinnyports,
	_param_mgcp,
	_param_ignorertcpjitter,
	_param_natalias,
	_param_mono,
	_param_untar_gui,
	_param_unlzo_gui,
	_param_waveform_gui,
	_param_spectrogram_gui,
	_param_audio_convert,
	_param_audio_transcribe,
	_param_rtp_streams_analysis,
	_param_disable_rtp_seq_probation,
	_param_saveaudio_from_rtp,
	_param_update_schema,
	_param_print_config_struct,
	_param_print_config_file,
	_param_print_config_file_default,
	_param_check_regexp,
	_param_test_regexp,
	_param_read_pcap,
	_param_max_packets,
	_param_time_to_terminate,
	_param_continue_after_read,
	_param_suppress_cleanup_after_read,
	_param_unlimited_read,
	_param_nonstop_read,
	_param_nonstop_read_quick,
	_param_diff_days,
	_param_diff_secs,
	_param_time_adjustment,
	_param_reindex_all,
	_param_run_cleanspool,
	_param_run_cleanspool_maxdays,
	_param_test_cleanspool_load,
	_param_run_droppartitions_maxdays,
	_param_run_droppartitions_rtp_stat_maxdays,
	_param_run_droppartitions_cdr_stat_maxdays,
	_param_clean_obsolete,
	_param_check_db,
	_param_fax_deduplicate,
	_param_create_udptl_streams,
	_param_conv_raw_info,
	_param_find_country_for_number,
	_param_find_country_for_ip,
	_param_test_billing,
	_param_test_billing_json,
	_param_watchdog,
	_param_cloud_db,
	_param_cloud_host,
	_param_cloud_token,
	_param_cloud_port,
	_param_server_host,
	_param_server_port,
	_param_server_pass,
	_param_disable_dbupgradecheck,
	_param_ssl_master_secret_file,
	_param_t2_boost,
	_param_json_config,
	_param_sip_msg_save,
	_param_dedup_pcap,
	_param_anonymize_pcap,
	_param_prepare_rtcp_data,
	_param_process_pcap,
	_param_heap_profiler,
	_param_revaluation,
	_param_reassign_countries,
	_param_eval_formula,
	_param_ipfix_client_emulation,
	_param_hep_client_emulation,
	_param_ws_calls,
	_param_extract_payload,
	_param_extract_rtp_payload,
	_param_load_rtp_pcap,
	_param_check_bad_ether_type,
	_param_manager_enable_unencrypted
};

struct portMatrixDefaultPort {
	char *portMatrix;
	int defaultPort;
};

#define MAX_TYPE_SPOOL_FILE (int)tsf_all
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
inline const char *getStorePcaps() {
	extern char opt_spooldir_main[1024];
	return(opt_spooldir_main);
}

void vmChdir() {
	extern char opt_spooldir_main[1024];
	chdir(opt_spooldir_main);
}

#define enable_pcap_split (opt_newdir && opt_pcap_split)

const char *getSpoolTypeDir(eTypeSpoolFile typeSpoolFile) {
	extern int opt_newdir;
	extern int opt_pcap_split;
	return(typeSpoolFile == tsf_sip ? (enable_pcap_split ? "SIP" : "ALL") :
	       typeSpoolFile == tsf_reg ? "REG" :
	       typeSpoolFile == tsf_skinny ? (enable_pcap_split ? "SKINNY" : "ALL") :
	       typeSpoolFile == tsf_mgcp ? (enable_pcap_split ? "MGCP" : "ALL") :
	       typeSpoolFile == tsf_ss7 ? "SS7" :
	       typeSpoolFile == tsf_rtp ? (enable_pcap_split ? "RTP" : "ALL") :
	       typeSpoolFile == tsf_graph ? "GRAPH" :
	       typeSpoolFile == tsf_audio ? "AUDIO" : 
	       NULL);
}

eTypeSpoolFile getSpoolTypeFile(const char *typeDir) {
	static struct {
		const char *dir;
		eTypeSpoolFile type;
	} dir_type[] = {
		{ "SIP", tsf_sip },
		{ "REG", tsf_reg },
		{ "SKINNY", tsf_skinny },
		{ "MGCP", tsf_mgcp },
		{ "SS7", tsf_ss7 },
		{ "RTP", tsf_rtp },
		{ "GRAPH", tsf_graph },
		{ "AUDIO", tsf_audio },
		{ "ALL", tsf_all }
	};
	for(unsigned i = 0; i < sizeof(dir_type) / sizeof(dir_type[0]); i++) {
		if(!strcasecmp(typeDir, dir_type[i].dir)) {
			return(dir_type[i].type);
		}
	}
	return(tsf_na);
}

const char *getSpoolTypeFilesIndex(eTypeSpoolFile typeSpoolFile, bool addFileConv) {
	extern int opt_pcap_dump_tar;
	extern int opt_newdir;
	extern int opt_pcap_split;
	return(addFileConv && opt_pcap_dump_tar ?
		typeSpoolFile == tsf_sip ? "sip" :
		typeSpoolFile == tsf_reg ? "sip" : 
		typeSpoolFile == tsf_skinny ? "sip" : 
		typeSpoolFile == tsf_mgcp ? "sip" : 
		typeSpoolFile == tsf_ss7 ? "sip" : 
		typeSpoolFile == tsf_rtp ? "rtp" :
		typeSpoolFile == tsf_graph ? "graph" :
		typeSpoolFile == tsf_audio ? "audio" : 
		NULL :
	       addFileConv && !enable_pcap_split ?
		typeSpoolFile == tsf_sip ? "sip" :
		typeSpoolFile == tsf_reg ? "reg" : 
		typeSpoolFile == tsf_skinny ? "sip" : 
		typeSpoolFile == tsf_mgcp ? "sip" : 
		typeSpoolFile == tsf_ss7 ? "ss7" : 
		typeSpoolFile == tsf_rtp ? "sip" :
		typeSpoolFile == tsf_graph ? "graph" :
		typeSpoolFile == tsf_audio ? "audio" : 
		NULL :
		//
		typeSpoolFile == tsf_sip ? "sip" :
		typeSpoolFile == tsf_reg ? "reg" : 
		typeSpoolFile == tsf_skinny ? "skinny" : 
		typeSpoolFile == tsf_mgcp ? "mgcp" : 
		typeSpoolFile == tsf_ss7 ? "ss7" : 
		typeSpoolFile == tsf_rtp ? "rtp" :
		typeSpoolFile == tsf_graph ? "graph" :
		typeSpoolFile == tsf_audio ? "audio" :
		typeSpoolFile == tsf_all ? "all" :
		NULL);
}

const char *getFileTypeExtension(eTypeSpoolFile typeSpoolFile) {
	return(typeSpoolFile == tsf_sip ? "pcap" :
	       typeSpoolFile == tsf_reg ? "pcap" : 
	       typeSpoolFile == tsf_skinny ? "pcap" : 
	       typeSpoolFile == tsf_mgcp ? "pcap" : 
	       typeSpoolFile == tsf_ss7 ? "pcap" : 
	       typeSpoolFile == tsf_rtp ? "pcap" :
	       typeSpoolFile == tsf_graph ? "graph" :
	       typeSpoolFile == tsf_audio ? "wav" : 
	       NULL);
}
eTypeSpoolFile getTypeSpoolFile(const char *filePathName);
eTypeSpoolFile findTypeSpoolFile(unsigned int spool_index, const char *filePathName);

#define snifferMode_read_from_interface_str string("1")
#define snifferMode_read_from_files_str string("2")
#define snifferMode_sender_str string("3")

inline unsigned spooldir_file_permission() {
	extern unsigned opt_spooldir_file_permission_int;
	return(opt_spooldir_file_permission_int);
}
inline unsigned spooldir_dir_permission() {
	extern unsigned opt_spooldir_dir_permission_int;
	return(opt_spooldir_dir_permission_int);
}
inline unsigned spooldir_owner_id() {
	extern unsigned opt_spooldir_owner_id;
	return(opt_spooldir_owner_id);
}
inline unsigned spooldir_group_id() {
	extern unsigned opt_spooldir_group_id;
	return(opt_spooldir_group_id);
}

inline bool isCloud() {
	extern bool cloud_router;
	extern char cloud_host[256];
	extern unsigned cloud_router_port;
	extern char cloud_token[256];
	return(cloud_router && cloud_host[0] && cloud_router_port && cloud_token[0]);
}

int useNewStore();
bool useSetId();
bool useCsvStoreFormat();

bool useChartsCacheInProcessCall();
bool useChartsCacheInStore();
bool useChartsCacheProcessThreads();
bool existsChartsCacheServer();

bool useCdrStatInProcessCall();
bool useCdrStatInStore();
bool useCdrStatProcessThreads();

int cleanup_calls_period();

void set_all_ports_for_tcp();

inline bool useChartsCacheOrCdrStatInProcessCall() {
	return(useChartsCacheInProcessCall() || useCdrStatInProcessCall());
}
inline bool useChartsCacheOrCdrStatInStore() {
	return(useChartsCacheInStore() || useCdrStatInStore());
}
inline bool useChartsCacheOrCdrStatProcessThreads() {
	return(useChartsCacheProcessThreads() || useCdrStatProcessThreads());
}


typedef struct mysqlSSLOptions {
	char key[PATH_MAX];
	char cert[PATH_MAX];
	char caCert[PATH_MAX];
	char caPath[PATH_MAX];
	string ciphers;
} mysqlSSLOptions;

#define numa_balancing_set_autodisable 1
#define numa_balancing_set_enable 2
#define numa_balancing_set_disable 3

#define numa_balancing_config_filename "/proc/sys/kernel/numa_balancing"


inline void inc_counter_user_packets(unsigned user_index) {
	extern volatile u_int64_t counter_user_packets[5];
	__SYNC_INC(counter_user_packets[user_index]);
}


#if EXPERIMENTAL_SEPARATE_PROCESSSING
inline int separate_processing() {
	extern int opt_separate_processing;
	return(opt_separate_processing);
}
#endif


string getVersionWithBuild() {
	string rslt;
	rslt = RTPSENSOR_VERSION;
	if(RTPSENSOR_BUILD_NUMBER != string("local_build")) {
		rslt += string("(b") + RTPSENSOR_BUILD_NUMBER + ")";
	}
	return(rslt);
}


#endif //VOIPMONITOR_H
