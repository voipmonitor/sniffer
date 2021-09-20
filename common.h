#ifndef COMMON_H
#define COMMON_H


#include "tools_define.h"

#include <sys/types.h>


struct sVerbose {
	int graph;
	int process_rtp;
	int read_rtp;
	int hash_rtp;
	int rtp_set_base_seq;
	int rtp_streams;
	int forcemark;
	int wavmix;
	int check_is_caller_called;
	int disable_threads_rtp;
	int packet_lost;
	int rrd_info;
	int http;
	int webrtc;
	int ssl;
	int tls;
	int ssl_sessionkey;
	int sip;
	char *tcpreassembly_debug_file;
	int ssldecode;
	int ssldecode_debug;
	int sip_packets;
	int set_ua;
	int dscp;
	int store_process_query;
	int store_process_query_compl;
	int store_process_query_compl_time;
	int call_listening;
	int skinny;
	int fraud;
	int fraud_file_log;
	int enable_bt_sighandler;
	int tcp_debug_port;
	u_char tcp_debug_ip[20];
	int tar;
	int chunk_buffer;
	unsigned long int ssrc;
	int jitter;
	int noaudiounlink;
	int capture_filter;
	int pcap_stat_period;
	int pcap_stat_to_stdout;
	int memory_stat;
	int memory_stat_log;
	int memory_stat_ignore_limit;
	int qring_stat;
	int qring_full;
	int alloc_stat;
	int qfiles;
	int query_error;
	char query_error_log[100];
	char query_regex[100];
	int new_invite;
	int dump_sip;
	int dump_sip_line;
	int dump_sip_without_counter;
	int reverse_invite;
	int mgcp;
	int mgcp_sdp;
	int manager;
	int scanpcapdir;
	int debug_rtcp;
	int defrag;
	int defrag_overflow;
	int dedup;
	int reassembly_sip;
	int reassembly_sip_output;
	int log_manager_cmd;
	int rtp_extend_stat;
	int process_rtp_header;
	int disable_process_packet_in_packetbuffer;
	int disable_push_to_t2_in_packetbuffer;
	int disable_save_packet;
	int disable_save_graph;
	int disable_save_call;
	int disable_save_message;
	int disable_save_register;
	int disable_save_sip_msg;
	int disable_read_rtp;
	int thread_create;
	int timezones;
	int tcpreplay;
	int abort_if_heap_full;
	int heap_use_time;
	int dtmf;
	int dtls;
	int cleanspool;
	int cleanspool_disable_rm;
	int t2_destroy_all;
	int log_profiler;
	int dump_packets_via_wireshark;
	int force_log_sqlq;
	int dump_call_flags;
	int log_srtp_callid;
	int send_call_info;
	int disable_cb_cache;
	int system_command;
	int malloc_trim;
	int socket_decode;
	int disable_load_codebooks;
	int multiple_store;
	int disable_store_rtp_stat;
	int disable_billing;
	int disable_custom_headers;
	int disable_cloudshare;
	int screen_popup;
	int screen_popup_syslog;
	int cleanup_calls;
	int usleep_stats;
	int charts_cache_only;
	int charts_cache_filters_eval;
	int charts_cache_filters_eval_rslt;
	int charts_cache_filters_eval_rslt_true;
	char sipcallerip_filter[100];
	char sipcalledip_filter[100];
	int suppress_cdr_insert;
	int suppress_server_store;
	int suppress_fork;
	char *trace_call;
	int energylevels;
	int _debug1;
	int _debug2;
	int _debug3;
};


#if defined __x86_64__ && !defined __ILP32__
#define int_64_format_prefix ""
#else
#define int_64_format_prefix "l"
#endif


#endif
