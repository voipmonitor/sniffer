#ifndef COMMON_H
#define COMMON_H

struct sVerbose {
	int graph;
	int process_rtp;
	int read_rtp;
	int rtp_set_base_seq;
	int check_is_caller_called;
	int disable_threads_rtp;
	int packet_lost;
	int rrd_info;
	int http;
	int webrtc;
	int ssl;
	int ssldecode;
	int ssldecode_debug;
	int sip_packets;
	int set_ua;
	int dscp;
	int store_process_query;
	int call_listening;
	int skinny;
	int fraud;
	int enable_bt_sighandler;
	int tcp_debug_port;
	int test_rtp_performance;
	int tar;
	int chunk_buffer;
	unsigned long int ssrc;
	int jitter;
	int noaudiounlink;
	int capture_filter;
	int pcap_stat_period;
	int memory_stat;
	int memory_stat_log;
	int memory_stat_ignore_limit;
	int qring_stat;
	int qfiles;
	int query_error;
	int dump_sip;
	int manager;
	int scanpcapdir;
	int debug_rtcp;
	int defrag;
	int dedup;
	int reassembly_sip;
	int reassembly_sip_output;
	int log_manager_cmd;
	int rtp_extend_stat;
	int disable_process_packet_in_packetbuffer;
	int thread_create;
	int timezones;
	int tcpreplay;
};

#endif
