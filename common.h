#ifndef COMMON_H
#define COMMON_H

struct sVerbose {
	int process_rtp;
	int read_rtp;
	int check_is_caller_called;
	int disable_threads_rtp;
	int packet_lost;
	int rrd_info;
	int http;
	int webrtc;
	int ssl;
	int sip_packets;
	int set_ua;
	int dscp;
	int store_process_query;
	int call_listening;
	int skinny;
	int fraud;
	int disable_bt_sighandler;
	int tcp_debug_port;
	int test_rtp_performance;
	int tar;
	int chunk_buffer;
	unsigned long int ssrc;
	int jitter;
	int noaudiounlink;
	int capture_filter;
};

#endif
