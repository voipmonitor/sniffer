#ifndef DPDK_H
#define DPDK_H


#include <pcap.h>
#include <string>
#include <string.h>


enum eDpdkTypeReadThread {
	_dpdk_trt_std = 1,
	_dpdk_trt_rte
};

enum eDpdkTypeWorkerThread {
	_dpdk_twt_na,
	_dpdk_twt_std,
	_dpdk_twt_rte
};

enum eDpdkTypeWorker2Thread {
	_dpdk_tw2t_na,
	_dpdk_tw2t_rte
};

enum eDpdkTypeUsleep {
	_dpdk_usleep_type_std,
	_dpdk_usleep_type_rte,
	_dpdk_usleep_type_rte_pause
};

struct sDpdkHeaderPacket {
	pcap_pkthdr header;
	u_char *packet;
	u_int32_t packet_maxlen;
};

struct sDpdkCallback {
	void *packet_user;
	sDpdkHeaderPacket *header_packet;
	u_char* (*packet_allocation)(void *user, u_int32_t *packet_maxlen);
	void (*packet_completion)(void *user, pcap_pkthdr *pcap_header, u_char *packet);
	void (*packet_process)(void *user);
	void (*packet_process__mbufs_in_packetbuffer)(void *user, pcap_pkthdr *pcap_header, void *mbuf);
};

struct sDpdkConfig {
	char device[100];
	int snapshot;
	int promisc;
	eDpdkTypeReadThread type_read_thread;
	eDpdkTypeWorkerThread type_worker_thread;
	eDpdkTypeWorker2Thread type_worker2_thread;
	int iterations_per_call;
	int read_usleep_if_no_packet;
	eDpdkTypeUsleep read_usleep_type;
	int worker_usleep_if_no_packet;
	eDpdkTypeUsleep worker_usleep_type;
	sDpdkCallback callback;
	bool init_in_activate;
	sDpdkConfig() {
		memset(this, 0, sizeof(*this));
	}
};

typedef struct sDpdk sDpdkHandle;


sDpdkHandle *create_dpdk_handle();
void destroy_dpdk_handle(sDpdkHandle *dpdk);
int dpdk_activate(sDpdkConfig *config, sDpdk *dpdk, std::string *error);
int dpdk_do_pre_init(std::string *error);
void dpdk_set_initialized(sDpdkHandle *dpdk);
void dpdk_reset_statistics(sDpdkHandle *dpdk, bool flush_buffer);
int dpdk_read_proc(sDpdk *dpdk);
int dpdk_worker_proc(sDpdk *dpdk);
int pcap_dpdk_stats(sDpdk *dpdk, pcap_stat *ps, string *str_out = NULL);
sDpdkConfig *dpdk_config(sDpdk *dpdk);
void dpdk_terminating(sDpdk *dpdk);
double rte_read_thread_cpu_usage(sDpdk *dpdk);
double rte_worker_thread_cpu_usage(sDpdk *dpdk);
double rte_worker2_thread_cpu_usage(sDpdk *dpdk);
string get_dpdk_cpu_cores(bool without_main);

u_char *dpdk_mbuf_to_packet(void *mbuf);
void dpdk_mbuf_free(void *mbuf);
void dpdk_memcpy(void *dst, void *src, size_t size);


#endif //DPDK_H
