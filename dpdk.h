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
};

struct sDpdkCallback {
	void *packet_user;
	sDpdkHeaderPacket *header_packet;
	u_char* (*packet_allocation)(void *user, u_int32_t caplen);
	void (*packet_completion)(void *user, pcap_pkthdr *pcap_header, u_char *packet);
	bool (*packet_completion_plus)(void *user, pcap_pkthdr *pcap_header, u_char *packet, void *pcap_header_plus2,
				       void *checkProtocolData);
	void (*packet_process)(void *user, u_int32_t caplen);
	void (*packets_get_pointers)(void *user, u_int32_t start, u_int32_t max, u_int32_t *pkts_len, u_int32_t snaplen,
				     void **headers, void **packets, u_int32_t *count, bool *filled);
	void (*packets_push)(void *user);
	void (*packet_process__mbufs_in_packetbuffer)(void *user, pcap_pkthdr *pcap_header, void *mbuf);
	void (*check_block)(void *user, unsigned pos, unsigned count);
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
void dpdk_check_params();
u_int16_t count_rte_read_threads();
double rte_read_thread_cpu_usage(sDpdk *dpdk, u_int16_t rte_read_thread_id);
double rte_worker_thread_cpu_usage(sDpdk *dpdk);
double rte_worker_slave_thread_cpu_usage(sDpdk *dpdk);
double rte_worker2_thread_cpu_usage(sDpdk *dpdk);
string get_dpdk_cpu_cores(bool without_main, bool detect_ht);

u_char *dpdk_mbuf_to_packet(void *mbuf);
void dpdk_mbuf_free(void *mbuf);
void dpdk_memcpy(void *dst, void *src, size_t size);

void dpdk_check_configuration();
void dpdk_check_affinity();

void init_dpdk();
void term_dpdk();


class cGlobalDpdkTools {
public:
	static void getPlannedMemoryConsumptionByNumaNodes(map<unsigned, unsigned> *pmc);
	static void getCountInterfacesByNumaNodes(map<unsigned, unsigned> *ci);
	static void getPorts(vector<string> *ports);
	static bool setHugePages();
	static bool setThreadsAffinity(string *read, string *worker, string *worker2);
	static bool setThreadsAffinity();
	static void getThreadsAffinity(string *read, string *worker, string *worker2);
	static void clearThreadsAffinity();
private:
	static unsigned get_planned_memory_consumption_mb(string *log = NULL);
private:
	static string dpdk_read_thread_lcore;
	static string dpdk_worker_thread_lcore;
	static string dpdk_worker2_thread_lcore;
};


#endif //DPDK_H
