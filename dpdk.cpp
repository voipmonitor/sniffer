#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/resource.h>
#include <string.h>

#include "pstat.h"
#include "tools.h"
#include "tools_global.h"
#include "sync.h"
#include "pcap_queue.h"
#include "voipmonitor_define.h"

#include "dpdk.h"


#if HAVE_LIBDPDK

#define ALLOW_EXPERIMENTAL_API 1

#include <rte_config.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_bus.h>
#include <rte_spinlock.h>

#if HAVE_LIBDPDK_VDEV
#include <rte_bus_vdev.h>
#endif


extern string opt_dpdk_cpu_cores;
extern string opt_dpdk_cpu_cores_map;
extern int opt_dpdk_main_thread_lcore;
extern string opt_dpdk_read_thread_lcore;
extern string opt_dpdk_worker_thread_lcore;
extern string opt_dpdk_worker2_thread_lcore;
extern bool opt_dpdk_worker_slave_thread;
extern int opt_dpdk_memory_channels;
extern string opt_dpdk_pci_device;
extern int opt_dpdk_force_max_simd_bitwidth;
extern int opt_dpdk_nb_mbufs;
extern bool opt_dpdk_nb_mbufs_strictly;
extern int opt_dpdk_mbuf_size;
extern int opt_dpdk_pkt_burst;
extern int opt_dpdk_ring_size;
extern int opt_dpdk_mempool_cache_size;
extern int opt_dpdk_batch_read;
extern int opt_dpdk_copy_packetbuffer;
extern int opt_dpdk_mbufs_in_packetbuffer;
extern int opt_dpdk_timer_reset_interval;
extern int opt_dpdk_mtu;
extern vector<string> opt_dpdk_vdev;
extern bool opt_dpdk_ignore_ierrors;
extern cThreadMonitor threadMonitor;


#define MAXIMUM_SNAPLEN		262144

#define DPDK_ARGC_MAX 64
#define DPDK_DEF_LOG_LEV RTE_LOG_ERR
#define DPDK_LIB_NAME ((char*)"vm_dpdk")
#if DPDK_ENV_CFG
#define DPDK_CFG_ENV_NAME "DPDK_CFG"
#define DPDK_DEF_CFG "--log-level=error -l0 -dlibrte_pmd_e1000.so -dlibrte_pmd_ixgbe.so -dlibrte_mempool_ring.so"
#define DPDK_CFG_MAX_LEN 1024
#endif
#define DPDK_PORTID_MAX (64 * 1024U - 1)
#define DPDK_NB_MBUFS ((opt_dpdk_nb_mbufs ? opt_dpdk_nb_mbufs : 1024) * (opt_dpdk_nb_mbufs_strictly ? 1 : 1024))
#define DPDK_MBUF_SIZE (opt_dpdk_mbuf_size ? opt_dpdk_mbuf_size : RTE_MBUF_DEFAULT_BUF_SIZE)
#define DPDK_DEF_MAC_ADDR "00:00:00:00:00:00"
#define DPDK_TX_BUF_NAME "tx_buffer"
#define DPDK_PREFIX "dpdk:"
#define DPDK_MAC_ADDR_SIZE 32
#define DPDK_PCI_ADDR_SIZE 16

#define MAX_PKT_BURST (opt_dpdk_pkt_burst ? opt_dpdk_pkt_burst : 32)

#define RING_SIZE (opt_dpdk_ring_size ? opt_dpdk_ring_size * 1024 : DPDK_NB_MBUFS)

#define MBUF_POOL_NAME "mbuf_pool"
#define MEMPOOL_CACHE_SIZE (opt_dpdk_mempool_cache_size ? opt_dpdk_mempool_cache_size : 512)

#define DPDK_ERR_PERM_MSG "permission denied, DPDK needs root permission"


// #ifdef HAVE_STRUCT_RTE_ETHER_ADDR
#define ETHER_ADDR_TYPE	struct rte_ether_addr
// #else
// #define ETHER_ADDR_TYPE	struct ether_addr
// #endif

#define DPDK_ENV_CFG 0
#define DPDK_TIMESTAMP_IN_MBUF 1
#define DPDK_WAIT_FOR_EMPTY_RING_IF_FULL 1
#define WORKER2_THREAD_SUPPORT 0
#define DPDK_ZC_SUPPORT 0

#define DPDK_MAX_COUNT_RTE_READ_THREADS 16

#define DEBUG_CYCLES false
#define DEBUG_CYCLES_MAX_LT_MS 100
#define DEBUG_EXT_STAT false

#define ENABLE_WORKER_SLAVE (opt_dpdk_worker_slave_thread && !opt_dpdk_mbufs_in_packetbuffer)
#define NEED_INIT_PB_BLOCK (ENABLE_WORKER_SLAVE && !opt_dpdk_copy_packetbuffer)

#define MIN(a,b) (((a)<(b))?(a):(b))


#if TEST_RTE_READ_MULTI_THREADS
volatile int rte_read_sync;
#endif


#if DEBUG_CYCLES
struct sDpdk_cycles {
	u_int64_t count;
	u_int64_t sum;
	u_int64_t min;
	u_int64_t max;
	u_int64_t begin;
	u_int64_t end;
	bool reset;
	inline void setBegin() {
		if(reset) {
			memset(this, 0, sizeof(*this));
			reset = false;
		}
		begin = rte_get_timer_cycles();
	}
	inline void setEnd() {
		end = rte_get_timer_cycles();
		u_int64_t diff = end - begin;
		++count;
		sum += diff;
		if(!min || diff < min) min = diff;
		if(diff > max) max = diff;
	}
};
#endif

struct dpdk_ts_helper{
	volatile uint64_t start_time;
	volatile uint64_t start_cycles;
	volatile uint64_t hz;
};

class cDpdkTools {
public:
	enum eTypeLcore {
		_tlc_read,
		_tlc_worker,
		_tlc_worker2
	};
public:
	cDpdkTools();
	void init();
	void setLCoresMap();
	int getFreeLcore(eTypeLcore type, int numa_node);
	void setUseLcore(int lcore);
	void setFreeLcore(int lcore);
	string getAllCores(bool without_main, bool detect_ht);
	string getCoresMap();
	int getMainThreadLcore();
	void getCoresForLcore(int lcore, list<int> *cores);
	string getCoresForLcore(int lcore);
private:
	int getFreeLcore(map<int, bool> &main_map, int numa_node);
	bool lcoreIsUsed(int lcore);
	bool lcoreIsInAny(int lcore);
private:
	int main_thread_lcore;
	map<int, bool> read_lcores;
	map<int, bool> worker_lcores;
	map<int, bool> worker2_lcores;
	map<int, bool> used_lcores;
	string lcores_map_str;
	map<int, list<int> > lcores_map;
	volatile int _sync_lcore;
};

struct sDpdk {
	uint16_t portid;
	bool portid_set;
	int must_clear_promisc;
	rte_mempool *pktmbuf_pool;
	rte_ring *rx_to_worker_ring;
	#if WORKER2_THREAD_SUPPORT
	rte_ring *worker_to_worker2_ring;
	#endif
	u_int64_t prev_ts_us;
	u_int64_t curr_ts_us;
	rte_eth_stats prev_stats;
	rte_eth_stats curr_stats;
	dpdk_ts_helper ts_helper;
	rte_spinlock_t ts_helper_lock;
	ETHER_ADDR_TYPE eth_addr;
	char mac_addr[DPDK_MAC_ADDR_SIZE];
	char pci_addr[DPDK_PCI_ADDR_SIZE];
	sDpdkConfig config;
	uint64_t pps;
	uint64_t bps;
	uint64_t bpf_drop;
	uint64_t ring_full_drop;
	#if WORKER2_THREAD_SUPPORT
	uint64_t ring2_full_drop;
	#endif
	bool terminating;
	int rte_read_thread_pid[DPDK_MAX_COUNT_RTE_READ_THREADS];
	int rte_worker_thread_pid;
	int rte_worker_slave_thread_pid;
	#if WORKER2_THREAD_SUPPORT
	int rte_worker2_thread_pid;
	#endif
	pstat_data rte_read_thread_pstat_data[DPDK_MAX_COUNT_RTE_READ_THREADS][2];
	pstat_data rte_worker_thread_pstat_data[2];
	pstat_data rte_worker_slave_thread_pstat_data[2];
	#if WORKER2_THREAD_SUPPORT
	pstat_data rte_worker2_thread_pstat_data[2];
	#endif
	volatile bool initialized;
	#if DEBUG_CYCLES
	sDpdk_cycles cycles[10];
	#endif
	bool cycles_reset;
	rte_mbuf **pkts_burst;
	u_int32_t *pkts_len;
	void **pb_headers;
	void **pb_packets;
	volatile u_int32_t batch_start;
	volatile u_int32_t batch_count;
	volatile int worker_slave_state;
	u_int64_t timestamp_us;
	#if LOG_PACKETS_SUM
	u_int64_t count_packets[2];
	#endif
	u_int64_t last_stat_ipackets;
	u_int64_t last_stat_ierrors;
	u_int64_t last_stat_imissed;
	u_int64_t last_stat_nombuf;
	u_int64_t last_stat_cout_packets[2];
	u_int64_t last_stat_ring_full_drop;
	u_int64_t last_stat_ring2_full_drop;
	sDpdk() {
		memset((void*)this, 0, sizeof(*this));
	}
	void worker_alloc() {
		pkts_burst = new FILE_LINE(0) rte_mbuf*[MAX_PKT_BURST];
		if(ENABLE_WORKER_SLAVE) {
			if(!pkts_len) {
				pkts_len = new FILE_LINE(0) u_int32_t[MAX_PKT_BURST];
			}
			if(!pb_headers) {
				pb_headers = new FILE_LINE(0) void*[MAX_PKT_BURST];
			}
			if(!pb_packets) {
				pb_packets = new FILE_LINE(0) void*[MAX_PKT_BURST];
			}
		}
	}
	void worker_free() {
		if(pkts_len) {
			delete [] pkts_len;
		}
		if(pb_headers) {
			delete [] pb_headers;
		}
		if(pb_packets) {
			delete [] pb_packets;
		}
		delete [] pkts_burst;
	}
};

struct sRteReadThreadArg {
	sDpdk *dpdk;
	int read_thread_id;
	int rxq;
};


static int rte_read_thread(void *arg);
static int rte_worker_thread(void *arg);
static int rte_worker_slave_thread(void *arg);
#if WORKER2_THREAD_SUPPORT
static int rte_worker2_thread(void *arg);
#endif
static inline void dpdk_process_packet(sDpdk *dpdk, rte_mbuf *mbuff, u_int64_t timestamp_us);
static inline void dpdk_process_packet_2__std(sDpdk *dpdk, rte_mbuf *mbuff, u_int64_t timestamp_us
					      #if WORKER2_THREAD_SUPPORT
					      ,bool free_mbuff
					      #endif
					      );
static inline void dpdk_process_packet_2__std_2(sDpdk *dpdk, rte_mbuf *mbuff, u_int64_t timestamp_us
						#if WORKER2_THREAD_SUPPORT
						,bool free_mbuff
						#endif
						);
static inline void dpdk_process_packet_2__mbufs_in_packetbuffer(sDpdk *dpdk, rte_mbuf *mbuff, u_int64_t timestamp_us
								#if WORKER2_THREAD_SUPPORT
								,bool free_mbuff
								#endif
								);
static inline void dpdk_copy_data(unsigned char *data, uint32_t maxlen, struct rte_mbuf *mbuf);
static inline uint32_t dpdk_gather_data(unsigned char *data, uint32_t maxlen, struct rte_mbuf *mbuf);
static inline u_int32_t get_len(rte_mbuf *mbuf);
static inline u_int32_t get_caplen(u_int32_t len, sDpdk *dpdk);
static inline u_int64_t get_timestamp_us(sDpdk *dpdk);
static int dpdk_pre_init(string *error_str);
static uint16_t portid_by_device(const char * device);
#if DPDK_ENV_CFG
static int parse_dpdk_cfg(char* dpdk_cfg,char** dargv);
#endif
static void dpdk_eval_res(int res_no, const char *cust_error, int syslog_print, string *error_str, const char *fmt, ...);
static int dpdk_init_timer(sDpdk *dpdk, bool use_lock);
static void eth_addr_str(ETHER_ADDR_TYPE *addrp, char* mac_str, int len);
static int check_link_status(uint16_t portid, struct rte_eth_link *plink);


static int is_dpdk_pre_inited = 0;
#if DPDK_ENV_CFG
static char dpdk_cfg_buf[DPDK_CFG_MAX_LEN];
#endif

static rte_eth_conf port_conf;

#if DPDK_TIMESTAMP_IN_MBUF == 1
static rte_mbuf_dynfield timestamp_dynfield_desc;
static int timestamp_dynfield_offset = -1;
#endif

static cDpdkTools *dpdk_tools;


sDpdkHandle *create_dpdk_handle() {
	return(new sDpdk);
}


void destroy_dpdk_handle(sDpdkHandle *dpdk) {
	if(dpdk->portid_set) {
		if(dpdk->must_clear_promisc) {
			rte_eth_promiscuous_disable(dpdk->portid);
		}
		rte_eth_dev_stop(dpdk->portid);
		rte_eth_dev_close(dpdk->portid);
	}
	delete dpdk;
}


int dpdk_activate(sDpdkConfig *config, sDpdk *dpdk, std::string *error) {
	int ret = PCAP_ERROR;
	uint16_t nb_ports = 0;
	uint16_t portid = DPDK_PORTID_MAX;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	port_conf.rxmode.offloads = 0;
	// port_conf.rxmode.split_hdr_size = 0; // obsolete
	port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
	port_conf.txmode.offloads = 0;
	struct rte_eth_conf local_port_conf = port_conf;
	struct rte_eth_dev_info dev_info;
	int is_port_up = 0;
	struct rte_eth_link link;
	
	//init EAL; fail if we have insufficient permission
	int is_dpdk_pre_inited_old = is_dpdk_pre_inited;
	ret = dpdk_pre_init(error);
	if(ret > 0 && is_dpdk_pre_inited_old <= 0 && is_dpdk_pre_inited > 0) {
		config->init_in_activate = true;
	} else if(ret < 0) {
		return(PCAP_ERROR);
	} else if(ret == 0) {
		*error = "DPDK is not available on this machine";
		return(PCAP_ERROR_NO_SUCH_DEVICE);
	}
	ret = dpdk_init_timer(dpdk, true);
	dpdk_eval_res(ret, NULL, 2, error,
		      "dpdk_activate(%s) - dpdk_init_timer",
		      config->device);
	if(ret < 0) {
		return(PCAP_ERROR);
	}
	nb_ports = rte_eth_dev_count_avail();
	if(nb_ports == 0) {
		dpdk_eval_res(0, "no ethernet ports", 2, error,
			      "dpdk_activate(%s) - rte_eth_dev_count_avail",
			      config->device);
		return(PCAP_ERROR);
	}
	if(opt_dpdk_vdev.size()) {
		ret = rte_eth_dev_get_port_by_name(config->device, &portid);
		dpdk_eval_res(ret, NULL, 2, error,
			      "dpdk_activate(%s) - rte_eth_dev_get_port_by_name(%s)",
			      config->device,
			      config->device);
	} else {
		ret = -1;
	}
	if(ret < 0) {
		portid = portid_by_device(config->device);
		if(portid == DPDK_PORTID_MAX) {
			dpdk_eval_res(0, "portid is invalid", 2, error,
				      "dpdk_activate(%s) - portid_by_device(%s)",
				      config->device,
				      config->device);
			return(PCAP_ERROR_NO_SUCH_DEVICE);
		}
	}
	int numa_node = rte_eth_dev_socket_id(portid);
	dpdk_eval_res(numa_node < 0 ? -rte_errno : 0, NULL, 2, error,
		      "dpdk_activate(%s) - rte_eth_dev_socket_id(%i) - rslt (numa_node): %i",
		      config->device,
		      portid,
		      numa_node);
	dpdk->portid = portid;
	dpdk->portid_set = true;
	if(config->snapshot <= 0 || config->snapshot > MAXIMUM_SNAPLEN) {
		config->snapshot = MAXIMUM_SNAPLEN;
	}
	// create the mbuf pool
	dpdk->pktmbuf_pool = rte_pktmbuf_pool_create((string(MBUF_POOL_NAME) + "_" + config->device).c_str(), DPDK_NB_MBUFS,
						     MEMPOOL_CACHE_SIZE, 0, DPDK_MBUF_SIZE,
						     rte_socket_id());
	dpdk_eval_res(dpdk->pktmbuf_pool == NULL ? -rte_errno : 0, dpdk->pktmbuf_pool == NULL && !rte_errno ? "failed allocation mbuf pool" : NULL, 2, error,
		      "dpdk_activate(%s) - rte_pktmbuf_pool_create",
		      config->device);
	if(dpdk->pktmbuf_pool == NULL) {
		return(PCAP_ERROR);
	}
	// config dev
	ret = rte_eth_dev_info_get(portid, &dev_info);
	dpdk_eval_res(ret, NULL, 2, error,
		      "dpdk_activate(%s) - rte_eth_dev_info_get(%i)",
		      config->device,
		      portid);
	if(ret < 0) {
		return(PCAP_ERROR);
	}
	if(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
		local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
	}
	extern int opt_dpdk_nb_rxq;
	extern bool opt_dpdk_nb_rxq_rss;
	uint16_t nb_rxq = opt_dpdk_nb_rxq > 0 ? opt_dpdk_nb_rxq : 1;
	if(nb_rxq > 1) {
		if(opt_dpdk_nb_rxq_rss) {
			local_port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
			local_port_conf.rx_adv_conf.rss_conf.rss_hf = dev_info.flow_type_rss_offloads & (RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP);
		}
	}
	ret = rte_eth_dev_configure(portid, nb_rxq, 1, &local_port_conf);
	dpdk_eval_res(ret, NULL, 2, error,
		      "dpdk_activate(%s) - rte_eth_dev_configure(portid:%i, nb_rxq:%i, nb_txq:%i)",
		      config->device,
		      portid, nb_rxq, 1);
	if(ret < 0) {
		return(PCAP_ERROR);
	}
	// adjust rx tx
	extern int opt_dpdk_nb_rx;
	extern int opt_dpdk_nb_tx;
	uint16_t nb_rx = opt_dpdk_nb_rx;
	uint16_t nb_tx = opt_dpdk_nb_tx;
	ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rx, &nb_tx);
	dpdk_eval_res(ret, NULL, 2, error,
		      "dpdk_activate(%s) - rte_eth_dev_adjust_nb_rx_tx_desc(%i)",
		      config->device,
		      portid);
	if(ret < 0) {
		return(PCAP_ERROR);
	}
	// get MAC addr
	rte_eth_macaddr_get(portid, &(dpdk->eth_addr));
	eth_addr_str(&(dpdk->eth_addr), dpdk->mac_addr, DPDK_MAC_ADDR_SIZE-1);
	// init RX queues
	for(uint16_t q = 0; q < nb_rxq; q++) {
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		rxq_conf.rx_free_thresh = MAX_PKT_BURST;
		ret = rte_eth_rx_queue_setup(portid, q, nb_rx,
					     rte_eth_dev_socket_id(portid),
					     &rxq_conf,
					     dpdk->pktmbuf_pool);
		dpdk_eval_res(ret, NULL, 2, error,
			      "dpdk_activate(%s) - rte_eth_rx_queue_setup(queue:%i, nb_rx: %i)",
			      config->device, q, nb_rx);
		if(ret < 0) {
			return(PCAP_ERROR);
		}
	}
	// init one TX queue
	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = local_port_conf.txmode.offloads;
	ret = rte_eth_tx_queue_setup(portid, 0, nb_tx,
				     rte_eth_dev_socket_id(portid),
				     &txq_conf);
	dpdk_eval_res(ret, NULL, 2, error,
		      "dpdk_activate(%s) - rte_eth_tx_queue_setup(%i)",
		      config->device,
		      portid);
	if(ret < 0) {
		return(PCAP_ERROR);
	}
	// Initialize TX buffers
	rte_eth_dev_tx_buffer *tx_buffer;
	tx_buffer = (rte_eth_dev_tx_buffer*)rte_zmalloc_socket(DPDK_TX_BUF_NAME,
							       RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
							       rte_eth_dev_socket_id(portid));
	dpdk_eval_res(tx_buffer == NULL ? -rte_errno : 0, NULL, 2, error,
		      "dpdk_activate(%s) - rte_zmalloc_socket",
		      config->device);
	if(tx_buffer == NULL) {
		return(PCAP_ERROR);
	}
	ret = rte_eth_tx_buffer_init(tx_buffer, MAX_PKT_BURST);
	dpdk_eval_res(ret, NULL, 2, error,
		      "dpdk_activate(%s) - rte_eth_tx_buffer_init",
		      config->device);
	if(ret < 0) {
		return(PCAP_ERROR);
	}
	if(config->type_worker_thread != _dpdk_twt_na) {
		dpdk->rx_to_worker_ring = rte_ring_create((string("rx_to_worker") + "_" + config->device).c_str(), RING_SIZE, rte_socket_id(), 
							  count_rte_read_threads() > 1 ? RING_F_MP_RTS_ENQ | RING_F_SC_DEQ : RING_F_SP_ENQ | RING_F_SC_DEQ);
		dpdk_eval_res(dpdk->rx_to_worker_ring == NULL ? -rte_errno : 0, NULL, 2, error,
			      "dpdk_activate(%s) - rte_ring_create(rx_to_worker)",
			      config->device);
		if(dpdk->rx_to_worker_ring == NULL) {
			return(PCAP_ERROR);
		}
	}
	#if WORKER2_THREAD_SUPPORT
	if(config->type_worker_thread == _dpdk_twt_rte && config->type_worker2_thread == _dpdk_tw2t_rte) {
		dpdk->worker_to_worker2_ring = rte_ring_create((string("worker_to_worker2") + "_" + config->device).c_str(), RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		dpdk_eval_res(dpdk->worker_to_worker2_ring == NULL ? -rte_errno : 0, NULL, 2, error,
			      "dpdk_activate(%s) - rte_ring_create(worker_to_worker2)",
			      config->device);
		if(dpdk->rx_to_worker_ring == NULL) {
			return(PCAP_ERROR);
		}
	}
	#endif
	dpdk->config = *config;
	if(config->type_worker_thread == _dpdk_twt_rte) {
		int lcore_id = dpdk_tools->getFreeLcore(cDpdkTools::_tlc_worker, numa_node);
		dpdk_eval_res(lcore_id, lcore_id < 0 ? "not available free lcore for worker thread" : NULL, 2, error,
			      "dpdk_activate(%s) - getFreeLcore(cDpdkTools::_tlc_worker)",
			      config->device);
		if(lcore_id < 0) {
			return(PCAP_ERROR);
		} else {
			ret = rte_eal_remote_launch(rte_worker_thread, dpdk, lcore_id);
			string cores_info;
			if(ret >= 0) {
				cores_info = dpdk_tools->getCoresForLcore(lcore_id);
				if(!cores_info.empty()) {
					cores_info = "/" + cores_info;
				}
			}
			dpdk_eval_res(ret, NULL, 2, error,
				      "dpdk_activate(%s) - rte_eal_remote_launch(%i%s) / worker",
				      config->device,
				      lcore_id,
				      cores_info.c_str());
			if(ret < 0) {
				return(PCAP_ERROR);
			}
			dpdk_tools->setUseLcore(lcore_id);
		}
	}
	if(config->type_worker_thread == _dpdk_twt_rte &&
	   ENABLE_WORKER_SLAVE) {
		int lcore_id = dpdk_tools->getFreeLcore(cDpdkTools::_tlc_worker, numa_node);
		dpdk_eval_res(lcore_id, lcore_id < 0 ? "not available free lcore for worker slave thread" : NULL, 2, error,
			      "dpdk_activate(%s) - getFreeLcore(cDpdkTools::_tlc_worker)",
			      config->device);
		if(lcore_id < 0) {
			return(PCAP_ERROR);
		} else {
			ret = rte_eal_remote_launch(rte_worker_slave_thread, dpdk, lcore_id);
			string cores_info;
			if(ret >= 0) {
				cores_info = dpdk_tools->getCoresForLcore(lcore_id);
				if(!cores_info.empty()) {
					cores_info = "/" + cores_info;
				}
			}
			dpdk_eval_res(ret, NULL, 2, error,
				      "dpdk_activate(%s) - rte_eal_remote_launch(%i%s) / worker slave",
				      config->device,
				      lcore_id,
				      cores_info.c_str());
			if(ret < 0) {
				return(PCAP_ERROR);
			}
			dpdk_tools->setUseLcore(lcore_id);
		}
	}
	#if WORKER2_THREAD_SUPPORT
	if(config->type_worker2_thread == _dpdk_tw2t_rte) {
		int lcore_id = dpdk->tools->getFreeLcore(cDpdkTools::_tlc_worker2, numa_node);
		dpdk_eval_res(lcore_id, lcore_id < 0 ? "not available free lcore for worker2 thread" : NULL, 2, error,
			      "dpdk_activate(%s) - getFreeLcore(cDpdkTools::_tlc_worker2)",
			      config->device);
		if(lcore_id < 0) {
			return(PCAP_ERROR);
		} else {
			ret = rte_eal_remote_launch(rte_worker2_thread, dpdk, lcore_id);
			string cores_info;
			if(ret >= 0) {
				cores_info = dpdk_tools->getCoresForLcore(lcore_id);
				if(!cores_info.empty()) {
					cores_info = "/" + cores_info;
				}
			}
			dpdk_eval_res(ret, NULL, 2, error,
				      "dpdk_activate(%s) - rte_eal_remote_launch(%i%s) / worker 2",
				      config->device,
				      lcore_id,
				      cores_info.c_str());
			if(ret < 0) {
				return(PCAP_ERROR);
			}
			dpdk->tools->setUseLcore(lcore_id);
		}
	}
	#endif
	if(config->type_read_thread == _dpdk_trt_rte) {
		u_int16_t nb_rte_read_threads = count_rte_read_threads();
		for(uint16_t rte_read_thread_id = 0; rte_read_thread_id < nb_rte_read_threads; rte_read_thread_id++) {
			int lcore_id = dpdk_tools->getFreeLcore(cDpdkTools::_tlc_read, numa_node);
			dpdk_eval_res(lcore_id, lcore_id < 0 ? "not available free lcore for read thread" : NULL, 2, error,
				      "dpdk_activate(%s) - getFreeLcore(cDpdkTools::_tlc_read)",
				      config->device);
			if(lcore_id < 0) {
				return(PCAP_ERROR);
			}
			sRteReadThreadArg *arg = new FILE_LINE(0) sRteReadThreadArg;
			arg->dpdk = dpdk;
			arg->read_thread_id = rte_read_thread_id;
			arg->rxq = nb_rte_read_threads > 1 ? rte_read_thread_id : -1;
			#if TEST_RTE_READ_MULTI_THREADS
			arg->rxq = 0;
			#endif
			syslog(LOG_INFO, "DPDK: Launching read thread %d on lcore %d with rxq %d", 
				   rte_read_thread_id, lcore_id, arg->rxq);
			ret = rte_eal_remote_launch(rte_read_thread, arg, lcore_id);
			string cores_info;
			if(ret >= 0) {
				cores_info = dpdk_tools->getCoresForLcore(lcore_id);
				if(!cores_info.empty()) {
					cores_info = "/" + cores_info;
				}
			}
			dpdk_eval_res(ret, NULL, 2, error,
				      "dpdk_activate(%s) - rte_eal_remote_launch(%i%s) / read",
				      config->device,
				      lcore_id,
				      cores_info.c_str());
			if(ret < 0) {
				return(PCAP_ERROR);
			}
			dpdk_tools->setUseLcore(lcore_id);
		}
	}
	if(opt_dpdk_mtu) {
		ret = rte_eth_dev_set_mtu(portid, opt_dpdk_mtu);
		dpdk_eval_res(ret, NULL, 2, error,
			      "dpdk_activate(%s) - rte_eth_dev_set_mtu",
			      config->device);
		if(ret < 0) {
			return(PCAP_ERROR);
		}
	}
	// Start device
	ret = rte_eth_dev_start(portid);
	dpdk_eval_res(ret, NULL, 2, error,
		      "dpdk_activate(%s) - rte_eth_dev_start(%i)",
		      config->device,
		      portid);
	if(ret < 0) {
		return(PCAP_ERROR);
	}
	// set promiscuous mode
	if(config->promisc) {
		dpdk->must_clear_promisc=1;
		rte_eth_promiscuous_enable(portid);
	}
	// check link status
	for(int i = 0; i < (opt_dpdk_vdev.size() ? 2 : 1); i++) {
		if(i == 1) {
			if(opt_dpdk_vdev.size()) {
				ret = rte_eth_dev_set_link_up(portid);
				dpdk_eval_res(ret, NULL, 2, error,
					      "dpdk_activate(%s) - rte_eth_dev_set_link_up(%i)",
					      config->device,
					      portid);
			} else {
				break;
			}
		}
		is_port_up = check_link_status(portid, &link);
		dpdk_eval_res(is_port_up, is_port_up == 0 ? "link is down" : NULL, 2, error,
			      "dpdk_activate(%s) - check_link_status(%i)",
			      config->device,
			      portid);
		if(is_port_up) {
			break;
		}
	}
	if(!is_port_up) {
		return(PCAP_ERROR_IFACE_NOT_UP);
	}
	if(nb_rxq > 1 && opt_dpdk_nb_rxq_rss) {
		struct rte_eth_rss_conf rss_conf;
		memset(&rss_conf, 0, sizeof(rss_conf));
		ret = rte_eth_dev_rss_hash_conf_get(portid, &rss_conf);
		if(ret == 0) {
			syslog(LOG_INFO, "DPDK RSS: Active RSS hash functions after start: 0x%lx", (unsigned long)rss_conf.rss_hf);
			if(rss_conf.rss_hf == 0) {
				syslog(LOG_WARNING, "DPDK RSS: WARNING! RSS is not active despite configuration!");
			}
		} else {
			syslog(LOG_WARNING, "DPDK RSS: Failed to get RSS configuration: %d", ret);
		}
	}
	// reset statistics
	dpdk_reset_statistics(dpdk, true);
	/*
	// format pcap_t
	pd->portid = portid;
	p->fd = pd->portid;
	if(p->snapshot <=0 || p->snapshot> MAXIMUM_SNAPLEN)
	{
		p->snapshot = MAXIMUM_SNAPLEN;
	}
	p->linktype = DLT_EN10MB; // Ethernet, the 10MB is historical.
	p->selectable_fd = p->fd;
	p->read_op = pcap_dpdk_dispatch;
	p->inject_op = pcap_dpdk_inject;
	// using pcap_filter currently, though DPDK provides their own BPF function. Because DPDK BPF needs load a ELF file as a filter.
	p->setfilter_op = install_bpf_program;
	p->setdirection_op = NULL;
	p->set_datalink_op = NULL;
	p->getnonblock_op = pcap_dpdk_getnonblock;
	p->setnonblock_op = pcap_dpdk_setnonblock;
	p->stats_op = pcap_dpdk_stats;
	p->cleanup_op = pcap_dpdk_close;
	p->breakloop_op = pcap_breakloop_common;
	// set default timeout
	pd->required_select_timeout.tv_sec = 0;
	pd->required_select_timeout.tv_usec = DPDK_DEF_MIN_SLEEP_MS*1000;
	p->required_select_timeout = &pd->required_select_timeout;
	*/
	
	rte_eth_dev_get_name_by_port(portid,dpdk->pci_addr);
	syslog(LOG_INFO, "DPDK - Port %d device: %s, MAC:%s, PCI:%s\n", 
	       portid, config->device, dpdk->mac_addr, dpdk->pci_addr);
	syslog(LOG_INFO, "DPDK - Port %d Link Up. Speed %u Mbps - %s\n",
	       portid, link.link_speed,
	       (link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ? ("full-duplex") : ("half-duplex\n"));
	
	return(0);
}


int dpdk_do_pre_init(std::string *error) {
	return(dpdk_pre_init(error));
}


void dpdk_set_initialized(sDpdkHandle *dpdk) {
	dpdk->initialized = true;
}


void dpdk_reset_statistics(sDpdkHandle *dpdk, bool flush_buffer) {
	if(flush_buffer) {
		u_int16_t nb_rx;
		rte_mbuf *pkts_burst[MAX_PKT_BURST];
		while((nb_rx = rte_eth_rx_burst(dpdk->portid, 0, pkts_burst, MAX_PKT_BURST)) > 0) {
			for(u_int16_t i = 0; i < nb_rx; i++) {
				rte_pktmbuf_free(pkts_burst[i]);
			}
		}
	}
	rte_eth_stats_reset(dpdk->portid);
	dpdk->prev_ts_us = get_timestamp_us(dpdk);
	rte_eth_stats_get(dpdk->portid, &(dpdk->prev_stats));
}


int dpdk_read_proc(sDpdk *dpdk) {
	rte_mbuf *pkts_burst[MAX_PKT_BURST];
	u_int64_t timestamp_us;
	if(dpdk->rx_to_worker_ring) {
		#if 0
		while(true) {
			u_int16_t nb_rx = rte_eth_rx_burst(dpdk->portid, 0, pkts_burst, MAX_PKT_BURST);
			if(nb_rx > 0) {
				for(u_int16_t i = 0; i < nb_rx; i++) {
					rte_pktmbuf_free(pkts_burst[i]);
				}
				//printf(" * %i\n", nb_rx);
			}
		}
		return(0);
		#else
		int nb_rx_sum = 0;
		for(int i = 0; i < dpdk->config.iterations_per_call; i++) {
			int nb_rx = (int)rte_eth_rx_burst(dpdk->portid, 0, pkts_burst, MAX_PKT_BURST);
			if(likely(nb_rx)) {
				#if DPDK_TIMESTAMP_IN_MBUF
				timestamp_us = get_timestamp_us(dpdk);
				for(u_int16_t i = 0; i < nb_rx; i++) {
					#if DPDK_TIMESTAMP_IN_MBUF == 1
					*RTE_MBUF_DYNFIELD(pkts_burst[i], timestamp_dynfield_offset, u_int64_t*) = timestamp_us;
					#elif DPDK_TIMESTAMP_IN_MBUF == 2
					*(u_int64_t*)&pkts_burst[i]->dynfield1[0] = timestamp_us;
					#endif
				}
				#endif
				u_int16_t nb_rx_enqueue = rte_ring_enqueue_burst(dpdk->rx_to_worker_ring, (void *const *)pkts_burst, nb_rx, NULL);
				if(nb_rx_enqueue < nb_rx) {
					for(u_int16_t i = nb_rx_enqueue; i < nb_rx; i++) {
						rte_pktmbuf_free(pkts_burst[i]);
					}
					dpdk->ring_full_drop += nb_rx - nb_rx_enqueue;
				}
				nb_rx_sum += nb_rx;
			} else if(dpdk->config.read_usleep_if_no_packet) {
				if(dpdk->config.read_usleep_type == _dpdk_usleep_type_rte) {
					rte_delay_us_block(dpdk->config.read_usleep_if_no_packet);
				} else if(dpdk->config.read_usleep_type == _dpdk_usleep_type_rte_pause) {
					rte_pause();
				} else {
					USLEEP(dpdk->config.read_usleep_if_no_packet);
				}
			}
		}
		return(nb_rx_sum);
		#endif
	} else {
		int nb_rx = (int)rte_eth_rx_burst(dpdk->portid, 0, pkts_burst, MAX_PKT_BURST);
		if(likely(nb_rx)) {
			timestamp_us = get_timestamp_us(dpdk);
			for(int i = 0; i < nb_rx; i++) {
				dpdk_process_packet(dpdk, pkts_burst[i], timestamp_us);
			}
		}
		return(nb_rx);
	}
}


int dpdk_worker_proc(sDpdk *dpdk) {
	#if DEBUG_CYCLES
	dpdk->cycles[9].setBegin();
	#endif
	rte_mbuf *pkts_burst[MAX_PKT_BURST];
	#if not DPDK_TIMESTAMP_IN_MBUF
	u_int64_t timestamp_us;
	#endif
	int nb_rx = (int)rte_ring_dequeue_burst(dpdk->rx_to_worker_ring, (void**)pkts_burst, MAX_PKT_BURST, NULL);
	if(likely(nb_rx)) {
		#if not DPDK_TIMESTAMP_IN_MBUF
		timestamp_us = get_timestamp_us(dpdk);
		#endif
		for(int i = 0; i < nb_rx; i++) {
			dpdk_process_packet(dpdk, pkts_burst[i],
					    #if DPDK_TIMESTAMP_IN_MBUF == 1
					    *RTE_MBUF_DYNFIELD(pkts_burst[i], timestamp_dynfield_offset, u_int64_t*)
					    #elif DPDK_TIMESTAMP_IN_MBUF == 2
					    *(u_int64_t*)&pkts_burst[i]->dynfield1[0]
					    #else
					    timestamp_us
					    #endif
					    );
		}
	}
	#if DEBUG_CYCLES
	dpdk->cycles[9].setEnd();
	#endif
	return(nb_rx);
}


int pcap_dpdk_stats(sDpdk *dpdk, pcap_stat *ps, string *str_out) {
	dpdk->curr_ts_us = get_timestamp_us(dpdk);
	rte_eth_stats_get(dpdk->portid,&(dpdk->curr_stats));
	if(ps) {
		ps->ps_recv = dpdk->curr_stats.ipackets;
		ps->ps_drop = dpdk->curr_stats.rx_nombuf + (opt_dpdk_ignore_ierrors ? 0 : dpdk->curr_stats.ierrors) + dpdk->bpf_drop;
		ps->ps_ifdrop = dpdk->curr_stats.imissed;
	}
	uint64_t delta_pkt = dpdk->curr_stats.ipackets - dpdk->prev_stats.ipackets;
	uint64_t delta_usec = dpdk->curr_ts_us - dpdk->prev_ts_us;
	uint64_t delta_bit = (dpdk->curr_stats.ibytes-dpdk->prev_stats.ibytes)*8;
	dpdk->pps = (uint64_t)(delta_pkt*1e6f/delta_usec);
	dpdk->bps = (uint64_t)(delta_bit*1e6f/delta_usec);
	if(str_out) {
		ostringstream outStr;
		outStr << fixed
		       << "DPDK "
		       << dpdk->config.device
		       << " portid " << dpdk->portid
		       << " ["
		       << setprecision(2) << dpdk->bps/1e6f << "Mb/s"
		       << "; packets: " << (dpdk->curr_stats.ipackets - dpdk->last_stat_ipackets);
		if(!opt_dpdk_ignore_ierrors &&
		   dpdk->curr_stats.ierrors > dpdk->last_stat_ierrors) {
			outStr << "; errors: " << (dpdk->curr_stats.ierrors - dpdk->last_stat_ierrors);
		}
		if(dpdk->curr_stats.imissed > dpdk->last_stat_imissed) {
			outStr << "; missed: " << (dpdk->curr_stats.imissed - dpdk->last_stat_imissed);
		}
		if(dpdk->curr_stats.rx_nombuf > dpdk->last_stat_nombuf) {
			outStr << "; nombuf: " << (dpdk->curr_stats.rx_nombuf - dpdk->last_stat_nombuf);
		}
		dpdk->last_stat_ipackets = dpdk->curr_stats.ipackets;
		if(!opt_dpdk_ignore_ierrors) {
			dpdk->last_stat_ierrors = dpdk->curr_stats.ierrors;
		}
		dpdk->last_stat_imissed = dpdk->curr_stats.imissed;
		dpdk->last_stat_nombuf = dpdk->curr_stats.rx_nombuf;
		#if LOG_PACKETS_SUM
		if(dpdk->count_packets[0] > 0) {
			outStr << "; packets_read: " << (dpdk->count_packets[0] - dpdk->last_stat_cout_packets[0]);
			dpdk->last_stat_cout_packets[0] = dpdk->count_packets[0];
		}
		if(dpdk->count_packets[1] > 0) {
			outStr << "; packets_worker: " << (dpdk->count_packets[1] - dpdk->last_stat_cout_packets[1]);
			dpdk->last_stat_cout_packets[1] = dpdk->count_packets[1];
		}
		#endif
		if(dpdk->rx_to_worker_ring) {
			unsigned int ring_count = rte_ring_count(dpdk->rx_to_worker_ring);
			if(ring_count > 0) {
				outStr << "; ring count: " << ring_count;
			}
			if(dpdk->ring_full_drop > dpdk->last_stat_ring_full_drop) {
				outStr << "; ring full: " << (dpdk->ring_full_drop - dpdk->last_stat_ring_full_drop);
			}
			dpdk->last_stat_ring_full_drop = dpdk->ring_full_drop;
		}
		#if WORKER2_THREAD_SUPPORT
		if(dpdk->worker_to_worker2_ring) {
			outStr << "; ring2 count: " << rte_ring_count(dpdk->worker_to_worker2_ring);
			outStr << "; ring2 full: " << (dpdk->ring2_full_drop - dpdk->last_stat_ring2_full_drop);
			dpdk->last_stat_ring2_full_drop = dpdk->ring2_full_drop;
		}
		#endif
		#if DEBUG_EXT_STAT
		int len = rte_eth_xstats_get(dpdk->portid, NULL, 0);
		if(len < 0) {
			outStr << "; error: " << "rte_eth_xstats_get failed";
		} else {
			struct rte_eth_xstat *xstats = (rte_eth_xstat*)calloc(len, sizeof(*xstats));
			if(xstats == NULL) {
				outStr << "; error: " << "failed to calloc memory for xstats";
			} else {
				int ret = rte_eth_xstats_get(dpdk->portid, xstats, len);
				if(ret < 0 || ret > len) {
					outStr << "; error: " << "rte_eth_xstats_get failed";
				} else {
					rte_eth_xstat_name *xstats_names = (rte_eth_xstat_name*)calloc(len, sizeof(*xstats_names));
					if(xstats_names == NULL) {
						outStr << "; error: " << "failed to calloc memory for xstats_names";
					} else {
						ret = rte_eth_xstats_get_names(dpdk->portid, xstats_names, len);
						if(ret < 0 || ret > len) {
							outStr << "; error: " << "rte_eth_xstats_get_names failed";
						} else {
							for(int i = 0; i < len; i++) {
								if(xstats[i].value > 0) {
									outStr << "; " << xstats_names[i].name << ": " << xstats[i].value;
								}
							}
						}
						free(xstats_names);
					}
				}
				free(xstats);
			}
		}
		#endif
		outStr << "]";
		#if DEBUG_CYCLES
		for(unsigned i = 0; i < sizeof(dpdk->cycles) / sizeof(dpdk->cycles[0]); i++) {
			if(dpdk->cycles[i].count && 
			   (!DEBUG_CYCLES_MAX_LT_MS || 
			    dpdk->cycles[i].max * 1000000000 / dpdk->ts_helper.hz > DEBUG_CYCLES_MAX_LT_MS * 1000000ul)) {
				outStr << " * C" << i 
				       << " " << dpdk->cycles[i].sum / dpdk->cycles[i].count * 1000000000 / dpdk->ts_helper.hz
				       << " " << dpdk->cycles[i].min * 1000000000 / dpdk->ts_helper.hz
				       << " " << dpdk->cycles[i].max * 1000000000 / dpdk->ts_helper.hz
				       << endl;
			}
			dpdk->cycles[i].reset = true;
		}
		#endif
		*str_out = outStr.str();
	}
	dpdk->prev_stats = dpdk->curr_stats;
	dpdk->prev_ts_us = get_timestamp_us(dpdk);
	return 0;
}


sDpdkConfig *dpdk_config(sDpdk *dpdk) {
	return(&dpdk->config);
}


void dpdk_terminating(sDpdk *dpdk) {
	dpdk->terminating = true;
}

void dpdk_check_params() {
	extern int opt_dpdk_nb_rxq;
	if(count_rte_read_threads() > DPDK_MAX_COUNT_RTE_READ_THREADS) {
		opt_dpdk_nb_rxq = DPDK_MAX_COUNT_RTE_READ_THREADS;
	}
}

u_int16_t count_rte_read_threads() {
	#if TEST_RTE_READ_MULTI_THREADS
	return(2);
	#endif
	extern int opt_dpdk_nb_rxq;
	extern bool opt_dpdk_rxq_per_thread;
	return(opt_dpdk_rxq_per_thread && opt_dpdk_nb_rxq > 1 ? opt_dpdk_nb_rxq : 1);
}

double rte_read_thread_cpu_usage(sDpdk *dpdk, u_int16_t rte_read_thread_id) {
	if(!dpdk->rte_read_thread_pid[rte_read_thread_id]) {
		return(-1);
	}
	if(dpdk->rte_read_thread_pstat_data[rte_read_thread_id][0].cpu_total_time) {
		dpdk->rte_read_thread_pstat_data[rte_read_thread_id][1] = dpdk->rte_read_thread_pstat_data[rte_read_thread_id][0];
	}
	pstat_get_data(dpdk->rte_read_thread_pid[rte_read_thread_id], dpdk->rte_read_thread_pstat_data[rte_read_thread_id]);
	double ucpu_usage, scpu_usage;
	if(dpdk->rte_read_thread_pstat_data[rte_read_thread_id][0].cpu_total_time && dpdk->rte_read_thread_pstat_data[rte_read_thread_id][1].cpu_total_time) {
		pstat_calc_cpu_usage_pct(
			&dpdk->rte_read_thread_pstat_data[rte_read_thread_id][0], &dpdk->rte_read_thread_pstat_data[rte_read_thread_id][1],
			&ucpu_usage, &scpu_usage);
		return(ucpu_usage + scpu_usage);
	}
	return(-1);
}

double rte_worker_thread_cpu_usage(sDpdk *dpdk) {
	if(!dpdk->rte_worker_thread_pid) {
		return(-1);
	}
	if(dpdk->rte_worker_thread_pstat_data[0].cpu_total_time) {
		dpdk->rte_worker_thread_pstat_data[1] = dpdk->rte_worker_thread_pstat_data[0];
	}
	pstat_get_data(dpdk->rte_worker_thread_pid, dpdk->rte_worker_thread_pstat_data);
	double ucpu_usage, scpu_usage;
	if(dpdk->rte_worker_thread_pstat_data[0].cpu_total_time && dpdk->rte_worker_thread_pstat_data[1].cpu_total_time) {
		pstat_calc_cpu_usage_pct(
			&dpdk->rte_worker_thread_pstat_data[0], &dpdk->rte_worker_thread_pstat_data[1],
			&ucpu_usage, &scpu_usage);
		return(ucpu_usage + scpu_usage);
	}
	return(-1);
}

double rte_worker_slave_thread_cpu_usage(sDpdk *dpdk) {
	if(!dpdk->rte_worker_slave_thread_pid) {
		return(-1);
	}
	if(dpdk->rte_worker_slave_thread_pstat_data[0].cpu_total_time) {
		dpdk->rte_worker_slave_thread_pstat_data[1] = dpdk->rte_worker_slave_thread_pstat_data[0];
	}
	pstat_get_data(dpdk->rte_worker_thread_pid, dpdk->rte_worker_slave_thread_pstat_data);
	double ucpu_usage, scpu_usage;
	if(dpdk->rte_worker_slave_thread_pstat_data[0].cpu_total_time && dpdk->rte_worker_slave_thread_pstat_data[1].cpu_total_time) {
		pstat_calc_cpu_usage_pct(
			&dpdk->rte_worker_slave_thread_pstat_data[0], &dpdk->rte_worker_slave_thread_pstat_data[1],
			&ucpu_usage, &scpu_usage);
		return(ucpu_usage + scpu_usage);
	}
	return(-1);
}

double rte_worker2_thread_cpu_usage(sDpdk *dpdk) {
	#if WORKER2_THREAD_SUPPORT
	if(!dpdk->rte_worker2_thread_pid) {
		return(-1);
	}
	if(dpdk->rte_worker2_thread_pstat_data[0].cpu_total_time) {
		dpdk->rte_worker2_thread_pstat_data[1] = dpdk->rte_worker2_thread_pstat_data[0];
	}
	pstat_get_data(dpdk->rte_worker2_thread_pid, dpdk->rte_worker2_thread_pstat_data);
	double ucpu_usage, scpu_usage;
	if(dpdk->rte_worker2_thread_pstat_data[0].cpu_total_time && dpdk->rte_worker2_thread_pstat_data[1].cpu_total_time) {
		pstat_calc_cpu_usage_pct(
			&dpdk->rte_worker2_thread_pstat_data[0], &dpdk->rte_worker2_thread_pstat_data[1],
			&ucpu_usage, &scpu_usage);
		return(ucpu_usage + scpu_usage);
	}
	#endif
	return(-1);
}


string get_dpdk_cpu_cores(bool without_main, bool detect_ht) {
	if(!without_main && !opt_dpdk_cpu_cores.empty()) {
		return(opt_dpdk_cpu_cores);
	}
	cDpdkTools tools;
	return(tools.getAllCores(without_main, detect_ht));
}


static int rte_read_thread(void *arg) {
	sRteReadThreadArg *rte_read_thread_arg = (sRteReadThreadArg*)arg;
	sDpdk *dpdk = rte_read_thread_arg->dpdk;
	int read_thread_id = rte_read_thread_arg->read_thread_id;
	int rxq = rte_read_thread_arg->rxq;
	delete rte_read_thread_arg;
	dpdk->rte_read_thread_pid[read_thread_id] = get_unix_tid();
	setpriority(PRIO_PROCESS, dpdk->rte_read_thread_pid[read_thread_id], -19);
	syslog(LOG_INFO, "DPDK - READ (rte) THREAD %i (thread_id=%d, rxq=%d)\n", 
	       dpdk->rte_read_thread_pid[read_thread_id], read_thread_id, rxq);
	threadMonitor.registerThread(dpdk->rte_read_thread_pid[read_thread_id], ("DPDK - READ (rte) - rxq=" + intToString(rxq)).c_str());
	while(!dpdk->initialized) {
		USLEEP(1000);
	}
	dpdk_reset_statistics(dpdk, true);
	void (*dpdk_process_packet_2)(sDpdk *dpdk, rte_mbuf *mbuff, u_int64_t timestamp_us
				      #if WORKER2_THREAD_SUPPORT
				      ,bool free_mbuff
				      #endif
				      ) =
		opt_dpdk_mbufs_in_packetbuffer ?
		 dpdk_process_packet_2__mbufs_in_packetbuffer :
		 dpdk_process_packet_2__std;
	#if DPDK_ZC_SUPPORT
	extern int opt_dpdk_zc;
	if(opt_dpdk_zc && dpdk->rx_to_worker_ring) {
		rte_ring_zc_data zcd;
		uint16_t nb_zcd, nb_rx;
		while(!dpdk->terminating) {
			nb_zcd = rte_ring_enqueue_zc_burst_start(dpdk->rx_to_worker_ring, MAX_PKT_BURST, &zcd, NULL);
			if(nb_zcd > 0) {
				nb_rx = rte_eth_rx_burst(dpdk->portid, 0, (rte_mbuf**)zcd.ptr1, zcd.n1);
				if(nb_rx == zcd.n1 && nb_zcd > zcd.n1) {
					nb_rx += rte_eth_rx_burst(dpdk->portid, 0, (rte_mbuf**)zcd.ptr2, nb_zcd - zcd.n1);
				}
				#if LOG_PACKETS_SUM
				dpdk->count_packets[0] += nb_rx;
				#endif
				rte_ring_enqueue_zc_finish(dpdk->rx_to_worker_ring, nb_rx);
				if(!nb_rx && dpdk->config.read_usleep_if_no_packet) {
					if(dpdk->config.read_usleep_type == _dpdk_usleep_type_rte) {
						rte_delay_us_block(dpdk->config.read_usleep_if_no_packet);
					} else if(dpdk->config.read_usleep_type == _dpdk_usleep_type_rte_pause) {
						rte_pause();
					} else {
						USLEEP(dpdk->config.read_usleep_if_no_packet);
					}
				}
			} else {
				++dpdk->ring_full_drop;
			}
		}
		threadMonitor.unregisterThread(dpdk->rte_read_thread_pid[read_thread_id]);
		return 0;
	}
	#endif
	if(opt_dpdk_batch_read > 1) {
		extern int opt_dpdk_nb_rxq;
		uint16_t nb_rxq = opt_dpdk_nb_rxq > 0 ? opt_dpdk_nb_rxq : 1;
		unsigned pkts_burst_cnt;
		rte_mbuf *pkts_burst[opt_dpdk_batch_read][MAX_PKT_BURST];
		uint16_t nb_rx[opt_dpdk_batch_read * nb_rxq];
		u_int64_t timestamp_us[opt_dpdk_batch_read];
		uint16_t nb_rx_enqueue;
		if(dpdk->rx_to_worker_ring) {
			uint16_t rxq_begin = rxq >= 0 ? rxq : 0;
			uint16_t rxq_end = rxq >= 0 ? rxq : nb_rxq - 1;
			while(!dpdk->terminating) {
				pkts_burst_cnt = 0;
				while(pkts_burst_cnt < (unsigned)opt_dpdk_batch_read) {
					for(uint16_t q = rxq_begin; q <= rxq_end; q++) {
						nb_rx[pkts_burst_cnt] = rte_eth_rx_burst(dpdk->portid, q, pkts_burst[pkts_burst_cnt], MAX_PKT_BURST);
						if(!nb_rx[pkts_burst_cnt]) {
							break;
						}
						#if LOG_PACKETS_SUM
						dpdk->count_packets[0] += nb_rx[pkts_burst_cnt];
						#endif
						#if DPDK_TIMESTAMP_IN_MBUF
						timestamp_us[pkts_burst_cnt] = get_timestamp_us(dpdk);
						#endif
						++pkts_burst_cnt;
					}
				}
				if(likely(pkts_burst_cnt)) {
					for(unsigned i = 0; i < pkts_burst_cnt; i++) {
						#if DPDK_TIMESTAMP_IN_MBUF
						for(u_int16_t j = 0; j < nb_rx[i]; j++) {
							#if DPDK_TIMESTAMP_IN_MBUF == 1
							*RTE_MBUF_DYNFIELD(pkts_burst[i][j], timestamp_dynfield_offset, u_int64_t*) = timestamp_us[i];
							#elif DPDK_TIMESTAMP_IN_MBUF == 2
							*(u_int64_t*)&pkts_burst[i][j]->dynfield1[0] = timestamp_us[i];
							#endif
						}
						#endif
						nb_rx_enqueue = rte_ring_enqueue_burst(dpdk->rx_to_worker_ring, (void *const *)pkts_burst[i], nb_rx[i], NULL);
						if(unlikely(nb_rx_enqueue < nb_rx[i])) {
							for(u_int16_t j = nb_rx_enqueue; j < nb_rx[i]; j++) {
								rte_pktmbuf_free(pkts_burst[i][j]);
							}
							dpdk->ring_full_drop += nb_rx[i] - nb_rx_enqueue;
						}
					}
				} else if(dpdk->config.read_usleep_if_no_packet) {
					if(dpdk->config.read_usleep_type == _dpdk_usleep_type_rte) {
						rte_delay_us_block(dpdk->config.read_usleep_if_no_packet);
					} else if(dpdk->config.read_usleep_type == _dpdk_usleep_type_rte_pause) {
						rte_pause();
					} else {
						USLEEP(dpdk->config.read_usleep_if_no_packet);
					}
				}
			}
		} else {
			while(!dpdk->terminating) {
				pkts_burst_cnt = 0;
				while(pkts_burst_cnt < (unsigned)opt_dpdk_batch_read) {
					nb_rx[pkts_burst_cnt] = rte_eth_rx_burst(dpdk->portid, 0, pkts_burst[pkts_burst_cnt], MAX_PKT_BURST);
					if(!nb_rx[pkts_burst_cnt]) {
						break;
					}
					#if LOG_PACKETS_SUM
					dpdk->count_packets[0] += nb_rx[pkts_burst_cnt];
					#endif
					timestamp_us[pkts_burst_cnt] = get_timestamp_us(dpdk);
					++pkts_burst_cnt;
				}
				if(likely(pkts_burst_cnt)) {
					for(unsigned i = 0; i < pkts_burst_cnt; i++) {
						for(u_int16_t j = 0; j < nb_rx[i]; j++) {
							dpdk_process_packet_2(dpdk, pkts_burst[i][j], timestamp_us[i]
									      #if WORKER2_THREAD_SUPPORT
									      ,true
									      #endif
									      );
						}
					}
				} else if(dpdk->config.read_usleep_if_no_packet) {
					if(dpdk->config.read_usleep_type == _dpdk_usleep_type_rte) {
						rte_delay_us_block(dpdk->config.read_usleep_if_no_packet);
					} else if(dpdk->config.read_usleep_type == _dpdk_usleep_type_rte_pause) {
						rte_pause();
					} else {
						USLEEP(dpdk->config.read_usleep_if_no_packet);
					}
				}
			}
		}
	} else {
		rte_mbuf *pkts_burst[MAX_PKT_BURST];
		uint16_t nb_rx, nb_rx_enqueue;
		u_int64_t timestamp_us;
		if(dpdk->rx_to_worker_ring) {
			extern int opt_dpdk_nb_rxq;
			uint16_t nb_rxq = opt_dpdk_nb_rxq > 0 ? opt_dpdk_nb_rxq : 1;
			uint16_t rxq_begin = rxq >= 0 ? rxq : 0;
			uint16_t rxq_end = rxq >= 0 ? rxq : nb_rxq - 1;
			syslog(LOG_INFO, "DPDK - READ THREAD %d: reading from queues %d to %d (rxq=%d, nb_rxq=%d)", 
			       read_thread_id, rxq_begin, rxq_end, rxq, nb_rxq);
			while(!dpdk->terminating) {
				#if DEBUG_CYCLES
				dpdk->cycles[0].setBegin();
				dpdk->cycles[1].setBegin();
				#endif
				for(uint16_t q = rxq_begin; q <= rxq_end; q++) {
					#if TEST_RTE_READ_MULTI_THREADS
					__SYNC_LOCK(rte_read_sync);
					#endif
					nb_rx = rte_eth_rx_burst(dpdk->portid, q, pkts_burst, MAX_PKT_BURST);
					#if TEST_RTE_READ_MULTI_THREADS
					__SYNC_UNLOCK(rte_read_sync);
					#endif
					#if DEBUG_CYCLES
					dpdk->cycles[1].setEnd();
					dpdk->cycles[2].setBegin();
					#endif
					if(likely(nb_rx)) {
						#if LOG_PACKETS_SUM
						dpdk->count_packets[0] += nb_rx;
						#endif
						#if DPDK_TIMESTAMP_IN_MBUF
						timestamp_us = get_timestamp_us(dpdk);
						for(u_int16_t i = 0; i < nb_rx; i++) {
							#if DPDK_TIMESTAMP_IN_MBUF == 1
							*RTE_MBUF_DYNFIELD(pkts_burst[i], timestamp_dynfield_offset, u_int64_t*) = timestamp_us;
							#elif DPDK_TIMESTAMP_IN_MBUF == 2
							*(u_int64_t*)&pkts_burst[i]->dynfield1[0] = timestamp_us;
							#endif
						}
						#endif
						nb_rx_enqueue = rte_ring_enqueue_burst(dpdk->rx_to_worker_ring, (void *const *)pkts_burst, nb_rx, NULL);
						if(unlikely(nb_rx_enqueue < nb_rx)) {
							for(u_int16_t i = nb_rx_enqueue; i < nb_rx; i++) {
								rte_pktmbuf_free(pkts_burst[i]);
							}
							dpdk->ring_full_drop += nb_rx - nb_rx_enqueue;
							#if DPDK_WAIT_FOR_EMPTY_RING_IF_FULL
							if(unlikely(!nb_rx_enqueue)) {
								while(!rte_ring_empty(dpdk->rx_to_worker_ring) && !dpdk->terminating) {
									USLEEP(1000);
								}
							}
							#endif
						}
					} else if(dpdk->config.read_usleep_if_no_packet) {
						if(dpdk->config.read_usleep_type == _dpdk_usleep_type_rte) {
							rte_delay_us_block(dpdk->config.read_usleep_if_no_packet);
						} else if(dpdk->config.read_usleep_type == _dpdk_usleep_type_rte_pause) {
							rte_pause();
						} else {
							USLEEP(dpdk->config.read_usleep_if_no_packet);
						}
					}
				}
				#if DEBUG_CYCLES
				dpdk->cycles[2].setEnd();
				dpdk->cycles[0].setEnd();
				#endif
			}
		} else {
			while(!dpdk->terminating) {
				#if DEBUG_CYCLES
				dpdk->cycles[0].setBegin();
				dpdk->cycles[1].setBegin();
				#endif
				nb_rx = rte_eth_rx_burst(dpdk->portid, 0, pkts_burst, MAX_PKT_BURST);
				#if DEBUG_CYCLES
				dpdk->cycles[1].setEnd();
				dpdk->cycles[2].setBegin();
				#endif
				if(likely(nb_rx)) {
					#if LOG_PACKETS_SUM
					dpdk->count_packets[0] += nb_rx;
					#endif
					timestamp_us = get_timestamp_us(dpdk);
					for(uint16_t i = 0; i < nb_rx; i++) {
						dpdk_process_packet_2(dpdk, pkts_burst[i], timestamp_us
								      #if WORKER2_THREAD_SUPPORT
								      ,true 
								      #endif
								      );
					}
				} else if(dpdk->config.read_usleep_if_no_packet) {
					if(dpdk->config.read_usleep_type == _dpdk_usleep_type_rte) {
						rte_delay_us_block(dpdk->config.read_usleep_if_no_packet);
					} else if(dpdk->config.read_usleep_type == _dpdk_usleep_type_rte_pause) {
						rte_pause();
					} else {
						USLEEP(dpdk->config.read_usleep_if_no_packet);
					}
				}
				#if DEBUG_CYCLES
				dpdk->cycles[2].setEnd();
				dpdk->cycles[0].setEnd();
				#endif
			}
		}
	}
	threadMonitor.unregisterThread(dpdk->rte_read_thread_pid[read_thread_id]);
	return 0;
}


//PcapQueue_readFromInterfaceThread::pcap_dispatch_data *_dd;

static int rte_worker_thread(void *arg) {
	sDpdk *dpdk = (sDpdk*)arg;
	dpdk->rte_worker_thread_pid = get_unix_tid();
	syslog(LOG_INFO, "DPDK - WORKER (rte) THREAD %i\n", dpdk->rte_worker_thread_pid);
	threadMonitor.registerThread(dpdk->rte_worker_thread_pid, "DPDK - WORKER (rte)");
	void (*dpdk_process_packet_2)(sDpdk *dpdk, rte_mbuf *mbuff, u_int64_t timestamp_us
				      #if WORKER2_THREAD_SUPPORT
				      ,bool free_mbuff
				      #endif
				      ) =
		opt_dpdk_mbufs_in_packetbuffer ?
		 dpdk_process_packet_2__mbufs_in_packetbuffer :
		 //dpdk_process_packet_2__std;
		 dpdk_process_packet_2__std_2;
	uint16_t nb_rx;
	pcap_pkthdr header;
	unsigned caplen;
	PcapQueue_readFromInterface_base::sCheckProtocolData checkProtocolData;
	dpdk->worker_alloc();
	#if DPDK_DEBUG
	bool enable_slave = false;
	bool per_1_packet = true;
	u_char *last_pb_headers = NULL;
	unsigned last_caplen = 0;
	u_int64_t last_timestamp_us = 0;
	PcapQueue_readFromInterfaceThread::pcap_dispatch_data *_dd = (PcapQueue_readFromInterfaceThread::pcap_dispatch_data*)dpdk->config.callback.packet_user;
	#endif
	u_int32_t batch_count = 0;
	if(NEED_INIT_PB_BLOCK) {
		dpdk->config.callback.packet_allocation(dpdk->config.callback.packet_user, 0, true, true);
	}
	while(!dpdk->terminating) {
		nb_rx = rte_ring_dequeue_burst(dpdk->rx_to_worker_ring, (void**)dpdk->pkts_burst, MAX_PKT_BURST, NULL);
		if(likely(nb_rx)) {
			#if LOG_PACKETS_SUM
			dpdk->count_packets[1] += nb_rx;
			#endif
			//cout << " * " << nb_rx << endl;
			#if not DPDK_TIMESTAMP_IN_MBUF
			dpdk->timestamp_us = get_timestamp_us(dpdk);
			#endif
			//if(false) {
			if(ENABLE_WORKER_SLAVE && nb_rx > 20) {
				for(uint16_t i = 0; i < nb_rx; i++) {
					dpdk->pkts_len[i] = get_len(dpdk->pkts_burst[i]);
				}
				uint16_t pkts_i = 0;
				while(pkts_i < nb_rx) {
					__SYNC_SET_TO(dpdk->worker_slave_state, 0);
					bool filled = false;
					#if DPDK_DEBUG
					if(per_1_packet) {
						dpdk->config.callback.packet_allocation(dpdk->config.callback.packet_user, dpdk->pkts_len[pkts_i]);
						dpdk->pb_headers[pkts_i] = (void*)_dd->pcap_header_plus2; 
						dpdk->pb_packets[pkts_i] = (void*)_dd->headerPacket.packet;
						dpdk->batch_start = pkts_i;
						dpdk->batch_count = 1;
					} else {
					#endif
						dpdk->config.callback.packets_get_pointers(dpdk->config.callback.packet_user, pkts_i, nb_rx, dpdk->pkts_len, dpdk->config.snapshot,
											   dpdk->pb_headers, dpdk->pb_packets, &batch_count, &filled);
						dpdk->batch_start = pkts_i;
						dpdk->batch_count = batch_count;
					#if DPDK_DEBUG
					}
					if(enable_slave) {
					#endif
						__SYNC_SET_TO(dpdk->worker_slave_state, 1);
					#if DPDK_DEBUG
					}
					if(dpdk->batch_count > 0) {
					#endif
						for(unsigned i = dpdk->batch_start; i < dpdk->batch_start + dpdk->batch_count; i++) {
							if(!(i % 2)
							#if DPDK_DEBUG
							|| !enable_slave
							#endif
							) {
								rte_mbuf *mbuff = dpdk->pkts_burst[i];
								rte_prefetch0(rte_pktmbuf_mtod(mbuff, void *));
								caplen = get_caplen(dpdk->pkts_len[i], dpdk);
								dpdk_copy_data((u_char*)dpdk->pb_packets[i], caplen, mbuff);
								rte_pktmbuf_free(mbuff);
								u_int64_t _timestamp_us = 
											  #if DPDK_TIMESTAMP_IN_MBUF == 1
											  *RTE_MBUF_DYNFIELD(mbuff, timestamp_dynfield_offset, u_int64_t*);
											  #elif DPDK_TIMESTAMP_IN_MBUF == 2
											  *(u_int64_t*)&mbuff->dynfield1[0];
											  #else
											  dpdk->timestamp_us;
											  #endif
								#if DPDK_DEBUG
								if(_timestamp_us < last_timestamp_us) {
									cout << "ERR timestamp " << (last_timestamp_us - _timestamp_us) << endl;
									cout << _dd->block->count << " / " << pkts_i << " / " << nb_rx << endl;
								}
								#endif
								header.ts.tv_sec = _timestamp_us / 1000000;
								header.ts.tv_usec = _timestamp_us % 1000000;
								header.caplen = caplen;
								header.len = dpdk->pkts_len[i];
								#if DPDK_DEBUG
								/*if(last_pb_headers &&
								   ((u_char*)dpdk->pb_headers[i] - last_pb_headers != last_caplen + 58 ||
								   (u_char*)dpdk->pb_packets[i] - (u_char*)dpdk->pb_headers[i] != 58)) {
									cout << "ERR offset" << endl;
									//abort();
								}*/
								//bool ok = 
								#endif
								dpdk->config.callback.packet_completion_plus(dpdk->config.callback.packet_user, &header, (u_char*)dpdk->pb_packets[i], (u_char*)dpdk->pb_headers[i],
													     &checkProtocolData);
								#if DPDK_DEBUG
								if(per_1_packet) {
									//if(ok) {
										_dd->block->inc_h(caplen);
									//}
								}
								last_pb_headers = (u_char*)dpdk->pb_headers[i];
								last_caplen = caplen;
								last_timestamp_us = _timestamp_us;
								//dpdk->config.callback.check_block(dpdk->config.callback.packet_user, i - pkts_i, batch_count);
								#endif
							}
						}
					#if DPDK_DEBUG
					} else {
						filled = true;
					}
					if(enable_slave) {
					#endif
						while(dpdk->worker_slave_state != 2) {
							if(dpdk->terminating) {
								dpdk->worker_free();
								return(0);
							}
							if(dpdk->config.worker_usleep_type == _dpdk_usleep_type_rte) {
								rte_delay_us_block(dpdk->config.worker_usleep_if_no_packet);
							} else if(dpdk->config.worker_usleep_type == _dpdk_usleep_type_rte_pause) {
								rte_pause();
							} else {
								USLEEP(dpdk->config.worker_usleep_if_no_packet);
							}
						}
					#if DPDK_DEBUG
					}
					#endif
					if(filled) {
						if(opt_dpdk_copy_packetbuffer) {
							dpdk->config.callback.packets_push(dpdk->config.callback.packet_user);
						} else {
							dpdk->config.callback.packet_allocation(dpdk->config.callback.packet_user, 0, true, true);
						}
						#if DPDK_DEBUG
						//static int _cf = 0;
						//cout << "push block " << (++_cf) << endl;
						last_pb_headers = NULL;
						#endif
					}
					pkts_i += dpdk->batch_count;
				}
			} else {
				for(uint16_t i = 0; i < nb_rx; i++) {
					rte_mbuf *mbuff = dpdk->pkts_burst[i];
					dpdk_process_packet_2(dpdk, mbuff, 
							      #if DPDK_TIMESTAMP_IN_MBUF == 1
							      *RTE_MBUF_DYNFIELD(mbuff, timestamp_dynfield_offset, u_int64_t*)
							      #elif DPDK_TIMESTAMP_IN_MBUF == 2
							      *(u_int64_t*)&mbuff->dynfield1[0]
							      #else
							      dpdk->timestamp_us
							      #endif
							      #if WORKER2_THREAD_SUPPORT
							      ,dpdk->config.type_worker2_thread != _dpdk_tw2t_rte
							      #endif
							      );
				}
			}
			#if WORKER2_THREAD_SUPPORT
			if(dpdk->config.type_worker2_thread == _dpdk_tw2t_rte) {
				u_int16_t nb_rx_enqueue = rte_ring_enqueue_burst(dpdk->worker_to_worker2_ring, (void *const *)pkts_burst, nb_rx, NULL);
				if(nb_rx_enqueue < nb_rx) {
					for(u_int16_t i = nb_rx_enqueue; i < nb_rx; i++) {
						rte_pktmbuf_free(dpdk->pkts_burst[i]);
					}
					dpdk->ring2_full_drop += nb_rx - nb_rx_enqueue;
				}
			}
			#endif
		} else if(dpdk->config.worker_usleep_if_no_packet) {
			if(dpdk->config.worker_usleep_type == _dpdk_usleep_type_rte) {
				rte_delay_us_block(dpdk->config.worker_usleep_if_no_packet);
			} else if(dpdk->config.worker_usleep_type == _dpdk_usleep_type_rte_pause) {
				rte_pause();
			} else {
				USLEEP(dpdk->config.worker_usleep_if_no_packet);
			}
		}
	}
	dpdk->worker_free();
	threadMonitor.unregisterThread(dpdk->rte_worker_thread_pid);
	return 0;
}

static int rte_worker_slave_thread(void *arg) {
	sDpdk *dpdk = (sDpdk*)arg;
	dpdk->rte_worker_slave_thread_pid = get_unix_tid();
	syslog(LOG_INFO, "DPDK - WORKER SLAVE (rte) THREAD %i\n", dpdk->rte_worker_slave_thread_pid);
	threadMonitor.registerThread(dpdk->rte_worker_slave_thread_pid, "DPDK - WORKER SLAVE (rte)");
	pcap_pkthdr header;
	unsigned caplen;
	PcapQueue_readFromInterface_base::sCheckProtocolData checkProtocolData;
	while(!dpdk->terminating) {
		while(dpdk->worker_slave_state != 1) {
			if(dpdk->terminating) {
				return 0;
			}
			if(dpdk->config.worker_usleep_type == _dpdk_usleep_type_rte) {
				rte_delay_us_block(dpdk->config.worker_usleep_if_no_packet);
			} else if(dpdk->config.worker_usleep_type == _dpdk_usleep_type_rte_pause) {
				rte_pause();
			} else {
				USLEEP(dpdk->config.worker_usleep_if_no_packet);
			}
		}
		for(unsigned i = dpdk->batch_start; i < dpdk->batch_start + dpdk->batch_count; i++) {
			if((i % 2)) {
				rte_mbuf *mbuff = dpdk->pkts_burst[i];
				rte_prefetch0(rte_pktmbuf_mtod(mbuff, void *));
				caplen = get_caplen(dpdk->pkts_len[i], dpdk);
				dpdk_copy_data((u_char*)dpdk->pb_packets[i], caplen, mbuff);
				rte_pktmbuf_free(mbuff);
				u_int64_t _timestamp_us = 
							  #if DPDK_TIMESTAMP_IN_MBUF == 1
							  *RTE_MBUF_DYNFIELD(dpdk->pkts_burst[i], timestamp_dynfield_offset, u_int64_t*);
							  #elif DPDK_TIMESTAMP_IN_MBUF == 2
							  *(u_int64_t*)&mbuff->dynfield1[0];
							  #else
							  dpdk->timestamp_us;
							  #endif
				header.ts.tv_sec = _timestamp_us / 1000000;
				header.ts.tv_usec = _timestamp_us % 1000000;
				header.caplen = caplen;
				header.len = dpdk->pkts_len[i];
				dpdk->config.callback.packet_completion_plus(dpdk->config.callback.packet_user, &header, (u_char*)dpdk->pb_packets[i], (u_char*)dpdk->pb_headers[i],
									     &checkProtocolData);
			}
		}
		__SYNC_SET_TO(dpdk->worker_slave_state, 2);
	}
	threadMonitor.unregisterThread(dpdk->rte_worker_slave_thread_pid);
	return 0;
}


#if WORKER2_THREAD_SUPPORT
static int rte_worker2_thread(void *arg) {
	sDpdk *dpdk = (sDpdk*)arg;
	dpdk->rte_worker2_thread_pid = get_unix_tid();
	syslog(LOG_INFO, "DPDK - WORKER 2 (rte) THREAD %i\n", dpdk->rte_worker2_thread_pid);
	threadMonitor.registerThread(dpdk->rte_worker2_thread_pid, "DPDK - WORKER 2 (rte)");
	rte_mbuf *pkts_burst[MAX_PKT_BURST];
	uint16_t nb_rx;
	while(!dpdk->terminating) {
		nb_rx = rte_ring_dequeue_burst(dpdk->worker_to_worker2_ring, (void**)pkts_burst, MAX_PKT_BURST, NULL);
		if(likely(nb_rx)) {
			for(u_int16_t i = 0; i < nb_rx; i++) {
				rte_pktmbuf_free(pkts_burst[i]);
			}
		} else if(dpdk->config.worker_usleep_if_no_packet) {
			if(dpdk->config.worker_usleep_type == _dpdk_usleep_type_rte) {
				rte_delay_us_block(dpdk->config.worker_usleep_if_no_packet);
			} else if(dpdk->config.worker_usleep_type == _dpdk_usleep_type_rte_pause) {
				rte_pause();
			} else {
				USLEEP(dpdk->config.worker_usleep_if_no_packet);
			}
		}
	}
	threadMonitor.unregisterThread(dpdk->rte_worker2_thread_pid);
	return 0;
}
#endif


static inline void dpdk_process_packet(sDpdk *dpdk, rte_mbuf *mbuff, u_int64_t timestamp_us) {
	#if DEBUG_CYCLES
	dpdk->cycles[3].setBegin();
	dpdk->cycles[4].setBegin();
	#endif
	pcap_pkthdr pcap_header;
	pcap_header.ts.tv_sec = timestamp_us / 1000000;
	pcap_header.ts.tv_usec = timestamp_us % 1000000;
	uint32_t pkt_len = get_len(mbuff);
	uint32_t caplen = get_caplen(pkt_len, dpdk);
	pcap_header.caplen = caplen;
	pcap_header.len = pkt_len;
	// volatile prefetch
	rte_prefetch0(rte_pktmbuf_mtod(mbuff, void *));
	#if DEBUG_CYCLES
	dpdk->cycles[4].setEnd();
	dpdk->cycles[5].setBegin();
	#endif
	u_char *packet = dpdk->config.callback.packet_allocation(dpdk->config.callback.packet_user, caplen, false, NEED_INIT_PB_BLOCK);
	#if DEBUG_CYCLES
	dpdk->cycles[5].setEnd();
	dpdk->cycles[6].setBegin();
	#endif
	dpdk_copy_data(packet, caplen, mbuff);
	#if DEBUG_CYCLES
	dpdk->cycles[6].setEnd();
	dpdk->cycles[7].setBegin();
	#endif
	dpdk->config.callback.packet_completion(dpdk->config.callback.packet_user, &pcap_header, packet);
	rte_pktmbuf_free(mbuff);
	#if DEBUG_CYCLES
	dpdk->cycles[7].setEnd();
	dpdk->cycles[3].setEnd();
	#endif
}


static inline void dpdk_process_packet_2__std(sDpdk *dpdk, rte_mbuf *mbuff, u_int64_t timestamp_us
					      #if WORKER2_THREAD_SUPPORT
					      ,bool free_mbuff
					      #endif
					      ) {
	#if DEBUG_CYCLES
	dpdk->cycles[3].setBegin();
	dpdk->cycles[4].setBegin();
	#endif
	uint32_t pkt_len = get_len(mbuff);
	uint32_t caplen = get_caplen(pkt_len, dpdk);
	dpdk->config.callback.packet_process(dpdk->config.callback.packet_user, caplen);
	#if DEBUG_CYCLES
	dpdk->cycles[4].setEnd();
	dpdk->cycles[5].setBegin();
	#endif
	sDpdkHeaderPacket *hp = dpdk->config.callback.header_packet;
	hp->header.ts.tv_sec = timestamp_us / 1000000;
	hp->header.ts.tv_usec = timestamp_us % 1000000;
	hp->header.caplen = caplen;
	hp->header.len = pkt_len;
	// volatile prefetch
	rte_prefetch0(rte_pktmbuf_mtod(mbuff, void *));
	dpdk_copy_data(hp->packet, caplen, mbuff);
	#if WORKER2_THREAD_SUPPORT
	if(likely(free_mbuff))
	#endif
	{
		rte_pktmbuf_free(mbuff);
	}
	#if DEBUG_CYCLES
	dpdk->cycles[5].setEnd();
	dpdk->cycles[3].setEnd();
	#endif
}


static inline void dpdk_process_packet_2__std_2(sDpdk *dpdk, rte_mbuf *mbuff, u_int64_t timestamp_us
						#if WORKER2_THREAD_SUPPORT
						,bool free_mbuff
						#endif
						) {
	uint32_t pkt_len = get_len(mbuff);
	uint32_t caplen = get_caplen(pkt_len, dpdk);
	dpdk->config.callback.packet_allocation(dpdk->config.callback.packet_user, caplen, false, NEED_INIT_PB_BLOCK);
	sDpdkHeaderPacket *hp = dpdk->config.callback.header_packet;
	hp->header.ts.tv_sec = timestamp_us / 1000000;
	hp->header.ts.tv_usec = timestamp_us % 1000000;
	hp->header.caplen = caplen;
	hp->header.len = pkt_len;
	// volatile prefetch
	rte_prefetch0(rte_pktmbuf_mtod(mbuff, void *));
	dpdk_copy_data(hp->packet, caplen, mbuff);
	dpdk->config.callback.packet_completion(dpdk->config.callback.packet_user, &hp->header, hp->packet);
	#if WORKER2_THREAD_SUPPORT
	if(likely(free_mbuff))
	#endif
	{
		rte_pktmbuf_free(mbuff);
	}
}


static inline void dpdk_process_packet_2__mbufs_in_packetbuffer(sDpdk *dpdk, rte_mbuf *mbuff, u_int64_t timestamp_us
								#if WORKER2_THREAD_SUPPORT
								,bool free_mbuff
								#endif
								) {
	pcap_pkthdr pcap_header;
	pcap_header.ts.tv_sec = timestamp_us / 1000000;
	pcap_header.ts.tv_usec = timestamp_us % 1000000;
	uint32_t pkt_len = get_len(mbuff);
	uint32_t caplen = get_caplen(pkt_len, dpdk);
	pcap_header.caplen = caplen;
	pcap_header.len = pkt_len;
	rte_prefetch0(rte_pktmbuf_mtod(mbuff, void *));
	dpdk->config.callback.packet_process__mbufs_in_packetbuffer(dpdk->config.callback.packet_user, &pcap_header, mbuff);
}


static inline void dpdk_copy_data(unsigned char *data, uint32_t maxlen, struct rte_mbuf *mbuf) {
	if(mbuf->nb_segs == 1) {
                rte_memcpy(data, rte_pktmbuf_mtod(mbuf, void*), maxlen);
        } else {
		dpdk_gather_data(data, maxlen, mbuf);
	}
}

static inline uint32_t dpdk_gather_data(unsigned char *data, uint32_t maxlen, struct rte_mbuf *mbuf) {
	uint32_t total_len = 0;
	while(mbuf && (total_len + mbuf->data_len) < maxlen) {
		rte_memcpy(data + total_len, rte_pktmbuf_mtod(mbuf,void *), mbuf->data_len);
		total_len += mbuf->data_len;
		mbuf = mbuf->next;
	}
	return total_len;
}


static inline u_int32_t get_len(rte_mbuf *mbuf) {
	if(mbuf->nb_segs == 1) {
		return(rte_pktmbuf_pkt_len(mbuf));
	} else {
		u_int32_t len = 0;
		while(mbuf) {
			len += rte_pktmbuf_pkt_len(mbuf);
			mbuf = mbuf->next;
		}
		return(len);
	}
}

static inline u_int32_t get_caplen(u_int32_t len, sDpdk *dpdk) {
	return(MIN(len, (uint32_t)dpdk->config.snapshot));
}


static inline u_int64_t get_timestamp_us(sDpdk *dpdk) {
	u_int64_t rslt_timestamp_us;
	rte_spinlock_lock(&dpdk->ts_helper_lock);
	dpdk_ts_helper ts_helper = dpdk->ts_helper;
	uint64_t cycles = rte_get_timer_cycles() - ts_helper.start_cycles;
	uint64_t shift_s = cycles / ts_helper.hz;
	if(shift_s >= (unsigned)opt_dpdk_timer_reset_interval) {
		dpdk_init_timer(dpdk, false);
		rslt_timestamp_us = dpdk->ts_helper.start_time;
		rte_spinlock_unlock(&dpdk->ts_helper_lock);
	} else {
		rte_spinlock_unlock(&dpdk->ts_helper_lock);
		rslt_timestamp_us = ts_helper.start_time +
				    shift_s * 1000000ull + 
				    (cycles % ts_helper.hz) * 1000000ull / ts_helper.hz;
	}
	return(rslt_timestamp_us);
}


static int dpdk_pre_init(string *error_str) {
	int ret;
	int dargv_cnt = 0;
	char *dargv[DPDK_ARGC_MAX];
	string dargs;
	#if DPDK_ENV_CFG
	char *ptr_dpdk_cfg = NULL;
	#else
	string _opt_dpdk_main_thread_lcore;
	string _opt_dpdk_cpu_cores_map;
	string _opt_dpdk_cpu_cores;
	string _opt_dpdk_memory_channels;
	string _opt_dpdk_force_max_simd_bitwidth;
	vector<string> _opt_dpdk_pci_devices;
	cDpdkTools tools;
	#endif
	if(is_dpdk_pre_inited != 0) {
		// already inited; did that succeed?
		if(is_dpdk_pre_inited > 0) {
			return(1);
		} else {
			return(is_dpdk_pre_inited == -ENOTSUP ? 0 : is_dpdk_pre_inited);
		}
	}
	dpdk_check_params();
	#if DPDK_ENV_CFG
	ptr_dpdk_cfg = getenv(DPDK_CFG_ENV_NAME);
	if(ptr_dpdk_cfg == NULL) {
		syslog(LOG_INFO, "env $DPDK_CFG is unset, so using default: %s\n", DPDK_DEF_CFG);
		ptr_dpdk_cfg = (char*)DPDK_DEF_CFG;
	}
	memset(dpdk_cfg_buf,0,sizeof(dpdk_cfg_buf));
	snprintf(dpdk_cfg_buf,DPDK_CFG_MAX_LEN-1,"%s %s",DPDK_LIB_NAME,ptr_dpdk_cfg);
	dargv_cnt = parse_dpdk_cfg(dpdk_cfg_buf,dargv);
	#else
	dargv[dargv_cnt++] = DPDK_LIB_NAME;
	if(!opt_dpdk_cpu_cores_map.empty()) {
		dargv[dargv_cnt++] = (char*)"--lcores";
		dargv[dargv_cnt++] = (char*)opt_dpdk_cpu_cores_map.c_str();
	} else if(!opt_dpdk_cpu_cores.empty()) {
		dargv[dargv_cnt++] = (char*)"-l";
		dargv[dargv_cnt++] = (char*)opt_dpdk_cpu_cores.c_str();
	} else {
		_opt_dpdk_cpu_cores_map = tools.getCoresMap();
		_opt_dpdk_cpu_cores = tools.getAllCores(false, false);
		if(!_opt_dpdk_cpu_cores_map.empty()) {
			dargv[dargv_cnt++] = (char*)"--lcores";
			dargv[dargv_cnt++] = (char*)_opt_dpdk_cpu_cores_map.c_str();
		} else if(!_opt_dpdk_cpu_cores.empty()) {
			dargv[dargv_cnt++] = (char*)"-l";
			dargv[dargv_cnt++] = (char*)_opt_dpdk_cpu_cores.c_str();
		}
	}
	if(tools.getMainThreadLcore() >= 0) {
		dargv[dargv_cnt++] = (char*)"--main-lcore";
		_opt_dpdk_main_thread_lcore = intToString(tools.getMainThreadLcore());
		dargv[dargv_cnt++] = (char*)_opt_dpdk_main_thread_lcore.c_str();
	}
	if(opt_dpdk_memory_channels) {
		dargv[dargv_cnt++] = (char*)"-n";
		_opt_dpdk_memory_channels = intToString(opt_dpdk_memory_channels);
		dargv[dargv_cnt++] = (char*)_opt_dpdk_memory_channels.c_str();
	}
	if(!opt_dpdk_pci_device.empty()) {
		_opt_dpdk_pci_devices = split(opt_dpdk_pci_device.c_str(), split(",|;| |\t|\r|\n", "|"), true);
		for(unsigned i = 0; i < _opt_dpdk_pci_devices.size(); i++) {
			dargv[dargv_cnt++] = (char*)"-a";
			dargv[dargv_cnt++] = (char*)_opt_dpdk_pci_devices[i].c_str();
		}
	}
	if(opt_dpdk_force_max_simd_bitwidth) {
		dargv[dargv_cnt++] = (char*)"--force-max-simd-bitwidth";
		_opt_dpdk_force_max_simd_bitwidth = intToString(opt_dpdk_force_max_simd_bitwidth);
		dargv[dargv_cnt++] = (char*)_opt_dpdk_force_max_simd_bitwidth.c_str();
	}
	#endif
	rte_log_set_global_level(DPDK_DEF_LOG_LEV);
	for(int i = 0; i < dargv_cnt; i++) {
		if(i > 0) dargs += " ";
		dargs += dargv[i];
	}
	ret = rte_eal_init(dargv_cnt, dargv);
	dpdk_eval_res(ret, NULL, 2, error_str, 
		      "dpdk_pre_init - rte_eal_init(%s)",
		      dargs.c_str());
	if(ret < 0) {
		if(rte_errno == EALREADY) {
			is_dpdk_pre_inited = 1;
			return(1);
		} else {
			is_dpdk_pre_inited = -rte_errno;
			return(rte_errno == ENOTSUP ? 0 : -rte_errno);
		}
	}
	// init succeeded, so we do not need to do it again later.
	#if DPDK_TIMESTAMP_IN_MBUF == 1
	strcpy(timestamp_dynfield_desc.name, "dynfield_clock");
	timestamp_dynfield_desc.size = sizeof(u_int64_t);
	timestamp_dynfield_desc.align = __alignof__(u_int64_t);
	timestamp_dynfield_offset = rte_mbuf_dynfield_register(&timestamp_dynfield_desc);
	dpdk_eval_res(timestamp_dynfield_offset, NULL, 2, error_str,
		      "dpdk_pre_init - rte_mbuf_dynfield_register(%s)",
		      timestamp_dynfield_desc.name);
	if(timestamp_dynfield_offset < 0) {
		is_dpdk_pre_inited = -rte_errno;
		return(-rte_errno);
	}
	#endif
	if(opt_dpdk_vdev.size()) {
		#if HAVE_LIBDPDK_VDEV
		for(unsigned i = 0; i < opt_dpdk_vdev.size(); i++) {
			size_t separator_pos = opt_dpdk_vdev[i].find(':');
			if(separator_pos != string::npos) {
				string vdev_name = trim_str(opt_dpdk_vdev[i].substr(0, separator_pos));
				string vdev_args = trim_str(opt_dpdk_vdev[i].substr(separator_pos + 1));
				ret = rte_vdev_init(vdev_name.c_str(), vdev_args.c_str());
				dpdk_eval_res(ret, NULL, 2, error_str,
					      "dpdk_pre_init - rte_vdev_init(%s)", 
					      opt_dpdk_vdev[i].c_str());
				if(ret < 0) {
					is_dpdk_pre_inited = -rte_errno;
					return(-rte_errno);
				}
			}
		}
		#else
		syslog(LOG_ERR, "DPDK error: dpdk vdev is not supported in your build");
		#endif
	}
	is_dpdk_pre_inited = 1;
	return(1);
}


static uint16_t portid_by_device(const char * device) {
	uint16_t ret = DPDK_PORTID_MAX;
	int len = strlen(device);
	int prefix_len = strlen(DPDK_PREFIX);
	unsigned long ret_ul = 0L;
	char *pEnd;
	if(len<=prefix_len || strncmp(device, DPDK_PREFIX, prefix_len)) { // check prefix dpdk:
		return ret;
	}
	//check all chars are digital
	for(int i=prefix_len; device[i]; i++) {
		if(device[i]<'0' || device[i]>'9') {
			return ret;
		}
	}
	ret_ul = strtoul(&(device[prefix_len]), &pEnd, 10);
	if(pEnd == &(device[prefix_len]) || *pEnd != '\0') {
		return ret;
	}
	// too large for portid
	if(ret_ul >= DPDK_PORTID_MAX) {
		return ret;
	}
	ret = (uint16_t)ret_ul;
	return ret;
}


#if DPDK_ENV_CFG
static int parse_dpdk_cfg(char* dpdk_cfg,char** dargv) {
	int cnt=0;
	memset(dargv,0,sizeof(dargv[0])*DPDK_ARGC_MAX);
	//current process name
	int skip_space = 1;
	int i=0;
	syslog(LOG_INFO, "dpdk cfg: %s\n", dpdk_cfg);
	// find first non space char
	// The last opt is NULL
	for(i=0;dpdk_cfg[i] && cnt<DPDK_ARGC_MAX-1;i++) {
		if(skip_space && dpdk_cfg[i]!=' ') { // not space
			skip_space=!skip_space; // skip normal char
			dargv[cnt++] = dpdk_cfg+i;
		}
		if(!skip_space && dpdk_cfg[i]==' ') { // fint a space
			dpdk_cfg[i]=0x00; // end of this opt
			skip_space=!skip_space; // skip space char
		}
	}
	dargv[cnt]=NULL;
	return cnt;
}
#endif


static void dpdk_eval_res(int res_no, const char *cust_error,
			  int syslog_print, // 1 - if error, 2 - all
			  string *error_str,
			  const char *fmt, ...) {
	char fmt_str[1024 * 8];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(fmt_str, sizeof(fmt_str), fmt, ap);
	va_end(ap);
	string _error_str = res_no < 0 || cust_error ? "DPDK ERROR" : "DPDK";
	_error_str += " - ";
	_error_str += fmt_str;
	if(res_no < 0 || cust_error) {
		_error_str += string(" - ERROR: ") + 
			      (cust_error ?
				cust_error :
				string(rte_strerror(rte_errno)) + 
				" (" + 
				(-res_no != rte_errno ? "r:" + intToString(res_no) + "/" : "") + 
				"e:" + intToString(rte_errno) + 
				")");
	} else {
		_error_str += " - OK (" + intToString(res_no) + ")";
	}
	if(syslog_print == 2 || (syslog_print == 1 && (res_no < 0 || cust_error))) {
		syslog(res_no < 0 || cust_error ? LOG_ERR : LOG_INFO, "%s", _error_str.c_str());
	}
	if((res_no < 0 || cust_error) && error_str) {
		*error_str = _error_str;
	}
}


static int dpdk_init_timer(sDpdk *dpdk, bool use_lock) {
	int rslt = 0;
	if(use_lock) rte_spinlock_lock(&dpdk->ts_helper_lock);
	dpdk->ts_helper.start_time = getTimeUS();
	dpdk->ts_helper.start_cycles = rte_get_timer_cycles();
	dpdk->ts_helper.hz = rte_get_timer_hz();
	if(dpdk->ts_helper.hz == 0) {
		rslt = -1;
	}
	if(sverb.dpdk_timer) {
		syslog(LOG_NOTICE, 
		       "DPDK TIMER: " 
		       "start_time: %" int_64_format_prefix "lu, "
		       "start_cycles: %" int_64_format_prefix "lu, "
		       "hz: %" int_64_format_prefix "lu",
		       dpdk->ts_helper.start_time,
		       dpdk->ts_helper.start_cycles,
		       dpdk->ts_helper.hz);
	}
	if(use_lock) rte_spinlock_unlock(&dpdk->ts_helper_lock);
	return(rslt);
}


static void eth_addr_str(ETHER_ADDR_TYPE *addrp, char* mac_str, int len) {
	int offset=0;
	if(addrp == NULL) {
		snprintf(mac_str, len-1, DPDK_DEF_MAC_ADDR);
		return;
	}
	for(int i=0; i<6; i++) {
		if(offset >= len) { // buffer overflow
			return;
		}
		if(i==0) {
			snprintf(mac_str+offset, len-1-offset, "%02X",addrp->addr_bytes[i]);
			offset+=2; // FF
		} else {
			snprintf(mac_str+offset, len-1-offset, ":%02X", addrp->addr_bytes[i]);
			offset+=3; // :FF
		}
	}
	return;
}


static int check_link_status(uint16_t portid, struct rte_eth_link *plink) {
	// wait up to 9 seconds to get link status
	rte_eth_link_get(portid, plink);
	return plink->link_status == RTE_ETH_LINK_UP;
}


cDpdkTools::cDpdkTools() {
	init();
	_sync_lcore = 0;
}

void cDpdkTools::init() {
	main_thread_lcore = -1;
	read_lcores.clear();
	worker_lcores.clear();
	worker2_lcores.clear();
	string dpdk_read_thread_lcore = opt_dpdk_read_thread_lcore;
	string dpdk_worker_thread_lcore = opt_dpdk_worker_thread_lcore;
	string dpdk_worker2_thread_lcore = opt_dpdk_worker2_thread_lcore;
	if(opt_dpdk_read_thread_lcore.empty() && opt_dpdk_worker_thread_lcore.empty() && opt_dpdk_worker2_thread_lcore.empty()) {
		cGlobalDpdkTools::getThreadsAffinity(&dpdk_read_thread_lcore, &dpdk_worker_thread_lcore, &dpdk_worker2_thread_lcore);
	}
	vector<string> read_lcores_str = split(dpdk_read_thread_lcore.c_str(), ",", true);
	for(unsigned i = 0; i < read_lcores_str.size(); i++) {
		read_lcores[atoi(read_lcores_str[i].c_str())] = true;
	}
	vector<string> worker_lcores_str = split(dpdk_worker_thread_lcore.c_str(), ",", true);
	for(unsigned i = 0; i < worker_lcores_str.size(); i++) {
		worker_lcores[atoi(worker_lcores_str[i].c_str())] = true;
	}
	vector<string> worker2_lcores_str = split(dpdk_worker2_thread_lcore.c_str(), ",", true);
	for(unsigned i = 0; i < worker2_lcores_str.size(); i++) {
		worker2_lcores[atoi(worker2_lcores_str[i].c_str())] = true;
	}
	setLCoresMap();
	lcores_map.clear();
	if(!lcores_map_str.empty() ||
	   !opt_dpdk_cpu_cores_map.empty()) {
		string lcores_map_str_tmp = !lcores_map_str.empty() ? lcores_map_str : opt_dpdk_cpu_cores_map;
		int pos[2] = { 0 , 0 };
		int length = lcores_map_str_tmp.length();
		int bracketCounter = 0;
		while(pos[0] < length) {
			pos[1] = pos[0];
			while(pos[1] < length) {
				if(lcores_map_str_tmp[pos[1]] == ',' && !bracketCounter) {
					break;
				} else if(lcores_map_str_tmp[pos[1]] == '(') {
					++bracketCounter;
				} else if(lcores_map_str_tmp[pos[1]] == ')') {
					--bracketCounter;
				}
				++pos[1];
			}
			if(pos[1] > pos[0] + 1) {
				string map_item = lcores_map_str_tmp.substr(pos[0], pos[1] - pos[0]);
				size_t posSep = map_item.find('@');
				if(posSep != string::npos) {
					string lc = map_item.substr(0, posSep);
					string c = map_item.substr(posSep + 1);
					vector<int> lcv;
					list<int> cl;
					get_list_cores(lc, lcv);
					get_list_cores(c, cl);
					if(lcv.size() && cl.size()) {
						for(unsigned i = 0; i < lcv.size(); i++) {
							lcores_map[lcv[i]] = cl;
						}
					}
				}
			}
			pos[0] = pos[1] + 1;
		}
	}
}

void cDpdkTools::setLCoresMap() {
	if(!(opt_dpdk_cpu_cores.empty() &&
	     opt_dpdk_cpu_cores_map.empty() &&
	     read_lcores.size())) {
		return;
	}
	int count_cores = sysconf(_SC_NPROCESSORS_ONLN);
	map<int, list<int> > cores_used;
	int lcore_id = 0;
	for(int i = 0; i < 3; i++) {
		map<int, bool> *map_src_lcores = i == 0 ? &read_lcores :
						 i == 1 ? &worker_lcores :
							  &worker2_lcores;
		for(map<int, bool>::iterator iter = map_src_lcores->begin(); iter != map_src_lcores->end(); iter++) {
			int core = iter->first;
			int lcore = lcore_id++;
			cores_used[core].push_back(lcore);
		}
	}
	int main_thread_core = -1;
	if(opt_dpdk_main_thread_lcore < 0) {
		for(int i = 0; i < count_cores; i++) {
			if(cores_used.find(i) == cores_used.end()) {
				main_thread_core = i;
				break;
			}
		}
	} else {
		main_thread_core = opt_dpdk_main_thread_lcore;
	}
	if(main_thread_core >= 0) {
		int lcore = lcore_id++;
		cores_used[main_thread_core].push_back(lcore);
	}
	lcore_id = 0;
	for(int i = 0; i < 3; i++) {
		map<int, bool> *map_src_lcores = i == 0 ? &read_lcores :
						 i == 1 ? &worker_lcores :
							  &worker2_lcores;
		unsigned size = map_src_lcores->size();
		map_src_lcores->clear();
		for(unsigned i = 0; i < size; i++) {
			(*map_src_lcores)[lcore_id] = true;
			++lcore_id;
		}
	}
	if(main_thread_core >= 0) {
		main_thread_lcore = lcore_id;
	}
	lcores_map_str = "";
	for(map<int, list<int> >::iterator iter = cores_used.begin(); iter != cores_used.end(); iter++) {
		string lcores;
		for(list<int>::iterator iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++) {
			if(!lcores.empty()) {
				lcores += ",";
			}
			lcores += intToString(*iter2);
		}
		if(!lcores_map_str.empty()) {
			lcores_map_str += ",";
		}
		lcores_map_str += "(" + lcores + ")@" + intToString(iter->first);
	}
}

int cDpdkTools::getFreeLcore(eTypeLcore type, int numa_node) {
	__SYNC_LOCK(_sync_lcore);
	int lcore_id = -1;
	switch(type) {
	case _tlc_read:
		lcore_id = getFreeLcore(read_lcores, numa_node);
		break;
	case _tlc_worker:
		lcore_id = getFreeLcore(worker_lcores, numa_node);
		break;
	case _tlc_worker2:
		lcore_id = getFreeLcore(worker2_lcores, numa_node);
		break;
	}
	if(lcore_id == -1) {
		int main_lcore_id = rte_get_main_lcore();
		for(int i = RTE_MAX_LCORE - 1; i >= 0; i--) {
			if(rte_lcore_is_enabled(i) && 
			   i != main_lcore_id && 
			   !lcoreIsUsed(i) &&
			   !lcoreIsInAny(i)) {
				lcore_id = i;
				break;
			}
		}
	}
	__SYNC_UNLOCK(_sync_lcore);
	return(lcore_id);
}

void cDpdkTools::setUseLcore(int lcore) {
	__SYNC_LOCK(_sync_lcore);
	used_lcores[lcore] = true;
	__SYNC_UNLOCK(_sync_lcore);
}

void cDpdkTools::setFreeLcore(int lcore) {
	__SYNC_LOCK(_sync_lcore);
	map<int, bool>::iterator iter = used_lcores.find(lcore);
	if(iter != used_lcores.end()) {
		used_lcores.erase(iter);
	}
	__SYNC_UNLOCK(_sync_lcore);
}

string cDpdkTools::getAllCores(bool without_main, bool detect_ht) {
	map<int, bool> all;
	if(!without_main && getMainThreadLcore() >= 0) {
		if(lcores_map.size()) {
			map<int, list<int> >::iterator iter = lcores_map.find(getMainThreadLcore());
			if(iter != lcores_map.end()) {
				for(list<int>::iterator iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++) {
					all[*iter2] = true;
				}
			}
		} else {
			all[getMainThreadLcore()] = true;
		}
	}
	for(int i = 0; i < 3; i++) {
		map<int, bool> *map_src_lcores = i == 0 ? &read_lcores :
						 i == 1 ? &worker_lcores :
							  &worker2_lcores;
		for(map<int, bool>::iterator iter = map_src_lcores->begin(); iter != map_src_lcores->end(); iter++) {
			if(lcores_map.size()) {
				map<int, list<int> >::iterator iter2 = lcores_map.find(iter->first);
				if(iter2 != lcores_map.end()) {
					for(list<int>::iterator iter3 = iter2->second.begin(); iter3 != iter2->second.end(); iter3++) {
						all[*iter3] = true;
					}
				}
			} else {
				all[iter->first] = true;
			}
		}
	}
	if(detect_ht) {
		cCpuCoreInfo cpu_core_info;
		if(cpu_core_info.ok_loaded()) {
			map<int, bool> all_with_ht;
			for(map<int, bool>::iterator iter = all.begin(); iter != all.end(); iter++) {
				vector<int> ht_cpus;
				if(cpu_core_info.getHT_cpus(iter->first, &ht_cpus)) {
					for(unsigned i = 0; i < ht_cpus.size(); i++) {
						all_with_ht[ht_cpus[i]] = true;
					}
				}
			}
			all = all_with_ht;
		}
	}
	string all_str;
	for(map<int, bool>::iterator iter = all.begin(); iter != all.end(); iter++) {
		if(!all_str.empty()) {
			all_str += ",";
		}
		all_str += intToString(iter->first);
	}
	return(all_str);
}

string cDpdkTools::getCoresMap() {
	return(!lcores_map_str.empty() ? lcores_map_str : opt_dpdk_cpu_cores_map);
}

int cDpdkTools::getMainThreadLcore() {
	return(main_thread_lcore >= 0 ? main_thread_lcore  : opt_dpdk_main_thread_lcore);
}

void cDpdkTools::getCoresForLcore(int lcore, list<int> *cores) {
	map<int, list<int> >::iterator iter = lcores_map.find(lcore);
	if(iter != lcores_map.end()) {
		*cores = iter->second;
	} else {
		cores->clear();
	}
}

string cDpdkTools::getCoresForLcore(int lcore) {
	list<int> cores;
	getCoresForLcore(lcore, &cores);
	if(cores.size()) {
		return(implode(cores, ","));
	} else {
		return("");
	}
}

int cDpdkTools::getFreeLcore(map<int, bool> &main_map, int numa_node) {
	bool check_numa_node = numa_node >= 0 && opt_dpdk_cpu_cores_map.empty();
	int main_lcore_id = rte_get_main_lcore();
	for(int pass = 0; pass < (check_numa_node ? 2 : 1); pass++) {
		for(map<int, bool>::iterator iter = main_map.begin(); iter != main_map.end(); iter++) {
			if(rte_lcore_is_enabled(iter->first) && 
			   iter->first != main_lcore_id && 
			   !lcoreIsUsed(iter->first)) {
				if(pass == 0 && check_numa_node) {
					cCpuCoreInfo coreInfo;
					cCpuCoreInfo::sCpuCoreInfo *cpu = coreInfo.get(iter->first);
					if(cpu && cpu->Node == numa_node) {
						return(iter->first);
					}
				} else {
					return(iter->first);
				}
			}
		}
	}
	return(-1);
}

bool cDpdkTools::lcoreIsUsed(int lcore) {
	return(used_lcores.find(lcore) != used_lcores.end());
}

bool cDpdkTools::lcoreIsInAny(int lcore) {
	return(read_lcores.find(lcore) != read_lcores.end() ||
	       worker_lcores.find(lcore) != worker_lcores.end() ||
	       worker2_lcores.find(lcore) != worker2_lcores.end());
}


u_char *dpdk_mbuf_to_packet(void *mbuf) {
	void *rslt = rte_pktmbuf_mtod((rte_mbuf*)mbuf, void*);
	rte_prefetch0(rslt);
	return((u_char*)rslt);
}


void dpdk_mbuf_free(void *mbuf) {
	rte_pktmbuf_free((rte_mbuf*)mbuf);
}


void dpdk_memcpy(void *dst, void *src, size_t size) {
	rte_memcpy(dst, src, size);
}

void dpdk_check_configuration() {
	if(!opt_dpdk_cpu_cores.empty() ||
	   !opt_dpdk_cpu_cores_map.empty()) {
		return;
	}
	map<int, bool> cores;
	if(!opt_dpdk_read_thread_lcore.empty()) {
		vector<string> read_cores_str = split(opt_dpdk_read_thread_lcore.c_str(), ",", true);
		for(unsigned i = 0; i < read_cores_str.size(); i++) {
			cores[atoi(read_cores_str[i].c_str())] = true;
		}
	}
	if(!opt_dpdk_worker_thread_lcore.empty()) {
		vector<string> worker_cores_str = split(opt_dpdk_worker_thread_lcore.c_str(), ",", true);
		for(unsigned i = 0; i < worker_cores_str.size(); i++) {
			cores[atoi(worker_cores_str[i].c_str())] = true;
		}
	}
	if(!opt_dpdk_worker2_thread_lcore.empty()) {
		vector<string> worker2_cores_str = split(opt_dpdk_worker2_thread_lcore.c_str(), ",", true);
		for(unsigned i = 0; i < worker2_cores_str.size(); i++) {
			cores[atoi(worker2_cores_str[i].c_str())] = true;
		}
	}
	if(cores.size() > 1) {
		cCpuCoreInfo cpu_core_info;
		if(cpu_core_info.ok_loaded()) {
			cCpuCoreInfo::sCpuCoreInfo *first_core = NULL;
			int first_ht_index = -1;
			int counter = 0;
			bool bad_combination_ht = false;
			bool bad_combination_socket = false;
			bool bad_combination_node = false;
			for(map<int, bool>::iterator iter = cores.begin(); iter != cores.end(); iter++) {
				cCpuCoreInfo::sCpuCoreInfo *core = cpu_core_info.get(iter->first);
				int ht_index = cpu_core_info.getHT_index(iter->first);
				if(ht_index < 0 || !core) {
					syslog(LOG_ERR, "DPDK error: unable to find information on core %i", iter->first);
					continue;
				}
				if(counter == 0) {
					first_core = core;
					first_ht_index = ht_index;
				} else {
					if(core->Socket != first_core->Socket) {
						bad_combination_socket = true;
					}
					if(core->Node != first_core->Node) {
						bad_combination_node = true;
					}
					if(ht_index != first_ht_index) {
						bad_combination_ht = true;
					}
				}
				++counter;
			}
			if(bad_combination_ht) {
				syslog(LOG_WARNING, "DPDK warning: You have chosen combinations of real and HT CPU cores. This may cause performance limitations.");
			}
			if(bad_combination_socket) {
				syslog(LOG_WARNING, "DPDK warning: You have chosen combinations of CPU cores from different sockets. This may cause performance limitations.");
			}
			if(bad_combination_node) {
				syslog(LOG_WARNING, "DPDK warning: You have chosen combinations of CPU cores from different nodes. This may cause performance limitations.");
			}
		}
	}
}

void dpdk_check_affinity() {
	extern bool opt_thread_affinity_ht;
	extern bool opt_other_thread_affinity_check;
	extern bool opt_other_thread_affinity_set;
	if(!opt_other_thread_affinity_check) {
		return;
	}
	int check_period_s = 60;
	static u_int32_t last_check_s = 0;
	uint32_t act_time_s = getTimeS_rdtsc();
	if(!last_check_s) {
		last_check_s = act_time_s;
		return;
	}
	if(last_check_s + check_period_s < act_time_s) {
		string dpdk_cpu_cores_str = get_dpdk_cpu_cores(true, opt_thread_affinity_ht);
		vector<int> dpdk_cpu_cores;
		get_list_cores(dpdk_cpu_cores_str, dpdk_cpu_cores);
		setAffinityForOtherProcesses(&dpdk_cpu_cores, !opt_other_thread_affinity_set, true, "DPDK warning: ", true);
		last_check_s = act_time_s;
	}
}

void init_dpdk() {
	dpdk_tools = new cDpdkTools();
}

void term_dpdk() {
	delete dpdk_tools;
}

#else //HAVE_LIBDPDK


#define ENABLE_WORKER_SLAVE false


struct sDpdk {
	sDpdkConfig config;
};

sDpdkHandle *create_dpdk_handle() {
	return(NULL);
}

void destroy_dpdk_handle(sDpdkHandle *dpdk) {
}

int dpdk_activate(sDpdkConfig *config, sDpdk *dpdk, std::string *error) {
	if(error) {
		*error = "DPDK ERROR - dpdk is not supported in your build";
	}
	return(-1);
}

unsigned get_planned_memory_consumption_mb(string *log) {
	return(0);
}

int dpdk_do_pre_init(std::string *error) {
	if(error) {
		*error = "DPDK ERROR - dpdk is not supported in your build";
	}
	return(-1);
}

void dpdk_set_initialized(sDpdkHandle *dpdk) {
}

void dpdk_reset_statistics(sDpdkHandle *dpdk, bool flush_buffer) {
}

int dpdk_read_proc(sDpdk *dpdk) {
	return(0);
}

int dpdk_worker_proc(sDpdk *dpdk) {
	return(0);
}

int pcap_dpdk_stats(sDpdk *dpdk, pcap_stat *ps, string *str_out) {
	return(0);
}

sDpdkConfig *dpdk_config(sDpdk *dpdk) {
	return(&dpdk->config);
}

void dpdk_terminating(sDpdk *dpdk) {
}

void dpdk_check_params() {
}

u_int16_t count_rte_read_threads() {
	return(1);
}

double rte_read_thread_cpu_usage(sDpdk *dpdk, u_int16_t rte_read_thread_id) {
	return(-1);
}

double rte_worker_thread_cpu_usage(sDpdk *dpdk) {
	return(-1);
}

double rte_worker_slave_thread_cpu_usage(sDpdk *dpdk) {
	return(-1);
}

double rte_worker2_thread_cpu_usage(sDpdk *dpdk) {
	return(-1);
}

string get_dpdk_cpu_cores(bool without_main, bool detect_ht) {
	return("");
}

u_char *dpdk_mbuf_to_packet(void *mbuf) {
	return(NULL);
}

void dpdk_mbuf_free(void *mbuf) {
}

void dpdk_memcpy(void *dst, void *src, size_t size) {
	memcpy(dst, src, size);
}

void dpdk_check_configuration() {
}

void dpdk_check_affinity() {
}

void init_dpdk() {
}

void term_dpdk() {
}


#endif //HAVE_LIBDPDK


void cGlobalDpdkTools::getPlannedMemoryConsumptionByNumaNodes(map<unsigned, unsigned> *pmc) {
	map<unsigned, unsigned> ci;
	getCountInterfacesByNumaNodes(&ci);
	if(ci.size()) {
		string mc_log;
		unsigned mc = get_planned_memory_consumption_mb(&mc_log);
		syslog(LOG_INFO, "DPDK - planned memory consumption per interface: %s", mc_log.c_str());
		for(map<unsigned, unsigned>::iterator iter = ci.begin(); iter != ci.end(); iter++) {
			(*pmc)[iter->first] = mc * iter->second;
		}
	}
}

void cGlobalDpdkTools::getCountInterfacesByNumaNodes(map<unsigned, unsigned> *ci) {
	extern vector<string> opt_dpdk_vdev;
	vector<string> ports;
	getPorts(&ports);
	if(ports.size() > 0) {
		for(unsigned i = 0; i < ports.size(); i++) {
			int numa_node = getNumaNodeForPciDevice(ports[i].c_str());
			if(numa_node >= 0) {
				(*ci)[numa_node]++;
			} else {
				(*ci)[0]++;
			}
		}
	} else if(opt_dpdk_vdev.size()) {
		(*ci)[0] = opt_dpdk_vdev.size();
	}
}

void cGlobalDpdkTools::getPorts(vector<string> *ports) {
	extern string opt_dpdk_pci_device;
	*ports = split(opt_dpdk_pci_device.c_str(), split(",|;| |\t|\r|\n", "|"), true);
}

bool cGlobalDpdkTools::setHugePages() {
	bool rslt = true;
	map<unsigned, unsigned> pmc;
	getPlannedMemoryConsumptionByNumaNodes(&pmc);
	if(pmc.size()) {
		unsigned hugePageSize_kB = cHugePagesTools::getHugePageSize_kB();
		if(!hugePageSize_kB) {
			return(false);
		}
		for(map<unsigned, unsigned>::iterator iter = pmc.begin(); iter != pmc.end(); iter++) {
			unsigned hp_number = iter->second * 1024 / hugePageSize_kB * 1.5;
			if(!cHugePagesTools::setHugePagesNumber(hp_number, true, iter->first, false,hugePageSize_kB)) {
				rslt = false;
			}
		}
	}
	return(rslt);
}

bool cGlobalDpdkTools::setThreadsAffinity(string *read, string *worker, string *worker2) {
	map<unsigned, unsigned> ci;
	getCountInterfacesByNumaNodes(&ci);
	if(!ci.size()) {
		return(true);
	}
	extern int opt_dpdk_read_thread;
	extern int opt_dpdk_worker_thread;
	extern int opt_dpdk_worker2_thread;
	list<unsigned> read_affinity;
	list<unsigned> worker_affinity;
	list<unsigned> worker2_affinity;
	cCpuCoreInfo coreInfo;
	bool rslt = true;
	for(map<unsigned, unsigned>::iterator iter = ci.begin(); iter != ci.end() && rslt; iter++) {
		if(opt_dpdk_read_thread == _dpdk_trt_rte) {
			for(unsigned i = 0; i < iter->second && rslt; i++) {
				for(unsigned j = 0; j < count_rte_read_threads(); j++) {
					int cpu = coreInfo.getFreeCpu(iter->first, true);
					if(cpu >= 0) {
						read_affinity.push_back(cpu);
					} else {
						rslt = false;
					}
				}
			}
		}
		if(opt_dpdk_worker_thread == _dpdk_trt_rte) {
			for(unsigned i = 0; i < iter->second && rslt; i++) {
				for(unsigned j = 0; j < (ENABLE_WORKER_SLAVE ? 2 : 1) && rslt; j++) {
					int cpu = coreInfo.getFreeCpu(iter->first, true);
					if(cpu >= 0) {
						worker_affinity.push_back(cpu);
					} else {
						rslt = false;
					}
				}
			}
		}
		if(opt_dpdk_worker2_thread == _dpdk_trt_rte) {
			for(unsigned i = 0; i < iter->second && rslt; i++) {
				int cpu = coreInfo.getFreeCpu(iter->first, true);
				if(cpu >= 0) {
					worker2_affinity.push_back(cpu);
				} else {
					rslt = false;
				}
			}
		}
	}
	if(rslt) {
		*read = implode(&read_affinity, ",");
		*worker = implode(&worker_affinity, ",");
		*worker2 = implode(&worker2_affinity, ",");
	}
	return(rslt);
}

bool cGlobalDpdkTools::setThreadsAffinity() {
	return(setThreadsAffinity(&dpdk_read_thread_lcore, &dpdk_worker_thread_lcore, &dpdk_worker2_thread_lcore));
}

void cGlobalDpdkTools::getThreadsAffinity(string *read, string *worker, string *worker2) {
	*read = dpdk_read_thread_lcore;
	*worker = dpdk_worker_thread_lcore;
	*worker2 = dpdk_worker2_thread_lcore;
}

void cGlobalDpdkTools::clearThreadsAffinity() {
	dpdk_read_thread_lcore.clear();
	dpdk_worker_thread_lcore.clear();
	dpdk_worker2_thread_lcore.clear();
}

unsigned cGlobalDpdkTools::get_planned_memory_consumption_mb(string *log) {
	u_int64_t memory_consumption_sum = 0;
#if HAVE_LIBDPDK
	// mbuf pool
	int dynfield_size = DPDK_TIMESTAMP_IN_MBUF == 1 ? sizeof(u_int64_t) : 0;
	size_t mbuf_size = sizeof(struct rte_mbuf) + DPDK_MBUF_SIZE + dynfield_size;
	size_t memory_consumption_mbuf_pool = DPDK_NB_MBUFS * (mbuf_size + sizeof(struct rte_mempool_objhdr)) + MEMPOOL_CACHE_SIZE * sizeof(void*);
	memory_consumption_sum += memory_consumption_mbuf_pool;
	if(log) {
		*log += "mbuf pool: " + intToString(memory_consumption_mbuf_pool / 1024 / 1024) + "MB; ";
	}
	// rx & tx queue
	extern int opt_dpdk_nb_rx;
	extern int opt_dpdk_nb_tx;
	extern int opt_dpdk_nb_rxq;
	u_int64_t memory_consumption_rx_tx_queue = (opt_dpdk_nb_rx * max(opt_dpdk_nb_rxq, 1) + opt_dpdk_nb_tx) * 64;
	memory_consumption_sum += memory_consumption_rx_tx_queue;
	if(log) {
		*log += "rx & tx queue: " + intToString(memory_consumption_rx_tx_queue / 1024 / 1024) + "MB; ";
	}
	// tx buffer
	u_int64_t memory_consumption_tx_buffer = RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST);
	memory_consumption_sum += memory_consumption_tx_buffer;
	if(log) {
		*log += "tx buffer: " + intToString(memory_consumption_tx_buffer / 1024 / 1024) + "MB; ";
	}
	// ring buffer for worker thread
	extern int opt_dpdk_worker_thread;
	if(opt_dpdk_worker_thread == 2) {
		u_int64_t memory_consumption_ring_buffer_worker_thread = RING_SIZE * 8;
		memory_consumption_sum += memory_consumption_ring_buffer_worker_thread;
		if(log) {
			*log += "ring buffer for worker thread: " + intToString(memory_consumption_ring_buffer_worker_thread / 1024 / 1024) + "MB; ";
		}
	}
	#if WORKER2_THREAD_SUPPORT
	// ring buffer for worker2 thread
	extern int opt_dpdk_worker2_thread;
	if(opt_dpdk_worker2_thread == 2) {
		u_int64_t memory_consumption_ring_buffer_worker2_thread = RING_SIZE * 8;
		memory_consumption_sum += memory_consumption_ring_buffer_worker2_thread;
		if(log) {
			*log += "ring buffer for worker2 thread: " + intToString(memory_consumption_ring_buffer_worker2_thread / 1024 / 1024) + "MB; ";
		}
	}
	#endif
	*log += "SUM: " + intToString(memory_consumption_sum / 1024 / 1024) + "MB";
#endif
	return(memory_consumption_sum / 1024 / 1024);
}

string cGlobalDpdkTools::dpdk_read_thread_lcore;
string cGlobalDpdkTools::dpdk_worker_thread_lcore;
string cGlobalDpdkTools::dpdk_worker2_thread_lcore;
