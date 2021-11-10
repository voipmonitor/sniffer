#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/resource.h>
#include <string.h>

#include "pstat.h"
#include "tools_global.h"
#include "sync.h"

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


extern string opt_dpdk_cpu_cores;
extern string opt_dpdk_cpu_cores_map;
extern int opt_dpdk_main_thread_lcore;
extern string opt_dpdk_read_thread_lcore;
extern string opt_dpdk_worker_thread_lcore;
extern string opt_dpdk_worker2_thread_lcore;
extern int opt_dpdk_memory_channels;
extern string opt_dpdk_pci_device;
extern int opt_dpdk_force_max_simd_bitwidth;
extern int opt_dpdk_nb_mbufs;
extern int opt_dpdk_pkt_burst;
extern int opt_dpdk_ring_size;
extern int opt_dpdk_mempool_cache_size;
extern int opt_dpdk_batch_read;
extern int opt_dpdk_mbufs_in_packetbuffer;


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
#define DPDK_NB_MBUFS ((opt_dpdk_nb_mbufs ? opt_dpdk_nb_mbufs : 1024) * 1024)
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

#define DEBUG_CYCLES false
#define DEBUG_CYCLES_MAX_LT_MS 100
#define DEBUG_EXT_STAT false


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
	uint64_t start_time;
	uint64_t start_cycles;
	uint64_t hz;
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
	int getFreeLcore(eTypeLcore type);
	void setUseLcore(int lcore);
	void setFreeLcore(int lcore);
	string getAllCores(bool without_main);
	string getCoresMap();
	int getMainThreadLcore();
private:
	int getFreeLcore(map<int, bool> &main_map);
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
	int rte_read_thread_pid;
	int rte_worker_thread_pid;
	#if WORKER2_THREAD_SUPPORT
	int rte_worker2_thread_pid;
	#endif
	pstat_data rte_read_thread_pstat_data[2];
	pstat_data rte_worker_thread_pstat_data[2];
	#if WORKER2_THREAD_SUPPORT
	pstat_data rte_worker2_thread_pstat_data[2];
	#endif
	volatile bool initialized;
	#if DEBUG_CYCLES
	sDpdk_cycles cycles[10];
	#endif
	bool cycles_reset;
	cDpdkTools *tools;
	sDpdk() {
		memset((void*)this, 0, sizeof(*this));
		tools = new cDpdkTools();
	}
	~sDpdk() {
		delete tools;
	}
};


static int rte_read_thread(void *arg);
static int rte_worker_thread(void *arg);
#if WORKER2_THREAD_SUPPORT
static int rte_worker2_thread(void *arg);
#endif
static inline uint32_t dpdk_gather_data(unsigned char *data, uint32_t len, struct rte_mbuf *mbuf);
static inline void dpdk_process_packet(sDpdk *dpdk, rte_mbuf *mbuff, u_int64_t timestamp_us);
static inline void dpdk_process_packet_2__std(sDpdk *dpdk, rte_mbuf *mbuff, u_int64_t timestamp_us
					      #if WORKER2_THREAD_SUPPORT
					      ,bool free_mbuff
					      #endif
					      );
static inline void dpdk_process_packet_2__mbufs_in_packetbuffer(sDpdk *dpdk, rte_mbuf *mbuff, u_int64_t timestamp_us
								#if WORKER2_THREAD_SUPPORT
								,bool free_mbuff
								#endif
								);
static inline u_int64_t get_timestamp_us(sDpdk *dpdk);
static int dpdk_pre_init(char * ebuf, int eaccess_not_fatal);
static uint16_t portid_by_device(const char * device);
#if DPDK_ENV_CFG
static int parse_dpdk_cfg(char* dpdk_cfg,char** dargv);
#endif
static void dpdk_fmt_errmsg_for_rte_errno(char *errbuf, size_t errbuflen, int errnum, const char *fmt, ...);
static int dpdk_init_timer(sDpdk *dpdk);
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


sDpdkHandle *create_dpdk_handle() {
	return(new sDpdk);
}


void destroy_dpdk_handle(sDpdkHandle *dpdk) {
	if(dpdk->must_clear_promisc) {
		rte_eth_promiscuous_disable(dpdk->portid);
	}
	rte_eth_dev_stop(dpdk->portid);
	rte_eth_dev_close(dpdk->portid);
	delete dpdk;
}


int dpdk_activate(sDpdkConfig *config, sDpdk *dpdk, std::string *error) {
	int ret = PCAP_ERROR;
	uint16_t nb_ports = 0;
	uint16_t portid = DPDK_PORTID_MAX;
	unsigned nb_mbufs = DPDK_NB_MBUFS;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	port_conf.rxmode.split_hdr_size = 0;
	port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
	struct rte_eth_conf local_port_conf = port_conf;
	struct rte_eth_dev_info dev_info;
	int is_port_up = 0;
	struct rte_eth_link link;
	char errbuf[PCAP_ERRBUF_SIZE * 2 + 1];
	do {
		//init EAL; fail if we have insufficient permission
		char dpdk_pre_init_errbuf[PCAP_ERRBUF_SIZE + 1];
		int is_dpdk_pre_inited_old = is_dpdk_pre_inited;
		ret = dpdk_pre_init(dpdk_pre_init_errbuf, 0);
		if(ret > 0 && is_dpdk_pre_inited_old <= 0 && is_dpdk_pre_inited > 0) {
			config->init_in_activate = true;
		}
		if(ret < 0) {
			// This returns a negative value on an error.
			snprintf(errbuf, PCAP_ERRBUF_SIZE * 2 + 1,
				 "Can't open device %s: %s",
				 config->device, dpdk_pre_init_errbuf);
			*error = errbuf;
			// ret is set to the correct error
			break;
		}
		if(ret == 0) {
			// This means DPDK isn't available on this machine.
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
				 "Can't open device %s: DPDK is not available on this machine",
				 config->device);
			*error = errbuf;
			return PCAP_ERROR_NO_SUCH_DEVICE;
		}
		ret = dpdk_init_timer(dpdk);
		if(ret<0) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
				 "dpdk error: Init timer is zero with device %s",
				 config->device);
			*error = errbuf;
			ret = PCAP_ERROR;
			break;
		}
		nb_ports = rte_eth_dev_count_avail();
		if(nb_ports == 0) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
				 "dpdk error: No Ethernet ports");
			*error = errbuf;
			ret = PCAP_ERROR;
			break;
		}
		portid = portid_by_device(config->device);
		if(portid == DPDK_PORTID_MAX) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
				 "dpdk error: portid is invalid. device %s",
				 config->device);
			*error = errbuf;
			ret = PCAP_ERROR_NO_SUCH_DEVICE;
			break;
		}
		dpdk->portid = portid;
		if(config->snapshot <= 0 || config->snapshot > MAXIMUM_SNAPLEN) {
			config->snapshot = MAXIMUM_SNAPLEN;
		}
		// create the mbuf pool
		dpdk->pktmbuf_pool = rte_pktmbuf_pool_create((string(MBUF_POOL_NAME) + "_" + config->device).c_str(), nb_mbufs,
							     MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
							     rte_socket_id());
		if(dpdk->pktmbuf_pool == NULL) {
			dpdk_fmt_errmsg_for_rte_errno(errbuf,
						      PCAP_ERRBUF_SIZE, rte_errno,
						      "dpdk error: Cannot init mbuf pool");
			*error = errbuf;
			ret = PCAP_ERROR;
			break;
		}
		// config dev
		rte_eth_dev_info_get(portid, &dev_info);
		if(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE) {
			local_port_conf.txmode.offloads |=DEV_TX_OFFLOAD_MBUF_FAST_FREE;
		}
		// only support 1 queue
		ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
		if(ret < 0) {
			dpdk_fmt_errmsg_for_rte_errno(errbuf,
						      PCAP_ERRBUF_SIZE, -ret,
						      "dpdk error: Cannot configure device: port=%u",
						      portid);
			*error = errbuf;
			ret = PCAP_ERROR;
			break;
		}
		// adjust rx tx
		extern int opt_dpdk_nb_rx;
		extern int opt_dpdk_nb_tx;
		uint16_t nb_rx = opt_dpdk_nb_rx;
		uint16_t nb_tx = opt_dpdk_nb_tx;
		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rx, &nb_tx);
		if(ret < 0) {
			dpdk_fmt_errmsg_for_rte_errno(errbuf,
			    PCAP_ERRBUF_SIZE, -ret,
			    "dpdk error: Cannot adjust number of descriptors: port=%u",
			    portid);
			*error = errbuf;
			ret = PCAP_ERROR;
			break;
		}
		// get MAC addr
		rte_eth_macaddr_get(portid, &(dpdk->eth_addr));
		eth_addr_str(&(dpdk->eth_addr), dpdk->mac_addr, DPDK_MAC_ADDR_SIZE-1);
		// init one RX queue
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		rxq_conf.rx_free_thresh = MAX_PKT_BURST;
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rx,
					     rte_eth_dev_socket_id(portid),
					     &rxq_conf,
					     dpdk->pktmbuf_pool);
		if(ret < 0) {
			dpdk_fmt_errmsg_for_rte_errno(errbuf,
						      PCAP_ERRBUF_SIZE, -ret,
						      "dpdk error: rte_eth_rx_queue_setup:port=%u",
						      portid);
			*error = errbuf;
			ret = PCAP_ERROR;
			break;
		}
		// init one TX queue
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_tx,
				rte_eth_dev_socket_id(portid),
				&txq_conf);
		if(ret < 0) {
			dpdk_fmt_errmsg_for_rte_errno(errbuf,
						      PCAP_ERRBUF_SIZE, -ret,
						      "dpdk error: rte_eth_tx_queue_setup:port=%u",
						      portid);
			*error = errbuf;
			ret = PCAP_ERROR;
			break;
		}
		// Initialize TX buffers
		rte_eth_dev_tx_buffer *tx_buffer;
		tx_buffer = (rte_eth_dev_tx_buffer*)rte_zmalloc_socket(DPDK_TX_BUF_NAME,
								       RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
								       rte_eth_dev_socket_id(portid));
		if(tx_buffer == NULL) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "dpdk error: Cannot allocate buffer for tx on port %u", portid);
			*error = errbuf;
			ret = PCAP_ERROR;
			break;
		}
		rte_eth_tx_buffer_init(tx_buffer, MAX_PKT_BURST);
		if(config->type_worker_thread != _dpdk_twt_na) {
			dpdk->rx_to_worker_ring = rte_ring_create("rx_to_worker", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
			if(dpdk->rx_to_worker_ring == NULL) {
				dpdk_fmt_errmsg_for_rte_errno(errbuf,
							      PCAP_ERRBUF_SIZE, rte_errno,
							      "dpdk error: rte_ring_create/rx_to_worker:port=%u",
							      portid);
				*error = errbuf;
				ret = PCAP_ERROR;
				break;
			}
		}
		#if WORKER2_THREAD_SUPPORT
		if(config->type_worker_thread == _dpdk_twt_rte && config->type_worker2_thread == _dpdk_tw2t_rte) {
			dpdk->worker_to_worker2_ring = rte_ring_create("worker_to_worker2", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
			if(dpdk->rx_to_worker_ring == NULL) {
				dpdk_fmt_errmsg_for_rte_errno(errbuf,
							      PCAP_ERRBUF_SIZE, rte_errno,
							      "dpdk error: rte_ring_create/worker_to_worker2:port=%u",
							      portid);
				*error = errbuf;
				ret = PCAP_ERROR;
				break;
			}
		}
		#endif
		dpdk->config = *config;
		if(config->type_worker_thread == _dpdk_twt_rte) {
			int lcore_id = dpdk->tools->getFreeLcore(cDpdkTools::_tlc_worker);
			if(lcore_id < 0) {
				snprintf(errbuf, PCAP_ERRBUF_SIZE,
					 "dpdk error: not available free lcore for worker thread, port=%u",portid);
				*error = errbuf;
				ret = PCAP_ERROR;
				break;
			} else {
				ret = rte_eal_remote_launch(rte_worker_thread, dpdk, lcore_id);
				if(ret < 0) {
					dpdk_fmt_errmsg_for_rte_errno(errbuf,
								      PCAP_ERRBUF_SIZE, -ret,
								      "dpdk error: rte_eal_remote_launch/worker:port=%u",
								      portid);
					*error = errbuf;
					ret = PCAP_ERROR;
					break;
				}
				dpdk->tools->setUseLcore(lcore_id);
			}
		}
		#if WORKER2_THREAD_SUPPORT
		if(config->type_worker2_thread == _dpdk_tw2t_rte) {
			int lcore_id = dpdk->tools->getFreeLcore(cDpdkTools::_tlc_worker2);
			if(lcore_id < 0) {
				snprintf(errbuf, PCAP_ERRBUF_SIZE,
					 "dpdk error: not available free lcore for worker2 thread, port=%u",portid);
				*error = errbuf;
				ret = PCAP_ERROR;
				break;
			} else {
				ret = rte_eal_remote_launch(rte_worker2_thread, dpdk, lcore_id);
				if(ret < 0) {
					dpdk_fmt_errmsg_for_rte_errno(errbuf,
								      PCAP_ERRBUF_SIZE, -ret,
								      "dpdk error: rte_eal_remote_launch/worker2:port=%u",
								      portid);
					*error = errbuf;
					ret = PCAP_ERROR;
					break;
				}
				dpdk->tools->setUseLcore(lcore_id);
			}
		}
		#endif
		if(config->type_read_thread == _dpdk_trt_rte) {
			int lcore_id = dpdk->tools->getFreeLcore(cDpdkTools::_tlc_read);
			if(lcore_id < 0) {
				snprintf(errbuf, PCAP_ERRBUF_SIZE,
					 "dpdk error: not available free lcore for read thread, port=%u",portid);
				*error = errbuf;
				ret = PCAP_ERROR;
				break;
			} else {
				ret = rte_eal_remote_launch(rte_read_thread, dpdk, lcore_id);
				if(ret < 0) {
					dpdk_fmt_errmsg_for_rte_errno(errbuf,
								      PCAP_ERRBUF_SIZE, -ret,
								      "dpdk error: rte_eal_remote_launch/read:port=%u",
								      portid);
					*error = errbuf;
					ret = PCAP_ERROR;
					break;
				}
				dpdk->tools->setUseLcore(lcore_id);
			}
		}
		// Start device
		ret = rte_eth_dev_start(portid);
		if(ret < 0) {
			dpdk_fmt_errmsg_for_rte_errno(errbuf,
						      PCAP_ERRBUF_SIZE, -ret,
						      "dpdk error: rte_eth_dev_start:port=%u",
						      portid);
			*error = errbuf;
			ret = PCAP_ERROR;
			break;
		}
		// set promiscuous mode
		if(config->promisc) {
			dpdk->must_clear_promisc=1;
			rte_eth_promiscuous_enable(portid);
		}
		// check link status
		is_port_up = check_link_status(portid, &link);
		if(!is_port_up) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
				 "dpdk error: link is down, port=%u",portid);
			*error = errbuf;
			ret = PCAP_ERROR_IFACE_NOT_UP;
			break;
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
		ret = 0; // OK
	} while(0);
	if(ret <= PCAP_ERROR)  {
		/*
		pcap_cleanup_live_common(p);
		*/
	} else {
		rte_eth_dev_get_name_by_port(portid,dpdk->pci_addr);
		syslog(LOG_INFO, "Port %d device: %s, MAC:%s, PCI:%s\n", 
		       portid, config->device, dpdk->mac_addr, dpdk->pci_addr);
		syslog(LOG_INFO, "Port %d Link Up. Speed %u Mbps - %s\n",
		       portid, link.link_speed,
		       (link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full-duplex") : ("half-duplex\n"));
	}
	return ret;
}


int dpdk_do_pre_init(std::string *error) {
	char dpdk_pre_init_errbuf[PCAP_ERRBUF_SIZE + 1];
	int ret = dpdk_pre_init(dpdk_pre_init_errbuf, 0);
	char errbuf[PCAP_ERRBUF_SIZE * 2 + 1];
	if(ret < 0) {
		// This returns a negative value on an error.
		snprintf(errbuf, PCAP_ERRBUF_SIZE * 2 + 1,
			 "PPDK pre init error: %s",
			 dpdk_pre_init_errbuf);
		if(error) {
			*error = errbuf;
		}
	}
	return(ret);
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
		ps->ps_drop = dpdk->curr_stats.ierrors;
		ps->ps_drop += dpdk->bpf_drop;
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
		       << "; packets: " << dpdk->curr_stats.ipackets
		       << "; errors: " << dpdk->curr_stats.ierrors
		       << "; imissed: " << dpdk->curr_stats.imissed
		       << "; nombuf: " << dpdk->curr_stats.rx_nombuf;
		if(dpdk->rx_to_worker_ring) {
			outStr << "; ring count: " << rte_ring_count(dpdk->rx_to_worker_ring);
			outStr << "; ring full: " << dpdk->ring_full_drop;
		}
		#if WORKER2_THREAD_SUPPORT
		if(dpdk->worker_to_worker2_ring) {
			outStr << "; ring2 count: " << rte_ring_count(dpdk->worker_to_worker2_ring);
			outStr << "; ring2 full: " << dpdk->ring2_full_drop;
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
				int ret = rte_eth_xstats_get(portid, xstats, len);
				if(ret < 0 || ret > len) {
					outStr << "; error: " << "rte_eth_xstats_get failed";
				} else {
					rte_eth_xstat_name *xstats_names = (rte_eth_xstat_name*)calloc(len, sizeof(*xstats_names));
					if(xstats_names == NULL) {
						outStr << "; error: " << "failed to calloc memory for xstats_names";
					} else {
						ret = rte_eth_xstats_get_names(portid, xstats_names, len);
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
	return 0;
}


sDpdkConfig *dpdk_config(sDpdk *dpdk) {
	return(&dpdk->config);
}


void dpdk_terminating(sDpdk *dpdk) {
	dpdk->terminating = true;
}


double rte_read_thread_cpu_usage(sDpdk *dpdk) {
	if(!dpdk->rte_read_thread_pid) {
		return(-1);
	}
	if(dpdk->rte_read_thread_pstat_data[0].cpu_total_time) {
		dpdk->rte_read_thread_pstat_data[1] = dpdk->rte_read_thread_pstat_data[0];
	}
	pstat_get_data(dpdk->rte_read_thread_pid, dpdk->rte_read_thread_pstat_data);
	double ucpu_usage, scpu_usage;
	if(dpdk->rte_read_thread_pstat_data[0].cpu_total_time && dpdk->rte_read_thread_pstat_data[1].cpu_total_time) {
		pstat_calc_cpu_usage_pct(
			&dpdk->rte_read_thread_pstat_data[0], &dpdk->rte_read_thread_pstat_data[1],
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


string get_dpdk_cpu_cores(bool without_main) {
	if(!without_main && !opt_dpdk_cpu_cores.empty()) {
		return(opt_dpdk_cpu_cores);
	}
	cDpdkTools tools;
	return(tools.getAllCores(without_main));
}


static int rte_read_thread(void *arg) {
	sDpdk *dpdk = (sDpdk*)arg;
	dpdk->rte_read_thread_pid = get_unix_tid();
	setpriority(PRIO_PROCESS, dpdk->rte_read_thread_pid, -19);
	printf(" * DPDK READ (rte) THREAD %i\n", dpdk->rte_read_thread_pid);
	while(!dpdk->initialized) {
		usleep(1000);
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
		return 0;
	}
	#endif
	if(opt_dpdk_batch_read > 1) {
		unsigned pkts_burst_cnt;
		rte_mbuf *pkts_burst[opt_dpdk_batch_read][MAX_PKT_BURST];
		uint16_t nb_rx[opt_dpdk_batch_read];
		u_int64_t timestamp_us[opt_dpdk_batch_read];
		uint16_t nb_rx_enqueue;
		if(dpdk->rx_to_worker_ring) {
			while(!dpdk->terminating) {
				pkts_burst_cnt = 0;
				while(pkts_burst_cnt < (unsigned)opt_dpdk_batch_read) {
					nb_rx[pkts_burst_cnt] = rte_eth_rx_burst(dpdk->portid, 0, pkts_burst[pkts_burst_cnt], MAX_PKT_BURST);
					if(!nb_rx[pkts_burst_cnt]) {
						break;
					}
					#if DPDK_TIMESTAMP_IN_MBUF
					timestamp_us[pkts_burst_cnt] = get_timestamp_us(dpdk);
					#endif
					++pkts_burst_cnt;
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
								usleep(1000);
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
	return 0;
}


static int rte_worker_thread(void *arg) {
	sDpdk *dpdk = (sDpdk*)arg;
	dpdk->rte_worker_thread_pid = get_unix_tid();
	printf(" * DPDK WORKER (rte) THREAD %i\n", dpdk->rte_worker_thread_pid);
	void (*dpdk_process_packet_2)(sDpdk *dpdk, rte_mbuf *mbuff, u_int64_t timestamp_us
				      #if WORKER2_THREAD_SUPPORT
				      ,bool free_mbuff
				      #endif
				      ) =
		opt_dpdk_mbufs_in_packetbuffer ?
		 dpdk_process_packet_2__mbufs_in_packetbuffer :
		 dpdk_process_packet_2__std;
	rte_mbuf *pkts_burst[MAX_PKT_BURST];
	uint16_t nb_rx;
	#if not DPDK_TIMESTAMP_IN_MBUF
	u_int64_t timestamp_us;
	#endif
	while(!dpdk->terminating) {
		nb_rx = rte_ring_dequeue_burst(dpdk->rx_to_worker_ring, (void**)pkts_burst, MAX_PKT_BURST, NULL);
		if(likely(nb_rx)) {
			#if not DPDK_TIMESTAMP_IN_MBUF
			timestamp_us = get_timestamp_us(dpdk);
			#endif
			for(uint16_t i = 0; i < nb_rx; i++) {
				dpdk_process_packet_2(dpdk, pkts_burst[i], 
						      #if DPDK_TIMESTAMP_IN_MBUF == 1
						      *RTE_MBUF_DYNFIELD(pkts_burst[i], timestamp_dynfield_offset, u_int64_t*)
						      #elif DPDK_TIMESTAMP_IN_MBUF == 2
						      *(u_int64_t*)&pkts_burst[i]->dynfield1[0]
						      #else
						      timestamp_us
						      #endif
						      #if WORKER2_THREAD_SUPPORT
						      ,dpdk->config.type_worker2_thread != _dpdk_tw2t_rte
						      #endif
						      );
			}
			#if WORKER2_THREAD_SUPPORT
			if(dpdk->config.type_worker2_thread == _dpdk_tw2t_rte) {
				u_int16_t nb_rx_enqueue = rte_ring_enqueue_burst(dpdk->worker_to_worker2_ring, (void *const *)pkts_burst, nb_rx, NULL);
				if(nb_rx_enqueue < nb_rx) {
					for(u_int16_t i = nb_rx_enqueue; i < nb_rx; i++) {
						rte_pktmbuf_free(pkts_burst[i]);
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
	return 0;
}


#if WORKER2_THREAD_SUPPORT
static int rte_worker2_thread(void *arg) {
	sDpdk *dpdk = (sDpdk*)arg;
	dpdk->rte_worker2_thread_pid = get_unix_tid();
	printf(" * DPDK WORKER 2 (rte) THREAD %i\n", dpdk->rte_worker2_thread_pid);
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
	uint32_t pkt_len = rte_pktmbuf_pkt_len(mbuff);
	uint32_t caplen = pkt_len < (uint32_t)dpdk->config.snapshot ? pkt_len: (uint32_t)dpdk->config.snapshot;
	pcap_header.caplen = caplen;
	pcap_header.len = pkt_len;
	// volatile prefetch
	rte_prefetch0(rte_pktmbuf_mtod(mbuff, void *));
	u_int32_t packet_maxlen;
	#if DEBUG_CYCLES
	dpdk->cycles[4].setEnd();
	dpdk->cycles[5].setBegin();
	#endif
	u_char *packet = dpdk->config.callback.packet_allocation(dpdk->config.callback.packet_user, &packet_maxlen);
	#if DEBUG_CYCLES
	dpdk->cycles[5].setEnd();
	dpdk->cycles[6].setBegin();
	#endif
	if(mbuff->nb_segs == 1) {
                rte_memcpy(packet, rte_pktmbuf_mtod(mbuff, void*), caplen);
        } else {
		dpdk_gather_data(packet, packet_maxlen, mbuff);
	}
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
	dpdk->config.callback.packet_process(dpdk->config.callback.packet_user);
	#if DEBUG_CYCLES
	dpdk->cycles[4].setEnd();
	dpdk->cycles[5].setBegin();
	#endif
	sDpdkHeaderPacket *hp = dpdk->config.callback.header_packet;
	hp->header.ts.tv_sec = timestamp_us / 1000000;
	hp->header.ts.tv_usec = timestamp_us % 1000000;
	uint32_t pkt_len = rte_pktmbuf_pkt_len(mbuff);
	uint32_t caplen = pkt_len < (uint32_t)dpdk->config.snapshot ? pkt_len: (uint32_t)dpdk->config.snapshot;
	hp->header.caplen = caplen;
	hp->header.len = pkt_len;
	// volatile prefetch
	rte_prefetch0(rte_pktmbuf_mtod(mbuff, void *));
	if(mbuff->nb_segs == 1) {
                rte_memcpy(hp->packet, rte_pktmbuf_mtod(mbuff, void*), caplen);
        } else {
		dpdk_gather_data(hp->packet, hp->packet_maxlen, mbuff);
	}
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


static inline void dpdk_process_packet_2__mbufs_in_packetbuffer(sDpdk *dpdk, rte_mbuf *mbuff, u_int64_t timestamp_us
								#if WORKER2_THREAD_SUPPORT
								,bool free_mbuff
								#endif
								) {
	pcap_pkthdr pcap_header;
	pcap_header.ts.tv_sec = timestamp_us / 1000000;
	pcap_header.ts.tv_usec = timestamp_us % 1000000;
	uint32_t pkt_len = rte_pktmbuf_pkt_len(mbuff);
	uint32_t caplen = pkt_len < (uint32_t)dpdk->config.snapshot ? pkt_len: (uint32_t)dpdk->config.snapshot;
	pcap_header.caplen = caplen;
	pcap_header.len = pkt_len;
	rte_prefetch0(rte_pktmbuf_mtod(mbuff, void *));
	dpdk->config.callback.packet_process__mbufs_in_packetbuffer(dpdk->config.callback.packet_user, &pcap_header, mbuff);
}


static inline uint32_t dpdk_gather_data(unsigned char *data, uint32_t len, struct rte_mbuf *mbuf) {
	uint32_t total_len = 0;
	while(mbuf && (total_len+mbuf->data_len) < len ){
		rte_memcpy(data+total_len, rte_pktmbuf_mtod(mbuf,void *),mbuf->data_len);
		total_len+=mbuf->data_len;
		mbuf=mbuf->next;
	}
	return total_len;
}


static inline u_int64_t get_timestamp_us(sDpdk *dpdk) {
	dpdk_ts_helper *ts_helper = &dpdk->ts_helper;
	uint64_t cycles = rte_get_timer_cycles() - ts_helper->start_cycles;
	return(ts_helper->start_time +
	       cycles / ts_helper->hz * 1000000 + 
	       (cycles % ts_helper->hz) * 1000000 / ts_helper->hz);
}


static int dpdk_pre_init(char * ebuf, int eaccess_not_fatal) {
	int ret;
	int dargv_cnt = 0;
	char *dargv[DPDK_ARGC_MAX];
	#if DPDK_ENV_CFG
	char *ptr_dpdk_cfg = NULL;
	#else
	string _opt_dpdk_main_thread_lcore;
	string _opt_dpdk_cpu_cores_map;
	string _opt_dpdk_cpu_cores;
	string _opt_dpdk_memory_channels;
	string _opt_dpdk_force_max_simd_bitwidth;
	cDpdkTools tools;
	#endif
	if(is_dpdk_pre_inited != 0) {
		// already inited; did that succeed?
		if(is_dpdk_pre_inited < 0) {
			// failed
			goto error;
		} else {
			// succeeded
			return 1;
		}
	}
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
		_opt_dpdk_cpu_cores = tools.getAllCores(false);
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
		dargv[dargv_cnt++] = (char*)"-a";
		dargv[dargv_cnt++] = (char*)opt_dpdk_pci_device.c_str();
	}
	if(opt_dpdk_force_max_simd_bitwidth) {
		dargv[dargv_cnt++] = (char*)"--force-max-simd-bitwidth";
		_opt_dpdk_force_max_simd_bitwidth = intToString(opt_dpdk_force_max_simd_bitwidth);
		dargv[dargv_cnt++] = (char*)_opt_dpdk_force_max_simd_bitwidth.c_str();
	}
	#endif
	rte_log_set_global_level(DPDK_DEF_LOG_LEV);
	ret = rte_eal_init(dargv_cnt, dargv);
	if(ret == -1) {
		// Indicate that we've called rte_eal_init() by setting
		// is_dpdk_pre_inited to the negative of the error code,
		// and process the error.
		is_dpdk_pre_inited = -rte_errno;
		goto error;
	}
	// init succeeded, so we do not need to do it again later.
	#if DPDK_TIMESTAMP_IN_MBUF == 1
	strcpy(timestamp_dynfield_desc.name, "dynfield_clock");
	timestamp_dynfield_desc.size = sizeof(u_int64_t);
	timestamp_dynfield_desc.align = __alignof__(u_int64_t);
	timestamp_dynfield_offset = rte_mbuf_dynfield_register(&timestamp_dynfield_desc);
	if(timestamp_dynfield_offset < 0) {
		goto error;
	}
	#endif
	is_dpdk_pre_inited = 1;
	return 1;
error:
	switch (-is_dpdk_pre_inited) {
		case EACCES:
			// This "indicates a permissions issue.".
			syslog(LOG_ERR, "%s\n", DPDK_ERR_PERM_MSG);
			// If we were told to treat this as just meaning
			// DPDK isn't available, do so.
			if(eaccess_not_fatal)
				return 0;
			// Otherwise report a fatal error.
			snprintf(ebuf, PCAP_ERRBUF_SIZE,
			    "DPDK requires that it run as root");
			return PCAP_ERROR_PERM_DENIED;
		case EAGAIN:
			// This "indicates either a bus or system
			// resource was not available, setup may
			// be attempted again."
			// There's no such error in pcap, so I'm
			// not sure what we should do here.
			snprintf(ebuf, PCAP_ERRBUF_SIZE,
			    "Bus or system resource was not available");
			break;
		case EALREADY:
			// This "indicates that the rte_eal_init
			// function has already been called, and
			// cannot be called again."
			// That's not an error; set the "we've
			// been here before" flag and return
			// success.
			is_dpdk_pre_inited = 1;
			return 1;
		case EFAULT:
			// This "indicates the tailq configuration
			// name was not found in memory configuration."
			snprintf(ebuf, PCAP_ERRBUF_SIZE,
			    "The tailq configuration name was not found in the memory configuration");
			return PCAP_ERROR;
		case EINVAL:
			// This "indicates invalid parameters were
			// passed as argv/argc."  Those came from
			// the configuration file.
			snprintf(ebuf, PCAP_ERRBUF_SIZE,
			    "The configuration file has invalid parameters");
			break;
		case ENOMEM:
			// This "indicates failure likely caused by
			// an out-of-memory condition."
			snprintf(ebuf, PCAP_ERRBUF_SIZE,
			    "Out of memory");
			break;
		case ENODEV:
			// This "indicates memory setup issues."
			snprintf(ebuf, PCAP_ERRBUF_SIZE,
			    "An error occurred setting up memory");
			break;
		case ENOTSUP:
			// This "indicates that the EAL cannot
			// initialize on this system."  We treat
			// that as meaning DPDK isn't available
			// on this machine, rather than as a
			// fatal error, and let our caller decide
			// whether that's a fatal error (if trying
			// to activate a DPDK device) or not (if
			// trying to enumerate devices).
			return 0;
		case EPROTO:
			// This "indicates that the PCI bus is
			// either not present, or is not readable
			// by the eal."  Does "the PCI bus is not
			// present" mean "this machine has no PCI
			// bus", which strikes me as a "not available"
			// case?  If so, should "is not readable by
			// the EAL" also something we should treat
			// as a "not available" case?  If not, we
			// can't distinguish between the two, so
			// we're stuck.
			snprintf(ebuf, PCAP_ERRBUF_SIZE,
			    "PCI bus is not present or not readable by the EAL");
			break;
		case ENOEXEC:
			// This "indicates that a service core
			// failed to launch successfully."
			snprintf(ebuf, PCAP_ERRBUF_SIZE,
			    "A service core failed to launch successfully");
			break;
		default:
			//
			// That's not in the list of errors in
			// the documentation; let it be reported
			// as an error.
			//
			dpdk_fmt_errmsg_for_rte_errno(ebuf,
			    PCAP_ERRBUF_SIZE, -is_dpdk_pre_inited,
			    "dpdk error: dpdk_pre_init failed");
			break;
	}
	// Error.
	return PCAP_ERROR;
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


static void dpdk_fmt_errmsg_for_rte_errno(char *errbuf, size_t errbuflen,
					  int errnum, const char *fmt, ...) {
	va_list ap;
	size_t msglen;
	char *p;
	size_t errbuflen_remaining;
	va_start(ap, fmt);
	vsnprintf(errbuf, errbuflen, fmt, ap);
	va_end(ap);
	msglen = strlen(errbuf);
	/*
	 * Do we have enough space to append ": "?
	 * Including the terminating '\0', that's 3 bytes.
	 */
	if(msglen + 3 > errbuflen) {
		/* No - just give them what we've produced. */
		return;
	}
	p = errbuf + msglen;
	errbuflen_remaining = errbuflen - msglen;
	*p++ = ':';
	*p++ = ' ';
	*p = '\0';
	msglen += 2;
	errbuflen_remaining -= 2;
	/*
	 * Now append the string for the error code.
	 * rte_strerror() is thread-safe, at least as of dpdk 18.11,
	 * unlike strerror() - it uses strerror_r() rather than strerror()
	 * for UN*X errno values, and prints to what I assume is a per-thread
	 * buffer (based on the "PER_LCORE" in "RTE_DEFINE_PER_LCORE" used
	 * to declare the buffers statically) for DPDK errors.
	 */
	snprintf(p, errbuflen_remaining, "%s", rte_strerror(errnum));
}


static int dpdk_init_timer(sDpdk *dpdk) {
	dpdk->ts_helper.start_time = getTimeUS();
	dpdk->ts_helper.start_cycles = rte_get_timer_cycles();
	dpdk->ts_helper.hz = rte_get_timer_hz();
	if(dpdk->ts_helper.hz == 0) {
		return -1;
	}
	return 0;
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
	return plink->link_status == ETH_LINK_UP;
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
	vector<string> read_lcores_str = split(opt_dpdk_read_thread_lcore.c_str(), ",", true);
	for(unsigned i = 0; i < read_lcores_str.size(); i++) {
		read_lcores[atoi(read_lcores_str[i].c_str())] = true;
	}
	vector<string> worker_lcores_str = split(opt_dpdk_worker_thread_lcore.c_str(), ",", true);
	for(unsigned i = 0; i < worker_lcores_str.size(); i++) {
		worker_lcores[atoi(worker_lcores_str[i].c_str())] = true;
	}
	vector<string> worker2_lcores_str = split(opt_dpdk_worker2_thread_lcore.c_str(), ",", true);
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

int cDpdkTools::getFreeLcore(eTypeLcore type) {
	__SYNC_LOCK(_sync_lcore);
	int lcore_id = -1;
	switch(type) {
	case _tlc_read:
		lcore_id = getFreeLcore(read_lcores);
		break;
	case _tlc_worker:
		lcore_id = getFreeLcore(worker_lcores);
		break;
	case _tlc_worker2:
		lcore_id = getFreeLcore(worker2_lcores);
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

string cDpdkTools::getAllCores(bool without_main) {
	map<int, bool> all;
	if(!without_main) {
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

int cDpdkTools::getFreeLcore(map<int, bool> &main_map) {
	int main_lcore_id = rte_get_main_lcore();
	for(map<int, bool>::iterator iter = main_map.begin(); iter != main_map.end(); iter++) {
		if(rte_lcore_is_enabled(iter->first) && 
		   iter->first != main_lcore_id && 
		   !lcoreIsUsed(iter->first)) {
			return(iter->first);
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


#else //HAVE_LIBDPDK


struct sDpdk {
	sDpdkConfig config;
};

sDpdkHandle *create_dpdk_handle() {
	return(NULL);
}

void destroy_dpdk_handle(sDpdkHandle *dpdk) {
}

int dpdk_activate(sDpdkConfig *config, sDpdk *dpdk, std::string *error) {
	*error = "not supported";
	return(-1);
}

int dpdk_do_pre_init(std::string *error) {
	*error = "not supported";
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

double rte_read_thread_cpu_usage(sDpdk *dpdk) {
	return(-1);
}

double rte_worker_thread_cpu_usage(sDpdk *dpdk) {
	return(-1);
}

double rte_worker2_thread_cpu_usage(sDpdk *dpdk) {
	return(-1);
}

string get_dpdk_cpu_cores(bool without_main) {
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


#endif //HAVE_LIBDPDK
