#include <errno.h>
#include <fcntl.h>
#include <iomanip>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <iostream>
#include <sstream>
#include <sys/syscall.h>
#include <vector>
#include <dirent.h>
#include <sys/poll.h>
#include <sys/resource.h>

#include <snappy-c.h>
#ifdef HAVE_LIBLZ4
#include <lz4.h>
#endif //HAVE_LIBLZ4

#include "pcap_queue_block.h"
#include "pcap_queue.h"
#include "hash.h"
#include "mirrorip.h"
#include "ipaccount.h"
#include "filter_mysql.h"
#include "tcpreassembly.h"
#include "sniff.h"
#include "sniff_proc_class.h"
#include "rrd.h"
#include "cleanspool.h"
#include "ssldata.h"
#include "tar.h"
#include "voipmonitor.h"
#include "server.h"
#include "ssl_dssl.h"
#include "tcmalloc_hugetables.h"
#include "heap_chunk.h"
#include "transcribe.h"
#include "ipfix.h"
#include "hep.h"
#include "ribbonsbc.h"

#ifndef FREEBSD
#include <malloc.h>
#endif

#if HAVE_LIBTCMALLOC    
#include <gperftools/malloc_extension.h>
#endif


#define OPT_PCAP_BLOCK_STORE_MAX_ITEMS			2000		// 500 kB
#define OPT_PCAP_FILE_STORE_MAX_BLOCKS			1000		// 500 MB
#define OPT_PCAP_STORE_QUEUE_MAX_BLOCKS_IN_MEMORY	500		// 250 MB
#define OPT_PCAP_STORE_QUEUE_MAX_BLOCKS_IN_DISK		40000		// 20 GB
#define OPT_PCAP_QUEUE_BYPASS_MAX_ITEMS			500		// 500 MB
#define AVG_PACKET_SIZE					250


#define VERBOSE 		(verbosity > 0)
#define DEBUG_VERBOSE 		(VERBOSE && false)
#define DEBUG_SLEEP		(DEBUG_VERBOSE && true)
#define DEBUG_ALL_PACKETS	(DEBUG_VERBOSE && false)
#define TERMINATING 		((is_terminating() && this->enableAutoTerminate) || this->threadDoTerminate)

#define FILE_BUFFER_SIZE 1000000

#define TRACE_INVITE_BYE 0
#define TRACE_MASTER_SECRET 0


using namespace std;

extern int check_sip20(char *data, unsigned long len, ParsePacket::ppContentsX *parseContents, bool isTcp);
void daemonizeOutput(string error);

extern int verbosity;
extern int verbosityE;
extern int opt_snaplen;
extern bool opt_libpcap_immediate_mode;
extern bool opt_libpcap_nonblock_mode;
extern int opt_rrd;
extern int opt_udpfrag;
extern int opt_skinny;
extern int opt_ipaccount;
extern int opt_pcapdump;
extern int opt_dup_check_type;
extern int opt_dup_check_ipheader;
extern bool opt_dup_check_collision_test;
extern int opt_mirrorip;
extern char opt_mirrorip_src[20];
extern char opt_mirrorip_dst[20];
extern int opt_enable_http;
extern int opt_enable_webrtc;
extern int opt_enable_ssl;
extern bool opt_enable_diameter;
extern int opt_fork;
extern int opt_id_sensor;
extern char opt_name_sensor[256];
extern int opt_t2_boost;
extern int opt_t2_boost_pb_detach_thread;
extern bool opt_t2_boost_pcap_dispatch;
extern pcap_t *global_pcap_handle;
extern u_int16_t global_pcap_handle_index;
extern char *sipportmatrix;
extern char *httpportmatrix;
extern char *webrtcportmatrix;
extern char *diameter_tcp_portmatrix;
extern MirrorIP *mirrorip;
extern char user_filter[10*2048];
extern Calltable *calltable;
extern volatile int calls_counter;
extern volatile int calls_for_store_counter;
extern volatile int registers_counter;
extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
extern PreProcessPacket **preProcessPacketCallX;
extern PreProcessPacket **preProcessPacketCallFindX;
extern int preProcessPacketCallX_count;
extern ProcessRtpPacket *processRtpPacketHash;
extern ProcessRtpPacket *processRtpPacketDistribute[MAX_PROCESS_RTP_PACKET_THREADS];
extern TcpReassembly *tcpReassemblyHttp;
extern TcpReassembly *tcpReassemblyWebrtc;
extern TcpReassembly *tcpReassemblySsl;
extern TcpReassembly *tcpReassemblySipExt;
extern TcpReassembly *tcpReassemblyDiameter;
extern char opt_pb_read_from_file[256];
extern double opt_pb_read_from_file_speed;
extern int opt_pb_read_from_file_acttime;
extern int opt_pb_read_from_file_acttime_diff_days;
extern int opt_pb_read_from_file_acttime_diff_secs;
extern int64_t opt_pb_read_from_file_time_adjustment;
extern unsigned int opt_pb_read_from_file_max_packets;
extern bool opt_continue_after_read;
extern bool opt_suppress_cleanup_after_read;
extern bool opt_nonstop_read;
extern bool opt_unlimited_read;
extern bool opt_nonstop_read_quick;
extern int opt_time_to_terminate;
extern char opt_scanpcapdir[2048];
extern int global_pcap_dlink;
extern char opt_cachedir[1024];
extern unsigned long long cachedirtransfered;
unsigned long long lastcachedirtransfered = 0;
extern char opt_cachedir[1024];
extern int opt_pcap_dump_tar;
extern volatile unsigned int glob_tar_queued_files;
extern bool opt_socket_use_poll;
extern bool opt_use_dpdk;
extern int opt_dpdk_init;
extern int opt_dpdk_read_thread;
extern int opt_dpdk_worker_thread;
extern int opt_dpdk_worker2_thread;
extern int opt_dpdk_iterations_per_call;
extern int opt_dpdk_read_usleep_if_no_packet;
extern int opt_dpdk_read_usleep_type;
extern int opt_dpdk_worker_usleep_if_no_packet;
extern int opt_dpdk_worker_usleep_type;
extern int opt_dpdk_mbufs_in_packetbuffer;
extern int opt_dpdk_prealloc_packetbuffer;
extern int opt_dpdk_defer_send_packetbuffer;
extern int opt_dpdk_rotate_packetbuffer;
extern int opt_dpdk_copy_packetbuffer;

extern sSnifferClientOptions snifferClientOptions;
extern sSnifferServerClientOptions snifferServerClientOptions;
extern cBuffersControl buffersControl;

vm_atomic<string> pbStatString;
vm_atomic<u_long> pbCountPacketDrop;

u_int64_t opt_pb_read_from_file_acttime_diff;

extern PcapQueue_readFromFifo *pcapQueueQ;

void *_PcapQueue_threadFunction(void *arg);
void *_PcapQueue_writeThreadFunction(void *arg);
void *_PcapQueue_readFromInterfaceThread_threadFunction(void *arg);
void *_PcapQueue_readFromFifo_destroyBlocksThreadFunction(void *arg);
void *_PcapQueue_readFromFifo_socketServerThreadFunction(void *arg);
void *_PcapQueue_readFromFifo_connectionThreadFunction(void *arg);

static bool __config_ENABLE_TOGETHER_READ_WRITE_FILE	= false;

bool opt_pcap_queue_disable = false;
u_int opt_pcap_queue_block_max_time_ms 			= 100;
size_t opt_pcap_queue_block_max_size   			= 1024 * 1024;
u_int opt_pcap_queue_file_store_max_time_ms		= 2000;
size_t opt_pcap_queue_file_store_max_size		= 200 * 1024 * 1024;
uint64_t opt_pcap_queue_store_queue_max_disk_size	= 0;
uint64_t opt_pcap_queue_bypass_max_size			= 256 * 1024 * 1024;
int opt_pcap_queue_compress				= -1;
pcap_block_store::compress_method opt_pcap_queue_compress_method 
							= pcap_block_store::snappy;
int opt_pcap_queue_compress_ratio = 100;
string opt_pcap_queue_disk_folder;
ip_port opt_pcap_queue_send_to_ip_port;
ip_port opt_pcap_queue_receive_from_ip_port;
int opt_pcap_queue_receive_from_port;
int opt_pcap_queue_receive_dlt 				= DLT_EN10MB;
int opt_pcap_queue_iface_separate_threads 		= 0;
int opt_pcap_queue_iface_dedup_separate_threads 	= 0;
int opt_pcap_queue_iface_dedup_separate_threads_extend	= 0;
int opt_pcap_queue_iface_extend2_use_alloc_stack	= 1;
int opt_pcap_queue_iface_qring_size 			= 5000;
int opt_pcap_queue_dequeu_window_length			= -1;
int opt_pcap_queue_dequeu_window_length_div		= 0;
int opt_pcap_queue_dequeu_need_blocks			= 0;
int opt_pcap_queue_dequeu_method			= 3;
int opt_pcap_queue_use_blocks				= 0;
int opt_pcap_queue_use_blocks_auto_enable		= 0;
int opt_pcap_queue_use_blocks_read_check		= 1;
int opt_pcap_dispatch					= 0;
int opt_pcap_queue_suppress_t1_thread			= 0;
int opt_pcap_queue_block_timeout			= 0;
bool opt_pcap_queue_pcap_stat_per_one_interface		= true;
bool opt_pcap_queues_mirror_nonblock_mode 		= true;
bool opt_pcap_queues_mirror_require_confirmation	= true;
bool opt_pcap_queues_mirror_use_checksum		= true;

#define _opt_pcap_queue_block_offset_init_size		(opt_pcap_queue_block_max_size / AVG_PACKET_SIZE * 1.1)
#define _opt_pcap_queue_block_offset_inc_size		(opt_pcap_queue_block_max_size / AVG_PACKET_SIZE / 4)
#define _opt_pcap_queue_block_restore_buffer_inc_size	(opt_pcap_queue_block_max_size / 4)

int pcap_drop_flag = 0;
int enable_bad_packet_order_warning = 0;
u_int64_t all_ringbuffers_size = 0;
double last_traffic = -1;

static pcap_block_store_queue *blockStoreBypassQueue; 

static unsigned long sumPacketsCounterIn[3];
static unsigned long sumPacketsCounterOut[3];
static unsigned long sumBlocksCounterIn[3];
static unsigned long sumBlocksCounterOut[3];
static unsigned long long sumPacketsSize[3];
#if LOG_PACKETS_PER_SEC or LOG_PACKETS_SUM
static unsigned long long sumPacketsCount[3];
#endif
static unsigned long long sumPacketsSizeOut[3];
#if LOG_PACKETS_PER_SEC or LOG_PACKETS_SUM
static unsigned long long sumPacketsCountOut[3];
#endif
static unsigned long long sumPacketsSizeCompress[3];
static unsigned long countBypassBufferSizeExceeded;
static double heap_pb_perc = 0;
static double heap_pb_used_perc = 0;
static double heap_pb_used_dequeu_perc = 0;
static double heap_pb_trash_perc = 0;
static double heap_pb_pool_perc = 0;
static unsigned heapFullCounter = 0;
static unsigned heapFullIfT2cpuIsLowCounter = 0;

extern MySqlStore *sqlStore;
extern MySqlStore *loadFromQFiles;
extern PcapQueue_outputThread *pcapQueueQ_outThread_detach;
extern PcapQueue_outputThread *pcapQueueQ_outThread_defrag;
extern PcapQueue_outputThread *pcapQueueQ_outThread_dedup;
extern PcapQueue_outputThread *pcapQueueQ_outThread_detach2;

extern unsigned int glob_ssl_calls;

bool packetbuffer_memory_is_full = false;

#include "sniff_inline.h"


pcap_t *pcap_handles[65535];
volatile u_int16_t pcap_handles_count;
volatile int _sync_pcap_handles;

u_int16_t register_pcap_handle(pcap_t *handle) {
	u_int16_t rslt_index;
	__SYNC_LOCK(_sync_pcap_handles);
	if(!pcap_handles_count) ++pcap_handles_count;
	rslt_index = pcap_handles_count;
	pcap_handles[pcap_handles_count++] = handle;
	__SYNC_UNLOCK(_sync_pcap_handles);
	return(rslt_index);
}


/*bool pcap_block_store::add(pcap_pkthdr *header, u_char *packet, int offset, int dlink, int memcpy_packet_size) {
	if(this->full) {
		return(false);
	}
	if((this->size + sizeof(pcap_pkthdr_plus) + header->caplen) > opt_pcap_queue_block_max_size ||
	   (!(this->count % 20) && this->size && getTimeMS_rdtsc() > (this->timestampMS + opt_pcap_queue_block_max_time_ms))) {
		this->full = true;
		return(false);
	}
	if(!this->block) {
		while(true) {
			this->block = new FILE_LINE(15001) u_char[opt_pcap_queue_block_max_size];
			if(this->block) {
				break;
			}
			syslog(LOG_ERR, "not enough memory for alloc packetbuffer block");
			sleep(1);
		}
	}
	if(!this->offsets_size) {
		this->offsets_size = _opt_pcap_queue_block_offset_init_size;
		this->offsets = new FILE_LINE(15002) uint32_t[this->offsets_size];
	}
	if(this->count == this->offsets_size) {
		uint32_t *offsets_old = this->offsets;
		size_t offsets_size_old = this->offsets_size;
		this->offsets_size += _opt_pcap_queue_block_offset_inc_size;
		this->offsets = new FILE_LINE(15003) uint32_t[this->offsets_size];
		memcpy_heapsafe(this->offsets, offsets_old, sizeof(uint32_t) * offsets_size_old,
				__FILE__, __LINE__);
		delete [] offsets_old;
	}
	this->offsets[this->count] = this->size;
	pcap_pkthdr_plus header_plus = pcap_pkthdr_plus(*header, offset, dlink);
	memcpy_heapsafe(this->block + this->size, this->block,
			&header_plus, NULL,
			sizeof(pcap_pkthdr_plus),
			__FILE__, __LINE__);
	this->size += sizeof(pcap_pkthdr_plus);
	memcpy_heapsafe(this->block + this->size, this->block,
			packet, NULL,
			memcpy_packet_size ? memcpy_packet_size : header->caplen,
			__FILE__, __LINE__);
	this->size += header->caplen;
	this->size_packets += header->caplen;
	++this->count;
	return(true);
}*/

void pcap_block_store::init(bool prefetch) {
	if(!this->dpdk) {
		this->block = new FILE_LINE(0) u_char[opt_pcap_queue_block_max_size];
		if(prefetch) {
			size_t offset = 0;
			while(offset < opt_pcap_queue_block_max_size) {
				this->block[offset] = 0;
				offset += 128;
			}
		}
		this->offsets_size = _opt_pcap_queue_block_offset_init_size;
		this->offsets = new FILE_LINE(0) uint32_t[this->offsets_size];
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		this->_sync_packets_lock = new FILE_LINE(0) volatile int8_t[this->offsets_size];
		memset((void*)this->_sync_packets_lock, 0, sizeof(int8_t) * this->offsets_size);
		#if DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH
		this->_sync_packets_flag = new FILE_LINE(0) volatile int8_t[this->offsets_size * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH];
		memset((void*)this->_sync_packets_flag, 0, sizeof(int8_t) * this->offsets_size * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH);
		#endif
		#endif
		timestampMS = getTimeMS_rdtsc();
	}
}

void pcap_block_store::clear(bool prefetch) {
	count = 0;
	size = 0;
	size_packets = 0;
	if(!this->dpdk && prefetch) {
		size_t offset = 0;
		while(offset < opt_pcap_queue_block_max_size) {
			this->block[offset] = 0;
			offset += 128;
		}
	}
	timestampMS = getTimeMS_rdtsc();
}

void pcap_block_store::copy(pcap_block_store *from) {
	count = from->count;
	size = from->size;
	size_packets = from->size_packets;
	if(!block) {
		block = new FILE_LINE(0) u_char[opt_pcap_queue_block_max_size];
	}
	dpdk_memcpy(block, from->block, size);
	if(!offsets || count > offsets_size)  {
		if(offsets) {
			delete [] offsets;
		}
		offsets = new FILE_LINE(0) uint32_t[from->offsets_size];
		offsets_size = from->offsets_size;
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		delete [] this->_sync_packets_lock;
		this->_sync_packets_lock = new FILE_LINE(0) volatile int8_t[this->offsets_size];
		#if DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH
		delete [] this->_sync_packets_flag;
		this->_sync_packets_flag = new FILE_LINE(0) volatile int8_t[this->offsets_size * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH];
		#endif
		#endif
	}
	dpdk_memcpy(offsets, from->offsets, count * sizeof(uint32_t));
	_sync_packet_lock = 0;
	#if DEBUG_SYNC_PCAP_BLOCK_STORE
	memset((void*)this->_sync_packets_lock, 0, sizeof(int8_t) * this->offsets_size);
	#if DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH
	memset((void*)this->_sync_packets_flag, 0, sizeof(int8_t) * this->offsets_size * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH);
	#endif
	#endif
	timestampMS = getTimeMS_rdtsc();
}

bool pcap_block_store::add_hp(pcap_pkthdr_plus *header, u_char *packet, int memcpy_packet_size) {
	if(this->full) {
		return(false);
	}
	u_int32_t caplen = header->get_caplen();
	u_int32_t size_header_a = (hm == plus2 ? PACKETBUFFER_ALIGN_PCAP_PKTHDR_PLUS2_SIZE : sizeof(pcap_pkthdr_plus));
	u_int32_t size_packet_a = PACKETBUFFER_ALIGN_PCAP_SIZE(caplen);
	if((this->size + size_header_a + size_packet_a) > opt_pcap_queue_block_max_size ||
	   (!(this->count % 20) && this->size && getTimeMS_rdtsc() > (this->timestampMS + opt_pcap_queue_block_max_time_ms))) {
		this->full = true;
		return(false);
	}
	if(!this->block) {
		while(true) {
			this->block = new FILE_LINE(15004) u_char[opt_pcap_queue_block_max_size];
			if(this->block) {
				break;
			}
			syslog(LOG_ERR, "not enough memory for alloc packetbuffer block");
			sleep(1);
		}
	}
	if(!this->offsets_size) {
		this->offsets_size = _opt_pcap_queue_block_offset_init_size;
		this->offsets = new FILE_LINE(15005) uint32_t[this->offsets_size];
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		this->_sync_packets_lock = new FILE_LINE(0) volatile int8_t[this->offsets_size];
		memset((void*)this->_sync_packets_lock, 0, sizeof(int8_t) * this->offsets_size);
		#if DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH
		this->_sync_packets_flag = new FILE_LINE(0) volatile int8_t[this->offsets_size * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH];
		memset((void*)this->_sync_packets_flag, 0, sizeof(int8_t) * this->offsets_size * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH);
		#endif
		#endif
	}
	if(this->count == this->offsets_size) {
		uint32_t *offsets_old = this->offsets;
		size_t offsets_size_old = this->offsets_size;
		this->offsets_size += _opt_pcap_queue_block_offset_inc_size;
		this->offsets = new FILE_LINE(15006) uint32_t[this->offsets_size];
		memcpy_heapsafe(this->offsets, offsets_old, sizeof(uint32_t) * offsets_size_old,
				__FILE__, __LINE__);
		delete [] offsets_old;
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		volatile int8_t *_sync_packets_lock_old = _sync_packets_lock;
		this->_sync_packets_lock = new FILE_LINE(0) volatile int8_t[this->offsets_size];
		memcpy((void*)this->_sync_packets_lock, (void*)_sync_packets_lock_old, 
		       sizeof(int8_t) * offsets_size_old);
		memset((void*)(this->_sync_packets_lock + offsets_size_old), 0, 
		       sizeof(int8_t) * (this->offsets_size - offsets_size_old));
		#if DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH
		volatile int8_t *_sync_packets_flag_old = _sync_packets_flag;
		this->_sync_packets_flag = new FILE_LINE(0) volatile int8_t[this->offsets_size * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH];
		memcpy((void*)this->_sync_packets_flag, (void*)_sync_packets_flag_old, 
		       sizeof(int8_t) * offsets_size_old * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH);
		memset((void*)(this->_sync_packets_flag + offsets_size_old * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH), 0, 
		       sizeof(int8_t) * (this->offsets_size - offsets_size_old) * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH);
		#endif
		#endif
	}
	this->offsets[this->count] = this->size;
	memcpy_heapsafe(this->block + this->size, this->block,
			header, NULL,
			(hm == plus2 ? sizeof(pcap_pkthdr_plus2) : sizeof(pcap_pkthdr_plus)),
			__FILE__, __LINE__);
	this->size += size_header_a;
	memcpy_heapsafe(this->block + this->size, this->block,
			packet, NULL,
			(memcpy_packet_size ? memcpy_packet_size : caplen),
			__FILE__, __LINE__);
	this->size += size_packet_a;
	this->size_packets += caplen;
	++this->count;
	return(true);
}

bool pcap_block_store::add_hp_ext(pcap_pkthdr_plus *header, u_char *packet, int memcpy_packet_size) {
	return(add_hp(header, packet, memcpy_packet_size));
}

/*bool pcap_block_store::add(pcap_pkthdr_plus *header, u_char *packet) {
	return(this->add((pcap_pkthdr*)header, packet, header->offset, header->dlink));
}*/

void pcap_block_store::inc_h(u_int32_t caplen) {
	if(this->count == this->offsets_size) {
		uint32_t *offsets_old = this->offsets;
		size_t offsets_size_old = this->offsets_size;
		this->offsets_size += _opt_pcap_queue_block_offset_inc_size;
		this->offsets = new FILE_LINE(15007) uint32_t[this->offsets_size];
		memcpy_heapsafe(this->offsets, offsets_old, sizeof(uint32_t) * offsets_size_old,
				__FILE__, __LINE__);
		delete [] offsets_old;
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		volatile int8_t *_sync_packets_lock_old = _sync_packets_lock;
		this->_sync_packets_lock = new FILE_LINE(0) volatile int8_t[this->offsets_size];
		memcpy((void*)this->_sync_packets_lock, (void*)_sync_packets_lock_old, 
		       sizeof(int8_t) * offsets_size_old);
		memset((void*)(this->_sync_packets_lock + offsets_size_old), 0, 
		       sizeof(int8_t) * (this->offsets_size - offsets_size_old));
		delete [] _sync_packets_lock_old;
		#if DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH
		volatile int8_t *_sync_packets_flag_old = _sync_packets_flag;
		this->_sync_packets_flag = new FILE_LINE(0) volatile int8_t[this->offsets_size * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH];
		memcpy((void*)this->_sync_packets_flag, (void*)_sync_packets_flag_old, 
		       sizeof(int8_t) * offsets_size_old * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH);
		memset((void*)(this->_sync_packets_flag + offsets_size_old * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH), 0, 
		       sizeof(int8_t) * (this->offsets_size - offsets_size_old) * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH);
		delete [] _sync_packets_flag_old;
		#endif
		#endif
	}
	this->offsets[this->count] = this->size;
	u_int32_t size_header_a = PACKETBUFFER_ALIGN_PCAP_PKTHDR_PLUS2_SIZE;
	u_int32_t size_packet_a = PACKETBUFFER_ALIGN_PCAP_SIZE(caplen);
	this->size += size_header_a + size_packet_a;
	this->size_packets += caplen;
	++this->count;
}

bool pcap_block_store::get_add_hp_pointers(pcap_pkthdr_plus2 **header, u_char **packet, unsigned min_size_for_packet) {
	if(!this->block) {
		while(true) {
			this->block = new FILE_LINE(15008) u_char[opt_pcap_queue_block_max_size];
			if(this->block) {
				break;
			}
			syslog(LOG_ERR, "not enough memory for alloc packetbuffer block");
			sleep(1);
		}
	}
	if(!this->offsets_size) {
		this->offsets_size = _opt_pcap_queue_block_offset_init_size;
		this->offsets = new FILE_LINE(15009) uint32_t[this->offsets_size];
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		this->_sync_packets_lock = new FILE_LINE(0) volatile int8_t[this->offsets_size];
		memset((void*)this->_sync_packets_lock, 0, sizeof(int8_t) * this->offsets_size);
		#if DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH
		this->_sync_packets_flag = new FILE_LINE(0) volatile int8_t[this->offsets_size * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH];
		memset((void*)this->_sync_packets_flag, 0, sizeof(int8_t) * this->offsets_size * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH);
		#endif
		#endif
	}
	u_int32_t size_header_a = PACKETBUFFER_ALIGN_PCAP_PKTHDR_PLUS2_SIZE;
	u_int32_t size_packet_a = PACKETBUFFER_ALIGN_PCAP_SIZE(min_size_for_packet);
	#if DPDK_DEBUG
	static unsigned _c = 0;
	bool log = false;
	if(log) cout << "B" << (++_c) << ":" << this->size << "/+" << size_packet_a;
	#endif
	if(this->size + size_header_a + size_packet_a > opt_pcap_queue_block_max_size) {
		#if DPDK_DEBUG
		if(log) cout << " > " << opt_pcap_queue_block_max_size << " FALSE" << endl;
		#endif
		this->full = true;
		return(false);
	}
	#if DPDK_DEBUG
	if(log) cout << ":OK|" << flush;
	#endif
	*header = (pcap_pkthdr_plus2*)(this->block + this->size);
	*packet = (u_char*)(this->block + this->size + size_header_a);
	return(true);
}

void pcap_block_store::add_dpdk(pcap_pkthdr_plus2 *header, void *mbuf) {
	if(!this->dpdk || !this->dpdk_data_size) {
		this->dpdk_data_size = 10000;
		this->dpdk_data = new FILE_LINE(0) s_dpdk_data[this->dpdk_data_size];
	}
	this->dpdk_data[this->count].header = *header;
	this->dpdk_data[this->count].packet = dpdk_mbuf_to_packet(mbuf);
	this->dpdk_data[this->count].mbuf = mbuf;
	u_int32_t caplen = header->get_caplen();
 	this->size += caplen;
	this->size_packets += caplen;
	++this->count;
}

bool pcap_block_store::is_dpkd_data_full() {
	return(this->count == this->dpdk_data_size);
}

bool pcap_block_store::isFull_checkTimeout(unsigned timeout_ms) {
	if(this->full) {
		return(true);
	}
	if(this->size && getTimeMS_rdtsc() > (this->timestampMS + (timeout_ms ? timeout_ms : opt_pcap_queue_block_max_time_ms))) {
		this->full = true;
		return(true);
	}
	return(false);
}

bool pcap_block_store::isFull_checkTimeout_ext(unsigned timeout_ms) {
	return(isFull_checkTimeout(timeout_ms));
}

bool pcap_block_store::isTimeout() {
	return(getTimeMS_rdtsc() > (this->timestampMS + opt_pcap_queue_block_max_time_ms));
}

void pcap_block_store::destroy(bool init) {
	if(!init) {
		if(__sync_lock_test_and_set(&this->_destroy_flag, 1)) {
			double_destroy_log();
			return;
		}
		#if DEBUG_DESTROY_PCAP_BLOCK_STORE
		string bt = get_backtrace();
		strncpy(destroy_bt, bt.c_str(), sizeof(destroy_bt) - 1);
		destroy_bt[sizeof(destroy_bt) - 1] = 0;
		destroy_src_flag[1] = destroy_src_flag[0];
		#endif
	}
	MEMORY_BARRIER_ARM;
	if(this->offsets) {
		delete [] this->offsets;
		this->offsets = NULL;
	}
	if(this->block) {
		delete [] this->block;
		this->block = NULL;
	}
	if(this->is_voip) {
		delete [] this->is_voip;
		this->is_voip = NULL;
	}
	if(this->dpdk_data) {
		for(unsigned i = 0; i < this->count; i++) {
			if(this->dpdk_data[i].mbuf) {
				dpdk_mbuf_free(this->dpdk_data[i].mbuf);
			}
		}
		delete [] this->dpdk_data;
		this->dpdk_data_size = 0;
	}
	this->size = 0;
	this->size_compress = 0;
	this->size_packets = 0;
	this->count = 0;
	this->offsets_size = 0;
	this->full = false;
	this->dlink = global_pcap_dlink;
	this->sensor_id = opt_id_sensor;
	this->sensor_ip = 0;
	memset(this->ifname, 0, sizeof(this->ifname));
	#if DEBUG_SYNC_PCAP_BLOCK_STORE
	if(this->_sync_packets_lock) {
		delete this->_sync_packets_lock;
	}
	#if DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH
	if(this->_sync_packets_flag) {
		delete this->_sync_packets_flag;
	}
	#endif
	#endif
	MEMORY_BARRIER_ARM;
}

void pcap_block_store::double_destroy_log() {
	#if DEBUG_DESTROY_PCAP_BLOCK_STORE
	syslog(LOG_NOTICE, "double call pcap_block_store::destroy() backtrace: %s, destroy_src_flag: %i/%i,  destroy bt: %s", 
	       get_backtrace().c_str(),
	       destroy_src_flag[0], destroy_src_flag[1],
	       destroy_bt);
	#else
	syslog(LOG_NOTICE, "double call pcap_block_store::destroy() backtrace: %s", get_backtrace().c_str());
	#endif
}

void pcap_block_store::destroyRestoreBuffer() {
	if(this->restoreBuffer) {
		delete [] this->restoreBuffer;
		this->restoreBuffer = NULL;
	}
	this->restoreBufferSize = 0;
	this->restoreBufferAllocSize = 0;
}

bool pcap_block_store::isEmptyRestoreBuffer() {
	return(!this->restoreBuffer);
}

void pcap_block_store::freeBlock() {
	if(this->block) {
		delete [] this->block;
		this->block = NULL;
	}
}

u_char* pcap_block_store::getSaveBuffer(uint32_t block_counter) {
	size_t sizeSaveBuffer = this->getSizeSaveBuffer();
	u_char *saveBuffer = new FILE_LINE(15010) u_char[sizeSaveBuffer];
	pcap_block_store_header header;
	header.hm = this->hm;
	header.size = this->size;
	header.size_compress = this->size_compress;
	header.count = this->count;
	header.dlink = this->dlink;
	header.sensor_id = this->sensor_id;
	header.counter = block_counter;
	strcpy(header.ifname, this->ifname);
	header.time_s = getTimeS();
	memcpy_heapsafe(saveBuffer, saveBuffer,
			&header, NULL,
			sizeof(header),
			__FILE__, __LINE__);
	memcpy_heapsafe(saveBuffer + sizeof(header), saveBuffer,
			this->offsets, this->offsets,
			sizeof(uint32_t) * this->count,
			__FILE__, __LINE__);
	memcpy_heapsafe(saveBuffer + sizeof(pcap_block_store_header) + this->count * sizeof(uint32_t), saveBuffer,
			this->block, this->block,
			this->getUseSize(),
			__FILE__, __LINE__);
	((pcap_block_store_header*)saveBuffer)->checksum = opt_pcap_queues_mirror_use_checksum ?
							    max(checksum32buf(saveBuffer + sizeof(pcap_block_store_header), sizeSaveBuffer - sizeof(pcap_block_store_header)), (u_int32_t)1) :
							    0;
	return(saveBuffer);
}

void pcap_block_store::restoreFromSaveBuffer(u_char *saveBuffer) {
	pcap_block_store_header *header = (pcap_block_store_header*)saveBuffer;
	this->hm = (header_mode)header->hm;
	this->size = header->size;
	this->size_compress = header->size_compress;
	this->count = header->count;
	this->dlink = header->dlink;
	this->sensor_id = header->sensor_id;
	strcpy_null_term(this->ifname, header->ifname);
	this->block_counter = header->counter;
	this->require_confirmation = header->require_confirmation;
	if(this->offsets) {
		delete [] this->offsets;
	}
	if(this->block) {
		delete [] this->block;
	}
	this->offsets_size = this->count;
	this->offsets = new FILE_LINE(15011) uint32_t[this->offsets_size];
	memcpy_heapsafe(this->offsets, this->offsets,
			saveBuffer + sizeof(pcap_block_store_header), saveBuffer,
			sizeof(uint32_t) * this->count,
			__FILE__, __LINE__);
	size_t sizeBlock = this->getUseSize();
	this->block = new FILE_LINE(15012) u_char[sizeBlock];
	memcpy_heapsafe(this->block, this->block,
			saveBuffer + sizeof(pcap_block_store_header) + this->count * sizeof(uint32_t), saveBuffer,
			sizeBlock,
			__FILE__, __LINE__);
	this->full = true;
	#if DEBUG_SYNC_PCAP_BLOCK_STORE
	this->_sync_packets_lock = new FILE_LINE(0) volatile int8_t[this->offsets_size];
	memset((void*)this->_sync_packets_lock, 0, sizeof(int8_t) * this->offsets_size);
	#if DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH
	this->_sync_packets_flag = new FILE_LINE(0) volatile int8_t[this->offsets_size * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH];
	memset((void*)this->_sync_packets_flag, 0, sizeof(int8_t) * this->offsets_size * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH);
	#endif
	#endif
}

int pcap_block_store::addRestoreChunk(u_char *buffer, u_char *buffer_alloc_begin, size_t size, size_t *offset, bool restoreFromStore, string *error) {
	u_char *_buffer = buffer + (offset ? *offset : 0);
	size_t _size = size - (offset ? *offset : 0);
	if(_size <= 0) {
		return(-1);
	}
	if(this->restoreBufferAllocSize < this->restoreBufferSize + _size) {
		this->restoreBufferAllocSize = this->restoreBufferSize + _size + _opt_pcap_queue_block_restore_buffer_inc_size;
		u_char *restoreBufferNew = new FILE_LINE(15013) u_char[this->restoreBufferAllocSize];
		if(this->restoreBuffer) {
			memcpy_heapsafe(restoreBufferNew, this->restoreBuffer, this->restoreBufferSize,
					__FILE__, __LINE__);
			delete [] this->restoreBuffer;
		}
		this->restoreBuffer = restoreBufferNew;
	}
	memcpy_heapsafe(this->restoreBuffer + this->restoreBufferSize, this->restoreBuffer,
			_buffer, buffer_alloc_begin,
			_size,
			__FILE__, __LINE__);
	this->restoreBufferSize += _size;
	if(this->restoreBufferSize > opt_pcap_queue_block_max_size * 10) {
		return(-2);
	}
	if(this->restoreBufferSize >= sizeof(pcap_block_store_header) &&
	   strncmp(((pcap_block_store_header*)this->restoreBuffer)->title, PCAP_BLOCK_STORE_HEADER_STRING, PCAP_BLOCK_STORE_HEADER_STRING_LEN)) {
		return(-3);
	}
	if(this->restoreBufferSize >= sizeof(pcap_block_store_header) &&
	   ((pcap_block_store_header*)this->restoreBuffer)->version != PCAP_BLOCK_STORE_HEADER_VERSION) {
		return(-6);
	}
	if(!restoreFromStore &&
	   this->restoreBufferSize >= sizeof(pcap_block_store_header) &&
	   ((pcap_block_store_header*)this->restoreBuffer)->time_s) {
		extern int opt_receive_packetbuffer_maximum_time_diff_s;
		int timeDiff = abs((int64_t)(((pcap_block_store_header*)this->restoreBuffer)->time_s) - (int64_t)(getTimeS())) % (3600/2);
		if(timeDiff > opt_receive_packetbuffer_maximum_time_diff_s) {
			string _error = 
				string("Time difference between ") + 
				(is_server() ? "server and client" : "mirror receiver and sender") + 
				" (id_sensor:" + 
				(((pcap_block_store_header*)this->restoreBuffer)->sensor_id > 0 ?
				  intToString(((pcap_block_store_header*)this->restoreBuffer)->sensor_id) : 
				  "local") + 
				") is too big (" + intToString(timeDiff) + "s)" + 
				" - data cannot be received. Please synchronise time on both " + 
				(is_server() ? "server and client" : "mirror receiver and sender") + 
				". Or increase configuration parameter receive_packetbuffer_maximum_time_diff_s on " + 
				(is_server() ? "server" : "mirror receiver") + 
				".";
			if(error) {
				*error = _error;
			}
			return(-7);
		} else {
			((pcap_block_store_header*)this->restoreBuffer)->time_s = 0;
		}
	}
	int sizeRestoreBuffer = this->getSizeSaveBufferFromRestoreBuffer();
	if(this->restoreBufferSize - _size > (size_t)sizeRestoreBuffer) {
		return(-4);
	}
	if(sizeRestoreBuffer < 0 ||
	   this->restoreBufferSize < (size_t)sizeRestoreBuffer) {
		return(0);
	}
	if(offset) {
		*offset = size - (this->restoreBufferSize - sizeRestoreBuffer);
	}
	if(((pcap_block_store_header*)this->restoreBuffer)->checksum) {
		u_int32_t checksum = checksum32buf(this->restoreBuffer + sizeof(pcap_block_store_header), sizeRestoreBuffer - sizeof(pcap_block_store_header));
		if(((pcap_block_store_header*)this->restoreBuffer)->checksum != max(checksum, (u_int32_t)1)) {
			return(-5);
		}
	}
	this->restoreFromSaveBuffer(this->restoreBuffer);
	this->destroyRestoreBuffer();
	return(1);
}

string pcap_block_store::addRestoreChunk_getErrorString(int errorCode) {
	string error;
	switch(errorCode) {
	case -1:
		error = "bad size / offset";
		break;
	case -2:
		error = "too big";
		break;
	case -3:
		error = "missing / bad block id";
		break;
	case -4:
		error = "oversize";
		break;
	case -5:
		error = "bad checksum";
		break;
	case -6:
		error = "bad version - sender and receiver must be the same version";
		break;
	case -7:
		error = "too different time between sender and receiver";
		break;
	default:
		error = "unknow error";
		break;
	}
	return(error);
}

bool pcap_block_store::compress() {
	if(!opt_pcap_queue_compress ||
	   this->size_compress) {
		return(true);
	}
	if(opt_pcap_queue_compress_ratio > 0 && opt_pcap_queue_compress_ratio < 100) {
		static __thread unsigned __counter;
		switch(opt_pcap_queue_compress_ratio / 10) {
		case 0: if((__counter++) % 6) return(true); break;
		case 1: if((__counter++) % 5) return(true); break;
		case 2: if((__counter++) % 4) return(true); break;
		case 3: if((__counter++) % 3) return(true); break;
		case 5: if((__counter++) % 2) return(true); break;
		case 6: if(!((__counter++) % 3)) return(true); break;
		case 7: if(!((__counter++) % 4)) return(true); break;
		case 8: if(!((__counter++) % 5)) return(true); break;
		case 9: if(!((__counter++) % 6)) return(true); break;
		}
	}
	switch(opt_pcap_queue_compress_method) {
	case lz4:
		#ifdef HAVE_LIBLZ4
		return(this->compress_lz4());
		#endif //HAVE_LIBLZ4
	case snappy:
	default:
		return(this->compress_snappy());
	}
	return(true);
}

bool pcap_block_store::compress_snappy() {
	size_t snappyBuffSize = snappy_max_compressed_length(this->size);
	u_char *snappyBuff = new FILE_LINE(15014) u_char[snappyBuffSize];
	if(!snappyBuff) {
		syslog(LOG_ERR, "packetbuffer: snappy_compress: snappy buffer allocation failed - PACKETBUFFER BLOCK DROPPED!");
		return(false);
	}
	snappy_status snappyRslt = snappy_compress((char*)this->block, this->size, (char*)snappyBuff, &snappyBuffSize);
	switch(snappyRslt) {
		case SNAPPY_OK:
			delete [] this->block;
			#if HEAPSAFE
				this->block = (u_char*)realloc_object(snappyBuff, snappyBuffSize, __FILE__, __LINE__, 16015);
			#else
				this->block = (u_char*)realloc(snappyBuff, snappyBuffSize);
			#endif
			this->size_compress = snappyBuffSize;
			sumPacketsSizeCompress[0] += this->size_compress;
			return(true);
		case SNAPPY_INVALID_INPUT:
			syslog(LOG_ERR, "packetbuffer: snappy_compress: invalid input");
			break;
		case SNAPPY_BUFFER_TOO_SMALL:
			syslog(LOG_ERR, "packetbuffer: snappy_compress: buffer is too small");
			break;
		default:
			syslog(LOG_ERR, "packetbuffer: snappy_compress: unknown error");
			break;
	}
	delete [] snappyBuff; 
	return(false);
}

bool pcap_block_store::compress_lz4() {
	#ifdef HAVE_LIBLZ4
	size_t lz4BuffSize = LZ4_compressBound(this->size);
	u_char *lz4Buff = new FILE_LINE(15015) u_char[lz4BuffSize];
	if(!lz4Buff) {
		syslog(LOG_ERR, "packetbuffer: lz4_compress: lz4 buffer allocation failed - PACKETBUFFER BLOCK DROPPED!");
		return(false);
	}
	int lz4_size = LZ4_compress((char*)this->block, (char*)lz4Buff, this->size);
	if(lz4_size > 0) {
		delete [] this->block;
		this->block = new FILE_LINE(15016) u_char[lz4_size];
		memcpy_heapsafe(this->block, lz4Buff, lz4_size,
				__FILE__, __LINE__);
		delete [] lz4Buff;
		this->size_compress = lz4_size;
		sumPacketsSizeCompress[0] += this->size_compress;
		return(true);
	} else {
		syslog(LOG_ERR, "packetbuffer: lz4_compress: error");
	}
	delete [] lz4Buff; 
	#endif //HAVE_LIBLZ4
	return(false);
}

bool pcap_block_store::uncompress(compress_method method) {
	if(!this->size_compress) {
		return(true);
	}
	switch(method == compress_method_default ? opt_pcap_queue_compress_method : method) {
	case lz4:
		#ifdef HAVE_LIBLZ4
		return(this->uncompress_lz4());
		#endif //HAVE_LIBLZ4
	case snappy:
	default:
		return(this->uncompress_snappy());
	}
	return(true);
}

bool pcap_block_store::uncompress_snappy() {
	if(!this->size_compress) {
		return(true);
	}
	size_t snappyBuffSize = this->size;
	u_char *snappyBuff = new FILE_LINE(15017) u_char[snappyBuffSize];
	snappy_status snappyRslt = snappy_uncompress((char*)this->block, this->size_compress, (char*)snappyBuff, &snappyBuffSize);
	switch(snappyRslt) {
		case SNAPPY_OK:
			delete [] this->block;
			this->block = snappyBuff;
			this->size_compress = 0;
			return(true);
		case SNAPPY_INVALID_INPUT:
			syslog(LOG_ERR, "packetbuffer: snappy_uncompress: invalid input");
			break;
		case SNAPPY_BUFFER_TOO_SMALL:
			syslog(LOG_ERR, "packetbuffer: snappy_uncompress: buffer is too small");
			break;
		default:
			syslog(LOG_ERR, "packetbuffer: snappy_uncompress: unknown error");
			break;
	}
	delete [] snappyBuff;
	return(false);
}



bool pcap_block_store::uncompress_lz4() {
	#ifdef HAVE_LIBLZ4
	if(!this->size_compress) {
		return(true);
	}
	size_t lz4BuffSize = this->size;
	u_char *lz4Buff = new FILE_LINE(15018) u_char[lz4BuffSize];
	if(LZ4_decompress_fast((char*)this->block, (char*)lz4Buff, this->size) >= 0) {
		delete [] this->block;
		this->block = lz4Buff;
		this->size_compress = 0;
		return(true);
	} else {
		syslog(LOG_ERR, "packetbuffer: lz4_uncompress: error");
	}
	delete [] lz4Buff;
	#endif //HAVE_LIBLZ4
	return(false);
}


pcap_block_store_queue::pcap_block_store_queue() {
	extern volatile int terminating;
	this->queueBlock = new FILE_LINE(15019) rqueue_quick<pcap_block_store*>(
				100000,
				100, 100,
				&terminating, true);
	this->sizeOfBlocks = 0;
	this->sizeOfBlocks_sync = 0;
}

pcap_block_store_queue::~pcap_block_store_queue() {
	pcap_block_store* blockStore;
	while(this->queueBlock->pop(&blockStore, false)) {
		delete blockStore;
	}
	delete this->queueBlock;
}


pcap_file_store::pcap_file_store(u_int id, const char *folder) {
	this->id = id;
	this->folder = folder;
	this->fileHandlePush = NULL;
	this->fileHandlePop = NULL;
	this->fileBufferPush = NULL;
	this->fileBufferPop = NULL;
	this->fileSize = 0;
	this->fileSizeFlushed = 0;
	this->countPush = 0;
	this->countPop = 0;
	this->full = false;
	this->timestampMS = getTimeMS_rdtsc();
	this->_sync_flush_file = 0;
}

pcap_file_store::~pcap_file_store() {
	this->destroy();
}

bool pcap_file_store::push(pcap_block_store *blockStore) {
	if(!this->fileHandlePush && !this->open(typeHandlePush)) {
		return(false);
	}
	size_t oldFileSize = this->fileSize;
	size_t sizeSaveBuffer = blockStore->getSizeSaveBuffer();
	u_char *saveBuffer = blockStore->getSaveBuffer();
	this->lock_sync_flush_file();
	unsigned long long timeBeforeWrite = getTimeNS();
	size_t rsltWrite = fwrite(saveBuffer, 1, sizeSaveBuffer, this->fileHandlePush);
	unsigned long long timeAfterWrite = getTimeNS();
	double diffTimeS = (timeAfterWrite - timeBeforeWrite) / 1e9;
	if(diffTimeS > 0.1) {
		syslog(LOG_NOTICE, "packetbuffer: slow write %zdB - %.3lfs", sizeSaveBuffer, diffTimeS);
	}
	if(rsltWrite == sizeSaveBuffer) {
		this->fileSize += rsltWrite;
	} else {
		syslog(LOG_ERR, "packetbuffer: write to %s failed", this->getFilePathName().c_str());
	}
	this->unlock_sync_flush_file();
	delete [] saveBuffer;
	if(rsltWrite == sizeSaveBuffer) {
		blockStore->freeBlock();
		blockStore->idFileStore = this->id;
		blockStore->filePosition = oldFileSize;
		++this->countPush;
		return(true);
	}
	fseek(this->fileHandlePush, oldFileSize, SEEK_SET);
	return(false);
}

bool pcap_file_store::pop(pcap_block_store *blockStore) {
	if(!blockStore->idFileStore) {
		syslog(LOG_ERR, "packetbuffer: invalid file store id");
		return(false);
	}
	if(!this->fileHandlePop && !this->open(typeHandlePop)) {
		return(false);
	}
	this->lock_sync_flush_file();
	if(this->fileSizeFlushed <= blockStore->filePosition) {
		this->fileSizeFlushed = this->fileSize;
		if(this->fileHandlePush) {
			fflush(this->fileHandlePush);
		}
	}
	this->unlock_sync_flush_file();
	fseek(this->fileHandlePop, blockStore->filePosition, SEEK_SET);
	blockStore->destroyRestoreBuffer();
	size_t readBuffSize = 1000;
	u_char *readBuff = new FILE_LINE(15020) u_char[readBuffSize];
	size_t readed;
	int rsltRestoreChunk = 0;
	while((readed = fread(readBuff, 1, readBuffSize, this->fileHandlePop)) > 0) {
		rsltRestoreChunk = blockStore->addRestoreChunk(readBuff, readBuff, readed, NULL, true);
		if(rsltRestoreChunk != 0) {
			break;
		}
	}
	if(rsltRestoreChunk < 0) {
		syslog(LOG_ERR, "packetbuffer: restore block from %s failed - %s", 
		       this->getFilePathName().c_str(),
		       blockStore->addRestoreChunk_getErrorString(rsltRestoreChunk).c_str());
	}
	delete [] readBuff;
	++this->countPop;
	blockStore->destroyRestoreBuffer();
	if(this->countPop == this->countPush && this->isFull()) {
		this->close(typeHandlePop);
	}
	return(rsltRestoreChunk > 0);
}

bool pcap_file_store::open(eTypeHandle typeHandle) {
	if((!(typeHandle & typeHandlePush) || this->fileHandlePush) &&
	   (!(typeHandle & typeHandlePop) || this->fileHandlePop)) {
		return(true);
	}
	bool rslt = true;
	string filePathName = this->getFilePathName();
	if(typeHandle & typeHandlePush) {
		remove(filePathName.c_str());
		this->fileHandlePush = fopen(filePathName.c_str(), "wb");
		if(this->fileHandlePush) {
			if(VERBOSE || DEBUG_VERBOSE) {
				ostringstream outStr;
				outStr << "create packet buffer store: " << filePathName
				       << " write handle: " << this->fileHandlePush
				       << endl;
				if(DEBUG_VERBOSE) {
					cout << outStr.str();
				} else {
					syslog(LOG_ERR, "packetbuffer: %s", outStr.str().c_str());
				}
			}
			this->fileBufferPush = new FILE_LINE(15021) u_char[FILE_BUFFER_SIZE];
			setbuffer(this->fileHandlePush, (char*)this->fileBufferPush, FILE_BUFFER_SIZE);
		} else {
			syslog(LOG_ERR, "packetbuffer: open %s for write failed", filePathName.c_str());
			rslt = false;
		}
	}
	if(typeHandle & typeHandlePop) {
		this->fileHandlePop = fopen(filePathName.c_str(), "rb");
		if(this->fileHandlePop) {
			if(VERBOSE || DEBUG_VERBOSE) {
				ostringstream outStr;
				outStr << "open file pcap store: " << filePathName
				       << " read handle: " << this->fileHandlePop
				       << endl;
				if(DEBUG_VERBOSE) {
					cout << outStr.str();
				} else {
					syslog(LOG_ERR, "packetbuffer: %s", outStr.str().c_str());
				}
			}
			this->fileBufferPop = new FILE_LINE(15022) u_char[FILE_BUFFER_SIZE];
			setbuffer(this->fileHandlePop, (char*)this->fileBufferPop, FILE_BUFFER_SIZE);
		} else {
			syslog(LOG_ERR, "packetbuffer: open %s for read failed", filePathName.c_str());
			rslt = false;
		}
	}
	return(rslt);
}

bool pcap_file_store::close(eTypeHandle typeHandle) {
	if(typeHandle & typeHandlePush &&
	   this->fileHandlePush != NULL) {
		this->lock_sync_flush_file();
		if(this->fileHandlePush) {
			fclose(this->fileHandlePush);
			this->fileHandlePush = NULL;
			delete [] this->fileBufferPush;
			this->fileBufferPush = NULL;
		}
		this->unlock_sync_flush_file();
	}
	if(typeHandle & typeHandlePop &&
	   this->fileHandlePop != NULL) {
		fclose(this->fileHandlePop);
		this->fileHandlePop = NULL;
		delete [] this->fileBufferPop;
		this->fileBufferPop = NULL;
	}
	return(true);
}

bool pcap_file_store::destroy() {
	this->close(typeHandleAll);
	string filePathName = this->getFilePathName();
	remove(filePathName.c_str());
	return(true);
}

string pcap_file_store::getFilePathName() {
	char filePathName[this->folder.length() + 100];
	sprintf(filePathName, "%s/pcap_store_%010u", this->folder.c_str(), this->id);
	return(filePathName);
}


pcap_store_queue::pcap_store_queue(const char *fileStoreFolder) {
	this->fileStoreFolder = fileStoreFolder;
	this->lastFileStoreId = 0;
	this->_sync_queue = 0;
	this->_sync_fileStore = 0;
	this->cleanupFileStoreCounter = 0;
	this->lastTimeLogErrDiskIsFull = 0;
	this->lastTimeLogErrMemoryIsFull = 0;
	this->firstTimeLogErrMemoryIsFull = 0;
	if(fileStoreFolder && fileStoreFolder[0] && access(fileStoreFolder, F_OK ) == -1) {
		mkdir_r(fileStoreFolder, 0700);
	}
}

pcap_store_queue::~pcap_store_queue() {
	pcap_file_store *fileStore;
	while(this->fileStore.size()) {
		fileStore = this->fileStore.front();
		delete fileStore;
		this->fileStore.pop_front();
	}
	pcap_block_store *blockStore;
	while(this->queueStore.size()) {
		blockStore = this->queueStore.front();
		delete blockStore;
		this->queueStore.pop_front();
	}
}

bool pcap_store_queue::push(pcap_block_store *blockStore, bool deleteBlockStoreIfFail) {
	if(opt_scanpcapdir[0]) {
		unsigned int usleepCounter = 0;
		while(!is_terminating() && buffersControl.getPerc_pb() > 20) {
			USLEEP_C(100, usleepCounter++);
		}
		if(is_terminating()) {
			return(false);
		}
	}
	bool saveToFileStore = false;
	bool locked_fileStore = false;
	if(opt_pcap_queue_store_queue_max_disk_size &&
	   this->fileStoreFolder.length()) {
		if(!buffersControl.check__pb__add_used()) {
			saveToFileStore = true;
		} else if(!__config_ENABLE_TOGETHER_READ_WRITE_FILE) {
			this->lock_fileStore();
			locked_fileStore = true;
			if(this->fileStore.size() &&
			   !this->fileStore[this->fileStore.size() - 1]->isFull(buffersControl.get__pb_used_size() == 0)) {
				saveToFileStore = true;
			} else {
				this->unlock_fileStore();
				locked_fileStore = false;
			}
		}
	}
	if(saveToFileStore) {
		pcap_file_store *fileStore;
		if(!locked_fileStore) {
			this->lock_fileStore();
		}
		if(this->getFileStoreUseSize(false) > opt_pcap_queue_store_queue_max_disk_size) {
			diskBufferIsFull_log();
			if(deleteBlockStoreIfFail) {
				delete blockStore;
			}
			this->unlock_fileStore();
			return(false);
		}
		if(!this->fileStore.size() ||
		   this->fileStore[this->fileStore.size() - 1]->isFull()) {
			++this->lastFileStoreId;
			if(!this->lastFileStoreId) {
				++this->lastFileStoreId;
			}
			fileStore = new FILE_LINE(15023) pcap_file_store(this->lastFileStoreId, this->fileStoreFolder.c_str());
			this->fileStore.push_back(fileStore);
		} else {
			fileStore = this->fileStore[this->fileStore.size() - 1];
		}
		if(!fileStore->push(blockStore)) {
			if(deleteBlockStoreIfFail) {
				delete blockStore;
			}
			this->unlock_fileStore();
			return(false);
		}
		this->unlock_fileStore();
	} else {
		if(locked_fileStore) {
			this->unlock_fileStore();
		}
		if(!buffersControl.check__pb__add_used()) {
			memoryBufferIsFull_log();
			if(deleteBlockStoreIfFail) {
				delete blockStore;
			}
			packetbuffer_memory_is_full = true;
			return(false);
		} else {
			buffersControl.add__pb_used_size(blockStore->getUseAllSize());
			packetbuffer_memory_is_full = false;
			firstTimeLogErrMemoryIsFull = 0;
		}
	}
	this->lock_queue();
	this->queueStore.push_back(blockStore);
	this->unlock_queue();
	return(true);
}

bool pcap_store_queue::pop(pcap_block_store **blockStore) {
	*blockStore = NULL;
	this->lock_queue();
	if(this->queueStore.size()) {
		*blockStore = this->queueStore.front();
		this->queueStore.pop_front();
	}
	this->unlock_queue();
	if(*blockStore && 
	   opt_pcap_queue_store_queue_max_disk_size &&
	   this->fileStoreFolder.length()) {
		if((*blockStore)->idFileStore) {
			pcap_file_store *_fileStore = this->findFileStoreById((*blockStore)->idFileStore);
			if(!_fileStore) {
				#if DEBUG_DESTROY_PCAP_BLOCK_STORE
				(*blockStore)->destroy_src_flag[0] = 2;
				#endif
				delete *blockStore;
				return(false);
			}
			unsigned int usleepCounter = 0;
			while(!__config_ENABLE_TOGETHER_READ_WRITE_FILE && !_fileStore->full) {
				USLEEP_C(100, usleepCounter++);
			}
			if(!_fileStore->pop(*blockStore)) {
				#if DEBUG_DESTROY_PCAP_BLOCK_STORE
				(*blockStore)->destroy_src_flag[0] = 3;
				#endif
				delete *blockStore;
				return(false);
			}
		}
		++this->cleanupFileStoreCounter;
		if(!(this->cleanupFileStoreCounter % 100)) {
			this->cleanupFileStore();
		}
	}
	return(true);
}

void pcap_store_queue::init() {
	if(opt_pcap_queue_store_queue_max_disk_size &&
	   this->fileStoreFolder.length()) {
		DIR* dp = opendir(this->fileStoreFolder.c_str());
		if(!dp) {
			return;
		}
		dirent* de;
		while((de = readdir(dp)) != NULL) {
			if(string(de->d_name).substr(0, 11) == "pcap_store_") { 
				unlink((this->fileStoreFolder + '/' + de->d_name).c_str());
			}
		}
		closedir(dp);
	}
}

pcap_file_store *pcap_store_queue::findFileStoreById(u_int id) {
	pcap_file_store *fileStore = NULL;
	this->lock_fileStore();
	for(size_t i  = 0; i < this->fileStore.size(); i++) {
		if(this->fileStore[i]->id == id) {
			fileStore = this->fileStore[i];
			break;
		}
	}
	this->unlock_fileStore();
	return(fileStore);
}

void pcap_store_queue::cleanupFileStore() {
	this->lock_fileStore();
	while(this->fileStore.size()) {
		pcap_file_store *fileStore = this->fileStore.front();
		if(fileStore->isForDestroy()) {
			delete fileStore;
			this->fileStore.pop_front();
		} else {
			break;
		}
	}
	this->unlock_fileStore();
}

uint64_t pcap_store_queue::getFileStoreUseSize(bool lock) {
	if(lock) {
		this->lock_fileStore();
	}
	uint64_t size = 0;
	size_t itemsInFileStore = this->fileStore.size();
	for(size_t i = 0; i < itemsInFileStore; i++) {
		size += this->fileStore[i]->fileSize;
	}
	if(lock) {
		this->unlock_fileStore();
	}
	return(size);
}

void pcap_store_queue::memoryBufferIsFull_log() {
	static volatile int _sync = 0;
	static volatile u_int64_t lastTimeLogErrMemoryIsFull_s = 0;
	u_int64_t actTime = getTimeMS();
	__SYNC_LOCK(_sync);
	if(actTime - 5000 > this->lastTimeLogErrMemoryIsFull &&
	   actTime - 5000 > lastTimeLogErrMemoryIsFull_s) {
		this->lastTimeLogErrMemoryIsFull = actTime;
		lastTimeLogErrMemoryIsFull_s = actTime;
		__SYNC_UNLOCK(_sync);
		syslog(LOG_ERR, "packetbuffer: MEMORY IS FULL");
		if(!this->firstTimeLogErrMemoryIsFull) {
			this->firstTimeLogErrMemoryIsFull = actTime;
		} else if(this->lastTimeLogErrMemoryIsFull > this->firstTimeLogErrMemoryIsFull &&
			  this->lastTimeLogErrMemoryIsFull - this->firstTimeLogErrMemoryIsFull > 2 * 60 * 1000) {
			extern bool opt_abort_if_heap_full;
			if(opt_abort_if_heap_full || sverb.abort_if_heap_full) {
				syslog(LOG_NOTICE, "buffersControl: %s", buffersControl.debug().c_str());
				syslog(LOG_ERR, "MEMORY IS FULL - ABORT!");
				abort();
			}
		}
	} else {
		__SYNC_UNLOCK(_sync);
	}
}

void pcap_store_queue::diskBufferIsFull_log() {
	u_int64_t actTime = getTimeMS();
	if(actTime - 1000 > this->lastTimeLogErrDiskIsFull) {
		syslog(LOG_ERR, "packetbuffer: DISK IS FULL");
		this->lastTimeLogErrDiskIsFull = actTime;
	}
}


PcapQueue::PcapQueue(eTypeQueue typeQueue, const char *nameQueue) {
	this->typeQueue = typeQueue;
	this->nameQueue = nameQueue;
	this->threadHandle = 0;
	this->writeThreadHandle = 0;
	this->enableMainThread = true;
	this->enableWriteThread = false;
	this->enableAutoTerminate = true;
	this->threadInitOk = false;
	this->threadInitFailed = false;
	this->writeThreadInitOk = false;
	this->threadTerminated = false;
	this->writeThreadTerminated = false;
	this->threadDoTerminate = false;
	this->mainThreadId = 0;
	this->writeThreadId = 0;
	for(int i = 0; i < PCAP_QUEUE_NEXT_THREADS_MAX; i++) {
		this->nextThreadsId[i] = 0;
	}
	memset(this->mainThreadPstatData, 0, sizeof(this->mainThreadPstatData));
	memset(this->writeThreadPstatData, 0, sizeof(this->writeThreadPstatData));
	for(int i = 0; i < PCAP_QUEUE_NEXT_THREADS_MAX; i++) {
		memset(this->nextThreadsPstatData[i], 0, sizeof(this->nextThreadsPstatData[i]));
	}
	memset(this->procPstatData, 0, sizeof(this->procPstatData));
	this->packetBuffer = NULL;
	this->instancePcapHandle = NULL;
	this->instancePcapFifo = NULL;
	this->initAllReadThreadsFinished = false;
	#if SNIFFER_THREADS_EXT
	thread_data_main = NULL;
	thread_data_write = NULL;
	#endif
	this->counter_calls_old = 0;
	this->counter_calls_clean_old = 0;
	this->counter_calls_save_1_old = 0;
	this->counter_calls_save_2_old = 0;
	this->counter_registers_old = 0;
	this->counter_registers_clean_old = 0;
	this->counter_sip_packets_old[0] = 0;
	this->counter_sip_packets_old[1] = 0;
	this->counter_sip_register_packets_old = 0;
	this->counter_sip_message_packets_old = 0;
	this->counter_rtp_packets_old[0] = 0;
	this->counter_rtp_packets_old[1] = 0;
	this->counter_all_packets_old = 0;
	for(unsigned i = 0; i < sizeof(this->counter_user_packets_old) / sizeof(this->counter_user_packets_old[0]); i++) {
		this->counter_user_packets_old[i] = 0;
	}
	this->lastTimeLogErrPcapNextExNullPacket = 0;
	this->lastTimeLogErrPcapNextExErrorReading = 0;
	this->pcapStatLogCounter = 0;
	this->pcapStatCpuCheckCounter = 0;
}

PcapQueue::~PcapQueue() {
	if(this->packetBuffer) {
		delete [] this->packetBuffer;
		syslog(LOG_NOTICE, "packetbuffer terminating (%s): free packetBuffer", nameQueue.c_str());
	}
}

void PcapQueue::setEnableMainThread(bool enable) {
	this->enableMainThread = enable;
}

void PcapQueue::setEnableWriteThread(bool enable) {
	this->enableWriteThread = enable;
}

void PcapQueue::setEnableAutoTerminate(bool enableAutoTerminate) {
	this->enableAutoTerminate = enableAutoTerminate;
}

bool PcapQueue::start() {
	if(this->init()) {
		return(this->createThread());
	} else {
		this->threadTerminated = true;
		return(false);
	}
}

void PcapQueue::terminate() {
	this->threadDoTerminate = true;
}

bool PcapQueue::isInitOk() {
	return((!this->enableMainThread || this->threadInitOk) &&
	       (!this->enableWriteThread || this->writeThreadInitOk));
}

bool PcapQueue::isTerminated() {
	return((!this->enableMainThread || this->threadTerminated) &&
	       (!this->enableWriteThread || this->writeThreadTerminated));
}

void PcapQueue::setInstancePcapHandle(PcapQueue *pcapQueue) {
	this->instancePcapHandle = pcapQueue;
}

void PcapQueue::setInstancePcapFifo(PcapQueue_readFromFifo *pcapQueue) {
	this->instancePcapFifo = pcapQueue;
}

void PcapQueue::pcapStat(pcapStatTask task, int statPeriod) {
	u_int64_t startTimeMS = getTimeMS_rdtsc();
	vector<u_int64_t> lapTime;
	vector<string> lapTimeDescr;
	int pstatDataIndex = task == pcapStatLog ? 0 : 1;
	
	if(task == pcapStatLog) {
		++pcapStatLogCounter;
		sumPacketsCounterIn[2] = sumPacketsCounterIn[0] - sumPacketsCounterIn[1];
		sumPacketsCounterIn[1] = sumPacketsCounterIn[0];
		sumPacketsCounterOut[2] = sumPacketsCounterOut[0] - sumPacketsCounterOut[1];
		sumPacketsCounterOut[1] = sumPacketsCounterOut[0];
		sumBlocksCounterIn[2] = sumBlocksCounterIn[0] - sumBlocksCounterIn[1];
		sumBlocksCounterIn[1] = sumBlocksCounterIn[0];
		sumBlocksCounterOut[2] = sumBlocksCounterOut[0] - sumBlocksCounterOut[1];
		sumBlocksCounterOut[1] = sumBlocksCounterOut[0];
		sumPacketsSize[2] = sumPacketsSize[0] - sumPacketsSize[1];
		sumPacketsSize[1] = sumPacketsSize[0];
		#if LOG_PACKETS_PER_SEC or LOG_PACKETS_SUM
		sumPacketsCount[2] = sumPacketsCount[0] - sumPacketsCount[1];
		sumPacketsCount[1] = sumPacketsCount[0];
		#endif
		sumPacketsSizeOut[2] = sumPacketsSizeOut[0] - sumPacketsSizeOut[1];
		sumPacketsSizeOut[1] = sumPacketsSizeOut[0];
		#if LOG_PACKETS_PER_SEC or LOG_PACKETS_SUM
		sumPacketsCountOut[2] = sumPacketsCountOut[0] - sumPacketsCountOut[1];
		sumPacketsCountOut[1] = sumPacketsCountOut[0];
		#endif
		sumPacketsSizeCompress[2] = sumPacketsSizeCompress[0] - sumPacketsSizeCompress[1];
		sumPacketsSizeCompress[1] = sumPacketsSizeCompress[0];
	}
	if(task == pcapStatCpuCheck) {
		++pcapStatCpuCheckCounter;
	}

	extern int opt_cpu_limit_warning_t0;
	extern int opt_cpu_limit_new_thread;
	extern int opt_cpu_limit_new_thread_if_heap_grows;
	extern int opt_cpu_limit_new_thread_high;
	extern int opt_cpu_limit_delete_thread;
	extern int opt_cpu_limit_delete_t2sip_thread;
	extern int opt_heap_limit_new_thread;

	if(task == pcapStatLog && this->instancePcapHandle) {
		if(this->instancePcapHandle->initAllReadThreadsFinished) {
			this->instancePcapHandle->prepareLogTraffic();
		} else {
			return;
		}
	}
	
	ostringstream outStr;
	outStr << fixed;
	pcap_drop_flag = 0;
	
	string pcapStatString_interface_rslt;
	if(task == pcapStatLog) {
		if(sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("pcapStatString_interface-before");
		}
		pcapStatString_interface_rslt = this->instancePcapHandle ? 
						 this->instancePcapHandle->pcapStatString_interface(statPeriod) :
						 this->pcapStatString_interface(statPeriod);
		if(sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("pcapStatString_interface-after");
		}
	}
	
	size_t count_calls = calltable->getCountCalls();
	heap_pb_perc = buffersControl.getPerc_pb();
	heap_pb_used_perc = buffersControl.getPerc_pb_used();
	heap_pb_used_dequeu_perc = buffersControl.getPerc_pb_used_dequeu();
	heap_pb_trash_perc = buffersControl.getPerc_pb_trash();
	heap_pb_pool_perc = buffersControl.getPerc_pb_pool();
	
	if(task == pcapStatCpuCheck) {
		extern bool opt_processing_limitations;
		extern int opt_processing_limitations_heap_high_limit;
		extern int opt_processing_limitations_heap_low_limit;
		extern cProcessingLimitations processing_limitations;
		if(opt_processing_limitations) {
			if(heap_pb_perc > opt_processing_limitations_heap_high_limit) {
				processing_limitations.incLimitations(cProcessingLimitations::_pl_all);
			} else if(calls_counter > 10000 &&
				  calls_counter > (int)count_calls * 2) {
				processing_limitations.incLimitations(cProcessingLimitations::_pl_active_calls);
			}
			if(heap_pb_perc < opt_processing_limitations_heap_low_limit) {
				processing_limitations.decLimitations(calls_counter < (int)count_calls * 1.5 ?
								       cProcessingLimitations::_pl_all :
								       cProcessingLimitations::_pl_rtp);
			}
		}
	}
	
	if(task == pcapStatLog && sverb.log_profiler) {
		lapTime.push_back(getTimeMS_rdtsc());
		lapTimeDescr.push_back("check heap");
	}
	
	if(task == pcapStatLog && !this->isMirrorSender()) {
		outStr << "calls[" << count_calls << ",r:" << calltable->registers_listMAP.size() << "]"
		       << "[";
		#if EXPERIMENTAL_SEPARATE_PROCESSSING
		if(separate_processing() == 2) {
			outStr << calltable->calls_queue.size();
		} else {
			outStr << calls_counter;
		}
		#else
		outStr << calls_counter;
		#endif
		extern volatile int storing_cdr_next_threads_count;
		if(storing_cdr_next_threads_count > 1 && calls_for_store_counter > 0) {
			outStr << "(s" << calls_for_store_counter << ")";
			calls_for_store_counter = 0;
		}
		outStr << ",r:" << registers_counter << "]";
		calltable->lock_calls_audioqueue();
		size_t audioQueueSize = calltable->audio_queue.size();
		if(audioQueueSize) {
			size_t audioQueueThreads = calltable->getCountActiveAudioQueueThreads(false);
			outStr << " audio[" << audioQueueSize << "/" << audioQueueThreads <<"]";
		}
		calltable->unlock_calls_audioqueue();
		string trabscribe_queue_log = transcribeQueueLog();
		if(!trabscribe_queue_log.empty()) {
			outStr << " transcribe[" << trabscribe_queue_log <<"]";
		}
		if(sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("calls");
		}
#if defined(HAVE_LIBGNUTLS) and defined(HAVE_SSL_WS)
		extern string getSslStat();
		string sslStat = getSslStat();
		if(!sslStat.empty()) {
			outStr << sslStat;
		}
		if(sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("ssl stat");
		}
#endif
		outStr << " ";
		if(opt_enable_ss7) {
			outStr << "ss7[" << calltable->ss7_listMAP.size() << "]"
			       << "[" << calltable->ss7_queue.size() << "] ";
		}
		if(opt_ipaccount) {
			outStr << "ipacc_buffer[" << lengthIpaccBuffer() << "/" << sizeIpaccBuffer() << "] ";
		}
		if(opt_rrd) {
			rrd_set_value(RRD_VALUE_inv, count_calls);
			rrd_set_value(RRD_VALUE_reg, calltable->registers_listMAP.size());
		}
		if(sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("rrd");
		}
		extern u_int64_t counter_calls;
		extern u_int64_t counter_calls_clean;
		extern volatile u_int64_t counter_calls_save_1;
		extern volatile u_int64_t counter_calls_save_2;
		extern u_int64_t counter_registers;
		extern u_int64_t counter_registers_clean;
		extern u_int64_t counter_sip_packets[2];
		extern u_int64_t counter_sip_register_packets;
		extern u_int64_t counter_sip_message_packets;
		extern u_int64_t counter_rtp_packets[2];
		extern u_int64_t counter_all_packets;
		extern volatile u_int64_t counter_user_packets[5];
		if(this->counter_calls_old ||
		   this->counter_calls_clean_old ||
		   this->counter_registers_old ||
		   this->counter_registers_clean_old ||
		   this->counter_sip_packets_old[0] ||
		   this->counter_sip_packets_old[1] ||
		   this->counter_rtp_packets_old[0] ||
		   this->counter_rtp_packets_old[1] ||
		   this->counter_all_packets_old) {
			outStr << "PS[C:";
			if(this->counter_calls_old) {
				long unsigned v = (counter_calls - this->counter_calls_old) / statPeriod;
				outStr << v;
				if(opt_rrd) {
					rrd_set_value(RRD_VALUE_PS_C, v);
				}
			} else {
				outStr << "-";
			}
			outStr << "/";
			if(this->counter_calls_clean_old) {
				outStr << '-' << (counter_calls_clean - this->counter_calls_clean_old) / statPeriod;
			} else {
				outStr << "-";
			}
			if(this->counter_calls_save_1_old ||
			   this->counter_calls_save_2_old) {
				outStr << "(";
				if(this->counter_calls_save_1_old) {
					outStr << (counter_calls_save_1 - this->counter_calls_save_1_old) / statPeriod;
				} else {
					outStr << "-";
				}
				outStr << "/";
				if(this->counter_calls_save_2_old) {
					outStr << (counter_calls_save_2 - this->counter_calls_save_2_old) / statPeriod;
				} else {
					outStr << "-";
				}
				outStr << ")";
			}
			outStr << " r:";
			if(this->counter_registers_old) {
				outStr << (counter_registers - this->counter_registers_old) / statPeriod;
			} else {
				outStr << "-";
			}
			outStr << "/";
			if(this->counter_registers_clean_old) {
				outStr << '-' << (counter_registers_clean - this->counter_registers_clean_old) / statPeriod;
			} else {
				outStr << "-";
			}
			outStr << " S:";
			if(this->counter_sip_packets_old[0]) {
				long unsigned v = (counter_sip_packets[0] - this->counter_sip_packets_old[0]) / statPeriod;
				outStr << v;
				if(opt_rrd) {
					rrd_set_value(RRD_VALUE_PS_S0, v);
				}
			} else {
				outStr << "-";
			}
			outStr << "/";
			if(this->counter_sip_packets_old[1]) {
				long unsigned v = (counter_sip_packets[1] - this->counter_sip_packets_old[1]) / statPeriod;
				outStr << v;
				if(opt_rrd) {
					rrd_set_value(RRD_VALUE_PS_S1, v);
				}
			} else {
				outStr << "-";
			}
			outStr << " SR:";
			if(this->counter_sip_register_packets_old) {
				long unsigned v = (counter_sip_register_packets - this->counter_sip_register_packets_old) / statPeriod;
				outStr << v;
				if(opt_rrd) {
					rrd_set_value(RRD_VALUE_PS_SR, v);
				}
			} else {
				outStr << "-";
			}
			outStr << " SM:";
			if(this->counter_sip_message_packets_old) {
				long unsigned v = (counter_sip_message_packets - this->counter_sip_message_packets_old) / statPeriod;
				outStr << v;
				if(opt_rrd) {
					rrd_set_value(RRD_VALUE_PS_SM, v);
				}
			} else {
				outStr << "-";
			}
			outStr << " R:";
			if(this->counter_rtp_packets_old[0]) {
				long unsigned v = (counter_rtp_packets[0] - this->counter_rtp_packets_old[0]) / statPeriod;
				outStr << v;
				if(opt_rrd) {
					rrd_set_value(RRD_VALUE_PS_R, v);
				}
			} else {
				outStr << "-";
			}
			outStr << "/";
			if(this->counter_rtp_packets_old[1]) {
				long unsigned v = (counter_rtp_packets[1] - this->counter_rtp_packets_old[1]) / statPeriod;
				outStr << v;
			} else {
				outStr << "-";
			}
			outStr << " A:";
			if(this->counter_all_packets_old) {
				long unsigned v = (counter_all_packets - this->counter_all_packets_old) / statPeriod;
				outStr << v;
				if(opt_rrd) {
					rrd_set_value(RRD_VALUE_PS_A, v);
				}
			} else {
				outStr << "-";
			}
			for(unsigned i = 0; i < sizeof(this->counter_user_packets_old) / sizeof(this->counter_user_packets_old[0]); i++) {
				if(counter_user_packets[i] && this->counter_user_packets_old[i]) {
					outStr << " U" << i << ":";
					outStr << (counter_user_packets[i] - this->counter_user_packets_old[i]) / statPeriod;
				}
			}
			outStr << "] ";
		}
		this->counter_calls_old = counter_calls;
		this->counter_calls_clean_old = counter_calls_clean;
		this->counter_calls_save_1_old = counter_calls_save_1;
		this->counter_calls_save_2_old = counter_calls_save_2;
		this->counter_registers_old = counter_registers;
		this->counter_registers_clean_old = counter_registers_clean;
		this->counter_sip_packets_old[0] = counter_sip_packets[0];
		this->counter_sip_packets_old[1] = counter_sip_packets[1];
		this->counter_sip_register_packets_old = counter_sip_register_packets;
		this->counter_sip_message_packets_old = counter_sip_message_packets;
		this->counter_rtp_packets_old[0] = counter_rtp_packets[0];
		this->counter_rtp_packets_old[1] = counter_rtp_packets[1];
		this->counter_all_packets_old = counter_all_packets;
		for(unsigned i = 0; i < sizeof(this->counter_user_packets_old) / sizeof(this->counter_user_packets_old[0]); i++) {
			this->counter_user_packets_old[i] = counter_user_packets[i];
		}
		if(sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("packet counters");
		}
		extern bool opt_save_query_main_to_files;
		if(loadFromQFiles) {
			string stat = loadFromQFiles->getLoadFromQFilesStat();
			string stat_proc = sverb.qfiles ? loadFromQFiles->getLoadFromQFilesStat(true) : "";
			u_int32_t avgDelayQuery = SqlDb::getAvgDelayQuery(SqlDb::_tq_store);
			u_int32_t countFilesQuery = loadFromQFiles->getLoadFromQFilesCount();
			SqlDb::resetDelayQuery(SqlDb::_tq_store);
			if(!stat.empty()) {
				outStr << "SQLf["
				       << stat;
				if(avgDelayQuery) {
					outStr << " / " << setprecision(3) << (double)avgDelayQuery / 1000 << "s";
				}
				if(!stat_proc.empty()) {
					outStr << " / " << stat_proc;
				}
				outStr << "] ";
			}
			if(opt_rrd && (avgDelayQuery || countFilesQuery)) {
				rrd_set_value(RRD_VALUE_SQLf_D, avgDelayQuery);
				rrd_set_value(RRD_VALUE_SQLf_C, countFilesQuery);
			}
		}
		if(!loadFromQFiles || !opt_save_query_main_to_files || sverb.force_log_sqlq) {
			bool filled = false;
			if(isCloud()) {
				int sizeSQLq = sqlStore->getSize(1, 0) +
					       (loadFromQFiles ? loadFromQFiles->getSize(1, 0) : 0);
				outStr << "SQLq[";
				outStr << (sizeSQLq >= 0 ? sizeSQLq : 0);
				filled = true;
			} else {
				map<int, int> size_map;
				map<int, int> size_map_by_id_2;
				sqlStore->fillSizeMap(&size_map, &size_map_by_id_2);
				if(loadFromQFiles) {
					loadFromQFiles->fillSizeMap(&size_map, &size_map_by_id_2);
				}
				bool first = true;
				for(map<int, int>::iterator iter = size_map_by_id_2.begin(); iter != size_map_by_id_2.end(); iter++) {
					int id_main = iter->first / 100;
					int id_2 = iter->first % 100;
					int size = iter->second;
					string id_main_str =
						id_main == STORE_PROC_ID_CDR ? "C" :
						id_main == STORE_PROC_ID_CDR_REDIRECT ? "Cr" :
						id_main == STORE_PROC_ID_CHARTS_CACHE  ? "ch" :
						id_main == STORE_PROC_ID_MESSAGE ? "M" :
						id_main == STORE_PROC_ID_SIP_MSG ? "SM" :
						id_main == STORE_PROC_ID_REGISTER ? "R" :
						id_main == STORE_PROC_ID_SS7 ? "7" :
						id_main == STORE_PROC_ID_SAVE_PACKET_SQL ? "L" :
						id_main == STORE_PROC_ID_CLEANSPOOL ? "Cl" :
						id_main == STORE_PROC_ID_HTTP ? "H" :
						id_main == STORE_PROC_ID_OTHER ? "O" :
						("i" + intToString(id_main) + "_");
					if(!filled) {
						outStr << "SQLq[";
					}
					outStr << (first ? "" : " ") << id_main_str << (id_2 + 1) << ":" << size;
					first = false;
					filled = true;
				}
				if(opt_rrd) {
					for(map<int, int>::iterator iter = size_map.begin(); iter != size_map.end(); iter++) {
						int id_main = iter->first;
						int size = iter->second;
						const char *id_main_rrd_str = 
							id_main == STORE_PROC_ID_CDR ? RRD_VALUE_SQLq_C :
							id_main == STORE_PROC_ID_MESSAGE ? RRD_VALUE_SQLq_M :
							id_main == STORE_PROC_ID_SIP_MSG ? RRD_VALUE_SQLq_SM :
							id_main == STORE_PROC_ID_REGISTER ? RRD_VALUE_SQLq_R :
							id_main == STORE_PROC_ID_HTTP ? RRD_VALUE_SQLq_H :
							NULL;
						if(id_main_rrd_str) {
							rrd_add_value(id_main_rrd_str, size);
						}
					}
				}
			}
			if(filled) {
				for(int i = 0; i < 2; i++) {
					SqlDb::eTypeQuery typeQuery = i == 0 ? SqlDb::_tq_std : SqlDb::_tq_redirect;
					const char *prefix = i == 0 ? "" : "R";
					u_int32_t avgDelayQuery = SqlDb::getAvgDelayQuery(typeQuery);
					if(avgDelayQuery) {
						outStr << " / " << setprecision(3) << prefix << (double)avgDelayQuery / 1000 << "s";
					}
					u_int32_t countQuery = SqlDb::getCountQuery(typeQuery);
					if(countQuery) {
						outStr << " / " << prefix << (countQuery / statPeriod) << "q/s";
					}
					SqlDb::resetDelayQuery(typeQuery);
				}
				u_int64_t insertCount = SqlDb::getCountInsert();
				if(insertCount) {
					if(insertCount / statPeriod) {
						outStr << " / " << (insertCount / statPeriod) << "i/s";
					}
					SqlDb::resetCountInsert();
				}
				outStr << "] ";
			}
		}
		if(sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("sql");
		}
	}
	
	double useAsyncWriteBuffer = buffersControl.getPerc_asyncwrite();
	if(task == pcapStatLog) {
		outStr << "heap[u" << setprecision(0) << heap_pb_used_perc
		       << "|t" << setprecision(0) << heap_pb_trash_perc;
		if(sverb.heap_use_time) {
			unsigned long trashMinTime;
			unsigned long trashMaxTime;
			buffersControl.PcapQueue_readFromFifo__blockStoreTrash_time_get(&trashMinTime, &trashMaxTime);
			buffersControl.PcapQueue_readFromFifo__blockStoreTrash_time_clear();
			if(trashMinTime || trashMaxTime) {
				outStr << "(" << trashMinTime << "-" << trashMaxTime << "ms)";
			}
		}
		if(opt_rrd) {
			rrd_set_value(RRD_VALUE_buffer, heap_pb_perc);
		}
		if(sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("heap");
		}
		if(opt_use_dpdk && opt_dpdk_rotate_packetbuffer &&
		   (opt_dpdk_copy_packetbuffer || opt_dpdk_prealloc_packetbuffer)) {
			outStr << "|p" << setprecision(0) << heap_pb_pool_perc;
		}
		outStr << "|a" << setprecision(0) << useAsyncWriteBuffer
		       << "] ";
		if(opt_rrd) {
			rrd_set_value(RRD_VALUE_ratio, useAsyncWriteBuffer);
		}
		unsigned int dequeu_time = buffersControl.get_dequeu_time();
		if(heap_pb_used_dequeu_perc > 0 || dequeu_time) {
			outStr << "deq["
			       << heap_pb_used_dequeu_perc << "/"
			       << dequeu_time << "] ";
		}
	}
	if(task == pcapStatCpuCheck) {
		if(useAsyncWriteBuffer > 50) {
			if(CleanSpool::suspend()) {
				syslog(LOG_NOTICE, "large workload disk operation - cleanspool suspended");
			}
		} else if(useAsyncWriteBuffer < 10) {
			if(CleanSpool::resume()) {
				syslog(LOG_NOTICE, "cleanspool resumed");
			}
		}
	}
	
	if(task == pcapStatLog) {
		if(this->instancePcapHandle) {
			unsigned long bypassBufferSizeExceeded = this->instancePcapHandle->pcapStat_get_bypass_buffer_size_exeeded();
			string statPacketDrops = this->instancePcapHandle->getStatPacketDrop();
			if(bypassBufferSizeExceeded || !statPacketDrops.empty()) {
				outStr << "drop[";
				if(bypassBufferSizeExceeded) {
					outStr << "H:" << bypassBufferSizeExceeded;
					if(opt_rrd) {
						rrd_set_value(RRD_VALUE_exceeded, bypassBufferSizeExceeded);
					}
				}
				if(!statPacketDrops.empty()) {
					if(bypassBufferSizeExceeded) {
						outStr << " ";
					}
					if(opt_rrd) {
						rrd_set_value(RRD_VALUE_packets, this->instancePcapHandle->getCountPacketDrop());
					}
					outStr << statPacketDrops;
				}
				outStr << "] ";
			}
		}
		if(sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("drop");
		}
		double diskBufferMb = this->pcapStat_get_disk_buffer_mb();
		if(diskBufferMb >= 0) {
			double diskBufferPerc = this->pcapStat_get_disk_buffer_perc();
			outStr << "fileq[" << setprecision(1) << diskBufferMb << "MB "
			       << setprecision(1) << diskBufferPerc << "%] ";
		}
		double compress = this->pcapStat_get_compress();
		if(compress >= 0) {
			outStr << "comp[" << setprecision(0) << compress << "] ";
		}
		double speed_mb_s = this->pcapStat_get_speed_mb_s(statPeriod);
		double speed_out_mb_s = this->pcapStat_get_speed_out_mb_s(statPeriod);
		#if LOG_PACKETS_PER_SEC
		double speed_packets_s = this->pcapStat_get_speed_packets_s(statPeriod);
		double speed_out_packets_s = this->pcapStat_get_speed_out_packets_s(statPeriod);
		#endif
		if(speed_mb_s >= 0 || speed_out_mb_s >= 0) {
			outStr << "[";
			#if LOG_PACKETS_PER_SEC or LOG_PACKETS_SUM
			bool needSeparator = false;
			#endif
			if(speed_mb_s >= 0 || speed_out_mb_s >= 0) {
				if(speed_mb_s >= 0) {
					outStr << setprecision(1) << speed_mb_s;
				} else {
					outStr << "-";
				}
				if(speed_out_mb_s >= 0) {
					outStr << "/";
					if(speed_out_mb_s >= 0) {
						outStr << setprecision(1) << speed_out_mb_s;
					} else {
						outStr << "-";
					}
				}
				outStr << "Mb/s";
				#if LOG_PACKETS_PER_SEC or LOG_PACKETS_SUM
				needSeparator = true;
				#endif
			}
			#if LOG_PACKETS_PER_SEC
			if(speed_packets_s >= 0 || speed_out_packets_s >= 0) {
				if(needSeparator) {
					outStr << " ";
					needSeparator = false;
				}
				if(speed_packets_s >= 0) {
					outStr << setprecision(0) << speed_packets_s;
				} else {
					outStr << "-";
				}
				if(speed_out_packets_s >= 0) {
					outStr << "/";
					if(speed_out_mb_s >= 0) {
						outStr << setprecision(0) << speed_out_packets_s;
					} else {
						outStr << "-";
					}
				}
				outStr << "p/s";
				needSeparator = true;
			}
			#endif
			#if LOG_PACKETS_SUM
			if(needSeparator) {
				outStr << " ";
				needSeparator = false;
			}
			if(sumPacketsCount[0] > 0) {
				outStr << setprecision(0) << sumPacketsCount[0];
			} else {
				outStr << "-";
			}
			outStr << "/";
			if(sumPacketsCountOut[0] > 0) {
				outStr << setprecision(0) << sumPacketsCountOut[0];
			} else {
				outStr << "-";
			}
			outStr << "p";
			needSeparator = true;
			#endif
			outStr << "] ";
			if(opt_rrd) {
				rrd_set_value(RRD_VALUE_mbs, speed_mb_s);
			}
			last_traffic = speed_mb_s;
		}
		
		extern unsigned int opt_push_batch_limit_for_traffic_lt_mb_s;
		if(opt_push_batch_limit_for_traffic_lt_mb_s) {
			extern unsigned int opt_push_batch_limit_ms;
			extern bool use_push_batch_limit_ms;
			use_push_batch_limit_ms = opt_push_batch_limit_ms > 0 && speed_mb_s < opt_push_batch_limit_for_traffic_lt_mb_s;
		}
		
		extern unsigned int opt_t2_boost_high_traffic_limit;
		if(opt_t2_boost == 2 && opt_t2_boost_high_traffic_limit > 0 && speed_mb_s > opt_t2_boost_high_traffic_limit) {
			extern bool batch_length_high_traffic_need;
			batch_length_high_traffic_need = true;
		}
		
		if(opt_cachedir[0] != '\0') {
			outStr << "cdq[" << calltable->files_queue.size() << "][" << ((float)(cachedirtransfered - lastcachedirtransfered) / 1024.0 / 1024.0 / (float)statPeriod) << " MB/s] ";
			lastcachedirtransfered = cachedirtransfered;
		}
		if(sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("x1");
		}
	}
	
	if(!this->isMirrorSender() && opt_pcap_dump_tar) {
		if(task == pcapStatLog) {
			outStr << "tarQ[" << glob_tar_queued_files << "] ";
			extern TarCopy *tarCopy;
			if(tarCopy) {
				outStr << "tarMq[" << tarCopy->queueLength() << "] ";
			}
			u_int64_t tarBufferSize = ChunkBuffer::getChunkBuffersSumsize();
			if(tarBufferSize) {
				outStr << "tarB[" << setprecision(0) << tarBufferSize / 1024 / 1024 << "MB] ";
				//outStr << "tarB[" << setprecision(1) << tarBufferSize / 1024. << "kB] ";
			}
			if(sverb.log_profiler) {
				lapTime.push_back(getTimeMS_rdtsc());
				lapTimeDescr.push_back("tarbuffer");
			}
		}
		extern TarQueue *tarQueue[2];
		for(int i = 0; i < 2; i++) {
			if(tarQueue[i]) {
				bool okPercTarCpu = false;
				for(int j = 0; j < tarQueue[i]->maxthreads; j++) {
					double tar_cpu = tarQueue[i]->getCpuUsagePerc(j, pstatDataIndex);
					if(tar_cpu > 0) {
						if(task == pcapStatLog) {
							if(okPercTarCpu) {
								outStr << '|';
							} else {
								outStr << (i ? "tarCPU-spool2[" : "tarCPU[");
								okPercTarCpu = true;
							}
							outStr << setprecision(1) << tar_cpu;
							if(opt_rrd) {
								rrd_add_value(RRD_VALUE_tarCPU, tar_cpu);
							}
						}
					}
				}
				if(task == pcapStatLog && okPercTarCpu) {
					outStr << "%] ";
				}
			}
		}
		if(task == pcapStatLog && sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("tar");
		}
	}
	
	ostringstream outStrStat;
	outStrStat << fixed;
	
	if(task == pcapStatLog && this->instancePcapHandle) {
		double sumMaxReadThreads;
		int countThreadsSumMaxReadThreads;
		outStrStat << this->instancePcapHandle->pcapStatString_cpuUsageReadThreads(&sumMaxReadThreads, &countThreadsSumMaxReadThreads, statPeriod, pstatDataIndex);
		double t0cpu = this->instancePcapHandle->getCpuUsagePerc(mainThread, pstatDataIndex);
		double t0cpuWrite = this->instancePcapHandle->getCpuUsagePerc(writeThread, pstatDataIndex);
		double t0cpuNextThreads[PCAP_QUEUE_NEXT_THREADS_MAX];
		for(int i = 0; i < PCAP_QUEUE_NEXT_THREADS_MAX; i++) {
			t0cpuNextThreads[i] = this->instancePcapHandle->getCpuUsagePerc((eTypeThread)(nextThread1 + i), pstatDataIndex);
		}
		if(t0cpu >= 0) {
			outStrStat << "t0CPU[" << setprecision(1) << t0cpu;
			if(t0cpuWrite >= 0) {
				outStrStat << "/" << setprecision(1) << t0cpuWrite;
			}
			for(int i = 0; i < PCAP_QUEUE_NEXT_THREADS_MAX; i++) {
				if(t0cpuNextThreads[i] >= 0) {
					outStrStat << "/" << setprecision(1) << t0cpuNextThreads[i];
				}
			}
			outStrStat << "%] ";
			if(opt_rrd) {
				rrd_set_value(RRD_VALUE_tCPU_t0, t0cpu);
			}
		}
		static int countOccurencesForWarning = 0;
		if((sumMaxReadThreads / countThreadsSumMaxReadThreads > opt_cpu_limit_warning_t0 || t0cpu > opt_cpu_limit_warning_t0) && 
		   getThreadingMode() < 5 &&
		   !(opt_pcap_queue_use_blocks && getThreadingMode() > 1)) {
			++countOccurencesForWarning;
		} else if(countOccurencesForWarning > 0) {
			--countOccurencesForWarning;
		}
		if(countOccurencesForWarning >= 3) {
			syslog(LOG_WARNING, "warning - reading process (t0CPU) needs to be threaded - try to set threading_mod to %i", getThreadingMode() + 1); 
			countOccurencesForWarning = 0;
		}
		if(sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("t0");
		}
	}
	
	if(task == pcapStatLog) {
		string t1cpu = this->getCpuUsage(false, pstatDataIndex);
		if(t1cpu.length()) {
			outStrStat << t1cpu << " ";
		} else {
			double t1cpu = this->getCpuUsagePerc(mainThread, pstatDataIndex);
			if(t1cpu >= 0) {
				outStrStat << "t1CPU[" << setprecision(1) << t1cpu << "%] ";
				if(opt_rrd) {
					rrd_set_value(RRD_VALUE_tCPU_t1, t1cpu);
				}
			}
		}
		if(sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("t1");
		}
	}
	
	double t2cpu = this->getCpuUsagePerc(writeThread, pstatDataIndex);
	double sum_t2cpu = 0;
	if(t2cpu >= 0) {
		if(isMirrorSender()) {
			if(task == pcapStatLog) {
				outStrStat << "t2CPU[" << t2cpu;
			}
		} else {
			if(task == pcapStatLog) {
				outStrStat << "t2CPU[" << "pb:" << setprecision(1) << t2cpu;
			}
			if(task == pcapStatCpuCheck) {
				if(opt_pcap_queue_dequeu_method &&
				   !opt_pcap_queue_dequeu_need_blocks &&
				   opt_pcap_queue_dequeu_window_length > 0) {
					static int do_decrease_dequeu_window_counter = 0;
					static int do_increase_dequeu_window_counter = 0;
					if((heap_pb_used_perc > opt_heap_limit_new_thread && 
					    t2cpu > opt_cpu_limit_new_thread_if_heap_grows) ||
					   t2cpu > opt_cpu_limit_new_thread) {
						if((++do_decrease_dequeu_window_counter) >= 2) {
							if(opt_pcap_queue_dequeu_window_length_div < 100) {
								if(!opt_pcap_queue_dequeu_window_length_div) {
									opt_pcap_queue_dequeu_window_length_div = 2;
								} else {
									opt_pcap_queue_dequeu_window_length_div *= 2;
								}
								syslog(LOG_INFO, "decrease pcap_queue_deque_window_length to %i", 
								       opt_pcap_queue_dequeu_window_length / opt_pcap_queue_dequeu_window_length_div);
							}
							do_decrease_dequeu_window_counter = 0;
						}
						do_increase_dequeu_window_counter = 0;
					} else if(heap_pb_used_perc < 5 && t2cpu < 30 &&
						  opt_pcap_queue_dequeu_window_length_div > 0) {
						if((++do_increase_dequeu_window_counter) >= 10) {
							if(opt_pcap_queue_dequeu_window_length_div > 2) {
								opt_pcap_queue_dequeu_window_length_div /= 2;
								syslog(LOG_INFO, "increase pcap_queue_deque_window_length to %i", 
								       opt_pcap_queue_dequeu_window_length / opt_pcap_queue_dequeu_window_length_div);
							} else {
								opt_pcap_queue_dequeu_window_length_div = 0;
								syslog(LOG_INFO, "restore pcap_queue_deque_window_length to %i", 
								       opt_pcap_queue_dequeu_window_length);
							}
							do_increase_dequeu_window_counter = 0;
						}
						do_decrease_dequeu_window_counter = 0;
					} else {
						do_decrease_dequeu_window_counter = 0;
						do_increase_dequeu_window_counter = 0;
					}
				}
			}
			if(pcapQueueQ_outThread_detach) {
				double detach_cpu = pcapQueueQ_outThread_detach->getCpuUsagePerc(0, pstatDataIndex);
				if(task == pcapStatLog && detach_cpu >= 0) {
					outStrStat << "/detach:" << setprecision(1) << detach_cpu;
					for(int i = 0; i < MAX_PRE_PROCESS_PACKET_NEXT_THREADS; i++) {
						if(pcapQueueQ_outThread_detach->existsNextThread(i)) {
							double next_cpu = pcapQueueQ_outThread_detach->getCpuUsagePerc(i + 1, pstatDataIndex);
							if(next_cpu >= 0) {
								outStrStat << "|" << setprecision(1) << next_cpu;
							}
						}
					}
				}
				if(task == pcapStatCpuCheck) {
					static int do_add_thread_counter;
					static int do_remove_thread_counter;
					if(detach_cpu > opt_cpu_limit_new_thread &&
					   heap_pb_used_perc > opt_heap_limit_new_thread) {
						if((++do_add_thread_counter) >= 2) {
							pcapQueueQ_outThread_detach->addNextThread();
							do_add_thread_counter = 0;
						}
						do_remove_thread_counter = 0;
					} else if(detach_cpu < opt_cpu_limit_delete_thread) {
						if((++do_remove_thread_counter) >= 2) {
							pcapQueueQ_outThread_detach->removeNextThread();
							do_remove_thread_counter = 0;
						}
						do_add_thread_counter = 0;
					} else {
						do_add_thread_counter = 0;
						do_remove_thread_counter = 0;
					}
				}
			}
			if(pcapQueueQ_outThread_defrag) {
				double defrag_cpu = pcapQueueQ_outThread_defrag->getCpuUsagePerc(0, pstatDataIndex);
				if(task == pcapStatLog && defrag_cpu >= 0) {
					outStrStat << "/defrag:" << setprecision(1) << defrag_cpu;
					#if not DEFRAG_MOD_OLDVER
					for(int i = 0; i < MAX_PRE_PROCESS_PACKET_NEXT_THREADS; i++) {
						if(pcapQueueQ_outThread_defrag->existsNextThread(i)) {
							double next_cpu = pcapQueueQ_outThread_defrag->getCpuUsagePerc(i + 1, pstatDataIndex);
							if(next_cpu >= 0) {
								outStrStat << "|" << setprecision(1) << next_cpu;
							}
						}
					}
					#endif
				}
				#if not DEFRAG_MOD_OLDVER
				if(task == pcapStatCpuCheck) {
					static int do_add_thread_counter;
					static int do_remove_thread_counter;
					if(defrag_cpu > opt_cpu_limit_new_thread &&
					   heap_pb_used_perc > opt_heap_limit_new_thread) {
						if((++do_add_thread_counter) >= 2) {
							pcapQueueQ_outThread_defrag->addNextThread();
							do_add_thread_counter = 0;
						}
						do_remove_thread_counter = 0;
					} else if(defrag_cpu < opt_cpu_limit_delete_thread) {
						if((++do_remove_thread_counter) >= 2) {
							pcapQueueQ_outThread_defrag->removeNextThread();
							do_remove_thread_counter = 0;
						}
						do_add_thread_counter = 0;
					} else {
						do_add_thread_counter = 0;
						do_remove_thread_counter = 0;
					}
				}
				#endif
			}
			if(pcapQueueQ_outThread_dedup) {
				double dedup_cpu = pcapQueueQ_outThread_dedup->getCpuUsagePerc(0, pstatDataIndex);
				if(task == pcapStatLog && dedup_cpu >= 0) {
					outStrStat << "/dedup:" << setprecision(1) << dedup_cpu;
				}
			}
			if(pcapQueueQ_outThread_detach2) {
				double detach_cpu = pcapQueueQ_outThread_detach2->getCpuUsagePerc(0, pstatDataIndex);
				if(task == pcapStatLog && detach_cpu >= 0) {
					outStrStat << "/detach2:" << setprecision(1) << detach_cpu;
					for(int i = 0; i < MAX_PRE_PROCESS_PACKET_NEXT_THREADS; i++) {
						if(pcapQueueQ_outThread_detach2->existsNextThread(i)) {
							double next_cpu = pcapQueueQ_outThread_detach2->getCpuUsagePerc(i + 1, pstatDataIndex);
							if(next_cpu >= 0) {
								outStrStat << "|" << setprecision(1) << next_cpu;
							}
						}
					}
				}
				if(task == pcapStatCpuCheck) {
					static int do_add_thread_counter;
					static int do_remove_thread_counter;
					if(detach_cpu > opt_cpu_limit_new_thread &&
					   heap_pb_used_perc > opt_heap_limit_new_thread) {
						if((++do_add_thread_counter) >= 2) {
							pcapQueueQ_outThread_detach2->addNextThread();
							do_add_thread_counter = 0;
						}
						do_remove_thread_counter = 0;
					} else if(detach_cpu < opt_cpu_limit_delete_thread) {
						if((++do_remove_thread_counter) >= 2) {
							pcapQueueQ_outThread_detach2->removeNextThread();
							do_remove_thread_counter = 0;
						}
						do_add_thread_counter = 0;
					} else {
						do_add_thread_counter = 0;
						do_remove_thread_counter = 0;
					}
				}
			}
			if(opt_ipaccount) {
				double ipacc_cpu = this->getCpuUsagePerc(destroyBlocksThread, pstatDataIndex);
				if(task == pcapStatLog && ipacc_cpu >= 0) {
					outStrStat << "/ipacc:" << setprecision(1) << ipacc_cpu;
				}
			}
			double last_t2cpu_preprocess_packet_out_thread_check_next_level = -2;
			#if CALLX_MOD_OLDVER
			double call_t2cpu_preprocess_packet_out_thread = -2;
			#endif
			double last_t2cpu_preprocess_packet_out_thread_rtp = -2;
			int count_t2cpu = 1;
			sum_t2cpu = t2cpu;
			last_t2cpu_preprocess_packet_out_thread_check_next_level = t2cpu;
			last_t2cpu_preprocess_packet_out_thread_rtp = t2cpu;
			for(int i = 0; i < PreProcessPacket::ppt_end_base; i++) {
				if(preProcessPacket[i]) {
					double t2cpu_preprocess_packet_thread_max = 0;
					double t2cpu_preprocess_packet_next_threads_sum = 0;
					int t2cpu_preprocess_packet_next_threads_count = 0;
					unsigned countOutPerc = 0;
					for(int j = 0; j < 1 + MAX_PRE_PROCESS_PACKET_NEXT_THREADS; j++) {
						if(j == 0 || preProcessPacket[i]->existsNextThread(j - 1)) {
							double t2cpu_preprocess_packet_out_thread = preProcessPacket[i]->getCpuUsagePerc(j, pstatDataIndex);
							if(t2cpu_preprocess_packet_out_thread >= 0) {
								if(t2cpu_preprocess_packet_out_thread > t2cpu_preprocess_packet_thread_max) {
									t2cpu_preprocess_packet_thread_max = t2cpu_preprocess_packet_out_thread;
								}
								if(j > 0) {
									t2cpu_preprocess_packet_next_threads_sum += t2cpu_preprocess_packet_out_thread;
									++t2cpu_preprocess_packet_next_threads_count;
								}
								if(task == pcapStatLog) {
									if(!countOutPerc) {
										outStrStat << "/" 
											   << preProcessPacket[i]->getShortcatTypeThread() << ":";
									} else {
										outStrStat << "|";
									}
									outStrStat << setprecision(1) << t2cpu_preprocess_packet_out_thread;
									++countOutPerc;
									if(i == 0 && sverb.alloc_stat) {
										if(preProcessPacket[i]->getAllocCounter(1) || preProcessPacket[i]->getAllocStackCounter(1)) {
											unsigned long stack = preProcessPacket[i]->getAllocStackCounter(0) - preProcessPacket[i]->getAllocStackCounter(1);
											unsigned long alloc = preProcessPacket[i]->getAllocCounter(0) - preProcessPacket[i]->getAllocCounter(1);
											outStrStat << "a" << stack << ':' << alloc << ':';
											if(alloc + stack) {
												outStrStat << (stack * 100 / (alloc + stack)) << '%';
											} else {
												outStrStat << '-';
											}
										}
										preProcessPacket[i]->setAllocCounter(preProcessPacket[i]->getAllocCounter(0), 1);
										preProcessPacket[i]->setAllocStackCounter(preProcessPacket[i]->getAllocStackCounter(0), 1);
									}
								}
								++count_t2cpu;
								sum_t2cpu += t2cpu_preprocess_packet_out_thread;
								if(
								   #if not CALLX_MOD_OLDVER
								   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_find_call &&
								   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_process_call &&
								   #else
								   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_call &&
								   #endif
								   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_register && 
								   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_sip_other && 
								   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_diameter && 
								   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_rtp && 
								   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_other) {
									last_t2cpu_preprocess_packet_out_thread_check_next_level = t2cpu_preprocess_packet_out_thread;
								}
								#if CALLX_MOD_OLDVER
								if(preProcessPacket[i]->getTypePreProcessThread() == PreProcessPacket::ppt_pp_call) {
									call_t2cpu_preprocess_packet_out_thread = t2cpu_preprocess_packet_out_thread;
								}
								#endif
								if(
								   #if not CALLX_MOD_OLDVER
								   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_find_call &&
								   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_process_call &&
								   #else
								   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_call &&
								   #endif
								   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_register && 
								   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_sip_other && 
								   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_diameter && 
								   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_other) {
									last_t2cpu_preprocess_packet_out_thread_rtp = t2cpu_preprocess_packet_out_thread;
								}
								#if C_THREAD_OVERLOAD_MONITORING
								if(task == pcapStatCpuCheck && preProcessPacket[i]->getTypePreProcessThread() == PreProcessPacket::ppt_pp_call) {
									static int c_thread_overload_counter = 0;
									if(t2cpu_preprocess_packet_out_thread > C_THREAD_OVERLOAD_MONITORING_LIMIT_CPU) {
										if((++c_thread_overload_counter) > C_THREAD_OVERLOAD_MONITORING_LIMIT_COUNTER) {
											syslog(LOG_ERR, "ABORT - due persistent overload thread c");
											abort();
										}
									} else {
										c_thread_overload_counter = 0;
									}
								}
								#endif
							}
						}
					}
					if(task == pcapStatCpuCheck) {
						if(opt_t2_boost &&
						   (preProcessPacket[i]->getTypePreProcessThread() == PreProcessPacket::ppt_detach_x ||
						    preProcessPacket[i]->getTypePreProcessThread() == PreProcessPacket::ppt_detach ||
						    preProcessPacket[i]->getTypePreProcessThread() == PreProcessPacket::ppt_sip
						    #if not CALLX_MOD_OLDVER
						    ||
						    preProcessPacket[i]->getTypePreProcessThread() == PreProcessPacket::ppt_pp_find_call ||
						    preProcessPacket[i]->getTypePreProcessThread() == PreProcessPacket::ppt_pp_process_call
						    #endif
						    )) {
							static int do_add_thread_counter[PreProcessPacket::ppt_end_base];
							static int do_remove_thread_counter[PreProcessPacket::ppt_end_base];
							if((t2cpu_preprocess_packet_next_threads_count < 2 ?
							     t2cpu_preprocess_packet_thread_max > opt_cpu_limit_new_thread :
							     t2cpu_preprocess_packet_next_threads_sum / t2cpu_preprocess_packet_next_threads_count > opt_cpu_limit_new_thread) &&
							   heap_pb_used_perc > opt_heap_limit_new_thread) {
								if((++do_add_thread_counter[i]) >= 2) {
									preProcessPacket[i]->addNextThread();
									do_add_thread_counter[i] = 0;
								}
								do_remove_thread_counter[i] = 0;
							} else if(t2cpu_preprocess_packet_thread_max < opt_cpu_limit_delete_thread) {
								if((++do_remove_thread_counter[i]) >= 2) {
									preProcessPacket[i]->removeNextThread();
									do_remove_thread_counter[i] = 0;
								}
								do_add_thread_counter[i] = 0;
							} else {
								do_add_thread_counter[i] = 0;
								do_remove_thread_counter[i] = 0;
							}
						}
					}
				}
			}
			if(opt_t2_boost) {
				#if CALLX_MOD_OLDVER
				if(preProcessPacketCallX && calltable->useCallX()) {
					for(int i = 0; i < preProcessPacketCallX_count + 1; i++) {
						double t2cpu_preprocess_packet_out_thread = preProcessPacketCallX[i]->getCpuUsagePerc(0, pstatDataIndex);
						if(t2cpu_preprocess_packet_out_thread >= 0) {
							if(task == pcapStatLog) {
								outStrStat << "/" 
									   << preProcessPacketCallX[i]->getShortcatTypeThread() << ":"
									   << setprecision(1) << t2cpu_preprocess_packet_out_thread;
								if(sverb.qring_stat) {
									double qringFillingPerc = preProcessPacketCallX[i]->getQringFillingPerc();
									if(qringFillingPerc > 0) {
										outStrStat << "r" << qringFillingPerc;
									}
								}
							}
							++count_t2cpu;
							sum_t2cpu += t2cpu_preprocess_packet_out_thread;
						}
						#if C_THREAD_OVERLOAD_MONITORING
						if(task == pcapStatCpuCheck) {
							static int c_thread_overload_counter = 0;
							if(t2cpu_preprocess_packet_out_thread > C_THREAD_OVERLOAD_MONITORING_LIMIT_CPU) {
								if((++c_thread_overload_counter) > C_THREAD_OVERLOAD_MONITORING_LIMIT_COUNTER) {
									syslog(LOG_ERR, "ABORT - due persistent overload thread cx");
									abort();
								}
							} else {
								c_thread_overload_counter = 0;
							}
						}
						#endif
					}
				}
				if(preProcessPacketCallFindX && calltable->useCallFindX()) {
					for(int i = 0; i < preProcessPacketCallX_count; i++) {
						double t2cpu_preprocess_packet_out_thread = preProcessPacketCallFindX[i]->getCpuUsagePerc(0, pstatDataIndex);
						if(t2cpu_preprocess_packet_out_thread >= 0) {
							if(task == pcapStatLog) {
								outStrStat << "/" 
									   << preProcessPacketCallFindX[i]->getShortcatTypeThread()
									   << setprecision(1) << t2cpu_preprocess_packet_out_thread;
								if(sverb.qring_stat) {
									double qringFillingPerc = preProcessPacketCallFindX[i]->getQringFillingPerc();
									if(qringFillingPerc > 0) {
										outStrStat << "r" << qringFillingPerc;
									}
								}
							}
							++count_t2cpu;
							sum_t2cpu += t2cpu_preprocess_packet_out_thread;
						}
					}
				}
				#endif
			}
			if(task == pcapStatLog && opt_rrd) {
				rrd_set_value(RRD_VALUE_tCPU_t2, sum_t2cpu);
			}
			int countRtpRhThreads = 0;
			bool needAddRtpRhThread = false;
			bool needRemoveRtpRhThread = false;
			int countRtpRdThreads = 0;
			bool needAddRtpRdThread = false;
			if(processRtpPacketHash) {
				double t2cpu_rh_max = 0;
				double t2cpu_rh_next_sum = 0;
				double t2cpu_rh_next_count = 0;
				unsigned countOutPerc = 0;
				for(int i = 0; i < 1 + MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS; i++) {
					if(i == 0 || processRtpPacketHash->existsNextThread(i - 1)) {
						double t2cpu_process_rtp_packet_out_thread = processRtpPacketHash->getCpuUsagePerc(i, pstatDataIndex);
						if(t2cpu_process_rtp_packet_out_thread >= 0) {
							if(task == pcapStatLog) {
								if(!countOutPerc) {
									outStrStat << "/" << "rh:";
								} else {
									outStrStat << "|";
								}
								outStrStat << setprecision(1) << t2cpu_process_rtp_packet_out_thread;
								++countOutPerc;
							}
							++count_t2cpu;
							sum_t2cpu += t2cpu_process_rtp_packet_out_thread;
							if(t2cpu_process_rtp_packet_out_thread > t2cpu_rh_max) {
								t2cpu_rh_max = t2cpu_process_rtp_packet_out_thread;
							}
							if(i > 0) {
								t2cpu_rh_next_sum += t2cpu_process_rtp_packet_out_thread;
								++t2cpu_rh_next_count;
							}
						}
						if(i > 0) {
							++countRtpRhThreads;
						}
					}
				}
				if((t2cpu_rh_next_count < 2 ?
				     t2cpu_rh_max > opt_cpu_limit_new_thread :
				     t2cpu_rh_next_sum / t2cpu_rh_next_count > opt_cpu_limit_new_thread) &&
				   heap_pb_used_perc > opt_heap_limit_new_thread) {
					needAddRtpRhThread = true;
				} else if(countRtpRhThreads > 0 &&
					  t2cpu_rh_max < opt_cpu_limit_delete_thread) {
					needRemoveRtpRhThread = true;
				}
				double t2cpu_rd_sum = 0;
				double t2cpu_rd_count = 0;
				countOutPerc = 0;
				for(int i = 0; i < MAX_PROCESS_RTP_PACKET_THREADS; i++) {
					if(processRtpPacketDistribute[i]) {
						double t2cpu_process_rtp_packet_out_thread = processRtpPacketDistribute[i]->getCpuUsagePerc(0, pstatDataIndex);
						if(t2cpu_process_rtp_packet_out_thread >= 0) {
							if(task == pcapStatLog) {
								if(!countOutPerc) {
									outStrStat << "/" << "rd:";
								} else {
									outStrStat << "|";
								}
								outStrStat << setprecision(1) << t2cpu_process_rtp_packet_out_thread;
								++countOutPerc;
							}
						}
						++countRtpRdThreads;
						++count_t2cpu;
						sum_t2cpu += t2cpu_process_rtp_packet_out_thread;
						t2cpu_rd_sum += t2cpu_process_rtp_packet_out_thread;
						++t2cpu_rd_count;
					}
				}
				if(t2cpu_rd_count > 0 &&
				   t2cpu_rd_sum / t2cpu_rd_count > opt_cpu_limit_new_thread &&
				   heap_pb_used_perc > opt_heap_limit_new_thread) {
					needAddRtpRdThread = true;
				}
			}
			if(task == pcapStatCpuCheck) {
				extern int opt_enable_preprocess_packet;
				if(opt_enable_preprocess_packet == -1) {
					static int do_start_last_level_counter = 0;
					static int do_stop_last_level_counter = 0;
					if(heap_pb_used_perc > opt_heap_limit_new_thread && 
					   last_t2cpu_preprocess_packet_out_thread_check_next_level > opt_cpu_limit_new_thread) {
						if((++do_start_last_level_counter) >= 2) {
							PreProcessPacket::autoStartNextLevelPreProcessPacket();
							do_start_last_level_counter = 0;
						}
						do_stop_last_level_counter = 0;
					} else if(last_t2cpu_preprocess_packet_out_thread_check_next_level < opt_cpu_limit_delete_t2sip_thread) {
						if((++do_stop_last_level_counter) >= 10) {
							PreProcessPacket::autoStopLastLevelPreProcessPacket();
							do_stop_last_level_counter = 0;
						}
						do_start_last_level_counter = 0;
					} else {
						do_start_last_level_counter = 0;
						do_stop_last_level_counter = 0;
					}
				}
				#if CALLX_MOD_OLDVER
				static int do_add_thread_callx_counter = 0;
				if(call_t2cpu_preprocess_packet_out_thread > opt_cpu_limit_new_thread_high &&
				   heap_pb_used_perc > opt_heap_limit_new_thread &&
				   calltable->enableCallX() && !calltable->useCallX()) {
					if((++do_add_thread_callx_counter) >= 2) {
						PreProcessPacket::autoStartCallX_PreProcessPacket();
						do_add_thread_callx_counter = 0;
					}
				} else {
					do_add_thread_callx_counter = 0;
				}
				#endif
				static int do_add_process_rtp_counter = 0;
				if(last_t2cpu_preprocess_packet_out_thread_rtp > opt_cpu_limit_new_thread &&
				   heap_pb_used_perc > opt_heap_limit_new_thread) {
					if((++do_add_process_rtp_counter) >= 2) {
						ProcessRtpPacket::autoStartProcessRtpPacket();
						do_add_process_rtp_counter = 0;
					}
				} else {
					do_add_process_rtp_counter = 0;
				}
				static int do_add_thread_rh_counter = 0;
				static int do_remove_thread_rh_counter = 0;
				if(needAddRtpRhThread) {
					if((++do_add_thread_rh_counter) >= 2) {
						processRtpPacketHash->addRtpRhThread();
						do_add_thread_rh_counter = 0;
					}
					do_remove_thread_rh_counter = 0;
				} else if(needRemoveRtpRhThread) {
					if((++do_remove_thread_rh_counter) >= 2) {
						processRtpPacketHash->removeRtpRhThread();
						do_remove_thread_rh_counter = 0;
					}
					do_add_thread_rh_counter = 0;
				} else {
					do_add_thread_rh_counter = 0;
					do_remove_thread_rh_counter = 0;
				}
				extern int opt_enable_process_rtp_packet_max;
				static int do_add_thread_rd_counter = 0;
				if(countRtpRdThreads < MAX_PROCESS_RTP_PACKET_THREADS &&
				   (opt_enable_process_rtp_packet_max <= 0 || countRtpRdThreads < opt_enable_process_rtp_packet_max) &&
				   needAddRtpRdThread) {
					if((++do_add_thread_rd_counter) >= 2) {
						ProcessRtpPacket::addRtpRdThread();
						do_add_thread_rd_counter = 0;
					}
				} else {
					do_add_thread_rd_counter = 0;
				}
			}
			if(task == pcapStatLog && count_t2cpu > 1) {
				outStrStat << "/S:" << setprecision(1) << sum_t2cpu;
			}
		}
		if(task == pcapStatLog) {
			outStrStat << "%] ";
		}
	}
	if(task == pcapStatLog && sverb.log_profiler) {
		lapTime.push_back(getTimeMS_rdtsc());
		lapTimeDescr.push_back("t2");
	}
	
	if(!isMirrorSender()) {
		double tRTPcpuMax = 0;
		double tRTPcpuMin = 0;
		double tRTPcpuSum = get_rtp_sum_cpu_usage(&tRTPcpuMax, &tRTPcpuMin, pstatDataIndex);
		if(tRTPcpuSum >= 0) {
			extern volatile int num_threads_active;
			if(task == pcapStatLog) {
				outStrStat << "tRTP_CPU[" << setprecision(1) << tRTPcpuSum << "%/";
				if(sverb.rtp_extend_stat) {
					outStrStat << get_rtp_threads_cpu_usage(pstatDataIndex, false) << "/";
				} else {
					outStrStat << tRTPcpuMax << "m/";
				}
				outStrStat << num_threads_active << "t] ";
			}
			if(task == pcapStatCpuCheck) {
				/*
				cout << " ** RTP THREADS ** " 
				     << num_threads_active << " / "
				     << "heap_trash_perc: " << heap_pb_trash_perc << " / " 
				     << "cpu_avg: " << tRTPcpuSum / num_threads_active << " / " 
				     << "cpu_max: " <<  tRTPcpuMax << " / " 
				     << "cpu_min: " << tRTPcpuMin
				     << endl;
				extern rtp_read_thread *rtp_threads;
				cout << "   ";
				for(int i = 0; i < num_threads_active; i++) {
					if(rtp_threads[i].threadId) {
						cout << "T" << (i + 1) << " "
						     << "c: " << rtp_threads[i].calls << " "
						     << "p: " << rtp_threads[i].cpu;
					}
					if(i < num_threads_active - 1) {
						cout << " / ";
					}
				}
				cout << endl;
				*/
				static int do_add_thread_counter = 0;
				static int do_remove_thread_counter = 0;
				if((tRTPcpuSum / num_threads_active > opt_cpu_limit_new_thread_high &&
				    (heap_pb_used_perc + heap_pb_trash_perc) > opt_heap_limit_new_thread) ||
				   (tRTPcpuSum / num_threads_active > opt_cpu_limit_new_thread &&
				    tRTPcpuMin > opt_cpu_limit_new_thread && 
				    (heap_pb_used_perc + heap_pb_trash_perc) > opt_heap_limit_new_thread) ||
				   (num_threads_active == 1 &&
				    tRTPcpuMax > (opt_cpu_limit_new_thread / 2) && 
				    (heap_pb_used_perc + heap_pb_trash_perc) > opt_heap_limit_new_thread)) {
					if(num_threads_active == 1 || (++do_add_thread_counter) >= 5) {
						double heap_pb_used_trash_perc = heap_pb_used_perc + heap_pb_trash_perc;
						int newThreads = heap_pb_used_trash_perc > 80 ? 4 :
								 heap_pb_used_trash_perc > 60 ? 3 :
								 heap_pb_used_trash_perc > 40 ? 2 :
												1;
						syslog(LOG_NOTICE,
						       "try create new rtp threads: %i, "
						       "num_threads_active: %i, "
						       "tRTPcpuSum: %.2lf, "
						       "tRTPcpuMin: %.2lf, "
						       "tRTPcpuMax: %.2lf, "
						       "opt_cpu_limit_new_thread_high: %i, "
						       "opt_cpu_limit_new_thread: %i, "
						       "heap_pb_used_perc: %.2lf, "
						       "heap_pb_trash_perc: %.2lf, "
						       "opt_heap_limit_new_thread: %i",
						       newThreads,
						       num_threads_active,
						       tRTPcpuSum,
						       tRTPcpuMin,
						       tRTPcpuMax,
						       opt_cpu_limit_new_thread_high,
						       opt_cpu_limit_new_thread,
						       heap_pb_used_perc,
						       heap_pb_trash_perc,
						       opt_heap_limit_new_thread);
						for(int i = 0; i < newThreads; i++) {
							if(add_rtp_read_thread()) {
								syslog(LOG_NOTICE, "create rtp thread");
							}
						}
						do_add_thread_counter = 0;
					}
					do_remove_thread_counter = 0;
				} else if(num_threads_active > 1 &&
					  tRTPcpuSum / num_threads_active < opt_cpu_limit_delete_thread &&
					  tRTPcpuMax < opt_cpu_limit_delete_thread &&
					  pcapStatCpuCheckCounter > 60 &&
					  !sverb.disable_read_rtp) {
					if((++do_remove_thread_counter) >= 10) {
						if(set_remove_rtp_read_thread()) {
							syslog(LOG_NOTICE, "remove rtp thread");
						}
						do_remove_thread_counter = 0;
					}
					do_add_thread_counter = 0;
				} else {
					do_add_thread_counter = 0;
					do_remove_thread_counter = 0;
				}
			}
		}
		if(task == pcapStatLog) {
			if(sverb.log_profiler) {
				lapTime.push_back(getTimeMS_rdtsc());
				lapTimeDescr.push_back("trtp");
			}
			if(tcpReassemblyHttp) {
				string cpuUsagePerc = tcpReassemblyHttp->getCpuUsagePerc(pstatDataIndex);
				if(!cpuUsagePerc.empty()) {
					outStrStat << "thttpCPU[" << cpuUsagePerc << "] ";
				}
				if(sverb.log_profiler) {
					lapTime.push_back(getTimeMS_rdtsc());
					lapTimeDescr.push_back("thttp");
				}
			}
			if(tcpReassemblyWebrtc) {
				string cpuUsagePerc = tcpReassemblyWebrtc->getCpuUsagePerc(pstatDataIndex);
				if(!cpuUsagePerc.empty()) {
					outStrStat << "twebrtcCPU[" << cpuUsagePerc << "] ";
				}
				if(sverb.log_profiler) {
					lapTime.push_back(getTimeMS_rdtsc());
					lapTimeDescr.push_back("twebrtc");
				}
			}
			if(tcpReassemblySsl) {
				string cpuUsagePerc = tcpReassemblySsl->getCpuUsagePerc(pstatDataIndex);
				if(!cpuUsagePerc.empty()) {
					outStrStat << "tsslCPU[" << cpuUsagePerc << "] ";
				}
				if(sverb.log_profiler) {
					lapTime.push_back(getTimeMS_rdtsc());
					lapTimeDescr.push_back("tssl");
				}
			}
			extern link_packets_queue dtls_queue;
			u_int32_t dtls_queue_links = dtls_queue.countLinks();
			u_int32_t dtls_queue_packets = dtls_queue.countPackets();
			if(dtls_queue_links > 0 || dtls_queue_packets > 0) {
				outStrStat << "dtls[l:" << dtls_queue_links 
					   << "/p:" << dtls_queue_packets
					   << "] ";
				if(sverb.log_profiler) {
					lapTime.push_back(getTimeMS_rdtsc());
					lapTimeDescr.push_back("dtls");
				}
			}
			if(tcpReassemblySipExt) {
				string cpuUsagePerc = tcpReassemblySipExt->getCpuUsagePerc(pstatDataIndex);
				if(!cpuUsagePerc.empty()) {
					outStrStat << "tsip_tcpCPU[" << cpuUsagePerc << "] ";
				}
				if(sverb.log_profiler) {
					lapTime.push_back(getTimeMS_rdtsc());
					lapTimeDescr.push_back("tsip");
				}
			}
			extern bool opt_ipfix;
			extern bool opt_ipfix_counter_log;
			if(opt_ipfix && opt_ipfix_counter_log) {
				extern cIpFixCounter ipfix_counter;
				string ipfix_counter_rslt = ipfix_counter.get_ip_counter();
				if(!ipfix_counter_rslt.empty()) {
					ipfix_counter.reset();
					outStrStat << "ipfix[" << ipfix_counter_rslt << "] ";
				}
			}
			extern bool opt_hep;
			extern bool opt_hep_counter_log;
			if(opt_hep && opt_hep_counter_log) {
				extern cHepCounter hep_counter;
				string hep_counter_rslt = hep_counter.get_ip_counter();
				if(!hep_counter_rslt.empty()) {
					hep_counter.reset();
					outStrStat << "hep[" << hep_counter_rslt << "] ";
				}
			}
			extern bool opt_ribbonsbc_listen;
			extern bool opt_ribbonsbc_counter_log;
			if(opt_ribbonsbc_listen && opt_ribbonsbc_counter_log) {
				extern cRibbonSbcCounter ribbonsbc_counter;
				string ribbonsbc_counter_rslt = ribbonsbc_counter.get_ip_counter();
				if(!ribbonsbc_counter_rslt.empty()) {
					ribbonsbc_counter.reset();
					outStrStat << "ribbonsbc[" << ribbonsbc_counter_rslt << "] ";
				}
			}
		}
		extern AsyncClose *asyncClose;
		if(asyncClose) {
			vector<double> v_tac_cpu;
			double last_tac_cpu = 0;
			bool exists_set_tac_cpu = false;
			for(int i = 0; i < asyncClose->getCountThreads(); i++) {
				double tac_cpu = asyncClose->getCpuUsagePerc(i, pstatDataIndex);
				last_tac_cpu = tac_cpu;
				if(tac_cpu >= 0) {
					v_tac_cpu.push_back(tac_cpu);
					exists_set_tac_cpu = true;
				}
			}
			if(task == pcapStatLog && exists_set_tac_cpu) {
				outStrStat << "tacCPU[";
				for(size_t i = 0; i < v_tac_cpu.size(); i++) {
					if(i) {
						outStrStat << '|';
					}
					outStrStat << setprecision(1) << v_tac_cpu[i];
					if(opt_rrd) {
						rrd_add_value(RRD_VALUE_zipCPU, v_tac_cpu[i]);
					}
				}
				outStrStat << "%] ";
				vector<unsigned> queue_size;
				asyncClose->getQueueSize(&queue_size, true);
				if(queue_size.size()) {
					outStrStat << "tacQ[";
					for(size_t i = 0; i < queue_size.size(); i++) {
						if(i) {
							outStrStat << '|';
						}
						outStrStat << queue_size[i];
					}
					outStrStat << "] ";
				}
			}
			if(task == pcapStatCpuCheck) {
				static int do_add_thread_counter = 0;
				static int do_remove_thread_counter = 0;
				if(last_tac_cpu > opt_cpu_limit_new_thread) {
					if((++do_add_thread_counter) >= 2) {
						if(asyncClose->addThread()) {
							syslog(LOG_NOTICE, "create tac thread");
						}
						do_add_thread_counter = 0;
					}
					do_remove_thread_counter = 0;
				} else if(last_tac_cpu < opt_cpu_limit_delete_thread) {
					if((++do_remove_thread_counter) >= 10) {
						if(asyncClose->removeThread()) {
							syslog(LOG_NOTICE, "remove tac thread");
						}
						do_remove_thread_counter = 0;
					}
					do_add_thread_counter = 0;
				} else {
					do_add_thread_counter = 0;
					do_remove_thread_counter = 0;
				}
			}
		}
		extern string storing_cdr_getCpuUsagePerc(double *avg, int pstatDataIndex);
		double storing_cdr_cpu_avg;
		string storing_cdr_cpu = storing_cdr_getCpuUsagePerc(&storing_cdr_cpu_avg, pstatDataIndex);
		if(task == pcapStatLog && !storing_cdr_cpu.empty()) {
			outStrStat << "storing[" << storing_cdr_cpu << "%] ";
		}
		if(task == pcapStatCpuCheck) {
			static int do_add_thread_counter = 0;
			static int do_remove_thread_counter = 0;
			if(storing_cdr_cpu_avg > opt_cpu_limit_new_thread &&
			   calls_counter > 10000 &&
			   calls_counter > (int)count_calls * 1.5) {
				if((++do_add_thread_counter) >= 2) {
					extern void storing_cdr_next_thread_add();
					storing_cdr_next_thread_add();
					do_add_thread_counter = 0;
				}
				do_remove_thread_counter = 0;
			} else if(storing_cdr_cpu_avg < opt_cpu_limit_delete_thread &&
				  calls_counter < (int)count_calls * 1.5) {
				if((++do_remove_thread_counter) >= 10) {
					extern void storing_cdr_next_thread_remove();
					storing_cdr_next_thread_remove();
					do_remove_thread_counter = 0;
				}
				do_add_thread_counter = 0;
			} else {
				do_add_thread_counter = 0;
				do_remove_thread_counter= 0;
			}
		}
		extern bool opt_charts_cache;
		if(opt_charts_cache || snifferClientOptions.remote_chart_server || existsRemoteChartServer()) {
			double chc_cpu_avg;
			string chc_cpu = calltable->processCallsInChartsCache_cpuUsagePerc(&chc_cpu_avg, pstatDataIndex);
			size_t ch_q = calltable->calls_charts_cache_queue.size();
			size_t chs_q_s = getRemoteChartServerQueueSize();
			extern u_int32_t counter_charts_cache;
			extern u_int64_t counter_charts_cache_delay_us;
			if(task == pcapStatLog &&
			   (!chc_cpu.empty() || (counter_charts_cache && counter_charts_cache_delay_us) || 
			    ch_q > 0 || chs_q_s > 0)) {
				outStrStat << "charts[";
				if(!chc_cpu.empty()) {
					outStrStat  << chc_cpu << "%";
				}
				if(counter_charts_cache && counter_charts_cache_delay_us) {
					if(!chc_cpu.empty()) {
						outStrStat  << "/";
					}
					outStrStat << counter_charts_cache << "r" << "/"
						   << (counter_charts_cache * 1000000ull / counter_charts_cache_delay_us) << "ps";
				}
				if(ch_q > 0) {
					if(!chc_cpu.empty()) {
						outStrStat  << "/";
					}
					outStrStat  << ch_q << "q";
				}
				if(chs_q_s > 0) {
					if(!chc_cpu.empty()) {
						outStrStat  << "/";
					}
					outStrStat  << chs_q_s << "qr";
				}
				outStrStat << "] ";
				counter_charts_cache = 0;
				counter_charts_cache_delay_us = 0;
			}
			if(task == pcapStatCpuCheck && pcapStatCpuCheckCounter > 2) {
				extern int opt_charts_cache_queue_limit;
				static int do_add_thread_counter = 0;
				static int do_remove_thread_counter = 0;
				if(chc_cpu_avg > opt_cpu_limit_new_thread &&
				   calltable->calls_charts_cache_queue.size() > (unsigned)opt_charts_cache_queue_limit / 3) {
					if((++do_add_thread_counter) >= 2) {
						calltable->processCallsInChartsCache_thread_add();
						do_add_thread_counter = 0;
					}
					do_remove_thread_counter = 0;
				} else if(storing_cdr_cpu_avg < opt_cpu_limit_delete_thread) {
					if((++do_remove_thread_counter) >= 10) {
						calltable->processCallsInChartsCache_thread_remove();
						do_remove_thread_counter = 0;
					}
					do_add_thread_counter = 0;
				} else {
					do_add_thread_counter = 0;
					do_remove_thread_counter = 0;
				}
			}
		}
		if(task == pcapStatLog) {
			if(opt_rrd) {
				extern RrdCharts *rrd_charts;
				double rrd_charts_cpu = rrd_charts->getCpuUsageQueueThreadPerc(pstatDataIndex);
				if(rrd_charts_cpu > 0) {
					 outStrStat << "RRD[" << setprecision(1) << rrd_charts_cpu << "%] ";
				}
			}
			if(sverb.log_profiler) {
				lapTime.push_back(getTimeMS_rdtsc());
				lapTimeDescr.push_back("tasync");
			}
			if(opt_ipaccount) {
				string ipaccCpu = getIpaccCpuUsagePerc(0);
				if(!ipaccCpu.empty()) {
					outStrStat << "tipaccCPU["
						   << ipaccCpu
						   << "] ";
				}
				if(sverb.log_profiler) {
					lapTime.push_back(getTimeMS_rdtsc());
					lapTimeDescr.push_back("tipacc");
				}
			}
		}
	}
	long unsigned int rss;
	if(task == pcapStatLog) {
		if(sverb.dedup_counter) {
			extern u_int64_t duplicate_counter;
			extern u_int64_t duplicate_counter_collisions;
			if(duplicate_counter) {
				outStrStat << "DUPL[" << duplicate_counter;
				if(duplicate_counter_collisions) {
					outStrStat << "/" << duplicate_counter_collisions;
				}
				outStrStat << "] ";
			}
		}
		outStrStat << "RSS/VSZ[";
		rss = this->getRssUsage(true);
		if(rss > 0) {
			outStrStat << setprecision(0) << (double)rss/1024/1024;
			if(opt_rrd) {
				rrd_set_value(RRD_VALUE_RSS, (double)rss/1024/1024);
			}
		}
		long unsigned int vsize = this->getVsizeUsage();
		if(vsize > 0) {
			if(rss > 0) {
				outStrStat << '|';
			}
			outStrStat << setprecision(0) << (double)vsize/1024/1024;
		}
		if(sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("rss_vsz");
		}
		outStrStat << "]MB ";
		u_int64_t hugepages_base = HugetlbSysAllocator_base();
		if(hugepages_base) {
			outStrStat << "HP["
				   << setprecision(0) << (double)hugepages_base/1024/1024
				   << "]MB ";
		}
		#if HAVE_LIBTCMALLOC
		outStrStat << "TCM[";
		const char *tcm_status_types[][2] = {
			{"generic.heap_size", "h"},
			{"generic.current_allocated_bytes", "a"},
			{"tcmalloc.pageheap_free_bytes", "f"},
			{"tcmalloc.pageheap_unmapped_bytes", "u"},
			{"tcmalloc.current_total_thread_cache_bytes", "tc"}
		};
		for(unsigned i = 0, j = 0; i < sizeof(tcm_status_types)/sizeof(tcm_status_types[0]); i++) {
			size_t tcm_bytes = 0;
			MallocExtension::instance()->GetNumericProperty(tcm_status_types[i][0], &tcm_bytes);
			if(round((double)tcm_bytes/1024/1024) > 0) {
				if(j) {
					outStrStat << "/";
				}
				outStrStat << tcm_status_types[i][1] << ":" << setprecision(0) << (double)tcm_bytes/1024/1024;
				++j;
			}
		}
		outStrStat << "]MB ";
		#endif
		#if SEPARATE_HEAP_FOR_HUGETABLE
		extern cHeap *heap_vm_hp;
		if(heap_vm_hp) {
			u_int64_t hugepages_vm_heap_size = heap_vm_hp->getSumSize();
			if(hugepages_vm_heap_size) {
				outStrStat << "HEAP_HUGEPAGE["
					   << setprecision(0) << (double)hugepages_vm_heap_size/(1024*1024)
					   << "]MB ";
			}
		}
		#endif //SEPARATE_HEAP_FOR_HUGETABLE
		#if SEPARATE_HEAP_FOR_HASHTABLE
		extern cHeap *heap_hashtable;
		if(heap_hashtable) {
			u_int64_t hashtable_heap_size = heap_hashtable->getSumSize();
			u_int64_t hashtable_alloc_size = heap_hashtable->getAllocSize();
			outStrStat << "HEAP_HASHTABLE["
				   << setprecision(0) << (double)hashtable_alloc_size/(1024*1024) << "/"
				   << setprecision(0) << (double)hashtable_heap_size/(1024*1024)
				   << "]MB ";
		}
		#endif //SEPARATE_HEAP_FOR_HASHTABLE
		//Get load average string
		outStrStat << getLoadAvgStr() << " ";
		map<string, pair<string, u_int64_t> > counters;
		get_interrupts_counters(&counters);
		if(counters["tlb"].second) {
			static u_int64_t oldCountersTlb;
			if(oldCountersTlb) {
				unsigned tlb = (counters["tlb"].second - oldCountersTlb) / statPeriod;
				outStrStat << (tlb > 10000 ? "*" : "") << "TLB[" << tlb << "] ";
				static unsigned counter_high_tlb = 0;
				if(tlb >= 500) {
					++counter_high_tlb;
					static bool try_disable_numa_balancing = false;
					extern int opt_numa_balancing_set;
					if(opt_numa_balancing_set == numa_balancing_set_autodisable &&
					   !try_disable_numa_balancing &&
					   counter_high_tlb >= (unsigned)(60 / sverb.pcap_stat_period)) {
						SimpleBuffer content;
						string error;
						if(file_get_contents(numa_balancing_config_filename, &content, &error) &&
						   atoi((char*)content) != 0) {
							try_disable_numa_balancing = true;
							syslog(LOG_NOTICE, "TLB is too high, try set numa_balancing to 0");
							content.clear();
							content.add("0");
							if(!file_put_contents(numa_balancing_config_filename, &content, &error)) {
								syslog(LOG_ERR, "%s", error.c_str());
							}
						}
						counter_high_tlb = 0;
					}
				} else {
					counter_high_tlb = 0;
				}
			}
			oldCountersTlb = counters["tlb"].second;
		}
		outStrStat << "v" << getVersionWithBuild() << " ";
		//outStrStat << pcapStatCounter << " ";
		if(opt_rrd) {
			double la[3];
			getLoadAvg(&la[0], &la[1], &la[2]);
			rrd_set_value(RRD_VALUE_LA_m1, la[0]);
			rrd_set_value(RRD_VALUE_LA_m5, la[1]);
			rrd_set_value(RRD_VALUE_LA_m15, la[2]);
		}
		pbStatString = outStr.str() + outStrStat.str() + externalError;
		externalError.erase();
		pbCountPacketDrop = this->instancePcapHandle ?
					this->instancePcapHandle->getCountPacketDrop() :
					this->getCountPacketDrop();
		if(sverb.skinny) {
			extern u_int64_t _handle_skinny_counter_all;
			extern u_int64_t _handle_skinny_counter_next_iterate;
			outStrStat << "skinny["
				   << _handle_skinny_counter_all
				   << "/"
				   << _handle_skinny_counter_next_iterate
				   << "] ";
		}
		if(VERBOSE) {
			outStr << outStrStat.str();
			extern bool incorrectCaplenDetected;
			if(incorrectCaplenDetected) {
				outStr << "!CAPLEN ";
			}
			extern char opt_syslog_string[256];
			if(opt_syslog_string[0]) {
				outStr << opt_syslog_string << " ";
			}
			if(sverb.log_profiler) {
				ostringstream outStrLogProfiler;
				u_int64_t endTimeMS = getTimeMS_rdtsc();
				u_int64_t prevTime = startTimeMS;
				for(unsigned i = 0; i < lapTime.size(); i++) {
					outStrLogProfiler << lapTimeDescr[i] << ":"
							  << (lapTime[i] > prevTime ? lapTime[i] - prevTime : 0) << ", ";
					prevTime = lapTime[i];
				}
				outStrLogProfiler << (endTimeMS > startTimeMS ? endTimeMS - startTimeMS : 0);
				outStr << "("
				       << (endTimeMS > startTimeMS + 100 ? "LOG PROFILER" : "log profiler") << " "
				       << outStrLogProfiler.str() << "ms) ";
			}
			outStr << endl;
			outStr << pcapStatString_interface_rslt;
			if(sverb.ssl_stats) {
				outStr << endl;
				outStr << ssl_stats_str();
				ssl_stats_reset();
			}
			string outStr_str = outStr.str();
			char *pointToBeginLine = (char*)outStr_str.c_str();
			while(pointToBeginLine && *pointToBeginLine) {
				char *pointToLineBreak = strchr(pointToBeginLine, '\n');
				if(pointToLineBreak) {
					*pointToLineBreak = '\0';
				}
				syslog(LOG_NOTICE, "%s", pointToBeginLine);
				if(sverb.pcap_stat_to_stdout) {
					cout << "VM(" << getpid() << ") " << pointToBeginLine << endl;
				}
				if(pointToLineBreak) {
					*pointToLineBreak = '\n';
					pointToBeginLine = pointToLineBreak + 1;
				} else {
					pointToBeginLine = NULL;
				}
			}
		}
	}

	if(task == pcapStatCpuCheck) {
		extern int global_livesniffer;
		extern map<unsigned int, livesnifferfilter_s*> usersniffer;
		extern map<unsigned int, string> usersniffer_kill_reason;
		extern volatile int usersniffer_sync;
		extern volatile int usersniffer_checksize_sync;
		extern pthread_t usersniffer_checksize_thread;
		extern int opt_livesniffer_timeout_s;
		extern int opt_livesniffer_tablesize_max_mb;
		if(global_livesniffer) {
			if(heap_pb_perc >= 60) {
				if(usersniffer.size()) {
					cLogSensor *log = cLogSensor::begin(cLogSensor::notice, "live sniffer", "too high load - terminate");
					__SYNC_LOCK(usersniffer_sync);
					for(map<unsigned int, livesnifferfilter_s*>::iterator iter = usersniffer.begin(); iter != usersniffer.end(); ) {
						string kill_reason = "too high load";
						log->log(NULL, "uid: %u, state: %s, reason: %s", iter->first, iter->second->getStringState().c_str(), kill_reason.c_str());
						delete iter->second;
						usersniffer_kill_reason[iter->first] = kill_reason;
						usersniffer.erase(iter++);
					}
					global_livesniffer = 0;
					__SYNC_UNLOCK(usersniffer_sync);
					if(log) {
						log->end();
					}
				}
			} else {
				time_t now = time(NULL);
				cLogSensor *log = NULL;
				__SYNC_LOCK(usersniffer_sync);
				for(map<unsigned int, livesnifferfilter_s*>::iterator iter = usersniffer.begin(); iter != usersniffer.end(); ) {
					if(now > iter->second->created_at && 
					   ((opt_livesniffer_timeout_s > 0 && (now - iter->second->created_at) >= opt_livesniffer_timeout_s) ||
					    (iter->second->timeout_s > 0 && (now - iter->second->created_at) >= iter->second->timeout_s))) {
						string kill_reason;
						if(opt_livesniffer_timeout_s > 0 && (now - iter->second->created_at) >= opt_livesniffer_timeout_s) {
							kill_reason = "timeout (in sniffer configuration - " + intToString(opt_livesniffer_timeout_s) + "s)";
						} else {
							kill_reason = "timeout (define in gui)";
						}
						if (!(iter->second->disable_timeout_warn_msg)) {
							if(!log) {
								log = cLogSensor::begin(cLogSensor::notice, "live sniffer", "timeout - terminate");
							}
							log->log(NULL, "uid: %u, state: %s, reason: %s", iter->first, iter->second->getStringState().c_str(), kill_reason.c_str());
						}
						delete iter->second;
						usersniffer_kill_reason[iter->first] = kill_reason;
						usersniffer.erase(iter++);
					} else {
						iter++;
					}
				}
				if(!usersniffer.size()) {
					global_livesniffer = 0;
				}
				__SYNC_UNLOCK(usersniffer_sync);
				if(log) {
					log->end();
				}
			}
			if(opt_livesniffer_tablesize_max_mb > 0 && usersniffer.size() && !usersniffer_checksize_sync) {
				usersniffer_checksize_sync = 1;
				extern void *checkSizeOfLivepacketTables(void *arg);
				vm_pthread_create_autodestroy("check size of livepacket tables",
							      &usersniffer_checksize_thread, NULL, checkSizeOfLivepacketTables, this, __FILE__, __LINE__);
			}
		}
	}

	if(task == pcapStatLog && opt_rrd) {
		if(opt_rrd == 1) {
			rrd_charts_create();
			rrd_charts_alter();
			opt_rrd ++;
		}
		rrd_update();
	}
	
	if(task == pcapStatLog) {
		extern bool opt_abort_if_heap_full;
		extern bool opt_exit_if_heap_full;
		if(opt_abort_if_heap_full || opt_exit_if_heap_full ||
		   sverb.abort_if_heap_full || sverb.exit_if_heap_full) {
			if(packetbuffer_memory_is_full || heap_pb_perc > 98) {
				if(++heapFullCounter > 10) {
					syslog(LOG_NOTICE, "buffersControl: %s", buffersControl.debug().c_str());
					syslog(LOG_ERR, "HEAP FULL - %s!", opt_exit_if_heap_full || sverb.exit_if_heap_full ? "EXIT" : "ABORT");
					if(opt_exit_if_heap_full || sverb.exit_if_heap_full) {
						extern WDT *wdt;
						wdt = NULL;
						exit(2);
					} else {
						abort();
					}
				}
			} else {
				heapFullCounter = 0;
			}
		}
		
		if(!is_client_packetbuffer_sender() && !is_sender()) {
			extern bool opt_abort_if_heap_full_and_t2cpu_is_low;
			extern bool opt_exit_if_heap_full_and_t2cpu_is_low;
			if(opt_abort_if_heap_full_and_t2cpu_is_low || opt_exit_if_heap_full_and_t2cpu_is_low) {
				if((packetbuffer_memory_is_full || heap_pb_perc > 98) && sum_t2cpu < 50) {
					if(++heapFullIfT2cpuIsLowCounter > 10) {
						syslog(LOG_NOTICE, "buffersControl: %s", buffersControl.debug().c_str());
						syslog(LOG_ERR, "HEAP FULL (and t2cpu is low) - %s!", opt_exit_if_heap_full_and_t2cpu_is_low ? "EXIT" : "ABORT");
						if(opt_exit_if_heap_full_and_t2cpu_is_low) {
							extern WDT *wdt;
							wdt = NULL;
							exit(2);
						} else {
							abort();
						}
					}
				} else {
					heapFullIfT2cpuIsLowCounter = 0;
				}
			}
		}
		
		extern int opt_abort_if_rss_gt_gb;
		if(opt_abort_if_rss_gt_gb > 0 && (int)(rss/1024/1024/1024) > opt_abort_if_rss_gt_gb) {
			syslog(LOG_ERR, "RSS %i > %i - ABORT!",
			       (int)(rss/1024/1024/1024), opt_abort_if_rss_gt_gb);
			exit(2);
		}
	}
}

string PcapQueue::pcapDropCountStat() {
	return(this->instancePcapHandle ?
		this->instancePcapHandle->pcapDropCountStat_interface() :
		this->pcapDropCountStat_interface());
}

void PcapQueue::initStat() {
	if(this->instancePcapHandle) {
		this->instancePcapHandle->initStat_interface();
	} else {
		this->initStat_interface();
	}
}

pcap_t* PcapQueue::getPcapHandle(int dlt) {
	return(this->instancePcapHandle ?
		this->instancePcapHandle->_getPcapHandle(dlt) :
		this->_getPcapHandle(dlt));
}

u_int16_t PcapQueue::getPcapHandleIndex(int dlt) {
	return(this->instancePcapHandle ?
		this->instancePcapHandle->_getPcapHandleIndex(dlt) :
		this->_getPcapHandleIndex(dlt));
}

bool PcapQueue::createThread() {
	if(this->enableMainThread) {
		this->createMainThread();
	}
	if(this->enableWriteThread) {
		this->createWriteThread();
	}
	return(true);
}

bool PcapQueue::createMainThread() {
	vm_pthread_create(("pb - main " + nameQueue).c_str(),
			  &this->threadHandle, NULL, _PcapQueue_threadFunction, this, __FILE__, __LINE__);
	return(true);
}

bool PcapQueue::createWriteThread() {
	vm_pthread_create(("pb - write " + nameQueue).c_str(),
			  &this->writeThreadHandle, NULL, _PcapQueue_writeThreadFunction, this, __FILE__, __LINE__);
	return(true);
}

bool PcapQueue::initThread(void *arg, unsigned int arg2, string */*error*/) {
	return(!this->enableMainThread || this->openFifoForRead(arg, arg2));
}

bool PcapQueue::initWriteThread(void *arg, unsigned int arg2) {
	return(!this->enableWriteThread || this->openFifoForWrite(arg, arg2));
}

string PcapQueue::pcapStatString_packets(int statPeriod) {
	ostringstream outStr;
	outStr << fixed;
	if(sumPacketsCounterIn[0]) {
		outStr << "PACKETS IN / OUT: " 
		       << setw(9) << sumPacketsCounterIn[0] << " / " 
		       << setw(9) << sumPacketsCounterOut[0] << "  ";
	}
	outStr << "BLOCKS IN / OUT: " 
	       << setw(7) << sumBlocksCounterIn[0] << " / " 
	       << setw(7) << sumBlocksCounterOut[0] << "  ";
	if(sumPacketsSizeCompress[0] && sumPacketsSize[0]) {
		outStr << "compress: " 
		       << setw(3) << setprecision(0) << (100.0 * sumPacketsSizeCompress[0] / sumPacketsSize[0]) << "%"
		       << " ( " << setw(12) << sumPacketsSizeCompress[0] << " / " << setw(12) << sumPacketsSize[0] << " )";
	}
	outStr << endl;
	if(sumPacketsCounterIn[1] || sumBlocksCounterIn[1]) {
		if(sumPacketsCounterIn[0]) {
			outStr << "              /s: " 
			       << setw(9) << sumPacketsCounterIn[2]/statPeriod << " / " 
			       << setw(9) << sumPacketsCounterOut[2]/statPeriod << "  ";
		}
		outStr << "               : " 
		       << setw(7) << sumBlocksCounterIn[2]/statPeriod << " / " 
		       << setw(7) << sumBlocksCounterOut[2]/statPeriod;
		if(sumPacketsSize[0]) {
			outStr << "                ";
			if(sumPacketsSizeCompress[0]) {
				outStr << "   " 
				       << setw(12) << sumPacketsSizeCompress[2]/statPeriod << " / " 
				       << setw(12) << sumPacketsSize[2]/statPeriod;
			}
			outStr << "   " << (double)sumPacketsSize[2]/statPeriod/(1024*1024)*8 << "Mb/s";
		}
		outStr << endl;
	}
	return(outStr.str());
}

double PcapQueue::pcapStat_get_compress() {
	if(sumPacketsSizeCompress[0] && sumPacketsSize[0]) {
		return(100.0 * sumPacketsSizeCompress[0] / sumPacketsSize[0]);
	} else {
		return(-1);
	}
}

double PcapQueue::pcapStat_get_speed_mb_s(int statPeriod) {
	if(sumPacketsSize[2]) {
		return(((double)sumPacketsSize[2])/statPeriod/(1024*1024)*8);
	} else {
		return(-1);
	}
}

#if LOG_PACKETS_PER_SEC
u_int64_t PcapQueue::pcapStat_get_speed_packets_s(int statPeriod) {
	if(sumPacketsCount[2]) {
		return(sumPacketsCount[2]/statPeriod);
	} else {
		return(-1);
	}
}
#endif

double PcapQueue::pcapStat_get_speed_out_mb_s(int statPeriod) {
	if(sumPacketsSizeOut[2]) {
		return(((double)sumPacketsSizeOut[2])/statPeriod/(1024*1024)*8);
	} else {
		return(-1);
	}
}

#if LOG_PACKETS_PER_SEC
u_int64_t PcapQueue::pcapStat_get_speed_out_packets_s(int statPeriod) {
	if(sumPacketsCountOut[2]) {
		return(sumPacketsCountOut[2]/statPeriod);
	} else {
		return(-1);
	}
}
#endif

int PcapQueue::getThreadPid(eTypeThread typeThread) {
	switch(typeThread) {
	case mainThread:
		return(threadTerminated ? 0 : mainThreadId);
	case writeThread:
		return(writeThreadTerminated ? 0 : writeThreadId);
	case nextThread1:
		return(nextThreadsId[0]);
	case nextThread2:
		return(nextThreadsId[1]);
	case nextThread3:
		return(nextThreadsId[2]);
	}
	return(0);
}

pstat_data *PcapQueue::getThreadPstatData(eTypeThread typeThread, int pstatDataIndex) {
	switch(typeThread) {
	case mainThread:
		return(mainThreadPstatData[pstatDataIndex]);
	case writeThread:
		return(writeThreadPstatData[pstatDataIndex]);
	case nextThread1:
		return(nextThreadsPstatData[0][pstatDataIndex]);
	case nextThread2:
		return(nextThreadsPstatData[1][pstatDataIndex]);
	case nextThread3:
		return(nextThreadsPstatData[2][pstatDataIndex]);
	}
	return(NULL);
}

void PcapQueue::preparePstatData(eTypeThread typeThread, int pstatDataIndex) {
	int pid = getThreadPid(typeThread);
	pstat_data *threadPstatData = getThreadPstatData(typeThread, pstatDataIndex);
	if(pid && threadPstatData) {
		if(threadPstatData[0].cpu_total_time) {
			threadPstatData[1] = threadPstatData[0];
		}
		pstat_get_data(pid, threadPstatData);
	}
}

void PcapQueue::prepareProcPstatData() {
	pstat_get_data(0, this->procPstatData);
}

double PcapQueue::getCpuUsagePerc(eTypeThread typeThread, int pstatDataIndex, bool preparePstatData) {
	if(this->threadInitFailed) {
		return(-1);
	}
	if(preparePstatData) {
		this->preparePstatData(typeThread, pstatDataIndex);
	}
	int pid = getThreadPid(typeThread);
	pstat_data *threadPstatData = getThreadPstatData(typeThread, pstatDataIndex);
	if(pid && threadPstatData) {
		double ucpu_usage, scpu_usage;
		if(threadPstatData[0].cpu_total_time && threadPstatData[1].cpu_total_time) {
			pstat_calc_cpu_usage_pct(
				&threadPstatData[0], &threadPstatData[1],
				&ucpu_usage, &scpu_usage);
			return(ucpu_usage + scpu_usage);
		}
	}
	return(-1);
}

long unsigned int PcapQueue::getVsizeUsage(bool preparePstatData) {
	if(preparePstatData) {
		this->prepareProcPstatData();
	}
	return(this->procPstatData[0].vsize);
}

long unsigned int PcapQueue::getRssUsage(bool preparePstatData) {
	if(preparePstatData) {
		this->prepareProcPstatData();
	}
	return(this->procPstatData[0].rss);
}

void PcapQueue::processBeforeAddToPacketBuffer(pcap_pkthdr* header,u_char* packet, u_int offset) {
	extern SocketSimpleBufferWrite *sipSendSocket;
	extern int opt_sip_send_before_packetbuffer;
	if(!sipSendSocket || !opt_sip_send_before_packetbuffer) {
		return;
	}
 
	iphdr2 *header_ip = (iphdr2*)(packet + offset);
	while(true) {
		int next_header_ip_offset = findNextHeaderIp(header_ip, offset, packet, header->caplen);
		if(next_header_ip_offset == 0) {
			break;
		} else if(next_header_ip_offset < 0) {
			return;
		} else {
			header_ip = (iphdr2*)((u_char*)header_ip + next_header_ip_offset);
			offset += next_header_ip_offset;
		}
	}

	char *data = NULL;
	int datalen = 0;
	vmPort sport;
	vmPort dport;
	bool isTcp = false;
	u_int8_t ip_protocol = header_ip->get_protocol(header->caplen - offset);
	if (ip_protocol == IPPROTO_UDP) {
		udphdr2 *header_udp = (udphdr2*) ((char*)header_ip + header_ip->get_hdr_size());
		datalen = get_udp_data_len(header_ip, header_udp, &data, packet, header->caplen);
		sport = header_udp->get_source();
		dport = header_udp->get_dest();
	} else if (ip_protocol == IPPROTO_TCP) {
		tcphdr2 *header_tcp = (tcphdr2*) ((char*)header_ip + header_ip->get_hdr_size());
		datalen = get_tcp_data_len(header_ip, header_tcp, &data, packet, header->caplen);
		sport = header_tcp->get_source();
		dport = header_tcp->get_dest();
		isTcp = true;
	} else {
		return;
	}
	
	if(sipSendSocket && sport.isSet() && dport.isSet() &&
	   (sipportmatrix[sport] || sipportmatrix[dport]) &&
	   check_sip20(data, datalen, NULL, isTcp)) {
		u_int16_t header_length = datalen;
		sipSendSocket->addData(&header_length, 2,
				       data, datalen);
	}
}


inline void *_PcapQueue_threadFunction(void *arg) {
	return(((PcapQueue*)arg)->threadFunction(arg, 0));
}

inline void *_PcapQueue_writeThreadFunction(void *arg) {
	return(((PcapQueue*)arg)->writeThreadFunction(arg, 0));
}


PcapQueue_readFromInterface_base::PcapQueue_readFromInterface_base(sInterface *interface) {
	if(interface) {
		this->interface = *interface;
	}
	this->interfaceNet = 0;
	this->interfaceMask = 0;
	this->pcapHandle = NULL;
	this->pcapHandleIndex = 0;
	this->pcapEnd = false;
	this->dpdkHandle = NULL;
	memset(&this->filterData, 0, sizeof(this->filterData));
	this->filterDataUse = false;
	this->pcapDumpHandle = NULL;
	this->pcapLinklayerHeaderType = 0;
	// CONFIG
	extern int opt_promisc;
	extern int opt_ringbuffer;
	this->pcap_snaplen = get_pcap_snaplen();
	this->pcap_promisc = opt_promisc;
	this->pcap_timeout = 100;
	this->pcap_buffer_size = opt_ringbuffer * 1024 * 1024;
	//
	memset(&this->last_ps, 0, sizeof(this->last_ps));
	this->countPacketDrop = 0;
	this->lastTimeLogErrPcapNextExNullPacket = 0;
	this->lastTimeLogErrPcapNextExErrorReading = 0;
	//
	libpcap_buffer_offset = 0;
	libpcap_buffer = NULL;
	libpcap_buffer_old = NULL;
	packets_counter = 0;
	extern vector<vmIP> if_filter_ip;
	extern vector<vmIPmask> if_filter_net;
	extern bool opt_if_filter_ip_quick;
	filter_ip = false;
	filter_ip_quick = NULL;
	filter_ip_std = NULL;
	if(if_filter_ip.size() || if_filter_net.size()) {
		filter_ip = true;
		int limit_host_bits_for_convert_to_ips = 8;
		if(opt_if_filter_ip_quick) {
			if(if_filter_ip.size()) {
				filter_ip_quick = new FILE_LINE(0) cQuickIPfilter;
				for(unsigned i = 0; i < if_filter_ip.size(); i++) {
					filter_ip_quick->add(&if_filter_ip[i]);
				}
			}
			if(if_filter_net.size()) {
				for(unsigned i = 0; i < if_filter_net.size(); i++) {
					if(if_filter_net[i].host_bits() <= limit_host_bits_for_convert_to_ips) {
						if(!filter_ip_quick) {
							filter_ip_quick = new FILE_LINE(0) cQuickIPfilter;
						}
						list<vmIP> list_ip;
						if_filter_net[i].ip_list(&list_ip);
						for(list<vmIP>::iterator iter = list_ip.begin(); iter != list_ip.end(); iter++) {
							filter_ip_quick->add(&*iter);
						}
					} else {
						if(!filter_ip_std) {
							filter_ip_std = new FILE_LINE(0) ListIP;
						}
						filter_ip_std->add(if_filter_net[i]);
					}
				}
			}
		} else {
			filter_ip_std = new FILE_LINE(0) ListIP;
			if(if_filter_ip.size()) {
				filter_ip_std->add(&if_filter_ip);
			}
			if(if_filter_net.size()) {
				filter_ip_std->add(&if_filter_net, limit_host_bits_for_convert_to_ips);
			}
		}
	}
	read_from_file_index = 0;
	#if EXPERIMENTAL_CHECK_PCAP_TIME
	lastPcapTime_s = 0;
	lastTimeErrorLogPcapTime_ms = 0;
	#endif
	firstTimeErrorLogEtherTypeFFFF_ms = 0;
	counterErrorLogEtherTypeFFFF_ms = 0;
	firstPacketTime_us = 0;
	firstPacketTime_at_ms = 0;
	waitForPacketTime = false;
	wait_header = NULL;
	wait_packet = NULL;
}

PcapQueue_readFromInterface_base::~PcapQueue_readFromInterface_base() {
	if(this->pcapHandle) {
		pcap_close(this->pcapHandle);
		syslog(LOG_NOTICE, "packetbuffer terminating: pcap_close pcapHandle (%s)", getInterfaceAlias().c_str());
	}
	if(this->pcapDumpHandle) {
		pcap_dump_close(this->pcapDumpHandle);
		syslog(LOG_NOTICE, "packetbuffer terminating: pcap_close pcapDumpHandle (%s)", getInterfaceAlias().c_str());
	}
	if(this->dpdkHandle) {
		destroy_dpdk_handle(this->dpdkHandle);
	}
	if(filter_ip_quick) {
		delete filter_ip_quick;
	}
	if(filter_ip_std) {
		delete filter_ip_std;
	}
}

bool PcapQueue_readFromInterface_base::startCapture(string *error, sDpdkConfig *dpdkConfig) {
	*error = "";
	static volatile int _sync_start_capture = 0;
	long unsigned int rssBeforeActivate, rssAfterActivate;
	unsigned int usleepCounter = 0;
	__SYNC_LOCK_WHILE(_sync_start_capture) {
		USLEEP_C(100, usleepCounter++);
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	char errorstr[4096];
	if(opt_pb_read_from_file[0]) {
		string _file = split(opt_pb_read_from_file, "@@")[0];
		if(_file == "/dev/stdin") {
			this->pcapHandle = pcap_open_offline("-", errbuf);
		} else {
			this->pcapHandle = pcap_open_offline_zip(_file.c_str(), errbuf);
		}
		if(this->pcapHandle) {
			syslog(LOG_NOTICE, "packetbuffer - successfully opened file %s", _file.c_str());
		} else {
			snprintf(errorstr, sizeof(errorstr), "pcap_open_offline %s failed: %s", _file.c_str(), errbuf); 
			syslog(LOG_ERR, "%s", errorstr);
			*error = errorstr;
			__SYNC_UNLOCK(_sync_start_capture);
			return(false);
		}
		this->pcapHandleIndex = register_pcap_handle(this->pcapHandle);
		this->pcapLinklayerHeaderType = pcap_datalink(this->pcapHandle);
		global_pcap_handle = this->pcapHandle;
		global_pcap_handle_index = this->pcapHandleIndex;
		global_pcap_dlink = this->pcapLinklayerHeaderType;
		read_from_file_index = 0;
		if(opt_pcapdump) {
			char pname[2048];
			snprintf(pname, sizeof(pname), "%s/dump-%s-%u.pcap", 
				 getPcapdumpDir(),
				 this->getInterfaceAlias().c_str(), (unsigned int)time(NULL));
			this->pcapDumpHandle = pcap_dump_open(this->pcapHandle, pname);
		}
		__SYNC_UNLOCK(_sync_start_capture);
		return(true);
	}
	if(VERBOSE) {
		syslog(LOG_NOTICE, "packetbuffer - %s: capturing", this->getInterfaceAlias().c_str());
	}
	if(opt_use_dpdk && dpdkConfig && dpdkConfig->device[0]) {
		this->dpdkHandle = create_dpdk_handle();
		if(!dpdk_activate(dpdkConfig, this->dpdkHandle, error)) {
			__SYNC_UNLOCK(_sync_start_capture);
			pcapLinklayerHeaderType = DLT_EN10MB;
			return(true);
		} else {
			if(!error->empty()) {
				syslog(LOG_ERR, "%s", error->c_str());
			}
			destroy_dpdk_handle(this->dpdkHandle);
			this->dpdkHandle = NULL;
		}
	}
	if(pcap_lookupnet(this->getInterface().c_str(), &this->interfaceNet, &this->interfaceMask, errbuf) == -1) {
		this->interfaceMask = PCAP_NETMASK_UNKNOWN;
	}
	if((this->pcapHandle = pcap_create(this->getInterface().c_str(), errbuf)) == NULL) {
		snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: pcap_create failed: %s", this->getInterfaceAlias().c_str(), errbuf); 
		goto failed;
	}
	this->pcapHandleIndex = register_pcap_handle(this->pcapHandle);
	global_pcap_handle = this->pcapHandle;
	global_pcap_handle_index = this->pcapHandleIndex;
	int status;
	if((status = pcap_set_snaplen(this->pcapHandle, this->pcap_snaplen)) != 0) {
		snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: pcap_snaplen failed", this->getInterfaceAlias().c_str()); 
		goto failed;
	}
	if(strcasecmp(this->getInterfaceAlias().c_str(), "any") &&
	   (status = pcap_set_promisc(this->pcapHandle, this->pcap_promisc)) != 0) {
		snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: pcap_set_promisc failed", this->getInterfaceAlias().c_str()); 
		goto failed;
	}
	if((status = pcap_set_timeout(this->pcapHandle, this->pcap_timeout)) != 0) {
		snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: pcap_set_timeout failed", this->getInterfaceAlias().c_str()); 
		goto failed;
	}
	if(opt_libpcap_immediate_mode) {
		if((status = pcap_set_immediate_mode(this->pcapHandle, 1)) != 0) {
			snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: pcap_set_immediate_mode failed", this->getInterfaceAlias().c_str()); 
			goto failed;
		}
	}
	if((status = pcap_set_buffer_size(this->pcapHandle, this->pcap_buffer_size)) != 0) {
		snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: pcap_set_buffer_size failed", this->getInterfaceAlias().c_str()); 
		goto failed;
	}
	rssBeforeActivate = getRss() / 1024 / 1024;
	if((status = pcap_activate(this->pcapHandle)) != 0) {
		snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: libpcap error: %s", this->getInterfaceAlias().c_str(), pcap_geterr(this->pcapHandle)); 
		cLogSensor::log(cLogSensor::error, errorstr);
		if(opt_fork) {
			ostringstream outStr;
			outStr << this->getInterfaceAlias() << ": libpcap error: " << pcap_geterr(this->pcapHandle);
			daemonizeOutput(outStr.str());
		}
		goto failed;
	}
	if(rssBeforeActivate) {
		for(int i = 0; i < 50; i++) {
			USLEEP(100);
			rssAfterActivate = getRss() / 1024 / 1024;
			if(!rssAfterActivate ||
			   rssAfterActivate > rssBeforeActivate + this->pcap_buffer_size * 0.9 / 1024 / 1024) {
				break;
			}
		}
		if(rssAfterActivate && rssAfterActivate > rssBeforeActivate &&
		   rssAfterActivate < rssBeforeActivate + this->pcap_buffer_size * 0.9 / 1024 / 1024) {
			syslog(LOG_NOTICE, "packetbuffer - %s: ringbuffer has only %lu MB which means that your kernel does not support ringbuffer (<2.6.32) or you have invalid ringbuffer setting", this->getInterfaceAlias().c_str(), rssAfterActivate - rssBeforeActivate); 
			if(opt_fork) {
				ostringstream outStr;
				outStr << this->getInterfaceAlias() << ": ringbuffer has only " << (rssAfterActivate - rssBeforeActivate) << " MB which means that your kernel does not support ringbuffer (<2.6.32) or you have invalid ringbuffer setting";
				daemonizeOutput(outStr.str());
			}
		}
		if(rssAfterActivate > rssBeforeActivate) {
			all_ringbuffers_size += (rssAfterActivate - rssBeforeActivate) * 1024 * 1024;
		}
	}
	if(opt_libpcap_nonblock_mode) {
		if(pcap_setnonblock(this->pcapHandle, 1, errbuf) < 0) {
			snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: pcap_setnonblock failed (%s)", this->getInterfaceAlias().c_str(), errbuf); 
			goto failed;
		}
	}
	if(opt_mirrorip) {
		if(opt_mirrorip_dst[0] == '\0') {
			syslog(LOG_ERR, "packetbuffer - %s: mirroring packets was disabled because mirroripdst is not set", this->getInterfaceAlias().c_str());
			opt_mirrorip = 0;
		} else {
			syslog(LOG_NOTICE, "packetbuffer - %s: starting mirroring [%s]->[%s]", opt_mirrorip_src, opt_mirrorip_dst, this->getInterfaceAlias().c_str());
			mirrorip = new FILE_LINE(15024) MirrorIP(opt_mirrorip_src, opt_mirrorip_dst);
		}
	}
	if(*user_filter != '\0' || !this->interface.filter.empty()) {
		vector<string> filters_v;
		if(*user_filter != '\0') {
			filters_v.push_back(user_filter);
		}
		if(!this->interface.filter.empty()) {
			filters_v.push_back(this->interface.filter);
		}
		string filters = filters_v.size() == 1 ?
				  filters_v[0] :
				  "(" + implode(filters_v, ") and (") + ")";
		syslog(LOG_ERR, "packetbuffer - %s: set filter: %s", this->getInterfaceAlias().c_str(), filters.c_str());
		// Compile and apply the filter
		struct bpf_program fp;
		if (pcap_compile(this->pcapHandle, &fp, filters.c_str(), 0, this->interfaceMask) == -1) {
			char user_filter_err[2048];
			snprintf(user_filter_err, sizeof(user_filter_err), "%.2000s%s", filters.c_str(), filters.length() > 2000 ? "..." : "");
			snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: can not parse filter %s: %s", this->getInterfaceAlias().c_str(), user_filter_err, pcap_geterr(this->pcapHandle));
			if(opt_fork) {
				ostringstream outStr;
				outStr << this->getInterfaceAlias() << ": can not parse filter " << user_filter_err << ": " << pcap_geterr(this->pcapHandle);
				daemonizeOutput(outStr.str());
			}
			goto failed;
		}
		if (pcap_setfilter(this->pcapHandle, &fp) == -1) {
			char user_filter_err[2048];
			snprintf(user_filter_err, sizeof(user_filter_err), "%.2000s%s", filters.c_str(), filters.length() > 2000 ? "..." : "");
			snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: can not install filter %s: %s", this->getInterfaceAlias().c_str(), user_filter_err, pcap_geterr(this->pcapHandle));
			if(opt_fork) {
				ostringstream outStr;
				outStr << this->getInterfaceAlias() << ": can not install filter " << user_filter_err << ": " << pcap_geterr(this->pcapHandle);
				daemonizeOutput(outStr.str());
			}
			goto failed;
		}
	}
	this->pcapLinklayerHeaderType = pcap_datalink(this->pcapHandle);
	if(!this->pcapLinklayerHeaderType) {
		snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: pcap_datalink failed", this->getInterfaceAlias().c_str()); 
		goto failed;
	}
	global_pcap_dlink = this->pcapLinklayerHeaderType;
//	syslog(LOG_NOTICE, "DLT - %s: %i", this->getInterfaceAlias().c_str(), this->pcapLinklayerHeaderType);
	if(opt_pcapdump) {
		char pname[2048];
		snprintf(pname, sizeof(pname), "%s/dump-%s-%u.pcap", 
			 getPcapdumpDir(),
			 this->getInterfaceAlias().c_str(), (unsigned int)time(NULL));
		this->pcapDumpHandle = pcap_dump_open(this->pcapHandle, pname);
	}
	__SYNC_UNLOCK(_sync_start_capture);
	return(true);
failed:
	__SYNC_UNLOCK(_sync_start_capture);
	syslog(LOG_ERR, "%s", errorstr);
	*error = errorstr;
	return(false);
}

inline int PcapQueue_readFromInterface_base::pcap_next_ex_iface(pcap_t *pcapHandle, pcap_pkthdr** header, u_char** packet,
								bool checkProtocol, sCheckProtocolData *checkProtocolData) {
	if(!pcapHandle) {
		*header = NULL;
		*packet = NULL;
		return(0);
	}
	int res;
	if(if_unlikely(opt_pb_read_from_file[0] && waitForPacketTime)) {
		u_int64_t packetTime = getTimeUS(*header);
		u_int64_t actTime_ms = getTimeMS_rdtsc();
		u_int64_t pushTime_ms = firstPacketTime_at_ms + (packetTime - firstPacketTime_us) / opt_pb_read_from_file_speed / 1000;
		if(pushTime_ms > actTime_ms) {
			if(pushTime_ms > actTime_ms + 5) {
				usleep(5000);
				return(0);
			} else {
				usleep((pushTime_ms - actTime_ms) * 1000);
			}
		}
		waitForPacketTime = false;
		*header = wait_header;
		*packet = wait_packet;
		goto checkProtocol;
	}
	res = ::pcap_next_ex(pcapHandle, header, (const u_char**)packet);
	if(!packet && res != -2) {
		if(VERBOSE) {
			u_int64_t actTime = getTimeMS();
			if(actTime - 1000 > this->lastTimeLogErrPcapNextExNullPacket) {
				syslog(LOG_NOTICE,"packetbuffer - %s: NULL PACKET, pcap response is %d", this->getInterfaceAlias().c_str(), res);
				this->lastTimeLogErrPcapNextExNullPacket = actTime;
			}
		}
		return(0);
	} else if(res == -1) {
		if(VERBOSE) {
			u_int64_t actTime = getTimeMS();
			if(actTime - 1000 > this->lastTimeLogErrPcapNextExErrorReading) {
				syslog(LOG_NOTICE,"packetbuffer - %s: error reading packets: %s", this->getInterfaceAlias().c_str(), pcap_geterr(this->pcapHandle));
				this->lastTimeLogErrPcapNextExErrorReading = actTime;
			}
		}
		return(0);
	} else if(res == -2) {
		if(VERBOSE && opt_pb_read_from_file[0]) {
			syslog(LOG_NOTICE,"packetbuffer - %s: end of pcap file", this->getInterfaceAlias().c_str());
			vector<string> _files = split(opt_pb_read_from_file, "@@");
			string _file;
			bool _next_read = false;
			if(read_from_file_index < _files.size() - 1) {
				_file = _files[++read_from_file_index];
				_next_read = true;
			} else if(opt_nonstop_read) {
				_file = _files[0];
				read_from_file_index = 0;
				opt_pb_read_from_file_acttime_diff = 0;
			}
			if(!_file.empty()) {
				pcap_close(this->pcapHandle);
				char errbuf[PCAP_ERRBUF_SIZE];
				this->pcapHandle = pcap_open_offline_zip(_file.c_str(), errbuf);
				if(this->pcapHandle) {
					syslog(LOG_NOTICE, "packetbuffer - successfully opened file %s", _file.c_str());
					this->pcapHandleIndex = register_pcap_handle(this->pcapHandle);
					this->pcapLinklayerHeaderType = pcap_datalink(this->pcapHandle);
					global_pcap_handle = this->pcapHandle;
					global_pcap_handle_index = this->pcapHandleIndex;
					global_pcap_dlink = this->pcapLinklayerHeaderType;
					if(_next_read) {
						res = ::pcap_next_ex(this->pcapHandle, header, (const u_char**)packet);
					}
				} else {
					syslog(LOG_ERR, "pcap_open_offline %s failed: %s", _file.c_str(), errbuf);
				}
			}
		}
		if(res == -2) {
			return(-1);
		}
	} else if(res == 0) {
		return(0);
	}
	/*
	{static timeval last_ts;
	 if(last_ts.tv_sec &&
	    (last_ts.tv_sec > (*header)->ts.tv_sec ||
	     (last_ts.tv_sec == (*header)->ts.tv_sec &&
	      last_ts.tv_usec > (*header)->ts.tv_usec))) {
		 cout << (last_ts.tv_usec - (*header)->ts.tv_usec) << " " << flush;
	 }
	 last_ts = (*header)->ts;
	}
	*/
	if(if_unlikely(opt_pb_read_from_file[0])) {
		if((*header)->caplen > this->pcap_snaplen) {
			(*header)->caplen = this->pcap_snaplen;
		}
		if((*header)->caplen > (*header)->len) {
			(*header)->caplen = (*header)->len;
		}
		++packets_counter;
		u_int64_t packetTime = getTimeUS(*header);
		if(opt_pb_read_from_file_time_adjustment) {
			packetTime += opt_pb_read_from_file_time_adjustment * 1000000ull;
			(*header)->ts.tv_sec = TIME_US_TO_S(packetTime);
			(*header)->ts.tv_usec = TIME_US_TO_DEC_US(packetTime);
		}
		if(opt_pb_read_from_file_acttime) {
			if(!opt_pb_read_from_file_acttime_diff) {
				opt_pb_read_from_file_acttime_diff = getTimeUS() - packetTime - 
								     opt_pb_read_from_file_acttime_diff_days * 24 * 3600 * 1000000ull - 
								     opt_pb_read_from_file_acttime_diff_secs * 1000000ull;
			}
			packetTime += opt_pb_read_from_file_acttime_diff;
			(*header)->ts.tv_sec = TIME_US_TO_S(packetTime);
			(*header)->ts.tv_usec = TIME_US_TO_DEC_US(packetTime);
		}
		if(opt_pb_read_from_file_speed) {
			u_int64_t actTime_ms = getTimeMS_rdtsc();
			if(!firstPacketTime_us) {
				firstPacketTime_us = packetTime;
				firstPacketTime_at_ms = actTime_ms;
			} else if(packetTime > firstPacketTime_us) {
				u_int64_t pushTime_ms = firstPacketTime_at_ms + (packetTime - firstPacketTime_us) / opt_pb_read_from_file_speed / 1000;
				if(pushTime_ms > actTime_ms) {
					if(pushTime_ms > actTime_ms + 5) {
						usleep(5000);
						waitForPacketTime = true;
						wait_header = *header;
						wait_packet = *packet;
						return(0);
					} else {
						usleep((pushTime_ms - actTime_ms) * 1000);
					}
				}
			}
		} else if(!opt_unlimited_read && !opt_nonstop_read_quick && heap_pb_used_perc > 5) {
			USLEEP(50);
		}
		if(opt_pb_read_from_file_max_packets && packets_counter > opt_pb_read_from_file_max_packets) {
			syslog(LOG_NOTICE,"packetbuffer - exceed limit of read packets, exiting");
			return(-1);
		}
	} else {
		extern int opt_use_oneshot_buffer;
		if(!libpcap_buffer_offset && opt_use_oneshot_buffer) {
		 
			struct _pcap {
				/*
				 * Method to call to read packets on a live capture.
				 */
				void *read_op;

				/*
				 * Method to call to read to read packets from a savefile.
				 */
				int (*next_packet_op)(pcap_t *, struct pcap_pkthdr *, u_char **);

				int fd;
				int selectable_fd;

				/*
				 * Read buffer.
				 */
				int bufsize;
				u_char *buffer;
				u_char *bp;
				int cc;

				int break_loop;		/* flag set to force break from packet-reading loop */

				void *priv;		/* private data for methods */

			};
			struct _pcap_linux {
				u_int	packets_read;	/* count of packets read with recvfrom() */
				long	proc_dropped;	/* packets reported dropped by /proc/net/dev */
				struct pcap_stat stat;

				char	*device;	/* device name */
				int	filter_in_userland; /* must filter in userland */
				int	blocks_to_filter_in_userland;
				int	must_do_on_close; /* stuff we must do when we close */
				int	timeout;	/* timeout for buffering */
				int	sock_packet;	/* using Linux 2.0 compatible interface */
				int	cooked;		/* using SOCK_DGRAM rather than SOCK_RAW */
				int	ifindex;	/* interface index of device we're bound to */
				int	lo_ifindex;	/* interface index of the loopback device */
				bpf_u_int32 oldmode;	/* mode to restore when turning monitor mode off */
				char	*mondevice;	/* mac80211 monitor device we created */
				u_char	*mmapbuf;	/* memory-mapped region pointer */
				size_t	mmapbuflen;	/* size of region */
				int	vlan_offset;	/* offset at which to insert vlan tags; if -1, don't insert */
				u_int	tp_version;	/* version of tpacket_hdr for mmaped ring */
				u_int	tp_hdrlen;	/* hdrlen of tpacket_hdr for mmaped ring */
				u_char	*oneshot_buffer; /* buffer for copy of packet */
			};
		 
			cout << "detect oneshot buffer" << endl;
			libpcap_buffer = &(((_pcap_linux*)((struct _pcap*)this->pcapHandle)->priv)->oneshot_buffer);
			libpcap_buffer_offset = (u_char*)libpcap_buffer - (u_char*)this->pcapHandle;
			int libpcap_buffer_ok = 0;
			if(libpcap_buffer_offset >= 0 && libpcap_buffer_offset < 1000 &&
			   *libpcap_buffer == *packet) {
				libpcap_buffer_ok = 1;
				cout << "method 1 success" << endl;
			} else { 
				for(int i = 0; i < 1000; i++) {
					if(*(u_char**)((u_char*)this->pcapHandle + i) == *packet) {
						libpcap_buffer = (u_char**)((u_char*)this->pcapHandle + i);
						libpcap_buffer_offset = i;
						libpcap_buffer_ok = 2;
						cout << "method 2 success" << endl;
						break;
					}
				}
			}
			if(!libpcap_buffer_ok) {
				libpcap_buffer = NULL;
				libpcap_buffer_offset = -1;
			}
			if(libpcap_buffer) {
				cout << "oneshot buffer: " << hex << (long)*libpcap_buffer << endl;
				cout << "packet: " << hex << (long)*packet << endl;
				cout << dec;
				if(libpcap_buffer_ok == 1) {
					cout << "device: " << ((_pcap_linux*)((struct _pcap*)this->pcapHandle)->priv)->device << endl;
				}
				cout << "offset: " << libpcap_buffer_offset << endl;
				libpcap_buffer_old = *packet;
			}
			syslog(LOG_NOTICE, "find oneshot libpcap buffer : %s", libpcap_buffer ? "success" : "failed");
		}
	}
	#if EXPERIMENTAL_CHECK_PCAP_TIME
	if((lastPcapTime_s &&
	    abs(lastPcapTime_s - (int64_t)((*header)->ts.tv_sec)) > 24 * 60 * 60) ||
	   (*header)->ts.tv_sec == 0) {
		u_int64_t actTimeMS = getTimeMS_rdtsc();
		if(!lastTimeErrorLogPcapTime_ms ||
		   actTimeMS > lastTimeErrorLogPcapTime_ms + 1000) {
			cLogSensor::log(cLogSensor::error,
					"bad pcap time from interface %s",
					interfaceName.c_str());
			lastTimeErrorLogPcapTime_ms = actTimeMS;
		}
		return(-12);
	}
	lastPcapTime_s = (*header)->ts.tv_sec;
	#endif
checkProtocol:
	if(checkProtocol || filter_ip) {
		sCheckProtocolData _checkProtocolData;
		if(!checkProtocolData) {
			checkProtocolData = &_checkProtocolData;
		}
		if(!check_protocol(*header, *packet, checkProtocolData) ||
		   !check_filter_ip(*header, *packet, checkProtocolData)) {
			return(-11);
		}
	}
	return(1);
}

bool PcapQueue_readFromInterface_base::check_protocol(pcap_pkthdr* header, u_char* packet, sCheckProtocolData *checkProtocolData) {
	if(parseEtherHeader(pcapLinklayerHeaderType, packet,
			    &checkProtocolData->header_eth, NULL,
			    checkProtocolData->header_ip_offset, checkProtocolData->protocol, checkProtocolData->vlan)) {
		if((checkProtocolData->protocol == ETHERTYPE_IP ||
		    (VM_IPV6_B && checkProtocolData->protocol == ETHERTYPE_IPV6)) &&
		   (((iphdr2*)(packet + checkProtocolData->header_ip_offset))->version == 4 ||
		    (VM_IPV6_B && ((iphdr2*)(packet + checkProtocolData->header_ip_offset))->version == 6)) &&
		   ((iphdr2*)(packet + checkProtocolData->header_ip_offset))->get_tot_len() + checkProtocolData->header_ip_offset <= header->len) {
			#if EXPERIMENTAL_SEPARATE_PROCESSSING
			#if EXPERIMENTAL_SEPARATE_PROCESSSING_NEXT_01
			if(separate_processing()) {
				u_int header_ip_offset = checkProtocolData->header_ip_offset;
				iphdr2 *header_ip = (iphdr2*)(packet + header_ip_offset);
				u_int16_t frag_data = header_ip->get_frag_data();
				if(header_ip->is_more_frag(frag_data) || header_ip->get_frag_offset(frag_data)) {
					return(true);
				}
				char *data = NULL;
				int datalen = 0;
				u_int8_t ip_protocol = header_ip->get_protocol(header->caplen - header_ip_offset);
				if(ip_protocol == IPPROTO_UDP) {
					udphdr2 *header_udp = (udphdr2*) ((char*)header_ip + header_ip->get_hdr_size());
					datalen = get_udp_data_len(header_ip, header_udp, &data, packet, header->caplen);
				} else if(ip_protocol == IPPROTO_TCP) {
					tcphdr2 *header_tcp = (tcphdr2*) ((char*)header_ip + header_ip->get_hdr_size());
					datalen = get_tcp_data_len(header_ip, header_tcp, &data, packet, header->caplen);
				} else {
					return(true);
				}
				if(IS_RTP(data, datalen)) {
					if(separate_processing() == 1) {
						return(false);
					}
				} else {
					if(separate_processing() == 2) {
						return(false);
					}
				}
			}
			#endif
			#endif
			return(true);
		} else if(checkProtocolData->header_ip_offset == 0xFFFF) {
			return(true);
		} else if(checkProtocolData->protocol == 0xFFFF) {
			u_int64_t actTime_ms = getTimeMS();
			++this->counterErrorLogEtherTypeFFFF_ms;
			if(!this->firstTimeErrorLogEtherTypeFFFF_ms) {
				this->firstTimeErrorLogEtherTypeFFFF_ms = actTime_ms;
			} else if(actTime_ms > this->firstTimeErrorLogEtherTypeFFFF_ms + 60000) {
				if(actTime_ms < this->firstTimeErrorLogEtherTypeFFFF_ms + 70000 &&
				   this->counterErrorLogEtherTypeFFFF_ms > 100) {
					ostringstream outStr;
					outStr << "A bad packet with ether_type 0xFFFF was detected on interface " << getInterfaceAlias() << ". Contact support!";
					cLogSensor::log(cLogSensor::error, outStr.str().c_str());
				}
				this->firstTimeErrorLogEtherTypeFFFF_ms = 0;
				this->counterErrorLogEtherTypeFFFF_ms = 0;
			}
		}
	}
	return(false);
}

bool PcapQueue_readFromInterface_base::check_filter_ip(pcap_pkthdr* header, u_char* packet, sCheckProtocolData *checkProtocolData) {
	if(filter_ip) {
		iphdr2 *iphdr = (iphdr2*)(packet + checkProtocolData->header_ip_offset);
		bool ip_ok = false;
		if(filter_ip_quick) {
			if(filter_ip_quick->check(iphdr->get_saddr()) || filter_ip_quick->check(iphdr->get_daddr())) {
				ip_ok = true;
			}
		}
		if(!ip_ok && filter_ip_std) {
			if(filter_ip_std->checkIP(iphdr->get_saddr()) || filter_ip_std->checkIP(iphdr->get_daddr())) {
				ip_ok = true;
			}
		}
		if(!ip_ok) {
			return(false);
		}
	}
	extern bool opt_is_client_packetbuffer_sender;
	if(opt_is_client_packetbuffer_sender) {
		iphdr2 *iphdr = (iphdr2*)(packet + checkProtocolData->header_ip_offset);
		if(iphdr->get_protocol(header->caplen - checkProtocolData->header_ip_offset) == IPPROTO_TCP) {
			tcphdr2 *header_tcp = (tcphdr2*)((char*)iphdr + iphdr->get_hdr_size());
			if((iphdr->get_daddr() == snifferClientOptions.host_ip &&
			    (unsigned)header_tcp->get_dest() == snifferClientOptions.port) ||
			   (iphdr->get_saddr() == snifferClientOptions.host_ip &&
			    (unsigned)header_tcp->get_source() == snifferClientOptions.port)) {
				return(false);
			}
		}
	}
	return(true);
}

void PcapQueue_readFromInterface_base::restoreOneshotBuffer() {
	if(libpcap_buffer_old && libpcap_buffer) {
		*libpcap_buffer = libpcap_buffer_old;
	}
}

/*
inline void __pcap_dispatch_handler(u_char *user, const pcap_pkthdr *header, const u_char *data) {
	if(header && data) {
		PcapQueue_readFromInterface_base *me = (PcapQueue_readFromInterface_base*)user;
		me->push((pcap_pkthdr*)header, (u_char*)data, 0, NULL);
	}
}

inline int PcapQueue_readFromInterface_base::pcap_dispatch(pcap_t *pcapHandle) {
	int res = ::pcap_dispatch(pcapHandle, 1, __pcap_dispatch_handler, ((u_char*)this));
	if(res == -1) {
		if(VERBOSE) {
			syslog (LOG_NOTICE,"packetbuffer dispatch - %s: error reading packets", this->getInterfaceAlias().c_str());
		}
		return(0);
	} else if(res == -2) {
		if(VERBOSE) {
			syslog(LOG_NOTICE,"packetbuffer dispatch - %s: end of pcap file, exiting", this->getInterfaceAlias().c_str());
		}
		return(-1);
	} else if(res == 0) {
		return(0);
	}
	return(1);
}
*/

inline int PcapQueue_readFromInterface_base::pcapProcess(sHeaderPacket **header_packet, int pushToStack_queue_index,
							 pcap_block_store *block_store, int block_store_index,
							 int ppf, pcap_dumper_t *pcapDumpHandle) {
	return(::pcapProcess(header_packet, pushToStack_queue_index,
			     block_store, block_store_index,
			     ppf,
			     &ppd, pcapLinklayerHeaderType, pcapDumpHandle, getInterfaceAlias().c_str()));
}

string PcapQueue_readFromInterface_base::pcapStatString_interface(int /*statPeriod*/) {
	ostringstream outStr;
	if(this->pcapHandle) {
		pcap_stat ps;
		int pcapstatres = pcap_stats(this->pcapHandle, &ps);
		if(pcapstatres == 0) {
			if(ps.ps_recv >= this->last_ps.ps_recv) {
				extern int opt_pcap_ifdrop_limit;
				bool pcapdrop = false;
				bool ifdrop = false;
				if(ps.ps_drop > this->last_ps.ps_drop) {
					pcapdrop = true;
					pcap_drop_flag = 1;
				}
				if(ps.ps_ifdrop > this->last_ps.ps_ifdrop &&
				   (ps.ps_ifdrop - this->last_ps.ps_ifdrop) > (ps.ps_recv - this->last_ps.ps_recv) * opt_pcap_ifdrop_limit / 100) {
					ifdrop = true;
				}
				if(pcapdrop) {
					++this->countPacketDrop;
				}
				if(pcapdrop || ifdrop) {
					outStr << fixed
					       << "DROPPED PACKETS - " << this->getInterfaceAlias() << ": "
					       << "libpcap or interface dropped some packets!"
					       << " rx:" << (ps.ps_recv - this->last_ps.ps_recv);
					if(pcapdrop) {
						outStr << " pcapdrop:" << (ps.ps_drop - this->last_ps.ps_drop) << " " 
						       << setprecision(1) << ((double)(ps.ps_drop - this->last_ps.ps_drop) / (ps.ps_recv - this->last_ps.ps_recv) * 100) << "%";
					}
					if(ifdrop) {
						outStr << " ifdrop:" << (ps.ps_ifdrop - this->last_ps.ps_ifdrop) << " " 
						       << setprecision(1) << ((double)(ps.ps_ifdrop - this->last_ps.ps_ifdrop) / (ps.ps_recv - this->last_ps.ps_recv) * 100) << "%";
					}
					outStr << endl
					       << "     increase --ring-buffer (kernel >= 2.6.31 and libpcap >= 1.0.0)" 
					       << endl;
				}
			}
			this->last_ps = ps;
		}
	} else if(this->dpdkHandle) {
		pcap_stat ps;
		string dpdk_stats_str_rslt;
		int pcapstatres = pcap_dpdk_stats(this->dpdkHandle, &ps, &dpdk_stats_str_rslt);
		if(pcapstatres == 0) {
			if(ps.ps_recv >= this->last_ps.ps_recv) {
				extern int opt_pcap_dpdk_ifdrop_limit;
				bool pcapdrop = false;
				bool ifdrop = false;
				if(ps.ps_drop > this->last_ps.ps_drop) {
					pcapdrop = true;
					pcap_drop_flag = 1;
				}
				if(ps.ps_ifdrop > this->last_ps.ps_ifdrop &&
				   (ps.ps_ifdrop - this->last_ps.ps_ifdrop) > (ps.ps_recv - this->last_ps.ps_recv) * opt_pcap_dpdk_ifdrop_limit / 100) {
					ifdrop = true;
					pcap_drop_flag = 1;
				}
				if(pcapdrop || ifdrop) {
					++this->countPacketDrop;
				}
				if(pcapdrop || ifdrop) {
					outStr << fixed
					       << "DROPPED PACKETS - " << this->getInterfaceAlias() << ": "
					       << "libdpdk or interface dropped some packets!"
					       << " rx:" << (ps.ps_recv - this->last_ps.ps_recv);
					if(pcapdrop) {
						outStr << " pcapdrop:" << (ps.ps_drop - this->last_ps.ps_drop) << " " 
						       << setprecision(1) << ((double)(ps.ps_drop - this->last_ps.ps_drop) / (ps.ps_recv - this->last_ps.ps_recv) * 100) << "%";
					}
					if(ifdrop) {
						outStr << " ifdrop:" << (ps.ps_ifdrop - this->last_ps.ps_ifdrop) << " " 
						       << setprecision(1) << ((double)(ps.ps_ifdrop - this->last_ps.ps_ifdrop) / (ps.ps_recv - this->last_ps.ps_recv) * 100) << "%";
					}
					outStr << endl;
				}
			}
			this->last_ps = ps;
			outStr << dpdk_stats_str_rslt << endl;
		}
	}
	return(outStr.str());
}

string PcapQueue_readFromInterface_base::pcapDropCountStat_interface() {
	ostringstream outStr;
	if(this->pcapHandle || this->dpdkHandle) {
		outStr << this->getInterfaceAlias() << " : " << "pdropsCount [" << this->countPacketDrop << "]";
		pcap_stat ps;
		int pcapstatres = 1;
		if(this->pcapHandle) {
			pcapstatres = pcap_stats(this->pcapHandle, &ps);
		} else if(this->dpdkHandle) {
			pcapstatres = pcap_dpdk_stats(this->dpdkHandle, &ps);
		}
		if(pcapstatres == 0) {
			outStr << " pcapdrop [" << ps.ps_drop << "]"
			       << " ifdrop [" << ps.ps_ifdrop << "]";
		}
	}
	return(outStr.str());
}

ulong PcapQueue_readFromInterface_base::getCountPacketDrop() {
	return(this->countPacketDrop);
}

string PcapQueue_readFromInterface_base::getStatPacketDrop() {
	if(this->countPacketDrop) {
		ostringstream outStr;
		outStr << "I-" << this->getInterfaceAlias() << ":" << this->countPacketDrop;
		return(outStr.str());
	}
	return("");
}

void PcapQueue_readFromInterface_base::initStat_interface() {
	if(this->pcapHandle) {
		pcap_stat ps;
		int pcapstatres = pcap_stats(this->pcapHandle, &ps);
		if(pcapstatres == 0) {
			this->last_ps = ps;
		}
		this->countPacketDrop = 0;
	}
}

string PcapQueue_readFromInterface_base::getInterface() {
	return(this->interface.interface);
}

string PcapQueue_readFromInterface_base::getInterfaceAlias() {
	return(this->interface.alias.empty() ? this->interface.interface : this->interface.alias);
}

void PcapQueue_readFromInterface_base::terminatingAtEndOfReadPcap() {
	if(opt_continue_after_read || opt_nonstop_read) {
		if(!opt_suppress_cleanup_after_read) {
			unsigned sleepCounter = 0;
			while(!is_terminating()) {
				this->tryForcePush();
				if(!opt_pb_read_from_file_max_packets) {
					if(buffersControl.getPerc_pb_used() > 0.1) {
						syslog(LOG_NOTICE, "wait for processing packetbuffer (%.1lf%%)", buffersControl.getPerc_pb_used());
						sleep(1);
						continue;
					}
					if(opt_nonstop_read_quick ?
					    sleepCounter > 1 :
					    sleepCounter > 10 && sleepCounter <= 15) {
						calltable->cleanup_calls(true);
						calltable->cleanup_registers(true);
						calltable->cleanup_ss7(true);
						extern int opt_sip_register;
						if(enable_register_engine) {
							extern Registers registers;
							registers.cleanup(false);
						}
					}
					if(opt_nonstop_read_quick ?
					    sleepCounter > 2 :
					    sleepCounter > 15) {
						calltable->destroyCallsIfPcapsClosed();
						calltable->destroyRegistersIfPcapsClosed();
					}
					if(opt_nonstop_read_quick ?
					    sleepCounter > 3 :
					    sleepCounter > 20) {
						if(flushAllTars()) {
							 syslog(LOG_NOTICE, "tars flushed");
						}
					}
					if(opt_nonstop_read &&
					   sleepCounter > (opt_nonstop_read_quick ? 4 : 30)) {
						rss_purge();
						syslog(LOG_NOTICE, "purge");
						extern void reset_cleanup_variables();
						reset_cleanup_variables();
						syslog(LOG_NOTICE, "reset cleanup variables");
						break;
					}
					if(sleepCounter > 300) {
						extern int opt_sip_register;
						if(enable_register_engine) {
							extern Registers registers;
							registers.cleanup(true);
						}
					}
				}
				sleep(1);
				++sleepCounter;
			}
		} else {
			if(!opt_nonstop_read) {
				while(!is_terminating()) {
					this->tryForcePush();
					sleep(1);
				}
			}
		}
	} else {
		while(buffersControl.getPerc_pb_used() > 0.1) {
			syslog(LOG_NOTICE, "wait for processing packetbuffer (%.1lf%%)", buffersControl.getPerc_pb_used());
			sleep(1);
		}
		int sleepTimeBeforeCleanup = opt_time_to_terminate > 0 ? (opt_time_to_terminate / 2) :
					     opt_enable_ssl ? 10 :
					     sverb.chunk_buffer ? 20 : 5;
		int sleepTimeAfterCleanup = opt_time_to_terminate > 0 ? (opt_time_to_terminate / 2) :
					    4;
		while((sleepTimeBeforeCleanup + sleepTimeAfterCleanup) && !is_terminating()) {
			syslog(LOG_NOTICE, "time to terminating: %u", sleepTimeBeforeCleanup + sleepTimeAfterCleanup);
			this->tryForcePush();
			sleep(1);
			if(sleepTimeBeforeCleanup) {
				--sleepTimeBeforeCleanup;
				if(!sleepTimeBeforeCleanup) {
					if(calltable->cleanup_calls(true)) {
						syslog(LOG_NOTICE, "add time to cleanup calls");
						++sleepTimeBeforeCleanup;
					}
					calltable->cleanup_registers(true);
					calltable->cleanup_ss7(true);
					extern int opt_sip_register;
					if(enable_register_engine) {
						extern Registers registers;
						registers.cleanup(true);
					}
				}
			} else if(sleepTimeAfterCleanup) {
				--sleepTimeAfterCleanup;
			}
		}
		vm_terminate();
	}
}


PcapQueue_readFromInterfaceThread::PcapQueue_readFromInterfaceThread(sInterface interface, eTypeInterfaceThread typeThread,
								     PcapQueue_readFromInterfaceThread *readThread,
								     PcapQueue_readFromInterfaceThread *prevThread,
								     PcapQueue_readFromInterface *parent)
 : PcapQueue_readFromInterface_base(&interface) {
	this->threadHandle = 0;
	this->threadId = 0;
	this->threadInitOk = 0;
	this->threadInitFailed = false;
	if(!opt_pcap_queue_use_blocks) {
		this->qringmax = opt_pcap_queue_iface_qring_size / 100;
		this->qring = new FILE_LINE(15025) hpi_batch*[this->qringmax];
		for(unsigned int i = 0; i < this->qringmax; i++) {
			this->qring[i] = new FILE_LINE(15026) hpi_batch(100);
		}
		this->qring_blocks = NULL;
		this->qring_blocks_used = NULL;
	} else {
		this->qringmax = opt_pcap_queue_iface_qring_size;
		this->qring_blocks = new FILE_LINE(15027) pcap_block_store*[this->qringmax];
		this->qring_blocks_used = new FILE_LINE(15028) volatile int[this->qringmax];
		for(unsigned int i = 0; i < this->qringmax; i++) {
			this->qring_blocks[i] = NULL;
			this->qring_blocks_used[i] = 0;
		}
		this->qring = NULL;
	}
	this->readit = 0;
	this->writeit = 0;
	this->qring_sync = 0;
	this->readIndex = 0;
	this->readIndexPos = 0;
	this->readIndexCount = 0;
	this->writeIndex = 0;
	this->writeIndexCount = 0;
	this->detachBuffer[0] = NULL;
	this->detachBuffer[1] = NULL;
	this->activeDetachBuffer = NULL;
	this->detachBufferLength = 0;
	this->detachBufferWritePos = 0;
	this->detachBufferReadPos = 0;
	this->detachBufferActiveIndex = 0;
	this->_sync_detachBuffer[0] = 0;
	this->_sync_detachBuffer[1] = 0;
	if(!opt_pcap_queue_use_blocks &&
	   opt_pcap_queue_iface_dedup_separate_threads_extend == 2 &&
	   (typeThread == read || typeThread == detach)) {
		this->detachBufferLength = 500000;
		for(int i = 0; i < 2; i++) {
			if(typeThread == read) {
				this->detachBuffer[i] = new FILE_LINE(15029) u_char[this->detachBufferLength + sizeof(pcap_pkthdr) * 2 + get_pcap_snaplen()];
				memset((u_char*)this->detachBuffer[i], 0, this->detachBufferLength + sizeof(pcap_pkthdr) * 2 + get_pcap_snaplen());
			} else {
				this->detachBuffer[i] = readThread->detachBuffer[i];
			}
		}
	}
	this->counter = 0;
	this->counter_pop_usleep = 0;
	this->pop_usleep_sum = 0;
	this->pop_usleep_sum_last_push = 0;
	this->force_push = false;
	memset(this->threadPstatData, 0, sizeof(this->threadPstatData));
	this->threadTerminated = false;
	this->_sync_qring = 0;
	this->readThread = readThread;
	this->dpdkWorkerThread = NULL;
	this->detachThread = NULL;
	this->pcapProcessThread = NULL;
	this->defragThread = NULL;
	this->md1Thread = NULL;
	this->md2Thread = NULL;
	this->dedupThread = NULL;
	this->serviceThread = NULL;
	this->typeThread = typeThread;
	this->prevThread = prevThread;
	this->parent = parent;
	this->threadDoTerminate = false;
	this->headerPacketStackSnaplen = NULL;
	this->headerPacketStackShort = NULL;
	this->headerPacketStackShortPacketLen = 0;
	if(typeThread == read) {
		this->headerPacketStackSnaplen = new FILE_LINE(15030) cHeaderPacketStack(opt_pcap_queue_iface_qring_size, get_pcap_snaplen());
		if(opt_pcap_queue_iface_dedup_separate_threads_extend == 2) {
			this->headerPacketStackShortPacketLen = 256;
			this->headerPacketStackShort = new FILE_LINE(15031) cHeaderPacketStack(opt_pcap_queue_iface_qring_size, this->headerPacketStackShortPacketLen);
		}
	}
	/*
	this->headerPacketStack = NULL;
	if(typeThread == read) {
		this->headerPacketStack = new FILE_LINE(15032) PcapQueue_HeaderPacketStack(this->qringmax);
	}
	*/
	allocCounter[0] = allocCounter[1] = 0;
	allocStackCounter[0] = allocStackCounter[1] = 0;
	for(int i = 0; i < 3; i++) {
		sumPacketsSize[i] = 0;
	}
	prepareHeaderPacketPool = false; // experimental option
	#if SNIFFER_THREADS_EXT
	thread_data = NULL;
	#endif
	#if DEBUG_PB_BLOCKS_SEQUENCE
	pb_blocks_sequence_last = 0;
	#endif
	vm_pthread_create(("pb - read thread " + getInterfaceAlias() + " " + getTypeThreadName()).c_str(),
			  &this->threadHandle, NULL, _PcapQueue_readFromInterfaceThread_threadFunction, this, __FILE__, __LINE__);
}

PcapQueue_readFromInterfaceThread::~PcapQueue_readFromInterfaceThread() {
	if(this->dpdkWorkerThread) {
		while(this->dpdkWorkerThread->threadInitOk && !this->dpdkWorkerThread->isTerminated()) {
			USLEEP(100000);
		}
		delete this->dpdkWorkerThread;
	}
	if(this->detachThread) {
		while(this->detachThread->threadInitOk && !this->detachThread->isTerminated()) {
			USLEEP(100000);
		}
		delete this->detachThread;
	}
	if(this->pcapProcessThread) {
		while(this->pcapProcessThread->threadInitOk && !this->pcapProcessThread->isTerminated()) {
			USLEEP(100000);
		}
		delete this->pcapProcessThread;
	}
	if(this->defragThread) {
		while(this->defragThread->threadInitOk && !this->defragThread->isTerminated()) {
			USLEEP(100000);
		}
		delete this->defragThread;
	}
	if(this->md1Thread) {
		while(this->md1Thread->threadInitOk && !this->md1Thread->isTerminated()) {
			USLEEP(100000);
		}
		delete this->md1Thread;
	}
	if(this->md2Thread) {
		while(this->md2Thread->threadInitOk && !this->md2Thread->isTerminated()) {
			USLEEP(100000);
		}
		delete this->md2Thread;
	}
	if(this->dedupThread) {
		while(this->dedupThread->threadInitOk && !this->dedupThread->isTerminated()) {
			USLEEP(100000);
		}
		delete this->dedupThread;
	}
	if(this->serviceThread) {
		while(this->serviceThread->threadInitOk && !this->serviceThread->isTerminated()) {
			USLEEP(100000);
		}
		delete this->serviceThread;
	}
	if(this->qring) {
		for(unsigned int i = 0; i < this->qringmax; i++) {
			delete this->qring[i];
		}
		delete [] this->qring;
	}
	if(this->qring_blocks) {
		delete [] this->qring_blocks;
	}
	if(this->qring_blocks_used) {
		delete [] this->qring_blocks_used;
	}
	if(this->headerPacketStackSnaplen) {
		delete this->headerPacketStackSnaplen;
	}
	if(this->headerPacketStackShort) {
		delete this->headerPacketStackShort;
	}
	if(this->detachBuffer[0] && this->typeThread == read) {
		for(int i = 0; i < 2; i++) {
			delete [] this->detachBuffer[i];
		}
	}
	/*
	if(this->headerPacketStack) {
		delete this->headerPacketStack;
	}
	*/
}

inline void PcapQueue_readFromInterfaceThread::push(sHeaderPacket **header_packet) {
	#if SNIFFER_THREADS_EXT
	if(sverb.sniffer_threads_ext && thread_data) {
		thread_data->inc_packets_out(HPH(*header_packet)->caplen);
	}
	#endif
	#if TRACE_INVITE_BYE
	if(memmem(HPP(*header_packet), HPH(*header_packet)->caplen, "INVITE sip", 10)) {
		cout << "push INVITE " << typeThread << endl;
	} else if(memmem(HPP(*header_packet), HPH(*header_packet)->caplen, "BYE sip", 7)) {
		cout << "push BYE " << typeThread << endl;
	} else if(memmem(HPP(*header_packet), HPH(*header_packet)->caplen, "REGISTER sip", 12)) {
		cout << "push REGISTER " << typeThread << endl;
	}
	#endif
	#if TRACE_MASTER_SECRET
	if(memmem(HPP(*header_packet), HPH(*header_packet)->caplen, "mastersecret", 12)) {
		cout << "push MASTERSECRET " << typeThread << endl;
	}
	#endif
	#if TRACE_CALL
	if(sverb.trace_call) {
		trace_call(HPP(*header_packet), HPH(*header_packet)->caplen, pcapLinklayerHeaderType,
			   (*header_packet)->detect_headers ? (*header_packet)->header_ip_offset : 0, getTimeUS(HPH(*header_packet)->ts),
			   NULL, 0,
			   __FILE__, __LINE__, __FUNCTION__, ("push - thread " + intToString(typeThread)).c_str());
	}
	#endif
	unsigned int _writeIndex;
	if(writeIndex) {
		_writeIndex = writeIndex - 1;
	} else {
		_writeIndex = writeit % qringmax;
		unsigned int usleepCounter = 0;
		while(qring[_writeIndex]->used) {
			if(is_terminating()) {
				return;
			}
			USLEEP_C(100, usleepCounter++);
		}
		writeIndex = _writeIndex + 1;
		writeIndexCount = 0;
	}
	hpi *item = &qring[_writeIndex]->hpis[writeIndexCount];
	item->header_packet = *header_packet;
	*header_packet = NULL;
	++writeIndexCount;
	if(writeIndexCount == qring[_writeIndex]->max_count ||
	   (writeIndexCount && force_push)) {
		force_push = false;
		#if RQUEUE_SAFE
		__SYNC_SET_TO(qring[_writeIndex]->count, writeIndexCount);
		__SYNC_SET(qring[_writeIndex]->used);
		writeIndex = 0;
		__SYNC_INCR(writeit, qringmax);
		#else
		qring[_writeIndex]->count = writeIndexCount;
		qring[_writeIndex]->used = 1;
		writeIndex = 0;
		if((writeit + 1) == qringmax) {
			writeit = 0;
		} else {
			writeit++;
		}
		#endif
	}
	/****
	uint32_t writeIndex = this->writeit[index] % this->qringmax;
	//__SYNC_LOCK(this->_sync_qring);
	while(this->qring[index][writeIndex].used > 0) {
		//__SYNC_UNLOCK(this->_sync_qring);
		USLEEP(100);
		//__SYNC_LOCK(this->_sync_qring);
	}
	if(this->qring[index][writeIndex].used < 0) {
		delete this->qring[index][writeIndex].header;
		delete [] this->qring[index][writeIndex].packet;
	}
	this->qring[index][writeIndex].header = header;
	this->qring[index][writeIndex].packet = packet;
	this->qring[index][writeIndex].ok_for_header_packet_stack = ok_for_header_packet_stack;
	this->qring[index][writeIndex].offset = offset;
	if(md5) {
		memcpy(this->qring[index][writeIndex].md5, md5, MD5_DIGEST_LENGTH);
	} else {
		this->qring[index][writeIndex].md5[0] = 0;
	}
	this->qring[index][writeIndex].counter = counter;
	this->qring[index][writeIndex].used = 1;
	if((this->writeit[index] + 1) == this->qringmax) {
		this->writeit[index] = 0;
	} else {
		this->writeit[index]++;
	}
	//__SYNC_UNLOCK(this->_sync_qring);
	****/
}

inline void PcapQueue_readFromInterfaceThread::push_block(pcap_block_store *block) {
	__SYNC_LOCK_ARM_ONLY(qring_sync);
	bool useDiskBuffer = opt_pcap_queue_store_queue_max_disk_size && !opt_pcap_queue_disk_folder.empty();
	if(!useDiskBuffer ?
	    pcapQueueQ->checkIfMemoryBufferIsFull(block->getUseAllSize(), true) :
	    pcapQueueQ->checkIfDiskBufferIsFull(true)) {
		unsigned int usleepCounter = 0;
		do {
			if(is_terminating()) {
				__SYNC_UNLOCK_ARM_ONLY(qring_sync);
				return;
			}
			__SYNC_UNLOCK_ARM_ONLY(qring_sync);
			USLEEP_C(100, usleepCounter++);
			__SYNC_LOCK_ARM_ONLY(qring_sync);
		} while(!useDiskBuffer ?
			 pcapQueueQ->checkIfMemoryBufferIsFull(block->getUseAllSize(), true) :
			 pcapQueueQ->checkIfDiskBufferIsFull(true));
	}
	unsigned int _writeIndex = writeit % qringmax;
	unsigned int usleepCounter = 0;
	while(qring_blocks_used[_writeIndex]) {
		if(is_terminating()) {
			__SYNC_UNLOCK_ARM_ONLY(qring_sync);
			return;
		}
		__SYNC_UNLOCK_ARM_ONLY(qring_sync);
		USLEEP_C(100, usleepCounter++);
		__SYNC_LOCK_ARM_ONLY(qring_sync);
	}
	qring_blocks[_writeIndex] = block;
	#if RQUEUE_SAFE
	__SYNC_SET(qring_blocks_used[_writeIndex]);
	writeIndex = 0;
	__SYNC_INCR(writeit, qringmax);
	#else
	qring_blocks_used[_writeIndex] = 1;
	writeIndex = 0;
	if((writeit + 1) == qringmax) {
		writeit = 0;
	} else {
		writeit++;
	}
	#endif
	__SYNC_UNLOCK_ARM_ONLY(qring_sync);
}

inline void PcapQueue_readFromInterfaceThread::tryForcePush() {
	if(writeIndexCount && force_push && writeIndex) {
		/*
		cout << "force push " << typeThread << endl;
		*/
		unsigned int _writeIndex = writeIndex - 1;
		force_push = false;
		#if RQUEUE_SAFE
		__SYNC_SET_TO(qring[_writeIndex]->count, writeIndexCount);
		__SYNC_SET(qring[_writeIndex]->used);
		writeIndex = 0;
		__SYNC_INCR(writeit, qringmax);
		#else
		qring[_writeIndex]->count = writeIndexCount;
		qring[_writeIndex]->used = 1;
		writeIndex = 0;
		if((writeit + 1) == qringmax) {
			writeit = 0;
		} else {
			writeit++;
		}
		#endif
	}
}

inline PcapQueue_readFromInterfaceThread::hpi PcapQueue_readFromInterfaceThread::pop() {
	unsigned int _readIndex;
	hpi rslt_hpi;
	if(readIndex) {
		_readIndex = readIndex - 1;
	} else {
		_readIndex = readit % qringmax;
		if(qring[_readIndex]->used) {
			readIndex = _readIndex + 1;
			readIndexPos = 0;
			readIndexCount = qring[_readIndex]->count;
		} else {
			rslt_hpi.header_packet = NULL;
			return(rslt_hpi);
		}
	}
	hpi *item = &qring[_readIndex]->hpis[readIndexPos];
	rslt_hpi.header_packet = item->header_packet;
	item->header_packet = NULL;
	#if TRACE_INVITE_BYE
	if(memmem(HPP(rslt_hpi.header_packet), HPH(rslt_hpi.header_packet)->caplen, "INVITE sip", 10)) {
		cout << "pop INVITE " << typeThread << endl;
	} else if(memmem(HPP(rslt_hpi.header_packet), HPH(rslt_hpi.header_packet)->caplen, "BYE sip", 7)) {
		cout << "pop BYE " << typeThread << endl;
	} else if(memmem(HPP(rslt_hpi.header_packet), HPH(rslt_hpi.header_packet)->caplen, "REGISTER sip", 12)) {
		cout << "pop REGISTER " << typeThread << endl;
	}
	#endif
	#if TRACE_MASTER_SECRET
	if(memmem(HPP(rslt_hpi.header_packet), HPH(rslt_hpi.header_packet)->caplen, "mastersecret", 12)) {
		cout << "pop MASTERSECRET " << typeThread << endl;
	}
	#endif
	#if TRACE_CALL
	if(sverb.trace_call) {
		trace_call(HPP(rslt_hpi.header_packet), HPH(rslt_hpi.header_packet)->caplen, pcapLinklayerHeaderType,
			   rslt_hpi.header_packet->detect_headers ? rslt_hpi.header_packet->header_ip_offset : 0, getTimeUS(HPH(rslt_hpi.header_packet)->ts),
			   NULL, 0,
			   __FILE__, __LINE__, __FUNCTION__, ("pop - thread " + intToString(typeThread)).c_str());
	}
	#endif
	++readIndexPos;
	if(readIndexPos == readIndexCount) {
		#if RQUEUE_SAFE
		__SYNC_NULL(qring[_readIndex]->used);
		readIndex = 0;
		__SYNC_INCR(readit, qringmax);
		#else
		qring[_readIndex]->used = 0;
		readIndex = 0;
		if((readit + 1) == qringmax) {
			readit = 0;
		} else {
			readit++;
		}
		#endif
	}
	return(rslt_hpi);
	/****
	uint32_t readIndex = this->readit[index] % this->qringmax;
	//__SYNC_LOCK(this->_sync_qring);
	hpi rslt_hpi;
	if(this->qring[index][readIndex].used <= 0) {
		rslt_hpi.header = NULL;
		rslt_hpi.packet = NULL;
		rslt_hpi.ok_for_header_packet_stack = false;
		rslt_hpi.offset = 0;
		rslt_hpi.md5[0] = 0;
		rslt_hpi.counter = 0;
		rslt_hpi.used = 0;
	} else {
		rslt_hpi.header = this->qring[index][readIndex].header;
		rslt_hpi.packet = this->qring[index][readIndex].packet;
		rslt_hpi.ok_for_header_packet_stack = this->qring[index][readIndex].ok_for_header_packet_stack;
		rslt_hpi.offset = this->qring[index][readIndex].offset;
		memcpy(rslt_hpi.md5, this->qring[index][readIndex].md5, MD5_DIGEST_LENGTH);
		rslt_hpi.counter = this->qring[index][readIndex].counter;
		rslt_hpi.used = 0;
		this->qring[index][readIndex].used = 0;
		if((this->readit[index] + 1) == this->qringmax) {
			this->readit[index] = 0;
		} else {
			this->readit[index]++;
		}
	}
	//__SYNC_UNLOCK(this->_sync_qring);
	return(rslt_hpi);
	****/
}

inline PcapQueue_readFromInterfaceThread::hpi PcapQueue_readFromInterfaceThread::POP() {
	return(this->dedupThread ? this->dedupThread->pop() : this->pop());
}

inline pcap_block_store *PcapQueue_readFromInterfaceThread::pop_block() {
	__SYNC_LOCK_ARM_ONLY(qring_sync);
	unsigned int _readIndex = readit % qringmax;
	if(!qring_blocks_used[_readIndex]) {
		__SYNC_UNLOCK_ARM_ONLY(qring_sync);
		return(NULL);
	}
	pcap_block_store *block = qring_blocks[_readIndex];
	#if RQUEUE_SAFE
	__SYNC_NULL(qring_blocks_used[_readIndex]);
	__SYNC_INCR(readit, qringmax);
	#else
	qring_blocks_used[_readIndex] = 0;
	if((readit + 1) == qringmax) {
		readit = 0;
	} else {
		readit++;
	}
	#endif
	#if DEBUG_PB_BLOCKS_SEQUENCE
	if(block) {
		if(block->pb_blocks_sequence != pb_blocks_sequence_last + 1) {
			syslog(LOG_NOTICE, "bad pb_blocks_sequence: %lu / %lu (%i,%i) %s:%i", 
			       block->pb_blocks_sequence, pb_blocks_sequence_last + 1, 
			       typeThread, threadId,
			       __FILE__, __LINE__);
		}
		pb_blocks_sequence_last = block->pb_blocks_sequence;
	}
	#endif
	__SYNC_UNLOCK_ARM_ONLY(qring_sync);
	return(block);
}

inline pcap_block_store *PcapQueue_readFromInterfaceThread::POP_BLOCK() {
	return(this->dedupThread ? this->dedupThread->pop_block() : 
	       this->pcapProcessThread ? this->pcapProcessThread->pop_block() :
	       this->pop_block());
}

void PcapQueue_readFromInterfaceThread::cancelThread() {
	syslog(LOG_NOTICE, "cancel read thread (%s)", getInterfaceAlias().c_str());
	pthread_cancel(this->threadHandle);
}


#define POP_FROM_PREV_THREAD \
	hpii = this->prevThread->pop(); \
	if(!hpii.header_packet) { \
		this->pop_usleep_sum += USLEEP_C(100, this->counter_pop_usleep++); \
		if(this->pop_usleep_sum > this->pop_usleep_sum_last_push + 100000) { \
			this->prevThread->setForcePush(); \
			this->pop_usleep_sum_last_push = this->pop_usleep_sum; \
		} \
		if(this->force_push) { \
			this->tryForcePush(); \
		} \
		continue; \
	} \
	this->counter_pop_usleep = 0; \
	this->pop_usleep_sum = 0; \
	this->pop_usleep_sum_last_push = 0;

void *PcapQueue_readFromInterfaceThread::threadFunction(void */*arg*/, unsigned int /*arg2*/) {
	if(this->typeThread == read) {
		extern string opt_sched_pol_interface;
		pthread_set_priority(opt_sched_pol_interface);
	}
	this->threadId = get_unix_tid();
	#if SNIFFER_THREADS_EXT
	this->thread_data = cThreadMonitor::getSelfThreadData();
	#endif
	if(VERBOSE) {
		ostringstream outStr;
		outStr << "start thread t0i_" 
		       << getTypeThreadName()
		       << " (" << this->getInterfaceAlias() << ") /" << this->threadId << endl;
		syslog(LOG_NOTICE, "%s", outStr.str().c_str());
	}
	if(this->typeThread == read) {
		sDpdkConfig dpdkConfig;
		if(!opt_pcap_queue_use_blocks) {
			if(opt_pcap_queue_iface_dedup_separate_threads) {
				if(opt_pcap_queue_iface_dedup_separate_threads_extend) {
					if(opt_pcap_queue_iface_dedup_separate_threads_extend == 2) {
						this->detachThread = new FILE_LINE(15033) PcapQueue_readFromInterfaceThread(this->interface, detach, this, this, this->parent);
						this->defragThread = new FILE_LINE(15034) PcapQueue_readFromInterfaceThread(this->interface, defrag, this, this->detachThread, this->parent);
					} else {
						this->defragThread = new FILE_LINE(15035) PcapQueue_readFromInterfaceThread(this->interface, defrag, this, this, this->parent);
					}
					this->md1Thread = new FILE_LINE(15036) PcapQueue_readFromInterfaceThread(this->interface, md1, this, this->defragThread, this->parent);
					this->md2Thread = new FILE_LINE(15037) PcapQueue_readFromInterfaceThread(this->interface, md2, this, this->md1Thread, this->parent);
					this->dedupThread = new FILE_LINE(15038) PcapQueue_readFromInterfaceThread(this->interface, dedup, this, this->md2Thread, this->parent);
					if(this->prepareHeaderPacketPool) {
						this->serviceThread = new FILE_LINE(15039) PcapQueue_readFromInterfaceThread(this->interface, service, this, this, this->parent);
					}
				} else {
					this->dedupThread = new FILE_LINE(15040) PcapQueue_readFromInterfaceThread(this->interface, dedup, this, this, this->parent);
				}
			}
		} else {
			strcpy_null_term(dpdkConfig.device, this->getInterface().c_str());
			dpdkConfig.snapshot = this->pcap_snaplen;
			dpdkConfig.promisc = this->pcap_promisc;
			dpdkConfig.type_read_thread = opt_dpdk_read_thread == 1 ? _dpdk_trt_std :
						      opt_dpdk_read_thread == 2 ? _dpdk_trt_rte :
						      _dpdk_trt_std;
			dpdkConfig.type_worker_thread = opt_dpdk_worker_thread == 1 ? _dpdk_twt_std :
							opt_dpdk_worker_thread == 2 ? _dpdk_twt_rte :
							_dpdk_twt_na;
			dpdkConfig.type_worker2_thread = opt_dpdk_worker2_thread == 1 ? _dpdk_tw2t_rte :
							 _dpdk_tw2t_na;
			dpdkConfig.iterations_per_call = opt_dpdk_iterations_per_call;
			dpdkConfig.read_usleep_if_no_packet = opt_dpdk_read_usleep_if_no_packet;
			dpdkConfig.read_usleep_type = opt_dpdk_read_usleep_type == 1 ? _dpdk_usleep_type_rte : 
						      opt_dpdk_read_usleep_type == 2 ? _dpdk_usleep_type_rte_pause : 
						      _dpdk_usleep_type_std;
			dpdkConfig.worker_usleep_if_no_packet = opt_dpdk_worker_usleep_if_no_packet;
			dpdkConfig.worker_usleep_type = opt_dpdk_worker_usleep_type == 1 ? _dpdk_usleep_type_rte : 
							opt_dpdk_worker_usleep_type == 2 ? _dpdk_usleep_type_rte_pause : 
							_dpdk_usleep_type_std;
			dispatch_data.me = this;
			dpdkConfig.callback.packet_user = &dispatch_data;
			dpdkConfig.callback.header_packet = &dispatch_data.headerPacket;
			dpdkConfig.callback.packet_allocation = _dpdk_packet_allocation;
			dpdkConfig.callback.packet_completion = _dpdk_packet_completion;
			dpdkConfig.callback.packet_completion_plus = _dpdk_packet_completion_plus;
			dpdkConfig.callback.packet_process = _dpdk_packet_process;
			dpdkConfig.callback.packets_get_pointers = _dpdk_packets_get_pointers;
			dpdkConfig.callback.packets_push = _dpdk_packets_push;
			dpdkConfig.callback.packet_process__mbufs_in_packetbuffer = _dpdk_packet_process__mbufs_in_packetbuffer;
			dpdkConfig.callback.check_block = _dpdk_check_block;
			if(opt_dup_check_type != _dedup_na) {
				this->md1Thread = new FILE_LINE(15041) PcapQueue_readFromInterfaceThread(this->interface, md1, this, this, this->parent);
				this->md2Thread = new FILE_LINE(15042) PcapQueue_readFromInterfaceThread(this->interface, md2, this, this->md1Thread, this->parent);
				this->dedupThread = new FILE_LINE(15043) PcapQueue_readFromInterfaceThread(this->interface, dedup, this, this->md2Thread, this->parent);
			} else {
				this->pcapProcessThread = new FILE_LINE(15044) PcapQueue_readFromInterfaceThread(this->interface, pcap_process, this, this, this->parent);
			}
		}
		string error;
		if(this->startCapture(&error, &dpdkConfig)) {
			if(this->dpdkHandle && dpdk_config(this->dpdkHandle)->type_worker_thread == _dpdk_twt_std) {
				this->dpdkWorkerThread = new FILE_LINE(0) PcapQueue_readFromInterfaceThread(this->interface, dpdk_worker, this, this, this->parent);
			}
		} else {
			this->threadTerminated = true;
			this->threadInitFailed = true;
			this->threadDoTerminate = true;
			if(this->dpdkWorkerThread) {
				this->dpdkWorkerThread->threadInitFailed = true;
				this->dpdkWorkerThread->threadDoTerminate = true;
			}
			if(this->detachThread) {
				this->detachThread->threadInitFailed = true;
				this->detachThread->threadDoTerminate = true;
			}
			if(this->pcapProcessThread) {
				this->pcapProcessThread->threadInitFailed = true;
				this->pcapProcessThread->threadDoTerminate = true;
			}
			if(this->defragThread) {
				this->defragThread->threadInitFailed = true;
				this->defragThread->threadDoTerminate = true;
			}
			if(this->md1Thread) {
				this->md1Thread->threadInitFailed = true;
				this->md1Thread->threadDoTerminate = true;
			}
			if(this->md2Thread) {
				this->md2Thread->threadInitFailed = true;
				this->md2Thread->threadDoTerminate = true;
			}
			if(this->dedupThread) {
				this->dedupThread->threadInitFailed = true;
				this->dedupThread->threadDoTerminate = true;
			}
			if(this->serviceThread) {
				this->serviceThread->threadInitFailed = true;
				this->serviceThread->threadDoTerminate = true;
			}
			if(!is_receiver()) {
				vm_terminate_error(error.c_str());
			}
			return(NULL);
		}
		this->threadInitOk = 1;
		while(this->threadInitOk != 2) {
			if(is_terminating()) {
				return(NULL);
			}
			USLEEP(1000);
		}
		this->initStat_interface();
		if(this->dpdkWorkerThread) {
			this->dpdkWorkerThread->pcapLinklayerHeaderType = this->pcapLinklayerHeaderType;
		}
		if(this->detachThread) {
			this->detachThread->pcapLinklayerHeaderType = this->pcapLinklayerHeaderType;
		}
		if(this->pcapProcessThread) {
			this->pcapProcessThread->pcapLinklayerHeaderType = this->pcapLinklayerHeaderType;
		}
		if(this->defragThread) {
			this->defragThread->pcapLinklayerHeaderType = this->pcapLinklayerHeaderType;
		}
		if(this->md1Thread) {
			this->md1Thread->pcapLinklayerHeaderType = this->pcapLinklayerHeaderType;
		}
		if(this->md2Thread) {
			this->md2Thread->pcapLinklayerHeaderType = this->pcapLinklayerHeaderType;
		}
		if(this->dedupThread) {
			this->dedupThread->pcapLinklayerHeaderType = this->pcapLinklayerHeaderType;
		}
		if(this->serviceThread) {
			this->serviceThread->pcapLinklayerHeaderType = this->pcapLinklayerHeaderType;
		}
	} else {
		while(!is_terminating() && this->readThread->threadInitOk != 2) {
			USLEEP(1000);
		}
		if(is_terminating()) {
			return(NULL);
		}
		this->threadInitOk = 1;
	}
	
	if(opt_pcap_queue_use_blocks) {
		threadFunction_blocks();
		this->threadTerminated = true;
		if(VERBOSE) {
			ostringstream outStr;
			outStr << "stop thread t0i_" 
			       << getTypeThreadName()
			       << " (" << this->getInterfaceAlias() << ") /" << this->threadId << endl;
			syslog(LOG_NOTICE, "%s", outStr.str().c_str());
		}
		return(NULL);
	}
	
	sHeaderPacket *header_packet_read = NULL;
	int res;
	pcap_pkthdr *pcap_next_ex_header, *detach_buffer_header;
	u_char *pcap_next_ex_packet, *detach_buffer_packet;
	bool _useOneshotBuffer = false;
	u_int64_t startDetachBufferWrite_ms = 0;
	bool forcePushDetachBufferWrite = false;
	unsigned int read_counter = 0;
	
	hpi hpii;
	pcap_dumper_t *_pcapDumpHandle = NULL;
	if(opt_pcapdump) {
		if(this->typeThread == dedup && this->readThread) {
			_pcapDumpHandle = this->readThread->pcapDumpHandle;
		}
	}
	while(!(is_terminating() || this->threadDoTerminate)) {
		switch(this->typeThread) {
		case read: {
			if(this->detachBuffer[0]) {
				if(!this->detachBufferWritePos) {
					unsigned int usleepCounter = 0;
					while(this->detachBuffer[this->detachBufferActiveIndex][0] && !is_terminating()) {
						USLEEP_C(10, usleepCounter++);
					}
					if(is_terminating()) {
						break;
					}
					lock_detach_buffer(this->detachBufferActiveIndex);
					this->activeDetachBuffer = this->detachBuffer[this->detachBufferActiveIndex];
					this->detachBufferWritePos = 1;
					startDetachBufferWrite_ms = getTimeMS_rdtsc();
					forcePushDetachBufferWrite = false;
				}
				if(_useOneshotBuffer) {
					setOneshotBuffer((u_char*)this->activeDetachBuffer + this->detachBufferWritePos + sizeof(pcap_pkthdr));
				} else {
					_useOneshotBuffer = useOneshotBuffer();
					if(_useOneshotBuffer) {
						setOneshotBuffer((u_char*)this->activeDetachBuffer + this->detachBufferWritePos + sizeof(pcap_pkthdr));
					}
				}
				res = this->pcap_next_ex_iface(this->pcapHandle, &pcap_next_ex_header, &pcap_next_ex_packet);
				if(res == -1) {
					forcePushDetachBufferWrite = true;
				} else if(res <= 0) {
					if(res == 0) {
						USLEEP(100);
					}
					if(getTimeMS_rdtsc() > startDetachBufferWrite_ms + 500 &&
					   this->detachBufferWritePos > 1) {
						//cout << "FORCE DETACH 1 " << this->interfaceName << endl;
						forcePushDetachBufferWrite = true;
					} else {
						continue;
					}
				} else {
					#if SNIFFER_THREADS_EXT
					if(sverb.sniffer_threads_ext && thread_data) {
						thread_data->inc_packets_in(pcap_next_ex_header->caplen);
					}
					#endif
					sumPacketsSize[0] += pcap_next_ex_header->caplen;
					#if TRACE_INVITE_BYE
					if(memmem(pcap_next_ex_packet, pcap_next_ex_header->caplen, "INVITE sip", 10)) {
						cout << "get INVITE (1) " << typeThread << endl;
					} else if(memmem(pcap_next_ex_packet, pcap_next_ex_header->caplen, "BYE sip", 7)) {
						cout << "get BYE (1) " << typeThread << endl;
					} else if(memmem(pcap_next_ex_packet, pcap_next_ex_header->caplen, "REGISTER sip", 12)) {
						cout << "get REGISTER (1) " << typeThread << endl;
					}
					#endif
					#if TRACE_MASTER_SECRET
					if(memmem(pcap_next_ex_packet, pcap_next_ex_header->caplen, "mastersecret", 12)) {
						cout << "get MASTERSECRET (1) " << typeThread << endl;
					}
					#endif
					#if TRACE_CALL
					if(sverb.trace_call) {
						trace_call(pcap_next_ex_packet, pcap_next_ex_header->caplen, pcapLinklayerHeaderType,
							   0, getTimeUS(pcap_next_ex_header->ts),
							   NULL, 0,
							   __FILE__, __LINE__, __FUNCTION__, ("get from pcap - thread " + intToString(typeThread)).c_str());
					}
					#endif
					memcpy((u_char*)this->activeDetachBuffer + this->detachBufferWritePos,
					       pcap_next_ex_header,
					       sizeof(pcap_pkthdr));
					if(!_useOneshotBuffer) {
						memcpy((u_char*)this->activeDetachBuffer + this->detachBufferWritePos + sizeof(pcap_pkthdr),
						       pcap_next_ex_packet,
						       pcap_next_ex_header->caplen);
					}
					//cout << "W" << this->detachBufferActiveIndex << "/" << this->detachBufferWritePos << endl;
					this->detachBufferWritePos += sizeof(pcap_pkthdr) + pcap_next_ex_header->caplen;
					++read_counter;
					if((read_counter & 0x3F) == 0 &&
					   getTimeMS_rdtsc() > startDetachBufferWrite_ms + 500) {
						//cout << "FORCE DETACH 2 " << this->interfaceName << endl;
						forcePushDetachBufferWrite = true;
					}
				}
				if(this->detachBufferWritePos >= this->detachBufferLength ||
				   (this->detachBufferWritePos > 1 && forcePushDetachBufferWrite)) {
					if(forcePushDetachBufferWrite) {
						pcap_pkthdr term_header;
						term_header.caplen = 0xFFFFFFFF;
						term_header.len = 0xFFFFFFFF;
						term_header.ts.tv_sec = 0;
						term_header.ts.tv_usec = 0;
						memcpy((u_char*)this->activeDetachBuffer + this->detachBufferWritePos,
						       &term_header,
						       sizeof(pcap_pkthdr));
					}
					this->activeDetachBuffer[0] = 0xFF;
					unlock_detach_buffer(this->detachBufferActiveIndex);
					this->detachBufferActiveIndex = this->detachBufferActiveIndex ? 0 : 1;
					this->detachBufferWritePos = 0;
				}
				if(res == -1) {
					if(opt_pb_read_from_file[0]) {
						terminatingAtEndOfReadPcap();
					}
					break;
				}
			} else {
				if(!header_packet_read) {
					if(sverb.alloc_stat) {
						if((this->prepareHeaderPacketPool ?
						     this->headerPacketStackSnaplen->pop_prepared(&header_packet_read) : 
						     this->headerPacketStackSnaplen->pop(&header_packet_read)) == 2) {
							++allocCounter[0];
						} else {
							++allocStackCounter[0];
						}
					} else {
						if(this->prepareHeaderPacketPool) {
							this->headerPacketStackSnaplen->pop_prepared(&header_packet_read);
						} else {
							this->headerPacketStackSnaplen->pop(&header_packet_read);
						}
					}
				} else {
					header_packet_read->clearPcapProcessData();
				}
				if(_useOneshotBuffer) {
					setOneshotBuffer(HPP(header_packet_read));
				} else {
					_useOneshotBuffer = useOneshotBuffer();
					if(_useOneshotBuffer) {
						setOneshotBuffer(HPP(header_packet_read));
					}
				}
				res = this->pcap_next_ex_iface(this->pcapHandle, &pcap_next_ex_header, &pcap_next_ex_packet);
				#if TRACE_INVITE_BYE
				if(memmem(pcap_next_ex_packet, pcap_next_ex_header->caplen, "INVITE sip", 10)) {
					cout << "get INVITE (2) " << typeThread << endl;
				} else if(memmem(pcap_next_ex_packet, pcap_next_ex_header->caplen, "BYE sip", 7)) {
					cout << "get BYE (2) " << typeThread << endl;
				} else if(memmem(pcap_next_ex_packet, pcap_next_ex_header->caplen, "REGISTER sip", 12)) {
					cout << "get REGISTER (2) " << typeThread << endl;
				}
				#endif
				#if TRACE_MASTER_SECRET
				if(memmem(pcap_next_ex_packet, pcap_next_ex_header->caplen, "mastersecret", 12)) {
					cout << "get MASTERSECRET (2) " << typeThread << endl;
				}
				#endif
				#if TRACE_CALL
				if(sverb.trace_call) {
					trace_call(pcap_next_ex_packet, pcap_next_ex_header->caplen, pcapLinklayerHeaderType,
						   0, getTimeUS(pcap_next_ex_header->ts),
						   NULL, 0,
						   __FILE__, __LINE__, __FUNCTION__, ("get from pcap - thread " + intToString(typeThread)).c_str());
				}
				#endif
				if(res == -1) {
					if(opt_pb_read_from_file[0]) {
						terminatingAtEndOfReadPcap();
					}
					break;
				} else if(res <= 0) {
					if(this->force_push) {
						this->tryForcePush();
					}
					if(res == 0) {
						USLEEP(100);
					}
					continue;
				}
				#if SNIFFER_THREADS_EXT
				if(sverb.sniffer_threads_ext && thread_data) {
					thread_data->inc_packets_in(pcap_next_ex_header->caplen);
				}
				#endif
				sumPacketsSize[0] += pcap_next_ex_header->caplen;
				memcpy(HPH(header_packet_read),
				       pcap_next_ex_header,
				       sizeof(pcap_pkthdr));
				if(!_useOneshotBuffer) {
					memcpy(HPP(header_packet_read),
					       pcap_next_ex_packet,
					       pcap_next_ex_header->caplen);
				}
				if(opt_pcap_queue_iface_dedup_separate_threads_extend) {
					this->push(&header_packet_read);
				} else {
					res = opt_pcap_queue_iface_dedup_separate_threads ?
					       this->pcapProcess(&header_packet_read, this->typeThread,
								 NULL, 0,
								 ppf_defrag | ppf_returnZeroInCheckData) :
					       this->pcapProcess(&header_packet_read, this->typeThread,
								 NULL, 0,
								 ppf_all, this->pcapDumpHandle);
					if(res == -1) {
						break;
					} else if(res > 0) {
						this->push(&header_packet_read);
					} else {
						if(header_packet_read) {
							PUSH_HP(&header_packet_read, this->typeThread);
						}
					}
				}
			}
			}
			break;
		case dpdk_worker:
			break;
		case detach:
			if(this->detachBuffer[0]) {
				if(!this->detachBufferReadPos) {
					unsigned int usleepCounter = 0;
					unsigned long usleepSumTime = 0;
					unsigned long usleepSumTime_lastPush = 0;
					while(!this->detachBuffer[this->detachBufferActiveIndex][0] && !is_terminating()) {
						if(usleepSumTime > usleepSumTime_lastPush + 10000) {
							if(this->force_push) {
								this->tryForcePush();
							}
							usleepSumTime_lastPush = usleepSumTime;
						}
						usleepSumTime += USLEEP_C(10, usleepCounter++);
					}
					if(is_terminating()) {
						break;
					}
					this->readThread->lock_detach_buffer(this->detachBufferActiveIndex);
					this->activeDetachBuffer = this->detachBuffer[this->detachBufferActiveIndex];
					this->detachBufferReadPos = 1;
				}
				//cout << "R" << this->detachBufferActiveIndex << "/" << this->detachBufferReadPos << endl;
				detach_buffer_header = (pcap_pkthdr*)(this->activeDetachBuffer + this->detachBufferReadPos);
				if(detach_buffer_header->caplen != 0xFFFFFFFF) {
					if(header_packet_read && 
					   header_packet_read->packet_alloc_size < detach_buffer_header->caplen) {
						DESTROY_HP(&header_packet_read);
					}
					if(!header_packet_read) {
						if(opt_pcap_queue_iface_extend2_use_alloc_stack) {
							if(sverb.alloc_stat) {
								if((detach_buffer_header->caplen > this->readThread->headerPacketStackShortPacketLen ? 
								     this->readThread->headerPacketStackSnaplen->pop(&header_packet_read) : 
								     this->readThread->headerPacketStackShort->pop(&header_packet_read)) == 2) {
									++allocCounter[0];
								} else {
									++allocStackCounter[0];
								}
							} else {
								if(detach_buffer_header->caplen > this->readThread->headerPacketStackShortPacketLen) {
									this->readThread->headerPacketStackSnaplen->pop(&header_packet_read);
								} else {
									this->readThread->headerPacketStackShort->pop(&header_packet_read);
								}
							}
						} else {
							header_packet_read = CREATE_HP(detach_buffer_header->caplen);
						}
					} else {
						header_packet_read->clearPcapProcessData();
					}
					detach_buffer_packet = (u_char*)this->activeDetachBuffer + this->detachBufferReadPos + sizeof(pcap_pkthdr);
					memcpy(HPH(header_packet_read),
					       detach_buffer_header,
					       sizeof(pcap_pkthdr));
					memcpy(HPP(header_packet_read),
					       detach_buffer_packet,
					       detach_buffer_header->caplen);
					#if TRACE_INVITE_BYE
					if(memmem(HPP(header_packet_read), detach_buffer_header->caplen, "INVITE sip", 10)) {
						cout << "detach INVITE " << typeThread << endl;
					} else if(memmem(HPP(header_packet_read), detach_buffer_header->caplen, "BYE sip", 7)) {
						cout << "detach BYE " << typeThread << endl;
					} else if(memmem(HPP(header_packet_read), detach_buffer_header->caplen, "REGISTER sip", 12)) {
						cout << "detach REGISTER " << typeThread << endl;
					}
					#endif
					#if TRACE_MASTER_SECRET
					if(memmem(HPP(header_packet_read), detach_buffer_header->caplen, "mastersecret", 12)) {
						cout << "detach MASTERSECRET " << typeThread << endl;
					}
					#endif
					#if TRACE_CALL
					if(sverb.trace_call) {
						trace_call(HPP(header_packet_read), detach_buffer_header->caplen, pcapLinklayerHeaderType,
							   0, getTimeUS(detach_buffer_header->ts),
							   NULL, 0,
							   __FILE__, __LINE__, __FUNCTION__, ("detach -thread " + intToString(typeThread)).c_str());
					}
					#endif
					this->push(&header_packet_read);
					this->detachBufferReadPos += sizeof(pcap_pkthdr) + detach_buffer_header->caplen;
				}
				if(this->detachBufferReadPos >= this->detachBufferLength ||
				   detach_buffer_header->caplen == 0xFFFFFFFF) {
					this->activeDetachBuffer[0] = 0;
					this->readThread->unlock_detach_buffer(this->detachBufferActiveIndex);
					this->detachBufferActiveIndex = this->detachBufferActiveIndex ? 0 : 1;
					this->detachBufferReadPos = 0;
				}
			} else {
				POP_FROM_PREV_THREAD;
				this->push(&hpii.header_packet);
			}
			break;
		case defrag: {
			POP_FROM_PREV_THREAD;
			#if SNIFFER_THREADS_EXT
			if(sverb.sniffer_threads_ext && thread_data) {
				thread_data->inc_packets_in(HPH(hpii.header_packet)->caplen);
			}
			#endif
			bool okPush = true;
			if(opt_udpfrag) {
				res = this->pcapProcess(&hpii.header_packet, this->typeThread,
							NULL, 0,
							ppf_defrag | ppf_returnZeroInCheckData);
				if(res == -1) {
					break;
				} else if(res == 0) {
					okPush = false;
				}
			}
			if(okPush) {
				this->push(&hpii.header_packet);
			} else if(hpii.header_packet) {
				PUSH_HP(&hpii.header_packet, this->typeThread);
			}
			}
			break;
		case md1:
		case md2: {
			POP_FROM_PREV_THREAD;
			#if SNIFFER_THREADS_EXT
			if(sverb.sniffer_threads_ext && thread_data) {
				thread_data->inc_packets_in(HPH(hpii.header_packet)->caplen);
			}
			#endif
			bool okPush = true;
			if((this->typeThread == md1 && !(this->counter % 2)) ||
			   (this->typeThread == md2 && (opt_dup_check_type != _dedup_na ? hpii.header_packet->dc.is_empty() : !hpii.header_packet->detect_headers))) {
				if(opt_dup_check_type != _dedup_na || !hpii.header_packet->detect_headers) {
					res = this->pcapProcess(&hpii.header_packet, this->typeThread,
								NULL, 0,
								(opt_dup_check_type != _dedup_na ? ppf_calcMD5 : 0) | ppf_returnZeroInCheckData);
					if(res == -1) {
						break;
					} else if(res == 0) {
						okPush = false;
					}
				}
			}
			if(okPush) {
				this->push(&hpii.header_packet);
			} else if(hpii.header_packet) {
				PUSH_HP(&hpii.header_packet, this->typeThread);
			}
			++this->counter;
			}
			break;
		case dedup: {
			POP_FROM_PREV_THREAD;
			#if SNIFFER_THREADS_EXT
			if(sverb.sniffer_threads_ext && thread_data) {
				thread_data->inc_packets_in(HPH(hpii.header_packet)->caplen);
			}
			#endif
			if(opt_pcap_queue_iface_dedup_separate_threads_extend) {
				bool okPush = true;
				if(opt_dup_check_type != _dedup_na) {
					res = this->pcapProcess(&hpii.header_packet, this->typeThread,
								NULL, 0,
								ppf_dedup | ppf_dump | ppf_returnZeroInCheckData, _pcapDumpHandle);
					if(res == -1) {
						break;
					} else if(res == 0) {
						okPush = false;
					}
				} else {
					if(pcapDumpHandle || !hpii.header_packet->detect_headers) {
						this->pcapProcess(&hpii.header_packet, this->typeThread,
								  NULL, 0,
								  ppf_dump | ppf_returnZeroInCheckData, _pcapDumpHandle);
					}
				}
				if(okPush) {
					this->push(&hpii.header_packet);
				} else {
					if(hpii.header_packet) {
						PUSH_HP(&hpii.header_packet, this->typeThread);
					}
					this->tryForcePush();
				}
			} else {
				bool okPush = true;
				res = this->pcapProcess(&hpii.header_packet, this->typeThread,
							NULL, 0,
							ppf_calcMD5 | ppf_dedup | ppf_dump | ppf_returnZeroInCheckData, _pcapDumpHandle);
				if(res == -1) {
					break;
				} else if(res == 0) {
					okPush = false;
				}
				if(okPush) {
					this->push(&hpii.header_packet);
				} else if(hpii.header_packet) {
					PUSH_HP(&hpii.header_packet, this->typeThread);
				}
			}
			}
			break;
		case service:
			if(!this->prepareHeaderPacketPool ||
			   !this->readThread->headerPacketStackSnaplen->pop_queue_prepare()) {
				USLEEP(10);
			}
			break;
		case pcap_process:
			break;
		}
	}
	if(header_packet_read) {
		DESTROY_HP(&header_packet_read);
	}
	this->restoreOneshotBuffer();
	this->threadTerminated = true;
	if(VERBOSE) {
		ostringstream outStr;
		outStr << "stop thread t0i_" 
		       << getTypeThreadName()
		       << " (" << this->getInterfaceAlias() << ") /" << this->threadId << endl;
		syslog(LOG_NOTICE, "%s", outStr.str().c_str());
	}
	return(NULL);
}

/*
void PcapQueue_readFromInterfaceThread::_pcap_dispatch_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
	pcap_dispatch_data *dd = (PcapQueue_readFromInterfaceThread::pcap_dispatch_data*)user;
	((PcapQueue_readFromInterfaceThread*)dd->me)->pcap_dispatch_handler(dd, header, packet);
}

void PcapQueue_readFromInterfaceThread::pcap_dispatch_handler(pcap_dispatch_data *dd, const struct pcap_pkthdr *header, const u_char *packet) {
	if(is_terminating() || this->threadDoTerminate) {
		return;
	}
	if(opt_pcap_queue_use_blocks_read_check || filter_ip) {
		if(!check_protocol((pcap_pkthdr*)header, (u_char*)packet, &dd->checkProtocolData) ||
		   (filter_ip && !check_filter_ip((u_char*)packet, &dd->checkProtocolData))) {
			return;
		}
	}
	while(!dd->block ||
	      !dd->block->get_add_hp_pointers(&dd->pcap_header_plus2, &dd->pcap_packet, pcap_snaplen) ||
	      (dd->block->count && force_push)) {
		if(dd->block) {
			this->push_block(dd->block);
		}
		dd->block = new FILE_LINE(15045) pcap_block_store(pcap_block_store::plus2);
		force_push = false;
	}
	sumPacketsSize[0] += header->caplen;
	dd->pcap_header_plus2->clear();
	if(opt_pcap_queue_use_blocks_read_check) {
		dd->pcap_header_plus2->detect_headers = 0x01;
		dd->pcap_header_plus2->header_ip_encaps_offset = dd->checkProtocolData.header_ip_offset;
		dd->pcap_header_plus2->header_ip_offset = dd->checkProtocolData.header_ip_offset;
		dd->pcap_header_plus2->eth_protocol = dd->checkProtocolData.protocol;
		dd->pcap_header_plus2->pid.vlan = dd->checkProtocolData.vlan;
		dd->pcap_header_plus2->pid.flags = 0;
	} else {
		dd->pcap_header_plus2->header_ip_encaps_offset = 0;
		dd->pcap_header_plus2->header_ip_offset = 0;
	}
	dd->pcap_header_plus2->convertFromStdHeader((pcap_pkthdr*)header);
	dd->pcap_header_plus2->dlink = pcapLinklayerHeaderType;
	memcpy(dd->pcap_packet, packet, header->caplen);
	dd->block->inc_h(dd->pcap_header_plus2);
}
*/

u_char* PcapQueue_readFromInterfaceThread::dpdk_packet_allocation(pcap_dispatch_data *dd, u_int32_t caplen, bool force, bool pb_init) {
	while(force ||
	      !dd->block ||
	      !dd->block->get_add_hp_pointers(&dd->pcap_header_plus2, &dd->headerPacket.packet, caplen)
	      #if not DPDK_DEBUG_DISABLE_FORCE_FLUSH
	      || (dd->block->count && force_push)
	      #endif
	      ) {
		if(opt_dpdk_copy_packetbuffer) {
			if(!dd->block) {
				u_int64_t wait_start = 0;
				if(sverb.dpdk) {
					wait_start = getTimeMS_rdtsc();
					cout << "wait for init first block" << flush;
				}
				while(!dd->block) {
					__ASM_PAUSE;
				}
				if(sverb.dpdk) {
					u_int64_t wait_stop = getTimeMS_rdtsc();
					if(wait_stop > wait_start) cout << " : " << (wait_stop - wait_start) << "ms";
					cout << endl;
				}
			} else {
				#if DPDK_DEBUG
				cout << " * dpdk_packet_allocation -> push "
				     << " size: " << dd->copy_block[dd->copy_block_active_index]->size
				     << " count: " << dd->copy_block[dd->copy_block_active_index]->count
				     << " set_active: " << (dd->block == dd->copy_block[dd->copy_block_active_index] ? "OK" : "FAILED")
				     << " check: " << (dpdk_check_block(dd, 0, 0, true) ? "OK" : "FAILED")
				     << endl;
				unsigned _clc = 0;
				for(unsigned i = 0; i < dd->block->count; i++) {
					u_int32_t _cl = dd->block->get_header(i)->get_caplen();
					if(_cl > 10000 && ((pcap_pkthdr_plus2*)dd->block->get_header(i))->ignore != 1) {
						cout << dd->block->get_header(i)->get_caplen() << "|";
						++_clc;
					}
				}
				if(_clc) {
					cout << endl;
				}
				#endif
				dd->copy_block_full[dd->copy_block_active_index] = 1;
				int copy_block_no_active_index = (dd->copy_block_active_index + 1) % 2;
				if(dd->copy_block_full[copy_block_no_active_index]) {
					u_int64_t wait_start = 0;
					if(sverb.dpdk) {
						wait_start = getTimeMS_rdtsc();
						cout << "wait for send no-active block - tid: "
						     << get_unix_tid() << ", " << __FILE__ << ":" << __LINE__ << flush;
					}
					while(dd->copy_block_full[copy_block_no_active_index]) {
						__ASM_PAUSE;
					}
					if(sverb.dpdk) {
						u_int64_t wait_stop = getTimeMS_rdtsc();
						if(wait_stop > wait_start) cout << " : " << (wait_stop - wait_start) << "ms";
						cout << endl;
					}
				}
				dd->block = dd->copy_block[copy_block_no_active_index];
				dd->copy_block_active_index = copy_block_no_active_index;
			}
		} else {
			if(dd->block) {
				if(opt_dpdk_defer_send_packetbuffer) {
					if(dd->last_full_block) {
						u_int64_t wait_start = 0;
						if(sverb.dpdk) {
							wait_start = getTimeMS_rdtsc();
							cout << "wait for free last block" << flush;
						}
						while(dd->last_full_block) {
							__ASM_PAUSE;
						}
						if(sverb.dpdk) {
							u_int64_t wait_stop = getTimeMS_rdtsc();
							if(wait_stop > wait_start) cout << " : " << (wait_stop - wait_start) << "ms";
							cout << endl;
						}
					}
					dd->last_full_block = dd->block;
				} else {
					this->push_block(dd->block);
				}
			}
			if(opt_dpdk_prealloc_packetbuffer) {
				if(!dd->next_free_block) {
					u_int64_t wait_start = 0;
					if(sverb.dpdk) {
						wait_start = getTimeMS_rdtsc();
						cout << "wait for next free block" << flush;
					}
					while(!dd->next_free_block) {
						__ASM_PAUSE;
					}
					if(sverb.dpdk) {
						u_int64_t wait_stop = getTimeMS_rdtsc();
						if(wait_stop > wait_start) cout << " : " << (wait_stop - wait_start) << "ms";
						cout << endl;
					}
				}
				dd->block = (pcap_block_store*)dd->next_free_block;
				dd->next_free_block = NULL;
			} else {
				dd->block = new FILE_LINE(0) pcap_block_store(pcap_block_store::plus2);
				if(pb_init) {
					dd->block->init(true);
				}
			}
		}
		force_push = false;
		if(force && dd->block) {
			break;
		}
	}
	return(dd->headerPacket.packet);
}

bool PcapQueue_readFromInterfaceThread::_packet_completion(pcap_pkthdr *pcap_header, u_char *packet, pcap_pkthdr_plus2 *pcap_header_plus2,
							   sCheckProtocolData *checkProtocolData) {
	if(opt_pcap_queue_use_blocks_read_check || filter_ip) {
		if(!check_protocol(pcap_header, packet, checkProtocolData) ||
		   !check_filter_ip(pcap_header, packet, checkProtocolData)) {
			return(false);
		}
	}
	pcap_header_plus2->clear();
	if(opt_pcap_queue_use_blocks_read_check) {
		pcap_header_plus2->detect_headers = 0x01;
		pcap_header_plus2->header_ip_encaps_offset = checkProtocolData->header_ip_offset;
		pcap_header_plus2->header_ip_offset = checkProtocolData->header_ip_offset;
		pcap_header_plus2->eth_protocol = checkProtocolData->protocol;
		pcap_header_plus2->pid.vlan = checkProtocolData->vlan;
		pcap_header_plus2->pid.flags = 0;
	} else {
		pcap_header_plus2->header_ip_encaps_offset = 0;
		pcap_header_plus2->header_ip_offset = 0;
	}
	pcap_header_plus2->convertFromStdHeader((pcap_pkthdr*)pcap_header);
	pcap_header_plus2->dlink = DLT_EN10MB;
	return(true);
}

void PcapQueue_readFromInterfaceThread::dpdk_packet_process(pcap_dispatch_data *dd, u_int32_t caplen) {
	if(dd->headerPacket.packet) {
		dpdk_packet_completion(dd, &dd->headerPacket.header, dd->headerPacket.packet);
	}
	while(!dd->block ||
	      !dd->block->get_add_hp_pointers(&dd->pcap_header_plus2, &dd->headerPacket.packet, caplen)
	      #if not DPDK_DEBUG_DISABLE_FORCE_FLUSH
	      || (dd->block->count && force_push)
	      #endif
	      ) {
		if(opt_dpdk_copy_packetbuffer) {
			if(!dd->block) {
				u_int64_t wait_start = 0;
				if(sverb.dpdk) {
					wait_start = getTimeMS_rdtsc();
					cout << "wait for init first block" << flush;
				}
				while(!dd->block) {
					__ASM_PAUSE;
				}
				if(sverb.dpdk) {
					u_int64_t wait_stop = getTimeMS_rdtsc();
					if(wait_stop > wait_start) cout << " : " << (wait_stop - wait_start) << "ms";
					cout << endl;
				}
			} else {
				#if DPDK_DEBUG
				cout << " * dpdk_packet_process -> push "
				     << " size: " << dd->copy_block[dd->copy_block_active_index]->size
				     << " count: " << dd->copy_block[dd->copy_block_active_index]->count
				     << " set_active: " << (dd->block == dd->copy_block[dd->copy_block_active_index] ? "OK" : "FAILED")
				     << " check: " << (dpdk_check_block(dd, 0, 0, true) ? "OK" : "FAILED")
				     << endl;
				unsigned _clc = 0;
				for(unsigned i = 0; i < dd->block->count; i++) {
					u_int32_t _cl = dd->block->get_header(i)->get_caplen();
					if(_cl > 10000 && ((pcap_pkthdr_plus2*)dd->block->get_header(i))->ignore != 1) {
						cout << dd->block->get_header(i)->get_caplen() << "|";
						++_clc;
					}
				}
				if(_clc) {
					cout << endl;
				}
				#endif
				dd->copy_block_full[dd->copy_block_active_index] = 1;
				int copy_block_no_active_index = (dd->copy_block_active_index + 1) % 2;
				if(dd->copy_block_full[copy_block_no_active_index]) {
					u_int64_t wait_start = 0;
					if(sverb.dpdk) {
						wait_start = getTimeMS_rdtsc();
						cout << "wait for send no-active block - tid: "
						     << get_unix_tid() << ", " << __FILE__ << ":" << __LINE__ << flush;
					}
					while(dd->copy_block_full[copy_block_no_active_index]) {
						__ASM_PAUSE;
					}
					if(sverb.dpdk) {
						u_int64_t wait_stop = getTimeMS_rdtsc();
						if(wait_stop > wait_start) cout << " : " << (wait_stop - wait_start) << "ms";
						cout << endl;
					}
				}
				dd->block = dd->copy_block[copy_block_no_active_index];
				dd->copy_block_active_index = copy_block_no_active_index;
			}
		} else {
			if(dd->block) {
				if(opt_dpdk_defer_send_packetbuffer) {
					if(dd->last_full_block) {
						u_int64_t wait_start = 0;
						if(sverb.dpdk) {
							wait_start = getTimeMS_rdtsc();
							cout << "wait for free last block" << flush;
						}
						while(dd->last_full_block) {
							__ASM_PAUSE;
						}
						if(sverb.dpdk) {
							u_int64_t wait_stop = getTimeMS_rdtsc();
							if(wait_stop > wait_start) cout << " : " << (wait_stop - wait_start) << "ms";
							cout << endl;
						}
					}
					dd->last_full_block = dd->block;
				} else {
					// delete dd->block;
					this->push_block(dd->block);
				}
			}
			if(opt_dpdk_prealloc_packetbuffer) {
				if(!dd->next_free_block) {
					u_int64_t wait_start = 0;
					if(sverb.dpdk) {
						wait_start = getTimeMS_rdtsc();
						cout << "wait for next free block" << flush;
					}
					while(!dd->next_free_block) {
						__ASM_PAUSE;
					}
					if(sverb.dpdk) {
						u_int64_t wait_stop = getTimeMS_rdtsc();
						if(wait_stop > wait_start) cout << " : " << (wait_stop - wait_start) << "ms";
						cout << endl;
					}
				}
				dd->block = (pcap_block_store*)dd->next_free_block;
				dd->next_free_block = NULL;
			} else {
				dd->block = new FILE_LINE(0) pcap_block_store(pcap_block_store::plus2);
			}
		}
		force_push = false;
	}
}

void PcapQueue_readFromInterfaceThread::dpdk_packets_get_pointers(pcap_dispatch_data *dd, u_int32_t start, u_int32_t max, u_int32_t *pkts_len, u_int32_t snaplen,
								  void **headers, void **packets, u_int32_t *count, bool *filled) {
	if(!dd->block) {
		u_int64_t wait_start = 0;
		if(sverb.dpdk) {
			wait_start = getTimeMS_rdtsc();
			cout << "wait for init first block" << flush;
		}
		while(!dd->block) {
			__ASM_PAUSE;
		}
		if(sverb.dpdk) {
			u_int64_t wait_stop = getTimeMS_rdtsc();
			if(wait_stop > wait_start) cout << " : " << (wait_stop - wait_start) << "ms";
			cout << endl;
		}
	}
	*count = 0;
	for(unsigned i = start; i < max; i++) {
		#if not DPDK_DEBUG_DISABLE_FORCE_FLUSH
		if(dd->block->count && force_push) {
			*filled = true;
			break;
		}
		#endif
		u_int32_t caplen = MIN(pkts_len[i], snaplen);
		if(dd->block->get_add_hp_pointers((pcap_pkthdr_plus2**)&headers[i], (u_char**)&packets[i], caplen)) {
			dd->block->inc_h(caplen);
			++*count;
		} else {
			*filled = true;
			break;
		}
	}
	force_push = false;
}

void PcapQueue_readFromInterfaceThread::dpdk_packet_process__mbufs_in_packetbuffer(pcap_dispatch_data *dd, pcap_pkthdr *pcap_header, void *mbuf) {
	if(!dd->block) {
		if(opt_dpdk_prealloc_packetbuffer) {
			if(!dd->next_free_block) {
				u_int64_t wait_start = 0;
				if(sverb.dpdk) {
					wait_start = getTimeMS_rdtsc();
					cout << "wait for next free block" << flush;
				}
				while(!dd->next_free_block) {
					__ASM_PAUSE;
				}
				if(sverb.dpdk) {
					u_int64_t wait_stop = getTimeMS_rdtsc();
					if(wait_stop > wait_start) cout << " : " << (wait_stop - wait_start) << "ms";
					cout << endl;
				}
			}
			dd->block = (pcap_block_store*)dd->next_free_block;
			dd->next_free_block = NULL;
		} else {
			dd->block = new FILE_LINE(0) pcap_block_store(pcap_block_store::plus2, true);
		}
	}
	sumPacketsSize[0] += pcap_header->caplen;
	if(!dd->pcap_header_plus2) {
		dd->pcap_header_plus2 = new FILE_LINE(0) pcap_pkthdr_plus2;
	}
	dd->pcap_header_plus2->clear();
	dd->pcap_header_plus2->header_ip_encaps_offset = 0;
	dd->pcap_header_plus2->header_ip_offset = 0;
	dd->pcap_header_plus2->convertFromStdHeader((pcap_pkthdr*)pcap_header);
	dd->pcap_header_plus2->dlink = DLT_EN10MB;
	dd->block->add_dpdk(dd->pcap_header_plus2, mbuf);
	if(dd->block->is_dpkd_data_full()) {
		if(opt_dpdk_defer_send_packetbuffer) {
			if(dd->last_full_block) {
				u_int64_t wait_start = 0;
				if(sverb.dpdk) {
					wait_start = getTimeMS_rdtsc();
					cout << "wait for free last block" << flush;
				}
				while(dd->last_full_block) {
					__ASM_PAUSE;
				}
				if(sverb.dpdk) {
					u_int64_t wait_stop = getTimeMS_rdtsc();
					if(wait_stop > wait_start) cout << " : " << (wait_stop - wait_start) << "ms";
					cout << endl;
				}
			}
			dd->last_full_block = dd->block;
		} else {
			this->push_block(dd->block);
		}
		dd->block = NULL;
	}
}

bool PcapQueue_readFromInterfaceThread::dpdk_check_block(pcap_dispatch_data *dd, unsigned pos, unsigned count, bool only_check) {
	bool rslt = true;
	unsigned start = 0;
	unsigned limit = dd->block->count - count + pos;
	for(unsigned i = start; i < limit; i++) {
		if(((pcap_pkthdr_plus2*)dd->block->get_header(i))->ignore == 1) {
			//cout << "skip ignore" << endl;
			continue;
		}
		unsigned caplen = dd->block->get_header(i)->get_caplen();
		u_int32_t size_header_a = PACKETBUFFER_ALIGN_PCAP_PKTHDR_PLUS2_SIZE;
		u_int32_t size_packet_a = PACKETBUFFER_ALIGN_PCAP_SIZE(caplen);
		if(i < dd->block->count - 1) {
			if(size_packet_a + size_header_a != (dd->block->offsets[i + 1] - dd->block->offsets[i])) {
				rslt = false;
				if(!only_check && sverb.dpdk) {
					cout << " * dpdk_check_block "
					     << "bad caplen/offset " << i << "/" << size_packet_a << "/" << (dd->block->offsets[i + 1] - dd->block->offsets[i]) << endl;
				}
			}
		} else {
			if(size_packet_a + size_header_a != (dd->block->size - dd->block->offsets[i])) {
				rslt = false;
				if(!only_check && sverb.dpdk) {
					cout << " * dpdk_check_block "
					     << "bad caplen/size " << i << "/" << size_packet_a << "/" << (dd->block->size - dd->block->offsets[i]) << endl;
				}
			}
		}
	}
	return(rslt);
}

#define DEBUG_threadFunction_blocks_LAG 0

void PcapQueue_readFromInterfaceThread::threadFunction_blocks() {
	
	if(this->typeThread == read) {
		extern string opt_sched_pol_interface;
		pthread_set_priority(opt_sched_pol_interface);
		if(dpdkHandle) {
			if(dpdk_config(dpdkHandle)->type_read_thread != _dpdk_trt_std) {
				if(opt_dpdk_copy_packetbuffer) {
					for(int i = 0; i < 2; i++) {
						dispatch_data.copy_block[i] = new FILE_LINE(0) pcap_block_store(pcap_block_store::plus2, opt_dpdk_mbufs_in_packetbuffer);
						dispatch_data.copy_block_full[i] = false;
						dispatch_data.copy_block[i]->init(true);
						#if DPDK_DEBUG
						dispatch_data.copy_block_block_orig[i] = dispatch_data.copy_block[i]->block;
						#endif
					}
				} else if(opt_dpdk_prealloc_packetbuffer) {
					pcap_block_store *next_free_block = NULL;
					next_free_block = (pcap_block_store*) new FILE_LINE(0) pcap_block_store(pcap_block_store::plus2, opt_dpdk_mbufs_in_packetbuffer);
					next_free_block->init(true);
					dispatch_data.next_free_block = next_free_block;
				}
			}
			dpdk_set_initialized(dpdkHandle);
			if(dpdk_config(dpdkHandle)->type_read_thread == _dpdk_trt_std) {
				dpdk_reset_statistics(dpdkHandle, true);
				syslog(LOG_INFO, "DPDK - READ THREAD: %i\n", get_unix_tid());
				while(!(is_terminating() || this->threadDoTerminate)) {
					if(!dpdk_read_proc(dpdkHandle)) {
						sDpdkConfig *_dpdk_config = dpdk_config(dpdkHandle);
						if(_dpdk_config->read_usleep_if_no_packet) {
							USLEEP(_dpdk_config->read_usleep_if_no_packet);
						}
					}
				}
				if(dispatch_data.block) {
					delete dispatch_data.block;
				}
			} else {
				if(opt_dpdk_copy_packetbuffer) {
					dispatch_data.copy_block_active_index = 0;
					int copy_block_no_active_index;
					dispatch_data.block = dispatch_data.copy_block[dispatch_data.copy_block_active_index];
					while(!(is_terminating() || this->threadDoTerminate)) {
						copy_block_no_active_index = (dispatch_data.copy_block_active_index + 1) % 2;
						if(dispatch_data.copy_block_full[copy_block_no_active_index]) {
							#if SNIFFER_THREADS_EXT
							if(sverb.sniffer_threads_ext && thread_data) {
								thread_data->inc_packets_in(dispatch_data.copy_block[copy_block_no_active_index]->size_packets,
											    dispatch_data.copy_block[copy_block_no_active_index]->count);
							}
							#endif
							#if DEBUG_threadFunction_blocks_LAG
							u_int64_t x[10];
							x[0] = getTimeUS();
							bool alloc = false;
							#endif
							pcap_block_store *block = NULL;
							if(opt_dpdk_rotate_packetbuffer) {
								block = parent->getInstancePcapFifo()->getBlockStoreFromPool();
								#if DEBUG_threadFunction_blocks_LAG
								x[1] = getTimeUS();
								#endif
								if(block) {
									block->clear(false);
								}
							}
							if(!block) {
								block =(pcap_block_store*) new FILE_LINE(0) pcap_block_store(pcap_block_store::plus2, opt_dpdk_mbufs_in_packetbuffer);
								#if DEBUG_threadFunction_blocks_LAG
								x[1] = getTimeUS();
								#endif
								block->init(true);
								#if DEBUG_threadFunction_blocks_LAG
								alloc = true;
								#endif
							}
							#if DEBUG_threadFunction_blocks_LAG
							x[2] = getTimeUS();
							#endif
							block->copy(dispatch_data.copy_block[copy_block_no_active_index]);
							#if SNIFFER_THREADS_EXT
							if(sverb.sniffer_threads_ext && thread_data) {
								thread_data->inc_packets_out(block->size_packets, block->count);
							}
							#endif
							#if DEBUG_threadFunction_blocks_LAG
							x[3] = getTimeUS();
							#endif
							this->push_block(block);
							#if DEBUG_threadFunction_blocks_LAG
							x[4] = getTimeUS();
							#endif
							dispatch_data.copy_block[copy_block_no_active_index]->clear(false);
							dispatch_data.copy_block_full[copy_block_no_active_index] = 0;
							#if DEBUG_threadFunction_blocks_LAG
							if(x[4] - x[0] > 5000) {
								 char b[10000];
								 snprintf(b, sizeof(b), 
									  " *** %s %lu %lu %lu %lu",
									  (alloc ? "A" : "r"),
									  x[1] - x[0],
									  x[2] - x[1],
									  x[3] - x[2],
									  x[4] - x[3]);
								 syslog(LOG_INFO, "%s", b);
								 cout << b << endl;
							}
							#endif
						}
						USLEEP(1);
					}
					for(int i = 0; i < 2; i++) {
						delete dispatch_data.copy_block[i];
					}
				} else {
					while(!(is_terminating() || this->threadDoTerminate)) {
						if(opt_dpdk_prealloc_packetbuffer && !dispatch_data.next_free_block) {
							pcap_block_store *next_free_block = NULL;
							if(opt_dpdk_rotate_packetbuffer) {
								next_free_block = parent->getInstancePcapFifo()->getBlockStoreFromPool();
								if(next_free_block) {
									next_free_block->clear(true);
								}
							}
							if(!next_free_block) {
								next_free_block = (pcap_block_store*) new FILE_LINE(0) pcap_block_store(pcap_block_store::plus2, opt_dpdk_mbufs_in_packetbuffer);
								next_free_block->init(true);
							}
							dispatch_data.next_free_block = next_free_block;
						}
						if(opt_dpdk_defer_send_packetbuffer && dispatch_data.last_full_block) {
							this->push_block((pcap_block_store*)dispatch_data.last_full_block);
							dispatch_data.last_full_block = NULL;
						}
						USLEEP(opt_dpdk_prealloc_packetbuffer || opt_dpdk_defer_send_packetbuffer ? 1 : 50);
					}
					if(dispatch_data.block) {
						delete dispatch_data.block;
					}
					if(dispatch_data.next_free_block) {
						delete dispatch_data.next_free_block;
					}
					if(dispatch_data.last_full_block) {
						delete dispatch_data.last_full_block;
					}
				}
			}
			this->threadTerminated = true;
			return;
		} else if(opt_t2_boost_pcap_dispatch) {
			dispatch_data.me = this;
			unsigned counter_zero_packets = 0;
			while(!(is_terminating() || this->threadDoTerminate)) {
				if(::pcap_dispatch(this->pcapHandle, 32, _pcap_dispatch_handler, (u_char*)&dispatch_data) > 0) {
					counter_zero_packets = 0;
				} else {
					USLEEP_C(50, ++counter_zero_packets);
				}
			}
			if(dispatch_data.block) {
				delete dispatch_data.block;
			}
			this->threadTerminated = true;
			return;
		}
	}
	
	if(this->typeThread == dpdk_worker) {
		syslog(LOG_INFO, "DPDK - WORKER (std) THREAD %i\n", get_unix_tid());
		while(!(is_terminating() || this->threadDoTerminate)) {
			if(!dpdk_worker_proc(readThread->dpdkHandle)) {
				sDpdkConfig *_dpdk_config = dpdk_config(readThread->dpdkHandle);
				if(_dpdk_config->worker_usleep_if_no_packet) {
					USLEEP(_dpdk_config->worker_usleep_if_no_packet);
				}
			}
		}
		if(dispatch_data.block) {
			delete dispatch_data.block;
		}
		this->threadTerminated = true;
		return;
	}
	
	int res;
	pcap_pkthdr *pcap_next_ex_header = NULL;
	u_char *pcap_next_ex_packet = NULL;
	pcap_pkthdr_plus2 *pcap_header_plus2 = NULL;
	u_char *pcap_packet = NULL;
	bool _useOneshotBuffer = false;
	pcap_block_store *block = NULL;
	sCheckProtocolData checkProtocolData;
	
	#if EXPERIMENTAL_INTERFACE_DUPL
	unsigned dupl_read_counter = 0;
	#endif
	
	while(!(is_terminating() || this->threadDoTerminate)) {
		switch(this->typeThread) {
		case read: {
			while(!block ||
			      !block->get_add_hp_pointers(&pcap_header_plus2, &pcap_packet, pcap_snaplen) ||
			      (block->count && force_push && getTimeMS_rdtsc() > (block->timestampMS + opt_pcap_queue_block_max_time_ms))) {
				if(block) {
					#if DEBUG_PACKET_DELAY_TEST
					int64_t system_time_ms = getTimeMS_rdtsc();
					int64_t system_time_ms_2 = getTimeMS();
					for(unsigned i = 0; i < block->count; i++) {
						int64_t packet_time_ms = getTimeUS(block->get_header(i)->header_fix_size.ts_tv_sec, block->get_header(i)->header_fix_size.ts_tv_usec) / 1000;
						if(abs(system_time_ms - packet_time_ms) > DEBUG_PACKET_DELAY_TEST) {
							cout << " *** " << typeThread << ", " 
							     << block->ifname << ", " 
							     << system_time_ms - packet_time_ms << ", "
							     << system_time_ms_2 - packet_time_ms << endl;
						}
					}
					#endif
					this->push_block(block);
					#if SNIFFER_THREADS_EXT
					if(sverb.sniffer_threads_ext && thread_data) {
						thread_data->inc_packets_out(block->size_packets, block->count);
					}
					#endif
				}
				block = new FILE_LINE(0) pcap_block_store(pcap_block_store::plus2);
				strncpy(block->ifname, this->getInterfaceAlias().c_str(), sizeof(block->ifname) - 1);
				force_push = false;
				//cout << 'X' << flush;
			}
			if(_useOneshotBuffer) {
				setOneshotBuffer(pcap_packet);
			} else {
				_useOneshotBuffer = useOneshotBuffer();
				if(_useOneshotBuffer) {
					setOneshotBuffer(pcap_packet);
				}
			}
			
			#if EXPERIMENTAL_INTERFACE_DUPL
			if(!(dupl_read_counter % 10)) {
			#endif
			
			res = this->pcap_next_ex_iface(this->pcapHandle, &pcap_next_ex_header, &pcap_next_ex_packet,
						       opt_pcap_queue_use_blocks_read_check, &checkProtocolData);
			
			#if DEBUG_PACKET_DELAY_TEST
			if(res > 0) {
				int64_t system_time_ms = getTimeMS_rdtsc();
				int64_t system_time_ms_2 = getTimeMS();
				int64_t packet_time_ms = getTimeUS(pcap_next_ex_header->ts.tv_sec, pcap_next_ex_header->ts.tv_usec) / 1000;
				if(abs(system_time_ms - packet_time_ms) > DEBUG_PACKET_DELAY_TEST) {
					cout << " * pcap_next_ex_iface * " 
					     << typeThread << ", " 
					     << interface.interface << ", " 
					     << system_time_ms - packet_time_ms << ", "
					     << system_time_ms_2 - packet_time_ms << endl;
				}
			}
			#endif
			
			#if EXPERIMENTAL_INTERFACE_DUPL
			}
			#endif
			
			if(res == -1) {
				if(opt_pb_read_from_file[0]) {
					this->push_block(block);
					block = NULL;
					terminatingAtEndOfReadPcap();
					if(opt_nonstop_read) {
						continue;
					} else {
						break;
					}
				}
				break;
			} else if(res <= 0) {
				if(res == 0) {
					USLEEP(100);
				}
				continue;
			}
			#if SNIFFER_THREADS_EXT
			if(sverb.sniffer_threads_ext && thread_data) {
				thread_data->inc_packets_in(pcap_next_ex_header->caplen);
			}
			#endif
			#if TRACE_INVITE_BYE
			if(memmem(pcap_next_ex_packet, pcap_next_ex_header->caplen, "INVITE sip", 10)) {
				cout << "get INVITE (3) " << typeThread << endl;
			} else if(memmem(pcap_next_ex_packet, pcap_next_ex_header->caplen, "BYE sip", 7)) {
				cout << "get BYE (3) " << typeThread << endl;
			} else if(memmem(pcap_next_ex_packet, pcap_next_ex_header->caplen, "REGISTER sip", 12)) {
				cout << "get REGISTER (3) " << typeThread << endl;
			}
			#endif
			#if TRACE_MASTER_SECRET
			if(memmem(pcap_next_ex_packet, pcap_next_ex_header->caplen, "mastersecret", 12)) {
				cout << "get MASTERSECRET (3) " << typeThread << endl;
			}
			#endif
			#if TRACE_CALL
			if(sverb.trace_call) {
				trace_call(pcap_next_ex_packet, pcap_next_ex_header->caplen, pcapLinklayerHeaderType,
					   0, getTimeUS(pcap_next_ex_header->ts),
					   NULL, 0,
					   __FILE__, __LINE__, __FUNCTION__, ("get from pcap - thread " + intToString(typeThread)).c_str());
			}
			#endif
			sumPacketsSize[0] += pcap_next_ex_header->caplen;
			pcap_header_plus2->clear();
			if(opt_pcap_queue_use_blocks_read_check) {
				pcap_header_plus2->detect_headers = 0x01;
				pcap_header_plus2->header_ip_encaps_offset = checkProtocolData.header_ip_offset;
				pcap_header_plus2->header_ip_offset = checkProtocolData.header_ip_offset;
				pcap_header_plus2->eth_protocol = checkProtocolData.protocol;
				pcap_header_plus2->pid.vlan = checkProtocolData.vlan;
				pcap_header_plus2->pid.flags = 0;
			} else {
				pcap_header_plus2->header_ip_encaps_offset = 0;
				pcap_header_plus2->header_ip_offset = 0;
			}
			pcap_header_plus2->convertFromStdHeader(pcap_next_ex_header);
			pcap_header_plus2->dlink = pcapLinklayerHeaderType;
			if(!_useOneshotBuffer) {
				memcpy(pcap_packet, pcap_next_ex_packet, pcap_next_ex_header->caplen);
			}
			block->inc_h(pcap_header_plus2);
			//cout << '.' << flush;
			
			#if EXPERIMENTAL_INTERFACE_DUPL
			++dupl_read_counter;
			#endif
			
			break;
		}
		default:
			block = this->prevThread->pop_block();
			if(!block) {
				this->pop_usleep_sum += USLEEP_C(20, this->counter_pop_usleep++);
				if(this->pop_usleep_sum > this->pop_usleep_sum_last_push + opt_pcap_queue_block_max_time_ms * 1000) {
					this->prevThread->setForcePush();
					this->pop_usleep_sum_last_push = this->pop_usleep_sum;
				}
				continue;
			}
			#if SNIFFER_THREADS_EXT
			if(sverb.sniffer_threads_ext && thread_data) {
				thread_data->inc_packets_in(block->size_packets, block->count);
			}
			#endif
			this->counter_pop_usleep = 0;
			this->pop_usleep_sum = 0;
			this->pop_usleep_sum_last_push = 0;
			this->processBlock(block);
			this->push_block(block);
			#if SNIFFER_THREADS_EXT
			if(sverb.sniffer_threads_ext && thread_data) {
				thread_data->inc_packets_out(block->size_packets, block->count);
			}
			#endif
			//cout << this->typeThread << flush;
			break;
		}
	}
	
	if(this->typeThread == read && block) {
		delete block;
	}
	
	this->restoreOneshotBuffer();
	this->threadTerminated = true;
}

void PcapQueue_readFromInterfaceThread::pcap_dispatch_handler(pcap_dispatch_data *dd, const struct pcap_pkthdr *header, const u_char *packet) {
	if(is_terminating() || this->threadDoTerminate) {
		return;
	}
	if(opt_pcap_queue_use_blocks_read_check || filter_ip) {
		if(!check_protocol((pcap_pkthdr*)header, (u_char*)packet, &dd->checkProtocolData) ||
		   !check_filter_ip((pcap_pkthdr*)header, (u_char*)packet, &dd->checkProtocolData)) {
			return;
		}
	}
	while(!dd->block ||
	      !dd->block->get_add_hp_pointers(&dd->pcap_header_plus2, &dd->pcap_packet, pcap_snaplen) ||
	      (dd->block->count && force_push)) {
		if(dd->block) {
			this->push_block(dd->block);
		}
		dd->block = new FILE_LINE(15045) pcap_block_store(pcap_block_store::plus2);
		force_push = false;
	}
	sumPacketsSize[0] += header->caplen;
	dd->pcap_header_plus2->clear();
	if(opt_pcap_queue_use_blocks_read_check) {
		dd->pcap_header_plus2->detect_headers = 0x01;
		dd->pcap_header_plus2->header_ip_encaps_offset = dd->checkProtocolData.header_ip_offset;
		dd->pcap_header_plus2->header_ip_offset = dd->checkProtocolData.header_ip_offset;
		dd->pcap_header_plus2->eth_protocol = dd->checkProtocolData.protocol;
		dd->pcap_header_plus2->pid.vlan = dd->checkProtocolData.vlan;
		dd->pcap_header_plus2->pid.flags = 0;
	} else {
		dd->pcap_header_plus2->header_ip_encaps_offset = 0;
		dd->pcap_header_plus2->header_ip_offset = 0;
	}
	dd->pcap_header_plus2->convertFromStdHeader((pcap_pkthdr*)header);
	dd->pcap_header_plus2->dlink = pcapLinklayerHeaderType;
	memcpy(dd->pcap_packet, packet, header->caplen);
	dd->block->inc_h(dd->pcap_header_plus2);
}

void PcapQueue_readFromInterfaceThread::processBlock(pcap_block_store *block) {
	unsigned counter = 0;
	int ppf = 0;
	pcap_dumper_t *_pcapDumpHandle = NULL;
	switch(this->typeThread) {
	case md1:
		ppf = (opt_dup_check_type != _dedup_na ? ppf_calcMD5 : ppf_na) |
		      (opt_udpfrag ? ppf_defragInPQout : ppf_returnZeroInCheckData);
		break;
	case md2:
		ppf = (opt_dup_check_type != _dedup_na ? ppf_calcMD5 : ppf_na) |
		      (opt_udpfrag ? ppf_defragInPQout : ppf_returnZeroInCheckData);
		break;
	case dedup:
		ppf = (opt_dup_check_type != _dedup_na ? ppf_dedup : ppf_na) |
		      (opt_udpfrag ? ppf_defragInPQout : ppf_returnZeroInCheckData);
		if(opt_pcapdump && readThread) {
			ppf |= ppf_dump;
			_pcapDumpHandle = readThread->pcapDumpHandle;
		}
		break;
	case pcap_process:
		ppf = (opt_udpfrag ? ppf_defragInPQout : ppf_returnZeroInCheckData);
		if(opt_pcapdump && readThread) {
			ppf |= ppf_dump;
			_pcapDumpHandle = readThread->pcapDumpHandle;
		}
		break;
	default:
		break;
	}
	for(unsigned i = 0; i < block->count; i++) {
		if(block->is_ignore(i)) {
			continue;
		}
		#if TRACE_INVITE_BYE
		if(memmem(block->get_packet(i), block->get_header(i)->header_fix_size.caplen, "INVITE sip", 10)) {
			cout << "process INVITE " << typeThread << endl;
		} else if(memmem(block->get_packet(i), block->get_header(i)->header_fix_size.caplen, "BYE sip", 7)) {
			cout << "process BYE " << typeThread << endl;
		} else if(memmem(block->get_packet(i), block->get_header(i)->header_fix_size.caplen, "REGISTER sip", 12)) {
			cout << "process REGISTER " << typeThread << endl;
		}
		#endif
		#if TRACE_MASTER_SECRET
		if(memmem(block->get_packet(i), block->get_header(i)->header_fix_size.caplen, "mastersecret", 12)) {
			cout << "process MASTERSECRET " << typeThread << endl;
		}
		#endif
		#if TRACE_CALL
		if(sverb.trace_call) {
			trace_call(block->get_packet(i), block->get_header(i)->header_fix_size.caplen, pcapLinklayerHeaderType,
				   0, getTimeUS(block->get_header(i)->header_fix_size.ts_tv_sec, block->get_header(i)->header_fix_size.ts_tv_usec),
				   NULL, 0,
				   __FILE__, __LINE__, __FUNCTION__, ("process block - typethread " + intToString(typeThread)).c_str());
		}
		#endif
		#if DEBUG_PACKET_DELAY_TEST
		int64_t system_time_ms = getTimeMS_rdtsc();
		int64_t system_time_ms_2 = getTimeMS();
		int64_t packet_time_ms = getTimeUS(block->get_header(i)->header_fix_size.ts_tv_sec, block->get_header(i)->header_fix_size.ts_tv_usec) / 1000;
		if(abs(system_time_ms - packet_time_ms) > DEBUG_PACKET_DELAY_TEST) {
			cout << " *** " << typeThread << ", " 
			     << block->ifname << ", " 
			     << system_time_ms - packet_time_ms << ", "
			     << system_time_ms_2 - packet_time_ms << endl;
		}
		#endif
		switch(this->typeThread) {
		case md1:
			if(!(counter % 2)) {
				this->pcapProcess(NULL, 0, block, i, ppf, _pcapDumpHandle);
			}
			break;
		case md2:
			if(((pcap_pkthdr_plus2*)block->get_header(i))->dc.is_empty()) {
				this->pcapProcess(NULL, 0, block, i, ppf, _pcapDumpHandle);
			}
			break;
		case dedup:
			this->pcapProcess(NULL, 0, block, i, ppf, _pcapDumpHandle);
			break;
		case pcap_process:
			this->pcapProcess(NULL, 0, block, i, ppf, _pcapDumpHandle);
			break;
		default:
			break;
		}
		++counter;
	}
}

void PcapQueue_readFromInterfaceThread::preparePstatData(int pstatDataIndex) {
	if(this->threadId && !this->threadDoTerminate) {
		if(this->threadPstatData[pstatDataIndex][0].cpu_total_time) {
			this->threadPstatData[pstatDataIndex][1] = this->threadPstatData[pstatDataIndex][0];
		}
		pstat_get_data(this->threadId, this->threadPstatData[pstatDataIndex]);
	}
}

double PcapQueue_readFromInterfaceThread::getCpuUsagePerc(int pstatDataIndex, bool preparePstatData) {
	if(preparePstatData) {
		this->preparePstatData(pstatDataIndex);
	}
	if(this->threadId && !this->threadDoTerminate) {
		double ucpu_usage, scpu_usage;
		if(this->threadPstatData[pstatDataIndex][0].cpu_total_time && this->threadPstatData[pstatDataIndex][1].cpu_total_time) {
			pstat_calc_cpu_usage_pct(
				&this->threadPstatData[pstatDataIndex][0], &this->threadPstatData[pstatDataIndex][1],
				&ucpu_usage, &scpu_usage);
			return(ucpu_usage + scpu_usage);
		}
	}
	return(-1);
}

void PcapQueue_readFromInterfaceThread::terminate() {
	if(dpdkHandle) {
		dpdk_terminating(dpdkHandle);
	}
	if(this->dpdkWorkerThread) {
		this->dpdkWorkerThread->terminate();
	}
	if(this->detachThread) {
		this->detachThread->terminate();
	}
	if(this->pcapProcessThread) {
		this->pcapProcessThread->terminate();
	}
	if(this->defragThread) {
		this->defragThread->terminate();
	}
	if(this->md1Thread) {
		this->md1Thread->terminate();
	}
	if(this->md2Thread) {
		this->md2Thread->terminate();
	}
	if(this->dedupThread) {
		this->dedupThread->terminate();
	}
	if(this->serviceThread) {
		this->serviceThread->terminate();
	}
	this->threadDoTerminate = true;
}

const char *PcapQueue_readFromInterfaceThread::getTypeThreadName() {
	return(typeThread == read ? "read" : 
	       typeThread == dpdk_worker ? "dpdk_worker" : 
	       typeThread == detach ? "detach" : 
	       typeThread == pcap_process ? "pcap_process" : 
	       typeThread == defrag ? "defrag" :
	       typeThread == md1 ? "md1" :
	       typeThread == md2 ? "md2" :
	       typeThread == dedup ? "dedup" :
	       typeThread == service ? "service" : "---");
}

void PcapQueue_readFromInterfaceThread::prepareLogTraffic() {
	sumPacketsSize[2] = sumPacketsSize[0] - sumPacketsSize[1];
	sumPacketsSize[1] = sumPacketsSize[0];
}

double PcapQueue_readFromInterfaceThread::getTraffic(int divide) {
	return((double)sumPacketsSize[2]/divide/(1024*1024)*8);
}

inline void *_PcapQueue_readFromInterfaceThread_threadFunction(void *arg) {
	return(((PcapQueue_readFromInterfaceThread*)arg)->threadFunction(arg, 0));
}


PcapQueue_readFromInterface::PcapQueue_readFromInterface(const char *nameQueue)
 : PcapQueue(readFromInterface, nameQueue) {
	all_ringbuffers_size = 0;
	memset(this->readThreads, 0, sizeof(this->readThreads));
	this->readThreadsCount = 0;
	this->lastReadThreadsIndex_pcapStatString_interface = -1;
	this->lastTimeLogErrThread0BufferIsFull = 0;
	this->block_qring = NULL;
	if(opt_pcap_queue_iface_dedup_separate_threads_extend &&
	   !opt_pcap_queue_suppress_t1_thread &&
	   !opt_pcap_queue_use_blocks) {
		this->setEnableWriteThread();
		extern volatile int terminating;
		this->block_qring = new FILE_LINE(15046) rqueue_quick<pcap_block_store*>(
			100,
			100, 100,
			&terminating, true);
	}
}

PcapQueue_readFromInterface::~PcapQueue_readFromInterface() {
	unsigned counter = 0;
	while(!this->threadTerminated && counter < 50) {
		USLEEP(100000);
		++counter;
	}
	if(!this->threadTerminated) {
		syslog(LOG_NOTICE, "cancel read thread (%s)", getInterfaceAlias().c_str());
		pthread_cancel(this->threadHandle);
	}
	pthread_join(this->threadHandle, NULL);
	if(this->writeThreadHandle) {
		pthread_join(this->writeThreadHandle, NULL);
	}
	if(this->block_qring) {
		pcap_block_store *blockStore;
		while(this->block_qring->pop(&blockStore, false)) {
			sHeaderPacket *hp;
			for(size_t i = 0; i < blockStore->count; i++) {
				u_char *packetPos = blockStore->block + blockStore->offsets[i] + sizeof(pcap_pkthdr_plus);
				hp = *(sHeaderPacket**)packetPos;
				DESTROY_HP(&hp);
			}
		}
		delete this->block_qring;
	}
}

void PcapQueue_readFromInterface::setInterfaces(const char* interfaces) {
	this->interfaces = interfaces;
}

void PcapQueue_readFromInterface::setFiltersByInterface(vector<dstring> filters) {
	this->filtersByInterface = filters;
}

void PcapQueue_readFromInterface::terminate() {
	for(int i = 0; i < this->readThreadsCount; i++) {
		this->readThreads[i]->terminate();
	}
	PcapQueue::terminate();
}

bool PcapQueue_readFromInterface::init() {
	if(opt_scanpcapdir[0]) {
		return(true);
	}
	vector<sInterface> interfaces;
	parseInterfaces(&interfaces);
	if(!opt_t2_boost && !opt_pcap_queue_iface_separate_threads) {
		if(!interfaces.size()) {
			return(false);
		} else if(interfaces.size() == 1) {
			interface = interfaces[0];
			return(true);
		}
	}
	for(size_t i = 0; i < interfaces.size(); i++) {
		if(this->readThreadsCount < READ_THREADS_MAX - 1) {
			this->readThreads[this->readThreadsCount] = new FILE_LINE(15047) PcapQueue_readFromInterfaceThread(interfaces[i], PcapQueue_readFromInterfaceThread::read, NULL, NULL, this);
			++this->readThreadsCount;
		}
	}
	return(this->readThreadsCount > 0);
}

void PcapQueue_readFromInterface::parseInterfaces(vector<sInterface> *interfaces) {
	parseInterfaces(this->interfaces.c_str(), &filtersByInterface, interfaces);
}

void PcapQueue_readFromInterface::parseInterfaces(const char *interfaces_str, vector<dstring> *filters_by_interface,
						  vector<sInterface> *interfaces) {
	vector<string> interfaces_v = split(interfaces_str, split(",|;| |\t|\r|\n", "|"), true);
	for(unsigned i = 0; i < interfaces_v.size(); i++) {
		sInterface interface;
		interface.interface = interfaces_v[i];
		if(filters_by_interface && filters_by_interface->size()) {
			list<string> filters;
			for(vector<dstring>::iterator iter = filters_by_interface->begin(); iter != filters_by_interface->end(); iter++) {
				if(iter->str[0] == interface.interface && !iter->str[1].empty()) {
					filters.push_back(iter->str[1]);
				}
			}
			if(filters.size()) {
				unsigned c = 0;
				for(list<string>::iterator iter = filters.begin(); iter != filters.end(); iter++) {
					if(filters.size() > 1) {
						interface.alias = interface.interface + '_' + intToString(c);
					} else {
						interface.alias = "";
					}
					interface.filter = *iter;
					++c;
					interfaces->push_back(interface);
				}
			} else {
				interfaces->push_back(interface);
			}
		} else {
			interfaces->push_back(interface);
		}
	}
}

void PcapQueue_readFromInterface::getInterfaces(const char *interfaces_str, vector<string> *rslt_interfaces) {
	vector<sInterface> interfaces;
	parseInterfaces(interfaces_str, NULL, &interfaces);
	rslt_interfaces->clear();
	for(unsigned i = 0; i < interfaces.size(); i++) {
		rslt_interfaces->push_back(interfaces[i].interface);
	}
}

unsigned PcapQueue_readFromInterface::getCountInterfaces(const char *interfaces_str, vector<dstring> *filters_by_interface) {
	vector<sInterface> interfaces;
	parseInterfaces(interfaces_str, filters_by_interface, &interfaces);
	return(interfaces.size());
}

bool PcapQueue_readFromInterface::initThread(void *arg, unsigned int arg2, string *error) {
	init_hash();
	return(this->startCapture(error, NULL) &&
	       this->openFifoForWrite(arg, arg2));
}

void* PcapQueue_readFromInterface::threadFunction(void *arg, unsigned int arg2) {
	this->mainThreadId = get_unix_tid();
	#if SNIFFER_THREADS_EXT
	this->thread_data_main = cThreadMonitor::getSelfThreadData();
	#endif
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		outStr << "start thread t0 (" << this->nameQueue << ") /" << this->mainThreadId << endl;
		if(DEBUG_VERBOSE) {
			cout << outStr.str();
		} else {
			syslog(LOG_NOTICE, "%s", outStr.str().c_str());
		}
	}
	string error;
	if(this->initThread(arg, arg2, &error)) {
		this->threadInitOk = true;
	} else {
		this->threadTerminated = true;
		this->threadInitFailed = true;
		if(is_receiver()) {
			this->initAllReadThreadsFinished = true;
		} else {
			vm_terminate_error(error.c_str());
		}
		return(NULL);
	}
	this->initStat();
	cHeaderPacketStack *headerPacketStack = NULL;
	bool headerPacketStackAlloc = false;
	PcapQueue_readFromInterfaceThread::hpi hpi;
	sHeaderPacket *header_packet_read = NULL;
	sHeaderPacket **header_packet_fetch = NULL;
	int res;
	u_int header_ip_encaps_offset = 0;
	u_int header_ip_offset = 0;
	sPacketInfoData pid;
	pid.clear();
	u_int dlink = global_pcap_dlink;

	if(this->readThreadsCount) {
		while(true) {
			if(is_terminating()) {
				return(NULL);
			}
			bool allInit_1 = true;
			for(int i = 0; i < this->readThreadsCount; i++) {
				if(this->readThreads[i]->threadInitOk == 0 &&
				   !this->readThreads[i]->threadInitFailed) {
					allInit_1 = false;
					break;
				}
			}
			if(allInit_1) {
				break;
			}
			USLEEP(50000);
		}
		for(int i = 0; i < this->readThreadsCount; i++) {
			if(this->readThreads[i]->threadInitOk) {
				this->readThreads[i]->threadInitOk = 2;
			}
		}
	}
	this->initAllReadThreadsFinished = true;
	
	if(opt_pcap_queue_use_blocks) {
		threadFunction_blocks();
		this->threadTerminated = true;
		if(VERBOSE || DEBUG_VERBOSE) {
			ostringstream outStr;
			outStr << "stop thread t0 (" << this->nameQueue << ") /" << this->mainThreadId << endl;
			if(DEBUG_VERBOSE) {
				cout << outStr.str();
			} else {
				syslog(LOG_NOTICE, "%s", outStr.str().c_str());
			}
		}
		return(NULL);
	}
	
	int blockStoreCount = this->readThreadsCount ? this->readThreadsCount : 1;
	pcap_block_store *blockStore[blockStoreCount];
	for(int i = 0; i < blockStoreCount; i++) {
		blockStore[i] = new FILE_LINE(15048) pcap_block_store;
		strncpy(blockStore[i]->ifname, 
			this->readThreadsCount ? 
				this->readThreads[i]->getInterfaceAlias().c_str() :
				this->getInterfaceAlias().c_str(),
			sizeof(blockStore[i]->ifname) - 1);
	}
	unsigned long counter = 0;
	unsigned long pop_usleep_sum = 0;
	unsigned long pop_usleep_sum_last_push = 0;
	pcap_pkthdr_plus pcap_header_plus;
	u_char existsThreadTimeFlags[1000];
	unsigned int usleepCounter = 0;
	u_int64_t checkAllReadThreads_lastTime = 0;
	while(!TERMINATING) {
		bool fetchPacketOk = false;
		int minThreadTimeIndex = -1;
		int blockStoreIndex = 0;
		if(this->readThreadsCount) {
			u_int64_t minThreadTime = 0;
			if(this->readThreadsCount == 1) {
				minThreadTimeIndex = 0;
			} else {
				u_int64_t threadTime = 0;
				for(int i = 0; i < this->readThreadsCount; i++) {
					threadTime = this->readThreads[i]->getTIME_usec();
					if(threadTime) {
						if(minThreadTime == 0 || minThreadTime > threadTime) {
							minThreadTimeIndex = i;
							minThreadTime = threadTime;
						}
					}
					if(i < (int)sizeof(existsThreadTimeFlags)) {
						existsThreadTimeFlags[i] = threadTime > 0;
					}
				}
			}
			if(minThreadTimeIndex >= 0) {
				hpi = this->readThreads[minThreadTimeIndex]->POP();
				if(hpi.header_packet) {
					#if SNIFFER_THREADS_EXT
					if(sverb.sniffer_threads_ext && thread_data_main) {
						thread_data_main->inc_packets_in(hpi.header_packet->header.caplen);
					}
					#endif
					header_packet_fetch = &hpi.header_packet;
					if(!hpi.header_packet->detect_headers) {
						::pcapProcess(header_packet_fetch, -1,
							      NULL, 0,
							      ppf_na,
							      &ppd, this->readThreads[minThreadTimeIndex]->pcapLinklayerHeaderType, NULL, NULL);
					}
					header_ip_encaps_offset = hpi.header_packet->header_ip_encaps_offset;
					header_ip_offset = hpi.header_packet->header_ip_offset;
					pid = hpi.header_packet->pid;
					dlink = this->readThreads[minThreadTimeIndex]->pcapLinklayerHeaderType;
					blockStoreIndex = minThreadTimeIndex;
					fetchPacketOk = true;
				}
			}
			if(fetchPacketOk) {
				usleepCounter = 0;
				pop_usleep_sum = 0;
				pop_usleep_sum_last_push = 0;
			} else {
				pop_usleep_sum += USLEEP_C(100, usleepCounter++);
			}
			bool checkAllReadThreads = false;
			if(pop_usleep_sum > pop_usleep_sum_last_push + 100000) {
				if(this->readThreadsCount == 1) {
					if(!fetchPacketOk) {
						this->readThreads[0]->setForcePUSH();
					}
				} else {
					checkAllReadThreads = true;
				}
				pop_usleep_sum_last_push = pop_usleep_sum;
			} else if(fetchPacketOk && this->readThreadsCount > 1 &&
				  minThreadTime > checkAllReadThreads_lastTime + 250000) {
				checkAllReadThreads = true;
			}
			if(checkAllReadThreads) {
				int checkReadThreadsCount = min(this->readThreadsCount, (int)sizeof(existsThreadTimeFlags));
				for(int i = 0; i < checkReadThreadsCount; i++) {
					if(!existsThreadTimeFlags[i]) {
						this->readThreads[i]->setForcePUSH();
					}
				}
				checkAllReadThreads_lastTime = minThreadTime;
			}
		} else if(opt_scanpcapdir[0] && this->pcapEnd) {
			USLEEP(10000);
		} else {
			if(!headerPacketStack) {
				headerPacketStack = new FILE_LINE(15049) cHeaderPacketStack(opt_pcap_queue_iface_qring_size, get_pcap_snaplen());
				headerPacketStackAlloc = true;
			}
			if(!header_packet_read) {
				headerPacketStack->pop(&header_packet_read);
			}
			bool _useOneshotBuffer = useOneshotBuffer();
			if(_useOneshotBuffer) {
				setOneshotBuffer(HPP(header_packet_read));
			}
			pcap_pkthdr *pcap_next_ex_header;
			u_char *pcap_next_ex_packet;
			res = this->pcap_next_ex_iface(this->pcapHandle, &pcap_next_ex_header, &pcap_next_ex_packet);
			if(res == -1) {
				if(opt_scanpcapdir[0]) {
					this->pcapEnd = true;
				} else if(opt_pb_read_from_file[0]) {
					if(!opt_pcap_queue_compress && this->instancePcapFifo && opt_pcap_queue_suppress_t1_thread) {
						this->instancePcapFifo->addBlockStoreToPcapStoreQueue(blockStore[blockStoreIndex]);
					} else {
						blockStoreBypassQueue->push(blockStore[blockStoreIndex]);
					}
					++sumBlocksCounterIn[0];
					if(opt_nonstop_read) {
						blockStore[blockStoreIndex] = this->new_blockstore(blockStoreIndex);
					} else {
						blockStore[blockStoreIndex] = NULL;
					}
					terminatingAtEndOfReadPcap();
					if(opt_nonstop_read) {
						continue;
					} else {
						break;
					}
				}
			} else if(res == 0) {
				USLEEP(100);
			} else if(res > 0) {
				#if SNIFFER_THREADS_EXT
				if(sverb.sniffer_threads_ext && thread_data_main) {
					thread_data_main->inc_packets_in(pcap_next_ex_header->caplen);
				}
				#endif
				this->ppd.pid.clear();
				if(pcap_next_ex_header->caplen > get_pcap_snaplen()) {
					pcap_next_ex_header->caplen = get_pcap_snaplen();
				}
				memcpy_heapsafe(HPH(header_packet_read), header_packet_read,
						pcap_next_ex_header, NULL,
						sizeof(pcap_pkthdr));
				if(!_useOneshotBuffer) {
					memcpy_heapsafe(HPP(header_packet_read), header_packet_read,
							pcap_next_ex_packet, NULL,
							pcap_next_ex_header->caplen);
				}
				fetchPacketOk = true;
				if(opt_scanpcapdir[0] &&
				   !blockStore[blockStoreIndex]->dlink && blockStore[blockStoreIndex]->dlink != this->pcapLinklayerHeaderType) {
					blockStore[blockStoreIndex]->dlink = this->pcapLinklayerHeaderType;
				}
				res = this->pcapProcess(&header_packet_read, 0,
							NULL, 0,
							ppf_all, this->pcapDumpHandle);
				if(res == -1) {
					break;
				} else if(res == 0) {
					if(header_packet_read) {
						if(header_packet_read->stack) {
							header_packet_read->clearPcapProcessData();
						} else {
							DESTROY_HP(&header_packet_read);
						}
					}
					fetchPacketOk = false;
				}
				if(fetchPacketOk) {
					header_packet_fetch = &header_packet_read;
					header_ip_encaps_offset = this->ppd.header_ip_encaps_offset;
					header_ip_offset = this->ppd.header_ip_offset;
					pid = this->ppd.pid;
					/* check change packet content - disabled
					if(ip_tot_len && ip_tot_len != ((iphdr2*)(packet_pcap + 14))->tot_len) {
						static u_int64_t lastTimeLogErrBuggyKernel = 0;
						u_int64_t actTime = getTimeMS(header);
						if(actTime - 1000 > lastTimeLogErrBuggyKernel) {
							syslog(LOG_ERR, "SUSPICIOUS CHANGE PACKET CONTENT: buggy kernel - contact support@voipmonitor.org");
							lastTimeLogErrBuggyKernel = actTime;
						}
					}
					*/
				}
			}
		}
		if(fetchPacketOk) {
			#if TRACE_INVITE_BYE
			if(memmem(HPP(*header_packet_fetch), HPH(*header_packet_fetch)->caplen, "INVITE sip", 10)) {
				cout << "add INVITE" << endl;
			} else if(memmem(HPP(*header_packet_fetch), HPH(*header_packet_fetch)->caplen, "BYE sip", 7)) {
				cout << "add BYE " << endl;
			} else if(memmem(HPP(*header_packet_fetch), HPH(*header_packet_fetch)->caplen, "REGISTER sip", 12)) {
				cout << "add REGISTER " << endl;
			}
			#endif
			#if TRACE_MASTER_SECRET
			if(memmem(HPP(*header_packet_fetch), HPH(*header_packet_fetch)->caplen, "mastersecret", 12)) {
				cout << "add MASTERSECRET" << endl;
			}
			#endif
			#if TRACE_CALL
			if(sverb.trace_call) {
				trace_call(HPP(*header_packet_fetch), HPH(*header_packet_fetch)->caplen, 0,
					   (*header_packet_fetch)->detect_headers ? (*header_packet_fetch)->header_ip_offset : 0, getTimeUS(HPH(*header_packet_fetch)->ts),
					   NULL, 0,
					   __FILE__, __LINE__, __FUNCTION__, "before add to packetbuffer");
			}
			#endif
			++sumPacketsCounterIn[0];
			extern SocketSimpleBufferWrite *sipSendSocket;
			if(sipSendSocket) {
				this->processBeforeAddToPacketBuffer(HPH(*header_packet_fetch), HPP(*header_packet_fetch), header_ip_offset);
			}
			bool okAddPacket = false;
			while(!okAddPacket && !TERMINATING) {
				if(blockStore[blockStoreIndex]->full) {
					this->push_blockstore(&blockStore[blockStoreIndex]);
					++sumBlocksCounterIn[0];
					blockStore[blockStoreIndex] = this->new_blockstore(blockStoreIndex);
				}
				pcap_header_plus.convertFromStdHeader(HPH(*header_packet_fetch));
				pcap_header_plus.header_ip_encaps_offset = header_ip_encaps_offset;
				pcap_header_plus.header_ip_offset = header_ip_offset;
				pcap_header_plus.dlink = dlink;
				pcap_header_plus.pid = pid;
				if(this->block_qring) {
					if(blockStore[blockStoreIndex]->add_hp(&pcap_header_plus, (u_char*)header_packet_fetch, sizeof(sHeaderPacket*))) {
						okAddPacket = true;
						*header_packet_fetch = NULL;
					}
				} else {
					if(blockStore[blockStoreIndex]->add_hp(&pcap_header_plus, HPP(*header_packet_fetch))) {
						okAddPacket = true;
						PUSH_HP(header_packet_fetch, HEADER_PACKET_STACK_PUSH_QUEUE_MAX - 1);
					}
				}
			}
		}
		++counter;
		if(!fetchPacketOk || blockStoreCount > 1) {
			for(int i = 0; i < blockStoreCount; i++) {
				if((!fetchPacketOk || i != blockStoreIndex) &&
				   blockStore[i]->isFull_checkTimeout()) {
					this->push_blockstore(&blockStore[i]);
					++sumBlocksCounterIn[0];
					blockStore[i] = this->new_blockstore(i);
				}
			}
		}
	}
	
	if(header_packet_read) {
		DESTROY_HP(&header_packet_read);
	}
	
	for(int i = 0; i < blockStoreCount; i++) {
		if(blockStore[i]) {
			if(this->block_qring) {
				sHeaderPacket *hp;
				for(size_t j = 0; j < blockStore[i]->count; j++) {
					u_char *packetPos = blockStore[i]->block + blockStore[i]->offsets[j] + sizeof(pcap_pkthdr_plus);
					hp = *(sHeaderPacket**)packetPos;
					DESTROY_HP(&hp);
				}
			}
			delete blockStore[i];
		}
	}
	
	while(this->readThreadsCount) {
		unsigned counter = 0;
		while(!this->readThreads[this->readThreadsCount - 1]->isTerminated() && counter < 50) {
			USLEEP(100000);
			++counter;
		}
		if(!this->readThreads[this->readThreadsCount - 1]->isTerminated()) {
			this->readThreads[this->readThreadsCount - 1]->restoreOneshotBuffer();
			this->readThreads[this->readThreadsCount - 1]->cancelThread();
		}
		delete this->readThreads[this->readThreadsCount - 1];
		--this->readThreadsCount;
	}
	
	if(headerPacketStack && headerPacketStackAlloc) {
		delete headerPacketStack;
	}
	this->restoreOneshotBuffer();
	
	this->threadTerminated = true;
	
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		outStr << "stop thread t0 (" << this->nameQueue << ") /" << this->mainThreadId << endl;
		if(DEBUG_VERBOSE) {
			cout << outStr.str();
		} else {
			syslog(LOG_NOTICE, "%s", outStr.str().c_str());
		}
	}
	
	return(NULL);
}

void PcapQueue_readFromInterface::threadFunction_blocks() {
	pcap_block_store *blockStore;
	int readThreadIndex;
	unsigned int usleepCounter = 0;
	while(!TERMINATING) {
		readThreadIndex = -1;
		if(this->readThreadsCount == 1) {
			readThreadIndex = 0;
		} else {
			unsigned maxThreadSize = 0;
			unsigned threadSize = 0;
			for(int i = 0; i < this->readThreadsCount; i++) {
				threadSize = this->readThreads[i]->getSIZE();
				if(threadSize) {
					if(threadSize > maxThreadSize) {
						readThreadIndex = i;
						maxThreadSize = threadSize;
					}
				}
			}
		}
		blockStore = NULL;
		if(readThreadIndex >= 0) {
			blockStore = this->readThreads[readThreadIndex]->POP_BLOCK();
		}
		if(blockStore) {
			if(!opt_pcap_queue_compress && this->instancePcapFifo && opt_pcap_queue_suppress_t1_thread) {
				this->instancePcapFifo->addBlockStoreToPcapStoreQueue(blockStore);
			} else {
				this->check_bypass_buffer();
				blockStoreBypassQueue->push(blockStore);
			}
			usleepCounter = 0;
		} else {
			USLEEP_C(20, usleepCounter++);
		}
	}

	while(this->readThreadsCount) {
		unsigned counter = 0;
		while(!this->readThreads[this->readThreadsCount - 1]->isTerminated() && counter < 50) {
			USLEEP(100000);
			++counter;
		}
		if(!this->readThreads[this->readThreadsCount - 1]->isTerminated()) {
			this->readThreads[this->readThreadsCount - 1]->restoreOneshotBuffer();
			this->readThreads[this->readThreadsCount - 1]->cancelThread();
		}
		delete this->readThreads[this->readThreadsCount - 1];
		--this->readThreadsCount;
	}
	
	this->threadTerminated = true;
}

void *PcapQueue_readFromInterface::writeThreadFunction(void *arg, unsigned int arg2) {
	this->writeThreadId = get_unix_tid();
	#if SNIFFER_THREADS_EXT
	this->thread_data_write = cThreadMonitor::getSelfThreadData();
	#endif
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		outStr << "start thread t0 (" << this->nameQueue << " / write" << ") /" << this->writeThreadId << endl;
		if(DEBUG_VERBOSE) {
			cout << outStr.str();
		} else {
			syslog(LOG_NOTICE, "%s", outStr.str().c_str());
		}
	}
	if(this->initWriteThread(arg, arg2)) {
		this->writeThreadInitOk = true;
	} else {
		this->writeThreadTerminated = true;
		vm_terminate_error("packetbuffer initializing failed");
		return(NULL);
	}
	while(!this->initAllReadThreadsFinished) {
		if(is_terminating()) {
			return(NULL);
		}
		USLEEP(50000);
	}
	if(this->block_qring) {
		sHeaderPacket *hp;
		unsigned int usleepCounter = 0;
		while(!TERMINATING) {
			pcap_block_store *blockStore;
			if(this->block_qring->pop(&blockStore, false)) {
				#if SNIFFER_THREADS_EXT
				if(sverb.sniffer_threads_ext && thread_data_write) {
					thread_data_write->inc_packets_in(blockStore->size_packets, blockStore->count);
				}
				#endif
				for(size_t i = 0; i < blockStore->count; i++) {
					u_char *packetPos = blockStore->block + blockStore->offsets[i] + sizeof(pcap_pkthdr_plus);
					hp = *(sHeaderPacket**)packetPos;
					memcpy_heapsafe(packetPos, blockStore->block,
							HPP(hp), NULL,
							HPH(hp)->caplen,
							__FILE__, __LINE__);
					PUSH_HP(&hp, HEADER_PACKET_STACK_PUSH_QUEUE_MAX - 1);
				}
				this->check_bypass_buffer();
				blockStoreBypassQueue->push(blockStore);
				#if SNIFFER_THREADS_EXT
				if(sverb.sniffer_threads_ext && thread_data_write) {
					thread_data_write->inc_packets_out(blockStore->size_packets, blockStore->count);
				}
				#endif
				usleepCounter = 0;
			} else {
				USLEEP_C(100, usleepCounter++);
			}
		}
	}
	this->writeThreadId = get_unix_tid();
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		outStr << "stop thread t0 (" << this->nameQueue << " / write" << ") /" << this->writeThreadId << endl;
		if(DEBUG_VERBOSE) {
			cout << outStr.str();
		} else {
			syslog(LOG_NOTICE, "%s", outStr.str().c_str());
		}
	}
	return(NULL);
}

bool PcapQueue_readFromInterface::openFifoForWrite(void */*arg*/, unsigned int /*arg2*/) {
	return(true);
}

bool PcapQueue_readFromInterface::startCapture(string *error, sDpdkConfig *dpdkConfig) {
	*error = "";
	if(this->readThreadsCount) {
		return(true);
	}
	if(opt_scanpcapdir[0]) {
		this->pcapHandle = NULL;
		this->pcapHandleIndex = 0;
		this->pcapLinklayerHeaderType = 0;
		global_pcap_handle = this->pcapHandle;
		global_pcap_handle_index = this->pcapHandleIndex;
		global_pcap_dlink = this->pcapLinklayerHeaderType;
		return(true);
	}
	return(this->PcapQueue_readFromInterface_base::startCapture(error, dpdkConfig));
}

bool PcapQueue_readFromInterface::openPcap(const char *filename, string *tempFileName) {
	while(this->pcapHandlesLapsed.size() > 3) {
		pcap_close(this->pcapHandlesLapsed.front());
		this->pcapHandlesLapsed.pop();
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcapHandle = pcap_open_offline_zip(filename, errbuf, tempFileName);
	if(!pcapHandle) {
		syslog(LOG_ERR, "pcap_open_offline %s failed: %s", filename, errbuf); 
		return(false);
	}
	u_int16_t pcapHandleIndex = register_pcap_handle(pcapHandle);
	int pcapLinklayerHeaderType = pcap_datalink(pcapHandle);
	if(*user_filter != '\0') {
		if(this->filterDataUse) {
			pcap_freecode(&this->filterData);
			this->filterDataUse = false;
		}
		if (pcap_compile(pcapHandle, &this->filterData, user_filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
			char user_filter_err[2048];
			snprintf(user_filter_err, sizeof(user_filter_err), "%.2000s%s", user_filter, strlen(user_filter) > 2000 ? "..." : "");
			syslog(LOG_NOTICE, "packetbuffer - %s: can not parse filter %s: %s", filename, user_filter_err, pcap_geterr(pcapHandle));
			return(false);
		}
		if (pcap_setfilter(pcapHandle, &this->filterData) == -1) {
			char user_filter_err[2048];
			snprintf(user_filter_err, sizeof(user_filter_err), "%.2000s%s", user_filter, strlen(user_filter) > 2000 ? "..." : "");
			syslog(LOG_NOTICE, "packetbuffer - %s: can not install filter %s: %s", filename, user_filter_err, pcap_geterr(pcapHandle));
			return(false);
		}
		this->filterDataUse = true;
	}
	if(this->pcapHandle) {
		this->pcapHandlesLapsed.push(this->pcapHandle);
	}
	global_pcap_dlink = pcapLinklayerHeaderType;
	global_pcap_handle = pcapHandle;
	global_pcap_handle_index = pcapHandleIndex;
	this->pcapLinklayerHeaderType = pcapLinklayerHeaderType;
	this->pcapHandle = pcapHandle;
	this->pcapHandleIndex = pcapHandleIndex;
	this->pcapEnd = false;
	return(true);
}

unsigned long PcapQueue_readFromInterface::pcapStat_get_bypass_buffer_size_exeeded() {
	return(countBypassBufferSizeExceeded);
}

string PcapQueue_readFromInterface::pcapStatString_interface(int statPeriod) {
	ostringstream outStr;
	if(this->readThreadsCount) {
		if(opt_pcap_queue_pcap_stat_per_one_interface) {
			++this->lastReadThreadsIndex_pcapStatString_interface;
			if(this->lastReadThreadsIndex_pcapStatString_interface >= this->readThreadsCount) {
				this->lastReadThreadsIndex_pcapStatString_interface = 0;
			}
			outStr << this->readThreads[this->lastReadThreadsIndex_pcapStatString_interface]->pcapStatString_interface(statPeriod);
		} else {
			for(int i = 0; i < this->readThreadsCount; i++) {
				outStr << this->readThreads[i]->pcapStatString_interface(statPeriod);
			}
		}
	} else if(this->pcapHandle) {
		return(this->PcapQueue_readFromInterface_base::pcapStatString_interface(statPeriod));
	}
	return(outStr.str());
}

string PcapQueue_readFromInterface::pcapDropCountStat_interface() {
	ostringstream outStr;
	if(this->readThreadsCount) {
		for(int i = 0; i < this->readThreadsCount; i++) {
			string istat = this->readThreads[i]->pcapDropCountStat_interface();
			if(istat.length()) {
				if(outStr.str().length()) {
					outStr << " | ";
				}
				outStr << this->readThreads[i]->pcapDropCountStat_interface();
			}
		}
	} else if(this->pcapHandle || this->dpdkHandle) {
		return(this->PcapQueue_readFromInterface_base::pcapDropCountStat_interface());
	}
	return(outStr.str());
}

ulong PcapQueue_readFromInterface::getCountPacketDrop() {
	if(this->readThreadsCount) {
		ulong countPacketDrop = 0;
		for(int i = 0; i < this->readThreadsCount; i++) {
			countPacketDrop += this->readThreads[i]->getCountPacketDrop();
		}
		return(countPacketDrop);
	} else if(this->pcapHandle || this->dpdkHandle) {
		return(this->PcapQueue_readFromInterface_base::getCountPacketDrop());
	}
	return(0);
}

string PcapQueue_readFromInterface::getStatPacketDrop() {
	if(this->readThreadsCount) {
		string rslt = "";
		for(int i = 0; i < this->readThreadsCount; i++) {
			string subRslt = this->readThreads[i]->getStatPacketDrop();
			if(!subRslt.empty()) {
				if(!rslt.empty()) {
					rslt += " ";
				}
				rslt += subRslt;
			}
		}
		return(rslt);
	} else if(this->pcapHandle || this->dpdkHandle) {
		return(this->PcapQueue_readFromInterface_base::getStatPacketDrop());
	}
	return("");
}

void PcapQueue_readFromInterface::initStat_interface() {
	if(this->readThreadsCount) {
		for(int i = 0; i < this->readThreadsCount; i++) {
			this->readThreads[i]->initStat_interface();
		}
	} else if(this->pcapHandle) {
		this->PcapQueue_readFromInterface_base::initStat_interface();
	}
}

string PcapQueue_readFromInterface::pcapStatString_cpuUsageReadThreads(double *sumMax, int *countThreadsSumMax, int divide, int pstatDataIndex) {
	ostringstream outStrStat;
	outStrStat << fixed;
	if(sumMax) {
		*sumMax  = 0;
	}
	if(countThreadsSumMax) {
		*countThreadsSumMax = 0;
	}
	for(int i = 0; i < this->readThreadsCount; i++) {
		if(this->readThreads[i]->threadInitFailed) {
			continue;
		}
		double sum = 0;
		double countThreads = 1;
		double ti_cpu = this->readThreads[i]->getCpuUsagePerc(pstatDataIndex);
		if(ti_cpu >= 0) {
			sum += ti_cpu;
			outStrStat << "t0i_" << this->readThreads[i]->getInterfaceAlias() << "_CPU[";
			outStrStat << setprecision(1) << this->readThreads[i]->getTraffic(divide) << "Mb/s";
			outStrStat << ";main:" << setprecision(1) << ti_cpu;
			if(sverb.alloc_stat) {
				if(this->readThreads[i]->allocCounter[1] || this->readThreads[i]->allocStackCounter[1]) {
					unsigned long stack = this->readThreads[i]->allocStackCounter[0] - this->readThreads[i]->allocStackCounter[1];
					unsigned long alloc = this->readThreads[i]->allocCounter[0] - this->readThreads[i]->allocCounter[1];
					outStrStat << "%%a" << stack << ':' << alloc << ':';
					if(alloc + stack) {
						outStrStat << (stack * 100 / (alloc + stack));
					} else {
						outStrStat << '-';
					}
				}
				this->readThreads[i]->allocCounter[1] = this->readThreads[i]->allocCounter[0];
				this->readThreads[i]->allocStackCounter[1] = this->readThreads[i]->allocStackCounter[0];
			}
			if(this->readThreads[i]->dpdkWorkerThread) {
				++countThreads;
				double tid_cpu = this->readThreads[i]->dpdkWorkerThread->getCpuUsagePerc(pstatDataIndex);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/dpdk_worker:" << setprecision(1) << tid_cpu;
				}
			}
			if(this->readThreads[i]->dpdkHandle && dpdk_config(this->readThreads[i]->dpdkHandle)->type_read_thread == _dpdk_trt_rte) {
				for(unsigned rte_read_thread_id = 0; rte_read_thread_id < count_rte_read_threads(); rte_read_thread_id++) {
					++countThreads;
					double tid_cpu = rte_read_thread_cpu_usage(this->readThreads[i]->dpdkHandle, rte_read_thread_id);
					if(tid_cpu >= 0) {
						sum += tid_cpu;
						outStrStat << "%/dpdk_rte_read:" << setprecision(1) << tid_cpu;
					}
				}
			}
			if(this->readThreads[i]->dpdkHandle && dpdk_config(this->readThreads[i]->dpdkHandle)->type_worker_thread == _dpdk_twt_rte) {
				++countThreads;
				double tid_cpu = rte_worker_thread_cpu_usage(this->readThreads[i]->dpdkHandle);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/dpdk_rte_worker:" << setprecision(1) << tid_cpu;
					double tid_slave_cpu = rte_worker_slave_thread_cpu_usage(this->readThreads[i]->dpdkHandle);
					if(tid_slave_cpu >= 0) {
						sum += tid_slave_cpu;
						outStrStat << "/" << setprecision(1) << tid_slave_cpu;
					}
				}
			}
			if(this->readThreads[i]->dpdkHandle && dpdk_config(this->readThreads[i]->dpdkHandle)->type_worker2_thread == _dpdk_tw2t_rte) {
				++countThreads;
				double tid_cpu = rte_worker2_thread_cpu_usage(this->readThreads[i]->dpdkHandle);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/dpdk_rte_worker2:" << setprecision(1) << tid_cpu;
				}
			}
			if(this->readThreads[i]->detachThread) {
				++countThreads;
				double tid_cpu = this->readThreads[i]->detachThread->getCpuUsagePerc(pstatDataIndex);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/detach:" << setprecision(1) << tid_cpu;
					if(sverb.alloc_stat) {
						if(this->readThreads[i]->detachThread->allocCounter[1] || this->readThreads[i]->detachThread->allocStackCounter[1]) {
							unsigned long stack = this->readThreads[i]->detachThread->allocStackCounter[0] - this->readThreads[i]->detachThread->allocStackCounter[1];
							unsigned long alloc = this->readThreads[i]->detachThread->allocCounter[0] - this->readThreads[i]->detachThread->allocCounter[1];
							outStrStat << "%%a" << stack << ':' << alloc << ':';
							if(alloc + stack) {
								outStrStat << (stack * 100 / (alloc + stack));
							} else {
								outStrStat << '-';
							}
						}
						this->readThreads[i]->detachThread->allocCounter[1] = this->readThreads[i]->detachThread->allocCounter[0];
						this->readThreads[i]->detachThread->allocStackCounter[1] = this->readThreads[i]->detachThread->allocStackCounter[0];
					}
				}
			}
			if(this->readThreads[i]->pcapProcessThread) {
				++countThreads;
				double tid_cpu = this->readThreads[i]->pcapProcessThread->getCpuUsagePerc(pstatDataIndex);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/pcap_process:" << setprecision(1) << tid_cpu;
				}
			}
			if(this->readThreads[i]->defragThread) {
				++countThreads;
				double tid_cpu = this->readThreads[i]->defragThread->getCpuUsagePerc(pstatDataIndex);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/defrag:" << setprecision(1) << tid_cpu;
				}
			}
			if(this->readThreads[i]->md1Thread) {
				++countThreads;
				double tid_cpu = this->readThreads[i]->md1Thread->getCpuUsagePerc(pstatDataIndex);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/md1:" << setprecision(1) << tid_cpu;
				}
			}
			if(this->readThreads[i]->md2Thread) {
				++countThreads;
				double tid_cpu = this->readThreads[i]->md2Thread->getCpuUsagePerc(pstatDataIndex);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/md2:" << setprecision(1) << tid_cpu;
				}
			}
			if(this->readThreads[i]->dedupThread) {
				++countThreads;
				double tid_cpu = this->readThreads[i]->dedupThread->getCpuUsagePerc(pstatDataIndex);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/dedup:" << setprecision(1) << tid_cpu;
				}
			}
			if(this->readThreads[i]->serviceThread) {
				++countThreads;
				double tid_cpu = this->readThreads[i]->serviceThread->getCpuUsagePerc(pstatDataIndex);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/service:" << setprecision(1) << tid_cpu;
				}
			}
			outStrStat << "%] ";
			if(sumMax && sum > *sumMax) {
				*sumMax = sum;
				if(countThreadsSumMax) {
					*countThreadsSumMax = countThreads;
				}
			}
		}
	}
	return(outStrStat.str());
}

string PcapQueue_readFromInterface::getInterface() {
	if(opt_scanpcapdir[0]) {
		return(string("dir ") + opt_scanpcapdir);
	} else if(opt_pb_read_from_file[0]) {
		return(string("file ") + opt_pb_read_from_file);
	} else {
		return(this->PcapQueue_readFromInterface_base::getInterface());
	}
}

string PcapQueue_readFromInterface::getInterfaceAlias() {
	if(opt_scanpcapdir[0]) {
		return(string("dir ") + opt_scanpcapdir);
	} else if(opt_pb_read_from_file[0]) {
		return(string("file ") + opt_pb_read_from_file);
	} else {
		return(this->PcapQueue_readFromInterface_base::getInterfaceAlias());
	}
}

void PcapQueue_readFromInterface::prepareLogTraffic() {
	for(int i = 0; i < this->readThreadsCount; i++) {
		if(this->readThreads[i]->threadInitFailed) {
			continue;
		}
		this->readThreads[i]->prepareLogTraffic();
	}
}

void PcapQueue_readFromInterface::check_bypass_buffer() {
	size_t blockStoreBypassQueueSize = 0;
	bool countBypassBufferSizeExceeded_inc = false;
	unsigned int usleepCounter = 0;
	while(!TERMINATING && (blockStoreBypassQueueSize = blockStoreBypassQueue->getUseSize()) > opt_pcap_queue_bypass_max_size) {
		if(opt_scanpcapdir[0]) {
			USLEEP_C(100, usleepCounter++);
		} else {
			u_int64_t actTime = getTimeMS();
			if(actTime - 1000 > this->lastTimeLogErrThread0BufferIsFull) {
				syslog(LOG_ERR, "packetbuffer %s: THREAD0 BUFFER IS FULL", this->nameQueue.c_str());
				this->lastTimeLogErrThread0BufferIsFull = actTime;
				cout << "bypass buffer size " << blockStoreBypassQueue->getUseItems() << " (" << blockStoreBypassQueue->getUseSize() << ")" << endl;
			}
			if(!countBypassBufferSizeExceeded_inc) {
				++countBypassBufferSizeExceeded;
				countBypassBufferSizeExceeded_inc = true;
			}
			USLEEP_C(100, usleepCounter++);
		}
	}
}

void PcapQueue_readFromInterface::push_blockstore(pcap_block_store **block_store) {
	#if SNIFFER_THREADS_EXT
	if(sverb.sniffer_threads_ext && thread_data_main) {
		thread_data_main->inc_packets_out((*block_store)->size_packets, (*block_store)->count);
	}
	#endif
	if(!opt_pcap_queue_compress && this->instancePcapFifo && opt_pcap_queue_suppress_t1_thread) {
		this->instancePcapFifo->addBlockStoreToPcapStoreQueue(*block_store);
	} else if(this->block_qring) {
		bool useDiskBuffer = opt_pcap_queue_store_queue_max_disk_size && !opt_pcap_queue_disk_folder.empty();
		if(!useDiskBuffer ?
		    pcapQueueQ->checkIfMemoryBufferIsFull((*block_store)->getUseAllSize(), true) :
		    pcapQueueQ->checkIfDiskBufferIsFull(true)) {
			unsigned int usleepCounter = 0;
			do {
				if(TERMINATING) {
					break;
				}
				USLEEP_C(100, usleepCounter++);
			} while(!useDiskBuffer ?
				 pcapQueueQ->checkIfMemoryBufferIsFull((*block_store)->getUseAllSize(), true) :
				 pcapQueueQ->checkIfDiskBufferIsFull(true));
		}
		this->block_qring->push(block_store, true);
	} else {
		this->check_bypass_buffer();
		blockStoreBypassQueue->push(*block_store);
	}
}

pcap_block_store *PcapQueue_readFromInterface::new_blockstore(int index_read_thread) {
	pcap_block_store *blockStore = new FILE_LINE(15050) pcap_block_store;
	strncpy(blockStore->ifname, 
		this->readThreadsCount ? 
			this->readThreads[index_read_thread]->getInterfaceAlias().c_str() :
			this->getInterfaceAlias().c_str(), 
		sizeof(blockStore->ifname) - 1);
	return(blockStore);
}


PcapQueue_readFromFifo::PcapQueue_readFromFifo(const char *nameQueue, const char *fileStoreFolder) 
 : PcapQueue(readFromFifo, nameQueue),
   pcapStoreQueue(fileStoreFolder) {
	this->packetServerDirection = directionNA;
	for(int i = 0; i < DLT_TYPES_MAX; i++) {
		this->pcapDeadHandles[i] = NULL;
		this->pcapDeadHandlesIndex[i] = 0;
		this->pcapDeadHandles_dlt[i] = 0;
	}
	this->pcapDeadHandles_count = 0;
	this->destroyBlocksThreadHandle = 0;
	this->socketServerThreadHandle = 0;
	this->cleanupBlockStoreTrash_counter = 0;
	this->blockStoreTrash_sync = 0;
	this->blockStorePool_sync = 0;
	this->socketHostIP.clear();
	this->socketHandle = 0;
	this->clientSocket = NULL;
	this->_sync_packetServerConnections = 0;
	this->lastCheckFreeSizeCachedir_timeMS = 0;
	this->_last_ts.tv_sec = 0;
	this->_last_ts.tv_usec = 0;
	this->block_counter = 0;
	this->last_pb_send_confirmation_time_us = 0;
	this->setEnableMainThread(opt_pcap_queue_compress || is_receiver() ||
				  (opt_pcap_queue_disk_folder.length() && opt_pcap_queue_store_queue_max_disk_size) ||
				  !opt_pcap_queue_suppress_t1_thread);
	this->setEnableWriteThread();
}

PcapQueue_readFromFifo::~PcapQueue_readFromFifo() {
	if(this->packetServerDirection == directionRead) {
		this->cleanupConnections(true);
		syslog(LOG_NOTICE, "packetbuffer terminating (%s): cleanupConnections", nameQueue.c_str());
	}
	if(this->pcapDeadHandles_count) {
		for(int i = 0; i < this->pcapDeadHandles_count; i++) {
			if(this->pcapDeadHandles[i]) {
				pcap_close(this->pcapDeadHandles[i]);
			}
		}
		syslog(LOG_NOTICE, "packetbuffer terminating (%s): pcap_close pcapDeadHandles", nameQueue.c_str());
	}
	if(this->socketHandle) {
		this->socketClose();
		if(this->packetServerDirection == directionRead && this->mainThreadId) {
			pthread_join(this->socketServerThreadHandle, NULL);
		}
		syslog(LOG_NOTICE, "packetbuffer terminating (%s): socketClose", nameQueue.c_str());
	}
	if(this->destroyBlocksThreadHandle) {
		pthread_join(this->destroyBlocksThreadHandle, NULL);
	}
	if(this->threadHandle) {
		pthread_join(this->threadHandle, NULL);
	}
	if(this->writeThreadHandle) {
		pthread_join(this->writeThreadHandle, NULL);
	}
	if(this->clientSocket) {
		delete this->clientSocket;
	}
	this->cleanupBlockStoreTrash(true);
	syslog(LOG_NOTICE, "packetbuffer terminating (%s): cleanupBlockStoreTrash", nameQueue.c_str());
}

void PcapQueue_readFromFifo::setPacketServer(ip_port ipPort, ePacketServerDirection direction) {
	this->packetServerIpPort = ipPort;
	this->packetServerDirection = direction;
	if(direction == directionRead) {
		this->setEnableMainThread();
	}
}

bool PcapQueue_readFromFifo::addBlockStoreToPcapStoreQueue(u_char *buffer, u_char *buffer_alloc_begin, size_t bufferLen, string *error, string *warning, u_int32_t *block_counter, bool *require_confirmation) {
	*error = "";
	*warning = "";
	pcap_block_store *blockStore = new FILE_LINE(0) pcap_block_store;
	int rsltAddRestoreChunk = blockStore->addRestoreChunk(buffer, buffer_alloc_begin, bufferLen, NULL, false, error);
	if(bufferLen >= sizeof(pcap_block_store::pcap_block_store_header)) {
		*require_confirmation = ((pcap_block_store::pcap_block_store_header*)buffer)->require_confirmation;
	}
	if(rsltAddRestoreChunk > 0) {
		string *check_headers_error = NULL;
		if(!blockStore->check_offsets()) {
			*error = "bad offsets";
		} else if(!blockStore->size_compress && !blockStore->check_headers(&check_headers_error)) {
			*error = "bad headers";
			if(check_headers_error) {
				*error += " - " + *check_headers_error;
				delete check_headers_error;
			}
		}
	} else if(rsltAddRestoreChunk < 0) {
		if(error->empty()) {
			*error = blockStore->addRestoreChunk_getErrorString(rsltAddRestoreChunk);
		}
	} 
	if(error->empty()) {
		if(*block_counter == blockStore->block_counter) {
			delete blockStore;
		} else {
			if(*block_counter &&
			   *block_counter + 1 != blockStore->block_counter) {
				*warning = "loss packetbuffer block";
			}
			unsigned int usleepCounter = 0;
			while(!this->pcapStoreQueue.push(blockStore, false)) {
				if(TERMINATING) {
					break;
				} else {
					USLEEP_C(100, usleepCounter++);
				}
			}
			sumPacketsCounterIn[0] += blockStore->count;
			sumPacketsSize[0] += blockStore->getSizePackets();
			#if LOG_PACKETS_PER_SEC or LOG_PACKETS_SUM
			sumPacketsCount[0] += blockStore->getCountPackets();
			#endif
			sumPacketsSizeCompress[0] += blockStore->size_compress;
			++sumBlocksCounterIn[0];
			*block_counter = blockStore->block_counter;
		}
		return(true);
	} else {
		delete blockStore;
		return(false);
	}
}

string PcapQueue_readFromFifo::debugBlockStoreTrash() {
	ostringstream outStr;
	size_t sum_size = 0;
	lock_blockStoreTrash();
	for(unsigned i = 0; i < this->blockStoreTrash.size(); i++) {
		pcap_block_store *bs = this->blockStoreTrash[i];
		outStr << "* " << hex << bs << dec << endl;
		outStr << "* " << sqlDateTimeString_us2ms(bs->timestampMS * 1000) << endl;
		outStr << "lock packets: " << (int)bs->_sync_packet_lock << endl;
		outStr << "size: " << bs->getUseAllSize() << endl;
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		unsigned counter = 0;
		for(unsigned j = 0; j < bs->count; j++) {
			if(bs->_sync_packets_lock[j]) {
				outStr << (++counter) << " "
				       << j
				       << endl;
				#if DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH
				if(bs->_sync_packets_flag[j * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH]) {
					outStr << "   ";
					for(int k = 0; k < bs->_sync_packets_flag[j * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH]; k++) {
						if(k) {
							outStr << "/";
						}
						outStr << (int)((u_int8_t)bs->_sync_packets_flag[j * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH + k + 1]);
					}
					outStr << endl;
				}
				#endif
			}
		}
		#endif
		outStr << "---------" << endl;
		sum_size += bs->getUseAllSize();
	}
	unlock_blockStoreTrash();
	outStr << "SUM SIZE: " << sum_size
	       << " (" << (sum_size / 1024 / 1024) << "MB)" << endl;
	return(outStr.str());
}

string PcapQueue_readFromFifo::saveBlockStoreTrash(const char *filter, const char *destFile) {
	string rslt;
	#if DEBUG_SYNC_PCAP_BLOCK_STORE && DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH
	lock_blockStoreTrash();
	for(unsigned i = 0; i < this->blockStoreTrash.size(); i++) {
		pcap_block_store *bs = this->blockStoreTrash[i];
		ostringstream outStrMemPointer;
		outStrMemPointer << hex << bs;
		ostringstream outStrTime;
		outStrTime << sqlDateTimeString_us2ms(bs->timestampMS * 1000);
		if(outStrMemPointer.str() == filter ||
		   outStrTime.str() == filter) {
			PcapDumper *dumper = new FILE_LINE(0) PcapDumper(PcapDumper::na, NULL);
			dumper->setEnableAsyncWrite(false);
			dumper->setTypeCompress(FileZipHandler::compress_na);
			if(dumper->open(tsf_na, destFile, bs->dlink)) {
				unsigned counter = 0;
				for(unsigned j = 0; j < bs->count; j++) {
					if(bs->_sync_packets_lock[j]) {
						pcap_pkthdr_plus *header_plus = bs->get_header(j);
						pcap_pkthdr header = header_plus->getStdHeader();
						u_char *packet = bs->get_packet(j);
						dumper->dump(&header, packet, header_plus->dlink, true);
						++counter;
					}
				}
				rslt = "save " + intToString(counter) + " packets to file " + destFile;
			} else {
				rslt = string("failed open file ") + destFile;
			}
			delete dumper;
			break;
		}
	}
	if(rslt.empty()) {
		rslt = string("failed find block via filter ") + filter;
	}
	#else
	rslt = "unsupported: need compilation with define DEBUG_SYNC_PCAP_BLOCK_STORE";
	#endif
	unlock_blockStoreTrash();
	return(rslt);
}

bool PcapQueue_readFromFifo::checkIfMemoryBufferIsFull(unsigned size, bool log) {
	if(!buffersControl.check__pb__add_used(size)) {
		if(log) {
			this->pcapStoreQueue.memoryBufferIsFull_log();
		}
		return(true);
	} else {
		this->pcapStoreQueue.firstTimeLogErrMemoryIsFull = 0;
	}
	return(false);
}

bool PcapQueue_readFromFifo::checkIfDiskBufferIsFull(bool log) {
	if(this->pcapStoreQueue.getFileStoreUseSize(true) > opt_pcap_queue_store_queue_max_disk_size) {
		if(log) {
			this->pcapStoreQueue.diskBufferIsFull_log();
		}
		return(true);
	}
	return(false);
}

pcap_block_store *PcapQueue_readFromFifo::getBlockStoreFromPool() {
	pcap_block_store *block = NULL;
	lock_blockStorePool();
	if(blockStorePool.size()) {
		block = blockStorePool.front();
		blockStorePool.pop_front();
		buffersControl.sub__pb_pool_size(block->getUseAllSize());
	}
	unlock_blockStorePool();
	return(block);
}

inline void PcapQueue_readFromFifo::addBlockStoreToPcapStoreQueue(pcap_block_store *blockStore) {
	unsigned int usleepCounter = 0;
	while(!TERMINATING) {
		if(this->pcapStoreQueue.push(blockStore, false)) {
			sumPacketsSize[0] += blockStore->getSizePackets();
			break;
		} else {
			USLEEP_C(100, usleepCounter++);
		}
	}
}

void PcapQueue_readFromFifo::addBlockStoreToPcapStoreQueue_ext(pcap_block_store *blockStore) {
	addBlockStoreToPcapStoreQueue(blockStore);
}

bool PcapQueue_readFromFifo::createThread() {
	PcapQueue::createThread();
	if(this->packetServerDirection == directionRead) {
		this->createSocketServerThread();
	}
	if(this->packetServerDirection != directionWrite &&
	   opt_ipaccount) {
		this->createDestroyBlocksThread();
	}
	return(true);
}

bool PcapQueue_readFromFifo::createDestroyBlocksThread() {
	vm_pthread_create("pb - destroy blocks",
			  &this->destroyBlocksThreadHandle, NULL, _PcapQueue_readFromFifo_destroyBlocksThreadFunction, this, __FILE__, __LINE__);
	return(true);
}

bool PcapQueue_readFromFifo::createSocketServerThread() {
	vm_pthread_create("pb - server",
			  &this->socketServerThreadHandle, NULL, _PcapQueue_readFromFifo_socketServerThreadFunction, this, __FILE__, __LINE__);
	return(true);
}

bool PcapQueue_readFromFifo::initThread(void *arg, unsigned int arg2, string *error) {
	if(this->packetServerDirection == directionRead &&
	   !this->openPcapDeadHandle(0)) {
		return(false);
	}
	this->pcapStoreQueue.init();
	return(PcapQueue::initThread(arg, arg2, error));
}

void *PcapQueue_readFromFifo::threadFunction(void *arg, unsigned int arg2) {
	int tid = get_unix_tid();
	if(this->packetServerDirection == directionRead && arg2) {
		if(arg2 == (unsigned int)-1) {
			this->nextThreadsId[socketServerThread - nextThread1] = tid;
		} else {
			this->packetServerConnections[arg2]->threadId = tid;
			this->packetServerConnections[arg2]->active = true;
		}
	} else {
		this->mainThreadId = tid;
		#if SNIFFER_THREADS_EXT
		this->thread_data_main = cThreadMonitor::getSelfThreadData();
		#endif
	}
	vmIP _socketClientIP;
	vmPort _socketClientPort;
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		outStr << "start thread t1 (" << this->nameQueue;
		if(this->packetServerDirection == directionRead && arg2) {
			if(arg2 == (unsigned int)-1) {
				outStr << " socket server";
			} else {
				_socketClientIP = this->packetServerConnections[arg2]->socketClientIP;
				_socketClientPort = this->packetServerConnections[arg2]->socketClientPort;
				outStr << " " << _socketClientIP.getString() << ":" << _socketClientPort.getPort();
			}
		}
		outStr << ") /" << tid << endl;
		if(DEBUG_VERBOSE) {
			cout << outStr.str();
		} else {
			syslog(LOG_NOTICE, "%s", outStr.str().c_str());
		}
	}
	string error;
	if(this->initThread(arg, arg2, &error)) {
		this->threadInitOk = true;
	} else {
		this->threadTerminated = true;
		vm_terminate_error(error.c_str());
		return(NULL);
	}
	if(this->packetServerDirection == directionRead && arg2) {
		pcap_block_store *blockStore = new FILE_LINE(15051) pcap_block_store;
		size_t bufferSize = 1000;
		u_char *buffer = new FILE_LINE(15052) u_char[bufferSize * 2];
		size_t bufferLen;
		size_t offsetBufferSyncRead;
		size_t offsetBuffer;
		size_t readLen;
		bool syncBeginBlock = true;
		bool forceStop = false;
		unsigned countErrors = 0;
		u_int64_t lastTimeErrorLogMS = 0;
		while(!TERMINATING && !forceStop) {
			if(arg2 == (unsigned int)-1) {
				int socketClient;
				vmIP socketClientIP;
				vmPort socketClientPort;
				if(this->socketAwaitConnection(&socketClient, &socketClientIP, &socketClientPort)) {
					if(!TERMINATING && !forceStop) {
						syslog(LOG_NOTICE, "accept new connection from %s:%i, socket: %i", 
						       socketClientIP.getString().c_str(), socketClientPort.getPort(), socketClient);
						this->createConnection(socketClient, socketClientIP, socketClientPort);
					}
				}
			} else {
				int sensorId = 0;
				string sensorName;
				string sensorTime;
				bool detectSensorName = false;
				bool detectSensorTime = false;
				bufferLen = 0;
				offsetBufferSyncRead = 0;
				int require_confirmation = -1;
				unsigned counterEmptyData = 0;
				while(!TERMINATING && !forceStop) {
					readLen = bufferSize;
					if(!this->socketRead(buffer + offsetBufferSyncRead, &readLen, arg2)) {
						syslog(LOG_NOTICE, "close connection from %s:%i", 
						       this->packetServerConnections[arg2]->socketClientIP.getString().c_str(), 
						       this->packetServerConnections[arg2]->socketClientPort.getPort());
						this->packetServerConnections[arg2]->active = false;
						forceStop = true;
						break;
					}
					if(!(opt_pcap_queue_store_queue_max_disk_size &&
					     !opt_pcap_queue_disk_folder.empty())) {
						double heapPerc = buffersControl.getPerc_pb();
						if(heapPerc > 90) {
							syslog(LOG_NOTICE, "enforce close connection (heap is almost full) from %s:%i", 
							       this->packetServerConnections[arg2]->socketClientIP.getString().c_str(), 
							       this->packetServerConnections[arg2]->socketClientPort.getPort());
							this->packetServerConnections[arg2]->active = false;
							forceStop = true;
							USLEEP(500000);
							break;
						} else if(heapPerc > 85) {
							USLEEP(10000);
						} else if(heapPerc > 80) {
							USLEEP(1000);
						}
					}
					if(readLen) {
						counterEmptyData = 0;
						bufferLen += readLen;
						if(syncBeginBlock) {
							if(!detectSensorName) {
								char *pointToSensorIdName = (char*)memmem(buffer, bufferLen, "sensor_id_name: ", 16);
								if(pointToSensorIdName) {
									pointToSensorIdName += 16;
									unsigned int offset = 0;
									bool separator = 0;
									bool nullTerm = false;
									sensorName = "";
									while((unsigned)(pointToSensorIdName - (char*)buffer + offset) < bufferLen &&
									      (pointToSensorIdName[offset] == 0 ||
									       (pointToSensorIdName[offset] >= ' ' && (unsigned char)pointToSensorIdName[offset] < 128))) {
										if(pointToSensorIdName[offset] == 0) {
											if(separator) {
												nullTerm = true;
											}
											break;
										}
										if(offset == 0) {
											sensorId = atoi(pointToSensorIdName + offset);
										} else if(separator) {
											sensorName = sensorName + pointToSensorIdName[offset];
										} else if(pointToSensorIdName[offset] == ':') {
											separator = true;
										}
										++offset;
									}
									if(sensorId > 0 && sensorName.length() && nullTerm) {
										extern SensorsMap sensorsMap;
										sensorsMap.setSensorName(sensorId, sensorName.c_str());
										syslog(LOG_NOTICE, "detect sensor name: '%s' for sensor id: %i", sensorName.c_str(), sensorId);
										detectSensorName = true;
									}
								}
							}
							if(!detectSensorTime) {
								char *pointToSensorTime = (char*)memmem(buffer, bufferLen, "sensor_time: ", 13);
								if(pointToSensorTime) {
									pointToSensorTime += 13;
									unsigned int offset = 0;
									bool nullTerm = false;
									while((unsigned)(pointToSensorTime - (char*)buffer + offset) < bufferLen &&
									      (pointToSensorTime[offset] == 0 ||
									       (pointToSensorTime[offset] >= ' ' && (unsigned char)pointToSensorTime[offset] < 128))) {
										if(pointToSensorTime[offset] == 0) {
											nullTerm = true;
											break;
										}
										sensorTime = sensorTime + pointToSensorTime[offset];
										++offset;
									}
									if(sensorTime.length() && nullTerm) {
										syslog(LOG_NOTICE, "reported sensor time: %s for sensor id: %i", sensorTime.c_str(), sensorId);
										time_t actualTimeSec = time(NULL);
										time_t sensorTimeSec = stringToTime(sensorTime.c_str());
										extern int opt_mirror_connect_maximum_time_diff_s;
										int timeDiff = abs((int64_t)actualTimeSec - (int64_t)sensorTimeSec) % (3600/2);
										if(timeDiff > opt_mirror_connect_maximum_time_diff_s) {
											cLogSensor::log(cLogSensor::error, 
													"sensor is not allowed to connect because of different time",
													"Time difference between mirror receiver and sender (id_sensor:%i) is too big (%is). Please synchronise time on both mirror receiver and sender. Or increase configuration parameter mirror_connect_maximum_time_diff_s on mirror receiver.",
													sensorId,
													timeDiff);
											string message = "bad time";
											send(this->packetServerConnections[arg2]->socketClient, message.c_str(), message.length(), 0);	
											this->packetServerConnections[arg2]->active = false;
											forceStop = true;
											break;
										} else {
											string message = "ok";
											send(this->packetServerConnections[arg2]->socketClient, message.c_str(), message.length(), 0);
										}
										detectSensorTime = true;
									}
								}
							}
							u_char *pointToBeginBlock = (u_char*)memmem(buffer, bufferLen, PCAP_BLOCK_STORE_HEADER_STRING, PCAP_BLOCK_STORE_HEADER_STRING_LEN);
							if(pointToBeginBlock) {
								if(pointToBeginBlock > buffer) {
									u_char *buffer2 = new FILE_LINE(15053) u_char[bufferSize * 2];
									memcpy_heapsafe(buffer2, buffer2,
											pointToBeginBlock, buffer,
											bufferLen - (pointToBeginBlock - buffer),
											__FILE__, __LINE__);
									bufferLen -= (pointToBeginBlock - buffer);
									delete [] buffer;
									buffer = buffer2;
								}
								syncBeginBlock = false;
								blockStore->destroyRestoreBuffer();
								if(DEBUG_VERBOSE) {
									cout << "SYNCED" << endl;
								}
								syslog(LOG_INFO, "synchronize ok in connection %s - %i",
								       this->packetServerConnections[arg2]->socketClientIP.getString().c_str(), 
								       this->packetServerConnections[arg2]->socketClientPort.getPort());
							} else {
								if(offsetBufferSyncRead) {
									u_char *buffer2 = new FILE_LINE(15054) u_char[bufferSize * 2];
									memcpy_heapsafe(buffer2, buffer2,
											buffer + offsetBufferSyncRead, buffer,
											readLen,
											__FILE__, __LINE__);
									delete [] buffer;
									buffer = buffer2;
								}
								offsetBufferSyncRead = readLen;
								bufferLen = readLen;
								continue;
							}
						}
						offsetBuffer = 0;
						while(offsetBuffer < bufferLen) {
							string error;
							int rsltAddRestoreChunk = blockStore->addRestoreChunk(buffer, buffer, bufferLen, &offsetBuffer, false, &error); 
							if(rsltAddRestoreChunk > 0) {
								string *check_headers_error = NULL;
								if(!blockStore->check_offsets()) {
									error = "bad offsets";
								} else if(!blockStore->size_compress && !blockStore->check_headers(&check_headers_error)) {
									error = "bad headers";
									if(check_headers_error) {
										error += " - " + *check_headers_error;
										delete check_headers_error;
									}
								} else {
									if(require_confirmation < 0) {
										require_confirmation = blockStore->require_confirmation;
									}
									if(require_confirmation > 0 &&
									   send(this->packetServerConnections[arg2]->socketClient, "block_ok", 8, 0) != 8) {
										error = "send ok to sender failed";
									} else {
										if(this->packetServerConnections[arg2]->block_counter == blockStore->block_counter) {
											blockStore->destroyRestoreBuffer();
										} else {
											if(this->packetServerConnections[arg2]->block_counter &&
											   this->packetServerConnections[arg2]->block_counter + 1 != blockStore->block_counter) {
												syslog(LOG_ERR, "loss packetbuffer block in conection %s - %i",
												       this->packetServerConnections[arg2]->socketClientIP.getString().c_str(), 
												       this->packetServerConnections[arg2]->socketClientPort.getPort());
											}
											this->packetServerConnections[arg2]->block_counter = blockStore->block_counter;
											blockStore->sensor_ip = this->packetServerConnections[arg2]->socketClientIP;
											unsigned int usleepCounter = 0;
											while(!this->pcapStoreQueue.push(blockStore, false)) {
												if(TERMINATING || forceStop) {
													break;
												} else {
													USLEEP_C(100, usleepCounter++);
												}
											}
											sumPacketsCounterIn[0] += blockStore->count;
											sumPacketsSize[0] += blockStore->getSizePackets();
											#if LOG_PACKETS_PER_SEC or LOG_PACKETS_SUM
											sumPacketsCount[0] += blockStore->getCountPackets();
											#endif
											sumPacketsSizeCompress[0] += blockStore->size_compress;
											++sumBlocksCounterIn[0];
											blockStore = new FILE_LINE(15055) pcap_block_store;
										}
									}
								}
							} else if(rsltAddRestoreChunk < 0) {
								if(error.empty()) {
									error = blockStore->addRestoreChunk_getErrorString(rsltAddRestoreChunk);
								}
							} else {
								offsetBuffer = bufferLen;
							}
							if(!error.empty()) {
								send(this->packetServerConnections[arg2]->socketClient, error.c_str(), error.length(), 0);
								blockStore->destroyRestoreBuffer();
								syncBeginBlock = true;
								u_int64_t actTimeMS = getTimeMS();
								if(!lastTimeErrorLogMS ||
								   actTimeMS > lastTimeErrorLogMS + 1000) {
									cLogSensor::log(cLogSensor::error, 
											"error in receiving packets from mirror sender",
											"connection from %s, error: %s", 
											this->packetServerConnections[arg2]->socketClientIP.getString().c_str(),
											error.c_str());
									lastTimeErrorLogMS = actTimeMS;
								}
								++countErrors;
								if(countErrors > 20) {
									syslog(LOG_NOTICE, "enforce close connection (too errors) from %s:%i", 
									       this->packetServerConnections[arg2]->socketClientIP.getString().c_str(), 
									       this->packetServerConnections[arg2]->socketClientPort.getPort());
									this->packetServerConnections[arg2]->active = false;
									forceStop = true;
								}
								break;
							} else {
								countErrors = 0;
							}
						}
						bufferLen = 0;
						offsetBufferSyncRead = 0;
					} else {
						++counterEmptyData;
						if(counterEmptyData > 300) {
							syslog(LOG_NOTICE, "enforce close connection (too empty data) from %s:%i", 
							       this->packetServerConnections[arg2]->socketClientIP.getString().c_str(), 
							       this->packetServerConnections[arg2]->socketClientPort.getPort());
							this->packetServerConnections[arg2]->active = false;
							forceStop = true;
						} else {
							USLEEP(100);
						}
					}
				}
			}
		}
		delete [] buffer;
		delete blockStore;
	} else {
		if(opt_pcap_queue_compress || !opt_pcap_queue_suppress_t1_thread) {
			pcap_block_store *blockStore;
			unsigned int usleepCounter = 0;
			#if DEBUG_PB_BLOCKS_SEQUENCE
			u_int64_t pb_blocks_sequence_last = 0;
			#endif
			while(!TERMINATING) {
				blockStore = blockStoreBypassQueue->pop(false);
				if(!blockStore) {
					USLEEP_C(100, usleepCounter++);
					continue;
				}
				#if DEBUG_PB_BLOCKS_SEQUENCE
				if(blockStore) {
					if(blockStore->pb_blocks_sequence != pb_blocks_sequence_last + 1) {
						syslog(LOG_NOTICE, "bad pb_blocks_sequence: %lu / %lu %s:%i", 
						       blockStore->pb_blocks_sequence, pb_blocks_sequence_last + 1, 
						       __FILE__, __LINE__);
					}
					pb_blocks_sequence_last = blockStore->pb_blocks_sequence;
				}
				#endif
				size_t blockSize = blockStore->size;
				size_t blockSizePackets = blockStore->size_packets;
				#if LOG_PACKETS_PER_SEC or LOG_PACKETS_SUM
				size_t blockCountPackets = blockStore->count;
				#endif
				#if SNIFFER_THREADS_EXT
				size_t blockCountPackets = blockStore->count;
				if(sverb.sniffer_threads_ext && thread_data_main) {
					thread_data_main->inc_packets_in(blockSizePackets, blockCountPackets);
				}
				#endif
				if(blockStore->compress()) {
					if(this->pcapStoreQueue.push(blockStore, false)) {
						#if SNIFFER_THREADS_EXT
						if(sverb.sniffer_threads_ext && thread_data_main) {
							thread_data_main->inc_packets_out(blockSizePackets, blockCountPackets);
						}
						#endif
						sumPacketsSize[0] += blockSizePackets ? blockSizePackets : blockSize;
						#if LOG_PACKETS_PER_SEC or LOG_PACKETS_SUM
						sumPacketsCount[0] += blockCountPackets;
						#endif
						blockStoreBypassQueue->pop(true, blockSize);
						usleepCounter = 0;
					} else {
						USLEEP_C(100, usleepCounter++);
					}
				} else {
					blockStoreBypassQueue->pop(true, blockSize);
					usleepCounter = 0;
				}
			}
		}
	}
	this->threadTerminated = true;
	if(this->packetServerDirection == directionRead && arg2) {
		cleanupConnections();
	}
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		outStr << "stop thread t1 (" << this->nameQueue;
		if(this->packetServerDirection == directionRead && arg2) {
			if(arg2 == (unsigned int)-1) {
				outStr << " socket server";
			} else {
				outStr << " " << _socketClientIP.getString() << ":" << _socketClientPort.getPort();
			}
		}
		outStr << ") /" << tid << endl;
		if(DEBUG_VERBOSE) {
			cout << outStr.str();
		} else {
			syslog(LOG_NOTICE, "%s", outStr.str().c_str());
		}
	}
	return(NULL);
}

void *PcapQueue_readFromFifo::writeThreadFunction(void *arg, unsigned int arg2) {
	if(!(this->packetServerDirection == directionWrite || is_client_packetbuffer_sender())) {
		extern string opt_sched_pol_interface;
		pthread_set_priority(opt_sched_pol_interface);
	}
	this->writeThreadId = get_unix_tid();
	#if SNIFFER_THREADS_EXT
	this->thread_data_write = cThreadMonitor::getSelfThreadData();
	#endif
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		outStr << "start thread t2 (" << this->nameQueue << " / write" << ") /" << this->writeThreadId << endl;
		if(DEBUG_VERBOSE) {
			cout << outStr.str();
		} else {
			syslog(LOG_NOTICE, "%s", outStr.str().c_str());
		}
	}
	if(this->initWriteThread(arg, arg2)) {
		this->writeThreadInitOk = true;
	} else {
		this->writeThreadTerminated = true;
		vm_terminate_error("packetbuffer initializing failed");
		return(NULL);
	}
	pcap_block_store *blockStore;
	// dequeu - method 1
	map<pcap_block_store*, size_t> listBlockStore;
	map<u_int64_t, list<sPacketTimeInfo>* > listPacketTimeInfo;
	// dequeu - method 2
	int blockInfoCount = 0;
	int blockInfoCountMax = 500;
	u_int64_t blockInfo_utime_first = 0;
	u_int64_t blockInfo_utime_last = 0;
	u_int64_t blockInfo_at_first = 0;
	u_int64_t blockInfo_at_last = 0;
	sBlockInfo blockInfo[blockInfoCountMax];
	// dequeu - method 3
	sBlocksInfo blocksInfo(512);
	//
	unsigned int usleepCounter = 0;
	unsigned long usleepSumTime = 0;
	unsigned long usleepSumTime_lastPush = 0;
	sHeaderPacketPQout hp_out;
	u_int64_t cleanupBlockStoreTrash_at_ms = 0;
	#if DEBUG_PB_BLOCKS_SEQUENCE
	u_int64_t pb_blocks_sequence_last = 0;
	#endif
	//
	while(!TERMINATING) {
		if(DEBUG_SLEEP && access((this->pcapStoreQueue.fileStoreFolder + "/__/sleep").c_str(), F_OK ) != -1) {
			sleep(1);
		}
		this->pcapStoreQueue.pop(&blockStore);
		if(blockStore) {
			#if SNIFFER_THREADS_EXT
			if(sverb.sniffer_threads_ext && thread_data_write) {
				thread_data_write->inc_packets_in(blockStore->size_packets, blockStore->count);
			}
			#endif
			if(opt_cachedir[0]) {
				this->checkFreeSizeCachedir();
			}
			++sumBlocksCounterOut[0];
			#if DEBUG_PB_BLOCKS_SEQUENCE
			if(blockStore) {
				if(blockStore->pb_blocks_sequence != pb_blocks_sequence_last + 1) {
					syslog(LOG_NOTICE, "bad pb_blocks_sequence: %lu / %lu %s:%i", 
					       blockStore->pb_blocks_sequence, pb_blocks_sequence_last + 1, 
					       __FILE__, __LINE__);
				}
				pb_blocks_sequence_last = blockStore->pb_blocks_sequence;
			}
			#endif
		}
		if(this->packetServerDirection == directionWrite || is_client_packetbuffer_sender()) {
			if(blockStore) {
				this->socketWritePcapBlock(blockStore);
				this->blockStoreTrashPush(blockStore);
			}
		} else {
			if(blockStore) {
				if(blockStore->size_compress) {
					buffersControl.sub__pb_used_size(blockStore->getUseAllSize());
					if(blockStore->uncompress()) {
						buffersControl.add__pb_used_size(blockStore->getUseAllSize());
					} else {
						delete blockStore;
						blockStore = NULL;
					}
				}
				if(opt_ipaccount && blockStore) {
					blockStore->is_voip = new FILE_LINE(15056) u_int8_t[blockStore->count];
					memset(blockStore->is_voip, 0, blockStore->count);
				}
				#if TRACE_CALL
				if(sverb.trace_call) {
					for(size_t i = 0; i < blockStore->count; i++) {
						trace_call((*blockStore)[i].packet, (*blockStore)[i].header->header_fix_size.caplen, 0,
							   (*blockStore)[i].header->header_ip_offset, getTimeUS((*blockStore)[i].header->header_fix_size.ts_tv_sec, (*blockStore)[i].header->header_fix_size.ts_tv_usec),
							   NULL, 0,
							   __FILE__, __LINE__, __FUNCTION__, "before deque");
					}
				}
				#endif
				#if DEBUG_PACKET_DELAY_TEST
				int64_t system_time_ms = getTimeMS_rdtsc();
				int64_t system_time_ms_2 = getTimeMS();
				for(unsigned i = 0; i < blockStore->count; i++) {
					int64_t packet_time_ms = getTimeUS(blockStore->get_header(i)->header_fix_size.ts_tv_sec, blockStore->get_header(i)->header_fix_size.ts_tv_usec) / 1000;
					if(abs(system_time_ms - packet_time_ms) > DEBUG_PACKET_DELAY_TEST) {
						cout << " *D* "
						     << blockStore->ifname << ", " 
						     << system_time_ms - packet_time_ms << ", "
						     << system_time_ms_2 - packet_time_ms << endl;
					}
				}
				#endif
			}
			if((opt_pcap_queue_dequeu_window_length > 0 ||
			    opt_pcap_queue_dequeu_need_blocks > 0) &&
			   (opt_pcap_queue_dequeu_method == 1 || opt_pcap_queue_dequeu_method == 2 || opt_pcap_queue_dequeu_method == 3)) {
				int _opt_pcap_queue_dequeu_window_length = opt_pcap_queue_dequeu_window_length;
				int _opt_pcap_queue_dequeu_need_blocks = opt_pcap_queue_dequeu_need_blocks;
				if(opt_pcap_queue_dequeu_window_length_div > 0) {
					_opt_pcap_queue_dequeu_window_length = opt_pcap_queue_dequeu_window_length / opt_pcap_queue_dequeu_window_length_div;
				}
				if(opt_pcap_queue_dequeu_method == 1) {
					// TODO: is_ignore / maybe rather delete method 1 - not used
					u_int64_t at = getTimeUS();
					if(blockStore) {
						buffersControl.add__pb_used_dequeu_size(blockStore->getUseAllSize());
						listBlockStore[blockStore] = 0;
						for(size_t i = 0; i < blockStore->count; i++) {
							sPacketTimeInfo pti;
							pti.blockStore = blockStore;
							pti.blockStoreIndex = i;
							pti.header = (*blockStore)[i].header;
							pti.packet = (*blockStore)[i].packet;
							pti.utime = getTimeUS(
									      #if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
									      pti.header->header.ts.tv_sec, pti.header->header.ts.tv_usec
									      #else
									      pti.header->header_fix_size.ts_tv_sec, pti.header->header_fix_size.ts_tv_usec
									      #endif
									      );
							pti.at = at;
							map<u_int64_t, list<sPacketTimeInfo>* >::iterator iter = listPacketTimeInfo.find(pti.utime);
							if(iter != listPacketTimeInfo.end()) {
								iter->second->push_back(pti);
							} else {
								list<sPacketTimeInfo> *newList = new FILE_LINE(15057) list<sPacketTimeInfo>;
								newList->push_back(pti);
								listPacketTimeInfo[pti.utime] = newList;
							}
						}
					}
					if(listPacketTimeInfo.size()) {
						map<u_int64_t, list<sPacketTimeInfo>* >::iterator first = listPacketTimeInfo.begin();
						map<u_int64_t, list<sPacketTimeInfo>* >::iterator last = listPacketTimeInfo.end();
						--last;
						while(listPacketTimeInfo.size() && !TERMINATING) {
							if(_opt_pcap_queue_dequeu_need_blocks ?
							    (signed)listPacketTimeInfo.size() >= _opt_pcap_queue_dequeu_need_blocks :
							    (last->first - first->first > (unsigned)_opt_pcap_queue_dequeu_window_length * 1000 && 
							     at - first->second->begin()->at > (unsigned)_opt_pcap_queue_dequeu_window_length * 1000)) {
								sPacketTimeInfo pti = *(first->second->begin());
								first->second->pop_front();
								++sumPacketsCounterOut[0];
								hp_out.header = pti.header;
								hp_out.packet = pti.packet;
								hp_out.block_store = pti.blockStore;
								hp_out.block_store_index = pti.blockStoreIndex;
								hp_out.dlt = pti.header->dlink ? 
										pti.header->dlink : 
										pti.blockStore->dlink;
								hp_out.sensor_id = pti.blockStore->sensor_id;
								hp_out.sensor_ip = pti.blockStore->sensor_ip;
								hp_out.block_store_locked = false;
								hp_out.header_ip_last_offset = 0xFFFF;
								this->processPacket(&hp_out);
								#if SNIFFER_THREADS_EXT
								if(sverb.sniffer_threads_ext && thread_data_write) {
									thread_data_write->inc_packets_out(hp_out.header->get_caplen());
								}
								#endif
								++listBlockStore[pti.blockStore];
								if(listBlockStore[pti.blockStore] == pti.blockStore->count) {
									this->blockStoreTrashPush(pti.blockStore);
									buffersControl.sub__pb_used_dequeu_size(pti.blockStore->getUseAllSize());
									listBlockStore.erase(pti.blockStore);
								}
								if(first->second->empty()) {
									delete first->second;
									listPacketTimeInfo.erase(first);
									first = listPacketTimeInfo.begin();
								}
								usleepCounter = 0;
								usleepSumTime = 0;
								usleepSumTime_lastPush = 0;
							} else {
								break;
							}
						}
					}
				} else if(opt_pcap_queue_dequeu_method == 2) {
					u_int64_t at = getTimeUS();
					if(blockStore) {
						blockInfo[blockInfoCount].blockStore = blockStore;
						if(blockInfo[blockInfoCount].set_first_last()) {
							buffersControl.add__pb_used_dequeu_size(blockStore->getUseAllSize());
							blockInfo[blockInfoCount].set_time_first_last();
							blockInfo[blockInfoCount].at = at;
							if(!blockInfo_utime_first ||
							   blockInfo[blockInfoCount].utime_first < blockInfo_utime_first) {
								blockInfo_utime_first = blockInfo[blockInfoCount].utime_first;
							}
							if(!blockInfo_utime_last ||
							   blockInfo[blockInfoCount].utime_last > blockInfo_utime_last) {
								blockInfo_utime_last = blockInfo[blockInfoCount].utime_last;
							}
							if(!blockInfo_at_first ||
							   blockInfo[blockInfoCount].at < blockInfo_at_first) {
								blockInfo_at_first = blockInfo[blockInfoCount].at;
							}
							if(!blockInfo_at_last ||
							   blockInfo[blockInfoCount].at > blockInfo_at_last) {
								blockInfo_at_last = blockInfo[blockInfoCount].at;
							}
							++blockInfoCount;
							buffersControl.set_dequeu_time(blockInfo_utime_last > blockInfo_utime_first ?
											(blockInfo_utime_last - blockInfo_utime_first) / 1000 : 0);
						} else {
							this->blockStoreTrashPush(blockStore);
							buffersControl.sub__pb_used_dequeu_size(blockStore->getUseAllSize());
						}
					}
					while(blockInfoCount &&
					      (_opt_pcap_queue_dequeu_need_blocks ?
						blockInfoCount >= _opt_pcap_queue_dequeu_need_blocks :
						((blockInfo_utime_last - blockInfo_utime_first > (unsigned)_opt_pcap_queue_dequeu_window_length * 1000 &&
						  blockInfo_at_last - blockInfo_at_first > (unsigned)_opt_pcap_queue_dequeu_window_length * 1000) ||
						  at - blockInfo_at_first > (unsigned)_opt_pcap_queue_dequeu_window_length * 1000 * 4 ||
						  buffersControl.getPerc_pb_used_dequeu() > 20 ||
						  blockInfoCount == blockInfoCountMax)) &&
					      !TERMINATING) {
						u_int64_t minUtime = 0;
						int minUtimeIndexBlockInfo = -1;
						for(int i = 0; i < blockInfoCount; i++) {
							if(!minUtime ||
							   blockInfo[i].utime_first < minUtime) {
								minUtime = blockInfo[i].utime_first;
								minUtimeIndexBlockInfo = i;
							}
						}
						if(minUtimeIndexBlockInfo < 0) {
							continue;
						}
						sBlockInfo *actBlockInfo = &blockInfo[minUtimeIndexBlockInfo];
						hp_out.header = (*actBlockInfo->blockStore)[actBlockInfo->pos_act].header;
						hp_out.packet = (*actBlockInfo->blockStore)[actBlockInfo->pos_act].packet;
						hp_out.block_store = actBlockInfo->blockStore;
						hp_out.block_store_index = actBlockInfo->pos_act;
						hp_out.dlt = (*actBlockInfo->blockStore)[actBlockInfo->pos_act].header->dlink ? 
								(*actBlockInfo->blockStore)[actBlockInfo->pos_act].header->dlink :
								actBlockInfo->blockStore->dlink;
						hp_out.sensor_id = actBlockInfo->blockStore->sensor_id;
						hp_out.sensor_ip = actBlockInfo->blockStore->sensor_ip;
						hp_out.block_store_locked = false;
						hp_out.header_ip_last_offset = 0xFFFF;
						this->processPacket(&hp_out);
						#if SNIFFER_THREADS_EXT
						if(sverb.sniffer_threads_ext && thread_data_write) {
							thread_data_write->inc_packets_out(hp_out.header->get_caplen());
						}
						#endif
						if(!actBlockInfo->inc_pos_act()) {
							this->blockStoreTrashPush(actBlockInfo->blockStore);
							buffersControl.sub__pb_used_dequeu_size(actBlockInfo->blockStore->getUseAllSize());
							--blockInfoCount;
							for(int i = minUtimeIndexBlockInfo; i < blockInfoCount; i++) {
								memcpy(blockInfo + i, blockInfo + i + 1, sizeof(sBlockInfo));
							}
							blockInfo_utime_first = 0;
							blockInfo_utime_last = 0;
							blockInfo_at_first = 0;
							blockInfo_at_last = 0;
							for(int i = 0; i < blockInfoCount; i++) {
								if(!blockInfo_utime_first ||
								   blockInfo[i].utime_first < blockInfo_utime_first) {
									blockInfo_utime_first = blockInfo[i].utime_first;
								}
								if(!blockInfo_utime_last ||
								   blockInfo[i].utime_last > blockInfo_utime_last) {
									blockInfo_utime_last = blockInfo[i].utime_last;
								}
								if(!blockInfo_at_first ||
								   blockInfo[i].at < blockInfo_at_first) {
									blockInfo_at_first = blockInfo[i].at;
								}
								if(!blockInfo_at_last ||
								   blockInfo[i].at > blockInfo_at_last) {
									blockInfo_at_last = blockInfo[i].at;
								}
							}
						} else {
							actBlockInfo->update_time_first();
							blockInfo_utime_first = minUtime;
						}
						usleepCounter = 0;
						usleepSumTime = 0;
						usleepSumTime_lastPush = 0;
					}
				} else {
					u_int64_t at = getTimeUS();
					if(blockStore) {
						sBlockInfo new_block_info;
						new_block_info.blockStore = blockStore;
						if(new_block_info.set_first_last()) {
							buffersControl.add__pb_used_dequeu_size(blockStore->getUseAllSize());
							new_block_info.set_time_first_last();
							new_block_info.at = at;
							int new_block_info_index = blocksInfo.new_block();
							blocksInfo.set(new_block_info_index, &new_block_info);
							blocksInfo.update_times(new_block_info_index);
							sBlocksInfo::sMinHeapData minHeapData(new_block_info_index);
							blocksInfo.minHeap->insert(minHeapData);
							buffersControl.set_dequeu_time(blocksInfo.utime_last > blocksInfo.utime_first ?
											(blocksInfo.utime_last - blocksInfo.utime_first) / 1000 : 0);
						} else {
							this->blockStoreTrashPush(blockStore);
							buffersControl.sub__pb_used_dequeu_size(blockStore->getUseAllSize());
						}
					}
					while(blocksInfo.usedCount &&
					      (_opt_pcap_queue_dequeu_need_blocks ?
						blocksInfo.usedCount >= _opt_pcap_queue_dequeu_need_blocks :
						((blocksInfo.utime_last - blocksInfo.utime_first > (unsigned)_opt_pcap_queue_dequeu_window_length * 1000 &&
						  blocksInfo.at_last - blocksInfo.at_first > (unsigned)_opt_pcap_queue_dequeu_window_length * 1000) ||
						  at - blocksInfo.at_first > (unsigned)_opt_pcap_queue_dequeu_window_length * 1000 * 4 ||
						  buffersControl.getPerc_pb_used_dequeu() > 20 ||
						  blocksInfo.is_full())) &&
					      !TERMINATING) {
						int min_block_info_index = blocksInfo.minHeap->getMin();
						if(min_block_info_index < 0) {
							break;
						}
						sBlockInfo *minBlockInfo = &blocksInfo.blocks[min_block_info_index];
						hp_out.header = (*minBlockInfo->blockStore)[minBlockInfo->pos_act].header;
						hp_out.packet = (*minBlockInfo->blockStore)[minBlockInfo->pos_act].packet;
						hp_out.block_store = minBlockInfo->blockStore;
						hp_out.block_store_index = minBlockInfo->pos_act;
						hp_out.dlt = (*minBlockInfo->blockStore)[minBlockInfo->pos_act].header->dlink ? 
								(*minBlockInfo->blockStore)[minBlockInfo->pos_act].header->dlink :
								minBlockInfo->blockStore->dlink;
						hp_out.sensor_id = minBlockInfo->blockStore->sensor_id;
						hp_out.sensor_ip = minBlockInfo->blockStore->sensor_ip;
						hp_out.block_store_locked = false;
						hp_out.header_ip_last_offset = 0xFFFF;
						this->processPacket(&hp_out);
						#if SNIFFER_THREADS_EXT
						if(sverb.sniffer_threads_ext && thread_data_write) {
							thread_data_write->inc_packets_out(hp_out.header->get_caplen());
						}
						#endif
						if(!minBlockInfo->inc_pos_act()) {
							this->blockStoreTrashPush(minBlockInfo->blockStore);
							buffersControl.sub__pb_used_dequeu_size(minBlockInfo->blockStore->getUseAllSize());
							blocksInfo.free_block(min_block_info_index);
							blocksInfo.minHeap->extractMin();
							blocksInfo.update_times();
						} else {
							minBlockInfo->update_time_first();
							blocksInfo.minHeap->doHeapify();
						}
						usleepCounter = 0;
						usleepSumTime = 0;
						usleepSumTime_lastPush = 0;
					}
				}
			} else {
				if(blockStore) {
					for(size_t i = 0; i < blockStore->count && !TERMINATING; i++) {
						if(blockStore->is_ignore(i)) {
							continue;
						}
						++sumPacketsCounterOut[0];
						hp_out.header = (*blockStore)[i].header;
						hp_out.packet = (*blockStore)[i].packet;
						hp_out.block_store = blockStore;
						hp_out.block_store_index = i;
						hp_out.dlt = (*blockStore)[i].header->dlink ? 
								(*blockStore)[i].header->dlink :
								blockStore->dlink;
						hp_out.sensor_id = blockStore->sensor_id;
						hp_out.sensor_ip = blockStore->sensor_ip;
						hp_out.block_store_locked = false;
						hp_out.header_ip_last_offset = 0xFFFF;
						this->processPacket(&hp_out);
						#if SNIFFER_THREADS_EXT
						if(sverb.sniffer_threads_ext && thread_data_write) {
							thread_data_write->inc_packets_out(hp_out.header->get_caplen());
						}
						#endif
					}
					this->blockStoreTrashPush(blockStore);
					usleepCounter = 0;
					usleepSumTime = 0;
					usleepSumTime_lastPush = 0;
				}
			}
		}
		if(!blockStore) {
			extern unsigned int opt_push_batch_limit_ms;
			if(usleepSumTime > usleepSumTime_lastPush + opt_push_batch_limit_ms * 1000 &&
			   this->packetServerDirection != directionWrite) {
				this->pushBatchProcessPacket();
				usleepSumTime_lastPush = usleepSumTime;
			}
			usleepSumTime += USLEEP_C(100, usleepCounter++);
		}
		if(!(this->packetServerDirection != directionWrite &&
		     opt_ipaccount)) {
			double heap_pb_trash_perc = buffersControl.getPerc_pb_trash();
			if(heap_pb_trash_perc > 20) {
				this->cleanupBlockStoreTrash();
			} else if(!(++this->cleanupBlockStoreTrash_counter % 10)) {
				u_int64_t time_ms = getTimeMS_rdtsc();
				if(!cleanupBlockStoreTrash_at_ms || 
				   (time_ms > cleanupBlockStoreTrash_at_ms && time_ms - cleanupBlockStoreTrash_at_ms > 1000)) {
					this->cleanupBlockStoreTrash();
					cleanupBlockStoreTrash_at_ms = time_ms;
				}
			}
		}
	}
	if(opt_pcap_queue_dequeu_method == 1) {
		map<pcap_block_store*, size_t>::iterator iter;
		for(iter = listBlockStore.begin(); iter != listBlockStore.end(); iter++) {
			this->blockStoreTrashPush(iter->first);
		}
		while(listPacketTimeInfo.size()) {
			delete listPacketTimeInfo.begin()->second;
			listPacketTimeInfo.erase(listPacketTimeInfo.begin()->first);
		}
	} else if(opt_pcap_queue_dequeu_method == 2) {
		for(int i = 0; i < blockInfoCount; i++) {
			this->blockStoreTrashPush(blockInfo[i].blockStore);
		}
	} else if(opt_pcap_queue_dequeu_method == 3) {
		list<int> used;
		blocksInfo.get_used(&used);
		for(list<int>::iterator iter = used.begin(); iter != used.end(); iter++) {
			this->blockStoreTrashPush(blocksInfo.blocks[*iter].blockStore);
		}
	}
	this->writeThreadTerminated = true;
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		outStr << "stop thread t2 (" << this->nameQueue << " / write" << ") /" << this->writeThreadId << endl;
		if(DEBUG_VERBOSE) {
			cout << outStr.str();
		} else {
			syslog(LOG_NOTICE, "%s", outStr.str().c_str());
		}
	}
	return(NULL);
}

void *PcapQueue_readFromFifo::destroyBlocksThreadFunction(void */*arg*/, unsigned int /*arg2*/) {
	int tid = get_unix_tid();
	this->nextThreadsId[destroyBlocksThread - nextThread1] = tid;
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		outStr << "start thread t2 (" << this->nameQueue << " / destroy blocks" << ") /" << tid << endl;
		if(DEBUG_VERBOSE) {
			cout << outStr.str();
		} else {
			syslog(LOG_NOTICE, "%s", outStr.str().c_str());
		}
	}
	while(!TERMINATING) {
		if(this->blockStoreTrash.size() < 3) {
			USLEEP(1000);
			continue;
		}
		pcap_block_store *block = NULL;
		lock_blockStoreTrash();
		block = this->blockStoreTrash.front();
		u_int64_t actTimeMS = getTimeMS_rdtsc();
                if(block->enableDestroy() &&
                   block->timestampMS + 2000 < actTimeMS &&
                   block->getLastPacketHeaderTimeMS() + 2000 < actTimeMS) {
			this->blockStoreTrash.pop_front();
		} else {
			if(block->timestampMS + 10000 < actTimeMS &&
			   block->getLastPacketHeaderTimeMS() + 10000 < actTimeMS) {
				block = NULL;
				for(int i = 0; i < ((int)this->blockStoreTrash.size() - 5); i++) {
					if(this->blockStoreTrash[i]->enableDestroy() &&
					   this->blockStoreTrash[i]->timestampMS + 2000 < actTimeMS &&
					   this->blockStoreTrash[i]->getLastPacketHeaderTimeMS() + 2000 < actTimeMS) {
						block = this->blockStoreTrash[i];
						this->blockStoreTrash.erase(this->blockStoreTrash.begin() + i);
						break;
					}
				}
			} else {
				block = NULL;
			}
		} 
		unlock_blockStoreTrash();
		if(block) {
			if(opt_ipaccount) {
				for(size_t i = 0; i < block->count && !TERMINATING; i++) {
					pcap_block_store::pcap_pkthdr_pcap headerPcap = (*block)[i];
					#if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
					ipaccount(headerPcap.header->header.ts.tv_sec,
						  (iphdr2*)(headerPcap.packet + headerPcap.header->header_ip_offset),
						  headerPcap.header->header.len - headerPcap.header->header_ip_offset,
						  block->is_voip[i]);
					#else
					ipaccount(headerPcap.header->std ? headerPcap.header->header_std.ts.tv_sec : headerPcap.header->header_fix_size.ts_tv_sec,
						  (iphdr2*)(headerPcap.packet + headerPcap.header->header_ip_offset),
						  (headerPcap.header->std ? headerPcap.header->header_std.len : headerPcap.header->header_fix_size.len) - headerPcap.header->header_ip_offset,
						  block->is_voip[i]);
					#endif
				}
			}
			buffersControl.sub__pb_trash_size(block->getUseAllSize());
			if(opt_use_dpdk && opt_dpdk_rotate_packetbuffer &&
			   (opt_dpdk_copy_packetbuffer || opt_dpdk_prealloc_packetbuffer) &&
			   buffersControl.check__pb__add_pool(block->getUseAllSize())) {
				 buffersControl.add__pb_pool_size(block->getUseAllSize());
				 lock_blockStorePool();
				 blockStorePool.push_back(block);
				 unlock_blockStorePool();
			} else {
				delete block;
			}
		} else {
			USLEEP(1000);
			continue;
		}
	}
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		outStr << "stop thread t2 (" << this->nameQueue << " / destroy blocks" << ") /" << tid << endl;
		if(DEBUG_VERBOSE) {
			cout << outStr.str();
		} else {
			syslog(LOG_NOTICE, "%s", outStr.str().c_str());
		}
	}
	return(NULL);
}

bool PcapQueue_readFromFifo::openFifoForRead(void *arg, unsigned int arg2) {
	if(this->packetServerDirection == directionRead) {
		if(!arg2) {
			return(this->socketListen());
		} else {
			return(true);
		}
	} else {
		return(PcapQueue::openFifoForRead(arg, arg2));
	}
	return(false);
}

bool PcapQueue_readFromFifo::openFifoForWrite(void */*arg*/, unsigned int /*arg2*/) {
	if(this->packetServerDirection == directionWrite) {
		return(this->socketGetHost() &&
		       this->socketReadyForConnect());
	}
	return(true);
}

bool PcapQueue_readFromFifo::openPcapDeadHandle(int dlt) {
	if(this->pcapDeadHandles_count) {
		if(dlt) {
			for(int i = 0; i < this->pcapDeadHandles_count; i++) {
				if(dlt == this->pcapDeadHandles_dlt[i]) {
					return(true);
				}
			}
		} else {
			return(true);
		}
	}
	if(this->pcapDeadHandles_count >= DLT_TYPES_MAX) {
		syslog(LOG_ERR, "packetbuffer %s: limit the number of dlt exhausted", this->nameQueue.c_str()); 
		return(false);
	}
	if((this->pcapDeadHandles[this->pcapDeadHandles_count] = pcap_open_dead(dlt ? dlt : opt_pcap_queue_receive_dlt, 65535)) == NULL) {
		syslog(LOG_ERR, "packetbuffer %s: pcap_create failed", this->nameQueue.c_str()); 
		return(false);
	} else {
		this->pcapDeadHandlesIndex[this->pcapDeadHandles_count] = register_pcap_handle(this->pcapDeadHandles[this->pcapDeadHandles_count]);
		this->pcapDeadHandles_dlt[this->pcapDeadHandles_count] = dlt ? dlt : opt_pcap_queue_receive_dlt;
		++this->pcapDeadHandles_count;
	}
	/*
	char errbuf[PCAP_ERRBUF_SIZE];
	if((this->pcapDeadHandle = pcap_create("lo", errbuf)) == NULL) {
		syslog(LOG_ERR, "packetbuffer %s: pcap_create failed on iface %s: %s", this->nameQueue.c_str(), "lo", errbuf); 
		return(false);
	}
	int status;
	if((status = pcap_activate(this->pcapDeadHandle)) != 0) {
		syslog(LOG_ERR, "packetbuffer %s: libpcap error: %s", this->nameQueue.c_str(), pcap_geterr(this->pcapDeadHandle)); 
		return(false);
	}
	*/
	if(!dlt) {
		global_pcap_handle = this->pcapDeadHandles[0];
		global_pcap_handle_index = this->pcapDeadHandlesIndex[0];
	}
	return(true);
}

double PcapQueue_readFromFifo::pcapStat_get_disk_buffer_perc() {
	if(opt_pcap_queue_store_queue_max_disk_size &&
	   this->pcapStoreQueue.fileStoreFolder.length()) {
		double useSize = this->pcapStoreQueue.getFileStoreUseSize();
		return(100 * useSize / opt_pcap_queue_store_queue_max_disk_size);
	} else {
		return(-1);
	}
}

double PcapQueue_readFromFifo::pcapStat_get_disk_buffer_mb() {
	if(opt_pcap_queue_store_queue_max_disk_size &&
	   this->pcapStoreQueue.fileStoreFolder.length()) {
		double useSize = this->pcapStoreQueue.getFileStoreUseSize();
		return(useSize / 1024 / 1024);
	} else {
		return(-1);
	}
}

string PcapQueue_readFromFifo::getCpuUsage(bool writeThread, int pstatDataIndex, bool preparePstatData) {
	if(!writeThread && this->packetServerDirection == directionRead) {
		bool empty = true;
		ostringstream outStr;
		this->lock_packetServerConnections();
		map<unsigned int, sPacketServerConnection*>::iterator iter;
		for(iter = this->packetServerConnections.begin(); iter != this->packetServerConnections.end(); ++iter) {
			if(iter->second->active) {
				sPacketServerConnection *connection = iter->second;
				if(preparePstatData) {
					if(connection->threadPstatData[pstatDataIndex][0].cpu_total_time) {
						connection->threadPstatData[pstatDataIndex][1] = connection->threadPstatData[pstatDataIndex][0];
					}
					pstat_get_data(connection->threadId, connection->threadPstatData[pstatDataIndex]);
				}
				if(connection->threadPstatData[pstatDataIndex][0].cpu_total_time &&
				   connection->threadPstatData[pstatDataIndex][1].cpu_total_time) {
					double ucpu_usage, scpu_usage;
					pstat_calc_cpu_usage_pct(
						&connection->threadPstatData[pstatDataIndex][0], &connection->threadPstatData[pstatDataIndex][1],
						&ucpu_usage, &scpu_usage);
					double cpu_usage = ucpu_usage + scpu_usage;
					if(empty) {
						outStr << "t1CPU[";
						empty = false;
					} else {
						outStr << "/";
					}
					outStr << fixed << setprecision(1) << cpu_usage << "%";
				}
			}
		}
		this->unlock_packetServerConnections();
		if(!empty) {
			outStr << "]";
		}
		return(outStr.str());
	}
	return("");
}

bool PcapQueue_readFromFifo::socketWritePcapBlock(pcap_block_store *blockStore) {
	++block_counter;
	if(is_client_packetbuffer_sender()) {
		return(socketWritePcapBlockBySnifferClient(blockStore));
	}
	bool rslt = false;
	unsigned counterSleep = 0;
	while(!TERMINATING) {
		size_t sizeSaveBuffer = blockStore->getSizeSaveBuffer();
		u_char *saveBuffer = blockStore->getSaveBuffer(block_counter);
		if(!opt_pcap_queues_mirror_require_confirmation ||
		   buffersControl.getPerc_pb() > 70) {
			((pcap_block_store::pcap_block_store_header*)saveBuffer)->time_s = 0;
		}
		rslt = this->socketWrite(saveBuffer, sizeSaveBuffer);
		delete [] saveBuffer;
		if(rslt) {
			if(opt_pcap_queues_mirror_require_confirmation) {
				char recv_data[1000] = "";
				size_t recv_data_len = sizeof(recv_data);
				bool rsltRead = this->_socketRead(this->socketHandle, (u_char*)recv_data, &recv_data_len, 4);
				if(rsltRead && recv_data_len > 0) {
					if(!memcmp(recv_data, "block_ok", 8)) {
						break;
					} else {
						syslog(LOG_ERR, "response from receiver: %s - try send block again", string(recv_data, recv_data_len).c_str());
						sleep(counterSleep < 10 ? 1 : 5);
						++counterSleep;
					}
				} else {
					syslog(LOG_ERR, "%s response from receiver - try send block again", recv_data_len ? "unknown" : "no");
					sleep(counterSleep < 10 ? 1 : 5);
					++counterSleep;
				}
			} else {
				break;
			}
		}
	}
	return(rslt);
}

bool PcapQueue_readFromFifo::socketWritePcapBlockBySnifferClient(pcap_block_store *blockStore) {
	bool ok = false;
	unsigned maxPass = 100000;
	for(unsigned int pass = 0; pass < maxPass; pass++) {
		if(is_terminating() > 1 && pass > 2) {
			break;
		}
		if(pass > 0) {
			if(this->clientSocket) {
				delete this->clientSocket;
				this->clientSocket = NULL;
			}
			if(is_terminating()) {
				USLEEP(100000);
			} else {
				sleep(pass < 10 ? 1 : 5);
			}
			syslog(LOG_INFO, "send packetbuffer block - next attempt %u", pass);
		}
		if(!this->clientSocket) {
			if(sverb.packetbuffer_send) {
				syslog(LOG_NOTICE, "packetbuffer block - create connection");
			}
			this->clientSocket = new FILE_LINE(0) cSocketBlock("packetbuffer block", true);
			this->clientSocket->setHostsPort(snifferClientOptions.hosts, snifferClientOptions.port);
			if(!this->clientSocket->connect()) {
				syslog(LOG_ERR, "send packetbuffer block error: %s", "failed connect to server");
				pcapQueueQ->externalError = "send packetbuffer block error: failed connect to server";
				continue;
			}
			string cmd = "{\"type_connection\":\"packetbuffer block\"}\r\n";
			if(!this->clientSocket->write(cmd)) {
				syslog(LOG_ERR, "send packetbuffer block error: %s", "failed send command");
				pcapQueueQ->externalError = "send packetbuffer block error: failed send command";
				continue;
			}
			string rsltRsaKey;
			if(!this->clientSocket->readBlock(&rsltRsaKey) || rsltRsaKey.find("key") == string::npos) {
				syslog(LOG_ERR, "send packetbuffer block error: %s", "failed read rsa key");
				pcapQueueQ->externalError = "send packetbuffer block error: failed read rsa key";
				continue;
			}
			JsonItem jsonRsaKey;
			jsonRsaKey.parse(rsltRsaKey);
			string rsa_key = jsonRsaKey.getValue("rsa_key");
			this->clientSocket->set_rsa_pub_key(rsa_key);
			this->clientSocket->generate_aes_keys();
			JsonExport json_keys;
			json_keys.add("password", snifferServerClientOptions.password);
			string aes_ckey, aes_ivec;
			this->clientSocket->get_aes_keys(&aes_ckey, &aes_ivec);
			json_keys.add("aes_ckey", aes_ckey);
			json_keys.add("aes_ivec", aes_ivec);
			json_keys.add("time", sqlDateTimeString(time(NULL)).c_str());
			json_keys.add("sensor_id", opt_id_sensor);
			json_keys.add("sensor_name", opt_name_sensor);
			if(!this->clientSocket->writeBlock(json_keys.getJson(), cSocket::_te_rsa)) {
				syslog(LOG_ERR, "send packetbuffer block error: %s", "failed send token & aes keys");
				pcapQueueQ->externalError = "";
				continue;
			}
			string connectResponse;
			if(!this->clientSocket->readBlock(&connectResponse) || connectResponse != "OK") {
				if(!this->clientSocket->isError() && connectResponse != "OK") {
					string errorStr = connectResponse == "bad time" ?
							   "different time between server and client" :
							   connectResponse;
					syslog(LOG_ERR, "send packetbuffer block error: %s", ("failed response from server - " + errorStr).c_str());
					pcapQueueQ->externalError = "send packetbuffer block error: failed response from server - " + errorStr;
					delete this->clientSocket;
					this->clientSocket = NULL;
				} else {
					syslog(LOG_ERR, "send packetbuffer block error: %s", "failed read ok");
					pcapQueueQ->externalError = "send packetbuffer block error: failed read ok";
				}
				continue;
			}
		}
		bool okSendBlock = true;
		size_t sizeSaveBuffer = blockStore->getSizeSaveBuffer();
		u_char *saveBuffer = blockStore->getSaveBuffer(block_counter);
		bool require_confirmation = opt_pcap_queues_mirror_require_confirmation;
		if(require_confirmation &&
		   buffersControl.getPerc_pb() > 30 &&
		   last_pb_send_confirmation_time_us > 20 * 1000) {
			((pcap_block_store::pcap_block_store_header*)saveBuffer)->require_confirmation = false;
			require_confirmation = false;
		}
		if(!require_confirmation ||
		   buffersControl.getPerc_pb() > 70) {
			((pcap_block_store::pcap_block_store_header*)saveBuffer)->time_s = 0;
		}
		u_int64_t start_write_us = 0;
		if(sverb.packetbuffer_send) {
			start_write_us = getTimeUS();
		}
		if(!this->clientSocket->writeBlock(saveBuffer, sizeSaveBuffer, cSocket::_te_aes)) {
			okSendBlock = false;
		}
		if(sverb.packetbuffer_send) {
			u_int64_t end_write_us = getTimeUS();
			syslog(LOG_NOTICE, "packetbuffer block - send %s - "
					   "size %.3lfkB, "
					   "packets: %" int_64_format_prefix "lu, "
					   "time: %" int_64_format_prefix "luus, "
					   "speed: %.3lfMB/s"
					   "%s",
			       okSendBlock ? "OK" : "FAILED",
			       (double)sizeSaveBuffer / 1e3,
			       blockStore->count,
			       end_write_us - start_write_us,
			       (double)sizeSaveBuffer / (end_write_us - start_write_us),
			       opt_pcap_queues_mirror_require_confirmation && !require_confirmation ? ", suppress confirmation" : "");
		}
		delete [] saveBuffer;
		if(!okSendBlock) {
			syslog(LOG_ERR, "send packetbuffer block error: %s", "failed send");
			pcapQueueQ->externalError = "send packetbuffer block error: failed send";
			continue;
		}
		if(require_confirmation) {
			u_int64_t start_confirmation_us;
			u_int64_t end_confirmation_us;
			if(sverb.packetbuffer_send) {
				start_confirmation_us = getTimeUS();
			} else {
				start_confirmation_us = getTimeMS_rdtsc() * 1000;
			}
			string response;
			if(!this->clientSocket->readBlock(&response, cSocket::_te_aes)) {
				syslog(LOG_ERR, "send packetbuffer block error: %s", "failed read response");
				pcapQueueQ->externalError = "send packetbuffer block error: failed read response";
				continue;
			}
			if(sverb.packetbuffer_send) {
				end_confirmation_us = getTimeUS();
				syslog(LOG_NOTICE, "packetbuffer block - confirmation %s - time: %" int_64_format_prefix "luus",
				       response == "OK" ? "OK" : "FAILED",
				       end_confirmation_us - start_confirmation_us);
			} else {
				end_confirmation_us = getTimeMS_rdtsc() * 1000;
			}
			last_pb_send_confirmation_time_us = end_confirmation_us > start_confirmation_us ? end_confirmation_us - start_confirmation_us : 0;
			if(response == "OK") {
				ok = true;
				break;
			} else {
				syslog(LOG_ERR, "send packetbuffer block error: %s", response.empty() ? "response is empty" : ("bad response - " + response).c_str());
				pcapQueueQ->externalError = "send packetbuffer block error: " + (response.empty() ? "response is empty" : ("bad response - " + response));
				if(response.find("bad header") != string::npos) {
					maxPass = pass + 10;
				}
			}
		} else {
			ok = true;
			break;
		}
	}
	return(ok);
}

bool PcapQueue_readFromFifo::socketGetHost() {
	this->socketHostIP.clear();
	while(!this->socketHostIP.isSet()) {
		this->socketHostIP = cResolver::resolve_n(this->packetServerIpPort.get_ip().c_str());
		if(!this->socketHostIP.isSet()) {
			syslog(LOG_ERR, "packetbuffer %s: cannot resolv: %s: host [%s] - trying again", this->nameQueue.c_str(), hstrerror(h_errno), this->packetServerIpPort.get_ip().c_str());  
			sleep(1);
		}
	}
	if(DEBUG_VERBOSE) {
		cout << "socketGetHost [" << this->packetServerIpPort.get_ip() << "] : OK" << endl;
	}
	return(true);
}

bool PcapQueue_readFromFifo::socketReadyForConnect() {
	return(true);
}

bool PcapQueue_readFromFifo::socketConnect() {
	if(!this->socketHostIP.isSet()) {
		this->socketGetHost();
	}
	if((this->socketHandle = socket_create(this->socketHostIP, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		syslog(LOG_ERR, "packetbuffer %s: cannot create socket - trying again", this->nameQueue.c_str());
		return(false);
	}
	if(socket_connect(this->socketHandle, this->socketHostIP, this->packetServerIpPort.get_port()) == -1) {
		syslog(LOG_ERR, "packetbuffer %s: failed to connect to server [%s] error:[%s] - trying again", this->nameQueue.c_str(), this->socketHostIP.getString().c_str(), strerror(errno));
		this->socketClose();
		return(false);
	}
	int flag = 1;
	setsockopt(this->socketHandle, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));
	if(opt_pcap_queues_mirror_nonblock_mode) {
		int flags = fcntl(this->socketHandle, F_GETFL, 0);
		if(flags >= 0) {
			fcntl(this->socketHandle, F_SETFL, flags | O_NONBLOCK);
		}
	}
	if(DEBUG_VERBOSE) {
		cout << this->nameQueue << " - socketConnect: " << this->packetServerIpPort.get_ip() << " : OK" << endl;
	}
	char dataSensorIdName[1024];
	snprintf(dataSensorIdName, sizeof(dataSensorIdName), "sensor_id_name: %i:%s", opt_id_sensor, opt_name_sensor);
	if(!socketWrite((u_char*)dataSensorIdName, strlen(dataSensorIdName) + 1, true)) {
		syslog(LOG_ERR, "packetbuffer write sensor_id_name failed - trying again");
		this->socketClose();
		return(false);
	}
	char dataTime[40];
	snprintf(dataTime, sizeof(dataTime), "sensor_time: %s", sqlDateTimeString(time(NULL)).c_str());
	if(!socketWrite((u_char*)dataTime, strlen(dataTime) + 1, true)) {
		syslog(LOG_ERR, "packetbuffer write sensor_time failed - trying again");
		this->socketClose();
		return(false);
	}
	char recv_data[100] = "";
	size_t recv_data_len = sizeof(recv_data);
	bool rsltRead = this->_socketRead(this->socketHandle, (u_char*)recv_data, &recv_data_len, 4);
	if(rsltRead) {
		if(recv_data_len > 0 &&
		   memmem(recv_data, recv_data_len,  "bad time", 8)) {
			syslog(LOG_ERR, "different time between receiver and sender - trying again");
			this->socketClose();
			return(false);
		}
	} else {
		this->socketClose();
		return(false);
	}
	return(true);
}

bool PcapQueue_readFromFifo::socketListen() {
	if((this->socketHandle = socket_create(str_2_vmIP(this->packetServerIpPort.get_ip().c_str()), SOCK_STREAM, IPPROTO_TCP)) == -1) {
		syslog(LOG_NOTICE, "packetbuffer %s: cannot create socket", this->nameQueue.c_str());
		return(false);
	}
	if(opt_pcap_queues_mirror_nonblock_mode) {
		int flags = fcntl(this->socketHandle, F_GETFL, 0);
		if(flags >= 0) {
			fcntl(this->socketHandle, F_SETFL, flags | O_NONBLOCK);
		}
	}
	int on = 1;
	setsockopt(this->socketHandle, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	int rsltListen;
	do {
		while(socket_bind(this->socketHandle, str_2_vmIP(this->packetServerIpPort.get_ip().c_str()), this->packetServerIpPort.get_port()) == -1 && !TERMINATING) {
			syslog(LOG_ERR, "packetbuffer %s: cannot bind to port [%d] - trying again after 5 seconds intervals", this->nameQueue.c_str(), this->packetServerIpPort.get_port());
			sleep(5);
		}
		if(TERMINATING) {
			return(false);
		}
		rsltListen = listen(this->socketHandle, 512);
		if(rsltListen == -1) {
			syslog(LOG_ERR, "packetbuffer %s: listen failed - retrying in 5 seconds intervals", this->nameQueue.c_str());
			sleep(5);
		}
	} while(rsltListen == -1);
	return(true);
}

bool PcapQueue_readFromFifo::socketAwaitConnection(int *socketClient, vmIP *socketClientIP, vmPort *socketClientPort) {
	*socketClient = -1;
	while(*socketClient < 0 && !TERMINATING) {
		bool doAccept = false;
		int timeout = 1;
		if(opt_socket_use_poll) {
			pollfd fds[2];
			memset(fds, 0 , sizeof(fds));
			fds[0].fd = this->socketHandle;
			fds[0].events = POLLIN;
			if(poll(fds, 1, timeout * 1000) > 0) {
				doAccept = true;
			}
		} else {
			fd_set rfds;
			FD_ZERO(&rfds);
			FD_SET(this->socketHandle, &rfds);
			struct timeval tv;
			tv.tv_sec = timeout;
			tv.tv_usec = 0;
			if(select(this->socketHandle + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv) > 0) {
				doAccept = true;
			}
		}
		if(doAccept) {
			*socketClient = socket_accept(this->socketHandle, socketClientIP, socketClientPort);
			if(opt_pcap_queues_mirror_nonblock_mode) {
				int flags = fcntl(*socketClient, F_GETFL, 0);
				if(flags >= 0) {
					fcntl(*socketClient, F_SETFL, flags | O_NONBLOCK);
				}
			}
		}
		USLEEP(100000);
	}
	return(*socketClient >= 0);
}

bool PcapQueue_readFromFifo::socketClose() {
	if(this->socketHandle) {
		close(this->socketHandle);
		this->socketHandle = 0;
	}
	return(true);
}

bool PcapQueue_readFromFifo::socketWrite(u_char *data, size_t dataLen, bool disableAutoConnect) {
	if(!this->socketHandle && !disableAutoConnect) {
		while(!this->socketConnect()) {
			for(int i = 0; i < 20; i++) {
				USLEEP(100000);
				if(TERMINATING) {
					return(false);
				}
			}
		}
	}
	size_t dataLenWrited = 0;
	while(dataLenWrited < dataLen && !TERMINATING) {
		size_t _dataLenWrited = dataLen - dataLenWrited;
		if(!this->_socketWrite(this->socketHandle, data + dataLenWrited, &_dataLenWrited)) {
			if(!disableAutoConnect) {
				this->socketClose();
				while(!this->socketConnect()) {
					for(int i = 0; i < 20; i++) {
						USLEEP(100000);
						if(TERMINATING) {
							return(false);
						}
					}
				}
			} else {
				return(false);
			}
		} else {
			dataLenWrited += _dataLenWrited;
		}
	}
	return(true);
}

bool PcapQueue_readFromFifo::_socketWrite(int socket, u_char *data, size_t *dataLen, int timeout) {
	if(opt_pcap_queues_mirror_nonblock_mode) {
		bool doWrite = false;
		if(opt_socket_use_poll) {
			pollfd fds[2];
			memset(fds, 0 , sizeof(fds));
			fds[0].fd = socket;
			fds[0].events = POLLOUT;
			int rsltPool = poll(fds, 1, timeout * 1000);
			if(rsltPool < 0) {
				return(false);
			}
			if(rsltPool > 0 && fds[0].revents) {
				doWrite = true;
			}
		} else {
			fd_set wfds;
			FD_ZERO(&wfds);
			FD_SET(socket, &wfds);
			struct timeval tv;
			tv.tv_sec = timeout;
			tv.tv_usec = 0;
			int rsltSelect = select(socket + 1, (fd_set *) 0, &wfds, (fd_set *) 0, &tv);
			if(rsltSelect < 0) {
				return(false);
			}
			if(rsltSelect > 0 && FD_ISSET(socket, &wfds)) {
				doWrite = true;
			}
		}
		if(doWrite) {
			ssize_t writeLen = send(socket, data, *dataLen, 0);
			if(writeLen <= 0) {
				return(false);
			}
			*dataLen = writeLen;
		}
	} else {
		ssize_t writeLen = send(socket, data, *dataLen, 0);
		if(writeLen <= 0) {
			return(false);
		}
		*dataLen = writeLen;
	}
	return(true);
}

bool PcapQueue_readFromFifo::socketRead(u_char *data, size_t *dataLen, int idConnection) {
	return(this->_socketRead(this->packetServerConnections[idConnection]->socketClient, 
				 data, dataLen));
}

bool PcapQueue_readFromFifo::_socketRead(int socket, u_char *data, size_t *dataLen, int timeout) {
	size_t maxDataLen = *dataLen;
	*dataLen = 0;
	if(opt_pcap_queues_mirror_nonblock_mode) {
		bool doRead = false;
		if(opt_socket_use_poll) {
			pollfd fds[2];
			memset(fds, 0 , sizeof(fds));
			fds[0].fd = socket;
			fds[0].events = POLLIN;
			int rsltPool = poll(fds, 1, timeout * 1000);
			if(rsltPool < 0) {
				return(false);
			}
			if(rsltPool > 0 && fds[0].revents) {
				doRead = true;
			}
		} else {
			fd_set rfds;
			FD_ZERO(&rfds);
			FD_SET(socket, &rfds);
			struct timeval tv;
			tv.tv_sec = timeout;
			tv.tv_usec = 0;
			int rsltSelect = select(socket + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv);
			if(rsltSelect < 0) {
				return(false);
			}
			if(rsltSelect > 0 && FD_ISSET(socket, &rfds)) {
				doRead = true;
			}
		}
		if(doRead) {
			ssize_t recvLen = recv(socket, data, maxDataLen, 0);
			if(recvLen <= 0) {
				return(false);
			}
			*dataLen = recvLen;
		}
	} else {
		ssize_t recvLen = recv(socket, data, maxDataLen, 0);
		if(recvLen <= 0) {
			return(false);
		}
		*dataLen = recvLen;
	}
	return(true);
}

void PcapQueue_readFromFifo::createConnection(int socketClient, vmIP socketClientIP, vmPort socketClientPort) {
	this->cleanupConnections();
	this->lock_packetServerConnections();
	unsigned int id = 1;
	map<unsigned int, sPacketServerConnection*>::iterator iter;
	for(iter = this->packetServerConnections.begin(); iter != this->packetServerConnections.end(); ++iter) {
		if(iter->first >= id) {
			id = iter->first + 1; 
		}
	}
	sPacketServerConnection *connection = new FILE_LINE(15058) sPacketServerConnection(socketClient, socketClientIP, socketClientPort, this, id);
	connection->active = true;
	this->packetServerConnections[id] = connection;
	this->unlock_packetServerConnections();
	vm_pthread_create_autodestroy(("pb - client " + connection->socketClientIP.getString()).c_str(), 
				      &connection->threadHandle, NULL, _PcapQueue_readFromFifo_connectionThreadFunction, connection, __FILE__, __LINE__);
}

void PcapQueue_readFromFifo::cleanupConnections(bool all) {
	this->lock_packetServerConnections();
	map<unsigned int, sPacketServerConnection*>::iterator iter;
	for(iter = this->packetServerConnections.begin(); iter != this->packetServerConnections.end();) {
		if(all && iter->second->active) {
			if(iter->second->socketClient) {
				close(iter->second->socketClient);
				iter->second->socketClient = 0;
			}
			iter->second->active = false;
		}
		if(!iter->second->active) {
			delete iter->second; 
			this->packetServerConnections.erase(iter++);
		} else {
			++iter;
		}
	}
	this->unlock_packetServerConnections();
}

void PcapQueue_readFromFifo::processPacket(sHeaderPacketPQout *hp) {
 
	#if TRAFFIC_DUMPER
	extern TrafficDumper *trafficDumper;
	if(trafficDumper) {
		pcap_pkthdr *header = hp->header->convertToStdHeader();
		trafficDumper->dump(header, hp->packet, hp->dlt, 
				    hp->block_store && hp->block_store->ifname[0] ? hp->block_store->ifname : "undefined");
	}
	#endif
 
	sumPacketsSizeOut[0] += hp->header->get_caplen();
	#if LOG_PACKETS_PER_SEC or LOG_PACKETS_SUM
	++sumPacketsCountOut[0];
	#endif
	
	extern int opt_sleepprocesspacket;
	if(opt_sleepprocesspacket) {
		usleep(100000);
	}
 
	extern int opt_blockprocesspacket;
	if(sverb.disable_process_packet_in_packetbuffer ||
	   opt_blockprocesspacket ||
	   (hp->block_store && hp->block_store->hm == pcap_block_store::plus2 && ((pcap_pkthdr_plus2*)hp->header)->ignore)) {
		return;
	}

	/*
	if((long)hp->block_store == 0x60e000022b00 &&
	   hp->block_store_index == 1245) {
		cout << "break 1" << endl;
	}
	*/
	
	if(pcapQueueQ_outThread_detach) {
		pcapQueueQ_outThread_detach->push(hp);
		return;
	} else if(pcapQueueQ_outThread_defrag) {
		pcapQueueQ_outThread_defrag->push(hp);
		return;
	} else if(pcapQueueQ_outThread_dedup) {
		pcapQueueQ_outThread_dedup->push(hp);
		return;
	} else if(pcapQueueQ_outThread_detach2) {
		pcapQueueQ_outThread_detach2->push(hp);
		return;
	}
	 
	/*
	if((long)hp->block_store == 0x60e000022b00 &&
	   hp->block_store_index == 1245) {
		cout << "break 2" << endl;
	}
	*/
	
	if(processPacket_analysis(hp)) {
		processPacket_push(hp);
	}
}

bool PcapQueue_readFromFifo::processPacket_analysis(sHeaderPacketPQout* hp) {

	pcap_pkthdr *header = hp->header->convertToStdHeader();
	
	if(header->caplen > header->len) {
		extern BogusDumper *bogusDumper;
		if(bogusDumper) {
			bogusDumper->dump(header, hp->packet, hp->dlt, "process_packet");
		}
		if(verbosity) {
			static u_int64_t lastTimeSyslog = 0;
			u_int64_t actTime = getTimeMS();
			if(actTime - 1000 > lastTimeSyslog) {
				syslog(LOG_NOTICE, "warning - incorrect caplen/len (%u/%u) in processPacket", header->caplen, header->len);
				lastTimeSyslog = actTime;
			}
		}
		return(false);
	}
	
	if(!this->_last_ts.tv_sec) {
		this->_last_ts.tv_sec = header->ts.tv_sec;
		this->_last_ts.tv_usec = header->ts.tv_usec;
	} else if(getTimeUS(this->_last_ts) > getTimeUS(header) + 1000) {
		if(verbosity > 1 || enable_bad_packet_order_warning) {
			static u_int64_t lastTimeSyslog = 0;
			u_int64_t actTime = getTimeMS();
			if(actTime - 1000 > lastTimeSyslog) {
				syslog(LOG_NOTICE, "warning - bad packet order (%" int_64_format_prefix "lu us) in processPacket", 
				       getTimeUS(this->_last_ts) - getTimeUS(header));
				lastTimeSyslog = actTime;
			}
		}
	} else {
		this->_last_ts.tv_sec = header->ts.tv_sec;
		this->_last_ts.tv_usec = header->ts.tv_usec;
	}
	
	iphdr2 *header_ip_encaps = hp->header->header_ip_encaps_offset != 0xFFFF ?
				    (iphdr2*)(hp->packet + hp->header->header_ip_encaps_offset) : 
				    NULL;
	iphdr2 *header_ip = hp->header_ip_last_offset != 0xFFFF ?
			     (iphdr2*)(hp->packet + hp->header_ip_last_offset) :
			    hp->header->header_ip_offset != 0xFFFF ?
			     (iphdr2*)(hp->packet + hp->header->header_ip_offset) :
			     NULL;

	if(header_ip && hp->header_ip_last_offset == 0xFFFF) {
		while(true) {
			int next_header_ip_offset = findNextHeaderIp(header_ip, hp->header->header_ip_offset, 
								     hp->packet, hp->header->get_caplen());
			if(next_header_ip_offset == 0) {
				break;
			} else if(next_header_ip_offset < 0) {
				return(false);
			} else {
				header_ip = (iphdr2*)((u_char*)header_ip + next_header_ip_offset);
				hp->header->header_ip_offset += next_header_ip_offset;
			}
		}
	}
	
	char *data = NULL;
	int datalen = 0;
	packet_flags pflags;
	pflags.init();
	vmPort sport;
	vmPort dport;
	u_int8_t header_ip_protocol = 0;
	if(header_ip) {
		if(hp->header->get_caplen() <= hp->header->header_ip_offset) {
			return(false);
		}
		header_ip_protocol = header_ip->get_protocol(hp->header->get_caplen() - hp->header->header_ip_offset);
		if(header_ip_protocol == IPPROTO_UDP) {
			udphdr2 *header_udp = (udphdr2*)((char*) header_ip + header_ip->get_hdr_size());
			datalen = get_udp_data_len(header_ip, header_udp, &data, hp->packet, header->caplen);
			sport = header_udp->get_source();
			dport = header_udp->get_dest();
			pflags.set_ss7(opt_enable_ss7 && (ss7_rudp_portmatrix[sport] || ss7_rudp_portmatrix[dport]));
		} else if(header_ip_protocol == IPPROTO_TCP) {
			tcphdr2 *header_tcp = (tcphdr2*)((char*)header_ip + header_ip->get_hdr_size());
			datalen = get_tcp_data_len(header_ip, header_tcp, &data, hp->packet, header->caplen);
			pflags.set_tcp(1);
			sport = header_tcp->get_source();
			dport = header_tcp->get_dest();
			if(opt_enable_ss7 && (ss7portmatrix[sport] || ss7portmatrix[dport])) {
				pflags.set_ss7(true);
			} else if(cFilters::saveMrcp() && IS_MRCP(data, datalen)) {
				pflags.set_mrcp(true);
			}
		} else if(opt_enable_ss7 && header_ip_protocol == IPPROTO_SCTP) {
			pflags.set_ss7(true);
			datalen = get_sctp_data_len(header_ip, &data, hp->packet, header->caplen);
		} else {
			//packet is not UDP and is not TCP, we are not interested, go to the next packet
			return(false);
		}
	} else if(opt_enable_ss7) {
		data = (char*)hp->packet;
		datalen = header->caplen;
		pflags.set_ss7(true);
	}
	
	if(!data || datalen < 0 || datalen > 0xFFFFF ||
	   (data - (char*)hp->packet) > header->caplen) {
		extern BogusDumper *bogusDumper;
		if(bogusDumper) {
			bogusDumper->dump(header, hp->packet, hp->dlt, "process_packet");
		}
		if(verbosity &&
		   !(opt_udpfrag && opt_pcap_queue_use_blocks)) {
			static u_int64_t lastTimeSyslog = 0;
			u_int64_t actTime = getTimeMS();
			if(actTime - 1000 > lastTimeSyslog) {
				syslog(LOG_NOTICE, "warning - incorrect dataoffset/caplen (%zd/%u) in processPacket", (size_t)(data - (char*)hp->packet), header->caplen);
				lastTimeSyslog = actTime;
			}
		}
		return(false);
	}
	
	#if EXPERIMENTAL_SEPARATE_PROCESSSING
	if(separate_processing()) {
		bool is_rtp = datalen > 2 && IS_RTP(data, datalen);
		if(separate_processing() == 1 ? is_rtp : !is_rtp) {
			return(false);
		}
	}
	#endif
	
	#if TRACE_INVITE_BYE
	if(memmem(data, datalen, "INVITE sip", 10)) {
		cout << "processPacket INVITE" << endl;
	} else if(memmem(data, datalen, "BYE sip", 7)) {
		cout << "processPacket BYE " << endl;
	} else if(memmem(data, datalen, "REGISTER sip", 12)) {
		cout << "processPacket REGISTER " << endl;
	}
	#endif
	#if TRACE_CALL
	if(sverb.trace_call) {
		trace_call(hp->packet, header->caplen, 0,
			   0, getTimeUS(header->ts),
			   (u_char*)data, datalen,
			   __FILE__, __LINE__, __FUNCTION__, "process packet");
	}
	#endif
	
	hp->header_ip_offset = header_ip ? (u_int16_t)((u_char*)header_ip - hp->packet) : 0xFFFF;
	hp->header_ip_encaps_offset = header_ip_encaps ? (u_int16_t)((u_char*)header_ip_encaps - hp->packet) : 0xFFFF;
	hp->header_ip_protocol = header_ip_protocol;
	hp->pflags =  pflags;
	hp->sport = sport;
	hp->dport = dport;
	hp->data_offset = data ? (u_int16_t)((u_char*)data - hp->packet) : 0xFFFF;;
	hp->datalen = datalen;

	return(true);
}

bool PcapQueue_readFromFifo::processPacket_push(sHeaderPacketPQout *hp) {

	#if USE_PACKET_NUMBER
	static u_int64_t packet_counter_all;
	++packet_counter_all;
	#endif
	
	#if DEBUG_ALLOC_PACKETS
	if(!hp->block_store) {
		debug_alloc_packet_set(hp->packet, "PcapQueue_readFromFifo::processPacket_push");
	}
	#endif
	
	pcap_pkthdr *header = hp->header->convertToStdHeader();
	
	iphdr2 *header_ip_encaps = hp->header_ip_encaps_offset != 0xFFFF ? (iphdr2*)(hp->packet + hp->header_ip_encaps_offset) : NULL;
	iphdr2 *header_ip = hp->header_ip_offset != 0xFFFF ? (iphdr2*)(hp->packet + hp->header_ip_offset) : NULL;
	
	if(opt_mirrorip && header_ip && (sipportmatrix[hp->sport] || sipportmatrix[hp->dport])) {
		mirrorip->send((char *)header_ip, (int)(header->caplen - ((u_char*)header_ip - hp->packet)));
	}
	
	if(hp->header_ip_protocol == IPPROTO_TCP) {
		if(opt_enable_http && (httpportmatrix[hp->sport] || httpportmatrix[hp->dport]) && 
		   tcpReassemblyHttp->check_ip(header_ip->get_saddr(), header_ip->get_daddr())) {
			tcpReassemblyHttp->push_tcp(header, header_ip, hp->packet, !hp->block_store,
						    hp->block_store, hp->block_store_index, hp->block_store_locked,
						    this->getPcapHandleIndex(hp->dlt), hp->dlt, hp->sensor_id, hp->sensor_ip, hp->header->pid);
			return(true);
		} else if(opt_enable_webrtc && (webrtcportmatrix[hp->sport] || webrtcportmatrix[hp->dport]) &&
			  tcpReassemblyWebrtc->check_ip(header_ip->get_saddr(), header_ip->get_daddr())) {
			tcpReassemblyWebrtc->push_tcp(header, header_ip, hp->packet, !hp->block_store,
						      hp->block_store, hp->block_store_index, hp->block_store_locked,
						      this->getPcapHandleIndex(hp->dlt), hp->dlt, hp->sensor_id, hp->sensor_ip, hp->header->pid);
			return(true);
		} else if(opt_enable_ssl && 
			  isSslIpPort(header_ip->get_saddr(), hp->sport, header_ip->get_daddr(), hp->dport)) {
			tcpReassemblySsl->push_tcp(header, header_ip, hp->packet, !hp->block_store,
						   hp->block_store, hp->block_store_index, hp->block_store_locked,
						   this->getPcapHandleIndex(hp->dlt), hp->dlt, hp->sensor_id, hp->sensor_ip, hp->header->pid);
			return(true);
		} else if(opt_ipaccount &&
			  !(sipportmatrix[hp->sport] || sipportmatrix[hp->dport]) &&
			  !(opt_enable_diameter && (diameter_tcp_portmatrix[hp->sport] || diameter_tcp_portmatrix[hp->dport]))) {
			return(false);
		}
	}

	if((opt_enable_http != 2 && opt_enable_webrtc != 2 && opt_enable_ssl != 2) &&
	   !is_terminating() &&
	   !sverb.disable_push_to_t2_in_packetbuffer) {
		extern bool ssl_client_random_enable;
		extern char *ssl_client_random_portmatrix;
		extern bool ssl_client_random_portmatrix_set;
		extern bool ssl_client_random_tcp_set;
		extern vector<vmIP> ssl_client_random_ip;
		extern vector<vmIPmask> ssl_client_random_net;
		if(hp->header_ip_protocol == IPPROTO_UDP &&
		   ssl_client_random_enable &&
		   ((ssl_client_random_portmatrix_set && ssl_client_random_portmatrix[hp->dport]) ||
		    (!ssl_client_random_portmatrix_set && !ssl_client_random_tcp_set)) &&
		   ((!ssl_client_random_ip.size() && !ssl_client_random_net.size()) ||
		    check_ip_in(header_ip->get_daddr(), &ssl_client_random_ip, &ssl_client_random_net, true)) &&
		   hp->datalen) {
			if(ssl_parse_client_random((u_char*)(hp->packet + hp->data_offset), hp->datalen)) {
				return(false);
			}
		}
		if(opt_t2_boost_direct_rtp) {
			if(hp->block_store && !hp->block_store_locked) {
				hp->block_store->lock_packet(hp->block_store_index, 1 /*pb lock flag*/);
				hp->block_store_locked = true;
			}
			preProcessPacket[PreProcessPacket::ppt_detach_x]->push_packet(
				header_ip ? (u_char*)header_ip - hp->packet : 0,
				header_ip_encaps ? (u_char*)header_ip_encaps - hp->packet : 0xFFFF,
				hp->data_offset,
				hp->datalen,
				header_ip ? hp->sport.getPort() : 0,
				header_ip ? hp->dport.getPort() : 0,
				hp->pflags,
				hp,
				this->getPcapHandleIndex(hp->dlt));
		} else {
			preProcessPacket[PreProcessPacket::ppt_detach]->push_packet(
				#if USE_PACKET_NUMBER
				packet_counter_all,
				#endif
				header_ip ? header_ip->get_saddr() : 0, header_ip ? hp->sport.getPort() : 0, header_ip ? header_ip->get_daddr() : 0, header_ip ? hp->dport.getPort() : 0,
				hp->datalen, hp->data_offset,
				this->getPcapHandleIndex(hp->dlt), header, hp->packet, hp->block_store ? _t_packet_alloc_na : _t_packet_alloc_header_plus,
				hp->pflags, header_ip_encaps, header_ip,
				hp->block_store, hp->block_store_index, hp->dlt, hp->sensor_id, hp->sensor_ip, hp->header->pid,
				hp->block_store_locked ? 2 : 1 /*blockstore_lock*/);
		}
		return(true);
	}
	
	return(false);
}

void PcapQueue_readFromFifo::pushBatchProcessPacket() {
	if(pcapQueueQ_outThread_detach) {
		pcapQueueQ_outThread_detach->push_batch();
	} else if(pcapQueueQ_outThread_defrag) {
		pcapQueueQ_outThread_defrag->push_batch();
	} else if(pcapQueueQ_outThread_dedup) {
		pcapQueueQ_outThread_dedup->push_batch();
	} else if(pcapQueueQ_outThread_detach2) {
		pcapQueueQ_outThread_detach2->push_batch();
	} else {
		if(opt_t2_boost_direct_rtp) {
			if(preProcessPacket[PreProcessPacket::ppt_detach_x]) {
				preProcessPacket[PreProcessPacket::ppt_detach_x]->push_batch();
			}
		} else {
			if(preProcessPacket[PreProcessPacket::ppt_detach]) {
				preProcessPacket[PreProcessPacket::ppt_detach]->push_batch();
			}
		}
	}
}

void PcapQueue_readFromFifo::checkFreeSizeCachedir() {
	if(!opt_cachedir[0]) {
		return;
	}
	u_int64_t actTimeMS = getTimeMS();
	if(!lastCheckFreeSizeCachedir_timeMS ||
	   actTimeMS - lastCheckFreeSizeCachedir_timeMS > 2000) {
		double freeSpacePerc = GetFreeDiskSpace_perc(opt_cachedir);
		if(freeSpacePerc >= 0 && freeSpacePerc <= 5) {
			syslog(freeSpacePerc <= 1 ? LOG_ERR : LOG_NOTICE,
			       "%s low disk free space in cachedir (%s) - %lliMB",
			       freeSpacePerc <= 1 ? "critical " : "",
			       opt_cachedir,
			       GetFreeDiskSpace(opt_cachedir) / (1024 * 1024));
		}
		lastCheckFreeSizeCachedir_timeMS = actTimeMS;
	}
}

void PcapQueue_readFromFifo::cleanupBlockStoreTrash(bool all) {
	if(all && (opt_enable_http || opt_enable_webrtc || opt_enable_ssl) && opt_pb_read_from_file[0]) {
		this->cleanupBlockStoreTrash();
		cout << "COUNT REST PACKETBUFFER BLOCKS: " << this->blockStoreTrash.size() << endl;
	}
	lock_blockStoreTrash();
	u_int64_t time_ms = getTimeMS_rdtsc();
	for(int i = 0; i < ((int)this->blockStoreTrash.size() - (all ? 0 : 5)); i++) {
		bool del = false;
		pcap_block_store *block = this->blockStoreTrash[i];
		if(all || 
		   (time_ms > block->pushToTrashMS + 100 &&
		    block->enableDestroy())) {
			del = true;
		} else if(opt_pcap_queue_block_timeout &&
			  (this->blockStoreTrash[this->blockStoreTrash.size() - 1]->timestampMS - block->timestampMS) > (unsigned)opt_pcap_queue_block_timeout * 1000) {
			syslog(LOG_NOTICE, "force destroy packetbuffer blok - use packets: %i", block->_sync_packet_lock);
			del = true;
		}
		if(del) {
			buffersControl.sub__pb_trash_size(block->getUseAllSize());
			if(opt_use_dpdk && opt_dpdk_rotate_packetbuffer &&
			   (opt_dpdk_copy_packetbuffer || opt_dpdk_prealloc_packetbuffer) &&
			   buffersControl.check__pb__add_pool(block->getUseAllSize())) {
				buffersControl.add__pb_pool_size(block->getUseAllSize());
				lock_blockStorePool();
				blockStorePool.push_back(block);
				unlock_blockStorePool();
			} else {
				if(SAFE_ATOMIC_LOAD(block->_destroy_flag) == 0) {
					#if DEBUG_DESTROY_PCAP_BLOCK_STORE
					block->destroy_src_flag[0] = 1;
					#endif
					delete block;
				} else {
					block->double_destroy_log();
				}
			}
			this->blockStoreTrash.erase(this->blockStoreTrash.begin() + i);
			--i;
		}
	}
	if(this->blockStoreTrash.size()) {
		buffersControl.PcapQueue_readFromFifo__blockStoreTrash_time_set(this->blockStoreTrash[this->blockStoreTrash.size() - 1]->timestampMS - this->blockStoreTrash[0]->timestampMS);
	}
	unlock_blockStoreTrash();
}

void *_PcapQueue_readFromFifo_destroyBlocksThreadFunction(void *arg) {
	PcapQueue_readFromFifo *pcapQueue = (PcapQueue_readFromFifo*)arg;
	return(pcapQueue->destroyBlocksThreadFunction(pcapQueue, 0));
}

void *_PcapQueue_readFromFifo_socketServerThreadFunction(void *arg) {
	PcapQueue_readFromFifo *pcapQueue = (PcapQueue_readFromFifo*)arg;
	return(pcapQueue->threadFunction(pcapQueue, (unsigned int)-1));
}

void *_PcapQueue_readFromFifo_connectionThreadFunction(void *arg) {
	PcapQueue_readFromFifo::sPacketServerConnection *connection = (PcapQueue_readFromFifo::sPacketServerConnection*)arg;
	return(connection->parent->threadFunction(connection->parent, connection->id));
}


PcapQueue_outputThread::PcapQueue_outputThread(eTypeOutputThread typeOutputThread, PcapQueue_readFromFifo *pcapQueue) {
	extern unsigned int opt_preprocess_packets_qring_length;
	extern unsigned int opt_preprocess_packets_qring_item_length;
	this->typeOutputThread = typeOutputThread;
	this->pcapQueue = pcapQueue;
	this->qring_batch_item_length = opt_preprocess_packets_qring_item_length ?
					 opt_preprocess_packets_qring_item_length :
					 min(opt_preprocess_packets_qring_length / 10, 1000u);
	this->qring_length = opt_preprocess_packets_qring_item_length ?
			      opt_preprocess_packets_qring_length :
			      opt_preprocess_packets_qring_length / this->qring_batch_item_length;
	this->readit = 0;
	this->writeit = 0;
	this->qring = new FILE_LINE(15059) sBatchHP*[this->qring_length];
	for(unsigned int i = 0; i < this->qring_length; i++) {
		this->qring[i] = new FILE_LINE(15060) sBatchHP(this->qring_batch_item_length);
		this->qring[i]->used = 0;
	}
	this->items_flag = new FILE_LINE(0) volatile int8_t[this->qring_batch_item_length];
	this->items_index = new FILE_LINE(0) u_int8_t[this->qring_batch_item_length];
	this->items_thread_index = new FILE_LINE(0) u_int8_t[this->qring_batch_item_length];
	this->qring_push_index = 0;
	this->qring_push_index_count = 0;
	memset(this->threadPstatData, 0, sizeof(this->threadPstatData));
	this->outThreadId = 0;
	this->defrag_counter = 0;
	this->ipfrag_lastcleanup = 0;
	if(typeOutputThread == dedup) {
		extern int opt_dup_check_check_type;
		this->dedup_buffer = new FILE_LINE(0) cPacketDuplBuffer((cPacketDuplBuffer::eType)opt_dup_check_check_type, (eDedupType)opt_dup_check_type);
		#if DEDUPLICATE_COLLISION_TEST
		extern bool opt_dup_check_collision_test;
		if(opt_dup_check_collision_test) {
			this->dedup_buffer_ct_md5 = new FILE_LINE(0) cPacketDuplBuffer(cPacketDuplBuffer::_hashtable, _dedup_md5);
		} else {
			this->dedup_buffer_ct_md5 = NULL;
		}
		#endif
	} else {
		this->dedup_buffer = NULL;
		#if DEDUPLICATE_COLLISION_TEST
		this->dedup_buffer_ct_md5 = NULL;
		#endif
	}
	this->initThreadOk = false;
	this->terminatingThread = false;
	#if not DEFRAG_MOD_OLDVER
	if(typeOutputThread == defrag) {
		this->ip_defrag = new FILE_LINE(0) cIpFrag(DEFRAG_THREADS_SPLIT);
	} else {
		this->ip_defrag = NULL;
	}
	#endif
	#if EXPERIMENTAL_CHECK_TID_IN_PUSH
	push_thread = 0;
	last_race_log[0] = 0;
	last_race_log[1] = 0;
	#endif
	for(int i = 0; i < MAX_PRE_PROCESS_PACKET_NEXT_THREADS; i++) {
		this->next_threads[i].null();
	}
	extern int opt_pre_process_packets_next_thread_detach;
	extern int opt_pre_process_packets_next_thread_detach2;
	#if not DEFRAG_MOD_OLDVER
	extern int opt_pre_process_packets_next_thread_defrag;
	#endif
	extern int opt_pre_process_packets_next_thread_max;
	this->next_threads_count = typeOutputThread == detach ?
				    min(max(opt_pre_process_packets_next_thread_detach, 0), min(opt_pre_process_packets_next_thread_max, MAX_PRE_PROCESS_PACKET_NEXT_THREADS)) :
				   typeOutputThread == detach2 ?
				    min(max(opt_pre_process_packets_next_thread_detach2, 0), min(opt_pre_process_packets_next_thread_max, MAX_PRE_PROCESS_PACKET_NEXT_THREADS)) :
				   #if not DEFRAG_MOD_OLDVER
				   typeOutputThread == defrag ?
				    min(max(opt_pre_process_packets_next_thread_defrag, 0), min(opt_pre_process_packets_next_thread_max, MAX_PRE_PROCESS_PACKET_NEXT_THREADS)) :
				   #endif
				    0;
	this->next_threads_count_mod = 0;
	#if SNIFFER_THREADS_EXT
	thread_data = NULL;
	#endif
	for(int i = 0; i < this->next_threads_count; i++) {
		this->next_threads[i].sem_init();
		arg_next_thread *arg = new FILE_LINE(0) arg_next_thread;
		arg->me = this;
		arg->next_thread_id = i + 1;
		vm_pthread_create(("t2 out thread next - " + getNameOutputThread()).c_str(),
				  &this->next_threads[i].thread_handle, NULL, PcapQueue_outputThread::_nextThreadFunction, arg, __FILE__, __LINE__);
	}
}

PcapQueue_outputThread::~PcapQueue_outputThread() {
	stop();
	for(unsigned int i = 0; i < this->qring_length; i++) {
		delete this->qring[i];
	}
	delete [] this->qring;
	delete [] this->items_flag;
	delete [] this->items_index;
	delete [] this->items_thread_index;
	if(typeOutputThread == defrag) {
		#if not DEFRAG_MOD_OLDVER
		if(ip_defrag) {
			delete ip_defrag;
		}
		#else
		ipfrag_prune(0, true, &ipfrag_data, -1, 0);
		#endif
	}
	if(typeOutputThread == dedup) {
		if(dedup_buffer) {
			delete dedup_buffer;
		}
		#if DEDUPLICATE_COLLISION_TEST
		if(dedup_buffer_ct_md5) {
			delete dedup_buffer_ct_md5;
		}
		#endif
	}
}

void PcapQueue_outputThread::start() {
	vm_pthread_create(("t2 out thread " + getNameOutputThread()).c_str(),
			  &this->out_thread_handle, NULL, PcapQueue_outputThread::_outThreadFunction, this, __FILE__, __LINE__);
}

void PcapQueue_outputThread::stop() {
	if(this->initThreadOk) {
		this->terminatingThread = true;
		pthread_join(this->out_thread_handle, NULL);
		this->initThreadOk = false;
		this->terminatingThread = false;
	}
}

void PcapQueue_outputThread::addNextThread() {
	extern int opt_pre_process_packets_next_thread_max;
	if(this->next_threads_count < MAX_PRE_PROCESS_PACKET_NEXT_THREADS &&
	   (opt_pre_process_packets_next_thread_max <= 0 || this->next_threads_count < opt_pre_process_packets_next_thread_max)) {
		this->next_threads_count_mod = 1;
	}
}

void PcapQueue_outputThread::removeNextThread() {
	extern int opt_pre_process_packets_next_thread_detach;
	extern int opt_pre_process_packets_next_thread_detach2;
	extern int opt_pre_process_packets_next_thread_defrag;
	if(this->next_threads_count > 0 &&
	   ((typeOutputThread == detach && (opt_pre_process_packets_next_thread_detach <= 0 || this->next_threads_count > opt_pre_process_packets_next_thread_detach)) ||
	    (typeOutputThread == detach2 && (opt_pre_process_packets_next_thread_detach2 <= 0 || this->next_threads_count > opt_pre_process_packets_next_thread_detach2)) ||
	    (typeOutputThread == defrag && (opt_pre_process_packets_next_thread_defrag <= 0 || this->next_threads_count > opt_pre_process_packets_next_thread_defrag)))) {
		this->next_threads_count_mod = -1;
	}
}

void PcapQueue_outputThread::push(sHeaderPacketPQout *hp) {
	#if EXPERIMENTAL_CHECK_TID_IN_PUSH
	static __thread unsigned _tid = 0;
	if(!_tid) {
		_tid = get_unix_tid();
	}
	if(!push_thread) {
		push_thread = _tid;
	} else if(push_thread != _tid) {
		u_int64_t time = getTimeMS_rdtsc();
		if(time > last_race_log[0] + 1000) {
			syslog(LOG_ERR, "race in %s %s %i (%i != %i)", getNameOutputThread().c_str(), __FILE__, __LINE__, push_thread, _tid);
			last_race_log[0] = time;
		}
		push_thread = _tid;
	}
	#endif
	if(is_terminating()) {
		hp->destroy_or_unlock_blockstore();
		return;
	}
	extern bool use_push_batch_limit_ms;
	u_int64_t time_us = use_push_batch_limit_ms ? hp->header->get_time_us() : 0;
	if(hp && hp->block_store && !hp->block_store_locked) {
		hp->block_store->lock_packet(hp->block_store_index, 1 /*pb lock flag*/);
		hp->block_store_locked = true;
	}
	if(!qring_push_index) {
		#if SNIFFER_THREADS_EXT
		if(sverb.sniffer_threads_ext && thread_data) {
			++thread_data->buffer_push_cnt_all;
		}
		#endif
		unsigned int usleepCounter = 0;
		while(this->qring[this->writeit]->used != 0) {
			if(is_terminating()) {
				hp->destroy_or_unlock_blockstore();
				return;
			}
			if(usleepCounter == 0) {
				#if SNIFFER_THREADS_EXT
				if(sverb.sniffer_threads_ext && thread_data) {
					++thread_data->buffer_push_cnt_full;
				}
				#endif
			}
			#if SNIFFER_THREADS_EXT
			if(sverb.sniffer_threads_ext && thread_data) {
				++thread_data->buffer_push_cnt_full_loop;
			}
			#endif
			extern unsigned int opt_sip_batch_usleep;
			if(opt_sip_batch_usleep) {
				#if SNIFFER_THREADS_EXT
				unsigned us =
				#endif
				USLEEP_C(opt_sip_batch_usleep, usleepCounter++);
				#if SNIFFER_THREADS_EXT
				if(sverb.sniffer_threads_ext && thread_data) {
					thread_data->buffer_push_sum_usleep_full_loop += us;
				}
				#endif
			} else {
				__ASM_PAUSE;
			}
		}
		qring_push_index = this->writeit + 1;
		qring_push_index_count = 0;
		qring_active_push_item = qring[qring_push_index - 1];
		extern unsigned int opt_push_batch_limit_ms;
		qring_active_push_item_limit_us = use_push_batch_limit_ms ? time_us + opt_push_batch_limit_ms * 1000 : 0;
	}
	qring_active_push_item->batch[qring_push_index_count] = *hp;
	++qring_push_index_count;
	if(qring_push_index_count == qring_active_push_item->max_count ||
	   time_us > qring_active_push_item_limit_us) {
		#if RQUEUE_SAFE
		__SYNC_SET_TO(qring_active_push_item->count, qring_push_index_count);
		__SYNC_SET(qring_active_push_item->used);
		__SYNC_INCR(this->writeit, this->qring_length);
		#else
		qring_active_push_item->count = qring_push_index_count;
		qring_active_push_item->used = 1;
		if((this->writeit + 1) == this->qring_length) {
			this->writeit = 0;
		} else {
			this->writeit++;
		}
		#endif
		qring_push_index = 0;
		qring_push_index_count = 0;
	}
}

void PcapQueue_outputThread::push_batch() {
	#if EXPERIMENTAL_CHECK_TID_IN_PUSH
	static __thread unsigned _tid = 0;
	if(!_tid) {
		_tid = get_unix_tid();
	}
	if(push_thread && push_thread != _tid) {
		u_int64_t time = getTimeMS_rdtsc();
		if(time > last_race_log[1] + 1000) {
			syslog(LOG_ERR, "race in %s %s %i (%i != %i)", getNameOutputThread().c_str(), __FILE__, __LINE__, push_thread, _tid);
			last_race_log[1] = time;
		}
		push_thread = _tid;
	}
	#endif
	if(qring_push_index && qring_push_index_count) {
		#if RQUEUE_SAFE
		__SYNC_SET_TO(qring_active_push_item->count, qring_push_index_count);
		__SYNC_SET(qring_active_push_item->used);
		__SYNC_INCR(this->writeit, this->qring_length);
		#else
		qring_active_push_item->count = qring_push_index_count;
		qring_active_push_item->used = 1;
		if((this->writeit + 1) == this->qring_length) {
			this->writeit = 0;
		} else {
			this->writeit++;
		}
		#endif
		qring_push_index = 0;
		qring_push_index_count = 0;
	}
}

void *PcapQueue_outputThread::_outThreadFunction(void *arg) {
	return(((PcapQueue_outputThread*)arg)->outThreadFunction());
}

void *PcapQueue_outputThread::outThreadFunction() {
	extern string opt_sched_pol_pb;
	pthread_set_priority(opt_sched_pol_pb);
	this->initThreadOk = true;
	extern unsigned int opt_preprocess_packets_qring_usleep;
	this->outThreadId = get_unix_tid();
	#if SNIFFER_THREADS_EXT
	this->thread_data = cThreadMonitor::getSelfThreadData();
	#endif
	syslog(LOG_NOTICE, "start thread t2_%s/%i", this->getNameOutputThread().c_str(), this->outThreadId);
	sBatchHP *batch;
	unsigned int usleepCounter = 0;
	unsigned long usleepSumTime = 0;
	unsigned long usleepSumTime_lastPush = 0;
	while(!is_terminating() && !this->terminatingThread) {
		if(this->next_threads_count_mod &&
		   (typeOutputThread == detach ||
		    typeOutputThread == detach2 ||
		    typeOutputThread == defrag)) {
			if(this->next_threads_count_mod > 0) {
				createNextThread();
			} else if(this->next_threads_count_mod < 0) {
				termNextThread();
			}
			this->next_threads_count_mod = 0;
		}
		if(this->qring[this->readit]->used == 1) {
			batch = this->qring[this->readit];
			#if SNIFFER_THREADS_EXT
			if(sverb.sniffer_threads_ext && thread_data) {
				for(unsigned batch_index = 0; batch_index < batch->count; batch_index++) {
					thread_data->inc_packets_in(batch->batch[batch_index].header->get_caplen());
				}
			}
			#endif
			uint32_t firstHeaderTimeS = batch->batch[0].header->get_tv_sec();
			if(typeOutputThread == detach && this->next_threads[0].thread_handle) {
				extern int opt_pre_process_packets_next_thread_sem_sync;
				unsigned count = batch->count;
				unsigned completed = 0;
				int _next_threads_count = this->next_threads_count;
				bool _process_only_in_next_threads = _next_threads_count > 1;
				for(unsigned batch_index = 0; batch_index < count; batch_index++) {
					this->items_flag[batch_index] = 0;
				}
				for(int i = 0; i < _next_threads_count; i++) {
					this->next_threads[i].next_data.null();
					if(_process_only_in_next_threads) {
						this->next_threads[i].next_data.start = i;
						this->next_threads[i].next_data.end = count;
						this->next_threads[i].next_data.skip = _next_threads_count;
					} else {
						this->next_threads[i].next_data.start = count / (_next_threads_count + 1) * (i + 1);
						this->next_threads[i].next_data.end = i == (_next_threads_count - 1) ? count : count / (_next_threads_count + 1) * (i + 2);
						this->next_threads[i].next_data.skip = 1;
					}
					this->next_threads[i].next_data.batch = batch->batch;
					this->next_threads[i].next_data.processing = 1;
					if(opt_pre_process_packets_next_thread_sem_sync) {
						sem_post(&this->next_threads[i].sem_sync[0]);
					} else {
						this->next_threads[i].next_data.data_ready = 1;
					}
				}
				if(_process_only_in_next_threads) {
					while(this->next_threads[0].next_data.processing || this->next_threads[1].next_data.processing ||
					      (_next_threads_count > 2 && this->isNextThreadsGt2Processing(_next_threads_count))) {
						if(completed < count &&
						   this->items_flag[completed] != 0) {
							this->processDetach_push(&batch->batch[completed]);
							++completed;
						} else {
							extern unsigned int opt_sip_batch_usleep;
							if(opt_sip_batch_usleep) {
								USLEEP(opt_sip_batch_usleep);
							} else {
								__ASM_PAUSE;
							}
						}
					}
				} else {
					for(unsigned batch_index = 0; 
					    batch_index < count / (_next_threads_count + 1); 
					    batch_index++) {
						if(opt_t2_boost_pb_detach_thread == 2) {
							this->processDetach_findHeaderIp(&batch->batch[batch_index]);
						}
					}
				}
				for(int i = 0; i < _next_threads_count; i++) {
					if(opt_pre_process_packets_next_thread_sem_sync == 2) {
						sem_wait(&this->next_threads[i].sem_sync[1]);
					} else {
						while(this->next_threads[i].next_data.processing) { 
							extern unsigned int opt_sip_batch_usleep;
							if(opt_sip_batch_usleep) {
								USLEEP(opt_sip_batch_usleep);
							} else {
								__ASM_PAUSE;
							}
						}
					}
				}
				for(unsigned batch_index = completed; batch_index < batch->count; batch_index++) {
					this->processDetach_push(&batch->batch[batch_index]);
				}
			} else if(typeOutputThread == detach2 && this->next_threads[0].thread_handle) {
				extern int opt_pre_process_packets_next_thread_sem_sync;
				unsigned count = batch->count;
				unsigned completed = 0;
				int _next_threads_count = this->next_threads_count;
				bool _process_only_in_next_threads = _next_threads_count > 1;
				for(unsigned batch_index = 0; batch_index < count; batch_index++) {
					this->items_flag[batch_index] = 0;
				}
				#if DEBUG_ALLOC_PACKETS
				for(unsigned batch_index = 0; batch_index < batch->count; batch_index++) {
					if(!batch->batch[batch_index].block_store) {
						debug_alloc_packet_set(batch->batch[batch_index].packet, "PcapQueue_outputThread::outThreadFunction - detach2");
					}
				}
				#endif
				for(int i = 0; i < _next_threads_count; i++) {
					this->next_threads[i].next_data.null();
					if(_process_only_in_next_threads) {
						this->next_threads[i].next_data.start = i;
						this->next_threads[i].next_data.end = count;
						this->next_threads[i].next_data.skip = _next_threads_count;
					} else {
						this->next_threads[i].next_data.start = count / (_next_threads_count + 1) * (i + 1);
						this->next_threads[i].next_data.end = i == (_next_threads_count - 1) ? count : count / (_next_threads_count + 1) * (i + 2);
						this->next_threads[i].next_data.skip = 1;
					}
					this->next_threads[i].next_data.batch = batch->batch;
					this->next_threads[i].next_data.processing = 1;
					if(opt_pre_process_packets_next_thread_sem_sync) {
						sem_post(&this->next_threads[i].sem_sync[0]);
					} else {
						this->next_threads[i].next_data.data_ready = 1;
					}
				}
				if(_process_only_in_next_threads) {
					while(this->next_threads[0].next_data.processing || this->next_threads[1].next_data.processing ||
					      (_next_threads_count > 2 && this->isNextThreadsGt2Processing(_next_threads_count))) {
						if(completed < count &&
						   this->items_flag[completed] != 0) {
							bool destroy = false;
							if(this->items_flag[completed] < 0) {
								destroy = true;
							} else {
								destroy = !this->pcapQueue->processPacket_push(&batch->batch[completed]);
								#if SNIFFER_THREADS_EXT
								if(!destroy) {
									tm_inc_packets_out(&batch->batch[completed]);
								}
								#endif
							}
							if(destroy) {
								batch->batch[completed].destroy_or_unlock_blockstore();
							}
							++completed;
						} else {
							extern unsigned int opt_sip_batch_usleep;
							if(opt_sip_batch_usleep) {
								USLEEP(opt_sip_batch_usleep);
							} else {
								__ASM_PAUSE;
							}
						}
					}
				} else {
					for(unsigned batch_index = 0; 
					    batch_index < count / (_next_threads_count + 1); 
					    batch_index++) {
						this->items_flag[batch_index] = this->pcapQueue->processPacket_analysis(&batch->batch[batch_index]) ? 1 : -1;
					}
				}
				for(int i = 0; i < _next_threads_count; i++) {
					if(opt_pre_process_packets_next_thread_sem_sync == 2) {
						sem_wait(&this->next_threads[i].sem_sync[1]);
					} else {
						while(this->next_threads[i].next_data.processing) { 
							extern unsigned int opt_sip_batch_usleep;
							if(opt_sip_batch_usleep) {
								USLEEP(opt_sip_batch_usleep);
							} else {
								__ASM_PAUSE;
							}
						}
					}
				}
				for(unsigned batch_index = completed; batch_index < batch->count; batch_index++) {
					bool destroy = false;
					if(this->items_flag[batch_index] < 0) {
						destroy = true;
					} else {
						destroy = !this->pcapQueue->processPacket_push(&batch->batch[batch_index]);
						#if SNIFFER_THREADS_EXT
						if(!destroy) {
							tm_inc_packets_out(&batch->batch[batch_index]);
						}
						#endif
					}
					if(destroy) {
						batch->batch[batch_index].destroy_or_unlock_blockstore();
					}
				}
			}
			#if not DEFRAG_MOD_OLDVER 
			else if(typeOutputThread == defrag && this->next_threads[0].thread_handle) {
				extern int opt_pre_process_packets_next_thread_sem_sync;
				unsigned count = batch->count;
				unsigned completed = 0;
				int _next_threads_count = this->next_threads_count;
				bool _process_only_in_next_threads = _next_threads_count > 1;
				for(unsigned batch_index = 0; batch_index < count; batch_index++) {
					this->items_flag[batch_index] = 0;
					sHeaderPacketPQout *hp = &batch->batch[batch_index];
					if(hp->header->header_ip_encaps_offset != 0xFFFF) {
						iphdr2 *header_ip_encaps = (iphdr2*)(hp->packet + hp->header->header_ip_encaps_offset);
						this->items_index[batch_index] = header_ip_encaps->get_saddr().getHashNumber() % DEFRAG_THREADS_SPLIT;
						this->items_thread_index[batch_index] = this->items_index[batch_index] % (_next_threads_count + (_process_only_in_next_threads ? 0 : 1));
					} else {
						this->items_index[batch_index] = 0;
						this->items_thread_index[batch_index] = 0;
					}
				}
				for(int i = 0; i < _next_threads_count; i++) {
					this->next_threads[i].next_data.null();
					if(_process_only_in_next_threads) {
						this->next_threads[i].next_data.start = 0;
						this->next_threads[i].next_data.end = count;
						this->next_threads[i].next_data.skip = 1;
						this->next_threads[i].next_data.thread_index = i;
					} else {
						this->next_threads[i].next_data.start = 0;
						this->next_threads[i].next_data.end = count;
						this->next_threads[i].next_data.skip = 1;
						this->next_threads[i].next_data.thread_index = i + 1;
					}
					this->next_threads[i].next_data.batch = batch->batch;
					this->next_threads[i].next_data.processing = 1;
					if(opt_pre_process_packets_next_thread_sem_sync) {
						sem_post(&this->next_threads[i].sem_sync[0]);
					} else {
						this->next_threads[i].next_data.data_ready = 1;
					}
				}
				if(_process_only_in_next_threads) {
					while(this->next_threads[0].next_data.processing || this->next_threads[1].next_data.processing ||
					      (_next_threads_count > 2 && this->isNextThreadsGt2Processing(_next_threads_count))) {
						if(completed < count &&
						   this->items_flag[completed] != 0) {
							if(this->items_flag[completed] > 0) {
								this->processDefrag_push(&batch->batch[completed]);
							}
							++completed;
						} else {
							extern unsigned int opt_sip_batch_usleep;
							if(opt_sip_batch_usleep) {
								USLEEP(opt_sip_batch_usleep);
							} else {
								__ASM_PAUSE;
							}
						}
					}
				} else {
					for(unsigned batch_index = 0; batch_index < count; batch_index++) {
						if(this->items_thread_index[batch_index] == 0) {
							this->items_flag[batch_index] = this->processDefrag_defrag(&batch->batch[batch_index], this->items_index[batch_index]) ? 1 : -1;
						}
					}
				}
				for(int i = 0; i < _next_threads_count; i++) {
					if(opt_pre_process_packets_next_thread_sem_sync == 2) {
						sem_wait(&this->next_threads[i].sem_sync[1]);
					} else {
						while(this->next_threads[i].next_data.processing) { 
							extern unsigned int opt_sip_batch_usleep;
							if(opt_sip_batch_usleep) {
								USLEEP(opt_sip_batch_usleep);
							} else {
								__ASM_PAUSE;
							}
						}
					}
				}
				for(unsigned batch_index = completed; batch_index < batch->count; batch_index++) {
					if(this->items_flag[batch_index] > 0) {
						this->processDefrag_push(&batch->batch[batch_index]);
					}
				}
			}
			#endif
			else {
				for(unsigned batch_index = 0; batch_index < batch->count; batch_index++) {
					switch(typeOutputThread) {
					case detach:
						this->processDetach(&batch->batch[batch_index]);
						break;
					case defrag:
						this->processDefrag(&batch->batch[batch_index], -1);
						break;
					case dedup:
						this->processDedup(&batch->batch[batch_index]);
						break;
					case detach2:
						this->processDetach2(&batch->batch[batch_index]);
						break;
					}
				}
			}
			if(typeOutputThread == defrag) {
				this->processDefrag_cleanup(firstHeaderTimeS);
			}
			#if RQUEUE_SAFE
			__SYNC_NULL(batch->count);
			__SYNC_NULL(batch->used);
			__SYNC_INCR(readit, this->qring_length);
			#else
			batch->count = 0;
			batch->used = 0;
			if((this->readit + 1) == this->qring_length) {
				this->readit = 0;
			} else {
				this->readit++;
			}
			#endif
			usleepCounter = 0;
			usleepSumTime = 0;
			usleepSumTime_lastPush = 0;
		} else {
			if(opt_preprocess_packets_qring_usleep) {
				usleepSumTime += USLEEP_C(opt_preprocess_packets_qring_usleep, usleepCounter++);
			} else {
				__ASM_PAUSE;
				++usleepCounter;
			}
			extern unsigned int opt_push_batch_limit_ms;
			if(usleepSumTime > usleepSumTime_lastPush + opt_push_batch_limit_ms * 1000) {
				switch(typeOutputThread) {
				case detach:
					if(pcapQueueQ_outThread_defrag) {
						pcapQueueQ_outThread_defrag->push_batch();
						break;
					}
				case defrag:
					if(pcapQueueQ_outThread_dedup) {
						pcapQueueQ_outThread_dedup->push_batch();
						break;
					}
				case dedup:
					if(pcapQueueQ_outThread_detach2) {
						pcapQueueQ_outThread_detach2->push_batch();
						break;
					}
				case detach2:
					if(opt_t2_boost_direct_rtp) {
						if(preProcessPacket[PreProcessPacket::ppt_detach_x]) {
							preProcessPacket[PreProcessPacket::ppt_detach_x]->push_batch();
						}
					} else {
						if(preProcessPacket[PreProcessPacket::ppt_detach]) {
							preProcessPacket[PreProcessPacket::ppt_detach]->push_batch();
						}
					}
					break;
				}
				usleepSumTime_lastPush = usleepSumTime;
			}
		}
	}
	syslog(LOG_NOTICE, "stop thread t2_%s/%i", this->getNameOutputThread().c_str(), this->outThreadId);
	return(NULL);
}

void *PcapQueue_outputThread::_nextThreadFunction(void *arg) {
	PcapQueue_outputThread::arg_next_thread *_arg = (PcapQueue_outputThread::arg_next_thread*)arg;
	void *rsltThread = _arg->me->nextThreadFunction(_arg->next_thread_id);
	delete _arg;
	return(rsltThread);
}

void *PcapQueue_outputThread::nextThreadFunction(int next_thread_index_plus) {
	unsigned int tid = get_unix_tid();
	this->next_threads[next_thread_index_plus - 1].thread_id = tid;
	syslog(LOG_NOTICE, "start next thread t2_%s/%i", this->getNameOutputThread().c_str(), this->next_threads[next_thread_index_plus - 1].thread_id);
	unsigned int usleepCounter = 0;
	while(!is_terminating() && !this->terminatingThread) {
		s_next_thread *next_thread = &this->next_threads[next_thread_index_plus - 1];
		s_next_thread_data *next_thread_data = &next_thread->next_data;
		extern int opt_pre_process_packets_next_thread_sem_sync;
		if(opt_pre_process_packets_next_thread_sem_sync) {
			sem_wait(&next_thread->sem_sync[0]);
		} else {
			while(!this->terminatingThread && !next_thread_data->data_ready && !next_thread->terminate) {
				extern unsigned int opt_sip_batch_usleep;
				if(opt_sip_batch_usleep) {
					USLEEP(opt_sip_batch_usleep);
				} else {
					__ASM_PAUSE;
				}
			}
			next_thread_data->data_ready = 0;
		}
		if(this->terminatingThread || next_thread->terminate) {
			break;
		}
		if(next_thread_data->batch) {
			unsigned batch_index_start = next_thread_data->start;
			unsigned batch_index_end = next_thread_data->end;
			unsigned batch_index_skip = next_thread_data->skip;
			switch(typeOutputThread) {
			case detach: {
				sHeaderPacketPQout *batch = (sHeaderPacketPQout*)next_thread_data->batch;
				for(unsigned batch_index = batch_index_start; 
				    batch_index < batch_index_end; 
				    batch_index += batch_index_skip) {
					if(opt_t2_boost_pb_detach_thread == 2) {
						this->processDetach_findHeaderIp(&batch[batch_index]);
					}
					this->items_flag[batch_index] = 1;
				} }
				break;
			case detach2: {
				sHeaderPacketPQout *batch = (sHeaderPacketPQout*)next_thread_data->batch;
				for(unsigned batch_index = batch_index_start; 
				    batch_index < batch_index_end; 
				    batch_index += batch_index_skip) {
					this->items_flag[batch_index] = this->pcapQueue->processPacket_analysis(&batch[batch_index]) ? 1 : -1;
				} }
				break;
			case defrag: {
				sHeaderPacketPQout *batch = (sHeaderPacketPQout*)next_thread_data->batch;
				for(unsigned batch_index = batch_index_start; 
				    batch_index < batch_index_end; 
				    batch_index += batch_index_skip) {
					if(this->items_thread_index[batch_index] == next_thread_data->thread_index) {
						this->items_flag[batch_index] = this->processDefrag_defrag(&batch[batch_index], this->items_index[batch_index]) ? 1 : -1;
					}
				} }
				break;
			default:
				break;
			}
			next_thread_data->processing = 0;
			usleepCounter = 0;
			if(opt_pre_process_packets_next_thread_sem_sync == 2) {
				sem_post(&next_thread->sem_sync[1]);
			}
		} else {
			extern unsigned int opt_sip_batch_usleep;
			if(opt_sip_batch_usleep) {
				USLEEP_C(opt_sip_batch_usleep, usleepCounter++);
			} else {
				__ASM_PAUSE;
			}
		}
	}
	syslog(LOG_NOTICE, "stop next thread t2_%s/%i", this->getNameOutputThread().c_str(), tid);
	return(NULL);
}

void PcapQueue_outputThread::createNextThread() {
	extern int opt_pre_process_packets_next_thread_max;
	if(!(this->next_threads_count < MAX_PRE_PROCESS_PACKET_NEXT_THREADS &&
	     (opt_pre_process_packets_next_thread_max <= 0 || this->next_threads_count < opt_pre_process_packets_next_thread_max))) {
		return;
	}
	this->next_threads[this->next_threads_count].null();
	this->next_threads[this->next_threads_count].sem_init();
	arg_next_thread *arg = new FILE_LINE(0) arg_next_thread;
	arg->me = this;
	arg->next_thread_id = this->next_threads_count + 1;
	vm_pthread_create(("t2 out thread next - " + getNameOutputThread()).c_str(),
			  &this->next_threads[this->next_threads_count].thread_handle, NULL, PcapQueue_outputThread::_nextThreadFunction, arg, __FILE__, __LINE__);
	while(!this->next_threads[this->next_threads_count].thread_id) {
		extern unsigned int opt_sip_batch_usleep;
		if(opt_sip_batch_usleep) {
			USLEEP(opt_sip_batch_usleep);
		} else {
			__ASM_PAUSE;
		}
	}
	++this->next_threads_count;
}

void PcapQueue_outputThread::termNextThread() {
	extern int opt_pre_process_packets_next_thread_detach;
	extern int opt_pre_process_packets_next_thread_detach2;
	extern int opt_pre_process_packets_next_thread_defrag;
	extern int opt_process_rtp_packets_hash_next_thread_sem_sync;
	if(!(this->next_threads_count > 0 &&
	     ((typeOutputThread == detach && (opt_pre_process_packets_next_thread_detach <= 0 || this->next_threads_count > opt_pre_process_packets_next_thread_detach)) ||
	      (typeOutputThread == detach2 && (opt_pre_process_packets_next_thread_detach2 <= 0 || this->next_threads_count > opt_pre_process_packets_next_thread_detach2)) ||
	      (typeOutputThread == defrag && (opt_pre_process_packets_next_thread_defrag <= 0 || this->next_threads_count > opt_pre_process_packets_next_thread_defrag))))) {
		return;
	}
	--this->next_threads_count;
	this->next_threads[this->next_threads_count].terminate = true;
	if(opt_process_rtp_packets_hash_next_thread_sem_sync) {
		sem_post(&this->next_threads[this->next_threads_count].sem_sync[0]);
	}
	pthread_join(this->next_threads[this->next_threads_count].thread_handle, NULL);
	this->next_threads[this->next_threads_count].sem_term();
	this->next_threads[this->next_threads_count].null();
}

void PcapQueue_outputThread::processDetach(sHeaderPacketPQout *hp) {
	if(opt_t2_boost_pb_detach_thread == 2) {
		processDetach_findHeaderIp(hp);
	}
	processDetach_push(hp);
}

void PcapQueue_outputThread::processDetach_findHeaderIp(sHeaderPacketPQout *hp) {
	if(hp->header->header_ip_offset != 0xFFFF && hp->header_ip_last_offset == 0xFFFF) {
		hp->header_ip_last_offset = hp->header->header_ip_offset;
		iphdr2 *header_ip = (iphdr2*)(hp->packet + hp->header_ip_last_offset);
		if(header_ip) {
			while(true) {
				int next_header_ip_offset = findNextHeaderIp(header_ip, hp->header_ip_last_offset, 
									     hp->packet, hp->header->get_caplen());
				if(next_header_ip_offset == 0) {
					break;
				} else if(next_header_ip_offset < 0) {
					hp->header_ip_last_offset = 0xFFFF;
					break;
				} else {
					header_ip = (iphdr2*)((u_char*)header_ip + next_header_ip_offset);
					hp->header_ip_last_offset += next_header_ip_offset;
				}
			}
		}
	}
}

void PcapQueue_outputThread::processDetach_push(sHeaderPacketPQout *hp) {
	if(pcapQueueQ_outThread_defrag) {
		pcapQueueQ_outThread_defrag->push(hp);
		#if SNIFFER_THREADS_EXT
		tm_inc_packets_out(hp);
		#endif
		return;
	} else if(pcapQueueQ_outThread_dedup) {
		pcapQueueQ_outThread_dedup->push(hp);
		#if SNIFFER_THREADS_EXT
		tm_inc_packets_out(hp);
		#endif
		return;
	} else if(pcapQueueQ_outThread_detach2) {
		pcapQueueQ_outThread_detach2->push(hp);
		#if SNIFFER_THREADS_EXT
		tm_inc_packets_out(hp);
		#endif
		return;
	}
	if(this->pcapQueue->processPacket_analysis(hp) &&
	   this->pcapQueue->processPacket_push(hp)) {
		#if SNIFFER_THREADS_EXT
		tm_inc_packets_out(hp);
		#endif
		return;
	}
	hp->destroy_or_unlock_blockstore();
}

void PcapQueue_outputThread::processDefrag(sHeaderPacketPQout *hp, int fdata_thread_index) {
	if(!processDefrag_defrag(hp, fdata_thread_index)) {
		return;
	}
	processDefrag_push(hp);
}

bool PcapQueue_outputThread::processDefrag_defrag(sHeaderPacketPQout *hp, int fdata_thread_index) {
	#if not DEFRAG_MOD_OLDVER
	if(fdata_thread_index < 0) {
		if(hp->header->header_ip_encaps_offset != 0xFFFF) {
			iphdr2 *header_ip_encaps = (iphdr2*)(hp->packet + hp->header->header_ip_encaps_offset);
			fdata_thread_index = header_ip_encaps->get_saddr().getHashNumber() % DEFRAG_THREADS_SPLIT;
		} else {
			fdata_thread_index = 0;
		}
	}
	#endif
	if(hp->block_store && hp->block_store->hm == pcap_block_store::plus2) {
		hp->header->header_ip_offset = ((pcap_pkthdr_plus2*)hp->header)->header_ip_encaps_offset;
	} else {
		u_int16_t header_ip_offset = 0;
		u_int16_t protocol;
		u_int16_t vlan;
		parseEtherHeader(hp->dlt, hp->packet,
				 NULL, NULL,
				 header_ip_offset, protocol, vlan);
		hp->header->header_ip_offset = header_ip_offset;
	}
	if(hp->header->header_ip_offset == 0xFFFF) {
		return(true);
	}
	iphdr2 *header_ip = (iphdr2*)(hp->packet + hp->header->header_ip_offset);
	u_int16_t frag_data = header_ip->get_frag_data();
	if(header_ip->is_more_frag(frag_data) || header_ip->get_frag_offset(frag_data)) {
		if(header_ip->get_tot_len() + hp->header->header_ip_offset > hp->header->get_caplen()) {
			static u_int64_t lastTimeLogErrBadIpHeader = 0;
			u_int64_t actTime = hp->header->get_time_ms();
			if(actTime - 1000 > lastTimeLogErrBadIpHeader) {
				syslog(LOG_ERR, "BAD FRAGMENTED HEADER_IP: bogus ip header length %i, caplen %i", header_ip->get_tot_len(), hp->header->get_caplen());
				lastTimeLogErrBadIpHeader = actTime;
			}
			hp->destroy_or_unlock_blockstore();
			return(false);
		}
		// packet is fragmented
		#if not DEFRAG_MOD_OLDVER
		int rsltDefrag = ip_defrag->defrag(header_ip, NULL, hp, fdata_thread_index, -1);
		#else
		int rsltDefrag = handle_defrag(header_ip, (void*)hp, &this->ipfrag_data);
		#endif
		if(rsltDefrag > 0) {
			// packets are reassembled
			header_ip = (iphdr2*)(hp->packet + hp->header->header_ip_offset);
			hp->header->pid.flags |= FLAG_FRAGMENTED;
			if(sverb.defrag) {
				defrag_counter++;
				cout << "*** DEFRAG (pcap_queue) 1 " << defrag_counter << endl;
			}
		} else {
			if(rsltDefrag < 0) {
				hp->destroy_or_unlock_blockstore();
			}
			return(false);
		}
	}
	unsigned headers_ip_counter = 0;
	unsigned headers_ip_offset[20];
	while(headers_ip_counter < sizeof(headers_ip_offset) / sizeof(headers_ip_offset[0]) - 1) {
		headers_ip_offset[headers_ip_counter] = hp->header->header_ip_offset;
		++headers_ip_counter;
		int next_header_ip_offset = findNextHeaderIp(header_ip, hp->header->header_ip_offset, 
							     hp->packet, hp->header->get_caplen());
		if(next_header_ip_offset == 0) {
			break;
		} else if(next_header_ip_offset < 0) {
			hp->destroy_or_unlock_blockstore();
			return(false);
		} else {
			header_ip = (iphdr2*)((u_char*)header_ip + next_header_ip_offset);
			hp->header->header_ip_offset += next_header_ip_offset;
		}
		int frag_data = header_ip->get_frag_data();
		if(header_ip->is_more_frag(frag_data) || header_ip->get_frag_offset(frag_data)) {
			// packet is fragmented
			#if not DEFRAG_MOD_OLDVER
			int rsltDefrag = ip_defrag->defrag(header_ip, NULL, hp, fdata_thread_index, -1);
			#else
			int rsltDefrag = handle_defrag(header_ip, (void*)hp, &this->ipfrag_data);
			#endif
			if(rsltDefrag > 0) {
				header_ip = (iphdr2*)(hp->packet + hp->header->header_ip_offset);
				header_ip->clear_frag_data();
				for(unsigned i = 0; i < headers_ip_counter; i++) {
					iphdr2 *header_ip_prev = (iphdr2*)(hp->packet + headers_ip_offset[i]);
					header_ip_prev->set_tot_len(header_ip->get_tot_len() + (hp->header->header_ip_offset - headers_ip_offset[i]));
					header_ip_prev->clear_frag_data();
					extern unsigned opt_udp_port_vxlan;
					if(opt_udp_port_vxlan &&
					   header_ip_prev->get_protocol() == IPPROTO_UDP) {
						udphdr2 *udphdr = (udphdr2*)((char*)header_ip_prev + header_ip_prev->get_hdr_size());
						if((unsigned)udphdr->get_dest() == opt_udp_port_vxlan) {
							udphdr->len = htons(header_ip_prev->get_tot_len() - header_ip_prev->get_hdr_size());
						}
					}
					extern unsigned opt_udp_port_hperm;
					if(opt_udp_port_hperm &&
					   header_ip_prev->get_protocol() == IPPROTO_UDP) {
						udphdr2 *udphdr = (udphdr2*)((char*)header_ip_prev + header_ip_prev->get_hdr_size());
						if((unsigned)udphdr->get_dest() == opt_udp_port_hperm) {
							udphdr->len = htons(header_ip_prev->get_tot_len() - header_ip_prev->get_hdr_size());
						}
					}
				}
				hp->header->pid.flags |= FLAG_FRAGMENTED;
				if(sverb.defrag) {
					defrag_counter++;
					cout << "*** DEFRAG (pcap_queue) 2 " << defrag_counter << endl;
				}
			} else {
				if(rsltDefrag < 0) {
					hp->destroy_or_unlock_blockstore();
				}
				return(false);
			}
		}
	}
	return(true);
}

void PcapQueue_outputThread::processDefrag_push(sHeaderPacketPQout *hp) {
	#if DEBUG_ALLOC_PACKETS
	if(!hp->block_store) {
		debug_alloc_packet_set(hp->packet, "PcapQueue_outputThread::processDefrag_push (1)");
	}
	#endif
	if(pcapQueueQ_outThread_dedup) {
		pcapQueueQ_outThread_dedup->push(hp);
		#if SNIFFER_THREADS_EXT
		tm_inc_packets_out(hp);
		#endif
		return;
	} else if(pcapQueueQ_outThread_detach2) {
		#if DEBUG_ALLOC_PACKETS
		if(!hp->block_store) {
			debug_alloc_packet_set(hp->packet, "PcapQueue_outputThread::processDefrag_push (2)");
		}
		#endif
		pcapQueueQ_outThread_detach2->push(hp);
		#if SNIFFER_THREADS_EXT
		tm_inc_packets_out(hp);
		#endif
		return;
	}
	if(this->pcapQueue->processPacket_analysis(hp) &&
	   this->pcapQueue->processPacket_push(hp)) {
		#if SNIFFER_THREADS_EXT
		tm_inc_packets_out(hp);
		#endif
		return;
	}
	hp->destroy_or_unlock_blockstore();
}


void PcapQueue_outputThread::processDefrag_cleanup(u_int32_t time_s) {
	if((ipfrag_lastcleanup + 2) < time_s) {
		if(ipfrag_lastcleanup) {
			#if not DEFRAG_MOD_OLDVER
			ip_defrag->cleanup(time_s, false, -1, 2);
			#else
			ipfrag_prune(time_s, false, &this->ipfrag_data, -1, 2);
			#endif
		}
		ipfrag_lastcleanup = time_s;
	}
}

void PcapQueue_outputThread::processDedup(sHeaderPacketPQout *hp) {
	sPacketDuplCheck *_dc = NULL;
	sPacketDuplCheck __dc;
	#if DEDUPLICATE_COLLISION_TEST
	sPacketDuplCheck *_dc_ct_md5 = NULL;
	sPacketDuplCheck __dc_ct_md5;
	#endif
	if(hp->block_store && hp->block_store->hm == pcap_block_store::plus2 && !((pcap_pkthdr_plus2*)hp->header)->dc.is_empty()) {
		_dc = &((pcap_pkthdr_plus2*)hp->header)->dc;
		#if DEDUPLICATE_COLLISION_TEST
		_dc_ct_md5 = &((pcap_pkthdr_plus2*)hp->header)->dc_ct_md5;
		#endif
	} else {
		if(hp->header->header_ip_offset) {
			iphdr2 *header_ip = (iphdr2*)(hp->packet + hp->header->header_ip_offset);
			char *data = NULL;
			int datalen = 0;
			udphdr2 *header_udp = NULL;
			tcphdr2 *header_tcp = NULL;
			u_int8_t ip_protocol = header_ip->get_protocol(hp->header->get_caplen() - hp->header->header_ip_offset);
			if(ip_protocol == IPPROTO_UDP) {
				header_udp = (udphdr2*)((char*)header_ip + header_ip->get_hdr_size());
				datalen = get_udp_data_len(header_ip, header_udp, &data, hp->packet, hp->header->get_caplen());
			} else if(ip_protocol == IPPROTO_TCP) {
				header_tcp = (tcphdr2*)((char*)header_ip + header_ip->get_hdr_size());
				datalen = get_tcp_data_len(header_ip, header_tcp, &data, hp->packet, hp->header->get_caplen());
			} else if (opt_enable_ss7 && ip_protocol == IPPROTO_SCTP) {
				datalen = get_sctp_data_len(header_ip, &data, hp->packet, hp->header->get_caplen());
			}
			if(datalen < 0 || datalen > 0xFFFFF) {
				hp->destroy_or_unlock_blockstore();
				return;
			}
			if(data && datalen) {
				sPacketDuplCheckProc dcp(&__dc, (eDedupType)opt_dup_check_type);
				#if DEDUPLICATE_COLLISION_TEST
				sPacketDuplCheckProc dcp_ct_md5(&__dc_ct_md5, _dedup_md5);
				#endif
				if(opt_dup_check_ipheader) {
					bool header_ip_set_orig = false;
					u_int8_t header_ip_ttl_orig = 0;
					u_int16_t header_ip_check_orig = 0;
					if(opt_dup_check_ipheader_ignore_ttl && opt_dup_check_ipheader == 1) {
						header_ip_ttl_orig = header_ip->get_ttl();
						header_ip_check_orig = header_ip->get_check();
						header_ip->set_ttl(0);
						header_ip->set_check(0);
						header_ip_set_orig = true;
					}
					bool header_udp_set_orig = false;
					u_int16_t header_udp_checksum_orig;
					if(opt_dup_check_udpheader_ignore_checksum && ip_protocol == IPPROTO_UDP) {
						header_udp_checksum_orig = header_udp->check;
						header_udp->check = 0;
						header_udp_set_orig = true;
					}
					if(opt_dup_check_ipheader == 1) {
						int data_dedup_size = MIN(datalen + (data - (char*)header_ip), header_ip->get_tot_len());
						if(data_dedup_size < 0 || data_dedup_size > 0xFFFFF) {
							hp->destroy_or_unlock_blockstore();
							return;
						}
						dcp.data(header_ip, data_dedup_size);
						#if DEDUPLICATE_COLLISION_TEST
						if(opt_dup_check_collision_test) {
							dcp_ct_md5.data(header_ip, data_dedup_size);
						}
						#endif
					} else if(opt_dup_check_ipheader == 2) {
						u_int16_t header_ip_size = header_ip->get_hdr_size();
						u_char *data_dedup = (u_char*)header_ip;
						int data_dedup_size = MIN(datalen + (data - (char*)header_ip), header_ip->get_tot_len());
						if(data_dedup_size > header_ip_size) {
							data_dedup += header_ip_size;
							data_dedup_size -= header_ip_size;
						}
						if(data_dedup_size < 0 || data_dedup_size > 0xFFFFF) {
							hp->destroy_or_unlock_blockstore();
							return;
						}
						dcp.data(data_dedup , data_dedup_size);
						header_ip->md5_update_ip(&dcp);
						#if DEDUPLICATE_COLLISION_TEST
						if(opt_dup_check_collision_test) {
							dcp_ct_md5.data(data_dedup , data_dedup_size);
							header_ip->md5_update_ip(&dcp_ct_md5);
						}
						#endif
					}
					if(header_ip_set_orig) {
						header_ip->set_ttl(header_ip_ttl_orig);
						header_ip->set_check(header_ip_check_orig);
					}
					if(header_udp_set_orig) {
						header_udp->check = header_udp_checksum_orig;
					}
				} else {
					dcp.data(data, datalen);
					#if DEDUPLICATE_COLLISION_TEST
					if(opt_dup_check_collision_test) {
						dcp_ct_md5.data(data, datalen);
					}
					#endif
				}
				dcp.final();
				_dc = &__dc;
				#if DEDUPLICATE_COLLISION_TEST
				if(opt_dup_check_collision_test) {
					dcp_ct_md5.final();
					_dc_ct_md5 = &__dc_ct_md5;
				}
				#endif
			}
		}
	}
	if(_dc) {
		#if DEDUPLICATE_COLLISION_TEST
		bool dupl_ct_md5 = false;
		if(opt_dup_check_collision_test) {
			dupl_ct_md5 = this->dedup_buffer_ct_md5->check_dupl(_dc_ct_md5, (eDedupType)opt_dup_check_type);
		}
		#endif
		if(this->dedup_buffer->check_dupl(_dc, (eDedupType)opt_dup_check_type)) {
			#if DEDUPLICATE_COLLISION_TEST
			if(opt_dup_check_collision_test && !dupl_ct_md5) {
				extern u_int64_t duplicate_counter_collisions;
				++duplicate_counter_collisions;
				if(sverb.dedup_collision) {
					cout << " *** COLLISION B *** " << duplicate_counter_collisions << endl;
					this->dedup_buffer->print_hash(_dc);
				}
			}
			#endif
			extern u_int64_t duplicate_counter;
			duplicate_counter++;
			if(sverb.dedup) {
				cout << "*** DEDUP (processDedup) " << duplicate_counter << endl;
			}
			hp->destroy_or_unlock_blockstore();
			return;
		}
	}
	if(pcapQueueQ_outThread_detach2) {
		pcapQueueQ_outThread_detach2->push(hp);
		#if SNIFFER_THREADS_EXT
		tm_inc_packets_out(hp);
		#endif
		return;
	}
	if(this->pcapQueue->processPacket_analysis(hp) &&
	   this->pcapQueue->processPacket_push(hp)) {
		#if SNIFFER_THREADS_EXT
		tm_inc_packets_out(hp);
		#endif
		return;
	}
	hp->destroy_or_unlock_blockstore();
}

void PcapQueue_outputThread::processDetach2(sHeaderPacketPQout *hp) {
	#if DEBUG_ALLOC_PACKETS
	if(!hp->block_store) {
		debug_alloc_packet_set(hp->packet, "PcapQueue_outputThread::processDetach2");
	}
	#endif
	if(this->pcapQueue->processPacket_analysis(hp) &&
	   this->pcapQueue->processPacket_push(hp)) {
		#if SNIFFER_THREADS_EXT
		tm_inc_packets_out(hp);
		#endif
		return;
	}
	hp->destroy_or_unlock_blockstore();
}

void PcapQueue_outputThread::preparePstatData(int nextThreadIndexPlus, int pstatDataIndex) {
	int thread_id = nextThreadIndexPlus ? this->next_threads[nextThreadIndexPlus - 1].thread_id : this->outThreadId;
	if(thread_id) {
		pstat_data (*thread_pstat_data)[2] = nextThreadIndexPlus ? this->next_threads[nextThreadIndexPlus - 1].thread_pstat_data : this->threadPstatData;
		if(thread_pstat_data[pstatDataIndex][0].cpu_total_time) {
			thread_pstat_data[pstatDataIndex][1] = thread_pstat_data[pstatDataIndex][0];
		}
		pstat_get_data(thread_id, thread_pstat_data[pstatDataIndex]);
	}
}

double PcapQueue_outputThread::getCpuUsagePerc(int nextThreadIndexPlus, int pstatDataIndex, bool preparePstatData) {
	if(preparePstatData) {
		this->preparePstatData(nextThreadIndexPlus, pstatDataIndex);
	}
	int thread_id = nextThreadIndexPlus ? this->next_threads[nextThreadIndexPlus - 1].thread_id : this->outThreadId;
	if(thread_id) {
		double ucpu_usage, scpu_usage;
		pstat_data (*thread_pstat_data)[2] = nextThreadIndexPlus ? this->next_threads[nextThreadIndexPlus - 1].thread_pstat_data : this->threadPstatData;
		if(thread_pstat_data[pstatDataIndex][0].cpu_total_time && thread_pstat_data[pstatDataIndex][1].cpu_total_time) {
			pstat_calc_cpu_usage_pct(
				&thread_pstat_data[pstatDataIndex][0], &thread_pstat_data[pstatDataIndex][1],
				&ucpu_usage, &scpu_usage);
			return(ucpu_usage + scpu_usage);
		}
	}
	return(-1);
}

static volatile int _dpdk_init;
static void *dpdk_main_thread_fce(void *arg) {
	dpdk_do_pre_init(NULL);
	_dpdk_init = true;
	while(!is_terminating()) {
		USLEEP(100000);
	}
	return(NULL);
}

void PcapQueue_init() {
	blockStoreBypassQueue = new FILE_LINE(15061) pcap_block_store_queue;
	if(opt_use_dpdk) {
		if(opt_dpdk_init == 0) {
			dpdk_do_pre_init(NULL);
		} else if(opt_dpdk_init == 1) {
			pthread_t dpdk_main_thread;
			vm_pthread_create_autodestroy("create dpdk main thread",
						      &dpdk_main_thread, NULL,
						      dpdk_main_thread_fce, NULL, 
						      __FILE__, __LINE__);
			while(!_dpdk_init) {
				USLEEP(100000);
			}
		}
	}
}

void PcapQueue_term() {
	delete blockStoreBypassQueue;
}

int getThreadingMode() {
	if(opt_pcap_queue_iface_separate_threads) {
		if(opt_pcap_queue_iface_dedup_separate_threads) {
			return(opt_pcap_queue_iface_dedup_separate_threads_extend == 2 ? 5 :
			       opt_pcap_queue_iface_dedup_separate_threads_extend == 1 ? 4 : 3);
		} else {
			return(2);
		}
	} else {
		return(1);
	}
}

void setThreadingMode(int threadingMode) {
	opt_pcap_queue_iface_separate_threads = 0;
	opt_pcap_queue_iface_dedup_separate_threads = 0;
	opt_pcap_queue_iface_dedup_separate_threads_extend = 0;
	switch(threadingMode) {
	case 2:
		opt_pcap_queue_iface_separate_threads = 1;
		break;
	case 3:
		opt_pcap_queue_iface_separate_threads = 1;
		opt_pcap_queue_iface_dedup_separate_threads = 1;
		break;
	case 4:
	case 5:
	case 6:
		opt_pcap_queue_iface_separate_threads = 1;
		opt_pcap_queue_iface_dedup_separate_threads = 1;
		opt_pcap_queue_iface_dedup_separate_threads_extend = threadingMode == 5 || threadingMode == 6 ? 2 : 1;
		opt_pcap_queue_iface_extend2_use_alloc_stack = threadingMode == 4 || threadingMode == 6;
		break;
	}
}
