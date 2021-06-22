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

#ifndef FREEBSD
#include <malloc.h>
#endif


#define TEST_DEBUG_PARAMS 0
#if TEST_DEBUG_PARAMS == 1
	#define OPT_PCAP_BLOCK_STORE_MAX_ITEMS			2000
	#define OPT_PCAP_FILE_STORE_MAX_BLOCKS			1000
	#define OPT_PCAP_STORE_QUEUE_MAX_BLOCKS_IN_MEMORY	500
	#define OPT_PCAP_STORE_QUEUE_MAX_BLOCKS_IN_DISK		40000
	#define OPT_PCAP_QUEUE_BYPASS_MAX_ITEMS			500
#else
	#define OPT_PCAP_BLOCK_STORE_MAX_ITEMS			2000		// 500 kB
	#define OPT_PCAP_FILE_STORE_MAX_BLOCKS			1000		// 500 MB
	#define OPT_PCAP_STORE_QUEUE_MAX_BLOCKS_IN_MEMORY	500		// 250 MB
	#define OPT_PCAP_STORE_QUEUE_MAX_BLOCKS_IN_DISK		40000		// 20 GB
	#define OPT_PCAP_QUEUE_BYPASS_MAX_ITEMS			500		// 500 MB
#endif
#define AVG_PACKET_SIZE						250


#define VERBOSE 		(verbosity > 0)
#define DEBUG_VERBOSE 		(VERBOSE && false)
#define DEBUG_SLEEP		(DEBUG_VERBOSE && true)
#define DEBUG_ALL_PACKETS	(DEBUG_VERBOSE && false)
#define EXTENDED_LOG		(DEBUG_VERBOSE || (VERBOSE && verbosityE > 1))
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
extern int opt_rrd;
extern int opt_udpfrag;
extern int opt_skinny;
extern int opt_ipaccount;
extern int opt_pcapdump;
extern int opt_dup_check;
extern int opt_dup_check_ipheader;
extern int opt_mirrorip;
extern char opt_mirrorip_src[20];
extern char opt_mirrorip_dst[20];
extern int opt_enable_http;
extern int opt_enable_webrtc;
extern int opt_enable_ssl;
extern int opt_fork;
extern int opt_id_sensor;
extern char opt_name_sensor[256];
extern int opt_mysqlstore_max_threads_cdr;
extern int opt_mysqlstore_max_threads_message;
extern int opt_mysqlstore_max_threads_register;
extern int opt_mysqlstore_max_threads_http;
extern int opt_mysqlstore_max_threads_ipacc_base;
extern int opt_mysqlstore_max_threads_ipacc_agreg2;
extern int opt_mysqlstore_max_threads_charts_cache;
extern int opt_t2_boost;
extern pcap_t *global_pcap_handle;
extern u_int16_t global_pcap_handle_index;
extern char *sipportmatrix;
extern char *httpportmatrix;
extern char *webrtcportmatrix;
extern MirrorIP *mirrorip;
extern char user_filter[10*2048];
extern Calltable *calltable;
extern volatile int calls_counter;
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
extern char opt_pb_read_from_file[256];
extern double opt_pb_read_from_file_speed;
extern int opt_pb_read_from_file_acttime;
extern int opt_pb_read_from_file_acttime_diff_days;
extern int64_t opt_pb_read_from_file_time_adjustment;
extern unsigned int opt_pb_read_from_file_max_packets;
extern bool opt_continue_after_read;
extern bool opt_nonstop_read;
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
#if TEST_DEBUG_PARAMS > 0
	u_int opt_pcap_queue_block_max_time_ms 			= 500;
	size_t opt_pcap_queue_block_max_size   			= OPT_PCAP_BLOCK_STORE_MAX_ITEMS * AVG_PACKET_SIZE;
	u_int opt_pcap_queue_file_store_max_time_ms		= 5000;
	size_t opt_pcap_queue_file_store_max_size		= opt_pcap_queue_block_max_size * OPT_PCAP_FILE_STORE_MAX_BLOCKS;
	uint64_t opt_pcap_queue_store_queue_max_memory_size	= opt_pcap_queue_block_max_size * OPT_PCAP_STORE_QUEUE_MAX_BLOCKS_IN_MEMORY;
	uint64_t opt_pcap_queue_store_queue_max_disk_size	= opt_pcap_queue_block_max_size * OPT_PCAP_STORE_QUEUE_MAX_BLOCKS_IN_DISK;
	uint64_t opt_pcap_queue_bypass_max_size			= opt_pcap_queue_block_max_size * OPT_PCAP_QUEUE_BYPASS_MAX_ITEMS;
#else
	u_int opt_pcap_queue_block_max_time_ms 			= 500;
	size_t opt_pcap_queue_block_max_size   			= 1024 * 1024;
	u_int opt_pcap_queue_file_store_max_time_ms		= 2000;
	size_t opt_pcap_queue_file_store_max_size		= 200 * 1024 * 1024;
	uint64_t opt_pcap_queue_store_queue_max_memory_size	= 200 * 1024 * 1024; //default is 200MB
	uint64_t opt_pcap_queue_store_queue_max_disk_size	= 0;
	uint64_t opt_pcap_queue_bypass_max_size			= 256 * 1024 * 1024;
#endif
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
int opt_pcap_queue_dequeu_method			= 2;
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

size_t _opt_pcap_queue_block_offset_init_size		= opt_pcap_queue_block_max_size / AVG_PACKET_SIZE * 1.1;
size_t _opt_pcap_queue_block_offset_inc_size		= opt_pcap_queue_block_max_size / AVG_PACKET_SIZE / 4;
size_t _opt_pcap_queue_block_restore_buffer_inc_size	= opt_pcap_queue_block_max_size / 4;

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
static unsigned long long sumPacketsSizeCompress[3];
static unsigned long maxBypassBufferItems;
static unsigned long maxBypassBufferSize;
static unsigned long countBypassBufferSizeExceeded;
static double heapPerc = 0;
static double heapTrashPerc = 0;
static unsigned heapFullCounter = 0;

extern MySqlStore *sqlStore;
extern MySqlStore *loadFromQFiles;
extern PcapQueue_outputThread *pcapQueueQ_outThread_defrag;
extern PcapQueue_outputThread *pcapQueueQ_outThread_dedup;

extern unsigned int glob_ssl_calls;

bool packetbuffer_memory_is_full = false;

#include "sniff_inline.h"


pcap_t *pcap_handles[65535];
volatile u_int16_t pcap_handles_count;
volatile int _sync_pcap_handles;

u_int16_t register_pcap_handle(pcap_t *handle) {
	u_int16_t rslt_index;
	while(__sync_lock_test_and_set(&_sync_pcap_handles, 1));
	if(!pcap_handles_count) ++pcap_handles_count;
	rslt_index = pcap_handles_count;
	pcap_handles[pcap_handles_count++] = handle;
	__sync_lock_release(&_sync_pcap_handles);
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

bool pcap_block_store::add_hp(pcap_pkthdr_plus *header, u_char *packet, int memcpy_packet_size) {
	if(this->full) {
		return(false);
	}
	if((this->size + (hm == plus2 ? sizeof(pcap_pkthdr_plus2) : sizeof(pcap_pkthdr_plus)) + header->get_caplen()) > opt_pcap_queue_block_max_size ||
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
	this->size += (hm == plus2 ? sizeof(pcap_pkthdr_plus2) : sizeof(pcap_pkthdr_plus));
	memcpy_heapsafe(this->block + this->size, this->block,
			packet, NULL,
			(memcpy_packet_size ? memcpy_packet_size : header->get_caplen()),
			__FILE__, __LINE__);
	this->size += header->get_caplen();
	this->size_packets += header->get_caplen();
	++this->count;
	return(true);
}

/*bool pcap_block_store::add(pcap_pkthdr_plus *header, u_char *packet) {
	return(this->add((pcap_pkthdr*)header, packet, header->offset, header->dlink));
}*/

void pcap_block_store::inc_h(pcap_pkthdr_plus2 *header) {
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
	this->size += sizeof(pcap_pkthdr_plus2) + header->get_caplen();
	this->size_packets += header->get_caplen();
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
	if(this->size + sizeof(pcap_pkthdr_plus2) + min_size_for_packet > opt_pcap_queue_block_max_size) {
		this->full = true;
		return(false);
	}
	*header = (pcap_pkthdr_plus2*)(this->block + this->size);
	*packet = (u_char*)(this->block + this->size + sizeof(pcap_pkthdr_plus2));
	return(true);
}

bool pcap_block_store::isFull_checkTimeout() {
	if(this->full) {
		return(true);
	}
	if(this->size && getTimeMS_rdtsc() > (this->timestampMS + opt_pcap_queue_block_max_time_ms)) {
		this->full = true;
		return(true);
	}
	return(false);
}

bool pcap_block_store::isTimeout() {
	return(getTimeMS_rdtsc() > (this->timestampMS + opt_pcap_queue_block_max_time_ms));
}

void pcap_block_store::destroy() {
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

int pcap_block_store::addRestoreChunk(u_char *buffer, size_t size, size_t *offset, bool restoreFromStore, string *error) {
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
			_buffer, buffer,
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
		int timeDiff = abs((int64_t)(((pcap_block_store_header*)this->restoreBuffer)->time_s) - (int64_t)(getTimeS())) % 3600;
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
		rsltRestoreChunk = blockStore->addRestoreChunk(readBuff, readed, NULL, true);
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
	sprintf(filePathName, TEST_DEBUG_PARAMS ? "%s/pcap_store_mx_%010u" : "%s/pcap_store_%010u", this->folder.c_str(), this->id);
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
		while(!is_terminating() && buffersControl.getPercUsePB() > 20) {
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
		if(!buffersControl.check__pcap_store_queue__push()) {
			saveToFileStore = true;
		} else if(!__config_ENABLE_TOGETHER_READ_WRITE_FILE) {
			this->lock_fileStore();
			locked_fileStore = true;
			if(this->fileStore.size() &&
			   !this->fileStore[this->fileStore.size() - 1]->isFull(buffersControl.get__pcap_store_queue__sizeOfBlocksInMemory() == 0)) {
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
			u_int64_t actTime = getTimeMS();
			if(actTime - 1000 > this->lastTimeLogErrDiskIsFull) {
				syslog(LOG_ERR, "packetbuffer: DISK IS FULL");
				this->lastTimeLogErrDiskIsFull = actTime;
			}
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
		this->unlock_fileStore();
		if(!fileStore->push(blockStore)) {
			if(deleteBlockStoreIfFail) {
				delete blockStore;
			}
			return(false);
		}
	} else {
		if(locked_fileStore) {
			this->unlock_fileStore();
		}
		if(!buffersControl.check__pcap_store_queue__push()) {
			u_int64_t actTime = getTimeMS();
			if(actTime - 1000 > this->lastTimeLogErrMemoryIsFull) {
				syslog(LOG_ERR, "packetbuffer: MEMORY IS FULL");
				this->lastTimeLogErrMemoryIsFull = actTime;
			}
			if(deleteBlockStoreIfFail) {
				delete blockStore;
			}
			packetbuffer_memory_is_full = true;
			return(false);
		} else {
			this->add_sizeOfBlocksInMemory(blockStore->getUseAllSize());
			packetbuffer_memory_is_full = false;
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
	if(*blockStore) {
		if((*blockStore)->idFileStore) {
			pcap_file_store *_fileStore = this->findFileStoreById((*blockStore)->idFileStore);
			if(!_fileStore) {
				delete *blockStore;
				return(false);
			}
			unsigned int usleepCounter = 0;
			while(!__config_ENABLE_TOGETHER_READ_WRITE_FILE && !_fileStore->full) {
				USLEEP_C(100, usleepCounter++);
			}
			if(!_fileStore->pop(*blockStore)) {
				delete *blockStore;
				return(false);
			}
		} else {
			this->sub_sizeOfBlocksInMemory((*blockStore)->getUseAllSize());
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
	this->pcapStatCounter = 0;
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

void PcapQueue::pcapStat(int statPeriod, bool statCalls) {
	u_int64_t startTimeMS = getTimeMS_rdtsc();
	vector<u_int64_t> lapTime;
	vector<string> lapTimeDescr;
	
	++pcapStatCounter;

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
	sumPacketsSizeCompress[2] = sumPacketsSizeCompress[0] - sumPacketsSizeCompress[1];
	sumPacketsSizeCompress[1] = sumPacketsSizeCompress[0];

	extern int opt_cpu_limit_warning_t0;
	extern int opt_cpu_limit_new_thread;
	extern int opt_cpu_limit_new_thread_high;
	extern int opt_cpu_limit_delete_thread;
	extern int opt_cpu_limit_delete_t2sip_thread;

	if(this->instancePcapHandle) {
		if(this->instancePcapHandle->initAllReadThreadsFinished) {
			this->instancePcapHandle->prepareLogTraffic();
		} else {
			return;
		}
	}
	ostringstream outStr;
	pcap_drop_flag = 0;
	if(sverb.log_profiler) {
		lapTime.push_back(getTimeMS_rdtsc());
		lapTimeDescr.push_back("pcapStatString_interface-before");
	}
	string pcapStatString_interface_rslt = this->instancePcapHandle ? 
						this->instancePcapHandle->pcapStatString_interface(statPeriod) :
						this->pcapStatString_interface(statPeriod);
	if(sverb.log_profiler) {
		lapTime.push_back(getTimeMS_rdtsc());
		lapTimeDescr.push_back("pcapStatString_interface-after");
	}
	if(EXTENDED_LOG) {
		string statString = "\n";
		if(statCalls) {
			ostringstream outStr;
			outStr << "CALLS: " << calltable->getCountCalls() << ", " << calls_counter;
			if(opt_ipaccount) {
				outStr << "  IPACC_BUFFER " << lengthIpaccBuffer();
			}
			outStr << endl;
			statString += outStr.str();
		}
		statString += 
			this->pcapStatString_packets(statPeriod) +
			(this->instancePcapHandle ? 
				this->instancePcapHandle->pcapStatString_bypass_buffer(statPeriod) :
				this->pcapStatString_bypass_buffer(statPeriod)) +
			this->pcapStatString_memory_buffer(statPeriod) +
			this->pcapStatString_disk_buffer(statPeriod) +
			pcapStatString_interface_rslt +
			"\n";
		if(statString.length()) {
			if(DEBUG_VERBOSE) {
				cout << statString;
			} else {
				syslog(LOG_NOTICE, "packetbuffer stat:");
				char *pointToBeginLine = (char*)statString.c_str();
				while(pointToBeginLine && *pointToBeginLine) {
					char *pointToLineBreak = strchr(pointToBeginLine, '\n');
					if(pointToLineBreak) {
						*pointToLineBreak = '\0';
					}
					syslog(LOG_NOTICE, "%s", pointToBeginLine);
					if(pointToLineBreak) {
						*pointToLineBreak = '\n';
						pointToBeginLine = pointToLineBreak + 1;
					} else {
						pointToBeginLine = NULL;
					}
				}
			}
		}
	} else {
		double memoryBufferPerc = buffersControl.getPercUsePBwithouttrash();
		heapPerc = memoryBufferPerc;
		double memoryBufferPerc_trash = buffersControl.getPercUsePBtrash();
		heapTrashPerc = memoryBufferPerc_trash;
		outStr << fixed;
		if(sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("check heap");
		}
		if(!this->isMirrorSender()) {
			outStr << "calls[" << calltable->getCountCalls() << ",r:" << calltable->registers_listMAP.size() << "]"
			       << "[" << calls_counter << ",r:" << registers_counter << "]";
			calltable->lock_calls_audioqueue();
			size_t audioQueueSize = calltable->audio_queue.size();
			if(audioQueueSize) {
				size_t audioQueueThreads = calltable->getCountAudioQueueThreads();
				outStr << "[" << audioQueueSize << "/" << audioQueueThreads <<"]";
			}
			calltable->unlock_calls_audioqueue();
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
			if (opt_rrd) {
				rrd_set_value(RRD_VALUE_inv, calltable->getCountCalls());
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
					if (opt_rrd) {
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
					if (opt_rrd) {
						rrd_set_value(RRD_VALUE_PS_S0, v);
					}
				} else {
					outStr << "-";
				}
				outStr << "/";
				if(this->counter_sip_packets_old[1]) {
					long unsigned v = (counter_sip_packets[1] - this->counter_sip_packets_old[1]) / statPeriod;
					outStr << v;
					if (opt_rrd) {
						rrd_set_value(RRD_VALUE_PS_S1, v);
					}
				} else {
					outStr << "-";
				}
				outStr << " SR:";
				if(this->counter_sip_register_packets_old) {
					long unsigned v = (counter_sip_register_packets - this->counter_sip_register_packets_old) / statPeriod;
					outStr << v;
					if (opt_rrd) {
						rrd_set_value(RRD_VALUE_PS_SR, v);
					}
				} else {
					outStr << "-";
				}
				outStr << " SM:";
				if(this->counter_sip_message_packets_old) {
					long unsigned v = (counter_sip_message_packets - this->counter_sip_message_packets_old) / statPeriod;
					outStr << v;
					if (opt_rrd) {
						rrd_set_value(RRD_VALUE_PS_SM, v);
					}
				} else {
					outStr << "-";
				}
				outStr << " R:";
				if(this->counter_rtp_packets_old[0]) {
					long unsigned v = (counter_rtp_packets[0] - this->counter_rtp_packets_old[0]) / statPeriod;
					outStr << v;
					if (opt_rrd) {
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
					if (opt_rrd) {
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
			extern bool opt_save_query_to_files;
			if(loadFromQFiles) {
				bool fill = false;
				string stat = loadFromQFiles->getLoadFromQFilesStat();
				string stat_proc = sverb.qfiles ? loadFromQFiles->getLoadFromQFilesStat(true) : "";
				u_int32_t avgDelayQuery = SqlDb::getAvgDelayQuery(SqlDb::_tq_store);
				u_int32_t countFilesQuery = loadFromQFiles->getLoadFromQFilesCount();
				SqlDb::resetDelayQuery(SqlDb::_tq_store);
				if(!stat.empty() || avgDelayQuery || !stat_proc.empty()) {
					outStr << "SQLf[";
				}
				if(!stat.empty()) {
					outStr << stat;
					fill = true;
				}
				if(avgDelayQuery) {
					if(fill) {
						outStr << " / ";
					}
					outStr << setprecision(3) << (double)avgDelayQuery / 1000 << "s";
					fill = true;
					if (opt_rrd) {
						rrd_set_value(RRD_VALUE_SQLf_D, avgDelayQuery);
						rrd_set_value(RRD_VALUE_SQLf_C, countFilesQuery);
					}
				}
				if(!stat_proc.empty()) {
					if(fill) {
						outStr << " / ";
					}
					outStr << stat_proc;
					fill = true;
				}
				if(fill) {
					outStr << "] ";
				}
			}
			if(!loadFromQFiles || !opt_save_query_to_files || sverb.force_log_sqlq) {
				outStr << "SQLq[";
				if(isCloud()) {
					int sizeSQLq = sqlStore->getSize(1, 0) +
						       (loadFromQFiles ? loadFromQFiles->getSize(1, 0) : 0);
					outStr << (sizeSQLq >=0 ? sizeSQLq : 0);
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
							id_main == STORE_PROC_ID_CHARTS_CACHE  ? "ch" :
							id_main == STORE_PROC_ID_MESSAGE ? "M" :
							id_main == STORE_PROC_ID_REGISTER ? "R" :
							id_main == STORE_PROC_ID_SS7 ? "7" :
							id_main == STORE_PROC_ID_SAVE_PACKET_SQL ? "L" :
							id_main == STORE_PROC_ID_CLEANSPOOL ? "Cl" :
							id_main == STORE_PROC_ID_HTTP ? "H" :
							("i" + intToString(id_main) + "_");
						outStr << (first ? "" : " ") << id_main_str << (id_2 + 1) << ":" << size;
						first = false;
					}
					if(opt_rrd) {
						for(map<int, int>::iterator iter = size_map.begin(); iter != size_map.end(); iter++) {
							int id_main = iter->first;
							int size = iter->second;
							const char *id_main_rrd_str = 
								id_main == STORE_PROC_ID_CDR ? RRD_VALUE_SQLq_C :
								id_main == STORE_PROC_ID_MESSAGE ? RRD_VALUE_SQLq_M :
								id_main == STORE_PROC_ID_REGISTER ? RRD_VALUE_SQLq_R :
								id_main == STORE_PROC_ID_HTTP ? RRD_VALUE_SQLq_H :
								NULL;
							if(id_main_rrd_str) {
								rrd_add_value(id_main_rrd_str, size);
							}
						}
					}
					#if 0
					int sizeSQLq;
					for(int i = 0; i < opt_mysqlstore_max_threads_cdr; i++) {
						sizeSQLq = sqlStore->getSize(STORE_PROC_ID_CDR, i) +
							   (loadFromQFiles ? loadFromQFiles->getSize(STORE_PROC_ID_CDR, i) : 0);
						if(i == 0 || sizeSQLq >= 1) {
							if(i) {
								outStr << " C" << (i+1) << ":";
							} else {
								outStr << "C:";
								if(sizeSQLq < 0) {
									sizeSQLq = 0;
								}
							}
							outStr << sizeSQLq;
							if (opt_rrd) {
								rrd_add_value(RRD_VALUE_SQLq_C, sizeSQLq);
							}
						}
					}
					for(int i = 0; i < opt_mysqlstore_max_threads_charts_cache; i++) {
						sizeSQLq = sqlStore->getSize(STORE_PROC_ID_CHARTS_CACHE, i) +
							   (loadFromQFiles ? loadFromQFiles->getSize(STORE_PROC_ID_CHARTS_CACHE, i) : 0);
						if(sizeSQLq >= 0) {
							if(i) {
								outStr << " ch" << (i+1) << ":";
							} else {
								outStr << " ch:";
								if(sizeSQLq < 0) {
									sizeSQLq = 0;
								}
							}
							outStr << sizeSQLq;
						}
					}
					for(int i = 0; i < opt_mysqlstore_max_threads_charts_cache; i++) {
						sizeSQLq = sqlStore->getSize(STORE_PROC_ID_CHARTS_CACHE_REMOTE, i) +
						           (loadFromQFiles ? loadFromQFiles->getSize(STORE_PROC_ID_CHARTS_CACHE_REMOTE, i) : 0);
						if(sizeSQLq >= 0) {
							if(i) {
								outStr << " chr" << (i+1) << ":";
							} else {
								outStr << " chr:";
								if(sizeSQLq < 0) {
									sizeSQLq = 0;
								}
							}
							outStr << sizeSQLq;
						}
					}
					for(int i = 0; i < opt_mysqlstore_max_threads_message; i++) {
						sizeSQLq = sqlStore->getSize(STORE_PROC_ID_MESSAGE, i) +
							   (loadFromQFiles ? loadFromQFiles->getSize(STORE_PROC_ID_MESSAGE, i) : 0);
						if(sizeSQLq >= (i ? 1 : 0)) {
							if(i) {
								outStr << " M" << (i+1) << ":";
							} else {
								outStr << " M:";
								if(sizeSQLq < 0) {
									sizeSQLq = 0;
								}
							}
							outStr << sizeSQLq;
							if (opt_rrd) {
								rrd_add_value(RRD_VALUE_SQLq_M, sizeSQLq / 100);
							}
						}
					}
					for(int i = 0; i < opt_mysqlstore_max_threads_register; i++) {
						sizeSQLq = sqlStore->getSize(STORE_PROC_ID_REGISTER, i) +
							   (loadFromQFiles ? loadFromQFiles->getSize(STORE_PROC_ID_REGISTER, i) : 0);
						if(sizeSQLq >= (i ? 1 : 0)) {
							if(i) {
								outStr << " R" << (i+1) << ":";
							} else {
								outStr << " R:";
								if(sizeSQLq < 0) {
									sizeSQLq = 0;
								}
							}
							outStr << sizeSQLq;
							if (opt_rrd) {
								rrd_add_value(RRD_VALUE_SQLq_R, sizeSQLq / 100);
							}
						}
					}
					if(opt_enable_ss7) {
						sizeSQLq = sqlStore->getSize(STORE_PROC_ID_SS7, -1) +
							   (loadFromQFiles ? loadFromQFiles->getSize(STORE_PROC_ID_SS7, -1) : 0);
						if(sizeSQLq >= 0) {
							outStr << " 7:" << sizeSQLq;
						}
					}
					sizeSQLq = sqlStore->getSize(STORE_PROC_ID_SAVE_PACKET_SQL, -1) +
						   (loadFromQFiles ? loadFromQFiles->getSize(STORE_PROC_ID_SAVE_PACKET_SQL, -1) : 0);
					if(sizeSQLq >= 0) {
						outStr << " L:" << sizeSQLq;
					}
					sizeSQLq = sqlStore->getSize(STORE_PROC_ID_CLEANSPOOL, -1) + 
						   (loadFromQFiles ? loadFromQFiles->getSize(STORE_PROC_ID_CLEANSPOOL, -1) : 0);
					if(sizeSQLq >= 0) {
						outStr << " Cl:" << sizeSQLq;
						if (opt_rrd) {
							rrd_set_value(RRD_VALUE_SQLq_Cl, sizeSQLq / 100);
						}
					}
					for(int i = 0; i < opt_mysqlstore_max_threads_http; i++) {
						sizeSQLq = sqlStore->getSize(STORE_PROC_ID_HTTP, i) +
							   (loadFromQFiles ? loadFromQFiles->getSize(STORE_PROC_ID_HTTP, i) : 0);
						if(sizeSQLq >= (i ? 1 : 0)) {
							if(i) {
								outStr << " H" << (i+1) << ":";
							} else {
								outStr << " H:";
							}
							outStr << sizeSQLq;
							if (opt_rrd) {
								rrd_add_value(RRD_VALUE_SQLq_H, sizeSQLq / 100);
							}
						}
					}
					if(opt_ipaccount) {
						for(int i = 0; i < opt_mysqlstore_max_threads_ipacc_base; i++) {
							sizeSQLq = sqlStore->getSize(STORE_PROC_ID_IPACC, i) + 
								   (loadFromQFiles ? loadFromQFiles->getSize(STORE_PROC_ID_IPACC, i) : 0);
							if(sizeSQLq >= 1) {
								outStr << " I" << (STORE_PROC_ID_IPACC + i) << ":" << sizeSQLq;
							}
						}
						for(int i = STORE_PROC_ID_IPACC_AGR_INTERVAL; i <= STORE_PROC_ID_IPACC_AGR_DAY; i++) {
							sizeSQLq = sqlStore->getSize(i, -1) +
								   (loadFromQFiles ? loadFromQFiles->getSize(i, -1) : 0);
							if(sizeSQLq >= 1) {
								outStr << " I" << i << ":" << sizeSQLq;
							}
						}
						for(int i = 0; i < opt_mysqlstore_max_threads_ipacc_agreg2; i++) {
							sizeSQLq = sqlStore->getSize(STORE_PROC_ID_IPACC_AGR2_HOUR, i) +
								   (loadFromQFiles ? loadFromQFiles->getSize(STORE_PROC_ID_IPACC_AGR2_HOUR, i) : 0);
							if(sizeSQLq >= 1) {
								outStr << " I" << (STORE_PROC_ID_IPACC_AGR2_HOUR + i) << ":" << sizeSQLq;
							}
						}
						/*
						sizeSQLq = sqlStoreLog->getSizeMult(12,
										    STORE_PROC_ID_IPACC_1,
										    STORE_PROC_ID_IPACC_2,
										    STORE_PROC_ID_IPACC_3,
										    STORE_PROC_ID_IPACC_AGR_INTERVAL,
										    STORE_PROC_ID_IPACC_AGR_HOUR,
										    STORE_PROC_ID_IPACC_AGR_DAY,
										    STORE_PROC_ID_IPACC_AGR2_HOUR_1,
										    STORE_PROC_ID_IPACC_AGR2_HOUR_2,
										    STORE_PROC_ID_IPACC_AGR2_HOUR_3,
										    STORE_PROC_ID_IPACC_AGR2_DAY_1,
										    STORE_PROC_ID_IPACC_AGR2_DAY_2,
										    STORE_PROC_ID_IPACC_AGR2_DAY_3);
						if(sizeSQLq >= 0) {
							outStr << " I:" << sizeSQLq;
						}
						*/
					}
					#endif
				}
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
			if(sverb.log_profiler) {
				lapTime.push_back(getTimeMS_rdtsc());
				lapTimeDescr.push_back("sql");
			}
		}
		outStr << "heap[" << setprecision(0) << memoryBufferPerc << "|"
				  << setprecision(0) << memoryBufferPerc_trash;
		if(sverb.heap_use_time) {
			unsigned long trashMinTime;
			unsigned long trashMaxTime;
			buffersControl.PcapQueue_readFromFifo__blockStoreTrash_time_get(&trashMinTime, &trashMaxTime);
			buffersControl.PcapQueue_readFromFifo__blockStoreTrash_time_clear();
			if(trashMinTime || trashMaxTime) {
				outStr << "(" << trashMinTime << "-" << trashMaxTime << "ms)";
			}
		}
		outStr << "|";
		if(opt_rrd) {
			rrd_set_value(RRD_VALUE_buffer, memoryBufferPerc + memoryBufferPerc_trash);
		}
		if(sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("heap");
		}
		double useAsyncWriteBuffer = buffersControl.getPercUseAsync();
		if(useAsyncWriteBuffer > 50) {
			if(CleanSpool::suspend()) {
				syslog(LOG_NOTICE, "large workload disk operation - cleanspool suspended");
			}
		} else if(useAsyncWriteBuffer < 10) {
			if(CleanSpool::resume()) {
				syslog(LOG_NOTICE, "cleanspool resumed");
			}
		}
		outStr << setprecision(0) << useAsyncWriteBuffer << "] ";
		if(opt_rrd) {
			rrd_set_value(RRD_VALUE_ratio, useAsyncWriteBuffer);
		}
		if(this->instancePcapHandle) {
			unsigned long bypassBufferSizeExeeded = this->instancePcapHandle->pcapStat_get_bypass_buffer_size_exeeded();
			string statPacketDrops = this->instancePcapHandle->getStatPacketDrop();
			if(bypassBufferSizeExeeded || !statPacketDrops.empty()) {
				outStr << "drop[";
				if(bypassBufferSizeExeeded) {
					outStr << "H:" << bypassBufferSizeExeeded;
					if(opt_rrd) {
						rrd_set_value(RRD_VALUE_exceeded, bypassBufferSizeExeeded);
					}
				}
				if(!statPacketDrops.empty()) {
					if(bypassBufferSizeExeeded) {
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
		double speed = this->pcapStat_get_speed_mb_s(statPeriod);
		if(speed >= 0) {
			outStr << "[" << setprecision(1) << speed << "Mb/s] ";
			if (opt_rrd) {
				rrd_set_value(RRD_VALUE_mbs, speed);
			}
			last_traffic = speed;
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
		outStr << "tarQ[" << glob_tar_queued_files << "] ";
		u_int64_t tarBufferSize = ChunkBuffer::getChunkBuffersSumsize();
		if(tarBufferSize) {
			outStr << "tarB[" << setprecision(0) << tarBufferSize / 1024 / 1024 << "MB] ";
		}
		if(sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("tarbuffer");
		}
		extern TarQueue *tarQueue[2];
		for(int i = 0; i < 2; i++) {
			if(tarQueue[i]) {
				bool okPercTarCpu = false;
				for(int j = 0; j < tarQueue[i]->maxthreads; j++) {
					double tar_cpu = tarQueue[i]->getCpuUsagePerc(j, true);
					if(tar_cpu > 0) {
						if(okPercTarCpu) {
							outStr << '|';
						} else {
							outStr << (i ? "tarCPU-spool2[" : "tarCPU[");
							okPercTarCpu = true;
						}
						outStr << setprecision(1) << tar_cpu;
						if (opt_rrd) {
							rrd_add_value(RRD_VALUE_tarCPU, tar_cpu);
						}
					}
				}
				if(okPercTarCpu) {
					outStr << "%] ";
				}
			}
		}
		if(sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("tar");
		}
	}
	ostringstream outStrStat;
	outStrStat << fixed;
	if(this->instancePcapHandle) {
		double sumMaxReadThreads;
		int countThreadsSumMaxReadThreads;
		outStrStat << this->instancePcapHandle->pcapStatString_cpuUsageReadThreads(&sumMaxReadThreads, &countThreadsSumMaxReadThreads, statPeriod);
		double t0cpu = this->instancePcapHandle->getCpuUsagePerc(mainThread, true);
		double t0cpuWrite = this->instancePcapHandle->getCpuUsagePerc(writeThread, true);
		double t0cpuNextThreads[PCAP_QUEUE_NEXT_THREADS_MAX];
		for(int i = 0; i < PCAP_QUEUE_NEXT_THREADS_MAX; i++) {
			t0cpuNextThreads[i] = this->instancePcapHandle->getCpuUsagePerc((eTypeThread)(nextThread1 + i), true);
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
			if (opt_rrd) {
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
	string t1cpu = this->getCpuUsage(false, true);
	if(t1cpu.length()) {
		outStrStat << t1cpu << " ";
	} else {
		double t1cpu = this->getCpuUsagePerc(mainThread, true);
		if(t1cpu >= 0) {
			outStrStat << "t1CPU[" << setprecision(1) << t1cpu << "%] ";
			if (opt_rrd) {
				rrd_set_value(RRD_VALUE_tCPU_t1, t1cpu);
			}
		}
	}
	if(sverb.log_profiler) {
		lapTime.push_back(getTimeMS_rdtsc());
		lapTimeDescr.push_back("t1");
	}
	double t2cpu = this->getCpuUsagePerc(writeThread, true);
	if(t2cpu >= 0) {
		if(isMirrorSender()) {
			outStrStat << "t2CPU[" << t2cpu;
		} else {
			outStrStat << "t2CPU[" << "pb:" << setprecision(1) << t2cpu;
			if(opt_pcap_queue_dequeu_method &&
			   !opt_pcap_queue_dequeu_need_blocks &&
			   opt_pcap_queue_dequeu_window_length > 0) {
				if(heapPerc > 30 && t2cpu > opt_cpu_limit_new_thread_high) {
					if(opt_pcap_queue_dequeu_window_length_div < 100) {
						if(!opt_pcap_queue_dequeu_window_length_div) {
							opt_pcap_queue_dequeu_window_length_div = 2;
						} else {
							opt_pcap_queue_dequeu_window_length_div *= 2;
						}
						syslog(LOG_INFO, "decrease pcap_queue_deque_window_length to %i", 
						       opt_pcap_queue_dequeu_window_length / opt_pcap_queue_dequeu_window_length_div);
					}
				} else if(heapPerc < 5 && t2cpu < 30 &&
					  opt_pcap_queue_dequeu_window_length_div > 0) {
					if(opt_pcap_queue_dequeu_window_length_div > 2) {
						opt_pcap_queue_dequeu_window_length_div /= 2;
						syslog(LOG_INFO, "increase pcap_queue_deque_window_length to %i", 
						       opt_pcap_queue_dequeu_window_length / opt_pcap_queue_dequeu_window_length_div);
					} else {
						opt_pcap_queue_dequeu_window_length_div = 0;
						syslog(LOG_INFO, "restore pcap_queue_deque_window_length to %i", 
						       opt_pcap_queue_dequeu_window_length);
					}
				}
			}
			if(pcapQueueQ_outThread_defrag) {
				double defrag_cpu = pcapQueueQ_outThread_defrag->getCpuUsagePerc(true);
				if(defrag_cpu >= 0) {
					outStrStat << "/defrag:" << setprecision(1) << defrag_cpu;
				}
			}
			if(pcapQueueQ_outThread_dedup) {
				double dedup_cpu = pcapQueueQ_outThread_dedup->getCpuUsagePerc(true);
				if(dedup_cpu >= 0) {
					outStrStat << "/dedup:" << setprecision(1) << dedup_cpu;
				}
			}
			if(opt_ipaccount) {
				double ipacc_cpu = this->getCpuUsagePerc(destroyBlocksThread, true);
				if(ipacc_cpu >= 0) {
					outStrStat << "/ipacc:" << setprecision(1) << ipacc_cpu;
				}
			}
			double last_t2cpu_preprocess_packet_out_thread_check_next_level = -2;
			double call_t2cpu_preprocess_packet_out_thread = -2;
			double last_t2cpu_preprocess_packet_out_thread_rtp = -2;
			int count_t2cpu = 1;
			double sum_t2cpu = t2cpu;
			last_t2cpu_preprocess_packet_out_thread_check_next_level = t2cpu;
			last_t2cpu_preprocess_packet_out_thread_rtp = t2cpu;
			for(int i = 0; i < PreProcessPacket::ppt_end_base; i++) {
				for(int j = 0; j < 1 + MAX_PRE_PROCESS_PACKET_NEXT_THREADS; j++) {
					if(j == 0 || preProcessPacket[i]->existsNextThread(j - 1)) {
						double percFullQring;
						double t2cpu_preprocess_packet_out_thread = preProcessPacket[i]->getCpuUsagePerc(true, j, j == 0 ? &percFullQring : NULL);
						if(t2cpu_preprocess_packet_out_thread >= 0) {
							outStrStat << "/" 
								   << preProcessPacket[i]->getShortcatTypeThread()
								   << setprecision(1) << t2cpu_preprocess_packet_out_thread;
							if(sverb.qring_stat) {
								double qringFillingPerc = preProcessPacket[i]->getQringFillingPerc();
								if(qringFillingPerc > 0) {
									outStrStat << "r" << qringFillingPerc;
								}
							}
							if(sverb.qring_full && percFullQring > sverb.qring_full) {
								outStrStat << "#" << percFullQring;
							}
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
							++count_t2cpu;
							sum_t2cpu += t2cpu_preprocess_packet_out_thread;
							if(preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_call &&
							   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_register && 
							   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_sip_other && 
							   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_rtp && 
							   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_other) {
								last_t2cpu_preprocess_packet_out_thread_check_next_level = t2cpu_preprocess_packet_out_thread;
							}
							if(preProcessPacket[i]->getTypePreProcessThread() == PreProcessPacket::ppt_pp_call) {
								call_t2cpu_preprocess_packet_out_thread = t2cpu_preprocess_packet_out_thread;
							}
							if(preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_call &&
							   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_register && 
							   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_sip_other && 
							   preProcessPacket[i]->getTypePreProcessThread() != PreProcessPacket::ppt_pp_other) {
								last_t2cpu_preprocess_packet_out_thread_rtp = t2cpu_preprocess_packet_out_thread;
							}
							if(j == 0 && opt_t2_boost &&
							   t2cpu_preprocess_packet_out_thread > opt_cpu_limit_new_thread_high &&
							   heapPerc > 10 &&
							   (preProcessPacket[i]->getTypePreProcessThread() == PreProcessPacket::ppt_detach ||
							    preProcessPacket[i]->getTypePreProcessThread() == PreProcessPacket::ppt_sip)) {
								preProcessPacket[i]->addNextThread();
							}
						}
					}
				}
			}
			if(opt_t2_boost) {
				if(preProcessPacketCallX && calltable->useCallX()) {
					for(int i = 0; i < preProcessPacketCallX_count + 1; i++) {
						double percFullQring;
						double t2cpu_preprocess_packet_out_thread = preProcessPacketCallX[i]->getCpuUsagePerc(true, 0, &percFullQring);
						if(t2cpu_preprocess_packet_out_thread >= 0) {
							outStrStat << "/" 
								   << preProcessPacketCallX[i]->getShortcatTypeThread()
								   << setprecision(1) << t2cpu_preprocess_packet_out_thread;
							if(sverb.qring_stat) {
								double qringFillingPerc = preProcessPacketCallX[i]->getQringFillingPerc();
								if(qringFillingPerc > 0) {
									outStrStat << "r" << qringFillingPerc;
								}
							}
							if(sverb.qring_full && percFullQring > sverb.qring_full) {
								outStrStat << "#" << percFullQring;
							}
							++count_t2cpu;
							sum_t2cpu += t2cpu_preprocess_packet_out_thread;
						}
					}
				}
				if(preProcessPacketCallFindX && calltable->useCallFindX()) {
					for(int i = 0; i < preProcessPacketCallX_count; i++) {
						double percFullQring;
						double t2cpu_preprocess_packet_out_thread = preProcessPacketCallFindX[i]->getCpuUsagePerc(true, 0, &percFullQring);
						if(t2cpu_preprocess_packet_out_thread >= 0) {
							outStrStat << "/" 
								   << preProcessPacketCallFindX[i]->getShortcatTypeThread()
								   << setprecision(1) << t2cpu_preprocess_packet_out_thread;
							if(sverb.qring_stat) {
								double qringFillingPerc = preProcessPacketCallFindX[i]->getQringFillingPerc();
								if(qringFillingPerc > 0) {
									outStrStat << "r" << qringFillingPerc;
								}
							}
							if(sverb.qring_full && percFullQring > sverb.qring_full) {
								outStrStat << "#" << percFullQring;
							}
							++count_t2cpu;
							sum_t2cpu += t2cpu_preprocess_packet_out_thread;
						}
					}
				}
			}
			if(opt_rrd) {
				rrd_set_value(RRD_VALUE_tCPU_t2, sum_t2cpu);
			}
			int countRtpRhThreads = 0;
			bool needAddRtpRhThreads = false;
			int countRtpRdThreads = 0;
			bool needAddRtpRdThreads = false;
			if(processRtpPacketHash) {
				for(int i = 0; i < 1 + MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS; i++) {
					if(i == 0 || processRtpPacketHash->existsNextThread(i - 1)) {
						double percFullQring;
						double t2cpu_process_rtp_packet_out_thread = processRtpPacketHash->getCpuUsagePerc(true, i, i == 0 ? &percFullQring : NULL);
						if(t2cpu_process_rtp_packet_out_thread >= 0) {
							outStrStat << "/" << (i == 0 ? "rm:" : "rh:")
								   << setprecision(1) << t2cpu_process_rtp_packet_out_thread;
							if(i == 0 && sverb.qring_stat) {
								double qringFillingPerc = processRtpPacketHash->getQringFillingPerc();
								if(qringFillingPerc > 0) {
									outStrStat << "r" << qringFillingPerc;
								}
							}
							if(i == 0 && sverb.qring_full && percFullQring > sverb.qring_full) {
								outStrStat << "#" << percFullQring;
							}
							++count_t2cpu;
							sum_t2cpu += t2cpu_process_rtp_packet_out_thread;
						}
						if(i > 0) {
							++countRtpRhThreads;
							if(t2cpu_process_rtp_packet_out_thread > opt_cpu_limit_new_thread) {
								needAddRtpRhThreads = true;
							}
						}
					}
				}
				for(int i = 0; i < MAX_PROCESS_RTP_PACKET_THREADS; i++) {
					if(processRtpPacketDistribute[i]) {
						double percFullQring;
						double t2cpu_process_rtp_packet_out_thread = processRtpPacketDistribute[i]->getCpuUsagePerc(true,0, &percFullQring);
						if(t2cpu_process_rtp_packet_out_thread >= 0) {
							outStrStat << "/" << "rd:" << setprecision(1) << t2cpu_process_rtp_packet_out_thread;
							if(sverb.qring_stat) {
								double qringFillingPerc = processRtpPacketDistribute[i]->getQringFillingPerc();
								if(qringFillingPerc > 0) {
									outStrStat << "r" << qringFillingPerc;
								}
							}
							if(sverb.qring_full && percFullQring > sverb.qring_full) {
								outStrStat << "#" << percFullQring;
							}
						}
						++countRtpRdThreads;
						if(t2cpu_process_rtp_packet_out_thread > opt_cpu_limit_new_thread) {
							needAddRtpRdThreads = true;
						}
						++count_t2cpu;
						sum_t2cpu += t2cpu_process_rtp_packet_out_thread;
					}
				}
			}
			extern int opt_enable_preprocess_packet;
			if(opt_enable_preprocess_packet == -1) {
				if(last_t2cpu_preprocess_packet_out_thread_check_next_level > opt_cpu_limit_new_thread) {
					PreProcessPacket::autoStartNextLevelPreProcessPacket();
				} else if(last_t2cpu_preprocess_packet_out_thread_check_next_level < opt_cpu_limit_delete_t2sip_thread) {
					PreProcessPacket::autoStopLastLevelPreProcessPacket();
				}
			}
			if(call_t2cpu_preprocess_packet_out_thread > opt_cpu_limit_new_thread_high &&
			   heapPerc > 10 &&
			   calltable->enableCallX() && !calltable->useCallX()) {
				PreProcessPacket::autoStartCallX_PreProcessPacket();
			}
			if(last_t2cpu_preprocess_packet_out_thread_rtp > opt_cpu_limit_new_thread) {
				ProcessRtpPacket::autoStartProcessRtpPacket();
			}
			extern int opt_process_rtp_packets_hash_next_thread_max;
			if(countRtpRhThreads < MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS &&
			   (opt_process_rtp_packets_hash_next_thread_max <= 0 || countRtpRhThreads < opt_process_rtp_packets_hash_next_thread_max) &&
			   needAddRtpRhThreads) {
				processRtpPacketHash->addRtpRhThread();
			}
			extern int opt_enable_process_rtp_packet_max;
			if(countRtpRdThreads < MAX_PROCESS_RTP_PACKET_THREADS &&
			   (opt_enable_process_rtp_packet_max <= 0 || countRtpRdThreads < opt_enable_process_rtp_packet_max) &&
			   needAddRtpRdThreads) {
				ProcessRtpPacket::addRtpRdThread();
			}
			if(count_t2cpu > 1) {
				outStrStat << "/S:" << setprecision(1) << sum_t2cpu;
			}
		}
		outStrStat << "%] ";
	}
	if(sverb.log_profiler) {
		lapTime.push_back(getTimeMS_rdtsc());
		lapTimeDescr.push_back("t2");
	}
	if(!isMirrorSender()) {
		double tRTPcpuMax = 0;
		double tRTPcpu = get_rtp_sum_cpu_usage(&tRTPcpuMax);
		if(tRTPcpu >= 0) {
			extern volatile int num_threads_active;
			outStrStat << "tRTP_CPU[" << setprecision(1) << tRTPcpu << "%/";
			if(sverb.rtp_extend_stat) {
				outStrStat << get_rtp_threads_cpu_usage(false) << "/";
			} else {
				outStrStat << tRTPcpuMax << "m/";
			}
			outStrStat << num_threads_active << "t] ";
			if(tRTPcpu / num_threads_active > opt_cpu_limit_new_thread ||
			   (heapPerc > 10 && tRTPcpuMax >= 98)) {
				for(int i = 0; i < (calls_counter > 1000 || heapPerc > 10 ? 3 : 1); i++) {
					add_rtp_read_thread();
				}
			} else if(num_threads_active > 1 &&
				  tRTPcpu / num_threads_active < opt_cpu_limit_delete_thread &&
				  pcapStatCounter > (opt_fork ? 100 : 10) &&
				  !sverb.disable_read_rtp) {
				set_remove_rtp_read_thread();
			}
		}
		if(sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("trtp");
		}
		if(tcpReassemblyHttp) {
			string cpuUsagePerc = tcpReassemblyHttp->getCpuUsagePerc();
			if(!cpuUsagePerc.empty()) {
				outStrStat << "thttpCPU[" << cpuUsagePerc << "] ";
			}
			if(sverb.log_profiler) {
				lapTime.push_back(getTimeMS_rdtsc());
				lapTimeDescr.push_back("thttp");
			}
		}
		if(tcpReassemblyWebrtc) {
			string cpuUsagePerc = tcpReassemblyWebrtc->getCpuUsagePerc();
			if(!cpuUsagePerc.empty()) {
				outStrStat << "twebrtcCPU[" << cpuUsagePerc << "] ";
			}
			if(sverb.log_profiler) {
				lapTime.push_back(getTimeMS_rdtsc());
				lapTimeDescr.push_back("twebrtc");
			}
		}
		if(tcpReassemblySsl) {
			string cpuUsagePerc = tcpReassemblySsl->getCpuUsagePerc();
			if(!cpuUsagePerc.empty()) {
				outStrStat << "tsslCPU[" << cpuUsagePerc << "] ";
			}
			if(sverb.log_profiler) {
				lapTime.push_back(getTimeMS_rdtsc());
				lapTimeDescr.push_back("tssl");
			}
		}
		if(tcpReassemblySipExt) {
			string cpuUsagePerc = tcpReassemblySipExt->getCpuUsagePerc();
			if(!cpuUsagePerc.empty()) {
				outStrStat << "tsip_tcpCPU[" << cpuUsagePerc << "] ";
			}
			if(sverb.log_profiler) {
				lapTime.push_back(getTimeMS_rdtsc());
				lapTimeDescr.push_back("tsip");
			}
		}
		extern AsyncClose *asyncClose;
		if(asyncClose) {
			vector<double> v_tac_cpu;
			double last_tac_cpu = 0;
			bool exists_set_tac_cpu = false;
			for(int i = 0; i < asyncClose->getCountThreads(); i++) {
				double tac_cpu = asyncClose->getCpuUsagePerc(i, true);
				last_tac_cpu = tac_cpu;
				if(tac_cpu >= 0) {
					v_tac_cpu.push_back(tac_cpu);
					exists_set_tac_cpu = true;
				}
			}
			if(exists_set_tac_cpu) {
				outStrStat << "tacCPU[";
				for(size_t i = 0; i < v_tac_cpu.size(); i++) {
					if(i) {
						outStrStat << '|';
					}
					outStrStat << setprecision(1) << v_tac_cpu[i];
					if (opt_rrd) {
						rrd_add_value(RRD_VALUE_zipCPU, v_tac_cpu[i]);
					}
				}
				outStrStat << "%] ";
			}
			if(last_tac_cpu > opt_cpu_limit_new_thread) {
				asyncClose->addThread();
			} else if(last_tac_cpu < opt_cpu_limit_delete_thread) {
				asyncClose->removeThread();
			}
		}
		extern string storing_cdr_getCpuUsagePerc(double *avg);
		double storing_cdr_cpu_avg;
		string storing_cdr_cpu = storing_cdr_getCpuUsagePerc(&storing_cdr_cpu_avg);
		if(!storing_cdr_cpu.empty()) {
			outStrStat << "storing[" << storing_cdr_cpu << "%] ";
		}
		if(storing_cdr_cpu_avg > opt_cpu_limit_new_thread_high &&
		   calls_counter > 10000 &&
		   calls_counter > (int)calltable->getCountCalls() * 2) {
			extern void storing_cdr_next_thread_add();
			storing_cdr_next_thread_add();
		} else if(storing_cdr_cpu_avg < opt_cpu_limit_delete_thread &&
			  calls_counter < (int)calltable->getCountCalls() * 1.5) {
			extern void storing_cdr_next_thread_remove();
			storing_cdr_next_thread_remove();
		}
		extern bool opt_charts_cache;
		if(opt_charts_cache || snifferClientOptions.remote_chart_server || existsRemoteChartServer()) {
			extern u_int32_t counter_charts_cache;
			extern u_int64_t counter_charts_cache_delay_us;
			double chc_cpu_avg;
			string chc_cpu = calltable->processCallsInChartsCache_cpuUsagePerc(&chc_cpu_avg);
			size_t ch_q = calltable->calls_charts_cache_queue.size();
			size_t chs_q_s = getRemoteChartServerQueueSize();
			if(!chc_cpu.empty() || (counter_charts_cache && counter_charts_cache_delay_us) || 
			   ch_q > 0 || chs_q_s > 0) {
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
			}
			if(pcapStatCounter > 2) {
				extern int opt_charts_cache_queue_limit;
				if(chc_cpu_avg > opt_cpu_limit_new_thread_high &&
				   calltable->calls_charts_cache_queue.size() > (unsigned)opt_charts_cache_queue_limit / 3) {
					calltable->processCallsInChartsCache_thread_add();
				} else if(storing_cdr_cpu_avg < opt_cpu_limit_delete_thread) {
					calltable->processCallsInChartsCache_thread_remove();
				}
			}
			counter_charts_cache = 0;
			counter_charts_cache_delay_us = 0;
		}
		if(opt_rrd) {
			extern RrdCharts rrd_charts;
			double rrd_charts_cpu = rrd_charts.getCpuUsageQueueThreadPerc(true);
			if(rrd_charts_cpu > 0) {
				 outStrStat << "RRD[" << setprecision(1) << rrd_charts_cpu << "%] ";
			}
		}
		if(sverb.log_profiler) {
			lapTime.push_back(getTimeMS_rdtsc());
			lapTimeDescr.push_back("tasync");
		}
		if(opt_ipaccount) {
			string ipaccCpu = getIpaccCpuUsagePerc();
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
	outStrStat << "RSS/VSZ[";
	long unsigned int rss = this->getRssUsage(true);
	if(rss > 0) {
		outStrStat << setprecision(0) << (double)rss/1024/1024;
		if (opt_rrd) {
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
	#ifdef HEAP_CHUNK_ENABLE
	extern cHeap *heap_vm;
	if(heap_vm) {
		u_int64_t hugepages_vm_heap_size = heap_vm->getSumSize();
		if(hugepages_vm_heap_size) {
			outStrStat << "HPSH["
				   << setprecision(0) << (double)hugepages_vm_heap_size/1024/1024
				   << "]MB ";
		}
	}
	#endif //HEAP_CHUNK_ENABLE
	//Get load average string
	outStrStat << getLoadAvgStr() << " ";
	map<string, pair<string, u_int64_t> > counters;
	get_interrupts_counters(&counters);
	if(counters["tlb"].second) {
		static u_int64_t oldCountersTlb;
		if(oldCountersTlb) {
			unsigned tlb = (counters["tlb"].second - oldCountersTlb) / statPeriod;
			outStrStat << "TLB[" << tlb << "] ";
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
	outStrStat << "v" << RTPSENSOR_VERSION << " ";
	//outStrStat << pcapStatCounter << " ";
	if (opt_rrd) {
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
	if(EXTENDED_LOG) {
		if(DEBUG_VERBOSE) {
			cout << outStrStat.str() << endl;
		} else {
			syslog(LOG_NOTICE, "packetbuffer cpu / mem stat:");
			syslog(LOG_NOTICE, "%s", outStrStat.str().c_str());
		}
	} else if(VERBOSE) {
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
		string outStr_str = outStr.str();
		char *pointToBeginLine = (char*)outStr_str.c_str();
		while(pointToBeginLine && *pointToBeginLine) {
			char *pointToLineBreak = strchr(pointToBeginLine, '\n');
			if(pointToLineBreak) {
				*pointToLineBreak = '\0';
			}
			syslog(LOG_NOTICE, "%s", pointToBeginLine);
			if(pointToLineBreak) {
				*pointToLineBreak = '\n';
				pointToBeginLine = pointToLineBreak + 1;
			} else {
				pointToBeginLine = NULL;
			}
		}
	}
	
	extern int global_livesniffer;
	extern map<unsigned int, livesnifferfilter_s*> usersniffer;
	extern map<unsigned int, string> usersniffer_kill_reason;
	extern volatile int usersniffer_sync;
	extern volatile int usersniffer_checksize_sync;
	extern pthread_t usersniffer_checksize_thread;
	extern int opt_livesniffer_timeout_s;
	extern int opt_livesniffer_tablesize_max_mb;
	if(global_livesniffer) {
		if(heapPerc + heapTrashPerc >= 60) {
			if(usersniffer.size()) {
				cLogSensor *log = cLogSensor::begin(cLogSensor::notice, "live sniffer", "too high load - terminate");
				while(__sync_lock_test_and_set(&usersniffer_sync, 1)) {};
				for(map<unsigned int, livesnifferfilter_s*>::iterator iter = usersniffer.begin(); iter != usersniffer.end(); ) {
					string kill_reason = "too high load";
					log->log(NULL, "uid: %u, state: %s, reason: %s", iter->first, iter->second->getStringState().c_str(), kill_reason.c_str());
					delete iter->second;
					usersniffer_kill_reason[iter->first] = kill_reason;
					usersniffer.erase(iter++);
				}
				global_livesniffer = 0;
				__sync_lock_release(&usersniffer_sync);
				if(log) {
					log->end();
				}
			}
		} else {
			time_t now = time(NULL);
			cLogSensor *log = NULL;
			while(__sync_lock_test_and_set(&usersniffer_sync, 1)) {};
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
					if(!log) {
						log = cLogSensor::begin(cLogSensor::notice, "live sniffer", "timeout - terminate");
					}
					log->log(NULL, "uid: %u, state: %s, reason: %s", iter->first, iter->second->getStringState().c_str(), kill_reason.c_str());
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
			__sync_lock_release(&usersniffer_sync);
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

	if (opt_rrd) {
		if (opt_rrd == 1) {
			rrd_charts_create();
			rrd_charts_alter();
			opt_rrd ++;
		}
		rrd_update();
	}
	
	if(sverb.abort_if_heap_full) {
		if(packetbuffer_memory_is_full || (heapPerc + heapTrashPerc) > 98) {
			if(++heapFullCounter > 10) {
				syslog(LOG_ERR, "HEAP FULL - ABORT!");
				exit(2);
			}
		} else {
			heapFullCounter = 0;
		}
	}
	
	extern int opt_abort_if_rss_gt_gb;
	if(opt_abort_if_rss_gt_gb > 0 && (int)(rss/1024/1024/1024) > opt_abort_if_rss_gt_gb) {
		syslog(LOG_ERR, "RSS %i > %i - ABORT!",
		       (int)(rss/1024/1024/1024), opt_abort_if_rss_gt_gb);
		exit(2);
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

pstat_data *PcapQueue::getThreadPstatData(eTypeThread typeThread) {
	switch(typeThread) {
	case mainThread:
		return(mainThreadPstatData);
	case writeThread:
		return(writeThreadPstatData);
	case nextThread1:
		return(nextThreadsPstatData[0]);
	case nextThread2:
		return(nextThreadsPstatData[1]);
	case nextThread3:
		return(nextThreadsPstatData[2]);
	}
	return(NULL);
}

void PcapQueue::preparePstatData(eTypeThread typeThread) {
	int pid = getThreadPid(typeThread);
	pstat_data *threadPstatData = getThreadPstatData(typeThread);
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

double PcapQueue::getCpuUsagePerc(eTypeThread typeThread, bool preparePstatData) {
	if(this->threadInitFailed) {
		return(-1);
	}
	if(preparePstatData) {
		this->preparePstatData(typeThread);
	}
	int pid = getThreadPid(typeThread);
	pstat_data *threadPstatData = getThreadPstatData(typeThread);
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
	if (header_ip->get_protocol() == IPPROTO_UDP) {
		udphdr2 *header_udp = (udphdr2*) ((char*)header_ip + header_ip->get_hdr_size());
		datalen = get_udp_data_len(header_ip, header_udp, &data, packet, header->caplen);
		sport = header_udp->get_source();
		dport = header_udp->get_dest();
	} else if (header_ip->get_protocol() == IPPROTO_TCP) {
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


PcapQueue_readFromInterface_base::PcapQueue_readFromInterface_base(const char *interfaceName) {
	if(interfaceName) {
		this->interfaceName = interfaceName;
	}
	this->interfaceNet = 0;
	this->interfaceMask = 0;
	this->pcapHandle = NULL;
	this->pcapHandleIndex = 0;
	this->pcapEnd = false;
	memset(&this->filterData, 0, sizeof(this->filterData));
	this->filterDataUse = false;
	this->pcapDumpHandle = NULL;
	this->pcapLinklayerHeaderType = 0;
	// CONFIG
	extern int opt_promisc;
	extern int opt_ringbuffer;
	this->pcap_snaplen = get_pcap_snaplen();
	this->pcap_promisc = opt_promisc;
	this->pcap_timeout = 1000;
	this->pcap_buffer_size = opt_ringbuffer * 1024 * 1024;
	//
	memset(&this->last_ps, 0, sizeof(this->last_ps));
	this->countPacketDrop = 0;
	this->lastPacketTimeUS = 0;
	this->lastTimeLogErrPcapNextExNullPacket = 0;
	this->lastTimeLogErrPcapNextExErrorReading = 0;
	//
	libpcap_buffer_offset = 0;
	libpcap_buffer = NULL;
	libpcap_buffer_old = NULL;
	packets_counter = 0;
	extern vector<vmIP> if_filter_ip;
	extern vector<vmIPmask> if_filter_net;
	if(if_filter_ip.size() || if_filter_net.size()) {
		filter_ip = new FILE_LINE(0) ListIP;
		if(if_filter_ip.size()) {
			filter_ip->add(&if_filter_ip);
		}
		if(if_filter_net.size()) {
			filter_ip->add(&if_filter_net);
		}
	} else {
		filter_ip = NULL;
	}
	read_from_file_index = 0;
}

PcapQueue_readFromInterface_base::~PcapQueue_readFromInterface_base() {
	if(this->pcapHandle) {
		pcap_close(this->pcapHandle);
		syslog(LOG_NOTICE, "packetbuffer terminating: pcap_close pcapHandle (%s)", interfaceName.c_str());
	}
	if(this->pcapDumpHandle) {
		pcap_dump_close(this->pcapDumpHandle);
		syslog(LOG_NOTICE, "packetbuffer terminating: pcap_close pcapDumpHandle (%s)", interfaceName.c_str());
	}
	if(filter_ip) {
		delete filter_ip;
	}
}

void PcapQueue_readFromInterface_base::setInterfaceName(const char *interfaceName) {
	this->interfaceName = interfaceName;
}

bool PcapQueue_readFromInterface_base::startCapture(string *error) {
	*error = "";
	static volatile int _sync_start_capture = 0;
	long unsigned int rssBeforeActivate, rssAfterActivate;
	unsigned int usleepCounter = 0;
	while(__sync_lock_test_and_set(&_sync_start_capture, 1)) {
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
			__sync_lock_release(&_sync_start_capture);
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
				 this->interfaceName.c_str(), (unsigned int)time(NULL));
			this->pcapDumpHandle = pcap_dump_open(this->pcapHandle, pname);
		}
		__sync_lock_release(&_sync_start_capture);
		return(true);
	}
	if(VERBOSE) {
		syslog(LOG_NOTICE, "packetbuffer - %s: capturing", this->getInterfaceName().c_str());
	}
	if(pcap_lookupnet(this->interfaceName.c_str(), &this->interfaceNet, &this->interfaceMask, errbuf) == -1) {
		this->interfaceMask = PCAP_NETMASK_UNKNOWN;
	}
	if((this->pcapHandle = pcap_create(this->interfaceName.c_str(), errbuf)) == NULL) {
		snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: pcap_create failed: %s", this->getInterfaceName().c_str(), errbuf); 
		goto failed;
	}
	this->pcapHandleIndex = register_pcap_handle(this->pcapHandle);
	global_pcap_handle = this->pcapHandle;
	global_pcap_handle_index = this->pcapHandleIndex;
	int status;
	if((status = pcap_set_snaplen(this->pcapHandle, this->pcap_snaplen)) != 0) {
		snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: pcap_snaplen failed", this->getInterfaceName().c_str()); 
		goto failed;
	}
	if((status = pcap_set_promisc(this->pcapHandle, this->pcap_promisc)) != 0) {
		snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: pcap_set_promisc failed", this->getInterfaceName().c_str()); 
		goto failed;
	}
	if((status = pcap_set_timeout(this->pcapHandle, this->pcap_timeout)) != 0) {
		snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: pcap_set_timeout failed", this->getInterfaceName().c_str()); 
		goto failed;
	}
	if((status = pcap_set_buffer_size(this->pcapHandle, this->pcap_buffer_size)) != 0) {
		snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: pcap_set_buffer_size failed", this->getInterfaceName().c_str()); 
		goto failed;
	}
	rssBeforeActivate = getRss() / 1024 / 1024;
	if((status = pcap_activate(this->pcapHandle)) != 0) {
		snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: libpcap error: %s", this->getInterfaceName().c_str(), pcap_geterr(this->pcapHandle)); 
		cLogSensor::log(cLogSensor::error, errorstr);
		if(opt_fork) {
			ostringstream outStr;
			outStr << this->getInterfaceName() << ": libpcap error: " << pcap_geterr(this->pcapHandle);
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
			syslog(LOG_NOTICE, "packetbuffer - %s: ringbuffer has only %lu MB which means that your kernel does not support ringbuffer (<2.6.32) or you have invalid ringbuffer setting", this->getInterfaceName().c_str(), rssAfterActivate - rssBeforeActivate); 
			if(opt_fork) {
				ostringstream outStr;
				outStr << this->getInterfaceName() << ": ringbuffer has only " << (rssAfterActivate - rssBeforeActivate) << " MB which means that your kernel does not support ringbuffer (<2.6.32) or you have invalid ringbuffer setting";
				daemonizeOutput(outStr.str());
			}
		}
		if(rssAfterActivate > rssBeforeActivate) {
			all_ringbuffers_size += (rssAfterActivate - rssBeforeActivate) * 1024 * 1024;
		}
	}
	if(opt_mirrorip) {
		if(opt_mirrorip_dst[0] == '\0') {
			syslog(LOG_ERR, "packetbuffer - %s: mirroring packets was disabled because mirroripdst is not set", this->getInterfaceName().c_str());
			opt_mirrorip = 0;
		} else {
			syslog(LOG_NOTICE, "packetbuffer - %s: starting mirroring [%s]->[%s]", opt_mirrorip_src, opt_mirrorip_dst, this->getInterfaceName().c_str());
			mirrorip = new FILE_LINE(15024) MirrorIP(opt_mirrorip_src, opt_mirrorip_dst);
		}
	}
	if(*user_filter != '\0') {
		// Compile and apply the filter
		struct bpf_program fp;
		if (pcap_compile(this->pcapHandle, &fp, user_filter, 0, this->interfaceMask) == -1) {
			char user_filter_err[2048];
			snprintf(user_filter_err, sizeof(user_filter_err), "%.2000s%s", user_filter, strlen(user_filter) > 2000 ? "..." : "");
			snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: can not parse filter %s: %s", this->getInterfaceName().c_str(), user_filter_err, pcap_geterr(this->pcapHandle));
			if(opt_fork) {
				ostringstream outStr;
				outStr << this->getInterfaceName() << ": can not parse filter " << user_filter_err << ": " << pcap_geterr(this->pcapHandle);
				daemonizeOutput(outStr.str());
			}
			goto failed;
		}
		if (pcap_setfilter(this->pcapHandle, &fp) == -1) {
			char user_filter_err[2048];
			snprintf(user_filter_err, sizeof(user_filter_err), "%.2000s%s", user_filter, strlen(user_filter) > 2000 ? "..." : "");
			snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: can not install filter %s: %s", this->getInterfaceName().c_str(), user_filter_err, pcap_geterr(this->pcapHandle));
			if(opt_fork) {
				ostringstream outStr;
				outStr << this->getInterfaceName() << ": can not install filter " << user_filter_err << ": " << pcap_geterr(this->pcapHandle);
				daemonizeOutput(outStr.str());
			}
			goto failed;
		}
	}
	this->pcapLinklayerHeaderType = pcap_datalink(this->pcapHandle);
	if(!this->pcapLinklayerHeaderType) {
		snprintf(errorstr, sizeof(errorstr), "packetbuffer - %s: pcap_datalink failed", this->getInterfaceName().c_str()); 
		goto failed;
	}
	global_pcap_dlink = this->pcapLinklayerHeaderType;
//	syslog(LOG_NOTICE, "DLT - %s: %i", this->getInterfaceName().c_str(), this->pcapLinklayerHeaderType);
	if(opt_pcapdump) {
		char pname[2048];
		snprintf(pname, sizeof(pname), "%s/dump-%s-%u.pcap", 
			 getPcapdumpDir(),
			 this->interfaceName.c_str(), (unsigned int)time(NULL));
		this->pcapDumpHandle = pcap_dump_open(this->pcapHandle, pname);
	}
	__sync_lock_release(&_sync_start_capture);
	return(true);
failed:
	__sync_lock_release(&_sync_start_capture);
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
	int res = ::pcap_next_ex(pcapHandle, header, (const u_char**)packet);
	if(!packet && res != -2) {
		if(VERBOSE) {
			u_int64_t actTime = getTimeMS();
			if(actTime - 1000 > this->lastTimeLogErrPcapNextExNullPacket) {
				syslog(LOG_NOTICE,"packetbuffer - %s: NULL PACKET, pcap response is %d", this->getInterfaceName().c_str(), res);
				this->lastTimeLogErrPcapNextExNullPacket = actTime;
			}
		}
		return(0);
	} else if(res == -1) {
		if(VERBOSE) {
			u_int64_t actTime = getTimeMS();
			if(actTime - 1000 > this->lastTimeLogErrPcapNextExErrorReading) {
				syslog(LOG_NOTICE,"packetbuffer - %s: error reading packets: %s", this->getInterfaceName().c_str(), pcap_geterr(this->pcapHandle));
				this->lastTimeLogErrPcapNextExErrorReading = actTime;
			}
		}
		return(0);
	} else if(res == -2) {
		if(VERBOSE && opt_pb_read_from_file[0]) {
			syslog(LOG_NOTICE,"packetbuffer - %s: end of pcap file", this->getInterfaceName().c_str());
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
	if(opt_pb_read_from_file[0]) {
		if((*header)->caplen > this->pcap_snaplen) {
			(*header)->caplen = this->pcap_snaplen;
		}
		if((*header)->caplen > (*header)->len) {
			(*header)->caplen = (*header)->len;
		}
		++packets_counter;
		if(opt_pb_read_from_file_time_adjustment) {
			u_int64_t packetTime = getTimeUS(*header);
			packetTime += opt_pb_read_from_file_time_adjustment * 1000000ull;
			(*header)->ts.tv_sec = TIME_US_TO_S(packetTime);
			(*header)->ts.tv_usec = TIME_US_TO_DEC_US(packetTime);
		}
		if(opt_pb_read_from_file_acttime) {
			u_int64_t packetTime = getTimeUS(*header);
			if(!opt_pb_read_from_file_acttime_diff) {
				opt_pb_read_from_file_acttime_diff = getTimeUS() - packetTime - opt_pb_read_from_file_acttime_diff_days * 24 * 3600 *1000000ull;
			}
			packetTime += opt_pb_read_from_file_acttime_diff;
			(*header)->ts.tv_sec = TIME_US_TO_S(packetTime);
			(*header)->ts.tv_usec = TIME_US_TO_DEC_US(packetTime);
		}
		if(opt_pb_read_from_file_speed) {
			static u_int64_t diffTime;
			u_int64_t packetTime = getTimeUS(*header);
			if(this->lastPacketTimeUS) {
				if(packetTime > this->lastPacketTimeUS) {
					diffTime += packetTime - this->lastPacketTimeUS;
					if(diffTime > 1000) {
						USLEEP(diffTime / opt_pb_read_from_file_speed);
						diffTime = 0;
					}
				}
			}
			this->lastPacketTimeUS = packetTime;
		} else {
			if(heapPerc > 5) {
				USLEEP(50);
			}
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
	if(checkProtocol || filter_ip) {
		sCheckProtocolData _checkProtocolData;
		if(!checkProtocolData) {
			checkProtocolData = &_checkProtocolData;
		}
		if(!parseEtherHeader(pcapLinklayerHeaderType, *packet,
				     checkProtocolData->header_sll, checkProtocolData->header_eth, NULL,
				     checkProtocolData->header_ip_offset, checkProtocolData->protocol, checkProtocolData->vlan) ||
		   !(checkProtocolData->protocol == ETHERTYPE_IP ||
		     (VM_IPV6_B && checkProtocolData->protocol == ETHERTYPE_IPV6)) ||
		   !(((iphdr2*)(*packet + checkProtocolData->header_ip_offset))->version == 4 ||
		     (VM_IPV6_B && ((iphdr2*)(*packet + checkProtocolData->header_ip_offset))->version == 6)) ||
		   ((iphdr2*)(*packet + checkProtocolData->header_ip_offset))->get_tot_len() + checkProtocolData->header_ip_offset > (*header)->len) {
			return(-11);
		}
		if(filter_ip) {
			iphdr2 *iphdr = (iphdr2*)(*packet + checkProtocolData->header_ip_offset);
			if(!filter_ip->checkIP(iphdr->get_saddr()) && !filter_ip->checkIP(iphdr->get_daddr())) {
				return(-11);
			}
		}
	}
	return(1);
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
			syslog (LOG_NOTICE,"packetbuffer dispatch - %s: error reading packets", this->getInterfaceName().c_str());
		}
		return(0);
	} else if(res == -2) {
		if(VERBOSE) {
			syslog(LOG_NOTICE,"packetbuffer dispatch - %s: end of pcap file, exiting", this->getInterfaceName().c_str());
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
			     &ppd, pcapLinklayerHeaderType, pcapDumpHandle, getInterfaceName().c_str()));
	return(0);
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
					++this->countPacketDrop;
					pcap_drop_flag = 1;
				}
				if(ps.ps_ifdrop > this->last_ps.ps_ifdrop &&
				   (ps.ps_ifdrop - this->last_ps.ps_ifdrop) > (ps.ps_recv - this->last_ps.ps_recv) * opt_pcap_ifdrop_limit / 100) {
					ifdrop = true;
				}
				if(pcapdrop || ifdrop) {
					outStr << fixed
					       << "DROPPED PACKETS - " << this->getInterfaceName() << ": "
					       << "libpcap or interface dropped some packets!"
					       << " rx:" << (ps.ps_recv - this->last_ps.ps_recv);
					if(pcapdrop) {
						outStr << " pcapdrop:" << (ps.ps_drop - this->last_ps.ps_drop) << " " 
						       << setprecision(1) << ((double)(ps.ps_drop - this->last_ps.ps_drop) / (ps.ps_recv - this->last_ps.ps_recv) * 100) << "%%";
					}
					if(ifdrop) {
						outStr << " ifdrop:" << (ps.ps_ifdrop - this->last_ps.ps_ifdrop) << " " 
						       << setprecision(1) << ((double)(ps.ps_ifdrop - this->last_ps.ps_ifdrop) / (ps.ps_recv - this->last_ps.ps_recv) * 100) << "%%";
					}
					outStr << endl
					       << "     increase --ring-buffer (kernel >= 2.6.31 and libpcap >= 1.0.0)" 
					       << endl;
				}
			}
			this->last_ps = ps;
		}
	}
	return(outStr.str());
}

string PcapQueue_readFromInterface_base::pcapDropCountStat_interface() {
	ostringstream outStr;
	if(this->pcapHandle) {
		outStr << this->getInterfaceName(true) << " : " << "pdropsCount [" << this->countPacketDrop << "]";
		pcap_stat ps;
		int pcapstatres = pcap_stats(this->pcapHandle, &ps);
		if(pcapstatres == 0) {
			outStr << " ringdrop [" << ps.ps_drop << "]"
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
		outStr << "I-" << this->getInterfaceName(true) << ":" << this->countPacketDrop;
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

string PcapQueue_readFromInterface_base::getInterfaceName(bool simple) {
	return((simple ? "" : "interface ") + this->interfaceName);
}

void PcapQueue_readFromInterface_base::terminatingAtEndOfReadPcap() {
	if(opt_continue_after_read || opt_nonstop_read) {
		unsigned sleepCounter = 0;
		while(!is_terminating()) {
			this->tryForcePush();
			if(!opt_pb_read_from_file_max_packets) {
				if(sleepCounter > 10 && sleepCounter <= 15) {
					calltable->cleanup_calls(NULL);
					calltable->cleanup_registers(NULL);
					calltable->cleanup_ss7(NULL);
					extern int opt_sip_register;
					if(opt_sip_register == 1) {
						extern Registers registers;
						registers.cleanup(0, true);
					}
				}
				if(sleepCounter > 15) {
					calltable->destroyCallsIfPcapsClosed();
					calltable->destroyRegistersIfPcapsClosed();
				}
				if(sleepCounter > 20) {
					if(flushAllTars()) {
						 syslog(LOG_NOTICE, "tars flushed");
					}
				}
				if(sleepCounter > 30 && opt_nonstop_read) {
					rss_purge();
					syslog(LOG_NOTICE, "purge");
					extern void reset_cleanup_variables();
					reset_cleanup_variables();
					syslog(LOG_NOTICE, "reset cleanup variables");
					break;
				}
			}
			sleep(1);
			++sleepCounter;
		}
	} else {
		while(buffersControl.getPercUsePBwithouttrash() > 0.1) {
			syslog(LOG_NOTICE, "wait for processing packetbuffer (%.1lf%%)", buffersControl.getPercUsePBwithouttrash());
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
					if(calltable->cleanup_calls(NULL)) {
						syslog(LOG_NOTICE, "add time to cleanup calls");
						++sleepTimeBeforeCleanup;
					}
					calltable->cleanup_registers(NULL);
					calltable->cleanup_ss7(NULL);
					extern int opt_sip_register;
					if(opt_sip_register == 1) {
						extern Registers registers;
						registers.cleanup(0, true);
					}
				}
			} else if(sleepTimeAfterCleanup) {
				--sleepTimeAfterCleanup;
			}
		}
		vm_terminate();
	}
}


PcapQueue_readFromInterfaceThread::PcapQueue_readFromInterfaceThread(const char *interfaceName, eTypeInterfaceThread typeThread,
								     PcapQueue_readFromInterfaceThread *readThread,
								     PcapQueue_readFromInterfaceThread *prevThread)
 : PcapQueue_readFromInterface_base(interfaceName) {
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
	this->detachThread = NULL;
	this->pcapProcessThread = NULL;
	this->defragThread = NULL;
	this->md1Thread = NULL;
	this->md2Thread = NULL;
	this->dedupThread = NULL;
	this->serviceThread = NULL;
	this->typeThread = typeThread;
	this->prevThread = prevThread;
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
	vm_pthread_create(("pb - read thread " + getInterfaceName() + " " + getTypeThreadName()).c_str(),
			  &this->threadHandle, NULL, _PcapQueue_readFromInterfaceThread_threadFunction, this, __FILE__, __LINE__);
}

PcapQueue_readFromInterfaceThread::~PcapQueue_readFromInterfaceThread() {
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
		qring[_writeIndex]->count = writeIndexCount;
		qring[_writeIndex]->used = 1;
		writeIndex = 0;
		if((writeit + 1) == qringmax) {
			writeit = 0;
		} else {
			writeit++;
		}
	}
	/****
	uint32_t writeIndex = this->writeit[index] % this->qringmax;
	//while(__sync_lock_test_and_set(&this->_sync_qring, 1));
	while(this->qring[index][writeIndex].used > 0) {
		//__sync_lock_release(&this->_sync_qring);
		USLEEP(100);
		//while(__sync_lock_test_and_set(&this->_sync_qring, 1));
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
	//__sync_lock_release(&this->_sync_qring);
	****/
}

inline void PcapQueue_readFromInterfaceThread::push_block(pcap_block_store *block) {
	if(!buffersControl.check__pcap_store_queue__push()) {
		if(!(opt_pcap_queue_store_queue_max_disk_size &&
		     !opt_pcap_queue_disk_folder.empty())) {
			unsigned int usleepCounter = 0;
			do {
				if(is_terminating()) {
					return;
				}
				USLEEP_C(100, usleepCounter++);
			} while(!buffersControl.check__pcap_store_queue__push());
		}
	}
	unsigned int _writeIndex = writeit % qringmax;
	unsigned int usleepCounter = 0;
	while(qring_blocks_used[_writeIndex]) {
		if(is_terminating()) {
			return;
		}
		USLEEP_C(100, usleepCounter++);
	}
	qring_blocks[_writeIndex] = block;
	qring_blocks_used[_writeIndex] = 1;
	writeIndex = 0;
	if((writeit + 1) == qringmax) {
		writeit = 0;
	} else {
		writeit++;
	}
}

inline void PcapQueue_readFromInterfaceThread::tryForcePush() {
	if(writeIndexCount && force_push && writeIndex) {
		/*
		cout << "force push " << typeThread << endl;
		*/
		unsigned int _writeIndex = writeIndex - 1;
		force_push = false;
		qring[_writeIndex]->count = writeIndexCount;
		qring[_writeIndex]->used = 1;
		writeIndex = 0;
		if((writeit + 1) == qringmax) {
			writeit = 0;
		} else {
			writeit++;
		}
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
		qring[_readIndex]->used = 0;
		readIndex = 0;
		if((readit + 1) == qringmax) {
			readit = 0;
		} else {
			readit++;
		}
	}
	return(rslt_hpi);
	/****
	uint32_t readIndex = this->readit[index] % this->qringmax;
	//while(__sync_lock_test_and_set(&this->_sync_qring, 1));
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
	//__sync_lock_release(&this->_sync_qring);
	return(rslt_hpi);
	****/
}

inline PcapQueue_readFromInterfaceThread::hpi PcapQueue_readFromInterfaceThread::POP() {
	return(this->dedupThread ? this->dedupThread->pop() : this->pop());
}

inline pcap_block_store *PcapQueue_readFromInterfaceThread::pop_block() {
	unsigned int _readIndex = readit % qringmax;
	if(!qring_blocks_used[_readIndex]) {
		return(NULL);
	}
	pcap_block_store *block = qring_blocks[_readIndex];
	qring_blocks_used[_readIndex] = 0;
	if((readit + 1) == qringmax) {
		readit = 0;
	} else {
		readit++;
	}
	return(block);
}

inline pcap_block_store *PcapQueue_readFromInterfaceThread::POP_BLOCK() {
	return(this->dedupThread ? this->dedupThread->pop_block() : 
	       this->pcapProcessThread ? this->pcapProcessThread->pop_block() :
	       this->pop_block());
}

void PcapQueue_readFromInterfaceThread::cancelThread() {
	syslog(LOG_NOTICE, "cancel read thread (%s)", interfaceName.c_str());
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
	this->threadId = get_unix_tid();
	if(VERBOSE) {
		ostringstream outStr;
		outStr << "start thread t0i_" 
		       << getTypeThreadName()
		       << " (" << this->getInterfaceName() << ") - pid: " << this->threadId << endl;
		syslog(LOG_NOTICE, "%s", outStr.str().c_str());
	}
	if(this->typeThread == read) {
		if(!opt_pcap_queue_use_blocks) {
			if(opt_pcap_queue_iface_dedup_separate_threads) {
				if(opt_pcap_queue_iface_dedup_separate_threads_extend) {
					if(opt_pcap_queue_iface_dedup_separate_threads_extend == 2) {
						this->detachThread = new FILE_LINE(15033) PcapQueue_readFromInterfaceThread(this->interfaceName.c_str(), detach, this, this);
						this->defragThread = new FILE_LINE(15034) PcapQueue_readFromInterfaceThread(this->interfaceName.c_str(), defrag, this, this->detachThread);
					} else {
						this->defragThread = new FILE_LINE(15035) PcapQueue_readFromInterfaceThread(this->interfaceName.c_str(), defrag, this, this);
					}
					this->md1Thread = new FILE_LINE(15036) PcapQueue_readFromInterfaceThread(this->interfaceName.c_str(), md1, this, this->defragThread);
					this->md2Thread = new FILE_LINE(15037) PcapQueue_readFromInterfaceThread(this->interfaceName.c_str(), md2, this, this->md1Thread);
					this->dedupThread = new FILE_LINE(15038) PcapQueue_readFromInterfaceThread(this->interfaceName.c_str(), dedup, this, this->md2Thread);
					if(this->prepareHeaderPacketPool) {
						this->serviceThread = new FILE_LINE(15039) PcapQueue_readFromInterfaceThread(this->interfaceName.c_str(), service, this, this);
					}
				} else {
					this->dedupThread = new FILE_LINE(15040) PcapQueue_readFromInterfaceThread(this->interfaceName.c_str(), dedup, this, this);
				}
			}
		} else {
			if(opt_dup_check) {
				this->md1Thread = new FILE_LINE(15041) PcapQueue_readFromInterfaceThread(this->interfaceName.c_str(), md1, this, this);
				this->md2Thread = new FILE_LINE(15042) PcapQueue_readFromInterfaceThread(this->interfaceName.c_str(), md2, this, this->md1Thread);
				this->dedupThread = new FILE_LINE(15043) PcapQueue_readFromInterfaceThread(this->interfaceName.c_str(), dedup, this, this->md2Thread);
			} else {
				this->pcapProcessThread = new FILE_LINE(15044) PcapQueue_readFromInterfaceThread(this->interfaceName.c_str(), pcap_process, this, this);
			}
		}
		string error;
		if(!this->startCapture(&error)) {
			this->threadTerminated = true;
			this->threadInitFailed = true;
			this->threadDoTerminate = true;
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
			bool okPush = true;;
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
			bool okPush = true;
			if((this->typeThread == md1 && !(this->counter % 2)) ||
			   (this->typeThread == md2 && (opt_dup_check ? !hpii.header_packet->md5[0] : !hpii.header_packet->detect_headers))) {
				if(opt_dup_check || !hpii.header_packet->detect_headers) {
					res = this->pcapProcess(&hpii.header_packet, this->typeThread,
								NULL, 0,
								(opt_dup_check ? ppf_calcMD5 : 0) | ppf_returnZeroInCheckData);
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
			if(opt_pcap_queue_iface_dedup_separate_threads_extend) {
				bool okPush = true;
				if(opt_dup_check) {
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
	return(NULL);
}

void PcapQueue_readFromInterfaceThread::threadFunction_blocks() {
	int res;
	pcap_pkthdr *pcap_next_ex_header = NULL;
	u_char *pcap_next_ex_packet = NULL;
	pcap_pkthdr_plus2 *pcap_header_plus2 = NULL;
	u_char *pcap_packet = NULL;
	bool _useOneshotBuffer = false;
	pcap_block_store *block = NULL;
	sCheckProtocolData checkProtocolData;
	
	while(!(is_terminating() || this->threadDoTerminate)) {
		switch(this->typeThread) {
		case read: {
			while(!block ||
			      !block->get_add_hp_pointers(&pcap_header_plus2, &pcap_packet, pcap_snaplen) ||
			      (block->count && force_push)) {
				if(block) {
					this->push_block(block);
				}
				block = new FILE_LINE(15045) pcap_block_store(pcap_block_store::plus2);
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
			res = this->pcap_next_ex_iface(this->pcapHandle, &pcap_next_ex_header, &pcap_next_ex_packet,
						       opt_pcap_queue_use_blocks_read_check, &checkProtocolData);
			if(res == -1) {
				if(opt_pb_read_from_file[0]) {
					this->push_block(block);
					block = NULL;
					terminatingAtEndOfReadPcap();
					break;
				}
				break;
			} else if(res <= 0) {
				if(res == 0) {
					USLEEP(100);
				}
				continue;
			}
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
			break;
		}
		default:
			block = this->prevThread->pop_block();
			if(!block) {
				this->pop_usleep_sum += USLEEP_C(100, this->counter_pop_usleep++);
				if(this->pop_usleep_sum > this->pop_usleep_sum_last_push + 200000) {
					this->prevThread->setForcePush();
					this->pop_usleep_sum_last_push = this->pop_usleep_sum;
				}
				continue;
			}
			this->counter_pop_usleep = 0;
			this->pop_usleep_sum = 0;
			this->pop_usleep_sum_last_push = 0;
			this->processBlock(block);
			this->push_block(block);
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

void PcapQueue_readFromInterfaceThread::processBlock(pcap_block_store *block) {
	unsigned counter = 0;
	int ppf = 0;
	pcap_dumper_t *_pcapDumpHandle = NULL;
	switch(this->typeThread) {
	case md1:
		ppf = (opt_dup_check ? ppf_calcMD5 : ppf_na) |
		      (opt_udpfrag ? ppf_defragInPQout : ppf_returnZeroInCheckData);
		break;
	case md2:
		ppf = (opt_dup_check ? ppf_calcMD5 : ppf_na) |
		      (opt_udpfrag ? ppf_defragInPQout : ppf_returnZeroInCheckData);
		break;
	case dedup:
		ppf = (opt_dup_check ? ppf_dedup : ppf_na) |
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
		switch(this->typeThread) {
		case md1:
			if(!(counter % 2)) {
				this->pcapProcess(NULL, 0, block, i, ppf, _pcapDumpHandle);
			}
			break;
		case md2:
			if(!((pcap_pkthdr_plus2*)block->get_header(i))->md5[0]) {
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

void PcapQueue_readFromInterfaceThread::preparePstatData() {
	if(this->threadId && !this->threadDoTerminate) {
		if(this->threadPstatData[0].cpu_total_time) {
			this->threadPstatData[1] = this->threadPstatData[0];
		}
		pstat_get_data(this->threadId, this->threadPstatData);
	}
}

double PcapQueue_readFromInterfaceThread::getCpuUsagePerc(bool preparePstatData) {
	if(preparePstatData) {
		this->preparePstatData();
	}
	if(this->threadId && !this->threadDoTerminate) {
		double ucpu_usage, scpu_usage;
		if(this->threadPstatData[0].cpu_total_time && this->threadPstatData[1].cpu_total_time) {
			pstat_calc_cpu_usage_pct(
				&this->threadPstatData[0], &this->threadPstatData[1],
				&ucpu_usage, &scpu_usage);
			return(ucpu_usage + scpu_usage);
		}
	}
	return(-1);
}

void PcapQueue_readFromInterfaceThread::terminate() {
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
	       typeThread == detach ? "detach" : 
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

void PcapQueue_readFromInterface::setInterfaceName(const char* interfaceName) {
	this->interfaceName = interfaceName;
}

void PcapQueue_readFromInterface::terminate() {
	for(int i = 0; i < this->readThreadsCount; i++) {
		this->readThreads[i]->terminate();
	}
	PcapQueue::terminate();
}

bool PcapQueue_readFromInterface::init() {
	if(opt_scanpcapdir[0] ||
	   !opt_pcap_queue_iface_separate_threads) {
		return(true);
	}
	vector<string> interfaces = split(this->interfaceName.c_str(), split(",|;| |\t|\r|\n", "|"), true);
	for(size_t i = 0; i < interfaces.size(); i++) {
		if(this->readThreadsCount < READ_THREADS_MAX - 1) {
			this->readThreads[this->readThreadsCount] = new FILE_LINE(15047) PcapQueue_readFromInterfaceThread(interfaces[i].c_str());
			++this->readThreadsCount;
		}
	}
	return(this->readThreadsCount > 0);
}

bool PcapQueue_readFromInterface::initThread(void *arg, unsigned int arg2, string *error) {
	init_hash();
	return(this->startCapture(error) &&
	       this->openFifoForWrite(arg, arg2));
}

void* PcapQueue_readFromInterface::threadFunction(void *arg, unsigned int arg2) {
	this->mainThreadId = get_unix_tid();
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		outStr << "start thread t0 (" << this->nameQueue << ") - pid: " << this->mainThreadId << endl;
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
		return(NULL);
	}
	
	int blockStoreCount = this->readThreadsCount ? this->readThreadsCount : 1;
	pcap_block_store *blockStore[blockStoreCount];
	for(int i = 0; i < blockStoreCount; i++) {
		blockStore[i] = new FILE_LINE(15048) pcap_block_store;
		strncpy(blockStore[i]->ifname, 
			this->readThreadsCount ? 
				this->readThreads[i]->getInterfaceName(true).c_str() :
				this->getInterfaceName(true).c_str(), 
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
			USLEEP_C(100, usleepCounter++);
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
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		outStr << "start thread t0 (" << this->nameQueue << " / write" << ") - pid: " << this->writeThreadId << endl;
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
				usleepCounter = 0;
			} else {
				USLEEP_C(100, usleepCounter++);
			}
		}
	}
	return(NULL);
}

bool PcapQueue_readFromInterface::openFifoForWrite(void */*arg*/, unsigned int /*arg2*/) {
	return(true);
}

bool PcapQueue_readFromInterface::startCapture(string *error) {
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
	return(this->PcapQueue_readFromInterface_base::startCapture(error));
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

string PcapQueue_readFromInterface::pcapStatString_bypass_buffer(int /*statPeriod*/) {
	ostringstream outStr;
	outStr << fixed;
	uint64_t useSize = blockStoreBypassQueue->getUseSize();
	uint64_t useItems = blockStoreBypassQueue->getUseItems();
	outStr << "PACKETBUFFER_THREAD0_HEAP: "
	       << setw(6) << (useSize / 1024 / 1024) << "MB (" << setw(3) << useItems << ")"
	       << " " << setw(5) << setprecision(1) << (100. * useSize / opt_pcap_queue_bypass_max_size) << "%"
	       << " of " << setw(6) << (opt_pcap_queue_bypass_max_size / 1024 / 1024) << "MB"
	       << "   peak: " << (maxBypassBufferSize / 1024 / 1024) << "MB" << " (" << maxBypassBufferItems << ")" << " / size exceeded occurrence " << countBypassBufferSizeExceeded << endl;
	return(outStr.str());
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
	} else if(this->pcapHandle) {
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
	} else if(this->pcapHandle) {
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
	} else if(this->pcapHandle) {
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

string PcapQueue_readFromInterface::pcapStatString_cpuUsageReadThreads(double *sumMax, int *countThreadsSumMax, int divide) {
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
		double ti_cpu = this->readThreads[i]->getCpuUsagePerc(true);
		if(ti_cpu >= 0) {
			sum += ti_cpu;
			outStrStat << "t0i_" << this->readThreads[i]->interfaceName << "_CPU[";
			outStrStat << setprecision(1) << this->readThreads[i]->getTraffic(divide) << "Mb/s";
			outStrStat << ';' << setprecision(1) << ti_cpu;
			if(sverb.qring_stat) {
				double qringFillingPerc = this->readThreads[i]->getQringFillingPerc();
				if(qringFillingPerc > 0) {
					outStrStat << "r" << qringFillingPerc;
				}
			}
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
			if(this->readThreads[i]->detachThread) {
				++countThreads;
				double tid_cpu = this->readThreads[i]->detachThread->getCpuUsagePerc(true);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/" << setprecision(1) << tid_cpu;
					if(sverb.qring_stat) {
						double qringFillingPerc = this->readThreads[i]->detachThread->getQringFillingPerc();
						if(qringFillingPerc > 0) {
							outStrStat << "r" << qringFillingPerc;
						}
					}
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
				double tid_cpu = this->readThreads[i]->pcapProcessThread->getCpuUsagePerc(true);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/" << setprecision(1) << tid_cpu;
					if(sverb.qring_stat) {
						double qringFillingPerc = this->readThreads[i]->pcapProcessThread->getQringFillingPerc();
						if(qringFillingPerc > 0) {
							outStrStat << "r" << qringFillingPerc;
						}
					}
				}
			}
			if(this->readThreads[i]->defragThread) {
				++countThreads;
				double tid_cpu = this->readThreads[i]->defragThread->getCpuUsagePerc(true);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/" << setprecision(1) << tid_cpu;
					if(sverb.qring_stat) {
						double qringFillingPerc = this->readThreads[i]->defragThread->getQringFillingPerc();
						if(qringFillingPerc > 0) {
							outStrStat << "r" << qringFillingPerc;
						}
					}
				}
			}
			if(this->readThreads[i]->md1Thread) {
				++countThreads;
				double tid_cpu = this->readThreads[i]->md1Thread->getCpuUsagePerc(true);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/" << setprecision(1) << tid_cpu;
					if(sverb.qring_stat) {
						double qringFillingPerc = this->readThreads[i]->md1Thread->getQringFillingPerc();
						if(qringFillingPerc > 0) {
							outStrStat << "r" << qringFillingPerc;
						}
					}
				}
			}
			if(this->readThreads[i]->md2Thread) {
				++countThreads;
				double tid_cpu = this->readThreads[i]->md2Thread->getCpuUsagePerc(true);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/" << setprecision(1) << tid_cpu;
					if(sverb.qring_stat) {
						double qringFillingPerc = this->readThreads[i]->md2Thread->getQringFillingPerc();
						if(qringFillingPerc > 0) {
							outStrStat << "r" << qringFillingPerc;
						}
					}
				}
			}
			if(this->readThreads[i]->dedupThread) {
				++countThreads;
				double tid_cpu = this->readThreads[i]->dedupThread->getCpuUsagePerc(true);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/" << setprecision(1) << tid_cpu;
					if(sverb.qring_stat) {
						double qringFillingPerc = this->readThreads[i]->dedupThread->getQringFillingPerc();
						if(qringFillingPerc > 0) {
							outStrStat << "r" << qringFillingPerc;
						}
					}
				}
			}
			if(this->readThreads[i]->serviceThread) {
				++countThreads;
				double tid_cpu = this->readThreads[i]->serviceThread->getCpuUsagePerc(true);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/" << setprecision(1) << tid_cpu;
					if(sverb.qring_stat) {
						double qringFillingPerc = this->readThreads[i]->serviceThread->getQringFillingPerc();
						if(qringFillingPerc> 0) {
							outStrStat << "r" << qringFillingPerc;
						}
					}
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

string PcapQueue_readFromInterface::getInterfaceName(bool simple) {
	if(opt_scanpcapdir[0]) {
		return(string("dir ") + opt_scanpcapdir);
	} else if(opt_pb_read_from_file[0]) {
		return(string("file ") + opt_pb_read_from_file);
	} else {
		return(this->PcapQueue_readFromInterface_base::getInterfaceName(simple));
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
			maxBypassBufferSize = 0;
			maxBypassBufferItems = 0;
		}
	}
	if(EXTENDED_LOG &&
	   blockStoreBypassQueueSize > maxBypassBufferSize) {
		maxBypassBufferSize = blockStoreBypassQueueSize;
		maxBypassBufferItems = blockStoreBypassQueue->getUseItems();
	}
}

void PcapQueue_readFromInterface::push_blockstore(pcap_block_store **block_store) {
	if(!opt_pcap_queue_compress && this->instancePcapFifo && opt_pcap_queue_suppress_t1_thread) {
		this->instancePcapFifo->addBlockStoreToPcapStoreQueue(*block_store);
	} else if(this->block_qring) {
		if(!buffersControl.check__pcap_store_queue__push()) {
			if(!(opt_pcap_queue_store_queue_max_disk_size &&
			     !opt_pcap_queue_disk_folder.empty())) {
				unsigned int usleepCounter = 0;
				do {
					if(TERMINATING) {
						break;
					}
					USLEEP_C(100, usleepCounter++);
				} while(!buffersControl.check__pcap_store_queue__push());
			}
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
			this->readThreads[index_read_thread]->getInterfaceName(true).c_str() :
			this->getInterfaceName(true).c_str(), 
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
	this->socketHostIP.clear();
	this->socketHandle = 0;
	this->clientSocket = NULL;
	this->_sync_packetServerConnections = 0;
	this->lastCheckFreeSizeCachedir_timeMS = 0;
	this->_last_ts.tv_sec = 0;
	this->_last_ts.tv_usec = 0;
	this->block_counter = 0;
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

bool PcapQueue_readFromFifo::addBlockStoreToPcapStoreQueue(u_char *buffer, size_t bufferLen, string *error, string *warning, u_int32_t *block_counter, bool *require_confirmation) {
	*error = "";
	*warning = "";
	pcap_block_store *blockStore = new FILE_LINE(0) pcap_block_store;
	int rsltAddRestoreChunk = blockStore->addRestoreChunk(buffer, bufferLen, NULL, false, error);
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
			sumPacketsSize[0] += blockStore->size_packets ? blockStore->size_packets : blockStore->size;
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
	lock_blockStoreTrash();
	for(unsigned i = 0; i < this->blockStoreTrash.size(); i++) {
		pcap_block_store *bs = this->blockStoreTrash[i];
		outStr << "* " << hex << bs << dec << endl;
		outStr << "* " << sqlDateTimeString_us2ms(bs->timestampMS * 1000) << endl;
		outStr << "lock packets: " << (int)bs->_sync_packet_lock << endl;
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
	}
	unlock_blockStoreTrash();
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

inline void PcapQueue_readFromFifo::addBlockStoreToPcapStoreQueue(pcap_block_store *blockStore) {
	unsigned int usleepCounter = 0;
	while(!TERMINATING) {
		if(this->pcapStoreQueue.push(blockStore, false)) {
			sumPacketsSize[0] += blockStore->size_packets ? blockStore->size_packets : blockStore->size;
			break;
		} else {
			USLEEP_C(100, usleepCounter++);
		}
	}
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
	}
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		outStr << "start thread t1 (" << this->nameQueue;
		if(this->packetServerDirection == directionRead && arg2) {
			if(arg2 == (unsigned int)-1) {
				outStr << " socket server";
			} else {
				outStr << " " << this->packetServerConnections[arg2]->socketClientIP.getString() << ":" << this->packetServerConnections[arg2]->socketClientPort.getPort();
			}
		}
		outStr << ") - pid: " << tid << endl;
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
						double heapPerc = buffersControl.getPercUsePB();
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
										int timeDiff = abs((int64_t)actualTimeSec - (int64_t)sensorTimeSec) % 3600;
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
							int rsltAddRestoreChunk = blockStore->addRestoreChunk(buffer, bufferLen, &offsetBuffer, false, &error); 
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
											sumPacketsSize[0] += blockStore->size_packets ? blockStore->size_packets : blockStore->size;
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
			while(!TERMINATING) {
				blockStore = blockStoreBypassQueue->pop(false);
				if(!blockStore) {
					USLEEP_C(100, usleepCounter++);
					continue;
				}
				size_t blockSize = blockStore->size;
				size_t blockSizePackets = blockStore->size_packets;
				if(blockStore->compress()) {
					if(this->pcapStoreQueue.push(blockStore, false)) {
						sumPacketsSize[0] += blockSizePackets ? blockSizePackets : blockSize;
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
	return(NULL);
}

void *PcapQueue_readFromFifo::writeThreadFunction(void *arg, unsigned int arg2) {
	this->writeThreadId = get_unix_tid();
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		outStr << "start thread t2 (" << this->nameQueue << " / write" << ") - pid: " << this->writeThreadId << endl;
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
	unsigned int usleepCounter = 0;
	unsigned long usleepSumTime = 0;
	unsigned long usleepSumTime_lastPush = 0;
	sHeaderPacketPQout hp_out;
	//
	while(!TERMINATING) {
		if(DEBUG_SLEEP && access((this->pcapStoreQueue.fileStoreFolder + "/__/sleep").c_str(), F_OK ) != -1) {
			sleep(1);
		}
		this->pcapStoreQueue.pop(&blockStore);
		if(blockStore) {
			if(opt_cachedir[0]) {
				this->checkFreeSizeCachedir();
			}
			++sumBlocksCounterOut[0];
		}
		if(this->packetServerDirection == directionWrite || is_client_packetbuffer_sender()) {
			if(blockStore) {
				this->socketWritePcapBlock(blockStore);
				this->blockStoreTrashPush(blockStore);
				buffersControl.add__PcapQueue_readFromFifo__blockStoreTrash_size(blockStore->getUseAllSize());
			}
		} else {
			if(blockStore) {
				if(blockStore->size_compress && !blockStore->uncompress()) {
					delete blockStore;
					blockStore = NULL;
				} else {
					buffersControl.add__PcapQueue_readFromFifo__blockStoreTrash_size(blockStore->getUseAllSize());
					if(opt_ipaccount) {
						blockStore->is_voip = new FILE_LINE(15056) u_int8_t[blockStore->count];
						memset(blockStore->is_voip, 0, blockStore->count);
					}
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
			}
			if((opt_pcap_queue_dequeu_window_length > 0 ||
			    opt_pcap_queue_dequeu_need_blocks > 0) &&
			   (opt_pcap_queue_dequeu_method == 1 || opt_pcap_queue_dequeu_method == 2)) {
				int _opt_pcap_queue_dequeu_window_length = opt_pcap_queue_dequeu_window_length;
				int _opt_pcap_queue_dequeu_need_blocks = opt_pcap_queue_dequeu_need_blocks;
				if(opt_pcap_queue_dequeu_window_length_div > 0) {
					_opt_pcap_queue_dequeu_window_length = opt_pcap_queue_dequeu_window_length / opt_pcap_queue_dequeu_window_length_div;
				}
				if(opt_pcap_queue_dequeu_method == 1) {
					u_int64_t at = getTimeUS();
					if(blockStore) {
						listBlockStore[blockStore] = 0;
						for(size_t i = 0; i < blockStore->count; i++) {
							sPacketTimeInfo pti;
							pti.blockStore = blockStore;
							pti.blockStoreIndex = i;
							pti.header = (*blockStore)[i].header;
							pti.packet = (*blockStore)[i].packet;
							pti.utime = getTimeUS(pti.header->header_fix_size.ts_tv_sec, pti.header->header_fix_size.ts_tv_usec);
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
								this->processPacket(&hp_out, _hppq_out_state_NA);
								++listBlockStore[pti.blockStore];
								if(listBlockStore[pti.blockStore] == pti.blockStore->count) {
									this->blockStoreTrashPush(pti.blockStore);
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
				} else {
					u_int64_t at = getTimeUS();
					if(blockStore) {
						blockInfo[blockInfoCount].blockStore = blockStore;
						blockInfo[blockInfoCount].count_processed = 0;
						blockInfo[blockInfoCount].utime_first = getTimeUS((*blockStore)[0].header->header_fix_size.ts_tv_sec, 
												  (*blockStore)[0].header->header_fix_size.ts_tv_usec);
						blockInfo[blockInfoCount].utime_last = getTimeUS((*blockStore)[blockStore->count - 1].header->header_fix_size.ts_tv_sec, 
												 (*blockStore)[blockStore->count - 1].header->header_fix_size.ts_tv_usec);
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
					}
					while(blockInfoCount &&
					      (_opt_pcap_queue_dequeu_need_blocks ?
						blockInfoCount >= _opt_pcap_queue_dequeu_need_blocks :
						((blockInfo_utime_last - blockInfo_utime_first > (unsigned)_opt_pcap_queue_dequeu_window_length * 1000 &&
						  blockInfo_at_last - blockInfo_at_first > (unsigned)_opt_pcap_queue_dequeu_window_length * 1000) ||
						  at - blockInfo_at_first > (unsigned)_opt_pcap_queue_dequeu_window_length * 1000 * 4 ||
						  buffersControl.getPercUsePBtrash() > 50 ||
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
						
						hp_out.header = (*actBlockInfo->blockStore)[actBlockInfo->count_processed].header;
						hp_out.packet = (*actBlockInfo->blockStore)[actBlockInfo->count_processed].packet;
						hp_out.block_store = actBlockInfo->blockStore;
						hp_out.block_store_index = actBlockInfo->count_processed;
						hp_out.dlt = (*actBlockInfo->blockStore)[actBlockInfo->count_processed].header->dlink ? 
								(*actBlockInfo->blockStore)[actBlockInfo->count_processed].header->dlink :
								actBlockInfo->blockStore->dlink;
						hp_out.sensor_id = actBlockInfo->blockStore->sensor_id;
						hp_out.sensor_ip = actBlockInfo->blockStore->sensor_ip;
						hp_out.block_store_locked = false;
						this->processPacket(&hp_out, _hppq_out_state_NA);
						++actBlockInfo->count_processed;
						if(actBlockInfo->count_processed == actBlockInfo->blockStore->count) {
							this->blockStoreTrashPush(actBlockInfo->blockStore);
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
							actBlockInfo->utime_first = getTimeUS((*actBlockInfo->blockStore)[actBlockInfo->count_processed].header->header_fix_size.ts_tv_sec,
											      (*actBlockInfo->blockStore)[actBlockInfo->count_processed].header->header_fix_size.ts_tv_usec);
							blockInfo_utime_first = minUtime;
						}
						usleepCounter = 0;
						usleepSumTime = 0;
						usleepSumTime_lastPush = 0;
					}
				}
			} else {
				if(blockStore) {
					for(size_t i = 0; i < blockStore->count && !TERMINATING; i++) {
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
						this->processPacket(&hp_out, _hppq_out_state_NA);
					}
					this->blockStoreTrashPush(blockStore);
					usleepCounter = 0;
					usleepSumTime = 0;
					usleepSumTime_lastPush = 0;
				}
			}
		}
		if(!blockStore) {
			if(usleepSumTime > usleepSumTime_lastPush + 100000 &&
			   this->packetServerDirection != directionWrite) {
				this->pushBatchProcessPacket();
				usleepSumTime_lastPush = usleepSumTime;
			}
			usleepSumTime += USLEEP_C(100, usleepCounter++);
		}
		if(!(this->packetServerDirection != directionWrite &&
		     opt_ipaccount)) {
			if(!(++this->cleanupBlockStoreTrash_counter % 10)) {
				this->cleanupBlockStoreTrash();
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
	}
	this->writeThreadTerminated = true;
	return(NULL);
}

void *PcapQueue_readFromFifo::destroyBlocksThreadFunction(void */*arg*/, unsigned int /*arg2*/) {
	int tid = get_unix_tid();
	this->nextThreadsId[destroyBlocksThread - nextThread1] = tid;
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		outStr << "start thread t2 (" << this->nameQueue << " / destroy blocks" << ") - pid: " << tid << endl;
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
					ipaccount(headerPcap.header->std ? headerPcap.header->header_std.ts.tv_sec : headerPcap.header->header_fix_size.ts_tv_sec,
						  (iphdr2*)(headerPcap.packet + headerPcap.header->header_ip_offset),
						  (headerPcap.header->std ? headerPcap.header->header_std.len : headerPcap.header->header_fix_size.len) - headerPcap.header->header_ip_offset,
						  block->is_voip[i]);
				}
			}
			buffersControl.sub__PcapQueue_readFromFifo__blockStoreTrash_size(block->getUseAllSize());
			delete block;
		} else {
			USLEEP(1000);
			continue;
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

string PcapQueue_readFromFifo::pcapStatString_memory_buffer(int /*statPeriod*/) {
	ostringstream outStr;
	outStr << fixed;
	uint64_t useSize = buffersControl.get__pcap_store_queue__sizeOfBlocksInMemory() + buffersControl.get__PcapQueue_readFromFifo__blockStoreTrash_size();
	outStr << "PACKETBUFFER_TOTAL_HEAP:   "
	       << setw(6) << (useSize / 1024 / 1024) << "MB" << setw(6) << ""
	       << " " << setw(5) << setprecision(1) << (100. * useSize / opt_pcap_queue_store_queue_max_memory_size) << "%"
	       << " of " << setw(6) << (opt_pcap_queue_store_queue_max_memory_size / 1024 / 1024) << "MB" << endl;
	outStr << "PACKETBUFFER_TRASH_HEAP:   "
	       << setw(6) << (buffersControl.get__PcapQueue_readFromFifo__blockStoreTrash_size() / 1024 / 1024) << "MB" << endl;
	return(outStr.str());
}

string PcapQueue_readFromFifo::pcapStatString_disk_buffer(int /*statPeriod*/) {
	ostringstream outStr;
	if(opt_pcap_queue_store_queue_max_disk_size &&
	   this->pcapStoreQueue.fileStoreFolder.length()) {
		outStr << fixed;
		uint64_t useSize = this->pcapStoreQueue.getFileStoreUseSize();
		outStr << "PACKETBUFFER_FILES:        "
		       << setw(6) << (useSize / 1024 / 1024) << "MB" << setw(6) << ""
		       << " " << setw(5) << setprecision(1) << (100. * useSize / opt_pcap_queue_store_queue_max_disk_size) << "%"
		       << " of " << setw(6) << (opt_pcap_queue_store_queue_max_disk_size / 1024 / 1024) << "MB" << endl;
	}
	return(outStr.str());
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

string PcapQueue_readFromFifo::getCpuUsage(bool writeThread, bool preparePstatData) {
	if(!writeThread && this->packetServerDirection == directionRead) {
		bool empty = true;
		ostringstream outStr;
		this->lock_packetServerConnections();
		map<unsigned int, sPacketServerConnection*>::iterator iter;
		for(iter = this->packetServerConnections.begin(); iter != this->packetServerConnections.end(); ++iter) {
			if(iter->second->active) {
				sPacketServerConnection *connection = iter->second;
				if(preparePstatData) {
					if(connection->threadPstatData[0].cpu_total_time) {
						connection->threadPstatData[1] = connection->threadPstatData[0];
					}
					pstat_get_data(connection->threadId, connection->threadPstatData);
				}
				if(connection->threadPstatData[0].cpu_total_time &&
				   connection->threadPstatData[1].cpu_total_time) {
					double ucpu_usage, scpu_usage;
					pstat_calc_cpu_usage_pct(
						&connection->threadPstatData[0], &connection->threadPstatData[1],
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
		   buffersControl.getPercUsePB() > 70) {
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
			this->clientSocket = new FILE_LINE(0) cSocketBlock("packetbuffer block", true);
			this->clientSocket->setHostPort(snifferClientOptions.host, snifferClientOptions.port);
			if(!this->clientSocket->connect()) {
				syslog(LOG_ERR, "send packetbuffer block error: %s", "failed connect to cloud router");
				pcapQueueQ->externalError = "send packetbuffer block error: failed connect to cloud router";
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
		if(!opt_pcap_queues_mirror_require_confirmation ||
		   buffersControl.getPercUsePB() > 70) {
			((pcap_block_store::pcap_block_store_header*)saveBuffer)->time_s = 0;
		}
		if(!this->clientSocket->writeBlock(saveBuffer, sizeSaveBuffer, cSocket::_te_aes)) {
			okSendBlock = false;
		}
		delete [] saveBuffer;
		if(!okSendBlock) {
			syslog(LOG_ERR, "send packetbuffer block error: %s", "failed send");
			pcapQueueQ->externalError = "send packetbuffer block error: failed send";
			continue;
		}
		if(opt_pcap_queues_mirror_require_confirmation) {
			string response;
			if(!this->clientSocket->readBlock(&response, cSocket::_te_aes)) {
				syslog(LOG_ERR, "send packetbuffer block error: %s", "failed read response");
				pcapQueueQ->externalError = "send packetbuffer block error: failed read response";
				continue;
			}
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

int PcapQueue_readFromFifo::processPacket(sHeaderPacketPQout *hp, eHeaderPacketPQoutState hp_state) {
 
	/*
	extern int opt_sleepprocesspacket;
	if(opt_sleepprocesspacket) {
		USLEEP(100000);
	}
	*/
 
	extern int opt_blockprocesspacket;
	if(sverb.disable_process_packet_in_packetbuffer ||
	   opt_blockprocesspacket ||
	   (hp_state == _hppq_out_state_NA &&
	    hp->block_store && hp->block_store->hm == pcap_block_store::plus2 && ((pcap_pkthdr_plus2*)hp->header)->ignore)) {
		return(0);
	}

	/*
	if((long)hp->block_store == 0x60e000022b00 &&
	   hp->block_store_index == 1245) {
		cout << "break 1" << endl;
	}
	*/
	
	if(opt_udpfrag && pcapQueueQ_outThread_defrag &&
	   hp_state == _hppq_out_state_NA) {
		pcapQueueQ_outThread_defrag->push(hp);
		return(-1);
	}
	
	if(opt_dup_check && pcapQueueQ_outThread_dedup &&
	   (hp_state == _hppq_out_state_NA || hp_state == _hppq_out_state_defrag)) {
		pcapQueueQ_outThread_dedup->push(hp);
		return(-1);
	}
	
	/*
	if((long)hp->block_store == 0x60e000022b00 &&
	   hp->block_store_index == 1245) {
		cout << "break 2" << endl;
	}
	*/
 
	static u_int64_t packet_counter_all;
	++packet_counter_all;
	
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
		return(0);
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
	
	iphdr2 *header_ip_encaps = hp->header->header_ip_encaps_offset == 0xFFFF ?
				   NULL :
				   (iphdr2*)(hp->packet + hp->header->header_ip_encaps_offset);
	iphdr2 *header_ip = hp->header->header_ip_offset == 0xFFFF ?
			     NULL :
			     (iphdr2*)(hp->packet + hp->header->header_ip_offset);

	if(header_ip) {
		while(true) {
			int next_header_ip_offset = findNextHeaderIp(header_ip, hp->header->header_ip_offset, 
								     hp->packet, hp->header->get_caplen());
			if(next_header_ip_offset == 0) {
				break;
			} else if(next_header_ip_offset < 0) {
				return(0);
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
	if(header_ip) {
		if (header_ip->get_protocol() == IPPROTO_UDP) {
			udphdr2 *header_udp = (udphdr2*)((char*) header_ip + header_ip->get_hdr_size());
			datalen = get_udp_data_len(header_ip, header_udp, &data, hp->packet, header->caplen);
			sport = header_udp->get_source();
			dport = header_udp->get_dest();
			pflags.ss7 = opt_enable_ss7 && (ss7_rudp_portmatrix[sport] || ss7_rudp_portmatrix[dport]);
		} else if (header_ip->get_protocol() == IPPROTO_TCP) {
			tcphdr2 *header_tcp = (tcphdr2*)((char*)header_ip + header_ip->get_hdr_size());
			datalen = get_tcp_data_len(header_ip, header_tcp, &data, hp->packet, header->caplen);
			pflags.tcp = 1;
			sport = header_tcp->get_source();
			dport = header_tcp->get_dest();
			if(opt_enable_ss7 && (ss7portmatrix[sport] || ss7portmatrix[dport])) {
				pflags.ss7 = 1;
			} else if(cFilters::saveMrcp() && IS_MRCP(data, datalen)) {
				pflags.mrcp = 1;
			}
		} else if (opt_enable_ss7 && header_ip->get_protocol() == IPPROTO_SCTP) {
			pflags.ss7 = 1;
			datalen = get_sctp_data_len(header_ip, &data, hp->packet, header->caplen);
		} else {
			//packet is not UDP and is not TCP, we are not interested, go to the next packet
			return(0);
		}
	} else if(opt_enable_ss7) {
		data = (char*)hp->packet;
		datalen = header->caplen;
		pflags.ss7 = 1;
	}
	
	if((data - (char*)hp->packet) > header->caplen) {
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
		return(0);
	}
	
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

	if(opt_mirrorip && (sipportmatrix[sport] || sipportmatrix[dport])) {
		mirrorip->send((char *)header_ip, (int)(header->caplen - ((u_char*)header_ip - hp->packet)));
	}

	if(header_ip && header_ip->get_protocol() == IPPROTO_TCP) {
		if(opt_enable_http && (httpportmatrix[sport] || httpportmatrix[dport]) && 
		   (tcpReassemblyHttp->check_ip(header_ip->get_saddr()) || tcpReassemblyHttp->check_ip(header_ip->get_daddr()))) {
			tcpReassemblyHttp->push_tcp(header, header_ip, hp->packet, !hp->block_store,
						    hp->block_store, hp->block_store_index, hp->block_store_locked,
						    this->getPcapHandleIndex(hp->dlt), hp->dlt, hp->sensor_id, hp->sensor_ip, hp->header->pid);
			return(1);
		} else if(opt_enable_webrtc && (webrtcportmatrix[sport] || webrtcportmatrix[dport]) &&
			  (tcpReassemblyWebrtc->check_ip(header_ip->get_saddr()) || tcpReassemblyWebrtc->check_ip(header_ip->get_daddr()))) {
			tcpReassemblyWebrtc->push_tcp(header, header_ip, hp->packet, !hp->block_store,
						      hp->block_store, hp->block_store_index, hp->block_store_locked,
						      this->getPcapHandleIndex(hp->dlt), hp->dlt, hp->sensor_id, hp->sensor_ip, hp->header->pid);
			return(1);
		} else if(opt_enable_ssl && 
			  (isSslIpPort(header_ip->get_saddr(), sport) ||
			   isSslIpPort(header_ip->get_daddr(), dport))) {
			tcpReassemblySsl->push_tcp(header, header_ip, hp->packet, !hp->block_store,
						   hp->block_store, hp->block_store_index, hp->block_store_locked,
						   this->getPcapHandleIndex(hp->dlt), hp->dlt, hp->sensor_id, hp->sensor_ip, hp->header->pid);
			return(1);
		} else if(opt_ipaccount &&
			  !(sipportmatrix[sport] || sipportmatrix[dport])) {
			return(0);
		}
	}

	if((opt_enable_http != 2 && opt_enable_webrtc != 2 && opt_enable_ssl != 2) &&
	   !is_terminating() &&
	   !sverb.disable_push_to_t2_in_packetbuffer) {
		extern bool ssl_client_random_enable;
		extern char *ssl_client_random_portmatrix;
		extern bool ssl_client_random_portmatrix_set;
		extern vector<vmIP> ssl_client_random_ip;
		extern vector<vmIPmask> ssl_client_random_net;
		if(header_ip && header_ip->get_protocol() == IPPROTO_UDP &&
		   ssl_client_random_enable &&
		   (!ssl_client_random_portmatrix_set || 
		    ssl_client_random_portmatrix[dport]) &&
		   ((!ssl_client_random_ip.size() && !ssl_client_random_net.size()) ||
		    check_ip_in(header_ip->get_daddr(), &ssl_client_random_ip, &ssl_client_random_net, true)) &&
		   datalen && string_looks_like_client_random((u_char*)data, datalen)) {
			if(ssl_parse_client_random((u_char*)data, datalen)) {
				return(0);
			}
		}
		preProcessPacket[PreProcessPacket::ppt_detach]->push_packet(
			#if USE_PACKET_NUMBER
			packet_counter_all,
			#endif
			header_ip ? header_ip->get_saddr() : 0, header_ip ? sport.getPort() : 0, header_ip ? header_ip->get_daddr() : 0, header_ip ? dport.getPort() : 0,
			datalen, data - (char*)hp->packet,
			this->getPcapHandleIndex(hp->dlt), header, hp->packet, hp->block_store ? false : true /*packetDelete*/,
			pflags, header_ip_encaps, header_ip,
			hp->block_store, hp->block_store_index, hp->dlt, hp->sensor_id, hp->sensor_ip, hp->header->pid,
			hp->block_store_locked ? 2 : 1 /*blockstore_lock*/);
		return(1);
	}
	
	return(0);
}

void PcapQueue_readFromFifo::pushBatchProcessPacket() {
	if(pcapQueueQ_outThread_defrag) {
		pcapQueueQ_outThread_defrag->push_batch();
	} else if(pcapQueueQ_outThread_dedup) {
		pcapQueueQ_outThread_dedup->push_batch();
	} else if(preProcessPacket[PreProcessPacket::ppt_detach]) {
		preProcessPacket[PreProcessPacket::ppt_detach]->push_batch();
	}
}

void PcapQueue_readFromFifo::checkFreeSizeCachedir() {
	if(!opt_cachedir[0]) {
		return;
	}
	u_int64_t actTimeMS = getTimeMS();
	if(!lastCheckFreeSizeCachedir_timeMS ||
	   actTimeMS - lastCheckFreeSizeCachedir_timeMS > 2000) {
		double freeSpacePerc = (double)GetFreeDiskSpace(opt_cachedir, true) / 100;
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
	for(int i = 0; i < ((int)this->blockStoreTrash.size() - (all ? 0 : 5)); i++) {
		bool del = false;
		if(all || this->blockStoreTrash[i]->enableDestroy()) {
			del = true;
		} else if(opt_pcap_queue_block_timeout &&
			  (this->blockStoreTrash[this->blockStoreTrash.size() - 1]->timestampMS - this->blockStoreTrash[i]->timestampMS) > (unsigned)opt_pcap_queue_block_timeout * 1000) {
			syslog(LOG_NOTICE, "force destroy packetbuffer blok - use packets: %i", this->blockStoreTrash[i]->_sync_packet_lock);
			del = true;
		}
		if(del) {
			buffersControl.sub__PcapQueue_readFromFifo__blockStoreTrash_size(this->blockStoreTrash[i]->getUseAllSize());
			delete this->blockStoreTrash[i];
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


inline void *_PcapQueue_outputThread_outThreadFunction(void *arg) {
	return(((PcapQueue_outputThread*)arg)->outThreadFunction());
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
	this->qring_push_index = 0;
	this->qring_push_index_count = 0;
	memset(this->threadPstatData, 0, sizeof(this->threadPstatData));
	this->outThreadId = 0;
	this->defrag_counter = 0;
	this->ipfrag_lastprune = 0;
	if(typeOutputThread == dedup) {
		this->dedup_buffer = new FILE_LINE(16003) u_char[65536 * MD5_DIGEST_LENGTH]; // 1M
		memset(this->dedup_buffer, 0, 65536 * MD5_DIGEST_LENGTH * sizeof(u_char));
	} else {
		this->dedup_buffer = NULL;
	}
	this->initThreadOk = false;
	this->terminatingThread = false;
}

PcapQueue_outputThread::~PcapQueue_outputThread() {
	stop();
	for(unsigned int i = 0; i < this->qring_length; i++) {
		delete this->qring[i];
	}
	delete [] this->qring;
	if(typeOutputThread == defrag) {
		ipfrag_prune(0, true, &ipfrag_data, -1, 0);
	}
	if(typeOutputThread == dedup) {
		delete [] dedup_buffer;
	}
}

void PcapQueue_outputThread::start() {
	vm_pthread_create(("t2 out thread " + getNameOutputThread()).c_str(),
			  &this->out_thread_handle, NULL, _PcapQueue_outputThread_outThreadFunction, this, __FILE__, __LINE__);
}

void PcapQueue_outputThread::stop() {
	if(this->initThreadOk) {
		this->terminatingThread = true;
		pthread_join(this->out_thread_handle, NULL);
		this->initThreadOk = false;
		this->terminatingThread = false;
	}
}

void PcapQueue_outputThread::push(sHeaderPacketPQout *hp) {
	if(hp && hp->block_store && !hp->block_store_locked) {
		hp->block_store->lock_packet(hp->block_store_index, 1 /*pb lock flag*/);
		hp->block_store_locked = true;
	}

	/*
	this->processDefrag(hp);
	return;
	*/
	
	if(!qring_push_index) {
		unsigned int usleepCounter = 0;
		while(this->qring[this->writeit]->used != 0) {
			if(is_terminating()) {
				return;
			}
			USLEEP_C(20, usleepCounter++);
		}
		qring_push_index = this->writeit + 1;
		qring_push_index_count = 0;
		qring_active_push_item = qring[qring_push_index - 1];
	}
	qring_active_push_item->batch[qring_push_index_count] = *hp;
	++qring_push_index_count;
	if(qring_push_index_count == qring_active_push_item->max_count) {
		qring_active_push_item->count = qring_push_index_count;
		qring_active_push_item->used = 1;
		if((this->writeit + 1) == this->qring_length) {
			this->writeit = 0;
		} else {
			this->writeit++;
		}
		qring_push_index = 0;
		qring_push_index_count = 0;
	}
}

void PcapQueue_outputThread::push_batch() {
	if(qring_push_index && qring_push_index_count) {
		qring_active_push_item->count = qring_push_index_count;
		qring_active_push_item->used = 1;
		if((this->writeit + 1) == this->qring_length) {
			this->writeit = 0;
		} else {
			this->writeit++;
		}
		qring_push_index = 0;
		qring_push_index_count = 0;
	}
}

void *PcapQueue_outputThread::outThreadFunction() {
	this->initThreadOk = true;
	extern unsigned int opt_preprocess_packets_qring_usleep;
	this->outThreadId = get_unix_tid();
	syslog(LOG_NOTICE, "start thread t2_%s/%i", this->getNameOutputThread().c_str(), this->outThreadId);
	sBatchHP *batch;
	unsigned int usleepCounter = 0;
	unsigned long usleepSumTime = 0;
	unsigned long usleepSumTime_lastPush = 0;
	while(!is_terminating() && !this->terminatingThread) {
		if(this->qring[this->readit]->used == 1) {
			batch = this->qring[this->readit];
			for(unsigned batch_index = 0; batch_index < batch->count; batch_index++) {
				switch(typeOutputThread) {
				case defrag:
					this->processDefrag(&batch->batch[batch_index]);
					break;
				case dedup:
					this->processDedup(&batch->batch[batch_index]);
					break;
				}
			}
			batch->count = 0;
			batch->used = 0;
			if((this->readit + 1) == this->qring_length) {
				this->readit = 0;
			} else {
				this->readit++;
			}
			usleepCounter = 0;
			usleepSumTime = 0;
			usleepSumTime_lastPush = 0;
		} else {
			usleepSumTime += USLEEP_C(opt_preprocess_packets_qring_usleep, usleepCounter++);
			if(usleepSumTime > usleepSumTime_lastPush + 100000) {
				switch(typeOutputThread) {
				case defrag:
					if(pcapQueueQ_outThread_dedup) {
						pcapQueueQ_outThread_dedup->push_batch();
						break;
					}
				case dedup:
					preProcessPacket[PreProcessPacket::ppt_detach]->push_batch();
					break;
				}
				usleepSumTime_lastPush = usleepSumTime;
			}
		}
	}
	return(NULL);
}

void PcapQueue_outputThread::processDefrag(sHeaderPacketPQout *hp) {
	uint32_t headerTimeS = hp->header->get_tv_sec();
	if(hp->block_store && hp->block_store->hm == pcap_block_store::plus2) {
		hp->header->header_ip_offset = ((pcap_pkthdr_plus2*)hp->header)->header_ip_encaps_offset;
	} else {
		sll_header *header_sll;
		ether_header *header_eth;
		u_int16_t header_ip_offset = 0;
		u_int16_t protocol;
		u_int16_t vlan;
		parseEtherHeader(hp->dlt, hp->packet,
				 header_sll, header_eth, NULL,
				 header_ip_offset, protocol, vlan);
		hp->header->header_ip_offset = header_ip_offset;
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
			return;
		}
		// packet is fragmented
		int rsltDefrag = handle_defrag(header_ip, (void*)hp, &this->ipfrag_data);
		if(rsltDefrag > 0) {
			// packets are reassembled
			header_ip = (iphdr2*)(hp->packet + hp->header->header_ip_offset);
			hp->header->pid.flags |= FLAG_FRAGMENTED;
			if(sverb.defrag) {
				defrag_counter++;
				cout << "*** DEFRAG 1 " << defrag_counter << endl;
			}
		} else {
			if(rsltDefrag < 0) {
				hp->destroy_or_unlock_blockstore();
			}
			return;
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
			return;
		} else {
			header_ip = (iphdr2*)((u_char*)header_ip + next_header_ip_offset);
			hp->header->header_ip_offset += next_header_ip_offset;
		}
		if(header_ip->get_protocol() == IPPROTO_UDP) {
			int frag_data = header_ip->get_frag_data();
			if(header_ip->is_more_frag(frag_data) || header_ip->get_frag_offset(frag_data)) {
				// packet is fragmented
				int rsltDefrag = handle_defrag(header_ip, (void*)hp, &this->ipfrag_data);
				if(rsltDefrag > 0) {
					header_ip = (iphdr2*)(hp->packet + hp->header->header_ip_offset);
					header_ip->clear_frag_data();
					for(unsigned i = 0; i < headers_ip_counter; i++) {
						iphdr2 *header_ip_prev = (iphdr2*)(hp->packet + headers_ip_offset[i]);
						header_ip_prev->set_tot_len(header_ip->get_tot_len() + (hp->header->header_ip_offset - headers_ip_offset[i]));
						header_ip_prev->clear_frag_data();
					}
					hp->header->pid.flags |= FLAG_FRAGMENTED;
					if(sverb.defrag) {
						defrag_counter++;
						cout << "*** DEFRAG 2 " << defrag_counter << endl;
					}
				} else {
					if(rsltDefrag < 0) {
						hp->destroy_or_unlock_blockstore();
					}
					return;
				}
			}
		}
	}
	
	if(this->pcapQueue->processPacket(hp, _hppq_out_state_defrag) == 0) {
		hp->destroy_or_unlock_blockstore();
	}
	
	if((ipfrag_lastprune + 2) < headerTimeS) {
		if(ipfrag_lastprune) {
			ipfrag_prune(headerTimeS, false, &this->ipfrag_data, -1, 2);
		}
		ipfrag_lastprune = headerTimeS;
	}
}

void PcapQueue_outputThread::processDedup(sHeaderPacketPQout *hp) {
	uint16_t *_md5 = NULL;
	uint16_t __md5[MD5_DIGEST_LENGTH / (sizeof(uint16_t) / sizeof(unsigned char))];
	if(hp->block_store && hp->block_store->hm == pcap_block_store::plus2 && ((pcap_pkthdr_plus2*)hp->header)->md5[0]) {
		_md5 = ((pcap_pkthdr_plus2*)hp->header)->md5;
	} else {
		if(hp->header->header_ip_offset) {
			iphdr2 *header_ip = (iphdr2*)(hp->packet + hp->header->header_ip_offset);
			char *data = NULL;
			int datalen = 0;
			if(header_ip->get_protocol() == IPPROTO_UDP) {
				udphdr2 *header_udp = (udphdr2*)((char*)header_ip + header_ip->get_hdr_size());
				datalen = get_udp_data_len(header_ip, header_udp, &data, hp->packet, hp->header->get_caplen());
			} else if(header_ip->get_protocol() == IPPROTO_TCP) {
				tcphdr2 *header_tcp = (tcphdr2*)((char*)header_ip + header_ip->get_hdr_size());
				datalen = get_tcp_data_len(header_ip, header_tcp, &data, hp->packet, hp->header->get_caplen());
			} else if (opt_enable_ss7 && header_ip->get_protocol() == IPPROTO_SCTP) {
				datalen = get_sctp_data_len(header_ip, &data, hp->packet, hp->header->get_caplen());
			}
			if(data && datalen) {
				MD5_CTX md5_ctx;
				MD5_Init(&md5_ctx);
				if(opt_dup_check_ipheader) {
					u_int8_t header_ip_ttl_orig = 0;
					u_int8_t header_ip_check_orig = 0;
					if(opt_dup_check_ipheader_ignore_ttl) {
						header_ip_ttl_orig = header_ip->get_ttl();
						header_ip_check_orig = header_ip->get_check();
						header_ip->set_ttl(0);
						header_ip->set_check(0);
					}
					MD5_Update(&md5_ctx, header_ip, MIN(datalen + (data - (char*)header_ip), header_ip->get_tot_len()));
					if(opt_dup_check_ipheader_ignore_ttl) {
						header_ip->set_ttl(header_ip_ttl_orig);
						header_ip->set_check(header_ip_check_orig);
					}
				} else {
					MD5_Update(&md5_ctx, data, datalen);
				}
				MD5_Final((unsigned char*)__md5, &md5_ctx);
				_md5 = __md5;
			}
		}
	}
	if(_md5) {
		if(memcmp(_md5, this->dedup_buffer + (_md5[0] * MD5_DIGEST_LENGTH), MD5_DIGEST_LENGTH) == 0) {
			if(sverb.dedup) {
				cout << "*** DEDUP 2" << endl;
			}
			hp->destroy_or_unlock_blockstore();
			return;
		}
		memcpy(this->dedup_buffer + (_md5[0] * MD5_DIGEST_LENGTH), _md5, MD5_DIGEST_LENGTH);
	}
	if(this->pcapQueue->processPacket(hp, _hppq_out_state_dedup) == 0) {
		hp->destroy_or_unlock_blockstore();
	}
}

void PcapQueue_outputThread::preparePstatData() {
	if(this->outThreadId) {
		if(this->threadPstatData[0].cpu_total_time) {
			this->threadPstatData[1] = this->threadPstatData[0];
		}
		pstat_get_data(this->outThreadId, this->threadPstatData);
	}
}

double PcapQueue_outputThread::getCpuUsagePerc(bool preparePstatData) {
	if(preparePstatData) {
		this->preparePstatData();
	}
	if(this->outThreadId) {
		double ucpu_usage, scpu_usage;
		if(this->threadPstatData[0].cpu_total_time && this->threadPstatData[1].cpu_total_time) {
			pstat_calc_cpu_usage_pct(
				&this->threadPstatData[0], &this->threadPstatData[1],
				&ucpu_usage, &scpu_usage);
			return(ucpu_usage + scpu_usage);
		}
	}
	return(-1);
}


void PcapQueue_init() {
	blockStoreBypassQueue = new FILE_LINE(15061) pcap_block_store_queue;
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
