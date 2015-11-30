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
#include <malloc.h>

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
#include "rrd.h"
#include "cleanspool.h"
#include "ssldata.h"
#include "tar.h"
#include "voipmonitor.h"


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
#define DEBUG_SYNC 		(DEBUG_VERBOSE && false)
#define DEBUG_SLEEP		(DEBUG_VERBOSE && true)
#define DEBUG_ALL_PACKETS	(DEBUG_VERBOSE && false)
#define EXTENDED_LOG		(DEBUG_VERBOSE || (VERBOSE && verbosityE > 1))
#define TERMINATING 		((is_terminating() && this->enableAutoTerminate) || this->threadDoTerminate)

#define MAX_TCPSTREAMS 1024
#define FILE_BUFFER_SIZE 1000000


using namespace std;

extern Call *process_packet(bool is_ssl, u_int64_t packet_number,
			    unsigned int saddr, int source, unsigned int daddr, int dest, 
			    char *data, int datalen, int dataoffset,
			    pcap_t *handle, pcap_pkthdr *header, const u_char *packet, 
			    int istcp, int *was_rtp, struct iphdr2 *header_ip, int *voippacket, int forceSip,
			    pcap_block_store *block_store, int block_store_index, int dlt, int sensor_id,
			    bool mainProcess = true, int sipOffset = 0,
			    PreProcessPacket::packet_parse_s *parsePacket = NULL);
extern int check_sip20(char *data, unsigned long len);
void daemonizeOutput(string error);

extern int verbosity;
extern int verbosityE;
extern int opt_rrd;
extern char opt_chdir[1024];
extern int opt_udpfrag;
extern int opt_skinny;
extern int opt_ipaccount;
extern int opt_pcapdump;
extern int opt_pcapdump_all;
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

extern pcap_t *global_pcap_handle;
extern char *sipportmatrix;
extern char *httpportmatrix;
extern char *webrtcportmatrix;
extern struct tcp_stream2_t *tcp_streams_hashed[MAX_TCPSTREAMS];
extern MirrorIP *mirrorip;
extern char user_filter[10*2048];
extern Calltable *calltable;
extern volatile int calls_counter;
extern PreProcessPacket *preProcessPacket;
extern ProcessRtpPacket *processRtpPacketHash;
extern ProcessRtpPacket *processRtpPacketDistribute[MAX_PROCESS_RTP_PACKET_THREADS];
extern TcpReassembly *tcpReassemblyHttp;
extern TcpReassembly *tcpReassemblyWebrtc;
extern TcpReassembly *tcpReassemblySsl;
extern char opt_pb_read_from_file[256];
extern int opt_pb_read_from_file_speed;
extern int opt_pb_read_from_file_acttime;
extern char opt_scanpcapdir[2048];
extern int global_pcap_dlink;
extern char opt_cachedir[1024];
extern unsigned long long cachedirtransfered;
unsigned long long lastcachedirtransfered = 0;
extern char opt_cachedir[1024];
extern char cloud_host[256];
extern int opt_pcap_dump_tar;
extern volatile unsigned int glob_tar_queued_files;

extern cBuffersControl buffersControl;

vm_atomic<string> pbStatString;
vm_atomic<u_long> pbCountPacketDrop;


void *_PcapQueue_threadFunction(void *arg);
void *_PcapQueue_writeThreadFunction(void *arg);
void *_PcapQueue_readFromInterfaceThread_threadFunction(void *arg);
void *_PcapQueue_readFromFifo_socketServerThreadFunction(void *arg);
void *_PcapQueue_readFromFifo_connectionThreadFunction(void *arg);

static bool __config_BYPASS_FIFO			= true;
static bool __config_USE_PCAP_FOR_FIFO			= false;
static bool __config_ENABLE_TOGETHER_READ_WRITE_FILE	= false;

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
string opt_pcap_queue_disk_folder;
ip_port opt_pcap_queue_send_to_ip_port;
ip_port opt_pcap_queue_receive_from_ip_port;
int opt_pcap_queue_receive_from_port;
int opt_pcap_queue_receive_dlt 				= DLT_EN10MB;
int opt_pcap_queue_iface_separate_threads 		= 0;
int opt_pcap_queue_iface_dedup_separate_threads 	= 0;
int opt_pcap_queue_iface_dedup_separate_threads_extend	= 0;
int opt_pcap_queue_iface_qring_size 			= 5000;
int opt_pcap_queue_dequeu_window_length			= -1;
int opt_pcap_queue_dequeu_method			= 2;
int opt_pcap_dispatch					= 0;
int opt_pcap_queue_suppress_t1_thread			= 0;
bool opt_pcap_queues_mirror_nonblock_mode 			= false;

size_t _opt_pcap_queue_block_offset_init_size		= opt_pcap_queue_block_max_size / AVG_PACKET_SIZE * 1.1;
size_t _opt_pcap_queue_block_offset_inc_size		= opt_pcap_queue_block_max_size / AVG_PACKET_SIZE / 4;
size_t _opt_pcap_queue_block_restore_buffer_inc_size	= opt_pcap_queue_block_max_size / 4;

int pcap_drop_flag = 0;
int enable_bad_packet_order_warning = 0;

static pcap_block_store_queue *blockStoreBypassQueue; 

static unsigned long sumPacketsCounterIn[2];
static unsigned long sumPacketsCounterOut[2];
static unsigned long sumBlocksCounterIn[2];
static unsigned long sumBlocksCounterOut[2];
static unsigned long long sumPacketsSize[2];
static unsigned long long sumPacketsSizeCompress[2];
static unsigned long maxBypassBufferItems;
static unsigned long maxBypassBufferSize;
static unsigned long countBypassBufferSizeExceeded;
static double heapPerc = 0;

extern MySqlStore *sqlStore;
extern MySqlStore *loadFromQFiles;

extern unsigned int glob_ssl_calls;

bool packetbuffer_memory_is_full = false;

#include "sniff_inline.h"


bool pcap_block_store::add(pcap_pkthdr *header, u_char *packet, int offset, int dlink, int memcpy_packet_size) {
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
			this->block = new FILE_LINE u_char[opt_pcap_queue_block_max_size];
			if(this->block) {
				break;
			}
			syslog(LOG_ERR, "not enough memory for alloc packetbuffer block");
			sleep(1);
		}
	}
	if(!this->offsets_size) {
		this->offsets_size = _opt_pcap_queue_block_offset_init_size;
		this->offsets = new FILE_LINE uint32_t[this->offsets_size];
	}
	if(this->count == this->offsets_size) {
		uint32_t *offsets_old = this->offsets;
		size_t offsets_size_old = this->offsets_size;
		this->offsets_size += _opt_pcap_queue_block_offset_inc_size;
		this->offsets = new FILE_LINE uint32_t[this->offsets_size];
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
	++this->count;
	return(true);
}

bool pcap_block_store::add(pcap_pkthdr_plus *header, u_char *packet) {
	return(this->add((pcap_pkthdr*)header, packet, header->offset, header->dlink));
}

bool pcap_block_store::isFull_checkTimout() {
	if(this->full) {
		return(true);
	}
	if(this->size && getTimeMS_rdtsc() > (this->timestampMS + opt_pcap_queue_block_max_time_ms)) {
		this->full = true;
		return(true);
	}
	return(false);
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
	this->size = 0;
	this->size_compress = 0;
	this->count = 0;
	this->offsets_size = 0;
	this->full = false;
	this->dlink = global_pcap_dlink;
	this->sensor_id = opt_id_sensor;
	memset(this->ifname, 0, sizeof(this->ifname));
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

u_char* pcap_block_store::getSaveBuffer() {
	size_t sizeSaveBuffer = this->getSizeSaveBuffer();
	u_char *saveBuffer = new FILE_LINE u_char[sizeSaveBuffer];
	pcap_block_store_header header;
	header.size = this->size;
	header.size_compress = this->size_compress;
	header.count = this->count;
	header.dlink = this->dlink;
	header.sensor_id = this->sensor_id;
	strcpy(header.ifname, this->ifname);
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
	return(saveBuffer);
}

void pcap_block_store::restoreFromSaveBuffer(u_char *saveBuffer) {
	pcap_block_store_header *header = (pcap_block_store_header*)saveBuffer;
	this->size = header->size;
	this->size_compress = header->size_compress;
	this->count = header->count;
	this->dlink = header->dlink;
	this->sensor_id = header->sensor_id;
	strncpy(this->ifname, header->ifname, sizeof(header->ifname));
	if(this->offsets) {
		delete [] this->offsets;
	}
	if(this->block) {
		delete [] this->block;
	}
	this->offsets_size = this->count;
	this->offsets = new FILE_LINE uint32_t[this->offsets_size];
	memcpy_heapsafe(this->offsets, this->offsets,
			saveBuffer + sizeof(pcap_block_store_header), saveBuffer,
			sizeof(uint32_t) * this->count,
			__FILE__, __LINE__);
	size_t sizeBlock = this->getUseSize();
	this->block = new FILE_LINE u_char[sizeBlock];
	memcpy_heapsafe(this->block, this->block,
			saveBuffer + sizeof(pcap_block_store_header) + this->count * sizeof(uint32_t), saveBuffer,
			sizeBlock,
			__FILE__, __LINE__);
	this->full = true;
}

int pcap_block_store::addRestoreChunk(u_char *buffer, size_t size, size_t *offset, bool autoRestore) {
	u_char *_buffer = buffer + (offset ? *offset : 0);
	size_t _size = size - (offset ? *offset : 0);
	if(_size <= 0) {
		return(-1);
	}
	if(this->restoreBufferAllocSize < this->restoreBufferSize + _size) {
		this->restoreBufferAllocSize = this->restoreBufferSize + _size + _opt_pcap_queue_block_restore_buffer_inc_size;
		u_char *restoreBufferNew = new FILE_LINE u_char[this->restoreBufferAllocSize];
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
	int sizeRestoreBuffer = this->getSizeSaveBufferFromRestoreBuffer();
	if(sizeRestoreBuffer < 0 ||
	   this->restoreBufferSize < (size_t)sizeRestoreBuffer) {
		return(0);
	}
	if(offset) {
		*offset = size - (this->restoreBufferSize - sizeRestoreBuffer);
	}
	if(autoRestore) {
		this->restoreFromSaveBuffer(this->restoreBuffer);
		this->destroyRestoreBuffer();
	}
	return(1);
}

bool pcap_block_store::compress() {
	if(!opt_pcap_queue_compress ||
	   this->size_compress) {
		return(true);
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
	u_char *snappyBuff = new FILE_LINE u_char[snappyBuffSize];
	if(!snappyBuff) {
		syslog(LOG_ERR, "packetbuffer: snappy_compress: snappy buffer allocation failed - PACKETBUFFER BLOCK DROPPED!");
		return(false);
	}
	snappy_status snappyRslt = snappy_compress((char*)this->block, this->size, (char*)snappyBuff, &snappyBuffSize);
	switch(snappyRslt) {
		case SNAPPY_OK:
			delete [] this->block;
			this->block = new FILE_LINE u_char[snappyBuffSize];
			memcpy_heapsafe(this->block, snappyBuff, snappyBuffSize,
					__FILE__, __LINE__);
			delete [] snappyBuff;
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
	u_char *lz4Buff = new FILE_LINE u_char[lz4BuffSize];
	if(!lz4Buff) {
		syslog(LOG_ERR, "packetbuffer: lz4_compress: lz4 buffer allocation failed - PACKETBUFFER BLOCK DROPPED!");
		return(false);
	}
	int lz4_size = LZ4_compress((char*)this->block, (char*)lz4Buff, this->size);
	if(lz4_size > 0) {
		delete [] this->block;
		this->block = new FILE_LINE u_char[lz4_size];
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
	u_char *snappyBuff = new FILE_LINE u_char[snappyBuffSize];
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
	u_char *lz4Buff = new FILE_LINE u_char[lz4BuffSize];
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
	extern int terminating;
	this->queueBlock = new FILE_LINE rqueue_quick<pcap_block_store*>(
				100000,
				100, 100,
				&terminating, true,
				__FILE__, __LINE__);
	this->countOfBlocks = 0;
	this->sizeOfBlocks = 0;
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
		syslog(LOG_NOTICE, "packetbuffer: slow write %luB - %.3lfs", sizeSaveBuffer, diffTimeS);
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
	u_char *readBuff = new FILE_LINE u_char[readBuffSize];
	size_t readed;
	while((readed = fread(readBuff, 1, readBuffSize, this->fileHandlePop)) > 0) {
		if(blockStore->addRestoreChunk(readBuff, readed) > 0) {
			break;
		}
	}
	delete [] readBuff;
	++this->countPop;
	blockStore->destroyRestoreBuffer();
	if(this->countPop == this->countPush && this->isFull()) {
		this->close(typeHandlePop);
	}
	return(true);
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
			this->fileBufferPush = new FILE_LINE u_char[FILE_BUFFER_SIZE];
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
			this->fileBufferPop = new FILE_LINE u_char[FILE_BUFFER_SIZE];
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
	if(!access(fileStoreFolder, F_OK )) {
		mkdir(fileStoreFolder, 0700);
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
		while(!is_terminating() && buffersControl.getPercUsePB() > 20) {
			usleep(100);
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
			u_long actTime = getTimeMS();
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
			fileStore = new FILE_LINE pcap_file_store(this->lastFileStoreId, this->fileStoreFolder.c_str());
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
			u_long actTime = getTimeMS();
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
			this->add_sizeOfBlocksInMemory(blockStore->getUseSize());
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
			while(!__config_ENABLE_TOGETHER_READ_WRITE_FILE && !_fileStore->full) {
				usleep(100);
			}
			if(!_fileStore->pop(*blockStore)) {
				delete *blockStore;
				return(false);
			}
		} else {
			this->sub_sizeOfBlocksInMemory((*blockStore)->getUseSize());
		}
		++this->cleanupFileStoreCounter;
		if(!(this->cleanupFileStoreCounter % 100)) {
			this->cleanupFileStore();
		}
	}
	return(true);
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
	this->fifoReadHandle = -1;
	this->fifoWriteHandle = -1;
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
	this->counter_sip_packets_old[0] = 0;
	this->counter_sip_packets_old[1] = 0;
	this->counter_sip_register_packets_old = 0;
	this->counter_sip_message_packets_old = 0;
	this->counter_rtp_packets_old = 0;
	this->counter_all_packets_old = 0;
	this->lastTimeLogErrPcapNextExNullPacket = 0;
	this->lastTimeLogErrPcapNextExErrorReading = 0;
}

PcapQueue::~PcapQueue() {
	if(this->fifoReadHandle >= 0) {
		close(this->fifoReadHandle);
	}
	if(this->fifoWriteHandle >= 0) {
		close(this->fifoWriteHandle);
		syslog(LOG_NOTICE, "packetbuffer terminating (%s): close fifoWriteHandle", nameQueue.c_str());
	}
	if(this->packetBuffer) {
		delete [] this->packetBuffer;
		syslog(LOG_NOTICE, "packetbuffer terminating (%s): free packetBuffer", nameQueue.c_str());
	}
}

void PcapQueue::setFifoFileForRead(const char *fifoFileForRead) {
	this->fifoFileForRead = fifoFileForRead;
}

void PcapQueue::setFifoFileForWrite(const char *fifoFileForWrite) {
	this->fifoFileForWrite = fifoFileForWrite;
}

void PcapQueue::setFifoReadHandle(int fifoReadHandle) {
	this->fifoReadHandle = fifoReadHandle;
}

void PcapQueue::setFifoWriteHandle(int fifoWriteHandle) {
	this->fifoWriteHandle = fifoWriteHandle;
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

//For RRDs files update
//rrd heap file db-heap.rrd
	double rrdheap_buffer = 0;
	double rrdheap_ratio = 0;
//rrd drop file db-drop.rrd
	unsigned long rrddrop_exceeded = 0;
	unsigned long rrddrop_packets = 0;
//rrd packet counters file 2db-PS.rrd
	int64_t rrdPS_C = 0;
	uint64_t rrdPS_S0 = 0;
	uint64_t rrdPS_S1 = 0;
	uint64_t rrdPS_SR = 0;
	uint64_t rrdPS_SM = 0;
	uint64_t rrdPS_R = 0;
	uint64_t rrdPS_A = 0;
//rrd SQL file db-SQL.rrd
	signed int rrdSQLf_D = 0;	//here is zero alowed
	signed int rrdSQLq_C = -1;
	signed int rrdSQLq_M = -1;
	signed int rrdSQLq_R = -1;
	signed int rrdSQLq_Cl = -1;
	signed int rrdSQLq_H = -1;
//rrd CPU consumption file db-tCPU.rrd
	double rrdtCPU_t0 = 0.0;
	double rrdtCPU_t1 = 0.0;
	double rrdtCPU_t2 = 0.0;
//rrd tacCPU consumption file db-tacCPU.rrd
	double rrdtacCPU_zip = 0.0;     //number of threads
	double rrdtacCPU_tar = 0.0;	//last thread load
//rrd mem consumption file db-RSSVSZ.rrd
	double rrdRSSVSZ_rss = 0;
	double rrdRSSVSZ_vsize = 0;
//rrd net bw to voipmonitor file db-speedmbs.rrd
	double rrdspeedmbs = 0.0;
//rrd calls counter file db-callscounter.rrd
	int rrdcallscounter = 0;

	if(!VERBOSE && !DEBUG_VERBOSE) {
		return;
	}

	if(this->instancePcapHandle &&
	   !this->instancePcapHandle->initAllReadThreadsFinished) {
		return;
	}
	ostringstream outStr;
	pcap_drop_flag = 0;
	string pcapStatString_interface_rslt = this->instancePcapHandle ? 
						this->instancePcapHandle->pcapStatString_interface(statPeriod) :
						this->pcapStatString_interface(statPeriod);
	if(EXTENDED_LOG) {
		string statString = "\n";
		if(statCalls) {
			ostringstream outStr;
			outStr << "CALLS: " << calltable->calls_listMAP.size() << ", " << calls_counter;
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
					syslog(LOG_NOTICE, pointToBeginLine);
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
		outStr << fixed;
		if(!this->isMirrorSender()) {
			outStr << "calls[" << calltable->calls_listMAP.size() << "][" << calls_counter << "]";
			calltable->lock_calls_audioqueue();
			size_t audioQueueSize = calltable->audio_queue.size();
			if(audioQueueSize) {
				size_t audioQueueThreads = calltable->getCountAudioQueueThreads();
				outStr << "[" << audioQueueSize << "/" << audioQueueThreads <<"]";
			}
			calltable->unlock_calls_audioqueue();
#ifdef HAVE_LIBGNUTLS
			extern string getSslStat();
			string sslStat = getSslStat();
			if(!sslStat.empty()) {
				outStr << sslStat;
			}
#endif
			outStr << " ";
			if(opt_ipaccount) {
				outStr << "ipacc_buffer[" << lengthIpaccBuffer() << "] ";
			}
			if (opt_rrd) rrdcallscounter = calltable->calls_listMAP.size();
			extern u_int64_t counter_calls;
			extern u_int64_t counter_sip_packets[2];
			extern u_int64_t counter_sip_register_packets;
			extern u_int64_t counter_sip_message_packets;
			extern u_int64_t counter_rtp_packets;
			extern u_int64_t counter_all_packets;
			if(this->counter_calls_old ||
			   this->counter_sip_packets_old[0] ||
			   this->counter_sip_packets_old[1] ||
			   this->counter_rtp_packets_old ||
			   this->counter_all_packets_old) {
				outStr << "PS[C:";
				if(this->counter_calls_old) {
					outStr << (counter_calls - this->counter_calls_old) / statPeriod;
					if (opt_rrd) rrdPS_C = (counter_calls - this->counter_calls_old) / statPeriod;
				} else {
					outStr << "-";
				}
				outStr << " S:";
				if(this->counter_sip_packets_old[0]) {
					outStr << (counter_sip_packets[0] - this->counter_sip_packets_old[0]) / statPeriod;
					if (opt_rrd) rrdPS_S0 = (counter_sip_packets[0] - this->counter_sip_packets_old[0]) / statPeriod;
				} else {
					outStr << "-";
				}
				outStr << "/";
				if(this->counter_sip_packets_old[1]) {
					outStr << (counter_sip_packets[1] - this->counter_sip_packets_old[1]) / statPeriod;
					if (opt_rrd) rrdPS_S1 = (counter_sip_packets[1] - this->counter_sip_packets_old[1]) / statPeriod;
				} else {
					outStr << "-";
				}
				outStr << " SR:";
				if(this->counter_sip_register_packets_old) {
					outStr << (counter_sip_register_packets - this->counter_sip_register_packets_old) / statPeriod;
					if (opt_rrd) rrdPS_SR = (counter_sip_register_packets - this->counter_sip_register_packets_old) / statPeriod;
				} else {
					outStr << "-";
				}
				outStr << " SM:";
				if(this->counter_sip_message_packets_old) {
					outStr << (counter_sip_message_packets - this->counter_sip_message_packets_old) / statPeriod;
					if (opt_rrd) rrdPS_SM = (counter_sip_message_packets - this->counter_sip_message_packets_old) / statPeriod;
				} else {
					outStr << "-";
				}

				outStr << " R:";
				if(this->counter_rtp_packets_old) {
					outStr << (counter_rtp_packets - this->counter_rtp_packets_old) / statPeriod;
					if (opt_rrd) rrdPS_R = (counter_rtp_packets - this->counter_rtp_packets_old) / statPeriod;
				} else {
					outStr << "-";
				}
				outStr << " A:";
				if(this->counter_all_packets_old) {
					outStr << (counter_all_packets - this->counter_all_packets_old) / statPeriod;
					if (opt_rrd) rrdPS_A = (counter_all_packets - this->counter_all_packets_old) / statPeriod;
				} else {
					outStr << "-";
				}
				outStr << "] ";
			}
			this->counter_calls_old = counter_calls;
			this->counter_sip_packets_old[0] = counter_sip_packets[0];
			this->counter_sip_packets_old[1] = counter_sip_packets[1];
			this->counter_sip_register_packets_old = counter_sip_register_packets;
			this->counter_sip_message_packets_old = counter_sip_message_packets;
			this->counter_rtp_packets_old = counter_rtp_packets;
			this->counter_all_packets_old = counter_all_packets;
			extern bool opt_save_query_to_files;
			if(loadFromQFiles) {
				string stat = loadFromQFiles->getLoadFromQFilesStat();
				u_int32_t avgDelayQuery = SqlDb::getAvgDelayQuery();
				SqlDb::resetDelayQuery();
				if(!stat.empty() || avgDelayQuery) {
					outStr << "SQLf[";
				}
				if(!stat.empty()) {
					outStr << stat;
				}
				if(avgDelayQuery) {
					if(!stat.empty()) {
						outStr << " / ";
					}
					outStr << setprecision(3) << (double)avgDelayQuery / 1000 << "s";
					if (opt_rrd) rrdSQLf_D = (signed int)avgDelayQuery;
				}
				if(!stat.empty() || avgDelayQuery) {
					outStr << "] ";
				}
			} else if(!opt_save_query_to_files) {
				outStr << "SQLq[";
				if(cloud_host[0]) {
					int sizeSQLq = sqlStore->getSize(1);
					outStr << (sizeSQLq >=0 ? sizeSQLq : 0);
				} else {
					int sizeSQLq;
					for(int i = 0; i < opt_mysqlstore_max_threads_cdr; i++) {
						sizeSQLq = sqlStore->getSize(STORE_PROC_ID_CDR_1 + i);
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
								if (rrdSQLq_C < 0) rrdSQLq_C = sizeSQLq;
								else rrdSQLq_C += sizeSQLq;
							}
						}
					}
					for(int i = 0; i < opt_mysqlstore_max_threads_message; i++) {
						sizeSQLq = sqlStore->getSize(STORE_PROC_ID_MESSAGE_1 + i);
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
								if (rrdSQLq_M < 0) rrdSQLq_M = sizeSQLq/100;
								else rrdSQLq_M += sizeSQLq / 100;
							}
						}
					}
					for(int i = 0; i < opt_mysqlstore_max_threads_register; i++) {
						sizeSQLq = sqlStore->getSize(STORE_PROC_ID_REGISTER_1 + i);
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
								if (rrdSQLq_R < 0)rrdSQLq_R = sizeSQLq / 100;
								else rrdSQLq_R += sizeSQLq / 100;
							}
						}
					}
					sizeSQLq = sqlStore->getSize(STORE_PROC_ID_SAVE_PACKET_SQL);
					if(sizeSQLq >= 0) {
						outStr << " L:" << sizeSQLq;
					}
					sizeSQLq = sqlStore->getSize(STORE_PROC_ID_CLEANSPOOL);
					if(sizeSQLq >= 0) {
						outStr << " Cl:" << sizeSQLq;
						if (opt_rrd) rrdSQLq_Cl = sizeSQLq / 100;
					}
					for(int i = 0; i < opt_mysqlstore_max_threads_http; i++) {
						sizeSQLq = sqlStore->getSize(STORE_PROC_ID_HTTP_1 + i);
						if(sizeSQLq >= (i ? 1 : 0)) {
							if(i) {
								outStr << " H" << (i+1) << ":";
							} else {
								outStr << " H:";
							}
							outStr << sizeSQLq;
							if (opt_rrd) {
								if (rrdSQLq_H < 0) rrdSQLq_H = sizeSQLq / 100;
								else rrdSQLq_H += sizeSQLq / 100;
							}
						}
					}
					if(opt_ipaccount) {
						for(int i = 0; i < opt_mysqlstore_max_threads_ipacc_base; i++) {
							sizeSQLq = sqlStore->getSize(STORE_PROC_ID_IPACC_1 + i);
							if(sizeSQLq >= 1) {
								outStr << " I" << (STORE_PROC_ID_IPACC_1 + i) << ":" << sizeSQLq;
							}
						}
						for(int i = STORE_PROC_ID_IPACC_AGR_INTERVAL; i <= STORE_PROC_ID_IPACC_AGR_DAY; i++) {
							sizeSQLq = sqlStore->getSize(i);
							if(sizeSQLq >= 1) {
								outStr << " I" << i << ":" << sizeSQLq;
							}
						}
						for(int i = 0; i < opt_mysqlstore_max_threads_ipacc_agreg2; i++) {
							sizeSQLq = sqlStore->getSize(STORE_PROC_ID_IPACC_AGR2_HOUR_1 + i);
							if(sizeSQLq >= 1) {
								outStr << " I" << (STORE_PROC_ID_IPACC_AGR2_HOUR_1 + i) << ":" << sizeSQLq;
							}
						}
						/*
						sizeSQLq = sqlStore->getSizeMult(12,
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
				}
				u_int32_t avgDelayQuery = SqlDb::getAvgDelayQuery();
				SqlDb::resetDelayQuery();
				if(avgDelayQuery) {
					outStr << " / " << setprecision(3) << (double)avgDelayQuery / 1000 << "s";
				}
				outStr << "] ";
			}
		}
		outStr << "heap[" << setprecision(0) << memoryBufferPerc << "|"
				  << setprecision(0) << memoryBufferPerc_trash << "|";
		if(opt_rrd) {
			rrdheap_buffer = memoryBufferPerc;
			rrdheap_ratio = buffersControl.getPercUseAsync();
		}

		double useAsyncWriteBuffer = buffersControl.getPercUseAsync();
		extern bool suspendCleanspool;
		extern volatile int clean_spooldir_run_processing;
		if(useAsyncWriteBuffer > 50) {
			if(!suspendCleanspool && isSetCleanspoolParameters()) {
				syslog(LOG_NOTICE, "large workload disk operation - cleanspool suspended");
				suspendCleanspool = true;
			}
		} else if(useAsyncWriteBuffer < 10) {
			if(suspendCleanspool && !clean_spooldir_run_processing) {
				syslog(LOG_NOTICE, "cleanspool resumed");
				suspendCleanspool = false;
			}
		}
		outStr << setprecision(0) << useAsyncWriteBuffer << "] ";
		if(this->instancePcapHandle) {
			unsigned long bypassBufferSizeExeeded = this->instancePcapHandle->pcapStat_get_bypass_buffer_size_exeeded();
			string statPacketDrops = this->instancePcapHandle->getStatPacketDrop();
			if(bypassBufferSizeExeeded || !statPacketDrops.empty()) {
				outStr << "drop[";
				if(bypassBufferSizeExeeded) {
					outStr << "H:" << bypassBufferSizeExeeded;
					if(opt_rrd) rrddrop_exceeded = bypassBufferSizeExeeded;
				}
				if(!statPacketDrops.empty()) {
					if(bypassBufferSizeExeeded) {
						outStr << " ";
					}
					if(opt_rrd) rrddrop_packets = this->instancePcapHandle->getCountPacketDrop();
					outStr << statPacketDrops;
				}
				outStr << "] ";
			}
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
			if (opt_rrd) rrdspeedmbs = speed;
		}
		if(opt_cachedir[0] != '\0') {
			outStr << "cdq[" << calltable->files_queue.size() << "][" << ((float)(cachedirtransfered - lastcachedirtransfered) / 1024.0 / 1024.0 / (float)statPeriod) << " MB/s] ";
			lastcachedirtransfered = cachedirtransfered;
		}
	}
	if(opt_pcap_dump_tar) {
		outStr << "tarQ[" << glob_tar_queued_files << "] ";
		u_int64_t tarBufferSize = ChunkBuffer::getChunkBuffersSumsize();
		if(tarBufferSize) {
			outStr << "tarB[" << setprecision(0) << tarBufferSize / 1024 / 1024 << "MB] ";
		}
		extern TarQueue *tarQueue;
		bool okPercTarCpu = false;
		for(int i = 0; i < tarQueue->maxthreads; i++) {
			double tar_cpu = tarQueue->getCpuUsagePerc(i, true);
			if(tar_cpu > 0) {
				if(okPercTarCpu) {
					outStr << '|';
				} else {
					outStr << "tarCPU[";
					okPercTarCpu = true;
				}
				outStr << setprecision(1) << tar_cpu;
				if (opt_rrd) {
					rrdtacCPU_tar += tar_cpu;
				}
			}
		}
		if(okPercTarCpu) {
			outStr << "%] ";
		}
	}
	ostringstream outStrStat;
	outStrStat << fixed;
	if(this->instancePcapHandle) {
		double sumMaxReadThreads;
		outStrStat << this->instancePcapHandle->pcapStatString_cpuUsageReadThreads(&sumMaxReadThreads);
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
			if (opt_rrd) rrdtCPU_t0 = t0cpu;
		}
		static int countOccurencesForWarning = 0;
		if((sumMaxReadThreads > 60 || t0cpu > 60) && getThreadingMode() < 4) {
			++countOccurencesForWarning;
		} else if(countOccurencesForWarning > 0) {
			--countOccurencesForWarning;
		}
		if(countOccurencesForWarning >= 3) {
			syslog(LOG_WARNING, "warning - reading process (t0CPU) needs to be threaded - try to set threading_mod to %i", getThreadingMode() + 1); 
			countOccurencesForWarning = 0;
		}
	}
	string t1cpu = this->getCpuUsage(false, true);
	if(t1cpu.length()) {
		outStrStat << t1cpu << " ";
	} else {
		double t1cpu = this->getCpuUsagePerc(mainThread, true);
		if(t1cpu >= 0) {
			outStrStat << "t1CPU[" << setprecision(1) << t1cpu << "%] ";
			if (opt_rrd) rrdtCPU_t1 = t1cpu;
		}
	}
	double t2cpu = this->getCpuUsagePerc(writeThread, true);
	if(t2cpu >= 0) {
		outStrStat << "t2CPU[" << setprecision(1) << t2cpu;
		if(preProcessPacket) {
			double t2cpu_preprocess_packet_out_thread = preProcessPacket->getCpuUsagePerc(true);
			if(t2cpu_preprocess_packet_out_thread >= 0) {
				outStrStat << "/" << setprecision(1) << t2cpu_preprocess_packet_out_thread;
				if (opt_rrd) rrdtCPU_t2 = t2cpu_preprocess_packet_out_thread;
			}
		} else {
			if (opt_rrd) rrdtCPU_t2 = t2cpu;
		}
		if(processRtpPacketHash) {
			for(int i = 0; i < 2; i++) {
				double t2cpu_process_rtp_packet_out_thread = processRtpPacketHash->getCpuUsagePerc(true, i);
				if(t2cpu_process_rtp_packet_out_thread >= 0) {
					outStrStat << "/" << setprecision(1) << t2cpu_process_rtp_packet_out_thread;
				}
			}
			for(int i = 0; i < MAX_PROCESS_RTP_PACKET_THREADS; i++) {
				if(processRtpPacketDistribute[i]) {
					double t2cpu_process_rtp_packet_out_thread = processRtpPacketDistribute[i]->getCpuUsagePerc(true);
					if(t2cpu_process_rtp_packet_out_thread >= 0) {
						outStrStat << "/" << setprecision(1) << t2cpu_process_rtp_packet_out_thread;
					}
				}
			}
		} else if(t2cpu > 60) {
			ProcessRtpPacket::autoStartProcessRtpPacket();
		}
		outStrStat << "%] ";
	}
	if(tcpReassemblyHttp) {
		string cpuUsagePerc = tcpReassemblyHttp->getCpuUsagePerc();
		if(!cpuUsagePerc.empty()) {
			outStrStat << "thttpCPU[" << cpuUsagePerc << "] ";
		}
	}
	if(tcpReassemblyWebrtc) {
		string cpuUsagePerc = tcpReassemblyWebrtc->getCpuUsagePerc();
		if(!cpuUsagePerc.empty()) {
			outStrStat << "twebrtcCPU[" << cpuUsagePerc << "] ";
		}
	}
	if(tcpReassemblySsl) {
		string cpuUsagePerc = tcpReassemblySsl->getCpuUsagePerc();
		if(!cpuUsagePerc.empty()) {
			outStrStat << "tsslCPU[" << cpuUsagePerc << "] ";
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
					rrdtacCPU_zip += v_tac_cpu[i];
				}
			}
			outStrStat << "%] ";
		}
		extern int opt_pcap_dump_asyncwrite_limit_new_thread;
		if(last_tac_cpu > opt_pcap_dump_asyncwrite_limit_new_thread) {
			asyncClose->addThread();
		}
		if(last_tac_cpu < 5) {
			asyncClose->removeThread();
		}
	}
	if(opt_ipaccount) {
		string ipaccCpu = getIpaccCpuUsagePerc();
		if(!ipaccCpu.empty()) {
			outStrStat << "tipaccCPU["
				   << ipaccCpu
				   << "] ";
		}
	}
	outStrStat << "RSS/VSZ[";
	long unsigned int rss = this->getRssUsage(true);
	if(rss > 0) {
		outStrStat << setprecision(0) << (double)rss/1024/1024;
		if (opt_rrd) rrdRSSVSZ_rss = (double)rss/1024/1024;
	}
	long unsigned int vsize = this->getVsizeUsage();
	if(vsize > 0) {
		if(rss > 0) {
			outStrStat << '|';
		}
		outStrStat << setprecision(0) << (double)vsize/1024/1024;
		if (opt_rrd) rrdRSSVSZ_vsize =(double)vsize/1024/1024;
	}
	outStrStat << "]MB ";
	outStrStat << "LA[" << getLoadAvgStr() << "] ";
	pbStatString = outStr.str() + outStrStat.str();
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
			syslog(LOG_NOTICE, outStrStat.str().c_str());
		}
	} else if(VERBOSE) {
		outStr << outStrStat.str();
		extern bool incorrectCaplenDetected;
		if(incorrectCaplenDetected) {
			outStr << " !CAPLEN";
		}
		extern char opt_syslog_string[256];
		if(opt_syslog_string[0]) {
			outStr << " " << opt_syslog_string;
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
			syslog(LOG_NOTICE, pointToBeginLine);
			if(pointToLineBreak) {
				*pointToLineBreak = '\n';
				pointToBeginLine = pointToLineBreak + 1;
			} else {
				pointToBeginLine = NULL;
			}
		}
	}
	sumPacketsCounterIn[1] = sumPacketsCounterIn[0];
	sumPacketsCounterOut[1] = sumPacketsCounterOut[0];
	sumBlocksCounterIn[1] = sumBlocksCounterIn[0];
	sumBlocksCounterOut[1] = sumBlocksCounterOut[0];
	sumPacketsSize[1] = sumPacketsSize[0];
	sumPacketsSizeCompress[1] = sumPacketsSizeCompress[0];

	if (opt_rrd) {
		if (opt_rrd == 1) {
			//CREATE rrd files:
			char filename[1000];
			sprintf(filename, "%s/rrd/" ,opt_chdir);
			mkdir_r(filename, 0777);
			sprintf(filename, "%s/rrd/2db-drop.rrd", opt_chdir);
			vm_rrd_create_rrddrop(filename);
			sprintf(filename, "%s/rrd/2db-heap.rrd", opt_chdir);
			vm_rrd_create_rrdheap(filename);
			sprintf(filename, "%s/rrd/2db-PS.rrd", opt_chdir);
			vm_rrd_create_rrdPS(filename);
			sprintf(filename, "%s/rrd/2db-SQL.rrd", opt_chdir);
			vm_rrd_create_rrdSQL(filename);
			sprintf(filename, "%s/rrd/2db-tCPU.rrd", opt_chdir);
			vm_rrd_create_rrdtCPU(filename);
			sprintf(filename, "%s/rrd/2db-tacCPU.rrd", opt_chdir);
			vm_rrd_create_rrdtacCPU(filename);
			sprintf(filename, "%s/rrd/2db-RSSVSZ.rrd", opt_chdir);
			vm_rrd_create_rrdRSSVSZ(filename);
			sprintf(filename, "%s/rrd/2db-speedmbs.rrd", opt_chdir);
			vm_rrd_create_rrdspeedmbs(filename);
			sprintf(filename, "%s/rrd/2db-callscounter.rrd", opt_chdir);
			vm_rrd_create_rrdcallscounter(filename);
			opt_rrd ++;
		} else {
			char filename[1000];
			std::ostringstream cmdUpdate;
//			UPDATES of rrd files:
			//update rrddrop
			cmdUpdate << "N:" << rrddrop_exceeded;
			cmdUpdate <<  ":" << rrddrop_packets;
			sprintf(filename, "%s/rrd/2db-drop.rrd", opt_chdir);
			vm_rrd_update(filename, cmdUpdate.str().c_str());

			//update rrdheap;
			cmdUpdate.str(std::string());
			cmdUpdate << "N:" << rrdheap_buffer;
			cmdUpdate <<  ":" << rrdheap_ratio;
			sprintf(filename, "%s/rrd/2db-heap.rrd", opt_chdir);
			vm_rrd_update(filename, cmdUpdate.str().c_str());

			//update rrdPS;
			cmdUpdate.str(std::string());
			cmdUpdate << "N:" << rrdPS_C;
			cmdUpdate <<  ":" << rrdPS_S0;
			cmdUpdate <<  ":" << rrdPS_S1;
			cmdUpdate <<  ":" << rrdPS_SR;
			cmdUpdate <<  ":" << rrdPS_SM;
			cmdUpdate <<  ":" << rrdPS_R;
			cmdUpdate <<  ":" << rrdPS_A;
			sprintf(filename, "%s/rrd/2db-PS.rrd", opt_chdir);
			vm_rrd_update(filename, cmdUpdate.str().c_str());

			//update rrdSQL;
			cmdUpdate.str(std::string());
			if (rrdSQLf_D < 0) cmdUpdate << "N:0";
			 else cmdUpdate << "N:" << rrdSQLf_D;
			if (rrdSQLq_C < 0) cmdUpdate <<  ":U";
			 else cmdUpdate <<  ":" << rrdSQLq_C;
			if (rrdSQLq_M < 0) cmdUpdate <<  ":U";
			 else cmdUpdate <<  ":" << rrdSQLq_M;
			if (rrdSQLq_R < 0) cmdUpdate <<  ":U";
			 else cmdUpdate <<  ":" << rrdSQLq_R;
			if (rrdSQLq_Cl < 0) cmdUpdate <<  ":U";
			 else cmdUpdate <<  ":" << rrdSQLq_Cl;
			if (rrdSQLq_H < 0) cmdUpdate <<  ":U";
			 else cmdUpdate <<  ":" << rrdSQLq_H;
			sprintf(filename, "%s/rrd/2db-SQL.rrd", opt_chdir);
			vm_rrd_update(filename, cmdUpdate.str().c_str());

			//update rrdtCPU;
			cmdUpdate.str(std::string());
			cmdUpdate << "N:" << rrdtCPU_t0;
			cmdUpdate <<  ":" << rrdtCPU_t1;
			cmdUpdate <<  ":" << rrdtCPU_t2;
			sprintf(filename, "%s/rrd/2db-tCPU.rrd", opt_chdir);
			vm_rrd_update(filename, cmdUpdate.str().c_str());

			//update rrdtacCPU;
			cmdUpdate.str(std::string());
			cmdUpdate << "N:" << rrdtacCPU_zip;
			cmdUpdate <<  ":" << rrdtacCPU_tar;
			sprintf(filename, "%s/rrd/2db-tacCPU.rrd", opt_chdir);
			vm_rrd_update(filename, cmdUpdate.str().c_str());

			//update rrdRSSVSZ;
			cmdUpdate.str(std::string());
			cmdUpdate << "N:" << rrdRSSVSZ_rss;
			cmdUpdate <<  ":" << rrdRSSVSZ_vsize;
			sprintf(filename, "%s/rrd/2db-RSSVSZ.rrd", opt_chdir);
			vm_rrd_update(filename, cmdUpdate.str().c_str());

			//update rrdspeedmbs;
			cmdUpdate.str(std::string());
			cmdUpdate << "N:" << rrdspeedmbs;
			sprintf(filename, "%s/rrd/2db-speedmbs.rrd", opt_chdir);
			vm_rrd_update(filename, cmdUpdate.str().c_str());

			//update rrdcallscounter;
			cmdUpdate.str(std::string());
			cmdUpdate << "N:" << rrdcallscounter;
			sprintf(filename, "%s/rrd/2db-callscounter.rrd", opt_chdir);
			vm_rrd_update(filename, cmdUpdate.str().c_str());
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
	pthread_create(&this->threadHandle, NULL, _PcapQueue_threadFunction, this);
	return(true);
}

bool PcapQueue::createWriteThread() {
	pthread_create(&this->writeThreadHandle, NULL, _PcapQueue_writeThreadFunction, this);
	return(true);
}

int PcapQueue::pcap_next_ex_queue(pcap_t *pcapHandle, pcap_pkthdr** header, u_char** packet) {
	int res = ::pcap_next_ex(pcapHandle, header, (const u_char**)packet);
	if(!packet && res != -2) {
		if(VERBOSE) {
			u_long actTime = getTimeMS();
			if(actTime - 1000 > this->lastTimeLogErrPcapNextExNullPacket) {
				syslog(LOG_NOTICE,"packetbuffer %s: NULL PACKET, pcap response is %d", this->nameQueue.c_str(), res);
				this->lastTimeLogErrPcapNextExNullPacket = actTime;
			}
		}
		return(0);
	} else if(res == -1) {
		if(VERBOSE) {
			u_long actTime = getTimeMS();
			if(actTime - 1000 > this->lastTimeLogErrPcapNextExErrorReading) {
				syslog(LOG_NOTICE,"packetbuffer %s: error reading packets", this->nameQueue.c_str());
				this->lastTimeLogErrPcapNextExErrorReading = actTime;
			}
		}
		return(0);
	} else if(res == -2) {
		if(VERBOSE && opt_pb_read_from_file[0]) {
			syslog(LOG_NOTICE,"packetbuffer %s: end of pcap file, exiting", this->nameQueue.c_str());
		}
		return(-1);
	} else if(res == 0) {
		return(0);
	}
	return(1);
}

int PcapQueue::readPcapFromFifo(pcap_pkthdr_plus *header, u_char **packet, bool usePacketBuffer) {
	int rsltRead;
	size_t sizeHeader = sizeof(pcap_pkthdr_plus);
	size_t readHeader = 0;
	while(readHeader < sizeHeader) {
		rsltRead = read(this->fifoReadHandle, (u_char*)header + readHeader, sizeHeader - readHeader);
		if(rsltRead < 0) {
			return(0);
		}
		readHeader += rsltRead;
	}
	if(header->header_fix_size.caplen <=0) {
		return(0);
	}
	if(usePacketBuffer) {
		if(!this->packetBuffer) {
			this->packetBuffer = new FILE_LINE u_char[100000];
		}
		*packet = this->packetBuffer;
	} else {
		*packet = new FILE_LINE u_char[header->header_fix_size.caplen];
	}
	size_t readPacket = 0;
	while(readPacket < header->header_fix_size.caplen) {
		rsltRead = read(this->fifoReadHandle, *packet + readPacket, header->header_fix_size.caplen - readPacket);
		if(rsltRead < 0) {
			if(!usePacketBuffer) {
				delete [] *packet;
			}
			return(0);
		}
		readPacket += rsltRead;
	}
	return(1);
}

bool PcapQueue::writePcapToFifo(pcap_pkthdr_plus *header, u_char *packet) {
	write(this->fifoWriteHandle, header, sizeof(pcap_pkthdr_plus));
	write(this->fifoWriteHandle, packet, header->header_fix_size.caplen);
	return(true);
}

bool PcapQueue::initThread(void *arg, unsigned int arg2, string *error) {
	return(!this->enableMainThread || this->openFifoForRead(arg, arg2));
}

bool PcapQueue::initWriteThread(void *arg, unsigned int arg2) {
	return(!this->enableWriteThread || this->openFifoForWrite(arg, arg2));
}

bool PcapQueue::openFifoForRead(void *arg, unsigned int arg2) {
	if(this->fifoReadHandle != -1) {
		return(true);
	}
	struct stat st;
	if(stat(this->fifoFileForRead.c_str(), &st) != 0) {
		mkfifo(this->fifoFileForRead.c_str(), 0666);
	}
	this->fifoReadHandle = open(this->fifoFileForRead.c_str(), O_WRONLY);
	if(this->fifoReadHandle >= 0) {
		if(DEBUG_VERBOSE) {
			cout << "openFifoForRead: OK" << endl;
		}
		return(true);
	} else {
		syslog(LOG_ERR, "packetbuffer %s: openFifoForRead failed", this->nameQueue.c_str());
		return(false);
	}
}

bool PcapQueue::openFifoForWrite(void *arg, unsigned int arg2) {
	if(this->fifoWriteHandle != -1) {
		return(true);
	}
	struct stat st;
	if(stat(this->fifoFileForWrite.c_str(), &st) != 0) {
		mkfifo(this->fifoFileForWrite.c_str(), 0666);
	}
	this->fifoWriteHandle = open(this->fifoFileForWrite.c_str(), O_RDWR);
	if(this->fifoWriteHandle >= 0) {
		if(DEBUG_VERBOSE) {
			cout << "openFifoForWrite: OK" << endl;
		}
		return(true);
	} else {
		syslog(LOG_ERR, "packetbuffer %s: openFifoForWrite failed", this->nameQueue.c_str());
		return(false);
	}
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
			       << setw(9) << (sumPacketsCounterIn[0]-sumPacketsCounterIn[1])/statPeriod << " / " 
			       << setw(9) << (sumPacketsCounterOut[0]-sumPacketsCounterOut[1])/statPeriod << "  ";
		}
		outStr << "               : " 
		       << setw(7) << (sumBlocksCounterIn[0]-sumBlocksCounterIn[1])/statPeriod << " / " 
		       << setw(7) << (sumBlocksCounterOut[0]-sumBlocksCounterOut[1])/statPeriod;
		if(sumPacketsSize[0]) {
			outStr << "                ";
			if(sumPacketsSizeCompress[0]) {
				outStr << "   " 
				       << setw(12) << (sumPacketsSizeCompress[0]-sumPacketsSizeCompress[1])/statPeriod << " / " 
				       << setw(12) << (sumPacketsSize[0]-sumPacketsSize[1])/statPeriod;
			}
			outStr << "   " << ((double)(sumPacketsSize[0]-sumPacketsSize[1]))/statPeriod/(1024*1024)*8 << "Mb/s";
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
	if(sumPacketsSize[0]-sumPacketsSize[1]) {
		return(((double)(sumPacketsSize[0]-sumPacketsSize[1]))/statPeriod/(1024*1024)*8);
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
	if(offset < 0) {
		//// doplnit zjištění offsetu
		return;
	}
	
	extern SocketSimpleBufferWrite *sipSendSocket;
	extern int opt_sip_send_before_packetbuffer;
	if(!sipSendSocket || !opt_sip_send_before_packetbuffer) {
		return;
	}
 
	iphdr2 *header_ip = (iphdr2*)(packet + offset);
	bool nextPass;
	do {
		nextPass = false;
		if(header_ip->protocol == IPPROTO_IPIP) {
			// ip in ip protocol
			header_ip = (iphdr2*)((char*)header_ip + sizeof(iphdr2));
		} else if(header_ip->protocol == IPPROTO_GRE) {
			// gre protocol
			header_ip = convertHeaderIP_GRE(header_ip);
			if(header_ip) {
				nextPass = true;
			} else {
				return;
			}
		}
	} while(nextPass);

	char *data = NULL;
	int datalen = 0;
	uint16_t sport = 0;
	uint16_t dport = 0;
	if (header_ip->protocol == IPPROTO_UDP) {
		udphdr2 *header_udp = (udphdr2*) ((char *) header_ip + sizeof(*header_ip));
		data = (char *) header_udp + sizeof(*header_udp);
		datalen = (int)(header->caplen - ((u_char*)data - packet));
		sport = header_udp->source;
		dport = header_udp->dest;
	} else if (header_ip->protocol == IPPROTO_TCP) {
		tcphdr2 *header_tcp = (tcphdr2*) ((char *) header_ip + sizeof(*header_ip));
		data = (char *) header_tcp + (header_tcp->doff * 4);
		datalen = (int)(header->caplen - ((u_char*)data - packet)); 
		sport = header_tcp->source;
		dport = header_tcp->dest;
	} else {
		return;
	}
	
	if(sipSendSocket && sport && dport &&
	   (sipportmatrix[htons(sport)] || sipportmatrix[htons(dport)]) &&
	   check_sip20(data, datalen)) {
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
	this->pcapEnd = false;
	memset(&this->filterData, 0, sizeof(this->filterData));
	this->filterDataUse = false;
	this->pcapDumpHandle = NULL;
	this->pcapDumpLength = 0;
	this->pcapLinklayerHeaderType = 0;
	// CONFIG
	extern int opt_promisc;
	extern int opt_ringbuffer;
	this->pcap_snaplen = opt_enable_http || opt_enable_webrtc || opt_enable_ssl ? 6000 : 3200;
	this->pcap_promisc = opt_promisc;
	this->pcap_timeout = 1000;
	this->pcap_buffer_size = opt_ringbuffer * 1024 * 1024;
	//
	this->_last_ps_drop = 0;
	this->_last_ps_ifdrop = 0;
	this->countPacketDrop = 0;
	this->lastPacketTimeUS = 0;
	this->lastTimeLogErrPcapNextExNullPacket = 0;
	this->lastTimeLogErrPcapNextExErrorReading = 0;
}

void PcapQueue_readFromInterface_base::setInterfaceName(const char *interfaceName) {
	this->interfaceName = interfaceName;
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
}

bool PcapQueue_readFromInterface_base::startCapture(string *error) {
	*error = "";
	static volatile int _sync_start_capture = 0;
	long unsigned int rssBeforeActivate, rssAfterActivate;
	while(__sync_lock_test_and_set(&_sync_start_capture, 1)) {
		usleep(100);
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	char errorstr[2048];
	if(VERBOSE) {
		syslog(LOG_NOTICE, "packetbuffer - %s: capturing", this->getInterfaceName().c_str());
	}
	if(pcap_lookupnet(this->interfaceName.c_str(), &this->interfaceNet, &this->interfaceMask, errbuf) == -1) {
		this->interfaceMask = PCAP_NETMASK_UNKNOWN;
	}
	if((this->pcapHandle = pcap_create(this->interfaceName.c_str(), errbuf)) == NULL) {
		sprintf(errorstr, "packetbuffer - %s: pcap_create failed: %s", this->getInterfaceName().c_str(), errbuf); 
		goto failed;
	}
	global_pcap_handle = this->pcapHandle;
	int status;
	if((status = pcap_set_snaplen(this->pcapHandle, this->pcap_snaplen)) != 0) {
		sprintf(errorstr, "packetbuffer - %s: pcap_snaplen failed", this->getInterfaceName().c_str()); 
		goto failed;
	}
	if((status = pcap_set_promisc(this->pcapHandle, this->pcap_promisc)) != 0) {
		sprintf(errorstr, "packetbuffer - %s: pcap_set_promisc failed", this->getInterfaceName().c_str()); 
		goto failed;
	}
	if((status = pcap_set_timeout(this->pcapHandle, this->pcap_timeout)) != 0) {
		sprintf(errorstr, "packetbuffer - %s: pcap_set_timeout failed", this->getInterfaceName().c_str()); 
		goto failed;
	}
	if((status = pcap_set_buffer_size(this->pcapHandle, this->pcap_buffer_size)) != 0) {
		sprintf(errorstr, "packetbuffer - %s: pcap_set_buffer_size failed", this->getInterfaceName().c_str()); 
		goto failed;
	}
	rssBeforeActivate = getRss() / 1024 / 1024;
	if((status = pcap_activate(this->pcapHandle)) != 0) {
		sprintf(errorstr, "packetbuffer - %s: libpcap error: %s", this->getInterfaceName().c_str(), pcap_geterr(this->pcapHandle)); 
		if(opt_fork) {
			ostringstream outStr;
			outStr << this->getInterfaceName() << ": libpcap error: " << pcap_geterr(this->pcapHandle);
			daemonizeOutput(outStr.str());
		}
		goto failed;
	}
	if(rssBeforeActivate) {
		for(int i = 0; i < 50; i++) {
			usleep(100);
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
	}
	if(opt_mirrorip) {
		if(opt_mirrorip_dst[0] == '\0') {
			syslog(LOG_ERR, "packetbuffer - %s: mirroring packets was disabled because mirroripdst is not set", this->getInterfaceName().c_str());
			opt_mirrorip = 0;
		} else {
			syslog(LOG_NOTICE, "packetbuffer - %s: starting mirroring [%s]->[%s]", opt_mirrorip_src, opt_mirrorip_dst, this->getInterfaceName().c_str());
			mirrorip = new FILE_LINE MirrorIP(opt_mirrorip_src, opt_mirrorip_dst);
		}
	}
	if(*user_filter != '\0') {
		char filter_exp[2048] = "";
		snprintf(filter_exp, sizeof(filter_exp), "%s", user_filter);
		// Compile and apply the filter
		struct bpf_program fp;
		if (pcap_compile(this->pcapHandle, &fp, filter_exp, 0, this->interfaceMask) == -1) {
			sprintf(errorstr, "packetbuffer - %s: can not parse filter %s: %s", this->getInterfaceName().c_str(), filter_exp, pcap_geterr(this->pcapHandle));
			if(opt_fork) {
				ostringstream outStr;
				outStr << this->getInterfaceName() << ": can not parse filter " << filter_exp << ": " << pcap_geterr(this->pcapHandle);
				daemonizeOutput(outStr.str());
			}
			goto failed;
		}
		if (pcap_setfilter(this->pcapHandle, &fp) == -1) {
			sprintf(errorstr, "packetbuffer - %s: can not install filter %s: %s", this->getInterfaceName().c_str(), filter_exp, pcap_geterr(this->pcapHandle));
			if(opt_fork) {
				ostringstream outStr;
				outStr << this->getInterfaceName() << ": can not install filter " << filter_exp << ": " << pcap_geterr(this->pcapHandle);
				daemonizeOutput(outStr.str());
			}
			goto failed;
		}
	}
	this->pcapLinklayerHeaderType = pcap_datalink(this->pcapHandle);
	if(!this->pcapLinklayerHeaderType) {
		sprintf(errorstr, "packetbuffer - %s: pcap_datalink failed", this->getInterfaceName().c_str()); 
		goto failed;
	}
	global_pcap_dlink = this->pcapLinklayerHeaderType;
//	syslog(LOG_NOTICE, "DLT - %s: %i", this->getInterfaceName().c_str(), this->pcapLinklayerHeaderType);
	if(opt_pcapdump) {
		char pname[1024];
		sprintf(pname, "/var/spool/voipmonitor/voipmonitordump-%s-%u.pcap", this->interfaceName.c_str(), (unsigned int)time(NULL));
		this->pcapDumpHandle = pcap_dump_open(this->pcapHandle, pname);
	}
	__sync_lock_release(&_sync_start_capture);
	return(true);
failed:
	__sync_lock_release(&_sync_start_capture);
	syslog(LOG_ERR, errorstr);
	*error = errorstr;
	return(false);
}

inline int PcapQueue_readFromInterface_base::pcap_next_ex_iface(pcap_t *pcapHandle, pcap_pkthdr** header, u_char** packet) {
	if(!pcapHandle) {
		*header = NULL;
		*packet = NULL;
		return(0);
	}
	int res = ::pcap_next_ex(pcapHandle, header, (const u_char**)packet);
	if(!packet && res != -2) {
		if(VERBOSE) {
			u_long actTime = getTimeMS();
			if(actTime - 1000 > this->lastTimeLogErrPcapNextExNullPacket) {
				syslog(LOG_NOTICE,"packetbuffer - %s: NULL PACKET, pcap response is %d", this->getInterfaceName().c_str(), res);
				this->lastTimeLogErrPcapNextExNullPacket = actTime;
			}
		}
		return(0);
	} else if(res == -1) {
		if(VERBOSE) {
			u_long actTime = getTimeMS();
			if(actTime - 1000 > this->lastTimeLogErrPcapNextExErrorReading) {
				syslog(LOG_NOTICE,"packetbuffer - %s: error reading packets", this->getInterfaceName().c_str());
				this->lastTimeLogErrPcapNextExErrorReading = actTime;
			}
		}
		return(0);
	} else if(res == -2) {
		if(VERBOSE && opt_pb_read_from_file[0]) {
			syslog(LOG_NOTICE,"packetbuffer - %s: end of pcap file, exiting", this->getInterfaceName().c_str());
		}
		return(-1);
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
		if(opt_pb_read_from_file_acttime) {
			static u_int64_t diffTime;
			u_int64_t packetTime = (*header)->ts.tv_sec * 1000000ull + (*header)->ts.tv_usec;
			if(!diffTime) {
				diffTime = getTimeUS() - packetTime;
			}
			packetTime += diffTime;
			(*header)->ts.tv_sec = packetTime / 1000000ull;
			(*header)->ts.tv_usec = packetTime % 1000000ull;
		}
		if(opt_pb_read_from_file_speed) {
			static u_int64_t diffTime;
			u_int64_t packetTime = (*header)->ts.tv_sec * 1000000ull + (*header)->ts.tv_usec;
			if(this->lastPacketTimeUS) {
				if(packetTime > this->lastPacketTimeUS) {
					diffTime += packetTime - this->lastPacketTimeUS;
					if(diffTime > 5000 * (unsigned)opt_pb_read_from_file_speed) {
						usleep(diffTime / opt_pb_read_from_file_speed / pow(1.1, opt_pb_read_from_file_speed));
						diffTime = 0;
					}
				}
			}
			this->lastPacketTimeUS = packetTime;
		} else {
			if(heapPerc > 80) {
				usleep(1);
			}
		}
	}
	return(1);
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

inline int PcapQueue_readFromInterface_base::pcapProcess(pcap_pkthdr** header, u_char** packet, bool *destroy,
							 bool enableDefrag, bool enableCalcMD5, bool enableDedup, bool enableDump) {
	return(::pcapProcess(header, packet, destroy,
			     enableDefrag, enableCalcMD5, enableDedup, enableDump,
			     &ppd, pcapLinklayerHeaderType, pcapDumpHandle, getInterfaceName().c_str()));
}

string PcapQueue_readFromInterface_base::pcapStatString_interface(int statPeriod) {
	ostringstream outStr;
	if(this->pcapHandle) {
		pcap_stat ps;
		int pcapstatres = pcap_stats(this->pcapHandle, &ps);
		if(pcapstatres == 0) {
			if(ps.ps_drop > this->_last_ps_drop/* || ps.ps_ifdrop > this->_last_ps_ifdrop*/) {
				outStr << "DROPPED PACKETS - " << this->getInterfaceName() << ": "
				       << "libpcap or interface dropped some packets!"
				       << " rx:" << ps.ps_recv
				       << " pcapdrop:" << ps.ps_drop - this->_last_ps_drop
				       << " ifdrop:"<< ps.ps_ifdrop - this->_last_ps_drop << endl
				       << "     increase --ring-buffer (kernel >= 2.6.31 and libpcap >= 1.0.0)" << endl;
				this->_last_ps_drop = ps.ps_drop;
				this->_last_ps_ifdrop = ps.ps_ifdrop;
				++this->countPacketDrop;
				pcap_drop_flag = 1;
			}
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
		if (pcapstatres == 0 && (ps.ps_drop || ps.ps_ifdrop)) {
			this->_last_ps_drop = ps.ps_drop;
			this->_last_ps_ifdrop = ps.ps_ifdrop;
		}
		this->countPacketDrop = 0;
	}
}

string PcapQueue_readFromInterface_base::getInterfaceName(bool simple) {
	return((simple ? "" : "interface ") + this->interfaceName);
}


PcapQueue_readFromInterfaceThread::PcapQueue_readFromInterfaceThread(const char *interfaceName, eTypeInterfaceThread typeThread,
								     PcapQueue_readFromInterfaceThread *readThread,
								     PcapQueue_readFromInterfaceThread *prevThread,
								     PcapQueue_readFromInterfaceThread *prevThread2)
 : PcapQueue_readFromInterface_base(interfaceName) {
	this->threadHandle = 0;
	this->threadId = 0;
	this->threadInitOk = 0;
	this->threadInitFailed = false;
	this->qringmax = opt_pcap_queue_iface_qring_size;
	for(int i = 0; i < 2; i++) {
		if(i == 0 || typeThread == defrag) {
			this->qring[i] = new FILE_LINE hpi[this->qringmax];
			memset(this->qring[i], 0, sizeof(hpi) * this->qringmax);
		} else {
			this->qring[i] = NULL;
		}
		this->readit[i] = 0;
		this->writeit[i] = 0;
	}
	memset(this->threadPstatData, 0, sizeof(this->threadPstatData));
	this->threadTerminated = false;
	this->_sync_qring = 0;
	this->readThread = readThread;
	this->defragThread = NULL;
	this->md1Thread = NULL;
	this->md2Thread = NULL;
	this->dedupThread = NULL;
	this->typeThread = typeThread;
	this->prevThreads[0] = prevThread;
	this->prevThreads[1] = prevThread2;
	this->indexDefragQring = 0;
	this->push_counter = 1;
	this->pop_counter = 1;
	this->threadDoTerminate = false;
	this->headerPacketStack = NULL;
	if(typeThread == read) {
		this->headerPacketStack = new FILE_LINE PcapQueue_HeaderPacketStack(this->qringmax);
	}
	pthread_create(&this->threadHandle, NULL, _PcapQueue_readFromInterfaceThread_threadFunction, this);
}

PcapQueue_readFromInterfaceThread::~PcapQueue_readFromInterfaceThread() {
	if(this->defragThread) {
		while(this->defragThread->threadInitOk && !this->defragThread->isTerminated()) {
			usleep(100000);
		}
		delete this->defragThread;
	}
	if(this->md1Thread) {
		while(this->md1Thread->threadInitOk && !this->md1Thread->isTerminated()) {
			usleep(100000);
		}
		delete this->md1Thread;
	}
	if(this->md2Thread) {
		while(this->md2Thread->threadInitOk && !this->md2Thread->isTerminated()) {
			usleep(100000);
		}
		delete this->md2Thread;
	}
	if(this->dedupThread) {
		while(this->dedupThread->threadInitOk && !this->dedupThread->isTerminated()) {
			usleep(100000);
		}
		delete this->dedupThread;
	}
	for(int i = 0; i < 2; i++) {
		if(this->qring[i]) {
			for(uint j = 0; j < this->qringmax; j++) {
				if(this->qring[i][j].used) {
					delete this->qring[i][j].header;
					delete [] this->qring[i][j].packet;
				}
			}
			delete [] this->qring[i];
		}
	}
	if(this->headerPacketStack) {
		delete this->headerPacketStack;
	}
}

inline void PcapQueue_readFromInterfaceThread::push(pcap_pkthdr* header,u_char* packet, bool ok_for_header_packet_stack,
						    u_int offset, uint16_t *md5, int index, uint32_t counter) {
	uint32_t writeIndex = this->writeit[index] % this->qringmax;
	//while(__sync_lock_test_and_set(&this->_sync_qring, 1));
	while(this->qring[index][writeIndex].used > 0) {
		//__sync_lock_release(&this->_sync_qring);
		usleep(100);
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
}

inline PcapQueue_readFromInterfaceThread::hpi PcapQueue_readFromInterfaceThread::pop(int index, bool moveReadit) {
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
		if(moveReadit) {
			this->qring[index][readIndex].used = 0;
			if((this->readit[index] + 1) == this->qringmax) {
				this->readit[index] = 0;
			} else {
				this->readit[index]++;
			}
		}
	}
	//__sync_lock_release(&this->_sync_qring);
	return(rslt_hpi);
}

inline void PcapQueue_readFromInterfaceThread::moveReadit(int index) {
	this->qring[index][this->readit[index] % this->qringmax].used = 0;
	if((this->readit[index] + 1) == this->qringmax) {
		this->readit[index] = 0;
	} else {
		this->readit[index]++;
	}
}


inline PcapQueue_readFromInterfaceThread::hpi PcapQueue_readFromInterfaceThread::POP(bool moveReadit) {
	return(this->dedupThread ? this->dedupThread->pop(0, moveReadit) : this->pop(0, moveReadit));
}

inline void PcapQueue_readFromInterfaceThread::moveREADIT() {
	if(this->dedupThread) {
		this->dedupThread->moveReadit(0);
	} else {
		this->moveReadit(0);
	}
}


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


void *PcapQueue_readFromInterfaceThread::threadFunction(void *arg, unsigned int arg2) {
	this->threadId = get_unix_tid();
	if(VERBOSE) {
		ostringstream outStr;
		outStr << "start thread t0i_" 
		       << (this->typeThread == read ? "read" : 
			   this->typeThread == defrag ? "defrag" :
			   this->typeThread == md1 ? "md1" :
			   this->typeThread == md2 ? "md2" :
			   this->typeThread == dedup ? "dedup" : "---") 
		       << " (" << this->getInterfaceName() << ") - pid: " << this->threadId << endl;
		syslog(LOG_NOTICE, outStr.str().c_str());
	}
	if(this->typeThread == read) {
		if(opt_pcap_queue_iface_dedup_separate_threads) {
			if(opt_pcap_queue_iface_dedup_separate_threads_extend) {
				this->defragThread = new FILE_LINE PcapQueue_readFromInterfaceThread(this->interfaceName.c_str(), defrag, this, this);
				this->md1Thread = new FILE_LINE PcapQueue_readFromInterfaceThread(this->interfaceName.c_str(), md1, this, this->defragThread);
				this->md2Thread = new FILE_LINE PcapQueue_readFromInterfaceThread(this->interfaceName.c_str(), md2, this, this->defragThread);
				this->dedupThread = new FILE_LINE PcapQueue_readFromInterfaceThread(this->interfaceName.c_str(), dedup, this, this->md1Thread, this->md2Thread);
			} else {
				this->dedupThread = new FILE_LINE PcapQueue_readFromInterfaceThread(this->interfaceName.c_str(), dedup, this, this);
			}
		}
		string error;
		if(!this->startCapture(&error)) {
			this->threadTerminated = true;
			this->threadInitFailed = true;
			this->threadDoTerminate = true;
			if(this->dedupThread) {
				this->dedupThread->threadInitFailed = true;
				this->dedupThread->threadDoTerminate = true;
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
			if(!opt_pcap_queue_receive_from_ip_port) {
				vm_terminate_error(error.c_str());
			}
			return(NULL);
		}
		this->threadInitOk = 1;
		while(this->threadInitOk != 2) {
			if(is_terminating()) {
				return(NULL);
			}
			usleep(1000);
		}
		this->initStat_interface();
		if(this->dedupThread) {
			this->dedupThread->pcapLinklayerHeaderType = this->pcapLinklayerHeaderType;
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
	} else {
		while(!is_terminating() && this->readThread->threadInitOk != 2) {
			usleep(1000);
		}
		if(is_terminating()) {
			return(NULL);
		}
	}
	pcap_pkthdr *header = NULL, *_header = NULL;
	u_char *packet = NULL, *_packet = NULL;
	u_int offset;
	bool ok_for_header_packet_stack = false;
	bool destroy = false;
	int res;
	u_int32_t libpcap_buffer_offset = 0;
	u_char **libpcap_buffer = NULL;
	u_char *libpcap_buffer_old = NULL;
	sHeaderPacket headerPacketRead;
	while(!(is_terminating() || this->threadDoTerminate)) {
		_header = NULL;
		_packet = NULL;
		ok_for_header_packet_stack = false;
		destroy = false;
		switch(this->typeThread) {
		case read: {
			if(!headerPacketRead.packet) {
				if(!this->headerPacketStack || !this->headerPacketStack->get_hp(&headerPacketRead)) {
					headerPacketRead.alloc(this->pcap_snaplen);
				}
			}
			if(libpcap_buffer) {
				*libpcap_buffer = headerPacketRead.packet;
				
			}
			res = this->pcap_next_ex_iface(this->pcapHandle, &header, &packet);
			if(res == -1) {
				break;
			} else if(res == 0) {
				continue;
			}
			/* check change packet content - disabled
			u_char *packet_pcap = packet;
			unsigned int ip_tot_len = 0;
			if(header->caplen >= 14 + sizeof(iphdr2)) {
				ip_tot_len = ((iphdr2*)(packet + 14))->tot_len;
			}
			*/
			memcpy(headerPacketRead.header, header, sizeof(pcap_pkthdr));
			if(!libpcap_buffer) {
				memcpy(headerPacketRead.packet, packet, header->caplen);
			}
			if(!libpcap_buffer_offset) {
				cout << "detect oneshot buffer" << endl;
				libpcap_buffer = &(((_pcap_linux*)((struct _pcap*)this->pcapHandle)->priv)->oneshot_buffer);
				libpcap_buffer_offset = (u_char*)libpcap_buffer - (u_char*)this->pcapHandle;
				int libpcap_buffer_ok = 0;
				if(libpcap_buffer_offset >= 0 && libpcap_buffer_offset < 1000 &&
				   *libpcap_buffer == packet) {
					libpcap_buffer_ok = 1;
					cout << "method 1 success" << endl;
				} else { 
					for(int i = 0; i < 1000; i++) {
						if(*(u_char**)((u_char*)this->pcapHandle + i) == packet) {
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
					cout << "packet: " << hex << (long)packet << endl;
					cout << dec;
					if(libpcap_buffer_ok == 1) {
						cout << "device: " << ((_pcap_linux*)((struct _pcap*)this->pcapHandle)->priv)->device << endl;
					}
					cout << "offset: " << libpcap_buffer_offset << endl;
					libpcap_buffer_old = packet;
				}
				syslog(LOG_NOTICE, "find oneshot libpcap buffer : %s", libpcap_buffer ? "success" : "failed");
			}
			ok_for_header_packet_stack = true;
			/* check change packet content - disabled
			if(ip_tot_len && ip_tot_len != ((iphdr2*)(packet_pcap + 14))->tot_len) {
				static u_long lastTimeLogErrBuggyKernel = 0;
				u_long actTime = getTimeMS(header);
				if(actTime - 1000 > lastTimeLogErrBuggyKernel) {
					syslog(LOG_ERR, "SUSPICIOUS CHANGE PACKET CONTENT: buggy kernel - contact support@voipmonitor.org");
					lastTimeLogErrBuggyKernel = actTime;
				}
			}
			*/
			if(opt_pcap_queue_iface_dedup_separate_threads_extend) {
				this->push(headerPacketRead.header, headerPacketRead.packet, ok_for_header_packet_stack, 0, NULL);
			} else {
				_header = header = headerPacketRead.header;
				_packet = packet = headerPacketRead.packet;
				res = opt_pcap_queue_iface_dedup_separate_threads ?
				       this->pcapProcess(&header, &packet, &destroy,
							 true, false, false, false) :
				       this->pcapProcess(&header, &packet, &destroy);
				if(res == -1) {
					break;
				} else if(res == 0) {
					if(destroy) {
						if(header != _header) delete header;
						if(packet != _packet) delete [] packet;
					}
					continue;
				} else {
					if(packet != _packet) {
						ok_for_header_packet_stack = false;
					}
				}
				this->push(header, packet, ok_for_header_packet_stack, this->ppd.header_ip_offset, NULL);
			}
			headerPacketRead.packet = NULL;
			}
			break;
		case defrag: {
			hpi hpii = this->prevThreads[0]->pop();
			if(!hpii.packet) {
				usleep(100);
				continue;
			} else {
				header = _header = hpii.header;
				packet = _packet = hpii.packet;
				ok_for_header_packet_stack = hpii.ok_for_header_packet_stack;
				if(opt_pcapdump_all) {
					if(this->pcapDumpHandle &&
					   this->pcapDumpLength > opt_pcapdump_all * 1000000ull) {
						pcap_dump_close(this->pcapDumpHandle);
						this->pcapDumpHandle = NULL;
						this->pcapDumpLength = 0;
					}
					if(!this->pcapDumpHandle) {
						char pname[1024];
						sprintf(pname, "%s/voipmonitordump-%s-%s.pcap", 
							opt_chdir,
							this->interfaceName.c_str(), 
							sqlDateTimeString(time(NULL)).c_str());
						this->pcapDumpHandle = pcap_dump_open(global_pcap_handle, pname);
					}
					pcap_dump((u_char*)this->pcapDumpHandle, header, packet);
					this->pcapDumpLength += header->caplen;
				}
				if(opt_udpfrag || opt_pcapdump_all) {
					res = this->pcapProcess(&header, &packet, &destroy,
								true, false, false, false);
					if(res == -1) {
						break;
					} else if(res == 0) {
						if(destroy) {
							if(header != _header) delete header;
							if(packet != _packet) delete [] packet;
						}
						sHeaderPacket headerPacket(_header, _packet);
						if(!(ok_for_header_packet_stack && this->readThread->headerPacketStack &&
						     this->readThread->headerPacketStack->add_hp(&headerPacket, 2))) {
							delete _header;
							delete [] _packet;
						}
						continue;
					} else if(packet != _packet) {
						ok_for_header_packet_stack = false;
					}
				}
				this->push(header, packet, ok_for_header_packet_stack, 0, NULL, this->indexDefragQring, this->push_counter);
				++this->push_counter;
				if(!this->push_counter) {
					++this->push_counter;
				}
				this->indexDefragQring = this->indexDefragQring ? 0 : 1;
			}
			}
			break;
		case md1:
		case md2: {
			uint32_t counter = 0;
			hpi hpii = this->prevThreads[0]->pop(this->typeThread == md1 ? 0 : 1);
			if(!hpii.packet) {
				usleep(100);
				continue;
			}
			header = _header = hpii.header;
			packet = _packet = hpii.packet;
			offset = hpii.offset;
			ok_for_header_packet_stack = hpii.ok_for_header_packet_stack;
			counter = hpii.counter;
			if(opt_dup_check) {
				res = this->pcapProcess(&header, &packet, &destroy,
							false, true, false, false);
				if(res == -1) {
					break;
				} else if(res == 0) {
					if(destroy) {
						if(header != _header) delete header;
						if(packet != _packet) delete [] packet;
					}
					sHeaderPacket headerPacket(_header, _packet);
					if(!(ok_for_header_packet_stack && this->readThread->headerPacketStack &&
					     this->readThread->headerPacketStack->add_hp(&headerPacket, 2))) {
						delete _header;
						delete [] _packet;
					}
					continue;
				}
				offset = this->ppd.header_ip_offset;
			} else {
				if(!offset) {
					this->pcapProcess(&header, &packet, &destroy,
							  false, false, false, false);
					offset = this->ppd.header_ip_offset;
				}
			}
			this->push(header, packet, ok_for_header_packet_stack, offset, this->ppd.md5, 0, counter);
			}
			break;
		case dedup: {
			if(opt_pcap_queue_iface_dedup_separate_threads_extend) {
				int threadIndex = -1;
				uint32_t counter[2];
				for(int i = 0; i < 2; i++) {
					counter[i] = this->prevThreads[i]->getCounter();
					if(counter[i] && this->pop_counter == counter[i]) {
						threadIndex = i;
						break;
					}
				}
				if(threadIndex < 0) {
					if(counter[0] && counter[1]) {
						threadIndex = counter[0] < counter[1] ? 0 : 1;
						this->pop_counter = counter[threadIndex];
					} else {
						usleep(100);
						continue;
					}
				}
				hpi hpii = this->prevThreads[threadIndex]->pop();
				if(!hpii.packet) {
					usleep(100);
					continue;
				}
				header = _header = hpii.header;
				packet = _packet = hpii.packet;
				offset = hpii.offset;
				ok_for_header_packet_stack = hpii.ok_for_header_packet_stack;
				++this->pop_counter;
				if(!this->pop_counter) {
					++this->pop_counter;
				}
				if(opt_dup_check) {
					if(hpii.md5[0]) {
						memcpy(this->ppd.md5, hpii.md5, MD5_DIGEST_LENGTH);
					} else {
						this->ppd.md5[0] = 0;
					}
					res = this->pcapProcess(&header, &packet, &destroy,
								false, false, true, true);
					if(res == -1) {
						break;
					} else if(res == 0) {
						if(destroy) {
							if(header != _header) delete header;
							if(packet != _packet) delete [] packet;
						}
						sHeaderPacket headerPacket(_header, _packet);
						if(!(ok_for_header_packet_stack && this->readThread->headerPacketStack &&
						     this->readThread->headerPacketStack->add_hp(&headerPacket, 3))) {
							delete _header;
							delete [] _packet;
						}
						continue;
					}
					offset = this->ppd.header_ip_offset;
				} else {
					if(pcapDumpHandle || !offset) {
						this->pcapProcess(&header, &packet, &destroy,
								  false, false, false, pcapDumpHandle);
						offset = this->ppd.header_ip_offset;
					}
				}
				this->push(header, packet, ok_for_header_packet_stack, offset, NULL);
			} else {
				hpi hpii = this->prevThreads[0]->pop();
				if(!hpii.packet) {
					usleep(100);
					continue;
				}
				header = _header = hpii.header;
				packet = _packet = hpii.packet;
				ok_for_header_packet_stack = hpii.ok_for_header_packet_stack;
				res = this->pcapProcess(&header, &packet, &destroy,
							false, true, true, true);
				if(res == -1) {
					break;
				} else if(res == 0) {
					if(destroy) {
						if(header != _header) delete header;
						if(packet != _packet) delete [] packet;
					}
					sHeaderPacket headerPacket(_header, _packet);
					if(!(ok_for_header_packet_stack && this->readThread->headerPacketStack &&
					     this->readThread->headerPacketStack->add_hp(&headerPacket, 3))) {
						delete _header;
						delete [] _packet;
					}
					continue;
				}
				this->push(header, packet, ok_for_header_packet_stack, this->ppd.header_ip_offset, NULL);
			}
			}
			break;
		}
		if(destroy) {
			if(_header) delete _header;
			if(_packet) delete [] _packet;
		}
	}
	if(headerPacketRead.packet) {
		headerPacketRead.free();
	}
	if(libpcap_buffer_old && libpcap_buffer) {
		*libpcap_buffer = libpcap_buffer_old;
	}
	this->threadTerminated = true;
	return(NULL);
}

void PcapQueue_readFromInterfaceThread::preparePstatData() {
	if(this->threadId) {
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
	if(this->threadId) {
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

string PcapQueue_readFromInterfaceThread::getQringFillingPerc() {
	ostringstream outStr;
	outStr << fixed;
	for(int i = 0; i < 2; i++) {
		double perc = getQringFillingPerc(i);
		if(perc >= 0) {
			if(outStr.str().length()) {
				outStr << ",";
			}
			outStr << setprecision(0) << perc;
		}
	}
	return(outStr.str());
}

void PcapQueue_readFromInterfaceThread::terminate() {
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
	this->threadDoTerminate = true;
}


inline void *_PcapQueue_readFromInterfaceThread_threadFunction(void *arg) {
	return(((PcapQueue_readFromInterfaceThread*)arg)->threadFunction(arg, 0));
}


PcapQueue_readFromInterface::PcapQueue_readFromInterface(const char *nameQueue)
 : PcapQueue(readFromInterface, nameQueue) {
	this->fifoWritePcapDumper = NULL;
	memset(this->readThreads, 0, sizeof(this->readThreads));
	this->readThreadsCount = 0;
	this->lastTimeLogErrThread0BufferIsFull = 0;
	this->block_qring = NULL;
	if(opt_pcap_queue_iface_dedup_separate_threads_extend &&
	   !opt_pcap_queue_suppress_t1_thread) {
		this->setEnableWriteThread();
		extern int terminating;
		this->block_qring = new FILE_LINE rqueue_quick<pcap_block_store*>(
			100,
			100, 100,
			&terminating, true,
			__FILE__, __LINE__);
	}
}

PcapQueue_readFromInterface::~PcapQueue_readFromInterface() {
	pthread_join(this->threadHandle, NULL);
	if(this->writeThreadHandle) {
		pthread_join(this->writeThreadHandle, NULL);
	}
	if(this->block_qring) {
		pcap_block_store *blockStore;
		delete_packet_info dpi;
		while(this->block_qring->pop(&blockStore, false)) {
			for(size_t i = 0; i < blockStore->count; i++) {
				u_char *packetPos = blockStore->block + blockStore->offsets[i] + sizeof(pcap_pkthdr_plus);
				dpi = *(delete_packet_info*)packetPos;
				this->delete_header_packet(dpi.header, dpi.packet, dpi.read_thread_index, dpi.ok_for_header_packet_stack ? 1 : -1);
			}
		}
		delete this->block_qring;
	}
	if(this->fifoWritePcapDumper) {
		pcap_dump_close(this->fifoWritePcapDumper);
		syslog(LOG_NOTICE, "packetbuffer terminating: pcap_dump_close fifoWritePcapDumper (%s)", interfaceName.c_str());
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
	if(opt_pb_read_from_file[0] || 
	   opt_scanpcapdir[0] ||
	   !opt_pcap_queue_iface_separate_threads) {
		return(true);
	}
	vector<string> interfaces = split(this->interfaceName.c_str(), split(",|;| |\t|\r|\n", "|"), true);
	for(size_t i = 0; i < interfaces.size(); i++) {
		if(this->readThreadsCount < READ_THREADS_MAX - 1) {
			this->readThreads[this->readThreadsCount] = new FILE_LINE PcapQueue_readFromInterfaceThread(interfaces[i].c_str());
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
			syslog(LOG_NOTICE, outStr.str().c_str());
		}
	}
	string error;
	if(this->initThread(arg, arg2, &error)) {
		this->threadInitOk = true;
	} else {
		this->threadTerminated = true;
		this->threadInitFailed = true;
		if(opt_pcap_queue_receive_from_ip_port) {
			this->initAllReadThreadsFinished = true;
		} else {
			vm_terminate_error(error.c_str());
		}
		return(NULL);
	}
	this->initStat();
	pcap_pkthdr *header;
	u_char *packet;
	bool ok_for_header_packet_stack;
	int res;
	u_int offset = 0;
	u_int dlink = global_pcap_dlink;
	bool destroy = false;

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
			usleep(50000);
		}
		for(int i = 0; i < this->readThreadsCount; i++) {
			if(this->readThreads[i]->threadInitOk) {
				this->readThreads[i]->threadInitOk = 2;
			}
		}
	}
	this->initAllReadThreadsFinished = true;
	
	if(__config_BYPASS_FIFO) {
		int blockStoreCount = this->readThreadsCount ? this->readThreadsCount : 1;
		pcap_block_store *blockStore[blockStoreCount];
		for(int i = 0; i < blockStoreCount; i++) {
			blockStore[i] = new FILE_LINE pcap_block_store;
			strncpy(blockStore[i]->ifname, 
				this->readThreadsCount ? 
					this->readThreads[i]->getInterfaceName(true).c_str() :
					this->getInterfaceName(true).c_str(), 
				sizeof(blockStore[i]->ifname) - 1);
		}
		delete_packet_info dpi;
		while(!TERMINATING) {
			bool fetchPacketOk = false;
			int minThreadTimeIndex = -1;
			int blockStoreIndex = 0;
			u_char *packet_pcap = NULL;
			ok_for_header_packet_stack = false;
			unsigned int ip_tot_len = 0;
			if(this->readThreadsCount) {
				if(this->readThreadsCount == 1) {
					minThreadTimeIndex = 0;
				} else {
					u_int64_t minThreadTime = 0;
					u_int64_t threadTime = 0;
					for(int i = 0; i < this->readThreadsCount; i++) {
						threadTime = this->readThreads[i]->getTIME_usec();
						if(threadTime) {
							if(minThreadTime == 0 || minThreadTime > threadTime) {
								minThreadTimeIndex = i;
								minThreadTime = threadTime;
							}
						}
					}
				}
				if(minThreadTimeIndex < 0) {
					usleep(100);
				} else {
					PcapQueue_readFromInterfaceThread::hpi hpi = this->readThreads[minThreadTimeIndex]->POP();
					if(!hpi.packet) {
						usleep(100);
					} else {
						header = hpi.header;
						packet = hpi.packet;
						ok_for_header_packet_stack = hpi.ok_for_header_packet_stack;
						if(hpi.offset != (u_int)-1) {
							offset = hpi.offset;
						} else {
							::pcapProcess(&header, &packet, NULL,
								      false, false, false, false,
								      &ppd, this->readThreads[minThreadTimeIndex]->pcapLinklayerHeaderType, NULL, NULL);
							offset = ppd.header_ip_offset;
						}
						destroy = true;
						dlink = this->readThreads[minThreadTimeIndex]->pcapLinklayerHeaderType;
						blockStoreIndex = minThreadTimeIndex;
						fetchPacketOk = true;
					}
				}
			} else if(opt_scanpcapdir[0] && this->pcapEnd) {
				usleep(10000);
			} else {
				res = this->pcap_next_ex_iface(this->pcapHandle, &header, &packet);
				packet_pcap = packet;
				if(res > 0 && packet && header->caplen >= 14 + sizeof(iphdr2)) {
					ip_tot_len = ((iphdr2*)(packet + 14))->tot_len;
				}
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
						blockStore[blockStoreIndex] = NULL;
						int sleepTime = sverb.test_rtp_performance ? 120 :
								opt_enable_ssl ? 10 :
								sverb.chunk_buffer ? 20 : 5;
						while(sleepTime && !is_terminating()) {
							syslog(LOG_NOTICE, "time to terminating: %u", sleepTime);
							sleep(1);
							--sleepTime;
						}
						vm_terminate();
						break;
					}
				} else if(res == 0) {
					usleep(100);
				} else {
					fetchPacketOk = true;
					if(opt_scanpcapdir[0] &&
					   !blockStore[blockStoreIndex]->dlink && blockStore[blockStoreIndex]->dlink != this->pcapLinklayerHeaderType) {
						blockStore[blockStoreIndex]->dlink = this->pcapLinklayerHeaderType;
					}
					res = this->pcapProcess(&header, &packet, &destroy);
					if(res == -1) {
						break;
					} else if(res == 0) {
						if(destroy) {
							delete header;
							delete [] packet;
						}
						fetchPacketOk = false;
					}
					if(fetchPacketOk) {
						offset = this->ppd.header_ip_offset;
						if(ip_tot_len && ip_tot_len != ((iphdr2*)(packet_pcap + 14))->tot_len) {
							static u_long lastTimeLogErrBuggyKernel = 0;
							u_long actTime = getTimeMS(header);
							if(actTime - 1000 > lastTimeLogErrBuggyKernel) {
								syslog(LOG_ERR, "SUSPICIOUS CHANGE PACKET CONTENT: buggy kernel - contact support@voipmonitor.org");
								lastTimeLogErrBuggyKernel = actTime;
							}
						}
					}
				}
			}
			bool checkFullAllBlockStores = false;
			if(fetchPacketOk) {
				++sumPacketsCounterIn[0];
				extern SocketSimpleBufferWrite *sipSendSocket;
				if(sipSendSocket) {
					this->processBeforeAddToPacketBuffer(header, packet, offset);
				}
				if(!blockStore[blockStoreIndex]->full) {
					if(this->block_qring) {
						dpi.header = header;
						dpi.packet = packet;
						dpi.ok_for_header_packet_stack = ok_for_header_packet_stack;
						dpi.read_thread_index = minThreadTimeIndex;
						blockStore[blockStoreIndex]->add(header, (u_char*)&dpi, offset, dlink, sizeof(dpi));
						destroy = false;
					} else {
						blockStore[blockStoreIndex]->add(header, packet, offset, dlink);
					}
				}
			} else {
				for(int i = 0; i < blockStoreCount; i++) {
					blockStore[i]->isFull_checkTimout();
				}
				checkFullAllBlockStores = true;
			}
			for(int i = 0; i < blockStoreCount; i++) {
				if(blockStore[i]->full || 
				   (i != blockStoreIndex && !checkFullAllBlockStores && !(blockStore[i]->count % 20) && blockStore[i]->isFull_checkTimout())) {
					if(!opt_pcap_queue_compress && this->instancePcapFifo && opt_pcap_queue_suppress_t1_thread) {
						this->instancePcapFifo->addBlockStoreToPcapStoreQueue(blockStore[i]);
					} else if(this->block_qring) {
						this->block_qring->push(&blockStore[i], true);
					} else {
						this->check_bypass_buffer();
						blockStoreBypassQueue->push(blockStore[i]);
					}
					++sumBlocksCounterIn[0];
					blockStore[i] = new FILE_LINE pcap_block_store;
					strncpy(blockStore[i]->ifname, 
						this->readThreadsCount ? 
							this->readThreads[i]->getInterfaceName(true).c_str() :
							this->getInterfaceName(true).c_str(), 
						sizeof(blockStore[i]->ifname) - 1);
					if(fetchPacketOk && i == blockStoreIndex) {
						if(this->block_qring) {
							dpi.header = header;
							dpi.packet = packet;
							dpi.ok_for_header_packet_stack = ok_for_header_packet_stack;
							dpi.read_thread_index = minThreadTimeIndex;
							blockStore[blockStoreIndex]->add(header, (u_char*)&dpi, offset, dlink, sizeof(dpi));
							destroy = false;
						} else {
							blockStore[blockStoreIndex]->add(header, packet, offset, dlink);
						}
					}
				}
			}
			if(fetchPacketOk && destroy) {
				this->delete_header_packet(header, packet, minThreadTimeIndex, ok_for_header_packet_stack ? 0 : -1);
			}
		}
		for(int i = 0; i < blockStoreCount; i++) {
			if(blockStore[i]) {
				if(this->block_qring) {
					delete_packet_info dpi;
					for(size_t j = 0; j < blockStore[i]->count; j++) {
						u_char *packetPos = blockStore[i]->block + blockStore[i]->offsets[j] + sizeof(pcap_pkthdr_plus);
						dpi = *(delete_packet_info*)packetPos;
						this->delete_header_packet(dpi.header, dpi.packet, dpi.read_thread_index, dpi.ok_for_header_packet_stack ? 1 : -1);
					}
				}
				delete blockStore[i];
			}
		}
	} else {
		while(!TERMINATING) {
			res = this->pcap_next_ex_iface(this->pcapHandle, &header, &packet);
			if(res == -1) {
				break;
			} else if(res == 0) {
				continue;
			}
			res = this->pcapProcess(&header, &packet, &destroy);
			if(res == -1) {
				break;
			} else if(res == 0) {
				if(destroy) {
					delete header;
					delete [] packet;
				}
				continue;
			}
			if(__config_USE_PCAP_FOR_FIFO) {
				pcap_dump((u_char*)this->fifoWritePcapDumper, header, packet);
			} else {
				pcap_pkthdr_plus header_plus(*header, this->ppd.header_ip_offset, dlink);
				this->writePcapToFifo(&header_plus, packet);
			}
			if(destroy) {
				delete header;
				delete [] packet;
			}
		}
	}
	while(this->readThreadsCount) {
		while(!this->readThreads[this->readThreadsCount - 1]->isTerminated()) {
			usleep(100000);
		}
		delete this->readThreads[this->readThreadsCount - 1];
		--this->readThreadsCount;
	}
	this->threadTerminated = true;
	return(NULL);
}

void *PcapQueue_readFromInterface::writeThreadFunction(void *arg, unsigned int arg2) {
	this->writeThreadId = get_unix_tid();
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		outStr << "start thread t0 (" << this->nameQueue << " / write" << ") - pid: " << this->writeThreadId << endl;
		if(DEBUG_VERBOSE) {
			cout << outStr.str();
		} else {
			syslog(LOG_NOTICE, outStr.str().c_str());
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
		usleep(50000);
	}
	if(this->block_qring) {
		delete_packet_info dpi;
		while(!TERMINATING) {
			pcap_block_store *blockStore;
			if(this->block_qring->pop(&blockStore, false)) {
				for(size_t i = 0; i < blockStore->count; i++) {
					u_char *packetPos = blockStore->block + blockStore->offsets[i] + sizeof(pcap_pkthdr_plus);
					dpi = *(delete_packet_info*)packetPos;
					memcpy_heapsafe(packetPos, blockStore->block,
							dpi.packet, NULL,
							dpi.header->caplen,
							__FILE__, __LINE__);
					this->delete_header_packet(dpi.header, dpi.packet, dpi.read_thread_index, dpi.ok_for_header_packet_stack ? 1 : -1);
				}
				this->check_bypass_buffer();
				blockStoreBypassQueue->push(blockStore);
			} else {
				usleep(100);
			}
		}
	}
	return(NULL);
}

bool PcapQueue_readFromInterface::openFifoForWrite(void *arg, unsigned int arg2) {
	if(__config_BYPASS_FIFO) {
		return(true);
	}
	if(__config_USE_PCAP_FOR_FIFO) {
		struct stat st;
		if(stat(this->fifoFileForWrite.c_str(), &st) != 0) {
			mkfifo(this->fifoFileForWrite.c_str(), 0666);
		}
		if((this->fifoWritePcapDumper = pcap_dump_open(this->pcapHandle, this->fifoFileForWrite.c_str())) == NULL) {
			syslog(LOG_ERR, "packetbuffer %s: pcap_dump_open error: %s", this->nameQueue.c_str(), pcap_geterr(this->pcapHandle));
			return(false);
		} else {
			if(DEBUG_VERBOSE) {
				cout << this->nameQueue << " - pcap_dump_open: OK" << endl;
			}
			return(true);
		}
	} else {
		return(PcapQueue::openFifoForWrite(arg, arg2));
	}
}

bool PcapQueue_readFromInterface::startCapture(string *error) {
	*error = "";
	if(this->readThreadsCount) {
		return(true);
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	if(opt_scanpcapdir[0]) {
		this->pcapHandle = NULL;
		this->pcapLinklayerHeaderType = 0;
		global_pcap_handle = this->pcapHandle;
		global_pcap_dlink = this->pcapLinklayerHeaderType;
		return(true);
	} else if(opt_pb_read_from_file[0]) {
		this->pcapHandle = pcap_open_offline_zip(opt_pb_read_from_file, errbuf);
		if(!this->pcapHandle) {
			char errorstr[2048];
			sprintf(errorstr, "pcap_open_offline %s failed: %s", opt_pb_read_from_file, errbuf); 
			syslog(LOG_ERR, errorstr);
			*error = errorstr;
			return(false);
		}
		this->pcapLinklayerHeaderType = pcap_datalink(this->pcapHandle);
		global_pcap_handle = this->pcapHandle;
		global_pcap_dlink = this->pcapLinklayerHeaderType;
		return(true);
	}
	return(this->PcapQueue_readFromInterface_base::startCapture(error));
}

bool PcapQueue_readFromInterface::openPcap(const char *filename) {
	while(this->pcapHandlesLapsed.size() > 3) {
		pcap_close(this->pcapHandlesLapsed.front());
		this->pcapHandlesLapsed.pop();
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcapHandle = pcap_open_offline_zip(filename, errbuf);
	if(!pcapHandle) {
		syslog(LOG_ERR, "pcap_open_offline %s failed: %s", filename, errbuf); 
		return(false);
	}
	int pcapLinklayerHeaderType = pcap_datalink(pcapHandle);
	if(*user_filter != '\0') {
		if(this->filterDataUse) {
			pcap_freecode(&this->filterData);
			this->filterDataUse = false;
		}
		char filter_exp[2048] = "";
		snprintf(filter_exp, sizeof(filter_exp), "%s", user_filter);
		if (pcap_compile(pcapHandle, &this->filterData, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
			syslog(LOG_NOTICE, "packetbuffer - %s: can not parse filter %s: %s", filename, filter_exp, pcap_geterr(pcapHandle));
			return(false);
		}
		if (pcap_setfilter(pcapHandle, &this->filterData) == -1) {
			syslog(LOG_NOTICE, "packetbuffer - %s: can not install filter %s: %s", filename, filter_exp, pcap_geterr(pcapHandle));
			return(false);
		}
		this->filterDataUse = true;
	}
	if(this->pcapHandle) {
		this->pcapHandlesLapsed.push(this->pcapHandle);
	}
	global_pcap_dlink = pcapLinklayerHeaderType;
	global_pcap_handle = pcapHandle;
	this->pcapLinklayerHeaderType = pcapLinklayerHeaderType;
	this->pcapHandle = pcapHandle;
	this->pcapEnd = false;
	return(true);
}

string PcapQueue_readFromInterface::pcapStatString_bypass_buffer(int statPeriod) {
	ostringstream outStr;
	if(__config_BYPASS_FIFO) {
		outStr << fixed;
		uint64_t useSize = blockStoreBypassQueue->getUseSize();
		uint64_t useItems = blockStoreBypassQueue->getUseItems();
		outStr << "PACKETBUFFER_THREAD0_HEAP: "
		       << setw(6) << (useSize / 1024 / 1024) << "MB (" << setw(3) << useItems << ")"
		       << " " << setw(5) << setprecision(1) << (100. * useSize / opt_pcap_queue_bypass_max_size) << "%"
		       << " of " << setw(6) << (opt_pcap_queue_bypass_max_size / 1024 / 1024) << "MB"
		       << "   peak: " << (maxBypassBufferSize / 1024 / 1024) << "MB" << " (" << maxBypassBufferItems << ")" << " / size exceeded occurrence " << countBypassBufferSizeExceeded << endl;
	}
	return(outStr.str());
}

unsigned long PcapQueue_readFromInterface::pcapStat_get_bypass_buffer_size_exeeded() {
	return(countBypassBufferSizeExceeded);
}

string PcapQueue_readFromInterface::pcapStatString_interface(int statPeriod) {
	ostringstream outStr;
	if(this->readThreadsCount) {
		for(int i = 0; i < this->readThreadsCount; i++) {
			outStr << this->readThreads[i]->pcapStatString_interface(statPeriod);
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

string PcapQueue_readFromInterface::pcapStatString_cpuUsageReadThreads(double *sumMax) {
	ostringstream outStrStat;
	outStrStat << fixed;
	if(sumMax) {
		*sumMax  = 0;
	}
	for(int i = 0; i < this->readThreadsCount; i++) {
		if(this->readThreads[i]->threadInitFailed) {
			continue;
		}
		double sum = 0;
		double ti_cpu = this->readThreads[i]->getCpuUsagePerc(true);
		if(ti_cpu >= 0) {
			sum += ti_cpu;
			outStrStat << "t0i_" << this->readThreads[i]->interfaceName << "_CPU[" << setprecision(1) << ti_cpu;
			if(sverb.qring_stat) {
				string qringFillingPerc = this->readThreads[i]->getQringFillingPerc();
				if(qringFillingPerc.length()) {
					outStrStat << "r" << qringFillingPerc;
				}
			}
			if(this->readThreads[i]->defragThread) {
				double tid_cpu = this->readThreads[i]->defragThread->getCpuUsagePerc(true);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/" << setprecision(1) << tid_cpu;
					if(sverb.qring_stat) {
						string qringFillingPerc = this->readThreads[i]->defragThread->getQringFillingPerc();
						if(qringFillingPerc.length()) {
							outStrStat << "r" << qringFillingPerc;
						}
					}
				}
			}
			if(this->readThreads[i]->md1Thread) {
				double tid_cpu = this->readThreads[i]->md1Thread->getCpuUsagePerc(true);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/" << setprecision(1) << tid_cpu;
					if(sverb.qring_stat) {
						string qringFillingPerc = this->readThreads[i]->md1Thread->getQringFillingPerc();
						if(qringFillingPerc.length()) {
							outStrStat << "r" << qringFillingPerc;
						}
					}
				}
			}
			if(this->readThreads[i]->md2Thread) {
				double tid_cpu = this->readThreads[i]->md2Thread->getCpuUsagePerc(true);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/" << setprecision(1) << tid_cpu;
					if(sverb.qring_stat) {
						string qringFillingPerc = this->readThreads[i]->md2Thread->getQringFillingPerc();
						if(qringFillingPerc.length()) {
							outStrStat << "r" << qringFillingPerc;
						}
					}
				}
			}
			if(this->readThreads[i]->dedupThread) {
				double tid_cpu = this->readThreads[i]->dedupThread->getCpuUsagePerc(true);
				if(tid_cpu >= 0) {
					sum += tid_cpu;
					outStrStat << "%/" << setprecision(1) << tid_cpu;
					if(sverb.qring_stat) {
						string qringFillingPerc = this->readThreads[i]->dedupThread->getQringFillingPerc();
						if(qringFillingPerc.length()) {
							outStrStat << "r" << qringFillingPerc;
						}
					}
				}
			}
			outStrStat << "%] ";
			if(sumMax && sum > *sumMax) {
				*sumMax = sum;
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

void PcapQueue_readFromInterface::check_bypass_buffer() {
	size_t blockStoreBypassQueueSize;
	bool _syslog = true;
	while(!TERMINATING && (blockStoreBypassQueueSize = blockStoreBypassQueue->getUseSize()) > opt_pcap_queue_bypass_max_size) {
		if(opt_scanpcapdir[0]) {
			usleep(100);
		} else {
			if(_syslog) {
				u_long actTime = getTimeMS();
				if(actTime - 1000 > this->lastTimeLogErrThread0BufferIsFull) {
					syslog(LOG_ERR, "packetbuffer %s: THREAD0 BUFFER IS FULL", this->nameQueue.c_str());
					this->lastTimeLogErrThread0BufferIsFull = actTime;
					cout << "bypass buffer size " << blockStoreBypassQueue->getUseItems() << " (" << blockStoreBypassQueue->getUseSize() << ")" << endl;
				}
				_syslog = false;
				++countBypassBufferSizeExceeded;
			}
			usleep(100);
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

void PcapQueue_readFromInterface::delete_header_packet(pcap_pkthdr *header, u_char *packet, int read_thread_index, int packet_stack_index) {
	sHeaderPacket headerPacket(header, packet);
	if(!(!TERMINATING &&
	     packet_stack_index >=0 &&
	     this->readThreadsCount && 
	     this->readThreads[read_thread_index]->headerPacketStack &&
	     this->readThreads[read_thread_index]->headerPacketStack->add_hp(&headerPacket, packet_stack_index))) {
		delete header;
		delete [] packet;
	}
}


PcapQueue_readFromFifo::PcapQueue_readFromFifo(const char *nameQueue, const char *fileStoreFolder) 
 : PcapQueue(readFromFifo, nameQueue),
   pcapStoreQueue(fileStoreFolder) {
	this->packetServerDirection = directionNA;
	this->fifoReadPcapHandle = NULL;
	for(int i = 0; i < DLT_TYPES_MAX; i++) {
		this->pcapDeadHandles[i] = NULL;
		this->pcapDeadHandles_dlt[i] = 0;
	}
	this->pcapDeadHandles_count = 0;
	this->socketServerThreadHandle = 0;
	this->cleanupBlockStoreTrash_counter = 0;
	this->socketHostEnt = NULL;
	this->socketHandle = 0;
	this->badTimeCounter = 0;
	this->_sync_packetServerConnections = 0;
	this->lastCheckFreeSizeCachedir_timeMS = 0;
	this->_last_ts.tv_sec = 0;
	this->_last_ts.tv_usec = 0;
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
	if(this->fifoReadPcapHandle) {
		pcap_close(this->fifoReadPcapHandle);
		syslog(LOG_NOTICE, "packetbuffer terminating (%s): pcap_close fifoReadPcapHandle", nameQueue.c_str());
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

inline void PcapQueue_readFromFifo::addBlockStoreToPcapStoreQueue(pcap_block_store *blockStore) {
	while(!TERMINATING) {
		if(this->pcapStoreQueue.push(blockStore, false)) {
			sumPacketsSize[0] += blockStore->size;
			break;
		} else {
			usleep(100);
		}
	}
}

bool PcapQueue_readFromFifo::createThread() {
	PcapQueue::createThread();
	if(this->packetServerDirection == directionRead) {
		this->createSocketServerThread();
	}
	return(true);
}

bool PcapQueue_readFromFifo::createSocketServerThread() {
	pthread_create(&this->socketServerThreadHandle, NULL, _PcapQueue_readFromFifo_socketServerThreadFunction, this);
	return(true);
}

bool PcapQueue_readFromFifo::initThread(void *arg, unsigned int arg2, string *error) {
	if(this->packetServerDirection == directionRead &&
	   !this->openPcapDeadHandle(0)) {
		return(false);
	}
	return(PcapQueue::initThread(arg, arg2, error));
}

void *PcapQueue_readFromFifo::threadFunction(void *arg, unsigned int arg2) {
	int pid = get_unix_tid();
	if(this->packetServerDirection == directionRead && arg2) {
		if(arg2 == (unsigned int)-1) {
			this->nextThreadsId[0] = get_unix_tid();
		} else {
			this->packetServerConnections[arg2]->threadId = pid;
			this->packetServerConnections[arg2]->active = true;
		}
	} else {
		this->mainThreadId = get_unix_tid();
	}
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		outStr << "start thread t1 (" << this->nameQueue;
		if(this->packetServerDirection == directionRead && arg2) {
			if(arg2 == (unsigned int)-1) {
				outStr << " socket server";
			} else {
				outStr << " " << this->packetServerConnections[arg2]->socketClientIP << ":" << this->packetServerConnections[arg2]->socketClientInfo.sin_port;
			}
		}
		outStr << ") - pid: " << pid << endl;
		if(DEBUG_VERBOSE) {
			cout << outStr.str();
		} else {
			syslog(LOG_NOTICE, outStr.str().c_str());
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
		pcap_block_store *blockStore = new FILE_LINE pcap_block_store;
		size_t bufferSize = 1000;
		u_char *buffer = new FILE_LINE u_char[bufferSize * 2];
		size_t bufferLen;
		size_t offsetBufferSyncRead;
		size_t offsetBuffer;
		size_t readLen;
		bool beginBlock = false;
		bool endBlock = false;
		bool syncBeginBlock = true;
		int _countTestSync = 0;
		bool forceStop = false;
		while(!TERMINATING && !forceStop) {
			if(arg2 == (unsigned int)-1) {
				int socketClient;
				sockaddr_in socketClientInfo;
				if(this->socketAwaitConnection(&socketClient, &socketClientInfo)) {
					if(!TERMINATING && !forceStop) {
						syslog(LOG_NOTICE, "accept new connection from %s:%i", inet_ntoa(socketClientInfo.sin_addr), socketClientInfo.sin_port);
						this->createConnection(socketClient, &socketClientInfo);
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
				while(!TERMINATING && !forceStop) {
					readLen = bufferSize;
					if(!this->socketRead(buffer + offsetBufferSyncRead, &readLen, arg2)) {
						syslog(LOG_NOTICE, "close connection from %s:%i", this->packetServerConnections[arg2]->socketClientIP.c_str(), this->packetServerConnections[arg2]->socketClientInfo.sin_port);
						this->packetServerConnections[arg2]->active = false;
						forceStop = true;
						break;
					}
					if(readLen) {
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
									       (pointToSensorIdName[offset] >= ' ' && pointToSensorIdName[offset] < 128))) {
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
									       (pointToSensorTime[offset] >= ' ' && pointToSensorTime[offset] < 128))) {
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
										if(abs(actualTimeSec % 3600 - sensorTimeSec % 3600) > 2) {
											syslog(LOG_ERR, "sensor is not allowed to connect because of different time between receiver (%s) and sensor %i (%s) - please synchronize clocks on both server ",
											       sqlDateTimeString(actualTimeSec).c_str(),
											       sensorId,
											       sensorTime.c_str());
											string message = "bad time";
											send(this->packetServerConnections[arg2]->socketClient, message.c_str(), message.length(), 0);
											close(this->packetServerConnections[arg2]->socketClient);
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
									u_char *buffer2 = new FILE_LINE u_char[bufferSize * 2];
									memcpy_heapsafe(buffer2, buffer2,
											pointToBeginBlock, buffer,
											bufferLen - (pointToBeginBlock - buffer),
											__FILE__, __LINE__);
									bufferLen -= (pointToBeginBlock - buffer);
									delete [] buffer;
									buffer = buffer2;
								}
								syncBeginBlock = false;
								beginBlock = true;
								blockStore->destroyRestoreBuffer();
								if(DEBUG_VERBOSE) {
									cout << "SYNCED" << endl;
								}
							} else {
								if(offsetBufferSyncRead) {
									u_char *buffer2 = new FILE_LINE u_char[bufferSize * 2];
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
						if(DEBUG_SYNC && !(++_countTestSync % 1000)) {
							cout << "SYNC!" << endl;
							syncBeginBlock = true;
						} else {
							offsetBuffer = 0;
							while(offsetBuffer < bufferLen) {
								if(blockStore->addRestoreChunk(buffer, bufferLen, &offsetBuffer)) {
									endBlock = true;
									if(blockStore->check_offsets()) {
										while(!this->pcapStoreQueue.push(blockStore, false)) {
											if(TERMINATING || forceStop) {
												break;
											} else {
												usleep(1000);
											}
										}
										sumPacketsCounterIn[0] += blockStore->count;
										sumPacketsSize[0] += blockStore->size;
										sumPacketsSizeCompress[0] += blockStore->size_compress;
										++sumBlocksCounterIn[0];
									} else {
										delete blockStore;
										syslog(LOG_ERR, "receive bad packetbuffer block in conection %s - %i",
										       this->packetServerConnections[arg2]->socketClientIP.c_str(), 
										       this->packetServerConnections[arg2]->socketClientInfo.sin_port);
									}
									blockStore = new FILE_LINE pcap_block_store;
								} else {
									offsetBuffer = bufferLen;
								}
							}
						}
						if(!beginBlock && !endBlock && !syncBeginBlock) {
							u_char *pointToBeginBlock = (u_char*)memmem(buffer, bufferLen, PCAP_BLOCK_STORE_HEADER_STRING, PCAP_BLOCK_STORE_HEADER_STRING_LEN);
							if(pointToBeginBlock && pointToBeginBlock != buffer) {
								syncBeginBlock = true;
								if(DEBUG_VERBOSE) {
									cout << "SYNC!!!" << endl;
								}
							}
						}
						bufferLen = 0;
						offsetBufferSyncRead = 0;
						beginBlock = false;
						endBlock = false;
					}
				}
			}
		}
		delete [] buffer;
		delete blockStore;
		
	} else if(__config_BYPASS_FIFO) {
		if(opt_pcap_queue_compress || !opt_pcap_queue_suppress_t1_thread) {
			pcap_block_store *blockStore;
			while(!TERMINATING) {
				blockStore = blockStoreBypassQueue->pop(false);
				if(!blockStore) {
					usleep(1000);
					continue;
				}
				size_t blockSize = blockStore->size;
				if(blockStore->compress()) {
					if(this->pcapStoreQueue.push(blockStore, false)) {
						sumPacketsSize[0] += blockSize;
						blockStoreBypassQueue->pop(true, blockSize);
					} else {
						usleep(1000);
					}
				} else {
					blockStoreBypassQueue->pop(true, blockSize);
				}
			}
		}
	} else {
		pcap_pkthdr_plus header;
		u_char *packet;
		int res;
		pcap_block_store *blockStore = new FILE_LINE pcap_block_store;
		while(!TERMINATING) {
			if(__config_USE_PCAP_FOR_FIFO) {
				pcap_pkthdr *_header;
				res = this->pcap_next_ex_queue(this->fifoReadPcapHandle, &_header, &packet);
				header = pcap_pkthdr_plus(*_header, -1, global_pcap_dlink);
			} else {
				res = this->readPcapFromFifo(&header, &packet, true);
			}
			if(res == -1) {
				break;
			} else if(res == 0) {
				continue;
			}
			++sumPacketsCounterIn[0];
			pcap_pkthdr *header_std = header.convertToStdHeader();
			this->processBeforeAddToPacketBuffer(header_std, packet, header.offset);
			blockStore->add(header_std, packet, header.offset, header.dlink);
			if(blockStore->full) {
				sumPacketsSize[0] += blockStore->size;
				if(blockStore->compress() && 
				   this->pcapStoreQueue.push(blockStore)) {
					++sumBlocksCounterIn[0];
					blockStore = new FILE_LINE pcap_block_store;
					blockStore->add(&header, packet);
				}
			}
		}
		delete blockStore;
	}
	this->threadTerminated = true;
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
			syslog(LOG_NOTICE, outStr.str().c_str());
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
	int blockInfoCountMax = 100;
	u_int64_t blockInfo_utime_first = 0;
	u_int64_t blockInfo_utime_last = 0;
	u_int64_t blockInfo_at_first = 0;
	u_int64_t blockInfo_at_last = 0;
	sBlockInfo blockInfo[blockInfoCountMax];
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
		if(this->packetServerDirection == directionWrite) {
			if(blockStore) {
				this->socketWritePcapBlock(blockStore);
				this->blockStoreTrash.push_back(blockStore);
				buffersControl.add__PcapQueue_readFromFifo__blockStoreTrash_size(blockStore->getUseSize());
			}
		} else {
			if(blockStore) {
				if(blockStore->size_compress && !blockStore->uncompress()) {
					delete blockStore;
					blockStore = NULL;
				} else {
					buffersControl.add__PcapQueue_readFromFifo__blockStoreTrash_size(blockStore->getUseSize());
				}
			}
			if(opt_pcap_queue_dequeu_window_length > 0 &&
			   (opt_pcap_queue_dequeu_method == 1 || opt_pcap_queue_dequeu_method == 2) &&
			   (!opt_pb_read_from_file[0])) {
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
							pti.utime = pti.header->header_fix_size.ts_tv_sec * 1000000ull + pti.header->header_fix_size.ts_tv_usec;
							pti.at = at;
							map<u_int64_t, list<sPacketTimeInfo>* >::iterator iter = listPacketTimeInfo.find(pti.utime);
							if(iter != listPacketTimeInfo.end()) {
								iter->second->push_back(pti);
							} else {
								list<sPacketTimeInfo> *newList = new FILE_LINE list<sPacketTimeInfo>;
								newList->push_back(pti);
								listPacketTimeInfo[pti.utime] = newList;
							}
						}
					}
					map<u_int64_t, list<sPacketTimeInfo>* >::iterator first = listPacketTimeInfo.begin();
					map<u_int64_t, list<sPacketTimeInfo>* >::iterator last = listPacketTimeInfo.end();
					--last;
					while(listPacketTimeInfo.size() && !TERMINATING) {
						if(last->first - first->first > (unsigned)opt_pcap_queue_dequeu_window_length * 1000 && 
						   at - first->second->begin()->at > (unsigned)opt_pcap_queue_dequeu_window_length * 1000) {
							sPacketTimeInfo pti = *(first->second->begin());
							first->second->pop_front();
							++sumPacketsCounterOut[0];
							this->processPacket(
								pti.header, pti.packet, 
								pti.blockStore, pti.blockStoreIndex,
								pti.header->dlink ? 
									pti.header->dlink : 
									pti.blockStore->dlink, 
								pti.blockStore->sensor_id);
							++listBlockStore[pti.blockStore];
							if(listBlockStore[pti.blockStore] == pti.blockStore->count) {
								this->blockStoreTrash.push_back(pti.blockStore);
								listBlockStore.erase(pti.blockStore);
							}
							if(first->second->empty()) {
								delete first->second;
								listPacketTimeInfo.erase(first);
								first = listPacketTimeInfo.begin();
							}
						} else {
							break;
						}
					}
				} else {
					u_int64_t at = getTimeUS();
					if(blockStore) {
						blockInfo[blockInfoCount].blockStore = blockStore;
						blockInfo[blockInfoCount].count_processed = 0;
						blockInfo[blockInfoCount].utime_first = (*blockStore)[0].header->header_fix_size.ts_tv_sec * 1000000ull +
											(*blockStore)[0].header->header_fix_size.ts_tv_usec;
						blockInfo[blockInfoCount].utime_last = (*blockStore)[blockStore->count - 1].header->header_fix_size.ts_tv_sec * 1000000ull +
										       (*blockStore)[blockStore->count - 1].header->header_fix_size.ts_tv_usec;
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
					      ((blockInfo_utime_last - blockInfo_utime_first > (unsigned)opt_pcap_queue_dequeu_window_length * 1000 &&
						blockInfo_at_last - blockInfo_at_first > (unsigned)opt_pcap_queue_dequeu_window_length * 1000) ||
					       at - blockInfo_at_first > (unsigned)opt_pcap_queue_dequeu_window_length * 1000 * 4 ||
					       buffersControl.getPercUsePBtrash() > 50 ||
					       blockInfoCount == blockInfoCountMax) &&
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
						this->processPacket(
							(*actBlockInfo->blockStore)[actBlockInfo->count_processed].header,
							(*actBlockInfo->blockStore)[actBlockInfo->count_processed].packet,
							actBlockInfo->blockStore,
							actBlockInfo->count_processed,
							(*actBlockInfo->blockStore)[actBlockInfo->count_processed].header->dlink ? 
								(*actBlockInfo->blockStore)[actBlockInfo->count_processed].header->dlink :
								actBlockInfo->blockStore->dlink,
							actBlockInfo->blockStore->sensor_id);
						++actBlockInfo->count_processed;
						if(actBlockInfo->count_processed == actBlockInfo->blockStore->count) {
							this->blockStoreTrash.push_back(actBlockInfo->blockStore);
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
							actBlockInfo->utime_first = (*actBlockInfo->blockStore)[actBlockInfo->count_processed].header->header_fix_size.ts_tv_sec * 1000000ull +
										    (*actBlockInfo->blockStore)[actBlockInfo->count_processed].header->header_fix_size.ts_tv_usec;
							blockInfo_utime_first = minUtime;
						}
					}
				}
			} else {
				if(blockStore) {
					for(size_t i = 0; i < blockStore->count && !TERMINATING; i++) {
						++sumPacketsCounterOut[0];
						this->processPacket(
							(*blockStore)[i].header, 
							(*blockStore)[i].packet, 
							blockStore, 
							i,
							(*blockStore)[i].header->dlink ? 
								(*blockStore)[i].header->dlink :
								blockStore->dlink, 
							blockStore->sensor_id);
					}
					this->blockStoreTrash.push_back(blockStore);
				}
			}
		}
		if(!blockStore) {
			usleep(1000);
		}
		if(!(++this->cleanupBlockStoreTrash_counter % 10)) {
			this->cleanupBlockStoreTrash();
		}
	}
	if(opt_pcap_queue_dequeu_method == 1) {
		map<pcap_block_store*, size_t>::iterator iter;
		for(iter = listBlockStore.begin(); iter != listBlockStore.end(); iter++) {
			this->blockStoreTrash.push_back(iter->first);
		}
		while(listPacketTimeInfo.size()) {
			delete listPacketTimeInfo.begin()->second;
			listPacketTimeInfo.erase(listPacketTimeInfo.begin()->first);
		}
	} else if(opt_pcap_queue_dequeu_method == 2) {
		for(int i = 0; i < blockInfoCount; i++) {
			this->blockStoreTrash.push_back(blockInfo[i].blockStore);
		}
	}
	this->writeThreadTerminated = true;
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
		if(__config_BYPASS_FIFO) {
			return(true);
		}
		if(__config_USE_PCAP_FOR_FIFO) {
			char errbuf[PCAP_ERRBUF_SIZE];
			struct stat st;
			if(stat(this->fifoFileForRead.c_str(), &st) != 0) {
				mkfifo(this->fifoFileForRead.c_str(), 0666);
			}
			if((this->fifoReadPcapHandle = pcap_open_offline(this->fifoFileForRead.c_str(), errbuf)) == NULL) {
				syslog(LOG_ERR, "packetbuffer %s: pcap_open_offline error: %s", this->nameQueue.c_str(), errbuf);
				return(false);
			} else {
				if(DEBUG_VERBOSE) {
					cout << this->nameQueue << " - pcap_open_offline: OK" << endl;
				}
				return(true);
			}
		} else {
			return(PcapQueue::openFifoForRead(arg, arg2));
		}
	}
	return(false);
}

bool PcapQueue_readFromFifo::openFifoForWrite(void *arg, unsigned int arg2) {
	if(this->packetServerDirection == directionWrite) {
		return(this->socketGetHost() &&
		       this->socketConnect());
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
	}
	return(true);
}

string PcapQueue_readFromFifo::pcapStatString_memory_buffer(int statPeriod) {
	ostringstream outStr;
	if(__config_BYPASS_FIFO) {
		outStr << fixed;
		uint64_t useSize = buffersControl.get__pcap_store_queue__sizeOfBlocksInMemory() + buffersControl.get__PcapQueue_readFromFifo__blockStoreTrash_size();
		outStr << "PACKETBUFFER_TOTAL_HEAP:   "
		       << setw(6) << (useSize / 1024 / 1024) << "MB" << setw(6) << ""
		       << " " << setw(5) << setprecision(1) << (100. * useSize / opt_pcap_queue_store_queue_max_memory_size) << "%"
		       << " of " << setw(6) << (opt_pcap_queue_store_queue_max_memory_size / 1024 / 1024) << "MB" << endl;
		outStr << "PACKETBUFFER_TRASH_HEAP:   "
		       << setw(6) << (buffersControl.get__PcapQueue_readFromFifo__blockStoreTrash_size() / 1024 / 1024) << "MB" << endl;
	}
	return(outStr.str());
}

string PcapQueue_readFromFifo::pcapStatString_disk_buffer(int statPeriod) {
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
	if(!this->socketHandle) {
		return(false);
	}
	size_t sizeSaveBuffer = blockStore->getSizeSaveBuffer();
	u_char *saveBuffer = blockStore->getSaveBuffer();
	bool rslt = this->socketWrite(saveBuffer, sizeSaveBuffer);
	delete [] saveBuffer;
	return(rslt);
}

bool PcapQueue_readFromFifo::socketGetHost() {
	this->socketHostEnt = NULL;
	while(!this->socketHostEnt) {
		this->socketHostEnt = gethostbyname(this->packetServerIpPort.get_ip().c_str());
		if(!this->socketHostEnt) {
			syslog(LOG_ERR, "packetbuffer %s: cannot resolv: %s: host [%s] - trying again", this->nameQueue.c_str(), hstrerror(h_errno), this->packetServerIpPort.get_ip().c_str());  
			sleep(1);
		}
	}
	if(DEBUG_VERBOSE) {
		cout << "socketGetHost [" << this->packetServerIpPort.get_ip() << "] : OK" << endl;
	}
	return(true);
}

bool PcapQueue_readFromFifo::socketConnect() {
	if(!this->socketHostEnt) {
		this->socketGetHost();
	}
	if((this->socketHandle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		syslog(LOG_NOTICE, "packetbuffer %s: cannot create socket", this->nameQueue.c_str());
		return(false);
	}
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(this->packetServerIpPort.get_port());
	addr.sin_addr.s_addr = *(long*)this->socketHostEnt->h_addr_list[0];
	while(connect(this->socketHandle, (struct sockaddr *)&addr, sizeof(addr)) == -1 && !TERMINATING) {
		syslog(LOG_NOTICE, "packetbuffer %s: failed to connect to server [%s] error:[%s] - trying again", this->nameQueue.c_str(), inet_ntoa(*(struct in_addr *)this->socketHostEnt->h_addr_list[0]), strerror(errno));
		sleep(1);
	}
	if(TERMINATING) {
		return(false);
	}
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
	socketWrite((u_char*)dataSensorIdName, strlen(dataSensorIdName) + 1);
	char dataTime[40];
	snprintf(dataTime, sizeof(dataTime), "sensor_time: %s", sqlDateTimeString(time(NULL)).c_str());
	socketWrite((u_char*)dataTime, strlen(dataTime) + 1);
	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(this->socketHandle, &rfds);
	struct timeval tv;
	tv.tv_sec = 4;
	tv.tv_usec = 0;
	if(select(this->socketHandle + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv) > 0) {
		char recv_data[100] = "";
		size_t recv_data_len = recv(this->socketHandle, recv_data, sizeof(recv_data), 0);
		if(recv_data_len > 0 && recv_data_len <= sizeof(recv_data) && 
		   memmem(recv_data, recv_data_len,  "bad time", 8)) {
			++this->badTimeCounter;
			string error = "different time between receiver and sender";
			if(this->badTimeCounter > 4) {
				syslog(LOG_ERR, "%s - terminating", error.c_str());
				vm_terminate_error("bad time");
			} else {
				syslog(LOG_ERR, "%s - check %i", error.c_str(), this->badTimeCounter);
			}
		} else {
			this->badTimeCounter = 0;
		}
	} else {
		this->badTimeCounter = 0;
	}
	return(true);
}

bool PcapQueue_readFromFifo::socketListen() {
	if((this->socketHandle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		syslog(LOG_NOTICE, "packetbuffer %s: cannot create socket", this->nameQueue.c_str());
		return(false);
	}
	if(opt_pcap_queues_mirror_nonblock_mode) {
		int flags = fcntl(this->socketHandle, F_GETFL, 0);
		if(flags >= 0) {
			fcntl(this->socketHandle, F_SETFL, flags | O_NONBLOCK);
		}
	}
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(this->packetServerIpPort.get_port());
	addr.sin_addr.s_addr = inet_addr(this->packetServerIpPort.get_ip().c_str());
	int on = 1;
	setsockopt(this->socketHandle, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	int rsltListen;
	do {
		while(bind(this->socketHandle, (sockaddr*)&addr, sizeof(addr)) == -1 && !TERMINATING) {
			syslog(LOG_ERR, "packetbuffer %s: cannot bind to port [%d] - trying again after 5 seconds intervals", this->nameQueue.c_str(), this->packetServerIpPort.get_port());
			sleep(5);
		}
		if(TERMINATING) {
			return(false);
		}
		rsltListen = listen(this->socketHandle, 5);
		if(rsltListen == -1) {
			syslog(LOG_ERR, "packetbuffer %s: listen failed - retrying in 5 seconds intervals", this->nameQueue.c_str());
			sleep(5);
		}
	} while(rsltListen == -1);
	return(true);
}

bool PcapQueue_readFromFifo::socketAwaitConnection(int *socketClient, sockaddr_in *socketClientInfo) {
	*socketClient = -1;
	socklen_t addrlen = sizeof(sockaddr_in);
	while(*socketClient < 0 && !TERMINATING) {
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(this->socketHandle, &rfds);
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		if(select(this->socketHandle + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv) > 0) {
			*socketClient = accept(this->socketHandle, (sockaddr*)socketClientInfo, &addrlen);
			if(opt_pcap_queues_mirror_nonblock_mode) {
				int flags = fcntl(*socketClient, F_GETFL, 0);
				if(flags >= 0) {
					fcntl(*socketClient, F_SETFL, flags | O_NONBLOCK);
				}
			}
		}
		usleep(100000);
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

bool PcapQueue_readFromFifo::socketWrite(u_char *data, size_t dataLen) {
	size_t dataLenWrited = 0;
	while(dataLenWrited < dataLen && !TERMINATING) {
		ssize_t _dataLenWrited = send(this->socketHandle, data + dataLenWrited, dataLen - dataLenWrited, 0);
		if(_dataLenWrited == -1) {
			this->socketConnect();
		} else {
			dataLenWrited += _dataLenWrited;
		}
	}
	return(true);
}

bool PcapQueue_readFromFifo::socketRead(u_char *data, size_t *dataLen, int idConnection) {
	size_t maxDataLen = *dataLen;
	*dataLen = 0;
	if(opt_pcap_queues_mirror_nonblock_mode) {
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(this->packetServerConnections[idConnection]->socketClient, &rfds);
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		int rsltSelect = select(this->packetServerConnections[idConnection]->socketClient + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv);
		if(rsltSelect < 0) {
			return(false);
		}
		if(rsltSelect > 0 && FD_ISSET(this->packetServerConnections[idConnection]->socketClient, &rfds)) {
			ssize_t recvLen = recv(this->packetServerConnections[idConnection]->socketClient, data, maxDataLen, 0);
			if(recvLen <= 0) {
				return(false);
			}
			*dataLen = recvLen;
		}
	} else {
		ssize_t recvLen = recv(this->packetServerConnections[idConnection]->socketClient, data, maxDataLen, 0);
		if(recvLen <= 0) {
			return(false);
		}
		*dataLen = recvLen;
	}
	return(true);
}

void PcapQueue_readFromFifo::createConnection(int socketClient, sockaddr_in *socketClientInfo) {
	this->cleanupConnections();
	this->lock_packetServerConnections();
	unsigned int id = 1;
	map<unsigned int, sPacketServerConnection*>::iterator iter;
	for(iter = this->packetServerConnections.begin(); iter != this->packetServerConnections.end(); ++iter) {
		if(iter->first >= id) {
			id = iter->first + 1; 
		}
	}
	sPacketServerConnection *connection = new FILE_LINE sPacketServerConnection(socketClient, *socketClientInfo, this, id);
	connection->socketClientIP = inet_ntoa(socketClientInfo->sin_addr);
	connection->active = true;
	this->packetServerConnections[id] = connection;
	this->unlock_packetServerConnections();
	pthread_create(&connection->threadHandle, NULL, _PcapQueue_readFromFifo_connectionThreadFunction, connection);
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

void PcapQueue_readFromFifo::processPacket(pcap_pkthdr_plus *header_plus, u_char *packet,
					   pcap_block_store *block_store, int block_store_index,
					   int dlt, int sensor_id) {
	iphdr2 *header_ip;
	tcphdr2 *header_tcp;
	udphdr2 *header_udp;
	udphdr2 header_udp_tmp;
	char *data = NULL;
	int datalen = 0;
	int istcp = 0;
	bool useTcpReassemblyHttp = false;
	bool useTcpReassemblyWebrtc = false;
	bool useTcpReassemblySsl = false;
	static u_int64_t packet_counter_all;
	
	extern int opt_blockprocesspacket;
	if(opt_blockprocesspacket) {
		return;
	}
	
	++packet_counter_all;
	
	pcap_pkthdr *header = header_plus->convertToStdHeader();
	
	if(header->caplen > header->len) {
		extern BogusDumper *bogusDumper;
		if(bogusDumper) {
			bogusDumper->dump(header, packet, dlt, "process_packet");
		}
		if(verbosity) {
			static u_long lastTimeSyslog = 0;
			u_long actTime = getTimeMS();
			if(actTime - 1000 > lastTimeSyslog) {
				syslog(LOG_NOTICE, "warning - incorrect caplen/len (%u/%u) in processPacket", header->caplen, header->len);
				lastTimeSyslog = actTime;
			}
		}
		return;
	}
	
	if(!this->_last_ts.tv_sec) {
		this->_last_ts = header->ts;
	} else if(this->_last_ts.tv_sec * 1000000ull + this->_last_ts.tv_usec > header->ts.tv_sec * 1000000ull + header->ts.tv_usec + 1000) {
		if(verbosity > 1 || enable_bad_packet_order_warning) {
			static u_long lastTimeSyslog = 0;
			u_long actTime = getTimeMS();
			if(actTime - 1000 > lastTimeSyslog) {
				syslog(LOG_NOTICE, "warning - bad packet order (%llu us) in processPacket", 
				       this->_last_ts.tv_sec * 1000000ull + this->_last_ts.tv_usec - header->ts.tv_sec * 1000000ull - header->ts.tv_usec);
				lastTimeSyslog = actTime;
			}
		}
	} else {
		this->_last_ts = header->ts;
	}
	
	if(header_plus->offset < 0) {
		//// doplnit zjištění offsetu
	}
	
	header_ip = (iphdr2*)(packet + header_plus->offset);

	bool nextPass;
	do {
		nextPass = false;
		if(header_ip->protocol == IPPROTO_IPIP) {
			// ip in ip protocol
			header_ip = (iphdr2*)((char*)header_ip + sizeof(iphdr2));
		} else if(header_ip->protocol == IPPROTO_GRE) {
			// gre protocol
			header_ip = convertHeaderIP_GRE(header_ip);
			if(header_ip) {
				nextPass = true;
			} else {
				if(opt_ipaccount) {
					ipaccount(header->ts.tv_sec, (iphdr2*) ((char*)(packet) + header_plus->offset), header->len - header_plus->offset, false);
				}
				return;
			}
		}
	} while(nextPass);

	header_udp = &header_udp_tmp;
	if (header_ip->protocol == IPPROTO_UDP) {
		// prepare packet pointers 
		header_udp = (udphdr2*) ((char *) header_ip + sizeof(*header_ip));
		data = (char *) header_udp + sizeof(*header_udp);
		datalen = (int)(header->caplen - ((u_char*)data - packet));
		istcp = 0;
	} else if (header_ip->protocol == IPPROTO_TCP) {
		header_tcp = (tcphdr2*) ((char *) header_ip + sizeof(*header_ip));
		istcp = 1;
		// prepare packet pointers 
		data = (char *) header_tcp + (header_tcp->doff * 4);
		datalen = (int)(header->caplen - ((u_char*)data - packet)); 
		header_udp->source = header_tcp->source;
		header_udp->dest = header_tcp->dest;
	} else {
		//packet is not UDP and is not TCP, we are not interested, go to the next packet
		// - interested only for ipaccount
		if(opt_ipaccount) {
			ipaccount(header->ts.tv_sec, (iphdr2*) ((char*)(packet) + header_plus->offset), header->len - header_plus->offset, false);
		}
		return;
	}
	
	if((data - (char*)packet) > header->caplen) {
		extern BogusDumper *bogusDumper;
		if(bogusDumper) {
			bogusDumper->dump(header, packet, dlt, "process_packet");
		}
		if(verbosity) {
			static u_long lastTimeSyslog = 0;
			u_long actTime = getTimeMS();
			if(actTime - 1000 > lastTimeSyslog) {
				syslog(LOG_NOTICE, "warning - incorrect dataoffset/caplen (%li/%u) in processPacket", data - (char*)packet, header->caplen);
				lastTimeSyslog = actTime;
			}
		}
		return;
	}

	if(header_ip->protocol == IPPROTO_TCP) {
		if(opt_enable_http && (httpportmatrix[htons(header_tcp->source)] || httpportmatrix[htons(header_tcp->dest)])) {
			tcpReassemblyHttp->push(header, header_ip, packet,
						block_store, block_store_index,
						this->getPcapHandle(dlt), dlt, sensor_id);
			useTcpReassemblyHttp = true;
		} else if(opt_enable_webrtc && (webrtcportmatrix[htons(header_tcp->source)] || webrtcportmatrix[htons(header_tcp->dest)])) {
			tcpReassemblyWebrtc->push(header, header_ip, packet,
						  block_store, block_store_index,
						  this->getPcapHandle(dlt), dlt, sensor_id);
			useTcpReassemblyWebrtc = true;
		} else if(opt_enable_ssl && 
			  (isSslIpPort(htonl(header_ip->saddr), htons(header_tcp->source)) ||
			   isSslIpPort(htonl(header_ip->daddr), htons(header_tcp->dest)))) {
			tcpReassemblySsl->push(header, header_ip, packet,
					       block_store, block_store_index,
					       this->getPcapHandle(dlt), dlt, sensor_id);
			useTcpReassemblySsl = true;
		}
	}

	if(opt_mirrorip && (sipportmatrix[htons(header_udp->source)] || sipportmatrix[htons(header_udp->dest)])) {
		mirrorip->send((char *)header_ip, (int)(header->caplen - ((u_char*)header_ip - packet)));
	}
	if(!useTcpReassemblyHttp && !useTcpReassemblyWebrtc && !useTcpReassemblySsl && 
	   opt_enable_http < 2 && opt_enable_webrtc < 2 && opt_enable_ssl < 2) {
		if(preProcessPacket) {
			preProcessPacket->push(false, packet_counter_all,
					       header_ip->saddr, htons(header_udp->source), header_ip->daddr, htons(header_udp->dest), 
					       data, datalen, data - (char*)packet, 
					       this->getPcapHandle(dlt), header, packet, false,
					       istcp, header_ip, 0,
					       block_store, block_store_index, dlt, sensor_id);
			if(opt_ipaccount) {
				//todo: detect if voippacket!
				ipaccount(header->ts.tv_sec, (iphdr2*) ((char*)(packet) + header_plus->offset), header->len - header_plus->offset, false);
			}
		} else {
			int voippacket = 0;
			int was_rtp = 0;
			if(sverb.test_rtp_performance) {
				u_int64_t _counter = 0;
				do {
					++_counter;
					process_packet(false, packet_counter_all,
						       header_ip->saddr, htons(header_udp->source), header_ip->daddr, htons(header_udp->dest), 
						       data, datalen, data - (char*)packet, 
						       this->getPcapHandle(dlt), header, packet, 
						       istcp, &was_rtp, header_ip, &voippacket, 0,
						       block_store, block_store_index, dlt, sensor_id);
					if(!(_counter % 50)) {
						usleep(1);
					}
				} while(packet_counter_all == (u_int64_t)sverb.test_rtp_performance);
			} else {
				process_packet(false, packet_counter_all,
					       header_ip->saddr, htons(header_udp->source), header_ip->daddr, htons(header_udp->dest), 
					       data, datalen, data - (char*)packet, 
					       this->getPcapHandle(dlt), header, packet, 
					       istcp, &was_rtp, header_ip, &voippacket, 0,
					       block_store, block_store_index, dlt, sensor_id);
			}
			// if packet was VoIP add it to ipaccount
			if(opt_ipaccount) {
				ipaccount(header->ts.tv_sec, (iphdr2*) ((char*)(packet) + header_plus->offset), header->len - header_plus->offset, voippacket);
			}
		}
	} else if(opt_ipaccount) {
		ipaccount(header->ts.tv_sec, (iphdr2*) ((char*)(packet) + header_plus->offset), header->len - header_plus->offset, false);
	}
}

void PcapQueue_readFromFifo::checkFreeSizeCachedir() {
	if(!opt_cachedir[0]) {
		return;
	}
	u_long actTimeMS = getTimeMS();
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
	for(int i = 0; i < ((int)this->blockStoreTrash.size() - (all ? 0 : 2)); i++) {
		if(all || this->blockStoreTrash[i]->enableDestroy()) {
			buffersControl.sub__PcapQueue_readFromFifo__blockStoreTrash_size(this->blockStoreTrash[i]->getUseSize());
			delete this->blockStoreTrash[i];
			this->blockStoreTrash.erase(this->blockStoreTrash.begin() + i);
			--i;
		}
	}
}

void *_PcapQueue_readFromFifo_socketServerThreadFunction(void *arg) {
	PcapQueue_readFromFifo *pcapQueue = (PcapQueue_readFromFifo*)arg;
	return(pcapQueue->threadFunction(pcapQueue, (unsigned int)-1));
}

void *_PcapQueue_readFromFifo_connectionThreadFunction(void *arg) {
	PcapQueue_readFromFifo::sPacketServerConnection *connection = (PcapQueue_readFromFifo::sPacketServerConnection*)arg;
	return(connection->parent->threadFunction(connection->parent, connection->id));
}


void PcapQueue_init() {
	blockStoreBypassQueue = new FILE_LINE pcap_block_store_queue;
}

void PcapQueue_term() {
	delete blockStoreBypassQueue;
}

int getThreadingMode() {
	if(opt_pcap_queue_iface_separate_threads) {
		if(opt_pcap_queue_iface_dedup_separate_threads) {
			return(opt_pcap_queue_iface_dedup_separate_threads_extend ? 4 : 3);
		} else {
			return(2);
		}
	} else {
		return(1);
	}
}
