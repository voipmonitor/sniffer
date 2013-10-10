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

#include <snappy-c.h>

#include "pcap_queue_block.h"
#include "pcap_queue.h"
#include "hash.h"
#include "mirrorip.h"
#include "ipaccount.h"
#include "filter_mysql.h"
#include "tcpreassembly.h"


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
#define TEST_PACKETS 		(DEBUG_VERBOSE && false)
#define VERBOSE_TEST_PACKETS	(TEST_PACKETS && false)
#define TERMINATING 		((terminating && this->enableAutoTerminate) || this->threadDoTerminate)

#define MAX_TCPSTREAMS 1024
#define FILE_BUFFER_SIZE 1000000


using namespace std;

extern int handle_defrag(iphdr2 *header_ip, struct pcap_pkthdr **header, u_char **packet, int destroy);
extern Call *process_packet(unsigned int saddr, int source, unsigned int daddr, int dest, char *data, int datalen,
			    pcap_t *handle, pcap_pkthdr *header, const u_char *packet, int istcp, int dontsave, int can_thread, int *was_rtp, struct iphdr2 *header_ip, int *voippacket, int disabledsave,
			    pcap_block_store *block_store, int block_store_index);

extern int verbosity;
extern int verbosityE;
extern int terminating;
extern int opt_udpfrag;
extern int opt_skinny;
extern int opt_ipaccount;
extern int opt_pcapdump;
extern int opt_dup_check;
extern int opt_dup_check_ipheader;
extern int opt_mirrorip;
extern char opt_mirrorip_src[20];
extern char opt_mirrorip_dst[20];
extern int opt_enable_tcpreassembly;
extern int opt_tcpreassembly_pb_lock;

extern pcap_t *handle;
extern char *sipportmatrix;
extern char *httpportmatrix;
extern unsigned int duplicate_counter;
extern struct tcp_stream2_t *tcp_streams_hashed[MAX_TCPSTREAMS];
extern MirrorIP *mirrorip;
extern IPfilter *ipfilter;
extern IPfilter *ipfilter_reload;
extern int ipfilter_reload_do;
extern TELNUMfilter *telnumfilter;
extern TELNUMfilter *telnumfilter_reload;
extern int telnumfilter_reload_do;
extern char user_filter[2048];
extern Calltable *calltable;
extern volatile int calls;
extern TcpReassembly *tcpReassembly;
extern char opt_pb_read_from_file[256];
extern int pcap_dlink;
extern queue<string> mysqlquery;
extern char opt_cachedir[1024];
extern unsigned long long cachedirtransfered;
unsigned long long lastcachedirtransfered = 0;


void *_PcapQueue_threadFunction(void* arg);
void *_PcapQueue_writeThreadFunction(void* arg);

static bool __config_BYPASS_FIFO			= true;
static bool __config_USE_PCAP_FOR_FIFO			= false;
static bool __config_ENABLE_TOGETHER_READ_WRITE_FILE	= false;

int opt_pcap_queue					= 1;
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
	uint64_t opt_pcap_queue_store_queue_max_memory_size	= 1024 * 1024 * 1024;
	uint64_t opt_pcap_queue_store_queue_max_disk_size	= 0;
	uint64_t opt_pcap_queue_bypass_max_size			= 256 * 1024 * 1024;
#endif
bool opt_pcap_queue_compress				= true;
string opt_pcap_queue_disk_folder;
string opt_pcap_queue_send_to_ip;
int opt_pcap_queue_send_to_port;
string opt_pcap_queue_receive_from_ip;
int opt_pcap_queue_receive_from_port;
int opt_pcap_queue_receive_dlt = DLT_EN10MB;

size_t _opt_pcap_queue_block_offset_inc_size		= opt_pcap_queue_block_max_size / AVG_PACKET_SIZE / 4;
size_t _opt_pcap_queue_block_restore_buffer_inc_size	= opt_pcap_queue_block_max_size / 4;

static pcap_block_store_queue blockStoreBypassQueue; 

static unsigned long sumPacketsCounterIn[2];
static unsigned long sumPacketsCounterOut[2];
static unsigned long sumBlocksCounterIn[2];
static unsigned long sumBlocksCounterOut[2];
static unsigned long long sumPacketsSize[2];
static unsigned long long sumPacketsSizeCompress[2];
static unsigned long maxBypassBufferItems;
static unsigned long maxBypassBufferSize;
static unsigned long countBypassBufferSizeExceeded;
static unsigned long countPacketDrop;


bool pcap_block_store::add(pcap_pkthdr *header, u_char *packet, int offset) {
	if(this->full) {
		return(false);
	}
	if((this->size + sizeof(pcap_pkthdr_plus) + header->caplen) > opt_pcap_queue_block_max_size ||
	   (this->size && (getTimeMS() - this->timestampMS) >= opt_pcap_queue_block_max_time_ms)) {
		this->full = true;
		return(false);
	}
	if(!this->block) {
		this->block = (u_char*)malloc(opt_pcap_queue_block_max_size);
	}
	if(!this->offsets_size) {
		this->offsets_size = _opt_pcap_queue_block_offset_inc_size;
		this->offsets = (uint32_t*)malloc(this->offsets_size * sizeof(uint32_t));
	}
	if(this->count == this->offsets_size) {
		uint32_t *offsets_old = this->offsets;
		size_t offsets_size_old = this->offsets_size;
		this->offsets_size += _opt_pcap_queue_block_offset_inc_size;
		this->offsets = (uint32_t*)malloc(this->offsets_size * sizeof(uint32_t));
		memcpy(this->offsets, offsets_old, sizeof(uint32_t) * offsets_size_old);
		free(offsets_old);
	}
	this->offsets[this->count] = this->size;
	pcap_pkthdr_plus header_plus = pcap_pkthdr_plus(*header, offset);
	memcpy(this->block + this->size, &header_plus, sizeof(pcap_pkthdr_plus));
	this->size += sizeof(pcap_pkthdr_plus);
	memcpy(this->block + this->size, packet, header->caplen);
	this->size += header->caplen;
	++this->count;
	return(true);
}

bool pcap_block_store::add(pcap_pkthdr_plus *header, u_char *packet) {
	return(this->add((pcap_pkthdr*)header, packet, header->offset));
}

void pcap_block_store::destroy() {
	if(this->offsets) {
		free(this->offsets);
		this->offsets = NULL;
	}
	if(this->block) {
		free(this->block);
		this->block = NULL;
	}
	this->size = 0;
	this->size_compress = 0;
	this->count = 0;
	this->offsets_size = 0;
	this->full = false;
}

void pcap_block_store::destroyRestoreBuffer() {
	if(this->restoreBuffer) {
		free(this->restoreBuffer);
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
		free(this->block);
		this->block = NULL;
	}
}

u_char* pcap_block_store::getSaveBuffer() {
	size_t sizeSaveBuffer = this->getSizeSaveBuffer();
	u_char *saveBuffer = (u_char*)malloc(sizeSaveBuffer);
	pcap_block_store_header header;
	header.size = this->size;
	header.size_compress = this->size_compress;
	header.count = this->count;
	memcpy(saveBuffer, 
	       &header, 
	       sizeof(header));
	memcpy(saveBuffer + sizeof(header), 
	       this->offsets, 
	       sizeof(uint32_t) * this->count);
	memcpy(saveBuffer + sizeof(pcap_block_store_header) + this->count * sizeof(uint32_t),
	       this->block,
	       this->getUseSize());
	return(saveBuffer);
}

void pcap_block_store::restoreFromSaveBuffer(u_char *saveBuffer) {
	pcap_block_store_header *header = (pcap_block_store_header*)saveBuffer;
	this->size = header->size;
	this->size_compress = header->size_compress;
	this->count = header->count;
	if(this->offsets) {
		free(this->offsets);
	}
	if(this->block) {
		free(this->block);
	}
	this->offsets_size = this->count;
	this->offsets = (uint32_t*)malloc(this->offsets_size * sizeof(uint32_t));
	memcpy(this->offsets,
	       saveBuffer + sizeof(pcap_block_store_header), 
	       sizeof(uint32_t) * this->count);
	size_t sizeBlock = this->getUseSize();
	this->block = (u_char*)malloc(sizeBlock);
	memcpy(this->block,
	       saveBuffer + sizeof(pcap_block_store_header) + this->count * sizeof(uint32_t),
	       sizeBlock);
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
		u_char *restoreBufferNew = (u_char*)malloc(this->restoreBufferAllocSize);
		if(this->restoreBuffer) {
			memcpy(restoreBufferNew, this->restoreBuffer, this->restoreBufferSize);
			free(this->restoreBuffer);
		}
		this->restoreBuffer = restoreBufferNew;
	}
	memcpy(this->restoreBuffer + this->restoreBufferSize, _buffer, _size);
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
	if(this->size_compress) {
		return(true);
	}
	size_t snappyBuffSize = snappy_max_compressed_length(this->size);
	u_char *snappyBuff = (u_char*)malloc(snappyBuffSize);
	snappy_status snappyRslt = snappy_compress((char*)this->block, this->size, (char*)snappyBuff, &snappyBuffSize);
	switch(snappyRslt) {
		case SNAPPY_OK:
			free(this->block);
			this->block = (u_char*)malloc(snappyBuffSize);
			memcpy(this->block, snappyBuff, snappyBuffSize);
			free(snappyBuff);
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
	free(snappyBuff);
	return(false);
}

bool pcap_block_store::uncompress() {
	if(!this->size_compress) {
		return(true);
	}
	size_t snappyBuffSize = this->size;
	u_char *snappyBuff = (u_char*)malloc(snappyBuffSize);
	snappy_status snappyRslt = snappy_uncompress((char*)this->block, this->size_compress, (char*)snappyBuff, &snappyBuffSize);
	switch(snappyRslt) {
		case SNAPPY_OK:
			free(this->block);
			this->block = snappyBuff;
			this->size_compress = 0;
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
	free(snappyBuff);
	return(false);
}


pcap_block_store_queue::pcap_block_store_queue() {
	this->countOfBlocks = 0;
	this->sizeOfBlocks = 0;
	this->_sync_queue = 0;
}

pcap_block_store_queue::~pcap_block_store_queue() {
	this->lock_queue();
	while(this->queue.size()) {
		delete this->queue.front();
		this->queue.pop_front();
	}
	this->unlock_queue();
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
	this->timestampMS = getTimeMS();
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
	free(saveBuffer);
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
	u_char *readBuff = (u_char*)malloc(readBuffSize);
	size_t readed;
	while((readed = fread(readBuff, 1, readBuffSize, this->fileHandlePop)) > 0) {
		if(blockStore->addRestoreChunk(readBuff, readed) > 0) {
			break;
		}
	}
	free(readBuff);
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
			this->fileBufferPush = (u_char*)malloc(FILE_BUFFER_SIZE);
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
			this->fileBufferPop = (u_char*)malloc(FILE_BUFFER_SIZE);
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
			free(this->fileBufferPush);
			this->fileBufferPush = NULL;
		}
		this->unlock_sync_flush_file();
	}
	if(typeHandle & typeHandlePop &&
	   this->fileHandlePop != NULL) {
		fclose(this->fileHandlePop);
		this->fileHandlePop = NULL;
		free(this->fileBufferPop);
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
	this->sizeOfBlocksInMemory = 0;
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
	while(this->queue.size()) {
		blockStore = this->queue.front();
		delete blockStore;
		this->queue.pop_front();
	}
}

bool pcap_store_queue::push(pcap_block_store *blockStore, size_t addUsedSize, bool deleteBlockStoreIfFail) {
	bool saveToFileStore = false;
	bool locked_fileStore = false;
	if(opt_pcap_queue_store_queue_max_disk_size &&
	   this->fileStoreFolder.length()) {
		if(this->sizeOfBlocksInMemory + addUsedSize >= opt_pcap_queue_store_queue_max_memory_size) {
			saveToFileStore = true;
		} else if(!__config_ENABLE_TOGETHER_READ_WRITE_FILE) {
			this->lock_fileStore();
			locked_fileStore = true;
			if(this->fileStore.size() &&
			   !this->fileStore[this->fileStore.size() - 1]->isFull(this->sizeOfBlocksInMemory == 0)) {
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
			if(!this->lastTimeLogErrDiskIsFull ||
			   getTimeMS() > this->lastTimeLogErrDiskIsFull + 1000) {
				syslog(LOG_ERR, "packetbuffer: DISK IS FULL");
				this->lastTimeLogErrDiskIsFull = getTimeMS();
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
			fileStore = new pcap_file_store(this->lastFileStoreId, this->fileStoreFolder.c_str());
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
		if(this->sizeOfBlocksInMemory + addUsedSize >= opt_pcap_queue_store_queue_max_memory_size) {
			if(!this->lastTimeLogErrMemoryIsFull ||
			   getTimeMS() > this->lastTimeLogErrMemoryIsFull + 1000) {
				syslog(LOG_ERR, "packetbuffer: MEMORY IS FULL");
				this->lastTimeLogErrMemoryIsFull = getTimeMS();
			}
			if(deleteBlockStoreIfFail) {
				delete blockStore;
			}
			return(false);
		} else {
			this->add_sizeOfBlocksInMemory(blockStore->getUseSize());
		}
	}
	this->lock_queue();
	this->queue.push_back(blockStore);
	this->unlock_queue();
	return(true);
}

bool pcap_store_queue::pop(pcap_block_store **blockStore) {
	*blockStore = NULL;
	this->lock_queue();
	if(this->queue.size()) {
		*blockStore = this->queue.front();
		this->queue.pop_front();
	}
	this->unlock_queue();
	if(*blockStore) {
		if((*blockStore)->idFileStore) {
			pcap_file_store *_fileStore = this->findFileStoreById((*blockStore)->idFileStore);
			if(!_fileStore) {
				free(*blockStore);
				return(false);
			}
			while(!__config_ENABLE_TOGETHER_READ_WRITE_FILE && !_fileStore->full) {
				usleep(100);
			}
			if(!_fileStore->pop(*blockStore)) {
				free(*blockStore);
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
	this->enableWriteThread = false;
	this->enableAutoTerminate = true;
	this->fifoReadHandle = -1;
	this->fifoWriteHandle = -1;
	this->threadInitOk = false;
	this->writeThreadInitOk = false;
	this->threadTerminated = false;
	this->writeThreadTerminated = false;
	this->threadDoTerminate = false;
	this->threadId = 0;
	this->writeThreadId = 0;
	memset(this->threadPstatData, 0, sizeof(this->threadPstatData));
	memset(this->writeThreadPstatData, 0, sizeof(this->writeThreadPstatData));
	this->packetBuffer = NULL;
	this->instancePcapHandle = NULL;
}

PcapQueue::~PcapQueue() {
	if(this->fifoReadHandle >= 0) {
		close(this->fifoReadHandle);
	}
	if(this->fifoWriteHandle >= 0) {
		close(this->fifoWriteHandle);
	}
	if(this->packetBuffer) {
		free(this->packetBuffer);
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

void PcapQueue::setEnableWriteThread() {
	this->enableWriteThread = true;
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
	return(this->threadInitOk &&
	       (!this->enableWriteThread || this->writeThreadInitOk));
}

bool PcapQueue::isTerminated() {
	return(this->threadTerminated &&
	       (!this->enableWriteThread || this->writeThreadTerminated));
}

void PcapQueue::setInstancePcapHandle(PcapQueue *pcapQueue) {
	this->instancePcapHandle = pcapQueue;
}

void PcapQueue::pcapStat(int statPeriod, bool statCalls) {
	if(!VERBOSE && !DEBUG_VERBOSE) {
		return;
	}
	ostringstream outStr;
	if(DEBUG_VERBOSE || verbosityE > 0) {
		string statString = "\n";
		if(statCalls) {
			ostringstream outStr;
			outStr << "CALLS: " << calltable->calls_listMAP.size() << ", " << calls;
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
			(this->instancePcapHandle ? 
				this->instancePcapHandle->pcapStatString_interface(statPeriod) :
				this->pcapStatString_interface(statPeriod)) +
			"\n";
		if(statString.length()) {
			if(DEBUG_VERBOSE) {
				cout << statString;
			} else {
				syslog(LOG_NOTICE, "packetbuffer stat:\n%s", statString.c_str());
			}
		}
	} else {
		double memoryBufferPerc = this->pcapStat_get_memory_buffer_perc();
		double memoryBufferPerc_trash = this->pcapStat_get_memory_buffer_perc_trash();
		outStr << fixed
		       << "calls[" << calltable->calls_listMAP.size() << "][" << calls << "] "
		       << "SQLqueue[" << mysqlquery.size() << "] "
		       << "heap[" << setprecision(1) << memoryBufferPerc << "% / "
				  << setprecision(1) << memoryBufferPerc_trash << "%] ";
		if(this->instancePcapHandle) {
			unsigned long bypassBufferSizeExeeded = this->instancePcapHandle->pcapStat_get_bypass_buffer_size_exeeded();
			outStr << "hoverruns[" << bypassBufferSizeExeeded << "] ";
		}
		double diskBufferMb = this->pcapStat_get_disk_buffer_mb();
		if(diskBufferMb >= 0) {
			double diskBufferPerc = this->pcapStat_get_disk_buffer_perc();
			outStr << "fileq[" << setprecision(1) << diskBufferMb << "MB "
			       << setprecision(1) << diskBufferPerc << "%] ";
		}
		double compress = this->pcapStat_get_compress();
		if(compress >= 0) {
			outStr << "comp[" << setprecision(1) << compress << "%] ";
		}
		double speed = this->pcapStat_get_speed_mb_s(statPeriod);
		if(speed >= 0) {
			outStr << "[" << setprecision(1) << speed << "Mb/s] ";
		}
		if(opt_cachedir[0] != '\0') {
			outStr << "cdq[" << calltable->files_queue.size() << "][" << ((float)(cachedirtransfered - lastcachedirtransfered) / 1024.0 / 1024.0 / (float)statPeriod) << " MB/s] ";
			lastcachedirtransfered = cachedirtransfered;
		}
	}
	ostringstream outStrStat;
	outStrStat << fixed;
	if(this->instancePcapHandle) {
		double t0cpu = this->instancePcapHandle->getCpuUsagePerc(false, true);
		if(t0cpu >= 0) {
			outStrStat << "t0CPU[" << setprecision(1) << t0cpu << "%] ";
		}
	}
	double t1cpu = this->getCpuUsagePerc(false, true);
	if(t1cpu >= 0) {
		outStrStat << "t1CPU[" << setprecision(1) << t1cpu << "%] ";
	}
	double t2cpu = this->getCpuUsagePerc(true, true);
	if(t2cpu >= 0) {
		outStrStat << "t2CPU[" << setprecision(1) << t2cpu << "%] ";
	}
	if(tcpReassembly) {
		double thttp_cpu = tcpReassembly->getCpuUsagePerc();
		if(thttp_cpu >= 0) {
			outStrStat << "thttpCPU[" << setprecision(1) << thttp_cpu << "%] ";
		}
	}
	long unsigned int rss = this->getRssUsage();
	if(rss > 0) {
		outStrStat << "res[" << setprecision(1) << (double)rss/1024/1024 << "MB] ";
	}
	long unsigned int vsize = this->getVsizeUsage();
	if(vsize > 0) {
		outStrStat << "virt[" << setprecision(1) << (double)vsize/1024/1024 << "MB] ";
	}
	if(DEBUG_VERBOSE || verbosityE > 0) {
		if(DEBUG_VERBOSE) {
			cout << outStrStat.str() << endl;
		} else {
			syslog(LOG_NOTICE, "packetbuffer cpu / mem stat:\n%s", outStrStat.str().c_str());
		}
	} else {
		outStr << outStrStat.str();
		outStr << endl;
		outStr << (this->instancePcapHandle ? 
				this->instancePcapHandle->pcapStatString_interface(statPeriod) :
				this->pcapStatString_interface(statPeriod));
		syslog(LOG_NOTICE, "%s", outStr.str().c_str());
	}
	sumPacketsCounterIn[1] = sumPacketsCounterIn[0];
	sumPacketsCounterOut[1] = sumPacketsCounterOut[0];
	sumBlocksCounterIn[1] = sumBlocksCounterIn[0];
	sumBlocksCounterOut[1] = sumBlocksCounterOut[0];
	sumPacketsSize[1] = sumPacketsSize[0];
	sumPacketsSizeCompress[1] = sumPacketsSizeCompress[0];
}

void PcapQueue::initStat() {
	if(this->instancePcapHandle) {
		this->instancePcapHandle->initStat_interface();
	} else {
		this->initStat_interface();
	}
}

pcap_t* PcapQueue::getPcapHandle() {
	return(this->instancePcapHandle ?
		this->instancePcapHandle->_getPcapHandle() :
		this->_getPcapHandle());
}

bool PcapQueue::createThread() {
	pthread_create(&this->threadHandle, NULL, _PcapQueue_threadFunction, this);
	if(this->enableWriteThread) {
		pthread_create(&this->writeThreadHandle, NULL, _PcapQueue_writeThreadFunction, this);
	}
	return(true);
}

int PcapQueue::pcap_next_ex(pcap_t *pcapHandle, pcap_pkthdr** header, u_char** packet) {
	int res = ::pcap_next_ex(pcapHandle, header, (const u_char**)packet);
	if(!packet && res != -2) {
		if(VERBOSE) {
			syslog(LOG_NOTICE,"packetbuffer %s: NULL PACKET, pcap response is %d", this->nameQueue.c_str(), res);
			}
		return(0);
	} else if(res == -1) {
		if(VERBOSE) {
			syslog (LOG_NOTICE,"packetbuffer %s: error reading packets", this->nameQueue.c_str());
		}
		return(0);
	} else if(res == -2) {
		if(VERBOSE) {
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
			this->packetBuffer = (u_char*)malloc(100000);
		}
		*packet = this->packetBuffer;
	} else {
		*packet = (u_char*)malloc(header->header_fix_size.caplen);
	}
	size_t readPacket = 0;
	while(readPacket < header->header_fix_size.caplen) {
		rsltRead = read(this->fifoReadHandle, *packet + readPacket, header->header_fix_size.caplen - readPacket);
		if(rsltRead < 0) {
			if(!usePacketBuffer) {
				free(*packet);
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

bool PcapQueue::initThread() {
	return(this->openFifoForRead() &&
	       (this->enableWriteThread || this->openFifoForWrite()));
}

bool PcapQueue::initWriteThread() {
	return(this->openFifoForWrite());
}

bool PcapQueue::openFifoForRead() {
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

bool PcapQueue::openFifoForWrite() {
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

void PcapQueue::preparePstatData(bool writeThread) {
	uint pid = writeThread ? this->writeThreadId : this->threadId;
	if(pid) {
		if(writeThread) {
			if(this->writeThreadPstatData[0].cpu_total_time) {
				this->writeThreadPstatData[1] = this->writeThreadPstatData[0];
			}
		} else {
			if(this->threadPstatData[0].cpu_total_time) {
				this->threadPstatData[1] = this->threadPstatData[0];
			}
		}
		pstat_get_data(pid, writeThread ? this->writeThreadPstatData : this->threadPstatData);
	}
}

double PcapQueue::getCpuUsagePerc(bool writeThread, bool preparePstatData) {
	if(preparePstatData) {
		this->preparePstatData(writeThread);
	}
	uint pid = writeThread ? this->writeThreadId : this->threadId;
	if(pid) {
		double ucpu_usage, scpu_usage;
		if(writeThread) {
			if(this->writeThreadPstatData[0].cpu_total_time && this->writeThreadPstatData[1].cpu_total_time) {
				pstat_calc_cpu_usage_pct(
					&this->writeThreadPstatData[0], &this->writeThreadPstatData[1],
					&ucpu_usage, &scpu_usage);
				return(ucpu_usage + scpu_usage);
			}
		} else {
			if(this->threadPstatData[0].cpu_total_time && this->threadPstatData[1].cpu_total_time) {
				pstat_calc_cpu_usage_pct(
					&this->threadPstatData[0], &this->threadPstatData[1],
					&ucpu_usage, &scpu_usage);
				return(ucpu_usage + scpu_usage);
			}
		}
	}
	return(-1);
}

long unsigned int PcapQueue::getVsizeUsage(bool writeThread, bool preparePstatData) {
	if(preparePstatData) {
		this->preparePstatData(writeThread);
	}
	uint pid = writeThread ? this->writeThreadId : this->threadId;
	if(pid) {
		return(this->threadPstatData[0].vsize);
	}
	return(0);
}

long unsigned int PcapQueue::getRssUsage(bool writeThread, bool preparePstatData) {
	if(preparePstatData) {
		this->preparePstatData(writeThread);
	}
	uint pid = writeThread ? this->writeThreadId : this->threadId;
	if(pid) {
		return(this->threadPstatData[0].rss);
	}
	return(0);
}


inline void *_PcapQueue_threadFunction(void* arg) {
	return(((PcapQueue*)arg)->threadFunction(arg));
}

inline void *_PcapQueue_writeThreadFunction(void* arg) {
	return(((PcapQueue*)arg)->writeThreadFunction(arg));
}


PcapQueue_readFromInterface::PcapQueue_readFromInterface(const char *nameQueue)
 : PcapQueue(readFromInterface, nameQueue) {
	this->interfaceNet = 0;
	this->interfaceMask = 0;
	this->pcapHandle = NULL;
	this->pcapDumpHandle = NULL;
	this->pcapLinklayerHeaderType = 0;
	this->fifoWritePcapDumper = NULL;
	this->ipfrag_lastprune = 0;
	// CONFIG
	extern int opt_promisc;
	extern int opt_ringbuffer;
	this->pcap_snaplen = opt_enable_tcpreassembly ? 6000 : 3200;
	this->pcap_promisc = opt_promisc;
	this->pcap_timeout = 1000;
	this->pcap_buffer_size = opt_ringbuffer * 1024 * 1024;
	//
	this->_last_ps_drop = 0;
	this->_last_ps_ifdrop = 0;
}

PcapQueue_readFromInterface::~PcapQueue_readFromInterface() {
	if(this->fifoWritePcapDumper) {
		pcap_dump_close(this->fifoWritePcapDumper);
	}
	if(this->pcapHandle) {
		pcap_close(this->pcapHandle);
	}
	if(this->pcapDumpHandle) {
		pcap_dump_close(this->pcapDumpHandle);
	}
}

void PcapQueue_readFromInterface::setInterfaceName(const char* interfaceName) {
	this->interfaceName = interfaceName;
}

bool PcapQueue_readFromInterface::initThread() {
	init_hash();
	memset(tcp_streams_hashed, 0, sizeof(tcp_stream2_t*) * MAX_TCPSTREAMS);
	return(this->startCapture() &&
	       this->openFifoForWrite());
}

void* PcapQueue_readFromInterface::threadFunction(void* ) {
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		this->threadId = syscall(SYS_gettid);
		outStr << "start thread t0 (" << this->nameQueue << ") - pid: " << this->threadId << endl;
		if(DEBUG_VERBOSE) {
			cout << outStr.str();
		} else {
			syslog(LOG_NOTICE, outStr.str().c_str());
		}
	}
	if(this->initThread()) {
		this->threadInitOk = true;
	} else {
		this->threadTerminated = true;
		terminating = 1;
		return(NULL);
	}
	this->initStat();
	pcap_pkthdr *header;
	u_char *packet;
	int res;
	bool destroy = false;
	size_t blockStoreBypassQueueSize;
	if(__config_BYPASS_FIFO) {
		pcap_block_store *blockStore = new pcap_block_store;
		while(!TERMINATING) {
			res = this->pcap_next_ex(this->pcapHandle, &header, &packet);
			if(opt_pb_read_from_file[0]/* && !(sumBlocksCounterIn[0] % 5)*/) {
				usleep(1);
			}
			if(res == -1) {
				if(opt_pb_read_from_file[0]) {
					blockStoreBypassQueue.push(blockStore);
					++sumBlocksCounterIn[0];
					blockStore = NULL;
					sleep(1);
					calltable->cleanup(0);
					this->pcapStat();
					terminating = 1;
				}
				break;
			} else if(res == 0) {
				continue;
			}
			if(!TEST_PACKETS) {
				res = this->pcapProcess(&header, &packet, &destroy);
				if(res == -1) {
					break;
				} else if(res == 0) {
					if(destroy) {
						free(header);
						free(packet);
					}
					continue;
				}
			}
			++sumPacketsCounterIn[0];
			if(TEST_PACKETS) {
				static char buff[101];
				sprintf(buff, "%0100lu", sumPacketsCounterIn[0]);
				packet = (u_char*)buff;
				header->len = 101;
				header->caplen = 101;
			}
			if(!blockStore->full) {
				blockStore->add(header, packet, this->ppd.offset);
			}
			if(blockStore->full) {
				bool _syslog = true;
				while((blockStoreBypassQueueSize = blockStoreBypassQueue.getUseSize()) > opt_pcap_queue_bypass_max_size) {
					if(_syslog) {
						syslog(LOG_ERR, "packetbuffer %s: THREAD0 BUFFER IS FULL", this->nameQueue.c_str());
						cout << "bypass buffer size " << blockStoreBypassQueue.getUseItems() << " (" << blockStoreBypassQueue.getUseSize() << ")" << endl;
						_syslog = false;
						++countBypassBufferSizeExceeded;
					}
					usleep(100);
					maxBypassBufferSize = 0;
					maxBypassBufferItems = 0;
				}
				if(blockStoreBypassQueueSize > maxBypassBufferSize) {
					maxBypassBufferSize = blockStoreBypassQueueSize;
					maxBypassBufferItems = blockStoreBypassQueue.getUseItems();
				}
				blockStoreBypassQueue.push(blockStore);
				++sumBlocksCounterIn[0];
				blockStore = new pcap_block_store;
				blockStore->add(header, packet, this->ppd.offset);
			}
			if(!TEST_PACKETS && destroy) {
				free(header);
				free(packet);
			}
		}
		if(blockStore) {
			delete blockStore;
		}
	} else {
		while(!TERMINATING) {
			res = this->pcap_next_ex(this->pcapHandle, &header, &packet);
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
					free(header);
					free(packet);
				}
				continue;
			}
			if(__config_USE_PCAP_FOR_FIFO) {
				pcap_dump((u_char*)this->fifoWritePcapDumper, header, packet);
			} else {
				pcap_pkthdr_plus header_plus(*header, this->ppd.offset);
				this->writePcapToFifo(&header_plus, packet);
			}
			if(destroy) {
				free(header);
				free(packet);
			}
		}
	}
	this->threadTerminated = true;
	return(NULL);
}

bool PcapQueue_readFromInterface::openFifoForWrite() {
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
		return(PcapQueue::openFifoForWrite());
	}
}

bool PcapQueue_readFromInterface::startCapture() {
	char errbuf[PCAP_ERRBUF_SIZE];
	if(opt_pb_read_from_file[0]) {
		this->pcapHandle = pcap_open_offline(opt_pb_read_from_file, errbuf);
		this->pcapLinklayerHeaderType = pcap_datalink(this->pcapHandle);
		handle = this->pcapHandle;
		return(true);
	}
	if(VERBOSE) {
		syslog(LOG_NOTICE, "packetbuffer %s: capturing on interface %s", this->nameQueue.c_str(), this->interfaceName.c_str()); 
	}
	if(pcap_lookupnet(this->interfaceName.c_str(), &this->interfaceNet, &this->interfaceMask, errbuf) == -1) {
		this->interfaceMask = PCAP_NETMASK_UNKNOWN;
	}
	if((this->pcapHandle = pcap_create(this->interfaceName.c_str(), errbuf)) == NULL) {
		syslog(LOG_ERR, "packetbuffer %s: pcap_create failed on iface %s: %s", this->nameQueue.c_str(), this->interfaceName.c_str(), errbuf); 
		return(false);
	}
	handle = this->pcapHandle;
	int status;
	if((status = pcap_set_snaplen(this->pcapHandle, this->pcap_snaplen)) != 0) {
		syslog(LOG_ERR, "packetbuffer %s: pcap_snaplen failed", this->nameQueue.c_str()); 
		return(false);
	}
	if((status = pcap_set_promisc(this->pcapHandle, this->pcap_promisc)) != 0) {
		syslog(LOG_ERR, "packetbuffer %s: pcap_set_promisc failed", this->nameQueue.c_str()); 
		return(false);
	}
	if((status = pcap_set_timeout(this->pcapHandle, this->pcap_timeout)) != 0) {
		syslog(LOG_ERR, "packetbuffer %s: pcap_set_timeout failed", this->nameQueue.c_str()); 
		return(false);
	}
	if((status = pcap_set_buffer_size(this->pcapHandle, this->pcap_buffer_size)) != 0) {
		syslog(LOG_ERR, "packetbuffer %s: pcap_set_buffer_size failed", this->nameQueue.c_str()); 
		return(false);
	}
	if((status = pcap_activate(this->pcapHandle)) != 0) {
		syslog(LOG_ERR, "packetbuffer %s: libpcap error: %s", this->nameQueue.c_str(), pcap_geterr(this->pcapHandle)); 
		return(false);
	}
	if(opt_mirrorip) {
		if(opt_mirrorip_dst[0] == '\0') {
			syslog(LOG_ERR, "packetbuffer %s: mirroring packets was disabled because mirroripdst is not set", this->nameQueue.c_str());
			opt_mirrorip = 0;
		} else {
			syslog(LOG_NOTICE, "packetbuffer %s: starting mirroring [%s]->[%s]", this->nameQueue.c_str(), opt_mirrorip_src, opt_mirrorip_dst);
			mirrorip = new MirrorIP(opt_mirrorip_src, opt_mirrorip_dst);
		}
	}
	char filter_exp[2048] = "";	// The filter expression
	struct bpf_program fp;		// The compiled filter 
	if(*user_filter != '\0') {
		snprintf(filter_exp, sizeof(filter_exp), "%s", user_filter);

		// Compile and apply the filter
		if (pcap_compile(this->pcapHandle, &fp, filter_exp, 0, this->interfaceMask) == -1) {
			fprintf(stderr, "packetbuffer %s: can not parse filter %s: %s", this->nameQueue.c_str(), filter_exp, pcap_geterr(this->pcapHandle));
			return(2);
		}
		if (pcap_setfilter(this->pcapHandle, &fp) == -1) {
			fprintf(stderr, "packetbuffer %s: can not install filter %s: %s", this->nameQueue.c_str(), filter_exp, pcap_geterr(this->pcapHandle));
			return(2);
		}
	}
	this->pcapLinklayerHeaderType = pcap_datalink(this->pcapHandle);
	if(!this->pcapLinklayerHeaderType) {
		syslog(LOG_ERR, "packetbuffer %s: pcap_datalink failed", this->nameQueue.c_str()); 
		return(false);
	}
	pcap_dlink = this->pcapLinklayerHeaderType;
	syslog(LOG_NOTICE, "DLT %i", this->pcapLinklayerHeaderType);
	if(opt_pcapdump) {
		char pname[1024];
		sprintf(pname, "/var/spool/voipmonitor/voipmonitordump-%u.pcap", (unsigned int)time(NULL));
		this->pcapDumpHandle = pcap_dump_open(this->pcapHandle, pname);
	}
	return(true);
}

string PcapQueue_readFromInterface::pcapStatString_bypass_buffer(int statPeriod) {
	ostringstream outStr;
	if(__config_BYPASS_FIFO) {
		outStr << fixed;
		uint64_t useSize = blockStoreBypassQueue.getUseSize();
		uint64_t useItems = blockStoreBypassQueue.getUseItems();
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
	if(this->pcapHandle) {
		pcap_stat ps;
		int pcapstatres = pcap_stats(this->pcapHandle, &ps);
		if(pcapstatres == 0) {
			if(ps.ps_drop > this->_last_ps_drop || ps.ps_ifdrop > this->_last_ps_ifdrop) {
				outStr << "DROPPED PACKETS: "
				       << "libpcap or interface dropped some packets!"
				       << " rx:" << ps.ps_recv
				       << " pcapdrop:" << ps.ps_drop - this->_last_ps_drop
				       << " ifdrop:"<< ps.ps_ifdrop - this->_last_ps_drop << endl
				       << "     increase --ring-buffer (kernel >= 2.6.31 and libpcap >= 1.0.0)" << endl;
				this->_last_ps_drop = ps.ps_drop;
				this->_last_ps_ifdrop = ps.ps_ifdrop;
				++countPacketDrop;
			} else if(countPacketDrop) {
				outStr << "pdropsCount[" << countPacketDrop << "]";
			}
		}
	}
	return(outStr.str());
}

void PcapQueue_readFromInterface::initStat_interface() {
	if(this->pcapHandle) {
		pcap_stat ps;
		int pcapstatres = pcap_stats(this->pcapHandle, &ps);
		if (pcapstatres == 0 && (ps.ps_drop || ps.ps_ifdrop)) {
			this->_last_ps_drop = ps.ps_drop;
			this->_last_ps_ifdrop = ps.ps_ifdrop;
		}
		countPacketDrop = 0;
	}
}

int PcapQueue_readFromInterface::pcapProcess(pcap_pkthdr** header, u_char** packet, bool *destroy) {
	*destroy = false;
	switch(this->pcapLinklayerHeaderType) {
		case DLT_LINUX_SLL:
			ppd.header_sll = (sll_header*)*packet;
			ppd.protocol = ppd.header_sll->sll_protocol;
			if(ppd.header_sll->sll_protocol == 129) {
				// VLAN tag
				ppd.protocol = *(short*)(*packet + 16 + 2);
				ppd.offset = 4;
			} else {
				ppd.offset = 0;
				ppd.protocol = ppd.header_sll->sll_protocol;
			}
			ppd.offset += sizeof(sll_header);
			break;
		case DLT_EN10MB:
			ppd.header_eth = (ether_header *)*packet;
			if(ppd.header_eth->ether_type == 129) {
				// VLAN tag
				ppd.offset = 4;
				//XXX: this is very ugly hack, please do it right! (it will work for "08 00" which is IPV4 but not for others! (find vlan_header or something)
				ppd.protocol = *(*packet + sizeof(ether_header) + 2);
			} else {
				ppd.offset = 0;
				ppd.protocol = ppd.header_eth->ether_type;
			}
			ppd.offset += sizeof(ether_header);
			break;
		case DLT_RAW:
			ppd.offset = 0;
			ppd.protocol = 8;
			break;
		default:
			syslog(LOG_ERR, "packetbuffer %s: datalink number [%d] is not supported", this->nameQueue.c_str(), this->pcapLinklayerHeaderType);
			return(0);
	}
	if(ppd.protocol != 8) {
		// not ipv4 
		return(0);
	}
	
	ppd.header_ip = (iphdr2*)(*packet + ppd.offset);

	//if UDP defrag is enabled process only UDP packets and only SIP packets
	if(opt_udpfrag && (ppd.header_ip->protocol == IPPROTO_UDP || ppd.header_ip->protocol == 4)) {
		int foffset = ntohs(ppd.header_ip->frag_off);
		if ((foffset & IP_MF) || ((foffset & IP_OFFSET) > 0)) {
			// packet is fragmented
			if(handle_defrag(ppd.header_ip, header, packet, 0)) {
				// packets are reassembled
				ppd.header_ip = (iphdr2*)(*packet + ppd.offset);
				*destroy = true;
			} else {
				return(0);
			}
		}
	}

	if(ppd.header_ip->protocol == 4) {
		ppd.header_ip = (iphdr2*)((char*)ppd.header_ip + sizeof(iphdr2));

		//if UDP defrag is enabled process only UDP packets and only SIP packets
		if(opt_udpfrag && ppd.header_ip->protocol == IPPROTO_UDP) {
			int foffset = ntohs(ppd.header_ip->frag_off);
			if ((foffset & IP_MF) || ((foffset & IP_OFFSET) > 0)) {
				// packet is fragmented
				pcap_pkthdr* header_old = *header;
				u_char* packet_old = *packet;
				if(handle_defrag(ppd.header_ip, header, packet, 0)) {
					// packet was returned
					ppd.header_ip = (iphdr2*)(*packet + ppd.offset);
					ppd.header_ip->frag_off = 0;
					ppd.header_ip = (iphdr2*)((char*)ppd.header_ip + sizeof(iphdr2));
					ppd.header_ip->frag_off = 0;
					//exit(0);
					if(*destroy) {
						free(header_old);
						free(packet_old);
					}
					*destroy = true;
				} else {
					return(0);
				}
			}
		}
	}
	
	// if IP defrag is enabled, run each 10 seconds cleaning 
	if(opt_udpfrag && (ipfrag_lastprune + 10) < (*header)->ts.tv_sec) {
		ipfrag_prune((*header)->ts.tv_sec, 0);
		ipfrag_lastprune = (*header)->ts.tv_sec;
		//TODO it would be good to still pass fragmented packets even it does not contain the last semant, the ipgrad_prune just wipes all unfinished frags
	}

	ppd.header_udp = &ppd.header_udp_tmp;
	if (ppd.header_ip->protocol == IPPROTO_UDP) {
		// prepare packet pointers 
		ppd.header_udp = (udphdr2*) ((char*) ppd.header_ip + sizeof(*ppd.header_ip));
		ppd.data = (char*) ppd.header_udp + sizeof(*ppd.header_udp);
		ppd.datalen = (int)((*header)->caplen - ((unsigned long) ppd.data - (unsigned long) *packet)); 
		ppd.traillen = (int)((*header)->caplen - ((unsigned long) ppd.header_ip - (unsigned long) *packet)) - ntohs(ppd.header_ip->tot_len);
		ppd.istcp = 0;
	} else if (ppd.header_ip->protocol == IPPROTO_TCP) {
		ppd.istcp = 1;
		// prepare packet pointers 
		ppd.header_tcp = (tcphdr*) ((char*) ppd.header_ip + sizeof(*ppd.header_ip));
		ppd.data = (char*) ppd.header_tcp + (ppd.header_tcp->doff * 4);
		ppd.datalen = (int)((*header)->caplen - ((unsigned long) ppd.data - (unsigned long) *packet)); 
		//if (datalen == 0 || !(sipportmatrix[htons(header_tcp->source)] || sipportmatrix[htons(header_tcp->dest)])) {
		if (!(sipportmatrix[htons(ppd.header_tcp->source)] || sipportmatrix[htons(ppd.header_tcp->dest)]) &&
		    !(opt_enable_tcpreassembly && (httpportmatrix[htons(ppd.header_tcp->source)] || httpportmatrix[htons(ppd.header_tcp->dest)])) &&
		    !(opt_skinny && (htons(ppd.header_tcp->source) == 2000 || htons(ppd.header_tcp->dest) == 2000))) {
			// not interested in TCP packet other than SIP port
			if(opt_ipaccount == 0 && !DEBUG_ALL_PACKETS) {
				return(0);
			}
		}

		ppd.header_udp->source = ppd.header_tcp->source;
		ppd.header_udp->dest = ppd.header_tcp->dest;
	} else {
		//packet is not UDP and is not TCP, we are not interested, go to the next packet (but if ipaccount is enabled, do not skip IP
		if(opt_ipaccount == 0 && !DEBUG_ALL_PACKETS) {
			return(0);
		}
	}

	if(ppd.datalen < 0) {
		return(0);
	}

	/* check for duplicate packets (md5 is expensive operation - enable only if you really need it */
	if(ppd.datalen > 0 && opt_dup_check && ppd.prevmd5s != NULL && (ppd.traillen < ppd.datalen) &&
	   !(ppd.istcp && opt_enable_tcpreassembly && (httpportmatrix[htons(ppd.header_tcp->source)] || httpportmatrix[htons(ppd.header_tcp->dest)]))) {
		MD5_Init(&ppd.ctx);
		if(opt_dup_check_ipheader) {
			// check duplicates based on full ip header and data 
			MD5_Update(&ppd.ctx, ppd.header_ip, MIN(ppd.datalen - ((char*)ppd.header_ip - ppd.data), ntohs(ppd.header_ip->tot_len)));
		} else {
			// check duplicates based only on data (without ip header and without UDP/TCP header). Duplicate packets 
			// will be matched regardless on IP 
			MD5_Update(&ppd.ctx, ppd.data, MAX(0, (unsigned long)ppd.datalen - ppd.traillen));
		}
		MD5_Final((unsigned char*)ppd.md5, &ppd.ctx);
		//#pragma GCC diagnostic push
		//#pragma GCC diagnostic ignored "-Wstrict-aliasing"
		if(memcmp(ppd.md5, ppd.prevmd5s + (*ppd.md5 * MD5_DIGEST_LENGTH), MD5_DIGEST_LENGTH) == 0) {
			//printf("dropping duplicate md5[%s]\n", md5);
			duplicate_counter++;
			return(0);
		}
		memcpy(ppd.prevmd5s+(*ppd.md5 * MD5_DIGEST_LENGTH), ppd.md5, MD5_DIGEST_LENGTH);
		//#pragma GCC diagnostic pop
	}
		
	if(this->pcapDumpHandle) {
		pcap_dump((u_char*)this->pcapDumpHandle, *header, *packet);
	}

	return(1);
}


PcapQueue_readFromFifo::PcapQueue_readFromFifo(const char *nameQueue, const char *fileStoreFolder) 
 : PcapQueue(readFromFifo, nameQueue),
   pcapStoreQueue(fileStoreFolder) {
	 this->packetServerPort = 0;
	 this->packetServerDirection = directionNA;
	 this->fifoReadPcapHandle = NULL;
	 this->pcapDeadHandle = NULL;
	 this->socketHostEnt = NULL;
	 this->socketHandle = 0;
	 this->socketClient = 0;
	 this->blockStoreTrash_size = 0;
	 this->cleanupBlockStoreTrash_counter = 0;
	 this->setEnableWriteThread();
}

PcapQueue_readFromFifo::~PcapQueue_readFromFifo() {
	if(this->fifoReadPcapHandle) {
		pcap_close(this->fifoReadPcapHandle);
	}
	if(this->pcapDeadHandle) {
		pcap_close(this->pcapDeadHandle);
	}
	if(this->socketHandle) {
		this->socketClose();
	}
	this->cleanupBlockStoreTrash(true);
}

void PcapQueue_readFromFifo::setPacketServer(const char *packetServer, int packetServerPort, ePacketServerDirection direction) {
	this->packetServer = packetServer;
	this->packetServerPort = packetServerPort;
	this->packetServerDirection = direction;
}

bool PcapQueue_readFromFifo::initThread() {
	if(this->packetServerDirection == directionRead &&
	   !this->openPcapDeadHandle()) {
		return(false);
	}
	return(PcapQueue::initThread());
}


void *PcapQueue_readFromFifo::threadFunction(void *) {
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		this->threadId = syscall(SYS_gettid);
		outStr << "start thread t1 (" << this->nameQueue << ") - pid: " << this->threadId << endl;
		if(DEBUG_VERBOSE) {
			cout << outStr.str();
		} else {
			syslog(LOG_NOTICE, outStr.str().c_str());
		}
	}
	if(this->initThread()) {
		this->threadInitOk = true;
	} else {
		this->threadTerminated = true;
		terminating = 1;
		return(NULL);
	}
	if(this->packetServerDirection == directionRead) {
		pcap_block_store *blockStore = new pcap_block_store;
		size_t bufferSize = 1000;
		u_char *buffer = new u_char[bufferSize * 2];
		size_t bufferLen;
		size_t offsetBufferSyncRead;
		size_t offsetBuffer;
		size_t readLen;
		bool beginBlock = false;
		bool endBlock = false;
		bool syncBeginBlock = true;
		int _countTestSync = 0;
		while(!TERMINATING) {
			this->socketAwaitConnection();
			bufferLen = 0;
			offsetBufferSyncRead = 0;
			while(true && !TERMINATING) {
				readLen = bufferSize;
				if(!this->socketRead(buffer + offsetBufferSyncRead, &readLen) || readLen == 0) {
					break;
				}
				if(readLen) {
					bufferLen += readLen;
					if(syncBeginBlock) {
						u_char *pointToBeginBlock = (u_char*)memmem(buffer, bufferLen, PCAP_BLOCK_STORE_HEADER_STRING, PCAP_BLOCK_STORE_HEADER_STRING_LEN);
						if(pointToBeginBlock) {
							if(pointToBeginBlock > buffer) {
								u_char *buffer2 = new u_char[bufferSize * 2];
								memcpy(buffer2, pointToBeginBlock, bufferLen - (pointToBeginBlock - buffer));
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
								memcpy(buffer, buffer + offsetBufferSyncRead, readLen);
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
								this->pcapStoreQueue.push(blockStore, this->blockStoreTrash_size);
								sumPacketsCounterIn[0] += blockStore->count;
								sumPacketsSize[0] += blockStore->size;
								sumPacketsSizeCompress[0] += blockStore->size_compress;
								++sumBlocksCounterIn[0];
								blockStore = new pcap_block_store;
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
		delete [] buffer;
		delete blockStore;
		
	} else if(__config_BYPASS_FIFO) {
		pcap_block_store *blockStore;
		while(!TERMINATING) {
			blockStore = blockStoreBypassQueue.pop(false);
			if(!blockStore) {
				usleep(1000);
				continue;
			}
			size_t blockSize = blockStore->size;
			if(opt_pcap_queue_compress) {
				blockStore->compress();
			}
			if(this->pcapStoreQueue.push(blockStore, this->blockStoreTrash_size, false)) {
				sumPacketsSize[0] += blockSize;
				blockStoreBypassQueue.pop(true, blockSize);
			} else {
				usleep(1000);
			}
		}
	} else {
		pcap_pkthdr_plus header;
		u_char *packet;
		int res;
		pcap_block_store *blockStore = new pcap_block_store;
		while(!TERMINATING) {
			if(__config_USE_PCAP_FOR_FIFO) {
				pcap_pkthdr *_header;
				res = this->pcap_next_ex(this->fifoReadPcapHandle, &_header, &packet);
				header = pcap_pkthdr_plus(*_header, -1);
			} else {
				res = this->readPcapFromFifo(&header, &packet, true);
			}
			if(res == -1) {
				break;
			} else if(res == 0) {
				continue;
			}
			++sumPacketsCounterIn[0];
			blockStore->add(&header, packet);
			if(blockStore->full) {
				sumPacketsSize[0] += blockStore->size;
				if(opt_pcap_queue_compress) {
					blockStore->compress();
				}
				if(this->pcapStoreQueue.push(blockStore, this->blockStoreTrash_size)) {
					++sumBlocksCounterIn[0];
					blockStore = new pcap_block_store;
					blockStore->add(&header, packet);
				}
			}
		}
		delete blockStore;
	}
	this->threadTerminated = true;
	return(NULL);
}

void *PcapQueue_readFromFifo::writeThreadFunction(void *) {
	if(VERBOSE || DEBUG_VERBOSE) {
		ostringstream outStr;
		this->writeThreadId = syscall(SYS_gettid);
		outStr << "start thread t2 (" << this->nameQueue << " / write" << ") - pid: " << this->writeThreadId << endl;
		if(DEBUG_VERBOSE) {
			cout << outStr.str();
		} else {
			syslog(LOG_NOTICE, outStr.str().c_str());
		}
	}
	if(this->initWriteThread()) {
		this->writeThreadInitOk = true;
	} else {
		this->writeThreadTerminated = true;
		terminating = 1;
		return(NULL);
	}
	pcap_block_store *blockStore;
	while(!TERMINATING) {
		if(DEBUG_SLEEP && access((this->pcapStoreQueue.fileStoreFolder + "/__/sleep").c_str(), F_OK ) != -1) {
			sleep(1);
		}
		this->pcapStoreQueue.pop(&blockStore);
		if(blockStore) {
			++sumBlocksCounterOut[0];
			if(this->packetServerDirection == directionWrite) {
				this->socketWritePcapBlock(blockStore);
			} else {
				if(blockStore->size_compress && !blockStore->uncompress()) {
					delete blockStore;
					continue;
				}
				for(size_t i = 0; i < blockStore->count; i++) {
					++sumPacketsCounterOut[0];
					if(TEST_PACKETS) {
						if(VERBOSE_TEST_PACKETS) {
							cout << "test packet " << (*blockStore)[i].packet << endl;
						}
						if(sumPacketsCounterOut[0] != (u_long)atol((char*)(*blockStore)[i].packet)) {
							cout << endl << endl << "ERROR: BAD PACKET ORDER" << endl << endl;
							//exit(1);
							sleep(5);
							sumPacketsCounterOut[0] = (u_long)atol((char*)(*blockStore)[i].packet);
						}
					} else {
						this->processPacket((*blockStore)[i].header, (*blockStore)[i].packet, blockStore, i);
					}
				}
			}
			this->blockStoreTrash.push_back(blockStore);
			this->blockStoreTrash_size += blockStore->getUseSize();
		} else {
			usleep(1000);
		}
		if(!(++this->cleanupBlockStoreTrash_counter % 10)) {
			this->cleanupBlockStoreTrash();
		}
	}
	this->writeThreadTerminated = true;
	return(NULL);
}

bool PcapQueue_readFromFifo::openFifoForRead() {
	if(this->packetServerDirection == directionRead) {
		return(this->socketListen());
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
			return(PcapQueue::openFifoForRead());
		}
	}
	return(false);
}

bool PcapQueue_readFromFifo::openFifoForWrite() {
	if(this->packetServerDirection == directionWrite) {
		return(this->socketGetHost() &&
		       this->socketConnect());
	}
	return(true);
}

bool PcapQueue_readFromFifo::openPcapDeadHandle() {
	if((this->pcapDeadHandle = pcap_open_dead(opt_pcap_queue_receive_dlt, 65535)) == NULL) {
		syslog(LOG_ERR, "packetbuffer %s: pcap_create failed", this->nameQueue.c_str()); 
		return(false);
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
	handle = this->pcapDeadHandle;
	return(true);
}

string PcapQueue_readFromFifo::pcapStatString_memory_buffer(int statPeriod) {
	ostringstream outStr;
	if(__config_BYPASS_FIFO) {
		outStr << fixed;
		uint64_t useSize = this->pcapStoreQueue.sizeOfBlocksInMemory + this->blockStoreTrash_size;
		outStr << "PACKETBUFFER_TOTAL_HEAP:   "
		       << setw(6) << (useSize / 1024 / 1024) << "MB" << setw(6) << ""
		       << " " << setw(5) << setprecision(1) << (100. * useSize / opt_pcap_queue_store_queue_max_memory_size) << "%"
		       << " of " << setw(6) << (opt_pcap_queue_store_queue_max_memory_size / 1024 / 1024) << "MB" << endl;
		outStr << "PACKETBUFFER_TRASH_HEAP:   "
		       << setw(6) << (this->blockStoreTrash_size / 1024 / 1024) << "MB" << endl;
	}
	return(outStr.str());
}

double PcapQueue_readFromFifo::pcapStat_get_memory_buffer_perc() {
	uint64_t useSize = this->pcapStoreQueue.sizeOfBlocksInMemory + this->blockStoreTrash_size;
	return(100. * useSize / opt_pcap_queue_store_queue_max_memory_size);
}

double PcapQueue_readFromFifo::pcapStat_get_memory_buffer_perc_trash() {
	uint64_t useSize = this->blockStoreTrash_size;
	return(100. * useSize / opt_pcap_queue_store_queue_max_memory_size);
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

bool PcapQueue_readFromFifo::socketWritePcapBlock(pcap_block_store *blockStore) {
	if(!this->socketHandle) {
		return(false);
	}
	size_t sizeSaveBuffer = blockStore->getSizeSaveBuffer();
	u_char *saveBuffer = blockStore->getSaveBuffer();
	bool rslt = this->socketWrite(saveBuffer, sizeSaveBuffer);
	free(saveBuffer);
	return(rslt);
}

bool PcapQueue_readFromFifo::socketGetHost() {
	this->socketHostEnt = NULL;
	while(!this->socketHostEnt) {
		this->socketHostEnt = gethostbyname(this->packetServer.c_str());
		if(!this->socketHostEnt) {
			syslog(LOG_ERR, "packetbuffer %s: cannot resolv: %s: host [%s] - trying again", this->nameQueue.c_str(), hstrerror(h_errno), this->packetServer.c_str());  
			sleep(1);
		}
	}
	if(DEBUG_VERBOSE) {
		cout << "socketGetHost [" << this->packetServer << "] : OK" << endl;
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
	addr.sin_port = htons(this->packetServerPort);
	addr.sin_addr.s_addr = *(long*)this->socketHostEnt->h_addr_list[0];
	while(connect(this->socketHandle, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		syslog(LOG_NOTICE, "packetbuffer %s: failed to connect to server [%s] error:[%s] - trying again", this->nameQueue.c_str(), inet_ntoa(*(struct in_addr *)this->socketHostEnt->h_addr_list[0]), strerror(errno));
		sleep(1);
	}
	if(DEBUG_VERBOSE) {
		cout << this->nameQueue << " - socketGetHost: " << this->packetServer << " : OK" << endl;
	}
	return(true);
}

bool PcapQueue_readFromFifo::socketListen() {
	if((this->socketHandle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		syslog(LOG_NOTICE, "packetbuffer %s: cannot create socket", this->nameQueue.c_str());
		return(false);
	}
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(this->packetServerPort);
	addr.sin_addr.s_addr = inet_addr(this->packetServer.c_str());
	int on = 1;
	setsockopt(this->socketHandle, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	int rsltListen;
	do {
		
		while(bind(this->socketHandle, (sockaddr*)&addr, sizeof(addr)) == -1) {
			syslog(LOG_ERR, "packetbuffer %s: cannot bind to port [%d] - trying again after 5 seconds intervals", this->nameQueue.c_str(), this->packetServerPort);
			sleep(5);
		}
		rsltListen = listen(this->socketHandle, 5);
		if(rsltListen == -1) {
			syslog(LOG_ERR, "packetbuffer %s: listen failed - retrying in 5 seconds intervals", this->nameQueue.c_str());
			sleep(5);
		}
	} while(rsltListen == -1);
	return(true);
}

bool PcapQueue_readFromFifo::socketAwaitConnection() {
	socklen_t addrlen = sizeof(this->socketClientInfo);
	this->socketClient = -1;
	while(this->socketClient < 0 && !TERMINATING) {
		this->socketClient = accept(this->socketHandle, (sockaddr*)&this->socketClientInfo, &addrlen);
		usleep(100000);
	}
	return(this->socketClient >= 0);
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

bool PcapQueue_readFromFifo::socketRead(u_char *data, size_t *dataLen) {
	ssize_t recvLen = recv(this->socketClient, data, *dataLen, 0);
	if(recvLen == -1) {
		*dataLen = 0;
		return(false);
	}
	*dataLen = recvLen;
	return(true);
}

void PcapQueue_readFromFifo::processPacket(pcap_pkthdr_plus *header_plus, u_char *packet,
					   pcap_block_store *block_store, int block_store_index) {
	iphdr2 *header_ip;
	tcphdr *header_tcp;
	udphdr2 *header_udp;
	udphdr2 header_udp_tmp;
	char *data = NULL;
	int datalen = 0;
	int istcp = 0;
	int was_rtp;
	bool useTcpReassembly = false;
	
	pcap_pkthdr *header = header_plus->convertToStdHeader();
	
	if(ipfilter_reload_do) {
		delete ipfilter;
		ipfilter = ipfilter_reload;
		ipfilter_reload = NULL;
		ipfilter_reload_do = 0; 
	}

	if(telnumfilter_reload_do) {
		delete telnumfilter;
		telnumfilter = telnumfilter_reload;
		telnumfilter_reload = NULL;
		telnumfilter_reload_do = 0; 
	}
	
	if(header_plus->offset < 0) {
		//// doplnit zjištění offsetu
	}
	
	header_ip = (iphdr2*)(packet + header_plus->offset);

	if(header_ip->protocol == 4) {
		// ip in ip protocol
		header_ip = (iphdr2*)((char*)header_ip + sizeof(iphdr2));
	}
	header_udp = &header_udp_tmp;
	if (header_ip->protocol == IPPROTO_UDP) {
		// prepare packet pointers 
		header_udp = (udphdr2*) ((char *) header_ip + sizeof(*header_ip));
		data = (char *) header_udp + sizeof(*header_udp);
		datalen = (int)(header->caplen - ((u_char*)data - packet));
		istcp = 0;
	} else if (header_ip->protocol == IPPROTO_TCP) {
		header_tcp = (tcphdr*) ((char *) header_ip + sizeof(*header_ip));
		if(opt_enable_tcpreassembly && (httpportmatrix[htons(header_tcp->source)] || httpportmatrix[htons(header_tcp->dest)])) {
			tcpReassembly->push(header, header_ip, packet,
					    block_store, block_store_index);
			useTcpReassembly = true;
		} else {
			istcp = 1;
			// prepare packet pointers 
			data = (char *) header_tcp + (header_tcp->doff * 4);
			datalen = (int)(header->caplen - ((u_char*)data - packet)); 
			header_udp->source = header_tcp->source;
			header_udp->dest = header_tcp->dest;
		}
	} else {
		//packet is not UDP and is not TCP, we are not interested, go to the next packet
		// - interested only for ipaccount
		if(opt_ipaccount) {
			ipaccount(header->ts.tv_sec, (iphdr2*) ((char*)(packet) + header_plus->offset), header->len - header_plus->offset, false);
		}
		return;
	}

	if(opt_mirrorip && (sipportmatrix[htons(header_udp->source)] || sipportmatrix[htons(header_udp->dest)])) {
		mirrorip->send((char *)header_ip, (int)(header->caplen - ((u_char*)header_ip - packet)));
	}
	int voippacket = 0;
	if(!useTcpReassembly && opt_enable_tcpreassembly != 2) {
		process_packet(header_ip->saddr, htons(header_udp->source), header_ip->daddr, htons(header_udp->dest), 
			data, datalen, this->getPcapHandle(), header, packet, istcp, 0, 1, &was_rtp, header_ip, &voippacket, 0,
			block_store, block_store_index);
	}

	// if packet was VoIP add it to ipaccount
	if(opt_ipaccount) {
		ipaccount(header->ts.tv_sec, (iphdr2*) ((char*)(packet) + header_plus->offset), header->len - header_plus->offset, voippacket);
	}
	
}

void PcapQueue_readFromFifo::cleanupBlockStoreTrash(bool all) {
	if(all && opt_enable_tcpreassembly && opt_pb_read_from_file[0]) {
		this->cleanupBlockStoreTrash();
		cout << "COUNT REST BLOCKS: " << this->blockStoreTrash.size() << endl;
	}
	for(size_t i = 0; i < this->blockStoreTrash.size(); i++) {
		if(all || this->blockStoreTrash[i]->enableDestroy()) {
			this->blockStoreTrash_size -= this->blockStoreTrash[i]->getUseSize();
			delete this->blockStoreTrash[i];
			this->blockStoreTrash.erase(this->blockStoreTrash.begin() + i);
			--i;
		}
	}
}
