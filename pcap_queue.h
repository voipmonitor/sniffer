#ifndef PCAP_QUEUE_H
#define PCAP_QUEUE_H


#include <memory.h>
#include <netdb.h>
#include <pthread.h>
#include <pcap.h>
#include <deque>
#include <queue>
#include <string>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/syscall.h>

#include "pcap_queue_block.h"
#include "md5.h"
#include "sniff.h"
#include "pstat.h"
#include "ip_frag.h"
#include "header_packet.h"

#define READ_THREADS_MAX 20
#define DLT_TYPES_MAX 10
#define PCAP_QUEUE_NEXT_THREADS_MAX 3

class pcap_block_store_queue {
public:
	pcap_block_store_queue();
	~pcap_block_store_queue();
	void push(pcap_block_store* blockStore) {
		if(this->queueBlock->push(&blockStore, true)) {
			this->add_sizeOfBlocks(blockStore->getUseSize());
		}
	}
	pcap_block_store* pop(bool removeFromFront = true, size_t blockSize = 0) {
		pcap_block_store* blockStore = NULL;
		if(this->queueBlock->get(&blockStore)) {
			if(removeFromFront) {
				this->queueBlock->moveReadit();
			}
		}
		if(blockStore && removeFromFront) {
			this->sub_sizeOfBlocks(blockSize ? blockSize : blockStore->getUseSize());
		}
		return(blockStore);
	}
	size_t getUseItems() {
		return(this->queueBlock->size());
	}	
	size_t getUseSize() {
		ssize_t sizeOfBlocks = this->sizeOfBlocks;
		return(max(sizeOfBlocks, (ssize_t)0));
	}
private:
	void add_sizeOfBlocks(size_t size) {
		while(__sync_lock_test_and_set(&this->sizeOfBlocks_sync, 1));
		this->sizeOfBlocks += size;
		__sync_lock_release(&this->sizeOfBlocks_sync);
	}
	void sub_sizeOfBlocks(size_t size) {
		while(__sync_lock_test_and_set(&this->sizeOfBlocks_sync, 1));
		this->sizeOfBlocks -= size;
		if(this->sizeOfBlocks < 0) {
			this->sizeOfBlocks = 0;
		}
		__sync_lock_release(&this->sizeOfBlocks_sync);
	}
private:
	rqueue_quick<pcap_block_store*> *queueBlock;
	volatile ssize_t sizeOfBlocks;
	volatile int sizeOfBlocks_sync;
};

class pcap_file_store {
public:
	enum eTypeHandle {
		typeHandlePush 	= 1,
		typeHandlePop 	= 2,
		typeHandleAll 	= 4
	};
public:
	pcap_file_store(u_int id = 0, const char *folder = NULL);
	~pcap_file_store();
	bool push(pcap_block_store *blockStore);
	bool pop(pcap_block_store *blockStore);
	bool isFull(bool forceSetFull = false) {
		if(this->full) {
			return(true);
		}
		extern size_t opt_pcap_queue_file_store_max_size;
		extern u_int opt_pcap_queue_file_store_max_time_ms;
		if(this->fileSize >= opt_pcap_queue_file_store_max_size ||
		   (this->fileSize && getTimeMS_rdtsc() > (this->timestampMS + opt_pcap_queue_file_store_max_time_ms)) ||
		   (this->fileSize && forceSetFull)) {
			this->close(typeHandlePush);
			this->full = true;
			return(true);
		}
		return(false);
	}
	bool isForDestroy() {
		return(this->full &&
		       this->countPush == this->countPop);
	}
	std::string getFilePathName();
private:
	bool open(eTypeHandle typeHandle);
	bool close(eTypeHandle typeHandle);
	bool destroy();
	void lock_sync_flush_file() {
		while(__sync_lock_test_and_set(&this->_sync_flush_file, 1));
	}
	void unlock_sync_flush_file() {
		__sync_lock_release(&this->_sync_flush_file);
	}
private:
	u_int id;
	std::string folder;
	FILE *fileHandlePush;
	FILE *fileHandlePop;
	u_char *fileBufferPush;
	u_char *fileBufferPop;
	size_t fileSize;
	size_t fileSizeFlushed;
	size_t countPush;
	size_t countPop;
	bool full;
	u_long timestampMS;
	volatile int _sync_flush_file;
friend class pcap_store_queue;
};

class pcap_store_queue {
public:
	pcap_store_queue(const char *fileStoreFolder);
	~pcap_store_queue();
	bool push(pcap_block_store *blockStore, bool deleteBlockStoreIfFail = true);
	bool pop(pcap_block_store **blockStore);
	size_t getQueueSize() {
		return(this->queueStore.size());
	}
	void init();
private:
	pcap_file_store *findFileStoreById(u_int id);
	void cleanupFileStore();
	uint64_t getFileStoreUseSize(bool lock = true);
	void lock_queue() {
		while(__sync_lock_test_and_set(&this->_sync_queue, 1));
	}
	void unlock_queue() {
		__sync_lock_release(&this->_sync_queue);
	}
	void lock_fileStore() {
		while(__sync_lock_test_and_set(&this->_sync_fileStore, 1));
	}
	void unlock_fileStore() {
		__sync_lock_release(&this->_sync_fileStore);
	}
	void add_sizeOfBlocksInMemory(size_t size) {
		extern cBuffersControl buffersControl;
		buffersControl.add__pcap_store_queue__sizeOfBlocksInMemory(size);
	}
	void sub_sizeOfBlocksInMemory(size_t size) {
		extern cBuffersControl buffersControl;
		buffersControl.sub__pcap_store_queue__sizeOfBlocksInMemory(size);
	}
private:
	std::string fileStoreFolder;
	std::deque<pcap_block_store*> queueStore;
	std::deque<pcap_file_store*> fileStore;
	u_int lastFileStoreId;
	volatile int _sync_queue;
	volatile int _sync_fileStore;
	int cleanupFileStoreCounter;
	u_long lastTimeLogErrDiskIsFull;
	u_long lastTimeLogErrMemoryIsFull;
friend class PcapQueue_readFromFifo;
};

enum eHeaderPacketPQoutState {
	_hppq_out_state_NA = 0,
	_hppq_out_state_defrag = 1,
	_hppq_out_state_dedup = 2
};

struct sHeaderPacketPQout {
	pcap_pkthdr_plus *header;
	u_char *packet;
	pcap_block_store *block_store;
	int block_store_index;
	int dlt; 
	int sensor_id; 
	u_int32_t sensor_ip;
	bool block_store_locked;
	void destroy_or_unlock_blockstore() {
		if(block_store) {
			if(block_store_locked) {
				block_store->unlock_packet(block_store_index);
				block_store_locked = false;
			}
		} else {
			delete header;
			delete [] packet;
		}
	}
	void alloc_and_copy_blockstore() {
		if(block_store) {
			pcap_pkthdr_plus *alloc_header = new FILE_LINE(16001) pcap_pkthdr_plus;
			u_char *alloc_packet = new FILE_LINE(16002) u_char[header->get_caplen()];
			memcpy(alloc_header, header, sizeof(pcap_pkthdr_plus));
			memcpy(alloc_packet, packet, header->get_caplen());
			header = alloc_header;
			packet = alloc_packet;
			if(block_store_locked) {
				block_store->unlock_packet(block_store_index);
				block_store_locked = false;
			}
			block_store = NULL;
			block_store_index = 0;
		}
	}
	inline void blockstore_addflag(int /*flag*/) {
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		if(block_store) {
			block_store->add_flag(block_store_index, flag);
		}
		#endif
	}
};

class PcapQueue {
public:
	enum eTypeQueue {
		readFromInterface,
		readFromFifo
	};
	enum eTypeThread {
		mainThread          = 0,
		writeThread         = 1,
		nextThread1         = 2,
		nextThread2         = 3,
		nextThread3         = 4,
		socketServerThread  = 2,
		destroyBlocksThread = 3
	};
	PcapQueue(eTypeQueue typeQueue, const char *nameQueue);
	virtual ~PcapQueue();
	void setEnableMainThread(bool enable = true);
	void setEnableWriteThread(bool enable = true);
	void setEnableAutoTerminate(bool enableAutoTerminate);
	bool start();
	virtual void terminate();
	bool isInitOk();
	bool isTerminated();
	void setInstancePcapHandle(PcapQueue *pcapQueue);
	void setInstancePcapFifo(class PcapQueue_readFromFifo *pcapQueue);
	inline pcap_t* getPcapHandle(int dlt);
	inline u_int16_t getPcapHandleIndex(int dlt);
	void pcapStat(int statPeriod = 1, bool statCalls = true);
	string pcapDropCountStat();
	void initStat();
	void getThreadCpuUsage(bool writeThread = false);
	bool threadInitIsOk() { return(threadInitOk); }
protected:
	virtual bool createThread();
	virtual bool createMainThread();
	virtual bool createWriteThread();
	virtual bool init() { return(true); };
	virtual bool initThread(void *arg, unsigned int arg2, string *error);
	virtual bool initWriteThread(void *arg, unsigned int arg2);
	virtual void *threadFunction(void *arg, unsigned int arg2) = 0;
	virtual void *writeThreadFunction(void */*arg*/, unsigned int /*arg2*/) { return(NULL); }
	virtual bool openFifoForRead(void */*arg*/, unsigned int /*arg2*/) { return(true); }
	virtual bool openFifoForWrite(void */*arg*/, unsigned int /*arg2*/) { return(true); }
	virtual pcap_t* _getPcapHandle(int /*dlt*/) { 
		extern pcap_t *global_pcap_handle;
		return(global_pcap_handle); 
	}
	virtual u_int16_t _getPcapHandleIndex(int /*dlt*/) { 
		extern u_int16_t global_pcap_handle_index;
		return(global_pcap_handle_index); 
	}
	virtual string pcapStatString_packets(int statPeriod);
	virtual double pcapStat_get_compress();
	virtual double pcapStat_get_speed_mb_s(int statPeriod);
	virtual string pcapStatString_bypass_buffer(int /*statPeriod*/) { return(""); }
	virtual unsigned long pcapStat_get_bypass_buffer_size_exeeded() { return(0); }
	virtual string pcapStatString_memory_buffer(int /*statPeriod*/) { return(""); }
	virtual string pcapStatString_disk_buffer(int /*statPeriod*/) { return(""); }
	virtual double pcapStat_get_disk_buffer_perc() { return(-1); }
	virtual double pcapStat_get_disk_buffer_mb() { return(-1); }
	virtual string pcapStatString_interface(int /*statPeriod*/) { return(""); }
	virtual string pcapDropCountStat_interface() { return(""); }
	virtual ulong getCountPacketDrop() { return(0); }
	virtual string getStatPacketDrop() { return(""); }
	virtual string pcapStatString_cpuUsageReadThreads(double *sumMax, int *countThreadsSumMax, int /*divide*/) { 
		if(sumMax) *sumMax = 0;
		if(countThreadsSumMax) *countThreadsSumMax = 0;
		return(""); 
	};
	virtual void initStat_interface() {};
	int getThreadPid(eTypeThread typeThread);
	pstat_data *getThreadPstatData(eTypeThread typeThread);
	void preparePstatData(eTypeThread typeThread = mainThread);
	void prepareProcPstatData();
	double getCpuUsagePerc(eTypeThread typeThread = mainThread, bool preparePstatData = false);
	virtual string getCpuUsage(bool /*writeThread*/ = false, bool /*preparePstatData*/ = false) { return(""); }
	long unsigned int getVsizeUsage(bool preparePstatData = false);
	long unsigned int getRssUsage(bool preparePstatData = false);
	virtual bool isMirrorSender() {
		return(false);
	}
	virtual bool isMirrorReceiver() {
		return(false);
	}
	inline void processBeforeAddToPacketBuffer(pcap_pkthdr* header,u_char* packet, u_int offset);
	virtual void prepareLogTraffic() {}
protected:
	eTypeQueue typeQueue;
	std::string nameQueue;
	pthread_t threadHandle;
	pthread_t writeThreadHandle;
	bool enableMainThread;
	bool enableWriteThread;
	bool enableAutoTerminate;
	volatile bool threadInitOk;
	bool threadInitFailed;
	bool writeThreadInitOk;
	bool threadTerminated;
	bool writeThreadTerminated;
	bool threadDoTerminate;
	int mainThreadId;
	int writeThreadId;
	int nextThreadsId[PCAP_QUEUE_NEXT_THREADS_MAX];
	pstat_data mainThreadPstatData[2];
	pstat_data writeThreadPstatData[2];
	pstat_data nextThreadsPstatData[PCAP_QUEUE_NEXT_THREADS_MAX][2];
	pstat_data procPstatData[2];
	bool initAllReadThreadsFinished;
protected:
	class PcapQueue_readFromFifo *instancePcapFifo;
private:
	u_char* packetBuffer;
	PcapQueue *instancePcapHandle;
	u_int64_t counter_calls_old;
	u_int64_t counter_calls_clean_old;
	u_int64_t counter_registers_old;
	u_int64_t counter_registers_clean_old;
	u_int64_t counter_sip_packets_old[2];
	u_int64_t counter_sip_register_packets_old;
	u_int64_t counter_sip_message_packets_old;
	u_int64_t counter_rtp_packets_old;
	u_int64_t counter_all_packets_old;
	u_long lastTimeLogErrPcapNextExNullPacket;
	u_long lastTimeLogErrPcapNextExErrorReading;
	u_long pcapStatCounter;
friend void *_PcapQueue_threadFunction(void *arg);
friend void *_PcapQueue_writeThreadFunction(void *arg);
};

struct pcapProcessData {
	pcapProcessData() {
		memset(this, 0, sizeof(pcapProcessData) - sizeof(ipfrag_data_s));
		extern int opt_dup_check;
		if(opt_dup_check) {
			this->prevmd5s = new FILE_LINE(16003) unsigned char[65536 * MD5_DIGEST_LENGTH]; // 1M
			memset(this->prevmd5s, 0, 65536 * MD5_DIGEST_LENGTH * sizeof(unsigned char));
		}
	}
	~pcapProcessData() {
		if(this->prevmd5s) {
			delete [] this->prevmd5s;
		}
		ipfrag_prune(0, true, &ipfrag_data, -1, 0);
	}
	sll_header *header_sll;
	ether_header *header_eth;
	iphdr2 *header_ip;
	tcphdr2 *header_tcp;
	udphdr2 *header_udp;
	udphdr2 header_udp_tmp;
	int protocol;
	u_int header_ip_offset;
	char *data;
	int datalen;
	int traillen;
	int istcp;
	int isother;
	unsigned char *prevmd5s;
	MD5_CTX ctx;
	u_int ipfrag_lastprune;
	ipfrag_data_s ipfrag_data;
};


class PcapQueue_readFromInterface_base {
public:
	struct sCheckProtocolData {
		sll_header *header_sll;
		ether_header *header_eth;
		u_int header_ip_offset;
		int protocol;
	};
public:
	PcapQueue_readFromInterface_base(const char *interfaceName = NULL);
	virtual ~PcapQueue_readFromInterface_base();
	void setInterfaceName(const char *interfaceName);
protected:
	virtual bool startCapture(string *error);
	inline int pcap_next_ex_iface(pcap_t *pcapHandle, pcap_pkthdr** header, u_char** packet,
				      bool checkProtocol = false, sCheckProtocolData *checkProtocolData = NULL);
	void restoreOneshotBuffer();
	inline int pcap_dispatch(pcap_t *pcapHandle);
	inline int pcapProcess(sHeaderPacket **header_packet, int pushToStack_queue_index,
			       pcap_block_store *block_store, int block_store_index,
			       int ppf);
	virtual string pcapStatString_interface(int statPeriod);
	virtual string pcapDropCountStat_interface();
	virtual ulong getCountPacketDrop();
	virtual string getStatPacketDrop();
	virtual void initStat_interface();
	virtual string getInterfaceName(bool simple = false);
	inline bool useOneshotBuffer() {
		return(libpcap_buffer);
	}
	inline void setOneshotBuffer(u_char *packet) {
		*libpcap_buffer = packet;
	}
	void terminatingAtEndOfReadPcap();
	virtual inline void tryForcePush() {}
protected:
	string interfaceName;
	bpf_u_int32 interfaceNet;
	bpf_u_int32 interfaceMask;
	pcap_t *pcapHandle;
	u_int16_t pcapHandleIndex;
	queue<pcap_t*> pcapHandlesLapsed;
	bool pcapEnd;
	bpf_program filterData;
	bool filterDataUse;
	pcap_dumper_t *pcapDumpHandle;
	u_int64_t pcapDumpLength;
	int pcapLinklayerHeaderType;
	size_t pcap_snaplen;
	pcapProcessData ppd;
private:
	int pcap_promisc;
	int pcap_timeout;
	int pcap_buffer_size;
	pcap_stat last_ps;
	u_long countPacketDrop;
	u_int64_t lastPacketTimeUS;
	u_long lastTimeLogErrPcapNextExNullPacket;
	u_long lastTimeLogErrPcapNextExErrorReading;
	int32_t libpcap_buffer_offset;
	u_char **libpcap_buffer;
	u_char *libpcap_buffer_old;
	u_int64_t packets_counter;
	ListIP *filter_ip;
};


/*
struct sHeaderPacket {
	sHeaderPacket(pcap_pkthdr *header = NULL, u_char *packet = NULL) {
		this->header = header;
		this->packet = packet;
	}
	inline void alloc(size_t snaplen) {
		header = new FILE_LINE(16004) pcap_pkthdr;
		packet = new FILE_LINE(16005) u_char[snaplen];
	}
	inline void free() {
		if(header) {
			delete header;
			header = NULL;
		}
		if(packet) {
			delete [] packet;
			packet = NULL;
		}
	}
	pcap_pkthdr *header;
	u_char *packet;
};

#define PcapQueue_HeaderPacketStack_add_max 5
#define PcapQueue_HeaderPacketStack_hp_max 100
class PcapQueue_HeaderPacketStack {
private:
	struct sHeaderPacketPool {
		void free_all() {
			for(u_int i = 0; i < PcapQueue_HeaderPacketStack_hp_max; i++) {
				hp[i].free();
			}
		}
		sHeaderPacket hp[PcapQueue_HeaderPacketStack_hp_max];
	};
public:
	PcapQueue_HeaderPacketStack(unsigned int size) {
		for(int ia = 0; ia < PcapQueue_HeaderPacketStack_add_max; ia++) {
			hpp_add_size[ia] = 0;
		}
		hpp_get_size = 0;
		stack = new FILE_LINE(16006) rqueue_quick<sHeaderPacketPool>(size, 0, 0, NULL, false, __FILE__, __LINE__);
	}
	~PcapQueue_HeaderPacketStack() {
		for(int ia = 0; ia < PcapQueue_HeaderPacketStack_add_max; ia++) {
			for(u_int i = 0; i < hpp_add_size[ia]; i++) {
				hpp_add[ia].hp[i].free();
			}
		}
		sHeaderPacket headerPacket;
		while(get_hp(&headerPacket)) {
			headerPacket.free();
		}
		delete stack;
	}
	bool add_hp(sHeaderPacket *headerPacket, int ia) {
		bool rslt = false;
		*(u_char*)(headerPacket->header) = 0;
		*(u_char*)(headerPacket->packet) = 0;
		if(hpp_add_size[ia] == PcapQueue_HeaderPacketStack_hp_max) {
			if(stack->push(&hpp_add[ia], false, true)) {
				hpp_add[ia].hp[0] = *headerPacket;
				hpp_add_size[ia] = 1;
				rslt = true;
			}
		} else {
			hpp_add[ia].hp[hpp_add_size[ia]] = *headerPacket;
			++hpp_add_size[ia];
			rslt = true;
		}
		return(rslt);
	}
	bool get_hp(sHeaderPacket *headerPacket) {
		bool rslt = false;
		if(hpp_get_size) {
			*headerPacket = hpp_get.hp[PcapQueue_HeaderPacketStack_hp_max - hpp_get_size];
			--hpp_get_size;
			rslt = true;
		} else {
			if(stack->pop(&hpp_get, false)) {
				*headerPacket = hpp_get.hp[0];
				hpp_get_size = PcapQueue_HeaderPacketStack_hp_max - 1;
				rslt = true;
			}
		}
		if(rslt &&
		   ((headerPacket->header && *(u_char*)(headerPacket->header)) ||
		    (headerPacket->packet && *(u_char*)(headerPacket->packet)))) {
			cout << "dupl in get_hp" << endl;
		}
		return(rslt);
	}
private:
	sHeaderPacketPool hpp_add[PcapQueue_HeaderPacketStack_add_max];
	u_int hpp_add_size[PcapQueue_HeaderPacketStack_add_max];
	sHeaderPacketPool hpp_get;
	u_int hpp_get_size;
	rqueue_quick<sHeaderPacketPool> *stack;
};
*/

class PcapQueue_readFromInterfaceThread : protected PcapQueue_readFromInterface_base {
public:
	enum eTypeInterfaceThread {
		read,
		detach,
		pcap_process,
		defrag,
		md1,
		md2,
		dedup,
		service
	};
	struct hpi {
		sHeaderPacket *header_packet;
	};
	struct hpi_batch {
		hpi_batch(uint32_t max_count) {
			this->max_count = max_count;
			this->hpis = new FILE_LINE(16007) hpi[max_count];
			memset(this->hpis, 0, sizeof(hpi) * max_count);
			count = 0;
			used = 0;
		}
		~hpi_batch() {
			for(unsigned i = 0; i < max_count; i++) {
				if(hpis[i].header_packet) {
					delete hpis[i].header_packet;
				}
			}
			delete [] hpis;
		}
		uint32_t max_count;
		hpi *hpis;
		volatile uint32_t count;
		volatile unsigned char used;
	};
	PcapQueue_readFromInterfaceThread(const char *interfaceName, eTypeInterfaceThread typeThread = read,
					  PcapQueue_readFromInterfaceThread *readThread = NULL,
					  PcapQueue_readFromInterfaceThread *prevThread = NULL);
	~PcapQueue_readFromInterfaceThread();
protected:
	inline void push(sHeaderPacket **header_packet);
	inline void push_block(pcap_block_store *block);
	inline void tryForcePush();
	inline hpi pop();
	inline hpi POP();
	inline pcap_block_store *pop_block();
	inline pcap_block_store *POP_BLOCK();
	u_int64_t getTime_usec() {
		if(!readIndex) {
			unsigned int _readIndex = readit % qringmax;
			if(qring[_readIndex]->used) {
				readIndex = _readIndex + 1;
				readIndexPos = 0;
				readIndexCount = qring[_readIndex]->count;
			}
		}
		if(readIndex && readIndexCount && readIndexPos < readIndexCount) {
			return(HPH(this->qring[readIndex - 1]->hpis[readIndexPos].header_packet)->ts.tv_sec * 1000000ull + 
			       HPH(this->qring[readIndex - 1]->hpis[readIndexPos].header_packet)->ts.tv_usec);
		}
		return(0);
	}
	u_int64_t getTIME_usec() {
		return(this->dedupThread ? this->dedupThread->getTime_usec() : this->getTime_usec());
	}
	unsigned getSize() {
		unsigned int _readit = readit;
		unsigned int _writeit = writeit;
		int size = _writeit >= _readit ? _writeit - _readit : _writeit + qringmax - _readit;
		return(size > 0 ? size : 0);
	}
	unsigned getSIZE() {
		return(this->dedupThread ? this->dedupThread->getSize() : this->getSize());
	}
	bool isTerminated() {
		return(this->threadTerminated);
	}
	void setForcePush() {
		this->force_push = true;
	}
	void setForcePUSH() {
		if(this->dedupThread) {
			this->dedupThread->setForcePush();
		} else {
			this->setForcePush();
		}
	}
	void cancelThread();
	inline void lock_detach_buffer(int index) {
		while(__sync_lock_test_and_set(&this->_sync_detachBuffer[index], 1)) usleep(10);
	}
	inline void unlock_detach_buffer(int index) {
		__sync_lock_release(&this->_sync_detachBuffer[index]);
	}
private:
	void *threadFunction(void *arg, unsigned int arg2);
	void threadFunction_blocks();
	void processBlock(pcap_block_store *block);
	void preparePstatData();
	double getCpuUsagePerc(bool preparePstatData = false);
	double getQringFillingPerc() {
		unsigned int _readit = readit;
		unsigned int _writeit = writeit;
		return(_writeit >= _readit ?
			(double)(_writeit - _readit) / qringmax * 100 :
			(double)(qringmax - _readit + _writeit) / qringmax * 100);
	}
	void terminate();
	const char *getTypeThreadName();
	void prepareLogTraffic();
	double getTraffic(int divide);
private:
	pthread_t threadHandle;
	int threadId;
	volatile int threadInitOk;
	bool threadInitFailed;
	hpi_batch **qring;
	pcap_block_store **qring_blocks;
	volatile int *qring_blocks_used;
	unsigned int qringmax;
	unsigned int readit;
	unsigned int writeit;
	unsigned int readIndex;
	unsigned int readIndexPos;
	unsigned int readIndexCount;
	unsigned int writeIndex;
	unsigned int writeIndexCount;
	volatile u_char *detachBuffer[2];
	volatile u_char *activeDetachBuffer;
	unsigned int detachBufferLength;
	unsigned int detachBufferWritePos;
	unsigned int detachBufferReadPos;
	int detachBufferActiveIndex;
	volatile int _sync_detachBuffer[2];
	unsigned int counter;
	unsigned int counter_pop_usleep;
	bool force_push;
	volatile bool threadTerminated;
	pstat_data threadPstatData[2];
	volatile int _sync_qring;
	eTypeInterfaceThread typeThread;
	PcapQueue_readFromInterfaceThread *readThread;
	PcapQueue_readFromInterfaceThread *detachThread;
	PcapQueue_readFromInterfaceThread *pcapProcessThread;
	PcapQueue_readFromInterfaceThread *defragThread;
	PcapQueue_readFromInterfaceThread *md1Thread;
	PcapQueue_readFromInterfaceThread *md2Thread;
	PcapQueue_readFromInterfaceThread *dedupThread;
	PcapQueue_readFromInterfaceThread *serviceThread;
	PcapQueue_readFromInterfaceThread *prevThread;
	bool threadDoTerminate;
	cHeaderPacketStack *headerPacketStackSnaplen;
	cHeaderPacketStack *headerPacketStackShort;
	unsigned headerPacketStackShortPacketLen;
	unsigned long allocCounter[2];
	unsigned long allocStackCounter[2];
	unsigned long long sumPacketsSize[3];
	bool prepareHeaderPacketPool; // experimental option
friend void *_PcapQueue_readFromInterfaceThread_threadFunction(void *arg);
friend class PcapQueue_readFromInterface;
};

class PcapQueue_readFromInterface : public PcapQueue, protected PcapQueue_readFromInterface_base {
public:
	PcapQueue_readFromInterface(const char *nameQueue);
	virtual ~PcapQueue_readFromInterface();
	void setInterfaceName(const char *interfaceName);
	void terminate();
	bool openPcap(const char *filename);
	bool isPcapEnd() {
		return(this->pcapEnd);
	}
protected:
	bool init();
	bool initThread(void *arg, unsigned int arg2, string *error);
	void *threadFunction(void *arg, unsigned int arg2);
	void threadFunction_blocks();
	void *writeThreadFunction(void *arg, unsigned int arg2);
	bool openFifoForWrite(void *arg, unsigned int arg2);
	bool startCapture(string *error);
	pcap_t* _getPcapHandle(int /*dlt*/) { 
		return(this->pcapHandle);
	}
	u_int16_t _getPcapHandleIndex(int /*dlt*/) { 
		return(this->pcapHandleIndex);
	}
	string pcapStatString_bypass_buffer(int statPeriod);
	unsigned long pcapStat_get_bypass_buffer_size_exeeded();
	string pcapStatString_interface(int statPeriod);
	string pcapDropCountStat_interface();
	virtual ulong getCountPacketDrop();
	virtual string getStatPacketDrop();
	void initStat_interface();
	string pcapStatString_cpuUsageReadThreads(double *sumMax, int *countThreadsSumMax, int divide);
	string getInterfaceName(bool simple = false);
	void prepareLogTraffic();
private:
	inline void check_bypass_buffer();
	inline void push_blockstore(pcap_block_store **block_store);
	inline pcap_block_store *new_blockstore(int index_read_thread);
protected:
	PcapQueue_readFromInterfaceThread *readThreads[READ_THREADS_MAX];
	int readThreadsCount;
	int lastReadThreadsIndex_pcapStatString_interface;
	u_long lastTimeLogErrThread0BufferIsFull;
private:
	rqueue_quick<pcap_block_store*> *block_qring;
};

class PcapQueue_readFromFifo : public PcapQueue {
public:
	enum ePacketServerDirection {
		directionNA,
		directionRead,
		directionWrite
	};
	struct sPacketServerConnection {
		sPacketServerConnection(int socketClient, sockaddr_in &socketClientInfo, PcapQueue_readFromFifo *parent, unsigned int id) {
			this->socketClient = socketClient;
			this->socketClientInfo = socketClientInfo;
			this->parent = parent;
			this->id = id;
			this->active = false;
			this->threadHandle = 0;
			this->threadId = 0;
			memset(this->threadPstatData, 0, sizeof(this->threadPstatData));
			this->block_counter = 0;
		}
		~sPacketServerConnection() {
			if(this->socketClient) {
				close(this->socketClient);
			}
		}
		int socketClient;
		sockaddr_in socketClientInfo;
		string socketClientIP;
		u_int32_t socketClientIPN;
		PcapQueue_readFromFifo *parent;
		unsigned int id;
		bool active;
		pthread_t threadHandle;
		int threadId;
		pstat_data threadPstatData[2];
		u_int32_t block_counter;
	};
	struct sPacketTimeInfo {
		pcap_block_store *blockStore;
		size_t blockStoreIndex;
		pcap_pkthdr_plus *header;
		u_char *packet;
		u_int64_t utime;
		u_int64_t at;
	};
	struct sBlockInfo {
		pcap_block_store *blockStore;
		size_t count_processed;
		u_int64_t utime_first;
		u_int64_t utime_last;
		u_int64_t at;
	};
public:
	PcapQueue_readFromFifo(const char *nameQueue, const char *fileStoreFolder);
	virtual ~PcapQueue_readFromFifo();
	void setPacketServer(ip_port ipPort, ePacketServerDirection direction);
	size_t getQueueSize() {
		return(this->pcapStoreQueue.getQueueSize());
	}
	bool addBlockStoreToPcapStoreQueue(u_char *buffer, size_t bufferLen, string *error, string *warning, u_int32_t *block_counter);
	inline void addBlockStoreToPcapStoreQueue(pcap_block_store *blockStore);
	inline unsigned long long getLastUS() {
		return(getTimeUS(_last_ts));
	}
protected:
	bool createThread();
	bool createDestroyBlocksThread();
	bool createSocketServerThread();
	bool initThread(void *arg, unsigned int arg2, string *error);
	void *threadFunction(void *arg, unsigned int arg2);
	void *writeThreadFunction(void *arg, unsigned int arg2);
	void *destroyBlocksThreadFunction(void *arg, unsigned int arg2);
	bool openFifoForRead(void *arg, unsigned int arg2);
	bool openFifoForWrite(void *arg, unsigned int arg2);
	bool openPcapDeadHandle(int dlt);
	pcap_t* _getPcapHandle(int dlt) {
		return(__getPcapHandle(dlt, NULL));
	}
	u_int16_t _getPcapHandleIndex(int dlt) {
		u_int16_t index = 0;
		__getPcapHandle(dlt, &index);
		return(index);
	}
	pcap_t* __getPcapHandle(int dlt, u_int16_t *index) {
		extern pcap_t *global_pcap_handle;
		extern u_int16_t global_pcap_handle_index;
		if(this->pcapDeadHandles_count) {
			if(!dlt) {
				if(index) {
					*index = this->pcapDeadHandlesIndex[0];
				}
				return(this->pcapDeadHandles[0]);
			}
			for(int i = 0; i < this->pcapDeadHandles_count; i++) {
				if(this->pcapDeadHandles_dlt[i] == dlt) {
					if(index) {
						*index = this->pcapDeadHandlesIndex[i];
					}
					return(this->pcapDeadHandles[i]);
				}
			}
			if(openPcapDeadHandle(dlt)) {
				if(index) {
					*index = this->pcapDeadHandlesIndex[this->pcapDeadHandles_count - 1];
				}
				return(this->pcapDeadHandles[this->pcapDeadHandles_count - 1]);
			} else {
				return(NULL);
			}
		}
		if(index) {
			*index = global_pcap_handle_index;
		}
		return(global_pcap_handle);
	}
	
	string pcapStatString_memory_buffer(int statPeriod);
	double pcapStat_get_memory_buffer_perc();
	double pcapStat_get_memory_buffer_perc_trash();
	string pcapStatString_disk_buffer(int statPeriod);
	double pcapStat_get_disk_buffer_perc();
	double pcapStat_get_disk_buffer_mb();
	string getCpuUsage(bool writeThread = false, bool preparePstatData = false);
	bool socketWritePcapBlock(pcap_block_store *blockStore);
	bool socketWritePcapBlockBySnifferClient(pcap_block_store *blockStore);
	bool socketGetHost();
	bool socketReadyForConnect();
	bool socketConnect();
	bool socketListen();
	bool socketAwaitConnection(int *socketClient, sockaddr_in *socketClientInfo);
	bool socketClose();
	bool socketWrite(u_char *data, size_t dataLen, bool disableAutoConnect = false);
	bool _socketWrite(int socket, u_char *data, size_t *dataLen, int timeout = 1);
	bool socketRead(u_char *data, size_t *dataLen, int idConnection);
	bool _socketRead(int socket, u_char *data, size_t *dataLen, int timeout = 1);
	bool isMirrorSender() {
		return(this->packetServerDirection == directionWrite || is_client_packetbuffer_sender());
	}
	bool isMirrorReceiver() {
		return(this->packetServerDirection == directionRead);
	}
private:
	void createConnection(int socketClient, sockaddr_in *socketClientInfo);
	void cleanupConnections(bool all = false);
	inline int processPacket(sHeaderPacketPQout *hp, eHeaderPacketPQoutState hp_state);
	void pushBatchProcessPacket();
	void checkFreeSizeCachedir();
	void cleanupBlockStoreTrash(bool all = false);
	void lock_packetServerConnections() {
		while(__sync_lock_test_and_set(&this->_sync_packetServerConnections, 1));
	}
	void unlock_packetServerConnections() {
		__sync_lock_release(&this->_sync_packetServerConnections);
	}
	void blockStoreTrashPush(pcap_block_store *block) {
		lock_blockStoreTrash();
		this->blockStoreTrash.push_back(block);
		unlock_blockStoreTrash();
	}
	void lock_blockStoreTrash() {
		while(__sync_lock_test_and_set(&this->blockStoreTrash_sync, 1));
	}
	void unlock_blockStoreTrash() {
		__sync_lock_release(&this->blockStoreTrash_sync);
	}
protected:
	ip_port packetServerIpPort;
	ePacketServerDirection packetServerDirection;
	pcap_t *pcapDeadHandles[DLT_TYPES_MAX];
	u_int16_t pcapDeadHandlesIndex[DLT_TYPES_MAX];
	int pcapDeadHandles_dlt[DLT_TYPES_MAX];
	int pcapDeadHandles_count;
	pthread_t destroyBlocksThreadHandle;
	pthread_t socketServerThreadHandle;
private:
	pcap_store_queue pcapStoreQueue;
	deque<pcap_block_store*> blockStoreTrash;
	u_int cleanupBlockStoreTrash_counter;
	volatile int blockStoreTrash_sync;
	u_int32_t socketHostIPl;
	int socketHandle;
	cSocketBlock *clientSocket;
	map<unsigned int, sPacketServerConnection*> packetServerConnections;
	volatile int _sync_packetServerConnections;
	u_long lastCheckFreeSizeCachedir_timeMS;
	volatile timeval _last_ts;
	u_int32_t block_counter;
friend void *_PcapQueue_readFromFifo_destroyBlocksThreadFunction(void *arg);
friend void *_PcapQueue_readFromFifo_socketServerThreadFunction(void *arg);
friend void *_PcapQueue_readFromFifo_connectionThreadFunction(void *arg);
friend class PcapQueue_outputThread;
};

class PcapQueue_outputThread {
public:
	enum eTypeOutputThread {
		defrag,
		dedup
	};
	struct sBatchHP {
		sBatchHP(unsigned max_count) {
			count = 0;
			used = 0;
			batch = new FILE_LINE(16008) sHeaderPacketPQout[max_count];
			this->max_count = max_count;
		}
		~sBatchHP() {
			delete [] batch;
		}
		sHeaderPacketPQout *batch;
		volatile unsigned count;
		volatile int used;
		unsigned max_count;
	};
	PcapQueue_outputThread(eTypeOutputThread typeOutputThread, PcapQueue_readFromFifo *pcapQueue);
	~PcapQueue_outputThread();
	void start();
	void stop();
	void terminate() {
		this->stop();
	}
	inline void push(sHeaderPacketPQout *hp);
	void push_batch();
	void *outThreadFunction();
	inline void processDefrag(sHeaderPacketPQout *hp);
	inline void processDedup(sHeaderPacketPQout *hp);
	string getNameOutputThread() {
		switch(typeOutputThread) {
		case defrag:
			return("defrag");
		case dedup:
			return("dedup");
		}
		return("");
	}
	void preparePstatData();
	double getCpuUsagePerc(bool preparePstatData);
private:
	eTypeOutputThread typeOutputThread;
	PcapQueue_readFromFifo *pcapQueue;
	unsigned int qring_batch_item_length;
	unsigned int qring_length;
	sBatchHP **qring;
	unsigned qring_push_index;
	unsigned qring_push_index_count;
	sBatchHP *qring_active_push_item;
	volatile unsigned int readit;
	volatile unsigned int writeit;
	pthread_t out_thread_handle;
	pstat_data threadPstatData[2];
	int outThreadId;
	ipfrag_data_s ipfrag_data;
	unsigned ipfrag_lastprune;
	unsigned defrag_counter;
	u_char *dedup_buffer;
	volatile bool initThreadOk;
	volatile bool terminatingThread;
friend inline void *_PcapQueue_outputThread_outThreadFunction(void *arg);
};


void PcapQueue_init();
void PcapQueue_term();
int getThreadingMode();
void setThreadingMode(int threadingMode);

u_int16_t register_pcap_handle(pcap_t *handle);
inline pcap_t *get_pcap_handle(u_int16_t index) {
	extern pcap_t *pcap_handles[65535];
	if(index) {
		return(pcap_handles[index]);
	}
	extern pcap_t *global_pcap_handle;
	return(global_pcap_handle);
}


#endif
