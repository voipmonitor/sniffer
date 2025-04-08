#ifndef PCAP_QUEUE_H
#define PCAP_QUEUE_H


#include <memory.h>
#include <netdb.h>
#include <pthread.h>
#include <pcap.h>
#include <deque>
#include <queue>
#include <string>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/syscall.h>

#include "pcap_queue_block.h"
#include "md5.h"
#include "sniff.h"
#include "pstat.h"
#include "ip_frag.h"
#include "header_packet.h"
#include "dpdk.h"

#define READ_THREADS_MAX 20
#define DLT_TYPES_MAX 10
#define PCAP_QUEUE_NEXT_THREADS_MAX 3

#define PSTAT_MAIN 0


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
		__SYNC_LOCK(this->sizeOfBlocks_sync);
		this->sizeOfBlocks += size;
		__SYNC_UNLOCK(this->sizeOfBlocks_sync);
	}
	void sub_sizeOfBlocks(size_t size) {
		__SYNC_LOCK(this->sizeOfBlocks_sync);
		this->sizeOfBlocks -= size;
		if(this->sizeOfBlocks < 0) {
			this->sizeOfBlocks = 0;
		}
		__SYNC_UNLOCK(this->sizeOfBlocks_sync);
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
		__SYNC_LOCK(this->_sync_flush_file);
	}
	void unlock_sync_flush_file() {
		__SYNC_UNLOCK(this->_sync_flush_file);
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
	u_int64_t timestampMS;
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
	void memoryBufferIsFull_log();
	void diskBufferIsFull_log();
	void lock_queue() {
		__SYNC_LOCK(this->_sync_queue);
	}
	void unlock_queue() {
		__SYNC_UNLOCK(this->_sync_queue);
	}
	void lock_fileStore() {
		__SYNC_LOCK(this->_sync_fileStore);
	}
	void unlock_fileStore() {
		__SYNC_UNLOCK(this->_sync_fileStore);
	}
private:
	std::string fileStoreFolder;
	std::deque<pcap_block_store*> queueStore;
	std::deque<pcap_file_store*> fileStore;
	u_int lastFileStoreId;
	volatile int _sync_queue;
	volatile int _sync_fileStore;
	int cleanupFileStoreCounter;
	u_int64_t lastTimeLogErrDiskIsFull;
	u_int64_t lastTimeLogErrMemoryIsFull;
	u_int64_t firstTimeLogErrMemoryIsFull;
friend class PcapQueue_readFromFifo;
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
	enum pcapStatTask {
		pcapStatLog,
		pcapStatCpuCheck
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
	PcapQueue_readFromFifo *getInstancePcapFifo() {
		return(instancePcapFifo);
	}
	inline pcap_t* getPcapHandle(int dlt);
	inline u_int16_t getPcapHandleIndex(int dlt);
	void pcapStat(pcapStatTask task, int statPeriod = 1);
	string pcapDropCountStat();
	string externalError;
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
	#if LOG_PACKETS_PER_SEC
	virtual u_int64_t pcapStat_get_speed_packets_s(int statPeriod);
	#endif
	virtual double pcapStat_get_speed_out_mb_s(int statPeriod);
	#if LOG_PACKETS_PER_SEC
	virtual u_int64_t pcapStat_get_speed_out_packets_s(int statPeriod);
	#endif
	virtual unsigned long pcapStat_get_bypass_buffer_size_exeeded() { return(0); }
	virtual double pcapStat_get_disk_buffer_perc() { return(-1); }
	virtual double pcapStat_get_disk_buffer_mb() { return(-1); }
	virtual string pcapStatString_interface(int /*statPeriod*/) { return(""); }
	virtual string pcapDropCountStat_interface() { return(""); }
	virtual ulong getCountPacketDrop() { return(0); }
	virtual string getStatPacketDrop() { return(""); }
	virtual string pcapStatString_cpuUsageReadThreads(double *sumMax, int *countThreadsSumMax, int /*divide*/, int /*pstatDataIndex*/) { 
		if(sumMax) *sumMax = 0;
		if(countThreadsSumMax) *countThreadsSumMax = 0;
		return(""); 
	};
	virtual void initStat_interface() {};
	int getThreadPid(eTypeThread typeThread);
	pstat_data *getThreadPstatData(eTypeThread typeThread, int pstatDataIndex);
	void preparePstatData(eTypeThread typeThread, int pstatDataIndex);
	void prepareProcPstatData();
	double getCpuUsagePerc(eTypeThread typeThread, int pstatDataIndex, bool preparePstatData = true);
	virtual string getCpuUsage(bool /*writeThread*/, int /*pstatDataIndex*/, bool /*preparePstatData*/ = true) { return(""); }
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
	pstat_data mainThreadPstatData[2][2];
	pstat_data writeThreadPstatData[2][2];
	pstat_data nextThreadsPstatData[PCAP_QUEUE_NEXT_THREADS_MAX][2][2];
	pstat_data procPstatData[2];
	bool initAllReadThreadsFinished;
protected:
	class PcapQueue_readFromFifo *instancePcapFifo;
private:
	u_char* packetBuffer;
	PcapQueue *instancePcapHandle;
	u_int64_t counter_calls_old;
	u_int64_t counter_calls_clean_old;
	u_int64_t counter_calls_save_1_old;
	u_int64_t counter_calls_save_2_old;
	u_int64_t counter_registers_old;
	u_int64_t counter_registers_clean_old;
	u_int64_t counter_sip_packets_old[2];
	u_int64_t counter_sip_register_packets_old;
	u_int64_t counter_sip_message_packets_old;
	u_int64_t counter_rtp_packets_old[2];
	u_int64_t counter_all_packets_old;
	u_int64_t counter_user_packets_old[5];
	u_int64_t lastTimeLogErrPcapNextExNullPacket;
	u_int64_t lastTimeLogErrPcapNextExErrorReading;
	u_long pcapStatLogCounter;
	u_long pcapStatCpuCheckCounter;
friend void *_PcapQueue_threadFunction(void *arg);
friend void *_PcapQueue_writeThreadFunction(void *arg);
};

struct pcapProcessData {
	pcapProcessData() {
		null();
		extern int opt_dup_check_type;
		if(opt_dup_check_type != _dedup_na) {
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
			this->dedup_buffer_ct_md5 = new FILE_LINE(0) cPacketDuplBuffer(cPacketDuplBuffer::_hashtable, _dedup_md5);
			#endif
		}
		#if not DEFRAG_MOD_OLDVER
		extern int opt_udpfrag;
		if(opt_udpfrag) {
			ip_defrag = new FILE_LINE(0) cIpFrag();
		} else {
			ip_defrag = NULL;
		}
		#endif
	}
	~pcapProcessData() {
		if(this->dedup_buffer) {
			delete this->dedup_buffer;
		}
		#if DEDUPLICATE_COLLISION_TEST
		if(this->dedup_buffer_ct_md5) {
			delete this->dedup_buffer_ct_md5;
		}
		#endif
		extern int opt_udpfrag;
		if(opt_udpfrag) {
			#if not DEFRAG_MOD_OLDVER
			delete ip_defrag;
			#else
			ipfrag_prune(0, true, &ipfrag_data, -1, 0);
			#endif
		}
	}
	void null() {
		int not_null_size = 0;
		not_null_size += sizeof(dedup_buffer);
		#if DEDUPLICATE_COLLISION_TEST
		not_null_size += sizeof(dedup_buffer_ct_md5);
		#endif
		#if not DEFRAG_MOD_OLDVER
		not_null_size += sizeof(ip_defrag);
		#else
		not_null_size += sizeof(ipfrag_data_s);
		#endif
		memset((void*)this, 0, sizeof(pcapProcessData) - not_null_size);
	}
	ether_header *header_eth;
	iphdr2 *header_ip;
	tcphdr2 *header_tcp;
	udphdr2 *header_udp;
	udphdr2 header_udp_tmp;
	u_int16_t protocol;
	u_int16_t header_ip_encaps_offset;
	u_int16_t header_ip_offset;
	char *data;
	int16_t datalen;
	int16_t traillen;
	packet_flags flags;
	sPacketInfoData pid;
	u_int ipfrag_lastprune;
	cPacketDuplBuffer *dedup_buffer;
	#if DEDUPLICATE_COLLISION_TEST
	cPacketDuplBuffer *dedup_buffer_ct_md5;
	#endif
	#if not DEFRAG_MOD_OLDVER
	cIpFrag *ip_defrag;
	#else
	ipfrag_data_s ipfrag_data;
	#endif
};

class PcapQueue_readFromInterface_base {
public:
public:
	struct sInterface {
		string interface;
		string alias;
		string filter;
	};
	struct sCheckProtocolData {
		sll_header *header_sll;
		ether_header *header_eth;
		u_int16_t header_ip_offset;
		u_int16_t protocol;
		u_int16_t vlan;
	};
public:
	PcapQueue_readFromInterface_base(sInterface *interface = NULL);
	virtual ~PcapQueue_readFromInterface_base();
protected:
	virtual bool startCapture(string *error, sDpdkConfig *dpdkConfig);
	inline int pcap_next_ex_iface(pcap_t *pcapHandle, pcap_pkthdr** header, u_char** packet,
				      bool checkProtocol = false, sCheckProtocolData *checkProtocolData = NULL);
	inline bool check_protocol(pcap_pkthdr* header, u_char* packet, sCheckProtocolData *checkProtocolData);
	inline bool check_filter_ip(pcap_pkthdr* header, u_char* packet, sCheckProtocolData *checkProtocolData);
	void restoreOneshotBuffer();
	inline int pcap_dispatch(pcap_t *pcapHandle);
	inline int pcapProcess(sHeaderPacket **header_packet, int pushToStack_queue_index,
			       pcap_block_store *block_store, int block_store_index,
			       int ppf, pcap_dumper_t *pcapDumpHandle = NULL);
	virtual string pcapStatString_interface(int statPeriod);
	virtual string pcapDropCountStat_interface();
	virtual ulong getCountPacketDrop();
	virtual string getStatPacketDrop();
	virtual void initStat_interface();
	virtual string getInterface();
	virtual string getInterfaceAlias();
	inline bool useOneshotBuffer() {
		return(libpcap_buffer);
	}
	inline void setOneshotBuffer(u_char *packet) {
		*libpcap_buffer = packet;
	}
	void terminatingAtEndOfReadPcap();
	virtual inline void tryForcePush() {}
protected:
	string interfaces;
	vector<dstring> filtersByInterface;
	sInterface interface;
	bpf_u_int32 interfaceNet;
	bpf_u_int32 interfaceMask;
	pcap_t *pcapHandle;
	u_int16_t pcapHandleIndex;
	queue<pcap_t*> pcapHandlesLapsed;
	bool pcapEnd;
	sDpdkHandle *dpdkHandle;
	bpf_program filterData;
	bool filterDataUse;
	pcap_dumper_t *pcapDumpHandle;
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
	u_int64_t lastTimeLogErrPcapNextExNullPacket;
	u_int64_t lastTimeLogErrPcapNextExErrorReading;
	int32_t libpcap_buffer_offset;
	u_char **libpcap_buffer;
	u_char *libpcap_buffer_old;
	u_int64_t packets_counter;
	bool filter_ip;
	cQuickIPfilter *filter_ip_quick;
	ListIP *filter_ip_std;
	unsigned read_from_file_index;
	#if EXPERIMENTAL_CHECK_PCAP_TIME
	int64_t lastPcapTime_s;
	u_int64_t lastTimeErrorLogPcapTime_ms;
	#endif
	u_int64_t firstTimeErrorLogEtherTypeFFFF_ms;
	u_int64_t counterErrorLogEtherTypeFFFF_ms;
friend class PcapQueue_readFromInterfaceThread;
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
		dpdk_worker,
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
	struct pcap_dispatch_data {
		pcap_dispatch_data() {
			memset(this, 0, sizeof(*this));
		}
		PcapQueue_readFromInterfaceThread *me;
		pcap_block_store *block;
		volatile pcap_block_store *next_free_block; 
		volatile pcap_block_store *last_full_block;
		pcap_block_store *copy_block[2];
		#if DPDK_DEBUG
		void *copy_block_block_orig[2];
		#endif
		volatile int copy_block_full[2];
		volatile int copy_block_active_index;
		pcap_pkthdr_plus2 *pcap_header_plus2;
		u_char *pcap_packet;
		sCheckProtocolData checkProtocolData;
		sDpdkHeaderPacket headerPacket;
	};
	PcapQueue_readFromInterfaceThread(sInterface interface, eTypeInterfaceThread typeThread = read,
					  PcapQueue_readFromInterfaceThread *readThread = NULL,
					  PcapQueue_readFromInterfaceThread *prevThread = NULL,
					  class PcapQueue_readFromInterface *parent = NULL);
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
			return(getTimeUS(HPH(this->qring[readIndex - 1]->hpis[readIndexPos].header_packet)));
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
		return(this->dedupThread ? this->dedupThread->getSize() : 
		       this->pcapProcessThread ? this->pcapProcessThread->getSize() :
		       this->getSize());
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
		__SYNC_LOCK_USLEEP(this->_sync_detachBuffer[index], 10);
	}
	inline void unlock_detach_buffer(int index) {
		__SYNC_UNLOCK(this->_sync_detachBuffer[index]);
	}
private:
	void *threadFunction(void *arg, unsigned int arg2);
	void threadFunction_blocks();
	inline static void _pcap_dispatch_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
		pcap_dispatch_data *dd = (PcapQueue_readFromInterfaceThread::pcap_dispatch_data*)user;
		dd->me->pcap_dispatch_handler(dd, header, packet);
	}
	void pcap_dispatch_handler(pcap_dispatch_data *dd, const struct pcap_pkthdr *header, const u_char *packet);
	inline static u_char* _dpdk_packet_allocation(void *user, u_int32_t caplen) {
		PcapQueue_readFromInterfaceThread::pcap_dispatch_data *dd = (PcapQueue_readFromInterfaceThread::pcap_dispatch_data*)user;
		return(dd->me->dpdk_packet_allocation(dd, caplen));
	}
	u_char* dpdk_packet_allocation(pcap_dispatch_data *dd, u_int32_t caplen);
	inline static void _dpdk_packet_completion(void *user, pcap_pkthdr *pcap_header, u_char *packet) {
		PcapQueue_readFromInterfaceThread::pcap_dispatch_data *dd = (PcapQueue_readFromInterfaceThread::pcap_dispatch_data*)user;
		dd->me->dpdk_packet_completion(dd, pcap_header, packet);
	}
	inline void dpdk_packet_completion(pcap_dispatch_data *dd, pcap_pkthdr *pcap_header, u_char *packet) {
		if(_packet_completion(pcap_header, packet, dd->pcap_header_plus2, &dd->checkProtocolData)) {
			sumPacketsSize[0] += pcap_header->caplen;
			dd->block->inc_h(dd->pcap_header_plus2);
		#if DPDK_DEBUG
		} else {
			cout << "bad packet" << endl;
		#endif
		}
	}
	inline static bool _dpdk_packet_completion_plus(void *user, pcap_pkthdr *pcap_header, u_char *packet, void *pcap_header_plus2,
							void *checkProtocolData) {
		PcapQueue_readFromInterfaceThread::pcap_dispatch_data *dd = (PcapQueue_readFromInterfaceThread::pcap_dispatch_data*)user;
		return(dd->me->dpdk_packet_completion_plus(dd, pcap_header, packet, (pcap_pkthdr_plus2*)pcap_header_plus2,
							   (PcapQueue_readFromInterface_base::sCheckProtocolData*)checkProtocolData));
	}
	inline bool dpdk_packet_completion_plus(pcap_dispatch_data *dd, pcap_pkthdr *pcap_header, u_char *packet, pcap_pkthdr_plus2 *pcap_header_plus2,
						PcapQueue_readFromInterface_base::sCheckProtocolData *checkProtocolData) {
		if(!_packet_completion(pcap_header, packet, pcap_header_plus2, checkProtocolData)) {
			pcap_header_plus2->clear_ext();
			pcap_header_plus2->ignore = true;
			#if DPDK_DEBUG
			cout << "bad packet" << endl;
			#endif
			return(false);

		}
		return(true);
	}
	bool _packet_completion(pcap_pkthdr *pcap_header, u_char *packet, pcap_pkthdr_plus2 *pcap_header_plus2,
				sCheckProtocolData *checkProtocolData);
	inline static void _dpdk_packet_process(void *user, u_int32_t caplen) {
		PcapQueue_readFromInterfaceThread::pcap_dispatch_data *dd = (PcapQueue_readFromInterfaceThread::pcap_dispatch_data*)user;
		dd->me->dpdk_packet_process(dd, caplen);
	}
	void dpdk_packet_process(pcap_dispatch_data *dd, u_int32_t caplen);
	inline static void _dpdk_packets_get_pointers(void *user, u_int32_t start, u_int32_t max, u_int32_t *pkts_len, u_int32_t snaplen,
						      void **headers, void **packets, u_int32_t *count, bool *filled) {
		PcapQueue_readFromInterfaceThread::pcap_dispatch_data *dd = (PcapQueue_readFromInterfaceThread::pcap_dispatch_data*)user;
		dd->me->dpdk_packets_get_pointers(dd, start, max, pkts_len, snaplen,
						  headers, packets, count, filled);
	}
	void dpdk_packets_get_pointers(pcap_dispatch_data *dd, u_int32_t start, u_int32_t max, u_int32_t *pkts_len, u_int32_t snaplen,
				       void **headers, void **packets, u_int32_t *count, bool *filled);
	inline static void _dpdk_packets_push(void *user) {
		PcapQueue_readFromInterfaceThread::pcap_dispatch_data *dd = (PcapQueue_readFromInterfaceThread::pcap_dispatch_data*)user;
		dd->me->dpdk_packets_push(dd);
	}
	inline void dpdk_packets_push(pcap_dispatch_data *dd) {
		#if DPDK_DEBUG
		cout << " * dpdk_packets_push "
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
			printf("wait for send no-active block\n");
			while(dd->copy_block_full[copy_block_no_active_index]) {
				USLEEP(1);
			}
		}
		dd->block = dd->copy_block[copy_block_no_active_index];
		dd->copy_block_active_index = copy_block_no_active_index;
	}
	inline static void _dpdk_packet_process__mbufs_in_packetbuffer(void *user, pcap_pkthdr *pcap_header, void *mbuf) {
		PcapQueue_readFromInterfaceThread::pcap_dispatch_data *dd = (PcapQueue_readFromInterfaceThread::pcap_dispatch_data*)user;
		dd->me->dpdk_packet_process__mbufs_in_packetbuffer(dd, pcap_header, mbuf);
	}
	void dpdk_packet_process__mbufs_in_packetbuffer(pcap_dispatch_data *dd, pcap_pkthdr *pcap_header, void *mbuf);
	inline static void _dpdk_check_block(void *user, unsigned pos, unsigned count) {
		PcapQueue_readFromInterfaceThread::pcap_dispatch_data *dd = (PcapQueue_readFromInterfaceThread::pcap_dispatch_data*)user;
		dd->me->dpdk_check_block(dd, pos, count);
	}
	bool dpdk_check_block(pcap_dispatch_data *dd, unsigned pos, unsigned count, bool only_check = false);
	void processBlock(pcap_block_store *block);
	void preparePstatData(int pstatDataIndex);
	double getCpuUsagePerc(int pstatDataIndex, bool preparePstatData = true);
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
	unsigned long pop_usleep_sum;
	unsigned long pop_usleep_sum_last_push;
	bool force_push;
	volatile bool threadTerminated;
	pstat_data threadPstatData[2][2];
	volatile int _sync_qring;
	eTypeInterfaceThread typeThread;
	PcapQueue_readFromInterfaceThread *readThread;
	PcapQueue_readFromInterfaceThread *dpdkWorkerThread;
	PcapQueue_readFromInterfaceThread *detachThread;
	PcapQueue_readFromInterfaceThread *pcapProcessThread;
	PcapQueue_readFromInterfaceThread *defragThread;
	PcapQueue_readFromInterfaceThread *md1Thread;
	PcapQueue_readFromInterfaceThread *md2Thread;
	PcapQueue_readFromInterfaceThread *dedupThread;
	PcapQueue_readFromInterfaceThread *serviceThread;
	PcapQueue_readFromInterfaceThread *prevThread;
	PcapQueue_readFromInterface *parent;
	bool threadDoTerminate;
	cHeaderPacketStack *headerPacketStackSnaplen;
	cHeaderPacketStack *headerPacketStackShort;
	unsigned headerPacketStackShortPacketLen;
	unsigned long allocCounter[2];
	unsigned long allocStackCounter[2];
	unsigned long long sumPacketsSize[3];
	bool prepareHeaderPacketPool; // experimental option
	pcap_dispatch_data dispatch_data;
friend void *_PcapQueue_readFromInterfaceThread_threadFunction(void *arg);
friend class PcapQueue_readFromInterface;
};

class PcapQueue_readFromInterface : public PcapQueue, protected PcapQueue_readFromInterface_base {
public:
	PcapQueue_readFromInterface(const char *nameQueue);
	virtual ~PcapQueue_readFromInterface();
	void setInterfaces(const char *interfaces);
	void setFiltersByInterface(vector<dstring> filters);
	void terminate();
	bool openPcap(const char *filename, string *tempFileName = NULL);
	bool isPcapEnd() {
		return(this->pcapEnd);
	}
	static void parseInterfaces(const char *interfaces_str, vector<dstring> *filters_by_interface,
				    vector<sInterface> *interfaces);
	static void getInterfaces(const char *interfaces_str, vector<string> *interfaces);
	static unsigned getCountInterfaces(const char *interfaces_str, vector<dstring> *filters_by_interface);
protected:
	bool init();
	void parseInterfaces(vector<sInterface> *interfaces);
	bool initThread(void *arg, unsigned int arg2, string *error);
	void *threadFunction(void *arg, unsigned int arg2);
	void threadFunction_blocks();
	void *writeThreadFunction(void *arg, unsigned int arg2);
	bool openFifoForWrite(void *arg, unsigned int arg2);
	bool startCapture(string *error, sDpdkConfig *dpdkConfig);
	pcap_t* _getPcapHandle(int /*dlt*/) { 
		return(this->pcapHandle);
	}
	u_int16_t _getPcapHandleIndex(int /*dlt*/) { 
		return(this->pcapHandleIndex);
	}
	unsigned long pcapStat_get_bypass_buffer_size_exeeded();
	string pcapStatString_interface(int statPeriod);
	string pcapDropCountStat_interface();
	virtual ulong getCountPacketDrop();
	virtual string getStatPacketDrop();
	void initStat_interface();
	string pcapStatString_cpuUsageReadThreads(double *sumMax, int *countThreadsSumMax, int divide, int pstatDataIndex);
	string getInterface();
	string getInterfaceAlias();
	void prepareLogTraffic();
private:
	inline void check_bypass_buffer();
	inline void push_blockstore(pcap_block_store **block_store);
	inline pcap_block_store *new_blockstore(int index_read_thread);
protected:
	PcapQueue_readFromInterfaceThread *readThreads[READ_THREADS_MAX];
	int readThreadsCount;
	int lastReadThreadsIndex_pcapStatString_interface;
	u_int64_t lastTimeLogErrThread0BufferIsFull;
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
		sPacketServerConnection(int socketClient, vmIP socketClientIP, vmPort socketClientPort,  PcapQueue_readFromFifo *parent, unsigned int id) {
			this->socketClient = socketClient;
			this->socketClientIP = socketClientIP;
			this->socketClientPort = socketClientPort;
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
		vmIP socketClientIP;
		vmPort socketClientPort;
		PcapQueue_readFromFifo *parent;
		unsigned int id;
		bool active;
		pthread_t threadHandle;
		int threadId;
		pstat_data threadPstatData[2][2];
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
		size_t pos_first;
		size_t pos_last;
		size_t pos_act;
		u_int64_t utime_first;
		u_int64_t utime_last;
		u_int64_t at;
		int next_block;
		inline bool set_first_last() {
			pos_first = 0;
			while(pos_first < blockStore->count && blockStore->is_ignore(pos_first)) {
				++pos_first;
			}
			if(pos_first == blockStore->count) {
				return(false);
			}
			pos_last = blockStore->count - 1;
			while(pos_last > pos_first && blockStore->is_ignore(pos_last)) {
				--pos_last;
			}
			pos_act = pos_first;
			return(true);
		}
		inline void set_time_first_last() {
			utime_first = getTimeUS(
				#if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
				(*blockStore)[pos_first].header->header.ts.tv_sec, 
				(*blockStore)[pos_first].header->header.ts.tv_usec
				#else
				(*blockStore)[pos_first].header->header_fix_size.ts_tv_sec, 
				(*blockStore)[pos_first].header->header_fix_size.ts_tv_usec
				#endif
				);
			utime_last = getTimeUS(
				#if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
				(*blockStore)[pos_last].header->header.ts.tv_sec, 
				(*blockStore)[pos_last].header->header.ts.tv_usec
				#else
				(*blockStore)[pos_last].header->header_fix_size.ts_tv_sec, 
				(*blockStore)[pos_last].header->header_fix_size.ts_tv_usec
				#endif
				);
		}
		inline void update_time_first() {
			utime_first = getTimeUS(
				#if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
				(*blockStore)[pos_act].header->header.ts.tv_sec,
				(*blockStore)[pos_act].header->header.ts.tv_usec
				#else
				(*blockStore)[pos_act].header->header_fix_size.ts_tv_sec,
				(*blockStore)[pos_act].header->header_fix_size.ts_tv_usec
				#endif
				);
		}
		inline bool inc_pos_act() {
			while(pos_act < pos_last) {
				++pos_act;
				if(!blockStore->is_ignore(pos_act)) {
					return(true);
				}
			}
			return(false);
		}
	};
	struct sBlocksInfo {
		struct sMinHeapData {
			inline sMinHeapData() {
				this->block_index = -1;
			}
			inline sMinHeapData(int block_index) {
				this->block_index = block_index;
			}
			inline int getIndex() {
				return(block_index);
			}
			int block_index;
			static inline bool gt(sMinHeapData a, sMinHeapData b, void *cmp_data) {
				sBlockInfo *blocks = (sBlockInfo*)cmp_data;
				return(blocks[a.block_index].utime_first > blocks[b.block_index].utime_first);
			}
			static inline bool lt(sMinHeapData a, sMinHeapData b, void *cmp_data) {
				sBlockInfo *blocks = (sBlockInfo*)cmp_data;
				return(blocks[a.block_index].utime_first < blocks[b.block_index].utime_first);
			}
		};
		sBlocksInfo(int blockInfoMax) {
			this->blockInfoMax = blockInfoMax;
			blocks = new FILE_LINE(0) sBlockInfo[blockInfoMax];
			for(int i = 0; i < blockInfoMax - 1; i++) {
				blocks[i].next_block = i + 1;
			}
			blocks[blockInfoMax - 1].next_block = -1;
			minHeap = new FILE_LINE(0) cMinHeap<sMinHeapData>(blockInfoMax, blocks);
			freeHead = 0;
			usedHead = -1;
			usedCount = 0;
			clean_times();
		}
		~sBlocksInfo() {
			delete [] blocks;
			delete minHeap;
		}
		inline int new_block() {
			if(freeHead == -1) {
				return(-1);
			}
			int _new = freeHead;
			freeHead = blocks[freeHead].next_block;
			blocks[_new].next_block = usedHead;
			usedHead = _new;
			++usedCount;
			return(_new);
		}
		inline void free_block(int index) {
			if(index < 0 || index >= blockInfoMax) {
				return;
			}
			int *prev = &usedHead;
			while(*prev != -1) {
				if(*prev == index) {
					*prev = blocks[index].next_block;
					break;
				}
				prev = &blocks[*prev].next_block;
			}
			blocks[index].next_block = freeHead;
			freeHead = index;
			--usedCount;
		}
		inline void set(int index, sBlockInfo *set_data) {
			int _next_block = blocks[index].next_block;
			blocks[index] = *set_data;
			blocks[index].next_block = _next_block;
		}
		inline bool is_full() {
			return(freeHead == -1);
		}
		inline void get_used(list<int> *used) {
			int index = usedHead;
			while(index != -1) {
				used->push_back(index);
				index = blocks[index].next_block;
			}
		}
		inline void clean_times() {
			utime_first = 0;
			utime_last = 0;
			at_first = 0;
			at_last = 0;
		}
		inline void update_times(int index) {
			if(!utime_first || blocks[index].utime_first < utime_first) {
				utime_first = blocks[index].utime_first;
			}
			if(!utime_last || blocks[index].utime_last > utime_last) {
				utime_last = blocks[index].utime_last;
			}
			if(!at_first || blocks[index].at < at_first) {
				at_first = blocks[index].at;
			}
			if(!at_last || blocks[index].at > at_last) {
				at_last = blocks[index].at;
			}
		}
		inline void update_times() {
			clean_times();
			int index = usedHead;
			while(index != -1) {
				update_times(index);
				index = blocks[index].next_block;
			}
		}
		sBlockInfo *blocks;
		cMinHeap<sMinHeapData> *minHeap;
		int blockInfoMax;
		int freeHead;
		int usedHead;
		int usedCount;
		u_int64_t utime_first;
		u_int64_t utime_last;
		u_int64_t at_first;
		u_int64_t at_last;
	};
public:
	PcapQueue_readFromFifo(const char *nameQueue, const char *fileStoreFolder);
	virtual ~PcapQueue_readFromFifo();
	void setPacketServer(ip_port ipPort, ePacketServerDirection direction);
	size_t getQueueSize() {
		return(this->pcapStoreQueue.getQueueSize());
	}
	bool addBlockStoreToPcapStoreQueue(u_char *buffer, u_char *buffer_alloc_begin, size_t bufferLen, string *error, string *warning, u_int32_t *block_counter, bool *require_confirmation);
	inline void addBlockStoreToPcapStoreQueue(pcap_block_store *blockStore);
	inline unsigned long long getLastUS() {
		return(getTimeUS(_last_ts));
	}
	string debugBlockStoreTrash();
	string saveBlockStoreTrash(const char *filter, const char *destFile);
	pcap_block_store *getBlockStoreFromPool();
	bool checkIfMemoryBufferIsFull(unsigned size, bool log);
	bool checkIfDiskBufferIsFull(bool log);
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
	double pcapStat_get_memory_buffer_perc();
	double pcapStat_get_memory_buffer_perc_trash();
	double pcapStat_get_disk_buffer_perc();
	double pcapStat_get_disk_buffer_mb();
	string getCpuUsage(bool writeThread, int pstatDataIndex, bool preparePstatData = true);
	bool socketWritePcapBlock(pcap_block_store *blockStore);
	bool socketWritePcapBlockBySnifferClient(pcap_block_store *blockStore);
	bool socketGetHost();
	bool socketReadyForConnect();
	bool socketConnect();
	bool socketListen();
	bool socketAwaitConnection(int *socketClient, vmIP *socketClientIP, vmPort *socketClientPort);
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
	void createConnection(int socketClient, vmIP socketClientIP, vmPort socketClientPort);
	void cleanupConnections(bool all = false);
	inline void processPacket(sHeaderPacketPQout *hp);
	inline bool processPacket_analysis(sHeaderPacketPQout *hp);
	inline bool processPacket_push(sHeaderPacketPQout *hp);
	void pushBatchProcessPacket();
	void checkFreeSizeCachedir();
	void cleanupBlockStoreTrash(bool all = false);
	void lock_packetServerConnections() {
		__SYNC_LOCK(this->_sync_packetServerConnections);
	}
	void unlock_packetServerConnections() {
		__SYNC_UNLOCK(this->_sync_packetServerConnections);
	}
	void blockStoreTrashPush(pcap_block_store *block) {
		block->pushToTrashMS = getTimeMS_rdtsc();
		lock_blockStoreTrash();
		this->blockStoreTrash.push_back(block);
		unlock_blockStoreTrash();
		extern cBuffersControl buffersControl;
		size_t block_size = block->getUseAllSize();
		buffersControl.sub__pb_used_size(block_size);
		buffersControl.add__pb_trash_size(block_size);
	}
	void lock_blockStoreTrash() {
		__SYNC_LOCK(this->blockStoreTrash_sync);
	}
	void unlock_blockStoreTrash() {
		__SYNC_UNLOCK(this->blockStoreTrash_sync);
	}
	void lock_blockStorePool() {
		__SYNC_LOCK(this->blockStorePool_sync);
	}
	void unlock_blockStorePool() {
		__SYNC_UNLOCK(this->blockStorePool_sync);
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
	deque<pcap_block_store*> blockStorePool;
	volatile int blockStorePool_sync;
	vmIP socketHostIP;
	int socketHandle;
	cSocketBlock *clientSocket;
	map<unsigned int, sPacketServerConnection*> packetServerConnections;
	volatile int _sync_packetServerConnections;
	u_int64_t lastCheckFreeSizeCachedir_timeMS;
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
		detach,
		defrag,
		dedup,
		detach2
	};
	struct sBatchHP {
		sBatchHP(unsigned max_count) {
			count = 0;
			used = 0;
			batch = new FILE_LINE(16008) sHeaderPacketPQout[max_count];
			this->max_count = max_count;
		}
		~sBatchHP() {
			if(count) {
				for(unsigned i = 0; i < count; i++) {
					batch[i].destroy_or_unlock_blockstore();
				}
			}
			delete [] batch;
		}
		sHeaderPacketPQout *batch;
		volatile unsigned count;
		volatile int used;
		unsigned max_count;
	};
	struct arg_next_thread {
		PcapQueue_outputThread *me;
		int next_thread_id;
	};
	struct s_next_thread_data {
		volatile void *batch;
		volatile unsigned start;
		volatile unsigned end;
		volatile unsigned skip;
		volatile int thread_index;
		volatile int data_ready;
		volatile int processing;
		void null() {
			batch = NULL;
			start = 0;
			end = 0;
			skip = 0;
			thread_index = 0;
			data_ready = 0;
			processing = 0;
		}
	};
	struct s_next_thread {
		volatile int thread_id;
		pthread_t thread_handle;
		pstat_data thread_pstat_data[2][2];
		s_next_thread_data next_data;
		sem_t sem_sync[2];
		volatile int terminate;
		void null() {
			thread_id = 0;
			thread_handle = 0;
			memset(thread_pstat_data, 0, sizeof(thread_pstat_data));
			next_data.null();
			memset(sem_sync, 0, sizeof(sem_sync));
			terminate = 0;
		}
		void sem_init() {
			extern int opt_process_rtp_packets_hash_next_thread_sem_sync;
			for(int i = 0; i < opt_process_rtp_packets_hash_next_thread_sem_sync; i++) {
				::sem_init(&sem_sync[i], 0, 0);
			}
		}
		void sem_term() {
			extern int opt_process_rtp_packets_hash_next_thread_sem_sync;
			for(int i = 0; i < opt_process_rtp_packets_hash_next_thread_sem_sync; i++) {
				sem_destroy(&sem_sync[i]);
			}
		}
	};
	PcapQueue_outputThread(eTypeOutputThread typeOutputThread, PcapQueue_readFromFifo *pcapQueue);
	~PcapQueue_outputThread();
	void start();
	void stop();
	void terminate() {
		this->stop();
	}
	void addNextThread();
	void removeNextThread();
	inline void push(sHeaderPacketPQout *hp);
	void push_batch();
	static void *_outThreadFunction(void *arg);
	void *outThreadFunction();
	static void *_nextThreadFunction(void *arg);
	void *nextThreadFunction(int next_thread_index_plus);
	void createNextThread();
	void termNextThread();
	inline void processDetach(sHeaderPacketPQout *hp);
	inline void processDetach_findHeaderIp(sHeaderPacketPQout *hp);
	inline void processDetach_push(sHeaderPacketPQout *hp);
	inline void processDefrag(sHeaderPacketPQout *hp, int fdata_thread_index);
	inline bool processDefrag_defrag(sHeaderPacketPQout *hp, int fdata_thread_index);
	inline void processDefrag_push(sHeaderPacketPQout *hp);
	inline void processDefrag_cleanup(u_int32_t time_s);
	inline void processDedup(sHeaderPacketPQout *hp);
	inline void processDetach2(sHeaderPacketPQout *hp);
	string getNameOutputThread() {
		switch(typeOutputThread) {
		case detach:
			return("detach");
		case defrag:
			return("defrag");
		case dedup:
			return("dedup");
		case detach2:
			return("detach2");
		}
		return("");
	}
	void preparePstatData(int nextThreadId, int pstatDataIndex);
	double getCpuUsagePerc(int nextThreadId, int pstatDataIndex, double *percFullQring, bool preparePstatData = true);
	bool existsNextThread(int next_thread_index) {
		return(next_thread_index < MAX_PRE_PROCESS_PACKET_NEXT_THREADS &&
		       this->next_threads[next_thread_index].thread_id);
	}
private:
	bool isNextThreadsGt2Processing(int next_threads) {
		for(int i = 2; i < next_threads; i++) {
			if(this->next_threads[i].next_data.processing) {
				return(true);
			}
		}
		return(false);
	}
private:
	eTypeOutputThread typeOutputThread;
	PcapQueue_readFromFifo *pcapQueue;
	unsigned int qring_batch_item_length;
	unsigned int qring_length;
	sBatchHP **qring;
	unsigned qring_push_index;
	unsigned qring_push_index_count;
	sBatchHP *qring_active_push_item;
	u_int64_t qring_active_push_item_limit_us;
	volatile unsigned int readit;
	volatile unsigned int writeit;
	pthread_t out_thread_handle;
	pstat_data threadPstatData[2][2];
	u_int64_t qringPushCounter;
	u_int64_t qringPushCounter_full;
	int outThreadId;
	#if not DEFRAG_MOD_OLDVER
	cIpFrag *ip_defrag;
	#else
	ipfrag_data_s ipfrag_data;
	#endif
	unsigned ipfrag_lastcleanup;
	unsigned defrag_counter;
	cPacketDuplBuffer *dedup_buffer;
	#if DEDUPLICATE_COLLISION_TEST
	cPacketDuplBuffer *dedup_buffer_ct_md5;
	#endif
	volatile bool initThreadOk;
	volatile bool terminatingThread;
	volatile int next_threads_count;
	volatile int next_threads_count_mod;
	s_next_thread next_threads[MAX_PRE_PROCESS_PACKET_NEXT_THREADS];
	volatile int8_t *items_flag;
	u_int8_t *items_index;
	u_int8_t *items_thread_index;
	#if EXPERIMENTAL_CHECK_TID_IN_PUSH
	unsigned push_thread;
	u_int64_t last_race_log[2];
	#endif
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
