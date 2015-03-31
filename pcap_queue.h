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

#define READ_THREADS_MAX 20
#define DLT_TYPES_MAX 10
#define PCAP_QUEUE_NEXT_THREADS_MAX 3
#define MAX_THREADS_DELETE 3

class pcap_block_store_queue {
public:
	pcap_block_store_queue();
	~pcap_block_store_queue();
	void push(pcap_block_store* blockStore) {
		this->lock_queue();
		this->queue.push_back(blockStore);
		this->add_sizeOfBlocks(blockStore->getUseSize());
		this->unlock_queue();
	}
	pcap_block_store* pop(bool removeFromFront = true, size_t blockSize = 0) {
		pcap_block_store* blockStore = NULL;
		this->lock_queue();
		if(this->queue.size()) {
			blockStore = this->queue.front();
			if(removeFromFront) {
				this->queue.pop_front();
			}
		}
		if(blockStore && removeFromFront) {
			this->sub_sizeOfBlocks(blockSize ? blockSize : blockStore->getUseSize());
		}
		this->unlock_queue();
		return(blockStore);
	}
	size_t getUseItems() {
		return(this->countOfBlocks);
	}	
	uint64_t getUseSize() {
		return(this->sizeOfBlocks);
	}
private:
	void lock_queue() {
		while(__sync_lock_test_and_set(&this->_sync_queue, 1));
	}
	void unlock_queue() {
		__sync_lock_release(&this->_sync_queue);
	}
	void add_sizeOfBlocks(size_t size) {
		__sync_fetch_and_add(&this->sizeOfBlocks, size);
		__sync_fetch_and_add(&this->countOfBlocks, 1);
	}
	void sub_sizeOfBlocks(size_t size) {
		__sync_fetch_and_sub(&this->sizeOfBlocks, size);
		__sync_fetch_and_sub(&this->countOfBlocks, 1);
	}
private:
	std::deque<pcap_block_store*> queue;
	volatile size_t countOfBlocks;
	volatile size_t sizeOfBlocks;
	volatile int _sync_queue;
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
		   (this->fileSize && (getTimeMS() - this->timestampMS) >= opt_pcap_queue_file_store_max_time_ms) ||
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
		return(this->queue.size());
	}
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
	std::deque<pcap_block_store*> queue;
	std::deque<pcap_file_store*> fileStore;
	u_int lastFileStoreId;
	volatile int _sync_queue;
	volatile int _sync_fileStore;
	int cleanupFileStoreCounter;
	u_long lastTimeLogErrDiskIsFull;
	u_long lastTimeLogErrMemoryIsFull;
friend class PcapQueue_readFromFifo;
};

class PcapQueue {
public:
	enum eTypeQueue {
		readFromInterface,
		readFromFifo
	};
	enum eTypeThread {
		mainThread,
		writeThread,
		nextThread1,
		nextThread2,
		nextThread3
	};
	PcapQueue(eTypeQueue typeQueue, const char *nameQueue);
	virtual ~PcapQueue();
	void setFifoFileForRead(const char *fifoFileForRead);
	void setFifoFileForWrite(const char *fifoFileForWrite);
	void setFifoReadHandle(int fifoReadHandle);
	void setFifoWriteHandle(int fifoWriteHandle);
	void setEnableWriteThread();
	void setEnableAutoTerminate(bool enableAutoTerminate);
	bool start();
	virtual void terminate();
	bool isInitOk();
	bool isTerminated();
	void setInstancePcapHandle(PcapQueue *pcapQueue);
	inline pcap_t* getPcapHandle(int dlt);
	void pcapStat(int statPeriod = 1, bool statCalls = true);
	string pcapDropCountStat();
	void initStat();
	void getThreadCpuUsage(bool writeThread = false);
protected:
	bool createThread();
	virtual bool createMainThread();
	virtual bool createWriteThread();
	inline int pcap_next_ex_queue(pcap_t* pcapHandle, pcap_pkthdr** header, u_char** packet);
	inline int readPcapFromFifo(pcap_pkthdr_plus *header, u_char **packet, bool usePacketBuffer = false);
	bool writePcapToFifo(pcap_pkthdr_plus *header, u_char *packet);
	virtual bool init() { return(true); };
	virtual bool initThread(void *arg, unsigned int arg2);
	virtual bool initWriteThread(void *arg, unsigned int arg2);
	virtual void *threadFunction(void *arg, unsigned int arg2) = 0;
	virtual void *writeThreadFunction(void *arg, unsigned int arg2) { return(NULL); }
	virtual bool openFifoForRead(void *arg, unsigned int arg2);
	virtual bool openFifoForWrite(void *arg, unsigned int arg2);
	virtual pcap_t* _getPcapHandle(int dlt) { 
		extern pcap_t *global_pcap_handle;
		return(global_pcap_handle); 
	}
	virtual string pcapStatString_packets(int statPeriod);
	virtual double pcapStat_get_compress();
	virtual double pcapStat_get_speed_mb_s(int statPeriod);
	virtual string pcapStatString_bypass_buffer(int statPeriod) { return(""); }
	virtual unsigned long pcapStat_get_bypass_buffer_size_exeeded() { return(0); }
	virtual string pcapStatString_memory_buffer(int statPeriod) { return(""); }
	virtual string pcapStatString_disk_buffer(int statPeriod) { return(""); }
	virtual double pcapStat_get_disk_buffer_perc() { return(-1); }
	virtual double pcapStat_get_disk_buffer_mb() { return(-1); }
	virtual string pcapStatString_interface(int statPeriod) { return(""); }
	virtual string pcapDropCountStat_interface() { return(""); }
	virtual ulong getCountPacketDrop() { return(0); }
	virtual string getStatPacketDrop() { return(""); }
	virtual string pcapStatString_cpuUsageReadThreads() { return(""); };
	virtual void initStat_interface() {};
	int getThreadPid(eTypeThread typeThread);
	pstat_data *getThreadPstatData(eTypeThread typeThread);
	void preparePstatData(eTypeThread typeThread = mainThread);
	void prepareProcPstatData();
	double getCpuUsagePerc(eTypeThread typeThread = mainThread, bool preparePstatData = false);
	virtual string getCpuUsage(bool writeThread = false, bool preparePstatData = false) { return(""); }
	long unsigned int getVsizeUsage(bool preparePstatData = false);
	long unsigned int getRssUsage(bool preparePstatData = false);
	virtual bool isMirrorSender() {
		return(false);
	}
	virtual bool isMirrorReceiver() {
		return(false);
	}
	void processBeforeAddToPacketBuffer(pcap_pkthdr* header,u_char* packet, u_int offset);
protected:
	eTypeQueue typeQueue;
	std::string nameQueue;
	pthread_t threadHandle;
	pthread_t writeThreadHandle;
	std::string fifoFileForRead;
	std::string fifoFileForWrite;
	bool enableWriteThread;
	bool enableAutoTerminate;
	int fifoReadHandle;
	int fifoWriteHandle;
	bool threadInitOk;
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
	bool initAllReadThreadsOk;
private:
	u_char* packetBuffer;
	PcapQueue *instancePcapHandle;
	u_int64_t counter_calls_old;
	u_int64_t counter_sip_packets_old[2];
	u_int64_t counter_rtp_packets_old;
	u_int64_t counter_all_packets_old;
friend void *_PcapQueue_threadFunction(void *arg);
friend void *_PcapQueue_writeThreadFunction(void *arg);
};

struct pcapProcessData {
	pcapProcessData() {
		memset(this, 0, sizeof(pcapProcessData) - sizeof(ipfrag_data_s));
		extern int opt_dup_check;
		if(opt_dup_check) {
			this->prevmd5s = new FILE_LINE unsigned char[65536 * MD5_DIGEST_LENGTH]; // 1M
			memset(this->prevmd5s, 0, 65536 * MD5_DIGEST_LENGTH * sizeof(unsigned char));
		}
	}
	~pcapProcessData() {
		if(this->prevmd5s) {
			delete [] this->prevmd5s;
		}
		ipfrag_prune(0, 1, &ipfrag_data);
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
	uint16_t md5[MD5_DIGEST_LENGTH / (sizeof(uint16_t) / sizeof(unsigned char))];
	unsigned char *prevmd5s;
	MD5_CTX ctx;
	u_int ipfrag_lastprune;
	ipfrag_data_s ipfrag_data;
};


class PcapQueue_readFromInterface_base {
public:
	PcapQueue_readFromInterface_base(const char *interfaceName = NULL);
	virtual ~PcapQueue_readFromInterface_base();
	void setInterfaceName(const char *interfaceName);
protected:
	virtual bool startCapture();
	inline int pcap_next_ex_iface(pcap_t *pcapHandle, pcap_pkthdr** header, u_char** packet);
	inline int pcap_dispatch(pcap_t *pcapHandle);
	inline int pcapProcess(pcap_pkthdr** header, u_char** packet, bool *destroy, 
			       bool enableDefrag = true, bool enableCalcMD5 = true, bool enableDedup = true, bool enableDump = true);
	virtual string pcapStatString_interface(int statPeriod);
	virtual string pcapDropCountStat_interface();
	virtual ulong getCountPacketDrop();
	virtual string getStatPacketDrop();
	virtual void initStat_interface();
	virtual string getInterfaceName(bool simple = false);
protected:
	string interfaceName;
	bpf_u_int32 interfaceNet;
	bpf_u_int32 interfaceMask;
	pcap_t *pcapHandle;
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
	u_int _last_ps_drop;
	u_int _last_ps_ifdrop;
	u_long countPacketDrop;
	u_int64_t lastPacketTimeUS;
};

class PcapQueue_readFromInterfaceThread : protected PcapQueue_readFromInterface_base {
public:
	enum eTypeInterfaceThread {
		read,
		defrag,
		md1,
		md2,
		dedup
	};
	struct hpi {
		pcap_pkthdr* header;
		u_char* packet;
		u_int offset;
		uint16_t md5[MD5_DIGEST_LENGTH / (sizeof(uint16_t) / sizeof(unsigned char))];
		volatile uint32_t counter;
		volatile signed char used;
	};
	PcapQueue_readFromInterfaceThread(const char *interfaceName, eTypeInterfaceThread typeThread = read,
					  PcapQueue_readFromInterfaceThread *readThread = NULL,
					  PcapQueue_readFromInterfaceThread *prevThread = NULL,
					  PcapQueue_readFromInterfaceThread *prevThread2 = NULL);
	~PcapQueue_readFromInterfaceThread();
protected:
	inline void push(pcap_pkthdr* header,u_char* packet, u_int offset, uint16_t *md5, int index = 0, uint32_t counter = 0);
	inline hpi pop(int index = 0, bool moveReadit = true, bool deferDestroy = false);
        inline void moveReadit(int index = 0, bool deferDestroy = false);
	inline hpi POP(bool moveReadit = true, bool deferDestroy = false);
	inline void moveREADIT(bool deferDestroy = false);
	u_int64_t getTime_usec(int index = 0) {
		if(this->qring[index][this->readit[index] % this->qringmax].used <= 0) {
			return(0);
		}
		return(this->qring[index][this->readit[index] % this->qringmax].header->ts.tv_sec * 1000000ull + 
		       this->qring[index][this->readit[index] % this->qringmax].header->ts.tv_usec);
	}
	u_int32_t getCounter(int index = 0) {
		if(this->qring[index][this->readit[index] % this->qringmax].used <= 0) {
			return(0);
		}
		return(this->qring[index][this->readit[index] % this->qringmax].counter);
	}
	u_int64_t getTIME_usec() {
		return(this->dedupThread ? this->dedupThread->getTime_usec() : this->getTime_usec());
	}
	bool isTerminated() {
		return(this->threadTerminated);
	}
private:
	void *threadFunction(void *arg, unsigned int arg2);
	void preparePstatData();
	double getCpuUsagePerc(bool preparePstatData = false);
	double getQringFillingPerc(int index) {
		if(!qring[index]) {
			return(-1);
		}
		unsigned int _readit = readit[index];
		unsigned int _writeit = writeit[index];
		return(_writeit >= _readit ?
			(double)(_writeit - _readit) / qringmax * 100 :
			(double)(qringmax - _readit + _writeit) / qringmax * 100);
	}
	string getQringFillingPerc();
	void terminate();
private:
	pthread_t threadHandle;
	int threadId;
	int threadInitOk;
	hpi *qring[2];
	unsigned int qringmax;
	volatile unsigned int readit[2];
	volatile unsigned int writeit[2];
	bool threadTerminated;
	pstat_data threadPstatData[2];
	volatile int _sync_qring;
	eTypeInterfaceThread typeThread;
	PcapQueue_readFromInterfaceThread *readThread;
	PcapQueue_readFromInterfaceThread *defragThread;
	PcapQueue_readFromInterfaceThread *md1Thread;
	PcapQueue_readFromInterfaceThread *md2Thread;
	PcapQueue_readFromInterfaceThread *dedupThread;
	PcapQueue_readFromInterfaceThread *prevThreads[2];
	int indexDefragQring;
	uint32_t push_counter;
	uint32_t pop_counter;
	bool threadDoTerminate;
friend void *_PcapQueue_readFromInterfaceThread_threadFunction(void *arg);
friend class PcapQueue_readFromInterface;
};

class PcapQueue_readFromInterface : public PcapQueue, protected PcapQueue_readFromInterface_base {
private: 
	struct sHeaderPacket {
		sHeaderPacket(pcap_pkthdr *header = NULL, u_char *packet = NULL) {
			this->header = header;
			this->packet = packet;
		}
		pcap_pkthdr *header;
		u_char *packet;
	};
	struct sThreadDeleteData {
		sThreadDeleteData(PcapQueue_readFromInterface *owner) : queue(100000, 1000, 1000, 
									      NULL, true, 
									      __FILE__, __LINE__) {
			threadHandle = (pthread_t)NULL;
			threadId = NULL;
			enableMallocTrim = false;
			enableLock = false;
			lastMallocTrimTime = 0;
			counter = 0;
			this->owner = owner;
		}
		pthread_t threadHandle;
		int *threadId;
		bool enableMallocTrim;
		bool enableLock;
		u_int32_t lastMallocTrimTime;
		u_int32_t counter;
		rqueue_quick<sHeaderPacket> queue;
		PcapQueue_readFromInterface *owner;
	};
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
	bool initThread(void *arg, unsigned int arg2);
	void *threadFunction(void *arg, unsigned int arg2);
	void *threadDeleteFunction(sThreadDeleteData *threadDeleteData);
	bool openFifoForWrite(void *arg, unsigned int arg2);
	bool startCapture();
	pcap_t* _getPcapHandle(int dlt) { 
		return(this->pcapHandle);
	}
	string pcapStatString_bypass_buffer(int statPeriod);
	unsigned long pcapStat_get_bypass_buffer_size_exeeded();
	string pcapStatString_interface(int statPeriod);
	string pcapDropCountStat_interface();
	virtual ulong getCountPacketDrop();
	virtual string getStatPacketDrop();
	void initStat_interface();
	string pcapStatString_cpuUsageReadThreads();
	string getInterfaceName(bool simple = false);
	void pushDelete(sHeaderPacket *headerPacket) {
		threadsDeleteData[(counterPushDelete++) % deleteThreadsCount]->queue.push(headerPacket, true);
	}
	void lock_delete() {
		while(__sync_lock_test_and_set(&this->_sync_delete, 1));
	}
	void unlock_delete() {
		__sync_lock_release(&this->_sync_delete);
	}
protected:
	pcap_dumper_t *fifoWritePcapDumper;
	PcapQueue_readFromInterfaceThread *readThreads[READ_THREADS_MAX];
	int readThreadsCount;
	u_long lastTimeLogErrThread0BufferIsFull;
private:
	sThreadDeleteData *threadsDeleteData[MAX_THREADS_DELETE];
	int deleteThreadsCount;
	u_int32_t counterPushDelete;
	static volatile int _sync_delete;
friend void *_PcapQueue_readFromInterfaceThread_threadDeleteFunction(void *arg);
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
		}
		~sPacketServerConnection() {
			if(this->socketClient) {
				close(this->socketClient);
			}
		}
		int socketClient;
		sockaddr_in socketClientInfo;
		string socketClientIP;
		PcapQueue_readFromFifo *parent;
		unsigned int id;
		bool active;
		pthread_t threadHandle;
		int threadId;
		pstat_data threadPstatData[2];
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
protected:
	bool initThread(void *arg, unsigned int arg2);
	void *threadFunction(void *arg, unsigned int arg2);
	void *writeThreadFunction(void *arg, unsigned int arg2);
	bool openFifoForRead(void *arg, unsigned int arg2);
	bool openFifoForWrite(void *arg, unsigned int arg2);
	bool openPcapDeadHandle(int dlt);
	pcap_t* _getPcapHandle(int dlt) {
		extern pcap_t *global_pcap_handle;
		if(this->pcapDeadHandles_count) {
			if(!dlt) {
				return(this->pcapDeadHandles[0]);
			}
			for(int i = 0; i < this->pcapDeadHandles_count; i++) {
				if(this->pcapDeadHandles_dlt[i] == dlt) {
					return(this->pcapDeadHandles[i]);
				}
			}
			if(openPcapDeadHandle(dlt)) {
				return(this->pcapDeadHandles[this->pcapDeadHandles_count - 1]);
			} else {
				return(NULL);
			}
		}
		return(this->fifoReadPcapHandle ? this->fifoReadPcapHandle : global_pcap_handle);
	}
	string pcapStatString_memory_buffer(int statPeriod);
	double pcapStat_get_memory_buffer_perc();
	double pcapStat_get_memory_buffer_perc_trash();
	string pcapStatString_disk_buffer(int statPeriod);
	double pcapStat_get_disk_buffer_perc();
	double pcapStat_get_disk_buffer_mb();
	string getCpuUsage(bool writeThread = false, bool preparePstatData = false);
	bool socketWritePcapBlock(pcap_block_store *blockStore);
	bool socketGetHost();
	bool socketConnect();
	bool socketListen();
	bool socketAwaitConnection(int *socketClient, sockaddr_in *socketClientInfo);
	bool socketClose();
	bool socketWrite(u_char *data, size_t dataLen);
	bool socketRead(u_char *data, size_t *dataLen, int idConnection);
	bool isMirrorSender() {
		return(this->packetServerDirection == directionWrite);
	}
	bool isMirrorReceiver() {
		return(this->packetServerDirection == directionRead);
	}
private:
	void createConnection(int socketClient, sockaddr_in *socketClientInfo);
	void cleanupConnections(bool all = false);
	void processPacket(pcap_pkthdr_plus *header, u_char *packet,
			   pcap_block_store *block_store, int block_store_index,
			   int dlt, int sensor_id);
	void checkFreeSizeCachedir();
	void cleanupBlockStoreTrash(bool all = false);
	void lock_packetServerConnections() {
		while(__sync_lock_test_and_set(&this->_sync_packetServerConnections, 1));
	}
	void unlock_packetServerConnections() {
		__sync_lock_release(&this->_sync_packetServerConnections);
	}
protected:
	ip_port packetServerIpPort;
	ePacketServerDirection packetServerDirection;
	pcap_t *fifoReadPcapHandle;
	pcap_t *pcapDeadHandles[DLT_TYPES_MAX];
	int pcapDeadHandles_dlt[DLT_TYPES_MAX];
	int pcapDeadHandles_count;
private:
	pcap_store_queue pcapStoreQueue;
	deque<pcap_block_store*> blockStoreTrash;
	u_int cleanupBlockStoreTrash_counter;
	hostent* socketHostEnt;
	int socketHandle;
	map<unsigned int, sPacketServerConnection*> packetServerConnections;
	volatile int _sync_packetServerConnections;
	u_long lastCheckFreeSizeCachedir_timeMS;
	timeval _last_ts;
friend void *_PcapQueue_readFromFifo_connectionThreadFunction(void *arg);
};


void PcapQueue_init();
void PcapQueue_term();


#endif
