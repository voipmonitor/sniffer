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

#include "pcap_queue_block.h"
#include "md5.h"
#include "sniff.h"


class pcap_block_store_queue {
public:
	pcap_block_store_queue();
	~pcap_block_store_queue();
	void push(pcap_block_store* blockStore) {
		this->lock_queue();
		this->queue.push_back(blockStore);
		this->unlock_queue();
	}
	pcap_block_store* pop() {
		pcap_block_store* blockStore = NULL;
		this->lock_queue();
		if(this->queue.size()) {
			blockStore = this->queue.front();
			this->queue.pop_front();
		}
		this->unlock_queue();
		return(blockStore);
	}
	size_t getUseItems() {
		this->lock_queue();
		size_t size = this->queue.size();
		this->unlock_queue();
		return(size);
	}	
	size_t getUseSize() {
		this->lock_queue();
		size_t size = 0;
		size_t _size_n =  this->queue.size();
		for(size_t i = 0; i < _size_n; i++) {
			size += this->queue[i]->getUseSize();
		}
		this->unlock_queue();
		return(size);
	}
private:
	void lock_queue() {
		while(__sync_lock_test_and_set(&this->_sync_queue, 1));
	}
	void unlock_queue() {
		__sync_lock_release(&this->_sync_queue);
	}
private:
	std::deque<pcap_block_store*> queue;
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
	bool push(pcap_block_store *blockStore);
	bool pop(pcap_block_store **blockStore);
	size_t getQueueSize() {
		return(this->queue.size());
	}
private:
	pcap_file_store *findFileStoreById(u_int id);
	void cleanupFileStore();
	size_t getFileStoreUseSize(bool lock = true);
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
		__sync_fetch_and_add(&this->sizeOfBlocksInMemory, size);
	}
	void sub_sizeOfBlocksInMemory(size_t size) {
		__sync_fetch_and_sub(&this->sizeOfBlocksInMemory, size);
	}
private:
	std::string fileStoreFolder;
	std::deque<pcap_block_store*> queue;
	std::deque<pcap_file_store*> fileStore;
	u_int lastFileStoreId;
	volatile size_t sizeOfBlocksInMemory;
	volatile int _sync_queue;
	volatile int _sync_fileStore;
	int cleanupFileStoreCounter;
friend class PcapQueue_readFromFifo;
};

class PcapQueue {
public:
	enum eTypeQueue {
		readFromInterface,
		readFromFifo
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
	void terminate();
	bool isInitOk();
	bool isTerminated();
	void setInstancePcapHandle(PcapQueue *pcapQueue);
	inline pcap_t* getPcapHandle();
	void pcapStat(int statPeriod = 1, bool statCalls = true);
	void initStat();
protected:
	bool createThread();
	inline int pcap_next_ex(pcap_t* pcapHandle, pcap_pkthdr** header, u_char** packet);
	inline int readPcapFromFifo(pcap_pkthdr_plus *header, u_char **packet, bool usePacketBuffer = false);
	bool writePcapToFifo(pcap_pkthdr_plus *header, u_char *packet);
	virtual bool init() { return(true); };
	virtual bool initThread();
	virtual bool initWriteThread();
	virtual void *threadFunction(void *) = 0;
	virtual void *writeThreadFunction(void *) { return(NULL); }
	virtual bool openFifoForRead();
	virtual bool openFifoForWrite();
	virtual pcap_t* _getPcapHandle() { 
		extern pcap_t *handle;
		return(handle); 
	}
	virtual string pcapStatString_packets(int statPeriod);
	virtual string pcapStatString_bypass_buffer(int statPeriod) { return(""); }
	virtual string pcapStatString_memory_buffer(int statPeriod) { return(""); }
	virtual string pcapStatString_disk_buffer(int statPeriod) { return(""); }
	virtual string pcapStatString_interface(int statPeriod) { return(""); }
	virtual void initStat_interface() {};
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
private:
	u_char* packetBuffer;
	PcapQueue *instancePcapHandle;
friend void *_PcapQueue_threadFunction(void* arg);
friend void *_PcapQueue_writeThreadFunction(void* arg);
};

class PcapQueue_readFromInterface : public PcapQueue {
private:
	struct pcapProcessData {
		pcapProcessData() {
			memset(this, 0, sizeof(pcapProcessData));
		}
		sll_header *header_sll;
		ether_header *header_eth;
		iphdr2 *header_ip;
		tcphdr *header_tcp;
		udphdr2 *header_udp;
		udphdr2 header_udp_tmp;
		int protocol;
		u_int offset;
		char *data;
		int datalen;
		int traillen;
		int istcp;
		unsigned char md5[MD5_DIGEST_LENGTH];
		unsigned char *prevmd5s;
		MD5_CTX ctx;
	};
public:
	PcapQueue_readFromInterface(const char *nameQueue);
	virtual ~PcapQueue_readFromInterface();
	void setInterfaceName(const char *interfaceName);
protected:
	bool initThread();
	void *threadFunction(void *);
	bool openFifoForWrite();
	bool startCapture();
	pcap_t* _getPcapHandle() { 
		return(this->pcapHandle);
	}
	string pcapStatString_bypass_buffer(int statPeriod);
	string pcapStatString_interface(int statPeriod);
	void initStat_interface();
private:
	inline int pcapProcess(pcap_pkthdr** header, u_char** packet, bool *destroy);
protected:
	std::string interfaceName;
	bpf_u_int32 interfaceNet;
	bpf_u_int32 interfaceMask;
	pcap_t *pcapHandle;
	pcap_dumper_t *pcapDumpHandle;
	int pcapLinklayerHeaderType;
	pcap_dumper_t *fifoWritePcapDumper;
	u_int ipfrag_lastprune;
	int pcap_snaplen;
	int pcap_promisc;
	int pcap_timeout;
	int pcap_buffer_size;
	u_int _last_ps_drop;
	u_int _last_ps_ifdrop;
private:
	pcapProcessData ppd;
};

class PcapQueue_readFromFifo : public PcapQueue {
public:
	enum ePacketServerDirection {
		directionNA,
		directionRead,
		directionWrite
	};
public:
	PcapQueue_readFromFifo(const char *nameQueue, const char *fileStoreFolder);
	virtual ~PcapQueue_readFromFifo();
	void setPacketServer(const char *packetServer, int packetServerPort, ePacketServerDirection direction);
	size_t getQueueSize() {
		return(this->pcapStoreQueue.getQueueSize());
	}
protected:
	void *threadFunction(void *);
	void *writeThreadFunction(void *);
	bool openFifoForRead();
	bool openFifoForWrite();
	pcap_t* _getPcapHandle() {
		extern pcap_t *handle;
		return(this->fifoReadPcapHandle ? this->fifoReadPcapHandle : handle);
	}
	string pcapStatString_memory_buffer(int statPeriod);
	string pcapStatString_disk_buffer(int statPeriod);
	bool socketWritePcapBlock(pcap_block_store *blockStore);
	bool socketGetHost();
	bool socketConnect();
	bool socketListen();
	bool socketAwaitConnection();
	bool socketClose();
	bool socketWrite(u_char *data, size_t dataLen);
	bool socketRead(u_char *data, size_t *dataLen);
private:
	void processPacket(pcap_pkthdr_plus *header, u_char *packet,
			   pcap_block_store *block_store, int block_store_index);
	void cleanupBlockStoreTrash();
protected:
	std::string packetServer;
	int packetServerPort;
	ePacketServerDirection packetServerDirection;
	pcap_t *fifoReadPcapHandle;
	hostent* socketHostEnt;
	int socketHandle;
	int socketClient;
	sockaddr_in socketClientInfo;
private:
	pcap_store_queue pcapStoreQueue;
	vector<pcap_block_store*> blockStoreTrash;
	u_int cleanupBlockStoreTrash_counter;
};


#endif