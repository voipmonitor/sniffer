#ifndef BUFFERS_CONTROL_H
#define BUFFERS_CONTROL_H

class cBuffersControl {
public:
	cBuffersControl() {
		max_buffer_mem = 0;
		max_buffer_mem_orig = 0;
		pcap_store_queue__sizeOfBlocksInMemory = 0;
		PcapQueue_readFromFifo__blockStoreTrash_size = 0;
		AsyncClose__sizeOfDataInMemory = 0;
		PcapQueue_readFromFifo__blockStoreTrash_minTime = -1;
		PcapQueue_readFromFifo__blockStoreTrash_maxTime = -1;
	}
	void setMaxBufferMem(u_int64_t max_buffer_mem, bool orig = false) {
		this->max_buffer_mem = max_buffer_mem;
		if(orig) {
			this->max_buffer_mem_orig = max_buffer_mem;
		}
	}
	u_int64_t getMaxBufferMem() {
		return(this->max_buffer_mem);
	}
	void restoreMaxBufferMemFromOrig() {
		this->max_buffer_mem = this->max_buffer_mem_orig;
	}
	bool isSetOrig() {
		return(this->max_buffer_mem_orig > 0);
	}
	//pcap_store_queue::sizeOfBlocksInMemory
	void set__pcap_store_queue__sizeOfBlocksInMemory(volatile u_int64_t *sizeOfBlocksInMemory) {
		this->pcap_store_queue__sizeOfBlocksInMemory = *sizeOfBlocksInMemory;
	}
	u_int64_t get__pcap_store_queue__sizeOfBlocksInMemory() {
		return(this->pcap_store_queue__sizeOfBlocksInMemory);
	}
	void add__pcap_store_queue__sizeOfBlocksInMemory(size_t size) {
		__sync_fetch_and_add(&this->pcap_store_queue__sizeOfBlocksInMemory, size);
	}
	void sub__pcap_store_queue__sizeOfBlocksInMemory(size_t size) {
		__sync_fetch_and_sub(&this->pcap_store_queue__sizeOfBlocksInMemory, size);
	}
	//PcapQueue_readFromFifo::blockStoreTrash_size
	void set__PcapQueue_readFromFifo__blockStoreTrash_size(volatile u_int64_t *blockStoreTrash_size) {
		this->PcapQueue_readFromFifo__blockStoreTrash_size = *blockStoreTrash_size;
	}
	u_int64_t get__PcapQueue_readFromFifo__blockStoreTrash_size() {
		return(this->PcapQueue_readFromFifo__blockStoreTrash_size);
	}
	void add__PcapQueue_readFromFifo__blockStoreTrash_size(size_t size) {
		__sync_fetch_and_add(&this->PcapQueue_readFromFifo__blockStoreTrash_size, size);
	}
	void sub__PcapQueue_readFromFifo__blockStoreTrash_size(size_t size) {
		__sync_fetch_and_sub(&this->PcapQueue_readFromFifo__blockStoreTrash_size, size);
	}
	//AsyncClose::sizeOfDataInMemory
	void set__AsyncClose__sizeOfDataInMemory(volatile u_int64_t *sizeOfDataInMemory) {
		this->AsyncClose__sizeOfDataInMemory = *sizeOfDataInMemory;
	}
	u_int64_t get__AsyncClose__sizeOfDataInMemory() {
		return(this->AsyncClose__sizeOfDataInMemory);
	}
	void add__AsyncClose__sizeOfDataInMemory(size_t size) {
		__sync_fetch_and_add(&this->AsyncClose__sizeOfDataInMemory, size);
	}
	void sub__AsyncClose__sizeOfDataInMemory(size_t size) {
		__sync_fetch_and_sub(&this->AsyncClose__sizeOfDataInMemory, size);
	}
	//
	bool check__pcap_store_queue__push() {
		return(check() &&
		       pcap_store_queue__sizeOfBlocksInMemory + PcapQueue_readFromFifo__blockStoreTrash_size < max_buffer_mem * 0.9);
	}
	bool check__AsyncClose__add(size_t add) {
		return((check() &&
		        AsyncClose__sizeOfDataInMemory + add < max_buffer_mem * 0.9) ||
		       AsyncClose__sizeOfDataInMemory + add < max_buffer_mem * 0.1);
	}
	bool check() {
		return(pcap_store_queue__sizeOfBlocksInMemory + 
		       PcapQueue_readFromFifo__blockStoreTrash_size + 
		       AsyncClose__sizeOfDataInMemory < max_buffer_mem);
	}
	double getPercUsePB() {
		return((double)(pcap_store_queue__sizeOfBlocksInMemory + PcapQueue_readFromFifo__blockStoreTrash_size) / (max_buffer_mem * 0.9) * 100);
	}
	double getPercUsePBwithouttrash() {
		return((double)pcap_store_queue__sizeOfBlocksInMemory / (max_buffer_mem * 0.9) * 100);
	}
	double getPercUsePBtrash() {
		return((double)PcapQueue_readFromFifo__blockStoreTrash_size / (max_buffer_mem * 0.9) * 100);
	}
	double getPercUseAsync() {
		return((double)AsyncClose__sizeOfDataInMemory / (max_buffer_mem * 0.9) * 100);
	}
	//
	void PcapQueue_readFromFifo__blockStoreTrash_time_set(unsigned long time) {
		if(PcapQueue_readFromFifo__blockStoreTrash_minTime == (unsigned long)-1 ||
		   time < PcapQueue_readFromFifo__blockStoreTrash_minTime) {
			PcapQueue_readFromFifo__blockStoreTrash_minTime = time;
		}
		if(PcapQueue_readFromFifo__blockStoreTrash_maxTime == (unsigned long)-1 ||
		   time > PcapQueue_readFromFifo__blockStoreTrash_maxTime) {
			PcapQueue_readFromFifo__blockStoreTrash_maxTime = time;
		}
	}
	void PcapQueue_readFromFifo__blockStoreTrash_time_get(unsigned long *min, unsigned long *max) {
		*min = PcapQueue_readFromFifo__blockStoreTrash_minTime == (unsigned long)-1 ? 0 : PcapQueue_readFromFifo__blockStoreTrash_minTime;
		*max = PcapQueue_readFromFifo__blockStoreTrash_maxTime == (unsigned long)-1 ? 0 : PcapQueue_readFromFifo__blockStoreTrash_maxTime;
	}
	void PcapQueue_readFromFifo__blockStoreTrash_time_clear() {
		PcapQueue_readFromFifo__blockStoreTrash_minTime = -1;
		PcapQueue_readFromFifo__blockStoreTrash_maxTime = -1;
	}
private:
	u_int64_t max_buffer_mem;
	u_int64_t max_buffer_mem_orig;
	volatile u_int64_t pcap_store_queue__sizeOfBlocksInMemory;
	volatile u_int64_t PcapQueue_readFromFifo__blockStoreTrash_size;
	volatile u_int64_t AsyncClose__sizeOfDataInMemory;
	unsigned long PcapQueue_readFromFifo__blockStoreTrash_minTime;
	unsigned long PcapQueue_readFromFifo__blockStoreTrash_maxTime;
};

#endif
