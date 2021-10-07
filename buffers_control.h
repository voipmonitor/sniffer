#ifndef BUFFERS_CONTROL_H
#define BUFFERS_CONTROL_H

class cBuffersControl {
public:
	cBuffersControl() {
		max_buffer_mem = 0;
		max_buffer_mem_orig = 0;
		pb_used_size = 0;
		pb_trash_size = 0;
		pb_pool_size = 0;
		asyncwrite_size = 0;
		pb_trash_minTime = -1;
		pb_trash_maxTime = -1;
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
	void set__pb_used_size(volatile u_int64_t *sizeOfBlocksInMemory) {
		this->pb_used_size = *sizeOfBlocksInMemory;
	}
	u_int64_t get__pb_used_size() {
		return(this->pb_used_size);
	}
	void add__pb_used_size(size_t size) {
		__sync_fetch_and_add(&this->pb_used_size, size);
	}
	void sub__pb_used_size(size_t size) {
		__sync_fetch_and_sub(&this->pb_used_size, size);
	}
	void set__pb_trash_size(volatile u_int64_t *blockStoreTrash_size) {
		this->pb_trash_size = *blockStoreTrash_size;
	}
	u_int64_t get__pb_trash_size() {
		return(this->pb_trash_size);
	}
	void add__pb_trash_size(size_t size) {
		__sync_fetch_and_add(&this->pb_trash_size, size);
	}
	void sub__pb_trash_size(size_t size) {
		__sync_fetch_and_sub(&this->pb_trash_size, size);
	}
	void set__pb_pool_size(volatile u_int64_t *blockStorePool_size) {
		this->pb_pool_size = *blockStorePool_size;
	}
	u_int64_t get__pb_pool_size() {
		return(this->pb_pool_size);
	}
	void add__pb_pool_size(size_t size) {
		__sync_fetch_and_add(&this->pb_pool_size, size);
	}
	void sub__pb_pool_size(size_t size) {
		__sync_fetch_and_sub(&this->pb_pool_size, size);
	}
	void set__asyncwrite_size(volatile u_int64_t *sizeOfDataInMemory) {
		this->asyncwrite_size = *sizeOfDataInMemory;
	}
	u_int64_t get__asyncwrite_size() {
		return(this->asyncwrite_size);
	}
	void add__asyncwrite_size(size_t size) {
		__sync_fetch_and_add(&this->asyncwrite_size, size);
	}
	void sub__asyncwrite_size(size_t size) {
		__sync_fetch_and_sub(&this->asyncwrite_size, size);
	}
	bool check__pb__add_used(size_t add = 0) {
		return(check() &&
		       pb_used_size + 
		       pb_trash_size +
		       pb_pool_size + add < max_buffer_mem * 0.9);
	}
	bool check__pb__add_pool(size_t add) {
		extern int opt_dpdk_rotate_packetbuffer_pool_max_perc;
		if(opt_dpdk_rotate_packetbuffer_pool_max_perc && check()) {
			u_int64_t sum = this->sum();
			if(sum < max_buffer_mem) {
				return(pb_pool_size + add < (max_buffer_mem - sum) * opt_dpdk_rotate_packetbuffer_pool_max_perc / 100);
			}
		}
		return(false);
	}
	bool check__asyncwrite__add(size_t add) {
		return((check() &&
		        asyncwrite_size + add < max_buffer_mem * 0.9) ||
		       asyncwrite_size + add < max_buffer_mem * 0.1);
	}
	bool check() {
		return(sum() < max_buffer_mem);
	}
	u_int64_t sum() {
		return(pb_used_size + 
		       pb_trash_size + 
		       pb_pool_size +
		       asyncwrite_size);
	}
	double getPerc_pb() {
		return((double)(pb_used_size + 
				pb_trash_size + 
				pb_pool_size) / (max_buffer_mem * 0.9) * 100);
	}
	double getPerc_pb_used() {
		return((double)pb_used_size / (max_buffer_mem * 0.9) * 100);
	}
	double getPerc_pb_trash() {
		return((double)pb_trash_size / (max_buffer_mem * 0.9) * 100);
	}
	double getPerc_pb_pool() {
		return((double)pb_pool_size / (max_buffer_mem * 0.9) * 100);
	}
	double getPerc_asyncwrite() {
		return((double)asyncwrite_size / (max_buffer_mem * 0.9) * 100);
	}
	void PcapQueue_readFromFifo__blockStoreTrash_time_set(unsigned long time) {
		if(pb_trash_minTime == (unsigned long)-1 ||
		   time < pb_trash_minTime) {
			pb_trash_minTime = time;
		}
		if(pb_trash_maxTime == (unsigned long)-1 ||
		   time > pb_trash_maxTime) {
			pb_trash_maxTime = time;
		}
	}
	void PcapQueue_readFromFifo__blockStoreTrash_time_get(unsigned long *min, unsigned long *max) {
		*min = pb_trash_minTime == (unsigned long)-1 ? 0 : pb_trash_minTime;
		*max = pb_trash_maxTime == (unsigned long)-1 ? 0 : pb_trash_maxTime;
	}
	void PcapQueue_readFromFifo__blockStoreTrash_time_clear() {
		pb_trash_minTime = -1;
		pb_trash_maxTime = -1;
	}
private:
	u_int64_t max_buffer_mem;
	u_int64_t max_buffer_mem_orig;
	volatile u_int64_t pb_used_size;
	volatile u_int64_t pb_trash_size;
	volatile u_int64_t pb_pool_size;
	volatile u_int64_t asyncwrite_size;
	unsigned long pb_trash_minTime;
	unsigned long pb_trash_maxTime;
};

#endif
