#ifndef BUFFERS_CONTROL_H
#define BUFFERS_CONTROL_H

class cBuffersControl {
public:
	cBuffersControl() {
		max_buffer_mem = 0;
		max_buffer_mem_own_use = 0;
		max_buffer_mem_other_uses = 0;
		pb_used_size = 0;
		pb_used_dequeu_size = 0;
		pb_trash_size = 0;
		pb_pool_size = 0;
		asyncwrite_size = 0;
		pb_trash_minTime = -1;
		pb_trash_maxTime = -1;
		dequeu_time = 0;
	}
	void setMaxBufferMemMB(u_int32_t max_buffer_mem_mb, u_int32_t max_buffer_mem_other_uses_mb) {
		this->max_buffer_mem = max_buffer_mem_mb * (1024ull * 1024);
		this->max_buffer_mem_own_use = (max_buffer_mem_mb - max_buffer_mem_other_uses_mb) * (1024ull * 1024);
		this->max_buffer_mem_other_uses = max_buffer_mem_other_uses_mb * (1024ull * 1024);
	}
	u_int64_t getMaxBufferMemMB() {
		return(this->max_buffer_mem / (1024 * 1024));
	}
	void set__pb_used_size(volatile u_int64_t *sizeOfBlocksInMemory) {
		this->pb_used_size = *sizeOfBlocksInMemory;
	}
	u_int64_t get__pb_used_size() {
		return(this->pb_used_size);
	}
	void add__pb_used_size(size_t size) {
		__SYNC_ADD(this->pb_used_size, size);
	}
	void sub__pb_used_size(size_t size) {
		__SYNC_SUB(this->pb_used_size, size);
		if(this->pb_used_size > LLONG_MAX) {
			this->pb_used_size = 0;
		}
	}
	void add__pb_used_dequeu_size(size_t size) {
		__SYNC_ADD(this->pb_used_dequeu_size, size);
	}
	void sub__pb_used_dequeu_size(size_t size) {
		__SYNC_SUB(this->pb_used_dequeu_size, size);
		if(this->pb_used_dequeu_size > LLONG_MAX) {
			this->pb_used_dequeu_size = 0;
		}
	}
	void set__pb_trash_size(volatile u_int64_t *blockStoreTrash_size) {
		this->pb_trash_size = *blockStoreTrash_size;
	}
	u_int64_t get__pb_trash_size() {
		return(this->pb_trash_size);
	}
	void add__pb_trash_size(size_t size) {
		__SYNC_ADD(this->pb_trash_size, size);
	}
	void sub__pb_trash_size(size_t size) {
		__SYNC_SUB(this->pb_trash_size, size);
		if(this->pb_trash_size > LLONG_MAX) {
			this->pb_trash_size = 0;
		}
	}
	void set__pb_pool_size(volatile u_int64_t *blockStorePool_size) {
		this->pb_pool_size = *blockStorePool_size;
	}
	u_int64_t get__pb_pool_size() {
		return(this->pb_pool_size);
	}
	void add__pb_pool_size(size_t size) {
		__SYNC_ADD(this->pb_pool_size, size);
	}
	void sub__pb_pool_size(size_t size) {
		__SYNC_SUB(this->pb_pool_size, size);
		if(this->pb_pool_size > LLONG_MAX) {
			this->pb_pool_size = 0;
		}
	}
	void set__asyncwrite_size(volatile u_int64_t *sizeOfDataInMemory) {
		this->asyncwrite_size = *sizeOfDataInMemory;
	}
	u_int64_t get__asyncwrite_size() {
		return(this->asyncwrite_size);
	}
	void add__asyncwrite_size(size_t size) {
		__SYNC_ADD(this->asyncwrite_size, size);
	}
	void sub__asyncwrite_size(size_t size) {
		__SYNC_SUB(this->asyncwrite_size, size);
		if(this->asyncwrite_size > LLONG_MAX) {
			this->asyncwrite_size = 0;
		}
	}
	bool check__pb__add_used(size_t add = 0) {
		return(check() &&
		       pb_used_size + 
		       pb_trash_size +
		       pb_pool_size + add < _max_buffer_mem_own_use_pb());
	}
	bool check__pb__add_pool(size_t add) {
		extern int opt_dpdk_rotate_packetbuffer_pool_max_perc;
		if(opt_dpdk_rotate_packetbuffer_pool_max_perc && check()) {
			u_int64_t sum = this->sum();
			if(sum < max_buffer_mem_own_use) {
				return(pb_pool_size + add < (max_buffer_mem_own_use - sum) * opt_dpdk_rotate_packetbuffer_pool_max_perc / 100);
			}
		}
		return(false);
	}
	bool check__asyncwrite__add(size_t add) {
		return((check() &&
		        asyncwrite_size + add < _max_buffer_mem_own_use_pb()) ||
		       asyncwrite_size + add < _max_buffer_mem_own_use_asyncwrite());
	}
	bool check() {
		return(sum() < max_buffer_mem_own_use);
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
				pb_pool_size) / _max_buffer_mem_own_use_pb() * 100);
	}
	double getPerc_pb_used() {
		return((double)pb_used_size / _max_buffer_mem_own_use_pb() * 100);
	}
	double getPerc_pb_used_dequeu() {
		return((double)pb_used_dequeu_size / _max_buffer_mem_own_use_pb() * 100);
	}
	double getPerc_pb_trash() {
		return((double)pb_trash_size / _max_buffer_mem_own_use_pb() * 100);
	}
	double getPerc_pb_pool() {
		return((double)pb_pool_size / _max_buffer_mem_own_use_pb() * 100);
	}
	double getPerc_asyncwrite() {
		return((double)asyncwrite_size / _max_buffer_mem_own_use_pb() * 100);
	}
	u_int64_t _max_buffer_mem_own_use_pb() {
		u_int16_t __asyncwrite_perc = _asyncwrite_perc();
		return(__asyncwrite_perc ?
			max_buffer_mem_own_use * (1. - 1./__asyncwrite_perc) :
			max_buffer_mem_own_use);
	}
	u_int64_t _max_buffer_mem_own_use_asyncwrite() {
		u_int16_t __asyncwrite_perc = _asyncwrite_perc();
		return(__asyncwrite_perc ?
			max_buffer_mem_own_use * (1./__asyncwrite_perc) : 
			0);
	}
	u_int16_t _asyncwrite_perc() {
		extern int opt_pcap_dump_asyncwrite;
		extern int opt_pcap_dump_tar;
		extern bool opt_pcap_dump_tar_bypass;
		return(!opt_pcap_dump_asyncwrite ? 0 :
		       opt_pcap_dump_tar && opt_pcap_dump_tar_bypass ? 5 :
		       10);
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
	void set_dequeu_time(unsigned int dequeu_time) {
		this->dequeu_time = dequeu_time;
	}
	unsigned int get_dequeu_time() {
		return(dequeu_time);
	}
	string debug() {
	       ostringstream outStr;
	       outStr << "BUFFERS CONTROL" << endl
		      << "   max_buffer_mem: " << max_buffer_mem << " (" << (max_buffer_mem / 1024 / 1024) << "MB)" << endl
		      << "   max_buffer_mem_own_use: " << max_buffer_mem_own_use << " (" << (max_buffer_mem_own_use / 1024 / 1024) << "MB)" << endl
		      << "   max_buffer_mem_other_uses: " << max_buffer_mem_other_uses << " (" << (max_buffer_mem_other_uses / 1024 / 1024) << "MB)" << endl
		      << "   pb_used_size: " << pb_used_size << " (" << (pb_used_size / 1024 / 1024) << "MB)" << endl
		      << "   pb_used_dequeu_size: " << pb_used_dequeu_size << " (" << (pb_used_dequeu_size / 1024 / 1024) << "MB)" << endl
		      << "   pb_trash_size: " << pb_trash_size << " (" << (pb_trash_size / 1024 / 1024) << "MB)" << endl
		      << "   pb_pool_size: " << pb_pool_size << " (" << (pb_pool_size / 1024 / 1024) << "MB)" << endl
		      << "   asyncwrite_size: " << asyncwrite_size << " (" << (asyncwrite_size / 1024 / 1024) << "MB)" << endl;
		return(outStr.str());
	}
private:
	u_int64_t max_buffer_mem;
	u_int64_t max_buffer_mem_own_use;
	u_int64_t max_buffer_mem_other_uses;
	volatile u_int64_t pb_used_size;
	volatile u_int64_t pb_used_dequeu_size;
	volatile u_int64_t pb_trash_size;
	volatile u_int64_t pb_pool_size;
	volatile u_int64_t asyncwrite_size;
	unsigned long pb_trash_minTime;
	unsigned long pb_trash_maxTime;
	unsigned int dequeu_time;
};

#endif
