#ifndef PCAP_QUEUE_H
#define PCAP_QUEUE_H


#include <memory.h>
#include <netdb.h>
#include <pthread.h>
#include <pcap.h>
#include <semaphore.h>
#include <deque>
#include <queue>
#include <string>
#include <vector>
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
#include "disk_io_monitor.h"

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
	void setUseSemSync(bool enable) {
		this->queueBlock->setUseSemSync(enable);
	}
	inline unsigned int wait_for_data(unsigned int timeout_us, unsigned int counter = (unsigned int)-1) {
		return(this->queueBlock->wait_for_data(timeout_us, counter));
	}
	inline unsigned int wait_for_free(unsigned int timeout_us, unsigned int counter = (unsigned int)-1) {
		return(this->queueBlock->wait_for_free(timeout_us, counter));
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
	void setUseSemSync(bool enable);
	unsigned int wait_for_data(unsigned int timeout_us, unsigned int counter = (unsigned int)-1);
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
	bool useSemSync;
	sem_t sem_filled;
friend class PcapQueue_readFromFifo;
};

struct sPcapStatData {
	enum eSectionNameBy {
		_section_id_by_title,
		_section_id_by_varname
	};
	enum eMode {
		_mode_standard,
		_mode_database_backup
	};
	struct sValue {
		string name;
		string value;
		string unit;
		vector<sValue> childs;
		sValue() {}
		sValue(const string &name, const string &value, const string &unit = "") : name(name), value(value), unit(unit) {}
	};
	struct sSectionValues {
		string sect_id;
		vector<sValue> values;
		sSectionValues() {}
		sSectionValues(const string &sect_id) : sect_id(sect_id) {}
	};
	struct sHelp {
		string title;
		string descr;
		vector<sValue> items;
		void set(const string &descr) {
			this->descr = descr;
		}
		void add(const string &name, const string &descr) {
			items.push_back(sValue(name, descr));
		}
	};
	struct sLoadState {
		struct {
			u_int64_t old_time_ms;
		} sql_q;
		struct {
			u_int64_t old_time_ms;
			unsigned long long last_transfered;
		} cache_dir_q;
		struct {
			u_int64_t old_time_ms;
		} read_threads;
		struct {
			u_int64_t old_time_ms;
			u_int64_t old_count_tlb;
		} tlb;
		struct {
			u_int64_t old_time_ms;
		} traffic;
		struct {
			u_int64_t old_time_ms;
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
		} ps;
		struct {
			u_int64_t key_found_old;
			u_int64_t sa_created_old;
			u_int64_t decrypt_ok_old;
			u_int64_t decrypt_no_key_old;
			u_int64_t decrypt_failed_old;
			u_int64_t packet_bad_old;
			u_int64_t decrypt_learned_spi_old;
			u_int64_t reassembly_used_old;
			u_int64_t incomplete_header_old;
			u_int64_t expires_updated_old;
		} esp;
		sLoadState() { reset(); }
		void reset() { memset((void*)this, 0, sizeof(*this)); }
	};
	eMode mode;
	bool initialized;
	struct sCalls {
		u_int64_t active;
		u_int64_t registers_active;
		u_int64_t total;
		u_int64_t storing;
		u_int64_t registers_total;
		bool valid;
		sCalls() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("calls"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const;
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
		void rrd() const;
	} calls;
	struct sAudio {
		u_int64_t queue_size;
		u_int64_t threads;
		bool valid;
		sAudio() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("audio"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} audio;
	struct sTranscribe {
		u_int64_t queue_size;
		u_int64_t count_threads;
		bool valid;
		sTranscribe() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("transcribe"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} transcribe;
	struct sSS7 {
		u_int64_t listmap_size;
		u_int64_t queue_size;
		bool valid;
		sSS7() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("ss7"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} ss7;
	struct sPS {
		unsigned long calls_new;
		unsigned long calls_cleanup;
		unsigned long calls_for_save;
		unsigned long calls_saved;
		unsigned long registers_new;
		unsigned long registers_cleanup;
		unsigned long packets_sip_all;
		unsigned long packets_sip_all_parsed;
		unsigned long packets_sip_register;
		unsigned long packets_sip_message;
		unsigned long packets_rtp;
		unsigned long packets_rtp_sdp_multi;
		unsigned long packets_all;
		vector_simple<unsigned long> packets_debug;
		bool calls_new_valid;
		bool calls_cleanup_valid;
		bool calls_for_save_valid;
		bool calls_saved_valid;
		bool registers_new_valid;
		bool registers_cleanup_valid;
		bool packets_sip_all_valid;
		bool packets_sip_all_parsed_valid;
		bool packets_sip_register_valid;
		bool packets_sip_message_valid;
		bool packets_rtp_valid;
		bool packets_rtp_sdp_multi_valid;
		bool packets_all_valid;
		bool valid;
		sPS() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("PS"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
		void rrd() const;
	} ps;
	struct sSqlF {
		struct sItem {
			int id_main;
			string_simple id_main_str;
			int id_2;
			int count;
			sItem() { memset((void*)this, 0, sizeof(*this)); }
		};
		vector_simple<sItem> items;
		vector_simple<sItem> items_proc;
		u_int32_t avg_delay;
		u_int32_t query_count;
		bool valid;
		sSqlF() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("SQLf"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
		void rrd() const;
	} sqlf;
	struct sSqlQ {
		struct sItem {
			int id_main;
			string_simple id_main_str;
			int id_2;
			int size;
			sItem() { memset((void*)this, 0, sizeof(*this)); }
		};
		vector_simple<sItem> items;
		u_int32_t avg_delay_std;
		u_int32_t avg_delay_redirect;
		u_int32_t count_std;
		u_int32_t count_redirect;
		u_int64_t insert_count;
		bool cloud_mode;
		int cloud_size;
		bool valid;
		sSqlQ() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("SQLq"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
		void rrd() const;
	} sqlq;
	struct sHeap {
		double all_perc;
		double used_perc;
		double trash_perc;
		double pool_perc;
		double async_write_perc;
		unsigned long trash_min_time;
		unsigned long trash_max_time;
		bool trash_time_valid;
		bool pool_valid;
		bool async_valid;
		bool valid;
		sHeap() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("heap"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
		void rrd() const;
	} heap;
	struct sDeq {
		double used_perc;
		unsigned int window;
		bool valid;
		sDeq() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("deq"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} deq;
	struct sDrop {
		struct sDropItem {
			string_simple interface_alias;
			u_int64_t count;
			sDropItem() { memset((void*)this, 0, sizeof(*this)); }
		};
		unsigned long bypass_buffer_exceeded;
		vector_simple<sDropItem> packet_drops;
		u_int64_t packet_drops_count;
		bool valid;
		sDrop() { memset((void*)this, 0, sizeof(*this)); }
		void load(unsigned long bypass, const vector<sDropItem> &drops, u_int64_t count);
		string title() const { return("drop"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
		void rrd() const;
	} drop;
	struct sPbDiskBuffer {
		double mb;
		double perc;
		bool valid;
		sPbDiskBuffer() { memset((void*)this, 0, sizeof(*this)); }
		void load(double mb, double perc);
		string title() const { return("fileq"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} pb_disk_buffer;
	struct sPbCompress {
		double value;
		bool valid;
		sPbCompress() { memset((void*)this, 0, sizeof(*this)); }
		void load(double value);
		string title() const { return("comp"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} pb_compress;
	struct sTraffic {
		double mbps_in;
		double mbps_out;
		double pps_in;
		double pps_out;
		u_int64_t packets_in_sum;
		u_int64_t packets_out_sum;
		bool mbps_in_valid;
		bool mbps_out_valid;
		bool pps_in_valid;
		bool pps_out_valid;
		bool packets_sum_valid;
		bool valid;
		sTraffic() { memset((void*)this, 0, sizeof(*this)); }
		void load(class PcapQueue *instance);
		string title() const { return(""); }
		string name() const { return("total_traffic"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(name(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
		void rrd() const;
	} traffic;
	struct sIo {
		sIOMetrics metrics;
		bool active;
		bool calibrating;
		int calibration_progress;
		string_simple status_string;
		sIo() : active(false), calibrating(false), calibration_progress(0) {}
		void load(double useAsyncWriteBuffer);
		string title() const { return("IO"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(active || calibrating) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
		void rrd() const;
	} disk_io;
	struct sCacheDirQ {
		u_int64_t files_queue;
		double mBps;
		bool valid;
		sCacheDirQ() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("cdq"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} cdq;
	struct sTarQueue {
		u_int64_t count;
		bool valid;
		sTarQueue() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("tarQ"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} tar_queue;
	struct sTarCopyQueue {
		u_int64_t length;
		bool valid;
		sTarCopyQueue() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("tarMq"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} tar_copy_queue;
	struct sTarChunkBuffer {
		double mb;
		bool valid;
		sTarChunkBuffer() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("tarB"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} tar_chunk_buffer;
	struct sFileBuffer {
		double mb;
		bool valid;
		sFileBuffer() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("fileB"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} file_buffer;
	struct sTarCPU {
		vector_simple<double> cpu_spool1;
		vector_simple<double> cpu_spool2;
		bool valid;
		sTarCPU() { memset((void*)this, 0, sizeof(*this)); }
		void load(int pstatDataIndex);
		string title() const { return("tarCPU"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const;
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
		void rrd() const;
	} tar_cpu;
	struct sReadThreads {
		struct sReadThread {
			string_simple interface_alias;
			double mbps;
			double cpu_main;
			bool cpu_main_valid;
			unsigned long aloc_stack;
			unsigned long alloc_alloc;
			double cpu_dpdk_worker;
			bool cpu_dpdk_worker_valid;
			vector_simple<double> cpu_dpdk_rte_read;
			double cpu_dpdk_rte_worker;
			bool cpu_dpdk_rte_worker_valid;
			double cpu_dpdk_rte_worker_slave;
			bool cpu_dpdk_rte_worker_slave_valid;
			double cpu_dpdk_rte_worker2;
			bool cpu_dpdk_rte_worker2_valid;
			double cpu_detach;
			bool cpu_detach_valid;
			unsigned long detach_aloc_stack;
			unsigned long detach_alloc_alloc;
			double cpu_pcap_process;
			bool cpu_pcap_process_valid;
			double cpu_defrag;
			bool cpu_defrag_valid;
			double cpu_md1;
			bool cpu_md1_valid;
			double cpu_md2;
			bool cpu_md2_valid;
			double cpu_dedup;
			bool cpu_dedup_valid;
			double cpu_service;
			bool cpu_service_valid;
			sReadThread() {memset((void*)this, 0, sizeof(*this));}
			string title() const;
			string render(bool with_title = true) const;
			void get_sections(vector<sValue> &out) const { out.push_back(sValue(string("read_thread_") + string(interface_alias), render(false))); }
			void get_values(vector<sValue> &out) const;
		};
		vector_simple<sReadThread> threads;
		double sum_max;
		int count_threads_sum_max;
		sReadThreads() : sum_max(0), count_threads_sum_max(0) {}
		void load(class PcapQueue *instance, int pstatDataIndex);
		string title() const { return("..."); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const;
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} read_threads;
	struct sT0 {
		double cpu_capture;
		double cpu_write;
		vector_simple<double> cpu_next;
		bool cpu_write_valid;
		bool valid;
		sT0() { memset((void*)this, 0, sizeof(*this)); }
		string title() const { return("t0CPU"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
		void rrd() const;
	} t0;
	struct sT1 {
		string_simple cpu_string;
		double cpu_perc;
		bool valid;
		sT1() { memset((void*)this, 0, sizeof(*this)); }
		string title() const { return("t1CPU"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
		void rrd() const;
	} t1;
	struct sT2 {
		struct sPreproc {
			string_simple name;
			double cpu;
			unsigned long aloc_stack;
			unsigned long alloc_alloc;
			vector_simple<double> cpu_next;
			sPreproc() { memset((void*)this, 0, sizeof(*this)); }
		};
		double cpu_mirror;
		bool cpu_mirror_valid;
		double cpu_pb;
		bool cpu_pb_valid;
		double cpu_detach;
		vector_simple<double> cpu_detach_next;
		bool cpu_detach_valid;
		double cpu_defrag;
		vector_simple<double> cpu_defrag_next;
		bool cpu_defrag_valid;
		double cpu_dedup;
		bool cpu_dedup_valid;
		double cpu_esp;
		bool cpu_esp_valid;
		double cpu_detach2;
		vector_simple<double> cpu_detach2_next;
		bool cpu_detach2_valid;
		double cpu_ipacc;
		bool cpu_ipacc_valid;
		vector_simple<sPreproc> preproc;
		double cpu_rtp_rh_main;
		bool cpu_rtp_rh_main_valid;
		vector_simple<double> cpu_rtp_rh_next;
		vector_simple<double> cpu_rtp_rd;
		double cpu_sum;
		double cpu_sum_for_rrd;
		int threads_count;
		bool valid;
		sT2() { memset((void*)this, 0, sizeof(*this)); }
		string title() const { return("t2CPU"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
		void rrd() const;
	} t2;
	struct sRTP {
		double cpu_sum;
		double cpu_max;
		double cpu_min;
		int threads_active;
		string_simple extend;
		bool valid;
		sRTP() { memset((void*)this, 0, sizeof(*this)); }
		string title() const { return("tRTP_CPU"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} rtp;
	struct sHttp {
		string_simple cpu_perc;
		bool valid;
		sHttp() { memset((void*)this, 0, sizeof(*this)); }
		void load(int pstatDataIndex);
		string title() const { return("thttpCPU"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} http;
	struct sWebrtc {
		string_simple cpu_perc;
		bool valid;
		sWebrtc() { memset((void*)this, 0, sizeof(*this)); }
		void load(int pstatDataIndex);
		string title() const { return("twebrtcCPU"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} webrtc;
	struct sSsl {
		string_simple cpu_perc;
		bool valid;
		sSsl() { memset((void*)this, 0, sizeof(*this)); }
		void load(int pstatDataIndex);
		string title() const { return("tsslCPU"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} ssl;
	struct sSslWs {
		unsigned int calls;
		unsigned int sessions_size;
		bool valid;
		sSslWs() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("tsslWS"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} ssl_ws;
	struct sDtls {
		u_int32_t queue_links;
		u_int32_t queue_packets;
		bool valid;
		sDtls() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("dtls"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} dtls;
	struct sEsp {
		unsigned long key_found;
		unsigned long sa_created;
		unsigned long decrypt_ok;
		unsigned long decrypt_no_key;
		unsigned long decrypt_failed;
		unsigned long packet_bad;
		unsigned long decrypt_learned_spi;
		unsigned long reassembly_used;
		unsigned long incomplete_header;
		unsigned long expires_updated;
		bool valid;
		sEsp() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("ESP"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} esp;
	struct sSipTcp {
		string_simple cpu_perc;
		bool valid;
		sSipTcp() { memset((void*)this, 0, sizeof(*this)); }
		void load(int pstatDataIndex);
		string title() const { return("tsip_tcpCPU"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} sip_tcp;
	struct sIpfix {
		string_simple value;
		void load();
		string title() const { return("ipfix"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(!value.empty()) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} ipfix;
	struct sHep {
		string_simple value;
		void load();
		string title() const { return("hep"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(!value.empty()) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} hep;
	struct sRibbonsbc {
		string_simple value;
		void load();
		string title() const { return("ribbonsbc"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(!value.empty()) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} ribbonsbc;
	struct sAsyncCloseCPU {
		vector_simple<double> cpu_perc;
		bool valid;
		sAsyncCloseCPU() { memset((void*)this, 0, sizeof(*this)); }
		void load(int pstatDataIndex);
		string title() const { return("tacCPU"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
		void rrd() const;
	} async_close_cpu;
	struct sAsyncCloseQueue {
		vector_simple<unsigned> queue;
		bool valid;
		sAsyncCloseQueue() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("tacQ"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} async_close_queue;
	struct sStoring {
		vector_simple<double> cpu_perc;
		bool valid;
		sStoring() { memset((void*)this, 0, sizeof(*this)); }
		void load(int pstatDataIndex);
		string title() const { return("storing"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} storing;
	struct sCharts {
		string_simple cpu_perc;
		u_int32_t requests;
		u_int64_t delay_us;
		u_int64_t queue_size;
		u_int64_t remote_queue_size;
		bool cpu_valid;
		bool requests_valid;
		bool queue_valid;
		bool remote_queue_valid;
		bool valid;
		sCharts() { memset((void*)this, 0, sizeof(*this)); }
		void load(int pstatDataIndex);
		string title() const { return("charts"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} charts;
	struct sIpacc {
		string_simple cpu_perc;
		bool valid;
		sIpacc() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("tipaccCPU"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} ipacc;
	struct sIpaccBuffer {
		u_int64_t buffer_length;
		u_int64_t buffer_size;
		bool valid;
		sIpaccBuffer() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("ipacc_buffer"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} ipacc_buffer;
	struct sRrd {
		double cpu_perc;
		bool valid;
		sRrd() { memset((void*)this, 0, sizeof(*this)); }
		void load(int pstatDataIndex);
		string title() const { return("RRD"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} rrd;
	struct sDedup {
		u_int64_t counter;
		u_int64_t collisions;
		bool valid;
		sDedup() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("DUPL"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} dedup;
	struct sRssVsz {
		u_int64_t rss_mb;
		u_int64_t vsz_mb;
		bool valid;
		sRssVsz() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("RSS/VSZ"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
		void rrd() const;
	} rss_vsz;
	struct sHugepages {
		u_int64_t base_mb;
		bool valid;
		sHugepages() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("HP"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} hugepages;
	struct sTcmAlloc {
		u_int64_t heap;
		u_int64_t alloc;
		u_int64_t free;
		u_int64_t unmapped;
		u_int64_t thread_cache;
		bool valid;
		sTcmAlloc() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("TCM"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} tcm_alloc;
	struct sHeapHugepage {
		u_int64_t mb;
		bool valid;
		sHeapHugepage() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("HEAP_HUGEPAGE"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} heap_hugepage;
	struct sHeapHashtable {
		u_int64_t alloc_mb;
		u_int64_t size_mb;
		bool valid;
		sHeapHashtable() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("HEAP_HASHTABLE"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} heap_hashtable;
	struct sLoadAvg {
		double la1;
		double la5;
		double la15;
		u_int64_t uptime_hours;
		int cpu_count;
		bool cpu_ht;
		bool overload_indicator;
		bool valid;
		sLoadAvg() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("LA"); }
		string name() const { return("LA"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(name(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
		void rrd() const;
	} load_avg;
	struct sTlb {
		unsigned int count;
		bool tlb_high_indicator;
		bool valid;
		sTlb() { memset((void*)this, 0, sizeof(*this)); }
		void load();
		string title() const { return("TLB"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(valid) { out.push_back(sValue(title(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} tlb;
	struct sVersion {
		string_simple value;
		void load();
		string title() const { return("v"); }
		string name() const { return("version"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(!value.empty()) { out.push_back(sValue(name(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} version;
	struct sExternalError {
		string_simple value;
		void load(const string &error);
		string title() const { return(""); }
		string name() const { return("external_error"); }
		string render(bool with_title = true) const;
		void get_sections(vector<sValue> &out) const { if(!value.empty()) { out.push_back(sValue(name(), render(false))); } }
		void get_values(vector<sValue> &out) const;
		void get_help(sHelp &out) const;
	} external_error;
	sPcapStatData() :
		mode(_mode_standard),
		initialized(false) {}
	string render();
	static string help();
	void get_sections_all(vector<sValue> &out, eSectionNameBy by = _section_id_by_title) const;
	void get_values_all(vector<sSectionValues> &out, eSectionNameBy by = _section_id_by_varname) const;
	string get_sections_all_json(eSectionNameBy by = _section_id_by_title) const;
	string get_values_all_json(eSectionNameBy by = _section_id_by_varname) const;
	void rrd_all() const;
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
	virtual double pcapStat_get_speed_mb_s(u_int64_t divide_ms);
	#if LOG_PACKETS_PER_SEC
	virtual u_int64_t pcapStat_get_speed_packets_s(u_int64_t divide_ms);
	#endif
	virtual double pcapStat_get_speed_out_mb_s(u_int64_t divide_ms);
	#if LOG_PACKETS_PER_SEC
	virtual u_int64_t pcapStat_get_speed_out_packets_s(u_int64_t divide_ms);
	#endif
	virtual unsigned long pcapStat_get_bypass_buffer_size_exeeded() { return(0); }
	virtual double pcapStat_get_disk_buffer_perc() { return(-1); }
	virtual double pcapStat_get_disk_buffer_mb() { return(-1); }
	virtual string pcapStatString_interface(int /*statPeriod*/) { return(""); }
	virtual string pcapDropCountStat_interface() { return(""); }
	virtual ulong getCountPacketDrop() { return(0); }
	virtual void getStatPacketDrop(vector<sPcapStatData::sDrop::sDropItem> * /*items*/) {}
	virtual void pcapStatString_cpuUsageReadThreads(double *sumMax, int *countThreadsSumMax, u_int64_t /*divide_ms*/, int /*pstatDataIndex*/, vector_simple<sPcapStatData::sReadThreads::sReadThread> * /*data*/) {
		if(sumMax) *sumMax = 0;
		if(countThreadsSumMax) *countThreadsSumMax = 0;
	};
	virtual void initStat_interface() {};
	int getThreadPid(eTypeThread typeThread);
	pstat_data *getThreadPstatData(eTypeThread typeThread, int pstatDataIndex);
	void preparePstatData(eTypeThread typeThread, int pstatDataIndex);
	double getCpuUsagePerc(eTypeThread typeThread, int pstatDataIndex, bool preparePstatData = true);
	virtual string getCpuUsage(bool /*writeThread*/, int /*pstatDataIndex*/, bool /*preparePstatData*/ = true) { return(""); }
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
	bool initAllReadThreadsFinished;
	cThreadMonitor::sThread *thread_data_main;
	cThreadMonitor::sThread *thread_data_write;
protected:
	class PcapQueue_readFromFifo *instancePcapFifo;
private:
	u_char* packetBuffer;
	PcapQueue *instancePcapHandle;
	u_int64_t lastTimeLogErrPcapNextExNullPacket;
	u_int64_t lastTimeLogErrPcapNextExErrorReading;
	u_long pcapStatLogCounter;
	u_long pcapStatCpuCheckCounter;
friend struct sPcapStatData::sReadThreads;
friend struct sPcapStatData::sTraffic;
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
		extern int opt_udpfrag;
		if(opt_udpfrag) {
			ip_defrag = new FILE_LINE(0) cIpFrag();
		} else {
			ip_defrag = NULL;
		}
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
			delete ip_defrag;
		}
	}
	void null() {
		int not_null_size = 0;
		not_null_size += sizeof(dedup_buffer);
		#if DEDUPLICATE_COLLISION_TEST
		not_null_size += sizeof(dedup_buffer_ct_md5);
		#endif
		not_null_size += sizeof(ip_defrag);
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
	cIpFrag *ip_defrag;
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
	void pcapBreakloopIface();
	inline int pcap_dispatch(pcap_t *pcapHandle);
	inline int pcapProcess(sHeaderPacket **header_packet, int pushToStack_queue_index,
			       pcap_block_store *block_store, int block_store_index,
			       int ppf, pcap_dumper_t *pcapDumpHandle = NULL);
	virtual string pcapStatString_interface(int statPeriod);
	virtual string pcapDropCountStat_interface();
	virtual ulong getCountPacketDrop();
	virtual void getStatPacketDrop(vector<sPcapStatData::sDrop::sDropItem> *items);
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
	int64_t lastPcapTime_s;
	u_int64_t lastTimeErrorLogPcapTime_ms;
	u_int64_t firstTimeErrorLogEtherTypeFFFF_ms;
	u_int64_t counterErrorLogEtherTypeFFFF_ms;
	u_int64_t firstPacketTime_us;
	u_int64_t firstPacketTime_at_ms;
	bool waitForPacketTime;
	pcap_pkthdr* wait_header;
	u_char *wait_packet;
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
	inline static u_char* _dpdk_packet_allocation(void *user, u_int32_t caplen, bool force, bool pb_init) {
		PcapQueue_readFromInterfaceThread::pcap_dispatch_data *dd = (PcapQueue_readFromInterfaceThread::pcap_dispatch_data*)user;
		return(dd->me->dpdk_packet_allocation(dd, caplen, force, pb_init));
	}
	u_char* dpdk_packet_allocation(pcap_dispatch_data *dd, u_int32_t caplen, bool force, bool pb_init);
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
			u_int64_t wait_start = 0;
			if(sverb.dpdk) {
				wait_start = getTimeMS_rdtsc();
				cout << "wait for send no-active block - tid: "
				     << get_unix_tid() << ", " << __FILE__ << ":" << __LINE__ << flush;
			}
			while(dd->copy_block_full[copy_block_no_active_index]) {
				__ASM_PAUSE;
			}
			if(sverb.dpdk) {
				u_int64_t wait_stop = getTimeMS_rdtsc();
				if(wait_stop > wait_start) cout << " : " << (wait_stop - wait_start) << "ms";
				cout << endl;
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
	void terminate();
	const char *getTypeThreadName();
	void prepareLogTraffic();
	double getTraffic(u_int64_t divide_ms);
private:
	pthread_t threadHandle;
	int threadId;
	volatile int threadInitOk;
	bool threadInitFailed;
	hpi_batch **qring;
	pcap_block_store **qring_blocks;
	volatile int *qring_blocks_used;
	unsigned int qringmax;
	volatile unsigned int readit;
	volatile unsigned int writeit;
	volatile int qring_sync;
	sem_t sem_qring_free_count;
	sem_t sem_qring_filled_count;
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
	volatile bool force_push;
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
	cThreadMonitor::sThread *thread_data;
	#if DEBUG_PB_BLOCKS_SEQUENCE
	u_int64_t pb_blocks_sequence_last;
	#endif
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
	virtual void getStatPacketDrop(vector<sPcapStatData::sDrop::sDropItem> *items);
	void initStat_interface();
	void pcapStatString_cpuUsageReadThreads(double *sumMax, int *countThreadsSumMax, u_int64_t divide_ms, int pstatDataIndex, vector_simple<sPcapStatData::sReadThreads::sReadThread> *data);
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
	sem_t sem_blocks_available;
	rqueue_quick<pcap_block_store*> *block_qring;
friend class PcapQueue_readFromInterfaceThread;
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
	void addBlockStoreToPcapStoreQueue_ext(pcap_block_store *blockStore);
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
	u_int64_t last_pb_send_confirmation_time_us;
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
		esp,
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
		volatile bool signal_done;
		void null() {
			batch = NULL;
			start = 0;
			end = 0;
			skip = 0;
			thread_index = 0;
			data_ready = 0;
			processing = 0;
			signal_done = false;
		}
	};
	struct s_next_thread {
		volatile int thread_id;
		pthread_t thread_handle;
		pstat_data thread_pstat_data[2][2];
		s_next_thread_data next_data;
		sem_t sem_sync;
		bool sem_sync_inited;
		sem_t sem_done;
		bool sem_done_inited;
		volatile int terminate;
		void null() {
			thread_id = 0;
			thread_handle = 0;
			memset(thread_pstat_data, 0, sizeof(thread_pstat_data));
			next_data.null();
			memset(&sem_sync, 0, sizeof(sem_sync));
			sem_sync_inited = false;
			memset(&sem_done, 0, sizeof(sem_done));
			sem_done_inited = false;
			terminate = 0;
		}
		void sem_init() {
			extern int opt_pcap_queue_output_next_thread_sem_sync;
			if(opt_pcap_queue_output_next_thread_sem_sync >= 1) {
				::sem_init(&sem_sync, 0, 0);
				sem_sync_inited = true;
			}
			if(opt_pcap_queue_output_next_thread_sem_sync == 2) {
				::sem_init(&sem_done, 0, 0);
				sem_done_inited = true;
			}
		}
		void sem_term() {
			if(sem_sync_inited) {
				sem_destroy(&sem_sync);
				sem_sync_inited = false;
			}
			if(sem_done_inited) {
				sem_destroy(&sem_done);
				sem_done_inited = false;
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
	inline __attribute__((always_inline)) void push(sHeaderPacketPQout *hp);
	bool _push__new_batch(u_int64_t time_us, sHeaderPacketPQout *hp);
	void _push__push_batch();
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
	inline void processEsp(sHeaderPacketPQout *hp);
	inline void processEsp_push(sHeaderPacketPQout *hp);
	inline void processDetach2(sHeaderPacketPQout *hp);
	string getNameOutputThread() {
		switch(typeOutputThread) {
		case detach:
			return("detach");
		case defrag:
			return("defrag");
		case dedup:
			return("dedup");
		case esp:
			return("esp");
		case detach2:
			return("detach2");
		}
		return("");
	}
	void preparePstatData(int nextThreadId, int pstatDataIndex);
	double getCpuUsagePerc(int nextThreadId, int pstatDataIndex, bool preparePstatData = true);
	bool existsNextThread(int next_thread_index) {
		return(next_thread_index < MAX_PRE_PROCESS_PACKET_NEXT_THREADS &&
		       this->next_threads[next_thread_index].thread_id);
	}
private:
	void flushDownstream();
	inline void tm_inc_packets_out(sHeaderPacketPQout *hp) {
		if(sverb.sniffer_threads_ext > 1 && thread_data) {
			thread_data->inc_packets_out(hp->header->get_caplen());
		}
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
	sem_t sem_qring_free_count;
	sem_t sem_qring_filled_count;
	volatile unsigned int readit;
	volatile unsigned int writeit;
	pthread_t out_thread_handle;
	pstat_data threadPstatData[2][2];
	int outThreadId;
	cIpFrag *ip_defrag;
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
	sem_t sem_items_ready;
	volatile int active_threads_for_batch;
	volatile int8_t *items_flag;
	u_int8_t *items_index;
	u_int8_t *items_thread_index;
	#if EXPERIMENTAL_CHECK_TID_IN_PUSH
	unsigned push_thread;
	u_int64_t last_race_log[2];
	#endif
	cThreadMonitor::sThread *thread_data;
friend inline void *_PcapQueue_outputThread_outThreadFunction(void *arg);
};


void PcapQueue_init();
void PcapQueue_term();
int getThreadingMode();
void setThreadingMode(int threadingMode);
void reset_pcap_stat_load_state();

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
