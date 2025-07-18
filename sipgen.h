#ifndef SIPGEN_H
#define SIPGEN_H


#include <string>
#include <map>
#include <set>

#include "ip.h"
#include "tools.h"
#include "tools_global.h"


using namespace std;

class sgMaster;
class sgCalls;
class sgCall;
class sgStream;

struct sgParams {
	sgParams() {
		pcap = "";
		interface = "";
		calls = 80;
		threads = 4;
		max_time = 0;
		dur_rtp_min = 2;
		dur_rtp_max = 30;
		time_183_ms_min = 50;
		time_183_ms_max = 1000;
		time_200_ms_min = 100;
		time_200_ms_max = 5000;
	}
	void parse(const char *params);
	void check();
	void printParams();
	string pcap;
	string interface;
	unsigned calls;
	unsigned threads;
	unsigned max_time;
	unsigned dur_rtp_min;
	unsigned dur_rtp_max;
	unsigned time_183_ms_min;
	unsigned time_183_ms_max;
	unsigned time_200_ms_min;
	unsigned time_200_ms_max;
};

class sgPackets {
public:
	struct sPacketInfo {
		u_int16_t size;
		u_int64_t time;
	};
	sgPackets();
	~sgPackets();
	void add(u_char *packet, u_int16_t size, u_int64_t time) {
		if(!first_time) {
			first_time = time;
		} else if(time >= first_time + max_time) {
			full = true;
		}
		sPacketInfo pi;
		pi.size = size;
		pi.time = time;
		info.push_back(pi);
		packets.push_back(packet);
	}
	unsigned size() {
		return(info.size());
	}
	u_int64_t time_packet() {
		return(info[pos].time);
	}
	bool is_full() {
		return(full);
	}
	u_char *get_packet(u_int16_t &size, u_int64_t &time) {
		if(pos >= packets.size()) {
			return(NULL);
		}
		u_char *packet = packets[pos];
		sPacketInfo pi = info[pos];
		size = pi.size;
		time = pi.time;
		++pos;
		return(packet);
	}
	bool completed() {
		return(pos >= packets.size());
	}
private:
	u_int64_t max_time;
	vector<sPacketInfo> info;
	vector<u_char*> packets;
	unsigned pos;
	u_int64_t first_time;
	bool full;
};

class sgPacketsQueue {
public:
	sgPacketsQueue();
	~sgPacketsQueue();
	void add(u_char *packet, u_int16_t size, u_int64_t time) {
		if(!packets_in) {
			packets_in = new FILE_LINE(0) sgPackets;
		}
		packets_in->add(packet, size, time);
		if(packets_in->is_full()) {
			push(packets_in);
			packets_in = NULL;
		}
	}
	void force_push() {
		if(packets_in) {
			push(packets_in);
			packets_in = NULL;
		}
	}
	void push(sgPackets *packets);
	sgPackets *pop();
	unsigned size() {
		return(queue.size());
	}
private:
	sgPackets *packets_in;
	list<sgPackets*> queue;
	volatile int sync;
};

class sgPacketsDestroyQueue {
public:
	sgPacketsDestroyQueue();
	~sgPacketsDestroyQueue();
	void push(sgPackets *packets);
	bool destroy();
private:
	list<sgPackets*> queue;
	volatile int sync;
};

class sgPacketsPool {
public:
	struct sPacketsItem {
		sgPackets *packets;
		int next;
	};
	struct sMinHeapData {
		inline sMinHeapData() {
			this->index = -1;
		}
		inline sMinHeapData(int index) {
			this->index = index;
		}
		inline int getIndex() {
			return(index);
		}
		int index;
		static inline bool gt(sMinHeapData a, sMinHeapData b, void *cmp_data) {
			sPacketsItem *items = (sPacketsItem*)cmp_data;
			return(items[a.index].packets->time_packet() > items[b.index].packets->time_packet());
		}
		static inline bool lt(sMinHeapData a, sMinHeapData b, void *cmp_data) {
			sPacketsItem *items = (sPacketsItem*)cmp_data;
			return(items[a.index].packets->time_packet() < items[b.index].packets->time_packet());
		}
	};
public:
	sgPacketsPool(int maxItems) {
		this->maxItems = maxItems;
		items = new FILE_LINE(0) sPacketsItem[maxItems];
		for(int i = 0; i < maxItems - 1; i++) {
			items[i].next = i + 1;
		}
		items[maxItems - 1].next = -1;
		minHeap = new FILE_LINE(0) cMinHeap<sMinHeapData>(maxItems, items);
		freeHead = 0;
		usedHead = -1;
		usedCount = 0;
	}
	~sgPacketsPool() {
		delete [] items;
		delete minHeap;
	}
	inline int new_item() {
		if(freeHead == -1) {
			return(-1);
		}
		int _new = freeHead;
		freeHead = items[freeHead].next;
		items[_new].next = usedHead;
		usedHead = _new;
		++usedCount;
		return(_new);
	}
	inline void free_item(int index) {
		if(index < 0 || index >= maxItems) {
			return;
		}
		int *prev = &usedHead;
		while(*prev != -1) {
			if(*prev == index) {
				*prev = items[index].next;
				break;
			}
			prev = &items[*prev].next;
		}
		items[index].next = freeHead;
		freeHead = index;
		--usedCount;
	}
	inline void set(int index, sgPackets *packets) {
		items[index].packets = packets;
	}
	inline bool is_full() {
		return(freeHead == -1);
	}
private:
	sPacketsItem *items;
	cMinHeap<sMinHeapData> *minHeap;
	int maxItems;
	int freeHead;
	int usedHead;
	int usedCount;
friend class sgMaster;
};

class sgMaster {
public:
	struct sStat {
		sStat() {
			calls = 0;
			packets_per_sec = 0;
		}
		unsigned calls;
		unsigned packets_per_sec;
	};
public:
	sgMaster(unsigned count_calls_instances);
	~sgMaster();
	void set_start_params(unsigned max_calls, unsigned max_time);
	void set_dst_pcap(const char *pcap_filename);
	void set_interface(const char *interface);
	void start();
private:
	void process();
	void process_packet(u_char *packet, u_int16_t size, u_int64_t time);
	void evEnd();
	void evStat(unsigned index, unsigned calls, unsigned packets_per_sec);
	void printStat();
	void checkEnd();
	static void *start_destroy_thread(void *arg);
	void destroy_thread();
	static void *start_stat_thread(void *arg);
	void stat_thread_proc();
private:
	unsigned count_calls_instances;
	sgCalls **calls_instances;
	sStat *stats;
	u_int64_t print_stat_last_at;
	sgPacketsPool *packets_pool;
	u_int64_t time_delay;
	unsigned max_calls;
	unsigned max_time;
	string pcap_filename;
	PcapDumper *dumper;
	string interface;
	volatile bool end;
	sgPacketsDestroyQueue destroy_queue;
	pthread_t destroy_queue_thread;
	pthread_t stat_thread;
	volatile bool terminating;
friend class sgCalls;
};

class sgCalls {
public:
	sgCalls(sgMaster *master, unsigned master_index,
		const char *callid_prefix,
		vmIP sip_src_ip,
		vmIP sip_dst_ip,
		vmIP rtp_src_ip,
		vmIP rtp_dst_ip,
		vmPort sip_dst_port);
	~sgCalls();
	void start(unsigned max_calls, unsigned max_time, bool run_in_thread);
	static void *start_process(void *arg);
	void process();
	void set_dst_pcap(const char *pcap_filename);
	void set_interface(const char *interface);
private:
	u_char *create_udp_packet(u_char *data, unsigned int data_len,
				  vmIPport *src, vmIPport *dst,
				  unsigned *packet_len);
	static pcap_pkthdr *create_pcap_pkthdr(u_int64_t time, unsigned packet_len);
	void newCall();
	void sendPacket(u_char *data, unsigned data_len,
			vmIPport *src, vmIPport *dst, u_int64_t time);
private:
	sgMaster *master;
	unsigned master_index;
	string callid_prefix;
	vmIP sip_src_ip;
	vmIP sip_dst_ip;
	vmIP rtp_src_ip;
	vmIP rtp_dst_ip;
	vmPort sip_dst_port;
	cBitSet sip_src_port_used;
	cBitSet rtp_src_port_used;
	cBitSet rtp_dst_port_used;
	set<u_int32_t> ssrc_used;
	map<string, sgCall*> calls;
	unsigned max_calls;
	unsigned max_time;
	string pcap_filename;
	PcapDumper *dumper;
	string interface;
	pcap_t *pcap;
	sgPacketsQueue packets_queue;
	pthread_t thread;
	volatile bool end;
	unsigned packets_counter;
	u_int64_t packets_counter_last_time;
friend class sgMaster;
friend class sgCall;
friend class sgStream;
};

class sgCall {
public:
	enum eState {
		state_na,
		state_invite,
		state_100,
		state_183,
		state_invite_ok,
		state_ack,
		state_streams,
		state_bye,
		state_bye_ok,
		state_end
	};
public:
	sgCall(sgCalls *calls);
	~sgCall();
private:
	string create_callid();
	string create_number();
	string create_domain();
	string create_tag();
	inline string rand_str(const char *charset, const int charset_size, int len_min, int len_max) {
		int len = len_min + (rand() % (len_max - len_min + 1));
		string rslt;
		for(int i = 0; i < len; ++i) {
			rslt += charset[rand() % charset_size];
		}
		return(rslt);
	}
	int process_state(u_int64_t time);
	void set_next_state();
	void create_sip_packet(u_int64_t time);
	void create_rtp_packets(u_int64_t time);
	string create_sip_invite();
	string create_sip_100();
	string create_sip_183();
	string create_sip_invite_ok();
	string create_sip_ack();
	string create_sip_bye();
	string create_sip_bye_ok();
	string create_sip(eState state);
	u_int8_t direction(eState state);
private:
	sgCalls *calls;
	string callid;
	string from;
	string from_domain;
	string from_tag;
	string to;
	string to_domain;
	string to_tag;
	string ua_src;
	string ua_dst;
	u_int16_t cseq_invite;
	u_int16_t cseq_bye;
	vmIPport sip_src;
	vmIPport sip_dst;
	vmIPport rtp_src;
	vmIPport rtp_dst;
	sgStream *stream_a;
	sgStream *stream_b;
	eState state;
	u_int64_t last_state_at;
	eState next_state;
	u_int64_t next_state_at;
	u_int64_t invite_at;
	u_int64_t begin_streams_at;
	u_int64_t streams_duration;
friend class sgCalls;
friend class sgStream;
};

class sgStream {
public:
	sgStream(sgCall *call, u_int8_t direction);
	~sgStream();
	void create_rtp_packet(u_int64_t time);
private:
	sgCall *call;
	u_int8_t direction;
	u_int32_t ssrc;
	u_int16_t seq;
	u_int32_t ts;
};


#endif // SIPGEN_H
