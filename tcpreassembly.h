#ifndef TCP_REASSEMBLY_H
#define TCP_REASSEMBLY_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <algorithm>

#include "sniff.h"
#include "pcap_queue_block.h"
#include "pstat.h"
#include "heap_safe.h"
#include "tools_global.h"


extern int opt_tcpreassembly_thread;


#define TCP_SEQ_IS_ROT(seq1, seq2) ((seq1) > ((u_int32_t)0xFFFF0000u) && (seq2) < (u_int32_t)0xFFFF)

#define TCP_SEQ_CMP(seq1, seq2) \
	((seq1) > (seq2) ? (TCP_SEQ_IS_ROT(seq1, seq2) ? -1 : 1) : \
	 (seq2) > (seq1) ? (TCP_SEQ_IS_ROT(seq2, seq1) ? 1 : -1): \
			   0)
	
#define TCP_SEQ_SUB(seq1, seq2) \
	(TCP_SEQ_IS_ROT(seq1, seq2) ? (((u_int32_t)0xFFFF0000u) - (seq1) + (seq2)) : \
				      ((seq1) - (seq2)))


class TcpReassemblyDataItem {
public: 
	enum eDirection {
		DIRECTION_NA = 0,
		DIRECTION_TO_DEST,
		DIRECTION_TO_SOURCE
	};
	TcpReassemblyDataItem() {
		this->data = NULL;
		this->datalen = 0;
		this->time.tv_sec = 0;
		this->time.tv_usec = 0;
		this->ack = 0;
		this->seq = 0;
		this->direction = DIRECTION_NA;
	}
	TcpReassemblyDataItem(u_char *data, u_int32_t datalen, timeval time, 
			      u_int32_t ack = 0, u_int32_t seq = 0, eDirection direction = DIRECTION_NA) {
		if(data && datalen) {
			this->data = new FILE_LINE(37001) u_char[datalen + 1];
			memcpy_heapsafe(this->data, data, datalen, 
					__FILE__, __LINE__);
			this->data[datalen] = 0;
			this->datalen = datalen;
		} else {
			this->data = NULL;
			this->datalen = 0;
		}
		this->time = time;
		this->ack = ack;
		this->seq = seq;
		this->direction = direction;
	}
	TcpReassemblyDataItem(const TcpReassemblyDataItem &dataItem) {
		if(dataItem.data && dataItem.datalen) {
			this->data = new FILE_LINE(37002) u_char[dataItem.datalen + 1];
			memcpy_heapsafe(this->data, dataItem.data, dataItem.datalen, 
					__FILE__, __LINE__);
			this->data[dataItem.datalen] = 0;
			this->datalen = dataItem.datalen;
		} else {
			this->data = NULL;
			this->datalen = 0;
		}
		this->time = dataItem.time;
		this->ack = dataItem.ack;
		this->seq = dataItem.seq;
		this->direction = dataItem.direction;
	}
	~TcpReassemblyDataItem() {
		if(this->data) {
			delete [] this->data;
		}
	}
	TcpReassemblyDataItem& operator = (const TcpReassemblyDataItem &dataItem) {
		if(this->data) {
			delete [] this->data;
		}
		if(dataItem.data && dataItem.datalen) {
			this->data = new FILE_LINE(37003) u_char[dataItem.datalen + 1];
			memcpy_heapsafe(this->data, dataItem.data, dataItem.datalen, 
					__FILE__, __LINE__);
			this->data[dataItem.datalen] = 0;
			this->datalen = dataItem.datalen;
		} else {
			this->data = NULL;
			this->datalen = 0;
		}
		this->time = dataItem.time;
		this->ack = dataItem.ack;
		this->seq = dataItem.seq;
		this->direction = dataItem.direction;
		return(*this);
	}
	void setData(u_char *data, u_int32_t datalen, bool newAlloc = true) {
		if(this->data) {
			delete [] this->data;
		}
		if(data && datalen) {
			if(newAlloc) {
				this->data = new FILE_LINE(37004) u_char[datalen + 1];
				memcpy_heapsafe(this->data, data, datalen, 
						__FILE__, __LINE__);
				this->data[datalen] = 0;
			} else {
				this->data = data;
			}
			this->datalen = datalen;
		} else {
			this->data = NULL;
			this->datalen = 0;
		}
	}
	void setTime(timeval time) {
		this->time = time;
	}
	void setAck(u_int32_t ack) {
		this->ack = ack;
	}
	void setSeq(u_int32_t seq) {
		this->seq = seq;
	}
	void setDirection(eDirection direction) {
		this->direction = direction;
	}
	void setDataTime(u_char *data, u_int32_t datalen, timeval time, bool newAlloc = true) {
		this->setData(data, datalen, newAlloc);
		this->setTime(time);
	}
	void clearData() {
		if(this->data) {
			delete [] this->data;
		}
		this->data = NULL;
		this->datalen = 0;
		this->ack = 0;
		this->seq = 0;
	}
	u_char *getData() {
		return(this->data);
	}
	string getDataString() {
		return(this->data ? (char*)this->data : "");
	}
	u_int32_t getDatalen() {
		return(this->datalen);
	}
	void setDatalen(u_int32_t datalen) {
		this->datalen = datalen;
	}
	timeval getTime() {
		return(this->time);
	}
	u_int64_t getTimeMS() {
		return(::getTimeMS(&this->time));
	}
	u_int32_t getAck() {
		return(this->ack);
	}
	u_int32_t getSeq() {
		return(this->seq);
	}
	eDirection getDirection() {
		return(this->direction);
	}
	bool isFill() {
		return(this->data != NULL);
	}
private:
	u_char *data;
	u_int32_t datalen;
	timeval time;
	u_int32_t ack;
	u_int32_t seq;
	eDirection direction;
};

class TcpReassemblyData {
public:
	TcpReassemblyData() {
		this->forceAppendExpectContinue = false;
	}
	void addData(u_char *data, u_int32_t datalen, timeval time, u_int32_t ack = 0, u_int32_t seq = 0, 
		     TcpReassemblyDataItem::eDirection direction = TcpReassemblyDataItem::DIRECTION_NA) {
		this->data.push_back(TcpReassemblyDataItem(data, datalen, time, ack, seq, direction));
	}
	void addRequest(u_char *data, u_int32_t datalen, timeval time, u_int32_t ack = 0, u_int32_t seq = 0) {
		request.push_back(TcpReassemblyDataItem(data, datalen, time, ack, seq));
	}
	void addResponse(u_char *data, u_int32_t datalen, timeval time, u_int32_t ack = 0, u_int32_t seq = 0) {
		response.push_back(TcpReassemblyDataItem(data, datalen, time, ack, seq));
	}
	void addExpectContinue(u_char *data, u_int32_t datalen, timeval time, u_int32_t ack = 0, u_int32_t seq = 0) {
		expectContinue.push_back(TcpReassemblyDataItem(data, datalen, time, ack, seq));
	}
	void addExpectContinueResponse(u_char *data, u_int32_t datalen, timeval time, u_int32_t ack = 0, u_int32_t seq = 0) {
		expectContinueResponse.push_back(TcpReassemblyDataItem(data, datalen, time, ack, seq));
	}
	bool isFill();
public:
	vector<TcpReassemblyDataItem> data;
	vector<TcpReassemblyDataItem> request;
	vector<TcpReassemblyDataItem> response;
	vector<TcpReassemblyDataItem> expectContinue;
	vector<TcpReassemblyDataItem> expectContinueResponse;
	bool forceAppendExpectContinue;
};

class TcpReassemblyProcessData {
public:
	virtual void processData(vmIP ip_src, vmIP ip_dst,
				 vmPort port_src, vmPort port_dst,
				 TcpReassemblyData *data,
				 u_char *ethHeader, u_int32_t ethHeaderLength,
				 u_int16_t handle_index, int dlt, int sensor_id, vmIP sensor_ip, sPacketInfoData pid,
				 void *uData, void *uData2, void *uData2_last,
				 class TcpReassemblyLink *reassemblyLink,
				 std::ostream *debugStream) = 0;
	virtual void writeToDb(bool /*all*/ = false) {}
	virtual void printContentSummary() {}
};

struct TcpReassemblyLink_id {
	TcpReassemblyLink_id(vmIP ip_src = 0, vmIP ip_dst = 0, 
			     vmPort port_src = 0, vmPort port_dst = 0) {
		this->ip_src = ip_src;
		this->ip_dst = ip_dst;
		this->port_src = port_src; 
		this->port_dst = port_dst;
	}
	void reverse() {
		vmIP tmp_ip = this->ip_src;
		this->ip_src = this->ip_dst;
		this->ip_dst = tmp_ip;
		vmPort tmp_port = this->port_src;
		this->port_src = this->port_dst;
		this->port_dst = tmp_port;
	}
	vmIP ip_src;
	vmIP ip_dst;
	vmPort port_src;
	vmPort port_dst;
	bool operator < (const TcpReassemblyLink_id& other) const {
		return((this->ip_src < other.ip_src) ? 1 : (this->ip_src > other.ip_src) ? 0 :
		       (this->ip_dst < other.ip_dst) ? 1 : (this->ip_dst > other.ip_dst) ? 0 :
		       (this->port_src < other.port_src) ? 1 : (this->port_src > other.port_src) ? 0 :
		       (this->port_dst < other.port_dst));
	}
};

class TcpReassemblyStream_packet {
public:
	enum eState {
		NA = 0,
		CHECK,
		FAIL
	};
	struct sFlags {
		union {
			int8_t flags;
			struct {
				int8_t is_sip : 1;
			} flags_bit;
		};
	};
	TcpReassemblyStream_packet() {
		time.tv_sec = 0;
		time.tv_usec = 0;
		memset(&header_tcp, 0, sizeof(header_tcp));
		next_seq = 0;
		data = NULL;
		datalen = 0;
		datacaplen = 0;
		block_store = NULL;
		block_store_index = 0;
		state = NA;
		flags.flags = 0;
		//locked_packet = false;
	}
	TcpReassemblyStream_packet(const TcpReassemblyStream_packet &packet) {
		this->copyFrom(packet);
		if(packet.data) {
			this->data = new FILE_LINE(37005) u_char[packet.datacaplen];
			memcpy_heapsafe(this->data, packet.data, packet.datacaplen, 
					__FILE__, __LINE__);
		}
	}
	~TcpReassemblyStream_packet() {
		if(this->data) {
			delete [] this->data;
		}
	}
	TcpReassemblyStream_packet& operator = (const TcpReassemblyStream_packet &packet) {
		if(this->data) {
			delete [] this->data;
		}
		this->copyFrom(packet);
		if(packet.data) {
			this->data = new FILE_LINE(37006) u_char[packet.datacaplen];
			memcpy_heapsafe(this->data, packet.data, packet.datacaplen, 
					__FILE__, __LINE__);
		}
		return(*this);
	}
	void setData(timeval time, tcphdr2 header_tcp,
		     u_char *data, u_int32_t datalen, u_int32_t datacaplen,
		     pcap_block_store *block_store, int block_store_index,
		     bool isSip) {
		this->time = time;
		this->header_tcp = header_tcp;
		this->next_seq = header_tcp.seq + datalen;
		if(datacaplen) {
			this->data = new FILE_LINE(37007) u_char[datacaplen];
			memcpy_heapsafe(this->data, this->data,
					data, block_store ? NULL : data,
					datacaplen, 
					__FILE__, __LINE__);
		} else {
			this->data = NULL;
		}
		this->datalen = datalen;
		this->datacaplen = datacaplen;
		this->block_store = block_store;
		this->block_store_index = block_store_index;
		this->flags.flags_bit.is_sip = isSip;
	}
private:
	void copyFrom(const TcpReassemblyStream_packet &packet) {
		this->time = packet.time;
		this->header_tcp = packet.header_tcp;
		this->next_seq = packet.next_seq;
		this->data = packet.data;
		this->datalen = packet.datalen;
		this->datacaplen = packet.datacaplen;
		this->block_store = packet.block_store;
		this->block_store_index = packet.block_store_index;
		this->state = packet.state;
		this->flags.flags = packet.flags.flags;
	}
	void cleanState() {
		this->state = NA;
	}
private:
	timeval time;
	tcphdr2 header_tcp;
	u_int32_t next_seq;
	u_char *data;
	u_int32_t datalen;
	u_int32_t datacaplen;
	pcap_block_store *block_store;
	int block_store_index;
	eState state;
	sFlags flags;
	//bool locked_packet;
friend class TcpReassemblyStream_packet_var;
friend class TcpReassemblyStream;
friend class TcpReassemblyLink;
friend class TcpReassembly;
};

class TcpReassemblyStream_packet_var {
public:
	TcpReassemblyStream_packet_var() {
		offset = 0;
		last_packet_at_from_header = 0;
	}
	void push(TcpReassemblyStream_packet packet);
	u_int32_t getNextSeqCheck() {
		map<uint32_t, TcpReassemblyStream_packet>::iterator iter;
		for(iter = this->queuePackets.begin(); iter != this->queuePackets.end(); iter++) {
			if(iter->second.datalen &&
			   (iter->second.state == TcpReassemblyStream_packet::NA ||
			    iter->second.state == TcpReassemblyStream_packet::CHECK)) {
				return(iter->second.next_seq);
			}
		}
		return(0);
	}
	u_int32_t isFail() {
		map<uint32_t, TcpReassemblyStream_packet>::iterator iter;
		for(iter = this->queuePackets.begin(); iter != this->queuePackets.end(); iter++) {
			if(iter->second.state != TcpReassemblyStream_packet::FAIL) {
				return(false);
			}
		}
		return(true);
	}
	TcpReassemblyStream_packet *getPacket(u_int32_t next_seq) {
		map<uint32_t, TcpReassemblyStream_packet>::iterator iter = queuePackets.find(next_seq);
		if(iter != queuePackets.end()) {
			return(&iter->second);
		}
		return(NULL);
	}
	TcpReassemblyStream_packet *getFirstPacket() {
		if(queuePackets.size()) {
			return(&(queuePackets.begin()->second));
		}
		return(NULL);
	}
private:
	void cleanState() {
		map<uint32_t, TcpReassemblyStream_packet>::iterator iter;
		for(iter = this->queuePackets.begin(); iter != this->queuePackets.end(); iter++) {
			iter->second.cleanState();
		}
	}
	u_int32_t getMaxNextSeq() {
		u_int32_t max_next_seq = 0;
		bool max_next_seq_set = false;
		map<uint32_t, TcpReassemblyStream_packet>::iterator iter;
		for(iter = this->queuePackets.begin(); iter != this->queuePackets.end(); iter++) {
			if(!max_next_seq_set ||
			   TCP_SEQ_CMP(iter->second.next_seq, max_next_seq) > 0) {
				max_next_seq = iter->second.next_seq;
				max_next_seq_set = true;
			}
		}
		return(max_next_seq);
	}
private:
	map<uint32_t, TcpReassemblyStream_packet> queuePackets;
	u_int32_t offset;
	u_int64_t last_packet_at_from_header;
friend class TcpReassemblyStream;
friend class TcpReassemblyLink;
friend class TcpReassembly;
};

class TcpReassemblyStream {
public:
	enum eDirection {
		DIRECTION_NA = 0,
		DIRECTION_TO_DEST,
		DIRECTION_TO_SOURCE
	};
	enum eType {
		TYPE_DATA,
		TYPE_SYN_SENT,
		TYPE_SYN_RECV,
		TYPE_FIN,
		TYPE_RST
	};
	enum eHttpType {
		HTTP_TYPE_NA = 0,
		HTTP_TYPE_POST,
		HTTP_TYPE_GET,
		HTTP_TYPE_HEAD,
		HTTP_TYPE_HTTP
	};
	struct s_index_item {
		inline s_index_item(u_int32_t seq, u_int32_t next_seq, u_int32_t len) {
			this->seq = seq;
			this->next_seq = next_seq;
			this->len = len;
		}
		u_int32_t seq;
		u_int32_t next_seq;
		u_int32_t len;
	};
	TcpReassemblyStream(class TcpReassemblyLink *link) {
		direction = DIRECTION_TO_DEST;
		type = TYPE_DATA;
		ack = 0;
		first_seq = 0;
		last_seq = 0;
		min_seq = 0;
		max_next_seq = 0;
		is_ok = false;
		completed_finally = false;
		exists_data = false;
		http_type = HTTP_TYPE_NA;
		http_header_length = 0;
		http_content_length = 0;
		http_ok = false;
		http_expect_continue = false;
		http_ok_expect_continue_post = false;
		http_ok_expect_continue_data = false;
		detect_ok_max_next_seq = 0;
		_ignore_expect_continue = false;
		_only_check_psh = false;
		_force_wait_for_next_psh = false;
		last_packet_at_from_header = 0;
		this->link = link;
		counterTryOk = 0;
	}
	void push(TcpReassemblyStream_packet packet);
	int ok(bool crazySequence = false, bool enableSimpleCmpMaxNextSeq = false, u_int32_t maxNextSeq = 0,
	       int enableValidateDataViaCheckData = -1, int needValidateDataViaCheckData = -1, int unlimitedReassemblyAttempts = -1,
	       TcpReassemblyStream *prevHttpStream = NULL, bool enableDebug = false,
	       u_int32_t forceFirstSeq = 0, int ignorePsh = -1);
	bool ok2_ec(u_int32_t nextAck, bool enableDebug = false);
	u_char *complete(u_int32_t *datalen, deque<s_index_item> *data_index, timeval *time, u_int32_t *seq, bool check = false,
			 size_t startIndex = 0, size_t *endIndex = NULL, bool breakIfPsh = false);
	bool saveCompleteData(bool check = false, TcpReassemblyStream *prevHttpStream = NULL);
	bool isSetCompleteData();
	void clearCompleteData();
	void cleanupCompleteData();
	void confirmCompleteData(u_int32_t datalen_confirmed, u_int32_t *last_seq = NULL);
	void printContent(int level  = 0);
	bool checkOkPost(TcpReassemblyStream *nextStream = NULL);
	TcpReassemblyStream_packet *getPacket(u_int32_t seq, u_int32_t next_seq) {
		map<uint32_t, TcpReassemblyStream_packet_var>::iterator iter = queuePacketVars.find(seq);
		if(iter != queuePacketVars.end()) {
			return(iter->second.getPacket(next_seq));
		}
		return(NULL);
	}
	TcpReassemblyStream_packet *getPacket(u_int32_t seq) {
		map<uint32_t, TcpReassemblyStream_packet_var>::iterator iter = queuePacketVars.find(seq);
		if(iter != queuePacketVars.end()) {
			return(iter->second.getFirstPacket());
		}
		return(NULL);
	}
	TcpReassemblyStream_packet_var *getPacketVars(u_int32_t seq) {
		map<uint32_t, TcpReassemblyStream_packet_var>::iterator iter = queuePacketVars.find(seq);
		if(iter != queuePacketVars.end()) {
			return(&iter->second);
		}
		return(NULL);
	}
	u_int32_t getPacketOffset(u_int32_t seq) {
		map<uint32_t, TcpReassemblyStream_packet_var>::iterator iter = queuePacketVars.find(seq);
		if(iter != queuePacketVars.end()) {
			return(iter->second.offset);
		}
		return(0);
	}
	void clearPacketOffset(u_int32_t seq) {
		map<uint32_t, TcpReassemblyStream_packet_var>::iterator iter = queuePacketVars.find(seq);
		if(iter != queuePacketVars.end()) {
			iter->second.offset = 0;
		}
	}
	inline eDirection getDirection() {
		return(direction);
	}
	inline TcpReassemblyLink *getLink() {
		return(link);
	}
private:
	bool checkCompleteContent();
	bool checkContentIsHttpRequest();
	void cleanPacketsState() {
		map<uint32_t, TcpReassemblyStream_packet_var>::iterator iter;
		for(iter = this->queuePacketVars.begin(); iter != this->queuePacketVars.end(); iter++) {
			iter->second.cleanState();
		}
		this->ok_packets.clear();
	}
	u_int32_t getLastSeqFromNextStream();
private:
	eDirection direction;
	eType type;
	u_int32_t ack;
	u_int32_t first_seq;
	u_int32_t last_seq;
	u_int32_t min_seq;
	u_int32_t max_next_seq;
	map<uint32_t, TcpReassemblyStream_packet_var> queuePacketVars;
	deque<d_u_int32_t> ok_packets;
	bool is_ok;
	bool completed_finally;
	bool exists_data;
	TcpReassemblyDataItem complete_data;
	deque<s_index_item> complete_data_index;
	eHttpType http_type;
	u_int32_t http_header_length;
	u_int32_t http_content_length;
	bool http_ok;
	bool http_ok_data_complete;
	bool http_expect_continue;
	bool http_ok_expect_continue_post;
	bool http_ok_expect_continue_data;
	u_int32_t detect_ok_max_next_seq;
	bool _ignore_expect_continue;
	bool _only_check_psh;
	bool _force_wait_for_next_psh;
	u_int64_t last_packet_at_from_header;
	TcpReassemblyLink *link;
	int counterTryOk;
friend class TcpReassemblyLink;
friend class TcpReassembly;
};

class TcpReassemblyLink {
public:
	enum eState {
		STATE_NA = 0,
		STATE_SYN_SENT,
		STATE_SYN_RECV,
		STATE_SYN_OK,
		STATE_SYN_FORCE_OK,
		STATE_RESET,
		STATE_CLOSE,
		STATE_CLOSED,
		STATE_CRAZY
	};
	class streamIterator {
		public:
			streamIterator(TcpReassemblyLink *link) {
				this->link = link;
				this->init();
			}
			bool init();
			bool next();
			bool nextAckInDirection();
			bool nextAckInReverseDirection();
			bool nextSeqInDirection();
			bool nextAckByMaxSeqInReverseDirection();
			void print();
			u_int32_t getMaxNextSeq();
		private:
			bool findSynSent();
			bool findFirstDataToDest();
		public:
			TcpReassemblyStream *stream;
			eState state;
		private:
			TcpReassemblyLink *link;
	};
	struct sRemainDataItem {
		u_int32_t ack;
		u_int32_t seq;
		u_char *data;
		u_int32_t datalen;
	};
	TcpReassemblyLink(class TcpReassembly *reassembly,
			  vmIP ip_src, vmIP ip_dst, 
			  vmPort port_src, vmPort port_dst,
			  u_char *packet, iphdr2 *header_ip,
			  u_int16_t handle_index, int dlt, int sensor_id, vmIP sensor_ip, sPacketInfoData pid,
			  void *uData, void *uData2) {
		this->reassembly = reassembly;
		this->ip_src = ip_src;
		this->ip_dst = ip_dst;
		this->port_src = port_src; 
		this->port_dst = port_dst;
		this->state = STATE_NA;
		this->forceOk = false;
		this->first_seq_to_dest = 0;
		this->first_seq_to_source = 0;
		this->rst = false;
		this->fin_to_dest = false;
		this->fin_to_source = false;
		this->_sync_queue = 0;
		this->_erase = 0;
		//this->created_at = getTimeMS();
		//this->last_packet_at = 0;
		this->created_at_from_header = 0;
		this->last_packet_at_from_header = 0;
		this->last_packet_process_cleanup_at = 0;
		this->last_ack = 0;
		this->exists_data = false;
		this->link_is_ok = 0;
		this->completed_offset = 0;
		this->direction_confirm = 0;
		this->ethHeader = NULL;
		this->ethHeaderLength = 0;
		if(packet && header_ip) {
			this->createEthHeader(packet, dlt);
		}
		this->handle_index = handle_index;
		this->dlt = dlt;
		this->sensor_id = sensor_id;
		this->sensor_ip = sensor_ip;
		this->pid = pid;
		this->uData = uData;
		this->uData2 = uData2;
		this->uData2_last = uData2;
		this->check_duplicity_seq = NULL;
		this->check_duplicity_seq_length = 10;
	}
	~TcpReassemblyLink();
	bool push(TcpReassemblyStream::eDirection direction,
		  timeval time, tcphdr2 header_tcp, 
		  u_char *data, u_int32_t datalen, u_int32_t datacaplen,
		  pcap_block_store *block_store, int block_store_index,
		  bool isSip) {
		if(datalen) {
			this->exists_data = true;
		}
		if(this->state == STATE_CRAZY) {
			return(this->push_crazy(
				direction, time, header_tcp, 
				data, datalen, datacaplen,
				block_store, block_store_index,
				isSip));
		} else {
			return(this->push_normal(
				direction, time, header_tcp, 
				data, datalen, datacaplen,
				block_store, block_store_index,
				isSip));
		}
	}
	bool push_normal(
		  TcpReassemblyStream::eDirection direction,
		  timeval time, tcphdr2 header_tcp, 
		  u_char *data, u_int32_t datalen, u_int32_t datacaplen,
		  pcap_block_store *block_store, int block_store_index,
		  bool isSip);
	bool push_crazy(
		  TcpReassemblyStream::eDirection direction,
		  timeval time, tcphdr2 header_tcp, 
		  u_char *data, u_int32_t datalen, u_int32_t datacaplen,
		  pcap_block_store *block_store, int block_store_index,
		  bool isSip);
	int okQueue(int final = 0, u_int32_t seq = 0, u_int32_t next_seq = 0, u_int32_t ack = 0, bool psh = false, bool enableDebug = false);
	int okQueue_normal(int final = 0, bool enableDebug = false);
	int okQueue_simple_by_ack(u_int32_t seq, u_int32_t ack, u_int32_t next_seq, bool psh, bool enableDebug = false);
	int okQueue_crazy(int final = 0, bool enableDebug = false);
	void complete(bool final = false, bool eraseCompletedStreams = false);
	void complete_normal(bool final = false);
	void complete_simple_by_ack();
	void complete_crazy(bool final = false, bool eraseCompletedStreams = false);
	streamIterator createIterator();
	TcpReassemblyStream *findStreamBySeq(u_int32_t seq) {
		for(size_t i = 0; i < this->queueStreams.size(); i++) {
			map<uint32_t, TcpReassemblyStream_packet_var>::iterator iter;
			iter = this->queueStreams[i]->queuePacketVars.find(seq);
			if(iter != this->queueStreams[i]->queuePacketVars.end()) {
				return(this->queueStreams[i]);
			}
		}
		return(NULL);
	}
	TcpReassemblyStream *findStreamByMinSeq(u_int32_t seq, bool dataOnly = false, 
						u_int32_t not_ack = 0, TcpReassemblyStream::eDirection direction = TcpReassemblyStream::DIRECTION_NA) {
		map<uint32_t, TcpReassemblyStream*>::iterator iter;
		for(iter = this->queue_by_ack.begin(); iter != this->queue_by_ack.end(); iter++) {
			if(iter->second &&
			   iter->second->min_seq == seq &&
			   (!not_ack || iter->second->ack != not_ack) &&
			   (direction == TcpReassemblyStream::DIRECTION_NA || iter->second->direction == direction)) {
				return(iter->second);
			}
		}
		if(!dataOnly && this->queue_nul_by_ack.size()) {
			iter = this->queue_nul_by_ack.end();
			do {
				--iter;
				if(iter->second->min_seq == seq &&
				   (!not_ack || iter->second->ack != not_ack) &&
				   (direction == TcpReassemblyStream::DIRECTION_NA || iter->second->direction == direction)) {
					return(iter->second);
				}
			} while(iter != this->queue_nul_by_ack.begin());
		}
		return(NULL);
	}
	TcpReassemblyStream *findStreamByMaxNextSeq(u_int32_t seq) {
		map<uint32_t, TcpReassemblyStream*>::iterator iter;
		for(iter = this->queue_by_ack.begin(); iter != this->queue_by_ack.end(); iter++) {
			if(iter->second &&
			   iter->second->max_next_seq == seq) {
				return(iter->second);
			}
		}
		return(NULL);
	}
	TcpReassemblyStream *findStreamByMaxNextSeq(u_int32_t seq_from, u_int32_t seq_to) {
		map<uint32_t, TcpReassemblyStream*>::iterator iter;
		for(iter = this->queue_by_ack.begin(); iter != this->queue_by_ack.end(); iter++) {
			if(iter->second &&
			   iter->second->max_next_seq >= seq_from && iter->second->max_next_seq <= seq_to) {
				return(iter->second);
			}
		}
		return(NULL);
	}
	TcpReassemblyStream *findStreamByNextSeq(u_int32_t seq_from, u_int32_t seq_to, TcpReassemblyStream_packet **packet) {
		*packet = NULL;
		map<uint32_t, TcpReassemblyStream*>::iterator iter;
		for(iter = this->queue_by_ack.begin(); iter != this->queue_by_ack.end() && !*packet; iter++) {
			if(iter->second &&
			   (seq_to ?
			     iter->second->min_seq <= seq_from && iter->second->max_next_seq >= seq_to :
			     iter->second->min_seq <= seq_from && iter->second->max_next_seq >= seq_from)) {
				TcpReassemblyStream *stream = iter->second;
				map<uint32_t, TcpReassemblyStream_packet_var>::iterator iter2;
				for(iter2 = stream->queuePacketVars.begin(); iter2 != stream->queuePacketVars.end() && !*packet; iter2++) {
					map<uint32_t, TcpReassemblyStream_packet>::iterator iter3;
					for(iter3 = iter2->second.queuePackets.begin(); iter3 != iter2->second.queuePackets.end() && !*packet; iter3++) {
						if(seq_to ?
						    iter3->first >= seq_from && iter3->first <= seq_to :
						    iter3->first == seq_from) {
							*packet = &iter3->second;
						}
					}
				}
				if(*packet) {
					return(stream);
				}
			}
		}
		return(NULL);
	}
	TcpReassemblyStream *findFlagStreamByAck(u_int32_t ack) {
		map<uint32_t, TcpReassemblyStream*>::iterator iter;
		iter = this->queue_flags_by_ack.find(ack);
		if(iter != this->queue_flags_by_ack.end()) {
			return(iter->second);
		}
		return(NULL);
	}
	TcpReassemblyStream *findFinalFlagStreamByAck(u_int32_t ack, TcpReassemblyStream::eDirection direction) {
		map<uint32_t, TcpReassemblyStream*>::iterator iter;
		iter = this->queue_flags_by_ack.find(ack);
		if(iter != this->queue_flags_by_ack.end() &&
		   iter->second->direction == direction) {
			return(iter->second);
		}
		return(NULL);
	}
	TcpReassemblyStream *findFinalFlagStreamBySeq(u_int32_t seq, TcpReassemblyStream::eDirection direction) {
		map<uint32_t, TcpReassemblyStream*>::iterator iter;
		for(iter = this->queue_flags_by_ack.begin(); iter != this->queue_flags_by_ack.end(); iter++) {
			if(iter->second->direction == direction &&
			   iter->second->min_seq >= seq) {
				return(iter->second);
			}
		}
		return(NULL);
	}
	bool existsFinallyUncompletedDataStream() {
		map<uint32_t, TcpReassemblyStream*>::iterator iter;
		for(iter = this->queue_by_ack.begin(); iter != this->queue_by_ack.end(); iter++) {
			if(iter->second->exists_data &&
			   !iter->second->completed_finally) {
				return(true);
			}
		}
		return(false);
	}
	void cleanup(u_int64_t act_time);
	void printContent(int level  = 0);
	void addRemainData(TcpReassemblyDataItem::eDirection direction, u_int32_t ack, u_int32_t seq, u_char *data, u_int32_t datalen);
	void clearRemainData(TcpReassemblyDataItem::eDirection direction);
	u_char *completeRemainData(TcpReassemblyDataItem::eDirection direction, u_int32_t *rslt_datalen, u_int32_t ack, u_int32_t seq, u_char *data, u_int32_t datalen, u_int32_t skip_first_items);
	u_int32_t getRemainDataLength(TcpReassemblyDataItem::eDirection direction, u_int32_t skip_first_items);
	u_int32_t getRemainDataItems(TcpReassemblyDataItem::eDirection direction);
	bool existsRemainData(TcpReassemblyDataItem::eDirection direction);
	bool existsAllAckSeq(TcpReassemblyDataItem::eDirection direction);
	list<d_u_int32_t> *getSipOffsets();
	void clearCompleteStreamsData();
	bool checkDuplicitySeq(u_int32_t newSeq);
private:
	void lock_queue() {
		extern int opt_sip_tcp_reassembly_ext_usleep;
		while(__sync_lock_test_and_set(&this->_sync_queue, 1)) {
			if(opt_sip_tcp_reassembly_ext_usleep) {
				USLEEP(opt_sip_tcp_reassembly_ext_usleep);
			}
		}
	}
	void unlock_queue() {
		__sync_lock_release(&this->_sync_queue);
	}
	void pushpacket(TcpReassemblyStream::eDirection direction,
		        TcpReassemblyStream_packet packet,
			bool isSip);
	void setLastSeq(TcpReassemblyStream::eDirection direction, 
			u_int32_t lastSeq);
	void switchDirection();
	void createEthHeader(u_char *packet, int dlt);
	void extCleanup(int id, bool all);
private:
	TcpReassembly *reassembly;
	vmIP ip_src;
	vmIP ip_dst;
	vmPort port_src;
	vmPort port_dst;
	eState state;
	bool forceOk;
	u_int32_t first_seq_to_dest;
	u_int32_t first_seq_to_source;
	bool rst;
	bool fin_to_dest;
	bool fin_to_source;
	map<uint32_t, TcpReassemblyStream*> queue_by_ack;
	map<uint32_t, TcpReassemblyStream*> queue_flags_by_ack;
	map<uint32_t, TcpReassemblyStream*> queue_nul_by_ack;
	deque<TcpReassemblyStream*> queueStreams;
	uint32_t last_ok_seq_direction[2];
	volatile int _sync_queue;
	volatile int _erase;
	//u_int64_t created_at;
	//u_int64_t last_packet_at;
	u_int64_t created_at_from_header;
	u_int64_t last_packet_at_from_header;
	u_int64_t last_packet_process_cleanup_at;
	u_int32_t last_ack;
	bool exists_data;
	int link_is_ok;
	size_t completed_offset;
	int direction_confirm;
	vector<TcpReassemblyStream*> ok_streams;
	u_char *ethHeader;
	u_int32_t ethHeaderLength;
	u_int16_t handle_index;
	int dlt; 
	int sensor_id;
	vmIP sensor_ip;
	sPacketInfoData pid;
	void *uData;
	void *uData2;
	void *uData2_last;
	vector<sRemainDataItem> remainData[2];
	u_int32_t *check_duplicity_seq;
	unsigned check_duplicity_seq_length;
	list<d_u_int32_t> sip_offsets;
friend class TcpReassembly;
friend class TcpReassemblyStream;
};

class TcpReassembly {
public:
	enum eType {
		http,
		webrtc,
		ssl,
		sip
	};
	struct sPacket {
		pcap_pkthdr *header; 
		iphdr2 *header_ip; 
		u_char *packet;
		bool alloc_packet;
		pcap_block_store *block_store; 
		int block_store_index;
		bool block_store_locked;
		u_int16_t handle_index; 
		int dlt; 
		int sensor_id;
		vmIP sensor_ip;
		sPacketInfoData pid;
		void *uData;
		void *uData2;
		bool isSip;
	};
public:
	TcpReassembly(eType type);
	~TcpReassembly();
	void push_tcp(pcap_pkthdr *header, iphdr2 *header_ip, u_char *packet, bool alloc_packet,
		      pcap_block_store *block_store, int block_store_index, bool block_store_locked,
		      u_int16_t handle_index, int dlt, int sensor_id, vmIP sensor_ip, sPacketInfoData pid,
		      void *uData = NULL, void *uData2 = NULL, bool isSip = false);
	void cleanup(bool all = false);
	void cleanup_simple(bool all = false, bool lock = false);
	void setEnableHttpForceInit(bool enableHttpForceInit = true) {
		this->enableHttpForceInit = enableHttpForceInit;
	}
	void setEnableCrazySequence(bool enableCrazySequence = true) {
		this->enableCrazySequence = enableCrazySequence;
	}
	void setEnableWildLink(bool enableWildLink = true) {
		this->enableWildLink = enableWildLink;
	}
	void setIgnoreTcpHandshake(bool ignoreTcpHandshake = true) {
		this->ignoreTcpHandshake = ignoreTcpHandshake;
	}
	void setEnableIgnorePairReqResp(bool enableIgnorePairReqResp = true) {
		this->enableIgnorePairReqResp = enableIgnorePairReqResp;
	}
	void setEnableDestroyStreamsInComplete(bool enableDestroyStreamsInComplete = true) {
		this->enableDestroyStreamsInComplete = enableDestroyStreamsInComplete;
	}
	void setEnableAllCompleteAfterZerodataAck(bool enableAllCompleteAfterZerodataAck = true) {
		this->enableAllCompleteAfterZerodataAck = enableAllCompleteAfterZerodataAck;
	}
	void setEnableValidateDataViaCheckData(bool enableValidateDataViaCheckData = true) {
		this->enableValidateDataViaCheckData = enableValidateDataViaCheckData;
	}
	void setUnlimitedReassemblyAttempts(bool unlimitedReassemblyAttempts = true) {
		this->unlimitedReassemblyAttempts = unlimitedReassemblyAttempts;
	}
	void setMaxReassemblyAttempts(int maxReassemblyAttempts = 50) {
		this->maxReassemblyAttempts = maxReassemblyAttempts;
	}
	void setEnableValidateLastQueueDataViaCheckData(bool enableValidateLastQueueDataViaCheckData = true) {
		this->enableValidateLastQueueDataViaCheckData = enableValidateLastQueueDataViaCheckData;
	}
	void setEnableStrictValidateDataViaCheckData(bool enableStrictValidateDataViaCheckData = true) {
		this->enableStrictValidateDataViaCheckData = enableStrictValidateDataViaCheckData;
	}
	void setNeedValidateDataViaCheckData(bool needValidateDataViaCheckData = true) {
		this->needValidateDataViaCheckData = needValidateDataViaCheckData;
	}
	void setSimpleByAck(bool simpleByAck = true) {
		this->simpleByAck = simpleByAck;
	}
	void setIgnorePshInCheckOkData(bool ignorePshInCheckOkData = true) {
		this->ignorePshInCheckOkData = ignorePshInCheckOkData;
	}
	void setSmartMaxSeq(bool smartMaxSeq = true) {
		this->smartMaxSeq = smartMaxSeq;
	}
	void setSmartMaxSeqByPsh(bool smartMaxSeqByPsh = true) {
		this->smartMaxSeqByPsh = smartMaxSeqByPsh;
	}
	void setSkipZeroData(bool skipZeroData = true) {
		this->skipZeroData = skipZeroData;
	}
	void setIgnoreZeroData(bool ignoreZeroData = true) {
		this->ignoreZeroData = ignoreZeroData;
	}
	void setEnableCleanupThread(bool enableCleanupThread = true) {
		this->enableCleanupThread = enableCleanupThread;
		this->createCleanupThread();
	}
	void setEnableAutoCleanup(bool enableAutoCleanup = true) {
		this->enableAutoCleanup = enableAutoCleanup;
	}
	void setCleanupPeriod(unsigned int cleanupPeriod = true) {
		this->cleanupPeriod = cleanupPeriod;
	}
	void setEnableHttpCleanupExt(bool enableHttpCleanupExt = true) {
		this->enableHttpCleanupExt = enableHttpCleanupExt;
	}
	void setEnablePacketThread(bool enablePacketThread = true) {
		this->enablePacketThread = enablePacketThread;
		this->createPacketThread();
	}
	void setDataCallback(TcpReassemblyProcessData *dataCallback) {
		this->dataCallback = dataCallback;
	}
	void setEnablePushLock(bool enablePushLock = true) {
		this->enablePushLock = enablePushLock;
	}
	void setEnableLinkLock(bool enableLinkLock = true) {
		this->enableLinkLock = enableLinkLock;
	}
	void setEnableSmartCompleteData(bool enableSmartCompleteData = true) {
		this->enableSmartCompleteData = enableSmartCompleteData;
	}
	void setCompleteMod(int completeMod) {
		this->completeMod = completeMod;
	}
	void setEnableExtStat(bool enableExtStat = true) {
		this->enableExtStat = enableExtStat;
	}
	void setEnableExtCleanupStreams(unsigned int extCleanupStreamsLimitStreams, unsigned int extCleanupStreamsLimitHeap) {
		this->extCleanupStreamsLimitStreams = extCleanupStreamsLimitStreams;
		this->extCleanupStreamsLimitHeap = extCleanupStreamsLimitHeap;
	}
	/*
	bool enableStop();
	*/
	void printContent();
	void printContentSummary();
	void setDoPrintContent() {
		this->doPrintContent = true;
	}
	void setIgnoreTerminating(bool ignoreTerminating);
	void addLog(string logString) {
		addLog(logString.c_str());
	}
	void addLog(const char *logString);
	bool isActiveLog() {
		return(this->log != NULL);
	}
	void prepareCleanupPstatData();
	double getCleanupCpuUsagePerc(bool preparePstatData = false);
	void preparePacketPstatData();
	double getPacketCpuUsagePerc(bool preparePstatData = false);
	string getCpuUsagePerc();
	bool check_ip(vmIP ip, vmPort port = 0) {
		if(type == http || type == webrtc) {
			extern vector<vmIP> httpip;
			extern vector<vmIPmask> httpnet;
			extern vector<vmIP> webrtcip;
			extern vector<vmIPmask> webrtcnet;
			return(check_ip_in(ip, (type == http ? &httpip : &webrtcip), (type == http ? &httpnet : &webrtcnet), true));
		} else if(type == ssl) {
			extern map<vmIPport, string> ssl_ipport;
			map<vmIPport, string>::iterator iter = ssl_ipport.find(vmIPport(ip, port));
			return(iter != ssl_ipport.end());
		}
		return(false);
	}
	bool check_port(vmPort port, vmIP ip = 0) {
		if(type == http || type == webrtc) {
			extern char *httpportmatrix;
			extern char *webrtcportmatrix;
			return(type == http ? httpportmatrix[port] : webrtcportmatrix[port]);
		} else if(type == ssl) {
			extern map<vmIPport, string> ssl_ipport;
			map<vmIPport, string>::iterator iter = ssl_ipport.find(vmIPport(ip, port));
			return(iter != ssl_ipport.end());
		}
		return(false);
	}
	eType getType() {
		return(type);
	}
	string getTypeString(bool upper = false) {
		string str = type == http ? "http" :
			     type == webrtc ? "webrtc" : 
			     type == ssl ? "ssl" : 
			     type == sip ? "sip" : "";
		if(upper) {
			std::transform(str.begin(), str.end(), str.begin(), ::toupper);
		}
		return(str);
	}
	void setLinkTimeout(u_int32_t linkTimeout) {
		this->linkTimeout = linkTimeout;
	}
	bool checkOkData(u_char * data, u_int32_t datalen, bool strict, bool check_ext, list<d_u_int32_t> *sip_offsets, u_int32_t *datalen_used = NULL);
	void enableDumper(const char *fileName, const char *ports);
private:
	void _push(pcap_pkthdr *header, iphdr2 *header_ip, u_char *packet,
		   pcap_block_store *block_store, int block_store_index,
		   u_int16_t handle_index, int dlt, int sensor_id, vmIP sensor_ip, sPacketInfoData pid,
		   void *uData, void *uData2, bool isSip);
	void createCleanupThread();
	void createPacketThread();
	void *cleanupThreadFunction(void *);
	void *packetThreadFunction(void *);
	void lock_links() {
		extern int opt_sip_tcp_reassembly_ext_usleep;
		while(__sync_lock_test_and_set(&this->_sync_links, 1)) {
			if(opt_sip_tcp_reassembly_ext_usleep) {
				USLEEP(opt_sip_tcp_reassembly_ext_usleep);
			}
		}
	}
	void unlock_links() {
		__sync_lock_release(&this->_sync_links);
	}
	void lock_push() {
		extern int opt_sip_tcp_reassembly_ext_usleep;
		while(__sync_lock_test_and_set(&this->_sync_push, 1)) {
			if(opt_sip_tcp_reassembly_ext_usleep) {
				USLEEP(opt_sip_tcp_reassembly_ext_usleep);
			}
		}
	}
	void unlock_push() {
		__sync_lock_release(&this->_sync_push);
	}
	void lock_cleanup() {
		extern int opt_sip_tcp_reassembly_ext_usleep;
		while(__sync_lock_test_and_set(&this->_sync_cleanup, 1)) {
			if(opt_sip_tcp_reassembly_ext_usleep) {
				USLEEP(opt_sip_tcp_reassembly_ext_usleep);
			}
		}
	}
	void unlock_cleanup() {
		__sync_lock_release(&this->_sync_cleanup);
	}
private:
	eType type;
	map<TcpReassemblyLink_id, TcpReassemblyLink*> links;
	volatile int _sync_links;
	volatile int _sync_push;
	volatile int _sync_cleanup;
	bool enableHttpForceInit;
	bool enableCrazySequence;
	bool enableWildLink;
	bool ignoreTcpHandshake;
	bool enableIgnorePairReqResp;
	bool enableDestroyStreamsInComplete;
	bool enableAllCompleteAfterZerodataAck;
	bool enableValidateDataViaCheckData;
	bool unlimitedReassemblyAttempts;
	int maxReassemblyAttempts;
	bool enableValidateLastQueueDataViaCheckData;
	bool enableStrictValidateDataViaCheckData;
	bool needValidateDataViaCheckData;
	bool simpleByAck;
	bool ignorePshInCheckOkData;
	bool smartMaxSeq;
	bool smartMaxSeqByPsh;
	bool skipZeroData;
	bool ignoreZeroData;
	bool enableCleanupThread;
	bool enableAutoCleanup;
	unsigned int cleanupPeriod;
	bool enableHttpCleanupExt;
	bool enablePacketThread;
	TcpReassemblyProcessData *dataCallback;
	bool enablePushLock;
	bool enableLinkLock;
	bool enableSmartCompleteData;
	int completeMod;
	bool enableExtStat;
	unsigned int extCleanupStreamsLimitStreams;
	unsigned int extCleanupStreamsLimitHeap;
	u_int64_t act_time_from_header;
	u_int64_t last_time;
	u_int64_t last_cleanup_call_time_from_header;
	u_int64_t last_erase_links_time;
	bool doPrintContent;
	pthread_t cleanupThreadHandle;
	pthread_t packetThreadHandle;
	int cleanupThreadId;
	int packetThreadId;
	bool terminated;
	bool ignoreTerminating;
	FILE *log;
	pstat_data cleanupThreadPstatData[2];
	pstat_data packetThreadPstatData[2];
	u_long _cleanupCounter;
	u_int32_t linkTimeout;
	SafeAsyncQueue<sPacket> *packetQueue;
	volatile bool initCleanupThreadOk;
	volatile bool initPacketThreadOk;
	volatile bool terminatingCleanupThread;
	volatile bool terminatingPacketThread;
	bool dumperEnable;
	list<u_int16_t> dumperPorts;
	string dumperFileName;
	PcapDumper *dumper;
	volatile int dumperSync;
	u_int64_t dumperFileCounter;
	u_int64_t dumperPacketCounter;
friend class TcpReassemblyLink;
friend class TcpReassemblyStream;
friend void *_TcpReassembly_cleanupThreadFunction(void* arg);
friend void *_TcpReassembly_packetThreadFunction(void* arg);
};

#endif
