#ifndef SNIFF_PROC_CLASS_H
#define SNIFF_PROC_CLASS_H


#include <unistd.h>
#include "sniff.h"
#include "calltable.h"


#define MAX_TCPSTREAMS 1024

class TcpReassemblySip {
public:
	struct tcp_stream_packet {
		u_int64_t packet_number;
		u_int32_t saddr;
		u_int16_t source; 
		u_int32_t daddr;
		u_int16_t dest;
		char *data;
		int datalen;
		int dataoffset;
		pcap_pkthdr header;
		u_char *packet;
		iphdr2 *header_ip;
		pcap_t *handle;
		int dlt; 
		int sensor_id;
		time_t ts;
		u_int32_t seq;
		u_int32_t next_seq;
		u_int32_t ack_seq;
		tcp_stream_packet *next;
		int lastpsh;
	};
	struct tcp_stream {
		tcp_stream() {
			packets = NULL;
			complete_data = NULL;
			last_ts = 0;
			last_seq = 0;
			last_ack_seq = 0;
		}
		tcp_stream_packet* packets;
		SimpleBuffer* complete_data;
		time_t last_ts;
		u_int32_t last_seq;
		u_int32_t last_ack_seq;
	};
	struct tcp_stream_id {
		tcp_stream_id(u_int32_t saddr = 0, u_int16_t source = 0, 
			      u_int32_t daddr = 0, u_int16_t dest = 0) {
			this->saddr = saddr;
			this->source = source;
			this->daddr = daddr; 
			this->dest = dest;
		}
		u_int32_t saddr;
		u_int16_t source;
		u_int32_t daddr;
		u_int16_t dest;
		bool operator < (const tcp_stream_id& other) const {
			return((this->saddr < other.saddr) ? 1 : (this->saddr > other.saddr) ? 0 :
			       (this->source < other.source) ? 1 : (this->source > other.source) ? 0 :
			       (this->daddr < other.daddr) ? 1 : (this->daddr > other.daddr) ? 0 :
			       (this->dest < other.dest));
		}
	};
public:
	void processPacket(
		u_int64_t packet_number,
		unsigned int saddr, int source, unsigned int daddr, int dest, char *data, int datalen, int dataoffset,
		pcap_t *handle, pcap_pkthdr header, const u_char *packet, struct iphdr2 *header_ip,
		int dlt, int sensor_id,
		bool issip);
	void clean(time_t ts = 0);
private:
	bool addPacket(
		tcp_stream *stream,
		u_int64_t packet_number,
		unsigned int saddr, int source, unsigned int daddr, int dest, char *data, int datalen, int dataoffset,
		pcap_t *handle, pcap_pkthdr header, const u_char *packet, struct iphdr2 *header_ip,
		int dlt, int sensor_id);
	void complete(
		tcp_stream *stream, tcp_stream_id id);
	tcp_stream_packet *getLastStreamPacket(tcp_stream *stream) {
		if(!stream->packets) {
			return(NULL);
		}
		tcp_stream_packet *packet = stream->packets;
		while(packet->next) {
			packet = packet->next;
		}
		return(packet);
	}
	bool isCompleteStream(tcp_stream *stream) {
		if(!stream->packets) {
			return(false);
		}
		int data_len;
		u_char *data;
		if(stream->complete_data) {
			data_len = stream->complete_data->size();
			data = stream->complete_data->data();
		} else {
			data_len = stream->packets->datalen;
			data = (u_char*)stream->packets->data;
		}
		while(data_len > 0) {
			u_char *endHeaderSepPos = (u_char*)memmem(data, data_len, "\r\n\r\n", 4);
			if(endHeaderSepPos) {
				*endHeaderSepPos = 0;
				char *contentLengthPos = strcasestr((char*)data, "Content-Length: ");
				*endHeaderSepPos = '\r';
				unsigned int contentLength = 0;
				if(contentLengthPos) {
					contentLength = atol(contentLengthPos + 16);
				}
				int sipDataLen = (endHeaderSepPos - data) + 4 + contentLength;
				extern int check_sip20(char *data, unsigned long len);
				if(sipDataLen == data_len) {
					return(true);
				} else if(sipDataLen < data_len) {
					if(!check_sip20((char*)(data + sipDataLen), data_len - sipDataLen)) {
						return(true);
					} else {
						data += sipDataLen;
						data_len -= sipDataLen;
					}
				} else {
					break;
				}
			} else {
				break;
			}
		}
		return(false);
	}
	void cleanStream(tcp_stream *stream, bool deletePackets);
private:
	map<tcp_stream_id, tcp_stream> tcp_streams;
};


class PreProcessPacket {
public:
	enum eTypePreProcessThread {
		ppt_detach,
		ppt_sip,
		ppt_extend
	};
	struct packet_parse_s {
		packet_parse_s() {
			init();
		}
		void init() {
			sip_method = -1;
			sip_response = false;
			lastSIPresponseNum = -1;
			call_cancel_lsr487 = false;
			call = NULL;
			merged = 0;
			call_created = NULL;
			detectUserAgent = false;
			_getCallID_reassembly = false;
			_getSipMethod = false;
			_getLastSipResponse = false;
			_findCall = false;
			_createCall = false;
		}
		packet_s packet;
		bool packetDelete;
		int forceSip;
		ParsePacket *parse;
		u_int32_t sipDataLen;
		bool isSip;
		string callid;
		int sip_method;
		bool sip_response;
		int lastSIPresponseNum;
		string lastSIPresponse;
		bool call_cancel_lsr487;
		Call *call;
		int merged;
		Call *call_created;
		bool detectUserAgent;
		bool _getCallID_reassembly;
		bool _getSipMethod;
		bool _getLastSipResponse;
		bool _findCall;
		bool _createCall;
		unsigned int hash[2];
	};
	struct batch_packet_parse_s {
		batch_packet_parse_s(unsigned max_count) {
			count = 0;
			used = 0;
			batch = new packet_parse_s[max_count];
			this->max_count = max_count;
		}
		~batch_packet_parse_s() {
			delete [] batch;
		}
		void allocParse() {
			for(unsigned i = 0; i < max_count; i++) {
				batch[i].parse = new FILE_LINE ParsePacket;
			}
		}
		void deleteParse() {
			for(unsigned i = 0; i < max_count; i++) {
				delete batch[i].parse;
			}
		}
		void setStdParse() {
			for(unsigned i = 0; i < max_count; i++) {
				batch[i].parse->setStdParse();
			}
		}
		packet_parse_s *batch;
		unsigned count;
		volatile int used;
		unsigned max_count;
	};
public:
	PreProcessPacket(eTypePreProcessThread typePreProcessThread);
	~PreProcessPacket();
	inline void push_packet_1(bool is_ssl, u_int64_t packet_number,
				  unsigned int saddr, int source, unsigned int daddr, int dest, 
				  char *data, int datalen, int dataoffset,
				  pcap_t *handle, pcap_pkthdr *header, const u_char *packet, bool packetDelete,
				  int istcp, struct iphdr2 *header_ip, int forceSip,
				  pcap_block_store *block_store, int block_store_index, int dlt, int sensor_id,
				  bool disableLock = false) {
		packet_s packetS;
		packetS.packet_number = packet_number;
		packetS.saddr = saddr;
		packetS.source = source;
		packetS.daddr = daddr; 
		packetS.dest = dest;
		packetS.data = data; 
		packetS.datalen = datalen; 
		packetS.dataoffset = dataoffset;
		packetS.handle = handle; 
		packetS.header = *header; 
		packetS.packet = packet; 
		packetS.istcp = istcp; 
		packetS.header_ip = header_ip; 
		packetS.block_store = block_store; 
		packetS.block_store_index =  block_store_index; 
		packetS.dlt = dlt; 
		packetS.sensor_id = sensor_id;
		packetS.is_ssl = is_ssl;
		this->push_packet_2(&packetS, NULL, packetDelete, forceSip, disableLock);
	}
	inline void push_packet_2(packet_s *packetS, packet_parse_s *packetParseS = NULL, bool packetDelete = false, int forceSip = 0, bool disableLock = false) {
	 
		extern int opt_enable_ssl;
		extern unsigned long preprocess_packet__last_cleanup;
		extern TcpReassemblySip tcpReassemblySip;
		extern char *sipportmatrix;
		
		extern int check_sip20(char *data, unsigned long len);
		
		switch(typePreProcessThread) {
		case ppt_detach:
			if(opt_enable_ssl && !disableLock) {
				this->lock_push();
			}
			if(packetS->block_store) {
				packetS->block_store->lock_packet(packetS->block_store_index);
			}
			break;
		case ppt_sip:
			if(packetS->header.ts.tv_sec - preprocess_packet__last_cleanup > 10) {
				// clean tcp_streams_list
				tcpReassemblySip.clean(packetS->header.ts.tv_sec);
				preprocess_packet__last_cleanup = packetS->header.ts.tv_sec;
			}
			break;
		case ppt_extend:
			break;
		}
	 
		if(!qring_push_index) {
			unsigned usleepCounter = 0;
			while(this->qring[this->writeit]->used != 0) {
				usleep(20 *
				       (usleepCounter > 10 ? 50 :
					usleepCounter > 5 ? 10 :
					usleepCounter > 2 ? 5 : 1));
				++usleepCounter;
			}
			qring_push_index = this->writeit + 1;
		}
		batch_packet_parse_s *_batch_parse_packet = this->qring[qring_push_index - 1];
		packet_parse_s *_parse_packet = &_batch_parse_packet->batch[_batch_parse_packet->count];
		if(packetParseS) {
			*_parse_packet  = *packetParseS;
		} else {
			_parse_packet->packet = *packetS;
			_parse_packet->packetDelete = packetDelete; 
			_parse_packet->forceSip = forceSip; 
		}
		
		switch(typePreProcessThread) {
		case ppt_detach:
			break;
		case ppt_sip:
			_parse_packet->_getSipMethod = false;
			if((forceSip ||
			    sipportmatrix[packetS->source] || 
			    sipportmatrix[packetS->dest]) &&
			   check_sip20(packetS->data, packetS->datalen)) {
				_parse_packet->sipDataLen = _parse_packet->parse->parseData(packetS->data, packetS->datalen, true);
				_parse_packet->isSip = _parse_packet->parse->isSip();
			} else {
				_parse_packet->sipDataLen = 0;
				_parse_packet->isSip = false;
			}
			if(_parse_packet->isSip) {
				_parse_packet->init();
				if(!this->sipProcess_base(_parse_packet)) {
					if(packetS->block_store) {
						packetS->block_store->unlock_packet(packetS->block_store_index);
					}
					return;
				}
				_parse_packet->hash[0] = 0;
				_parse_packet->hash[1] = 0;
			} else {
				if(!this->sipProcess_reassembly(_parse_packet)) {
					if(packetS->block_store) {
						packetS->block_store->unlock_packet(packetS->block_store_index);
					}
					return;
				}
				if(packetS->datalen > 2/* && (htons(*(unsigned int*)data) & 0xC000) == 0x8000*/) { // disable condition - failure for udptl (fax)
					_parse_packet->hash[0] = tuplehash(packetS->saddr, packetS->source);
					_parse_packet->hash[1] = tuplehash(packetS->daddr, packetS->dest);
				}
			}
			break;
		case ppt_extend:
			if(_parse_packet->isSip) {
				this->sipProcess_extend(_parse_packet);
			}
			break;
		}
		
		++_batch_parse_packet->count;
		if(_batch_parse_packet->count == _batch_parse_packet->max_count) {
			_batch_parse_packet->used = 1;
			if((this->writeit + 1) == this->qring_length) {
				this->writeit = 0;
			} else {
				this->writeit++;
			}
			qring_push_index = 0;
		}
		if(typePreProcessThread == ppt_detach &&
		   opt_enable_ssl && !disableLock) {
			this->unlock_push();
		}
	}
	void preparePstatData();
	double getCpuUsagePerc(bool preparePstatData);
	void terminate();
private:
	bool sipProcess_base(packet_parse_s *parse_packet);
	bool sipProcess_extend(packet_parse_s *parse_packet);
	bool sipProcess_getCallID(packet_parse_s *parse_packet);
	bool sipProcess_reassembly(packet_parse_s *parse_packet);
	void sipProcess_getSipMethod(packet_parse_s *parse_packet);
	void sipProcess_getLastSipResponse(packet_parse_s *parse_packet);
	void sipProcess_findCall(packet_parse_s *parse_packet);
	void sipProcess_createCall(packet_parse_s *parse_packet);
	void *outThreadFunction();
	void lock_push() {
		while(__sync_lock_test_and_set(&this->_sync_push, 1)) {
			usleep(10);
		}
	}
	void unlock_push() {
		__sync_lock_release(&this->_sync_push);
	}
private:
	eTypePreProcessThread typePreProcessThread;
	unsigned int qring_batch_item_length;
	unsigned int qring_length;
	batch_packet_parse_s **qring;
	unsigned qring_push_index;
	volatile unsigned int readit;
	volatile unsigned int writeit;
	pthread_t out_thread_handle;
	pstat_data threadPstatData[2];
	int outThreadId;
	volatile int _sync_push;
	bool term_preProcess;
friend inline void *_PreProcessPacket_outThreadFunction(void *arg);
};


class ProcessRtpPacket {
public:
	enum eType {
		hash,
		distribute
	};
public:
	struct rtp_call_info {
		Call *call;
		bool iscaller;
		bool is_rtcp;
		s_sdp_flags sdp_flags;
		bool use_sync;
	};
	struct packet_rtp_s {
		packet_s packet;
		unsigned int hash_s;
		unsigned int hash_d;
		rtp_call_info call_info[20];
		int call_info_length;
		bool call_info_find_by_dest;
	};
	struct batch_packet_rtp_s {
		batch_packet_rtp_s(unsigned max_count) {
			count = 0;
			used = 0;
			batch = new packet_rtp_s[max_count];
			this->max_count = max_count;
		}
		~batch_packet_rtp_s() {
			delete [] batch;
		}
		packet_rtp_s *batch;
		unsigned count;
		volatile int used;
		unsigned max_count;
	};
public:
	ProcessRtpPacket(eType type, int indexThread);
	~ProcessRtpPacket();
	inline void push_packet_rtp_1(packet_s *packetS,
				      unsigned int hash_s, unsigned int hash_d) {
		if(packetS->block_store) {
			packetS->block_store->lock_packet(packetS->block_store_index);
		}
		if(!qring_push_index) {
			unsigned usleepCounter = 0;
			while(this->qring[this->writeit]->used != 0) {
				usleep(20 *
				       (usleepCounter > 10 ? 50 :
					usleepCounter > 5 ? 10 :
					usleepCounter > 2 ? 5 : 1));
				++usleepCounter;
			}
			qring_push_index = this->writeit + 1;
		}
		batch_packet_rtp_s *_batch_rtp_packet = this->qring[qring_push_index - 1];
		_batch_rtp_packet->batch[_batch_rtp_packet->count].packet = *packetS;
		_batch_rtp_packet->batch[_batch_rtp_packet->count].hash_s = hash_s;
		_batch_rtp_packet->batch[_batch_rtp_packet->count].hash_d = hash_d;
		_batch_rtp_packet->batch[_batch_rtp_packet->count].call_info_length = -1;
		++_batch_rtp_packet->count;
		if(_batch_rtp_packet->count == _batch_rtp_packet->max_count) {
			_batch_rtp_packet->used = 1;
			if((this->writeit + 1) == this->qring_length) {
				this->writeit = 0;
			} else {
				this->writeit++;
			}
			qring_push_index = 0;
		}
	}
	inline void push_packet_rtp_2(packet_rtp_s *packet) {
		if(!qring_push_index) {
			unsigned usleepCounter = 0;
			while(this->qring[this->writeit]->used != 0) {
				usleep(20 *
				       (usleepCounter > 10 ? 50 :
					usleepCounter > 5 ? 10 :
					usleepCounter > 2 ? 5 : 1));
				++usleepCounter;
			}
			qring_push_index = this->writeit + 1;
		}
		batch_packet_rtp_s *_batch_rtp_packet = this->qring[qring_push_index - 1];
		_batch_rtp_packet->batch[_batch_rtp_packet->count] = *packet;
		++_batch_rtp_packet->count;
		if(_batch_rtp_packet->count == _batch_rtp_packet->max_count) {
			_batch_rtp_packet->used = 1;
			if((this->writeit + 1) == this->qring_length) {
				this->writeit = 0;
			} else {
				this->writeit++;
			}
			qring_push_index = 0;
		}
	}
	void preparePstatData(bool nextThread = false);
	double getCpuUsagePerc(bool preparePstatData, bool nextThread = false);
	void terminate();
	static void autoStartProcessRtpPacket();
private:
	void *outThreadFunction();
	void *nextThreadFunction();
	void rtp_batch(batch_packet_rtp_s *_batch_packet);
	void find_hash(packet_rtp_s *_packet, bool lock = true);
public:
	eType type;
	int indexThread;
	int outThreadId;
	int nextThreadId;
private:
	unsigned int qring_batch_item_length;
	unsigned int qring_length;
	batch_packet_rtp_s **qring;
	unsigned qring_push_index;
	volatile unsigned int readit;
	volatile unsigned int writeit;
	pthread_t out_thread_handle;
	pthread_t next_thread_handle;
	pstat_data threadPstatData[2][2];
	bool term_processRtp;
	volatile batch_packet_rtp_s *hash_batch_thread_process;
	sem_t sem_sync_next_thread[2];
friend inline void *_ProcessRtpPacket_outThreadFunction(void *arg);
friend inline void *_ProcessRtpPacket_nextThreadFunction(void *arg);
};


#endif
