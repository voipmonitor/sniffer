#ifndef SNIFF_PROC_CLASS_H
#define SNIFF_PROC_CLASS_H


#include <unistd.h>
#include <list>
#include "sniff.h"
#include "calltable.h"
#include "websocket.h"


class TcpReassemblySip {
public:
	struct tcp_stream_packet {
		packet_s_process *packetS;
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
			last_seq = 0;
			last_ack_seq = 0;
			last_time_us = 0;
		}
		tcp_stream_packet* packets;
		SimpleBuffer* complete_data;
		u_int32_t last_seq;
		u_int32_t last_ack_seq;
		u_int64_t last_time_us;
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
	TcpReassemblySip();
	void processPacket(packet_s_process **packetS_ref, bool isSip, class PreProcessPacket *processPacket);
	void clean(time_t ts = 0);
private:
	bool addPacket(tcp_stream *stream, packet_s_process **packetS_ref, PreProcessPacket *processPacket);
	void complete(tcp_stream *stream, tcp_stream_id id, PreProcessPacket *processPacket);
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
			data_len = stream->packets->packetS->datalen;
			data = (u_char*)stream->packets->packetS->data;
		}
		return(this->checkSip(data, data_len, false));
	}
	void cleanStream(tcp_stream *stream, bool callFromClean = false);
public:
	static bool checkSip(u_char *data, int data_len, bool strict, list<d_u_int32_t> *offsets = NULL) {
		if(check_websocket(data, data_len)) {
			cWebSocketHeader ws(data, data_len);
			bool allocData;
			u_char *ws_data = ws.decodeData(&allocData);
			bool rslt = checkSip(ws_data, ws.getDataLength(), strict, offsets);
			if(rslt && offsets && offsets->size()) {
				unsigned count = 0;
				for(list<d_u_int32_t>::iterator iter = offsets->begin(); iter != offsets->end(); iter++) {
					if(count > 0) {
						iter->val[0] += ws.getHeaderLength();
					}
					iter->val[1] += ws.getHeaderLength();
					++count;
				}
			}
			if(allocData) {
				delete [] ws_data;
			}
			return(rslt);
		}
		extern int check_sip20(char *data, unsigned long len, ParsePacket::ppContentsX *parseContents, bool isTcp);
		u_int32_t offset = 0;
		if(!data || data_len < 10 ||
		   !check_sip20((char*)data, data_len, NULL, true)) {
			return(false);
		}
		while(data_len > 0) {
			unsigned int contentLength = 0;
			u_char *endHeaderSepPos = (u_char*)memmem(data, min(data_len, 5000), "\r\n\r\n", 4);
			if(endHeaderSepPos) {
				*endHeaderSepPos = 0;
				for(int pass = 0; pass < 2; ++pass) {
					char *contentLengthPos = strcasestr((char*)data, pass ? "\r\nl:" : "\r\nContent-Length:");
					if(contentLengthPos) {
						contentLengthPos += pass ? 4 : 17;
						while(*contentLengthPos == ' ') {
							++contentLengthPos;
						}
						contentLength = atol(contentLengthPos);
						break;
					}
				}
				*endHeaderSepPos = '\r';
			} else {
				break;
			}
			int sipDataLen = (endHeaderSepPos - data) + 4 + contentLength;
			if(offsets) {
				offsets->push_back(d_u_int32_t(offset, sipDataLen));
			}
			if(sipDataLen == data_len) {
				return(true);
			} else if(sipDataLen > 0 && sipDataLen < data_len) {
				if(!check_sip20((char*)(data + sipDataLen), data_len - sipDataLen, NULL, true)) {
					return(strict ? false : true);
				} else {
					data += sipDataLen;
					data_len -= sipDataLen;
					offset += sipDataLen;
				}
			} else {
				break;
			}
		}
		return(false);
	}
private:
	map<tcp_stream_id, tcp_stream> tcp_streams;
	time_t last_cleanup;
};


/* no need ?
class ReassemblyWebsocket {
public:
	class websocket_stream {
	public:
		~websocket_stream();
		void add(packet_s_process *packet);
		u_char *complete(unsigned *length);
		unsigned length();
		void clear();
	private:
		list<packet_s_process*> packets;
	};
public:
	ReassemblyWebsocket();
	~ReassemblyWebsocket();
	int processPacket(packet_s_process **packetS_ref, bool createStream);
	bool existsStream(packet_s_process **packetS_ref);
private:
	map<sStreamId, websocket_stream*> streams;
};
*/

class ReassemblyWebsocketBuffer {
public:
	~ReassemblyWebsocketBuffer();
	u_char *processPacket(u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport, 
			      u_char *data, unsigned length, bool createStream,
			      unsigned *completed_length);
	bool existsStream(u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport);
private:
	map<sStreamId, SimpleBuffer*> streams;
};


//#define PREPROCESS_DETACH2

class PreProcessPacket {
public:
	enum eTypePreProcessThread {
		ppt_detach,
		#ifdef PREPROCESS_DETACH2
		ppt_detach2,
		#endif
		ppt_sip,
		ppt_extend,
		ppt_pp_call,
		ppt_pp_register,
		ppt_pp_sip_other,
		ppt_pp_rtp,
		ppt_pp_other,
		ppt_end
	};
	struct batch_packet_s {
		batch_packet_s(unsigned max_count) {
			count = 0;
			used = 0;
			batch = new FILE_LINE(28001) packet_s_plus_pointer*[max_count];
			for(unsigned i = 0; i < max_count; i++) {
				batch[i] = new FILE_LINE(28002) packet_s_plus_pointer;
			}
			this->max_count = max_count;
		}
		~batch_packet_s() {
			for(unsigned i = 0; i < max_count; i++) {
				batch[i]->blockstore_clear();
				batch[i]->packetdelete();
				delete batch[i];
			}
			delete [] batch;
		}
		packet_s_plus_pointer **batch;
		volatile unsigned count;
		volatile int used;
		unsigned max_count;
	};
	struct batch_packet_s_process {
		batch_packet_s_process(unsigned max_count) {
			count = 0;
			used = 0;
			batch = new FILE_LINE(28003) packet_s_process*[max_count];
			memset(batch, 0, sizeof(packet_s_process*) * max_count);
			this->max_count = max_count;
		}
		~batch_packet_s_process() {
			for(int i = 0; i < used; i++) {
				if(batch[i]) {
					batch[i]->blockstore_clear();
					batch[i]->packetdelete();
					delete batch[i];
				}
			}
			delete [] batch;
		}
		packet_s_process **batch;
		volatile unsigned count;
		volatile int used;
		unsigned max_count;
	};
public:
	PreProcessPacket(eTypePreProcessThread typePreProcessThread);
	~PreProcessPacket();
	inline void push_packet(bool is_ssl, 
				#if USE_PACKET_NUMBER
				u_int64_t packet_number,
				#endif
				unsigned int saddr, int source, unsigned int daddr, int dest, 
				int datalen, int dataoffset,
				u_int16_t handle_index, pcap_pkthdr *header, const u_char *packet, bool packetDelete,
				int istcp, int isother, struct iphdr2 *header_ip,
				pcap_block_store *block_store, int block_store_index, int dlt, int sensor_id, u_int32_t sensor_ip,
				int blockstore_lock = 1) {
		if(opt_enable_ssl) {
			this->lock_push();
		}
		packet_s packetS;
		#if USE_PACKET_NUMBER
		packetS.packet_number = packet_number;
		#endif
		packetS.saddr = saddr;
		packetS.source = source;
		packetS.daddr = daddr; 
		packetS.dest = dest;
		packetS.datalen = datalen; 
		packetS.dataoffset = dataoffset;
		packetS.handle_index = handle_index; 
		packetS.header_pt = header;
		packetS.packet = packet; 
		packetS._packet_alloc = packetDelete; 
		packetS.istcp = istcp; 
		packetS.isother = isother; 
		packetS.header_ip_offset = header_ip ? ((u_char*)header_ip - packet) : 0; 
		packetS.block_store = block_store; 
		packetS.block_store_index =  block_store_index; 
		packetS.dlt = dlt; 
		packetS.sensor_id_u = (u_int16_t)sensor_id;
		packetS.sensor_ip = sensor_ip;
		packetS.is_ssl = is_ssl;
		extern int opt_skinny;
		extern char *sipportmatrix;
		extern char *skinnyportmatrix;
		packetS.is_skinny = opt_skinny && istcp && (skinnyportmatrix[source] || skinnyportmatrix[dest]);
		extern int opt_mgcp;
		extern unsigned opt_tcp_port_mgcp_gateway;
		extern unsigned opt_udp_port_mgcp_gateway;
		extern unsigned opt_tcp_port_mgcp_callagent;
		extern unsigned opt_udp_port_mgcp_callagent;
		packetS.is_mgcp = opt_mgcp && 
				  (istcp ?
				    ((unsigned)source == opt_tcp_port_mgcp_gateway || (unsigned)dest == opt_tcp_port_mgcp_gateway ||
				     (unsigned)source == opt_tcp_port_mgcp_callagent || (unsigned)dest == opt_tcp_port_mgcp_callagent) :
				    ((unsigned)source == opt_udp_port_mgcp_gateway || (unsigned)dest == opt_udp_port_mgcp_gateway ||
				     (unsigned)source == opt_udp_port_mgcp_callagent || (unsigned)dest == opt_udp_port_mgcp_callagent));
		packetS.is_need_sip_process = !packetS.isother &&
					      (is_ssl ||
					       sipportmatrix[source] || sipportmatrix[dest] ||
					       packetS.is_skinny ||
					       packetS.is_mgcp);
		extern bool opt_t2_boost;
		if(!opt_t2_boost ||
		   packetS.is_need_sip_process ||
		   datalen > 2 ||
		   blockstore_lock != 1) {
			if(blockstore_lock == 1) {
				packetS.blockstore_lock(3 /*pb lock flag*/);
			} else if(blockstore_lock == 2) {
				packetS.blockstore_setlock();
			}
			this->push_packet_detach(&packetS);
		} else if(packetDelete) {
			delete header;
			delete [] packet;
		}
		if(opt_enable_ssl) {
			this->unlock_push();
		}
	}
	inline void push_packet_detach(packet_s *packetS) {
		if(this->outThreadState == 2) {
			if(!qring_push_index) {
				unsigned usleepCounter = 0;
				while(this->qring_detach[this->writeit]->used != 0) {
					usleep(20 *
					       (usleepCounter > 10 ? 50 :
						usleepCounter > 5 ? 10 :
						usleepCounter > 2 ? 5 : 1));
					++usleepCounter;
				}
				qring_push_index = this->writeit + 1;
				qring_push_index_count = 0;
				qring_detach_active_push_item = qring_detach[qring_push_index - 1];
			}
			*(packet_s*)qring_detach_active_push_item->batch[qring_push_index_count] = *packetS;
			extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end];
			void **p = qring_detach_active_push_item->batch[qring_push_index_count]->pointer;
			if(packetS->is_need_sip_process) {
				p[0] = preProcessPacket[PreProcessPacket::ppt_detach]->packetS_sip_pop_from_stack();
				p[1] = preProcessPacket[PreProcessPacket::ppt_detach]->stackSip;
			} else if(!packetS->isother) {
				p[0] = preProcessPacket[PreProcessPacket::ppt_detach]->packetS_rtp_pop_from_stack();
				p[1] = preProcessPacket[PreProcessPacket::ppt_detach]->stackRtp;
			} else {
				p[0] = preProcessPacket[PreProcessPacket::ppt_detach]->packetS_other_pop_from_stack();
				p[1] = preProcessPacket[PreProcessPacket::ppt_detach]->stackOther;
			}
			++qring_push_index_count;
			if(qring_push_index_count == qring_detach_active_push_item->max_count) {
				#if RQUEUE_SAFE
					__SYNC_SET_TO_LOCK(qring_detach_active_push_item->count, qring_push_index_count, this->_sync_count);
					__SYNC_SET(qring_detach_active_push_item->used);
					__SYNC_INCR(this->writeit, this->qring_length);
				#else
					qring_detach_active_push_item->count = qring_push_index_count;
					qring_detach_active_push_item->used = 1;
					if((this->writeit + 1) == this->qring_length) {
						this->writeit = 0;
					} else {
						this->writeit++;
					}
				#endif
				qring_push_index = 0;
				qring_push_index_count = 0;
			}
		} else {
			while(this->outThreadState) {
				usleep(10);
			}
			this->process_DETACH(packetS);
		}
	}
	inline void push_packet(packet_s_process *packetS) {
		if(is_terminating()) {
			this->packetS_destroy(packetS);
			return;
		}
		if(this->outThreadState == 2) {
			++qringPushCounter;
			if(!qring_push_index) {
				unsigned usleepCounter = 0;
				while(this->qring[this->writeit]->used != 0) {
					usleep(20 *
					       (usleepCounter > 10 ? 50 :
						usleepCounter > 5 ? 10 :
						usleepCounter > 2 ? 5 : 1));
					if(usleepCounter == 0) {
						++qringPushCounter_full;
					}
					++usleepCounter;
				}
				qring_push_index = this->writeit + 1;
				qring_push_index_count = 0;
				qring_active_push_item = qring[qring_push_index - 1];
			}
			qring_active_push_item->batch[qring_push_index_count] = packetS;
			++qring_push_index_count;
			if(qring_push_index_count == qring_active_push_item->max_count) {
			        #if RQUEUE_SAFE
					__SYNC_SET_TO_LOCK(qring_active_push_item->count, qring_push_index_count, this->_sync_count);
					__SYNC_SET(qring_active_push_item->used);
					__SYNC_INCR(this->writeit, this->qring_length);
				#else
					qring_active_push_item->count = qring_push_index_count;
					qring_active_push_item->used = 1;
					if((this->writeit + 1) == this->qring_length) {
						this->writeit = 0;
					} else {
						this->writeit++;
					}
				#endif
				qring_push_index = 0;
				qring_push_index_count = 0;
			}
		} else {
			while(this->outThreadState) {
				usleep(10);
			}
			if(qring_push_index && qring_push_index_count) {
				for(unsigned int i = 0; i < qring_push_index_count; i++) {
					packet_s_process *_packetS = qring[qring_push_index - 1]->batch[i];
					switch(this->typePreProcessThread) {
					case ppt_detach:
					#ifdef PREPROCESS_DETACH2
					case ppt_detach2:
					#endif
						break;
					case ppt_sip:
						this->process_SIP(_packetS);
						break;
					case ppt_extend:
						this->process_SIP_EXTEND(_packetS);
						break;
					case ppt_pp_call:
						this->process_CALL(_packetS);
						break;
					case ppt_pp_register:
						this->process_REGISTER(_packetS);
						break;
					case ppt_pp_sip_other:
						this->process_SIP_OTHER(_packetS);
						break;
					case ppt_pp_rtp:
						this->process_RTP(_packetS);
						break;
					case ppt_pp_other:
						this->process_OTHER(_packetS);
						break;
					case ppt_end:
						break;
					}
				}
				qring_push_index = 0;
				qring_push_index_count = 0;
			}
			switch(this->typePreProcessThread) {
			case ppt_detach:
			#ifdef PREPROCESS_DETACH2
			case ppt_detach2:
			#endif
				break;
			case ppt_sip:
				this->process_SIP(packetS);
				break;
			case ppt_extend:
				this->process_SIP_EXTEND(packetS);
				break;
			case ppt_pp_call:
				this->process_CALL(packetS);
				break;
			case ppt_pp_register:
				this->process_REGISTER(packetS);
				break;
			case ppt_pp_sip_other:
				this->process_SIP_OTHER(packetS);
				break;
			case ppt_pp_rtp:
				this->process_RTP(packetS);
				break;
			case ppt_pp_other:
				this->process_OTHER(packetS);
				break;
			case ppt_end:
				break;
			}
		}
	}
	inline void push_batch() {
		if(typePreProcessThread == ppt_detach && opt_enable_ssl) {
			this->lock_push();
		}
		if(this->outThreadState == 2) {
			if(qring_push_index && qring_push_index_count) {
				#if RQUEUE_SAFE
					if(typePreProcessThread == ppt_detach) {
						__SYNC_SET_TO_LOCK(qring_detach_active_push_item->count, qring_push_index_count, this->_sync_count);
						__SYNC_SET(qring_detach_active_push_item->used);
					} else {
						__SYNC_SET_TO_LOCK(qring_active_push_item->count, qring_push_index_count, this->_sync_count);
						__SYNC_SET(qring_active_push_item->used);
					}
					__SYNC_INCR(this->writeit, this->qring_length);
				#else
					if(typePreProcessThread == ppt_detach) {
						qring_detach_active_push_item->count = qring_push_index_count;
						qring_detach_active_push_item->used = 1;
					} else {
						qring_active_push_item->count = qring_push_index_count;
						qring_active_push_item->used = 1;
					}
					if((this->writeit + 1) == this->qring_length) {
						this->writeit = 0;
					} else {
						this->writeit++;
					}
				#endif
				qring_push_index = 0;
				qring_push_index_count = 0;
			}
		} else {
			while(this->outThreadState) {
				usleep(10);
			}
			push_batch_nothread();
		}
		if(typePreProcessThread == ppt_detach && opt_enable_ssl) {
			this->unlock_push();
		}
	}
	void push_batch_nothread();
	void preparePstatData();
	double getCpuUsagePerc(bool preparePstatData, double *percFullQring = NULL);
	void terminate();
	static void autoStartNextLevelPreProcessPacket();
	static void autoStopLastLevelPreProcessPacket(bool force = false);
	double getQringFillingPerc() {
		unsigned int _readit = readit;
		unsigned int _writeit = writeit;
		return(_writeit >= _readit ?
			(double)(_writeit - _readit) / qring_length * 100 :
			(double)(qring_length - _readit + _writeit) / qring_length * 100);
	}
	inline packet_s_process *packetS_sip_create() {
		packet_s_process *packetS = new FILE_LINE(28004) packet_s_process;
		return(packetS);
	}
	inline packet_s_process_0 *packetS_rtp_create() {
		packet_s_process_0 *packetS = new FILE_LINE(28005) packet_s_process_0;
		return(packetS);
	}
	inline packet_s_stack *packetS_other_create() {
		packet_s_stack *packetS = new FILE_LINE(0) packet_s_stack;
		return(packetS);
	}
	inline packet_s_process *packetS_sip_pop_from_stack() {
		packet_s_process *packetS;
		if(this->stackSip->popq((void**)&packetS)) {
			++allocStackCounter[0];
		} else {
			packetS = new FILE_LINE(28006) packet_s_process;
			++allocCounter[0];
		}
		return(packetS);
	}
	inline packet_s_process_0 *packetS_rtp_pop_from_stack() {
		packet_s_process_0 *packetS;
		if(this->stackRtp->popq((void**)&packetS)) {
			++allocStackCounter[0];
		} else {
			packetS = new FILE_LINE(28007) packet_s_process_0;
			++allocCounter[0];
		}
		return(packetS);
	}
	inline packet_s_stack *packetS_other_pop_from_stack() {
		packet_s_stack *packetS;
		if(this->stackOther->popq((void**)&packetS)) {
			++allocStackCounter[0];
		} else {
			packetS = new FILE_LINE(0) packet_s_stack;
			++allocCounter[0];
		}
		return(packetS);
	}
	inline bool check_enable_destroy(packet_s_process_0 *packetS) {
		if(packetS->is_use_reuse_counter()) {
			bool enable = false;
			packetS->reuse_counter_lock();
			packetS->reuse_counter_dec();
			enable = packetS->reuse_counter == 0;
			packetS->reuse_counter_unlock();
			return(enable);
		}
		return(true);
	}
	inline bool check_enable_push_to_stack(packet_s_process_0 *packetS) {
		return(check_enable_destroy(packetS));
	}
	inline void packetS_destroy(packet_s *packetS) {
		extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end];
		if(packetS->__type == _t_packet_s_process) {
			preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy((packet_s_process**)&packetS);
		} else if(packetS->__type == _t_packet_s_process_0) {
			preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy((packet_s_process_0**)&packetS);
		} else if(packetS->__type == _t_packet_s_stack) {
			preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy((packet_s_stack**)&packetS);
		}
	}
	inline void packetS_destroy(packet_s_process **packetS) {
		if(!check_enable_destroy(*packetS)) {
			return;
		}
		(*packetS)->blockstore_unlock();
		(*packetS)->packetdelete();
		(*packetS)->term();
		delete *packetS;
		*packetS = NULL;
	}
	inline void packetS_destroy(packet_s_process_0 **packetS) {
		if(!check_enable_destroy(*packetS)) {
			return;
		}
		(*packetS)->blockstore_unlock();
		(*packetS)->packetdelete();
		delete *packetS;
		*packetS = NULL;
	}
	inline void packetS_destroy(packet_s_stack **packetS) {
		(*packetS)->blockstore_unlock();
		(*packetS)->packetdelete();
		delete *packetS;
		*packetS = NULL;
	}
	inline void packetS_push_to_stack(packet_s_process **packetS, u_int16_t queue_index) {
		if(sverb.t2_destroy_all) {
			this->packetS_destroy(packetS);
			return;
		}
		if(!check_enable_push_to_stack(*packetS)) {
			return;
		}
		if((*packetS)->_blockstore_lock) {
			(*packetS)->block_store->unlock_packet((*packetS)->block_store_index);
		}
		if((*packetS)->_packet_alloc) {
			delete (*packetS)->header_pt;
			delete [] (*packetS)->packet;
		}
		(*packetS)->term();
		extern int opt_block_alloc_stack;
		if(opt_block_alloc_stack ||
		   !(*packetS)->stack ||
		   !(*packetS)->stack->push((void*)*packetS, queue_index)) {
			delete *packetS;
		}
		*packetS = NULL;
	}
	inline void packetS_push_to_stack(packet_s_process_0 **packetS, u_int16_t queue_index) {
		if(sverb.t2_destroy_all) {
			this->packetS_destroy(packetS);
			return;
		}
		if(!check_enable_push_to_stack(*packetS)) {
			return;
		}
		if((*packetS)->_blockstore_lock) {
			(*packetS)->block_store->unlock_packet((*packetS)->block_store_index);
		}
		if((*packetS)->_packet_alloc) {
			delete (*packetS)->header_pt;
			delete [] (*packetS)->packet;
		}
		extern int opt_block_alloc_stack;
		if(opt_block_alloc_stack ||
		   !(*packetS)->stack ||
		   !(*packetS)->stack->push((void*)*packetS, queue_index)) {
			delete *packetS;
		}
		*packetS = NULL;
	}
	inline void packetS_push_to_stack(packet_s_stack **packetS, u_int16_t queue_index) {
		if(sverb.t2_destroy_all) {
			this->packetS_destroy(packetS);
			return;
		}
		if((*packetS)->_blockstore_lock) {
			(*packetS)->block_store->unlock_packet((*packetS)->block_store_index);
		}
		if((*packetS)->_packet_alloc) {
			delete (*packetS)->header_pt;
			delete [] (*packetS)->packet;
		}
		extern int opt_block_alloc_stack;
		if(opt_block_alloc_stack ||
		   !(*packetS)->stack ||
		   !(*packetS)->stack->push((void*)*packetS, queue_index)) {
			delete *packetS;
		}
		*packetS = NULL;
	}
	inline eTypePreProcessThread getTypePreProcessThread() {
		return(typePreProcessThread);
	}
	inline void startOutThread() {
		runOutThread();
	}
	inline void stopOutThread(bool force = false) {
		endOutThread(force);
	}
	inline bool isActiveOutThread() {
		return(outThreadState == 2);
	}
	inline unsigned long getAllocCounter(int index) {
		return(allocCounter[index]);
	}
	inline unsigned long getAllocStackCounter(int index) {
		return(allocStackCounter[index]);
	}
	inline void setAllocCounter(unsigned long c, int index) {
		allocCounter[index] = c;
	}
	inline void setAllocStackCounter(unsigned long c, int index) {
		allocStackCounter[index] = c;
	}
	string getNameTypeThread() {
		switch(typePreProcessThread) {
		case ppt_detach:
			return("detach");
		#ifdef PREPROCESS_DETACH2
		case ppt_detach2:
			return("detach2");
		#endif
		case ppt_sip:
			return("sip");
		case ppt_extend:
			return("extend");
		case ppt_pp_call:
			return("call");
		case ppt_pp_register:
			return("register");
		case ppt_pp_sip_other:
			return("sip other");
		case ppt_pp_rtp:
			return("rtp");
		case ppt_pp_other:
			return("other");
		case ppt_end:
			break;
		}
		return("");
	}
	string getShortcatTypeThread() {
		switch(typePreProcessThread) {
		case ppt_detach:
			return("d");
		#ifdef PREPROCESS_DETACH2
		case ppt_detach2:
			return("2:");
		#endif
		case ppt_sip:
			return("s");
		case ppt_extend:
			return("e");
		case ppt_pp_call:
			return("c");
		case ppt_pp_register:
			return("g");
		case ppt_pp_sip_other:
			return("so");
		case ppt_pp_rtp:
			return("r");
		case ppt_pp_other:
			return("o");
		case ppt_end:
			break;
		}
		return("");
	}
	static packet_s_process *clonePacketS(u_char *newData, unsigned newDataLength, packet_s_process *packetS);
private:
	void process_DETACH(packet_s *packetS_detach);
	void process_DETACH_plus(packet_s_plus_pointer *packetS_detach);
	void process_SIP(packet_s_process *packetS);
	void process_SIP_EXTEND(packet_s_process *packetS);
	void process_CALL(packet_s_process *packetS);
	void process_REGISTER(packet_s_process *packetS);
	void process_SIP_OTHER(packet_s_process *packetS);
	void process_RTP(packet_s_process_0 *packetS);
	void process_OTHER(packet_s_stack *packetS);
	void process_parseSipDataExt(packet_s_process **packetS_ref);
	inline void process_parseSipData(packet_s_process **packetS_ref);
	inline void process_sip(packet_s_process **packetS_ref);
	inline void process_skinny(packet_s_process **packetS_ref);
	inline void process_mgcp(packet_s_process **packetS_ref);
	inline void process_websocket(packet_s_process **packetS_ref);
	inline bool process_getCallID(packet_s_process **packetS_ref);
	inline bool process_getCallID_publish(packet_s_process **packetS_ref);
	inline void process_getSipMethod(packet_s_process **packetS_ref);
	inline void process_getLastSipResponse(packet_s_process **packetS_ref);
	inline void process_findCall(packet_s_process **packetS_ref);
	inline void process_createCall(packet_s_process **packetS_ref);
	void runOutThread();
	void endOutThread(bool force = false);
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
	batch_packet_s **qring_detach;
	batch_packet_s *qring_detach_active_push_item;
	batch_packet_s_process **qring;
	batch_packet_s_process *qring_active_push_item;
	unsigned qring_push_index;
	unsigned qring_push_index_count;
	volatile unsigned int readit;
	volatile unsigned int writeit;
	pthread_t out_thread_handle;
	pstat_data threadPstatData[2];
	u_int64_t qringPushCounter;
	u_int64_t qringPushCounter_full;
	int outThreadId;
	volatile int _sync_push;
	volatile int _sync_count;
	bool term_preProcess;
	cHeapItemsPointerStack *stackSip;
	cHeapItemsPointerStack *stackRtp;
	cHeapItemsPointerStack *stackOther;
	volatile int outThreadState;
	unsigned long allocCounter[2];
	unsigned long allocStackCounter[2];
	u_int64_t getCpuUsagePerc_counter;
	u_int64_t getCpuUsagePerc_counter_at_start_out_thread;
	static u_long autoStartNextLevelPreProcessPacket_last_time_s;
friend inline void *_PreProcessPacket_outThreadFunction(void *arg);
friend class TcpReassemblySip;
friend class SipTcpData;
};

inline packet_s_process *PACKET_S_PROCESS_SIP_CREATE() {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end];
	return(preProcessPacket[PreProcessPacket::ppt_detach]->packetS_sip_create());
}

inline packet_s_process_0 *PACKET_S_PROCESS_RTP_CREATE() {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end];
	return(preProcessPacket[PreProcessPacket::ppt_detach]->packetS_rtp_create());
}

inline packet_s_stack *PACKET_S_PROCESS_OTHER_CREATE() {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end];
	return(preProcessPacket[PreProcessPacket::ppt_detach]->packetS_other_create());
}

inline packet_s_process *PACKET_S_PROCESS_SIP_POP_FROM_STACK() {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end];
	return(preProcessPacket[PreProcessPacket::ppt_detach]->packetS_sip_pop_from_stack());
}

inline packet_s_process_0 *PACKET_S_PROCESS_RTP_POP_FROM_STACK() {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end];
	return(preProcessPacket[PreProcessPacket::ppt_detach]->packetS_rtp_pop_from_stack());
}

inline packet_s_stack *PACKET_S_PROCESS_OTHER_POP_FROM_STACK() {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end];
	return(preProcessPacket[PreProcessPacket::ppt_detach]->packetS_other_pop_from_stack());
}

inline void PACKET_S_PROCESS_DESTROY(packet_s_process_0 **packet) {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end];
	if((*packet)->__type == _t_packet_s_process_0) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy(packet);
	} else if((*packet)->__type == _t_packet_s_process) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy((packet_s_process**)packet);
	} else if((*packet)->__type == _t_packet_s_stack) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy((packet_s_stack**)packet);
	}
}

inline void PACKET_S_PROCESS_DESTROY(packet_s_process **packet) {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end];
	if((*packet)->__type == _t_packet_s_process) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy(packet);
	} else if((*packet)->__type == _t_packet_s_process_0) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy((packet_s_process_0**)packet);
	} else if((*packet)->__type == _t_packet_s_stack) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy((packet_s_stack**)packet);
	}
}

inline void PACKET_S_PROCESS_DESTROY(packet_s_stack **packet) {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end];
	if((*packet)->__type == _t_packet_s_stack) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy(packet);
	} else if((*packet)->__type == _t_packet_s_process) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy((packet_s_process**)packet);
	} else if((*packet)->__type == _t_packet_s_process_0) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy((packet_s_process_0**)packet);
	}
}

inline void PACKET_S_PROCESS_PUSH_TO_STACK(packet_s_process_0 **packet, u_int16_t queue_index) {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end];
	if((*packet)->__type == _t_packet_s_process_0) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_push_to_stack(packet, queue_index);
	} else if((*packet)->__type == _t_packet_s_process) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_push_to_stack((packet_s_process**)packet, queue_index);
	} else if((*packet)->__type == _t_packet_s_stack) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_push_to_stack((packet_s_stack**)packet, queue_index);
	}
}

inline void PACKET_S_PROCESS_PUSH_TO_STACK(packet_s_process **packet, u_int16_t queue_index) {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end];
	if((*packet)->__type == _t_packet_s_process) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_push_to_stack(packet, queue_index);
	} else if((*packet)->__type == _t_packet_s_process_0) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_push_to_stack((packet_s_process_0**)packet, queue_index);
	} else if((*packet)->__type == _t_packet_s_stack) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_push_to_stack((packet_s_stack**)packet, queue_index);
	}
}

inline void PACKET_S_PROCESS_PUSH_TO_STACK(packet_s_stack **packet, u_int16_t queue_index) {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end];
	if((*packet)->__type == _t_packet_s_stack) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_push_to_stack(packet, queue_index);
	} else if((*packet)->__type == _t_packet_s_process) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_push_to_stack((packet_s_process**)packet, queue_index);
	} else if((*packet)->__type == _t_packet_s_process_0) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_push_to_stack((packet_s_process_0**)packet, queue_index);
	}
}


class ProcessRtpPacket {
public:
	enum eType {
		hash,
		distribute
	};
public:
	struct batch_packet_s_process {
		batch_packet_s_process(unsigned max_count) {
			count = 0;
			used = 0;
			batch = new FILE_LINE(28008) packet_s_process_0*[max_count];
			memset(batch, 0, sizeof(packet_s_process_0*) * max_count);
			this->max_count = max_count;
		}
		~batch_packet_s_process() {
			for(int i = 0; i < used; i++) {
				if(batch[i]) {
					batch[i]->blockstore_clear();
					delete batch[i];
					batch[i]= NULL;
				}
			}
			delete [] batch;
		}
		packet_s_process_0 **batch;
		volatile unsigned count;
		volatile int used;
		unsigned max_count;
	};
	struct arg_next_thread {
		ProcessRtpPacket *processRtpPacket;
		int next_thread_id;
	};
	struct s_hash_thread_data {
		volatile batch_packet_s_process *batch;
		volatile unsigned start;
		volatile unsigned end;
		volatile unsigned skip;
		volatile int processing;
		void null() {
			batch = NULL;
			start = 0;
			end = 0;
			skip = 0;
			processing = 0;
		}
	};
public:
	ProcessRtpPacket(eType type, int indexThread);
	~ProcessRtpPacket();
	inline void push_packet(packet_s_process_0 *packetS) {
		if(is_terminating()) {
			PACKET_S_PROCESS_DESTROY(&packetS);
			return;
		}
		if(!qring_push_index) {
			++qringPushCounter;
			unsigned usleepCounter = 0;
			while(this->qring[this->writeit]->used != 0) {
				usleep(20 *
				       (usleepCounter > 10 ? 50 :
					usleepCounter > 5 ? 10 :
					usleepCounter > 2 ? 5 : 1));
				if(usleepCounter == 0) {
					++qringPushCounter_full;
				}
				++usleepCounter;
			}
			qring_push_index = this->writeit + 1;
			qring_push_index_count = 0;
			qring_active_push_item = this->qring[qring_push_index - 1];
		}
		qring_active_push_item->batch[qring_push_index_count] = packetS;
		++qring_push_index_count;
		if(qring_push_index_count == qring_active_push_item->max_count) {
			#if RQUEUE_SAFE
				__SYNC_SET_TO_LOCK(qring_active_push_item->count, qring_push_index_count, this->_sync_count);
				__SYNC_SET(qring_active_push_item->used);
				__SYNC_INCR(this->writeit, this->qring_length);
			#else
				qring_active_push_item->count = qring_push_index_count;
				qring_active_push_item->used = 1;
				if((this->writeit + 1) == this->qring_length) {
					this->writeit = 0;
				} else {
					this->writeit++;
				}
			#endif
			qring_push_index = 0;
			qring_push_index_count = 0;
		}
	}
	inline void push_batch() {
		if(qring_push_index && qring_push_index_count) {
			#if RQUEUE_SAFE
				__SYNC_SET_TO_LOCK(qring_active_push_item->count, qring_push_index_count, this->_sync_count);
				__SYNC_SET(qring_active_push_item->used);
				__SYNC_INCR(this->writeit, this->qring_length);
			#else
				qring_active_push_item->count = qring_push_index_count;
				qring_active_push_item->used = 1;
				if((this->writeit + 1) == this->qring_length) {
					this->writeit = 0;
				} else {
					this->writeit++;
				}
			#endif
			qring_push_index = 0;
			qring_push_index_count = 0;
		}
	}
	void preparePstatData(int nextThreadId = 0);
	double getCpuUsagePerc(bool preparePstatData, int nextThreadId = 0, double *percFullQring = NULL);
	void terminate();
	static void autoStartProcessRtpPacket();
	void addRtpRhThread();
	static void addRtpRdThread();
	double getQringFillingPerc() {
		unsigned int _readit = readit;
		unsigned int _writeit = writeit;
		return(_writeit >= _readit ?
			(double)(_writeit - _readit) / qring_length * 100 :
			(double)(qring_length - _readit + _writeit) / qring_length * 100);
	}
	bool isNextThreadsGt2Processing(int process_rtp_packets_hash_next_threads) {
		for(int i = 2; i < process_rtp_packets_hash_next_threads; i++) {
			if(this->hash_thread_data[i].processing) {
				return(true);
			}
		}
		return(false);
	}
	bool existsNextThread(int next_thread_index) {
		return(next_thread_index < MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS &&
		       this->nextThreadId[next_thread_index]);
	}
private:
	void *outThreadFunction();
	void *nextThreadFunction(int next_thread_index_plus);
	void rtp_batch(batch_packet_s_process *batch, unsigned count);
	inline void rtp_packet_distr(packet_s_process_0 *packetS, int _process_rtp_packets_distribute_threads_use);
	void find_hash(packet_s_process_0 *packetS, bool lock = true);
public:
	eType type;
	int indexThread;
	int outThreadId;
	int nextThreadId[MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS];
private:
	int process_rtp_packets_hash_next_threads;
	unsigned int qring_batch_item_length;
	unsigned int qring_length;
	batch_packet_s_process **qring;
	batch_packet_s_process *qring_active_push_item;
	unsigned qring_push_index;
	unsigned qring_push_index_count;
	volatile unsigned int readit;
	volatile unsigned int writeit;
	pthread_t out_thread_handle;
	pthread_t next_thread_handle[MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS];
	pstat_data threadPstatData[1 + MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS][2];
	u_int64_t qringPushCounter;
	u_int64_t qringPushCounter_full;
	bool term_processRtp;
	s_hash_thread_data hash_thread_data[MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS];
	volatile int *hash_find_flag;
	sem_t sem_sync_next_thread[MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS][2];
	volatile int _sync_count;
friend inline void *_ProcessRtpPacket_outThreadFunction(void *arg);
friend inline void *_ProcessRtpPacket_nextThreadFunction(void *arg);
};


#endif
