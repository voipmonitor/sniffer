#ifndef SNIFF_PROC_CLASS_H
#define SNIFF_PROC_CLASS_H


#include <unistd.h>
#include <list>
#include <queue>
#include "sniff.h"
#include "calltable.h"
#include "websocket.h"
#include "pcap_queue.h"

#if ENABLE_MOODY_CAMEL
#include "concurrentqueue/concurrentqueue_bounded.h"
#endif


#define LF_CHAR '\n'
#define CR_CHAR '\r'
#define LF_STR "\n"
#define CR_STR "\r"
#define LF_STR_ESC "\\n"
#define CR_STR_ESC "\\r"
#define LF_LINE_SEPARATOR "\n"
#define CR_LF_LINE_SEPARATOR "\r\n"
#define SIP_LINE_SEPARATOR(lf) (lf ? LF_LINE_SEPARATOR : CR_LF_LINE_SEPARATOR)
#define SIP_DBLLINE_SEPARATOR(lf) (lf ? LF_LINE_SEPARATOR LF_LINE_SEPARATOR :CR_LF_LINE_SEPARATOR CR_LF_LINE_SEPARATOR)
#define SIP_LINE_SEPARATOR_SIZE(lf) (lf ? 1 : 2)
#define SIP_DBLLINE_SEPARATOR_SIZE(lf) (lf ? 2 : 4)
#define SIP_LINE_SEPARATOR_STR(lf, str) (lf ? LF_LINE_SEPARATOR str: CR_LF_LINE_SEPARATOR str)


extern int opt_t2_boost_direct_rtp;


class TcpReassemblySip {
public:
	enum e_checksip_strict_mode {
		_chssm_na = 0,
		_chssm_strict = 1,
		_chssm_ext = 2,
		_chssm_content_length = 4
	};
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
		tcp_stream_id(vmIP saddr = 0, vmPort source = 0, 
			      vmIP daddr = 0, vmPort dest = 0) {
			this->saddr = saddr;
			this->source = source;
			this->daddr = daddr; 
			this->dest = dest;
		}
		vmIP saddr;
		vmPort source;
		vmIP daddr;
		vmPort dest;
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
			data_len = stream->packets->packetS->datalen_();
			data = (u_char*)stream->packets->packetS->data_();
		}
		return(this->checkSip(data, data_len, TcpReassemblySip::_chssm_na));
	}
	void cleanStream(tcp_stream *stream, bool callFromClean = false);
public:
	static int checkSip(u_char *data, int data_len, int8_t strict_mode, list<d_u_int32_t> *offsets = NULL, int *data_len_used = NULL) {
		if(data_len_used) {
			*data_len_used = 0;
		}
		if(check_websocket(data, data_len)) {
			cWebSocketHeader ws(data, data_len);
			bool allocData;
			u_char *ws_data = ws.decodeData(&allocData);
			if(ws_data) {
				int rslt = checkSip(ws_data, ws.getDataLength(), strict_mode, offsets);
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
			} else {
				return(false);
			}
		}
		extern int check_sip20(char *data, unsigned long len, ParsePacket::ppContentsX *parseContents, bool isTcp);
		if(!data || data_len < 10 ||
		   !check_sip20((char*)data, data_len, NULL, true)) {
			return(false);
		}
		return(_checkSip(data, data_len, strict_mode, offsets, data_len_used));
	}
	static int _checkSip(u_char *data, int data_len, int8_t strict_mode, list<d_u_int32_t> *offsets = NULL, int *data_len_used = NULL) {
		extern int check_sip20(char *data, unsigned long len, ParsePacket::ppContentsX *parseContents, bool isTcp);
		int count_ok = 0;
		u_int32_t offset = 0;
		int data_len_orig = data_len;
		if(data_len_used) {
			*data_len_used = 0;
		}
		while(data_len > 0) {
			bool existsContentLength = false;
			unsigned int contentLength = 0;
			bool use_lf_line_separator = false;
			u_char *endHeaderSepPos = NULL;
			for(int pass_line_separator = 0; pass_line_separator < 2 && !endHeaderSepPos; pass_line_separator++) {
				endHeaderSepPos = (u_char*)memmem(data, min(data_len, 5000), 
								  SIP_DBLLINE_SEPARATOR(pass_line_separator == 1), 
								  SIP_DBLLINE_SEPARATOR_SIZE(pass_line_separator == 1));
				if(endHeaderSepPos && pass_line_separator == 1) {
					use_lf_line_separator = true;
				}
			}
			if(endHeaderSepPos) {
				u_char endHeaderSepPos_char = *endHeaderSepPos;
				*endHeaderSepPos = 0;
				for(int pass = 0; pass < 2; ++pass) {
					char *contentLengthPos = strcasestr((char*)data, 
									    pass ? 
									     LF_LINE_SEPARATOR "l:" : 
									     LF_LINE_SEPARATOR "Content-Length:");
					if(contentLengthPos) {
						contentLengthPos += (pass ? 2 : 15) + 1;
						while(*contentLengthPos == ' ') {
							++contentLengthPos;
						}
						contentLength = atol(contentLengthPos);
						existsContentLength = true;
						break;
					}
				}
				*endHeaderSepPos = endHeaderSepPos_char;
			} else {
				break;
			}
			if((strict_mode & _chssm_content_length)  && !existsContentLength) {
				return(0);
			}
			int sipDataLen = (endHeaderSepPos - data) + SIP_DBLLINE_SEPARATOR_SIZE(use_lf_line_separator) + contentLength;
			if(sipDataLen == data_len) {
				if((strict_mode & _chssm_ext) && !_checkSipExt(data, sipDataLen)) {
					return(0);
				}
				if(data_len_used) {
					*data_len_used = data_len_orig;
				}
				if(offsets) {
					offsets->push_back(d_u_int32_t(offset, sipDataLen));
				}
				return(count_ok + 1);
			} else if(sipDataLen > 0 && sipDataLen < data_len) {
				if(strict_mode & _chssm_strict) {
					int data_len_reduk = data_len;
					while(data_len_reduk > sipDataLen && 
					      (*(char*)(data + data_len_reduk - 1) == LF_CHAR ||
					       *(char*)(data + data_len_reduk - 1) == CR_CHAR)) {
						--data_len_reduk;
					}
					if(sipDataLen == data_len_reduk &&
					   (!(strict_mode & _chssm_ext) || _checkSipExt(data, sipDataLen))) {
						if(data_len_used) {
							*data_len_used = data_len_orig;
						}
						if(offsets) {
							offsets->push_back(d_u_int32_t(offset, sipDataLen));
						}
						return(count_ok + 1);
					}
				}
				if(!check_sip20((char*)(data + sipDataLen), data_len - sipDataLen, NULL, true)) {
					if(data_len_used) {
						*data_len_used = (strict_mode & _chssm_strict) ? 0 : offset + sipDataLen;
					}
					if(offsets) {
						offsets->push_back(d_u_int32_t(offset, sipDataLen));
					}
					return((strict_mode & _chssm_strict) ? 0 : count_ok + 1);
				} else {
					if(offsets) {
						offsets->push_back(d_u_int32_t(offset, sipDataLen));
					}
					data += sipDataLen;
					data_len -= sipDataLen;
					offset += sipDataLen;
					++count_ok;
				}
			} else {
				break;
			}
		}
		if(data_len_used) {
			*data_len_used = (strict_mode & _chssm_strict) ? 0 : offset;
		}
		return((strict_mode & _chssm_strict) ? 0 : count_ok);
	}
	static int _checkSipExt(u_char *data, int data_len) {
		char *callIdPos = strncasestr((char*)data, LF_LINE_SEPARATOR "Call-ID:", data_len);
		if(callIdPos) {
			int callIdOffset = callIdPos - ((char*)data);
			char *callIdPos2 = strncasestr((char*)data + callIdOffset + 1, LF_LINE_SEPARATOR "Call-ID:", data_len - callIdOffset - 1);
			if(callIdPos2) {
				return(false);
			}
		}
		return(true);
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

class ReassemblyBuffer {
public:
	enum eType {
		_na                   = 0x00,
		_websocket            = 0x01,
		_sip                  = 0x02,
		_type_mask            = 0x0F,
		_incomplete_flag      = 0x10,
		_websocket_incomplete = _incomplete_flag | _websocket,
		_sip_incomplete       = _incomplete_flag | _sip
	};
	struct sData_base {
		eType type;
		timeval time;
		u_int32_t ack;
		u_int32_t seq;
		u_int16_t handle_index;
		int dlt;
		int sensor_id;
		vmIP sensor_ip;
		sPacketInfoData pid;
	};
	struct sData : sData_base {
		SimpleBuffer *ethHeader;
		SimpleBuffer *buffer;
	};
	struct sDataRslt : sData_base {
		u_char *ethHeader;
		unsigned ethHeaderLength;
		bool ethHeaderAlloc;
		u_char *data;
		unsigned dataLength;
		bool dataAlloc;
		vmIP saddr;
		vmPort sport;
		vmIP daddr;
		vmPort dport;
	};
public:
	ReassemblyBuffer();
	~ReassemblyBuffer();
	void processPacket(u_char *ethHeader, unsigned ethHeaderLength,
			   vmIP saddr, vmPort sport, vmIP daddr, vmPort dport, 
			   eType type, u_char *data, unsigned length, bool createStream,
			   timeval time, u_int32_t ack, u_int32_t seq,
			   u_int16_t handle_index, int dlt, int sensor_id, vmIP sensor_ip, sPacketInfoData pid,
			   list<sDataRslt> *dataRslt);
	bool existsStream(vmIP saddr, vmPort sport, vmIP daddr, vmPort dport);
	bool existsStream(sStreamId *sid);
	void cleanup(timeval time, list<sDataRslt> *dataRslt);
private:
	sDataRslt complete(sStreamId *streamId, sData *b_data);
private:
	map<sStreamId, sData> streams;
	u_int64_t minTimeInStreams;
};


class PreProcessPacket {
public:
	enum eTypePreProcessThread {
		ppt_detach_x,
		ppt_detach,
		ppt_sip,
		ppt_extend,
		#if not CALLX_MOD_OLDVER
		ppt_pp_find_call,
		ppt_pp_process_call,
		#else
		ppt_pp_call,
		#endif
		ppt_pp_register,
		ppt_pp_sip_other,
		ppt_pp_diameter,
		ppt_pp_rtp,
		ppt_pp_other,
		ppt_end_base,
		#if CALLX_MOD_OLDVER
		ppt_pp_callx,
		ppt_pp_callfindx
		#endif
	};
	enum eCallX_state {
		callx_na,
		callx_process,
		callx_find
	};
	struct pcap_queue_packet_data {
		u_int16_t header_ip_offset;
		u_int16_t header_ip_encaps_offset;
		u_int16_t data_offset;
		u_int32_t datalen;
		u_int16_t source;
		u_int16_t dest;
		packet_flags pflags;
		sHeaderPacketPQout hp;
		u_int16_t handle_index;
	};
	struct batch_pcap_queue_packet_data {
		batch_pcap_queue_packet_data(unsigned max_count) {
			count = 0;
			used = 0;
			batch = new FILE_LINE(0) pcap_queue_packet_data*[max_count];
			for(unsigned i = 0; i < max_count; i++) {
				batch[i] = new FILE_LINE(0) pcap_queue_packet_data;
			}
			this->max_count = max_count;
		}
		~batch_pcap_queue_packet_data() {
			for(unsigned i = 0; i < max_count; i++) {
				if(i < count) {
					batch[i]->hp.destroy_or_unlock_blockstore();
				}
				delete batch[i];
			}
			delete [] batch;
		}
		void realloc(unsigned new_max_count) {
			for(unsigned i = 0; i < max_count; i++) {
				delete batch[i];
			}
			delete [] batch;
			max_count = new_max_count;
			batch = new FILE_LINE(0) pcap_queue_packet_data*[max_count];
			for(unsigned i = 0; i < max_count; i++) {
				batch[i] = new FILE_LINE(0) pcap_queue_packet_data;
			}
		}
		pcap_queue_packet_data **batch;
		volatile unsigned count;
		volatile int used;
		unsigned max_count;
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
				delete batch[i];
			}
			delete [] batch;
		}
		void realloc(unsigned new_max_count) {
			for(unsigned i = 0; i < max_count; i++) {
				delete batch[i];
			}
			delete [] batch;
			max_count = new_max_count;
			batch = new FILE_LINE(0) packet_s_plus_pointer*[max_count];
			for(unsigned i = 0; i < max_count; i++) {
				batch[i] = new FILE_LINE(0) packet_s_plus_pointer;
			}
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
		void realloc(unsigned new_max_count) {
			delete [] batch;
			max_count = new_max_count;
			batch = new FILE_LINE(0) packet_s_process*[max_count];
			memset(batch, 0, sizeof(packet_s_process*) * max_count);
		}
		packet_s_process **batch;
		volatile unsigned count;
		volatile int used;
		unsigned max_count;
	};
	struct batch_packet_s_time {
		inline batch_packet_s_time(unsigned max_count) {
			batch = new FILE_LINE(0) packet_s_process*[max_count];
			packet_batch_time_ms = new FILE_LINE(0) u_int64_t[max_count];
			count = 0;
			count_processed = 0;
			this->max_count = max_count;
		}
		inline ~batch_packet_s_time() {
			for(unsigned i = count_processed; i < count; i++) {
				batch[i]->blockstore_clear();
				batch[i]->packetdelete();
				delete batch[i];
			}
			delete [] batch;
			delete [] packet_batch_time_ms;
		}
		inline void push(packet_s_process *packet) {
			batch[count] = packet;
			packet_batch_time_ms[count] = getTimeMS_rdtsc();
			++count;
		}
		packet_s_process **batch;
		u_int64_t *packet_batch_time_ms;
		volatile unsigned count;
		volatile unsigned count_processed;
		unsigned max_count;
	};
	struct arg_next_thread {
		PreProcessPacket *preProcessPacket;
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
		volatile int mode;
		map<string, Call*> map_calls;
		void null(bool null_map_calls = false) {
			batch = NULL;
			start = 0;
			end = 0;
			skip = 0;
			thread_index = 0;
			data_ready = 0;
			processing = 0;
			mode = 0;
			if(null_map_calls) {
				map_calls.clear();
			}
		}
	};
	struct s_next_thread {
		volatile int thread_id;
		pthread_t thread_handle;
		pstat_data thread_pstat_data[2][2];
		s_next_thread_data next_data;
		sem_t sem_sync[2];
		volatile int terminate;
		void null() {
			thread_id = 0;
			thread_handle = 0;
			memset(thread_pstat_data, 0, sizeof(thread_pstat_data));
			next_data.null();
			memset(sem_sync, 0, sizeof(sem_sync));
			terminate = 0;
		}
		void sem_init() {
			extern int opt_process_rtp_packets_hash_next_thread_sem_sync;
			for(int i = 0; i < opt_process_rtp_packets_hash_next_thread_sem_sync; i++) {
				::sem_init(&sem_sync[i], 0, 0);
			}
		}
		void sem_term() {
			extern int opt_process_rtp_packets_hash_next_thread_sem_sync;
			for(int i = 0; i < opt_process_rtp_packets_hash_next_thread_sem_sync; i++) {
				sem_destroy(&sem_sync[i]);
			}
		}
	};
public:
	PreProcessPacket(eTypePreProcessThread typePreProcessThread, unsigned idPreProcessThread = 0);
	~PreProcessPacket();
	inline void push_packet(
				u_int16_t header_ip_offset,
				u_int16_t header_ip_encaps_offset,
				u_int16_t data_offset,
				u_int32_t datalen,
				u_int16_t source,
				u_int16_t dest,
				packet_flags pflags,
				sHeaderPacketPQout *hp,
				u_int16_t handle_index) {
		bool _lock = false;
		if(this->needLockPush) {
			this->lock_push();
			_lock = true;
		}
		pcap_queue_packet_data *packet_data;
		packet_data = push_packet_detach_x__get_pointer();
		packet_data->header_ip_offset = header_ip_offset;
		packet_data->header_ip_encaps_offset = header_ip_encaps_offset;
		packet_data->data_offset = data_offset;
		packet_data->datalen = datalen;
		packet_data->source = source;
		packet_data->dest = dest;
		packet_data->pflags = pflags;
		packet_data->hp = *hp;
		packet_data->handle_index = handle_index;
		extern bool use_push_batch_limit_ms;
		push_packet_detach_x__finish(use_push_batch_limit_ms ? hp->header->get_time_us() : 0);
		if(_lock) {
			this->unlock_push();
		}
	}
	inline void push_packet(
				#if USE_PACKET_NUMBER
				u_int64_t packet_number,
				#endif
				vmIP saddr, vmPort source, vmIP daddr, vmPort dest, 
				int datalen, int dataoffset,
				u_int16_t handle_index, pcap_pkthdr *header, const u_char *packet, e_packet_alloc_type packet_alloc_type,
				packet_flags pflags, struct iphdr2 *header_ip_encaps, struct iphdr2 *header_ip,
				pcap_block_store *block_store, int block_store_index, int dlt, int sensor_id, vmIP sensor_ip, sPacketInfoData pid,
				int blockstore_lock = 1) {
		extern int opt_t2_boost;
		extern int opt_skinny;
		extern bool opt_enable_diameter;
		extern char *sipportmatrix;
		extern char *skinnyportmatrix;
		extern char *diameter_tcp_portmatrix;
		extern char *diameter_udp_portmatrix;
		extern int opt_mgcp;
		extern char *mgcp_gateway_tcp_portmatrix;
		extern char *mgcp_gateway_udp_portmatrix;
		extern char *mgcp_callagent_tcp_portmatrix;
		extern char *mgcp_callagent_udp_portmatrix;
		extern bool opt_ipfix;
		pflags.set_skinny(opt_skinny && pflags.get_tcp() && (skinnyportmatrix[source] || skinnyportmatrix[dest]));
		pflags.set_mgcp(opt_mgcp && 
				(pflags.get_tcp() ?
				  (mgcp_gateway_tcp_portmatrix[source] || mgcp_gateway_tcp_portmatrix[dest] ||
				   mgcp_callagent_tcp_portmatrix[source] || mgcp_callagent_tcp_portmatrix[dest]) :
				  (mgcp_gateway_udp_portmatrix[source] || mgcp_gateway_udp_portmatrix[dest] ||
				   mgcp_callagent_udp_portmatrix[source] || mgcp_callagent_udp_portmatrix[dest])));
		pflags.set_dtls_handshake(!pflags.get_tcp() && IS_DTLS_HANDSHAKE(packet + dataoffset, datalen));
		pflags.set_diameter(opt_enable_diameter && 
				    (pflags.get_tcp() ?
				      diameter_tcp_portmatrix[source] || diameter_tcp_portmatrix[dest] :
				      diameter_udp_portmatrix[source] || diameter_udp_portmatrix[dest]));
		pflags.set_ipfix_qos(opt_ipfix &&
				     !saddr.isSet() && !daddr.isSet() && !source.isSet() && !dest.isSet() &&
				     datalen > 10 && !memcmp(packet + dataoffset, "IPFIX_QOS:", 10));
		#if not EXPERIMENTAL_SUPPRESS_AUDIOCODES
		extern bool opt_audiocodes;
		sAudiocodes *audiocodes = NULL;
		if(if_unlikely(opt_audiocodes)) {
			extern unsigned opt_udp_port_audiocodes;
			extern unsigned opt_tcp_port_audiocodes;
			if(pflags.get_tcp() ?
			    (opt_tcp_port_audiocodes && 
			     (source.getPort() == opt_tcp_port_audiocodes || dest.getPort() == opt_tcp_port_audiocodes)) : 
			    (opt_udp_port_audiocodes && 
			     (source.getPort() == opt_udp_port_audiocodes || dest.getPort() == opt_udp_port_audiocodes))) {
				audiocodes = new FILE_LINE(0) sAudiocodes;
				if(!audiocodes->parse((u_char*)(packet + dataoffset), datalen)) {
					delete audiocodes;
					audiocodes = NULL;
				}
			}
		}
		#endif
		bool need_sip_process = (!pflags.other_processing() &&
					 (pflags.is_ssl() ||
					  sipportmatrix[source] || sipportmatrix[dest] ||
					  pflags.is_skinny() ||
					  pflags.is_mgcp() ||
					  pflags.is_diameter() ||
					  pflags.is_ipfix_qos()))
					#if not EXPERIMENTAL_SUPPRESS_AUDIOCODES
					||
					(audiocodes && audiocodes->media_type == sAudiocodes::ac_mt_SIP)
					#endif
					;
		bool ok_push = !opt_t2_boost ||
			       need_sip_process ||
			       datalen > 2 ||
			       blockstore_lock != 1;
		if(!ok_push) {
			if(packet_alloc_type > _t_packet_alloc_na) {
				if(packet_alloc_type &_t_packet_alloc_header_plus) {
					delete (pcap_pkthdr_plus*)header;
				} else if(packet_alloc_type &_t_packet_alloc_header_std) {
					delete (pcap_pkthdr*)header;
				}
				delete [] packet;
			}
			return;
		}
		bool _lock = false;
		packet_s *packetS;
		if(typePreProcessThread == ppt_detach) {
			if(this->needLockPush) {
				this->lock_push();
				_lock = true;
			}
			if(this->outThreadState == 2) {
				packetS = push_packet_detach__get_pointer();
			} else {
				static packet_s _packetS;
				packetS = &_packetS;
			}
		} else {
			static __thread packet_s *_packetS = NULL;
			if(!_packetS) {
				_packetS = new FILE_LINE(0) packet_s;
			}
			packetS = _packetS;
		}
		packetS->packet_s::init();
		#if USE_PACKET_NUMBER
		packetS->packet_number = packet_number;
		#endif
		#if not EXPERIMENTAL_PACKETS_WITHOUT_IP
		packetS->_saddr = saddr;
		packetS->_daddr = daddr; 
		#endif
		packetS->_source = source;
		packetS->_dest = dest;
		packetS->_datalen = datalen; 
		packetS->_datalen_set = 0; 
		packetS->_dataoffset = dataoffset;
		packetS->handle_index = handle_index; 
		packetS->header_pt = header;
		packetS->packet = packet; 
		packetS->_packet_alloc_type = packet_alloc_type; 
		packetS->pflags = pflags;
		packetS->header_ip_encaps_offset = header_ip_encaps ? ((u_char*)header_ip_encaps - packet) : 0xFFFF; 
		packetS->header_ip_offset = header_ip ? ((u_char*)header_ip - packet) : 0; 
		#if not NOT_USE_SEPARATE_TIME_US
		packetS->time_us = ::getTimeUS(header->ts);
		#endif
		packetS->block_store = block_store; 
		packetS->block_store_index =  block_store_index; 
		packetS->dlt = dlt; 
		packetS->sensor_id_u = (u_int16_t)sensor_id;
		packetS->sensor_ip = sensor_ip;
		packetS->pid = pid;
		#if not EXPERIMENTAL_SUPPRESS_AUDIOCODES
		packetS->audiocodes = audiocodes;
		if(audiocodes) {
			packetS->pid.flags |= FLAG_AUDIOCODES;
		}
		#endif
		packetS->need_sip_process = need_sip_process;
		if(blockstore_lock == 1) {
			packetS->blockstore_lock(3 /*pb lock flag*/);
		} else if(blockstore_lock == 2) {
			packetS->blockstore_setlock();
		}
		if(typePreProcessThread == ppt_detach) {
			if(this->outThreadState == 2) {
				push_packet_detach__finish(packetS);
			} else {
				push_packet_detach(packetS);
			}
			if(_lock) {
				this->unlock_push();
			}
		} else {
			process_DETACH_type(packetS);
		}
	}
	inline pcap_queue_packet_data *push_packet_detach_x__get_pointer() {
		if(!qring_push_index) {
			#if SNIFFER_THREADS_EXT
			if(sverb.sniffer_threads_ext && thread_data) {
				++thread_data->buffer_push_cnt_all;
			}
			#endif
			unsigned int usleepCounter = 0;
			while(this->qring_detach_x[this->writeit]->used != 0) {
				if(usleepCounter == 0) {
					#if SNIFFER_THREADS_EXT
					if(sverb.sniffer_threads_ext && thread_data) {
						++thread_data->buffer_push_cnt_full;
					}
					#endif
				}
				#if SNIFFER_THREADS_EXT
				if(sverb.sniffer_threads_ext && thread_data) {
					++thread_data->buffer_push_cnt_full_loop;
				}
				#endif
				extern unsigned int opt_preprocess_packets_qring_push_usleep;
				if(opt_preprocess_packets_qring_push_usleep) {
					#if SNIFFER_THREADS_EXT
					unsigned us =
					#endif
					USLEEP_C(opt_preprocess_packets_qring_push_usleep, usleepCounter++);
					#if SNIFFER_THREADS_EXT
					if(sverb.sniffer_threads_ext && thread_data) {
						thread_data->buffer_push_sum_usleep_full_loop += us;
					}
					#endif
				} else {
					__ASM_PAUSE;
					++usleepCounter;
				}
			}
			qring_push_index = this->writeit + 1;
			qring_push_index_count = 0;
			qring_detach_x_active_push_item = qring_detach_x[qring_push_index - 1];
		}
		return((pcap_queue_packet_data*)qring_detach_x_active_push_item->batch[qring_push_index_count]);
	}
	inline void push_packet_detach_x__finish(u_int64_t time_us) {
		if(qring_push_index_count == 0) {
			extern bool use_push_batch_limit_ms;
			extern unsigned int opt_push_batch_limit_ms;
			qring_detach_x_active_push_item_limit_us = use_push_batch_limit_ms ? time_us + opt_push_batch_limit_ms * 1000 : 0;
		}
		++qring_push_index_count;
		if(qring_push_index_count == qring_detach_x_active_push_item->max_count ||
		   time_us > qring_detach_x_active_push_item_limit_us) {
			#if RQUEUE_SAFE
				__SYNC_SET_TO_LOCK(qring_detach_x_active_push_item->count, qring_push_index_count, this->_sync_count);
				__SYNC_SET(qring_detach_x_active_push_item->used);
				__SYNC_INCR(this->writeit, this->qring_length);
			#else
				qring_detach_x_active_push_item->count = qring_push_index_count;
				qring_detach_x_active_push_item->used = 1;
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
	inline packet_s *push_packet_detach__get_pointer() {
		if(!qring_push_index) {
			#if SNIFFER_THREADS_EXT
			if(sverb.sniffer_threads_ext && thread_data) {
				++thread_data->buffer_push_cnt_all;
			}
			#endif
			unsigned int usleepCounter = 0;
			while(this->qring_detach[this->writeit]->used != 0) {
				if(usleepCounter == 0) {
					#if SNIFFER_THREADS_EXT
					if(sverb.sniffer_threads_ext && thread_data) {
						++thread_data->buffer_push_cnt_full;
					}
					#endif
				}
				#if SNIFFER_THREADS_EXT
				if(sverb.sniffer_threads_ext && thread_data) {
					++thread_data->buffer_push_cnt_full_loop;
				}
				#endif
				extern unsigned int opt_preprocess_packets_qring_push_usleep;
				if(opt_preprocess_packets_qring_push_usleep) {
					#if SNIFFER_THREADS_EXT
					unsigned us =
					#endif
					USLEEP_C(opt_preprocess_packets_qring_push_usleep, usleepCounter++);
					#if SNIFFER_THREADS_EXT
					if(sverb.sniffer_threads_ext && thread_data) {
						thread_data->buffer_push_sum_usleep_full_loop += us;
					}
					#endif
				} else {
					__ASM_PAUSE;
					++usleepCounter;
				}
			}
			qring_push_index = this->writeit + 1;
			qring_push_index_count = 0;
			qring_detach_active_push_item = qring_detach[qring_push_index - 1];
		}
		return((packet_s_plus_pointer*)qring_detach_active_push_item->batch[qring_push_index_count]);
	}
	inline void push_packet_detach__finish(packet_s *packetS) {
		extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
		void **p = ((packet_s_plus_pointer*)packetS)->p_pointer;
		if(packetS->need_sip_process) {
			p[0] = preProcessPacket[PreProcessPacket::ppt_detach]->packetS_sip_pop_from_stack(this->typePreProcessThread);
			p[1] = opt_preprocess_packet_stack == 1 ? (void*)preProcessPacket[PreProcessPacket::ppt_detach]->stackSipBasic :
			       #if ENABLE_MOODY_CAMEL
			       opt_preprocess_packet_stack == 2 ? (void*)preProcessPacket[PreProcessPacket::ppt_detach]->stackSipMoodyCamel : 
			       #endif
			       NULL;
		} else if(!packetS->pflags.other_processing()) {
			p[0] = preProcessPacket[PreProcessPacket::ppt_detach]->packetS_rtp_pop_from_stack(this->typePreProcessThread);
			p[1] = opt_preprocess_packet_stack == 1 ? (void*)preProcessPacket[PreProcessPacket::ppt_detach]->stackRtpBasic :
			       #if ENABLE_MOODY_CAMEL
			       opt_preprocess_packet_stack == 2 ? (void*)preProcessPacket[PreProcessPacket::ppt_detach]->stackRtpMoodyCamel :
			       #endif
			       NULL;
		} else {
			p[0] = preProcessPacket[PreProcessPacket::ppt_detach]->packetS_other_pop_from_stack(this->typePreProcessThread);
			p[1] = opt_preprocess_packet_stack == 1 ? (void*)preProcessPacket[PreProcessPacket::ppt_detach]->stackOtherBasic :
			       #if ENABLE_MOODY_CAMEL
			       opt_preprocess_packet_stack == 2 ? (void*)preProcessPacket[PreProcessPacket::ppt_detach]->stackOtherMoodyCamel :
			       #endif
			       NULL;
		}
		extern bool use_push_batch_limit_ms;
		u_int64_t time_us = use_push_batch_limit_ms ? packetS->getTimeUS() : 0;
		if(qring_push_index_count == 0) {
			extern unsigned int opt_push_batch_limit_ms;
			qring_detach_active_push_item_limit_us = use_push_batch_limit_ms ? time_us + opt_push_batch_limit_ms * 1000 : 0;
		}
		++qring_push_index_count;
		if(qring_push_index_count == qring_detach_active_push_item->max_count ||
		   time_us > qring_detach_active_push_item_limit_us) {
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
	}
	inline void push_packet_detach(packet_s *packetS) {
		if(this->outThreadState == 2) {
			packet_s *packetS_pointer = push_packet_detach__get_pointer();
			*packetS_pointer = *packetS;
			push_packet_detach__finish(packetS_pointer);
		} else {
			unsigned int usleepCounter = 0;
			while(this->outThreadState) {
				USLEEP_C(10, usleepCounter++);
			}
			this->process_DETACH(packetS);
		}
	}
	inline void push_packet_detach__active__prepare() {
		if(!qring_push_index) {
			#if SNIFFER_THREADS_EXT
			if(sverb.sniffer_threads_ext && thread_data) {
				++thread_data->buffer_push_cnt_all;
			}
			#endif
			unsigned int usleepCounter = 0;
			while(this->qring_detach[this->writeit]->used != 0) {
				if(usleepCounter == 0) {
					#if SNIFFER_THREADS_EXT
					if(sverb.sniffer_threads_ext && thread_data) {
						++thread_data->buffer_push_cnt_full;
					}
					#endif
				}
				#if SNIFFER_THREADS_EXT
				if(sverb.sniffer_threads_ext && thread_data) {
					++thread_data->buffer_push_cnt_full_loop;
				}
				#endif
				extern unsigned int opt_preprocess_packets_qring_push_usleep;
				if(opt_preprocess_packets_qring_push_usleep) {
					#if SNIFFER_THREADS_EXT
					unsigned us =
					#endif
					USLEEP_C(opt_preprocess_packets_qring_push_usleep, usleepCounter++);
					#if SNIFFER_THREADS_EXT
					if(sverb.sniffer_threads_ext && thread_data) {
						thread_data->buffer_push_sum_usleep_full_loop += us;
					}
					#endif
				} else {
					__ASM_PAUSE;
					++usleepCounter;
				}
			}
			qring_push_index = this->writeit + 1;
			qring_push_index_count = 0;
			qring_detach_active_push_item = qring_detach[qring_push_index - 1];
		}
	}
	inline void push_packet_detach__active__finish(unsigned count) {
		#if RQUEUE_SAFE
			__SYNC_SET_TO_LOCK(qring_detach_active_push_item->count, count, this->_sync_count);
			__SYNC_SET(qring_detach_active_push_item->used);
			__SYNC_INCR(this->writeit, this->qring_length);
		#else
			qring_detach_active_push_item->count = count;
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
	inline bool push_packet(packet_s_process *packetS) {
		#if EXPERIMENTAL_CHECK_TID_IN_PUSH
		static __thread unsigned _tid = 0;
		if(!_tid) {
			_tid = get_unix_tid();
		}
		if(!push_thread) {
			push_thread = _tid;
		} else if(push_thread != _tid) {
			u_int64_t time = getTimeMS_rdtsc();
			if(time > last_race_log[0] + 1000) {
				syslog(LOG_ERR, "race in %s %s %i (%i != %i)", getNameTypeThread().c_str(), __FILE__, __LINE__, push_thread, _tid);
				last_race_log[0] = time;
			}
			push_thread = _tid;
		}
		#endif
		if(is_terminating()) {
			this->packetS_destroy(packetS);
			return(false);
		}
		extern bool use_push_batch_limit_ms;
		u_int64_t time_us = use_push_batch_limit_ms ? packetS->getTimeUS() : 0;
		bool _lock = false;
		if(this->needLockPush) {
			lock_push();
			_lock = true;
		}
		if(this->outThreadState == 2) {
			#if SNIFFER_THREADS_EXT
			if(sverb.sniffer_threads_ext && thread_data) {
				++thread_data->buffer_push_cnt_all;
			}
			#endif
			if(!qring_push_index) {
				unsigned int usleepCounter = 0;
				while(this->qring[this->writeit]->used != 0) {
					if(is_terminating()) {
						this->packetS_destroy(packetS);
						if(_lock) {
							unlock_push();
						}
						return(false);
					}
					if(usleepCounter == 0) {
						#if SNIFFER_THREADS_EXT
						if(sverb.sniffer_threads_ext && thread_data) {
							++thread_data->buffer_push_cnt_full;
						}
						#endif
					}
					#if SNIFFER_THREADS_EXT
					if(sverb.sniffer_threads_ext && thread_data) {
						++thread_data->buffer_push_cnt_full_loop;
					}
					#endif
					extern unsigned int opt_preprocess_packets_qring_push_usleep;
					if(opt_preprocess_packets_qring_push_usleep) {
						#if SNIFFER_THREADS_EXT
						unsigned us =
						#endif
						USLEEP_C(opt_preprocess_packets_qring_push_usleep, usleepCounter++);
						#if SNIFFER_THREADS_EXT
						if(sverb.sniffer_threads_ext && thread_data) {
							thread_data->buffer_push_sum_usleep_full_loop += us;
						}
						#endif
					} else {
						__ASM_PAUSE;
						++usleepCounter;
					}
				}
				qring_push_index = this->writeit + 1;
				qring_push_index_count = 0;
				qring_active_push_item = qring[qring_push_index - 1];
				extern unsigned int opt_push_batch_limit_ms;
				qring_active_push_item_limit_us = use_push_batch_limit_ms ? time_us + opt_push_batch_limit_ms * 1000 : 0;
			}
			qring_active_push_item->batch[qring_push_index_count] = packetS;
			++qring_push_index_count;
			if(qring_push_index_count == qring_active_push_item->max_count ||
			   time_us > qring_active_push_item_limit_us) {
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
			extern ParsePacket _parse_packet_global_process_packet;
			unsigned int usleepCounter = 0;
			while(this->outThreadState) {
				USLEEP_C(10, usleepCounter++);
			}
			if(qring_push_index && qring_push_index_count) {
				for(unsigned int i = 0; i < qring_push_index_count; i++) {
					packet_s_process *_packetS = qring[qring_push_index - 1]->batch[i];
					switch(this->typePreProcessThread) {
					case ppt_detach_x:
						break;
					case ppt_detach:
						break;
					case ppt_sip:
						this->process_SIP(_packetS);
						break;
					case ppt_extend:
						this->process_SIP_EXTEND(_packetS);
						break;
					#if not CALLX_MOD_OLDVER
					case ppt_pp_find_call:
						this->process_FIND_CALL(_packetS);
						break;
					case ppt_pp_process_call:
						this->process_PROCESS_CALL(_packetS);
						break;
					#else
					case ppt_pp_call:
						this->process_CALL(_packetS);
						break;
					case ppt_pp_callx:
						this->process_CALLX(_packetS);
						break;
					case ppt_pp_callfindx:
						this->process_CallFindX(_packetS);
						break;
					#endif
					case ppt_pp_register:
						this->process_REGISTER(_packetS);
						break;
					case ppt_pp_sip_other:
						this->process_SIP_OTHER(_packetS);
						break;
					case ppt_pp_diameter:
						this->process_DIAMETER(_packetS);
						break;
					case ppt_pp_rtp:
						this->process_RTP(_packetS);
						break;
					case ppt_pp_other:
						this->process_OTHER(_packetS);
						break;
					case ppt_end_base:
						break;
					}
				}
				qring_push_index = 0;
				qring_push_index_count = 0;
			}
			switch(this->typePreProcessThread) {
			case ppt_detach_x:
				break;
			case ppt_detach:
				break;
			case ppt_sip:
				_parse_packet_global_process_packet.refreshIfNeed();
				this->process_SIP(packetS);
				break;
			case ppt_extend:
				this->process_SIP_EXTEND(packetS);
				break;
			#if not CALLX_MOD_OLDVER
			case ppt_pp_find_call:
				this->process_FIND_CALL(packetS);
				break;
			case ppt_pp_process_call:
				this->process_PROCESS_CALL(packetS, 0, true);
				break;
			#else
			case ppt_pp_call:
				this->process_CALL(packetS);
				break;
			case ppt_pp_callx:
				this->process_CALLX(packetS);
				break;
			case ppt_pp_callfindx:
				this->process_CallFindX(packetS);
				break;
			#endif
			case ppt_pp_register:
				this->process_REGISTER(packetS);
				break;
			case ppt_pp_sip_other:
				this->process_SIP_OTHER(packetS);
				break;
			case ppt_pp_diameter:
				this->process_DIAMETER(packetS);
				break;
			case ppt_pp_rtp:
				this->process_RTP(packetS);
				break;
			case ppt_pp_other:
				this->process_OTHER(packetS);
				break;
			case ppt_end_base:
				break;
			}
		}
		if(_lock) {
			unlock_push();
		}
		return(true);
	}
	inline void push_packet_to_rtp_delay_queue(packet_s_process *packetS) {
		extern bool use_push_batch_limit_ms;
		u_int64_t time_us = use_push_batch_limit_ms ? packetS->getTimeUS() : 0;
		if(!rtp_delay_queue_push_item) {
			if(rtp_delay_queue__max_length_ms > 0) {
				bool rtp_delay_queue_full = false;
				unsigned int usleepCounter = 0;
				do {
					rtp_delay_queue_full = false;
					__SYNC_LOCK(rtp_delay_queue_lock);
					if(rtp_delay_queue.size() > 1) {
						batch_packet_s_time *front = rtp_delay_queue.front();
						rtp_delay_queue_full = rtp_delay_queue_last_time > front->batch[front->count - 1]->getTimeUS() + rtp_delay_queue__max_length_ms * 1000 * 1.5;
					}
					__SYNC_UNLOCK(rtp_delay_queue_lock);
					if(rtp_delay_queue_full) {
						extern unsigned int opt_preprocess_packets_qring_push_usleep;
						if(opt_preprocess_packets_qring_push_usleep) {
							USLEEP_C(opt_preprocess_packets_qring_push_usleep, usleepCounter++);
						} else {
							__ASM_PAUSE;
							++usleepCounter;
						}
					}
				} while(rtp_delay_queue_full);
			}
			extern unsigned int opt_preprocess_packets_qring_item_length;
			rtp_delay_queue_push_item = new FILE_LINE(0) batch_packet_s_time(opt_preprocess_packets_qring_item_length);
			extern unsigned int opt_push_batch_limit_ms;
			rtp_delay_queue_push_item_limit_us = use_push_batch_limit_ms ? time_us + opt_push_batch_limit_ms * 1000 : 0;
		}
		rtp_delay_queue_push_item->push(packetS);
		if(rtp_delay_queue_push_item->count == rtp_delay_queue_push_item->max_count ||
		   time_us > rtp_delay_queue_push_item_limit_us) {
			__SYNC_LOCK(rtp_delay_queue_lock);
			rtp_delay_queue.push(rtp_delay_queue_push_item);
			rtp_delay_queue_last_time = rtp_delay_queue_push_item->batch[rtp_delay_queue_push_item->count - 1]->getTimeUS();
			__SYNC_UNLOCK(rtp_delay_queue_lock);
			rtp_delay_queue_push_item = NULL;
		}
	}
	inline void push_batch() {
		#if EXPERIMENTAL_CHECK_TID_IN_PUSH
		static __thread unsigned _tid = 0;
		if(!_tid) {
			_tid = get_unix_tid();
		}
		if(push_thread && push_thread != _tid) {
			u_int64_t time = getTimeMS_rdtsc();
			if(time > last_race_log[1] + 1000) {
				syslog(LOG_ERR, "race in %s %s %i (%i != %i)", getNameTypeThread().c_str(), __FILE__, __LINE__, push_thread, _tid);
				last_race_log[1] = time;
			}
			push_thread = _tid;
		}
		#endif
		bool _lock = false;
		if(this->needLockPush) {
			this->lock_push();
			_lock = true;
		}
		if(this->outThreadState == 2) {
			if(qring_push_index && qring_push_index_count) {
				#if RQUEUE_SAFE
					if(typePreProcessThread == ppt_detach_x) {
						__SYNC_SET_TO_LOCK(qring_detach_x_active_push_item->count, qring_push_index_count, this->_sync_count);
						__SYNC_SET(qring_detach_x_active_push_item->used);
					} else if(typePreProcessThread == ppt_detach) {
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
			unsigned int usleepCounter = 0;
			while(this->outThreadState) {
				USLEEP_C(10, usleepCounter++);
			}
			push_batch_nothread();
		}
		if(_lock) {
			this->unlock_push();
		}
	}
	inline void push_batch_to_rtp_delay_queue() {
		if(rtp_delay_queue_push_item) {
			__SYNC_LOCK(rtp_delay_queue_lock);
			rtp_delay_queue.push(rtp_delay_queue_push_item);
			rtp_delay_queue_last_time = rtp_delay_queue_push_item->batch[rtp_delay_queue_push_item->count - 1]->getTimeUS();
			__SYNC_UNLOCK(rtp_delay_queue_lock);
			rtp_delay_queue_push_item = NULL;
		}
	}
	void push_batch_nothread();
	void preparePstatData(int nextThreadId, int pstatDataIndex);
	double getCpuUsagePerc(int nextThreadId, int pstatDataIndex, bool preparePstatData = true);
	void terminate();
	void addNextThread();
	void removeNextThread();
	static void autoStartNextLevelPreProcessPacket();
	#if CALLX_MOD_OLDVER
	static void autoStartCallX_PreProcessPacket();
	#endif
	static void autoStopLastLevelPreProcessPacket(bool force = false);
	inline packet_s_process *packetS_sip_create() {
		packet_s_process *packetS = new FILE_LINE(28004) packet_s_process;
		return(packetS);
	}
	inline packet_s_process_0 *packetS_rtp_create() {
		packet_s_process_0 *packetS = packet_s_process_0::create();
		return(packetS);
	}
	inline packet_s_stack *packetS_other_create() {
		packet_s_stack *packetS = new FILE_LINE(0) packet_s_stack;
		return(packetS);
	}
	inline packet_s_process *packetS_sip_pop_from_stack(u_int16_t pop_queue_index) {
		packet_s_process *packetS;
		if(opt_preprocess_packet_stack == 1) {
			if(opt_t2_boost_direct_rtp ?
			    this->stackSipBasic->pop((void**)&packetS, pop_queue_index) :
			    this->stackSipBasic->popq((void**)&packetS)) {
				++allocStackCounter[0];
				return(packetS);
			}
		#if ENABLE_MOODY_CAMEL
		} else if(opt_preprocess_packet_stack == 2) {
			if(this->stackSipMoodyCamel->pop((void**)&packetS)) {
				++allocStackCounter[0];
				return(packetS);
			}
		#endif
		}
		packetS = new FILE_LINE(28006) packet_s_process;
		++allocCounter[0];
		return(packetS);
	}
	inline packet_s_process_0 *packetS_rtp_pop_from_stack(u_int16_t pop_queue_index) {
		packet_s_process_0 *packetS;
		if(opt_preprocess_packet_stack == 1) {
			if(opt_t2_boost_direct_rtp ?
			    this->stackRtpBasic->pop((void**)&packetS, pop_queue_index) :
			    this->stackRtpBasic->popq((void**)&packetS)) {
				++allocStackCounter[0];
				return(packetS);
			}
		#if ENABLE_MOODY_CAMEL
		} else if(opt_preprocess_packet_stack == 2) {
			if(this->stackRtpMoodyCamel->pop((void**)&packetS)) {
				++allocStackCounter[0];
				return(packetS);
			}
		#endif
		}
		packetS = packet_s_process_0::create();
		++allocCounter[0];
		return(packetS);
	}
	inline packet_s_stack *packetS_other_pop_from_stack(u_int16_t pop_queue_index) {
		packet_s_stack *packetS;
		if(opt_preprocess_packet_stack == 1) {
			if(opt_t2_boost_direct_rtp ?
			    this->stackOtherBasic->pop((void**)&packetS, pop_queue_index) :
			    this->stackOtherBasic->popq((void**)&packetS)) {
				++allocStackCounter[0];
				return(packetS);
			}
		#if ENABLE_MOODY_CAMEL
		} else if(opt_preprocess_packet_stack == 2) {
			if(this->stackOtherMoodyCamel->pop((void**)&packetS)) {
				++allocStackCounter[0];
				return(packetS);
			}
		#endif
		}
		packetS = new FILE_LINE(0) packet_s_stack;
		++allocCounter[0];
		return(packetS);
	}
	inline bool check_enable_destroy(packet_s_process_0 *packetS) {
		if(packetS->is_use_reuse_counter()) {
			bool enable = false;
			packetS->reuse_counter_lock();
			packetS->reuse_counter_dec();
			enable = packetS->reuse_counter_c == 0;
			packetS->reuse_counter_unlock();
			return(enable);
		}
		return(true);
	}
	inline bool check_enable_push_to_stack(packet_s_process_0 *packetS) {
		return(check_enable_destroy(packetS));
	}
	inline void packetS_destroy(packet_s *packetS) {
		extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
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
		(*packetS)->term();
		packet_s_process_0::free(*packetS);
		*packetS = NULL;
	}
	inline void packetS_destroy(packet_s_stack **packetS) {
		(*packetS)->blockstore_unlock();
		(*packetS)->packetdelete();
		(*packetS)->term();
		delete *packetS;
		*packetS = NULL;
	}
	void _packetS_destroy(packet_s_process_0 *packetS);
	inline void packetS_push_to_stack(packet_s_process **packetS, u_int16_t queue_index) {
		if(!opt_preprocess_packet_stack) {
			this->packetS_destroy(packetS);
			return;
		}
		if(!check_enable_push_to_stack(*packetS)) {
			return;
		}
		if((*packetS)->_blockstore_lock) {
			(*packetS)->block_store->unlock_packet((*packetS)->block_store_index);
		}
		if((*packetS)->_packet_alloc_type > _t_packet_alloc_na) {
			if((*packetS)->_packet_alloc_type &_t_packet_alloc_header_plus) {
				delete (pcap_pkthdr_plus*)(*packetS)->header_pt;
			} else if((*packetS)->_packet_alloc_type &_t_packet_alloc_header_std) {
				delete (pcap_pkthdr*)(*packetS)->header_pt;
			}
			#if DEBUG_ALLOC_PACKETS
			debug_alloc_packet_free((*packetS)->packet);
			#endif
			delete [] (*packetS)->packet;
		}
		(*packetS)->term();
		extern int opt_block_alloc_stack;
		if(opt_block_alloc_stack ||
		   !(*packetS)->p_stack ||
		   !_push_to_stack((packet_s_stack*)*packetS, queue_index)) {
			delete *packetS;
		}
		*packetS = NULL;
	}
	inline void packetS_push_to_stack(packet_s_process_0 **packetS, u_int16_t queue_index) {
		if(!opt_preprocess_packet_stack) {
			this->packetS_destroy(packetS);
			return;
		}
		if(!check_enable_push_to_stack(*packetS)) {
			return;
		}
		if((*packetS)->_blockstore_lock) {
			(*packetS)->block_store->unlock_packet((*packetS)->block_store_index);
		}
		if((*packetS)->_packet_alloc_type > _t_packet_alloc_na) {
			if((*packetS)->_packet_alloc_type &_t_packet_alloc_header_plus) {
				delete (pcap_pkthdr_plus*)(*packetS)->header_pt;
			} else if((*packetS)->_packet_alloc_type &_t_packet_alloc_header_std) {
				delete (pcap_pkthdr*)(*packetS)->header_pt;
			}
			#if DEBUG_ALLOC_PACKETS
			debug_alloc_packet_free((*packetS)->packet);
			#endif
			delete [] (*packetS)->packet;
		}
		(*packetS)->term();
		extern int opt_block_alloc_stack;
		if(opt_block_alloc_stack ||
		   !(*packetS)->p_stack ||
		   !_push_to_stack((packet_s_stack*)*packetS, queue_index)) {
			packet_s_process_0::free(*packetS);
		}
		*packetS = NULL;
	}
	inline void packetS_push_to_stack(packet_s_stack **packetS, u_int16_t queue_index) {
		if(!opt_preprocess_packet_stack) {
			this->packetS_destroy(packetS);
			return;
		}
		if((*packetS)->_blockstore_lock) {
			(*packetS)->block_store->unlock_packet((*packetS)->block_store_index);
		}
		if((*packetS)->_packet_alloc_type > _t_packet_alloc_na) {
			if((*packetS)->_packet_alloc_type &_t_packet_alloc_header_plus) {
				delete (pcap_pkthdr_plus*)(*packetS)->header_pt;
			} else if((*packetS)->_packet_alloc_type &_t_packet_alloc_header_std) {
				delete (pcap_pkthdr*)(*packetS)->header_pt;
			}
			#if DEBUG_ALLOC_PACKETS
			debug_alloc_packet_free((*packetS)->packet);
			#endif
			delete [] (*packetS)->packet;
		}
		(*packetS)->term();
		extern int opt_block_alloc_stack;
		if(opt_block_alloc_stack ||
		   !(*packetS)->p_stack ||
		   !_push_to_stack((packet_s_stack*)*packetS, queue_index)) {
			delete *packetS;
		}
		*packetS = NULL;
	}
	inline bool _push_to_stack(packet_s_stack *packetS, u_int16_t queue_index) {
		if(opt_preprocess_packet_stack == 1) {
			return(((cHeapItemsPointerStack*)packetS->p_stack)->push((void*)packetS, queue_index));
		#if ENABLE_MOODY_CAMEL
		} else if(opt_preprocess_packet_stack == 2) {
			return(((BoundedMoodycamel<void*>*)packetS->p_stack)->push((void*)packetS));
		#endif
		}
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
		case ppt_detach_x:
			return("detachx");
		case ppt_detach:
			return("detach");
		case ppt_sip:
			return("sip");
		case ppt_extend:
			return("extend");
		#if not CALLX_MOD_OLDVER
		case ppt_pp_find_call:
			return("find_call");
		case ppt_pp_process_call:
			return("process_call");
		#else
		case ppt_pp_call:
			return("call");
		case ppt_pp_callx:
			return("callx");
		case ppt_pp_callfindx:
			return("callfindx");
		#endif
		case ppt_pp_register:
			return("register");
		case ppt_pp_sip_other:
			return("sip other");
		case ppt_pp_diameter:
			return("diameter");
		case ppt_pp_rtp:
			return("rtp");
		case ppt_pp_other:
			return("other");
		case ppt_end_base:
			break;
		}
		return("");
	}
	string getShortcatTypeThread() {
		switch(typePreProcessThread) {
		case ppt_detach_x:
			return("dx");
		case ppt_detach:
			return("d");
		case ppt_sip:
			return("s");
		case ppt_extend:
			return("e");
		#if not CALLX_MOD_OLDVER
		case ppt_pp_find_call:
			return("cf");
		case ppt_pp_process_call:
			return("cp");
		#else
		case ppt_pp_call:
			return("c");
		case ppt_pp_callx:
			return("cx");
		case ppt_pp_callfindx:
			return("cfx");
		#endif
		case ppt_pp_register:
			return("g");
		case ppt_pp_sip_other:
			return("so");
		case ppt_pp_diameter:
			return("dm");
		case ppt_pp_rtp:
			return("r");
		case ppt_pp_other:
			return("o");
		case ppt_end_base:
			break;
		}
		return("");
	}
	static packet_s_process *clonePacketS(u_char *newData, unsigned newDataLength, packet_s_process *packetS);
	static packet_s_process *clonePacketS(packet_s_process *packetS);
	bool existsNextThread(int next_thread_index) {
		return(next_thread_index < MAX_PRE_PROCESS_PACKET_NEXT_THREADS &&
		       this->next_threads[next_thread_index].thread_id);
	}
private:
	inline void process_DETACH_X_1(pcap_queue_packet_data *packet_data, packet_s_plus_pointer *packetS_detach) {
		extern int opt_t2_boost;
		extern int opt_skinny;
		extern bool opt_enable_diameter;
		extern char *sipportmatrix;
		extern char *skinnyportmatrix;
		extern char *diameter_tcp_portmatrix;
		extern char *diameter_udp_portmatrix;
		extern int opt_mgcp;
		extern char *mgcp_gateway_tcp_portmatrix;
		extern char *mgcp_gateway_udp_portmatrix;
		extern char *mgcp_callagent_tcp_portmatrix;
		extern char *mgcp_callagent_udp_portmatrix;
		extern bool opt_ipfix;
		pcap_pkthdr *header = packet_data->hp.header->_getStdHeader();
		u_char *packet = packet_data->hp.packet;
		#if not EXPERIMENTAL_PACKETS_WITHOUT_IP
		vmIP saddr = ((iphdr2*)(packet + packet_data->header_ip_offset))->get_saddr();
		vmIP daddr = ((iphdr2*)(packet + packet_data->header_ip_offset))->get_daddr();
		#endif
		int blockstore_lock = packet_data->hp.block_store_locked ? 2 : 1;
		packet_data->pflags.set_skinny(opt_skinny && packet_data->pflags.get_tcp() && (skinnyportmatrix[packet_data->source] || skinnyportmatrix[packet_data->dest]));
		packet_data->pflags.set_mgcp(opt_mgcp && 
					     (packet_data->pflags.get_tcp() ?
					       (mgcp_gateway_tcp_portmatrix[packet_data->source] || mgcp_gateway_tcp_portmatrix[packet_data->dest] ||
						mgcp_callagent_tcp_portmatrix[packet_data->source] || mgcp_callagent_tcp_portmatrix[packet_data->dest]) :
					       (mgcp_gateway_udp_portmatrix[packet_data->source] || mgcp_gateway_udp_portmatrix[packet_data->dest] ||
						mgcp_callagent_udp_portmatrix[packet_data->source] || mgcp_callagent_udp_portmatrix[packet_data->dest])));
		packet_data->pflags.set_dtls_handshake(!packet_data->pflags.get_tcp() && IS_DTLS_HANDSHAKE(packet + packet_data->data_offset, packet_data->datalen));
		packet_data->pflags.set_diameter(opt_enable_diameter && 
						 (packet_data->pflags.get_tcp() ?
						   diameter_tcp_portmatrix[packet_data->source] || diameter_tcp_portmatrix[packet_data->dest] :
						   diameter_udp_portmatrix[packet_data->source] || diameter_udp_portmatrix[packet_data->dest]));
		packet_data->pflags.set_ipfix_qos(opt_ipfix &&
						  !saddr.isSet() && !daddr.isSet() && !packet_data->source && !packet_data->dest &&
						  packet_data->datalen > 10 && !memcmp(packet + packet_data->data_offset, "IPFIX_QOS:", 10));
		#if not EXPERIMENTAL_SUPPRESS_AUDIOCODES
		extern bool opt_audiocodes;
		sAudiocodes *audiocodes = NULL;
		if(if_unlikely(opt_audiocodes)) {
			extern unsigned opt_udp_port_audiocodes;
			extern unsigned opt_tcp_port_audiocodes;
			if(packet_data->pflags.get_tcp() ?
			    (opt_tcp_port_audiocodes && 
			     (packet_data->source == opt_tcp_port_audiocodes || packet_data->dest == opt_tcp_port_audiocodes)) : 
			    (opt_udp_port_audiocodes && 
			     (packet_data->source == opt_udp_port_audiocodes || packet_data->dest == opt_udp_port_audiocodes))) {
				audiocodes = new FILE_LINE(0) sAudiocodes;
				if(!audiocodes->parse(packet + packet_data->data_offset, packet_data->datalen)) {
					delete audiocodes;
					audiocodes = NULL;
				}
			}
		}
		#endif
		bool need_sip_process = (!packet_data->pflags.other_processing() &&
					 (packet_data->pflags.is_ssl() ||
					  sipportmatrix[packet_data->source] || sipportmatrix[packet_data->dest] ||
					  packet_data->pflags.is_skinny() ||
					  packet_data->pflags.is_mgcp() ||
					  packet_data->pflags.is_ipfix_qos()))
					#if not EXPERIMENTAL_SUPPRESS_AUDIOCODES
					||
					(audiocodes && audiocodes->media_type == sAudiocodes::ac_mt_SIP)
					#endif
					;
		bool is_rtp = opt_t2_boost_direct_rtp ?
			       (!packet_data->pflags.call_signalling() &&
				packet_data->datalen > 2 &&
				(IS_RTP(packet + packet_data->data_offset, packet_data->datalen) || 
				 IS_DTLS(packet + packet_data->data_offset, packet_data->datalen))) :
			       false;
		if(need_sip_process && is_rtp && opt_t2_boost_direct_rtp) {
			extern bool check_sip_method(u_char *data, unsigned long len);
			if(check_sip_method(packet + packet_data->data_offset, packet_data->datalen)) {
				is_rtp = false;
			} else {
				need_sip_process = false;
			}
		}
		bool ok_push = !opt_t2_boost ||
			       need_sip_process ||
			       (opt_t2_boost_direct_rtp ? is_rtp : packet_data->datalen > 2) ||
			       blockstore_lock != 1;
		if(!ok_push) {
			if(!packet_data->hp.block_store) {
				delete (pcap_pkthdr_plus*)header;
				delete [] packet;
			}
			packetS_detach->p_pointer[0] = NULL;
			packetS_detach->p_pointer[1] = NULL;
			packetS_detach->skip = true;
			return;
		}
		packetS_detach->skip = false;
		packetS_detach->packet_s::init();
		#if USE_PACKET_NUMBER
		packetS_detach->packet_number = 0; //packet_number;
		#endif
		#if not EXPERIMENTAL_PACKETS_WITHOUT_IP
		packetS_detach->_saddr = saddr;
		packetS_detach->_daddr = daddr; 
		#endif
		packetS_detach->_source = packet_data->source;
		packetS_detach->_dest = packet_data->dest;
		packetS_detach->_datalen = packet_data->datalen; 
		packetS_detach->_datalen_set = 0; 
		packetS_detach->_dataoffset = packet_data->data_offset;
		packetS_detach->handle_index = packet_data->handle_index; 
		packetS_detach->header_pt = header;
		packetS_detach->packet = packet; 
		packetS_detach->_packet_alloc_type = packet_data->hp.block_store ? _t_packet_alloc_na : _t_packet_alloc_header_plus; 
		packetS_detach->pflags = packet_data->pflags;
		packetS_detach->header_ip_encaps_offset = packet_data->header_ip_encaps_offset; 
		packetS_detach->header_ip_offset = packet_data->header_ip_offset; 
		#if not NOT_USE_SEPARATE_TIME_US
		packetS_detach->time_us = ::getTimeUS(header->ts);
		#endif
		packetS_detach->block_store = packet_data->hp.block_store; 
		packetS_detach->block_store_index =  packet_data->hp.block_store_index; 
		packetS_detach->dlt = packet_data->hp.dlt; 
		packetS_detach->sensor_id_u = (u_int16_t)packet_data->hp.sensor_id;
		packetS_detach->sensor_ip = packet_data->hp.sensor_ip;
		packetS_detach->pid = packet_data->hp.header->pid;
		#if not EXPERIMENTAL_SUPPRESS_AUDIOCODES
		packetS_detach->audiocodes = audiocodes;
		if(audiocodes) {
			packetS_detach->pid.flags |= FLAG_AUDIOCODES;
		}
		#endif
		packetS_detach->need_sip_process = need_sip_process;
		packetS_detach->is_rtp = is_rtp;
		if(blockstore_lock == 1) {
			packetS_detach->blockstore_lock(3 /*pb lock flag*/);
		} else if(blockstore_lock == 2) {
			packetS_detach->blockstore_setlock();
		}
	}
	inline void process_DETACH_X_2(packet_s_plus_pointer *packetS_detach) {
		if(packetS_detach->skip) {
			packetS_detach->p_pointer[0] = NULL;
			packetS_detach->p_pointer[1] = NULL;
			return;
		}
		extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
		if(packetS_detach->need_sip_process) {
			packetS_detach->p_pointer[0] = preProcessPacket[PreProcessPacket::ppt_detach]->packetS_sip_pop_from_stack(this->typePreProcessThread);
			packetS_detach->p_pointer[1] = opt_preprocess_packet_stack == 1 ? (void*)preProcessPacket[PreProcessPacket::ppt_detach]->stackSipBasic :
						       #if ENABLE_MOODY_CAMEL
						       opt_preprocess_packet_stack == 2 ? (void*)preProcessPacket[PreProcessPacket::ppt_detach]->stackSipMoodyCamel :
						       #endif
						       NULL;
		} else if(!packetS_detach->pflags.other_processing()) {
			packetS_detach->p_pointer[0] = preProcessPacket[PreProcessPacket::ppt_detach]->packetS_rtp_pop_from_stack(this->typePreProcessThread);
			packetS_detach->p_pointer[1] = opt_preprocess_packet_stack == 1 ? (void*)preProcessPacket[PreProcessPacket::ppt_detach]->stackRtpBasic :
						       #if ENABLE_MOODY_CAMEL
						       opt_preprocess_packet_stack == 2 ? (void*)preProcessPacket[PreProcessPacket::ppt_detach]->stackRtpMoodyCamel :
						       #endif
						       NULL;
		} else {
			packetS_detach->p_pointer[0] = preProcessPacket[PreProcessPacket::ppt_detach]->packetS_other_pop_from_stack(this->typePreProcessThread);
			packetS_detach->p_pointer[1] = opt_preprocess_packet_stack == 1 ? (void*)preProcessPacket[PreProcessPacket::ppt_detach]->stackOtherBasic :
						       #if ENABLE_MOODY_CAMEL
						       opt_preprocess_packet_stack == 2 ? (void*)preProcessPacket[PreProcessPacket::ppt_detach]->stackOtherMoodyCamel :
						       #endif
						       NULL;
		}
	}
	inline void process_DETACH(packet_s *packetS_detach) {
		extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
		packet_s_process *packetS = packetS_detach->need_sip_process ?
					     preProcessPacket[PreProcessPacket::ppt_detach]->packetS_sip_pop_from_stack(this->typePreProcessThread) : 
					    !packetS_detach->pflags.other_processing() ?
					     (packet_s_process*)preProcessPacket[PreProcessPacket::ppt_detach]->packetS_rtp_pop_from_stack(this->typePreProcessThread) :
					     (packet_s_process*)preProcessPacket[PreProcessPacket::ppt_detach]->packetS_other_pop_from_stack(this->typePreProcessThread);
		u_int8_t __type = packetS->__type;
		*(packet_s*)packetS = *(packet_s*)packetS_detach;
		packetS->__type = __type;
		preProcessPacket[ppt_sip]->push_packet(packetS);
	}
	inline void process_DETACH_type(packet_s *packetS_detach) {
		extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
		packet_s_process *packetS = packetS_detach->need_sip_process ?
					     preProcessPacket[PreProcessPacket::ppt_detach]->packetS_sip_pop_from_stack(this->typePreProcessThread) : 
					    !packetS_detach->pflags.other_processing() ?
					     (packet_s_process*)preProcessPacket[PreProcessPacket::ppt_detach]->packetS_rtp_pop_from_stack(this->typePreProcessThread) :
					     (packet_s_process*)preProcessPacket[PreProcessPacket::ppt_detach]->packetS_other_pop_from_stack(this->typePreProcessThread);
		u_int8_t __type = packetS->__type;
		*(packet_s*)packetS = *(packet_s*)packetS_detach;
		packetS->__type = __type;
		preProcessPacket[typePreProcessThread]->push_packet(packetS);
	}
	inline void process_DETACH_plus(packet_s_plus_pointer *packetS_detach, bool push = true) {
		extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
		packet_s_process *packetS = (packet_s_process*)packetS_detach->p_pointer[0];
		if(!packetS) {
			return;
		}
		#if EXPERIMENTAL_T2_STOP_IN_PROCESS_DETACH
			_packetS_destroy(packetS);
			packetS_detach->blockstore_unlock();
			return;
		#endif
		u_int8_t __type = packetS->__type;
		*(packet_s*)packetS = *(packet_s*)packetS_detach;
		packetS->__type = __type;
		packetS->p_stack = (cHeapItemsPointerStack*)packetS_detach->p_pointer[1];
		#if EXPERIMENTAL_PRECREATION_RTP_HASH_INDEX
		if(__type >= _t_packet_s_process_0) {
			packetS->h[0] = 
				#if not EXPERIMENTAL_PACKETS_WITHOUT_IP
					tuplehash(packetS->saddr_pt_()->getHashNumber(), packetS->source_());
				#else
					tuplehash(packetS->saddr_().getHashNumber(), packetS->source_());
				#endif
				;
			packetS->h[1] =
				#if not EXPERIMENTAL_PACKETS_WITHOUT_IP
					tuplehash(packetS->daddr_pt_()->getHashNumber(), packetS->dest_());
				#else
					tuplehash(packetS->daddr_().getHashNumber(), packetS->dest_());
				#endif
				;
		}
		#endif
		if(push) {
			preProcessPacket[ppt_sip]->push_packet(packetS);
		}
	}
	void process_SIP(packet_s_process *packetS, bool parallel_threads = false);
	void process_SIP_EXTEND(packet_s_process *packetS);
	#if not CALLX_MOD_OLDVER
	void process_FIND_CALL(packet_s_process *packetS);
	void _process_FIND_CALL_push(packet_s_process *packetS);
	void process_PROCESS_CALL(packet_s_process *packetS, int threadIndex = 0, bool callCleanupCalls = false);
	#else
	void process_CALL(packet_s_process *packetS);
	void process_CALLX(packet_s_process *packetS);
	void process_CallFindX(packet_s_process *packetS);
	#endif
	void process_REGISTER(packet_s_process *packetS);
	void process_SIP_OTHER(packet_s_process *packetS);
	void process_DIAMETER(packet_s_process *packetS);
	void process_RTP(packet_s_process_0 *packetS);
	void process_OTHER(packet_s_stack *packetS);
	void process_parseSipDataExt(packet_s_process **packetS_ref, packet_s_process *packetS_orig);
	inline void process_parseSipData(packet_s_process **packetS_ref, packet_s_process *packetS_orig
	#if DEBUG_PACKET_COUNT
	, bool debug_packet_count = false
	#endif
	);
	inline void process_sip(packet_s_process **packetS_ref);
	inline void process_skinny(packet_s_process **packetS_ref);
	inline void process_mgcp(packet_s_process **packetS_ref);
	inline void process_websocket(packet_s_process **packetS_ref, packet_s_process *packetS_orig);
	void process_diameterExt(packet_s_process **packetS_ref, packet_s_process *packetS_orig);
	inline void process_diameter(packet_s_process **packetS_ref);
	inline void process_ipfix_qos(packet_s_process **packetS_ref);
	inline bool process_getCallID(packet_s_process **packetS_ref);
	inline void process_getSipMethod(packet_s_process **packetS_ref);
	inline void process_getLastSipResponse(packet_s_process **packetS_ref);
	inline void process_findSipCall(packet_s_process **packetS_ref, map<string, Call*> *map_calls = NULL);
	inline void process_createSipCall(packet_s_process **packetS_ref, map<string, Call*> *map_calls = NULL);
	inline void process_findIpfixQosCall(packet_s_process **packetS_ref);
	void runOutThread();
	void endOutThread(bool force = false);
	void *outThreadFunction();
	void *nextThreadFunction(int next_thread_index_plus);
	void createNextThread();
	void termNextThread();
	inline void processNextAction(packet_s_process *packetS);
	bool isNextThreadsGt2Processing(int next_threads) {
		for(int i = 2; i < next_threads; i++) {
			if(this->next_threads[i].next_data.processing) {
				return(true);
			}
		}
		return(false);
	}
	void lock_push() {
		__SYNC_LOCK(this->_sync_push);
	}
	void unlock_push() {
		__SYNC_UNLOCK(this->_sync_push);
	}
	int get_opt_pre_process_packets_next_thread() {
		extern int opt_pre_process_packets_next_thread;
		#if not CALLX_MOD_OLDVER
		extern int opt_pre_process_packets_next_thread_find_call;
		extern int opt_pre_process_packets_next_thread_process_call;
		#endif
		return(typePreProcessThread == ppt_detach_x || 
		       typePreProcessThread == ppt_detach || 
		       typePreProcessThread == ppt_sip ? 
			opt_pre_process_packets_next_thread :
		       #if not CALLX_MOD_OLDVER
		       typePreProcessThread == ppt_pp_find_call ?
			opt_pre_process_packets_next_thread_find_call :
		       typePreProcessThread == ppt_pp_process_call ?
			opt_pre_process_packets_next_thread_process_call :
		       #endif
			-1);
	}
	int get_opt_pre_process_packets_next_thread_max() {
		extern int opt_pre_process_packets_next_thread_max;
		return(opt_pre_process_packets_next_thread_max);
	}
private:
	eTypePreProcessThread typePreProcessThread;
	bool needLockPush;
	unsigned idPreProcessThread;
	unsigned int qring_batch_item_length;
	unsigned int qring_length;
	batch_pcap_queue_packet_data **qring_detach_x;
	batch_pcap_queue_packet_data *qring_detach_x_active_push_item;
	u_int64_t qring_detach_x_active_push_item_limit_us;
	batch_packet_s **qring_detach;
	batch_packet_s *qring_detach_active_push_item;
	u_int64_t qring_detach_active_push_item_limit_us;
	batch_packet_s_process **qring;
	batch_packet_s_process *qring_active_push_item;
	u_int64_t qring_active_push_item_limit_us;
	unsigned qring_push_index;
	unsigned qring_push_index_count;
	volatile unsigned int readit;
	volatile unsigned int writeit;
	int outThreadId;
	pthread_t out_thread_handle;
	pstat_data threadPstatData[2][2];
	volatile int next_threads_count;
	volatile int next_threads_count_mod;
	s_next_thread next_threads[MAX_PRE_PROCESS_PACKET_NEXT_THREADS];
	volatile int next_threads_completed;
	volatile int8_t *items_flag;
	volatile int8_t *items_thread_index;
	volatile int items_processed;
	volatile int _sync_push;
	volatile int _sync_count;
	bool term_preProcess;
	cHeapItemsPointerStack *stackSipBasic;
	cHeapItemsPointerStack *stackRtpBasic;
	cHeapItemsPointerStack *stackOtherBasic;
	#if ENABLE_MOODY_CAMEL
	BoundedMoodycamel<void*> *stackSipMoodyCamel;
	BoundedMoodycamel<void*> *stackRtpMoodyCamel;
	BoundedMoodycamel<void*> *stackOtherMoodyCamel;
	#endif
	volatile int outThreadState;
	unsigned long allocCounter[2];
	unsigned long allocStackCounter[2];
	u_int64_t getCpuUsagePerc_counter;
	u_int64_t getCpuUsagePerc_counter_at_start_out_thread;
	static u_long autoStartNextLevelPreProcessPacket_last_time_s;
	#if EXPERIMENTAL_CHECK_TID_IN_PUSH
	unsigned push_thread;
	u_int64_t last_race_log[2];
	#endif
	int rtp_delay_queue__delay_ms;
	int rtp_delay_queue__max_length_ms;
	bool rtp_delay_queue__use;
	queue<batch_packet_s_time*> rtp_delay_queue;
	batch_packet_s_time* rtp_delay_queue_push_item;
	u_int64_t rtp_delay_queue_push_item_limit_us;
	batch_packet_s_time* rtp_delay_queue_pop_item;
	volatile u_int64_t rtp_delay_queue_last_time;
	volatile int rtp_delay_queue_lock;
	#if SNIFFER_THREADS_EXT
	cThreadMonitor::sThread *thread_data;
	#endif
friend inline void *_PreProcessPacket_outThreadFunction(void *arg);
friend inline void *_PreProcessPacket_nextThreadFunction(void *arg);
friend class TcpReassemblySip;
friend class SipTcpData;
friend class DiameterTcpData;
};

inline packet_s_process *PACKET_S_PROCESS_SIP_CREATE() {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
	return(preProcessPacket[PreProcessPacket::ppt_detach]->packetS_sip_create());
}

inline packet_s_process_0 *PACKET_S_PROCESS_RTP_CREATE() {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
	return(preProcessPacket[PreProcessPacket::ppt_detach]->packetS_rtp_create());
}

inline packet_s_stack *PACKET_S_PROCESS_OTHER_CREATE() {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
	return(preProcessPacket[PreProcessPacket::ppt_detach]->packetS_other_create());
}

inline packet_s_process *PACKET_S_PROCESS_SIP_POP_FROM_STACK() {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
	return(preProcessPacket[PreProcessPacket::ppt_detach]->packetS_sip_pop_from_stack(0));
}

inline packet_s_process_0 *PACKET_S_PROCESS_RTP_POP_FROM_STACK() {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
	return(preProcessPacket[PreProcessPacket::ppt_detach]->packetS_rtp_pop_from_stack(0));
}

inline packet_s_stack *PACKET_S_PROCESS_OTHER_POP_FROM_STACK() {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
	return(preProcessPacket[PreProcessPacket::ppt_detach]->packetS_other_pop_from_stack(0));
}

inline void PACKET_S_PROCESS_DESTROY(packet_s_process_0 **packet) {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
	if((*packet)->__type == _t_packet_s_process_0) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy(packet);
	} else if((*packet)->__type == _t_packet_s_process) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy((packet_s_process**)packet);
	} else if((*packet)->__type == _t_packet_s_stack) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy((packet_s_stack**)packet);
	}
}

inline void PACKET_S_PROCESS_DESTROY(packet_s_process **packet) {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
	if((*packet)->__type == _t_packet_s_process) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy(packet);
	} else if((*packet)->__type == _t_packet_s_process_0) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy((packet_s_process_0**)packet);
	} else if((*packet)->__type == _t_packet_s_stack) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy((packet_s_stack**)packet);
	}
}

inline void PACKET_S_PROCESS_DESTROY(packet_s_stack **packet) {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
	if((*packet)->__type == _t_packet_s_stack) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy(packet);
	} else if((*packet)->__type == _t_packet_s_process) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy((packet_s_process**)packet);
	} else if((*packet)->__type == _t_packet_s_process_0) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_destroy((packet_s_process_0**)packet);
	}
}

inline void PACKET_S_PROCESS_PUSH_TO_STACK(packet_s_process_0 **packet, u_int16_t queue_index) {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
	if((*packet)->__type == _t_packet_s_process_0) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_push_to_stack(packet, queue_index);
	} else if((*packet)->__type == _t_packet_s_process) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_push_to_stack((packet_s_process**)packet, queue_index);
	} else if((*packet)->__type == _t_packet_s_stack) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_push_to_stack((packet_s_stack**)packet, queue_index);
	}
}

inline void PACKET_S_PROCESS_PUSH_TO_STACK(packet_s_process **packet, u_int16_t queue_index) {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
	if((*packet)->__type == _t_packet_s_process) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_push_to_stack(packet, queue_index);
	} else if((*packet)->__type == _t_packet_s_process_0) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_push_to_stack((packet_s_process_0**)packet, queue_index);
	} else if((*packet)->__type == _t_packet_s_stack) {
		preProcessPacket[PreProcessPacket::ppt_detach]->packetS_push_to_stack((packet_s_stack**)packet, queue_index);
	}
}

inline void PACKET_S_PROCESS_PUSH_TO_STACK(packet_s_stack **packet, u_int16_t queue_index) {
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
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
		void realloc(unsigned new_max_count) {
			delete [] batch;
			max_count = new_max_count;
			batch = new FILE_LINE(0) packet_s_process_0*[max_count];
			memset(batch, 0, sizeof(packet_s_process_0*) * max_count);
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
		#if EXPERIMENTAL_PROCESS_RTP_MOD_02
		volatile int thread_index;
		#endif
		volatile int data_ready;
		volatile int processing;
		unsigned counters[2];
		void null() {
			batch = NULL;
			start = 0;
			end = 0;
			skip = 0;
			#if EXPERIMENTAL_PROCESS_RTP_MOD_02
			thread_index = 0;
			#endif
			data_ready = 0;
			processing = 0;
			counters[0] = 0;
			counters[1] = 0;
		}
	};
	struct s_hash_next_thread {
		volatile int thread_id;
		pthread_t thread_handle;
		pstat_data thread_pstat_data[2][2];
		s_hash_thread_data hash_data;
		sem_t sem_sync[2];
		volatile int terminate;
		void null() {
			thread_id = 0;
			thread_handle = 0;
			memset(thread_pstat_data, 0, sizeof(thread_pstat_data));
			hash_data.null();
			memset(sem_sync, 0, sizeof(sem_sync));
			terminate = 0;
		}
		void sem_init() {
			extern int opt_process_rtp_packets_hash_next_thread_sem_sync;
			for(int i = 0; i < opt_process_rtp_packets_hash_next_thread_sem_sync; i++) {
				::sem_init(&sem_sync[i], 0, 0);
			}
		}
		void sem_term() {
			extern int opt_process_rtp_packets_hash_next_thread_sem_sync;
			for(int i = 0; i < opt_process_rtp_packets_hash_next_thread_sem_sync; i++) {
				sem_destroy(&sem_sync[i]);
			}
		}
	};
public:
	ProcessRtpPacket(eType type, int indexThread);
	~ProcessRtpPacket();
	inline void push_packet(packet_s_process_0 *packetS) {
		#if EXPERIMENTAL_CHECK_TID_IN_PUSH
		static __thread unsigned _tid = 0;
		if(!_tid) {
			_tid = get_unix_tid();
		}
		if(!push_thread) {
			push_thread = _tid;
		} else if(push_thread != _tid) {
			u_int64_t time = getTimeMS_rdtsc();
			if(time > last_race_log[0] + 1000) {
				syslog(LOG_ERR, "race in %s %s %i (%i != %i)", getNameTypeThread().c_str(), __FILE__, __LINE__, push_thread, _tid);
				last_race_log[0] = time;
			}
			push_thread = _tid;
		}
		#endif
		if(is_terminating()) {
			PACKET_S_PROCESS_DESTROY(&packetS);
			return;
		}
		if(!packetS) {
			syslog(LOG_NOTICE, "NULL packetS in %s %i", __FILE__, __LINE__);
			return;
		}
		extern bool use_push_batch_limit_ms;
		u_int64_t time_us = use_push_batch_limit_ms ? packetS->getTimeUS() : 0;
		if(!qring_push_index) {
			#if SNIFFER_THREADS_EXT
			if(sverb.sniffer_threads_ext && thread_data) {
				++thread_data->buffer_push_cnt_all;
			}
			#endif
			unsigned int usleepCounter = 0;
			while(this->qring[this->writeit]->used != 0) {
				if(is_terminating()) {
					PACKET_S_PROCESS_DESTROY(&packetS);
					return;
				}
				if(usleepCounter == 0) {
					#if SNIFFER_THREADS_EXT
					if(sverb.sniffer_threads_ext && thread_data) {
						++thread_data->buffer_push_cnt_full;
					}
					#endif
				}
				#if SNIFFER_THREADS_EXT
				if(sverb.sniffer_threads_ext && thread_data) {
					++thread_data->buffer_push_cnt_full_loop;
				}
				#endif
				extern unsigned int opt_process_rtp_packets_qring_push_usleep;
				if(opt_process_rtp_packets_qring_push_usleep) {
					#if SNIFFER_THREADS_EXT
					unsigned us =
					#endif
					USLEEP_C(opt_process_rtp_packets_qring_push_usleep, usleepCounter++);
					#if SNIFFER_THREADS_EXT
					if(sverb.sniffer_threads_ext && thread_data) {
						thread_data->buffer_push_sum_usleep_full_loop += us;
					}
					#endif
				} else {
					__ASM_PAUSE;
					++usleepCounter;
				}
			}
			qring_push_index = this->writeit + 1;
			qring_push_index_count = 0;
			qring_active_push_item = this->qring[qring_push_index - 1];
			extern unsigned int opt_push_batch_limit_ms;
			qring_active_push_item_limit_us = use_push_batch_limit_ms ? time_us + opt_push_batch_limit_ms * 1000 : 0;
		}
		qring_active_push_item->batch[qring_push_index_count] = packetS;
		++qring_push_index_count;
		if(qring_push_index_count == qring_active_push_item->max_count ||
		   time_us > qring_active_push_item_limit_us) {
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
		#if EXPERIMENTAL_CHECK_TID_IN_PUSH
		static __thread unsigned _tid = 0;
		if(!_tid) {
			_tid = get_unix_tid();
		}
		if(push_thread && push_thread != _tid) {
			u_int64_t time = getTimeMS_rdtsc();
			if(time > last_race_log[1] + 1000) {
				syslog(LOG_ERR, "race in %s %s %i (%i != %i)", getNameTypeThread().c_str(), __FILE__, __LINE__, push_thread, _tid);
				last_race_log[1] = time;
			}
			push_thread = _tid;
		}
		#endif
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
	void preparePstatData(int nextThreadId, int pstatDataIndex);
	double getCpuUsagePerc(int nextThreadId, int pstatDataIndex, bool preparePstatData = true);
	void terminate();
	static void autoStartProcessRtpPacket();
	void addRtpRhThread();
	void removeRtpRhThread();
	static void addRtpRdThread();
	static void lockAddRtpRdThread() {
		__SYNC_LOCK(_sync_add_rtp_rd_threads);
	}
	static void unlockAddRtpRdThread() {
		__SYNC_UNLOCK(_sync_add_rtp_rd_threads);
	}
	bool isNextThreadsGt2Processing(int process_rtp_packets_hash_next_threads) {
		for(int i = 2; i < process_rtp_packets_hash_next_threads; i++) {
			if(this->hash_next_threads[i].hash_data.processing) {
				return(true);
			}
		}
		return(false);
	}
	bool existsNextThread(int next_thread_index) {
		return(next_thread_index < MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS &&
		       this->hash_next_threads[next_thread_index].thread_id);
	}
	string getNameTypeThread() {
		switch(type) {
		case hash:
			return("hash");
		case distribute:
			return("distribute");
		}
		return("");
	}
	string getShortcatTypeThread() {
		switch(type) {
		case hash:
			return("h");
		case distribute:
			return("d");
		}
		return("");
	}
	inline int getCalls() {
		return(calls);
	}
	inline void incCalls() {
		__SYNC_INC(calls);
	}
	inline void decCalls() {
		if(calls > 0) __SYNC_DEC(calls);
	}
private:
	void *outThreadFunction();
	void *nextThreadFunction(int next_thread_index_plus);
	void rtp_batch(batch_packet_s_process *batch, unsigned count);
	inline void rtp_packet_distr(packet_s_process_0 *packetS, int _process_rtp_packets_distribute_threads_use);
	inline void find_hash(packet_s_process_0 *packetS, unsigned *counters, bool lock = true);
	void createNextHashThread();
	void termNextHashThread();
public:
	eType type;
	int indexThread;
	int outThreadId;
private:
	volatile int process_rtp_packets_hash_next_threads;
	volatile int process_rtp_packets_hash_next_threads_mod;
	unsigned int qring_batch_item_length;
	unsigned int qring_length;
	batch_packet_s_process **qring;
	batch_packet_s_process *qring_active_push_item;
	u_int64_t qring_active_push_item_limit_us;
	unsigned qring_push_index;
	unsigned qring_push_index_count;
	volatile unsigned int readit;
	volatile unsigned int writeit;
	pthread_t out_thread_handle;
	pstat_data threadPstatData[2][2];
	bool term_processRtp;
	s_hash_next_thread hash_next_threads[MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS];
	volatile int8_t *hash_find_flag;
	volatile int _sync_count;
	#if EXPERIMENTAL_CHECK_TID_IN_PUSH
	unsigned push_thread;
	u_int64_t last_race_log[2];
	#endif
	volatile u_int32_t calls;
	static volatile int _sync_add_rtp_rd_threads;
	#if SNIFFER_THREADS_EXT
	cThreadMonitor::sThread *thread_data;
	#endif
friend inline void *_ProcessRtpPacket_outThreadFunction(void *arg);
friend inline void *_ProcessRtpPacket_nextThreadFunction(void *arg);
};


#endif
