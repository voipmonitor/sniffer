#ifndef SIPREC_H
#define SIPREC_H


#include <set>

#include "cloud_router/cloud_router_base.h"

#include "tools.h"


class cSipRecCall {
public:
	struct sId {
		string callid;
		vmIP src_ip;
		inline bool operator == (const sId& other) const {
			return(this->callid == other.callid &&
			       this->src_ip == other.src_ip); 
		}
		inline bool operator < (const sId& other) const {
			return(this->callid < other.callid ? true : !(this->callid == other.callid) ? false :
			       this->src_ip < other.src_ip);
		}
		string getString() {
			return(src_ip.getString() + "/" + callid);
		}
	};
	struct sContent {
		string content_type;
		unsigned content_length;
		string content_disposition;
		string content;
	};
	struct sInvite {
		string str;
		string request_line;
		map<string, string> tags;
		vector<sContent> contents;
	};
	struct sBye {
		string str;
		string request_line;
		map<string, string> tags;
	};
	struct sCancel {
		string str;
		string request_line;
		map<string, string> tags;
	};
	struct sMetadata {
		vmIP caller_ip;
		vmIP called_ip;
		vmPort caller_port;
		vmPort called_port;
		vmPort caller_rtp_port;
		vmPort called_rtp_port;
		vmPort caller_rtcp_port;
		vmPort called_rtcp_port;
		string caller_aor;
		string called_aor;
		string caller_label;
		string called_label;
		bool isCompleted(bool check_rtp_port) {
			return(isCompletedCallerdAor() &&
			       isCompletedCallerdIpPort() &&
			       (!check_rtp_port || isCompletedCallerdRtpPort()));
		}
		bool isCompletedCallerdAor() {
			return(!caller_aor.empty() && !called_aor.empty());
		}
		bool isCompletedCallerdIpPort() {
			return(caller_ip.isSet() && called_ip.isSet() &&
			       caller_port.isSet() && called_port.isSet());
		}
		bool isCompletedCallerdRtpPort() {
			return(caller_rtp_port.isSet() && called_rtp_port.isSet());
		}
		bool isCompletedCallerdRtcpPort() {
			return(caller_rtcp_port.isSet() && called_rtcp_port.isSet());
		}
	};
	struct sSdpPayload {
	       unsigned payload;
	       string codec;
	       unsigned sampling_freq;
	};
	enum eSdpMediaDirection {
		sdp_media_direction_unknown = 0,
		sdp_media_direction_caller = 1,
		sdp_media_direction_called = 2
	};
	struct sSdpMedia {
		string media_type;
		vmPort port;
		string transport_protocol;
		vector<sSdpPayload> payloads;
		string label;
		vmPort reverse_port;
		vmPort rtcp_port;
		vmPort reverse_rtcp_port;
		bool rtcp_mux;
		eSdpMediaDirection direction;
		bool active;
		u_int64_t last_packet_at_ms;
		sSdpMedia() {
			direction = sdp_media_direction_unknown;
			active = false;
			rtcp_mux = false;
			last_packet_at_ms = 0;
		}
	};
	struct sSdp {
		vmIP c_in;
		vector<sSdpMedia> media;
		volatile int _sync_lock_sdp;
		sSdp() {
			_sync_lock_sdp = 0;
		}
		void setActive(vmPort port, bool active) {
			lock();
			for(vector<sSdpMedia>::iterator it = media.begin(); it != media.end(); it++) {
				if(it->reverse_port == port || it->reverse_rtcp_port == port) {
					it->active = active;
				}
			}
			unlock();
		}
		void updateLastPacketTime(vmPort port, u_int64_t time_ms) {
			lock();
			for(vector<sSdpMedia>::iterator it = media.begin(); it != media.end(); it++) {
				if(it->reverse_port == port || it->reverse_rtcp_port == port) {
					it->last_packet_at_ms = time_ms;
				}
			}
			unlock();
		}
		u_int64_t getLastPacketTime(vmPort port) {
			u_int64_t rslt = 0;
			lock();
			for(vector<sSdpMedia>::iterator it = media.begin(); it != media.end(); it++) {
				if(it->reverse_port == port || it->reverse_rtcp_port == port) {
					rslt = it->last_packet_at_ms;
					break;
				}
			}
			unlock();
			return(rslt);
		}
		unsigned countActive() {
			unsigned count = 0;
			lock();
			for(vector<sSdpMedia>::iterator it = media.begin(); it != media.end(); it++) {
				if(it->active) {
					++count;
				}
			}
			unlock();
			return(count);
		}
		bool isSetBothDirections() {
			bool caller = false;
			bool called = false;
			lock();
			for(vector<sSdpMedia>::iterator it = media.begin(); it != media.end(); it++) {
				if(it->direction == sdp_media_direction_caller) {
					caller = true;
				} else if(it->direction == sdp_media_direction_called) {
					called = true;
				}
			}
			unlock();
			return(caller && called);
		}
		void lock() { __SYNC_LOCK(_sync_lock_sdp); }
		void unlock() { __SYNC_UNLOCK(_sync_lock_sdp); }
	};
	enum eParticipantType {
		participant_type_unknown = -1,
		participant_type_caller = 0,
		participant_type_called = 1
	};
public:
	cSipRecCall();
	~cSipRecCall();
	bool parseInvite(const char *invite_str, vmIP src_ip);
	bool parseBye(const char *bye_str, vmIP src_ip);
	bool parseCancel(const char *cancel_str, vmIP src_ip);
	void addInvite(const sInvite &inv);
	void detectFromToTag();
	const char *getXmlMetadata();
	bool parseXmlMetadata(const char *xml = NULL);
	bool isCompletedXmlMetadata(bool check_rtp_port);
	const char *getSdpData();
	int parseSdpData(const char *sdp_str = NULL);
	void clearSdpData();
	void startStreams();
	void stopStreams();
	int setSdpMediaDirections();
	void setReverseRtpPorts();
	string createInviteRequest(bool use_real_caller_called = false, bool use_direction_separation = false, bool use_real_rtp_ip_ports = false);
	string createInviteResponse(bool use_real_caller_called = false, bool use_direction_separation = false, bool use_rtp_reverse_ports = false, bool use_real_rtp_ip_ports = false);
	string createByeRequest(bool use_real_caller_called = false);
	string createByeResponse(bool use_real_caller_called = false);
	string createCancelRequest(bool use_real_caller_called = false);
	string createCancelResponse(bool use_real_caller_called = false);
	void evTimeoutStream();
	void add_ref() { __SYNC_INC(ref_count); }
	void destroy() { if(__SYNC_DEC(ref_count) == 0) delete this; }
private:
	const char *parseSipHeaders(const char *ptr, map<string, string> &tags);
	string extractTag(const string& header);
	bool parseParticipantNode(void *participantNode, bool is_caller);
	const char *find_end_line(const char *ptr) {
		while(*ptr && *ptr != '\r' && *ptr != '\n') {
			ptr++;
		}
		return(ptr);
	}
	const char *skip_cr_lf(const char *ptr) {
		if(*ptr == '\r' && *(ptr + 1) == '\n') {
			ptr += 2;
		} else if(*ptr == '\n') {
			ptr++;
		}
		return(ptr);
	}
	size_t skip_cr_lf(string &str, size_t pos) {
		if(pos >= str.length()) {
			return(pos);
		}
		if(pos + 1 < str.length() && str[pos] == '\r' && str[pos + 1] == '\n') {
			pos += 2;
		} else if(str[pos] == '\n') {
			pos++;
		}
		return(pos);
	}
	bool line_is_empty(const char *ptr) {
		return((*ptr == '\r' && *(ptr + 1) == '\n') ||
		       *ptr == '\n');
	}
public:
	volatile int ref_count;
	sId id;
	u_int64_t start_time_us;
	vector<sInvite> invite;
	sBye bye;
	sCancel cancel;
	sMetadata metadata;
	sSdp sdp;
	string from_tag;
	string to_tag;
	vmIP local_ip;
	vmPort local_port;
	int thread_idx;
};

class cSipRecStream {
public:
	cSipRecStream(cSipRecCall *call, vmPort port, bool rtcp);
	~cSipRecStream();
	void processPacket(u_char *data, unsigned len, vmIP src_ip, vmPort src_port, vmIP dst_ip, vmPort dst_port);
private:
	bool createSocket();
public:
	cSipRecCall *call;
	vmPort port;
	bool rtcp;
	int socket;
	u_int64_t start_at_ms;
};

class cSipRecThread {
public:
	cSipRecThread();
	~cSipRecThread();
	static void *_thread_fce(void *arg);
	void thread_fce();
	bool addStream(cSipRecCall *call, vmPort port, bool rtcp);
	void removeStream(vmPort port);
	void _removeStream(vmPort port);
	unsigned getStreamsCount() { return(streams.size()); }
	void stop();
private:
	void lock() { __SYNC_LOCK(_sync_lock); }
	void unlock() { __SYNC_UNLOCK(_sync_lock); }
	void checkTimeout();
private:
	map<vmPort, cSipRecStream*> streams;
	volatile int _sync_lock;
	pthread_t thread_id;
	volatile bool terminate;
	int pipe_fd[2];
	int epoll_fd;
	u_int64_t last_check_timeout_ms;
};

class cSipRecStreams {
public:
	cSipRecStreams(unsigned max_threads, unsigned max_streams_per_thread);
	~cSipRecStreams();
	bool addStream(cSipRecCall *call, vmPort port, bool rtcp);
	void stopStream(vmPort port);
	void stopAllStreams();
	void stopAllThreads();
private:
	int findThreadWithMinStreams();
	void lock() { __SYNC_LOCK(_sync_lock); }
	void unlock() { __SYNC_UNLOCK(_sync_lock); }
private:
	unsigned max_threads;
	unsigned max_streams_per_thread;
	unsigned threads_count;
	cSipRecThread **threads;
	map<vmPort, unsigned> stream_by_thread;
	volatile int _sync_lock;
};

class cSipRecServer : public cServer {
public:
	cSipRecServer(bool udp);
	virtual ~cSipRecServer();
	void createConnection(cSocket *socket);
	void evData(u_char *data, size_t dataLen, vmIP ip, vmPort port, vmIP local_ip, vmPort local_port, cSocket *socket);
};

class cSipRecConnection : public cServerConnection {
public:
	cSipRecConnection(cSocket *socket);
	virtual ~cSipRecConnection();
	void evData(u_char *data, size_t dataLen);
	void connection_process();
};

class cSipRecPacketSender : public cTimer {
public:
	cSipRecPacketSender();
	virtual ~cSipRecPacketSender();
	void sendPacket(u_char *data, unsigned dataLen, vmIP src_ip, vmPort src_port, vmIP dst_ip, vmPort dst_port);
private:
	void pushPacket(pcap_pkthdr *header, u_char *packet, unsigned dataLen, bool tcp,
			vmIP src_ip, vmPort src_port, vmIP dst_ip, vmPort dst_port,
			int dlink, int pcap_handle_index);
	void evTimer(u_int32_t time_s, int typeTimer, void *data);
	void block_store_lock() { __SYNC_LOCK_USLEEP(block_store_sync, 50); }
	void block_store_unlock() { __SYNC_UNLOCK(block_store_sync); }
private:
	struct pcap_block_store *block_store;
	volatile int block_store_sync;
};

class cSipRec {
public:
	cSipRec();
	~cSipRec();
	void setRtpPortsLimit(unsigned rtp_port_min, unsigned rtp_port_max);
	void setBindParams(vmIP ip, vmPort port, bool udp);
	void setRtpStreamTimeout(unsigned rtp_stream_timeout_s);
	void setRtpStreamsMaxThreads(unsigned rtp_streams_max_threads);
	void setRtpStreamsMaxPerThread(unsigned rtp_streams_max_per_thread);
	void setUseRealCallerCalled(bool use_real_caller_called);
	void setUseRealSipIpPorts(bool use_real_sip_ip_ports);
	void setUseRealRtpIpPorts(bool use_real_rtp_ip_ports);
	bool getUseRealRtpIpPorts() { return(use_real_rtp_ip_ports); }
	void setVerbose(bool verbose);
	void startServer();
	vmPort getRtpPort();
	void freeRtpPort(vmPort port);
	void initRtpPortsHeap();
	void processData(u_char *data, size_t dataLen, vmIP ip, vmPort port, vmIP local_ip, vmPort local_port, cSocket *socket);
	void processInvite(u_char *data, size_t dataLen, vmIP ip, vmPort port, vmIP local_ip, vmPort local_port, cSocket *socket);
	void processBye(u_char *data, size_t dataLen, vmIP ip, vmPort port, vmIP local_ip, vmPort local_port, cSocket *socket);
	void processCancel(u_char *data, size_t dataLen, vmIP ip, vmPort port, vmIP local_ip, vmPort local_port, cSocket *socket);
	void sendPacket(u_char *data, unsigned dataLen, vmIP src_ip, vmPort src_port, vmIP dst_ip, vmPort dst_port);
	void deleteCall(cSipRecCall *call, const char *reason);
	bool addStream(cSipRecCall *call, vmPort port, bool rtcp);
	void stopStream(cSipRecCall *call, vmPort port, bool rtcp);
	unsigned getRtpStreamTimeout() { return(rtp_stream_timeout_s); }
private:
	bool sendResponse(string &response, vmIP ip, vmPort port, cSocket *socket);
	void checkParams();
	void lock() { __SYNC_LOCK(_sync_lock); }
	void unlock() { __SYNC_UNLOCK(_sync_lock); }
	void lock_rtp_ports() { __SYNC_LOCK(_sync_lock_rtp_ports); }
	void unlock_rtp_ports() { __SYNC_UNLOCK(_sync_lock_rtp_ports); }
private:
	unsigned rtp_port_min;
	unsigned rtp_port_max;
	vmIP bind_ip;
	vmPort bind_port;
	bool bind_udp;
	set<u_int16_t> free_rtp_ports;
	map<cSipRecCall::sId, cSipRecCall*> calls_by_call_id;
	cSipRecStreams *streams;
	cSipRecServer *server;
	cSipRecPacketSender *packet_sender;
	unsigned rtp_stream_timeout_s;
	unsigned rtp_streams_max_threads;
	unsigned rtp_streams_max_per_thread;
	bool use_real_caller_called;
	bool use_real_sip_ip_ports;
	bool use_real_rtp_ip_ports;
	volatile int _sync_lock;
	volatile int _sync_lock_rtp_ports;
	bool verbose;
};


void sipRecStart();
void sipRecStop();


#endif //SIPREC_H
