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
		string caller_aor;
		string called_aor;
		string caller_label;
		string called_label;
		bool isCompleted(bool check_rtp_port) {
			return(caller_ip.isSet() && called_ip.isSet() &&
			       caller_port.isSet() && called_port.isSet() &&
			       (!check_rtp_port || (caller_rtp_port.isSet() && called_rtp_port.isSet())) &&
			       !caller_aor.empty() && !called_aor.empty() &&
			       !caller_label.empty() && !called_label.empty());
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
		eSdpMediaDirection direction;
		bool active;
		sSdpMedia() {
			direction = sdp_media_direction_unknown;
			active = false;
		}
	};
	struct sSdp {
		vmIP c_in;
		vector<sSdpMedia> media;
		void setActive(vmPort port, bool active) {
			for(vector<sSdpMedia>::iterator it = media.begin(); it != media.end(); it++) {
				if(it->reverse_port == port) {
					it->active = active;
				}
			}
		}
		unsigned countActive() {
			unsigned count = 0;
			for(vector<sSdpMedia>::iterator it = media.begin(); it != media.end(); it++) {
				if(it->active) {
					++count;
				}
			}
			return(count);
		}
	};
public:
	cSipRecCall();
	~cSipRecCall();
	bool parseInvite(const char *invite_str, vmIP src_ip);
	bool parseBye(const char *bye_str, vmIP src_ip);
	bool parseCancel(const char *cancel_str, vmIP src_ip);
	void addInvite(const sInvite &inv);
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
	string createInviteRequest(bool use_real_ip_ports = false);
	string createInviteResponse(bool use_real_ip_ports = false);
	string createByeRequest(bool use_real_ip_ports = false);
	string createByeResponse(bool use_real_ip_ports = false);
	string createCancelRequest(bool use_real_ip_ports = false);
	string createCancelResponse(bool use_real_ip_ports = false);
	void evTimeoutStream();
private:
	const char *parseSipHeaders(const char *ptr, map<string, string> &tags);
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
		if(str[pos] == '\r' && str[pos + 1] == '\n') {
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
	sId id;
	u_int64_t start_time_us;
	vector<sInvite> invite;
	sBye bye;
	sCancel cancel;
	sMetadata metadata;
	sSdp sdp;
	vmIP local_ip;
	vmPort local_port;
};

class cSipRecStream {
public:
	cSipRecStream(cSipRecCall *call, vmPort port);
	~cSipRecStream();
	void processPacket(u_char *data, unsigned len, vmIP src_ip, vmPort src_port, vmIP dst_ip, vmPort dst_port);
private:
	bool createSocket();
public:
	cSipRecCall *call;
	vmPort port;
	int socket;
	u_int64_t start_at_ms;
	u_int64_t last_packet_at_ms;
};

class cSipRecThread {
public:
	cSipRecThread();
	~cSipRecThread();
	static void *_thread_fce(void *arg);
	void thread_fce();
	bool addStream(cSipRecCall *call, vmPort port);
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
	cSipRecStreams(unsigned max_threads);
	~cSipRecStreams();
	bool addStream(cSipRecCall *call, vmPort port);
	void stopStream(vmPort port);
	void stopAllStreams();
	void stopAllThreads();
private:
	int findThreadWithMinStreams();
	void lock() { __SYNC_LOCK(_sync_lock); }
	void unlock() { __SYNC_UNLOCK(_sync_lock); }
private:
	unsigned max_threads;
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
	void setRtpStreamManThreads(unsigned rtp_streams_max_threads);
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
	void deleteCall(cSipRecCall *call);
	bool addStream(cSipRecCall *call, vmPort port);
	void stopStream(vmPort port);
	vmIP getBindIP() { return(bind_ip); }
	vmPort getBindPort() { return(bind_port); }
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
	volatile int _sync_lock;
	volatile int _sync_lock_rtp_ports;
	bool verbose;
};


void sipRecStart();
void sipRecStop();


#endif //SIPREC_H
