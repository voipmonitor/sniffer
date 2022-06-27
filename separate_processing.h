#ifndef SEPARATE_PROCESSING_H
#define SEPARATE_PROCESSING_H


#if EXPERIMENTAL_SEPARATE_PROCESSSING


#include "ip.h"
#include "rqueue.h"
#include "calltable.h"


#define SEPARATE_PROCESSING_VERSION 1


class cSeparateProcessing {
public:
	enum eMainType {
		 _sip = 1,
		 _rtp
	};
	enum eSideType {
		_sender = 1,
		_receiver
	};
	enum eDataType {
		_rtp_ip_port = 1,
		_close_call,
		_rtp_streams,
		_rtp_exists
	};
	enum eCloseCallType {
		_stop_processing = 1,
		_destroy_call,
		_destroy_call_if_not_exists_rtp
	};
	struct sDataHeader {
		u_int8_t version;
		eDataType data_type;
		u_int32_t length;
	};
	struct sDataCall {
		u_int64_t first_packet_time_us;
		unsigned long call_flags;
		u_int64_t time_us;
		u_int16_t call_id_length;
	};
	struct sDataCloseCall {
		eCloseCallType type;
		u_int64_t first_packet_time_us;
		unsigned long call_flags;
		u_int64_t time_us;
		u_int16_t call_id_length;
	};
	struct sDataRtpIpPort {
		bool add;
		vmIP ip;
		vmPort port;
		bool is_caller;
		bool is_rtcp;
		s_sdp_flags sdp_flags;
		bool ignore_rtcp_check;
	};
	struct sDataRtpIpPort_comb {
		string call_id;
		sDataCall *callData;
		sDataRtpIpPort *rtpIpPort;
		u_char *buff;
		Call *call;
	};
	struct sDataRtpStream_header {
		u_int32_t count;
		u_int16_t call_id_length;
	};
	struct sDataRtpStream {
		vmIP saddr;
		vmIP daddr;
		vmPort sport;
		vmPort dport;
		u_int32_t ssrc;
		int32_t first_codec;
		u_int64_t first_time_us;
		u_int64_t last_time_us;
		u_int32_t received;
		u_int32_t lost;
	};
	struct sDataRtpTarPos_header {
		u_int32_t count;
	};
	struct sDataRtpTarPos {
		u_int64_t tar_pos;
	};
	struct sProcessRtpIpPortData {
		sProcessRtpIpPortData() {
			last_processed_time_us = 0;
		}
		list<sDataRtpIpPort_comb> data;
		u_int64_t last_processed_time_us;
	};
	struct sDataRtpExists {
		u_int32_t count_streams;
		u_int64_t first_rtp_time_us;
		u_int16_t call_id_length;
	};
public:
	cSeparateProcessing(eMainType mainType, eSideType sideType);
	~cSeparateProcessing();
	void start();
	void stop();
	void sendRtpIpPort(const char *call_id, u_int64_t call_first_packet_time_us, unsigned long call_flags,
			   u_int64_t time_us,
			   sDataRtpIpPort *rtpIpPort);
	void sendCloseCall(const char *call_id, u_int64_t call_first_packet_time_us, unsigned long call_flags,
			   eCloseCallType type, u_int64_t time_us);
	void sendRtpStreams(class Call *call); 
	void sendRtpStreams(const char *call_id, 
			    u_int32_t count_streams, sDataRtpStream streams[], 
			    u_int32_t count_tar_pos, sDataRtpTarPos tar_pos[]);
	void sendRtpExists(class Call *call); 
	void sendRtpExists(const char *call_id, u_int32_t count_streams, u_int64_t first_rtp_time_us);
private:
	void initThreads();
	void startReadThread();
	void startWriteThread();
	void startProcessThread();
	static void *_readThread(void *arg);
	static void *_writeThread(void *arg);
	static void *_processThread(void *arg);
	void readThread();
	void writeThread();
	void processThread();
	void pushBuff(u_char *buff);
	void processBuff(u_char *buff);
	void processRtpIpPort(u_char *buff);
	void processRtpIpPort(const char *call_id, sDataCall *dataCall, sDataRtpIpPort *rtpIpPort, u_char *buff, bool *delete_buff);
	void processRtpIpPort(sProcessRtpIpPortData *data);
	void processCloseCall(u_char *buff);
	void processCloseCall(const char *call_id, sDataCloseCall *dataCloseCall);
	void processRtpStreams(u_char *buff);
	void processRtpStreams(const char *call_id, u_int32_t count_streams, sDataRtpStream streams[], u_int32_t count_tar_pos, sDataRtpTarPos tar_pos[]);
	void processRtpExists(u_char *buff);
	void processRtpExists(const char *call_id, u_int32_t count_streams, u_int64_t first_rtp_time_us);
	const char *getNameMainType() {
		return(mainType == _sip ? "sip" :
		       mainType == _rtp ? "rtp" : "");
	}
	const char *getNameSideType() {
		return(sideType == _sender ? "sender" :
		       sideType == _receiver ? "receiver" : "");
	}
	string getNameType() {
		return(string(getNameMainType()) + " / " + getNameSideType());
	}
	string getFifoPath();
	string getFifoName();
	string getFifoPathName();
	bool createFifo();
	bool openFifo();
	void closeFifo();
	bool is_terminating();
private:
	eMainType mainType;
	eSideType sideType;
	u_int32_t buff_queue_max_length;
	rqueue_quick<void*> *buff_queue;
	pthread_t readThreadHandle;
	pthread_t writeThreadHandle;
	pthread_t processThreadHandle;
	int fd_fifo;
	int usleep_us;
	bool terminating;
	sProcessRtpIpPortData processRtpIpPortData;
};


void separate_processing_init();
void separate_processing_start();
void separate_processing_stop();
void separate_processing_term();

void sendRtpIpPort(const char *call_id, u_int64_t call_first_packet_time_us, unsigned long call_flags,
		   u_int64_t time_us, 
		   cSeparateProcessing::sDataRtpIpPort *rtpIpPort);
void sendCloseCall(const char *call_id, u_int64_t call_first_packet_time_us, unsigned long call_flags,
		   cSeparateProcessing::eCloseCallType type, u_int64_t time_us);
void sendRtpStreams(class Call *call);
void sendExistsRtp(class Call *call);


#endif // EXPERIMENTAL_SEPARATE_PROCESSSING


#endif //SEPARATE_PROCESSING_H
