/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

/* Calls are stored into indexed array. 
 * Into one calltable is stored SIP call-id and IP-port of SDP session
 */

#ifndef CALLTABLE_H
#define CALLTABLE_H

#include <queue>
#include <map>
#include <list>

#include <arpa/inet.h>
#include <time.h>

#include <pcap.h>

#include <string>

#include "jitterbuffer/asterisk/circbuf.h"
#include "rtp.h"
#include "tools.h"
#include "voipmonitor.h"

#define MAX_IP_PER_CALL 40	//!< total maxumum of SDP sessions for one call-id
#define MAX_SSRC_PER_CALL 40	//!< total maxumum of SDP sessions for one call-id
#define MAX_FNAME 256		//!< max len of stored call-id
#define MAX_RTPMAP 40          //!< max rtpmap records
#define MAXNODE 150000
#define MAXLEN_SDP_SESSID 16
#define RTPMAP_BY_CALLERD true
#define MAX_SIPCALLERDIP 4

#define INVITE 1
#define BYE 2
#define CANCEL 3
#define RES10X 100
#define RES18X 180
#define RES2XX 200
#define RES300 300
#define RES3XX 399
#define RES401 401
#define RES403 403
#define RES404 404
#define RES4XX 400
#define RES5XX 500
#define RES6XX 600
#define REGISTER 4
#define MESSAGE 5
#define INFO 6
#define SUBSCRIBE 7
#define OPTIONS 8
#define NOTIFY 9
#define ACK 10
#define PRACK 11
#define PUBLISH 12
#define REFER 13
#define UPDATE 14
#define SKINNY_NEW 100

#define IS_SIP_RES3XX(sip_method) (sip_method == RES300 || sip_method == RES3XX)
#define IS_SIP_RES4XX(sip_method) (sip_method == RES401 || sip_method == RES403 || sip_method == RES404 || sip_method == RES4XX)
#define IS_SIP_RESXXX(sip_method) (sip_method == RES10X || sip_method == RES18X || sip_method == RES2XX || IS_SIP_RES3XX(sip_method) || IS_SIP_RES4XX(sip_method) || sip_method == RES5XX || sip_method == RES6XX)

#define FLAG_SAVERTP		(1 << 0)
#define FLAG_SAVERTCP		(1 << 1)
#define FLAG_SAVESIP		(1 << 2)
#define FLAG_SAVEREGISTER	(1 << 3)
#define FLAG_SAVEAUDIO		(1 << 4)
#define FLAG_FORMATAUDIO_WAV	(1 << 5)
#define FLAG_FORMATAUDIO_OGG	(1 << 6)
#define FLAG_SAVEAUDIO_WAV	(FLAG_SAVEAUDIO|FLAG_FORMATAUDIO_WAV)
#define FLAG_SAVEAUDIO_OGG	(FLAG_SAVEAUDIO|FLAG_FORMATAUDIO_OGG)
#define FLAG_SAVEGRAPH		(1 << 7)
#define FLAG_SAVERTPHEADER	(1 << 8)
#define FLAG_SKIPCDR		(1 << 9)
#define FLAG_RUNSCRIPT		(1 << 10)
#define FLAG_RUNAMOSLQO		(1 << 11)
#define FLAG_RUNBMOSLQO		(1 << 12)
#define FLAG_HIDEMESSAGE	(1 << 13)

#define CHAN_SIP	1
#define CHAN_SKINNY	2

#define CDR_NEXT_MAX 10

typedef struct {
	double ts;
	char dtmf;
	unsigned int saddr;
	unsigned int daddr;
} dtmfq;

struct s_sdp_flags {
	s_sdp_flags() {
		is_fax = 0;
		rtcp_mux = 0;
	}
	int operator != (const s_sdp_flags &other) {
		return(is_fax != other.is_fax ||
		       rtcp_mux != other.rtcp_mux);
	}
	int16_t is_fax;
	int16_t rtcp_mux;
};

struct hash_node_call {
	hash_node_call *next;
	Call *call;
	int iscaller;
	u_int16_t is_rtcp;
	s_sdp_flags sdp_flags;
};

struct hash_node {
	hash_node *next;
	hash_node_call *calls;
	u_int32_t addr;
	u_int16_t port;
};

struct ip_port_call_info {
	u_int32_t addr;
	u_int16_t port;
	bool iscaller;
	char sessid[MAXLEN_SDP_SESSID];
	u_int32_t sip_src_addr;
	s_sdp_flags sdp_flags;
};

struct raws_t {
	int ssrc_index;
	int rawiterator;
	int codec;
	struct timeval tv;
	string filename;
};



/**
  * This class implements operations on call
*/
class Call {
public:
	struct sSipResponse {
		sSipResponse(const char *SIPresponse = NULL, int SIPresponseNum = 0) {
			if(SIPresponse) {
				this->SIPresponse = SIPresponse;
			}
			this->SIPresponseNum = SIPresponseNum;
		}
		string SIPresponse;
		int SIPresponseNum;
	};
	struct sSipHistory {
		sSipHistory(u_int64_t time = 0,
			    const char *SIPrequest = NULL,
			    const char *SIPresponse = NULL, int SIPresponseNum = 0) {
			this->time = time;
			if(SIPrequest && SIPrequest[0]) {
				this->SIPrequest = SIPrequest;
			}
			if(SIPresponse && SIPresponse[0]) {
				this->SIPresponse = SIPresponse;
			}
			this->SIPresponseNum = SIPresponseNum;
		}
		u_int64_t time;
		string SIPrequest;
		string SIPresponse;
		int SIPresponseNum;
	};
public:
	int type;			//!< type of call, INVITE or REGISTER
	bool is_ssl;			//!< call was decrypted
	char chantype;
	RTP *rtp[MAX_SSRC_PER_CALL];		//!< array of RTP streams
	volatile int rtplock;
	unsigned long call_id_len;	//!< length of call-id 	
	string call_id;	//!< call-id from SIP session
	char fbasename[MAX_FNAME];	//!< basename of file 
	char fbasename_safe[MAX_FNAME];	//!< basename of file 
	unsigned long long fname2;	//!< basename of file 
	char callername[256];		//!< callerid name from SIP header
	char caller[256];		//!< From: xxx 
	char caller_domain[256];	//!< From: xxx 
	char called[256];		//!< To: xxx
	map<string, string> called_invite_branch_map;
	char called_domain[256];	//!< To: xxx
	char contact_num[64];		//!< 
	char contact_domain[128];	//!< 
	char digest_username[64];	//!< 
	char digest_realm[64];		//!< 
	int register_expires;	
	char byecseq[32];		
	char invitecseq[32];		
	char cancelcseq[32];		
	char custom_header1[256];	//!< Custom SIP header
	char match_header[128];	//!< Custom SIP header
	bool seeninvite;		//!< true if we see SIP INVITE within the Call
	bool seeninviteok;			//!< true if we see SIP INVITE within the Call
	bool seenbye;			//!< true if we see SIP BYE within the Call
	bool seenbyeandok;		//!< true if we see SIP OK TO BYE OR TO CANEL within the Call
	bool seenRES2XX;
	bool seenRES2XX_no_BYE;
	bool seenRES18X;
	bool sighup;			//!< true if call is saving during sighup
	string dirname();		//!< name of the directory to store files for the Call
	string dirnamesqlfiles();
	char a_ua[1024];		//!< caller user agent 
	char b_ua[1024];		//!< callee user agent 
	int rtpmap[MAX_IP_PER_CALL][MAX_RTPMAP]; //!< rtpmap for every rtp stream
	RTP tmprtp;			//!< temporary structure used to decode information from frame
	RTP *lastcallerrtp;		//!< last RTP stream from caller
	RTP *lastcalledrtp;		//!< last RTP stream from called
	u_int32_t saddr;		//!< source IP address of first INVITE
	unsigned short sport;		//!< source port of first INVITE
	int whohanged;			//!< who hanged up. 0 -> caller, 1-> callee, -1 -> unknown
	int recordstopped;		//!< flag holding if call was stopped to avoid double free
	int dtmfflag;			//!< used for holding dtmf states 
	unsigned int dtmfflag2;			//!< used for holding dtmf states 
	int silencerecording;
	int msgcount;
	int regcount;
	int reg401count;
	int regstate;
	bool regresponse;
	timeval regrrdstart;		// time of first REGISTER
	int regrrddiff;			// RRD diff time REGISTER<->OK in [ms]- RFC6076
	unsigned long long flags1;	//!< bit flags used to store max 64 flags 
	#if SYNC_CALL_RTP
	volatile unsigned int rtppcaketsinqueue;
	#else
	volatile u_int32_t rtppcaketsinqueue_p;
	volatile u_int32_t rtppcaketsinqueue_m;
	#endif
	volatile int end_call;
	unsigned int unrepliedinvite;
	unsigned int ps_drop;
	unsigned int ps_ifdrop;
	char forcemark[2];
	queue<u_int64_t> forcemark_time[2];
	volatile int _forcemark_lock;
	int first_codec;
	bool	has_second_merged_leg;

	float a_mos_lqo;
	float b_mos_lqo;

	time_t progress_time;		//!< time in seconds of 18X response
	time_t first_rtp_time;		//!< time in seconds of first RTP packet
	time_t connect_time;		//!< time in seconds of 200 OK
	time_t last_packet_time;	
	time_t last_rtp_a_packet_time;	
	time_t last_rtp_b_packet_time;	
	time_t first_packet_time;	
	time_t destroy_call_at;	
	time_t destroy_call_at_bye;	
	unsigned int first_packet_usec;
	std::queue <short int> spybuffer;
	std::queue <char> spybufferchar;
	std::queue <dtmfq> dtmf_history;
	
	u_int64_t first_invite_time_usec;
	u_int64_t first_response_100_time_usec;
	u_int64_t first_response_xxx_time_usec;
	u_int64_t first_message_time_usec;
	u_int64_t first_response_200_time_usec;

	uint8_t	caller_sipdscp;
	uint8_t	called_sipdscp;

	int isfax;
	char seenudptl;

	void *rtp_cur[2];		//!< last RTP structure in direction 0 and 1 (iscaller = 1)
	void *rtp_prev[2];		//!< previouse RTP structure in direction 0 and 1 (iscaller = 1)

	u_int32_t sipcallerip[MAX_SIPCALLERDIP];	//!< SIP signalling source IP address
	u_int32_t sipcalledip[MAX_SIPCALLERDIP];	//!< SIP signalling destination IP address
	u_int32_t lastsipcallerip;		
	
	list<d_u_int32_t> invite_sdaddr;

	u_int16_t sipcallerport;
	u_int16_t sipcalledport;

	char lastSIPresponse[128];
	int lastSIPresponseNum;
	list<sSipResponse> SIPresponse;
	list<sSipHistory> SIPhistory;
	bool new_invite_after_lsr487;
	bool cancel_lsr487;
	
	int reason_sip_cause;
	string reason_sip_text;
	int reason_q850_cause;
	string reason_q850_text;

	string sip_pcapfilename;
	string rtp_pcapfilename;
	string pcapfilename;

	char *contenttype;
	char *message;
	int content_length;

	int last_callercodec;		//!< Last caller codec 
	int last_calledcodec;		//!< Last called codec 

	int codec_caller;
	int codec_called;

	pthread_mutex_t buflock;		//!< mutex locking calls_queue
	pvt_circbuf *audiobuffer1;
	int last_seq_audiobuffer1;
	pvt_circbuf *audiobuffer2;
	int last_seq_audiobuffer2;

	unsigned int skinny_partyid;

	unsigned int flags;		//!< structure holding FLAGS*

	int *listening_worker_run;
	pthread_mutex_t listening_worker_run_lock;

	int thread_num;

	char oneway;
	char absolute_timeout_exceeded;
	char zombie_timeout_exceeded;
	char bye_timeout_exceeded;
	char rtp_timeout_exceeded;
	char sipwithoutrtp_timeout_exceeded;
	char oneway_timeout_exceeded;
	char force_terminate;
	char pcap_drop;
	unsigned int lastsrcip;

	void *listening_worker_args;
	
	int ssrc_n;				//!< last index of rtp array
	int ipport_n;				//!< last index of addr and port array 

	string geoposition;

	/* obsolete
	map<string, string> custom_headers;
	*/
	map<int, map<int, dstring> > custom_headers;

	list<unsigned int> proxies;
	
	bool onCall_2XX;
	bool onCall_18X;
	bool updateDstnumOnAnswer;
	bool updateDstnumFromMessage;
	
	int useSensorId;
	int useDlt;
	pcap_t *useHandle;
	
	bool force_close;

	unsigned int caller_silence;
	unsigned int called_silence;
	unsigned int caller_noise;
	unsigned int called_noise;
	unsigned int caller_lastsilence;
	unsigned int called_lastsilence;

	unsigned int caller_clipping_8k;
	unsigned int called_clipping_8k;
	
	int vlan;

	unsigned int lastcallerssrc;
	unsigned int lastcalledssrc;

	vector<string> mergecalls;

	/**
	 * constructor
	 *
	 * @param call_id unique identification of call parsed from packet
	 * @param call_id_len lenght of the call_id buffer
	 * @param time time of the first packet
	 * @param ct reference to calltable
	 * 
	*/
	Call(char *call_id, unsigned long call_id_len, time_t time);

	/**
	 * destructor
	 * 
	*/
	~Call();

	/**
	 * @brief find Call by IP adress and port. 
	 *
	 * This function is applied for every incoming UDP packet
	 *
	 * @param addr IP address of the packet
	 * @param port port number of the packet
	 * 
	 * @return reference to the finded Call or NULL if not found. 
	*/
	Call *find_by_ip_port(in_addr_t addr, unsigned short port, int *iscaller);

	int get_index_by_ip_port(in_addr_t addr, unsigned short port);
	
	Call* find_by_sessid(char *sessid);
	
	int get_index_by_sessid(char *sessid, in_addr_t sip_src_addr = 0);

	/**
	 * @brief close all rtp[].gfileRAW
	 *
	 * close all RTP[].gfileRAW to flush writes 
	 * 
	 * @return nothing
	*/
	void closeRawFiles();
	
	/**
	 * @brief read RTP packet 
	 *
	 * Used for reading RTP packet 
	 *
	 * @param data pointer to the packet buffer
	 * @param datalen lenght of the buffer
	 * @param header header structure of the packet
	 * @param saddr source IP adress of the packet
	 * 
	*/
	void read_rtp(struct packet_s *packetS, int iscaller, char enable_save_packet, char *ifname = NULL);

	/**
	 * @brief read RTCP packet 
	 *
	 * Used for reading RTCP packet 
	 *
	 * @param data pointer to the packet buffer
	 * @param datalen lenght of the buffer
	 * @param header header structure of the packet
	 * @param saddr source IP adress of the packet
	 * 
	*/
	void read_rtcp(struct packet_s *packetS, int iscaller, char enable_save_packet);

	/**
	 * @brief adds RTP stream to the this Call 
	 *
	 * Adds RTP stream to the this Call which is identified by IP address and port number
	 *
	 * @param addr IP address of the RTP stream
	 * @param port port number of the RTP stream
	 * 
	 * @return return 0 on success, 1 if IP and port is duplicated and -1 on failure
	*/
	int add_ip_port(in_addr_t sip_src_addr, in_addr_t addr, unsigned short port, char *sessid, char *ua, unsigned long ua_len, bool iscaller, int *rtpmap, s_sdp_flags sdp_flags);
	
	bool refresh_data_ip_port(in_addr_t addr, unsigned short port, bool iscaller, int *rtpmap, s_sdp_flags sdp_flags);
	
	void add_ip_port_hash(in_addr_t sip_src_addr, in_addr_t addr, unsigned short port, char *sessid, char *ua, unsigned long ua_len, bool iscaller, int *rtpmap, s_sdp_flags sdp_flags, int allowrelation);

	/**
	 * @brief get pointer to PcapDumper of the writing pcap file  
	 *
	 * @return pointer to PcapDumper
	*/
	PcapDumper *getPcap() { return(&this->pcap); }
	PcapDumper *getPcapSip() { return(&this->pcapSip); }
	PcapDumper *getPcapRtp() { return(&this->pcapRtp); }
	
	/**
	 * @brief get time of the last seen packet which belongs to this call
	 *
	 * @return time of the last packet in seconds from UNIX epoch
	*/
	time_t get_last_packet_time() { return last_packet_time; };

	/**
	 * @brief get time of the last seen rtp packet which belongs to this call
	 *
	 * @return time of the last rtp packet in seconds from UNIX epoch
	*/
	time_t get_last_rtp_packet_time() { return max(last_rtp_a_packet_time, last_rtp_b_packet_time); };

	/**
	 * @brief set time of the last seen packet which belongs to this call
	 *
	 * this time is used for calculating lenght of the call
	 *
	 * @param timestamp in seconds from UNIX epoch
	 *
	*/
	void set_last_packet_time(time_t mtime) { last_packet_time = mtime; };

	/**
	 * @brief get first time of the the packet which belongs to this call
	 *
	 * this time is used as start of the call in CDR record
	 *
	 * @return time of the first packet in seconds from UNIX epoch
	*/
	time_t get_first_packet_time() { return first_packet_time; };

	/**
	 * @brief set first time of the the packet which belongs to this call
	 *
	 * @param timestamp in seconds from UNIX epoch
	 *
	*/
	void set_first_packet_time(time_t mtime, unsigned int usec) { first_packet_time = mtime; first_packet_usec = usec;};

	/**
	 * @brief convert raw files to one WAV
	 *
	*/
	int convertRawToWav();
 
	/**
	 * @brief save call to database
	 *
	*/
	int saveToDb(bool enableBatchIfPossible = true);

	/**
	 * @brief save register msgs to database
	 *
	*/
	int saveRegisterToDb(bool enableBatchIfPossible = true);

	/**
	 * @brief save sip MSSAGE to database
	 *
	*/
	int saveMessageToDb(bool enableBatchIfPossible = true);

	/**
	 * @brief calculate duration of the call
	 *
	 * @return lenght of the call in seconds
	*/
	int duration() { return last_packet_time - first_packet_time; };
	
	int connect_duration() { return(connect_time ? duration() - (connect_time - first_packet_time) : 0); };
	
	int duration_active() { extern volatile unsigned int glob_last_packet_time; return glob_last_packet_time - first_packet_time; };
	
	int connect_duration_active() { return(connect_time ? duration_active() - (connect_time - first_packet_time) : 0); };
	
	/**
	 * @brief return start of the call which is first seen packet 
	 *
	 * @param timestamp in seconds from UNIX epoch
	*/
	int calltime() { return first_packet_time; };

	/**
	 * @brief remove call from hash table
	 *
	*/
	void hashRemove();
	
	void skinnyTablesRemove();
	
	void removeFindTables(bool set_end_call = false);

	/**
	 * @brief remove all RTP 
	 *
	*/
	void removeRTP();

	/**
	 * @brief stop recording packets to pcap file
	 *
	*/
	void stoprecording();

	/**
	 * @brief substitute all nonalphanum string to "_" (except for @)
	 *
	*/
	char *get_fbasename_safe();

	/**
	 * @brief save call to register tables and remove from calltable 
	 *
	*/
	void saveregister();

	/**
	 * @brief print debug information for the call to stdout
	 *
	*/
	void addtocachequeue(string file);
	static void _addtocachequeue(string file);

	void addtofilesqueue(string file, string column, long long writeBytes);
	static void _addtofilesqueue(string file, string column, string dirnamesqlfiles, long long writeBytes);

	float mos_lqo(char *deg, int samplerate);

	void handle_dtmf(char dtmf, double dtmf_time, unsigned int saddr, unsigned int daddr);
	
	void handle_dscp(int sip_method, struct iphdr2 *header_ip, unsigned int saddr, unsigned int daddr, int *iscalledOut = NULL, bool enableSetSipcallerdip = false);
	
	bool check_is_caller_called(int sip_method, unsigned int saddr, unsigned int daddr, bool *iscaller, bool *iscalled = NULL, bool enableSetSipcallerdip = false);

	void dump();

	bool isFillRtpMap(int index) {
		for(int i = 0; i < MAX_RTPMAP; i++) {
			if(rtpmap[index][i]) {
				return(true);
			}
		}
		return(false);
	}

	int getFillRtpMapByCallerd(bool iscaller) {
		for(int i = ipport_n - 1; i >= 0; i--) {
			if(ip_port[i].iscaller == iscaller &&
			   isFillRtpMap(i)) {
				return(i);
			}
		}
		return(-1);
	}

	void atFinish();
	
	bool isPcapsClose() {
		return(pcap.isClose() &&
		       pcapSip.isClose() &&
		       pcapRtp.isClose());
	}
	bool isGraphsClose() {
		for(int i = 0; i < MAX_SSRC_PER_CALL; i++) {
			if(rtp[i] && !rtp[i]->graph.isClose()) {
				return(false);
			}
		}
		return(true);
	}
	bool isReadyForWriteCdr() {
		return(isPcapsClose() && isGraphsClose() &&
		       !chunkBuffersCount);
	}
	
	u_int32_t getAllReceivedRtpPackets();
	
	void incChunkBuffers() {
		__sync_add_and_fetch(&chunkBuffersCount, 1);
	}
	void decChunkBuffers() {
		__sync_sub_and_fetch(&chunkBuffersCount, 1);
	}
	
	void addTarPos(u_int64_t pos, int type);
	
	void forcemark_lock() {
		while(__sync_lock_test_and_set(&this->_forcemark_lock, 1));
	}
	void forcemark_unlock() {
		__sync_lock_release(&this->_forcemark_lock);
	}
	
	void shift_destroy_call_at(pcap_pkthdr *header, int lastSIPresponseNum = 0) {
		if(this->destroy_call_at > 0) {
			time_t new_destroy_call_at = 
				this->seenbyeandok ?
					header->ts.tv_sec + 5 :
				this->seenbye ?
					header->ts.tv_sec + 60 :
					header->ts.tv_sec + (lastSIPresponseNum == 487 || this->lastSIPresponseNum == 487 ? 15 : 5);
			if(new_destroy_call_at > this->destroy_call_at) {
				this->destroy_call_at = new_destroy_call_at;
			}
		}
	}

private:
	ip_port_call_info ip_port[MAX_IP_PER_CALL];
	PcapDumper pcap;
	PcapDumper pcapSip;
	PcapDumper pcapRtp;
	volatile u_int16_t chunkBuffersCount;
	list<u_int64_t> tarPosSip;
	list<u_int64_t> tarPosRtp;
	list<u_int64_t> tarPosGraph;
public:
	bool error_negative_payload_length;
	bool use_removeRtp;
	volatile int hash_counter;
	volatile bool use_rtcp_mux;
	bool rtp_from_multiple_sensors;
	volatile int in_preprocess_queue_before_process_packet;
	volatile u_int32_t in_preprocess_queue_before_process_packet_at;
};

typedef struct {
	Call *call;
	int is_rtcp;
	s_sdp_flags sdp_flags;
	int iscaller;
} Ipportnode;


/**
  * This class implements operations on Call list
*/
class Calltable {
private:
	struct sAudioQueueThread {
		sAudioQueueThread() {
			thread_handle = 0;
			thread_id = 0;
		}
		pthread_t thread_handle;
		int thread_id;
	};
public:
	deque<Call*> calls_queue; //!< this queue is used for asynchronous storing CDR by the worker thread
	deque<Call*> audio_queue; //!< this queue is used for asynchronous audio convert by the worker thread
	deque<Call*> calls_deletequeue; //!< this queue is used for asynchronous storing CDR by the worker thread
	queue<string> files_queue; //!< this queue is used for asynchronous storing CDR by the worker thread
	queue<string> files_sqlqueue; //!< this queue is used for asynchronous storing CDR by the worker thread
	list<Call*> calls_list; //!< 
	list<Call*>::iterator call;
	map<string, Call*> calls_listMAP; //!< 
	map<string, Call*>::iterator callMAPIT; //!< 
	map<string, Call*> calls_mergeMAP; //!< 
	map<string, Call*>::iterator mergeMAPIT; //!< 
	map<string, Call*> skinny_ipTuples; //!< 
	map<string, Call*>::iterator skinny_ipTuplesIT; //!< 
	map<unsigned int, Call*> skinny_partyID; //!< 
	map<unsigned int, Call*>::iterator skinny_partyIDIT; //!< 
	map<unsigned int, Ipportnode*>::iterator ipportmapIT;

	/**
	 * @brief constructor
	 *
	*/
	Calltable();
	/*
	Calltable() { 
		pthread_mutex_init(&qlock, NULL); 
		printf("SS:%d\n", sizeof(calls_hash));
		printf("SS:%s\n", 1);
		memset(calls_hash, 0x0, sizeof(calls_hash) * MAXNODE);
	};
	*/

	/**
	 * destructor
	 * 
	*/
	~Calltable();

	/**
	 * @brief lock calls_queue structure 
	 *
	*/
	void lock_calls_queue() { pthread_mutex_lock(&qlock); };
	void lock_calls_audioqueue() { pthread_mutex_lock(&qaudiolock); };
	void lock_calls_deletequeue() { pthread_mutex_lock(&qdellock); };
	void lock_files_queue() { pthread_mutex_lock(&flock); };
	void lock_calls_listMAP() {
		unsigned usleepCounter = 0;
		while(__sync_lock_test_and_set(&this->_sync_lock_calls_listMAP, 1)) {
			usleep(10 *
			       (usleepCounter > 10 ? 50 :
				usleepCounter > 5 ? 10 :
				usleepCounter > 2 ? 5 : 1));
			++usleepCounter;
		}
	}
	void lock_calls_mergeMAP() {
		unsigned usleepCounter = 0;
		while(__sync_lock_test_and_set(&this->_sync_lock_calls_mergeMAP, 1)) {
			usleep(10 *
			       (usleepCounter > 10 ? 50 :
				usleepCounter > 5 ? 10 :
				usleepCounter > 2 ? 5 : 1));
			++usleepCounter;
		}
	}

	/**
	 * @brief unlock calls_queue structure 
	 *
	*/
	void unlock_calls_queue() { pthread_mutex_unlock(&qlock); };
	void unlock_calls_audioqueue() { pthread_mutex_unlock(&qaudiolock); };
	void unlock_calls_deletequeue() { pthread_mutex_unlock(&qdellock); };
	void unlock_files_queue() { pthread_mutex_unlock(&flock); };
	void unlock_calls_listMAP() {
		__sync_lock_release(&this->_sync_lock_calls_listMAP);
	}
	void unlock_calls_mergeMAP() {
		__sync_lock_release(&this->_sync_lock_calls_mergeMAP);
	}
	/**
	 * @brief lock files_queue structure 
	 *
	*/

	/**
	 * @brief add Call to Calltable
	 *
	 * @param call_id unique identifier of the Call which is parsed from the SIP packets
	 * @param call_id_len lenght of the call_id buffer
	 * @param time timestamp of arrivel packet in seconds from UNIX epoch
	 *
	 * @return reference of the new Call class
	*/
	Call *add(char *call_id, unsigned long call_id_len, time_t time, u_int32_t saddr, unsigned short port, pcap_t *handle, int dlt, int sensorId, bool preprocess_queue = false);

	/**
	 * @brief find Call by call_id
	 *
	 * @param call_id unique identifier of the Call which is parsed from the SIP packets
	 * @param call_id_len lenght of the call_id buffer
	 *
	 * @return reference of the Call if found, otherwise return NULL
	*/
	Call *find_by_call_id(char *call_id, unsigned long call_id_len, bool preprocess_queue = false, int *call_type = NULL) {
		Call *rslt_call = NULL;
		string call_idS = string(call_id, call_id_len);
		lock_calls_listMAP();
		callMAPIT = calls_listMAP.find(call_idS);
		if(callMAPIT != calls_listMAP.end() &&
		   !callMAPIT->second->end_call) {
			rslt_call = callMAPIT->second;
			if(call_type) {
				*call_type = rslt_call->type;
			}
			if(preprocess_queue && rslt_call->type != REGISTER) {
				__sync_add_and_fetch(&rslt_call->in_preprocess_queue_before_process_packet, 1);
			}
		}
		unlock_calls_listMAP();
		return(rslt_call);
	}
	Call *find_by_mergecall_id(char *call_id, unsigned long call_id_len, bool preprocess_queue = false, int *call_type = NULL) {
		Call *rslt_call = NULL;
		string call_idS = string(call_id, call_id_len);
		lock_calls_mergeMAP();
		mergeMAPIT = calls_mergeMAP.find(call_idS);
		if(mergeMAPIT != calls_mergeMAP.end() &&
		   !mergeMAPIT->second->end_call) {
			rslt_call = mergeMAPIT->second;
			if(call_type) {
				*call_type = rslt_call->type;
			}
			if(preprocess_queue && rslt_call->type != REGISTER) {
				__sync_add_and_fetch(&rslt_call->in_preprocess_queue_before_process_packet, 1);
			}
		}
		unlock_calls_mergeMAP();
		return(rslt_call);
	}
	Call *find_by_skinny_partyid(unsigned int partyid);
	Call *find_by_skinny_ipTuples(unsigned int saddr, unsigned int daddr);

	/**
	 * @brief find Call by IP adress and port number
	 *
	 * @param addr IP address of the packet
	 * @param port port number of the packet
	 *
	 * @return reference of the Call if found, otherwise return NULL
	*/
	Call *find_by_ip_port(in_addr_t addr, unsigned short port, int *iscaller);

	/**
	 * @brief Save inactive calls to MySQL and delete it from list
	 *
	 *
	 * walk this list of Calls and if any of the call is inactive more
	 * than 5 minutes, save it to MySQL and delete it from the list
	 *
	 * @param cuutime current time
	 *
	 * @return reference of the Call if found, otherwise return NULL
	*/
	int cleanup( time_t currtime );

	/**
	 * @brief add call to hash table
	 *
	*/
	void hashAdd(in_addr_t addr, unsigned short port, Call* call, int iscaller, int isrtcp, s_sdp_flags sdp_flags, int allowrelation);


	/**
	 * @brief find call
	 *
	*/
	hash_node_call *hashfind_by_ip_port(in_addr_t addr, unsigned short port, unsigned int hash = 0, bool lock = true);

	/**
	 * @brief remove call from hash
	 *
	*/
	void hashRemove(Call *call, in_addr_t addr, unsigned short port, bool rtcp = false);
	int hashRemove(Call *call);
	
	void processCallsInAudioQueue(bool lock = true);
	static void *processAudioQueueThread(void *);
	size_t getCountAudioQueueThreads() {
		return(audioQueueThreads.size());
	}
	void setAudioQueueTerminating() {
		audioQueueTerminating = 1;
	}

	void destroyCallsIfPcapsClosed();
	
	void lock_calls_hash() {
		unsigned usleepCounter = 0;
		while(__sync_lock_test_and_set(&this->_sync_lock_calls_hash, 1)) {
			usleep(10 *
			       (usleepCounter > 10 ? 50 :
				usleepCounter > 5 ? 10 :
				usleepCounter > 2 ? 5 : 1));
			++usleepCounter;
		}
	}
	void unlock_calls_hash() {
		__sync_lock_release(&this->_sync_lock_calls_hash);
	}
private:
	pthread_mutex_t qlock;		//!< mutex locking calls_queue
	pthread_mutex_t qaudiolock;	//!< mutex locking calls_audioqueue
	pthread_mutex_t qdellock;	//!< mutex locking calls_deletequeue
	pthread_mutex_t flock;		//!< mutex locking calls_queue

	void *calls_hash[MAXNODE];
	volatile int _sync_lock_calls_hash;
	volatile int _sync_lock_calls_listMAP;
	volatile int _sync_lock_calls_mergeMAP;
	
	list<sAudioQueueThread*> audioQueueThreads;
	unsigned int audioQueueThreadsMax;
	int audioQueueTerminating;
};


inline unsigned int tuplehash(u_int32_t addr, u_int16_t port) {
	unsigned int key;

	key = (unsigned int)(addr * port);
	key += ~(key << 15);
	key ^=  (key >> 10);
	key +=  (key << 3);
	key ^=  (key >> 6);
	key += ~(key << 11);
	key ^=  (key >> 16);
	return key % MAXNODE;
}


class CustomHeaders {
public:
	enum eType {
		cdr,
		message
	};
	struct sCustomHeaderData {
		string header;
		string leftBorder;
		string rightBorder;
		string regularExpression;
	};
	struct sCustomHeaderDataPlus : public sCustomHeaderData {
		string type;
		int dynamic_table;
		int dynamic_column;
	};
public:
	CustomHeaders(eType type);
	void load(class SqlDb *sqlDb = NULL, bool lock = true);
	void clear(bool lock = true);
	void refresh(SqlDb *sqlDb = NULL);
	void addToStdParse(ParsePacket *parsePacket);
	void parse(Call *call, char *data, int datalen, ParsePacket *parsePacket);
	void setCustomHeaderContent(Call *call, int pos1, int pos2, dstring *content);
	void prepareSaveRows_cdr(Call *call, class SqlDb_row *cdr_next, class SqlDb_row cdr_next_ch[], char *cdr_next_ch_name[]);
	void prepareSaveRows_message(Call *call, class SqlDb_row *message, class SqlDb_row message_next_ch[], char *message_next_ch_name[]);
	string getDeleteQuery(const char *id, const char *prefix, const char *suffix);
	list<string> getAllNextTables() {
		return(allNextTables);
	}
	list<string> *getAllNextTablesPointer() {
		return(&allNextTables);
	}
	void createMysqlPartitions(class SqlDb *sqlDb);
	unsigned long getLoadTime() {
		return(loadTime);
	}
	string getQueryForSaveUseInfo(Call *call);
	void createTablesIfNotExists(SqlDb *sqlDb);
	void createTableIfNotExists(const char *tableName, SqlDb *sqlDb = NULL);
	void createColumnsForFixedHeaders(SqlDb *sqlDb = NULL);
private:
	void lock_custom_headers() {
		while(__sync_lock_test_and_set(&this->_sync_custom_headers, 1));
	}
	void unlock_custom_headers() {
		__sync_lock_release(&this->_sync_custom_headers);
	}
private:
	eType type;
	string configTable;
	string nextTablePrefix;
	string fixedTable;
	map<int, map<int, sCustomHeaderData> > custom_headers;
	list<string> allNextTables;
	unsigned loadTime;
	unsigned lastTimeSaveUseInfo;
	volatile int _sync_custom_headers;
};


int sip_request_name_to_int(const char *requestName, bool withResponse = false);
const char *sip_request_int_to_name(int requestCode, bool withResponse = false);


#endif
