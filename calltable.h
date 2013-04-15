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

#include "rtp.h"

#define MAX_IP_PER_CALL 30	//!< total maxumum of SDP sessions for one call-id
#define MAX_SSRC_PER_CALL 30	//!< total maxumum of SDP sessions for one call-id
#define MAX_CALL_ID 128		//!< max len of stored call-id
#define MAX_FNAME 256		//!< max len of stored call-id
#define MAX_RTPMAP 30          //!< max rtpmap records
#define MAXNODE 150000

#define INVITE 1
#define BYE 2
#define CANCEL 3
#define RES2XX 4
#define RES3XX 5
#define RES401 6
#define RES403 7
#define RES4XX 8
#define RES5XX 9
#define RES6XX 10
#define RES18X 11
#define REGISTER 12
#define MESSAGE 13
#define INFO 14
#define SKINNY_NEW 100

#define FLAG_SAVERTP		(1 << 0)
#define FLAG_SAVESIP		(1 << 1)
#define FLAG_SAVEREGISTER	(1 << 2)
#define FLAG_SAVEWAV		(1 << 3)
#define FLAG_SAVEGRAPH		(1 << 4)

/**
  * This class implements operations on call
*/
class Call {
public:
	int type;			//!< type of call, INVITE or REGISTER
	RTP *rtp[MAX_SSRC_PER_CALL];		//!< array of RTP streams
	unsigned long call_id_len;	//!< length of call-id 	
	char call_id[MAX_CALL_ID];	//!< call-id from SIP session
	char fbasename[MAX_FNAME];	//!< basename of file 
	char fbasename_safe[MAX_FNAME];	//!< basename of file 
	unsigned long long fname2;	//!< basename of file 
	char callername[256];		//!< callerid name from SIP header
	char caller[256];		//!< From: xxx 
	char caller_domain[256];	//!< From: xxx 
	char called[256];		//!< To: xxx
	char called_domain[256];	//!< To: xxx
	char contact_num[64];		//!< 
	char contact_domain[128];	//!< 
	char digest_username[64];	//!< 
	char digest_realm[64];		//!< 
	int register_expires;	
	char byecseq[32];		
	char invitecseq[32];		
	char custom_header1[256];	//!< Custom SIP header
	char match_header[128];	//!< Custom SIP header
	bool seeninvite;		//!< true if we see SIP INVITE within the Call
	bool seeninviteok;			//!< true if we see SIP INVITE within the Call
	bool seenbye;			//!< true if we see SIP BYE within the Call
	bool seenbyeandok;		//!< true if we see SIP OK TO BYE OR TO CANEL within the Call
	bool sighup;			//!< true if call is saving during sighup
	string dirname();		//!< name of the directory to store files for the Call
	char a_ua[1024];		//!< caller user agent 
	char b_ua[1024];		//!< callee user agent 
	int rtpmap[MAX_IP_PER_CALL][MAX_RTPMAP]; //!< rtpmap for every rtp stream
	RTP tmprtp;			//!< temporary structure used to decode information from frame
	RTP *lastcallerrtp;		//!< last RTP stream from caller
	RTP *lastcalledrtp;		//!< last RTP stream from called
	void *calltable;		//!< reference to calltable
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
	unsigned long long flags1;	//!< bit flags used to store max 64 flags 
	volatile unsigned int rtppcaketsinqueue;
	unsigned int unrepliedinvite;
	Call *relationcall;

	time_t progress_time;		//!< time in seconds of 18X response
	time_t first_rtp_time;		//!< time in seconds of first RTP packet
	time_t connect_time;		//!< time in seconds of 200 OK
	time_t last_packet_time;	
	time_t first_packet_time;	
	time_t destroy_call_at;	
	unsigned int first_packet_usec;

	int isfax;

	void *rtp_cur[2];		//!< last RTP structure in direction 0 and 1 (iscaller = 1)
	void *rtp_prev[2];		//!< previouse RTP structure in direction 0 and 1 (iscaller = 1)

	u_int32_t sipcallerip;		//!< SIP signalling source IP address
	u_int32_t sipcalledip;		//!< SIP signalling destination IP address

	u_int32_t sipcallerip2;		//!< SIP signalling destination IP address
	u_int32_t sipcalledip2;		//!< SIP signalling destination IP address
	u_int32_t sipcallerip3;		//!< SIP signalling destination IP address
	u_int32_t sipcalledip3;		//!< SIP signalling destination IP address
	u_int32_t sipcallerip4;		//!< SIP signalling destination IP address
	u_int32_t sipcalledip4;		//!< SIP signalling destination IP address

	char lastSIPresponse[128];
	int lastSIPresponseNum;

	string sip_pcapfilename;
	string rtp_pcapfilename;
	string pcapfilename;

	char *contenttype;
	char *message;

	int last_callercodec;		//!< Last caller codec 
	int last_calledcodec;		//!< Last called codec 

	int fifo1;
	int fifo2;
	int codec_caller;
	int codec_called;

	unsigned int skinny_partyid;

	unsigned int flags;		//!< structure holding FLAGS*

	int *listening_worker_run;

	int thread_num;

	void *listening_worker_args;
	
	int ssrc_n;				//!< last index of rtp array

	string geoposition;

	/**
	 * constructor
	 *
	 * @param call_id unique identification of call parsed from packet
	 * @param call_id_len lenght of the call_id buffer
	 * @param time time of the first packet
	 * @param ct reference to calltable
	 * 
	*/
	Call(char *call_id, unsigned long call_id_len, time_t time, void *ct);

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
	void read_rtp( unsigned char *data, int datalen, struct pcap_pkthdr *header, u_int32_t saddr, u_int32_t daddr, unsigned short port, int iscaller);

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
	void read_rtcp(unsigned char*, int, pcap_pkthdr*, u_int32_t, short unsigned int, int);

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
	int add_ip_port(in_addr_t addr, unsigned short port, char *ua, unsigned long ua_len, bool iscaller, int *rtpmap);

	/**
	 * @brief get file descriptor of the writing pcap file  
	 *
	 * @return file descriptor of the writing pcap file
	*/
	pcap_dumper_t *get_fsip_pcap() { return fsip_pcap; };
	pcap_dumper_t *get_frtp_pcap() { return frtp_pcap; };
	pcap_dumper_t *get_f_pcap() { return f_pcap; };
	
	/**
	 * @brief set file descriptor of the writing pcap file  
	 *
	 * @param file descriptor
	*/
	void set_fsip_pcap(pcap_dumper_t *f_pcap) { this->fsip_pcap = f_pcap; };
	void set_frtp_pcap(pcap_dumper_t *f_pcap) { this->frtp_pcap = f_pcap; };
	void set_f_pcap(pcap_dumper_t *f_pcap) { this->f_pcap = f_pcap; };

	/**
	 * @brief get time of the last seen packet which belongs to this call
	 *
	 * @param f_pcap file descriptor 
	 *
	 * @return time of the last packet in seconds from UNIX epoch
	*/
	time_t get_last_packet_time() { return last_packet_time; };

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
	 * @brief prepare for escape string - connect if need
	 *
	*/
	bool prepareForEscapeString();

#ifdef ISCURL	
	/**
	 * @brief send cdr
	 *
	*/
	string getKeyValCDRtext();
#endif

	/**
	 * @brief save call to database
	 *
	*/
	int saveToDb(bool enableBatchIfPossible = true);

	/**
	 * @brief save register msgs to database
	 *
	*/
	int saveRegisterToDb();

	/**
	 * @brief save sip MSSAGE to database
	 *
	*/
	int saveMessageToDb();

	/**
	 * @brief calculate duration of the call
	 *
	 * @return lenght of the call in seconds
	*/
	int duration() { return last_packet_time - first_packet_time; };
	
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

	/**
	 * @brief remove call from map table
	 *
	*/
	void mapRemove();

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

	void dump();

private:
	in_addr_t addr[MAX_IP_PER_CALL];	//!< IP address from SDP (indexed together with port)
	unsigned short port[MAX_IP_PER_CALL];	//!< port number from SDP (indexed together with IP)
	bool iscaller[MAX_IP_PER_CALL];         //!< is that RTP stream from CALLER party? 
	int ipport_n;				//!< last index of addr and port array 
	pcap_dumper_t *f_pcap;
	pcap_dumper_t *fsip_pcap;
	pcap_dumper_t *frtp_pcap;
};

typedef struct {
	Call *call;
	int is_rtcp;
	int iscaller;
} Ipportnode;


/**
  * This class implements operations on Call list
*/
class Calltable {
public:
	queue<Call*> calls_queue; //!< this queue is used for asynchronous storing CDR by the worker thread
	queue<Call*> calls_deletequeue; //!< this queue is used for asynchronous storing CDR by the worker thread
	queue<string> files_queue; //!< this queue is used for asynchronous storing CDR by the worker thread
	list<Call*> calls_list; //!< 
	list<Call*>::iterator call;
	map<string, Call*> calls_listMAP; //!< 
	map<string, Call*>::iterator callMAPIT; //!< 
	map<unsigned int, Call*> skinny_partyID; //!< 
	map<unsigned int, Call*>::iterator skinny_partyIDIT; //!< 
	map<unsigned int, std::map<unsigned int, Ipportnode*> > ipportmap;
//	map<unsigned int, std::map<unsigned int, Ipportnode*> >::iterator ipportmapIT;
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
	void lock_calls_deletequeue() { pthread_mutex_lock(&qdellock); };
	void lock_files_queue() { pthread_mutex_lock(&flock); };
	void lock_calls_listMAP() { pthread_mutex_lock(&calls_listMAPlock); };

	/**
	 * @brief unlock calls_queue structure 
	 *
	*/
	void unlock_calls_queue() { pthread_mutex_unlock(&qlock); };
	void unlock_calls_deletequeue() { pthread_mutex_unlock(&qdellock); };
	void unlock_files_queue() { pthread_mutex_unlock(&flock); };
	void unlock_calls_listMAP() { pthread_mutex_unlock(&calls_listMAPlock); };
	
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
	Call *add(char *call_id, unsigned long call_id_len, time_t time, u_int32_t saddr, unsigned short port);

	/**
	 * @brief find Call by call_id
	 *
	 * @param call_id unique identifier of the Call which is parsed from the SIP packets
	 * @param call_id_len lenght of the call_id buffer
	 *
	 * @return reference of the Call if found, otherwise return NULL
	*/
	Call *find_by_call_id(char *call_id, unsigned long call_id_len);
	Call *find_by_skinny_partyid(unsigned int partyid);

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
	void hashAdd(in_addr_t addr, unsigned short port, Call* call, int iscaller, int isrtcp, int allowrelation = 0);


	/**
	 * @brief find call
	 *
	*/
	Call *hashfind_by_ip_port(in_addr_t addr, unsigned short port, int *iscaller, int *isrtcp);

	/**
	 * @brief remove call from hash
	 *
	*/
	void hashRemove(in_addr_t addr, unsigned short port);

	/**
	 * @brief find call
	 *
	*/
	Call *mapfind_by_ip_port(in_addr_t addr, unsigned short port, int *iscaller, int *isrtcp);

	/**
	 * @brief add call to map table
	 *
	*/
	void mapAdd(in_addr_t addr, unsigned short port, Call* call, int iscaller, int isrtcp);

	/**
	 * @brief remove call from map
	 *
	*/
	void mapRemove(in_addr_t addr, unsigned short port);
private:
	pthread_mutex_t qlock;		//!< mutex locking calls_queue
	pthread_mutex_t qdellock;	//!< mutex locking calls_deletequeue
	pthread_mutex_t flock;		//!< mutex locking calls_queue
	pthread_mutex_t calls_listMAPlock;
//	pthread_mutexattr_t   calls_listMAPlock_attr;

	struct hash_node {
		Call *call;
		hash_node *next;
		int iscaller;
		u_int32_t addr;
		u_int16_t port;
		u_int16_t is_rtcp;
	};

	void *calls_hash[MAXNODE];

	unsigned int tuplehash(u_int32_t addr, u_int16_t port) {
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
};

#ifdef ISCURL  
int sendCDR(string data);
#endif

#endif
