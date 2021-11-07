#ifndef SEND_CALL_INFO_H
#define SEND_CALL_INFO_H


#include "tools.h"
#include "sql_db.h"


enum eTypeSci {
	sci_18X = (1 << 0),
	sci_200 = (1 << 1),
	sci_invite = (1 << 2),
	sci_hangup = (1 << 3)
};

struct sSciPacketInfo {
	string caller_number;
	string called_number_to;
	string called_number_uri;
	string callername;
	string caller_domain;
	string called_domain_to;
	string called_domain_uri;
	vmIP src_ip;
	vmIP dst_ip;
	vmPort src_port;
	vmPort dst_port;
};

struct sSciInfo {
	sSciInfo() {
		typeSci = 0;
		caller_ip.clear();
		called_ip.clear();
		at = 0;
	}
	u_int8_t typeSci;
	string callid;
	string caller_number;
	string called_number_to;
	string called_number_uri;
	string called_number_final;
	string callername;
	string caller_domain;
	string called_domain_to;
	string called_domain_uri;
	string called_domain_final;
	vmIP caller_ip;
	vmIP called_ip;
	u_int64_t at;
	u_int16_t counter;
	sSciPacketInfo packet_info;
	bool packet_info_set;
};

class SendCallInfoItem {
public:
	enum eInfoOnMatch {
		iom_first,
		iom_all
	};
	enum eRequestType {
		rt_get,
		rt_post,
		rt_json
	};
	enum eCalledSrc {
		cs_default,
		cs_to,
		cs_uri
	};
public:
	SendCallInfoItem(unsigned int dbId);
	bool load(SqlDb *sqlDb = NULL);
	void evSci(sSciInfo *sci);
	string called_number(sSciInfo *sci) {
		return(calledNumberSrc == cs_to && !sci->called_number_to.empty() ? sci->called_number_to :
		       calledNumberSrc == cs_uri && !sci->called_number_uri.empty() ? sci->called_number_uri : sci->called_number_final);
	}
	string called_domain(sSciInfo *sci) {
		return(calledDomainSrc == cs_to && !sci->called_domain_to.empty() ? sci->called_domain_to :
		       calledDomainSrc == cs_uri && !sci->called_domain_uri.empty() ? sci->called_domain_uri : sci->called_domain_final);
	}
private:
	unsigned int dbId;
	SqlDb_row dbRow;
	string name;
	u_int8_t infoOn;
	eInfoOnMatch infoOnMatch;
	string requestUrl;
	eRequestType requestType;
	bool suppressParametersEncoding;
	eCalledSrc calledNumberSrc;
	eCalledSrc calledDomainSrc;
	bool additionalPacketInformation;
	bool jsonOutput;
	string authUser;
	string authPassword;
	vector<dstring> headers;
	vector<dstring> fields;
	ListIP_wb ipCallerFilter;
	ListIP_wb ipCalledFilter;
	ListPhoneNumber_wb phoneNumberCallerFilter;
	ListPhoneNumber_wb phoneNumberCalledFilter;
	ListCheckString_wb domainCallerFilter;
	ListCheckString_wb domainCalledFilter;
};

class SendCallInfo {
public:
	SendCallInfo();
	~SendCallInfo();
	void load(bool lock = true);
	void clear(bool lock = true);
	void refresh();
	void stopPopCallInfoThread(bool wait = false);
	void evCall(class Call *call, eTypeSci typeSci, u_int64_t at, u_int16_t counter, sSciPacketInfo *packet_info);
private:
	void initPopCallInfoThread();
	void popCallInfoThread();
	void getSciFromCall(sSciInfo *sciInfo, Call *call, 
			    eTypeSci typeSci, u_int64_t at,
			    u_int16_t counter, sSciPacketInfo *packet_info);
	void lock() {
		while(__sync_lock_test_and_set(&this->_sync, 1));
	}
	void unlock() {
		__sync_lock_release(&this->_sync);
	}
private:
	list<SendCallInfoItem*> listSci;
	SafeAsyncQueue<sSciInfo> sciQueue;
	pthread_t threadPopCallInfo;
	bool runPopCallInfoThread;
	bool termPopCallInfoThread;
	volatile int _sync;
friend void *_SendCallInfo_popCallInfoThread(void *arg);
};


void initSendCallInfo(SqlDb *sqlDb = NULL);
void termSendCallInfo();
inline bool isSendCallInfoReady() {
	extern volatile int _sendCallInfo_ready;
	return(_sendCallInfo_ready);
}
inline bool useAdditionalPacketInformationInSendCallInfo() {
	extern volatile int _sendCallInfo_useAdditionalPacketInformation;
	return(_sendCallInfo_useAdditionalPacketInformation);
}
void refreshSendCallInfo();
void sendCallInfoEvCall(Call *call, eTypeSci typeSci, struct timeval tv, u_int16_t counter, sSciPacketInfo *packet_info);
bool isExistsSendCallInfo(SqlDb *sqlDb = NULL);


#endif
