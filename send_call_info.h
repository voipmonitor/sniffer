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
	string called_number;
	string callername;
	string caller_domain;
	string called_domain;
	vmIP caller_ip;
	vmIP called_ip;
	u_int64_t at;
};

class SendCallInfoItem {
public:
	enum eRequestType {
		rt_get,
		rt_post
	};
public:
	SendCallInfoItem(unsigned int dbId);
	bool load(SqlDb *sqlDb = NULL);
	void evSci(sSciInfo *sci);
private:
	unsigned int dbId;
	SqlDb_row dbRow;
	string name;
	u_int8_t infoOn;
	string requestUrl;
	eRequestType requestType;
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
	void evCall(class Call *call, eTypeSci typeSci, u_int64_t at);
private:
	void initPopCallInfoThread();
	void popCallInfoThread();
	void getSciFromCall(sSciInfo *sciInfo, Call *call, 
			    eTypeSci typeSci, u_int64_t at);
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
void refreshSendCallInfo();
void sendCallInfoEvCall(Call *call, eTypeSci typeSci, struct timeval tv);
bool isExistsSendCallInfo(SqlDb *sqlDb = NULL);


#endif
