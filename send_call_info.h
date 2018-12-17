#ifndef SEND_CALL_INFO_H
#define SEND_CALL_INFO_H


#include "tools.h"
#include "sql_db.h"


struct sSciInfo {
	enum eTypeSci {
		sci_18X,
		sci_200,
		sci_invite
	};
	sSciInfo() {
		typeSci = (eTypeSci)0;
		caller_ip = 0;
		called_ip = 0;
		at = 0;
	}
	eTypeSci typeSci;
	string callid;
	string caller_number;
	string called_number;
	u_int32_t caller_ip;
	u_int32_t called_ip;
	u_int64_t at;
};

class SendCallInfoItem {
public:
	enum eInfoOn {
		infoOn_183_180,
		infoOn_200, 
		infoOn_183_180_200,
		infoOn_invite
	};
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
	eInfoOn infoOn;
	string requestUrl;
	eRequestType requestType;
	ListIP_wb ipCallerFilter;
	ListIP_wb ipCalledFilter;
	ListPhoneNumber_wb phoneNumberCallerFilter;
	ListPhoneNumber_wb phoneNumberCalledFilter;
};

class SendCallInfo {
public:
	SendCallInfo();
	~SendCallInfo();
	void load(bool lock = true);
	void clear(bool lock = true);
	void refresh();
	void stopPopCallInfoThread(bool wait = false);
	void evCall(class Call *call, sSciInfo::eTypeSci typeSci, u_int64_t at);
private:
	void initPopCallInfoThread();
	void popCallInfoThread();
	void getSciFromCall(sSciInfo *sciInfo, Call *call, 
			    sSciInfo::eTypeSci typeSci, u_int64_t at);
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
void sendCallInfoEvCall(Call *call, sSciInfo::eTypeSci typeSci, struct timeval tv);
bool isExistsSendCallInfo(SqlDb *sqlDb = NULL);


#endif
