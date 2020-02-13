#ifndef CLOUD_ROUTER_CLIENT_H
#define CLOUD_ROUTER_CLIENT_H


#include "cloud_router_base.h"

#include <queue>


class cCR_Receiver_service : public cReceiver {
public:
	cCR_Receiver_service(const char *token, int32_t sensor_id, const char *sensor_string, unsigned sensor_version);
	void setEnableTermninateIfConnectFailed(bool enableTermninateIfConnectFailed = true);
	void setResponseSender(class cCR_ResponseSender *response_sender);
	bool start(string host, u_int16_t port);
	virtual bool receive_process_loop_begin();
	virtual void evData(u_char *data, size_t dataLen);
	string getConnectFrom() {
		return(connect_from);
	}
	bool get_use_mysql_set_id() {
		return(use_mysql_set_id);
	}
protected:
	string token;
	int32_t sensor_id;
	string sensor_string;
	unsigned sensor_version;
	bool enableTermninateIfConnectFailed;
	string host;
	u_int16_t port;
	bool connection_ok;
	string connect_from;
	bool use_mysql_set_id;
	cCR_ResponseSender *response_sender;
};

class cCR_Client_response : public cClient {
public:
	cCR_Client_response(string gui_task_id, string command, cCR_ResponseSender *response_sender = NULL);
	bool start(string host, u_int16_t port);
	virtual void client_process();
protected:
	string gui_task_id;
	string command;
	cCR_ResponseSender *response_sender;
};

class cCR_ResponseSender {
private:
	struct sDataForSend {
		string task_id;
		SimpleBuffer *buffer;
	};
public:
	cCR_ResponseSender();
	~cCR_ResponseSender();
	void add(string task_id, SimpleBuffer *buffer);
	void start(string host, u_int16_t port, string token);
	void stop();
	static void *sendProcess(void*);
	void sendProcess();
private:
	void lock_data() {
		while(__sync_lock_test_and_set(&_sync_data, 1)) {
			USLEEP(10);
		}
	}
	void unlock_data() {
		__sync_lock_release(&_sync_data);
	}
private:
	string host;
	u_int16_t port;
	string token;
	volatile bool terminate;
	cSocketBlock *socket;
	pthread_t send_process_thread;
	queue<sDataForSend> data_for_send;
	volatile int _sync_data;
};


#endif //CLOUD_ROUTER_CLIENT_H
