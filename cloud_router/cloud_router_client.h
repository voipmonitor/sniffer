#ifndef CLOUD_ROUTER_CLIENT_H
#define CLOUD_ROUTER_CLIENT_H


#include "cloud_router_base.h"


class cCR_Receiver_service : public cReceiver {
public:
	cCR_Receiver_service(const char *token, int32_t sensor_id);
	bool start(string host, u_int16_t port);
	virtual bool receive_process_loop_begin();
	virtual void evData(u_char *data, size_t dataLen);
protected:
	string token;
	int32_t sensor_id;
	string host;
	u_int16_t port;
	bool connection_ok;
};

class cCR_Client_response : public cClient {
public:
	cCR_Client_response(const char *command, u_int64_t gui_task_id);
	bool start(string host, u_int16_t port);
	virtual void client_process();
	bool write(u_char *data, size_t dataLen);
	bool writeEnc(u_char *data, size_t dataLen, const char *key);
protected:
	string command;
	u_int64_t gui_task_id;
};


#endif //CLOUD_ROUTER_CLIENT_H
