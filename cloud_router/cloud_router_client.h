#ifndef CLOUD_ROUTER_CLIENT_H
#define CLOUD_ROUTER_CLIENT_H


#include "cloud_router_base.h"


class cCR_Receiver_service : public cReceiver {
public:
	cCR_Receiver_service(const char *token, int32_t sensor_id, const char *sensor_string, unsigned sensor_version);
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
	string host;
	u_int16_t port;
	bool connection_ok;
	string connect_from;
	bool use_mysql_set_id;
};

class cCR_Client_response : public cClient {
public:
	cCR_Client_response(string gui_task_id, string command);
	bool start(string host, u_int16_t port);
	virtual void client_process();
protected:
	string gui_task_id;
	string command;
};


#endif //CLOUD_ROUTER_CLIENT_H
