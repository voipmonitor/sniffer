#include "cloud_router_client.h"

#include <iostream>
#include <sstream>
#include <syslog.h>
#include <stdlib.h>
#include <math.h>


extern sCloudRouterVerbose& CR_VERBOSE();
extern void CR_SET_TERMINATE();


cCR_Receiver_service::cCR_Receiver_service(const char *token, int32_t sensor_id) {
	this->token = token;
	this->sensor_id = sensor_id;
	port = 0;
	connection_ok = false;
}

bool cCR_Receiver_service::start(string host, u_int16_t port) {
	this->host = host;
	this->port = port;
	_receive_start();
	return(true);
}

bool cCR_Receiver_service::receive_process_loop_begin() {
	if(connection_ok) {
		if(receive_socket->isError()) {
			_close();
			connection_ok = false;
		} else {
			return(true);
		}
	}
	if(!receive_socket) {
		_connect(host, port, 5);
	}
	if(!receive_socket) {
		return(false);
	}
	string connectCmd = "{\"type_connection\":\"sniffer_service\"}\r\n";
	if(!receive_socket->write(connectCmd)) {
		if(!receive_socket->isError()) {
			receive_socket->setError("failed send command sniffer_service");
		}
		_close();
		return(false);
	}
	string rsltRsaKeyIP;
	if(!receive_socket->readBlock(&rsltRsaKeyIP) || rsltRsaKeyIP.find("rsa_key") == string::npos) {
		if(!receive_socket->isError()) {
			receive_socket->setError("failed read rsa key");
		}
		_close();
		return(false);
	}
	JsonItem jsonRsaKey;
	jsonRsaKey.parse(rsltRsaKeyIP);
	string rsa_key = jsonRsaKey.getValue("rsa_key");
	connect_from = jsonRsaKey.getValue("ip");
	receive_socket->set_rsa_pub_key(rsa_key);
	receive_socket->generate_aes_keys();
	JsonExport json_keys;
	json_keys.add("token", token);
	json_keys.add("sensor_id", sensor_id);
	string aes_ckey, aes_ivec;
	receive_socket->get_aes_keys(&aes_ckey, &aes_ivec);
	json_keys.add("aes_ckey", aes_ckey);
	json_keys.add("aes_ivec", aes_ivec);
	if(start_ok) {
		json_keys.add("restore", true);
	}
	json_keys.add("check_ping_response", true);
	if(!receive_socket->writeBlock(json_keys.getJson(), cSocket::_te_rsa)) {
		if(!receive_socket->isError()) {
			receive_socket->setError("failed send token & aes keys");
		}
		_close();
		return(false);
	}
	string rsltConnectData;
	if(!receive_socket->readBlock(&rsltConnectData) || rsltConnectData != "OK") {
		if(!receive_socket->isError()) {
			receive_socket->setError(rsltConnectData != "OK" ? rsltConnectData.c_str() : "failed read ok");
			if(rsltConnectData != "OK" && !start_ok) {
				CR_SET_TERMINATE();
			}
		}
		_close();
		return(false);
	}
	connection_ok = true;
	if(CR_VERBOSE().start_client) {
		ostringstream verbstr;
		verbstr << "connection to cloud established";
		syslog(LOG_INFO, "%s", verbstr.str().c_str());
	}
	return(true);
}

void cCR_Receiver_service::evData(u_char *data, size_t dataLen) {
	receive_socket->writeBlock("OK");
	string idCommand = string((char*)data, dataLen);
	size_t idCommandSeparatorPos = idCommand.find('/'); 
	if(idCommandSeparatorPos != string::npos) {
		cCR_Client_response *response = new cCR_Client_response(idCommand.substr(0, idCommandSeparatorPos), idCommand.substr(idCommandSeparatorPos + 1));
		response->start(receive_socket->getHost(), receive_socket->getPort());
	}
}


cCR_Client_response::cCR_Client_response(string gui_task_id, string command) {
	this->gui_task_id = gui_task_id;
	this->command = command;
}

bool cCR_Client_response::start(string host, u_int16_t port) {
	if(!_connect(host, port)) {
		return(false);
	}
	string connectCmd = "{\"type_connection\":\"sniffer_response\",\"gui_task_id\":\"" + gui_task_id + "\"}\r\n";
	if(!client_socket->write(connectCmd)) {
		delete client_socket;
		client_socket = NULL;
		return(false);
	}
	_client_start();
	return(true);
	
}

void cCR_Client_response::client_process() {
	extern int parse_command(string cmd, int client, cClient *c_client);
	parse_command(command, 0, this);
	client_socket->writeAesEnc(NULL, 0, true);
	delete this;
}
