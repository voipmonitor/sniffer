#include "cloud_router_client.h"

#include <iostream>
#include <sstream>
#include <syslog.h>
#include <stdlib.h>
#include <math.h>


extern sCloudRouterVerbose& CR_VERBOSE();
extern void CR_SET_TERMINATE();


cCR_Receiver_service::cCR_Receiver_service(const char *token, int32_t sensor_id, const char *sensor_string, unsigned sensor_version) {
	this->token = token;
	this->sensor_id = sensor_id;
	this->sensor_string = sensor_string ? sensor_string : "";
	this->sensor_version = sensor_version;
	enableTermninateIfConnectFailed = false;
	port = 0;
	connection_ok = false;
	use_mysql_set_id = false;
	response_sender = NULL;
}

void cCR_Receiver_service::setEnableTermninateIfConnectFailed(bool enableTermninateIfConnectFailed) {
	this->enableTermninateIfConnectFailed = enableTermninateIfConnectFailed;
}

void cCR_Receiver_service::setResponseSender(cCR_ResponseSender *response_sender) {
	this->response_sender = response_sender;
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
	if(!sensor_string.empty()) {
		json_keys.add("sensor_string", sensor_string);
	}
	string aes_ckey, aes_ivec;
	receive_socket->get_aes_keys(&aes_ckey, &aes_ivec);
	json_keys.add("aes_ckey", aes_ckey);
	json_keys.add("aes_ivec", aes_ivec);
	json_keys.add("sensor_version", sensor_version);
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
	if(!receive_socket->readBlock(&rsltConnectData) || receive_socket->isError()) {
		_close();
		return(false);
	}
	bool rsltIsOK = false;
	string rsltError;
	if(!rsltConnectData.empty()) {
		if(rsltConnectData[0] == '{' && rsltConnectData[rsltConnectData.length() - 1] == '}') {
			JsonItem jsonResult;
			jsonResult.parse(rsltConnectData);
			if(jsonResult.getValue("result") == "OK") {
				rsltIsOK = true;
				use_mysql_set_id = atoi(jsonResult.getValue("use_mysql_set_id").c_str());
			} else {
				rsltError = jsonResult.getValue("error");
			}
		} else if(rsltConnectData == "OK") {
			rsltIsOK = true;
		} else {
			rsltError = rsltConnectData;
		}
	}
	if(!rsltIsOK) {
		if(rsltError.empty()) {
			rsltError = "failed read ok";
		}
		receive_socket->setError(rsltError.c_str());
		if(!start_ok && enableTermninateIfConnectFailed) {
			CR_SET_TERMINATE();
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
		cCR_Client_response *response = new FILE_LINE(0) cCR_Client_response(
				idCommand.substr(0, idCommandSeparatorPos), 
				idCommand.substr(idCommandSeparatorPos + 1),
				response_sender);
		response->start(receive_socket->getHost(), receive_socket->getPort());
	}
}


cCR_Client_response::cCR_Client_response(string gui_task_id, string command, cCR_ResponseSender *response_sender) {
	this->gui_task_id = gui_task_id;
	this->command = command;
	if(command.find("file_exists") != string::npos ||
	   command.find("fileexists") != string::npos) {
		this->response_sender = response_sender;
	} else {
		this->response_sender = NULL;
	}
}

bool cCR_Client_response::start(string host, u_int16_t port) {
	if(response_sender) {
		this->writeToBuffer();
	} else {
		if(!_connect(host, port)) {
			return(false);
		}
	}
	if(!response_sender) {
		string connectCmd = "{\"type_connection\":\"sniffer_response\",\"gui_task_id\":\"" + gui_task_id + "\"}\r\n";
		if(!client_socket->write(connectCmd)) {
			delete client_socket;
			client_socket = NULL;
			return(false);
		}
	}
	_client_start();
	return(true);
	
}

void cCR_Client_response::client_process() {
	extern int parse_command(string cmd, sClientInfo client, cClient *c_client);
	parse_command(command, 0, this);
	if(response_sender) {
		response_sender->add(gui_task_id, buffer);
		buffer = NULL;
	} else {
		client_socket->writeAesEnc(NULL, 0, true);
	}
	delete this;
}


cCR_ResponseSender::cCR_ResponseSender() {
	terminate = false;
	socket = NULL;
	send_process_thread = 0;
	_sync_data = 0;
}

cCR_ResponseSender::~cCR_ResponseSender() {
	stop();
}

void cCR_ResponseSender::add(string task_id, SimpleBuffer *buffer) {
	lock_data();
	sDataForSend data;
	data.task_id = task_id;
	data.buffer = buffer;
	data_for_send.push(data);
	unlock_data();
}

void cCR_ResponseSender::start(string host, u_int16_t port, string token) {
	this->host = host;
	this->port = port;
	this->token = token;
	vm_pthread_create("cCR_ResponseSender::start", &send_process_thread, NULL, cCR_ResponseSender::sendProcess, this, __FILE__, __LINE__);
}

void cCR_ResponseSender::stop() {
	terminate = true;
	if(send_process_thread) {
		pthread_join(send_process_thread, NULL);
		send_process_thread = 0;
	}
}

void *cCR_ResponseSender::sendProcess(void *arg) {
	((cCR_ResponseSender*)arg)->sendProcess();
	return(NULL);
}

void cCR_ResponseSender::sendProcess() {
	u_int64_t lastTimeOkSend_ms = 0;
	while(!terminate) {
		lock_data();
		unsigned data_for_send_size = data_for_send.size();
		unlock_data();
		if(!data_for_send_size) {
			USLEEP(100000);
			continue;
		}
		if(!socket) {
			socket = new FILE_LINE(0) cSocketBlock("sniffer response", true);
			socket->setHostPort(host, port);
			if(!socket->connect()) {
				delete socket;
				socket = NULL;
				// log "failed connect"
				sleep(5);
				continue;
			}
			string cmd = "{\"type_connection\":\"sniffer_responses\"}\r\n";
			if(!socket->write(cmd)) {
				delete socket;
				socket = NULL;
				// log "failed send command"
				sleep(1);
				continue;
			}
			string rsltRsaKey;
			if(!socket->readBlock(&rsltRsaKey) || rsltRsaKey.find("key") == string::npos) {
				delete socket;
				socket = NULL;
				// log "failed read rsa key"
				sleep(1);
				continue;
			}
			JsonItem jsonRsaKey;
			jsonRsaKey.parse(rsltRsaKey);
			string rsa_key = jsonRsaKey.getValue("rsa_key");
			socket->set_rsa_pub_key(rsa_key);
			socket->generate_aes_keys();
			JsonExport json_keys;
			json_keys.add("token", token);
			string aes_ckey, aes_ivec;
			socket->get_aes_keys(&aes_ckey, &aes_ivec);
			json_keys.add("aes_ckey", aes_ckey);
			json_keys.add("aes_ivec", aes_ivec);
			if(!socket->writeBlock(json_keys.getJson(), cSocket::_te_rsa)) {
				delete socket;
				socket = NULL;
				// log "failed send token & aes keys"
				sleep(1);
				continue;
			}
			string connectResponse;
			if(!socket->readBlock(&connectResponse) || connectResponse != "OK") {
				delete socket;
				socket = NULL;
				// log "failed read response after send token & aes keys"
				sleep(1);
				continue;
			}
		}
		u_int64_t actTime_ms = getTimeMS();
		if(lastTimeOkSend_ms && actTime_ms > lastTimeOkSend_ms &&
		   (actTime_ms - lastTimeOkSend_ms) > (60 - 5) * 1000) {
			if(!socket->checkHandleRead()) {
				delete socket;
				socket = NULL;
				continue;
			}
		}
		sDataForSend data;
		lock_data();
		data = data_for_send.front();
		unlock_data();
		unsigned data_buffer_size = data.task_id.length() + 1 + data.buffer->size();
		u_char *data_buffer = new u_char[data_buffer_size];
		memcpy(data_buffer, data.task_id.c_str(), data.task_id.length());
		memcpy(data_buffer + data.task_id.length(), "#", 1);
		memcpy(data_buffer + data.task_id.length() + 1, data.buffer->data(), data.buffer->size());
		if(!socket->writeBlock(data_buffer,data_buffer_size, cSocket::_te_aes)) {
			delete [] data_buffer;
			delete socket;
			socket = NULL;
			// log "failed write response"
			continue;
		}
		string dataResponse;
		if(!socket->readBlock(&dataResponse, cSocket::_te_aes, "", true) || dataResponse != "OK") {
			if(dataResponse.find("missing gui task id") != string::npos || 
			   dataResponse.find("unknown gui task id") != string::npos) {
				lock_data();
				data_for_send.pop();
				unlock_data();
			}
			delete [] data_buffer;
			delete socket;
			socket = NULL;
			// log "failed read response after send data"
			continue;
		}
		delete data.buffer;
		delete [] data_buffer;
		lock_data();
		data_for_send.pop();
		unlock_data();
		lastTimeOkSend_ms = getTimeMS();
	}
	if(socket) {
		delete socket;
		socket = NULL;
	}
}
