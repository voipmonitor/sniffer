#ifndef MGCP_H
#define MGCP_H


#include <string>

#include "tools.h"


enum eMgcpRequestType {
	_mgcp_na,
	_mgcp_EPCF,
	_mgcp_CRCX,
	_mgcp_MDCX,
	_mgcp_DLCX,
	_mgcp_RQNT,
	_mgcp_NTFY,
	_mgcp_AUEP,
	_mgcp_AUCX,
	_mgcp_RSIP,
	_mgcp_MESG
};

struct sMgcpRequestType {
	eMgcpRequestType type;
	const char *string;
	const char *description;
};

struct sMgcpParameters {
	sMgcpParameters() {
	}
	bool is_set() {
		return(!call_id.empty() ||
		       !requested_events.empty() ||
		       !connection_mode.empty());
	}
	void debug_output();
	std::string call_id;
	std::string requested_events;
	std::string connection_mode;
};

struct sMgcpRequest {
	sMgcpRequest() {
		type = _mgcp_na;
		transaction_id = 0;
		version_prefix_ok = false;
	}
	bool is_set() {
		return(type != _mgcp_na && transaction_id);
	}
	bool is_set_call_id() {
		return(!parameters.call_id.empty());
	}
	string call_id() {
		return("MGCP#" + parameters.call_id + "/" + intToString(transaction_id));
	}
	void debug_output(const char *firstLineSuffix);
	eMgcpRequestType type;
	u_int32_t transaction_id;
	std::string endpoint;
	bool version_prefix_ok;
	std::string version;
	sMgcpParameters parameters;
	u_int64_t time;
};

struct sMgcpResponse {
	sMgcpResponse() {
		code = -1;
		transaction_id = 0;
	}
	bool is_set() {
		return(code >= 0 && transaction_id);
	}
	void debug_output();
	int code;
	u_int32_t transaction_id;
	std::string response;
	sMgcpParameters parameters;
	u_int64_t time;
};

struct sMgcpRequestResponse {
	u_int64_t request_time;
	
	u_int64_t response_time;
};

eMgcpRequestType check_mgcp_request(char *data, unsigned long len);
int check_mgcp_response(char *data, unsigned long len);
bool check_mgcp(char *data, unsigned long len);

void *handle_mgcp(struct packet_s_process *packetS);


#endif
