#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <iomanip>
#include <iostream>
#include <vector>

#include "voipmonitor.h"
#include "tools.h"
#include "mgcp.h"
#include "sniff.h"
#include "calltable.h"
#include "filter_mysql.h"
#include "pcap_queue.h"


using namespace std;


extern void process_sdp(Call *call, packet_s_process *packetS, int iscaller, char *from, unsigned sdplen,
			char *callidstr, char *to, char *branch);
extern void detect_to_extern(packet_s_process *packetS, char *to, unsigned to_length, bool *detected);
extern void detect_branch_extern(packet_s_process *packetS, char *branch, unsigned branch_length, bool *detected);


static bool parse_mgcp_request(sMgcpRequest *request, vector<string> *mgcp_lines);
static bool parse_mgcp_response(sMgcpResponse *response, vector<string> *mgcp_lines);
static bool parse_mgcp_parameters(sMgcpParameters *parameters, vector<string> *mgcp_lines);
static bool parse_mgcp_request(sMgcpRequest *request, const char *mgcp_line);
static bool parse_mgcp_response(sMgcpResponse *response, const char *mgcp_line);
static void parse_mgcp_parameters(sMgcpParameters *parameters, const char *mgcp_line);


extern Calltable *calltable;
extern int verbosity;
extern int opt_saveSIP;
extern int opt_saveRTP;
extern int opt_saveudptl;
extern int opt_saverfc2833;
extern int opt_savewav_force;
extern int opt_pcap_split;
extern int opt_newdir;


sMgcpRequestType mgcpRequestType[] = {
	{ _mgcp_EPCF, "EPCF", "EndpointConfiguration" },
	{ _mgcp_CRCX, "CRCX", "CreateConnection" },
	{ _mgcp_MDCX, "MDCX", "ModifyConnection" },
	{ _mgcp_DLCX, "DLCX", "DeleteConnection" },
	{ _mgcp_RQNT, "RQNT", "NotificationRequest" },
	{ _mgcp_NTFY, "NTFY", "Notify" },
	{ _mgcp_AUEP, "AUEP", "AuditEndpoint" },
	{ _mgcp_AUCX, "AUCX", "AuditConnection" },
	{ _mgcp_RSIP, "RSIP", "RestartInProgress" },
	{ _mgcp_MESG, "MESG", "Message" }
};


eMgcpRequestType getMgcpRequestType(const char *typeString) {
	for(unsigned i = 0; i < sizeof(mgcpRequestType) / sizeof(mgcpRequestType[0]); i++) {
		if(!strcasecmp(typeString, mgcpRequestType[i].string)) {
			return(mgcpRequestType[i].type);
		}
	}
	return(_mgcp_na);
}

string getMgcpRequestTypeString(eMgcpRequestType type, bool description) {
	for(unsigned i = 0; i < sizeof(mgcpRequestType) / sizeof(mgcpRequestType[0]); i++) {
		if(type == mgcpRequestType[i].type) {
			return(description ? mgcpRequestType[i].description : mgcpRequestType[i].string);
		}
	}
	return("");
}


eMgcpRequestType check_mgcp_request(char *data, unsigned long len) {
	if(len < 4) {
		return(_mgcp_na);
	}
	for(unsigned i = 0; i < sizeof(mgcpRequestType) / sizeof(mgcpRequestType[0]); i++) {
		if(!strncmp(data, mgcpRequestType[i].string, 4)) {
			 return(len == 4 || data[4] == ' ' || data[4] == '\t' ?
				 mgcpRequestType[i].type :
				 _mgcp_na);
		}
	}
	return(_mgcp_na);
}

int check_mgcp_response(char *data, unsigned long len) {
	if(len < 3) {
		return(-1);
	}
	for(unsigned i = 0; i < 3; i++) {
		if(!isdigit(data[i])) {
			return(-1);
		}
	}
	return(len == 3 || data[3] == ' ' || data[3] == '\t' ?
		atoi(data) : 
		-1);
}

bool check_mgcp(char *data, unsigned long len) {
	return(check_mgcp_request(data, len) != _mgcp_na ||
	       check_mgcp_response(data, len) >= 0);
}


void *handle_mgcp(packet_s_process *packetS) {
	bool is_request = false;
	bool is_response = false;
	eMgcpRequestType request_type = check_mgcp_request(packetS->data_(), packetS->datalen_());
	int response_code = -1;
	if(request_type != _mgcp_na) {
		is_request = true;
	} else {
		response_code = check_mgcp_response(packetS->data_(), packetS->datalen_());
		if(response_code >= 0) {
			is_response = true;
		}
	}
	if((!is_request && !is_response) ||
	   (is_request && 
	    (request_type == _mgcp_EPCF || request_type == _mgcp_AUEP || request_type == _mgcp_AUCX || request_type == _mgcp_RSIP))) {
		return(NULL);
	}
	int mgcp_header_len = packetS->datalen_();
	u_char *sdp = NULL;
	unsigned sdp_separator_length = 0;
	for(int i = 0; i < 2; i++) {
		sdp = (u_char*)memmem(packetS->data_(), packetS->datalen_(), i == 0 ? "\r\n\r\n" : "\n\n", i == 0 ? 4 : 2);
		if(sdp) {
			sdp_separator_length = i == 0 ? 4 : 2;
			break;
		}
	}
	if(sdp) {
		mgcp_header_len = sdp - (u_char*)packetS->data_();
	}
	vector<string> mgcp_lines = split(string(packetS->data_(), mgcp_header_len).c_str(), "\n", true);
	if(!mgcp_lines.size()) {
		return(NULL);
	}
	sMgcpRequest request;
	sMgcpResponse response;
	if(is_request) {
		parse_mgcp_request(&request, &mgcp_lines);
		if(request.is_set()) {
			request.time = getTimeUS(packetS->header_pt);
		} else {
			return(NULL);
		}
	}
	if(is_response) {
		parse_mgcp_response(&response, &mgcp_lines);
		if(response.is_set()) {
			response.time = getTimeUS(packetS->header_pt);
		} else {
			return(NULL);
		}
	}
	Call *call = NULL;
	if(is_request) {
		if(request.is_set_call_id()) {
			call = calltable->find_by_stream_callid(packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_(), request.parameters.call_id.c_str());
			if(request_type == _mgcp_CRCX) {
				if(call) {
					calltable->lock_calls_listMAP();
					map<sStreamIds2, Call*>::iterator callMAPIT = calltable->calls_by_stream_callid_listMAP.find(sStreamIds2(packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_(), request.parameters.call_id.c_str(), true));
					calltable->calls_by_stream_callid_listMAP.erase(callMAPIT);
					for(unsigned i = 1; i < 100; i++) {
						string call_id_undup = request.call_id() + "_" + intToString(i);
						callMAPIT = calltable->calls_by_stream_callid_listMAP.find(sStreamIds2(packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_(), call_id_undup.c_str(), true));
						if(callMAPIT == calltable->calls_by_stream_callid_listMAP.end()) {
							calltable->calls_by_stream_callid_listMAP[sStreamIds2(packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_(), call_id_undup.c_str(), true)] = call;
							break;
						}
					}
					call->removeFindTables(NULL, true);
					calltable->unlock_calls_listMAP();
				} else {
					calltable->lock_calls_listMAP();
					map<sStreamId, Call*>::iterator callMAPIT = calltable->calls_by_stream_listMAP.find(sStreamId(packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_(), true));
					if(callMAPIT != calltable->calls_by_stream_listMAP.end()) {
						callMAPIT->second->removeFindTables(NULL, true);
					}
					calltable->unlock_calls_listMAP();
				}
				unsigned long int flags = 0;
				set_global_flags(flags);
				IPfilter::add_call_flags(&flags, packetS->saddr_(), packetS->daddr_());
				if(flags & FLAG_SKIPCDR) {
					if(verbosity > 1)
						syslog(LOG_NOTICE, "call skipped due to ip or tel capture rules\n");
					return NULL;
				}       
				call = calltable->add_mgcp(&request, packetS->header_pt->ts.tv_sec, packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_(),
							   get_pcap_handle(packetS->handle_index), packetS->dlt, packetS->sensor_id_());
				call->set_first_packet_time_us(getTimeUS(packetS->header_pt));
				strcpy_null_term(call->called_final, request.endpoint.c_str());
				call->setSipcallerip(packetS->saddr_(), packetS->saddr_(true), packetS->header_ip_protocol(true), packetS->source_());
				call->setSipcalledip(packetS->daddr_(), packetS->daddr_(true), packetS->header_ip_protocol(true), packetS->dest_());
				call->flags = flags;
				strcpy_null_term(call->fbasename, request.call_id().c_str());
				if(enable_save_sip_rtp_audio(call)) {
					if(enable_pcap_split) {
						if(enable_save_sip(call)) {
							string pathfilename = call->get_pathfilename(tsf_mgcp);
							if(call->getPcapSip()->open(tsf_mgcp, pathfilename.c_str(), call->useHandle, call->useDlt)) {
								if(verbosity > 3) {
									syslog(LOG_NOTICE,"pcap_filename: [%s]\n", pathfilename.c_str());
								}
							}
						}
						if(enable_save_rtp(call)) {
							string pathfilename = call->get_pathfilename(tsf_rtp);
							if(call->getPcapRtp()->open(tsf_rtp, pathfilename.c_str(), call->useHandle, call->useDlt)) {
								if(verbosity > 3) {
									syslog(LOG_NOTICE,"pcap_filename: [%s]\n", pathfilename.c_str());
								}
							}
						}
					} else {
						if(enable_save_sip_rtp(call)) {
							string pathfilename = call->get_pathfilename(tsf_mgcp);
							if(call->getPcap()->open(tsf_mgcp, pathfilename.c_str(), call->useHandle, call->useDlt)) {
								if(verbosity > 3) {
									syslog(LOG_NOTICE,"pcap_filename: [%s]\n", pathfilename.c_str());
								}
							}
						}
					}
				}
			} else if(call) {
				calltable->lock_calls_listMAP();
				calltable->calls_by_stream_id2_listMAP[sStreamId2(call->saddr, call->sport, call->daddr, call->dport, request.transaction_id, true)] = call;
				call->mgcp_transactions.push_back(request.transaction_id);
				calltable->unlock_calls_listMAP();
			}
		} else {
			call = calltable->find_by_stream(packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_());
			if(call) {
				calltable->lock_calls_listMAP();
				calltable->calls_by_stream_id2_listMAP[sStreamId2(call->saddr, call->sport, call->daddr, call->dport, request.transaction_id, true)] = call;
				call->mgcp_transactions.push_back(request.transaction_id);
				calltable->unlock_calls_listMAP();
			}
		}
		if(sverb.mgcp && call) {
			request.debug_output(sdp ? "(SDP)" : NULL);
		}
	}
	if(is_response) {
		call = calltable->find_by_stream_id2(packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_(), response.transaction_id);
		if(sverb.mgcp && call) {
			response.debug_output();
		}
	}
	if(call) {
		if(is_request) {
			call->mgcp_requests[request.transaction_id] = request;
		}
		if(is_response) {
			call->mgcp_responses[response.transaction_id] = response;
			if(call->mgcp_requests.find(response.transaction_id) != call->mgcp_requests.end()) {
				request = call->mgcp_requests[response.transaction_id];
			}
		}
		if(is_request && request_type == _mgcp_DLCX) {
			call->destroy_call_at = packetS->header_pt->ts.tv_sec + 10;
		} else {
			call->shift_destroy_call_at(packetS->getTime_s());
		}
		if(is_response) {
			if(call->lastSIPresponseNum == 0 || call->lastSIPresponseNum < 300) {
				call->lastSIPresponseNum = response_code;
				strcpy_null_term(call->lastSIPresponse, response.response.c_str());
			}
		}
		if(sdp) {
			if(sverb.mgcp_sdp) {
				cout << "SDP: " << endl << string((char*)sdp + sdp_separator_length, packetS->datalen_() - mgcp_header_len - sdp_separator_length) << endl;
			}
			int iscaller;
			call->check_is_caller_called(NULL, MGCP, 0, 
						     packetS->saddr_(), packetS->daddr_(), 
						     packetS->saddr_(true), packetS->daddr_(true), packetS->header_ip_protocol(true),
						     packetS->source_(), packetS->dest_(), 
						     &iscaller, NULL);
			char to[1024];
			char branch[100];
			detect_to_extern(packetS, to, sizeof(to), NULL);
			detect_branch_extern(packetS, branch, sizeof(branch), NULL);
			process_sdp(call, packetS, iscaller, (char*)(sdp + sdp_separator_length), 0,
				    (char*)call->call_id.c_str(), to, branch);
		}
		if(!call->connect_time_us && is_request) {
			if((request_type == _mgcp_CRCX && request.parameters.connection_mode == "SENDRECV") ||
			   (request_type == _mgcp_RQNT && request.parameters.requested_events == "L/HF(N),L/HU(N)")) {
				call->connect_time_us = getTimeUS(packetS->header_pt);
			}
		}
		save_packet(call, packetS, _t_packet_mgcp);
		if(request.type == _mgcp_CRCX || request.type == _mgcp_MDCX || request.type == _mgcp_DLCX) {
			call->set_last_mgcp_connect_packet_time_us(getTimeUS(packetS->header_pt));
		}
		call->set_last_signal_packet_time_us(getTimeUS(packetS->header_pt));
	}
	return(NULL);
}

bool parse_mgcp_request(sMgcpRequest *request, vector<string> *mgcp_lines) {
	if(!mgcp_lines->size()) {
		return(false);
	}
	if(!parse_mgcp_request(request, (*mgcp_lines)[0].c_str())) {
		return(false);
	}
	if(mgcp_lines->size() > 1) {
		parse_mgcp_parameters(&request->parameters, mgcp_lines);
	}
	return(true);
}

bool parse_mgcp_response(sMgcpResponse *response, vector<string> *mgcp_lines) {
	if(!mgcp_lines->size()) {
		return(false);
	}
	if(!parse_mgcp_response(response, (*mgcp_lines)[0].c_str())) {
		return(false);
	}
	if(mgcp_lines->size() > 1) {
		parse_mgcp_parameters(&response->parameters, mgcp_lines);
	}
	return(true);
}

bool parse_mgcp_parameters(sMgcpParameters *parameters, vector<string> *mgcp_lines) {
	for(unsigned i = 1; i < mgcp_lines->size(); i++) {
		parse_mgcp_parameters(parameters, (*mgcp_lines)[i].c_str());
	}
	return(parameters->is_set());
}

bool parse_mgcp_request(sMgcpRequest *request, const char *mgcp_line) {
	const char *pos = mgcp_line;
	int counter = 0;
	while(pos) {
		const char *posSpaceSeparator = strchr(pos, ' ');
		if(posSpaceSeparator) {
			*(char*)posSpaceSeparator = 0;
		}
		switch(counter) {
		case 0:
			request->type = getMgcpRequestType(pos);
			if(request->type == _mgcp_na) {
				return(false);
			}
			break;
		case 1:
			request->transaction_id = atoll(pos);
			break;
		case 2:
			request->endpoint = pos;
			break;
		case 3:
			if(!strcasecmp(pos, "MGCP")) {
				request->version_prefix_ok = true;
			}
			break;
		case 4:
			if(request->version_prefix_ok) {
				request->version = pos;
			}
			break;
		}
		if(posSpaceSeparator) {
			*(char*)posSpaceSeparator = ' ';
			pos = posSpaceSeparator + 1;
		} else {
			pos = NULL;
		}
		++counter;
	}
	return(request->is_set());
}

bool parse_mgcp_response(sMgcpResponse *response, const char *mgcp_line) {
	const char *pos = mgcp_line;
	int counter = 0;
	while(pos) {
		const char *posSpaceSeparator = NULL;
		if(counter < 2) {
			posSpaceSeparator = strchr(pos, ' ');
			if(posSpaceSeparator) {
				*(char*)posSpaceSeparator = 0;
			}
		}
		switch(counter) {
		case 0:
			if(!isdigit(*pos)) {
				return(false);
			}
			response->code = atoi(pos);
			break;
		case 1:
			response->transaction_id = atoll(pos);
			break;
		case 2:
			response->response = pos;
			break;
		}
		if(posSpaceSeparator) {
			*(char*)posSpaceSeparator = ' ';
			pos = posSpaceSeparator + 1;
		} else {
			pos = NULL;
		}
		++counter;
	}
	return(response->is_set());
}

void parse_mgcp_parameters(sMgcpParameters *parameters, const char *mgcp_line) {
	if(strlen(mgcp_line) < 3 || mgcp_line[1] != ':') {
		return;
	}
	unsigned pos_content = 2;
	while(mgcp_line[pos_content] == ' ') {
		++pos_content;
	}
	switch(mgcp_line[0]) {
	case 'C':
		parameters->call_id = mgcp_line + pos_content;
		break;
	case 'R':
		parameters->requested_events = mgcp_line + pos_content;
		break;
	case 'M':
		parameters->connection_mode = mgcp_line + pos_content;
		break;
	}
}


void sMgcpParameters::debug_output() {
	if(!is_set()) {
		return;
	}
	if(!call_id.empty()) {
		cout << "   par call_id: " << call_id << endl;
	}
	if(!requested_events.empty()) {
		cout << "   par requested_events: " << requested_events << endl;
	}
}

void sMgcpRequest::debug_output(const char *firstLineSuffix) {
	if(!is_set()) {
		return;
	}
	cout << "request " << getMgcpRequestTypeString(type, false) << " (" << getMgcpRequestTypeString(type, true) << ")";
	if(firstLineSuffix) {
		cout << " " << firstLineSuffix;
	}
	cout << endl;
	cout << "   transaction_id: " << transaction_id << endl
	     << "   endpoint: " << endpoint << endl
	     << "   version_prefix_ok: " << version_prefix_ok << endl
	     << "   version: " << version << endl;
	this->parameters.debug_output();
}

void sMgcpResponse::debug_output() {
	if(!is_set()) {
		return;
	}
	cout << "response " << code << " (" << response << ")" << endl
	     << "   transaction_id: " << transaction_id << endl;
	this->parameters.debug_output();
}
