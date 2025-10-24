#include <algorithm>
#include <fcntl.h>
#include <sys/epoll.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "voipmonitor.h"

#include "siprec.h"

#include "pcap_queue.h"
#include "header_packet.h"
#include "sniff_inline.h"
#include "sniff_proc_class.h"


extern int opt_t2_boost;

static cSipRec *sip_rec;


cSipRecCall::cSipRecCall() {
}

cSipRecCall::~cSipRecCall() {
	stopStreams();
}

bool cSipRecCall::parseInvite(const char *invite_str, vmIP src_ip) {
	sInvite current_invite;
	current_invite.str = invite_str;
	const char *ptr = invite_str;
	const char *line_start = ptr;
	ptr = find_end_line(ptr);
	current_invite.request_line.assign(line_start, ptr - line_start);
	ptr = skip_cr_lf(ptr);
	ptr = parseSipHeaders(ptr, current_invite.tags);
	if(current_invite.tags.find("call-id") == current_invite.tags.end()) {
		return(false);
	}
	if(*ptr) {
		string body(ptr);
		map<string, string>::iterator ct_it = current_invite.tags.find("content-type");
		if(ct_it != current_invite.tags.end() && ct_it->second.find("multipart") != string::npos) {
			size_t boundary_pos = ct_it->second.find("boundary=");
			if(boundary_pos != string::npos) {
				string boundary = ct_it->second.substr(boundary_pos + 9);
				if(boundary[0] == '"') {
					boundary = boundary.substr(1, boundary.find('"', 1) - 1);
				} else {
					size_t end = boundary.find_first_of(" ;\r\n");
					if(end != string::npos) {
						boundary = boundary.substr(0, end);
					}
				}
				string delimiter = "--" + boundary;
				size_t pos = 0;
				while((pos = body.find(delimiter, pos)) != string::npos) {
					pos += delimiter.length();
					pos = skip_cr_lf(body, pos);
					if(body[pos] == '-' && body[pos + 1] == '-') {
						break;
					}
					sContent content;
					while(pos < body.length()) {
						size_t line_end = body.find('\n', pos);
						if(line_end == string::npos) break;
						size_t line_len = line_end - pos;
						if(body[line_end - 1] == '\r') line_len--;
						if(line_len == 0) {
							pos = line_end + 1;
							break;
						}
						string header = body.substr(pos, line_len);
						size_t colon = header.find(':');
						if(colon != string::npos) {
							string name = header.substr(0, colon);
							transform(name.begin(), name.end(), name.begin(), ::tolower);
							string value = header.substr(colon + 1);
							size_t value_start = value.find_first_not_of(" \t");
							if(value_start != string::npos) {
								value = value.substr(value_start);
							}
							if(name == "content-type") {
								content.content_type = value;
							} else if(name == "content-length") {
								content.content_length = atoi(value.c_str());
							} else if(name == "content-disposition") {
								content.content_disposition = value;
							}
						}
						pos = line_end + 1;
					}
					size_t next_delim = body.find("\r\n--" + boundary, pos);
					if(next_delim == string::npos) {
						next_delim = body.find("\n--" + boundary, pos);
					}
					if(next_delim != string::npos) {
						content.content = body.substr(pos, next_delim - pos);
						pos = next_delim;
						if(body[pos] == '\r') pos++;
						if(body[pos] == '\n') pos++;
					} else {
						break;
					}
					current_invite.contents.push_back(content);
				}
			}
		} else {
			sContent content;
			if(ct_it != current_invite.tags.end()) {
				content.content_type = ct_it->second;
			}
			map<string, string>::iterator cl_it = current_invite.tags.find("content-length");
			if(cl_it == current_invite.tags.end()) {
				cl_it = current_invite.tags.find("l");
			}
			if(cl_it != current_invite.tags.end()) {
				content.content_length = atoi(cl_it->second.c_str());
			}
			content.content = body;
			current_invite.contents.push_back(content);
		}
	}
	invite.push_back(current_invite);
	id.callid = current_invite.tags["call-id"];
	id.src_ip = src_ip;
	return(true);
}

bool cSipRecCall::parseBye(const char *bye_str, vmIP src_ip) {
	bye.str = bye_str;
	const char *ptr = bye_str;
	const char *line_start = ptr;
	ptr = find_end_line(ptr);
	bye.request_line.assign(line_start, ptr - line_start);
	ptr = skip_cr_lf(ptr);
	parseSipHeaders(ptr, bye.tags);
	if(bye.tags.find("call-id") == bye.tags.end()) {
		return(false);
	}
	id.callid = bye.tags["call-id"];
	id.src_ip = src_ip;
	return(true);
}

bool cSipRecCall::parseCancel(const char *cancel_str, vmIP src_ip) {
	cancel.str = cancel_str;
	const char *ptr = cancel_str;
	const char *line_start = ptr;
	ptr = find_end_line(ptr);
	cancel.request_line.assign(line_start, ptr - line_start);
	ptr = skip_cr_lf(ptr);
	parseSipHeaders(ptr, cancel.tags);
	if(cancel.tags.find("call-id") == cancel.tags.end()) {
		return(false);
	}
	id.callid = cancel.tags["call-id"];
	id.src_ip = src_ip;
	return(true);
}

void cSipRecCall::addInvite(const sInvite &inv) {
	invite.push_back(inv);
}

const char *cSipRecCall::getXmlMetadata() {
	if(invite.empty()) return(NULL);
	for(vector<sContent>::iterator it = invite.back().contents.begin(); it != invite.back().contents.end(); it++) {
		if(it->content_type.find("application/rs-metadata") != string::npos ||
		   it->content_type.find("application/xml") != string::npos) {
			/* check content disposition
			if(!it->content_disposition.empty() &&
			   it->content_disposition.find("recording-session") == string::npos) {
				continue;
			}
			*/
			return(it->content.c_str());
		}
	}
	return(NULL);
}

bool cSipRecCall::parseXmlMetadata(const char *xml) {
	if(!xml) {
		xml = getXmlMetadata();
		if(!xml) return(false);
	}
	xmlDocPtr doc = xmlReadMemory(xml, strlen(xml), NULL, NULL,
	                              XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
	if(!doc) {
		return(false);
	}
	xmlNodePtr root = xmlDocGetRootElement(doc);
	if(!root) {
		xmlFreeDoc(doc);
		return(false);
	}
	/* check namespace
	const char* SIPREC_NAMESPACE = "urn:ietf:params:xml:ns:recording:1";
	bool namespace_valid = false;
	if(root->ns && root->ns->href) {
		string ns_href((char*)root->ns->href);
		if(ns_href == SIPREC_NAMESPACE) {
			namespace_valid = true;
		}
	}
	if(!namespace_valid) {
		if(sip_rec && sverb.siprec) {
			syslog(LOG_WARNING, "SIPREC: XML metadata missing required namespace: %s", SIPREC_NAMESPACE);
		}
	}
	*/
	int participant_count = 0;
	vector<string> stream_labels;
	for(xmlNodePtr node = root->children; node; node = node->next) {
		if(node->type != XML_ELEMENT_NODE) continue;
		if(xmlStrcmp(node->name, (xmlChar*)"participant") == 0) {
			bool is_caller = (participant_count == 0);
			parseParticipantNode(node, is_caller);
			participant_count++;
			if(participant_count >= 2) break;
		}
	}
	for(xmlNodePtr node = root->children; node; node = node->next) {
		if(node->type != XML_ELEMENT_NODE) continue;
		if(xmlStrcmp(node->name, (xmlChar*)"stream") == 0) {
			for(xmlNodePtr child = node->children; child; child = child->next) {
				if(child->type == XML_ELEMENT_NODE &&
				   xmlStrcmp(child->name, (xmlChar*)"label") == 0) {
					xmlChar* label = xmlNodeGetContent(child);
					bool label_ok = false;
					if(label) {
						if(*(char*)label) {
							stream_labels.push_back((char*)label);
							label_ok = true;
						}
						xmlFree(label);
					}
					if(label_ok) {
						break;
					}
				}
			}
		}
	}
	if(stream_labels.size() >= 1) {
		metadata.caller_label = stream_labels[0];
	}
	if(stream_labels.size() >= 2) {
		metadata.called_label = stream_labels[1];
	}
	xmlFreeDoc(doc);
	return(isCompletedXmlMetadata(false));
}

bool cSipRecCall::isCompletedXmlMetadata(bool check_rtp_port) {
	return(metadata.isCompleted(check_rtp_port));
}

const char *cSipRecCall::getSdpData() {
	if(invite.empty()) return(NULL);
	for(vector<sContent>::iterator it = invite.back().contents.begin(); it != invite.back().contents.end(); it++) {
		if(it->content_type.find("application/sdp") != string::npos) {
			return(it->content.c_str());
		}
	}
	return(NULL);
}

int cSipRecCall::parseSdpData(const char *sdp_str) {
	if(!sdp_str) {
		sdp_str = getSdpData();
		if(!sdp_str) return(0);
	}
	int media_counter = 0;
	const char *ptr = sdp_str;
	const char *line_start;
	sSdpMedia *current_media = NULL;
	while(*ptr) {
		line_start = ptr;
		ptr = find_end_line(ptr);
		string line(line_start, ptr - line_start);
		ptr = skip_cr_lf(ptr);
		if(line.length() < 2 || line[1] != '=') {
			continue;
		}
		char type = line[0];
		string value = line.substr(2);
		switch(type) {
		case 'c':
			if(value.compare(0, 7, "IN IP4 ") == 0) {
				sdp.c_in.setFromString(value.c_str() + 7);
			} else if(value.compare(0, 7, "IN IP6 ") == 0) {
				sdp.c_in.setFromString(value.c_str() + 7);
			}
			break;
		case 'm':
			{
				sdp.media.push_back(sSdpMedia());
				current_media = &sdp.media.back();
				size_t space1 = value.find(' ');
				if(space1 != string::npos) {
					current_media->media_type = value.substr(0, space1);
					size_t space2 = value.find(' ', space1 + 1);
					if(space2 != string::npos) {
						current_media->port.setPort(atoi(value.c_str() + space1 + 1));
						size_t space3 = value.find(' ', space2 + 1);
						if(space3 != string::npos) {
							current_media->transport_protocol = value.substr(space2 + 1, space3 - space2 - 1);
						}
						++media_counter;
					}
				}
			}
			break;
		case 'a':
			if(current_media) {
				if(value.compare(0, 7, "rtpmap:") == 0) {
					size_t space = value.find(' ', 7);
					if(space != string::npos) {
						sSdpPayload payload;
						payload.payload = atoi(value.c_str() + 7);
						string codec_info = value.substr(space + 1);
						size_t slash = codec_info.find('/');
						if(slash != string::npos) {
							payload.codec = codec_info.substr(0, slash);
							payload.sampling_freq = atoi(codec_info.c_str() + slash + 1);
						} else {
							payload.codec = codec_info;
							payload.sampling_freq = 0;
						}
						current_media->payloads.push_back(payload);
					}
				} else if(value.compare(0, 6, "label:") == 0) {
					current_media->label = value.substr(6);
				}
			}
			break;
		}
	}
	return(media_counter);
}

void cSipRecCall::clearSdpData() {
	sdp.c_in.clear();
	sdp.media.clear();
}

void cSipRecCall::startStreams() {
	for(vector<sSdpMedia>::iterator it = sdp.media.begin(); it != sdp.media.end(); it++) {
		if(!it->active) {
			sip_rec->addStream(this, it->reverse_port);
		}
	}
}

void cSipRecCall::stopStreams() {
	for(vector<sSdpMedia>::iterator it = sdp.media.begin(); it != sdp.media.end(); it++) {
		if(it->active) {
			sip_rec->stopStream(it->reverse_port);
		}
	}
}

int cSipRecCall::setSdpMediaDirections() {
	bool set_direction_to_caller = false;
	bool set_direction_to_called = false;
	for(vector<sSdpMedia>::iterator it = sdp.media.begin(); it != sdp.media.end(); it++) {
		if(!metadata.caller_label.empty() && it->label == metadata.caller_label) {
			it->direction = sdp_media_direction_caller;
			if(!metadata.caller_rtp_port.isSet() && it->port.isSet()) {
				metadata.caller_rtp_port = it->port;
				set_direction_to_caller = true;
			}
		} else if(!metadata.called_label.empty() && it->label == metadata.called_label) {
			it->direction = sdp_media_direction_called;
			if(!metadata.called_rtp_port.isSet() && it->port.isSet()) {
				metadata.called_rtp_port = it->port;
				set_direction_to_called = true;
			}
		} else {
			it->direction = sdp_media_direction_unknown;
		}
	}
	return((set_direction_to_caller ? 1 : 0) +
	       (set_direction_to_called ? 1 : 0));
}

void cSipRecCall::setReverseRtpPorts() {
	if(!sip_rec) return;
	for(vector<sSdpMedia>::iterator it = sdp.media.begin(); it != sdp.media.end(); it++) {
		it->reverse_port = sip_rec->getRtpPort();
	}
}

string cSipRecCall::createInviteRequest(bool use_real_ip_ports) {
	if(invite.empty()) {
		return("");
	}
	sInvite last_invite = invite.back();
	ostringstream request;
	request << last_invite.request_line << "\r\n";
	map<string, string>::iterator it;
	if((it = last_invite.tags.find("via")) != last_invite.tags.end()) {
		request << "Via: " << it->second << "\r\n";
	}
	if((it = last_invite.tags.find("from")) != last_invite.tags.end()) {
		request << "From: " << it->second << "\r\n";
	}
	if((it = last_invite.tags.find("to")) != last_invite.tags.end()) {
		request << "To: " << it->second << "\r\n";
	}
	if((it = last_invite.tags.find("call-id")) != last_invite.tags.end()) {
		request << "Call-ID: " << it->second << "\r\n";
	}
	if((it = last_invite.tags.find("cseq")) != last_invite.tags.end()) {
		request << "CSeq: " << it->second << "\r\n";
	}
	if((it = last_invite.tags.find("contact")) != last_invite.tags.end()) {
		request << "Contact: " << it->second << "\r\n";
	}
	request << "Content-Type: application/sdp\r\n";
	ostringstream sdp_body;
	sdp_body << "v=0\r\n";
	if(use_real_ip_ports && metadata.caller_ip.isSet()) {
		sdp_body << "o=caller " << start_time_us << " 0 IN IP" << metadata.caller_ip.vi() << " " << metadata.caller_ip.getString() << "\r\n";
		sdp_body << "s=Call\r\n";
		sdp_body << "c=IN IP" << metadata.caller_ip.vi() << " " << metadata.caller_ip.getString() << "\r\n";
	} else {
		sdp_body << "o=caller " << start_time_us << " 0 IN IP" << sdp.c_in.vi() << " " << sdp.c_in.getString() << "\r\n";
		sdp_body << "s=Call\r\n";
		sdp_body << "c=IN IP" << sdp.c_in.vi() << " " << sdp.c_in.getString() << "\r\n";
	}
	sdp_body << "t=0 0\r\n";
	if(use_real_ip_ports) {
		for(vector<sSdpMedia>::iterator it = sdp.media.begin(); it != sdp.media.end(); it++) {
			if(it->direction == sdp_media_direction_caller) {
				sdp_body << "m=" << it->media_type << " " << metadata.caller_rtp_port.getPort() << " "
					 << it->transport_protocol;
				for(vector<sSdpPayload>::iterator p_it = it->payloads.begin(); p_it != it->payloads.end(); p_it++) {
					sdp_body << " " << p_it->payload;
				}
				sdp_body << "\r\n";
				for(vector<sSdpPayload>::iterator p_it = it->payloads.begin(); p_it != it->payloads.end(); p_it++) {
					if(!p_it->codec.empty()) {
						sdp_body << "a=rtpmap:" << p_it->payload << " " << p_it->codec;
						if(p_it->sampling_freq > 0) {
							sdp_body << "/" << p_it->sampling_freq;
						}
						sdp_body << "\r\n";
					}
				}
			}
		}
	} else {
		for(vector<sSdpMedia>::iterator it = sdp.media.begin(); it != sdp.media.end(); it++) {
			sdp_body << "m=" << it->media_type << " " << it->port.getPort() << " "
				 << it->transport_protocol;
			for(vector<sSdpPayload>::iterator p_it = it->payloads.begin(); p_it != it->payloads.end(); p_it++) {
				sdp_body << " " << p_it->payload;
			}
			sdp_body << "\r\n";
			for(vector<sSdpPayload>::iterator p_it = it->payloads.begin(); p_it != it->payloads.end(); p_it++) {
				if(!p_it->codec.empty()) {
					sdp_body << "a=rtpmap:" << p_it->payload << " "
						 << p_it->codec;
					if(p_it->sampling_freq > 0) {
						sdp_body << "/" << p_it->sampling_freq;
					}
					sdp_body << "\r\n";
				}
			}
		}
	}
	string sdp_str = sdp_body.str();
	request << "Content-Length: " << sdp_str.length() << "\r\n";
	request << "\r\n";
	request << sdp_str;
	return(request.str());
}

string cSipRecCall::createInviteResponse(bool use_real_ip_ports) {
	if(invite.empty()) {
		return("");
	}
	sInvite last_invite = invite.back();
	ostringstream response;
	response << "SIP/2.0 200 OK\r\n";
	map<string, string>::iterator it;
	if((it = last_invite.tags.find("via")) != last_invite.tags.end()) {
		response << "Via: " << it->second << "\r\n";
	}
	if((it = last_invite.tags.find("from")) != last_invite.tags.end()) {
		response << "From: " << it->second << "\r\n";
	}
	if((it = last_invite.tags.find("to")) != last_invite.tags.end()) {
		response << "To: " << it->second << "\r\n";
	}
	if((it = last_invite.tags.find("call-id")) != last_invite.tags.end()) {
		response << "Call-ID: " << it->second << "\r\n";
	}
	if((it = last_invite.tags.find("cseq")) != last_invite.tags.end()) {
		response << "CSeq: " << it->second << "\r\n";
	}
	if((it = last_invite.tags.find("contact")) != last_invite.tags.end()) {
		response << "Contact: " << it->second << "\r\n";
	}
	response << "Content-Type: application/sdp\r\n";
	response << "Content-Disposition: session\r\n";
	ostringstream sdp_body;
	sdp_body << "v=0\r\n";
	if(use_real_ip_ports && metadata.called_ip.isSet()) {
		sdp_body << "o=callee " << start_time_us << " 0 IN IP" << metadata.called_ip.vi() << " " << metadata.called_ip.getString() << "\r\n";
		sdp_body << "s=Call\r\n";
		sdp_body << "c=IN IP" << metadata.called_ip.vi() << " " << metadata.called_ip.getString() << "\r\n";
	} else {
		sdp_body << "o=siprec " << start_time_us << " 0 IN IP" << sip_rec->getBindIP().vi() << " " << sip_rec->getBindIP().getString() << "\r\n";
		sdp_body << "s=SIPREC Session\r\n";
		sdp_body << "c=IN IP" << sip_rec->getBindIP().vi() << " " << sip_rec->getBindIP().getString() << "\r\n";
	}
	sdp_body << "t=0 0\r\n";
	if(use_real_ip_ports) {
		for(vector<sSdpMedia>::iterator it = sdp.media.begin(); it != sdp.media.end(); it++) {
			if(it->direction == sdp_media_direction_called) {
				sdp_body << "m=" << it->media_type << " " << metadata.caller_rtp_port.getPort() << " "
					 << it->transport_protocol;
				for(vector<sSdpPayload>::iterator p_it = it->payloads.begin(); p_it != it->payloads.end(); p_it++) {
					sdp_body << " " << p_it->payload;
				}
				sdp_body << "\r\n";
				for(vector<sSdpPayload>::iterator p_it = it->payloads.begin(); p_it != it->payloads.end(); p_it++) {
					if(!p_it->codec.empty()) {
						sdp_body << "a=rtpmap:" << p_it->payload << " " << p_it->codec;
						if(p_it->sampling_freq > 0) {
							sdp_body << "/" << p_it->sampling_freq;
						}
						sdp_body << "\r\n";
					}
				}
			}
		}
	} else {
		for(vector<sSdpMedia>::iterator it = sdp.media.begin(); it != sdp.media.end(); it++) {
			if(it->reverse_port.isSet()) {
				sdp_body << "m=" << it->media_type << " " << it->reverse_port.getPort() << " "
					 << it->transport_protocol;
				for(vector<sSdpPayload>::iterator p_it = it->payloads.begin(); p_it != it->payloads.end(); p_it++) {
					sdp_body << " " << p_it->payload;
				}
				sdp_body << "\r\n";
				for(vector<sSdpPayload>::iterator p_it = it->payloads.begin(); p_it != it->payloads.end(); p_it++) {
					if(!p_it->codec.empty()) {
						sdp_body << "a=rtpmap:" << p_it->payload << " "
							 << p_it->codec;
						if(p_it->sampling_freq > 0) {
							sdp_body << "/" << p_it->sampling_freq;
						}
						sdp_body << "\r\n";
					}
				}
			}
		}
	}
	string sdp_str = sdp_body.str();
	response << "Content-Length: " << sdp_str.length() << "\r\n";
	response << "\r\n";
	response << sdp_str;
	return(response.str());
}

string cSipRecCall::createByeRequest(bool /*use_real_ip_ports*/) {
	if(bye.request_line.empty()) {
		return("");
	}
	ostringstream request;
	request << bye.request_line << "\r\n";
	map<string, string>::iterator it;
	if((it = bye.tags.find("via")) != bye.tags.end()) {
		request << "Via: " << it->second << "\r\n";
	}
	if((it = bye.tags.find("from")) != bye.tags.end()) {
		request << "From: " << it->second << "\r\n";
	}
	if((it = bye.tags.find("to")) != bye.tags.end()) {
		request << "To: " << it->second << "\r\n";
	}
	if((it = bye.tags.find("call-id")) != bye.tags.end()) {
		request << "Call-ID: " << it->second << "\r\n";
	}
	if((it = bye.tags.find("cseq")) != bye.tags.end()) {
		request << "CSeq: " << it->second << "\r\n";
	}
	request << "Content-Length: 0\r\n";
	request << "\r\n";
	return(request.str());
}

string cSipRecCall::createByeResponse(bool /*use_real_ip_ports*/) {
	if(bye.request_line.empty()) {
		return("");
	}
	ostringstream response;
	response << "SIP/2.0 200 OK\r\n";
	map<string, string>::iterator it;
	if((it = bye.tags.find("via")) != bye.tags.end()) {
		response << "Via: " << it->second << "\r\n";
	}
	if((it = bye.tags.find("from")) != bye.tags.end()) {
		response << "From: " << it->second << "\r\n";
	}
	if((it = bye.tags.find("to")) != bye.tags.end()) {
		response << "To: " << it->second << "\r\n";
	}
	if((it = bye.tags.find("call-id")) != bye.tags.end()) {
		response << "Call-ID: " << it->second << "\r\n";
	}
	if((it = bye.tags.find("cseq")) != bye.tags.end()) {
		response << "CSeq: " << it->second << "\r\n";
	}
	response << "Content-Length: 0\r\n";
	response << "\r\n";
	return(response.str());
}

string cSipRecCall::createCancelRequest(bool /*use_real_ip_ports*/) {
	if(cancel.request_line.empty()) {
		return("");
	}
	ostringstream request;
	request << cancel.request_line << "\r\n";
	map<string, string>::iterator it;
	if((it = cancel.tags.find("via")) != cancel.tags.end()) {
		request << "Via: " << it->second << "\r\n";
	}
	if((it = cancel.tags.find("from")) != cancel.tags.end()) {
		request << "From: " << it->second << "\r\n";
	}
	if((it = cancel.tags.find("to")) != cancel.tags.end()) {
		request << "To: " << it->second << "\r\n";
	}
	if((it = cancel.tags.find("call-id")) != cancel.tags.end()) {
		request << "Call-ID: " << it->second << "\r\n";
	}
	if((it = cancel.tags.find("cseq")) != cancel.tags.end()) {
		request << "CSeq: " << it->second << "\r\n";
	}
	request << "Content-Length: 0\r\n";
	request << "\r\n";
	return(request.str());
}

string cSipRecCall::createCancelResponse(bool /*use_real_ip_ports*/) {
	if(cancel.request_line.empty()) {
		return("");
	}
	ostringstream response;
	response << "SIP/2.0 200 OK\r\n";
	map<string, string>::iterator it;
	if((it = cancel.tags.find("via")) != cancel.tags.end()) {
		response << "Via: " << it->second << "\r\n";
	}
	if((it = cancel.tags.find("from")) != cancel.tags.end()) {
		response << "From: " << it->second << "\r\n";
	}
	if((it = cancel.tags.find("to")) != cancel.tags.end()) {
		response << "To: " << it->second << "\r\n";
	}
	if((it = cancel.tags.find("call-id")) != cancel.tags.end()) {
		response << "Call-ID: " << it->second << "\r\n";
	}
	if((it = cancel.tags.find("cseq")) != cancel.tags.end()) {
		response << "CSeq: " << it->second << "\r\n";
	}
	response << "Content-Length: 0\r\n";
	response << "\r\n";
	return(response.str());
}

void cSipRecCall::evTimeoutStream() {
	if(!sdp.countActive()) {
		sip_rec->deleteCall(this);
	}
}

const char *cSipRecCall::parseSipHeaders(const char *ptr, map<string, string> &tags) {
	const char *line_start;
	while(*ptr) {
		line_start = ptr;
		if(line_is_empty(ptr)) {
			ptr = skip_cr_lf(ptr);
			break;
		}
		ptr = find_end_line(ptr);
		string header_line(line_start, ptr - line_start);
		size_t colon_pos = header_line.find(':');
		if(colon_pos != string::npos) {
			string name = header_line.substr(0, colon_pos);
			string value = header_line.substr(colon_pos + 1);
			size_t value_start = value.find_first_not_of(" \t");
			if(value_start != string::npos) {
				value = value.substr(value_start);
			}
			transform(name.begin(), name.end(), name.begin(), ::tolower);
			tags[name] = value;
		}
		ptr = skip_cr_lf(ptr);
	}
	return(ptr);
}

bool cSipRecCall::parseParticipantNode(void *participantNode, bool is_caller) {
	if(!participantNode) return(false);
	xmlNodePtr xmlParticipant = (xmlNodePtr)participantNode;
	for(xmlNodePtr child = xmlParticipant->children; child; child = child->next) {
		if(child->type != XML_ELEMENT_NODE) continue;
		if(xmlStrcmp(child->name, (xmlChar*)"nameID") == 0) {
			xmlChar* aor = xmlGetProp(child, (xmlChar*)"aor");
			bool aor_ok = false;
			if(aor) {
				if(*(char*)aor) {
					aor_ok = true;
					string aor_str = (char*)aor;
					if(is_caller) {
						metadata.caller_aor = aor_str;
					} else {
						metadata.called_aor = aor_str;
					}
					if(aor_str.compare(0, 4, "sip:") == 0) {
						size_t at_pos = aor_str.find('@', 4);
						if(at_pos != string::npos) {
							size_t colon_pos = aor_str.find(':', at_pos);
							if(colon_pos != string::npos) {
								string ip = aor_str.substr(at_pos + 1, colon_pos - at_pos - 1);
								string port_str = aor_str.substr(colon_pos + 1);
								if(is_caller) {
									metadata.caller_ip.setFromString(ip.c_str());
									metadata.caller_port.setPort(atoi(port_str.c_str()));
								} else {
									metadata.called_ip.setFromString(ip.c_str());
									metadata.called_port.setPort(atoi(port_str.c_str()));
								}
							} else {
								string ip = aor_str.substr(at_pos + 1);
								if(is_caller) {
									metadata.caller_ip.setFromString(ip.c_str());
									metadata.caller_port.setPort(5060);
								} else {
									metadata.called_ip.setFromString(ip.c_str());
									metadata.called_port.setPort(5060);
								}
							}
						}
					}
				}
				xmlFree(aor);
			}
			if(aor_ok) {
				break;
			}
		}
	}
	return(true);
}


cSipRecStream::cSipRecStream(cSipRecCall *call, vmPort port) {
	this->call = call;
	this->port = port;
	this->socket = -1;
	start_at_ms = getTimeMS_rdtsc();
	last_packet_at_ms = 0;
	createSocket();
	call->sdp.setActive(port, true);
}

cSipRecStream::~cSipRecStream() {
	call->sdp.setActive(port, false);
	if(socket >= 0) {
		close(socket);
	}
	sip_rec->freeRtpPort(port);
}

bool cSipRecStream::createSocket() {
	socket = ::socket(AF_INET, SOCK_DGRAM, 0);
	if(socket < 0) {
		return(false);
	}
	int flags = fcntl(socket, F_GETFL, 0);
	fcntl(socket, F_SETFL, flags | O_NONBLOCK);
	int opt = 1;
	if(setsockopt(socket, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt)) < 0) {
		close(socket);
		socket = -1;
		return(false);
	}
	sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port.getPort());
	addr.sin_addr.s_addr = INADDR_ANY;
	if(bind(socket, (sockaddr*)&addr, sizeof(addr)) < 0) {
		close(socket);
		socket = -1;
		return(false);
	}
	return(true);
}

void cSipRecStream::processPacket(u_char *data, unsigned len, vmIP src_ip, vmPort src_port, vmIP dst_ip, vmPort dst_port) {
	/*
	cout << "rtp packet "
	     << src_ip.getString() << " : " << src_port.getString() << " -> "
	     << dst_ip.getString() << " : " << dst_port.getString() << endl;
	*/
	sip_rec->sendPacket(data, len, src_ip, src_port, dst_ip, dst_port);
	last_packet_at_ms = getTimeMS_rdtsc();
	/*
	//TODO
	cSipRecCall::sSdpMedia *media = NULL;
	for(vector<cSipRecCall::sSdpMedia>::iterator it = call->sdp.media.begin();
	    it != call->sdp.media.end(); it++) {
		if(it->reverse_port == port) {
			media = &(*it);
			break;
		}
	}
	if(!media) {
		return;
	}
	if(media->direction == cSipRecCall::sdp_media_direction_unknown) {
		return;
	}
	bool is_caller_stream = (media->direction == cSipRecCall::sdp_media_direction_caller);
	vmIP expected_src_ip;
	vmPort expected_src_port;
	vmIP expected_dst_ip;
	vmPort expected_dst_port;
	if(is_caller_stream) {
		expected_src_ip = call->metadata.caller_ip;
		expected_src_port = call->metadata.caller_port;
		expected_dst_ip = call->metadata.called_ip;
		expected_dst_port = call->metadata.called_port;
	} else {
		expected_src_ip = call->metadata.called_ip;
		expected_src_port = call->metadata.called_port;
		expected_dst_ip = call->metadata.caller_ip;
		expected_dst_port = call->metadata.caller_port;
	}
	if(src_ip != expected_src_ip || src_port != expected_src_port) {
		return;
	}
	if(dst_ip != expected_dst_ip || dst_port != expected_dst_port) {
		return;
	}
	*/
}


cSipRecThread::cSipRecThread() {
	_sync_lock = 0;
	terminate = false;
	last_check_timeout_ms = 0;
	pipe(pipe_fd);
	int flags = fcntl(pipe_fd[0], F_GETFL, 0);
	fcntl(pipe_fd[0], F_SETFL, flags | O_NONBLOCK);
	epoll_fd = epoll_create1(0);
	epoll_event ev;
	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = pipe_fd[0];
	epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pipe_fd[0], &ev);
	vm_pthread_create("siprec thread",  &thread_id, NULL, _thread_fce, this, __FILE__, __LINE__);
}

cSipRecThread::~cSipRecThread() {
	stop();
	lock();
	for(map<vmPort, cSipRecStream*>::iterator it = streams.begin(); it != streams.end(); it++) {
		delete it->second;
	}
	streams.clear();
	unlock();
	close(epoll_fd);
	close(pipe_fd[0]);
	close(pipe_fd[1]);
}

void *cSipRecThread::_thread_fce(void *arg) {
	((cSipRecThread*)arg)->thread_fce();
	return(NULL);
}

void cSipRecThread::thread_fce() {
	epoll_event events[64];
	u_char buffer[65536];
	while(!terminate) {
		int nfds = epoll_wait(epoll_fd, events, 64, 1000);
		if(nfds > 0) {
			for(int i = 0; i < nfds; i++) {
				if(events[i].data.fd == pipe_fd[0]) {
					char dummy;
					read(pipe_fd[0], &dummy, 1);
				} else {
					cSipRecStream *stream = (cSipRecStream*)events[i].data.ptr;
					if(stream && stream->socket >= 0) {
						sockaddr_storage src_addr;
						struct iovec iov;
						iov.iov_base = buffer;
						iov.iov_len = sizeof(buffer);
						#if VM_IPV6
						char control_buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
						#else
						char control_buf[CMSG_SPACE(sizeof(struct in_pktinfo))];
						#endif
						struct msghdr msg;
						memset(&msg, 0, sizeof(msg));
						msg.msg_name = &src_addr;
						msg.msg_namelen = sizeof(src_addr);
						msg.msg_iov = &iov;
						msg.msg_iovlen = 1;
						msg.msg_control = control_buf;
						msg.msg_controllen = sizeof(control_buf);
						ssize_t len = recvmsg(stream->socket, &msg, 0);
						if(len > 0) {
							vmIP src_ip;
							vmPort src_port;
							vmIP dst_ip;
							vmPort dst_port;
							dst_port = stream->port;
							if(src_addr.ss_family == AF_INET) {
								sockaddr_in *addr_in = (sockaddr_in*)&src_addr;
								src_ip.setIPv4(addr_in->sin_addr.s_addr, true);
								src_port.setPort(addr_in->sin_port, true);
							}
							#if VM_IPV6
							else if(src_addr.ss_family == AF_INET6) {
								sockaddr_in6 *addr_in6 = (sockaddr_in6*)&src_addr;
								src_ip.setIPv6(addr_in6->sin6_addr, true);
								src_port.setPort(addr_in6->sin6_port, true);
							}
							#endif
							for(struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
								if(cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
									struct in_pktinfo *pktinfo = (struct in_pktinfo*)CMSG_DATA(cmsg);
									dst_ip.setIPv4(pktinfo->ipi_addr.s_addr, true);
									break;
								}
								#if VM_IPV6
								else if(cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
									struct in6_pktinfo *pktinfo = (struct in6_pktinfo*)CMSG_DATA(cmsg);
									dst_ip.setIPv6(pktinfo->ipi6_addr, true);
									break;
								}
								#endif
							}
							stream->processPacket(buffer, len, src_ip, src_port, dst_ip, dst_port);
						}
					}
				}
			}
		}
		checkTimeout();
	}
}

void cSipRecThread::checkTimeout() {
	u_int64_t now_ms = getTimeMS_rdtsc();
	if(now_ms - last_check_timeout_ms < 1000) {
		return;
	}
	last_check_timeout_ms = now_ms;
	lock();
	vector<vmPort> to_remove;
	for(map<vmPort, cSipRecStream*>::iterator it = streams.begin(); it != streams.end(); it++) {
		cSipRecStream *stream = it->second;
		if(sip_rec->getRtpStreamTimeout() > 0) {
			if((stream->last_packet_at_ms > 0 ?
			     stream->last_packet_at_ms + sip_rec->getRtpStreamTimeout() * 1000 :
			     stream->start_at_ms + sip_rec->getRtpStreamTimeout() * 1000) < now_ms) {
				to_remove.push_back(it->first);
			}
		}
	}
	unlock();
	for(vector<vmPort>::iterator it = to_remove.begin(); it != to_remove.end(); it++) {
		map<vmPort, cSipRecStream*>::iterator stream_it = streams.find(*it);
		if(stream_it != streams.end()) {
			cSipRecCall *call = stream_it->second->call;
			sip_rec->stopStream(*it);
			call->evTimeoutStream();
		}
	}
}

bool cSipRecThread::addStream(cSipRecCall *call, vmPort port) {
	lock();
	if(streams.find(port) != streams.end()) {
		unlock();
		return(false);
	}
	cSipRecStream *stream = new FILE_LINE(0) cSipRecStream(call, port);
	if(stream->socket < 0) {
		delete stream;
		unlock();
		return(false);
	}
	epoll_event ev;
	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.ptr = stream;
	if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, stream->socket, &ev) < 0) {
		delete stream;
		unlock();
		return(false);
	}
	streams[port] = stream;
	unlock();
	char dummy = 1;
	write(pipe_fd[1], &dummy, 1);
	return(true);
}

void cSipRecThread::removeStream(vmPort port) {
	lock();
	_removeStream(port);
	unlock();
	char dummy = 1;
	write(pipe_fd[1], &dummy, 1);
}

void cSipRecThread::_removeStream(vmPort port) {
	map<vmPort, cSipRecStream*>::iterator it = streams.find(port);
	if(it != streams.end()) {
		epoll_ctl(epoll_fd, EPOLL_CTL_DEL, it->second->socket, NULL);
		delete it->second;
		streams.erase(it);
	}
}

void cSipRecThread::stop() {
	terminate = true;
	char dummy = 1;
	write(pipe_fd[1], &dummy, 1);
	if(thread_id) {
		pthread_join(thread_id, NULL);
		thread_id = 0;
	}
}


cSipRecStreams::cSipRecStreams(unsigned max_threads) {
	this->max_threads = max_threads;
	this->threads_count = 0;
	threads = new FILE_LINE(0) cSipRecThread*[max_threads];
	for(unsigned i = 0; i < max_threads; i++) {
		threads[i] = NULL;
	}
	_sync_lock = 0;
}

cSipRecStreams::~cSipRecStreams() {
	stopAllStreams();
	stopAllThreads();
	lock();
	for(unsigned i = 0; i < threads_count; i++) {
		if(threads[i]) {
			delete threads[i];
		}
	}
	unlock();
	delete [] threads;
}

bool cSipRecStreams::addStream(cSipRecCall *call, vmPort port) {
	lock();
	if(stream_by_thread.find(port) != stream_by_thread.end()) {
		unlock();
		return(false);
	}
	int thread_idx = findThreadWithMinStreams();
	if(thread_idx < 0) {
		if(threads_count >= max_threads) {
			unlock();
			return(false);
		}
		thread_idx = threads_count;
		threads[thread_idx] = new FILE_LINE(0) cSipRecThread();
		threads_count++;
	}
	if(!threads[thread_idx]->addStream(call, port)) {
		unlock();
		return(false);
	}
	stream_by_thread[port] = thread_idx;
	unlock();
	return(true);
}

void cSipRecStreams::stopStream(vmPort port) {
	lock();
	map<vmPort, unsigned>::iterator it = stream_by_thread.find(port);
	if(it != stream_by_thread.end()) {
		unsigned thread_idx = it->second;
		if(thread_idx < threads_count && threads[thread_idx]) {
			threads[thread_idx]->removeStream(port);
		}
		stream_by_thread.erase(it);
	}
	unlock();
}

void cSipRecStreams::stopAllStreams() {
	lock();
	for(map<vmPort, unsigned>::iterator it = stream_by_thread.begin(); it != stream_by_thread.end(); it++) {
		unsigned thread_idx = it->second;
		if(thread_idx < threads_count && threads[thread_idx]) {
			threads[thread_idx]->removeStream(it->first);
		}
	}
	stream_by_thread.clear();
	unlock();
}

void cSipRecStreams::stopAllThreads() {
	lock();
	for(unsigned i = 0; i < threads_count; i++) {
		if(threads[i]) {
			threads[i]->stop();
		}
	}
	unlock();
}

int cSipRecStreams::findThreadWithMinStreams() {
	int min_idx = -1;
	unsigned min_count = UINT_MAX;
	for(unsigned i = 0; i < threads_count; i++) {
		if(threads[i]) {
			unsigned count = threads[i]->getStreamsCount();
			if(count < min_count) {
				min_count = count;
				min_idx = i;
			}
		}
	}
	return(min_idx);
}


cSipRecServer::cSipRecServer(bool udp) 
 : cServer(udp, true) {
}

cSipRecServer::~cSipRecServer() {
}

void cSipRecServer::createConnection(cSocket *socket) {
	if(is_terminating()) {
		return;
	}
	cSipRecConnection *connection = new FILE_LINE(0) cSipRecConnection(socket);
	connection->connection_start();
}

void cSipRecServer::evData(u_char *data, size_t dataLen, vmIP ip, vmPort port, cSocket *socket) {
	sip_rec->processData(data, dataLen, ip, port, socket);
}


cSipRecConnection::cSipRecConnection(cSocket *socket) 
 : cServerConnection(socket, true) {
}

cSipRecConnection::~cSipRecConnection() {
}

void cSipRecConnection::evData(u_char *data, size_t dataLen) {
	sip_rec->processData(data, dataLen, socket->getIPL(), socket->getPort(), socket);
}

void cSipRecConnection::connection_process() {
	cServerConnection::connection_process();
	delete this;
}


cSipRecPacketSender::cSipRecPacketSender()
 : cTimer(NULL) {
	block_store = NULL;
	block_store_sync = 0;
	if(opt_t2_boost) {
		setEveryMS(100);
		start();
	}
}

cSipRecPacketSender::~cSipRecPacketSender() {
}

void cSipRecPacketSender::sendPacket(u_char *data, unsigned dataLen, vmIP src_ip, vmPort src_port, vmIP dst_ip, vmPort dst_port) {
	int dlink = PcapDumper::get_global_pcap_dlink_en10();
	if(!dlink) {
		dlink = DLT_EN10MB;
	}
	int pcap_handle_index = PcapDumper::get_global_handle_index_en10();
	ether_header header_eth;
	memset(&header_eth, 0, sizeof(header_eth));
	header_eth.ether_type = htons(src_ip.is_v6() ? ETHERTYPE_IPV6 : ETHERTYPE_IP);
	timespec time;
	clock_gettime(CLOCK_REALTIME, &time);
	pcap_pkthdr *udpHeader;
	u_char *udpPacket;
	createSimpleUdpDataPacket(sizeof(header_eth), &udpHeader,  &udpPacket,
				  (u_char*)&header_eth, data, dataLen, 0,
				  src_ip, dst_ip, src_port, dst_port,
				  time.tv_sec, time.tv_nsec / 1000);
	pushPacket(udpHeader, udpPacket, dataLen, false,
		   src_ip, src_port, dst_ip, dst_port,
		   dlink, pcap_handle_index);
}

void cSipRecPacketSender::pushPacket(pcap_pkthdr *header, u_char *packet, unsigned dataLen, bool tcp,
				     vmIP src_ip, vmPort src_port, vmIP dst_ip, vmPort dst_port,
				     int dlink, int pcap_handle_index) {
	if(opt_t2_boost) {
		block_store_lock();
		if(!block_store) {
			block_store = new FILE_LINE(0) pcap_block_store(pcap_block_store::plus2);
		}
		pcap_pkthdr_plus2 header_plus;
		header_plus.clear();
		header_plus.convertFromStdHeader(header);
		header_plus.header_ip_encaps_offset = sizeof(ether_header);
		header_plus.header_ip_offset = sizeof(ether_header);
		header_plus.dlink = dlink;
		header_plus.detect_headers = 1;
		header_plus.eth_protocol = src_ip.is_v6() ? ETHERTYPE_IPV6 : ETHERTYPE_IP;
		if(!block_store->add_hp_ext(&header_plus, packet)) {
			extern PcapQueue_readFromFifo *pcapQueueQ;
			pcapQueueQ->addBlockStoreToPcapStoreQueue_ext(block_store);
			block_store = new FILE_LINE(0) pcap_block_store;
			block_store->add_hp_ext(&header_plus, packet);
		}
		delete header;
		delete [] packet;
		block_store_unlock();
	} else {
		unsigned iphdrSize = ((iphdr2*)(packet + sizeof(ether_header)))->get_hdr_size();
		unsigned dataOffset = sizeof(ether_header) + iphdrSize + 
				      (tcp ?
					((tcphdr2*)(packet + sizeof(ether_header) + iphdrSize))->doff * 4 :
					sizeof(udphdr2));
		packet_flags pflags;
		pflags.init();
		if(tcp) {
			pflags.set_tcp(2);
		}
		sPacketInfoData pid;
		pid.clear();
		extern int opt_id_sensor;
		extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
		if(opt_t2_boost_direct_rtp) {
			sHeaderPacketPQout hp(header, packet,
					      dlink, opt_id_sensor, vmIP());
			preProcessPacket[PreProcessPacket::ppt_detach_x]->push_packet(
				sizeof(ether_header), 0xFFFF,
				dataOffset, dataLen,
				src_port, dst_port,
				pflags,
				&hp,
				pcap_handle_index);
		} else {
			preProcessPacket[PreProcessPacket::ppt_detach]->push_packet(
				#if USE_PACKET_NUMBER
				0, 
				#endif
				src_ip, src_port, dst_ip, dst_port, 
				dataLen, dataOffset,
				pcap_handle_index, header, packet, _t_packet_alloc_header_std, 
				pflags, (iphdr2*)(packet + sizeof(ether_header)), (iphdr2*)(packet + sizeof(ether_header)),
				NULL, 0, dlink, opt_id_sensor, vmIP(), pid,
				false);
		}
	}
}

void cSipRecPacketSender::evTimer(u_int32_t /*time_s*/, int /*typeTimer*/, void */*data*/) {
	block_store_lock();
	if(block_store && block_store->isFull_checkTimeout_ext(100)) {
		extern PcapQueue_readFromFifo *pcapQueueQ;
		pcapQueueQ->addBlockStoreToPcapStoreQueue_ext(block_store);
		block_store = NULL;
	}
	block_store_unlock();
}


cSipRec::cSipRec() {
	rtp_port_min = 0;
	rtp_port_max = 0;
	rtp_stream_timeout_s = 10;
	rtp_streams_max_threads = 4;
	_sync_lock = 0;
	_sync_lock_rtp_ports = 0;
	verbose = false;
}

cSipRec::~cSipRec() {
	if(server) {
		delete server;
	}
	if(streams) {
		delete streams;
	}
	if(packet_sender) {
		delete packet_sender;
	}
}

void cSipRec::setRtpPortsLimit(unsigned rtp_port_min, unsigned rtp_port_max) {
	this->rtp_port_min = rtp_port_min;
	this->rtp_port_max = rtp_port_max;
	initRtpPortsHeap();
}

void cSipRec::setBindParams(vmIP ip, vmPort port, bool udp) {
	bind_ip = ip;
	bind_port = port;
	bind_udp = udp;
}

void cSipRec::setRtpStreamTimeout(unsigned rtp_stream_timeout_s) {
	this->rtp_stream_timeout_s = rtp_stream_timeout_s;
}

void cSipRec::setRtpStreamManThreads(unsigned rtp_streams_max_threads) {
	this->rtp_streams_max_threads = rtp_streams_max_threads;
}

void cSipRec::setVerbose(bool verbose) {
	this->verbose = verbose;
}

void cSipRec::startServer() {
	checkParams();
	packet_sender = new FILE_LINE(0) cSipRecPacketSender();
	streams = new FILE_LINE(0) cSipRecStreams(rtp_streams_max_threads);
	server = new FILE_LINE(0) cSipRecServer(bind_udp);
	server->setStartVerbString("START SIPREC LISTEN");
	server->listen_start("siprec_server", bind_ip, bind_port);
}

vmPort cSipRec::getRtpPort() {
	if(free_rtp_ports.empty()) {
		return(vmPort());
	}
	u_int16_t port;
	lock_rtp_ports();
	set<u_int16_t>::iterator it = free_rtp_ports.begin();
	port = *it;
	free_rtp_ports.erase(it);
	unlock_rtp_ports();
	return(port);
}

void cSipRec::freeRtpPort(vmPort port) {
	lock_rtp_ports();
	if(port.port >= rtp_port_min && port.port <= rtp_port_max && port.port % 2 == 0) {
		free_rtp_ports.insert(port);
	}
	unlock_rtp_ports();
}

void cSipRec::initRtpPortsHeap() {
	free_rtp_ports.clear();
	if(rtp_port_min == 0 && rtp_port_max == 0) {
		rtp_port_min = 0;
		rtp_port_max = 0xFFFF;
	}
	for(u_int16_t port = rtp_port_min; port <= rtp_port_max; port += 2) {
		if(port % 2 == 0) {
			free_rtp_ports.insert(port);
		}
	}
}

void cSipRec::processData(u_char *data, size_t dataLen, vmIP ip, vmPort port, cSocket *socket) {
	if(dataLen < 6) return;
	if(!strncasecmp((char*)data, "INVITE", 6)) {
		processInvite(data, dataLen, ip, port, socket);
	} else if(!strncasecmp((char*)data, "BYE", 3)) {
		processBye(data, dataLen, ip, port, socket);
	} else if(!strncasecmp((char*)data, "CANCEL", 6)) {
		processCancel(data, dataLen, ip, port, socket);
	}
}

void cSipRec::processInvite(u_char *data, size_t dataLen, vmIP ip, vmPort port, cSocket *socket) {
	if(verbose) {
		cout << " *** INVITE REQUEST" << endl;
		cout << string((char*)data, dataLen) << endl;
	}
	cSipRecCall *call = new FILE_LINE(0) cSipRecCall;
	if(!call->parseInvite(string((char*)data, dataLen).c_str(), ip)) {
		delete call;
		return;
	}
	lock();
	if(calls_by_call_id.find(call->id) == calls_by_call_id.end()) {
		calls_by_call_id[call->id] = call;
	} else {
		cSipRecCall *exists_call = calls_by_call_id[call->id];
		exists_call->addInvite(call->invite[0]);
		delete call;
		call = exists_call;
		call->stopStreams();
		call->clearSdpData();
	}
	unlock();
	sendPacket(data, dataLen, ip, port, bind_ip, bind_port);
	call->parseXmlMetadata();
	call->parseSdpData();
	call->setSdpMediaDirections();
	call->setReverseRtpPorts();
	call->startStreams();
	string response = call->createInviteResponse();
	if(verbose) {
		cout << " *** INVITE RESPONSE" << endl;
		cout << response << endl;
	}
	sendResponse(response, ip, port, socket);
	sendPacket((u_char*)response.c_str(), response.length(), bind_ip, bind_port, ip, port);
}

void cSipRec::processBye(u_char *data, size_t dataLen, vmIP ip, vmPort port, cSocket *socket) {
	if(verbose) {
		cout << " *** BYE REQUEST" << endl;
		cout << string((char*)data, dataLen) << endl;
	}
	cSipRecCall *call = new FILE_LINE(0) cSipRecCall;
	if(!call->parseBye(string((char*)data, dataLen).c_str(), ip)) {
		delete call;
		return;
	}
	lock();
	if(calls_by_call_id.find(call->id) == calls_by_call_id.end()) {
		unlock();
		delete call;
		return;
	} else {
		cSipRecCall *exists_call = calls_by_call_id[call->id];
		exists_call->bye = call->bye;
		delete call;
		call = exists_call;
	}
	unlock();
	sendPacket(data, dataLen, ip, port, bind_ip, bind_port);
	string response = call->createByeResponse();
	if(verbose) {
		cout << " *** BYE RESPONSE" << endl;
		cout << response << endl;
	}
	sendResponse(response, ip, port, socket);
	sendPacket((u_char*)response.c_str(), response.length(), bind_ip, bind_port, ip, port);
	call->stopStreams();
	deleteCall(call);
}

void cSipRec::processCancel(u_char *data, size_t dataLen, vmIP ip, vmPort port, cSocket *socket) {
	if(verbose) {
		cout << " *** CANCEL REQUEST" << endl;
		cout << string((char*)data, dataLen) << endl;
	}
	cSipRecCall *call = new FILE_LINE(0) cSipRecCall;
	if(!call->parseCancel(string((char*)data, dataLen).c_str(), ip)) {
		delete call;
		return;
	}
	lock();
	if(calls_by_call_id.find(call->id) == calls_by_call_id.end()) {
		unlock();
		delete call;
		return;
	} else {
		cSipRecCall *exists_call = calls_by_call_id[call->id];
		exists_call->cancel = call->cancel;
		delete call;
		call = exists_call;
	}
	unlock();
	sendPacket(data, dataLen, ip, port, bind_ip, bind_port);
	string response = call->createCancelResponse();
	if(verbose) {
		cout << " *** CANCEL RESPONSE" << endl;
		cout << response << endl;
	}
	sendResponse(response, ip, port, socket);
	sendPacket((u_char*)response.c_str(), response.length(), bind_ip, bind_port, ip, port);
	call->stopStreams();
	deleteCall(call);
}

void cSipRec::sendPacket(u_char *data, unsigned dataLen, vmIP src_ip, vmPort src_port, vmIP dst_ip, vmPort dst_port) {
	if(packet_sender) {
		packet_sender->sendPacket(data, dataLen, src_ip, src_port, dst_ip, dst_port);
	}
}

void cSipRec::deleteCall(cSipRecCall *call) {
	lock();
	if(calls_by_call_id.find(call->id) != calls_by_call_id.end()) {
		calls_by_call_id.erase(call->id);
		delete call;
		if(verbose) {
			cout << " *** DELETE CALL" << endl;
		}
	}
	unlock();
}

bool cSipRec::addStream(cSipRecCall *call, vmPort port) {
	if(streams) {
		return(streams->addStream(call, port));
	}
	return(false);
}    

void cSipRec::stopStream(vmPort port) {
	if(streams) {
		streams->stopStream(port);
	}
}

bool cSipRec::sendResponse(string &response, vmIP ip, vmPort port, cSocket *socket) {
	if(bind_udp) {
		if(ip.v() == 4) {
			sockaddr_in dest_addr;
			socket_set_saddr(&dest_addr, ip, port);
			return(sendto(socket->getHandle(), response.c_str(), response.length(), 0,
				      (struct sockaddr*)&dest_addr, sizeof(dest_addr)) > 0);
		}
		#if VM_IPV6
		else {
			sockaddr_in6 dest_addr;
			socket_set_saddr(&dest_addr, ip, port);
			return(sendto(socket->getHandle(), response.c_str(), response.length(), 0,
				      (struct sockaddr*)&dest_addr, sizeof(dest_addr)) > 0);
		}
		#endif
	} else {
		return(socket->write(response.c_str()));
	}
	return(true);
}

void cSipRec::checkParams() {
	if(rtp_port_min == 0 && rtp_port_max == 0 && free_rtp_ports.empty()) {
		initRtpPortsHeap();
	}
}

void sipRecStart() {
	extern string opt_siprec_bind_ip;
	extern int opt_siprec_bind_port;
	extern bool opt_siprec_bind_udp;
	extern int opt_siprec_rtp_min;
	extern int opt_siprec_rtp_max;
	extern int opt_siprec_rtp_stream_timeout_s;
	extern int opt_siprec_rtp_streams_max_threads;
	sip_rec = new cSipRec();
	sip_rec->setRtpPortsLimit(opt_siprec_rtp_min, opt_siprec_rtp_max);
	sip_rec->setBindParams(str_2_vmIP(opt_siprec_bind_ip.c_str()), opt_siprec_bind_port, opt_siprec_bind_udp);
	if(opt_siprec_rtp_stream_timeout_s > 0) {
		sip_rec->setRtpStreamTimeout(opt_siprec_rtp_stream_timeout_s);
	}
	if(opt_siprec_rtp_streams_max_threads > 0) {
		sip_rec->setRtpStreamManThreads(opt_siprec_rtp_streams_max_threads);
	}
	sip_rec->setVerbose(sverb.siprec);
	sip_rec->startServer();
}

void sipRecStop() {
	if(sip_rec) {
		delete sip_rec;
		sip_rec = NULL;
	}
}

void siprec_test() {
	sip_rec = new cSipRec();
	sip_rec->setRtpPortsLimit(20000, 30000);
	sip_rec->setBindParams(str_2_vmIP("192.168.1.12"), 12345, true);
	sip_rec->setVerbose(true);
	sip_rec->startServer();
}
