#include "ss7_parser.h"

#include "sniff.h"
#include "config_param.h"


extern int opt_ss7_mtp3_standard;
extern int opt_ss7_isup_variant;
extern bool opt_ss7_mtp2_extended_seq;
extern int opt_ss7_m2pa_port;
extern vector<string> opt_ws_params;
extern map<string, string> opt_ws_params_ss7;


void cSs7Parser::parse(packet_s_stack *packetS, vector<Ss7::sParseData> *parse_data, vector<Ss7::sParseData> *parse_data_retransmissions) {
	__SYNC_LOCK(this->_sync_streams);
	u_int32_t time_s = getTimeS_rdtsc();
	u_char *data = (u_char*)packetS->data_();
	unsigned datalen = packetS->datalen_();
	Ss7::sParseData parse_data_item;
	bool ok = false;
	switch(packetS->dlt) {
	case DLT_MTP2:
		ok = parseMtp2(data, datalen, opt_ss7_mtp2_extended_seq, opt_ss7_mtp3_standard, &parse_data_item);
		break;
	case DLT_MTP2_WITH_PHDR:
		ok = datalen > 4 &&
		     parseMtp2(data + 4, datalen - 4,
			       data[1] == SS7_MTP2_ANNEX_A_USED_UNKNOWN ? opt_ss7_mtp2_extended_seq : data[1] == SS7_MTP2_ANNEX_A_USED,
			       opt_ss7_mtp3_standard, &parse_data_item);
		break;
	default:
		switch(packetS->header_ip_protocol()) {
		case IPPROTO_SCTP:
			parseSctp(packetS, data, datalen, opt_ss7_mtp3_standard, time_s, parse_data, parse_data_retransmissions);
			break;
		case IPPROTO_UDP:
			parse_data_item.encaps = Ss7::sParseData::_encaps_rudp;
			ok = parseRudp(data, datalen, opt_ss7_mtp3_standard, &parse_data_item);
			break;
		case IPPROTO_TCP:
			parseSonusTcp(packetS, data, datalen, time_s, parse_data, parse_data_retransmissions);
			break;
		}
		break;
	}
	if(ok) {
		parse_data->push_back(parse_data_item);
	}
	__SYNC_UNLOCK(this->_sync_streams);
}

void cSs7Parser::compare(packet_s_stack *packetS, vector<Ss7::sParseData> *parse_data_ws) {
	vector<Ss7::sParseData> parse_data_native;
	vector<Ss7::sParseData> parse_data_native_retransmissions;
	parse(packetS, &parse_data_native, &parse_data_native_retransmissions);
	vector<bool> native_used(parse_data_native.size(), false);
	vector<bool> native_retransmissions_used(parse_data_native_retransmissions.size(), false);
	string diff;
	for(unsigned i = 0; i < parse_data_ws->size(); i++) {
		Ss7::sParseData *data_ws = &(*parse_data_ws)[i];
		if(!data_ws->isOk()) {
			continue;
		}
		int native_index = findIsupMessage(&parse_data_native, &native_used, data_ws);
		if(native_index >= 0) {
			vector<Ss7::sParseData::sDebugField> fields_ws;
			vector<Ss7::sParseData::sDebugField> fields_native;
			data_ws->getDebugFields(&fields_ws);
			parse_data_native[native_index].getDebugFields(&fields_native);
			for(unsigned j = 0; j < fields_ws.size(); j++) {
				if(fields_ws[j].value != fields_native[j].value) {
					diff += string(" [") + intToString(i) + "] " + fields_ws[j].name + ": ws '" + fields_ws[j].value + "' native '" + fields_native[j].value + "'\n";
				}
			}
		} else if(findIsupMessage(&parse_data_native_retransmissions, &native_retransmissions_used, data_ws) < 0) {
			diff += string(" [") + intToString(i) + "] only ws: " + data_ws->ss7_id() + " message type " + intToString(data_ws->isup_message_type) + "\n";
		}
	}
	for(unsigned i = 0; i < parse_data_native.size(); i++) {
		if(!native_used[i]) {
			diff += string(" only native: ") + parse_data_native[i].ss7_id() + " message type " + intToString(parse_data_native[i].isup_message_type) + "\n";
		}
	}
	if(!diff.empty()) {
		cout << " * SS7 COMPARE * " << Ss7::packetAddressesToString(packetS) << endl
		     << diff;
	}
}

int cSs7Parser::findIsupMessage(vector<Ss7::sParseData> *parse_data, vector<bool> *used, Ss7::sParseData *message) {
	string ss7_id = message->ss7_id();
	for(unsigned i = 0; i < parse_data->size(); i++) {
		if(!(*used)[i] &&
		   (*parse_data)[i].isup_message_type == message->isup_message_type &&
		   (*parse_data)[i].ss7_id() == ss7_id) {
			(*used)[i] = true;
			return(i);
		}
	}
	return(-1);
}

void cSs7Parser::parseSctp(packet_s_stack *packetS, u_char *data, unsigned datalen, int mtp3_standard, u_int32_t time_s, vector<Ss7::sParseData> *parse_data, vector<Ss7::sParseData> *parse_data_retransmissions) {
	iphdr2 *header_ip = packetS->header_ip_();
	u_char *header_sctp = (u_char*)header_ip + header_ip->get_hdr_size();
	u_int16_t sport = ntoh16(header_sctp);
	u_int16_t dport = ntoh16(header_sctp + 2);
	u_int16_t ports[] = { min(sport, dport), max(sport, dport) };
	u_int32_t ports_ppid = 0;
	for(unsigned i = 0; i < 2 && !ports_ppid; i++) {
		if(ports[i] == SS7_SCTP_PORT_M2UA) {
			ports_ppid = SS7_SCTP_PPID_M2UA;
		} else if(ports[i] == SS7_SCTP_PORT_M3UA) {
			ports_ppid = SS7_SCTP_PPID_M3UA;
		} else if(ports[i] == opt_ss7_m2pa_port) {
			ports_ppid = SS7_SCTP_PPID_M2PA;
		}
	}
	sSctpTsns *tsns = NULL;
	bool tsns_lookup_done = false;
	unsigned offset = 0;
	while(offset + 4 <= datalen) {
		unsigned chunk_length = ntoh16(data + offset + 2);
		if(chunk_length < 4) {
			break;
		}
		unsigned chunk_captured_length = min(chunk_length, datalen - offset);
		if(data[offset] != 0 || chunk_captured_length < 16) {
			offset += (chunk_length + 3) & ~3;
			continue;
		}
		u_int32_t ppid = ntoh32(data + offset + 12);
		if(ppid != SS7_SCTP_PPID_M2UA && ppid != SS7_SCTP_PPID_M3UA && ppid != SS7_SCTP_PPID_M2PA) {
			ppid = ports_ppid;
		}
		if(ppid && (data[offset + 1] & 0x03) == 0x03 && chunk_captured_length > 16) {
			u_int32_t tsn = ntoh32(data + offset + 4);
			if(!tsns_lookup_done) {
				sSctpAssocId assoc_id(sport, dport, ntoh32(header_sctp + 4));
				map<sSctpAssocId, sSctpTsns>::iterator iter = sctp_tsns.find(assoc_id);
				if(iter != sctp_tsns.end()) {
					tsns = &iter->second;
				} else if(sctp_tsns.size() < SS7_SCTP_TSN_MAX_ASSOCIATIONS) {
					tsns = &sctp_tsns[assoc_id];
					tsns->spaces[tsns->current_space].max_tsn = tsn;
				}
				if(tsns) {
					tsns->last_time_s = time_s;
				}
				tsns_lookup_done = true;
			}
			vector<Ss7::sParseData> *parse_data_target = (tsns && checkSctpTsnRetransmission(tsns, tsn)) ? parse_data_retransmissions : parse_data;
			if(parse_data_target) {
				Ss7::sParseData parse_data_item;
				parse_data_item.encaps = Ss7::sParseData::_encaps_sctp;
				parse_data_item.transport_seq = tsn;
				bool ok = false;
				switch(ppid) {
				case SS7_SCTP_PPID_M2UA:
					ok = parseM2ua(data + offset + 16, chunk_captured_length - 16, mtp3_standard, &parse_data_item);
					break;
				case SS7_SCTP_PPID_M3UA:
					ok = parseM3ua(data + offset + 16, chunk_captured_length - 16, mtp3_standard, &parse_data_item);
					break;
				case SS7_SCTP_PPID_M2PA:
					ok = parseM2pa(data + offset + 16, chunk_captured_length - 16, mtp3_standard, &parse_data_item);
					break;
				}
				if(ok) {
					parse_data_target->push_back(parse_data_item);
				}
			}
		}
		offset += (chunk_length + 3) & ~3;
	}
}

bool cSs7Parser::checkSctpTsnRetransmission(sSctpTsns *tsns, u_int32_t tsn) {
	if(!isSctpTsnNear(tsns->spaces[tsns->current_space].max_tsn, tsn)) {
		tsns->current_space ^= 1;
		if(!tsns->prev_space_valid || !isSctpTsnNear(tsns->spaces[tsns->current_space].max_tsn, tsn)) {
			tsns->spaces[tsns->current_space].max_tsn = tsn;
			memset(tsns->spaces[tsns->current_space].seen, 0, sizeof(tsns->spaces[tsns->current_space].seen));
		}
		tsns->prev_space_valid = true;
	}
	sSctpTsnSpace *space = &tsns->spaces[tsns->current_space];
	u_int32_t ahead = tsn - space->max_tsn;
	u_int32_t tsn_index = tsn % SS7_SCTP_TSN_WINDOW;
	if(ahead && ahead < SS7_SCTP_TSN_WINDOW) {
		for(u_int32_t i = 1; i <= ahead; ) {
			u_int32_t clear_index = (space->max_tsn + i) % SS7_SCTP_TSN_WINDOW;
			if(!(clear_index % 64) && i + 63 <= ahead) {
				space->seen[clear_index / 64] = 0;
				i += 64;
			} else {
				space->seen[clear_index / 64] &= ~(1ULL << (clear_index % 64));
				i++;
			}
		}
		space->max_tsn = tsn;
	} else if(space->seen[tsn_index / 64] & (1ULL << (tsn_index % 64))) {
		return(true);
	}
	space->seen[tsn_index / 64] |= 1ULL << (tsn_index % 64);
	return(false);
}

void cSs7Parser::setOptionsFromWsParams() {
	extern cConfig CONFIG;
	string value;
	opt_ws_params_ss7.clear();
	if(CONFIG.isSet("ss7_mtp3_standard")) {
		opt_ws_params_ss7["mtp3.standard"] = getWsMtp3StandardName(opt_ss7_mtp3_standard);
	} else if(getWsParam("mtp3.standard", &value)) {
		for(int mtp3_standard = _mtp3_itu; mtp3_standard <= _mtp3_japan; mtp3_standard++) {
			if(!strcasecmp(value.c_str(), getWsMtp3StandardName(mtp3_standard)) ||
			   !strcasecmp(value.c_str(), getWsMtp3StandardDescription(mtp3_standard))) {
				opt_ss7_mtp3_standard = mtp3_standard;
				break;
			}
		}
	}
	if(CONFIG.isSet("ss7_isup_variant")) {
		opt_ws_params_ss7["isup.variant"] = getWsIsupVariantDescription(opt_ss7_isup_variant);
	} else if(getWsParam("isup.variant", &value)) {
		for(int isup_variant = _isup_itu; isup_variant <= _isup_japan_ttc; isup_variant++) {
			if(!strcasecmp(value.c_str(), getWsIsupVariantName(isup_variant)) ||
			   !strcasecmp(value.c_str(), getWsIsupVariantDescription(isup_variant))) {
				opt_ss7_isup_variant = isup_variant;
				break;
			}
		}
	}
	if(CONFIG.isSet("ss7_mtp2_extended_seq")) {
		opt_ws_params_ss7["mtp2.use_extended_sequence_numbers"] = opt_ss7_mtp2_extended_seq ? "TRUE" : "FALSE";
	} else if(getWsParam("mtp2.use_extended_sequence_numbers", &value)) {
		opt_ss7_mtp2_extended_seq = isWsParamTrue(value);
	}
	if(CONFIG.isSet("ss7_m2pa_port")) {
		opt_ws_params_ss7["m2pa.port"] = intToString(opt_ss7_m2pa_port);
	} else if(getWsParam("m2pa.port", &value)) {
		opt_ss7_m2pa_port = atoi(value.c_str());
	}
}

void cSs7Parser::checkWsParams() {
	string value;
	for(map<string, string>::iterator iter = opt_ws_params_ss7.begin(); iter != opt_ws_params_ss7.end(); iter++) {
		if(getWsParam(iter->first.c_str(), &value)) {
			cLogSensor::log(cLogSensor::warning,
					"ws_param overridden by ss7 option",
					"ws_param %s is ignored, ss7 option value %s is used",
					iter->first.c_str(), iter->second.c_str());
		}
	}
	if(opt_enable_ss7 != _ss7_mode_native) {
		return;
	}
	const char *unsupported_params[][2] = {
		{ "m3ua.version", "rfc4666" },
		{ "m2pa.version", "RFC4165" },
		{ "m2ua.protocol_data_1_tag", "rfc3331" }
	};
	for(unsigned i = 0; i < sizeof(unsupported_params) / sizeof(unsupported_params[0]); i++) {
		if(getWsParam(unsupported_params[i][0], &value) && strcasecmp(value.c_str(), unsupported_params[i][1])) {
			cLogSensor::log(cLogSensor::warning,
					"ws_param not supported by ss7 = native",
					"ws_param %s: %s is not supported by ss7 = native, %s is used",
					unsupported_params[i][0], value.c_str(), unsupported_params[i][1]);
		}
	}
	if(getWsParam("mtp2.reverse_bit_order_mtp2", &value) && isWsParamTrue(value)) {
		cLogSensor::log(cLogSensor::warning,
				"ws_param not supported by ss7 = native",
				"ws_param mtp2.reverse_bit_order_mtp2 is not supported by ss7 = native");
	}
}

bool cSs7Parser::getWsParam(const char *name, string *value) {
	const char *name_separator = strchr(name, '.');
	string name_module(name, name_separator - name);
	bool exists = false;
	for(unsigned i = 0; i < opt_ws_params.size(); i++) {
		size_t separator = opt_ws_params[i].find(':');
		if(separator == string::npos) {
			continue;
		}
		string param = opt_ws_params[i].substr(0, separator);
		size_t module_separator = param.find('.');
		if(module_separator != string::npos &&
		   !strcasecmp(trim_str(param.substr(0, module_separator)).c_str(), name_module.c_str()) &&
		   trim_str(param.substr(module_separator + 1)) == name_separator + 1) {
			*value = trim_str(opt_ws_params[i].substr(separator + 1));
			exists = true;
		}
	}
	return(exists);
}

const char *cSs7Parser::getWsMtp3StandardName(int mtp3_standard) {
	switch(mtp3_standard) {
	case _mtp3_ansi:
		return("ansi");
	case _mtp3_china:
		return("chinese-itu");
	case _mtp3_japan:
		return("japan");
	}
	return("itu");
}

const char *cSs7Parser::getWsMtp3StandardDescription(int mtp3_standard) {
	switch(mtp3_standard) {
	case _mtp3_ansi:
		return("ANSI");
	case _mtp3_china:
		return("Chinese ITU");
	case _mtp3_japan:
		return("Japan");
	}
	return("ITU");
}

const char *cSs7Parser::getWsIsupVariantName(int isup_variant) {
	switch(isup_variant) {
	case _isup_french:
		return("French");
	case _isup_israeli:
		return("Israeli");
	case _isup_russian:
		return("Russian");
	case _isup_japan:
		return("Japan");
	case _isup_japan_ttc:
		return("Japan_TTC");
	}
	return("ITU");
}

const char *cSs7Parser::getWsIsupVariantDescription(int isup_variant) {
	switch(isup_variant) {
	case _isup_french:
		return("French National Standard");
	case _isup_israeli:
		return("Israeli National Standard");
	case _isup_russian:
		return("Russian National Standard");
	case _isup_japan:
		return("Japan National Standard");
	case _isup_japan_ttc:
		return("Japan National Standard (TTC)");
	}
	return("ITU Standard");
}

void cSs7Parser::parseSonusTcp(packet_s_stack *packetS, u_char *data, unsigned datalen, u_int32_t time_s, vector<Ss7::sParseData> *parse_data, vector<Ss7::sParseData> *parse_data_retransmissions) {
	tcphdr2 *header_tcp = packetS->header_tcp_();
	sStreamId stream_id(packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_());
	if(header_tcp->flags_bit.syn) {
		sonus_streams.erase(stream_id);
	}
	if(datalen) {
		u_int32_t seq = ntohl(header_tcp->seq);
		sSonusStream *stream;
		map<sStreamId, sSonusStream>::iterator iter = sonus_streams.find(stream_id);
		if(iter == sonus_streams.end()) {
			stream = &sonus_streams[stream_id];
			stream->next_seq = seq;
		} else {
			stream = &iter->second;
		}
		stream->last_time_s = time_s;
		if(seq != stream->next_seq) {
			u_int32_t behind = stream->next_seq - seq;
			if(behind < SS7_SONUS_STREAM_SEQ_WINDOW) {
				if(behind >= datalen) {
					if(parse_data_retransmissions) {
						bool retransmission_synced = false;
						parseSonusCm(data, datalen, &retransmission_synced, parse_data_retransmissions);
					}
					datalen = 0;
				} else {
					data += behind;
					datalen -= behind;
					seq += behind;
				}
			} else {
				stream->pending.clear();
				stream->synced = false;
			}
		}
		if(datalen) {
			stream->next_seq = seq + datalen;
			if(stream->pending.empty()) {
				unsigned processed = parseSonusCm(data, datalen, &stream->synced, parse_data);
				stream->pending.assign((char*)data + processed, datalen - processed);
			} else {
				stream->pending.append((char*)data, datalen);
				unsigned processed = parseSonusCm((u_char*)stream->pending.data(), stream->pending.length(), &stream->synced, parse_data);
				stream->pending.erase(0, processed);
			}
		}
	}
	if(header_tcp->flags_bit.fin || header_tcp->flags_bit.rst) {
		sonus_streams.erase(stream_id);
	}
}

unsigned cSs7Parser::parseSonusCm(u_char *data, unsigned datalen, bool *synced, vector<Ss7::sParseData> *parse_data) {
	unsigned offset = 0;
	while(offset + SS7_SONUS_CM_HEADER_LENGTH <= datalen) {
		u_char *pdu = data + offset;
		unsigned pdu_length = ntoh16(pdu + 2);
		bool header_ok = pdu[0] == 0 && pdu[1] <= SS7_SONUS_CM_MAX_COMMAND;
		if(header_ok && !*synced) {
			if(offset + SS7_SONUS_CM_HEADER_LENGTH + min(pdu_length, (unsigned)SS7_SONUS_IMF_TRAFFIC_HEADER_LENGTH) > datalen) {
				break;
			}
			switch(pdu_length ? pdu[SS7_SONUS_CM_HEADER_LENGTH] : 0) {
			case SS7_SONUS_IMF_TYPE_TRAFFIC:
				header_ok = pdu_length >= SS7_SONUS_IMF_TRAFFIC_HEADER_LENGTH &&
					    ntoh16(pdu + SS7_SONUS_CM_HEADER_LENGTH + 21) == pdu_length - SS7_SONUS_IMF_TRAFFIC_HEADER_LENGTH;
				break;
			case SS7_SONUS_IMF_TYPE_VERSION:
				header_ok = pdu_length >= SS7_SONUS_IMF_VERSION_MIN_LENGTH && pdu_length <= SS7_SONUS_IMF_VERSION_MAX_LENGTH;
				break;
			case SS7_SONUS_IMF_TYPE_LSTATUS:
				header_ok = pdu_length == SS7_SONUS_IMF_LSTATUS_LENGTH;
				break;
			default:
				header_ok = false;
				break;
			}
		}
		if(!header_ok) {
			*synced = false;
			offset++;
			continue;
		}
		if(offset + SS7_SONUS_CM_HEADER_LENGTH + pdu_length > datalen) {
			break;
		}
		parseSonusImf(pdu + SS7_SONUS_CM_HEADER_LENGTH, pdu_length, parse_data);
		*synced = true;
		offset += SS7_SONUS_CM_HEADER_LENGTH + pdu_length;
	}
	return(offset);
}

void cSs7Parser::parseSonusImf(u_char *data, unsigned datalen, vector<Ss7::sParseData> *parse_data) {
	if(datalen < SS7_SONUS_IMF_TRAFFIC_HEADER_LENGTH || data[0] != SS7_SONUS_IMF_TYPE_TRAFFIC ||
	   data[11] < 1 || data[11] > SS7_SONUS_IMF_MAX_NA || data[12] > SS7_SONUS_IMF_MAX_VARIANT ||
	   data[17] > SS7_SONUS_IMF_MAX_DIRECTION || data[19] || data[20]) {
		return;
	}
	unsigned msu_length = ntoh16(data + 21);
	if(msu_length > datalen - SS7_SONUS_IMF_TRAFFIC_HEADER_LENGTH) {
		return;
	}
	int mtp3_standard;
	switch(data[12]) {
	case SS7_SONUS_IMF_VARIANT_ANSI:
		mtp3_standard = _mtp3_ansi;
		break;
	case SS7_SONUS_IMF_VARIANT_ITU:
		mtp3_standard = _mtp3_itu;
		break;
	case SS7_SONUS_IMF_VARIANT_CHINA:
		mtp3_standard = _mtp3_china;
		break;
	case SS7_SONUS_IMF_VARIANT_JAPAN:
		mtp3_standard = _mtp3_japan;
		break;
	default:
		mtp3_standard = opt_ss7_mtp3_standard;
		break;
	}
	Ss7::sParseData parse_data_item;
	parse_data_item.encaps = Ss7::sParseData::_encaps_sonus;
	parse_data_item.transport_seq = ntoh32(data + 7);
	parse_data_item.transport_link = ((u_int64_t)data[11] << 32) | ntoh32(data + 13);
	bool ok = false;
	switch(data[18]) {
	case SS7_SONUS_IMF_LINK_LSL:
	case SS7_SONUS_IMF_LINK_ANNEXA:
	case SS7_SONUS_IMF_LINK_M2PA:
	case SS7_SONUS_IMF_LINK_M2UA:
	case SS7_SONUS_IMF_LINK_ATM:
	case SS7_SONUS_IMF_LINK_IPSP:
	case SS7_SONUS_IMF_LINK_M3UA_MG:
	case SS7_SONUS_IMF_LINK_M3UA_SG:
	case SS7_SONUS_IMF_LINK_M3UA_SRV:
		ok = parseMtp3(data + SS7_SONUS_IMF_TRAFFIC_HEADER_LENGTH, msu_length, mtp3_standard, &parse_data_item);
		break;
	case SS7_SONUS_IMF_LINK_M3UA:
		ok = parseM3ua(data + SS7_SONUS_IMF_TRAFFIC_HEADER_LENGTH, msu_length, mtp3_standard, &parse_data_item);
		break;
	}
	if(ok) {
		parse_data->push_back(parse_data_item);
	}
}

bool cSs7Parser::parseM3ua(u_char *data, unsigned datalen, int mtp3_standard, Ss7::sParseData *parse_data) {
	unsigned offset = 0;
	u_int16_t tag;
	u_char *param;
	unsigned param_length;
	while((tag = getSigtranParam(data, datalen, &offset, &param, &param_length))) {
		if(tag == SS7_M3UA_PARAM_PROTOCOL_DATA) {
			if(param_length <= 12 || param[8] != SS7_MTP3_SI_ISUP) {
				return(false);
			}
			parse_data->m3ua_protocol_data_opc = ntoh32(param);
			parse_data->m3ua_protocol_data_dpc = ntoh32(param + 4);
			parse_data->mtp3_opc = parse_data->m3ua_protocol_data_opc;
			parse_data->mtp3_dpc = parse_data->m3ua_protocol_data_dpc;
			return(parseIsup(param + 12, param_length - 12, mtp3_standard, parse_data));
		}
	}
	return(false);
}

bool cSs7Parser::parseM2ua(u_char *data, unsigned datalen, int mtp3_standard, Ss7::sParseData *parse_data) {
	if(datalen < 8 || data[2] != SS7_M2UA_MESSAGE_CLASS_MAUP || data[3] != SS7_M2UA_MESSAGE_TYPE_DATA) {
		return(false);
	}
	unsigned offset = 0;
	u_int16_t tag;
	u_char *param;
	unsigned param_length;
	while((tag = getSigtranParam(data, datalen, &offset, &param, &param_length))) {
		if(tag == SS7_M2UA_PARAM_INTERFACE_IDENTIFIER_INT && param_length >= 4) {
			parse_data->transport_link = ntoh32(param);
		} else if(tag == SS7_M2UA_PARAM_INTERFACE_IDENTIFIER_TEXT) {
			u_int64_t interface_identifier_hash = 0;
			for(unsigned i = 0; i < param_length; i++) {
				interface_identifier_hash = interface_identifier_hash * 31 + param[i];
			}
			parse_data->transport_link = interface_identifier_hash;
		} else if(tag == SS7_M2UA_PARAM_PROTOCOL_DATA_1) {
			return(parseMtp3(param, param_length, mtp3_standard, parse_data));
		} else if(tag == SS7_M2UA_PARAM_PROTOCOL_DATA_2) {
			return(param_length > 1 && parseMtp3(param + 1, param_length - 1, mtp3_standard, parse_data));
		}
	}
	return(false);
}

bool cSs7Parser::parseM2pa(u_char *data, unsigned datalen, int mtp3_standard, Ss7::sParseData *parse_data) {
	if(datalen < 16 || data[3] != SS7_M2PA_TYPE_USER_DATA) {
		return(false);
	}
	unsigned length = min((unsigned)ntoh32(data + 4), datalen);
	return(length > 17 && parseMtp3(data + 17, length - 17, mtp3_standard, parse_data));
}

bool cSs7Parser::parseMtp2(u_char *data, unsigned datalen, bool extended_seq, int mtp3_standard, Ss7::sParseData *parse_data) {
	unsigned header_length = extended_seq ? 6 : 3;
	if(datalen <= header_length) {
		return(false);
	}
	unsigned li = extended_seq ? letoh16(data + 4) & 0x1FF : data[2] & 0x3F;
	if(li < 3) {
		return(false);
	}
	parse_data->transport_seq = extended_seq ? letoh16(data + 2) & 0x0FFF : data[1] & 0x7F;
	return(parseMtp3(data + header_length, datalen - header_length, mtp3_standard, parse_data));
}

bool cSs7Parser::parseRudp(u_char *data, unsigned datalen, int mtp3_standard, Ss7::sParseData *parse_data) {
	unsigned header_length = datalen >= 4 ? data[1] : 0;
	if(header_length < 4 || header_length + 16 > datalen) {
		return(false);
	}
	u_char *sm = data + header_length;
	unsigned sm_length = datalen - header_length;
	if(ntoh32(sm) != SS7_CISCO_SM_MESSAGE_TYPE_PDU) {
		return(false);
	}
	switch(ntoh16(sm + 4)) {
	case SS7_CISCO_SM_PROTOCOL_BSM_V1:
	case SS7_CISCO_SM_PROTOCOL_EISUP_100:
	case SS7_CISCO_SM_PROTOCOL_EISUP_101:
	case SS7_CISCO_SM_PROTOCOL_EISUP_114:
	case SS7_CISCO_SM_PROTOCOL_EISUP_122:
		return(false);
	}
	u_int16_t pdu_type = ntoh16(sm + 8);
	unsigned pdu_length = ntoh16(sm + 14);
	if(pdu_type != SS7_CISCO_SM_PDU_MTP3_TO_SLT && pdu_type != SS7_CISCO_SM_PDU_MTP3_FROM_SLT) {
		return(false);
	}
	parse_data->transport_seq = data[2];
	parse_data->transport_link = ntoh16(sm + 10);
	return(parseMtp3(sm + 16, min(pdu_length, sm_length - 16), mtp3_standard, parse_data));
}

bool cSs7Parser::parseMtp3(u_char *data, unsigned datalen, int mtp3_standard, Ss7::sParseData *parse_data) {
	if(datalen < 8 || (data[0] & 0x0F) != SS7_MTP3_SI_ISUP) {
		return(false);
	}
	u_char *label = data + 1;
	unsigned label_length;
	switch(mtp3_standard) {
	case _mtp3_ansi:
	case _mtp3_china:
		parse_data->mtp3_dpc = letoh24(label);
		parse_data->mtp3_opc = letoh24(label + 3);
		label_length = 7;
		break;
	case _mtp3_japan:
		parse_data->mtp3_dpc = letoh16(label);
		parse_data->mtp3_opc = letoh16(label + 2);
		label_length = 5;
		break;
	default:
		parse_data->mtp3_dpc = letoh32(label) & 0x3FFF;
		parse_data->mtp3_opc = (letoh32(label) >> 14) & 0x3FFF;
		label_length = 4;
		break;
	}
	return(parseIsup(label + label_length, datalen - 1 - label_length, mtp3_standard, parse_data));
}

bool cSs7Parser::parseIsup(u_char *data, unsigned datalen, int mtp3_standard, Ss7::sParseData *parse_data) {
	if(datalen < 3) {
		return(false);
	}
	parse_data->isup_cic = letoh16(data) & (mtp3_standard == _mtp3_ansi ? 0x3FFF :
						opt_ss7_isup_variant == _isup_japan_ttc ? 0x1FFF :
						0x0FFF);
	parse_data->isup_message_type = data[2];
	data += 3;
	datalen -= 3;
	u_char *param;
	unsigned param_length;
	switch(parse_data->isup_message_type) {
	case SS7_IAM:
		parseIsupIam(data, datalen, mtp3_standard, parse_data);
		break;
	case SS7_SAM:
		if(getIsupVariableParam(data, datalen, 0, &param, &param_length) && param_length > 1) {
			getIsupDigits(param + 1, param_length - 1, param[0] & 0x80, &parse_data->isup_subsequent_number);
		}
		break;
	case SS7_REL:
		if(getIsupVariableParam(data, datalen, 0, &param, &param_length) && param_length > 1) {
			unsigned coding_standard = (param[0] >> 5) & 0x03;
			if(mtp3_standard == _mtp3_ansi) {
				if(coding_standard == SS7_ISUP_CAUSE_CODING_ITU || coding_standard == SS7_ISUP_CAUSE_CODING_NATIONAL) {
					parse_data->isup_cause_indicator = param[1] & 0x7F;
				}
			} else if(coding_standard == SS7_ISUP_CAUSE_CODING_ITU || coding_standard == SS7_ISUP_CAUSE_CODING_ISO) {
				unsigned cause_offset = param[0] & 0x80 ? 1 : 2;
				if(param_length > cause_offset) {
					parse_data->isup_cause_indicator = param[cause_offset] & 0x7F;
				}
			}
		}
		break;
	}
	return(true);
}

void cSs7Parser::parseIsupIam(u_char *data, unsigned datalen, int mtp3_standard, Ss7::sParseData *parse_data) {
	if(!datalen) {
		return;
	}
	parse_data->isup_satellite_indicator = data[0] & 0x03;
	parse_data->isup_echo_control_device_indicator = data[0] & 0x10 ? 1 : 0;
	if(datalen < 4) {
		return;
	}
	parse_data->isup_calling_partys_category = data[3];
	if(datalen > 4 && mtp3_standard != _mtp3_ansi) {
		parse_data->isup_transmission_medium_requirement = data[4];
	}
	if(datalen < 7) {
		return;
	}
	u_char *param;
	unsigned param_length;
	if(getIsupVariableParam(data, datalen, 5, &param, &param_length) && param_length >= 2) {
		parse_data->isup_called_party_nature_of_address_indicator = param[0] & 0x7F;
		parse_data->isup_inn_indicator = param[1] & 0x80 ? 1 : 0;
		getIsupDigits(param + 2, param_length - 2, param[0] & 0x80, &parse_data->e164_called_party_number_digits);
	}
	if(!data[6]) {
		return;
	}
	unsigned offset = 6 + data[6];
	while(offset + 2 <= datalen && data[offset]) {
		param = data + offset + 2;
		param_length = data[offset + 1];
		if(offset + 2 + param_length > datalen) {
			break;
		}
		if(data[offset] == SS7_ISUP_PARAM_CALLING_PARTY_NUMBER && param_length >= 2) {
			parse_data->isup_calling_party_nature_of_address_indicator = param[0] & 0x7F;
			parse_data->isup_ni_indicator = param[1] & 0x80 ? 1 : 0;
			parse_data->isup_address_presentation_restricted_indicator = (param[1] & 0x0C) >> 2;
			parse_data->isup_screening_indicator = param[1] & 0x03;
			getIsupDigits(param + 2, param_length - 2, param[0] & 0x80, &parse_data->e164_calling_party_number_digits);
			break;
		}
		offset += 2 + param_length;
	}
}

u_int16_t cSs7Parser::getSigtranParam(u_char *data, unsigned datalen, unsigned *offset, u_char **param, unsigned *param_length) {
	if(datalen < 8) {
		return(0);
	}
	unsigned length = min((unsigned)ntoh32(data + 4), datalen);
	if(*offset < 8) {
		*offset = 8;
	}
	if(*offset + 4 > length) {
		return(0);
	}
	u_int16_t tag = ntoh16(data + *offset);
	unsigned tlv_length = ntoh16(data + *offset + 2);
	if(tlv_length < 4) {
		return(0);
	}
	*param = data + *offset + 4;
	*param_length = min(tlv_length, length - *offset) - 4;
	*offset += (tlv_length + 3) & ~3;
	return(tag);
}

bool cSs7Parser::getIsupVariableParam(u_char *data, unsigned datalen, unsigned pointer_offset, u_char **param, unsigned *param_length) {
	if(pointer_offset >= datalen || !data[pointer_offset]) {
		return(false);
	}
	unsigned length_offset = pointer_offset + data[pointer_offset];
	if(length_offset >= datalen) {
		return(false);
	}
	*param = data + length_offset + 1;
	*param_length = min((unsigned)data[length_offset], datalen - length_offset - 1);
	return(true);
}

void cSs7Parser::getIsupDigits(u_char *data, unsigned datalen, bool odd, string *digits) {
	unsigned count = datalen * 2 - (odd && datalen ? 1 : 0);
	for(unsigned i = 0; i < count && i < 32; i++) {
		u_char digit = i % 2 ? data[i / 2] >> 4 : data[i / 2] & 0x0F;
		digits->push_back(digit < 10 ? '0' + digit : 'A' + digit - 10);
	}
}
