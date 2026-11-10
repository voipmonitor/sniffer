#ifndef SS7_PARSER_H
#define SS7_PARSER_H

#include "calltable.h"


#define SS7_PARSER_STREAM_TIMEOUT_S 300

#define SS7_SCTP_TSN_WINDOW 16384
#define SS7_SCTP_TSN_MAX_ASSOCIATIONS 10000

#define SS7_SCTP_PPID_M2UA 2
#define SS7_SCTP_PPID_M3UA 3
#define SS7_SCTP_PPID_M2PA 5

#define SS7_SCTP_PORT_M2UA 2904
#define SS7_SCTP_PORT_M3UA 2905
#define SS7_SCTP_PORT_M2PA 3565

#define SS7_M3UA_PARAM_PROTOCOL_DATA 0x0210
#define SS7_M2UA_MESSAGE_CLASS_MAUP 6
#define SS7_M2UA_MESSAGE_TYPE_DATA 1
#define SS7_M2UA_PARAM_INTERFACE_IDENTIFIER_INT 0x0001
#define SS7_M2UA_PARAM_INTERFACE_IDENTIFIER_TEXT 0x0003
#define SS7_M2UA_PARAM_PROTOCOL_DATA_1 0x0300
#define SS7_M2UA_PARAM_PROTOCOL_DATA_2 0x0301
#define SS7_M2PA_TYPE_USER_DATA 1

#define SS7_MTP2_ANNEX_A_USED 1
#define SS7_MTP2_ANNEX_A_USED_UNKNOWN 2

#define SS7_CISCO_SM_MESSAGE_TYPE_PDU 0x8000
#define SS7_CISCO_SM_PROTOCOL_BSM_V1 0x0004
#define SS7_CISCO_SM_PROTOCOL_EISUP_100 0x0100
#define SS7_CISCO_SM_PROTOCOL_EISUP_101 0x0101
#define SS7_CISCO_SM_PROTOCOL_EISUP_114 0x0114
#define SS7_CISCO_SM_PROTOCOL_EISUP_122 0x0122
#define SS7_CISCO_SM_PDU_MTP3_TO_SLT 0x10
#define SS7_CISCO_SM_PDU_MTP3_FROM_SLT 0x11

#define SS7_SONUS_CM_HEADER_LENGTH 4
#define SS7_SONUS_CM_MAX_COMMAND 2
#define SS7_SONUS_IMF_TYPE_LSTATUS 252
#define SS7_SONUS_IMF_TYPE_TRAFFIC 253
#define SS7_SONUS_IMF_TYPE_VERSION 254
#define SS7_SONUS_IMF_TRAFFIC_HEADER_LENGTH 23
#define SS7_SONUS_IMF_VERSION_MIN_LENGTH 9
#define SS7_SONUS_IMF_VERSION_MAX_LENGTH 25
#define SS7_SONUS_IMF_LSTATUS_LENGTH 20
#define SS7_SONUS_IMF_MAX_NA 99
#define SS7_SONUS_IMF_MAX_DIRECTION 2
#define SS7_SONUS_IMF_VARIANT_ANSI 1
#define SS7_SONUS_IMF_VARIANT_ITU 2
#define SS7_SONUS_IMF_VARIANT_CHINA 3
#define SS7_SONUS_IMF_VARIANT_JAPAN 4
#define SS7_SONUS_IMF_MAX_VARIANT 5
#define SS7_SONUS_IMF_LINK_LSL 1
#define SS7_SONUS_IMF_LINK_ANNEXA 2
#define SS7_SONUS_IMF_LINK_M2PA 3
#define SS7_SONUS_IMF_LINK_M2UA 4
#define SS7_SONUS_IMF_LINK_ATM 5
#define SS7_SONUS_IMF_LINK_M3UA 6
#define SS7_SONUS_IMF_LINK_IPSP 10
#define SS7_SONUS_IMF_LINK_M3UA_MG 11
#define SS7_SONUS_IMF_LINK_M3UA_SG 13
#define SS7_SONUS_IMF_LINK_M3UA_SRV 14
#define SS7_SONUS_STREAM_SEQ_WINDOW (1 << 24)

#define SS7_MTP3_SI_ISUP 5

#define SS7_ISUP_PARAM_CALLING_PARTY_NUMBER 0x0A
#define SS7_ISUP_CAUSE_CODING_ITU 0
#define SS7_ISUP_CAUSE_CODING_ISO 1
#define SS7_ISUP_CAUSE_CODING_NATIONAL 2


class cSs7Parser {
public:
	enum eMtp3Standard {
		_mtp3_itu = 1,
		_mtp3_ansi,
		_mtp3_china,
		_mtp3_japan
	};
	enum eIsupVariant {
		_isup_itu = 1,
		_isup_french,
		_isup_israeli,
		_isup_russian,
		_isup_japan,
		_isup_japan_ttc
	};
private:
	struct sSctpAssocId {
		sSctpAssocId(u_int16_t sport, u_int16_t dport, u_int32_t vtag) {
			this->sport = sport;
			this->dport = dport;
			this->vtag = vtag;
		}
		bool operator < (const sSctpAssocId& other) const {
			return(this->vtag < other.vtag ||
			       (this->vtag == other.vtag &&
				(this->sport < other.sport ||
				 (this->sport == other.sport && this->dport < other.dport))));
		}
		u_int16_t sport;
		u_int16_t dport;
		u_int32_t vtag;
	};
	struct sSctpTsnSpace {
		u_int32_t max_tsn;
		u_int64_t seen[SS7_SCTP_TSN_WINDOW / 64];
	};
	struct sSctpTsns {
		sSctpTsns() {
			current_space = 0;
			prev_space_valid = false;
			last_time_s = 0;
			memset(spaces, 0, sizeof(spaces));
		}
		sSctpTsnSpace spaces[2];
		unsigned current_space;
		bool prev_space_valid;
		u_int32_t last_time_s;
	};
	struct sSonusStream {
		sSonusStream() {
			next_seq = 0;
			last_time_s = 0;
			synced = false;
		}
		u_int32_t next_seq;
		u_int32_t last_time_s;
		bool synced;
		string pending;
	};
public:
	cSs7Parser() {
		_sync_streams = 0;
	}
	void clearStreams() {
		__SYNC_LOCK(this->_sync_streams);
		sctp_tsns.clear();
		sonus_streams.clear();
		__SYNC_UNLOCK(this->_sync_streams);
	}
	void cleanup(u_int32_t time_s) {
		__SYNC_LOCK(this->_sync_streams);
		cleanupStreams(&sctp_tsns, time_s);
		cleanupStreams(&sonus_streams, time_s);
		__SYNC_UNLOCK(this->_sync_streams);
	}
	void parse(packet_s_stack *packetS, vector<Ss7::sParseData> *parse_data, vector<Ss7::sParseData> *parse_data_retransmissions = NULL);
	void compare(packet_s_stack *packetS, vector<Ss7::sParseData> *parse_data_ws);
	static void setOptionsFromWsParams();
	static void checkWsParams();
private:
	static bool getWsParam(const char *name, string *value);
	static bool isWsParamTrue(string value) {
		return(!strcasecmp(value.c_str(), "true") || !strcasecmp(value.c_str(), "yes"));
	}
	static const char *getWsMtp3StandardName(int mtp3_standard);
	static const char *getWsMtp3StandardDescription(int mtp3_standard);
	static const char *getWsIsupVariantName(int isup_variant);
	static const char *getWsIsupVariantDescription(int isup_variant);
	static int findIsupMessage(vector<Ss7::sParseData> *parse_data, vector<bool> *used, Ss7::sParseData *message);
	void parseSctp(packet_s_stack *packetS, u_char *data, unsigned datalen, int mtp3_standard, u_int32_t time_s, vector<Ss7::sParseData> *parse_data, vector<Ss7::sParseData> *parse_data_retransmissions);
	static bool isSctpTsnNear(u_int32_t max_tsn, u_int32_t tsn) {
		return(tsn - max_tsn - 1 < SS7_SCTP_TSN_WINDOW - 1 || max_tsn - tsn < SS7_SCTP_TSN_WINDOW);
	}
	bool checkSctpTsnRetransmission(sSctpTsns *tsns, u_int32_t tsn);
	void parseSonusTcp(packet_s_stack *packetS, u_char *data, unsigned datalen, u_int32_t time_s, vector<Ss7::sParseData> *parse_data, vector<Ss7::sParseData> *parse_data_retransmissions);
	unsigned parseSonusCm(u_char *data, unsigned datalen, bool *synced, vector<Ss7::sParseData> *parse_data);
	void parseSonusImf(u_char *data, unsigned datalen, vector<Ss7::sParseData> *parse_data);
	bool parseM3ua(u_char *data, unsigned datalen, int mtp3_standard, Ss7::sParseData *parse_data);
	bool parseM2ua(u_char *data, unsigned datalen, int mtp3_standard, Ss7::sParseData *parse_data);
	bool parseM2pa(u_char *data, unsigned datalen, int mtp3_standard, Ss7::sParseData *parse_data);
	bool parseMtp2(u_char *data, unsigned datalen, bool extended_seq, int mtp3_standard, Ss7::sParseData *parse_data);
	bool parseRudp(u_char *data, unsigned datalen, int mtp3_standard, Ss7::sParseData *parse_data);
	bool parseMtp3(u_char *data, unsigned datalen, int mtp3_standard, Ss7::sParseData *parse_data);
	bool parseIsup(u_char *data, unsigned datalen, int mtp3_standard, Ss7::sParseData *parse_data);
	void parseIsupIam(u_char *data, unsigned datalen, int mtp3_standard, Ss7::sParseData *parse_data);
	u_int16_t getSigtranParam(u_char *data, unsigned datalen, unsigned *offset, u_char **param, unsigned *param_length);
	bool getIsupVariableParam(u_char *data, unsigned datalen, unsigned pointer_offset, u_char **param, unsigned *param_length);
	void getIsupDigits(u_char *data, unsigned datalen, bool odd, string *digits);
	template<class tKey, class tStream>
	void cleanupStreams(map<tKey, tStream> *streams, u_int32_t time_s) {
		for(typename map<tKey, tStream>::iterator iter = streams->begin(); iter != streams->end(); ) {
			if(iter->second.last_time_s + SS7_PARSER_STREAM_TIMEOUT_S < time_s) {
				streams->erase(iter++);
			} else {
				iter++;
			}
		}
	}
private:
	map<sSctpAssocId, sSctpTsns> sctp_tsns;
	map<sStreamId, sSonusStream> sonus_streams;
	volatile int _sync_streams;
};


#endif
