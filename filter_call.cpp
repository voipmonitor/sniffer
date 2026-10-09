#include <math.h>

#include "filter_call.h"
#include "calltable.h"
#include "header_packet.h"
#include "codecs.h"


extern CustomHeaders *custom_headers_cdr;


static const char *sipResponseSeparators = ",\n or \n OR \n|";
static const char *orValuesSeparators = " or \n OR \n|";
static const char *callidDtmfSeparators = ",\n;\n or \n OR \n|\n ";
static const char *filterKeysIgnore = ",datefrom,dateto,datefrom_strict,dateto_strict,last_days,last_minutes,rec_filter_sections,";

static struct {
	const char *name;
	u_int64_t flags;
} callFlagsFilters[] = {
	{ "missing_srtp_key", CDR_SRTP_WITHOUT_KEY },
	{ "detect_fas", CDR_FAS_DETECTED },
	{ "detect_zerossrc", CDR_ZEROSSRC_DETECTED },
	{ "is_sipalg_detected", CDR_SIPALG_DETECTED },
	{ "proclim_suppress_rtp_read", CDR_PROCLIM_SUPPRESS_RTP_READ },
	{ "proclim_suppress_rtp_proc", CDR_PROCLIM_SUPPRESS_RTP_PROC },
	{ "pcap_in_safespool", CDR_PCAP_IN_SAFESPOOLDIR },
	{ "pcap_dump_error", CDR_PCAP_DUMP_ERROR_DLT | CDR_PCAP_DUMP_ERROR_MAXPCAPSIZE | CDR_PCAP_DUMP_ERROR_CAPLEN },
	{ "duplicate_seq_in_rtp", CDR_RTP_DUPL_SEQ },
	{ "stopped_jb_due_to_high_ooo", CDR_STOPPED_JB_DUE_TO_HIGH_OOO },
	{ "detect_fas_silence_after_answer", CDR_SILENCE_AFTERANSWER },
	{ "next_branches", CDR_NEXT_BRANCHES }
};

static struct {
	const char *name;
	const char *value;
	cRecordFilterItem_Call::eTypeFilter typeFilter;
	u_int64_t flags;
	u_int64_t flags_eq;
} callFlagsValueFilters[] = {
	{ "ip_fragmented", "no", cRecordFilterItem_Call::_tf_flags_eq, CDR_SIP_FRAGMENTED | CDR_RTP_FRAGMENTED, 0 },
	{ "ip_fragmented", "sip", cRecordFilterItem_Call::_tf_flags, CDR_SIP_FRAGMENTED, 0 },
	{ "ip_fragmented", "rtp", cRecordFilterItem_Call::_tf_flags, CDR_RTP_FRAGMENTED, 0 },
	{ "ip_fragmented", "sip_or_rtp", cRecordFilterItem_Call::_tf_flags, CDR_SIP_FRAGMENTED | CDR_RTP_FRAGMENTED, 0 },
	{ "change_src_rtp_port", "none", cRecordFilterItem_Call::_tf_flags_eq, CDR_CHANGE_SRC_PORT_CALLER | CDR_CHANGE_SRC_PORT_CALLED, 0 },
	{ "change_src_rtp_port", "caller", cRecordFilterItem_Call::_tf_flags, CDR_CHANGE_SRC_PORT_CALLER, 0 },
	{ "change_src_rtp_port", "called", cRecordFilterItem_Call::_tf_flags, CDR_CHANGE_SRC_PORT_CALLED, 0 },
	{ "change_src_rtp_port", "caller_or_called", cRecordFilterItem_Call::_tf_flags, CDR_CHANGE_SRC_PORT_CALLER | CDR_CHANGE_SRC_PORT_CALLED, 0 },
	{ "change_src_rtp_port", "caller_and_called", cRecordFilterItem_Call::_tf_flags_eq, CDR_CHANGE_SRC_PORT_CALLER | CDR_CHANGE_SRC_PORT_CALLED, CDR_CHANGE_SRC_PORT_CALLER | CDR_CHANGE_SRC_PORT_CALLED },
	{ "televent_request_response", "request_with_response", cRecordFilterItem_Call::_tf_flags_eq, CDR_TELEVENT_EXISTS_REQUEST | CDR_TELEVENT_EXISTS_RESPONSE, CDR_TELEVENT_EXISTS_REQUEST | CDR_TELEVENT_EXISTS_RESPONSE },
	{ "televent_request_response", "request_without_response", cRecordFilterItem_Call::_tf_flags_eq, CDR_TELEVENT_EXISTS_REQUEST | CDR_TELEVENT_EXISTS_RESPONSE, CDR_TELEVENT_EXISTS_REQUEST },
	{ "televent_request_response", "no_request", cRecordFilterItem_Call::_tf_flags_eq, CDR_TELEVENT_EXISTS_REQUEST, 0 }
};

static struct {
	const char *name1;
	const char *name2;
	const char *typeName;
	const char *column1;
	const char *column2;
} cdrMosFilters[] = {
	{ "mosf1", "mosf1_called", "mos_callerd_type", "a_mos_f1_mult10", "b_mos_f1_mult10" },
	{ "mosf2", "mosf2_called", "mos_callerd_type", "a_mos_f2_mult10", "b_mos_f2_mult10" },
	{ "mosadapt", "mosadapt_called", "mos_callerd_type", "a_mos_adapt_mult10", "b_mos_adapt_mult10" },
	{ "mos_lqo_caller", "mos_lqo_called", "mos_callerd_type", "a_mos_lqo_mult10", "b_mos_lqo_mult10" },
	{ "mosf1_min", "mosf1_min_called", "mos_min_tab_callerd_type", "a_mos_f1_min_mult10", "b_mos_f1_min_mult10" },
	{ "mosf2_min", "mosf2_min_called", "mos_min_tab_callerd_type", "a_mos_f2_min_mult10", "b_mos_f2_min_mult10" },
	{ "mosadapt_min", "mosadapt_min_called", "mos_min_tab_callerd_type", "a_mos_adapt_min_mult10", "b_mos_adapt_min_mult10" }
};

static struct {
	const char *name;
	const char *columns_a;
	const char *columns_b;
	double divisor;
} cdrMetricFilters[] = {
	{ "mos_min_min", "a_mos_f1_min_mult10,a_mos_f2_min_mult10,a_mos_adapt_min_mult10", "b_mos_f1_min_mult10,b_mos_f2_min_mult10,b_mos_adapt_min_mult10", 10 },
	{ "mos_xr_avg", "a_mos_xr_mult10", "b_mos_xr_mult10", 10 },
	{ "mos_xr_min", "a_mos_xr_min_mult10", "b_mos_xr_min_mult10", 10 },
	{ "mos_silence_avg", "a_mos_silence_mult10", "b_mos_silence_mult10", 10 },
	{ "mos_silence_min", "a_mos_silence_min_mult10", "b_mos_silence_min_mult10", 10 },
	{ "rtcp_frl_pkt", "a_rtcp_fraclost_pktcount", "b_rtcp_fraclost_pktcount", 1 },
	{ "delay_sum", "a_delay_sum", "b_delay_sum", 1 },
	{ "delay_avg", "a_delay_avg_mult100", "b_delay_avg_mult100", 100 },
	{ "jitter_max", "a_maxjitter", "b_maxjitter", 1 },
	{ "jitter_avg", "a_avgjitter_mult10", "b_avgjitter_mult10", 10 },
	{ "mos_f1_min", "a_mos_f1_min_mult10", "b_mos_f1_min_mult10", 10 },
	{ "mos_f2_min", "a_mos_f2_min_mult10", "b_mos_f2_min_mult10", 10 },
	{ "mos_adapt_min", "a_mos_adapt_min_mult10", "b_mos_adapt_min_mult10", 10 },
	{ "mos_f1_avg", "a_mos_f1_mult10", "b_mos_f1_mult10", 10 },
	{ "mos_f2_avg", "a_mos_f2_mult10", "b_mos_f2_mult10", 10 },
	{ "mos_adapt_avg", "a_mos_adapt_mult10", "b_mos_adapt_mult10", 10 },
	{ "packet_loss_perc", "a_packet_loss_perc_mult1000", "b_packet_loss_perc_mult1000", 1000 },
	{ "silence", "caller_silence", "called_silence", 1 },
	{ "silence_end", "caller_silence_end", "called_silence_end", 1 },
	{ "clipping", "caller_clipping_div3", "called_clipping_div3", 1./3 },
	{ "silence_afteranswer", "silence_afteranswer", "silence_afteranswer", 100 },
	{ "rtp_ttl_min", "a_ttl_min", "b_ttl_min", 1 },
	{ "rtp_ttl_max", "a_ttl_max", "b_ttl_max", 1 },
	{ "rtp_ttl_avg", "a_ttl_avg_mult10", "b_ttl_avg_mult10", 10 },
	{ "rtp_ab_ptime", "a_rtp_ptime", "b_rtp_ptime", 1 }
};

static struct {
	const char *name1;
	const char *name2;
	const char *typeName;
	const char *column1;
	const char *column2;
	double divisor;
	double value_mult;
	double value_offset;
} cdrRtcpFilters[] = {
	{ "rtcp_maxjitter", "rtcp_maxjitter_called", "rtcp_jitter_callerd_type", "a_rtcp_maxjitter", "b_rtcp_maxjitter", 1, 1, 0 },
	{ "rtcp_avgjitter", "rtcp_avgjitter_called", "rtcp_jitter_callerd_type", "a_rtcp_avgjitter_mult10", "b_rtcp_avgjitter_mult10", 10, 1, 0 },
	{ "rtcp_maxfr", "rtcp_maxfr_called", "rtcp_fr_callerd_type", "a_rtcp_maxfr", "b_rtcp_maxfr", 1, 2.56, -0.05 },
	{ "rtcp_avgfr", "rtcp_avgfr_called", "rtcp_fr_callerd_type", "a_rtcp_avgfr_mult10", "b_rtcp_avgfr_mult10", 10, 2.56, -0.05 },
	{ "rtcp_maxrtd", "rtcp_maxrtd_called", "rtcp_rtd_callerd_type", "a_rtcp_maxrtd_mult10", "b_rtcp_maxrtd_mult10", 10, 1, 0 },
	{ "rtcp_avgrtd", "rtcp_avgrtd_called", "rtcp_rtd_callerd_type", "a_rtcp_avgrtd_mult10", "b_rtcp_avgrtd_mult10", 10, 1, 0 }
};

static struct {
	const char *name;
	eCallField field;
} cdrTtlFilters[] = {
	{ "ttl_min", cf_ttl_min },
	{ "ttl_max", cf_ttl_max },
	{ "ttl_avg", cf_ttl_avg }
};

static struct {
	int codec;
	int variants[5];
} codecVariants[] = {
	{ PAYLOAD_SILK, { PAYLOAD_SILK8, PAYLOAD_SILK12, PAYLOAD_SILK16, PAYLOAD_SILK24, -1 } },
	{ PAYLOAD_ISAC, { PAYLOAD_ISAC16, PAYLOAD_ISAC32, -1, -1, -1 } },
	{ PAYLOAD_G7221, { PAYLOAD_G72218, PAYLOAD_G722112, PAYLOAD_G722116, PAYLOAD_G722124, PAYLOAD_G722148 } },
	{ PAYLOAD_OPUS, { PAYLOAD_OPUS8, PAYLOAD_OPUS12, PAYLOAD_OPUS16, PAYLOAD_OPUS24, PAYLOAD_OPUS48 } },
	{ PAYLOAD_XOPUS, { PAYLOAD_XOPUS8, PAYLOAD_XOPUS12, PAYLOAD_XOPUS16, PAYLOAD_XOPUS24, PAYLOAD_XOPUS48 } }
};


cRecordFilterItem_CheckStringOr::cRecordFilterItem_CheckStringOr(cRecordFilter *parent, unsigned recordFieldIndex, const char *filter, const char *separators, const char *separatorsSeparator, bool enableNull)
 : cRecordFilterItem_base(parent, recordFieldIndex) {
	null = false;
	emptyAsNull = false;
	vector<string> values;
	if(!separators || !*separators) {
		string value = trim_str(filter);
		if(!value.empty()) {
			values.push_back(value);
		}
	} else {
		values = split_filter(filter, separators, separatorsSeparator);
	}
	for(unsigned i = 0; i < values.size(); i++) {
		if(enableNull && values[i] == "NULL") {
			null = true;
			continue;
		}
		sItem item;
		string value = values[i];
		if(!value.empty() && value[0] == '!') {
			item._not = true;
			value = value.substr(1);
		}
		item.pattern.add(value.c_str(), false);
		items.push_back(item);
	}
}

bool cRecordFilterItem_CheckStringOr::check(void *rec, bool */*findInBlackList*/) {
	if(!items.size() && !null) {
		return(true);
	}
	string value = getField_string(rec);
	if(emptyAsNull && value.empty()) {
		return(null);
	}
	if(null && value.find_first_not_of(' ') == string::npos) {
		return(true);
	}
	return(checkValue(value.c_str()));
}

bool cRecordFilterItem_CheckStringOr::checkValue(const char *value) {
	for(unsigned i = 0; i < items.size(); i++) {
		bool match = items[i].pattern.check(value);
		if(items[i]._not ? !match : match) {
			return(true);
		}
	}
	return(false);
}

bool cRecordFilterItem_CustomHeaderNum::check(void *rec, bool */*findInBlackList*/) {
	if(custom_headers_cdr) {
		string customHeaderContent = custom_headers_cdr->getValue((Call*)rec, INVITE, customHeader.c_str());
		if(!customHeaderContent.empty()) {
			double customHeaderValue = atof(customHeaderContent.c_str());
			return(cond == cRecordFilterItem_base::_ge ?
				customHeaderValue >= value :
				customHeaderValue < value);
		}
	}
	return(false);
}

bool cRecordFilterItem_CustomHeader::check(void *rec, bool */*findInBlackList*/) {
	if(!custom_headers_cdr || (!items.size() && !null)) {
		return(true);
	}
	string customHeaderContent = custom_headers_cdr->getValue((Call*)rec, INVITE, customHeader.c_str());
	if(customHeaderContent.empty()) {
		return(null);
	}
	return(checkValue(customHeaderContent.c_str()));
}


cRecordFilterItem_SipResponseNum::cRecordFilterItem_SipResponseNum(cRecordFilter *parent, unsigned recordFieldIndex, const char *filter)
 : cRecordFilterItem_base(parent, recordFieldIndex) {
	vector<string> items = split(filter, split(" |,|;|\t|\r|\n", "|"), true);
	for(unsigned i = 0; i < items.size(); i++) {
		if(items[i][0] == '!') {
			ranges_not.push_back(parseRange(items[i].substr(1)));
		} else {
			ranges.push_back(parseRange(items[i]));
		}
	}
}

bool cRecordFilterItem_SipResponseNum::check(void *rec, bool *findInBlackList) {
	int num = getField_int(rec);
	if(ranges_not.size() && inRanges(&ranges_not, num)) {
		if(findInBlackList) {
			*findInBlackList = true;
		}
		return(false);
	}
	return(!ranges.size() || inRanges(&ranges, num));
}

bool cRecordFilterItem_SipResponseNum::isNumFilter(const char *filter) {
	vector<string> items = split(filter, split(" |,|;|\t|\r|\n", "|"), true);
	if(!items.size()) {
		return(false);
	}
	for(unsigned i = 0; i < items.size(); i++) {
		string item = trimNumSuffix(items[i][0] == '!' ? items[i].substr(1) : items[i]);
		if(item.empty()) {
			return(false);
		}
		for(unsigned j = 0; j < item.length(); j++) {
			if(!isdigit(item[j])) {
				return(false);
			}
		}
	}
	return(true);
}

string cRecordFilterItem_SipResponseNum::trimNumSuffix(string item) {
	while(item.length() && (item[item.length() - 1] == '%' || toupper(item[item.length() - 1]) == 'X')) {
		item.resize(item.length() - 1);
	}
	return(item);
}

cRecordFilterItem_SipResponseNum::sRange cRecordFilterItem_SipResponseNum::parseRange(string item) {
	item = trimNumSuffix(item);
	sRange range;
	if(atoi(item.c_str()) < 100) {
		string from = item;
		string to = item;
		while(from.length() < 3) {
			from += '0';
			to += '9';
		}
		range.from = atoi(from.c_str());
		range.to = atoi(to.c_str());
	} else {
		range.from = range.to = atoi(item.c_str());
	}
	return(range);
}

bool cRecordFilterItem_SipResponseNum::inRanges(vector<sRange> *ranges, int num) {
	for(unsigned i = 0; i < ranges->size(); i++) {
		if(num >= (*ranges)[i].from && num <= (*ranges)[i].to) {
			return(true);
		}
	}
	return(false);
}

cRecordFilterItem_SipResponse::cRecordFilterItem_SipResponse(cRecordFilter *parent, const char *filter)
 : cRecordFilterItem_rec(parent) {
	positive_never = false;
	vector<string> values = split_filter(filter, sipResponseSeparators, "\n");
	for(unsigned i = 0; i < values.size(); i++) {
		if(values[i].empty()) {
			positive_never = true;
			continue;
		}
		sItem item;
		item._not = values[i][0] == '!';
		if(cRecordFilterItem_SipResponseNum::isNumFilter(values[i].c_str())) {
			item.num = new FILE_LINE(0) cRecordFilterItem_SipResponseNum(parent, cf_lastSIPresponseNum, values[i].c_str());
		} else {
			string value = item._not ? values[i].substr(1) : values[i];
			item.pattern.add(value.c_str(), false);
		}
		items.push_back(item);
	}
}

cRecordFilterItem_SipResponse::~cRecordFilterItem_SipResponse() {
	for(unsigned i = 0; i < items.size(); i++) {
		if(items[i].num) {
			delete items[i].num;
		}
	}
}

bool cRecordFilterItem_SipResponse::check(void *rec, bool */*findInBlackList*/) {
	string lastSIPresponse;
	bool lastSIPresponse_set = false;
	bool exists_positive = positive_never;
	bool match_positive = false;
	for(unsigned i = 0; i < items.size(); i++) {
		bool match;
		if(items[i].num) {
			match = items[i].num->check(rec);
		} else {
			if(!lastSIPresponse_set) {
				lastSIPresponse = parent->getField_string(rec, cf_lastSIPresponse);
				lastSIPresponse_set = true;
			}
			match = items[i].pattern.check(lastSIPresponse.c_str());
			if(items[i]._not) {
				match = !match;
			}
		}
		if(items[i]._not) {
			if(!match) {
				return(false);
			}
		} else {
			exists_positive = true;
			if(match) {
				match_positive = true;
			}
		}
	}
	return(!exists_positive || match_positive);
}

cRecordFilterItem_SipResponseAll::cRecordFilterItem_SipResponseAll(cRecordFilter *parent, const char *filter)
 : cRecordFilterItem_rec(parent) {
	vector<string> values = split_filter(filter, sipResponseSeparators, "\n");
	for(unsigned i = 0; i < values.size(); i++) {
		bool _not = !values[i].empty() && values[i][0] == '!';
		string value = _not ? values[i].substr(1) : values[i];
		sItem item;
		if(isNumber(value.c_str())) {
			item.num = atoi(value.c_str());
		} else {
			item.pattern.add(value.c_str(), false);
		}
		if(_not) {
			items_not.push_back(item);
		} else {
			items.push_back(item);
		}
	}
}

bool cRecordFilterItem_SipResponseAll::check(void *rec, bool *findInBlackList) {
	CallBranch *c_branch = ((Call*)rec)->branch_main();
	for(unsigned i = 0; i < items_not.size(); i++) {
		if(checkItem(c_branch, &items_not[i])) {
			if(findInBlackList) {
				*findInBlackList = true;
			}
			return(false);
		}
	}
	if(items.size()) {
		for(unsigned i = 0; i < items.size(); i++) {
			if(checkItem(c_branch, &items[i])) {
				return(true);
			}
		}
		return(false);
	}
	return(true);
}

bool cRecordFilterItem_SipResponseAll::checkItem(CallBranch *c_branch, sItem *item) {
	extern bool opt_cdr_sipresp;
	bool rslt = false;
	c_branch->sip_resp_hist_lock();
	if(opt_cdr_sipresp) {
		for(list<Call::sSipResponse>::iterator iter = c_branch->SIPresponse.begin(); iter != c_branch->SIPresponse.end() && !rslt; iter++) {
			rslt = item->num >= 0 ?
				iter->SIPresponseNum == item->num :
				item->pattern.check(iter->SIPresponse.c_str());
		}
	}
	for(list<Call::sSipHistory>::iterator iter = c_branch->SIPhistory.begin(); iter != c_branch->SIPhistory.end() && !rslt; iter++) {
		if(iter->SIPresponseNum) {
			rslt = item->num >= 0 ?
				iter->SIPresponseNum == item->num :
				item->pattern.check(iter->SIPresponse.c_str());
		}
	}
	c_branch->sip_resp_hist_unlock();
	return(rslt);
}

cRecordFilterItem_SipRequestHist::cRecordFilterItem_SipRequestHist(cRecordFilter *parent, const char *filter)
 : cRecordFilterItem_rec(parent) {
	vector<string> rows = split(filter, split(";|\n", "|"), true);
	for(unsigned i = 0; i < rows.size(); i++) {
		JsonItem row;
		row.parse(rows[i]);
		if(row.getLocalCount() < 2) {
			continue;
		}
		string request = row.getLocalItem(0)->getLocalValue();
		sItem item;
		if(!request.empty() && request[0] == '!') {
			item._not = true;
			request = request.substr(1);
		}
		if(request.empty()) {
			continue;
		}
		item.pattern.add(request.c_str(), false);
		item.count = atoi(row.getLocalItem(1)->getLocalValue().c_str());
		if(row.getLocalCount() > 2 && is_true(row.getLocalItem(2)->getLocalValue().c_str())) {
			item._not = true;
		}
		items.push_back(item);
	}
}

bool cRecordFilterItem_SipRequestHist::check(void *rec, bool */*findInBlackList*/) {
	if(!items.size()) {
		return(true);
	}
	CallBranch *c_branch = ((Call*)rec)->branch_main();
	bool rslt = false;
	c_branch->sip_resp_hist_lock();
	for(unsigned i = 0; i < items.size() && !rslt; i++) {
		unsigned count = 0;
		for(list<Call::sSipHistory>::iterator iter = c_branch->SIPhistory.begin(); iter != c_branch->SIPhistory.end(); iter++) {
			if(iter->SIPrequest.length() && items[i].pattern.check(iter->SIPrequest.c_str())) {
				++count;
			}
		}
		rslt = items[i]._not ?
			count == 0 :
			count >= (items[i].count >= 2 ? items[i].count : 1);
	}
	c_branch->sip_resp_hist_unlock();
	return(rslt);
}

cRecordFilterItem_Reason::cRecordFilterItem_Reason(cRecordFilter *parent, eTypeReason typeReason, const char *filter)
 : cRecordFilterItem_rec(parent) {
	this->typeReason = typeReason;
	positive_never = false;
	vector<string> values = split_filter(filter, sipResponseSeparators, "\n");
	for(unsigned i = 0; i < values.size(); i++) {
		sItem item;
		if(values[i] == "NULL") {
			item.null = true;
		} else {
			string value = values[i];
			if(!value.empty() && value[0] == '!') {
				item._not = true;
				value = value.substr(1);
			}
			if(value.empty() && !item._not) {
				positive_never = true;
				continue;
			}
			if(isNumber(value.c_str())) {
				item.num = atoi(value.c_str());
			} else {
				item.pattern.add(value.c_str(), false);
			}
		}
		items.push_back(item);
	}
}

bool cRecordFilterItem_Reason::check(void *rec, bool */*findInBlackList*/) {
	extern int opt_cdr_reason_string_enable;
	if(!items.size()) {
		return(!positive_never);
	}
	CallBranch *c_branch = ((Call*)rec)->branch_main();
	int cause = typeReason == _sip ? c_branch->reason_sip_cause : c_branch->reason_q850_cause;
	string *text = typeReason == _sip ? &c_branch->reason_sip_text : &c_branch->reason_q850_text;
	bool text_null = !opt_cdr_reason_string_enable || text->empty();
	for(unsigned i = 0; i < items.size(); i++) {
		bool rslt;
		if(items[i].null) {
			rslt = !cause;
		} else if(items[i].num >= 0) {
			rslt = items[i]._not ?
				!cause || cause != items[i].num :
				cause && cause == items[i].num;
		} else {
			rslt = items[i]._not ?
				text_null || !items[i].pattern.check(text->c_str()) :
				!text_null && items[i].pattern.check(text->c_str());
		}
		if(rslt) {
			return(true);
		}
	}
	return(false);
}

cRecordFilterItem_CdrField::cRecordFilterItem_CdrField(cRecordFilter *parent, const char *columns, double divisor, eCond cond, double value)
 : cRecordFilterItem_rec(parent) {
	this->columns = split(columns, ",", true);
	this->divisor = divisor;
	this->cond = cond;
	this->value = value;
}

bool cRecordFilterItem_CdrField::check(void *rec, bool */*findInBlackList*/) {
	Call *call = (Call*)rec;
	double field_value = 0;
	bool field_value_set = false;
	for(unsigned i = 0; i < columns.size(); i++) {
		double column_value;
		if(call->getCdrFieldValue(columns[i].c_str(), &column_value) &&
		   (!field_value_set || column_value < field_value)) {
			field_value = column_value;
			field_value_set = true;
		}
	}
	if(!field_value_set) {
		return(false);
	}
	field_value /= divisor;
	switch(cond) {
	case _ge:
		return(field_value >= value);
	case _gt:
		return(field_value > value);
	case _lt:
		return(field_value < value);
	case _eq:
		return(field_value == value);
	case _mos:
		return(field_value > 0 && field_value <= value);
	}
	return(false);
}

bool cRecordFilterItem_CdrFieldsSum::check(void *rec, bool */*findInBlackList*/) {
	if(!columns.size()) {
		return(false);
	}
	Call *call = (Call*)rec;
	double sum = 0;
	for(unsigned i = 0; i < columns.size(); i++) {
		double column_value;
		if(!call->getCdrFieldValue(columns[i].column.c_str(), &column_value)) {
			return(false);
		}
		sum += column_value * columns[i].multiplier;
	}
	return(sum >= value);
}

unsigned cRecordFilterItem_CallStream::rtpStreamsSize(Call *call) {
	return(call->saved_data ? call->saved_data->rtp_streams.size() : call->rtp_streams_size());
}

bool cRecordFilterItem_CallStream::rtpStream(Call *call, unsigned index, Call::sSavedData::sRtpStream *stream) {
	Call::sSavedData *saved_data = call->saved_data;
	if(saved_data) {
		if(index >= saved_data->rtp_streams.size()) {
			return(false);
		}
		*stream = saved_data->rtp_streams[index];
		return(true);
	}
	return(call->getRtpStreamData(index, stream));
}

unsigned cRecordFilterItem_CallStream::sdpRowsSize(Call *call) {
	return(call->saved_data ? call->saved_data->sdp_streams.size() : call->sdp_rows_size());
}

bool cRecordFilterItem_CallStream::sdpRow(Call *call, unsigned index, s_sdp_store_data *sdp_row) {
	Call::sSavedData *saved_data = call->saved_data;
	if(saved_data) {
		if(index >= saved_data->sdp_streams.size()) {
			return(false);
		}
		*sdp_row = saved_data->sdp_streams[index];
		return(true);
	}
	s_sdp_store_data *row = call->sdp_row_by_index(index);
	if(!row) {
		return(false);
	}
	*sdp_row = *row;
	return(true);
}

bool cRecordFilterItem_CallStream::getStreamValue(Call *call, unsigned index, double *streamValue) {
	Call::sSavedData::sRtpStream stream;
	if(!rtpStream(call, index, &stream)) {
		return(false);
	}
	if(side != _any && (stream.flags_null || !matchSide(side, stream.is_caller, true))) {
		return(false);
	}
	switch(field) {
	case _sf_received:
		if(stream.received < 0) {
			return(false);
		}
		*streamValue = stream.received;
		return(true);
	case _sf_rtp_ptime:
		if(!stream.rtp_ptime) {
			return(false);
		}
		*streamValue = stream.rtp_ptime;
		return(true);
	case _sf_diff_rtp_sdp_ptime:
		if(!stream.rtp_ptime || !stream.sdp_ptime) {
			return(false);
		}
		*streamValue = abs((int)stream.rtp_ptime - (int)stream.sdp_ptime);
		return(true);
	case _sf_in_multiple_calls:
		if(stream.flags_null) {
			return(false);
		}
		*streamValue = stream.in_multiple_calls ? 1 : 0;
		return(true);
	default:
		return(false);
	}
}

bool cRecordFilterItem_CallStream::getSdpRowValue(Call *call, unsigned index, double *streamValue) {
	s_sdp_store_data sdp_row;
	if(!sdpRow(call, index, &sdp_row)) {
		return(false);
	}
	if(!matchSide(side, sdp_row.is_caller, false)) {
		return(false);
	}
	if(!sdp_row.ptime) {
		return(false);
	}
	*streamValue = sdp_row.ptime;
	return(true);
}

bool cRecordFilterItem_CallStream::check(void *rec, bool */*findInBlackList*/) {
	Call *call = (Call*)rec;
	bool sdp_rows = field == _sf_sdp_row_ptime;
	unsigned size = sdp_rows ? sdpRowsSize(call) : rtpStreamsSize(call);
	if(field == _sf_count) {
		return(cmpValue(size));
	}
	for(unsigned i = 0; i < size; i++) {
		double streamValue;
		if((sdp_rows ? getSdpRowValue(call, i, &streamValue) : getStreamValue(call, i, &streamValue)) &&
		   cmpValue(streamValue)) {
			return(true);
		}
	}
	return(false);
}

bool cRecordFilterItem_CallStreamIpPort::parseEntry(const char *value, sEntry *entry, bool *entry_negative) {
	string v = value;
	trim(v);
	*entry_negative = false;
	if(v.length() && v[0] == '!') {
		*entry_negative = true;
		v = v.substr(1);
		trim(v);
	}
	if(v.length() > 4 && !strcasecmp(v.c_str() + v.length() - 4, " NOT")) {
		*entry_negative = true;
		v = v.substr(0, v.length() - 4);
		trim(v);
	}
	entry->ip_set = false;
	entry->port_set = false;
	entry->port_min = 0;
	entry->port_max = 0;
	const char *p = v.c_str();
	const char *end_ptr = p;
	vmIPmask ip_mask;
	if(ip_mask.setFromString(p, &end_ptr) && ip_mask.ip.isSet()) {
		entry->ip_set = true;
		entry->ip_min = ip_mask.network();
		entry->ip_max = ip_mask.broadcast();
		p = end_ptr;
	}
	while(*p == ' ') {
		++p;
	}
	if(!strncasecmp(p, "port:", 5)) {
		p += 5;
	} else if(*p == ':') {
		++p;
	} else if(entry->ip_set) {
		return(entry->ip_set);
	} else {
		return(false);
	}
	while(*p == ' ') {
		++p;
	}
	if(!isdigit(*p)) {
		return(entry->ip_set);
	}
	entry->port_set = true;
	entry->port_min = entry->port_max = atoi(p);
	while(isdigit(*p)) {
		++p;
	}
	while(*p == ' ') {
		++p;
	}
	if(*p == ':') {
		++p;
		while(*p == ' ') {
			++p;
		}
		if(isdigit(*p)) {
			entry->port_max = atoi(p);
		}
	}
	return(true);
}

void cRecordFilterItem_CallStreamIpPort::addEntries(const char *value, bool negative_entries) {
	vector<string> delim;
	delim.push_back(";");
	delim.push_back("\n");
	vector<string> items = split(value, delim, true);
	for(unsigned i = 0; i < items.size(); i++) {
		sEntry entry;
		bool entry_negative;
		if(parseEntry(items[i].c_str(), &entry, &entry_negative) && entry_negative == negative_entries) {
			entries.push_back(entry);
		}
	}
}

bool cRecordFilterItem_CallStreamIpPort::matchEntries(vmIPport *ip_port) {
	for(unsigned i = 0; i < entries.size(); i++) {
		sEntry *entry = &entries[i];
		if(entry->ip_set && !(ip_port->ip >= entry->ip_min && ip_port->ip <= entry->ip_max)) {
			continue;
		}
		if(entry->port_set && !(ip_port->port.getPort() >= entry->port_min && ip_port->port.getPort() <= entry->port_max)) {
			continue;
		}
		return(true);
	}
	return(false);
}

bool cRecordFilterItem_CallStreamIpPort::check(void *rec, bool */*findInBlackList*/) {
	Call *call = (Call*)rec;
	bool found = false;
	if(target == _t_sdp) {
		unsigned size = cRecordFilterItem_CallStream::sdpRowsSize(call);
		for(unsigned i = 0; i < size && !found; i++) {
			s_sdp_store_data sdp_row;
			if(cRecordFilterItem_CallStream::sdpRow(call, i, &sdp_row) &&
			   cRecordFilterItem_CallStream::matchSide(side, sdp_row.is_caller, false)) {
				found = matchEntries(&sdp_row.ip_port);
			}
		}
	} else {
		unsigned size = cRecordFilterItem_CallStream::rtpStreamsSize(call);
		for(unsigned i = 0; i < size && !found; i++) {
			Call::sSavedData::sRtpStream stream;
			if(cRecordFilterItem_CallStream::rtpStream(call, i, &stream)) {
				found = matchEntries(target == _t_rtp_src ? &stream.src : &stream.dst);
			}
		}
	}
	return(negative ? !found : found);
}

bool cRecordFilterItem_Dscp::check(void *rec, bool */*findInBlackList*/) {
	bool null;
	int value = (int)getField_float(rec, &null);
	if(null) {
		return(false);
	}
	if(eq >= 0) {
		return(value == eq);
	}
	return((ge < 0 || value >= ge) &&
	       (lt < 0 || value < lt));
}

cRecordFilterItem_Dtmf::cRecordFilterItem_Dtmf(cRecordFilter *parent, const char *filter)
 : cRecordFilterItem_rec(parent) {
	vector<string> values = split_filter(filter, callidDtmfSeparators, "\n");
	for(unsigned i = 0; i < values.size(); i++) {
		if(values[i].length() == 1) {
			chars += values[i];
		} else {
			sItem item;
			string value = values[i];
			if(!value.empty() && value[0] == '!') {
				item._not = true;
				value = value.substr(1);
			}
			if(value.empty()) {
				continue;
			}
			item.pattern.add(value.c_str(), false);
			items.push_back(item);
		}
	}
}

bool cRecordFilterItem_Dtmf::check(void *rec, bool */*findInBlackList*/) {
	if(chars.empty() && !items.size()) {
		return(true);
	}
	Call *call = (Call*)rec;
	if(!(call->flags & FLAG_SAVEDTMFDB)) {
		return(false);
	}
	bool rslt = false;
	__SYNC_LOCK_USLEEP(call->dtmf_sync, 50);
	if(!chars.empty()) {
		for(std::deque<s_dtmf>::iterator iter = call->dtmf_history.begin(); iter != call->dtmf_history.end() && !rslt; iter++) {
			rslt = chars.find(iter->dtmf) != string::npos;
		}
	}
	if(!rslt && items.size()) {
		map<sStream, string> sequences;
		for(std::deque<s_dtmf>::iterator iter = call->dtmf_history.begin(); iter != call->dtmf_history.end(); iter++) {
			sequences[sStream(iter->saddr, iter->daddr)] += iter->dtmf;
		}
		for(unsigned i = 0; i < items.size() && !rslt; i++) {
			for(map<sStream, string>::iterator iter = sequences.begin(); iter != sequences.end() && !rslt; iter++) {
				bool match = items[i].pattern.check(iter->second.c_str());
				rslt = items[i]._not ? !match : match;
			}
		}
	}
	__SYNC_UNLOCK(call->dtmf_sync);
	return(rslt);
}

bool cRecordFilterItem_DtmfCount::check(void *rec, bool */*findInBlackList*/) {
	Call *call = (Call*)rec;
	if(!(call->flags & FLAG_SAVEDTMFDB)) {
		return(!count_ge && count_lt == 1);
	}
	bool rslt = false;
	__SYNC_LOCK_USLEEP(call->dtmf_sync, 50);
	if(!count_ge && count_lt == 1) {
		rslt = call->dtmf_history.empty();
	} else {
		map<cRecordFilterItem_Dtmf::sStream, unsigned> counts;
		for(std::deque<s_dtmf>::iterator iter = call->dtmf_history.begin(); iter != call->dtmf_history.end(); iter++) {
			++counts[cRecordFilterItem_Dtmf::sStream(iter->saddr, iter->daddr)];
		}
		for(map<cRecordFilterItem_Dtmf::sStream, unsigned>::iterator iter = counts.begin(); iter != counts.end() && !rslt; iter++) {
			rslt = (!count_ge || iter->second >= count_ge) &&
			       (!count_lt || iter->second < count_lt);
		}
	}
	__SYNC_UNLOCK(call->dtmf_sync);
	return(rslt);
}

cRecordFilterItem_CountryCode::cRecordFilterItem_CountryCode(cRecordFilter *parent, unsigned recordFieldIndex, const char *filter)
 : cRecordFilterItem_base(parent, recordFieldIndex) {
	vector<string> values = split_filter(filter, orValuesSeparators, "\n");
	all = values.empty();
	for(unsigned i = 0; i < values.size() && !all; i++) {
		vector<string> part_codes;
		vector<string> items = split(values[i].c_str(), ",", true);
		for(unsigned j = 0; j < items.size(); j++) {
			if(items[j].substr(0, 2) == "c_") {
				vector<string> continent_codes = getCountriesByContinent(items[j].substr(2).c_str());
				part_codes.insert(part_codes.end(), continent_codes.begin(), continent_codes.end());
			} else {
				part_codes.push_back(items[j]);
			}
		}
		if(!part_codes.size()) {
			all = true;
		}
		for(unsigned j = 0; j < part_codes.size(); j++) {
			string code = part_codes[j];
			for(unsigned k = 0; k < code.length(); k++) {
				code[k] = toupper(code[k]);
			}
			codes.insert(code);
		}
	}
}

bool cRecordFilterItem_CountryCode::check(void *rec, bool */*findInBlackList*/) {
	return(all || codes.find(getField_string(rec)) != codes.end());
}

cRecordFilterItem_Trunk::cRecordFilterItem_Trunk(cRecordFilter *parent, int trunk, vector<string> *ips)
 : cRecordFilterItem_rec(parent) {
	this->trunk = trunk;
	for(unsigned i = 0; i < ips->size(); i++) {
		ListIP_wb *group = new FILE_LINE(0) ListIP_wb;
		group->setSkipInvalid();
		group->addWhite((*ips)[i].c_str(), false);
		groups.push_back(group);
	}
}

cRecordFilterItem_Trunk::~cRecordFilterItem_Trunk() {
	for(unsigned i = 0; i < groups.size(); i++) {
		delete groups[i];
	}
}

bool cRecordFilterItem_Trunk::check(void *rec, bool */*findInBlackList*/) {
	vmIP ips[2] = { parent->getField_ip(rec, cf_callerip), parent->getField_ip(rec, cf_calledip) };
	for(unsigned i = 0; i < groups.size(); i++) {
		for(int side = 0; side < 2; side++) {
			if(trunk == 3) {
				if(groups[i]->checkIP_sql(ips[side]) != 0) {
					return(false);
				}
			} else if(trunk == side + 1 && groups[i]->checkIP_sql(ips[side]) > 0) {
				return(true);
			}
		}
	}
	return(trunk == 3);
}

bool cRecordFilterItem_AB::check(void *rec, bool */*findInBlackList*/) {
	switch(comb) {
	case _comb_values:
		{
		bool white = false;
		for(int i = 0; i < 3; i++) {
			cRecordFilterItem_base *item = i < 2 ? items[i] : proxies[0];
			if(item) {
				bool item_white;
				bool item_black;
				item->checkWhiteBlack(rec, &item_white, &item_black);
				if(item_black) {
					return(false);
				}
				if(item_white) {
					white = true;
				}
			}
		}
		return(white || items[0]->whiteIsEmpty());
		}
	case _comb_sides_or:
		return(items[0]->check(rec) || items[1]->check(rec));
	case _comb_sides_and:
		{
		bool white[2] = { false, false };
		bool white_proxy[2] = { false, false };
		bool with_white[2] = { false, false };
		for(int i = 0; i < 2; i++) {
			if(!items[i]) {
				continue;
			}
			bool black;
			items[i]->checkWhiteBlack(rec, &white[i], &black);
			if(black) {
				return(false);
			}
			if(proxies[i]) {
				proxies[i]->checkWhiteBlack(rec, &white_proxy[i], &black);
				if(black) {
					return(false);
				}
			}
			with_white[i] = !items[i]->whiteIsEmpty();
		}
		if(with_white[0] && with_white[1]) {
			return((white[0] && white[1]) ||
			       (white_proxy[0] && white[1]) ||
			       (white[0] && white_proxy[1]));
		}
		for(int i = 0; i < 2; i++) {
			if(with_white[i]) {
				return(white[i] || white_proxy[i]);
			}
		}
		return(true);
		}
	}
	return(true);
}

cRecordFilterItem_Call::cRecordFilterItem_Call(cRecordFilter *parent, eTypeFilter typeFilter, const char *filter)
 : cRecordFilterItem_rec(parent) {
	this->typeFilter = typeFilter;
	this->filter = filter ? filter : "";
	this->filter_num = 0;
	this->filter_num2 = 0;
	this->codec_all_streams = false;
	if(typeFilter == _tf_codec ||
	   typeFilter == _tf_codec_exclude ||
	   typeFilter == _tf_bye) {
		split2int(this->filter, split(",|;|\n", '|'), &filter_int);
	}
	if(typeFilter == _tf_codec ||
	   typeFilter == _tf_codec_exclude) {
		for(unsigned i = 0; i < sizeof(codecVariants) / sizeof(codecVariants[0]); i++) {
			if(filter_int.find(codecVariants[i].codec) != filter_int.end()) {
				for(unsigned j = 0; j < sizeof(codecVariants[i].variants) / sizeof(codecVariants[i].variants[0]); j++) {
					if(codecVariants[i].variants[j] >= 0) {
						filter_int.insert(codecVariants[i].variants[j]);
					}
				}
			}
		}
	}
}

cRecordFilterItem_Call::cRecordFilterItem_Call(cRecordFilter *parent, eTypeFilter typeFilter, u_int64_t filter_num, u_int64_t filter_num2)
 : cRecordFilterItem_rec(parent) {
	this->typeFilter = typeFilter;
	this->filter_num = filter_num;
	this->filter_num2 = filter_num2;
	this->codec_all_streams = false;
}

int cRecordFilterItem_Call::rtpMosF2Mult10(RTP *rtp) {
	#if not EXPERIMENTAL_LITE_RTP_MOD
	if(rtp && rtp->mosf2_avg > 0) {
		return(LIMIT_TINYINT_UNSIGNED((int)round(rtp->mosf2_avg)));
	}
	#endif
	return(-1);
}

void cRecordFilterItem_Call::getCodecData(Call *call, sCodecData *codecData) {
	codecData->rtp_rows_match = false;
	if(call->saved_data) {
		for(int i = 0; i < 2; i++) {
			codecData->payload_ab[i] = call->saved_data->payload_ab[i];
			codecData->mos_f2_ab[i] = call->saved_data->mos_f2_ab[i];
		}
		codecData->payload = call->saved_data->payload;
		codecData->payload_null = call->saved_data->payload_null;
		if(codec_all_streams) {
			for(set<int>::iterator iter = call->saved_data->rtp_rows_payloads.begin(); iter != call->saved_data->rtp_rows_payloads.end() && !codecData->rtp_rows_match; iter++) {
				codecData->rtp_rows_match = codecMatch(*iter);
			}
		}
	} else if(call->isClosed()) {
		for(int i = 0; i < 2; i++) {
			codecData->payload_ab[i] = call->rtpab[i] ? call->rtpab[i]->first_codec_() : -1;
			codecData->mos_f2_ab[i] = rtpMosF2Mult10(call->rtpab[i]);
		}
		codecData->payload = call->get_payload_rslt();
		codecData->payload_null = false;
		if(codec_all_streams) {
			for(unsigned i = 0; i < call->rtp_rows_size() && !codecData->rtp_rows_match; i++) {
				RTP *rtp_i = call->rtp_rows_stream_by_index(i);
				if(rtp_i) {
					codecData->rtp_rows_match = codecMatch(rtp_i->first_codec_());
				}
			}
		}
	} else {
		codecData->payload_ab[0] = call->last_callercodec;
		codecData->payload_ab[1] = call->last_calledcodec;
		codecData->mos_f2_ab[0] = rtpMosF2Mult10(call->lastactivecallerrtp);
		codecData->mos_f2_ab[1] = rtpMosF2Mult10(call->lastactivecalledrtp);
		codecData->payload = -1;
		codecData->payload_null = true;
	}
}

bool cRecordFilterItem_Call::check(void *rec, bool */*findInBlackList*/) {
	Call *call = (Call*)rec;
	switch(typeFilter) {
	case _tf_codec:
	case _tf_codec_exclude:
		{
		sCodecData codecData;
		getCodecData(call, &codecData);
		int a_mos = codecData.mos_f2_ab[0] >= 0 ? codecData.mos_f2_ab[0] > 0 : -1;
		int b_mos = codecData.mos_f2_ab[1] >= 0 ? codecData.mos_f2_ab[1] > 0 : -1;
		int a_payload = codecData.payload_ab[0] >= 0 ? codecMatch(codecData.payload_ab[0]) : -1;
		int b_payload = codecData.payload_ab[1] >= 0 ? codecMatch(codecData.payload_ab[1]) : -1;
		int payload = codecData.payload_null ? -1 : codecMatch(codecData.payload);
		int rslt = sqlOr(sqlOr(sqlAnd(a_mos, a_payload),
				       sqlAnd(sqlAnd(codecData.mos_f2_ab[0] <= 0, b_mos), b_payload)),
				 sqlOr(payload, codecData.rtp_rows_match));
		return(typeFilter == _tf_codec ? rslt > 0 : rslt == 0);
		}
	case _tf_codec_ab_eq:
	case _tf_codec_ab_diff:
		{
		sCodecData codecData;
		getCodecData(call, &codecData);
		return(typeFilter == _tf_codec_ab_eq ?
			codecData.payload_ab[0] >= 0 && codecData.payload_ab[0] == codecData.payload_ab[1] :
			codecData.payload_ab[0] >= 0 && codecData.payload_ab[1] >= 0 && codecData.payload_ab[0] != codecData.payload_ab[1]);
		}
	case _tf_custom_headers_cond:
		if(custom_headers_cdr) {
			map<string, string> custom_headers;
			custom_headers_cdr->getHeaderValues(call, INVITE, &custom_headers);
			string filter_data = filter;
			size_t pos[2];
			while((pos[0] = filter_data.find("{{")) != string::npos &&
			      (pos[1] = filter_data.find("}}", pos[0])) != string::npos) {
				string field = filter_data.substr(pos[0] + 2, pos[1] - pos[0] - 2);
				map<string, string>::iterator iter = custom_headers.find(field);
				string value = iter != custom_headers.end() ? iter->second : "";
				filter_data = filter_data.substr(0, pos[0]) + "'" + value + "'" + filter_data.substr(pos[1] + 2);
			}
			cEvalFormula f(cEvalFormula::_est_na);
			return(f.e(filter_data.c_str()).getBool());
		}
		break;
	case _tf_flags:
		return((call->rslt_save_cdr_flags & filter_num) != 0);
	case _tf_bye:
		return(filter_int.find(call->rslt_save_cdr_bye) != filter_int.end());
	case _tf_who_hangup:
		{
		int whohanged = call->branch_main()->whohanged;
		return((whohanged == 0 || whohanged == 1) && (u_int64_t)(whohanged ? 2 : 1) == filter_num);
		}
	case _tf_one_way:
	case _tf_missing_rtp:
		{
		if(!call->connect_time_us) {
			return(false);
		}
		bool a_saddr;
		bool b_saddr;
		getSaddrExists(call, &a_saddr, &b_saddr);
		return(typeFilter == _tf_one_way ?
			a_saddr != b_saddr :
			!a_saddr && !b_saddr);
		}
	case _tf_country_compare_numbers:
	case _tf_country_compare_ips:
		{
		extern CountryDetect *countryDetect;
		string country_a = parent->getField_string(rec, typeFilter == _tf_country_compare_numbers ? cf_caller_country : cf_callerip_country);
		string country_b = parent->getField_string(rec, typeFilter == _tf_country_compare_numbers ? cf_called_country : cf_calledip_country);
		switch(filter_num) {
		case 1:
			return(country_a == country_b);
		case 2:
			return(country_a != country_b);
		case 3:
		case 4:
			{
			string local_country;
			if(!countryDetect || !countryDetect->getCountryCodeForLocalNumbers(call->useSensorId, &local_country)) {
				return(filter_num == 3 ? country_a == country_b : country_a != country_b);
			}
			if(local_country.empty()) {
				return(false);
			}
			if(filter_num == 3) {
				return(!strcasecmp(country_a.c_str(), local_country.c_str()) &&
				       !strcasecmp(country_b.c_str(), local_country.c_str()));
			} else {
				return((!call->saved_data || call->saved_data->countries_set) &&
				       (strcasecmp(country_a.c_str(), local_country.c_str()) ||
					strcasecmp(country_b.c_str(), local_country.c_str())));
			}
			}
		}
		}
		break;
	case _tf_flags_eq:
		return((call->rslt_save_cdr_flags & filter_num) == filter_num2);
	case _tf_rtp_state:
		{
		bool a_saddr;
		bool b_saddr;
		getSaddrExists(call, &a_saddr, &b_saddr);
		if(filter == "missing") {
			return(!a_saddr && !b_saddr);
		} else if(filter == "exists") {
			return(a_saddr || b_saddr);
		} else if(filter == "zero_one") {
			return(!a_saddr || !b_saddr);
		} else if(filter == "one_way") {
			return(a_saddr != b_saddr);
		} else if(filter == "two_way") {
			return(a_saddr && b_saddr);
		}
		}
		break;
	}
	return(true);
}


cRecordFilterItem_CallSubFilter::~cRecordFilterItem_CallSubFilter() {
	if(subFilter) {
		delete subFilter;
	}
}

bool cRecordFilterItem_CallSubFilter::check(void *rec, bool */*findInBlackList*/) {
	bool rslt = subFilter->check(rec);
	return(negative ? !rslt : rslt);
}

cCallFilter::cCallFilter(const char *filter, const char *keyPrefix, bool nested) {
	setUseRecordArray(false);
	setFilter(filter, keyPrefix, nested);
}

void cCallFilter::setFilter(const char *filter, const char *keyPrefix, bool nested) {
	JsonItem jsonData;
	jsonData.parse(filter);
	cFilterData filterData;
	extern sExistsColumns existsColumns;
	unsigned keyPrefixLength = keyPrefix ? strlen(keyPrefix) : 0;
	for(unsigned int i = 0; i < jsonData.getLocalCount(); i++) {
		JsonItem *item = jsonData.getLocalItem(i);
		string filterName = item->getLocalName();
		string filterTypeName = filterName;
		string filterValue = item->getLocalValue();
		if(filterValue.empty()) {
			continue;
		}
		if(keyPrefixLength && filterTypeName.length() > keyPrefixLength &&
		   !strncmp(filterTypeName.c_str(), keyPrefix, keyPrefixLength)) {
			filterTypeName = filterTypeName.substr(keyPrefixLength);
		}
		filterData.add(filterTypeName, filterName, filterValue);
	}
	if(!filterData["calldate"].empty()) {
		cRecordFilterItem_calldate *filter = new FILE_LINE(0) cRecordFilterItem_calldate(this, cf_calldate, atol(filterData["calldate"].c_str()), cRecordFilterItem_base::_ge);
		addFilter(filter);
	}
	if(!filterData["calldate_from"].empty()) {
		cRecordFilterItem_calldate *filter = new FILE_LINE(0) cRecordFilterItem_calldate(this, cf_calldate, atol(filterData["calldate_from"].c_str()), cRecordFilterItem_base::_ge);
		addFilter(filter);
	}
	if(!filterData["calldate_to"].empty()) {
		cRecordFilterItem_calldate *filter = new FILE_LINE(0) cRecordFilterItem_calldate(this, cf_calldate, atol(filterData["calldate_to"].c_str()), cRecordFilterItem_base::_lt);
		addFilter(filter);
	}
	addFilterAB(filterData, "sipcallerip", "sipcalledip", "sipcallerdip_type",
		    sAbDef(_ab_ip, cf_callerip, cf_calledip).proxy("sipcallerdip_with_proxy"));
	if(!isEmptyOrZero(filterData["proxyip"])) {
		cRecordFilterItem_CallProxy *filter = new FILE_LINE(0) cRecordFilterItem_CallProxy(this);
		filter->addWhite(filterData["proxyip"].c_str());
		addFilter(filter);
	}
	addFilterAB(filterData, "sipcallerip_group_id", "sipcalledip_group_id", "sipcallerdip_group_id_type",
		    sAbDef(_ab_ip, cf_callerip, cf_calledip).codebook("cb_ip_groups", "ip").proxy("sipcallerdip_with_proxy"));
	addFilterAB(filterData, "country_code_sipcallerip", "country_code_sipcalledip", "country_code_sipcallerdip_type",
		    sAbDef(_ab_country_code, cf_callerip_country, cf_calledip_country).sideComb());
	addFilterAB(filterData, "sipcallerip_encaps", "sipcalledip_encaps", "sipcallerdip_encaps_type",
		    sAbDef(_ab_ip, cf_callerip_encaps, cf_calledip_encaps));
	addFilterAB(filterData, "sipcallerport", "sipcalledport", "sipcallerdport_type",
		    sAbDef(_ab_num_list, cf_callerport, cf_calledport).sideComb());
	addFilterAB(filterData, "a_saddr", "b_saddr", "ab_saddr_type",
		    sAbDef(_ab_ip, cf_rtp_src, cf_rtp_dst));
	addFilterAB(filterData, "a_saddr_group_id", "b_saddr_group_id", "ab_saddr_group_id_type",
		    sAbDef(_ab_ip, cf_rtp_src, cf_rtp_dst).codebook("cb_ip_groups", "ip"));
	addFilterAB(filterData, "caller", "called", "callerd_type",
		    sAbDef(_ab_phone_number, cf_caller, cf_called).phoneType((PhoneNumber::eTypeNumber)atoi(filterData["callerd_search_type"].c_str())).nullValue());
	addFilterAB(filterData, "country_code_caller", "country_code_called", "country_code_callerd_type",
		    sAbDef(_ab_country_code, cf_caller_country, cf_called_country).sideComb());
	addFilterAB(filterData, "caller_group_id", "called_group_id", "callerd_group_id_type",
		    sAbDef(_ab_phone_number, cf_caller, cf_called).codebook("cb_number_groups", "number").phoneType(PhoneNumber::_tn_prefix_auto));
	addFilterAB(filterData, "caller_domain", "called_domain", "callerd_domain_type",
		    sAbDef(_ab_check_string, cf_callerdomain, cf_calleddomain).nullValue());
	if(!filterData["caller_domain_group_id"].empty() || !filterData["called_domain_group_id"].empty()) {
		bool type0 = filterData["callerd_domain_group_id_type"].empty() || filterData["callerd_domain_group_id_type"] == "0";
		vector<int> ids[2];
		ids[0] = split2int(filterData["caller_domain_group_id"], ',');
		if(!type0) {
			ids[1] = split2int(filterData["called_domain_group_id"], ',');
		}
		string ids_str;
		for(int i = 0; i < 2; i++) {
			for(unsigned j = 0; j < ids[i].size(); j++) {
				ids_str += (ids_str.empty() ? "" : ",") + intToString(ids[i][j]);
			}
		}
		if(!ids_str.empty()) {
			map<int, int> groups_side;
			SqlDb *sqlDb = createSqlObject();
			sqlDb->query("select id, side from cb_domain_groups where id in (" + ids_str + ")");
			SqlDb_row row;
			while((row = sqlDb->fetchRow())) {
				groups_side[atoi(row["id"].c_str())] = atoi(row["side"].c_str());
			}
			delete sqlDb;
			bool split_by_side = !type0;
			for(unsigned j = 0; j < ids[0].size() && !split_by_side; j++) {
				map<int, int>::iterator iter = groups_side.find(ids[0][j]);
				if(iter != groups_side.end() && iter->second) {
					split_by_side = true;
				}
			}
			if(split_by_side) {
				for(int i = 0; i < 2; i++) {
					vector<int> *side_ids = &ids[type0 ? 0 : i];
					string side_ids_str;
					for(unsigned j = 0; j < side_ids->size(); j++) {
						map<int, int>::iterator iter = groups_side.find((*side_ids)[j]);
						if(iter != groups_side.end() && (!iter->second || iter->second == i + 1)) {
							side_ids_str += (side_ids_str.empty() ? "" : ",") + intToString(iter->first);
						}
					}
					filterData[i == 0 ? "caller_domain_group_id" : "called_domain_group_id"] = side_ids_str;
				}
				filterData["callerd_domain_group_id_type"] = "1";
			}
		}
	}
	addFilterAB(filterData, "caller_domain_group_id", "called_domain_group_id", "callerd_domain_group_id_type",
		    sAbDef(_ab_check_string, cf_callerdomain, cf_calleddomain).codebook("cb_domain_groups", "domain").nullValue());
	addFilterAB(filterData, "caller_agent", "called_agent", "callerd_agent_type",
		    sAbDef(_ab_check_string, cf_calleragent, cf_calledagent).splitBy(",|\n", "|"));
	addFilterAB(filterData, "caller_agent_group_id", "called_agent_group_id", "callerd_agent_group_id_type",
		    sAbDef(_ab_check_string, cf_calleragent, cf_calledagent).splitBy(",|\n", "|").codebook("cb_ua_groups", "ua"));
	addFilterAB(filterData, "a_ua", "b_ua", "ab_ua_type",
		    sAbDef(_ab_check_string, cf_calleragent, cf_calledagent).splitBy(",|\n", "|").revertNeg().emptyNull());
	addFilterAB(filterData, "a_ua_group_id", "b_ua_group_id", "ab_ua_group_id_type",
		    sAbDef(_ab_check_string, cf_calleragent, cf_calledagent).splitBy(",|\n", "|").codebook("cb_ua_groups", "ua").emptyNull());
	if(!isEmptyOrZero(filterData["callid"])) {
		addFilter(new FILE_LINE(0) cRecordFilterItem_CheckStringOr(this, cf_callid, filterData["callid"].c_str(), callidDtmfSeparators, "\n"));
	}
	if(!isEmptyOrZero(filterData["callername"])) {
		addFilter(new FILE_LINE(0) cRecordFilterItem_CheckStringOr(this, cf_callername, filterData["callername"].c_str(), orValuesSeparators, "\n", true));
	}
	addFilterDataNotAvailable(filterData, "note");
	if(!isEmptyOrZero(filterData["digest_username"])) {
		cRecordFilterItems gItems(cRecordFilterItems::_or);
		if(existsColumns.cdr_next_digest_username) {
			cRecordFilterItem_CheckStringOr *filter = new FILE_LINE(0) cRecordFilterItem_CheckStringOr(this, cf_digest_username, filterData["digest_username"].c_str(), "", "|");
			filter->setEmptyAsNull();
			gItems.addFilter(filter);
		}
		if(custom_headers_cdr) {
			string header = custom_headers_cdr->getHeaderKeyForSpecialType(CustomHeaders::digest_username);
			if(!header.empty()) {
				gItems.addFilter(new FILE_LINE(0) cRecordFilterItem_CustomHeader(this, header.c_str(), filterData["digest_username"].c_str(), "", "|"));
			}
		}
		if(gItems.isSet()) {
			addFilter(&gItems);
		}
	}
	bool codec_all_streams = !filterData["codec_all_streams"].empty() && is_true(filterData["codec_all_streams"].c_str());
	if(!filterData["codec"].empty()) {
		cRecordFilterItem_Call *filter = new FILE_LINE(0) cRecordFilterItem_Call(this, cRecordFilterItem_Call::_tf_codec, filterData["codec"].c_str());
		filter->setCodecAllStreams(codec_all_streams);
		addFilter(filter);
	}
	if(!filterData["exclude_codec"].empty()) {
		cRecordFilterItem_Call *filter = new FILE_LINE(0) cRecordFilterItem_Call(this, cRecordFilterItem_Call::_tf_codec_exclude, filterData["exclude_codec"].c_str());
		filter->setCodecAllStreams(codec_all_streams);
		addFilter(filter);
	}
	if(!filterData["codec_compare"].empty()) {
		if(atoi(filterData["codec_compare"].c_str()) == 1) {
			cRecordFilterItem_Call *filter = new FILE_LINE(0) cRecordFilterItem_Call(this, cRecordFilterItem_Call::_tf_codec_ab_eq, (u_int64_t)0);
			addFilter(filter);
		}
		if(atoi(filterData["codec_compare"].c_str()) == 2) {
			cRecordFilterItem_Call *filter = new FILE_LINE(0) cRecordFilterItem_Call(this, cRecordFilterItem_Call::_tf_codec_ab_diff, (u_int64_t)0);
			addFilter(filter);
		}
	}
	if(!isEmptyOrZero(filterData["sensor_id"])) {
		vector<string> sensors = split(filterData["sensor_id"].c_str(), ",", true);
		bool sensors_all = false;
		bool sensors_local = false;
		string sensors_ids;
		for(unsigned i = 0; i < sensors.size() && !sensors_all; i++) {
			size_t digits_pos = sensors[i][0] == '-' ? 1 : 0;
			bool number = sensors[i].length() > digits_pos &&
				      sensors[i].find_first_not_of("0123456789", digits_pos) == string::npos;
			int sensor = atoi(sensors[i].c_str());
			if(number && sensor == -1) {
				sensors_all = true;
			} else if((number && sensor <= 0) || sensors[i] == "local") {
				sensors_local = true;
			} else if(number) {
				sensors_ids += (sensors_ids.empty() ? "" : ",") + intToString(sensor);
			}
		}
		if(!sensors_all) {
			vector<int> id_sensors;
			if(!sensors_ids.empty()) {
				SqlDb *sqlDb = createSqlObject();
				sqlDb->query("select id_sensor from sensors where id in (" + sensors_ids + ")");
				SqlDb_row row;
				while((row = sqlDb->fetchRow())) {
					int id_sensor = atoi(row["id_sensor"].c_str());
					if(id_sensor > 0) {
						id_sensors.push_back(id_sensor);
					}
				}
				delete sqlDb;
			}
			cRecordFilterItems gItems(cRecordFilterItems::_or);
			if(id_sensors.size()) {
				cRecordFilterItem_numList *filter = new FILE_LINE(0) cRecordFilterItem_numList(this, cf_id_sensor);
				for(unsigned i = 0; i < id_sensors.size(); i++) {
					filter->addNum(id_sensors[i]);
				}
				gItems.addFilter(filter);
			}
			if(sensors_local) {
				gItems.addFilter(new FILE_LINE(0) cRecordFilterItem_numInterval(this, cf_id_sensor, 0, cRecordFilterItem_base::_le));
			}
			if(gItems.isSet()) {
				addFilter(&gItems);
			}
		}
	}
	if(!isEmptyOrZero(filterData["trunk"])) {
		int trunk = filterData["trunk"].find_first_not_of("0123456789") == string::npos ?
			     atoi(filterData["trunk"].c_str()) :
			     0;
		vector<string> trunk_ips;
		SqlDb *sqlDb = createSqlObject();
		sqlDb->query("select ip from cb_ip_groups where trunk");
		SqlDb_row row;
		while((row = sqlDb->fetchRow())) {
			if(!isEmptyOrZero(row["ip"])) {
				trunk_ips.push_back(row["ip"]);
			}
		}
		delete sqlDb;
		if(trunk_ips.size() && trunk >= 1 && trunk <= 3) {
			addFilter(new FILE_LINE(0) cRecordFilterItem_Trunk(this, trunk, &trunk_ips));
		}
	}
	if(!filterData["vlan"].empty()) {
		cRecordFilterItem_numList *filter = new FILE_LINE(0) cRecordFilterItem_numList(this, cf_vlan);
		filter->addNumComb(filterData["vlan"].c_str());
		addFilter(filter);
	}
	addFilterNumInterval(filterData, "vlan_gt", cf_vlan, cRecordFilterItem_base::_ge, true, true);
	addFilterNumInterval(filterData, "vlan_lt", cf_vlan, cRecordFilterItem_base::_lt, true, true);
	if(is_true(filterData["connected"].c_str())) {
		cRecordFilterItem_numInterval *filter = new FILE_LINE(0) cRecordFilterItem_numInterval(this, cf_connect_duration, 0, cRecordFilterItem_base::_ge);
		addFilter(filter);
	}
	addFilterNumInterval(filterData, "durationgt", cf_duration, cRecordFilterItem_base::_ge);
	addFilterNumInterval(filterData, "durationlt", cf_duration, cRecordFilterItem_base::_lt);
	addFilterNumInterval(filterData, "connect_durationgtt", cf_connect_duration, cRecordFilterItem_base::_gt);
	addFilterNumInterval(filterData, "connect_durationgt", cf_connect_duration, cRecordFilterItem_base::_ge);
	addFilterNumInterval(filterData, "connect_durationlt", cf_connect_duration, cRecordFilterItem_base::_lt);
	addFilterNumInterval(filterData, "pddgt", cf_progress_time, cRecordFilterItem_base::_ge);
	addFilterNumInterval(filterData, "pddlt", cf_progress_time, cRecordFilterItem_base::_lt);
	addFilterNumInterval(filterData, "ringinggt", cf_ringing_time, cRecordFilterItem_base::_ge);
	addFilterNumInterval(filterData, "ringinglt", cf_ringing_time, cRecordFilterItem_base::_lt);
	if(existsColumns.cdr_post_bye_delay) {
		addFilterNumInterval(filterData, "pbdgt", cf_post_bye_delay, cRecordFilterItem_base::_ge);
		addFilterNumInterval(filterData, "pbdlt", cf_post_bye_delay, cRecordFilterItem_base::_lt);
	}
	if(existsColumns.cdr_response_time_100) {
		addFilterNumInterval(filterData, "response_time_100_gt", cf_response_time_100, cRecordFilterItem_base::_ge);
		addFilterNumInterval(filterData, "response_time_100_lt", cf_response_time_100, cRecordFilterItem_base::_lt);
	}
	if(!filterData["sipresponse"].empty()) {
		if(cRecordFilterItem_SipResponseNum::isNumFilter(filterData["sipresponse"].c_str())) {
			addFilter(new FILE_LINE(0) cRecordFilterItem_SipResponseNum(this, cf_lastSIPresponseNum, filterData["sipresponse"].c_str()));
		} else {
			addFilter(new FILE_LINE(0) cRecordFilterItem_SipResponse(this, filterData["sipresponse"].c_str()));
		}
	}
	if(!filterData["allsipresponse"].empty()) {
		addFilter(new FILE_LINE(0) cRecordFilterItem_SipResponseAll(this, filterData["allsipresponse"].c_str()));
	}
	if(!filterData["allsiprequests"].empty()) {
		addFilter(new FILE_LINE(0) cRecordFilterItem_SipRequestHist(this, filterData["allsiprequests"].c_str()));
	}
	if(existsColumns.cdr_reason) {
		if(!filterData["reason_sip"].empty()) {
			addFilter(new FILE_LINE(0) cRecordFilterItem_Reason(this, cRecordFilterItem_Reason::_sip, filterData["reason_sip"].c_str()));
		}
		if(!filterData["reason_q850"].empty()) {
			addFilter(new FILE_LINE(0) cRecordFilterItem_Reason(this, cRecordFilterItem_Reason::_q850, filterData["reason_q850"].c_str()));
		}
	}
	if(!filterData["who_hangup"].empty()) {
		addFilter(new FILE_LINE(0) cRecordFilterItem_Call(this, cRecordFilterItem_Call::_tf_who_hangup, (u_int64_t)atoi(filterData["who_hangup"].c_str())));
	}
	if(!filterData["unconfirmed_bye"].empty()) {
		u_int64_t flags = 0;
		vector<int> bits = split2int(filterData["unconfirmed_bye"], ',');
		for(unsigned i = 0; i < bits.size(); i++) {
			flags |= bits[i];
		}
		if(flags) {
			addFilter(new FILE_LINE(0) cRecordFilterItem_Call(this, cRecordFilterItem_Call::_tf_flags, flags));
		}
	}
	if(!filterData["bye_code"].empty()) {
		addFilter(new FILE_LINE(0) cRecordFilterItem_Call(this, cRecordFilterItem_Call::_tf_bye, filterData["bye_code"].c_str()));
	}
	if(!filterData["bye"].empty() && is_true(filterData["bye"].c_str())) {
		addFilter(new FILE_LINE(0) cRecordFilterItem_Call(this, cRecordFilterItem_Call::_tf_bye, "1"));
	}
	if(!filterData["one_way"].empty() && is_true(filterData["one_way"].c_str())) {
		addFilter(new FILE_LINE(0) cRecordFilterItem_Call(this, cRecordFilterItem_Call::_tf_one_way, (u_int64_t)0));
	}
	if(!filterData["missing_rtp"].empty() && is_true(filterData["missing_rtp"].c_str())) {
		addFilter(new FILE_LINE(0) cRecordFilterItem_Call(this, cRecordFilterItem_Call::_tf_missing_rtp, (u_int64_t)0));
	}
	for(unsigned i = 0; i < sizeof(callFlagsFilters) / sizeof(callFlagsFilters[0]); i++) {
		if(!filterData[callFlagsFilters[i].name].empty() && is_true(filterData[callFlagsFilters[i].name].c_str())) {
			addFilter(new FILE_LINE(0) cRecordFilterItem_Call(this, cRecordFilterItem_Call::_tf_flags, callFlagsFilters[i].flags));
		}
	}
	for(unsigned i = 0; i < sizeof(callFlagsValueFilters) / sizeof(callFlagsValueFilters[0]); i++) {
		if(filterData[callFlagsValueFilters[i].name] == callFlagsValueFilters[i].value) {
			addFilter(new FILE_LINE(0) cRecordFilterItem_Call(this, callFlagsValueFilters[i].typeFilter, callFlagsValueFilters[i].flags, callFlagsValueFilters[i].flags_eq));
		}
	}
	if(!filterData["protocols_tcp_udp"].empty()) {
		u_int64_t protocols = 0;
		vector<string> items = split(filterData["protocols_tcp_udp"].c_str(), ",", true);
		for(unsigned i = 0; i < items.size(); i++) {
			if(items[i] == "tcp") {
				protocols |= CDR_PROTO_TCP;
			} else if(items[i] == "udp") {
				protocols |= CDR_PROTO_UDP;
			} else if(items[i] == "tls") {
				protocols |= CDR_PROTO_TLS;
			} else if(items[i] == "tcpudp") {
				protocols |= CDR_PROTO_TCP | CDR_PROTO_UDP;
			}
		}
		addFilter(new FILE_LINE(0) cRecordFilterItem_Call(this, cRecordFilterItem_Call::_tf_flags_eq, CDR_PROTO_TCP | CDR_PROTO_UDP | CDR_PROTO_TLS, protocols));
	}
	if(!filterData["sdp_media_type"].empty()) {
		u_int64_t media_types = 0;
		unsigned media_types_count = 0;
		vector<string> items = split(filterData["sdp_media_type"].c_str(), ",", true);
		for(unsigned i = 0; i < items.size(); i++) {
			u_int64_t media_type = items[i] == "audio" ? CDR_SDP_EXISTS_MEDIA_TYPE_AUDIO :
					       items[i] == "image" ? CDR_SDP_EXISTS_MEDIA_TYPE_IMAGE :
					       items[i] == "video" ? CDR_SDP_EXISTS_MEDIA_TYPE_VIDEO : 0;
			if(media_type) {
				media_types |= media_type;
				++media_types_count;
			}
		}
		if(media_types) {
			if(media_types_count > 1 && filterData["sdp_media_type_multiple_operator"] != "or") {
				addFilter(new FILE_LINE(0) cRecordFilterItem_Call(this, cRecordFilterItem_Call::_tf_flags_eq, media_types, media_types));
			} else {
				addFilter(new FILE_LINE(0) cRecordFilterItem_Call(this, cRecordFilterItem_Call::_tf_flags, media_types));
			}
		}
	}
	if(!filterData["rtp_state"].empty()) {
		addFilter(new FILE_LINE(0) cRecordFilterItem_Call(this, cRecordFilterItem_Call::_tf_rtp_state, filterData["rtp_state"].c_str()));
	}
	for(unsigned i = 0; i < sizeof(cdrMosFilters) / sizeof(cdrMosFilters[0]); i++) {
		addFilterAB(filterData, cdrMosFilters[i].name1, cdrMosFilters[i].name2, cdrMosFilters[i].typeName,
			    sAbDef(_ab_cdr_mos, cdrMosFilters[i].column1, cdrMosFilters[i].column2).sideComb().zeroValue());
	}
	bool mos_min_chart_field = !filterData["mos_min_chart_field"].empty() && is_true(filterData["mos_min_chart_field"].c_str());
	addFilterCdrMetric(filterData, "mos_min",
			   mos_min_chart_field ? "a_mos_min_mult10" : "a_mos_f1_mult10,a_mos_f2_mult10,a_mos_adapt_mult10",
			   mos_min_chart_field ? "b_mos_min_mult10" : "b_mos_f1_mult10,b_mos_f2_mult10,b_mos_adapt_mult10",
			   10);
	for(unsigned i = 0; i < sizeof(cdrMetricFilters) / sizeof(cdrMetricFilters[0]); i++) {
		addFilterCdrMetric(filterData, cdrMetricFilters[i].name, cdrMetricFilters[i].columns_a, cdrMetricFilters[i].columns_b, cdrMetricFilters[i].divisor);
	}
	addFilterCdrDelay(filterData);
	addFilterCdrLoss(filterData);
	addFilterCdrLastRtpFromEnd(filterData);
	addFilterStreams(filterData);
	addFilterStreamMetric(filterData, "rtp_ptime", cRecordFilterItem_CallStream::_sf_rtp_ptime);
	addFilterStreamMetric(filterData, "sdp_ptime", cRecordFilterItem_CallStream::_sf_sdp_row_ptime);
	addFilterStreamMetric(filterData, "diff_rtp_sdp_ptime", cRecordFilterItem_CallStream::_sf_diff_rtp_sdp_ptime);
	addFilterStreamPorts(filterData);
	addFilterStreamIpPorts(filterData, "rtp_ip_port_source", "rtp_ip_port_dest", "rtp_ip_port_sd_type",
			       cRecordFilterItem_CallStreamIpPort::_t_rtp_src, false);
	addFilterStreamIpPorts(filterData, "sdp_ip_port_source", "sdp_ip_port_dest", "sdp_ip_port_sd_type",
			       cRecordFilterItem_CallStreamIpPort::_t_sdp, true);
	for(unsigned i = 0; i < sizeof(cdrRtcpFilters) / sizeof(cdrRtcpFilters[0]); i++) {
		addFilterAB(filterData, cdrRtcpFilters[i].name1, cdrRtcpFilters[i].name2, cdrRtcpFilters[i].typeName,
			    sAbDef(_ab_cdr_ge, cdrRtcpFilters[i].column1, cdrRtcpFilters[i].column2)
				.sideComb().zeroValue()
				.cdrValue(cdrRtcpFilters[i].divisor, cdrRtcpFilters[i].value_mult, cdrRtcpFilters[i].value_offset));
	}
	if(!filterData["international"].empty()) {
		cRecordFilterItem_numList *filter = new FILE_LINE(0) cRecordFilterItem_numList(this, cf_called_international);
		filter->addNumComb(filterData["international"].c_str());
		addFilter(filter);
	}
	if(!filterData["country_compare_numbers"].empty()) {
		addFilter(new FILE_LINE(0) cRecordFilterItem_Call(this, cRecordFilterItem_Call::_tf_country_compare_numbers, (u_int64_t)atoi(filterData["country_compare_numbers"].c_str())));
	}
	if(!filterData["country_compare_ips"].empty()) {
		addFilter(new FILE_LINE(0) cRecordFilterItem_Call(this, cRecordFilterItem_Call::_tf_country_compare_ips, (u_int64_t)atoi(filterData["country_compare_ips"].c_str())));
	}
	if(existsColumns.cdr_max_retransmission_invite) {
		addFilterNumInterval(filterData, "max_retransmission_invite_gt", cf_max_retransmission_invite, cRecordFilterItem_base::_ge, true, true);
		addFilterNumInterval(filterData, "max_retransmission_invite_lt", cf_max_retransmission_invite, cRecordFilterItem_base::_lt, true, true);
	}
	if(existsColumns.cdr_ttl) {
		for(unsigned i = 0; i < sizeof(cdrTtlFilters) / sizeof(cdrTtlFilters[0]); i++) {
			string name_ge = string(cdrTtlFilters[i].name) + "_ge";
			string name_lt = string(cdrTtlFilters[i].name) + "_lt";
			if(cdrTtlFilters[i].field == cf_ttl_avg) {
				if(!filterData[name_ge].empty()) {
					addFilter(new FILE_LINE(0) cRecordFilterItem_numInterval(this, cf_ttl_avg, round(atof_mysql(filterData[name_ge].c_str()) * 10), cRecordFilterItem_base::_ge));
				}
				if(!filterData[name_lt].empty()) {
					addFilter(new FILE_LINE(0) cRecordFilterItem_numInterval(this, cf_ttl_avg, round(atof_mysql(filterData[name_lt].c_str()) * 10), cRecordFilterItem_base::_lt));
				}
			} else {
				addFilterNumInterval(filterData, name_ge.c_str(), cdrTtlFilters[i].field, cRecordFilterItem_base::_ge);
				addFilterNumInterval(filterData, name_lt.c_str(), cdrTtlFilters[i].field, cRecordFilterItem_base::_lt);
			}
		}
	}
	cRecordFilterItems gDscpItems(cRecordFilterItems::_or);
	for(unsigned i = 0; i < 4; i++) {
		string name = string("dscp_") + (i == 0 || i == 2 ? "caller" : "called") + "_" + (i < 2 ? "sip" : "rtp");
		string *value_eq = &filterData[name + "_eq"];
		string *value_ge = &filterData[name + "_ge"];
		string *value_lt = &filterData[name + "_lt"];
		if(value_eq->empty() && value_ge->empty() && value_lt->empty()) {
			continue;
		}
		cRecordFilterItem_Dscp *filter = new FILE_LINE(0) cRecordFilterItem_Dscp(this, i == 0 ? cf_dscp_caller_sip : i == 1 ? cf_dscp_called_sip : i == 2 ? cf_dscp_caller_rtp : cf_dscp_called_rtp);
		if(!value_eq->empty()) {
			filter->eq = atoi(value_eq->c_str());
		} else {
			if(!value_ge->empty()) {
				filter->ge = atoi(value_ge->c_str());
			}
			if(!value_lt->empty()) {
				filter->lt = atoi(value_lt->c_str());
			}
		}
		gDscpItems.addFilter(filter);
	}
	if(gDscpItems.isSet()) {
		addFilter(&gDscpItems);
	}
	if(!filterData["dtmf"].empty()) {
		addFilter(new FILE_LINE(0) cRecordFilterItem_Dtmf(this, filterData["dtmf"].c_str()));
	}
	if(!isEmptyOrZero(filterData["dtmf_count_gt"]) || !isEmptyOrZero(filterData["dtmf_count_lt"])) {
		unsigned dtmf_count_gt = isEmptyOrZero(filterData["dtmf_count_gt"]) ? 0 : atoi(filterData["dtmf_count_gt"].c_str());
		unsigned dtmf_count_lt = isEmptyOrZero(filterData["dtmf_count_lt"]) ? 0 : atoi(filterData["dtmf_count_lt"].c_str());
		addFilter(new FILE_LINE(0) cRecordFilterItem_DtmfCount(this, dtmf_count_gt, dtmf_count_lt));
	}
	if(custom_headers_cdr) {
		list<string> customHeaders;
		custom_headers_cdr->getHeaders(&customHeaders);
		for(list<string>::iterator iter = customHeaders.begin(); iter != customHeaders.end(); iter++) {
			if(!filterData[*iter].empty()) {
				addFilter(new FILE_LINE(0) cRecordFilterItem_CustomHeader(this, iter->c_str(), filterData[*iter].c_str(), ",|;|\n| ", "|", true));
			}
			if(!filterData[*iter + "_ge"].empty()) {
				addFilter(new FILE_LINE(0) cRecordFilterItem_CustomHeaderNum(this, iter->c_str(), cRecordFilterItem_base::_ge, atof(filterData[*iter + "_ge"].c_str())));
			}
			if(!filterData[*iter + "_lt"].empty()) {
				addFilter(new FILE_LINE(0) cRecordFilterItem_CustomHeaderNum(this, iter->c_str(), cRecordFilterItem_base::_lt, atof(filterData[*iter + "_lt"].c_str())));
			}
		}
		if(!filterData["custhead_group_id"].empty()) {
			string group_ids;
			vector<int> ids = split2int(filterData["custhead_group_id"], ',');
			for(unsigned i = 0; i < ids.size(); i++) {
				group_ids += (i ? "," : "") + intToString(ids[i]);
			}
			if(!group_ids.empty()) {
				cRecordFilterItems gItems(cRecordFilterItems::_or);
				SqlDb *sqlDb = createSqlObject();
				sqlDb->query("select cdr_custom_headers_id, content from cb_custhead_cdr_groups where id in (" + group_ids + ")");
				SqlDb_row row;
				while((row = sqlDb->fetchRow())) {
					string header = custom_headers_cdr->getHeaderKeyForDbId(atol(row["cdr_custom_headers_id"].c_str()));
					if(!header.empty() && !row["content"].empty()) {
						gItems.addFilter(new FILE_LINE(0) cRecordFilterItem_CustomHeader(this, header.c_str(), row["content"].c_str(), ",|;|\n", "|"));
					}
				}
				delete sqlDb;
				if(gItems.isSet()) {
					addFilter(&gItems);
				}
			}
		}
		if(!filterData["custom_headers_cdr_cond"].empty()) {
			cRecordFilterItem_Call *filter = new FILE_LINE(0) cRecordFilterItem_Call(this, cRecordFilterItem_Call::_tf_custom_headers_cond, filterData["custom_headers_cdr_cond"].c_str());
			addFilter(filter);
		}
	}
	if(!filterData["OR"].empty() && atoi(filterData["OR"].c_str())) {
		setCond(cRecordFilter::_or);
	}
	if(is_true(filterData["current_selection"].c_str())) {
		filterData.setUnused("current_selection");
	}
	if(!nested) {
		addFilterCombination(filterData);
	}
	unsupportedKeys = filterData.getUnusedKeys(filterKeysIgnore);
	if(!unsupportedKeysComb.empty()) {
		unsupportedKeys += (unsupportedKeys.empty() ? "" : ",") + unsupportedKeysComb;
	}
	if(!unsupportedKeys.empty()) {
		syslog(LOG_NOTICE, "cCallFilter: unsupported filter keys: %s", unsupportedKeys.c_str());
	}
	setNoLock();
}


void cCallFilter::addFilterAB(cFilterData &filterData, const char *name1, const char *name2, const char *typeName, sAbDef def) {
	filterData.setUsed(name1);
	filterData.setUsed(name2);
	filterData.setUsed(def.proxyName);
	bool proxy = def.proxyName && !filterData[def.proxyName].empty() && is_true(filterData[def.proxyName].c_str());
	bool ab_type = !filterData[typeName].empty() && filterData[typeName] != "0";
	cRecordFilterItem_AB *filter;
	if(!ab_type) {
		if(filterData[name1].empty() ||
		   (!def.zeroIsValue && filterData[name1] == "0" && isEmptyOrZero(filterData[name2]))) {
			return;
		}
		const char *value = filterData[name1].c_str();
		cRecordFilterItem_AB::eComb comb = def.sideCombination ?
						    cRecordFilterItem_AB::_comb_sides_or :
						   (def.revertNegation && value[0] == '!' ?
						     cRecordFilterItem_AB::_comb_sides_and :
						     cRecordFilterItem_AB::_comb_values);
		filter = new FILE_LINE(0) cRecordFilterItem_AB(this, comb);
		filter->items[0] = createAbItem(&def, 0, value);
		filter->items[1] = createAbItem(&def, 1, value);
		if(proxy) {
			filter->proxies[0] = createAbProxyItem(&def, value);
		}
	} else {
		if(isEmptyOrZero(filterData[name1]) && isEmptyOrZero(filterData[name2])) {
			return;
		}
		filter = new FILE_LINE(0) cRecordFilterItem_AB(this, cRecordFilterItem_AB::_comb_sides_and);
		for(int i = 0; i < 2; i++) {
			const char *name = i == 0 ? name1 : name2;
			if(!isEmptyOrZero(filterData[name])) {
				const char *value = filterData[name].c_str();
				filter->items[i] = createAbItem(&def, i, value);
				if(proxy) {
					filter->proxies[i] = createAbProxyItem(&def, value);
				}
			}
		}
	}
	addFilter(filter);
}

cRecordFilterItem_base *cCallFilter::createAbItem(sAbDef *def, int side, const char *value) {
	unsigned field = side == 0 ? def->field1 : def->field2;
	switch(def->itemType) {
	case _ab_ip:
		{
		cRecordFilterItem_IP *filter = new FILE_LINE(0) cRecordFilterItem_IP(this, field);
		if(def->codebook_table) {
			filter->addWhite(def->codebook_table, def->codebook_column, value);
		} else {
			filter->addWhite(value);
		}
		return(filter);
		}
	case _ab_phone_number:
		{
		cRecordFilterItem_PhoneNumber *filter = new FILE_LINE(0) cRecordFilterItem_PhoneNumber(this, field);
		if(def->enableNull) {
			filter->setEnableNull();
		}
		if(def->codebook_table) {
			filter->addWhite(def->codebook_table, def->codebook_column, value, def->phoneNumberType);
		} else {
			filter->addWhite(value, def->phoneNumberType);
		}
		return(filter);
		}
	case _ab_check_string:
		{
		cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, field);
		filter->setDisableInterval();
		if(def->enableNull) {
			filter->setEnableNull();
		}
		if(def->emptyAsNull) {
			filter->setEmptyAsNull();
		}
		if(def->splitSeparators) {
			filter->setSeparators(def->splitSeparators, def->splitSeparatorsSeparator);
		}
		if(def->codebook_table) {
			filter->addWhite(def->codebook_table, def->codebook_column, value);
		} else {
			filter->addWhite(value);
		}
		return(filter);
		}
	case _ab_country_code:
		return(new FILE_LINE(0) cRecordFilterItem_CountryCode(this, field, value));
	case _ab_num_list:
		{
		cRecordFilterItem_numList *filter = new FILE_LINE(0) cRecordFilterItem_numList(this, field);
		filter->addNumComb(value);
		return(filter);
		}
	case _ab_cdr_mos:
		return(new FILE_LINE(0) cRecordFilterItem_CdrField(this, side == 0 ? def->column1 : def->column2, 10, cRecordFilterItem_CdrField::_mos, atof(value)));
	case _ab_cdr_ge:
		return(new FILE_LINE(0) cRecordFilterItem_CdrField(this, side == 0 ? def->column1 : def->column2, def->divisor, cRecordFilterItem_CdrField::_ge,
								   atof_mysql(value) * def->value_mult + def->value_offset));
	}
	return(NULL);
}

void cCallFilter::addFilterCdrDelay(cFilterData &filterData) {
	static const char *delayIndex[] = { "50", "70", "90", "120", "150", "200", "300" };
	unsigned delayCount = sizeof(delayIndex) / sizeof(delayIndex[0]);
	bool strict = !filterData["_d_strict"].empty() && filterData["_d_strict"] != "false";
	bool ab_type = !filterData["_d_callerd_type"].empty() && filterData["_d_callerd_type"] != "0";
	cRecordFilterItems gItems(strict ? cRecordFilterItems::_and : cRecordFilterItems::_or);
	for(unsigned i = 0; i < delayCount; i++) {
		string name = string("_d") + delayIndex[i];
		string name_called = name + "_called";
		if(filterData[name].empty() && filterData[name_called].empty()) {
			continue;
		}
		cRecordFilterItems gSideItems(ab_type ? cRecordFilterItems::_and : cRecordFilterItems::_or);
		for(int side = 0; side < 2; side++) {
			string value = filterData[ab_type && side == 1 ? name_called : name];
			if(ab_type ? isEmptyOrZero(value) : value.empty()) {
				continue;
			}
			cRecordFilterItem_CdrFieldsSum *filter = new FILE_LINE(0) cRecordFilterItem_CdrFieldsSum(this, atof_mysql(value.c_str()));
			for(unsigned j = i; j < delayCount; j++) {
				filter->addColumn(string(side == 0 ? "a_d" : "b_d") + delayIndex[j], 1);
				if(strict) {
					break;
				}
			}
			gSideItems.addFilter(filter);
		}
		if(gSideItems.isSet()) {
			gItems.addFilter(&gSideItems);
		}
	}
	if(gItems.isSet()) {
		addFilter(&gItems);
	}
}

void cCallFilter::addFilterCdrLoss(cFilterData &filterData) {
	bool strict = !filterData["loss_strict"].empty() && filterData["loss_strict"] != "false";
	bool ab_type = !filterData["loss_callerd_type"].empty() && filterData["loss_callerd_type"] != "0";
	cRecordFilterItems gItems(strict ? cRecordFilterItems::_and : cRecordFilterItems::_or);
	for(unsigned i = 1; i <= 10; i++) {
		string name = "loss" + intToString(i);
		string name_called = name + "_called";
		if(filterData[name].empty() && filterData[name_called].empty()) {
			continue;
		}
		cRecordFilterItems gSideItems(ab_type ? cRecordFilterItems::_and : cRecordFilterItems::_or);
		for(int side = 0; side < 2; side++) {
			string value = filterData[ab_type && side == 1 ? name_called : name];
			if(ab_type ? isEmptyOrZero(value) : value.empty()) {
				continue;
			}
			cRecordFilterItem_CdrFieldsSum *filter = new FILE_LINE(0) cRecordFilterItem_CdrFieldsSum(this, atof_mysql(value.c_str()));
			for(unsigned j = i; j >= 1; j--) {
				filter->addColumn(string(side == 0 ? "a_sl" : "b_sl") + intToString(j), strict ? 1 : j);
				if(strict) {
					break;
				}
			}
			gSideItems.addFilter(filter);
		}
		if(gSideItems.isSet()) {
			gItems.addFilter(&gSideItems);
		}
	}
	if(gItems.isSet()) {
		addFilter(&gItems);
	}
}

void cCallFilter::addFilterCdrLastRtpFromEnd(cFilterData &filterData) {
	bool comb_or = !filterData["ab_last_rtp_from_end_or"].empty() && filterData["ab_last_rtp_from_end_or"] != "0";
	cRecordFilterItems gItems(comb_or ? cRecordFilterItems::_or : cRecordFilterItems::_and);
	for(int side = 0; side < 2; side++) {
		string column = side == 0 ? "a_last_rtp_from_end" : "b_last_rtp_from_end";
		string value_eq = filterData[column + "_eq"];
		string value_gt = filterData[column + "_gt"];
		string value_lt = filterData[column + "_lt"];
		cRecordFilterItems gSideItems(cRecordFilterItems::_and);
		if(!value_eq.empty()) {
			gSideItems.addFilter(new FILE_LINE(0) cRecordFilterItem_CdrField(this, column.c_str(), 1, cRecordFilterItem_CdrField::_eq,
											 atof_mysql(value_eq.c_str())));
		} else {
			if(!value_gt.empty()) {
				gSideItems.addFilter(new FILE_LINE(0) cRecordFilterItem_CdrField(this, column.c_str(), 1, cRecordFilterItem_CdrField::_gt,
												 atof_mysql(value_gt.c_str())));
			}
			if(!value_lt.empty()) {
				gSideItems.addFilter(new FILE_LINE(0) cRecordFilterItem_CdrField(this, column.c_str(), 1, cRecordFilterItem_CdrField::_lt,
												 atof_mysql(value_lt.c_str())));
			}
		}
		if(gSideItems.isSet()) {
			gItems.addFilter(&gSideItems);
		}
	}
	if(gItems.isSet()) {
		addFilter(&gItems);
	}
}

void cCallFilter::addFilterDataNotAvailable(cFilterData &filterData, const char *name) {
	if(filterData[name].empty()) {
		return;
	}
	syslog(LOG_NOTICE, "cCallFilter: filter key %s is not available in sniffer - condition never matches", name);
	addFilter(new FILE_LINE(0) cRecordFilterItem_Fixed(this, false));
}

void cCallFilter::addFilterCdrMetric(cFilterData &filterData, const char *name, const char *columns_a, const char *columns_b, double divisor) {
	string name_ge = string(name) + "_ge";
	string name_lt = string(name) + "_lt";
	string name_ge_called = string(name) + "_ge_called";
	string name_lt_called = string(name) + "_lt_called";
	string name_type = string(name) + "_callerd_type";
	bool ab_type = !filterData[name_type].empty() && filterData[name_type] != "0";
	filterData.setUsed(name_ge_called.c_str());
	filterData.setUsed(name_lt_called.c_str());
	cRecordFilterItems gItems(ab_type ? cRecordFilterItems::_and : cRecordFilterItems::_or);
	for(int side = 0; side < 2; side++) {
		const char *columns = side == 0 ? columns_a : columns_b;
		string *value_ge = &filterData[ab_type && side == 1 ? name_ge_called : name_ge];
		string *value_lt = &filterData[ab_type && side == 1 ? name_lt_called : name_lt];
		if(value_ge->empty() && value_lt->empty()) {
			continue;
		}
		cRecordFilterItems gSideItems(cRecordFilterItems::_and);
		if(!value_ge->empty()) {
			gSideItems.addFilter(new FILE_LINE(0) cRecordFilterItem_CdrField(this, columns, divisor, cRecordFilterItem_CdrField::_ge, atof_mysql(value_ge->c_str())));
		}
		if(!value_lt->empty()) {
			gSideItems.addFilter(new FILE_LINE(0) cRecordFilterItem_CdrField(this, columns, divisor, cRecordFilterItem_CdrField::_lt, atof_mysql(value_lt->c_str())));
		}
		gItems.addFilter(&gSideItems);
	}
	if(gItems.isSet()) {
		addFilter(&gItems);
	}
}

void cCallFilter::addFilterStreamMetric(cFilterData &filterData, const char *name, cRecordFilterItem_CallStream::eField field) {
	string name_ge = string(name) + "_ge";
	string name_lt = string(name) + "_lt";
	string name_ge_called = string(name) + "_ge_called";
	string name_lt_called = string(name) + "_lt_called";
	string name_type = string(name) + "_callerd_type";
	bool ab_type = !filterData[name_type].empty() && filterData[name_type] != "0";
	filterData.setUsed(name_ge_called.c_str());
	filterData.setUsed(name_lt_called.c_str());
	cRecordFilterItems gItems(ab_type ? cRecordFilterItems::_and : cRecordFilterItems::_or);
	for(int side = 0; side < (ab_type ? 2 : 1); side++) {
		string *value_ge = &filterData[ab_type && side == 1 ? name_ge_called : name_ge];
		string *value_lt = &filterData[ab_type && side == 1 ? name_lt_called : name_lt];
		if(value_ge->empty() && value_lt->empty()) {
			continue;
		}
		cRecordFilterItem_CallStream *item = new FILE_LINE(0) cRecordFilterItem_CallStream(this, field,
												  !ab_type ? cRecordFilterItem_CallStream::_any :
												  side == 0 ? cRecordFilterItem_CallStream::_caller :
													      cRecordFilterItem_CallStream::_called);
		if(!value_ge->empty()) {
			item->setGe(atof_mysql(value_ge->c_str()));
		}
		if(!value_lt->empty()) {
			item->setLt(atof_mysql(value_lt->c_str()));
		}
		gItems.addFilter(item);
	}
	if(gItems.isSet()) {
		addFilter(&gItems);
	}
}

void cCallFilter::addFilterStreams(cFilterData &filterData) {
	if(!filterData["rtp_streams_ge"].empty()) {
		cRecordFilterItem_CallStream *item = new FILE_LINE(0) cRecordFilterItem_CallStream(this, cRecordFilterItem_CallStream::_sf_count);
		item->setGe(atof_numval(filterData["rtp_streams_ge"].c_str()));
		addFilter(item);
	}
	if(!filterData["rtp_stream_packets_ge"].empty()) {
		cRecordFilterItem_CallStream *item = new FILE_LINE(0) cRecordFilterItem_CallStream(this, cRecordFilterItem_CallStream::_sf_received);
		item->setGe(atof_numval(filterData["rtp_stream_packets_ge"].c_str()));
		addFilter(item);
	}
	if(!filterData["rtp_stream_packets_le"].empty()) {
		cRecordFilterItem_CallStream *item = new FILE_LINE(0) cRecordFilterItem_CallStream(this, cRecordFilterItem_CallStream::_sf_received);
		item->setLe(atof_numval(filterData["rtp_stream_packets_le"].c_str()));
		addFilter(item);
	}
	if(filterData["rtp_stream_used_in_another_call"] == "true") {
		cRecordFilterItem_CallStream *item = new FILE_LINE(0) cRecordFilterItem_CallStream(this, cRecordFilterItem_CallStream::_sf_in_multiple_calls);
		item->setGe(1);
		addFilter(item);
	}
	if(!filterData["rtp_ip_port"].empty()) {
		for(int negative = 0; negative < 2; negative++) {
			cRecordFilterItem_CallStreamIpPort *item = new FILE_LINE(0) cRecordFilterItem_CallStreamIpPort(this, cRecordFilterItem_CallStreamIpPort::_t_rtp_dst,
														       cRecordFilterItem_CallStream::_any, negative);
			item->addEntries(filterData["rtp_ip_port"].c_str(), negative);
			if(item->isSet()) {
				addFilter(item);
			} else {
				delete item;
			}
		}
	}
}

cRecordFilterItem_base *cCallFilter::createCombinationLeaf(sCombRow *row) {
	if(row->filter_cfg.empty()) {
		return(new FILE_LINE(0) cRecordFilterItem_Fixed(this, true));
	}
	cCallFilter *subFilter = new FILE_LINE(0) cCallFilter(row->filter_cfg.c_str(), "f", true);
	if(subFilter->existsUnsupportedKeys()) {
		unsupportedKeysComb += (unsupportedKeysComb.empty() ? "" : ",") + subFilter->getUnsupportedKeys();
	}
	return(new FILE_LINE(0) cRecordFilterItem_CallSubFilter(this, subFilter, row->negative));
}

void cCallFilter::buildCombinationGroup(vector<sCombRow> *rows, unsigned *index, cRecordFilterItems *group) {
	int logic_level = (*rows)[*index].logic_level;
	cRecordFilterItems andGroup(cRecordFilterItems::_and);
	bool andGroupSet = false;
	while(*index < rows->size() && (*rows)[*index].logic_level >= logic_level) {
		if(!andGroupSet || (*rows)[*index].logic_level == logic_level) {
			if(andGroupSet) {
				group->addFilter(&andGroup);
				andGroup = cRecordFilterItems(cRecordFilterItems::_and);
			}
			andGroup.addFilter(createCombinationLeaf(&(*rows)[*index]));
			andGroupSet = true;
			++*index;
		} else {
			cRecordFilterItems subGroup(cRecordFilterItems::_or);
			buildCombinationGroup(rows, index, &subGroup);
			andGroup.addFilter(&subGroup);
			while(*index < rows->size() && (*rows)[*index].logic_level > logic_level) {
				++*index;
			}
		}
	}
	if(andGroupSet) {
		group->addFilter(&andGroup);
	}
}

void cCallFilter::addFilterCombination(cFilterData &filterData) {
	if(filterData["filters_comb"].empty()) {
		return;
	}
	vector<string> rowsStr = split(filterData["filters_comb"].c_str(), "\n", true);
	vector<sCombRow> rows;
	for(unsigned i = 0; i < rowsStr.size(); i++) {
		vector<string> fields = split(rowsStr[i].c_str(), "||F||", false, true);
		if(fields.size() < 9) {
			filterData.setUnused("filters_comb");
			syslog(LOG_NOTICE, "cCallFilter: filters_comb contains a malformed row - condition is not evaluated natively");
			return;
		}
		sCombRow row;
		row.logic_level = atoi(fields[3].c_str());
		row.negative = !fields[6].empty() && fields[6] != "0";
		row.filter_cfg = fields[8];
		row.unresolved = row.filter_cfg.empty() &&
				 (!fields[0].empty() || !fields[1].empty()) &&
				 fields[0] != "-1";
		rows.push_back(row);
	}
	if(!rows.size()) {
		filterData.setUnused("filters_comb");
		syslog(LOG_NOTICE, "cCallFilter: filters_comb contains no usable row - condition is not evaluated natively");
		return;
	}
	for(unsigned i = 0; i < rows.size(); i++) {
		if(rows[i].unresolved) {
			filterData.setUnused("filters_comb");
			syslog(LOG_NOTICE, "cCallFilter: filters_comb refers to a filter template which the sniffer cannot resolve");
			return;
		}
	}
	unsigned index = 0;
	cRecordFilterItems combGroup(cRecordFilterItems::_or);
	buildCombinationGroup(&rows, &index, &combGroup);
	if(combGroup.isSet()) {
		addFilter(&combGroup);
	}
}

void cCallFilter::addFilterStreamPorts(cFilterData &filterData) {
	if(!filterData["rtp_port"].empty()) {
		unsigned port = atoi(filterData["rtp_port"].c_str());
		unsigned port_to = !filterData["rtp_port_to"].empty() ? atoi(filterData["rtp_port_to"].c_str()) : port;
		cRecordFilterItem_CallStreamIpPort *item = new FILE_LINE(0) cRecordFilterItem_CallStreamIpPort(this, cRecordFilterItem_CallStreamIpPort::_t_rtp_dst);
		item->addPortRange(port, port_to);
		addFilter(item);
	} else {
		filterData.setUsed("rtp_port_to");
	}
	bool ab_type = !filterData["rtp_port_sd_type"].empty() && filterData["rtp_port_sd_type"] != "0";
	string *source = &filterData["rtp_port_source"];
	string *source_to = &filterData["rtp_port_source_to"];
	string *dest = &filterData["rtp_port_dest"];
	string *dest_to = &filterData["rtp_port_dest_to"];
	cRecordFilterItem_CallStreamIpPort *item_src = NULL;
	cRecordFilterItem_CallStreamIpPort *item_src_dst = NULL;
	cRecordFilterItem_CallStreamIpPort *item_dst = NULL;
	if(!source->empty()) {
		unsigned port = atoi(source->c_str());
		unsigned port_to = !source_to->empty() ? atoi(source_to->c_str()) : port;
		item_src = new FILE_LINE(0) cRecordFilterItem_CallStreamIpPort(this, cRecordFilterItem_CallStreamIpPort::_t_rtp_src);
		item_src->addPortRange(port, port_to);
		item_src_dst = new FILE_LINE(0) cRecordFilterItem_CallStreamIpPort(this, cRecordFilterItem_CallStreamIpPort::_t_rtp_dst);
		item_src_dst->addPortRange(port, port_to);
	}
	if(ab_type && !dest->empty()) {
		unsigned port = atoi(dest->c_str());
		unsigned port_to = !dest_to->empty() ? atoi(dest_to->c_str()) : port;
		item_dst = new FILE_LINE(0) cRecordFilterItem_CallStreamIpPort(this, cRecordFilterItem_CallStreamIpPort::_t_rtp_dst);
		item_dst->addPortRange(port, port_to);
	}
	if(ab_type) {
		delete item_src_dst;
		if(item_src && item_dst) {
			cRecordFilterItems gItems(cRecordFilterItems::_and);
			gItems.addFilter(item_src);
			gItems.addFilter(item_dst);
			addFilter(&gItems);
		} else if(item_src) {
			addFilter(item_src);
		} else if(item_dst) {
			addFilter(item_dst);
		}
	} else {
		delete item_dst;
		if(item_src) {
			cRecordFilterItems gItems(cRecordFilterItems::_or);
			gItems.addFilter(item_src);
			gItems.addFilter(item_src_dst);
			addFilter(&gItems);
		}
	}
}

void cCallFilter::addFilterStreamIpPorts(cFilterData &filterData, const char *nameSource, const char *nameDest, const char *nameType,
					 cRecordFilterItem_CallStreamIpPort::eTarget target, bool sdp) {
	bool ab_type = !filterData[nameType].empty() && filterData[nameType] != "0";
	string *source = &filterData[nameSource];
	string *dest = &filterData[nameDest];
	if(source->empty() && dest->empty()) {
		return;
	}
	cRecordFilterItem_CallStream::eSide side_src = sdp && ab_type ? cRecordFilterItem_CallStream::_caller : cRecordFilterItem_CallStream::_any;
	cRecordFilterItem_CallStream::eSide side_dst = sdp && ab_type ? cRecordFilterItem_CallStream::_called : cRecordFilterItem_CallStream::_any;
	for(int negative = 0; negative < 2; negative++) {
		cRecordFilterItem_CallStreamIpPort *item_src = NULL;
		cRecordFilterItem_CallStreamIpPort *item_src_dst = NULL;
		cRecordFilterItem_CallStreamIpPort *item_dst = NULL;
		if(!source->empty()) {
			item_src = new FILE_LINE(0) cRecordFilterItem_CallStreamIpPort(this, target, side_src, negative);
			item_src->addEntries(source->c_str(), negative);
			if(!item_src->isSet()) {
				delete item_src;
				item_src = NULL;
			} else if(!sdp) {
				item_src_dst = new FILE_LINE(0) cRecordFilterItem_CallStreamIpPort(this, cRecordFilterItem_CallStreamIpPort::_t_rtp_dst, side_src, negative);
				item_src_dst->addEntries(source->c_str(), negative);
			}
		}
		if(ab_type && !dest->empty()) {
			item_dst = new FILE_LINE(0) cRecordFilterItem_CallStreamIpPort(this, sdp ? target : cRecordFilterItem_CallStreamIpPort::_t_rtp_dst, side_dst, negative);
			item_dst->addEntries(dest->c_str(), negative);
			if(!item_dst->isSet()) {
				delete item_dst;
				item_dst = NULL;
			}
		}
		if(ab_type) {
			if(item_src_dst) {
				delete item_src_dst;
			}
			if(item_src && item_dst) {
				cRecordFilterItems gItems(negative ? cRecordFilterItems::_or : cRecordFilterItems::_and);
				gItems.addFilter(item_src);
				gItems.addFilter(item_dst);
				addFilter(&gItems);
			} else if(item_src) {
				addFilter(item_src);
			} else if(item_dst) {
				addFilter(item_dst);
			}
		} else {
			if(item_dst) {
				delete item_dst;
			}
			if(item_src && item_src_dst) {
				cRecordFilterItems gItems(negative ? cRecordFilterItems::_and : cRecordFilterItems::_or);
				gItems.addFilter(item_src);
				gItems.addFilter(item_src_dst);
				addFilter(&gItems);
			} else if(item_src) {
				addFilter(item_src);
			} else if(item_src_dst) {
				delete item_src_dst;
			}
		}
	}
}

void cCallFilter::addFilterNumInterval(cFilterData &filterData, const char *name, unsigned field, cRecordFilterItem_base::eCmpCond cond, bool zeroIsEmpty, bool mysqlConversion) {
	if(zeroIsEmpty ? !isEmptyOrZero(filterData[name]) : !filterData[name].empty()) {
		addFilter(new FILE_LINE(0) cRecordFilterItem_numInterval(this, field, mysqlConversion ?
									       atof_mysql(filterData[name].c_str()) :
									       atof_numval(filterData[name].c_str()), cond));
	}
}

cRecordFilterItem_CallProxy *cCallFilter::createAbProxyItem(sAbDef *def, const char *value) {
	cRecordFilterItem_CallProxy *filter = new FILE_LINE(0) cRecordFilterItem_CallProxy(this);
	if(def->codebook_table) {
		filter->addWhite(def->codebook_table, def->codebook_column, value);
	} else {
		filter->addWhite(value);
	}
	return(filter);
}


double cCallFilter::getField_float(void *rec, unsigned registerFieldIndex, bool *null) {
	extern sExistsColumns existsColumns;
	Call *call = (Call*)rec;
	bool _null = false;
	double rslt = 0;
	switch(registerFieldIndex) {
	case cf_duration:
		rslt = durationValue(call->isClosed() ? call->duration_us() : call->duration_active_us(), existsColumns.cdr_duration_ms);
		break;
	case cf_connect_duration:
		if(call->connect_time_us) {
			rslt = durationValue(call->isClosed() ? call->connect_duration_us() : call->connect_duration_active_us(), existsColumns.cdr_connect_duration_ms);
		} else {
			_null = true;
		}
		break;
	case cf_progress_time:
		if(call->progress_time_us) {
			rslt = durationValue(call->progress_time_us - call->first_packet_time_us, existsColumns.cdr_progress_time_ms);
		} else {
			_null = true;
		}
		break;
	case cf_ringing_time:
		{
		bool connect_duration_null;
		double connect_duration = getField_float(rec, cf_connect_duration, &connect_duration_null);
		bool progress_time_null;
		double progress_time = getField_float(rec, cf_progress_time, &progress_time_null);
		rslt = getField_float(rec, cf_duration, NULL) - (connect_duration_null ? 0 : connect_duration) - (progress_time_null ? 0 : progress_time);
		}
		break;
	case cf_post_bye_delay:
		{
		CallBranch *c_branch = call->branch_main();
		if(c_branch->seenbye_time_usec && c_branch->seenbye_and_ok_time_usec &&
		   c_branch->seenbye_and_ok_time_usec > c_branch->seenbye_time_usec) {
			rslt = durationValue(c_branch->seenbye_and_ok_time_usec - c_branch->seenbye_time_usec, existsColumns.cdr_post_bye_delay_ms);
		} else {
			_null = true;
		}
		}
		break;
	case cf_vlan:
		{
		u_int16_t vlan = call->branch_main()->getVlan();
		if(VLAN_IS_SET(vlan)) {
			rslt = vlan;
		} else {
			_null = true;
		}
		}
		break;
	case cf_response_time_100:
		if(call->saved_data) {
			if(call->saved_data->response_time_100_null) {
				_null = true;
			} else {
				rslt = call->saved_data->response_time_100;
			}
		} else if(call->first_invite_time_us && call->first_response_100_time_us) {
			extern bool opt_response_time_from_first_invite;
			rslt = min(65535., opt_response_time_from_first_invite ?
					    round((call->first_response_100_time_us - call->first_invite_time_us) / 1000.) :
					    round(call->branch_main()->get_min_response_100_time_us() / 1000.));
		} else {
			_null = true;
		}
		break;
	case cf_ttl_min:
	case cf_ttl_max:
	case cf_ttl_avg:
		if(call->ttl_count > 0) {
			rslt = registerFieldIndex == cf_ttl_min ? call->ttl_min :
			       registerFieldIndex == cf_ttl_max ? call->ttl_max :
			       round((double)call->ttl_sum / call->ttl_count * 10);
		} else {
			_null = true;
		}
		break;
	case cf_dscp_caller_sip:
	case cf_dscp_called_sip:
	case cf_dscp_caller_rtp:
	case cf_dscp_called_rtp:
		{
		extern int opt_dscp;
		if(!opt_dscp || !existsColumns.cdr_dscp) {
			_null = true;
		} else if(registerFieldIndex == cf_dscp_caller_sip) {
			rslt = call->caller_sipdscp;
		} else if(registerFieldIndex == cf_dscp_called_sip) {
			rslt = call->called_sipdscp;
		} else if(call->saved_data) {
			rslt = call->saved_data->dscp_rtp[registerFieldIndex == cf_dscp_caller_rtp ? 0 : 1];
		} else {
			#if not EXPERIMENTAL_LITE_RTP_MOD
			RTP *rtp = registerFieldIndex == cf_dscp_caller_rtp ? call->lastactivecallerrtp : call->lastactivecalledrtp;
			if(rtp) {
				rslt = rtp->dscp;
			}
			#endif
		}
		}
		break;
	case cf_max_retransmission_invite:
		{
		unsigned max_retrans = call->saved_data ?
					call->saved_data->max_retransmission_invite :
					call->getMaxRetransmissionInvite(call->branch_main());
		if(max_retrans > 0) {
			rslt = max_retrans;
		} else {
			_null = true;
		}
		}
		break;
	default:
		rslt = getField_int(rec, registerFieldIndex);
		break;
	}
	if(null) {
		*null = _null;
	}
	return(rslt);
}


cUserRestriction::cUserRestriction() {
	cond_ip = NULL;
	cond_number = NULL;
	cond_domain = NULL;
	cond_vlan = NULL;
	cond_ch_cdr = NULL;
	cond_ch_message = NULL;
	clear();
}

cUserRestriction::~cUserRestriction() {
	clear();
}

void cUserRestriction::load(unsigned uid, bool *useCustomHeaders, SqlDb *sqlDb) {
	*useCustomHeaders = false;
	this->uid = uid;
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	list<SqlDb_condField> cond;
	cond.push_back(SqlDb_condField("id", intToString(uid)));
	sqlDb->select("users", NULL, &cond);
	SqlDb_row row = sqlDb->fetchRow();
	if(row) {
		src_ip = row["ip"];
		src_number = row["number"];
		src_domain = row["domain"];
		src_vlan = row["vlan"];
		src_ch_cdr =  row["custom_headers_cdr"];
		src_ch_message = row["custom_headers_message"];
		comb_cond = atoi(row["ip_number_domain_or"].c_str()) > 0 ? _cc_or : _cc_and;
		if(!src_ch_cdr.empty() || !src_ch_message.empty()) {
			*useCustomHeaders = true;
		}
		apply();
	} else {
		clear();
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
}

void cUserRestriction::apply() {
	if(!src_ip.empty()) {
		cond_ip = new FILE_LINE(0) ListIP;
		cond_ip->add(src_ip.c_str());
	}
	if(!src_number.empty()) {
		cond_number = new FILE_LINE(0) ListPhoneNumber;
		cond_number->add(src_number.c_str(), PhoneNumber::_tn_prefix);
	}
	if(!src_domain.empty()) {
		cond_domain = new FILE_LINE(0) ListCheckString;
		cond_domain->add(src_domain.c_str());
	}
	if(!src_vlan.empty()) {
		vector<int> vlans = split2int(src_vlan, split(",|;|\n", '|'), true);
		if(vlans.size()) {
			cond_vlan = new FILE_LINE(0) list<u_int16_t>;
			for(unsigned i = 0; i < vlans.size(); i++) {
				cond_vlan->push_back(vlans[i]);
			}
			cond_vlan->sort();
		}
	}
	if(!src_ch_cdr.empty()) {
		cond_ch_cdr = new FILE_LINE(0) cLogicHierarchyAndOr_custom_header();
		cond_ch_cdr->set(src_ch_cdr.c_str());
	}
	if(!src_ch_message.empty()) {
		cond_ch_message = new FILE_LINE(0) cLogicHierarchyAndOr_custom_header();
		cond_ch_message->set(src_ch_message.c_str());
	}
}

void cUserRestriction::clear() {
	uid = 0;
	src_ip = "";
	src_number = "";
	src_domain = "";
	src_vlan = "";
	src_ch_cdr = "";
	src_ch_message = "";
	comb_cond = _cc_and;
	if(cond_ip) {
		delete cond_ip;
		cond_ip = NULL;
	}
	if(cond_number) {
		delete cond_number;
		cond_number = NULL;
	}
	if(cond_domain) {
		delete cond_domain;
		cond_domain = NULL;
	}
	if(cond_vlan) {
		delete cond_vlan;
		cond_vlan = NULL;
	}
	if(cond_ch_cdr) {
		delete cond_ch_cdr;
		cond_ch_cdr = NULL;
	}
	if(cond_ch_message) {
		delete cond_ch_message;
		cond_ch_message = NULL;
	}
}

bool cUserRestriction::check(eTypeSrc type_src,
			     vmIP *ip_src, vmIP *ip_dst,
			     const char *number_src, const char *number_dst, const char *number_contact,
			     const char *domain_src, const char *domain_dst, const char *domain_contact,
			     u_int16_t vlan,
			     map<string, string> *ch) {
	unsigned count_used_cond = 0;
	if(cond_ip) {
		bool rslt_any = false;
		for(unsigned i = 0; i < 2; i++) {
			if(i == 0 ? ip_src : ip_dst) {
				bool rslt = cond_ip->checkIP(*(i == 0 ? ip_src : ip_dst));
				if(rslt) {
					if(comb_cond == _cc_or) return(true); 
					rslt_any = true;
					break;
				}
			}
		}
		if(!rslt_any && comb_cond == _cc_and) return(false);
		++count_used_cond;
	}
	if(cond_number) {
		bool rslt_any = false;
		for(unsigned i = 0; i < 3; i++) {
			if(i == 0 ? number_src : 
			   i == 1 ? number_dst : number_contact) {
				bool rslt = cond_number->checkNumber(i == 0 ? number_src : 
								     i == 1 ? number_dst : number_contact);
				if(rslt) {
					if(comb_cond == _cc_or) return(true); 
					rslt_any = true;
					break;
				}
			}
		}
		if(!rslt_any && comb_cond == _cc_and) return(false);
		++count_used_cond;
	}
	if(cond_domain) {
		bool rslt_any = false;
		for(unsigned i = 0; i < 3; i++) {
			if(i == 0 ? domain_src : 
			   i == 1 ? domain_dst : domain_contact) {
				bool rslt = cond_domain->check(i == 0 ? domain_src : 
							       i == 1 ? domain_dst : domain_contact);
				if(rslt) {
					if(comb_cond == _cc_or) return(true); 
					rslt_any = true;
					break;
				}
			}
		}
		if(!rslt_any && comb_cond == _cc_and) return(false);
		++count_used_cond;
	}
	if(cond_vlan && vlan != VLAN_UNSET) {
		list<u_int16_t>::iterator iter = std::lower_bound(cond_vlan->begin(), cond_vlan->end(), vlan);
		bool rslt = iter != cond_vlan->end() && *iter == vlan;
		if(comb_cond == _cc_or) {
			if(rslt) return(true); 
		} else {
			if(!rslt) return(false); 
		}
		++count_used_cond;
	}
	if(type_src == _ts_cdr && cond_ch_cdr && ch) {
		bool rslt = cond_ch_cdr->eval(ch);
		if(comb_cond == _cc_or) {
			if(rslt) return(true); 
		} else {
			if(!rslt) return(false); 
		}
		++count_used_cond;
	}
	if(type_src == _ts_message && cond_ch_message && ch) {
		bool rslt = cond_ch_message->eval(ch);
		if(comb_cond == _cc_or) {
			if(rslt) return(true); 
		} else {
			if(!rslt) return(false); 
		}
		++count_used_cond;
	}
	return(comb_cond == _cc_or ?
		count_used_cond == 0 :
		true);
}

cLogicHierarchyAndOr::cLogicHierarchyAndOr() {
}

cLogicHierarchyAndOr::~cLogicHierarchyAndOr() {
	clear();
}

bool cLogicHierarchyAndOr::eval(void *data) {
	unsigned index = 0;
	return(eval(&index, data));
}

void cLogicHierarchyAndOr::set(const char *src) {
	vector<string> src_v = split(src, '\n');
	for(unsigned i = 0; i < src_v.size(); i++) {
		if(src_v[i][0] == '[' && src_v[i][src_v[i].length() - 1] == ']') {
			size_t delim_pos = src_v[i].find(',');
			if(delim_pos != string::npos) {
				string a = src_v[i].substr(1, delim_pos - 1);
				string b = src_v[i].substr(delim_pos + 1, src_v[i].length() - delim_pos - 2);
				if(b.length() > 2 && b[0] == '"' && b[b.length() - 1] == '"') {
					b = b.substr(1, b.length() - 2);
				}
				if(!a.empty() && !b.empty()) {
					cItem *item = createItem(atoi(a.c_str()), b.c_str()); 
					if(item) {
						items.push_back(item);
					}
				}
			}
		}
	}
}

bool cLogicHierarchyAndOr::eval(unsigned *index, void *data) {
	int level = items[*index]->level;
	vector<bool> rslts;
	while(*index < items.size()) {
		if(items[*index]->level < level) {
			break;
		} else if(items[*index]->level > level) {
			bool rslt = eval(index, data);
			rslts[rslts.size() - 1] = rslts[rslts.size() - 1] & rslt;
		} else {
			bool rslt = items[*index]->eval(data);
			rslts.push_back(rslt);
			++*index;
		}
	}
	for(unsigned i = 0; i < rslts.size(); i++) {
		if(rslts[i]) {
			return(true);
		}
	}
	return(false);
}

cLogicHierarchyAndOr::cItem *cLogicHierarchyAndOr::createItem(int level, const char *data) {
	cItem *item = new FILE_LINE(0) cItem(level);
	return(item);
}


void cLogicHierarchyAndOr::clear() {
	for(unsigned i = 0; i < items.size(); i++) {
		delete items[i];
	}
	items.clear();
}

bool cLogicHierarchyAndOr_custom_header::cItemCustomHeader::eval(void *data) {
	map<string, string> *ch = (map<string, string>*)data;
	map<string, string>::iterator iter = ch->find(custom_header);
	if(iter != ch->end()) {
		return(str_like(iter->second.c_str(), pattern.c_str()));
	} else {
		return(false);
	}
}

cLogicHierarchyAndOr::cItem *cLogicHierarchyAndOr_custom_header::createItem(int level, const char *data) {
	const char *data_separator = strchr(data, ':');
	if(data_separator) {
		string custom_header = string(data).substr(0, data_separator - data);
		string value = string(data_separator + 1);
		cItemCustomHeader *item = new FILE_LINE(0) cItemCustomHeader(level, custom_header.c_str(), value.c_str());
		return(item);
	}
	return(NULL);
}
