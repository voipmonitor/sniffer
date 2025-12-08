#include "voipmonitor.h"

#include "ipfix.h"
#include "tools.h"
#include "header_packet.h"
#include "sniff_inline.h"
#include "sniff_proc_class.h"

#include <stddef.h>
#include <pcap.h>


#define IPFIX_VERSION_DEFAULT 10


extern bool opt_ipfix_counter_log;
extern bool opt_ipfix_via_pb;
extern int opt_t2_boost;

cIpFixCounter ipfix_counter;


string sIPFixQosStatsExt::json(const char *callid) {
	JsonExport json;
	json.add("IncRtpBytes", IncRtpBytes);
	json.add("IncRtpPackets", IncRtpPackets);
	json.add("IncRtpLostPackets", IncRtpLostPackets);
	json.add("IncRtpAvgJitter", IncRtpAvgJitter);
	json.add("IncRtpMaxJitter", IncRtpMaxJitter);
	json.add("IncRtcpBytes", IncRtcpBytes);
	json.add("IncRtcpPackets", IncRtcpPackets);
	json.add("IncRtcpLostPackets", IncRtcpLostPackets);
	json.add("IncRtcpAvgJitter", IncRtcpAvgJitter);
	json.add("IncRtcpMaxJitter", IncRtcpMaxJitter);
	json.add("IncRtcpAvgLat", IncRtcpAvgLat);
	json.add("IncRtcpMaxLat", IncRtcpMaxLat);
	json.add("IncrVal", IncrVal);
	json.add("IncMos", IncMos);
	json.add("OutRtpBytes", OutRtpBytes);
	json.add("OutRtpPackets", OutRtpPackets);
	json.add("OutRtpLostPackets", OutRtpLostPackets);
	json.add("OutRtpAvgJitter", OutRtpAvgJitter);
	json.add("OutRtpMaxJitter", OutRtpMaxJitter);
	json.add("OutRtcpBytes", OutRtcpBytes);
	json.add("OutRtcpPackets", OutRtcpPackets);
	json.add("OutRtcpLostPackets", OutRtcpLostPackets);
	json.add("OutRtcpAvgJitter", OutRtcpAvgJitter);
	json.add("OutRtcpMaxJitter", OutRtcpMaxJitter);
	json.add("OutRtcpAvgLat", OutRtcpAvgLat);
	json.add("OutRtcpMaxLat", OutRtcpMaxLat);
	json.add("OutrVal", OutrVal);
	json.add("OutMos", OutMos);
	json.add("Type", Type);
	json.add("CallerIncSrcIP", ipv4_2_vmIP(*(u_int32_t*)CallerIncSrcIP, true).getString());
	json.add("CallerIncDstIP", ipv4_2_vmIP(*(u_int32_t*)CallerIncDstIP, true).getString());
	json.add("CallerIncSrcPort", CallerIncSrcPort);
	json.add("CallerIncDstPort", CallerIncDstPort);
	json.add("CalleeIncSrcIP", ipv4_2_vmIP(*(u_int32_t*)CalleeIncSrcIP, true).getString());
	json.add("CalleeIncDstIP", ipv4_2_vmIP(*(u_int32_t*)CalleeIncDstIP, true).getString());
	json.add("CalleeIncSrcPort", CalleeIncSrcPort);
	json.add("CalleeIncDstPort", CalleeIncDstPort);
	json.add("CallerOutSrcIP", ipv4_2_vmIP(*(u_int32_t*)CallerOutSrcIP, true).getString());
	json.add("CallerOutDstIP", ipv4_2_vmIP(*(u_int32_t*)CallerOutDstIP, true).getString());
	json.add("CallerOutSrcPort", CallerOutSrcPort);
	json.add("CallerOutDstPort", CallerOutDstPort);
	json.add("CalleeOutSrcIP", ipv4_2_vmIP(*(u_int32_t*)CalleeOutSrcIP, true).getString());
	json.add("CalleeOutDstIP", ipv4_2_vmIP(*(u_int32_t*)CalleeOutDstIP, true).getString());
	json.add("CalleeOutSrcPort", CalleeOutSrcPort);
	json.add("CalleeOutDstPort", CalleeOutDstPort);
	json.add("CallerIntSlot", CallerIntSlot);
	json.add("CallerIntPort", CallerIntPort);
	json.add("CallerIntVlan", CallerIntVlan);
	json.add("CalleeIntSlot", CalleeIntSlot);
	json.add("CalleeIntPort", CalleeIntPort);
	json.add("CalleeIntVlan", CalleeIntVlan);
	json.add("BeginTimeSec", BeginTimeSec);
	json.add("BeginTimeMic", BeginTimeMic);
	json.add("EndTimeSec", EndTimeSec);
	json.add("EndTimeMic", EndTimeMic);
	json.add("Separator", Separator);
	json.add("IncRealm", IncRealm);
	json.add("OutRealm", OutRealm);
	json.add("IncCallID", IncCallID);
	json.add("OutCallID", OutCallID);
	if(callid) {
		json.add("CallID", callid);
	}
	return(json.getJson());
}

void sIPFixQosStatsExt::load_from_json(const char *json, unsigned json_len) {
	string json_str(json, json_len);
	load_from_json(json_str.c_str());
}

void sIPFixQosStatsExt::load_from_json(const char *json) {
	JsonItem json_data;
	json_data.parse(json);
	IncRtpBytes = atol(json_data.getValue("IncRtpBytes").c_str());
	IncRtpPackets = atol(json_data.getValue("IncRtpPackets").c_str());
	IncRtpLostPackets = atol(json_data.getValue("IncRtpLostPackets").c_str());
	IncRtpAvgJitter = atol(json_data.getValue("IncRtpAvgJitter").c_str());
	IncRtpMaxJitter = atol(json_data.getValue("IncRtpMaxJitter").c_str());
	IncRtcpBytes = atol(json_data.getValue("IncRtcpBytes").c_str());
	IncRtcpPackets = atol(json_data.getValue("IncRtcpPackets").c_str());
	IncRtcpLostPackets = atol(json_data.getValue("IncRtcpLostPackets").c_str());
	IncRtcpAvgJitter = atol(json_data.getValue("IncRtcpAvgJitter").c_str());
	IncRtcpMaxJitter = atol(json_data.getValue("IncRtcpMaxJitter").c_str());
	IncRtcpAvgLat = atol(json_data.getValue("IncRtcpAvgLat").c_str());
	IncRtcpMaxLat = atol(json_data.getValue("IncRtcpMaxLat").c_str());
	OutRtpBytes = atol(json_data.getValue("OutRtpBytes").c_str());
	OutRtpPackets = atol(json_data.getValue("OutRtpPackets").c_str());
	OutRtpLostPackets = atol(json_data.getValue("OutRtpLostPackets").c_str());
	OutRtpAvgJitter = atol(json_data.getValue("OutRtpAvgJitter").c_str());
	OutRtpMaxJitter = atol(json_data.getValue("OutRtpMaxJitter").c_str());
	OutRtcpBytes = atol(json_data.getValue("OutRtcpBytes").c_str());
	OutRtcpPackets = atol(json_data.getValue("OutRtcpPackets").c_str());
	OutRtcpLostPackets = atol(json_data.getValue("OutRtcpLostPackets").c_str());
	OutRtcpAvgJitter = atol(json_data.getValue("OutRtcpAvgJitter").c_str());
	OutRtcpMaxJitter = atol(json_data.getValue("OutRtcpMaxJitter").c_str());
	OutRtcpAvgLat = atol(json_data.getValue("OutRtcpAvgLat").c_str());
	OutRtcpMaxLat = atol(json_data.getValue("OutRtcpMaxLat").c_str());
	*(u_int32_t*)CallerIncSrcIP = str_2_vmIP(json_data.getValue("CallerIncSrcIP").c_str()).getIPv4(true);
	CallerIncSrcPort = atoi(json_data.getValue("CallerIncSrcPort").c_str());
	*(u_int32_t*)CallerIncDstIP = str_2_vmIP(json_data.getValue("CallerIncDstIP").c_str()).getIPv4(true);
	CallerIncDstPort = atoi(json_data.getValue("CallerIncDstPort").c_str());
	*(u_int32_t*)CalleeIncSrcIP = str_2_vmIP(json_data.getValue("CalleeIncSrcIP").c_str()).getIPv4(true);
	CalleeIncSrcPort = atoi(json_data.getValue("CalleeIncSrcPort").c_str());
	*(u_int32_t*)CalleeIncDstIP = str_2_vmIP(json_data.getValue("CalleeIncDstIP").c_str()).getIPv4(true);
	CalleeIncDstPort = atoi(json_data.getValue("CalleeIncDstPort").c_str());
	*(u_int32_t*)CallerOutSrcIP = str_2_vmIP(json_data.getValue("CallerOutSrcIP").c_str()).getIPv4(true);
	CallerOutSrcPort = atoi(json_data.getValue("CallerOutSrcPort").c_str());
	*(u_int32_t*)CallerOutDstIP = str_2_vmIP(json_data.getValue("CallerOutDstIP").c_str()).getIPv4(true);
	CallerOutDstPort = atoi(json_data.getValue("CallerOutDstPort").c_str());
	*(u_int32_t*)CalleeOutSrcIP = str_2_vmIP(json_data.getValue("CalleeOutSrcIP").c_str()).getIPv4(true);
	CalleeOutSrcPort = atoi(json_data.getValue("CalleeOutSrcPort").c_str());
	*(u_int32_t*)CalleeOutDstIP = str_2_vmIP(json_data.getValue("CalleeOutDstIP").c_str()).getIPv4(true);
	CalleeOutDstPort = atoi(json_data.getValue("CalleeOutDstPort").c_str());
	IncMos = atol(json_data.getValue("IncMos").c_str());
	IncrVal = atol(json_data.getValue("IncrVal").c_str());
	OutMos = atol(json_data.getValue("OutMos").c_str());
	OutrVal = atol(json_data.getValue("OutrVal").c_str());
	Type = atoi(json_data.getValue("Type").c_str());
	BeginTimeSec = atol(json_data.getValue("BeginTimeSec").c_str());
	BeginTimeMic = atol(json_data.getValue("BeginTimeMic").c_str());
	EndTimeSec = atol(json_data.getValue("EndTimeSec").c_str());
	EndTimeMic = atol(json_data.getValue("EndTimeMic").c_str());
	Separator = atoi(json_data.getValue("Separator").c_str());
	IncRealm = json_data.getValue("IncRealm");
	OutRealm = json_data.getValue("OutRealm");
	IncCallID = json_data.getValue("IncCallID");
	OutCallID = json_data.getValue("OutCallID");
}

void sIPFixQosStatsExt::load(sIPFixQosStats *src, sIPFixHeader *header) {
	memcpy((sIPFixQosStats*)this, src, sizeof(sIPFixQosStats));
	ntoh();
	IncRealm.clear();
	OutRealm.clear();
	IncCallID.clear();
	OutCallID.clear();
	u_char *data_end = (u_char*)header + ntohs(header->Length);
	u_char *var_data = (u_char*)src + offsetof(sIPFixQosStats, Separator);
	if(var_data >= data_end || *var_data != Separator) {
		return;
	}
	var_data++;
	for(int i = 0; i < 4; i++) {
		if(var_data + 2 > data_end) {
			return;
		}
		u_int16_t field_len = ntohs(*(u_int16_t*)var_data);
		var_data += 2;
		string *target_field = NULL;
		switch(i) {
		case 0:
			target_field = &IncRealm;
			break;
		case 1:
			target_field = &OutRealm;
			break;
		case 2:
			target_field = &IncCallID;
			break;
		case 3:
			target_field = &OutCallID;
			break;
		}
		if(field_len > 0) {
			if(var_data + field_len > data_end) {
				return;
			}
			*target_field = string((char*)var_data, field_len);
			var_data += field_len;
			if(i < 3 && var_data < data_end && *var_data == Separator) {
				var_data++;
			}
		}
	}
}

void sIPFixQosStatsExt::getRtpStreams(vector<sIPFixQosStreamStat> *streams, const char *callid) {
	if(!callid || !streams) {
		return;
	}
	bool isIncCall = (IncCallID == callid);
	bool isOutCall = (OutCallID == callid);
	if(!isIncCall && !isOutCall) {
		return;
	}
	if(isIncCall) {
		// Add Caller Inc stream (Caller → SBC)
		sIPFixQosStreamStat stream1;
		stream1.RtpBytes = IncRtpBytes;
		stream1.RtpPackets = IncRtpPackets;
		stream1.RtpLostPackets = IncRtpLostPackets;
		stream1.RtpAvgJitter = IncRtpAvgJitter;
		stream1.RtpMaxJitter = IncRtpMaxJitter;
		stream1.RtcpBytes = IncRtcpBytes;
		stream1.RtcpPackets = IncRtcpPackets;
		stream1.RtcpLostPackets = IncRtcpLostPackets;
		stream1.RtcpAvgJitter = IncRtcpAvgJitter;
		stream1.RtcpMaxJitter = IncRtcpMaxJitter;
		stream1.RtcpAvgLat = IncRtcpAvgLat;
		stream1.RtcpMaxLat = IncRtcpMaxLat;
		stream1.rVal = IncrVal;
		stream1.Mos = IncMos;
		stream1.SrcIP = ipv4_2_vmIP(*(u_int32_t*)CallerIncSrcIP, true);
		stream1.DstIP = ipv4_2_vmIP(*(u_int32_t*)CallerIncDstIP, true);
		stream1.SrcPort = CallerIncSrcPort;
		stream1.DstPort = CallerIncDstPort;
		stream1.CodecType = Type;
		stream1.BeginTimeUS = TIME_S_TO_US(BeginTimeSec) + BeginTimeMic;
		stream1.EndTimeUS = TIME_S_TO_US(EndTimeSec) + EndTimeMic;
		stream1.iscaller = true;  // Caller → SBC (incoming side)
		streams->push_back(stream1);
		// Add Callee Inc stream (SBC → Caller)
		sIPFixQosStreamStat stream2;
		stream2.RtpBytes = IncRtpBytes;  // Same statistics for both Inc directions
		stream2.RtpPackets = IncRtpPackets;
		stream2.RtpLostPackets = IncRtpLostPackets;
		stream2.RtpAvgJitter = IncRtpAvgJitter;
		stream2.RtpMaxJitter = IncRtpMaxJitter;
		stream2.RtcpBytes = IncRtcpBytes;
		stream2.RtcpPackets = IncRtcpPackets;
		stream2.RtcpLostPackets = IncRtcpLostPackets;
		stream2.RtcpAvgJitter = IncRtcpAvgJitter;
		stream2.RtcpMaxJitter = IncRtcpMaxJitter;
		stream2.RtcpAvgLat = IncRtcpAvgLat;
		stream2.RtcpMaxLat = IncRtcpMaxLat;
		stream2.rVal = IncrVal;
		stream2.Mos = IncMos;
		stream2.SrcIP = ipv4_2_vmIP(*(u_int32_t*)CalleeIncSrcIP, true);
		stream2.DstIP = ipv4_2_vmIP(*(u_int32_t*)CalleeIncDstIP, true);
		stream2.SrcPort = CalleeIncSrcPort;
		stream2.DstPort = CalleeIncDstPort;
		stream2.CodecType = Type;
		stream2.BeginTimeUS = TIME_S_TO_US(BeginTimeSec) + BeginTimeMic;
		stream2.EndTimeUS = TIME_S_TO_US(EndTimeSec) + EndTimeMic;
		stream2.iscaller = false;  // SBC → Caller (callee to caller on incoming side)
		streams->push_back(stream2);
	}
	if(isOutCall) {
		// Add Caller Out stream (SBC → Callee)
		sIPFixQosStreamStat stream3;
		stream3.RtpBytes = OutRtpBytes;
		stream3.RtpPackets = OutRtpPackets;
		stream3.RtpLostPackets = OutRtpLostPackets;
		stream3.RtpAvgJitter = OutRtpAvgJitter;
		stream3.RtpMaxJitter = OutRtpMaxJitter;
		stream3.RtcpBytes = OutRtcpBytes;
		stream3.RtcpPackets = OutRtcpPackets;
		stream3.RtcpLostPackets = OutRtcpLostPackets;
		stream3.RtcpAvgJitter = OutRtcpAvgJitter;
		stream3.RtcpMaxJitter = OutRtcpMaxJitter;
		stream3.RtcpAvgLat = OutRtcpAvgLat;
		stream3.RtcpMaxLat = OutRtcpMaxLat;
		stream3.rVal = OutrVal;
		stream3.Mos = OutMos;
		stream3.SrcIP = ipv4_2_vmIP(*(u_int32_t*)CallerOutSrcIP, true);
		stream3.DstIP = ipv4_2_vmIP(*(u_int32_t*)CallerOutDstIP, true);
		stream3.SrcPort = CallerOutSrcPort;
		stream3.DstPort = CallerOutDstPort;
		stream3.CodecType = Type;
		stream3.BeginTimeUS = TIME_S_TO_US(BeginTimeSec) + BeginTimeMic;
		stream3.EndTimeUS = TIME_S_TO_US(EndTimeSec) + EndTimeMic;
		stream3.iscaller = true;  // SBC → Callee (outgoing side)
		streams->push_back(stream3);
		// Add Callee Out stream (Callee → SBC)
		sIPFixQosStreamStat stream4;
		stream4.RtpBytes = OutRtpBytes;  // Same statistics for both Out directions
		stream4.RtpPackets = OutRtpPackets;
		stream4.RtpLostPackets = OutRtpLostPackets;
		stream4.RtpAvgJitter = OutRtpAvgJitter;
		stream4.RtpMaxJitter = OutRtpMaxJitter;
		stream4.RtcpBytes = OutRtcpBytes;
		stream4.RtcpPackets = OutRtcpPackets;
		stream4.RtcpLostPackets = OutRtcpLostPackets;
		stream4.RtcpAvgJitter = OutRtcpAvgJitter;
		stream4.RtcpMaxJitter = OutRtcpMaxJitter;
		stream4.RtcpAvgLat = OutRtcpAvgLat;
		stream4.RtcpMaxLat = OutRtcpMaxLat;
		stream4.rVal = OutrVal;
		stream4.Mos = OutMos;
		stream4.SrcIP = ipv4_2_vmIP(*(u_int32_t*)CalleeOutSrcIP, true);
		stream4.DstIP = ipv4_2_vmIP(*(u_int32_t*)CalleeOutDstIP, true);
		stream4.SrcPort = CalleeOutSrcPort;
		stream4.DstPort = CalleeOutDstPort;
		stream4.CodecType = Type;
		stream4.BeginTimeUS = TIME_S_TO_US(BeginTimeSec) + BeginTimeMic;
		stream4.EndTimeUS = TIME_S_TO_US(EndTimeSec) + EndTimeMic;
		stream4.iscaller = false;  // Callee → SBC (callee to caller on outgoing side)
		streams->push_back(stream4);
	}
}

void sIPFixQosStatsExt::ntoh() {
	IncRtpBytes        = ntohl(IncRtpBytes);
	IncRtpPackets      = ntohl(IncRtpPackets);
	IncRtpLostPackets  = ntohl(IncRtpLostPackets);
	IncRtpAvgJitter    = ntohl(IncRtpAvgJitter);
	IncRtpMaxJitter    = ntohl(IncRtpMaxJitter);
	IncRtcpBytes       = ntohl(IncRtcpBytes);
	IncRtcpPackets     = ntohl(IncRtcpPackets);
	IncRtcpLostPackets = ntohl(IncRtcpLostPackets);
	IncRtcpAvgJitter   = ntohl(IncRtcpAvgJitter);
	IncRtcpMaxJitter   = ntohl(IncRtcpMaxJitter);
	IncRtcpAvgLat      = ntohl(IncRtcpAvgLat);
	IncRtcpMaxLat      = ntohl(IncRtcpMaxLat);
	IncrVal            = ntohl(IncrVal);
	IncMos             = ntohl(IncMos);
	OutRtpBytes        = ntohl(OutRtpBytes);
	OutRtpPackets      = ntohl(OutRtpPackets);
	OutRtpLostPackets  = ntohl(OutRtpLostPackets);
	OutRtpAvgJitter    = ntohl(OutRtpAvgJitter);
	OutRtpMaxJitter    = ntohl(OutRtpMaxJitter);
	OutRtcpBytes       = ntohl(OutRtcpBytes);
	OutRtcpPackets     = ntohl(OutRtcpPackets);
	OutRtcpLostPackets = ntohl(OutRtcpLostPackets);
	OutRtcpAvgJitter   = ntohl(OutRtcpAvgJitter);
	OutRtcpMaxJitter   = ntohl(OutRtcpMaxJitter);
	OutRtcpAvgLat      = ntohl(OutRtcpAvgLat);
	OutRtcpMaxLat      = ntohl(OutRtcpMaxLat);
	OutrVal            = ntohl(OutrVal);
	OutMos             = ntohl(OutMos);
	CallerIncSrcPort   = ntohs(CallerIncSrcPort);
	CallerIncDstPort   = ntohs(CallerIncDstPort);
	CalleeIncSrcPort   = ntohs(CalleeIncSrcPort);
	CalleeIncDstPort   = ntohs(CalleeIncDstPort);
	CallerOutSrcPort   = ntohs(CallerOutSrcPort);
	CallerOutDstPort   = ntohs(CallerOutDstPort);
	CalleeOutSrcPort   = ntohs(CalleeOutSrcPort);
	CalleeOutDstPort   = ntohs(CalleeOutDstPort);
	CallerIntVlan      = ntohs(CallerIntVlan);
	CalleeIntVlan      = ntohs(CalleeIntVlan);
	BeginTimeSec       = ntohl(BeginTimeSec);
	BeginTimeMic       = ntohl(BeginTimeMic);
	EndTimeSec         = ntohl(EndTimeSec);
	EndTimeMic         = ntohl(EndTimeMic);
}

cIPFixServer::cIPFixServer() {
}

cIPFixServer::~cIPFixServer() {
}

void cIPFixServer::createConnection(cSocket *socket) {
	if(is_terminating()) {
		return;
	}
	cIPFixConnection *connection = new FILE_LINE(0) cIPFixConnection(socket);
	connection->connection_start();
}

cIPFixConnection::cIPFixConnection(cSocket *socket)
: cServerConnection(socket), cTimer(NULL) {
	block_store = NULL;
	block_store_sync = 0;
	if(opt_t2_boost && opt_ipfix_via_pb) {
		setEveryMS(100);
		start();
	}
}

cIPFixConnection::~cIPFixConnection() {
}

void cIPFixConnection::connection_process() {
	SimpleBuffer read_buffer;
	while((socket && !socket->isError() && !socket->isTerminate()) && !is_terminating())  {
		u_char buffer[10000];
		size_t buffer_length = sizeof(buffer);
		if(socket->read(buffer, &buffer_length) && buffer_length > 0) {
			read_buffer.add(buffer, buffer_length);
			bool rslt_check = check(&read_buffer);
			if(rslt_check) {
				process(&read_buffer);
			}
		} else if(read_buffer.size() > 1024 * 1024) {
			read_buffer.clear();
			syslog(LOG_NOTICE, "IPFIX data exceeded the limit of 1MB. Check the IPFIX data sent.");
		}
	}
	delete this;
}

int cIPFixConnection::check(SimpleBuffer *data) {
	return(checkIPFixData(data, false));
}

int cIPFixConnection::process(SimpleBuffer *data) {
	if(data->size() < sizeof(sIPFixHeader)) {
		return(false);
	}
	unsigned offset = 0;
	unsigned counter = 0;
	do {
		sIPFixHeader *header = (sIPFixHeader*)(data->data() + offset);
		if(!checkIPFixVersion(ntohs(header->Version))) {
			++offset;
			continue;
		}
		u_int16_t length = ntohs(header->Length);
		if(length > data->size() - offset) {
			break;
		}
		if(length < sizeof(sIPFixHeader)) {
			offset += sizeof(sIPFixHeader);
			continue;
		}
		process_ipfix(header);
		offset += length;
		++counter;
	} while(offset < data->size() &&
		data->size() - offset > sizeof(sIPFixHeader));
	if(offset == data->size()) {
		data->clear();
	} else {
		data->removeDataFromLeft(offset);
	}
	return(counter);
}

void cIPFixConnection::process_ipfix(sIPFixHeader *header) {
	// cout << htons(header->SetID) << endl;
	if(opt_ipfix_counter_log) {
		 ipfix_counter.inc(socket->getIPL());
	}
	switch(htons(header->SetID)) {
	case _ipfix_HandShake:
		process_ipfix_HandShake(header);
		break;
	case _ipfix_SipIn:
		process_ipfix_SipIn(header);
		break;
	case _ipfix_SipOut:
		process_ipfix_SipOut(header);
		break;
	case _ipfix_SipInTCP:
		process_ipfix_SipInTcp(header);
		break;
	case _ipfix_SipOutTCP:
		process_ipfix_SipOutTcp(header);
		break;
	case _ipfix_QosStats:
		process_ipfix_QosStats(header);
		break;
	case _ipfix_UdpIn:
		process_ipfix_UdpIn(header);
		break;
	case _ipfix_UdpOut:
		process_ipfix_UdpOut(header);
		break;
	default:
		process_ipfix_other(header);
		break;
	}
}

void cIPFixConnection::process_ipfix_HandShake(sIPFixHeader *header) {
	// sIPFixHandShake *data = (sIPFixHandShake*)((u_char*)header + sizeof(sIPFixHeader));
	// cout << "Hostname: " << data->Hostname(header) << " |" << endl;
	header->SetID = ntohs(_ipfix_HandShake_Response);
	socket->write((u_char*)header, htons(header->Length));
}

void cIPFixConnection::process_ipfix_SipIn(sIPFixHeader *header) {
	if(header->DataLength() < sizeof(sIPFixSipIn)) return;
	sIPFixSipIn *data = (sIPFixSipIn*)((u_char*)header + sizeof(sIPFixHeader));
	string sip_data = data->SipMsg(header);
	process_packet(header, sip_data, false, data->GetTime(), data->GetSrc(), data->GetDst(), "SIP In (SetID 258)");
}

void cIPFixConnection::process_ipfix_SipOut(sIPFixHeader *header) {
	if(header->DataLength() < sizeof(sIPFixSipOut)) return;
	sIPFixSipOut *data = (sIPFixSipOut*)((u_char*)header + sizeof(sIPFixHeader));
	string sip_data = data->SipMsg(header);
	process_packet(header, sip_data, false, data->GetTime(), data->GetSrc(header), data->GetDst(header), "SIP Out (SetID 259)");
}

void cIPFixConnection::process_ipfix_SipInTcp(sIPFixHeader *header) {
	if(header->DataLength() < sizeof(sIPFixSipInTCP)) return;
	sIPFixSipInTCP *data = (sIPFixSipInTCP*)((u_char*)header + sizeof(sIPFixHeader));
	string sip_data = data->SipMsg(header);
	process_packet(header, sip_data, true, data->GetTime(), data->GetSrc(), data->GetDst(), "SIP In TCP (SetID 260)");
}

void cIPFixConnection::process_ipfix_SipOutTcp(sIPFixHeader *header) {
	if(header->DataLength() < sizeof(sIPFixSipOutTCP)) return;
	sIPFixSipOutTCP *data = (sIPFixSipOutTCP*)((u_char*)header + sizeof(sIPFixHeader));
	string sip_data = data->SipMsg(header);
	process_packet(header, sip_data, true, data->GetTime(), data->GetSrc(), data->GetDst(), "SIP Out TCP (SetID 261)");
}

void cIPFixConnection::process_ipfix_QosStats(sIPFixHeader *header) {
	if(header->DataLength() < sizeof(sIPFixQosStats)) return;
	sIPFixQosStats *data = (sIPFixQosStats*)((u_char*)header + sizeof(sIPFixHeader));
	sIPFixQosStatsExt qos_ext;
	qos_ext.load(data, header);
	int dlink = PcapDumper::get_global_pcap_dlink_en10();
	int pcap_handle_index = PcapDumper::get_global_handle_index_en10();
	ether_header header_eth;
	memset(&header_eth, 0, sizeof(header_eth));
	header_eth.ether_type = htons(ETHERTYPE_IP);
	pcap_pkthdr *udpHeader;
	u_char *udpPacket;
	vmIPport src;
	vmIPport dst;
	for(int i = 0; i < 2; i++) {
		string *callid = NULL;
		switch(i) {
		case 0:
			callid = &qos_ext.IncCallID;
			break;
		case 1:
			callid = &qos_ext.OutCallID;
			break;
		}
		if(!callid->empty()) {
			string json_data = "IPFIX_QOS:" + qos_ext.json(callid->c_str());
			createSimpleUdpDataPacket(sizeof(header_eth), &udpHeader,  &udpPacket,
						  (u_char*)&header_eth, (u_char*)json_data.c_str(), json_data.length(), 0,
						  src.ip, dst.ip, src.port, dst.port,
						  qos_ext.EndTimeSec, qos_ext.EndTimeMic);
			push_packet(src, dst,
				    udpHeader, udpPacket, json_data.length(), false,
				    dlink, pcap_handle_index);
		}
	}
	if(sverb.ipfix) {
		cout << "* IPFIX QoS Statistics (SetID 268) *" << endl;
		cout << "id/seq: " << ntohs(header->SetID) << " / " << ntohl(header->SeqNum) << endl;
		cout << "Begin time: " << qos_ext.BeginTimeSec << "." << qos_ext.BeginTimeMic << endl;
		cout << "End time: " << qos_ext.EndTimeSec << "." << qos_ext.EndTimeMic << endl;
		cout << "Caller Inc: " << ipv4_2_vmIP(*(u_int32_t*)qos_ext.CallerIncSrcIP, true).getString() << ":" << qos_ext.CallerIncSrcPort
		     << " -> " << ipv4_2_vmIP(*(u_int32_t*)qos_ext.CallerIncDstIP, true).getString() << ":" << qos_ext.CallerIncDstPort << endl;
		cout << "Callee Inc: " << ipv4_2_vmIP(*(u_int32_t*)qos_ext.CalleeIncSrcIP, true).getString() << ":" << qos_ext.CalleeIncSrcPort
		     << " -> " << ipv4_2_vmIP(*(u_int32_t*)qos_ext.CalleeIncDstIP, true).getString() << ":" << qos_ext.CalleeIncDstPort << endl;
		cout << "Caller Out: " << ipv4_2_vmIP(*(u_int32_t*)qos_ext.CallerOutSrcIP, true).getString() << ":" << qos_ext.CallerOutSrcPort
		     << " -> " << ipv4_2_vmIP(*(u_int32_t*)qos_ext.CallerOutDstIP, true).getString() << ":" << qos_ext.CallerOutDstPort << endl;
		cout << "Callee Out: " << ipv4_2_vmIP(*(u_int32_t*)qos_ext.CalleeOutSrcIP, true).getString() << ":" << qos_ext.CalleeOutSrcPort
		     << " -> " << ipv4_2_vmIP(*(u_int32_t*)qos_ext.CalleeOutDstIP, true).getString() << ":" << qos_ext.CalleeOutDstPort << endl;
		cout << "RTP Inc: packets=" << qos_ext.IncRtpPackets << " lost=" << qos_ext.IncRtpLostPackets 
		     << " jitter=" << qos_ext.IncRtpAvgJitter << endl;
		cout << "RTP Out: packets=" << qos_ext.OutRtpPackets << " lost=" << qos_ext.OutRtpLostPackets 
		     << " jitter=" << qos_ext.OutRtpAvgJitter << endl;
		cout << "MOS Inc=" << qos_ext.IncMos << " Out=" << qos_ext.OutMos << endl;
		cout << "R-val Inc=" << qos_ext.IncrVal << " Out=" << qos_ext.OutrVal << endl;
		cout << "Type: " << (int)qos_ext.Type << endl;
		if(!qos_ext.IncRealm.empty()) {
			cout << "IncRealm: " << qos_ext.IncRealm << endl;
		}
		if(!qos_ext.OutRealm.empty()) {
			cout << "OutRealm: " << qos_ext.OutRealm << endl;
		}
		if(!qos_ext.IncCallID.empty()) {
			cout << "IncCallID: " << qos_ext.IncCallID << endl;
		}
		if(!qos_ext.OutCallID.empty()) {
			cout << "OutCallID: " << qos_ext.OutCallID << endl;
		}
		hexdump((u_char*)header + sizeof(sIPFixHeader),
			ntohs(header->Length) - sizeof(sIPFixHeader));
		cout << endl;
	}
}

void cIPFixConnection::process_ipfix_UdpIn(sIPFixHeader *header) {
	if(header->DataLength() < sizeof(sIPFixUdpIn)) return;
	sIPFixUdpIn *data = (sIPFixUdpIn*)((u_char*)header + sizeof(sIPFixHeader));
	if(sverb.ipfix) {
		cout << "* IPFIX UDP In (SetID 266) *" << endl;
		cout << "id/seq: " << ntohs(header->SetID) << " / " << ntohl(header->SeqNum) << endl;
		cout << "time: " << data->GetTime().tv_sec << "." << setw(6) << data->GetTime().tv_usec << endl;
		cout << data->GetSrc(header).getString() << " -> " << data->GetDst(header).getString() << endl;
		u_int16_t _data_len;
		string _data_type;
		u_char *_data = data->GetData(header, &_data_len, &_data_type);
		if(_data && _data_len) {
			cout << "DATA " << _data_type << ":" << endl;
			hexdump(_data, _data_len);
		} else {
			hexdump((u_char*)header + sizeof(sIPFixHeader),
				ntohs(header->Length) - sizeof(sIPFixHeader));
		}
		cout << endl << endl;
	}
}

void cIPFixConnection::process_ipfix_UdpOut(sIPFixHeader *header) {
	if(header->DataLength() < sizeof(sIPFixUdpOut)) return;
	sIPFixUdpOut *data = (sIPFixUdpOut*)((u_char*)header + sizeof(sIPFixHeader));
	if(sverb.ipfix) {
		cout << "* IPFIX UDP Out (SetID 267) *" << endl;
		cout << "id/seq: " << ntohs(header->SetID) << " / " << ntohl(header->SeqNum) << endl;
		cout << "time: " << data->GetTime().tv_sec << "." << setw(6) << data->GetTime().tv_usec << endl;
		cout << "CallID: " << data->CallID(header) << endl;
		cout << data->GetSrc(header).getString() << " -> " << data->GetDst(header).getString() << endl;
		u_int16_t _data_len;
		string _data_type;
		u_char *_data = data->GetData(header, &_data_len, &_data_type);
		if(_data && _data_len) {
			cout << "DATA " << _data_type << ":" << endl;
			hexdump(_data, _data_len);
		} else {
			hexdump((u_char*)header + sizeof(sIPFixHeader),
				ntohs(header->Length) - sizeof(sIPFixHeader));
		}
		cout << endl << endl;
	}
}

void cIPFixConnection::process_ipfix_other(sIPFixHeader *header) {
	if(sverb.ipfix) {
		cout << "* IPFIX (Unknown SetID" << htons(header->SetID) << ") *" << endl;
		cout << "id/seq: " << ntohs(header->SetID) << " / " << ntohl(header->SeqNum) << endl;
		hexdump((u_char*)header + sizeof(sIPFixHeader),
			ntohs(header->Length) - sizeof(sIPFixHeader));
		cout << endl << endl;
	}
}

void cIPFixConnection::process_packet(sIPFixHeader *header, string &data, bool tcp, timeval time, vmIPport src, vmIPport dst, const char *type) {
	if(sverb.ipfix) {
		cout << "* IPFIX " << type << " *" << endl;
		cout << "id/seq: " << ntohs(header->SetID) << " / " << ntohl(header->SeqNum) << endl;
		cout << "time: " << time.tv_sec << "." << setw(6) << time.tv_usec << endl;
		cout << src.getString() << " -> " << dst.getString() << endl;
		cout << data;
		cout << endl << endl;
	}
	/*
	u_int64_t time_us = getTimeUS();
	time.tv_sec = time_us / 1000000ull;
	time.tv_usec = time_us % 1000000ull;
	*/
	//
	int dlink = PcapDumper::get_global_pcap_dlink_en10();
	int pcap_handle_index = PcapDumper::get_global_handle_index_en10();
	ether_header header_eth;
	memset(&header_eth, 0, sizeof(header_eth));
	header_eth.ether_type = htons(ETHERTYPE_IP);
	if(tcp) {
		pcap_pkthdr *tcpHeader;
		u_char *tcpPacket;
		createSimpleTcpDataPacket(sizeof(header_eth), &tcpHeader,  &tcpPacket,
					  (u_char*)&header_eth, (u_char*)data.c_str(), data.length(), 0,
					  src.ip, dst.ip, src.port, dst.port,
					  0, 0, 0,
					  time.tv_sec, time.tv_usec, dlink);
		push_packet(src, dst,
			    tcpHeader, tcpPacket, data.length(), true,
			    dlink, pcap_handle_index);
	} else {
		pcap_pkthdr *udpHeader;
		u_char *udpPacket;
		createSimpleUdpDataPacket(sizeof(header_eth), &udpHeader,  &udpPacket,
					  (u_char*)&header_eth, (u_char*)data.c_str(), data.length(), 0,
					  src.ip, dst.ip, src.port, dst.port,
					  time.tv_sec, time.tv_usec);
		push_packet(src, dst,
			    udpHeader, udpPacket, data.length(), false,
			    dlink, pcap_handle_index);
	}
}

void cIPFixConnection::push_packet(vmIPport src, vmIPport dst,
				   pcap_pkthdr *header, u_char *packet, unsigned data_len, bool tcp,
				   int dlink, int pcap_handle_index) {
	if(opt_t2_boost && opt_ipfix_via_pb) {
		block_store_lock();
		if(!block_store) {
			block_store = new FILE_LINE(0) pcap_block_store;
		}
		pcap_pkthdr_plus header_plus;
		header_plus.convertFromStdHeader(header);
		header_plus.header_ip_encaps_offset = 0xFFFF;
		header_plus.header_ip_offset = sizeof(ether_header);
		header_plus.dlink = dlink;
		header_plus.pid.clear();
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
				dataOffset, data_len,
				src.port, dst.port,
				pflags,
				&hp,
				pcap_handle_index);
		} else {
			preProcessPacket[PreProcessPacket::ppt_detach]->push_packet(
				#if USE_PACKET_NUMBER
				0, 
				#endif
				src.ip, src.port, dst.ip, dst.port,
				data_len, dataOffset,
				pcap_handle_index, header, packet, _t_packet_alloc_header_std, 
				pflags, (iphdr2*)(packet + sizeof(ether_header)), (iphdr2*)(packet + sizeof(ether_header)),
				NULL, 0, dlink, opt_id_sensor, vmIP(), pid,
				false);
		}
	}
}

void cIPFixConnection::evTimer(u_int32_t /*time_s*/, int /*typeTimer*/, void */*data*/) {
	block_store_lock();
	if(block_store && block_store->isFull_checkTimeout_ext(100)) {
		extern PcapQueue_readFromFifo *pcapQueueQ;
		pcapQueueQ->addBlockStoreToPcapStoreQueue_ext(block_store);
		block_store = NULL;
	}
	block_store_unlock();
}


string cIpFixCounter::get_ip_counter() {
	string rslt;
	lock();
	for(map<vmIP, u_int64_t>::iterator iter = ip_counter.begin(); iter != ip_counter.end(); iter++) {
		if(!rslt.empty()) {
			rslt += ";";
		}
		rslt += iter->first.getString() + ":" + intToString(iter->second);
	}
	unlock();
	return(rslt);
}

u_int64_t cIpFixCounter::get_sum_counter() {
	u_int64_t sum = 0;
	lock();
	for(map<vmIP, u_int64_t>::iterator iter = ip_counter.begin(); iter != ip_counter.end(); iter++) {
		sum += iter->second;
	}
	unlock();
	return(sum);
}


int checkIPFixData(SimpleBuffer *data, bool strict) {
	if(data->size() < sizeof(sIPFixHeader)) {
		return(false);
	}
	unsigned offset = 0;
	unsigned counter = 0;
	do {
		sIPFixHeader *header = (sIPFixHeader*)(data->data() + offset);
		if(!checkIPFixVersion(ntohs(header->Version))) {
			if(strict) {
				break;
			}
			++offset;
			continue;
		}
		u_int16_t length = ntohs(header->Length);
		if(length > data->size() - offset) {
			break;
		}
		if(length < sizeof(sIPFixHeader)) {
			if(strict) {
				break;
			}
			offset += sizeof(sIPFixHeader); 
			continue;
		}
		offset += length;
		++counter;
	} while(offset < data->size() &&
		data->size() - offset > sizeof(sIPFixHeader));
	return(strict ? offset == data->size() : counter > 0);
}

bool checkIPFixVersion(u_int16_t version) {
	extern vector<int> opt_ipfix_version;
	if(opt_ipfix_version.size()) {
		for(unsigned i = 0; i < opt_ipfix_version.size(); i++) {
			if(opt_ipfix_version[i] == version) {
				return(true);
			}
		}
	} else {
		return(version == IPFIX_VERSION_DEFAULT);
	}
	return(false);
}


void IPFix_client_emulation(const char *pcap, vmIP client_ip, vmIP server_ip, vmIP destination_ip, vmPort destination_port) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	if(!(handle = pcap_open_offline_zip(pcap, errbuf))) {
		fprintf(stderr, "Couldn't open pcap file '%s': %s\n", pcap, errbuf);
		return;
	}
	set_all_ports_for_tcp();
	int dlink = pcap_datalink(handle);
	pcap_pkthdr *pcap_next_ex_header;
	const u_char *pcap_next_ex_packet;
	sHeaderPacket *header_packet = NULL;
	pcapProcessData ppd;
	int res;
	cSocket socket("IPFix_client_emulation");
	socket.setHostPort(destination_ip.getString(), destination_port);
	if(!socket.connect()) {
		return;
	} else {
		cout << "ok connect" << endl;
	}
	while((res = pcap_next_ex(handle, &pcap_next_ex_header, &pcap_next_ex_packet)) > 0) {
		if(header_packet && header_packet->packet_alloc_size != 0xFFFF) {
			DESTROY_HP(&header_packet);
		}
		if(header_packet) {
			header_packet->clearPcapProcessData();
		} else {
			header_packet = CREATE_HP(0xFFFF);
		}
		memcpy_heapsafe(HPH(header_packet), header_packet,
				pcap_next_ex_header, NULL,
				sizeof(pcap_pkthdr));
		memcpy_heapsafe(HPP(header_packet), header_packet,
				pcap_next_ex_packet, NULL,
				pcap_next_ex_header->caplen);
		ppd.header_udp = NULL;
		ppd.header_tcp = NULL;
		ppd.datalen = 0;
		if(!pcapProcess(&header_packet, -1,
				NULL, 0,
				ppf_all,
				&ppd, dlink, NULL, NULL)) {
			continue;
		}
		u_int32_t caplen = HPH(header_packet)->caplen;
		u_char *packet = HPP(header_packet);
		if(ppd.header_ip) {
			if(ppd.header_ip->get_protocol() == IPPROTO_UDP) {
				ppd.header_udp = (udphdr2*)((char*)ppd.header_ip + ppd.header_ip->get_hdr_size());
				ppd.datalen = get_udp_data_len(ppd.header_ip, ppd.header_udp, &ppd.data, packet, caplen);
			} else if(ppd.header_ip->get_protocol() == IPPROTO_TCP) {
				ppd.header_tcp = (tcphdr2*) ((char*) ppd.header_ip + ppd.header_ip->get_hdr_size());
				ppd.datalen = get_tcp_data_len(ppd.header_ip, ppd.header_tcp, &ppd.data, packet, caplen);
			}
			if(ppd.datalen) {
				if(ppd.header_ip->get_saddr() == client_ip && ppd.header_ip->get_daddr() == server_ip) {
					cout << " -> " << flush;
					if(socket.write((u_char*)ppd.data, ppd.datalen)) {
						cout << "ok write" << endl;
					}
				} else if(ppd.header_ip->get_saddr() == server_ip && ppd.header_ip->get_daddr() == client_ip) {
					cout << " <- " << flush;
					SimpleBuffer read_buffer;
					do {
						u_char buffer[10000];
						size_t read_length = sizeof(buffer);
						if(socket.read(buffer, &read_length)) {
							read_buffer.add(buffer, read_length);
						}
						if(checkIPFixData(&read_buffer, true)) {
							cout << "ok read" << endl;
							break;
						}
					} while(!socket.isError());
				} else {
					cout << "unknown ip: " << ppd.header_ip->get_saddr().getString() << " -> " <<ppd.header_ip->get_daddr().getString() << endl;
				}
			}
		}
	}
	if(header_packet) {
		DESTROY_HP(&header_packet);
	}
	pcap_close(handle);
}


static cIPFixServer *IPFixServer;

void IPFixServerStart(const char *host, int port) {
	if(IPFixServer) {
		delete IPFixServer;
	}
	IPFixServer =  new FILE_LINE(0) cIPFixServer;
	IPFixServer->setStartVerbString("START IPFIX LISTEN");
	IPFixServer->listen_start("ipfix_server", host, port);
}

void IPFixServerStop() {
	if(IPFixServer) {
		delete IPFixServer;
		IPFixServer = NULL;
	}
}
