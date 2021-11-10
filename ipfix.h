#ifndef IPFIX_H
#define IPFIX_H

#include <string>

#include "ip.h"

#include "cloud_router/cloud_router_base.h"


using namespace std;


enum eIPFixIDtype {
	_ipfix_HandShake = 256,
	_ipfix_HandShake_Response = 257,
	_ipfix_SipIn = 258,
	_ipfix_SipOut = 259,
	_ipfix_SipInTCP = 260,
	_ipfix_SipOutTCP = 261
};

struct sIPFixHeader {
	u_int16_t Version;		// r.uint16,
	u_int16_t Length;		// r.uint16,
	u_int32_t ExportTime;		// r.uint32,
	u_int32_t SeqNum;		// r.uint32,
	u_int32_t ObservationID;	// r.uint32,
	u_int16_t SetID;		// r.uint16,
	u_int16_t SetLen;		// r.uint16,
} __attribute__((packed));

struct sIPFixHandShake {
	u_int16_t MaVer;		// r.uint16,
	u_int16_t MiVer;		// r.uint16,
	u_int16_t CFlags1;		// r.uint16,
	u_int16_t CFlags2;		// r.uint16,
	u_int16_t SFlags;		// r.uint16,
	u_int16_t Timeout;		// r.uint16,
	u_int32_t SystemID;		// r.uint32,
	u_int16_t Product;		// r.uint16,
	u_int8_t Major;			// r.uint8,
	u_int8_t Minor;			// r.uint8,
	u_int8_t Revision;		// r.uint8,
	u_int8_t HostnameLen;		// r.uint8,
	char _Hostname;			// new r.String('HostnameLen', 'utf8')
	string Hostname() {
		return(string(&_Hostname, HostnameLen));
	}
} __attribute__((packed));

struct sIPFixSipOut_next {
	u_int8_t CallIDEnd;		// r.uint8,
	u_int16_t IPlen;		// r.uint16,
	u_int8_t VLan;			// r.uint8,
	u_int8_t Tos;			// r.uint8,
	u_int16_t Tlen;			// r.uint16,
	u_int16_t TID;			// r.uint16,
	u_int16_t TFlags;		// r.uint16,
	u_int8_t TTL;			// r.uint8,
	u_int8_t TProto;		// r.uint8,
	u_int16_t TPos;			// r.uint16,
	u_int8_t SrcIP[4];		// new r.Array(r.uint8, 4),
	u_int8_t DstIP[4];		// new r.Array(r.uint8, 4),
	u_int16_t DstPort;		// r.uint16,
	u_int16_t SrcPort;		// r.uint16,
	u_int16_t UDPLen;		// r.uint16,
	u_int16_t SipMsgLen;		// r.uint16,
	char _SipMsg;			// new r.String('SipMsgLen', 'utf8')
} __attribute__((packed));

struct sIPFixSipOut {
	u_int32_t TimeSec;		// r.uint32,
	u_int32_t TimeMic;		// r.uint32,
	u_int8_t IntSlot;		// r.uint8,
	u_int8_t IntPort;		// r.uint8,
	u_int16_t IntVlan;		// r.uint16,
	u_int8_t CallIDLen;		// r.uint8,
	char _CallID;			// new r.String('CallIDLen', 'utf8'),
	string CallID() {
		return(string(&_CallID, CallIDLen));
	}
	string SipMsg(sIPFixHeader *header) {
		sIPFixSipOut_next *data_next = next();
		return(string(&data_next->_SipMsg, 
			      min((int)htons(data_next->SipMsgLen),
				  (int)(htons(header->Length) - sizeof(sIPFixHeader) - (sizeof(sIPFixSipOut) - sizeof(char)) - (sizeof(sIPFixSipOut_next) - sizeof(char)) - CallIDLen))));
	}
	timeval GetTime() {
		timeval rslt;
		rslt.tv_sec = ntohl(TimeSec);
		rslt.tv_usec = ntohl(TimeMic);
		return(rslt);
	}
	vmIPport GetSrc() {
		vmIPport rslt;
		sIPFixSipOut_next *data_next = next();
		rslt.ip.setIPv4(*(u_int32_t*)&data_next->SrcIP, true);
		rslt.port.setPort(data_next->SrcPort, true);
		return(rslt);
	}
	vmIPport GetDst() {
		vmIPport rslt;
		sIPFixSipOut_next *data_next = next();
		rslt.ip.setIPv4(*(u_int32_t*)&data_next->DstIP, true);
		rslt.port.setPort(data_next->DstPort, true);
		return(rslt);
	}
	sIPFixSipOut_next *next() {
		return((sIPFixSipOut_next*)((u_char*)this + sizeof(*this) - sizeof(_CallID) + CallIDLen));
	}
} __attribute__((packed));

struct sIPFixSipIn {
	u_int32_t TimeSec;		// r.uint32,
	u_int32_t TimeMic;		// r.uint32,
	u_int8_t IntSlot;		// r.uint8,
	u_int8_t IntPort;		// r.uint8,
	u_int16_t IntVlan;		// r.uint16,
	u_int8_t CallIDEnd;		// r.uint8,
	u_int16_t IPlen;		// r.uint16,
	u_int8_t VLan;			// r.uint8,
	u_int8_t Tos;			// r.uint8,
	u_int16_t Tlen;			// r.uint16,
	u_int16_t TID;			// r.uint16,
	u_int16_t TFlags;		// r.uint16,
	u_int8_t TTL;			// r.uint8,
	u_int8_t TProto;		// r.uint8,
	u_int16_t TPos;			// r.uint16,
	u_int8_t SrcIP[4];		// new r.Array(r.uint8, 4),
	u_int8_t DstIP[4];		// new // r.Array(r.uint8, 4),
	u_int16_t DstPort;		// r.uint16,
	u_int16_t SrcPort;		// r.uint16,
	u_int16_t UDPLen;		// r.uint16,
	u_int16_t SipMsgLen;		// r.uint16,
	char _SipMsg;			// new r.String('SipMsgLen', 'utf8')
	string SipMsg(sIPFixHeader *header) {
		return(string(&_SipMsg, 
			      min((int)htons(SipMsgLen), 
				  (int)(htons(header->Length) - sizeof(sIPFixHeader) - (sizeof(sIPFixSipIn) - sizeof(char))))));
	}
	timeval GetTime() {
		timeval rslt;
		rslt.tv_sec = ntohl(TimeSec);
		rslt.tv_usec = ntohl(TimeMic);
		return(rslt);
	}
	vmIPport GetSrc() {
		vmIPport rslt;
		rslt.ip.setIPv4(*(u_int32_t*)&SrcIP, true);
		rslt.port.setPort(SrcPort, true);
		return(rslt);
	}
	vmIPport GetDst() {
		vmIPport rslt;
		rslt.ip.setIPv4(*(u_int32_t*)&DstIP, true);
		rslt.port.setPort(DstPort, true);
		return(rslt);
	}
} __attribute__((packed));

struct sIPFixSipOutTCP_next {
	u_int8_t CallIDEnd;		// r.uint8,
	u_int16_t SipMsgLen;		// r.uint16,
	char _SipMsg;			// new r.String('SipMsgLen', 'utf8')
} __attribute__((packed));
 
struct sIPFixSipOutTCP {
	u_int32_t TimeSec;		// r.uint32,
	u_int32_t TimeMic;		// r.uint32,
	u_int8_t IntSlot;		// r.uint8,
	u_int8_t IntPort;		// r.uint8,
	u_int16_t IntVlan;		// r.uint16,
	u_int8_t DstIP[4];		// new r.Array(r.uint8, 4),
	u_int8_t SrcIP[4];		// new r.Array(r.uint8, 4),
	u_int16_t DstPort;		// r.uint16,
	u_int16_t SrcPort;		// r.uint16,
	u_int32_t Context;		// r.uint32,
	u_int8_t CallIDLen;		// r.uint8,
	char _CallID;			// new r.String('CallIDLen', 'utf8'),
	string CallID() {
		return(string(&_CallID, CallIDLen));
	}
	string SipMsg(sIPFixHeader *header) {
		sIPFixSipOutTCP_next *data_next = next();
		return(string(&data_next->_SipMsg, 
			      min((int)htons(data_next->SipMsgLen),
				  (int)(htons(header->Length) - sizeof(sIPFixHeader) - (sizeof(sIPFixSipOutTCP) - sizeof(char)) - (sizeof(sIPFixSipOutTCP_next) - sizeof(char)) - CallIDLen))));
	}
	timeval GetTime() {
		timeval rslt;
		rslt.tv_sec = ntohl(TimeSec);
		rslt.tv_usec = ntohl(TimeMic);
		return(rslt);
	}
	vmIPport GetSrc() {
		vmIPport rslt;
		rslt.ip.setIPv4(*(u_int32_t*)&SrcIP, true);
		rslt.port.setPort(SrcPort, true);
		return(rslt);
	}
	vmIPport GetDst() {
		vmIPport rslt;
		rslt.ip.setIPv4(*(u_int32_t*)&DstIP, true);
		rslt.port.setPort(DstPort, true);
		return(rslt);
	}
	sIPFixSipOutTCP_next *next() {
		return((sIPFixSipOutTCP_next*)((u_char*)this + sizeof(*this) - sizeof(_CallID) + CallIDLen));
	}
} __attribute__((packed));

struct sIPFixSipInTCP {
	u_int32_t TimeSec;		// r.uint32,
	u_int32_t TimeMic;		// r.uint32,
	u_int8_t IntSlot;		// r.uint8,
	u_int8_t IntPort;		// r.uint8,
	u_int16_t IntVlan;		// r.uint16,
	u_int8_t DstIP[4];		// new r.Array(r.uint8, 4),
	u_int8_t SrcIP[4];		// new r.Array(r.uint8, 4),
	u_int16_t DstPort;		// r.uint16,
	u_int16_t SrcPort;		// r.uint16,
	u_int32_t Context;		// r.uint32,
	u_int8_t CallIDEnd;		// r.uint8,
	u_int16_t SipMsgLen;		// r.uint16,
	char _SipMsg;			// new r.String('SipMsgLen', 'utf8')
	string SipMsg(sIPFixHeader *header) {
		return(string(&_SipMsg, 
			      min((int)htons(SipMsgLen), 
				  (int)(htons(header->Length) - sizeof(sIPFixHeader) - (sizeof(sIPFixSipInTCP) - sizeof(char))))));
	}
	timeval GetTime() {
		timeval rslt;
		rslt.tv_sec = ntohl(TimeSec);
		rslt.tv_usec = ntohl(TimeMic);
		return(rslt);
	}
	vmIPport GetSrc() {
		vmIPport rslt;
		rslt.ip.setIPv4(*(u_int32_t*)&SrcIP, true);
		rslt.port.setPort(SrcPort, true);
		return(rslt);
	}
	vmIPport GetDst() {
		vmIPport rslt;
		rslt.ip.setIPv4(*(u_int32_t*)&DstIP, true);
		rslt.port.setPort(DstPort, true);
		return(rslt);
	}
} __attribute__((packed));


class cIPFixServer : public cServer {
public:
	cIPFixServer();
	~cIPFixServer();
	virtual void createConnection(cSocket *socket);
};

class cIPFixConnection : public cServerConnection {
public:
	cIPFixConnection(cSocket *socket);
	~cIPFixConnection();
	virtual void connection_process();
private:
	bool read(SimpleBuffer *out_buffer, int timeout_ms = 5000);
	int check(SimpleBuffer *data, bool strict = true);
	int process(SimpleBuffer *data);
	void process_ipfix(sIPFixHeader *header);
	void process_ipfix_HandShake(sIPFixHeader *header);
	void process_ipfix_SipIn(sIPFixHeader *header);
	void process_ipfix_SipOut(sIPFixHeader *header);
	void process_ipfix_SipInTcp(sIPFixHeader *header);
	void process_ipfix_SipOutTcp(sIPFixHeader *header);
	void push_packet(sIPFixHeader *header, string &data, bool tcp, timeval time, vmIPport src, vmIPport dst);
};


int checkIPFixData(SimpleBuffer *data, bool strict = true);
void IPFix_client_emulation(const char *pcap, vmIP client_ip, vmIP server_ip, vmIP destination_ip, vmPort destination_port);
void IPFixServerStart(const char *host, int port);
void IPFixServerStop();


#endif //IPFIX_H
