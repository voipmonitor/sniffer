#ifndef IPFIX_H
#define IPFIX_H

#include <string>

#include "ip.h"

#include "cloud_router/cloud_router_base.h"

#include "tools.h"


using namespace std;


enum eIPFixIDtype {
	_ipfix_HandShake = 256,
	_ipfix_HandShake_Response = 257,
	_ipfix_SipIn = 258,
	_ipfix_SipOut = 259,
	_ipfix_SipInTCP = 260,
	_ipfix_SipOutTCP = 261,
	_ipfix_UdpIn = 266,
	_ipfix_UdpOut = 267,
	_ipfix_QosStats = 268
};

struct sIPFixHeader {
	u_int16_t Version;		// r.uint16,
	u_int16_t Length;		// r.uint16,
	u_int32_t ExportTime;		// r.uint32,
	u_int32_t SeqNum;		// r.uint32,
	u_int32_t ObservationID;	// r.uint32,
	u_int16_t SetID;		// r.uint16,
	u_int16_t SetLen;		// r.uint16,
	u_int16_t DataLength() {
		return(ntohs(Length) > sizeof(*this) ? ntohs(Length) - sizeof(*this) : 0);
	}
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
	string Hostname(sIPFixHeader *header) {
		unsigned base_size = sizeof(sIPFixHandShake) - sizeof(char);
		return(string(&_Hostname, 
			      min((unsigned)HostnameLen,
			          header->DataLength() > base_size ? header->DataLength() - base_size : 0)));
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
	string CallID(sIPFixHeader *header) {
		unsigned base_size = sizeof(sIPFixSipOut) - sizeof(char);
		return(string(&_CallID, 
			      min((unsigned)CallIDLen,
			          header->DataLength() > base_size ? header->DataLength() - base_size : 0)));
	}
	string SipMsg(sIPFixHeader *header) {
		string rslt;
		sIPFixSipOut_next *data_next = next(header);
		if(data_next) {
			u_int16_t data_next_length = next_length(header);
			unsigned base_size = sizeof(sIPFixSipOut_next) - sizeof(char);
			if(data_next_length > base_size) {
				return(string(&data_next->_SipMsg, 
					      min((unsigned)htons(data_next->SipMsgLen),
						  (unsigned)(data_next_length - base_size))));
			}
		}
		return(rslt);
	}
	timeval GetTime() {
		timeval rslt;
		rslt.tv_sec = ntohl(TimeSec);
		rslt.tv_usec = ntohl(TimeMic);
		return(rslt);
	}
	vmIPport GetSrc(sIPFixHeader *header) {
		vmIPport rslt;
		sIPFixSipOut_next *data_next = next(header);
		if(data_next) {
			rslt.ip.setIPv4(*(u_int32_t*)&data_next->SrcIP, true);
			rslt.port.setPort(data_next->SrcPort, true);
		}
		return(rslt);
	}
	vmIPport GetDst(sIPFixHeader *header) {
		vmIPport rslt;
		sIPFixSipOut_next *data_next = next(header);
		if(data_next) {
			rslt.ip.setIPv4(*(u_int32_t*)&data_next->DstIP, true);
			rslt.port.setPort(data_next->DstPort, true);
		}
		return(rslt);
	}
	sIPFixSipOut_next *next(sIPFixHeader *header) {
		unsigned base_size = sizeof(*this) - sizeof(_CallID);
		unsigned actual_callid_len = min((unsigned)CallIDLen,
		                                  header->DataLength() > base_size ? header->DataLength() - base_size : 0);
		unsigned fixLength = base_size + actual_callid_len;
		if(header->DataLength() >= fixLength + sizeof(sIPFixSipOut_next)) {
			return((sIPFixSipOut_next*)((u_char*)this + fixLength));
		} else {
			return(NULL);
		}
	}
	u_int16_t next_length(sIPFixHeader *header) {
		unsigned base_size = sizeof(*this) - sizeof(_CallID);
		unsigned actual_callid_len = min((unsigned)CallIDLen,
		                                  header->DataLength() > base_size ? header->DataLength() - base_size : 0);
		unsigned fixLength = base_size + actual_callid_len;
		if(header->DataLength() >= fixLength + sizeof(sIPFixSipOut_next)) {
			return(header->DataLength() - fixLength);
		} else {
			return(0);
		}
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
		unsigned base_size = sizeof(sIPFixSipIn) - sizeof(char);
		return(string(&_SipMsg, 
			      min((unsigned)htons(SipMsgLen), 
				  header->DataLength() > base_size ? header->DataLength() - base_size : 0)));
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
	string CallID(sIPFixHeader *header) {
		unsigned base_size = sizeof(sIPFixSipOutTCP) - sizeof(char);
		return(string(&_CallID, 
			      min((unsigned)CallIDLen,
			          header->DataLength() > base_size ? header->DataLength() - base_size : 0)));
	}
	string SipMsg(sIPFixHeader *header) {
		string rslt;
		sIPFixSipOutTCP_next *data_next = next(header);
		if(data_next) {
			u_int16_t data_next_length = next_length(header);
			unsigned base_size = sizeof(sIPFixSipOutTCP_next) - sizeof(char);
			if(data_next_length > base_size) {
				return(string(&data_next->_SipMsg, 
					      min((unsigned)htons(data_next->SipMsgLen),
						  (unsigned)(data_next_length - base_size))));
			}
		}
		return(rslt);
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
	sIPFixSipOutTCP_next *next(sIPFixHeader *header) {
		unsigned base_size = sizeof(*this) - sizeof(_CallID);
		unsigned actual_callid_len = min((unsigned)CallIDLen,
		                                  header->DataLength() > base_size ? header->DataLength() - base_size : 0);
		unsigned fixLength = base_size + actual_callid_len;
		if(header->DataLength() >= fixLength + sizeof(sIPFixSipOutTCP_next)) {
			return((sIPFixSipOutTCP_next*)((u_char*)this + fixLength));
		} else {
			return(NULL);
		}
	}
	u_int16_t next_length(sIPFixHeader *header) {
		unsigned base_size = sizeof(*this) - sizeof(_CallID);
		unsigned actual_callid_len = min((unsigned)CallIDLen,
		                                  header->DataLength() > base_size ? header->DataLength() - base_size : 0);
		unsigned fixLength = base_size + actual_callid_len;
		if(header->DataLength() >= fixLength + sizeof(sIPFixSipOutTCP_next)) {
			return(header->DataLength() - fixLength);
		} else {
			return(0);
		}
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
		unsigned base_size = sizeof(sIPFixSipInTCP) - sizeof(char);
		return(string(&_SipMsg, 
			      min((unsigned)htons(SipMsgLen), 
				  header->DataLength() > base_size ? header->DataLength() - base_size : 0)));
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

struct sIPFixUdpIn {
	u_int32_t TimeSec;		// r.uint32,
	u_int32_t TimeMic;		// r.uint32,
	u_int8_t IntSlot;		// r.uint8,
	u_int8_t IntPort;		// r.uint8,
	u_int16_t IntVlan;		// r.uint16,
	u_int8_t Separator;		// r.uint8, // 0xff separator
	u_int16_t IPlen;		// r.uint16, // Length of IP packet
	char _IPpacket;			// Raw IP packet
	timeval GetTime() {
		timeval rslt;
		rslt.tv_sec = ntohl(TimeSec);
		rslt.tv_usec = ntohl(TimeMic);
		return(rslt);
	}
	vmIPport GetSrc(sIPFixHeader *header) {
		vmIPport rslt;
		u_int16_t ip_len = get_ip_len(header);
		if(ip_len >= sizeof(iphdr2)) {
			iphdr2 *header_ip = (iphdr2*)&_IPpacket;
			rslt.ip = header_ip->get_saddr();
			u_int8_t ip_protocol = header_ip->get_protocol();
			if(ip_protocol == IPPROTO_UDP) {
				if(ip_len >= sizeof(iphdr2) + sizeof(udphdr2)) {
					udphdr2 *header_udp = (udphdr2*)((char*)&_IPpacket + sizeof(iphdr2));
					rslt.port = header_udp->get_source();
				}
			} else if(ip_protocol == IPPROTO_TCP) {
				if(ip_len >= sizeof(iphdr2) + sizeof(tcphdr2)) {
					tcphdr2 *header_tcp = (tcphdr2*)((char*)&_IPpacket + sizeof(iphdr2));
					rslt.port = header_tcp->get_source();
				}
			}
		}
		return(rslt);
	}
	vmIPport GetDst(sIPFixHeader *header) {
		vmIPport rslt;
		u_int16_t ip_len = get_ip_len(header);
		if(ip_len >= sizeof(iphdr2)) {
			iphdr2 *header_ip = (iphdr2*)&_IPpacket;
			rslt.ip = header_ip->get_daddr();
			u_int8_t ip_protocol = header_ip->get_protocol();
			if(ip_protocol == IPPROTO_UDP) {
				if(ip_len >= sizeof(iphdr2) + sizeof(udphdr2)) {
					udphdr2 *header_udp = (udphdr2*)((char*)&_IPpacket + sizeof(iphdr2));
					rslt.port = header_udp->get_dest();
				}
			} else if(ip_protocol == IPPROTO_TCP) {
				if(ip_len >= sizeof(iphdr2) + sizeof(tcphdr2)) {
					tcphdr2 *header_tcp = (tcphdr2*)((char*)&_IPpacket + sizeof(iphdr2));
					rslt.port = header_tcp->get_dest();
				}
			}
		}
		return(rslt);
	}
	u_char *GetData(sIPFixHeader *header, u_int16_t *data_len, string *data_type) {
		*data_len = 0;
		u_int16_t ip_len = get_ip_len(header);
		if(ip_len >= sizeof(iphdr2)) {
			iphdr2 *header_ip = (iphdr2*)&_IPpacket;
			u_int8_t ip_protocol = header_ip->get_protocol();
			if(ip_protocol == IPPROTO_UDP) {
				if(ip_len >= sizeof(iphdr2) + sizeof(udphdr2)) {
					udphdr2 *header_udp = (udphdr2*)((char*)&_IPpacket + sizeof(iphdr2));
					*data_len = ip_len - sizeof(iphdr2) - sizeof(udphdr2);
					*data_type = "UDP";
					return((u_char*)header_udp + sizeof(udphdr2));
				}
			} else if(ip_protocol == IPPROTO_TCP) {
				if(ip_len >= sizeof(iphdr2) + sizeof(tcphdr2)) {
					tcphdr2 *header_tcp = (tcphdr2*)((char*)&_IPpacket + sizeof(iphdr2));
					unsigned tcp_header_len = header_tcp->doff * 4;
					if(tcp_header_len >= sizeof(tcphdr2) && ip_len >= sizeof(iphdr2) + tcp_header_len) {
						*data_len = ip_len - sizeof(iphdr2) - tcp_header_len;
						*data_type = "TCP";
						return((u_char*)header_tcp + tcp_header_len);
					}
				}
			}
		}
		return(NULL);
	}
	u_int16_t get_ip_len(sIPFixHeader *header) {
		unsigned offset = offsetof(sIPFixUdpIn, _IPpacket);
		return(min((unsigned)ntohs(IPlen), 
			   header->DataLength() > offset ?
			   header->DataLength() - offset : 0));
	}
} __attribute__((packed));

struct sIPFixUdpOut_next {
	u_int8_t CallIDEnd;		// r.uint8, // 0xff separator after CallID
	u_int16_t IPlen;		// r.uint16, // Length of IP packet
	char _IPpacket;			// Raw IP packet
} __attribute__((packed));

struct sIPFixUdpOut {
	u_int32_t TimeSec;		// r.uint32,
	u_int32_t TimeMic;		// r.uint32,
	u_int8_t IntSlot;		// r.uint8,
	u_int8_t IntPort;		// r.uint8,
	u_int16_t IntVlan;		// r.uint16,
	u_int8_t CallIDLen;		// r.uint8,
	char _CallID;			// new r.String('CallIDLen', 'utf8'),
	string CallID(sIPFixHeader *header) {
		unsigned base_size = sizeof(sIPFixUdpOut) - sizeof(char);
		return(string(&_CallID, 
			      min((unsigned)CallIDLen,
			          header->DataLength() > base_size ?
			          header->DataLength() - base_size : 0)));
	}
	timeval GetTime() {
		timeval rslt;
		rslt.tv_sec = ntohl(TimeSec);
		rslt.tv_usec = ntohl(TimeMic);
		return(rslt);
	}
	vmIPport GetSrc(sIPFixHeader *header) {
		vmIPport rslt;
		sIPFixUdpOut_next *data_next = next(header);
		if(data_next) {
			u_int16_t ip_len = get_ip_len(header);
			if(ip_len >= sizeof(iphdr2)) {
				iphdr2 *header_ip = (iphdr2*)&data_next->_IPpacket;
				rslt.ip = header_ip->get_saddr();
				u_int8_t ip_protocol = header_ip->get_protocol();
				if(ip_protocol == IPPROTO_UDP) {
					if(ip_len >= sizeof(iphdr2) + sizeof(udphdr2)) {
						udphdr2 *header_udp = (udphdr2*)((char*)&data_next->_IPpacket + sizeof(iphdr2));
						rslt.port = header_udp->get_source();
					}
				} else if(ip_protocol == IPPROTO_TCP) {
					if(ip_len >= sizeof(iphdr2) + sizeof(tcphdr2)) {
						tcphdr2 *header_tcp = (tcphdr2*)((char*)&data_next->_IPpacket + sizeof(iphdr2));
						rslt.port = header_tcp->get_source();
					}
				}
			}
		}
		return(rslt);
	}
	vmIPport GetDst(sIPFixHeader *header) {
		vmIPport rslt;
		sIPFixUdpOut_next *data_next = next(header);
		if(data_next) {
			u_int16_t ip_len = get_ip_len(header);
			if(ip_len >= sizeof(iphdr2)) {
				iphdr2 *header_ip = (iphdr2*)&data_next->_IPpacket;
				rslt.ip = header_ip->get_daddr();
				u_int8_t ip_protocol = header_ip->get_protocol();
				if(ip_protocol == IPPROTO_UDP) {
					if(ip_len >= sizeof(iphdr2) + sizeof(udphdr2)) {
						udphdr2 *header_udp = (udphdr2*)((char*)&data_next->_IPpacket + sizeof(iphdr2));
						rslt.port = header_udp->get_dest();
					}
				} else if(ip_protocol == IPPROTO_TCP) {
					if(ip_len >= sizeof(iphdr2) + sizeof(tcphdr2)) {
						tcphdr2 *header_tcp = (tcphdr2*)((char*)&data_next->_IPpacket + sizeof(iphdr2));
						rslt.port = header_tcp->get_dest();
					}
				}
			}
		}
		return(rslt);
	}
	u_char *GetData(sIPFixHeader *header, u_int16_t *data_len, string *data_type) {
		*data_len = 0;
		sIPFixUdpOut_next *data_next = next(header);
		if(data_next) {
			u_int16_t ip_len = get_ip_len(header);
			if(ip_len >= sizeof(iphdr2)) {
				iphdr2 *header_ip = (iphdr2*)&data_next->_IPpacket;
				u_int8_t ip_protocol = header_ip->get_protocol();
				if(ip_protocol == IPPROTO_UDP) {
					if(ip_len >= sizeof(iphdr2) + sizeof(udphdr2)) {
						udphdr2 *header_udp = (udphdr2*)((char*)&data_next->_IPpacket + sizeof(iphdr2));
						*data_len = ip_len - sizeof(iphdr2) - sizeof(udphdr2);
						*data_type = "UDP";
						return((u_char*)header_udp + sizeof(udphdr2));
					}
				} else if(ip_protocol == IPPROTO_TCP) {
					if(ip_len >= sizeof(iphdr2) + sizeof(tcphdr2)) {
						tcphdr2 *header_tcp = (tcphdr2*)((char*)&data_next->_IPpacket + sizeof(iphdr2));
						unsigned tcp_header_len = header_tcp->doff * 4;
						if(tcp_header_len >= sizeof(tcphdr2) && ip_len >= sizeof(iphdr2) + tcp_header_len) {
							*data_len = ip_len - sizeof(iphdr2) - tcp_header_len;
							*data_type = "TCP";
							return((u_char*)header_tcp + tcp_header_len);
						}
					}
				}
			}
		}
		return(NULL);
	}
	sIPFixUdpOut_next *next(sIPFixHeader *header) {
		unsigned base_size = sizeof(*this) - sizeof(_CallID);
		unsigned actual_callid_len = min((unsigned)CallIDLen,
		                                  header->DataLength() > base_size ?
		                                  header->DataLength() - base_size : 0);
		unsigned fixLength = base_size + actual_callid_len;
		if(header->DataLength() >= fixLength + sizeof(sIPFixUdpOut_next)) {
			return((sIPFixUdpOut_next*)((u_char*)this + fixLength));
		} else {
			return(NULL);
		}
	}
	u_int16_t next_length(sIPFixHeader *header) {
		unsigned base_size = sizeof(*this) - sizeof(_CallID);
		unsigned actual_callid_len = min((unsigned)CallIDLen,
		                                  header->DataLength() > base_size ?
		                                  header->DataLength() - base_size : 0);
		unsigned fixLength = base_size + actual_callid_len;
		if(header->DataLength() >= fixLength + sizeof(sIPFixUdpOut_next)) {
			return(header->DataLength() - fixLength);
		} else {
			return(0);
		}
	}
	u_int16_t get_ip_len(sIPFixHeader *header) {
		sIPFixUdpOut_next *data_next = next(header);
		if(data_next) {
			unsigned next_len = next_length(header);
			unsigned offset = offsetof(sIPFixUdpOut_next, _IPpacket);
			return(min((unsigned)ntohs(data_next->IPlen),
				   next_len > offset ? next_len - offset : 0));
		}
		return(0);
	}
} __attribute__((packed));

struct sIPFixQosStreamStat {
	// RTP Incoming statistics
	u_int32_t RtpBytes;
	u_int32_t RtpPackets;
	u_int32_t RtpLostPackets;
	u_int32_t RtpAvgJitter;
	u_int32_t RtpMaxJitter;
	// RTCP Incoming statistics
	u_int32_t RtcpBytes;
	u_int32_t RtcpPackets;
	u_int32_t RtcpLostPackets;
	u_int32_t RtcpAvgJitter;
	u_int32_t RtcpMaxJitter;
	u_int32_t RtcpAvgLat;
	u_int32_t RtcpMaxLat;
	// Incoming quality metrics
	u_int32_t rVal;
	u_int32_t Mos;
	//
	vmIP SrcIP;
	vmIP DstIP;
	vmPort SrcPort;
	vmPort DstPort;
	//
	u_int8_t CodecType;
	u_int64_t BeginTimeUS;
	u_int64_t EndTimeUS;
	// Direction: true = caller->callee, false = callee->caller
	bool iscaller;
};

struct sIPFixQosStats {
	// RTP Incoming statistics
	u_int32_t IncRtpBytes;		// Total bytes
	u_int32_t IncRtpPackets;	// Total packets
	u_int32_t IncRtpLostPackets;	// Lost packets
	u_int32_t IncRtpAvgJitter;	// Average jitter
	u_int32_t IncRtpMaxJitter;	// Maximum jitter
	// RTCP Incoming statistics
	u_int32_t IncRtcpBytes;
	u_int32_t IncRtcpPackets;
	u_int32_t IncRtcpLostPackets;
	u_int32_t IncRtcpAvgJitter;
	u_int32_t IncRtcpMaxJitter;
	u_int32_t IncRtcpAvgLat;	// Average latency
	u_int32_t IncRtcpMaxLat;	// Maximum latency
	// Incoming quality metrics
	u_int32_t IncrVal;		// R-value
	u_int32_t IncMos;		// MOS score
	// RTP Outgoing statistics
	u_int32_t OutRtpBytes;
	u_int32_t OutRtpPackets;
	u_int32_t OutRtpLostPackets;
	u_int32_t OutRtpAvgJitter;
	u_int32_t OutRtpMaxJitter;
	// RTCP Outgoing statistics
	u_int32_t OutRtcpBytes;
	u_int32_t OutRtcpPackets;
	u_int32_t OutRtcpLostPackets;
	u_int32_t OutRtcpAvgJitter;
	u_int32_t OutRtcpMaxJitter;
	u_int32_t OutRtcpAvgLat;
	u_int32_t OutRtcpMaxLat;
	// Outgoing quality metrics
	u_int32_t OutrVal;		// R-value
	u_int32_t OutMos;		// MOS score
	// Codec type
	u_int8_t Type;
	// Caller Incoming addresses
	u_int8_t CallerIncSrcIP[4];
	u_int8_t CallerIncDstIP[4];
	u_int16_t CallerIncSrcPort;
	u_int16_t CallerIncDstPort;
	// Callee Incoming addresses
	u_int8_t CalleeIncSrcIP[4];
	u_int8_t CalleeIncDstIP[4];
	u_int16_t CalleeIncSrcPort;
	u_int16_t CalleeIncDstPort;
	// Caller Outgoing addresses
	u_int8_t CallerOutSrcIP[4];
	u_int8_t CallerOutDstIP[4];
	u_int16_t CallerOutSrcPort;
	u_int16_t CallerOutDstPort;
	// Callee Outgoing addresses
	u_int8_t CalleeOutSrcIP[4];
	u_int8_t CalleeOutDstIP[4];
	u_int16_t CalleeOutSrcPort;
	u_int16_t CalleeOutDstPort;
	// Interface information
	u_int8_t CallerIntSlot;
	u_int8_t CallerIntPort;
	u_int16_t CallerIntVlan;
	u_int8_t CalleeIntSlot;
	u_int8_t CalleeIntPort;
	u_int16_t CalleeIntVlan;
	// Timestamps
	u_int32_t BeginTimeSec;
	u_int32_t BeginTimeMic;
	u_int32_t EndTimeSec;
	u_int32_t EndTimeMic;
	u_int8_t Separator;
	//
	// Variable length fields follow after Separator
	// u_int16_t IncRealmLen;
	// char IncRealm[IncRealmLen];
	// u_int8_t IncRealmEnd;
	//
	// u_int16_t OutRealmLen;
	// char OutRealm[OutRealmLen];
	// u_int8_t OutRealmEnd;
	//
	// u_int16_t IncCallIDLen;
	// char IncCallID[IncCallIDLen];
	// u_int8_t IncCallIDEnd;
	//
	// u_int16_t OutCallIDLen;
	// char OutCallID[OutCallIDLen];
} __attribute__((packed));

struct sIPFixQosStatsExt : sIPFixQosStats {
	string IncRealm;
	string OutRealm;
	string IncCallID;
	string OutCallID;
	string json(const char *callid);
	void load_from_json(const char *json, unsigned json_len);
	void load_from_json(const char *json);
	void load(sIPFixQosStats *src, sIPFixHeader *header);
	void getRtpStreams(vector<sIPFixQosStreamStat> *streams, const char *callid);
	void ntoh();
};

class cIPFixServer : public cServer {
public:
	cIPFixServer();
	~cIPFixServer();
	virtual void createConnection(cSocket *socket);
};

class cIPFixConnection : public cServerConnection, public cTimer {
public:
	cIPFixConnection(cSocket *socket);
	~cIPFixConnection();
	virtual void connection_process();
private:
	int check(SimpleBuffer *data);
	int process(SimpleBuffer *data);
	void process_ipfix(sIPFixHeader *header);
	void process_ipfix_HandShake(sIPFixHeader *header);
	void process_ipfix_SipIn(sIPFixHeader *header);
	void process_ipfix_SipOut(sIPFixHeader *header);
	void process_ipfix_SipInTcp(sIPFixHeader *header);
	void process_ipfix_SipOutTcp(sIPFixHeader *header);
	void process_ipfix_QosStats(sIPFixHeader *header);
	void process_ipfix_UdpIn(sIPFixHeader *header);
	void process_ipfix_UdpOut(sIPFixHeader *header);
	void process_ipfix_other(sIPFixHeader *header);
	void process_packet(sIPFixHeader *header, string &data, bool tcp, timeval time, vmIPport src, vmIPport dst, const char *type);
	void process_rtp_packet(sIPFixHeader *header, string &payload, timeval time, vmIPport src, vmIPport dst, 
				u_int32_t ssrc, u_int16_t seq_num, u_int32_t timestamp, u_int8_t payload_type, u_int8_t marker);
	void process_udp_packet(sIPFixHeader *header, string &data, timeval time, vmIPport src, vmIPport dst);
	void push_packet(vmIPport src, vmIPport dst,
			 pcap_pkthdr *header, u_char *packet, unsigned data_len, bool tcp,
			 int dlink, int pcap_handle_index);
	void evTimer(u_int32_t time_s, int typeTimer, void *data);
	void block_store_lock() {
		__SYNC_LOCK_USLEEP(block_store_sync, 50);
	}
	void block_store_unlock() {
		__SYNC_UNLOCK(block_store_sync);
	}
private:
	struct pcap_block_store *block_store;
	volatile int block_store_sync;
};

class cIpFixCounter {
public:
	void inc(vmIP ip) {
		lock();
		ip_counter[ip]++;
		unlock();
	}
	void reset() {
		lock();
		ip_counter.clear();
		unlock();
	}
	string get_ip_counter();
	u_int64_t get_sum_counter();
private:
	void lock() {
		__SYNC_LOCK(sync);
	}
	void unlock() {
		__SYNC_UNLOCK(sync);
	}
private:
	map<vmIP, u_int64_t> ip_counter;
	volatile int sync;
};


int checkIPFixData(SimpleBuffer *data, bool strict);
bool checkIPFixVersion(u_int16_t version);
void IPFix_client_emulation(const char *pcap, vmIP client_ip, vmIP server_ip, vmIP destination_ip, vmPort destination_port);
void IPFixServerStart(const char *host, int port);
void IPFixServerStop();


#endif //IPFIX_H
