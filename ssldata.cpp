#include <iomanip>

#include "ssldata.h"
#include "sql_db.h"


using namespace std;


extern vector<string> decrypt_ssl(char *data, unsigned int datalen, unsigned int saddr, unsigned int daddr, int sport, int dport);
extern Call *process_packet(u_int64_t packet_number,
			    unsigned int saddr, int source, unsigned int daddr, int dest, 
			    char *data, int datalen, int dataoffset,
			    pcap_t *handle, pcap_pkthdr *header, const u_char *packet, 
			    int istcp, int *was_rtp, struct iphdr2 *header_ip, int *voippacket, int forceSip,
			    pcap_block_store *block_store, int block_store_index, int dlt, int sensor_id,
			    bool mainProcess = true, int sipOffset = 0,
			    ParsePacket *parsePacket = NULL, u_int32_t parsePacket_sipDataLen = 0, bool parsePacket_isSip = false,
			    unsigned int hash_s = 0, unsigned int hash_d = 0);


extern map<d_u_int32_t, string> ssl_ipport;
extern PreProcessPacket *preProcessPacket;


SslData::SslData() {
	this->counterProcessData = 0;
}

SslData::~SslData() {
}

void SslData::processData(u_int32_t ip_src, u_int32_t ip_dst,
			  u_int16_t port_src, u_int16_t port_dst,
			  TcpReassemblyData *data,
			  u_char *ethHeader, u_int32_t ethHeaderLength,
			  pcap_t *handle, int dlt, int sensor_id,
			  TcpReassemblyLink *reassemblyLink,
			  bool debugSave) {
	++this->counterProcessData;
	if(debugSave) {
		cout << "### SslData::processData " << this->counterProcessData << endl;
	}
	for(size_t i_data = 0; i_data < data->data.size(); i_data++) {
		TcpReassemblyDataItem *dataItem = &data->data[i_data];
		if(debugSave) {
			cout << "###"
			     << fixed
			     << setw(15) << inet_ntostring(htonl(ip_src))
			     << " / "
			     << setw(5) << port_src
			     << (dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? " --> " : " <-- ")
			     << setw(15) << inet_ntostring(htonl(ip_dst))
			     << " / "
			     << setw(5) << port_dst
			     << "  len: " << setw(4) << dataItem->getDatalen();
			u_int32_t ack = dataItem->getAck();
			if(ack) {
				cout << "  ack: " << setw(5) << ack;
			}
			cout << endl;
		}
		for(int pass = 0; pass < 2; pass++) {
			u_char *ssl_data;
			u_int32_t ssl_datalen;
			bool alloc_ssl_data = false;
			if(reassemblyLink->getRemainData()) {
				ssl_datalen = reassemblyLink->getRemainDataLength() + dataItem->getDatalen();
				ssl_data = new u_char[ssl_datalen];
				memcpy(ssl_data, reassemblyLink->getRemainData(), reassemblyLink->getRemainDataLength());
				memcpy(ssl_data + reassemblyLink->getRemainDataLength(), dataItem->getData(), dataItem->getDatalen());
				alloc_ssl_data = true;
			} else {
				ssl_data = dataItem->getData();
				ssl_datalen = dataItem->getDatalen();
			}
			u_int32_t ssl_data_offset = 0;
			while(ssl_data_offset < ssl_datalen &&
			      ssl_datalen - ssl_data_offset >= 5) {
				SslHeader header(ssl_data + ssl_data_offset, ssl_datalen - ssl_data_offset);
				if(header.length && header.length + 5 <= ssl_datalen - ssl_data_offset) {
					if(debugSave) {
						cout << "SSL HEADER "
						     << "content type: " << (int)header.content_type << " / "
						     << "version: " << hex << header.version << dec << " / "
						     << "length: " << header.length
						     << endl;
					}
					u_int32_t _ip_src = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? ip_src : ip_dst;
					u_int32_t _ip_dst = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? ip_dst : ip_src;
					u_int16_t _port_src = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? port_src : port_dst;
					u_int16_t _port_dst = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? port_dst : port_src;
					vector<string> rslt_decrypt = decrypt_ssl((char*)(ssl_data + ssl_data_offset), header.length + 5, htonl(_ip_src), htonl(_ip_dst), _port_src, _port_dst);
					for(size_t i = 0; i < rslt_decrypt.size(); i++) {
						if(debugSave) {
							cout << "DECRYPT DATA: " << rslt_decrypt[i] << endl;
						}
						if(!ethHeader || !ethHeaderLength) {
							continue;
						}
						u_int32_t udpPacketLength = ethHeaderLength + sizeof(iphdr2) + sizeof(udphdr2) + rslt_decrypt[i].size();
						u_char *udpPacket = new u_char[udpPacketLength];
						memcpy(udpPacket, ethHeader, ethHeaderLength);
						iphdr2 iphdr;
						memset(&iphdr, 0, sizeof(iphdr2));
						iphdr.version = 4;
						iphdr.ihl = 5;
						iphdr.protocol = IPPROTO_UDP;
						iphdr.saddr = _ip_src;
						iphdr.daddr = _ip_dst;
						iphdr.tot_len = htons(sizeof(iphdr2) + sizeof(udphdr2) + rslt_decrypt[i].size());
						iphdr.ttl = 50;
						memcpy(udpPacket + ethHeaderLength, &iphdr, sizeof(iphdr2));
						udphdr2 udphdr;
						memset(&udphdr, 0, sizeof(udphdr2));
						udphdr.source = htons(_port_src);
						udphdr.dest = htons(_port_dst);
						udphdr.len = htons(sizeof(udphdr2) + rslt_decrypt[i].size());
						memcpy(udpPacket + ethHeaderLength + sizeof(iphdr2), &udphdr, sizeof(udphdr2));
						memcpy(udpPacket + ethHeaderLength + sizeof(iphdr2) + sizeof(udphdr2), rslt_decrypt[i].c_str(), rslt_decrypt[i].size());
						pcap_pkthdr header;
						memset(&header, 0, sizeof(pcap_pkthdr));
						header.ts.tv_sec = dataItem->getTime().tv_sec;
						header.ts.tv_usec = dataItem->getTime().tv_usec;
						header.caplen = udpPacketLength;
						header.len = udpPacketLength;
						int was_rtp = 0;
						int voippacket = 0;
						if(preProcessPacket) {
							preProcessPacket->push(0, _ip_src, _port_src, _ip_dst, _port_dst, 
									       (char*)(udpPacket + ethHeaderLength + sizeof(iphdr2) + sizeof(udphdr2)), rslt_decrypt[i].size(), ethHeaderLength + sizeof(iphdr2) + sizeof(udphdr2),
									       handle, &header, udpPacket, true, 
									       false, (iphdr2*)(udpPacket + ethHeaderLength), 1,
									       NULL, 0, dlt, sensor_id);
						} else {
							process_packet(0, _ip_src, _port_src, _ip_dst, _port_dst, 
								       (char*)rslt_decrypt[i].c_str(), rslt_decrypt[i].size(), ethHeaderLength + sizeof(iphdr2) + sizeof(udphdr2),
								       handle, &header, udpPacket, 
								       false, &was_rtp, (iphdr2*)(udpPacket + ethHeaderLength), &voippacket, 1,
								       NULL, 0, dlt, sensor_id);
							delete [] udpPacket;
						}
					}
					ssl_data_offset += header.length + 5;
				} else {
					break;
				}
			}
			if(pass == 0) {
				bool ok = false;
				if(reassemblyLink->getRemainDataLength() &&
				   !ssl_data_offset &&
				   _checkOkSslData(dataItem->getData(), dataItem->getDatalen())) {
					// next pass with ignore remainData
					reassemblyLink->clearRemainData();
					if(debugSave) {
						cout << "SKIP REMAIN DATA" << endl;
					}
				} else {
					if(ssl_data_offset < ssl_datalen) {
						reassemblyLink->setRemainData(ssl_data + ssl_data_offset, ssl_datalen - ssl_data_offset);
						if(debugSave) {
							cout << "REMAIN DATA LENGTH: " << ssl_datalen - ssl_data_offset << endl;
						}
					} else {
						reassemblyLink->clearRemainData();
					}
					ok = true;
				}
				if(alloc_ssl_data) {
					delete [] ssl_data;
				}
				if(ok) {
					break;
				}
			}
		}
	}
	delete data;
}
 
void SslData::printContentSummary() {
}


bool checkOkSslData(u_char *data, u_int32_t datalen) {
	u_int32_t offset = 0;
	u_int32_t len;
	while(offset < datalen &&
	      datalen - offset >= 5 &&
	      (len = _checkOkSslData(data + offset, datalen - offset)) > 0) {
		offset += len;
		if(offset == datalen) {
			return(true);
		}
	}
	return(false);
}

u_int32_t _checkOkSslData(u_char *data, u_int32_t datalen) {
	SslData::SslHeader header(data, datalen);
	return(header.length && header.length + 5 <= datalen ? header.length + 5: 0);
}


bool isSslIpPort(u_int32_t ip, u_int16_t port) {
	map<d_u_int32_t, string>::iterator iter = ssl_ipport.find(d_u_int32_t(ip, port));
	return(iter != ssl_ipport.end());
}
