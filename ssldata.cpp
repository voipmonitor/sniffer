#include <iomanip>

#include "ssldata.h"
#include "sql_db.h"
#include "ssl.h"


using namespace std;


vector<string> decrypt_ssl(char *data, unsigned int datalen, unsigned int saddr, unsigned int daddr, int sport, int dport);


extern map<d_u_int32_t, string> ssl_ipport;


SslData::SslData() {
	this->counterProcessData = 0;
}

SslData::~SslData() {
}

void SslData::processData(u_int32_t ip_src, u_int32_t ip_dst,
			  u_int16_t port_src, u_int16_t port_dst,
			  TcpReassemblyData *data,
			  bool debugSave) {
	++this->counterProcessData;
	if(debugSave) {
		cout << "### SslData::processData " << this->counterProcessData << endl;
	}
	for(size_t i_data = 0; i_data < data->data.size(); i_data++) {
		TcpReassemblyDataItem *dataItem = &data->data[i_data];
		if(debugSave) {
			cout << fixed
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
		u_char *ssl_data = dataItem->getData();
		u_int32_t ssl_datalen = dataItem->getDatalen();
		u_int32_t ssl_data_offset = 0;
		while(ssl_data_offset < ssl_datalen &&
		      ssl_datalen - ssl_data_offset >= 5) {
			SslHeader header(ssl_data + ssl_data_offset, ssl_datalen - ssl_data_offset);
			if(header.length && header.length + 5 <= ssl_datalen - ssl_data_offset) {
				if(debugSave) {
					cout << "SSL header "
					     << "content type: " << (int)header.content_type << " / "
					     << "version: " << hex << header.version << dec << " / "
					     << "length: " << header.length
					     << endl;
				}
				u_int32_t _ip_src = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? ip_src : ip_dst;
				u_int32_t _ip_dst = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? ip_dst : ip_src;
				u_int16_t _port_src = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? port_src : port_dst;
				u_int16_t _port_dst = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? port_dst : port_src;
				vector<string> rslt_decrypt = decrypt_ssl((char*)(ssl_data + ssl_data_offset), header.length + 5, _ip_src, _ip_dst, _port_src, _port_dst);
				for(size_t i = 0; i < rslt_decrypt.size(); i++) {
					if(debugSave) {
						cout << "DECRYPT DATA: " << rslt_decrypt[i] << endl;
					}
				}
				ssl_data_offset += header.length + 5;
			} else {
				break;
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
