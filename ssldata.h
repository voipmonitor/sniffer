#ifndef SSLDATA_H
#define SSLDATA_H

//#include "pcap_queue_block.h"
#include "tcpreassembly.h"
#include "sniff_proc_class.h"


class SslData : public TcpReassemblyProcessData {
public:
	struct SslHeader {
		SslHeader(u_char *data, u_int32_t datalen) {
			header_version = 0;
			if(datalen >= 5) {
				content_type = *(u_int8_t*)(data);
				version = htons(*(u_int16_t*)(data + 1));
				length = htons(*(u_int16_t*)(data + 3));
				if(isOkV1()) {
					header_version = 1;
				}
			}
			if(!header_version && datalen >= 5 && (data[0] & 0x80) == 0x80) {
				length = htons(*(u_int16_t*)(data)) & 0x0FFF;
				content_type = *(u_int8_t*)(data + 2);
				version = htons(*(u_int16_t*)(data + 3));
				if(isOkV2()) {
					header_version = 2;
				}
			}
			if(!header_version) {
				content_type = 0;
				version = 0;
				length = 0;
			}
		}
		bool isOk() {
			return(header_version == 1 ? isOkV1() :
			       header_version == 2 ? isOkV2() : false);
		}
		bool isOkV1() {
			return(content_type >= 20 && content_type <= 23 &&
			       isOkVersion());
		}
		bool isOkV2() {
			return(content_type <= 5 &&
			       isOkVersion());
		}
		bool isOkVersion() {
			return(version >= 0x300 && version <= 0x303);
		}
		unsigned getDataOffsetLength() {
			return(header_version == 1 ? 5 :
			       header_version == 2 ? 2 : 0);
		}
		u_int8_t content_type;
		u_int16_t version;
		u_int16_t length;
		int header_version;
	};
public:
	SslData();
	virtual ~SslData();
	void processData(u_int32_t ip_src, u_int32_t ip_dst,
			 u_int16_t port_src, u_int16_t port_dst,
			 TcpReassemblyData *data,
			 u_char *ethHeader, u_int32_t ethHeaderLength,
			 u_int16_t handle_index, int dlt, int sensor_id, u_int32_t sensor_ip,
			 void *uData, TcpReassemblyLink *reassemblyLink,
			 std::ostream *debugStream);
	void printContentSummary();
private:
	unsigned int counterProcessData;
	ReassemblyWebsocketBuffer reassemblyWebsocketBuffer;
};


bool checkOkSslData(u_char *data, u_int32_t datalen);
u_int32_t _checkOkSslData(u_char *data, u_int32_t datalen);
bool checkOkSslHeader(u_char *data, u_int32_t datalen);
bool isSslIpPort(u_int32_t ip, u_int16_t port);


#endif
