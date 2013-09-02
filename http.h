#ifndef HTTP_H
#define HTTP_H

#include "pcap_queue_block.h"
#include "tcpreassembly.h"


class HttpData : public TcpReassemblyProcessData {
public:
	void processData(u_int32_t ip_src, u_int32_t ip_dst,
			 u_int16_t port_src, u_int16_t port_dst,
			 TcpReassemblyData *data);
	string getUri(string &request);
	string getUriValue(string &uri, const char *valueName);
	string getUriPathValue(string &uri, const char *valueName);
	string getTag(string &data, const char *tag);
	string getJsonValue(string &data, const char *valueName);
};

#endif
