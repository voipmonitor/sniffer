#ifndef SIP_TCP_DATA_H
#define SIP_TCP_DATA_H

#include "tcpreassembly.h"


class SipTcpData : public TcpReassemblyProcessData {
public:
	SipTcpData();
	virtual ~SipTcpData();
	void processData(u_int32_t ip_src, u_int32_t ip_dst,
			 u_int16_t port_src, u_int16_t port_dst,
			 TcpReassemblyData *data,
			 u_char *ethHeader, u_int32_t ethHeaderLength,
			 u_int16_t handle_index, int dlt, int sensor_id, u_int32_t sensor_ip,
			 void *uData, TcpReassemblyLink *reassemblyLink,
			 bool debugSave);
	void printContentSummary();
private:
	unsigned int counterProcessData;
};


bool checkOkSipData(u_char *data, u_int32_t datalen, bool strict);


#endif
