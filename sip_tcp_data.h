#ifndef SIP_TCP_DATA_H
#define SIP_TCP_DATA_H

#include "tcpreassembly.h"


class SipTcpData : public TcpReassemblyProcessData {
public:
	struct Cache_id {
		Cache_id(vmIP ip_src, vmIP ip_dst,
			 vmPort port_src, vmPort port_dst,
			 u_int32_t ack, u_int32_t seq) {
			this->ip_src = ip_src;
			this->ip_dst = ip_dst;
			this->port_src = port_src; 
			this->port_dst = port_dst;
			this->ack = ack;
			this->seq = seq;
		}
		vmIP ip_src;
		vmIP ip_dst;
		vmPort port_src;
		vmPort port_dst;
		u_int32_t ack;
		u_int32_t seq;
		bool operator < (const Cache_id& other) const {
			return((this->ip_src < other.ip_src) ? 1 : (this->ip_src > other.ip_src) ? 0 :
			       (this->ip_dst < other.ip_dst) ? 1 : (this->ip_dst > other.ip_dst) ? 0 :
			       (this->port_src < other.port_src) ? 1 : (this->port_src > other.port_src) ? 0 :
			       (this->port_dst < other.port_dst) ? 1 : (this->port_dst > other.port_dst) ? 0 :
			       (this->ack < other.ack) ? 1 : (this->ack > other.ack) ? 0 :
			       this->seq < other.seq);
		}
	};
	struct Cache_data {
		map<string, u_int64_t> data;
	};
public:
	SipTcpData();
	virtual ~SipTcpData();
	void processData(vmIP ip_src, vmIP ip_dst,
			 vmPort port_src, vmPort port_dst,
			 TcpReassemblyData *data,
			 u_char *ethHeader, u_int32_t ethHeaderLength,
			 u_int16_t handle_index, int dlt, int sensor_id, vmIP sensor_ip, sPacketInfoData pid,
			 void *uData, void *uData2, void *uData2_last, TcpReassemblyLink *reassemblyLink,
			 std::ostream *debugStream);
	void cleanupCache(u_int64_t cache_time);
	void printContentSummary();
private:
	unsigned int counterProcessData;
	map<Cache_id, Cache_data*> cache;
	u_int64_t last_cache_time_cleanup;
};


bool checkOkSipData(u_char *data, u_int32_t datalen, bool strict, list<d_u_int32_t> *offsets = NULL);


#endif
