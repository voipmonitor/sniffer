#ifndef SIP_TCP_DATA_H
#define SIP_TCP_DATA_H

#include "tcpreassembly.h"


class SipTcpData : public TcpReassemblyProcessData {
public:
	struct Cache_id {
		Cache_id(u_int32_t ip_src, u_int32_t ip_dst,
			 u_int16_t port_src, u_int16_t port_dst) {
			this->ip_src = ip_src;
			this->ip_dst = ip_dst;
			this->port_src = port_src; 
			this->port_dst = port_dst;
		}
		u_int32_t ip_src;
		u_int32_t ip_dst;
		u_int16_t port_src;
		u_int16_t port_dst;
		bool operator < (const Cache_id& other) const {
			return((this->ip_src < other.ip_src) ? 1 : (this->ip_src > other.ip_src) ? 0 :
			       (this->ip_dst < other.ip_dst) ? 1 : (this->ip_dst > other.ip_dst) ? 0 :
			       (this->port_src < other.port_src) ? 1 : (this->port_src > other.port_src) ? 0 :
			       this->port_dst < other.port_dst);
		}
	};
	struct Cache_data {
		map<string, u_int64_t> data;
	};
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
	void cleanupCache(u_int64_t cache_time);
	void printContentSummary();
private:
	unsigned int counterProcessData;
	map<Cache_id, Cache_data*> cache;
	u_int64_t last_cache_time_cleanup;
};


bool checkOkSipData(u_char *data, u_int32_t datalen, bool strict, list<d_u_int32_t> *offsets = NULL);


#endif
