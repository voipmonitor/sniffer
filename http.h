#ifndef HTTP_H
#define HTTP_H

#include "pcap_queue_block.h"
#include "tcpreassembly.h"


struct HttpDataCache_id {
	HttpDataCache_id(u_int32_t ip_src, u_int32_t ip_dst,
			 u_int16_t port_src, u_int16_t port_dst,
			 string *http, string *body,
			 string *http_master = NULL, string *body_master = NULL) {
		this->ip_src = ip_src;
		this->ip_dst = ip_dst;
		this->port_src = port_src; 
		this->port_dst = port_dst;
		if(http) {
			this->http = *http;
		}
		if(body) {
			this->body = *body;
		}
		if(http_master) {
			this->http_master = *http_master;
		}
		if(body_master) {
			this->body_master = *body_master;
		}
	}
	u_int32_t ip_src;
	u_int32_t ip_dst;
	u_int16_t port_src;
	u_int16_t port_dst;
	string http;
	string body;
	string http_master;
	string body_master;
	bool operator < (const HttpDataCache_id& other) const {
		return((this->ip_src < other.ip_src) ? 1 : (this->ip_src > other.ip_src) ? 0 :
		       (this->ip_dst < other.ip_dst) ? 1 : (this->ip_dst > other.ip_dst) ? 0 :
		       (this->port_src < other.port_src) ? 1 : (this->port_src > other.port_src) ? 0 :
		       (this->port_dst < other.port_dst) ? 1 : (this->port_dst > other.port_dst) ? 0 :
		       (this->http < other.http) ? 1 : (this->http > other.http) ? 0 :
		       (this->body < other.body) ? 1 : (this->body > other.body) ? 0 :
		       (this->http_master < other.http_master) ? 1 : (this->http_master > other.http_master) ? 0 :
		       (this->body_master < other.body_master));
	}
};

struct HttpDataCache {
	HttpDataCache(uint32_t id = 0, u_int64_t timestamp = 0) {
		this->id = id;
		this->timestamp = timestamp;
		this->timestamp_clock = getTimeMS()/1000;
	}
	uint32_t id;
	u_int64_t timestamp;
	u_int64_t timestamp_clock;
};

class HttpCache {
public:
	HttpCache();
	HttpDataCache get(u_int32_t ip_src, u_int32_t ip_dst,
			  u_int16_t port_src, u_int16_t port_dst,
			  string *http, string *body,
			  string *http_master = NULL, string *body_master = NULL);
	void add(u_int32_t ip_src, u_int32_t ip_dst,
		 u_int16_t port_src, u_int16_t port_dst,
		 string *http, string *body,
		 string *http_master, string *body_master,
		 u_int32_t id, u_int64_t timestamp);
	void cleanup(bool force = false);
	void clear();
	u_int32_t getSize() {
		return(this->cache.size());
	}
private:
	map<HttpDataCache_id, HttpDataCache> cache;
	u_int64_t cleanupCounter;
	u_int64_t lastAddTimestamp;
};

class HttpData : public TcpReassemblyProcessData {
public:
	HttpData();
	virtual ~HttpData();
	void processData(u_int32_t ip_src, u_int32_t ip_dst,
			 u_int16_t port_src, u_int16_t port_dst,
			 TcpReassemblyData *data,
			 u_char *ethHeader, u_int32_t ethHeaderLength,
			 u_int16_t handle_index, int dlt, int sensor_id, u_int32_t sensor_ip,
			 TcpReassemblyLink *reassemblyLink,
			 bool debugSave);
	string getUri(string &request);
	string getUriValue(string &uri, const char *valueName);
	string getUriPathValue(string &uri, const char *valueName);
	string getTag(string &data, const char *tag);
	string getJsonValue(string &data, const char *valueName);
	void printContentSummary();
private:
	unsigned int counterProcessData;
	HttpCache cache;
};

class HttpPacketsDumper {
public:
	enum eReqResp {
		request,
		response
	};
	struct HttpLink_id {
		HttpLink_id(u_int32_t ip1 = 0, u_int32_t ip2 = 0,
			    u_int16_t port1 = 0, u_int16_t port2 = 0) {
			this->ip1 = ip1 > ip2 ? ip1 : ip2;
			this->ip2 = ip1 < ip2 ? ip1 : ip2;
			this->port1 = port1 > port2 ? port1 : port2; 
			this->port2 = port1 < port2 ? port1 : port2;
		}
		u_int32_t ip1;
		u_int32_t ip2;
		u_int16_t port1;
		u_int16_t port2;
		bool operator < (const HttpLink_id& other) const {
			return((this->ip1 < other.ip1) ? 1 : (this->ip1 > other.ip1) ? 0 :
			       (this->ip2 < other.ip2) ? 1 : (this->ip2 > other.ip2) ? 0 :
			       (this->port1 < other.port1) ? 1 : (this->port1 > other.port1) ? 0 :
			       (this->port2 < other.port2));
		}
	};
	class HttpLink {
	public:
		HttpLink(u_int32_t ip1 = 0, u_int32_t ip2 = 0,
			 u_int16_t port1 = 0, u_int16_t port2 = 0) {
			this->ip1 = ip1;
			this->ip2 = ip2;
			this->port1 = port1;
			this->port2 = port2;
			this->seq[0] = 1;
			this->seq[1] = 1;
		}
		u_int32_t ip1;
		u_int32_t ip2;
		u_int16_t port1;
		u_int16_t port2;
		u_int32_t seq[2];
	};
public:
	HttpPacketsDumper();
	~HttpPacketsDumper();
	void setPcapName(const char *pcapName);
	void setTemplatePcapName();
	void setPcapDumper(PcapDumper *pcapDumper);
	void dumpData(const char *timestamp_from, const char *timestamp_to, const char *ids);
	void dumpDataItem(eReqResp reqResp, string header, string body,
			  timeval time,
			  u_int32_t ip_src, u_int32_t ip_dst,
			  u_int16_t port_src, u_int16_t port_dst);
	void setUnlinkPcap();
	string getPcapName();
	void openPcapDumper();
	void closePcapDumper(bool force = false);
private:
	string pcapName;
	bool unlinkPcap;
	PcapDumper *pcapDumper;
	bool selfOpenPcapDumper;
	map<HttpLink_id, HttpLink> links;
};

#endif
