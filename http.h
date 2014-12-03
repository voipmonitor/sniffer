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
			 pcap_t *handle, int dlt, int sensor_id,
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

#endif
