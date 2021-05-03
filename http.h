#ifndef HTTP_H
#define HTTP_H

#include "pcap_queue_block.h"
#include "tcpreassembly.h"


struct HttpDataCache_id {
	HttpDataCache_id(vmIP ip_src, vmIP ip_dst,
			 vmPort port_src, vmPort port_dst) {
		this->ip_src = ip_src;
		this->ip_dst = ip_dst;
		this->port_src = port_src; 
		this->port_dst = port_dst;
	}
	vmIP ip_src;
	vmIP ip_dst;
	vmPort port_src;
	vmPort port_dst;
	bool operator < (const HttpDataCache_id& other) const {
		return((this->ip_src < other.ip_src) ? 1 : (this->ip_src > other.ip_src) ? 0 :
		       (this->ip_dst < other.ip_dst) ? 1 : (this->ip_dst > other.ip_dst) ? 0 :
		       (this->port_src < other.port_src) ? 1 : (this->port_src > other.port_src) ? 0 :
		       this->port_dst < other.port_dst);
	}
};

struct HttpDataCache_data {
	HttpDataCache_data(const char *url, const char *url_md5,
			   const char *http, const char *http_md5,
			   const char *body, const char *body_md5,
			   const char *callid, const char *sessionid, const char *external_transaction_id) {
		if(url) this->url = url;
		if(url_md5) this->url_md5 = url_md5; else if(url) this->url_md5 = GetStringMD5(url);
		if(http) this->http = http;
		if(http_md5) this->http_md5 = http_md5; else if(http) this->http_md5 = GetStringMD5(http);
		if(body) this->body = body;
		if(body_md5) this->body_md5 = body_md5; else if(body) this->body_md5 = GetStringMD5(body);
		if(callid) this->callid = callid;
		if(sessionid) this->sessionid = sessionid;
		if(external_transaction_id) this->external_transaction_id = external_transaction_id;
	}
	string url;
	string url_md5;
	string http;
	string http_md5;
	string body;
	string body_md5;
	string callid;
	string sessionid;
	string external_transaction_id;
};

struct HttpDataCache_relation {
	HttpDataCache_relation();
	~HttpDataCache_relation();
	void addResponse(u_int64_t timestamp,
			 const char *http, const char *body);
	bool checkExistsResponse(const char *http_md5, const char *body_md5);
	HttpDataCache_data *request;
	map<u_int64_t, HttpDataCache_data*> responses;
	u_int64_t last_timestamp_response;
};

struct HttpDataCache_link {
	~HttpDataCache_link();
	void addRequest(u_int64_t timestamp,
			const char *url, const char *http, const char *body,
			const char *callid, const char *sessionid, const char *external_transaction_id);
	void addResponse(u_int64_t timestamp,
			 const char *http, const char *body,
			 const char *url_master, const char *http_master, const char *body_master);
	bool checkExistsRequest(const char *url_md5, const char *http_md5, const char *body_md5);
	void writeToDb(const HttpDataCache_id *id, bool all, u_int64_t time);
	void writeDataToDb(bool response, u_int64_t timestamp, const HttpDataCache_id *id, HttpDataCache_data *data);
	void writeQueryInsertToDb();
	string getRelationsMapId(const char *url_md5, const char *http_md5, const char *body_md5) {
		return(string(url_md5) + '#' + string(http_md5) + '#' + string(body_md5));
	}
	string getRelationsMapId(string &url_md5, string &http_md5, string &body_md5) {
		return(url_md5 + '#' + http_md5 + '#' + body_md5);
	}
	map<u_int64_t, HttpDataCache_relation*> relations;
	map<string, HttpDataCache_relation*> relations_map;
	string queryInsert;
	string lastRequest_http_md5;
	string lastRequest_body_md5;
	static u_int32_t writeToDb_counter;
};

struct HttpDataCache {
	HttpDataCache();
	void addRequest(u_int64_t timestamp,
			vmIP ip_src, vmIP ip_dst,
			vmPort port_src, vmPort port_dst,
			const char *url, const char *http, const char *body,
			const char *callid, const char *sessionid, const char *external_transaction_id);
	void addResponse(u_int64_t timestamp,
			 vmIP ip_src, vmIP ip_dst,
			 vmPort port_src, vmPort port_dst,
			 const char *http, const char *body,
			 const char *url_master, const char *http_master, const char *body_master);
	void writeToDb(bool all = false, bool ifExpiration = false);
	map<HttpDataCache_id, HttpDataCache_link> data;
	void lock() {
		while(__sync_lock_test_and_set(&this->_sync, 1)) USLEEP(100);
	}
	void unlock() {
		__sync_lock_release(&this->_sync);
	}
	u_int64_t last_timestamp;
	u_int64_t init_at;
	u_int64_t last_write_at;
	int _sync;
};

class HttpData : public TcpReassemblyProcessData {
public:
	HttpData();
	virtual ~HttpData();
	void processData(vmIP ip_src, vmIP ip_dst,
			 vmPort port_src, vmPort port_dst,
			 TcpReassemblyData *data,
			 u_char *ethHeader, u_int32_t ethHeaderLength,
			 u_int16_t handle_index, int dlt, int sensor_id, vmIP sensor_ip, sPacketInfoData pid,
			 void *uData, void *uData2, void *uData2_last, TcpReassemblyLink *reassemblyLink,
			 std::ostream *debugStream);
	void writeToDb(bool all = false);
	string getUri(string &request);
	string getUriValue(string &uri, const char *valueName);
	string getUriPathValue(string &uri, const char *valueName);
	string getTag(string &data, const char *tag);
	string getJsonValue(string &data, const char *valueName);
	string getXmlValue(string &data, const char *valueName);
	void printContentSummary();
private:
	unsigned int counterProcessData;
	unsigned int counterSaveData;
	HttpDataCache cache;
};

class HttpPacketsDumper {
public:
	enum eReqResp {
		request,
		response
	};
	struct HttpLink_id {
		HttpLink_id(vmIP ip1 = 0, vmIP ip2 = 0,
			    vmPort port1 = 0, vmPort port2 = 0) {
			this->ip1 = ip1 > ip2 ? ip1 : ip2;
			this->ip2 = ip1 < ip2 ? ip1 : ip2;
			this->port1 = port1 > port2 ? port1 : port2; 
			this->port2 = port1 < port2 ? port1 : port2;
		}
		vmIP ip1;
		vmIP ip2;
		vmPort port1;
		vmPort port2;
		bool operator < (const HttpLink_id& other) const {
			return((this->ip1 < other.ip1) ? 1 : (this->ip1 > other.ip1) ? 0 :
			       (this->ip2 < other.ip2) ? 1 : (this->ip2 > other.ip2) ? 0 :
			       (this->port1 < other.port1) ? 1 : (this->port1 > other.port1) ? 0 :
			       (this->port2 < other.port2));
		}
	};
	class HttpLink {
	public:
		HttpLink(vmIP ip1 = 0, vmIP ip2 = 0,
			 vmPort port1 = 0, vmPort port2 = 0) {
			this->ip1 = ip1;
			this->ip2 = ip2;
			this->port1 = port1;
			this->port2 = port2;
			this->seq[0] = 1;
			this->seq[1] = 1;
		}
		vmIP ip1;
		vmIP ip2;
		vmPort port1;
		vmPort port2;
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
			  vmIP ip_src, vmIP ip_dst,
			  vmPort port_src, vmPort port_dst);
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
