/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

#ifndef IPACCOUNT_H
#define IPACCOUNT_H

#include <map>
#include <vector>
#include <string>
#include <algorithm>

#include "sniff.h"
#include "sql_db.h"

void ipaccount(time_t, struct iphdr2 *, int, int);

struct octects_t {
	octects_t() {
		octects = 0;
		numpackets = 0;
		interval_time = 0;
		voippacket = 0;
		erase = false;
	}
	unsigned int octects;
	unsigned int numpackets;
	unsigned int interval_time;
	int voippacket;
	bool erase;
};

struct octects_live_t {
	int all;
	unsigned long long int dst_octects;
	unsigned int dst_numpackets;
	unsigned long long int src_octects;
	unsigned int src_numpackets;
	unsigned long long int voipdst_octects;
	unsigned int voipdst_numpackets;
	unsigned long long int voipsrc_octects;
	unsigned int voipsrc_numpackets;
	unsigned long long int all_octects;
	unsigned long long int voipall_octects;
	unsigned int all_numpackets;
	unsigned int voipall_numpackets;
	vector<unsigned int> ipfilter;
	unsigned int fetch_timestamp;
	bool isIpInFilter(unsigned int ip) {
		vector<unsigned int>::iterator findIp;
		findIp = std::lower_bound(ipfilter.begin(), ipfilter.end(), ip);
		return(findIp != ipfilter.end() && (*findIp) == ip);
  	}
	void setFilter(const char *ipfilter);
};

struct cust_cache_item {
	cust_cache_item() {
		cust_id = 0;
		add_timestamp = 0;
	}
	unsigned int cust_id;
	unsigned int add_timestamp;
};

struct cust_cache_rec {
	cust_cache_rec() {
		ip = 0;
		cust_id = 0;
	}
	unsigned int ip;
	unsigned int cust_id;
	bool operator < (const cust_cache_rec& other) const { 
		return(this->ip < other.ip); 
	}
	bool operator < (const unsigned int& _ip) const { 
		return(this->ip < _ip); 
	}
};

struct cust_pn_cache_rec {
	cust_pn_cache_rec() {
		cust_id = 0;
	}
	string numberFrom;
	string numberTo;
	unsigned int cust_id;
	string reseller_id;
	bool operator < (const cust_pn_cache_rec& other) const { 
		return(this->numberFrom < other.numberFrom); 
	}
	bool operator < (const string& _numberFrom) const { 
		return(this->numberFrom < _numberFrom); 
	}
};

struct next_cache_rec {
	next_cache_rec() {
		ip = 0;
		mask = 0;
	}
	unsigned int ip;
	unsigned int mask;
	bool operator < (const next_cache_rec& other) const {
		return((this->ip < other.ip) ? 1 : (this->ip > other.ip) ? 0 :
		       (this->mask < other.mask));
	}
};

struct cust_reseller {
	cust_reseller() {
		cust_id = 0;
	}
	unsigned int cust_id;
	string reseller_id;
};

class IpaccAgreg {
public:
	struct AgregData {
		AgregData() {
			id_customer = 0;
			id_customer2 = 0;
			traffic_in = 0;
			traffic_out = 0;
			packets_in = 0;
			packets_out = 0;
			traffic_voip_in = 0;
			traffic_voip_out = 0;
			packets_voip_in = 0;
			packets_voip_out = 0;
		}
		void addIn(unsigned int traffic, unsigned int packets, bool voip) {
			traffic_in += traffic;
			packets_in += packets;
			if(voip) {
				traffic_voip_in += traffic;
				packets_voip_in += packets;
			}
		}
		void addOut(unsigned int traffic, unsigned int packets, bool voip) {
			traffic_out += traffic;
			packets_out += packets;
			if(voip) {
				traffic_voip_out += traffic;
				packets_voip_out += packets;
			}
		}
		unsigned int id_customer;
		unsigned int id_customer2;
		unsigned long traffic_in;
		unsigned long traffic_out;
		unsigned long packets_in;
		unsigned long packets_out;
		unsigned long traffic_voip_in;
		unsigned long traffic_voip_out;
		unsigned long packets_voip_in;
		unsigned long packets_voip_out;
	};
	struct AgregIP {
		AgregIP(unsigned int ip, unsigned int proto, unsigned int port) {
			this->ip = ip;
			this->proto = proto;
			this->port = port;
		}
		unsigned int ip;
		unsigned int proto;
		unsigned int port;
		bool operator < (const AgregIP& other) const { 
			return((this->ip < other.ip) ? 1 : (this->ip > other.ip) ? 0 :
			       (this->proto < other.proto) ? 1 : (this->proto > other.proto) ? 0 :
			       (this->port < other.port));
		}
	};
	struct AgregIP2 {
		AgregIP2(unsigned int ip1, unsigned int ip2, unsigned int proto, unsigned int port) {
			this->ip1 = ip1;
			this->ip2 = ip2;
			this->proto = proto;
			this->port = port;
		}
		unsigned int ip1;
		unsigned int ip2;
		unsigned int proto;
		unsigned int port;
		bool operator < (const AgregIP2& other) const { 
			return((this->ip1 < other.ip1) ? 1 : (this->ip1 > other.ip1) ? 0 :
			       (this->ip2 < other.ip2) ? 1 : (this->ip2 > other.ip2) ? 0 :
			       (this->proto < other.proto) ? 1 : (this->proto > other.proto) ? 0 :
			       (this->port < other.port));
		}
	};
	~IpaccAgreg();
	void add(unsigned int src, unsigned int dst,
		 unsigned int src_id_customer, unsigned int dst_id_customer,
		 bool src_ip_next, bool dst_ip_next,
		 unsigned int proto, unsigned int port,
		 unsigned int traffic, unsigned int packets, bool voip);
	void save(unsigned int time_interval);
private:
	map<AgregIP, AgregData*> map1;
	map<AgregIP2, AgregData*> map2;
};

class CustIpCache {
public:
	CustIpCache();
	~CustIpCache();
	void setConnectParams(const char *sqlDriver, const char *odbcDsn, const char *odbcUser, const char *odbcPassword, const char *odbcDriver);
	void setConnectParamsRadius(const char *radiusSqlDriver, const char *radiusHost, const char *radiusDb,const char *radiusUser, const char *radiusPassword);
	void setQueryes(const char *getIp, const char *fetchAllIp);
	void setQueryesRadius(const char *fetchAllRadiusNames, const char *fetchAllRadiusIp, const char *fetchAllRadiusIpWhere);
	int connect();
	bool okParams();
	int getCustByIp(unsigned int ip);
	int getCustByIpFromDb(unsigned int ip, bool saveToCache = false);
	int fetchAllIpQueryFromDb();
	int getCustByIpFromCacheMap(unsigned int ip);
	int getCustByIpFromCacheVect(unsigned int ip);
	void flush();
	void clear();
	string printVect();
	void setMaxQueryPass(unsigned int maxQueryPass) {
		if(this->sqlDb) {
			this->sqlDb->setMaxQueryPass(maxQueryPass);
		}
		if(this->sqlDbRadius) {
			this->sqlDbRadius->setMaxQueryPass(maxQueryPass);
		}
	}
private:
	SqlDb *sqlDb;
	SqlDb *sqlDbRadius;
	map<unsigned int, cust_cache_item> custCacheMap;
	vector<cust_cache_rec> custCacheVect;
	string sqlDriver;
	string odbcDsn;
	string odbcUser;
	string odbcPassword;
	string odbcDriver;
	string radiusSqlDriver;
	string radiusHost;
	string radiusDb;
	string radiusUser;
	string radiusPassword;
	string query_getIp;
	string query_fetchAllIp;
	string query_fetchAllRadiusNames;
	string query_fetchAllRadiusIp;
	string query_fetchAllRadiusIpWhere;
	unsigned int flushCounter;
	bool doFlushVect;
};

class NextIpCache {
public:
	NextIpCache();
	~NextIpCache();
	int connect();
	bool isIn(unsigned int ip);
	void fetch();
	void flush();
private:
	SqlDb *sqlDb;
	vector<next_cache_rec> nextCache;
	unsigned int flushCounter;
	bool doFlush;
};

class CustPhoneNumberCache {
public:
	CustPhoneNumberCache();
	~CustPhoneNumberCache();
	void setConnectParams(const char *sqlDriver, const char *odbcDsn, const char *odbcUser, const char *odbcPassword, const char *odbcDriver);
	void setQueryes(const char *fetchPhoneNumbers);
	int connect();
	bool okParams();
	cust_reseller getCustomerByPhoneNumber(char *number);
	int fetchPhoneNumbersFromDb();
	void flush();
	void setMaxQueryPass(unsigned int maxQueryPass) {
		if(this->sqlDb) {
			this->sqlDb->setMaxQueryPass(maxQueryPass);
		}
	}
private:
	SqlDb *sqlDb;
	vector<cust_pn_cache_rec> custCache;
	string sqlDriver;
	string odbcDsn;
	string odbcUser;
	string odbcPassword;
	string odbcDriver;
	string query_fetchPhoneNumbers;
	unsigned int flushCounter;
	bool doFlush;
};

unsigned int lengthIpaccBuffer();
void initIpacc();
void freeMemIpacc();

#endif
