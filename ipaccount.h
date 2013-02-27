/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

#ifndef IPACCOUNT_H
#define IPACCOUNT_H

#include <map>
#include <vector>
#include <string>

#include "sql_db.h"

void ipaccount(time_t, struct iphdr *, int, int);

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
	unsigned int ipfilter;
	unsigned int fetch_timestamp;
};

struct cust_cache_item {
	unsigned int cust_id;
	unsigned int add_timestamp;
};

struct cust_cache_rec {
	unsigned int ip;
	unsigned int cust_id;
	bool operator < (const cust_cache_rec& other) const { 
		return(this->ip < other.ip); 
	}
	bool operator < (const unsigned int& _ip) const { 
		return(this->ip < _ip); 
	}
};

class CustIpCache {
public:
	enum ModeCache {
		_mode_auto,
		_mode_map,
		_mode_vect
	};
	CustIpCache();
	~CustIpCache();
	void setConnectParams(const char *sqlDriver, const char *odbcDsn, const char *odbcUser, const char *odbcPassword, const char *odbcDriver);
	void setQueryes(const char *getIp, const char *fetchAllIp);
	int connect();
	bool okParams();
	int getCustByIp(unsigned int ip);
	int getCustByIpFromDb(unsigned int ip, bool saveToCache = false);
	int fetchAllIpQueryFromDb();
	int getCustByIpFromCacheMap(unsigned int ip);
	int getCustByIpFromCacheVect(unsigned int ip);
	void flush();
private:
	SqlDb *sqlDb;
	map<unsigned int, cust_cache_item> custCacheMap;
	vector<cust_cache_rec> custCacheVect;
	string sqlDriver;
	string odbcDsn;
	string odbcUser;
	string odbcPassword;
	string odbcDriver;
	string query_getIp;
	string query_fetchAllIp;
	unsigned int flushCounter;
};

#endif
