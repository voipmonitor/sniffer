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
#include "tools.h"

void ipaccount(time_t, struct iphdr2 *, int, int);

struct octects_t {
	octects_t() {
		octects = 0;
		numpackets = 0;
	}
	u_int32_t octects;
	u_int32_t numpackets;
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
	vector<vmIP> ipfilter;
	unsigned int fetch_timestamp;
	bool isIpInFilter(vmIP ip) {
		vector<vmIP>::iterator findIp;
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
		ip.clear();
		cust_id = 0;
	}
	vmIP ip;
	unsigned int cust_id;
	bool operator < (const cust_cache_rec& other) const { 
		return(this->ip < other.ip); 
	}
	bool operator < (const vmIP& _ip) const { 
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
		ip.clear();
		mask = 0;
	}
	vmIP ip;
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

struct t_ipacc_buffer_key {
	vmIP saddr;
	vmIP daddr;
	vmPort port; 
	int proto;
	bool voip;
	inline bool operator == (const t_ipacc_buffer_key& other) const {
		return(this->saddr == other.saddr &&
		       this->daddr == other.daddr &&
		       this->port == other.port &&
		       this->proto == other.proto && 
		       this->voip == other.voip);
	}
	inline bool operator < (const t_ipacc_buffer_key& other) const { 
		return(this->saddr < other.saddr ? 1 : this->saddr > other.saddr ? 0 :
		       this->daddr < other.daddr ? 1 : this->daddr > other.daddr ? 0 :
		       this->port < other.port ? 1 : this->port > other.port ? 0 :
		       this->proto < other.proto ? 1 : this->proto > other.proto ? 0 :
		       this->voip < other.voip);
	}
};

typedef map<t_ipacc_buffer_key, octects_t> t_ipacc_buffer; 

class Ipacc {
public:
	struct packet {
		time_t timestamp;
		vmIP saddr;
		vmIP daddr;
		vmPort port; 
		int proto;
		int packetlen;
		int voippacket;
		volatile int used;
	};
	struct s_ipacc_data {
		unsigned int interval_time;
		t_ipacc_buffer ipacc_buffer;
	};
	struct s_cache {
		s_cache() {
			custIpCache = NULL;
			nextIpCache = NULL;
			custPnCache = NULL;
			custIpCustomerCache = NULL;
			init();
		}
		~s_cache() {
			term();
		}
		class CustIpCache *custIpCache;
		class NextIpCache *nextIpCache;
		class CustPhoneNumberCache *custPnCache;
		class CustIpCustomerCache *custIpCustomerCache;
		void init();
		void term();
	};
	struct s_save_thread_data {
		pthread_t thread;
		int tid;
		pstat_data pstat[2];
		sem_t sem[2];
		s_ipacc_data *data;
		s_cache cache;
	};
public:
	Ipacc();
	~Ipacc();
	inline void push(time_t timestamp, vmIP saddr, vmIP daddr, vmPort port, int proto, int packetlen, int voippacket);
	void init();
	void term();
	int refreshCustIpCache();
	void save(unsigned int interval_time, t_ipacc_buffer *ipacc_buffer, s_cache *cache);
	inline void add_octets(time_t timestamp, vmIP saddr, vmIP daddr, vmPort port, int proto, int packetlen, int voippacket);
	unsigned int lengthBuffer();
	unsigned int sizeBuffer();
	class CustIpCache *getCustIpCache() {
		return(save_thread_data[0].cache.custIpCache);
	}
	class CustPhoneNumberCache *getCustPnCache() {
		return(save_thread_data[0].cache.custPnCache);
	}
	void startThread();
	void stopThread();
	string getCpuUsagePerc();
private:
	void *outThreadFunction();
	void lock_map_ipacc_data() {
		__SYNC_LOCK(map_ipacc_data_sync);
	}
	void unlock_map_ipacc_data() {
		__SYNC_UNLOCK(map_ipacc_data_sync);
	}
	void processSave_thread(int threadIndex);
	static void *_processSave_thread(void *_threadIndex);
private:
	map<unsigned int, s_ipacc_data*> map_ipacc_data;
	unsigned last_ipacc_time;
	s_ipacc_data *last_ipacc_data;
	volatile int map_ipacc_data_sync;
	unsigned map_ipacc_data_save_limit;
	SqlDb *sqlDbSave;
	packet *qring;
	unsigned int qringmax;
	volatile unsigned int readit;
	volatile unsigned int writeit;
	pthread_t out_thread_handle;
	int outThreadId;
	pstat_data threadPstatData[2];
	unsigned save_thread_count;
	s_save_thread_data *save_thread_data;
	int terminating_save_threads;
friend inline void *_Ipacc_outThreadFunction(void *arg);
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
		AgregIP(vmIP ip, unsigned int proto, vmPort port) {
			this->ip = ip;
			this->proto = proto;
			this->port = port;
		}
		vmIP ip;
		unsigned int proto;
		vmPort port;
		bool operator < (const AgregIP& other) const { 
			return((this->ip < other.ip) ? 1 : (this->ip > other.ip) ? 0 :
			       (this->proto < other.proto) ? 1 : (this->proto > other.proto) ? 0 :
			       (this->port < other.port));
		}
	};
	struct AgregIP2 {
		AgregIP2(vmIP ip1, vmIP ip2, unsigned int proto, vmPort port) {
			this->ip1 = ip1;
			this->ip2 = ip2;
			this->proto = proto;
			this->port = port;
		}
		vmIP ip1;
		vmIP ip2;
		unsigned int proto;
		vmPort port;
		bool operator < (const AgregIP2& other) const { 
			return((this->ip1 < other.ip1) ? 1 : (this->ip1 > other.ip1) ? 0 :
			       (this->ip2 < other.ip2) ? 1 : (this->ip2 > other.ip2) ? 0 :
			       (this->proto < other.proto) ? 1 : (this->proto > other.proto) ? 0 :
			       (this->port < other.port));
		}
	};
	struct AgregDataWithIP {
		vmIP ip;
		AgregData *data;
		static bool compare_traffic_desc(const AgregDataWithIP& first, const AgregDataWithIP& second) {
			return((first.data->traffic_in + first.data->traffic_out) >
			       (second.data->traffic_in + second.data->traffic_out));
		}
	};
	~IpaccAgreg();
	void add(vmIP src, vmIP dst,
		 unsigned int src_id_customer, unsigned int dst_id_customer,
		 bool src_ip_next, bool dst_ip_next,
		 unsigned int proto, vmPort port,
		 unsigned int traffic, unsigned int packets, bool voip);
	void save(unsigned int time_interval);
private:
	map<AgregIP, AgregData*> map1;
	map<AgregIP, map<vmIP, AgregData*> > map2;
};

class CustIpCache {
public:
	CustIpCache();
	~CustIpCache();
	void setConnectParams(const char *sqlDriver, const char *odbcDsn, const char *odbcUser, const char *odbcPassword, const char *odbcDriver);
	void setConnectParamsRadius(const char *radiusSqlDriver, const char *radiusHost, const char *radiusDb,const char *radiusUser, const char *radiusPassword, bool radiusDisableSecureAuth);
	void setQueryes(const char *getIp, const char *fetchAllIp);
	void setQueryesRadius(const char *fetchAllRadiusNames, const char *fetchAllRadiusIp, const char *fetchAllRadiusIpWhere);
	int connect();
	bool okParams();
	int getCustByIp(vmIP ip);
	int getCustByIpFromDb(vmIP ip, bool saveToCache = false);
	int fetchAllIpQueryFromDb();
	int getCustByIpFromCacheMap(vmIP ip);
	int getCustByIpFromCacheVect(vmIP ip);
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
	map<vmIP, cust_cache_item> custCacheMap;
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
	bool radiusDisableSecureAuth;
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
	bool isIn(vmIP ip);
	void fetch();
	void flush();
	void setMaxQueryPass(unsigned int maxQueryPass) {
		if(this->sqlDb) {
			this->sqlDb->setMaxQueryPass(maxQueryPass);
		}
	}
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
	cust_reseller getCustomerByPhoneNumber(const char *number);
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

class CustIpCustomerCache {
public: 
	struct customer {
		ListIP list_ip;
		u_int32_t id;
	};
public:
	CustIpCustomerCache();
	u_int32_t getCustomerId(vmIP ip);
	int load(bool useLock = false, bool exitIfLock = false);
	void _load(map<vmIP, u_int32_t> *custCacheMap, list<customer> *custCache);
	void flush();
private:
	void lock_cache() {
		while(__sync_lock_test_and_set(&this->cache_sync, 1));
	}
	void unlock_cache() {
		__sync_lock_release(&this->cache_sync);
	}
	void lock_load() {
		while(__sync_lock_test_and_set(&this->load_sync, 1));
	}
	void unlock_load() {
		__sync_lock_release(&this->load_sync);
	}
private:
	map<vmIP, u_int32_t> custCacheMap;
	list<customer> custCache;
	unsigned int flushCounter;
	volatile int cache_sync;
	volatile int load_sync;
};

CustIpCache *getCustIpCache();
CustPhoneNumberCache *getCustPnCache();
int refreshCustIpCache();
unsigned int lengthIpaccBuffer();
unsigned int sizeIpaccBuffer();
string getIpaccCpuUsagePerc();
void initIpacc();
void termIpacc();
void ipaccStartThread();
void ipaccStopThread();

#endif
