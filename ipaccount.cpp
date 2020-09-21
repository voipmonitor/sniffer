/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

/*
This unit reads and parse packets from network interface or file 
and insert them into Call class. 

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <syslog.h>
#include <semaphore.h>
#include <algorithm>
#include <iomanip>

#include "ipaccount.h"
#include "codecs.h"
#include "calltable.h"
#include "sniff.h"
#include "voipmonitor.h"
#include "filter_mysql.h"
#include "hash.h"
#include "rtp.h"
#include "rtcp.h"
#include "md5.h"
#include "tools.h"
#include "mirrorip.h"
#include "sql_db.h"


using namespace std;

extern int verbosity;

extern char *ipaccountportmatrix;

extern int opt_ipacc_interval;
extern int opt_ipacc_only_agregation;
extern int opt_ipacc_enable_agregation_both_sides;
extern int opt_ipacc_limit_agregation_both_sides;
extern bool opt_ipacc_sniffer_agregate;
extern bool opt_ipacc_agregate_only_customers_on_main_side;
extern bool opt_ipacc_agregate_only_customers_on_any_side;
extern char get_customer_by_ip_sql_driver[256];
extern char get_customer_by_ip_odbc_dsn[256];
extern char get_customer_by_ip_odbc_user[256];
extern char get_customer_by_ip_odbc_password[256];
extern char get_customer_by_ip_odbc_driver[256];
extern char get_customer_by_ip_query[1024];
extern char get_customers_ip_query[1024];
extern char get_customers_radius_name_query[1024];
extern char get_customer_by_pn_sql_driver[256];
extern char get_customer_by_pn_odbc_dsn[256];
extern char get_customer_by_pn_odbc_user[256];
extern char get_customer_by_pn_odbc_password[256];
extern char get_customer_by_pn_odbc_driver[256];
extern char get_customers_pn_query[1024];
extern char get_radius_ip_driver[256];
extern char get_radius_ip_host[256];
extern char get_radius_ip_db[256];
extern char get_radius_ip_user[256];
extern char get_radius_ip_password[256];
extern bool get_radius_ip_disable_secure_auth;
extern char get_radius_ip_query[1024];
extern char get_radius_ip_query_where[1024];
extern int get_customer_by_ip_flush_period;
extern vector<string> opt_national_prefix;
extern int opt_mysqlstore_max_threads_ipacc_base;
extern int opt_mysqlstore_max_threads_ipacc_agreg2;

extern char mysql_host[256];
extern char mysql_database[256];
extern char mysql_user[256];
extern char mysql_password[256];
extern int opt_mysql_port;
extern char mysql_socket[256];
extern mysqlSSLOptions optMySsl;

extern MySqlStore *sqlStore;

typedef map<unsigned int, octects_live_t*> t_ipacc_live;
t_ipacc_live ipacc_live;

Ipacc *IPACC;

inline void *_Ipacc_outThreadFunction(void *arg) {
	return(((Ipacc*)arg)->outThreadFunction());
}

void Ipacc::s_cache::init() {
	if(get_customer_by_ip_sql_driver[0] && get_customer_by_ip_odbc_dsn[0]) {
		custIpCache = new FILE_LINE(12004) CustIpCache();
		custIpCache->setConnectParams(
			get_customer_by_ip_sql_driver, 
			get_customer_by_ip_odbc_dsn, 
			get_customer_by_ip_odbc_user, 
			get_customer_by_ip_odbc_password, 
			get_customer_by_ip_odbc_driver);
		custIpCache->setConnectParamsRadius(
			get_radius_ip_driver,
			get_radius_ip_host,
			get_radius_ip_db,
			get_radius_ip_user,
			get_radius_ip_password,
			get_radius_ip_disable_secure_auth);
		custIpCache->setQueryes(
			get_customer_by_ip_query, 
			get_customers_ip_query);
		custIpCache->setQueryesRadius(
			get_customers_radius_name_query, 
			get_radius_ip_query,
			get_radius_ip_query_where);
		custIpCache->connect();
		if(get_customers_ip_query[0]) {
			custIpCache->fetchAllIpQueryFromDb();
			custIpCache->setMaxQueryPass(2);
		}
	} else {
		custIpCustomerCache = new FILE_LINE(0) CustIpCustomerCache();
	}
	if(isSqlDriver("mysql")) {
		nextIpCache = new FILE_LINE(12005) NextIpCache();
		nextIpCache->connect();
		nextIpCache->fetch();
		nextIpCache->setMaxQueryPass(2);
	}
	if(get_customer_by_pn_sql_driver[0] && get_customer_by_pn_odbc_dsn[0]) {
		custPnCache = new FILE_LINE(12006) CustPhoneNumberCache();
		custPnCache->setConnectParams(
			get_customer_by_pn_sql_driver, 
			get_customer_by_pn_odbc_dsn, 
			get_customer_by_pn_odbc_user, 
			get_customer_by_pn_odbc_password, 
			get_customer_by_pn_odbc_driver);
		custPnCache->setQueryes(get_customers_pn_query);
		custPnCache->connect();
		if(get_customers_pn_query[0]) {
			custPnCache->fetchPhoneNumbersFromDb();
			custPnCache->setMaxQueryPass(2);
		}
	}
}

void Ipacc::s_cache::term() {
	if(custIpCache) {
		delete custIpCache;
	}
	if(nextIpCache) {
		delete nextIpCache;
	}
	if(custPnCache) {
		delete custPnCache;
	}
	if(custIpCustomerCache) {
		delete custIpCustomerCache;
	}
}

Ipacc::Ipacc() {
	sqlDbSave = NULL;
	map_ipacc_data_sync = 0;
	map_ipacc_data_save_limit = 2;
	last_ipacc_time = 0;
	last_ipacc_data = NULL;
	qringmax = 10000;
	readit = 0;
	writeit = 0;
	qring = new FILE_LINE(12001) packet[qringmax];
	for(unsigned int i = 0; i < qringmax; i++) {
		qring[i].used = 0;
	}
	memset(this->threadPstatData, 0, sizeof(this->threadPstatData));
	save_thread_count = 2;
	save_thread_data = new FILE_LINE(0) s_save_thread_data[save_thread_count];
	for(unsigned i = 0; i < save_thread_count; i++) {
		save_thread_data[i].tid = 0;
		save_thread_data[i].thread = 0;
		memset(save_thread_data[i].pstat, 0, sizeof(save_thread_data[i].pstat));
		save_thread_data[i].data = NULL;
	}
	terminating_save_threads = 0;
	init();
}

Ipacc::~Ipacc() {
	stopThread();
	delete [] qring;
	delete [] save_thread_data;
	term();
}

inline void Ipacc::push(time_t timestamp, vmIP saddr, vmIP daddr, vmPort port, int proto, int packetlen, int voippacket) {
	while(this->qring[this->writeit].used != 0) {
		USLEEP(10);
	}
	packet *_packet = &this->qring[this->writeit];
	_packet->timestamp = timestamp;
	_packet->saddr = saddr;
	_packet->daddr = daddr;
	_packet->port = port;
	_packet->proto = proto;
	_packet->packetlen = packetlen;
	_packet->voippacket = voippacket;
	_packet->used = 1;
	if((this->writeit + 1) == this->qringmax) {
		this->writeit = 0;
	} else {
		this->writeit++;
	}
}

void Ipacc::save(unsigned int interval_time, t_ipacc_buffer *ipacc_buffer, s_cache *cache) {
	if(cache->custIpCache) {
		cache->custIpCache->flush();
	}
	if(cache->nextIpCache) {
		cache->nextIpCache->flush();
	}
	if(cache->custPnCache) {
		cache->custPnCache->flush();
	}
	if(cache->custIpCustomerCache) {
		cache->custIpCustomerCache->flush();
	}
	unsigned int src_id_customer,
		     dst_id_customer;
	bool src_ip_next,
	     dst_ip_next;
	map<unsigned int,IpaccAgreg*> agreg;
	map<unsigned int, IpaccAgreg*>::iterator agregIter;
	char insertQueryBuff[1000];
	/*
	sqlStore->lock(STORE_PROC_ID_IPACC_1);
	if(opt_ipacc_sniffer_agregate) {
		for(int i = 1; i < opt_mysqlstore_max_threads_ipacc_base; i++) {
			sqlStore->lock(STORE_PROC_ID_IPACC_1 + i);
		}
	}
	*/
	int _counter  = 0;
	t_ipacc_buffer::iterator iter;
	for(iter = ipacc_buffer->begin(); iter != ipacc_buffer->end(); iter++) {
		if(iter->second.octects > 0) {
			src_id_customer = cache->custIpCache ? cache->custIpCache->getCustByIp(iter->first.saddr) : 
					  cache->custIpCustomerCache ? cache->custIpCustomerCache->getCustomerId(iter->first.saddr) : 0;
			src_ip_next = cache->nextIpCache ? cache->nextIpCache->isIn(iter->first.saddr) : false;
			dst_id_customer = cache->custIpCache ? cache->custIpCache->getCustByIp(iter->first.daddr) : 
					  cache->custIpCustomerCache ? cache->custIpCustomerCache->getCustomerId(iter->first.daddr) : 0;
			dst_ip_next = cache->nextIpCache ? cache->nextIpCache->isIn(iter->first.daddr) : false;
			if(!cache->custIpCache || 
			   !opt_ipacc_agregate_only_customers_on_any_side ||
  			   src_id_customer || dst_id_customer ||
			   src_ip_next || dst_ip_next) {
				if(!opt_ipacc_only_agregation) {
					if(isTypeDb("mysql")) {
						snprintf(insertQueryBuff, sizeof(insertQueryBuff),
							"insert into ipacc ("
								"interval_time, saddr, src_id_customer, daddr, dst_id_customer, proto, port, "
								"octects, numpackets, voip, do_agr_trigger"
							") values ("
								"'%s', %s, %u, %s, %u, %u, %u, %u, %u, %u, %u)",
							sqlDateTimeString(interval_time).c_str(),
							iter->first.saddr.getStringForMysqlIpColumn("ipacc", "saddr").c_str(),
							src_id_customer,
							iter->first.daddr.getStringForMysqlIpColumn("ipacc", "daddr").c_str(),
							dst_id_customer,
							iter->first.proto,
							iter->first.port.getPort(),
							iter->second.octects,
							iter->second.numpackets,
							iter->first.voip,
							opt_ipacc_sniffer_agregate ? 0 : 1);
						sqlStore->query_lock(insertQueryBuff, 
								     STORE_PROC_ID_IPACC,
								     opt_ipacc_sniffer_agregate ? _counter % opt_mysqlstore_max_threads_ipacc_base : 0);
					} else {
						SqlDb_row row;
						string ipacc_table = "ipacc";
						row.add(sqlDateTimeString(interval_time).c_str(), "interval_time");
						row.add(iter->first.saddr, "saddr", false, sqlDbSave, ipacc_table.c_str());
						if(src_id_customer) {
							row.add(src_id_customer, "src_id_customer");
						}
						row.add(iter->first.daddr, "daddr", false, sqlDbSave, ipacc_table.c_str());
						if(dst_id_customer) {
							row.add(dst_id_customer, "dst_id_customer");
						}
						row.add(iter->first.proto, "proto");
						row.add(iter->first.port.getPort(), "port");
						row.add(iter->second.octects, "octects");
						row.add(iter->second.numpackets, "numpackets");
						row.add(iter->first.voip, "voip");
						row.add(opt_ipacc_sniffer_agregate ? 0 : 1, "do_agr_trigger");
						sqlDbSave->insert(ipacc_table, row);
					}
				}
				++_counter;
				if(opt_ipacc_sniffer_agregate) {
					agregIter = agreg.find(interval_time);
					if(agregIter == agreg.end()) {
						agreg[interval_time] = new FILE_LINE(12002) IpaccAgreg;
						agregIter = agreg.find(interval_time);
					}
					agregIter->second->add(
						iter->first.saddr, iter->first.daddr, 
						src_id_customer, dst_id_customer, 
						src_ip_next, dst_ip_next,
						iter->first.proto, iter->first.port,
						iter->second.octects, iter->second.numpackets, iter->first.voip);
				}
			}
		}
	}
	/*
	sqlStore->unlock(STORE_PROC_ID_IPACC_1);
	if(opt_ipacc_sniffer_agregate) {
		for(int i = 1; i < opt_mysqlstore_max_threads_ipacc_base; i++) {
			sqlStore->unlock(STORE_PROC_ID_IPACC_1 + i);
		}
	}
	*/
	if(opt_ipacc_sniffer_agregate) {
		for(agregIter = agreg.begin(); agregIter != agreg.end(); ++agregIter) {
			agregIter->second->save(agregIter->first);
			delete agregIter->second;
		}
	}
	
	/*
	if(custIpCache) {
		custIpCache->flush();
	}
	if(nextIpCache) {
		nextIpCache->flush();
	}
	if(custPnCache) {
		custPnCache->flush();
	}
	if(custIpCustomerCache) {
		custIpCustomerCache->flush();
	}
	
	octects_t *ipacc_data;
	unsigned int src_id_customer,
		     dst_id_customer;
	bool src_ip_next,
	     dst_ip_next;
	map<unsigned int,IpaccAgreg*> agreg;
	map<unsigned int, IpaccAgreg*>::iterator agregIter;
	char insertQueryBuff[1000];
	sqlStore->lock(STORE_PROC_ID_IPACC_1);
	if(opt_ipacc_sniffer_agregate) {
		for(int i = 1; i < opt_mysqlstore_max_threads_ipacc_base; i++) {
			sqlStore->lock(STORE_PROC_ID_IPACC_1 + i);
		}
	}
	int _counter  = 0;
	bool enableClear = true;
	t_ipacc_buffer::iterator iter;
	for (iter = ipacc_buffer[indexIpaccBuffer].begin(); iter != ipacc_buffer[indexIpaccBuffer].end(); iter++) {
			
		ipacc_data = iter->second;
		if(ipacc_data->octects == 0) {
			ipacc_data->erase = true;
		} else if(!interval_time_limit ||  ipacc_data->interval_time <= interval_time_limit) {
			src_id_customer = custIpCache ? custIpCache->getCustByIp(iter->first.saddr) : 
					  custIpCustomerCache ? custIpCustomerCache->getCustomerId(iter->first.saddr) : 0;
			src_ip_next = nextIpCache ? nextIpCache->isIn(iter->first.saddr) : false;
			dst_id_customer = custIpCache ? custIpCache->getCustByIp(iter->first.daddr) : 
					  custIpCustomerCache ? custIpCustomerCache->getCustomerId(iter->first.daddr) : 0;
			dst_ip_next = nextIpCache ? nextIpCache->isIn(iter->first.daddr) : false;
			if(!custIpCache || 
			   !opt_ipacc_agregate_only_customers_on_any_side ||
  			   src_id_customer || dst_id_customer ||
			   src_ip_next || dst_ip_next) {
				if(!opt_ipacc_only_agregation) {
					if(isTypeDb("mysql")) {
						snprintf(insertQueryBuff, sizeof(insertQueryBuff),
							"insert into ipacc ("
								"interval_time, saddr, src_id_customer, daddr, dst_id_customer, proto, port, "
								"octects, numpackets, voip, do_agr_trigger"
							") values ("
								"'%s', %s, %u, %s, %u, %u, %u, %u, %u, %u, %u)",
							sqlDateTimeString(ipacc_data->interval_time).c_str(),
							iter->first.saddr.getStringForMysqlIpColumn("ipacc", "saddr").c_str(),
							src_id_customer,
							iter->first.daddr.getStringForMysqlIpColumn("ipacc", "daddr").c_str(),
							dst_id_customer,
							iter->first.proto,
							iter->first.port.getPort(),
							ipacc_data->octects,
							ipacc_data->numpackets,
							ipacc_data->voippacket,
							opt_ipacc_sniffer_agregate ? 0 : 1);
						sqlStore->query(insertQueryBuff, 
								STORE_PROC_ID_IPACC_1 + 
								(opt_ipacc_sniffer_agregate ? _counter % opt_mysqlstore_max_threads_ipacc_base : 0));
					} else {
						SqlDb_row row;
						string ipacc_table = "ipacc";
						row.add(sqlDateTimeString(ipacc_data->interval_time).c_str(), "interval_time");
						row.add(iter->first.saddr, "saddr", false, sqlDbSave, ipacc_table.c_str());
						if(src_id_customer) {
							row.add(src_id_customer, "src_id_customer");
						}
						row.add(iter->first.daddr, "daddr", false, sqlDbSave, ipacc_table.c_str());
						if(dst_id_customer) {
							row.add(dst_id_customer, "dst_id_customer");
						}
						row.add(iter->first.proto, "proto");
						row.add(iter->first.port.getPort(), "port");
						row.add(ipacc_data->octects, "octects");
						row.add(ipacc_data->numpackets, "numpackets");
						row.add(ipacc_data->voippacket, "voip");
						row.add(opt_ipacc_sniffer_agregate ? 0 : 1, "do_agr_trigger");
						sqlDbSave->insert(ipacc_table, row);
					}
				}
				++_counter;
				
				if(opt_ipacc_sniffer_agregate) {
					agregIter = agreg.find(ipacc_data->interval_time);
					if(agregIter == agreg.end()) {
						agreg[ipacc_data->interval_time] = new FILE_LINE(12002) IpaccAgreg;
						agregIter = agreg.find(ipacc_data->interval_time);
					}
					agregIter->second->add(
						iter->first.saddr, iter->first.daddr, 
						src_id_customer, dst_id_customer, 
						src_ip_next, dst_ip_next,
						iter->first.proto, iter->first.port,
						ipacc_data->octects, ipacc_data->numpackets, ipacc_data->voippacket);
				}
			}
			ipacc_data->erase = true;
		} else {
			enableClear = false;
		}
	}
	for (iter = ipacc_buffer[indexIpaccBuffer].begin(); iter != ipacc_buffer[indexIpaccBuffer].end();) {
		if(iter->second->erase) {
			delete iter->second;
			if(!enableClear) {
				ipacc_buffer[indexIpaccBuffer].erase(iter++);
				continue;
			}
		}
		iter++;
	}
	if(enableClear) {
		ipacc_buffer[indexIpaccBuffer].clear();
	}
	sqlStore->unlock(STORE_PROC_ID_IPACC_1);
	if(opt_ipacc_sniffer_agregate) {
		for(int i = 1; i < opt_mysqlstore_max_threads_ipacc_base; i++) {
			sqlStore->unlock(STORE_PROC_ID_IPACC_1 + i);
		}
	}
	if(opt_ipacc_sniffer_agregate) {
		for(agregIter = agreg.begin(); agregIter != agreg.end(); ++agregIter) {
			agregIter->second->save(agregIter->first);
			delete agregIter->second;
		}
	}
	
	__sync_sub_and_fetch(&sync_save_ipacc_buffer[indexIpaccBuffer], 1);
	
	//printf("flush\n");
	
	*/
}

inline void Ipacc::add_octets(time_t timestamp, vmIP saddr, vmIP daddr, vmPort port, int proto, int packetlen, int voippacket) {
	unsigned int cur_interval_time = timestamp / opt_ipacc_interval * opt_ipacc_interval;
	s_ipacc_data *ipacc_data;
	if(last_ipacc_time && last_ipacc_time == cur_interval_time) {
		ipacc_data = last_ipacc_data;
	} else {
		if(last_ipacc_time && cur_interval_time / opt_ipacc_interval <= last_ipacc_time / opt_ipacc_interval - map_ipacc_data_save_limit) {
			return;
		}
		lock_map_ipacc_data();
		map<unsigned int, s_ipacc_data*>::iterator iter = map_ipacc_data.find(cur_interval_time);
		if(iter != map_ipacc_data.end()) {
			ipacc_data = iter->second;
		} else {
			ipacc_data = new FILE_LINE(0) s_ipacc_data;
			ipacc_data->interval_time = cur_interval_time;
			map_ipacc_data[cur_interval_time] = ipacc_data;
			if(cur_interval_time > last_ipacc_time) {
				last_ipacc_time = cur_interval_time;
				last_ipacc_data = ipacc_data;
			}
		}
		unlock_map_ipacc_data();
	}
	t_ipacc_buffer_key key;
	key.saddr = saddr;
	key.daddr = daddr;
	key.port = port;
	key.proto = proto;
	key.voip = voippacket;
	t_ipacc_buffer::iterator iter = ipacc_data->ipacc_buffer.find(key);
	if(iter != ipacc_data->ipacc_buffer.end()) {
		iter->second.octects += packetlen;
		iter->second.numpackets++;
	} else {
		octects_t octects_data;
		octects_data.octects += packetlen;
		octects_data.numpackets++;
		ipacc_data->ipacc_buffer[key] = octects_data;
	}

	/*
	t_ipacc_buffer_key key;
	key.saddr = saddr;
	key.daddr = daddr;
	key.port = port;
	key.proto = proto;
	octects_t *octects_data;
	unsigned int cur_interval_time = timestamp / opt_ipacc_interval * opt_ipacc_interval;
	int indexIpaccBuffer = (cur_interval_time / opt_ipacc_interval) % 2;
	if(last_flush_interval_time != cur_interval_time &&
	   (timestamp - cur_interval_time) > opt_ipacc_interval / 5) {
		int saveIndexIpaccBuffer = indexIpaccBuffer == 0 ? 1 : 0;
		if(!__sync_fetch_and_add(&sync_save_ipacc_buffer[saveIndexIpaccBuffer], 1)) {
			last_flush_interval_time = cur_interval_time;
			save(saveIndexIpaccBuffer, last_flush_interval_time);
		}
	}
	t_ipacc_buffer::iterator iter;
	iter = ipacc_buffer[indexIpaccBuffer].find(key);
	if(iter == ipacc_buffer[indexIpaccBuffer].end()) {
		// not found;
		octects_data = new FILE_LINE(12003) octects_t;
		octects_data->octects += packetlen;
		octects_data->numpackets++;
		octects_data->interval_time = cur_interval_time;
		octects_data->voippacket = voippacket;
		ipacc_buffer[indexIpaccBuffer][key] = octects_data;
//		printf("key: %s\n", buf);
	} else {
		//found
		octects_t *tmp = iter->second;
		tmp->octects += packetlen;
		tmp->numpackets++;
		tmp->interval_time = cur_interval_time;
		tmp->voippacket = voippacket;
//		printf("key[%s] %u\n", key.c_str(), tmp->octects);
	}
	*/
}

unsigned int Ipacc::lengthBuffer() {
	unsigned int sum_size = 0;
	lock_map_ipacc_data();
	for(map<unsigned int, s_ipacc_data*>::iterator iter = map_ipacc_data.begin(); iter != map_ipacc_data.end(); iter++) {
		sum_size += iter->second->ipacc_buffer.size();
	}
	unlock_map_ipacc_data();
	return(sum_size);
}

unsigned int Ipacc::sizeBuffer() {
	return(map_ipacc_data.size());
}

void Ipacc::init() {
	sqlDbSave = createSqlObject();
}

void Ipacc::term() {
	for(map<unsigned int, s_ipacc_data*>::iterator iter = map_ipacc_data.begin(); iter != map_ipacc_data.end(); iter++) {
		delete iter->second;
	}
	delete sqlDbSave;
}

int Ipacc::refreshCustIpCache() {
	if(save_thread_data[0].cache.custIpCache) {
		save_thread_data[0].cache.custIpCache->clear();
		return(save_thread_data[0].cache.custIpCache->fetchAllIpQueryFromDb());
	}
	if(save_thread_data[0].cache.custIpCustomerCache) {
		return(save_thread_data[0].cache.custIpCustomerCache->load(true, true));
	}
	return(0);
}

string Ipacc::getCpuUsagePerc() {
	ostringstream outStr;
	outStr << fixed;
	double cpu = get_cpu_usage_perc(this->outThreadId, this->threadPstatData);
	if(cpu > 0) {
		outStr << setprecision(1) << cpu << "a%";
	}
	for(unsigned i = 0; i < save_thread_count; i++) {
		cpu = get_cpu_usage_perc(save_thread_data[i].tid, save_thread_data[i].pstat);
		if(cpu > 0) {
			if(outStr.str().length()) {
				outStr << "/";
			}
			outStr << setprecision(1) << cpu << "b%";
		}
	}
	return(outStr.str());
}

void Ipacc::startThread() {
	vm_pthread_create("ipaccount",
			  &this->out_thread_handle, NULL, _Ipacc_outThreadFunction, this, __FILE__, __LINE__);
	for(unsigned i = 0; i < save_thread_count; i++) {
		if(i > 0) {
			for(int j = 0; j < 2; j++) {
				sem_init(&save_thread_data[i].sem[j], 0, 0);
			}
		}
		vm_pthread_create((string("ipacc save - ") + (i == 0 ? "main thread" : "next thread " + intToString(i))).c_str(),
				  &save_thread_data[i].thread, NULL, _processSave_thread, (void*)(long)i, __FILE__, __LINE__);
	}
}

void Ipacc::stopThread() {
	terminating_save_threads = 1;
	pthread_join(save_thread_data[0].thread, NULL);
	for(unsigned i = 1; i < save_thread_count; i++) {
		sem_post(&save_thread_data[i].sem[0]);
		pthread_join(save_thread_data[i].thread, NULL);
		for(int j = 0; j < 2; j++) {
			sem_destroy(&save_thread_data[i].sem[j]);
		}
	}
}

void *Ipacc::outThreadFunction() {
	this->outThreadId = get_unix_tid();
	syslog(LOG_NOTICE, "start Ipacc out thread %i", this->outThreadId);
	while(!is_terminating()) {
		if(this->qring[this->readit].used == 1) {
			packet *_packet = &this->qring[this->readit];
			add_octets(_packet->timestamp, _packet->saddr, _packet->daddr, _packet->port, _packet->proto, _packet->packetlen, _packet->voippacket);
			_packet->used = 0;
			if((this->readit + 1) == this->qringmax) {
				this->readit = 0;
			} else {
				this->readit++;
			}
		} else {
			USLEEP(1000);
		}
	}
	return(NULL);
}

void Ipacc::processSave_thread(int threadIndex) {
	save_thread_data[threadIndex].tid = get_unix_tid();
	if(threadIndex == 0) {
		while(!terminating_save_threads) {
			unsigned map_ipacc_data_size = map_ipacc_data.size();
			if(map_ipacc_data_size <= map_ipacc_data_save_limit) {
				 USLEEP(100000);
				 continue;
			}
			for(unsigned i = 1; i < save_thread_count; i++) {
				save_thread_data[i].data = NULL;
			}
			lock_map_ipacc_data();
			unsigned data_counter = 0;
			for(map<unsigned int, s_ipacc_data*>::iterator iter = map_ipacc_data.begin(); iter != map_ipacc_data.end(); ) {
				save_thread_data[data_counter].data = iter->second;
				map_ipacc_data.erase(iter++);
				++data_counter;
				if(data_counter >= save_thread_count ||
				   data_counter >= map_ipacc_data_size - map_ipacc_data_save_limit) {
					break;
				}
			}
			unlock_map_ipacc_data();
			if(data_counter > 0) {
				if(data_counter > 1) {
					for(unsigned i = 1; i < data_counter; i++) {
						sem_post(&save_thread_data[i].sem[0]);
					}
				}
				save(save_thread_data[threadIndex].data->interval_time, 
				     &save_thread_data[threadIndex].data->ipacc_buffer, 
				     &save_thread_data[threadIndex].cache);
				delete save_thread_data[threadIndex].data;
				if(data_counter > 1) {
					for(unsigned i = 1; i < data_counter; i++) {
						sem_wait(&save_thread_data[i].sem[1]);
					}
				}
			} else {
				USLEEP(100000);
			}
		}
		terminating_save_threads = 2;
	} else {
		while(terminating_save_threads < 2) {
			sem_wait(&save_thread_data[threadIndex].sem[0]);
			if(terminating_save_threads == 2) {
				break;
			}
			save(save_thread_data[threadIndex].data->interval_time, 
			     &save_thread_data[threadIndex].data->ipacc_buffer, 
			     &save_thread_data[threadIndex].cache);
			delete save_thread_data[threadIndex].data;
			sem_post(&save_thread_data[threadIndex].sem[1]);
		}
	}
}

void *Ipacc::_processSave_thread(void *_threadIndex) {
	IPACC->processSave_thread((int)(long)_threadIndex);
	return(NULL);
}

inline void ipacc_add_octets(time_t timestamp, vmIP saddr, vmIP daddr, vmPort port, int proto, int packetlen, int voippacket) {
	IPACC->push(timestamp, saddr, daddr, port, proto, packetlen, voippacket);
 
	t_ipacc_live::iterator it;
	octects_live_t *data;
	for(it = ipacc_live.begin(); it != ipacc_live.end();) {
		data = it->second;
		if(!data) {
			it++;
			continue;
		}
		
		if((time(NULL) - data->fetch_timestamp) > 120) {
			if(verbosity > 0) {
				cout << "FORCE STOP LIVE IPACC id: " << it->first << endl; 
			}
			free(it->second);
			ipacc_live.erase(it++);
			continue;
		} else if(data->all) {
			data->all_octects += packetlen;
			data->all_numpackets++;
			if(voippacket) {
				data->voipall_octects += packetlen;
				data->voipall_numpackets++;
			}
		} else if(data->isIpInFilter(saddr)) {
			data->src_octects += packetlen;
			data->src_numpackets++;
			if(voippacket) {
				data->voipsrc_octects += packetlen;
				data->voipsrc_numpackets++;
			}
		} else if(data->isIpInFilter(daddr)) {
			data->dst_octects += packetlen;
			data->dst_numpackets++;
			if(voippacket) {
				data->voipdst_octects += packetlen;
				data->voipdst_numpackets++;
			}
		}
		it++;
		//cout << saddr << "  " << daddr << "  " << port << "  " << proto << "   " << packetlen << endl;
	}
}

void ipaccount(time_t timestamp, struct iphdr2 *header_ip, int packetlen, int voippacket){
	struct udphdr2 *header_udp;
	struct tcphdr2 *header_tcp;

	if (header_ip->get_protocol() == IPPROTO_UDP) {
		// prepare packet pointers 
		header_udp = (udphdr2 *)((char*)header_ip + header_ip->get_hdr_size());
		if(ipaccountportmatrix[header_udp->get_source()]) {
			ipacc_add_octets(timestamp, header_ip->get_saddr(), header_ip->get_daddr(), header_udp->get_source(), IPPROTO_TCP, packetlen, voippacket);
		} else if (ipaccountportmatrix[header_udp->get_dest()]) {
			ipacc_add_octets(timestamp, header_ip->get_saddr(), header_ip->get_daddr(), header_udp->get_dest(), IPPROTO_TCP, packetlen, voippacket);
		} else {
			ipacc_add_octets(timestamp, header_ip->get_saddr(), header_ip->get_daddr(), 0, IPPROTO_TCP, packetlen, voippacket);
		}
	} else if (header_ip->get_protocol() == IPPROTO_TCP) {
		header_tcp = (tcphdr2*)((char*)header_ip + header_ip->get_hdr_size());
		if(ipaccountportmatrix[header_tcp->get_source()]) {
			ipacc_add_octets(timestamp, header_ip->get_saddr(), header_ip->get_daddr(), header_tcp->get_source(), IPPROTO_TCP, packetlen, voippacket);
		} else if (ipaccountportmatrix[header_tcp->get_dest()]) {
			ipacc_add_octets(timestamp, header_ip->get_saddr(), header_ip->get_daddr(), header_tcp->get_dest(), IPPROTO_TCP, packetlen, voippacket);
		} else {
			ipacc_add_octets(timestamp, header_ip->get_saddr(), header_ip->get_daddr(), 0, IPPROTO_TCP, packetlen, voippacket);
		}
	} else {
		ipacc_add_octets(timestamp, header_ip->get_saddr(), header_ip->get_daddr(), 0, header_ip->get_protocol(), packetlen, voippacket);
	}

}

IpaccAgreg::~IpaccAgreg() {
	map<AgregIP, AgregData*>::iterator iter1;
	for(iter1 = this->map1.begin(); iter1 != this->map1.end(); ++iter1) {
		delete iter1->second;
	}
	map<AgregIP, map<vmIP, AgregData*> >::iterator iter21;
	map<vmIP, AgregData*>::iterator iter22;
	for(iter21 = this->map2.begin(); iter21 != this->map2.end(); ++iter21) {
		for(iter22 = iter21->second.begin(); iter22 != iter21->second.end(); ++iter22) {
			delete iter22->second;
		}
	}
}

void IpaccAgreg::add(vmIP src, vmIP dst,
		     unsigned int src_id_customer, unsigned int dst_id_customer,
		     bool src_ip_next, bool dst_ip_next,
		     unsigned int proto, vmPort port,
		     unsigned int traffic, unsigned int packets, bool voip) {
	AgregIP srcA(src, proto, port), dstA(dst, proto, port);
	map<AgregIP, AgregData*>::iterator iter1;
	if(src_id_customer || src_ip_next || !opt_ipacc_agregate_only_customers_on_main_side) {
		iter1 = this->map1.find(srcA);
		if(iter1 == this->map1.end()) {
			AgregData *agregData = new FILE_LINE(12007) AgregData;
			agregData->id_customer = src_id_customer;
			agregData->addOut(traffic, packets, voip);
			this->map1[srcA] = agregData;
		} else {
			iter1->second->addOut(traffic, packets, voip);
		}
	}
	if(dst_id_customer || dst_ip_next || !opt_ipacc_agregate_only_customers_on_main_side) {
		iter1 = this->map1.find(dstA);
		if(iter1 == this->map1.end()) {
			AgregData *agregData = new FILE_LINE(12008) AgregData;
			agregData->id_customer = dst_id_customer;
			agregData->addIn(traffic, packets, voip);
			this->map1[dstA] = agregData;
		} else {
			iter1->second->addIn(traffic, packets, voip);
		}
	}
	if(opt_ipacc_enable_agregation_both_sides) {
		if(src_id_customer || src_ip_next || !opt_ipacc_agregate_only_customers_on_main_side) {
			AgregIP srcA(src, proto, port);
			map<AgregIP, map<vmIP, AgregData*> >::iterator iter21;
			map<vmIP, AgregData*>::iterator iter22;
			if((iter21 = this->map2.find(srcA)) != this->map2.end() &&
			   (iter22 = iter21->second.find(dst)) != iter21->second.end()) {
				iter22->second->addOut(traffic, packets, voip);
			} else {
				AgregData *agregData = new FILE_LINE(12009) AgregData;
				agregData->id_customer = src_id_customer;
				agregData->id_customer2 = dst_id_customer;
				agregData->addOut(traffic, packets, voip);
				this->map2[srcA][dst] = agregData;
			}
		}
		if(dst_id_customer || dst_ip_next || !opt_ipacc_agregate_only_customers_on_main_side) {
			AgregIP dstA(dst, proto, port);
			map<AgregIP, map<vmIP, AgregData*> >::iterator iter21;
			map<vmIP, AgregData*>::iterator iter22;
			if((iter21 = this->map2.find(dstA)) != this->map2.end() &&
			   (iter22 = iter21->second.find(src)) != iter21->second.end()) {
				iter22->second->addIn(traffic, packets, voip);
			} else {
				AgregData *agregData = new FILE_LINE(12009) AgregData;
				agregData->id_customer = dst_id_customer;
				agregData->id_customer2 = src_id_customer;
				agregData->addIn(traffic, packets, voip);
				this->map2[dstA][src] = agregData;
			}
		}
		/*
		AgregIP2 srcDstA(src, dst, proto, port), dstSrcA(dst, src, proto, port);
		map<AgregIP2, AgregData*>::iterator iter2;
		if(src_id_customer || src_ip_next || !opt_ipacc_agregate_only_customers_on_main_side) {
			iter2 = this->map2.find(srcDstA);
			if(iter2 == this->map2.end()) {
				AgregData *agregData = new FILE_LINE(12009) AgregData;
				agregData->id_customer = src_id_customer;
				agregData->id_customer2 = dst_id_customer;
				agregData->addOut(traffic, packets, voip);
				this->map2[srcDstA] = agregData;
			} else {
				iter2->second->addOut(traffic, packets, voip);
			}
		}
		if(dst_id_customer || dst_ip_next || !opt_ipacc_agregate_only_customers_on_main_side) {
			iter2 = this->map2.find(dstSrcA);
			if(iter2 == this->map2.end()) {
				AgregData *agregData = new FILE_LINE(12010) AgregData;
				agregData->id_customer = dst_id_customer;
				agregData->id_customer2 = src_id_customer;
				agregData->addIn(traffic, packets, voip);
				this->map2[dstSrcA] = agregData;
			} else {
				iter2->second->addIn(traffic, packets, voip);
			}
		}
		*/
	}
}

void IpaccAgreg::save(unsigned int time_interval) {
	char insertQueryBuff[10000];
	const char *agreg_table;
	const char *agreg_time_field;
	char agreg_time[100];
	
	map<AgregIP, AgregData*>::iterator iter1;
	for(int i = 0; i < 3; i++) {
		agreg_table = 
			i == 0 ? "ipacc_agr_interval" :
			(i == 1 ? "ipacc_agr_hour" : "ipacc_agr_day");
		agreg_time_field = 
			i == 0 ? "interval_time" :
			(i == 1 ? "time_hour" : "date_day");
		strcpy(agreg_time,
			i == 0 ?
				sqlDateTimeString(time_interval).c_str() :
			(i == 1 ?
				sqlDateTimeString(time_interval / 3600 * 3600).c_str() :
				sqlDateString(time_interval).c_str()));
	/*
	sqlStore->lock(
		i == 0 ? STORE_PROC_ID_IPACC_AGR_INTERVAL :
		(i == 1 ? STORE_PROC_ID_IPACC_AGR_HOUR : STORE_PROC_ID_IPACC_AGR_DAY));
	*/
	for(iter1 = this->map1.begin(); iter1 != this->map1.end(); iter1++) {
		snprintf(insertQueryBuff, sizeof(insertQueryBuff),
			"set @i = 0; "
			"while @i < 2 do "
				"update %s set "
					"traffic_in = traffic_in + %lu, "
					"traffic_out = traffic_out + %lu, "
					"traffic_sum = traffic_sum + %lu, "
					"packets_in = packets_in + %lu, "
					"packets_out = packets_out + %lu, "
					"packets_sum = packets_sum + %lu, "
					"traffic_voip_in = traffic_voip_in + %lu, "
					"traffic_voip_out = traffic_voip_out + %lu, "
					"traffic_voip_sum = traffic_voip_sum + %lu, "
					"packets_voip_in = packets_voip_in + %lu, "
					"packets_voip_out = packets_voip_out + %lu, "
					"packets_voip_sum = packets_voip_sum + %lu "
				"where %s = '%s' and "
					"addr = %s and customer_id = %u and "
					"proto = %u and port = %u; "
				"if(row_count() <= 0 and @i = 0) then "
					"insert ignore into %s ("
							"%s, addr, customer_id, proto, port, "
							"traffic_in, traffic_out, traffic_sum, "
							"packets_in, packets_out, packets_sum, "
							"traffic_voip_in, traffic_voip_out, traffic_voip_sum, "
							"packets_voip_in, packets_voip_out, packets_voip_sum"
						") values ("
							"'%s', %s, %u, %u, %u, "
							"%lu, %lu, %lu, "
							"%lu, %lu, %lu, "
							"%lu, %lu, %lu, "
							"%lu, %lu, %lu);"
					"if(row_count() > 0) then "
						"set @i = 2; "
					"end if; "
				"else "
					"set @i = 2; "
				"end if; "
				"set @i = @i + 1; "
			"end while",
			agreg_table,
			iter1->second->traffic_in,
			iter1->second->traffic_out,
			iter1->second->traffic_in + iter1->second->traffic_out,
			iter1->second->packets_in,
			iter1->second->packets_out,
			iter1->second->packets_in + iter1->second->packets_out,
			iter1->second->traffic_voip_in,
			iter1->second->traffic_voip_out,
			iter1->second->traffic_voip_in + iter1->second->traffic_voip_out,
			iter1->second->packets_voip_in,
			iter1->second->packets_voip_out,
			iter1->second->packets_voip_in + iter1->second->packets_voip_out,
			agreg_time_field,
			agreg_time,
			iter1->first.ip.getStringForMysqlIpColumn(agreg_table, "addr").c_str(),
			iter1->second->id_customer,
			iter1->first.proto,
			iter1->first.port.getPort(),
			agreg_table,
			agreg_time_field,
			agreg_time,
			iter1->first.ip.getStringForMysqlIpColumn(agreg_table, "addr").c_str(),
			iter1->second->id_customer,
			iter1->first.proto,
			iter1->first.port.getPort(),
			iter1->second->traffic_in,
			iter1->second->traffic_out,
			iter1->second->traffic_in + iter1->second->traffic_out,
			iter1->second->packets_in,
			iter1->second->packets_out,
			iter1->second->packets_in + iter1->second->packets_out,
			iter1->second->traffic_voip_in,
			iter1->second->traffic_voip_out,
			iter1->second->traffic_voip_in + iter1->second->traffic_voip_out,
			iter1->second->packets_voip_in,
			iter1->second->packets_voip_out,
			iter1->second->packets_voip_in + iter1->second->packets_voip_out);
		sqlStore->query_lock(insertQueryBuff,
				     i == 0 ? STORE_PROC_ID_IPACC_AGR_INTERVAL :
				     (i == 1 ? STORE_PROC_ID_IPACC_AGR_HOUR : STORE_PROC_ID_IPACC_AGR_DAY),
				     0);
	}
	/*
	sqlStore->unlock(
		i == 0 ? STORE_PROC_ID_IPACC_AGR_INTERVAL :
		(i == 1 ? STORE_PROC_ID_IPACC_AGR_HOUR : STORE_PROC_ID_IPACC_AGR_DAY));
	*/
	}
	
	map<AgregIP, map<vmIP, AgregData*> >::iterator iter21;
	map<vmIP, AgregData*>::iterator iter22;
	agreg_table = "ipacc_agr2_hour";
	agreg_time_field = "time_hour";
	strcpy(agreg_time, sqlDateTimeString(time_interval / 3600 * 3600).c_str());
	/*
	for(int i = 0; i < opt_mysqlstore_max_threads_ipacc_agreg2; i++) {
		sqlStore->lock(STORE_PROC_ID_IPACC_AGR2_HOUR_1 + i);
	}
	*/
	int _counter = 0;
	for(iter21 = this->map2.begin(); iter21 != this->map2.end(); iter21++) {
		list<AgregDataWithIP> ad_ip;
		for(iter22 = iter21->second.begin(); iter22 != iter21->second.end(); ++iter22) {
			AgregDataWithIP ap_ip_item;
			ap_ip_item.ip = iter22->first;
			ap_ip_item.data = iter22->second;
			ad_ip.push_back(ap_ip_item);
		}
		ad_ip.sort(AgregDataWithIP::compare_traffic_desc);
		int _counter2 = 0;
		for(list<AgregDataWithIP>::iterator iter_data = ad_ip.begin(); iter_data != ad_ip.end(); iter_data++) {
			snprintf(insertQueryBuff, sizeof(insertQueryBuff),
				"set @i = 0; "
				"while @i < 2 do "
					"update %s set "
						"traffic_in = traffic_in + %lu, "
						"traffic_out = traffic_out + %lu, "
						"traffic_sum = traffic_sum + %lu, "
						"packets_in = packets_in + %lu, "
						"packets_out = packets_out + %lu, "
						"packets_sum = packets_sum + %lu, "
						"traffic_voip_in = traffic_voip_in + %lu, "
						"traffic_voip_out = traffic_voip_out + %lu, "
						"traffic_voip_sum = traffic_voip_sum + %lu, "
						"packets_voip_in = packets_voip_in + %lu, "
						"packets_voip_out = packets_voip_out + %lu, "
						"packets_voip_sum = packets_voip_sum + %lu "
					"where %s = '%s' and "
						"addr = %s and addr2 = %s  and customer_id = %u and "
						"proto = %u and port = %u; "
					"if(row_count() <= 0 and @i = 0) then "
						"insert ignore into %s ("
								"%s, addr, addr2, customer_id, proto, port, "
								"traffic_in, traffic_out, traffic_sum, "
								"packets_in, packets_out, packets_sum, "
								"traffic_voip_in, traffic_voip_out, traffic_voip_sum, "
								"packets_voip_in, packets_voip_out, packets_voip_sum"
							") values ("
								"'%s', %s, %s, %u, %u, %u, "
								"%lu, %lu, %lu, "
								"%lu, %lu, %lu, "
								"%lu, %lu, %lu, "
								"%lu, %lu, %lu);"
						"if(row_count() > 0) then "
							"set @i = 2; "
						"end if; "
					"else "
						"set @i = 2; "
					"end if; "
					"set @i = @i + 1; "
				"end while",
				agreg_table,
				iter_data->data->traffic_in,
				iter_data->data->traffic_out,
				iter_data->data->traffic_in + iter_data->data->traffic_out,
				iter_data->data->packets_in,
				iter_data->data->packets_out,
				iter_data->data->packets_in + iter_data->data->packets_out,
				iter_data->data->traffic_voip_in,
				iter_data->data->traffic_voip_out,
				iter_data->data->traffic_voip_in + iter_data->data->traffic_voip_out,
				iter_data->data->packets_voip_in,
				iter_data->data->packets_voip_out,
				iter_data->data->packets_voip_in + iter_data->data->packets_voip_out,
				agreg_time_field,
				agreg_time,
				iter21->first.ip.getStringForMysqlIpColumn(agreg_table, "addr").c_str(),
				iter_data->ip.getStringForMysqlIpColumn(agreg_table, "addr2").c_str(),
				iter_data->data->id_customer,
				iter21->first.proto,
				iter21->first.port.getPort(),
				agreg_table,
				agreg_time_field,
				agreg_time,
				iter21->first.ip.getStringForMysqlIpColumn(agreg_table, "addr").c_str(),
				iter_data->ip.getStringForMysqlIpColumn(agreg_table, "addr2").c_str(),
				iter_data->data->id_customer,
				iter21->first.proto,
				iter21->first.port.getPort(),
				iter_data->data->traffic_in,
				iter_data->data->traffic_out,
				iter_data->data->traffic_in + iter_data->data->traffic_out,
				iter_data->data->packets_in,
				iter_data->data->packets_out,
				iter_data->data->packets_in + iter_data->data->packets_out,
				iter_data->data->traffic_voip_in,
				iter_data->data->traffic_voip_out,
				iter_data->data->traffic_voip_in + iter_data->data->traffic_voip_out,
				iter_data->data->packets_voip_in,
				iter_data->data->packets_voip_out,
				iter_data->data->packets_voip_in + iter_data->data->packets_voip_out);
			sqlStore->query_lock(insertQueryBuff,
					     STORE_PROC_ID_IPACC_AGR2_HOUR,
					     (_counter % opt_mysqlstore_max_threads_ipacc_agreg2));
			++_counter;
			++_counter2;
			if(!opt_ipacc_limit_agregation_both_sides || _counter2 >= opt_ipacc_limit_agregation_both_sides) {
				break;
			}
		}
	}
	/*
	for(int i = 0; i < opt_mysqlstore_max_threads_ipacc_agreg2; i++) {
		sqlStore->unlock(STORE_PROC_ID_IPACC_AGR2_HOUR_1 + i);
	}
	*/
}

CustIpCache::CustIpCache() {
	this->sqlDb = NULL;
	this->sqlDbRadius = NULL;
	this->radiusDisableSecureAuth = false;
	this->flushCounter = 0;
	this->doFlushVect = false;
}

CustIpCache::~CustIpCache() {
	if(this->sqlDb) {
		delete this->sqlDb;
	}
	if(this->sqlDbRadius) {
		delete this->sqlDbRadius;
	}
}

void CustIpCache::setConnectParams(const char *sqlDriver, const char *odbcDsn, const char *odbcUser, const char *odbcPassword, const char *odbcDriver) {
	if(sqlDriver) 		this->sqlDriver = sqlDriver;
	if(odbcDsn) 		this->odbcDsn = odbcDsn;
	if(odbcUser) 		this->odbcUser = odbcUser;
	if(odbcPassword)	this->odbcPassword = odbcPassword;
	if(odbcDriver) 		this->odbcDriver = odbcDriver;
}

void CustIpCache::setConnectParamsRadius(const char *radiusSqlDriver, const char *radiusHost, const char *radiusDb,const char *radiusUser, const char *radiusPassword, bool radiusDisableSecureAuth) {
	if(radiusSqlDriver)	this->radiusSqlDriver = radiusSqlDriver;
	if(radiusHost)		this->radiusHost = radiusHost;
	if(radiusDb)		this->radiusDb = radiusDb;
	if(radiusUser)		this->radiusUser = radiusUser;
	if(radiusPassword)	this->radiusPassword = radiusPassword;
	this->radiusDisableSecureAuth = radiusDisableSecureAuth;
}

void CustIpCache::setQueryes(const char *getIp, const char *fetchAllIp) {
	if(getIp)		this->query_getIp = getIp;
	if(fetchAllIp)		this->query_fetchAllIp = fetchAllIp;
}

void CustIpCache::setQueryesRadius(const char *fetchAllRadiusNames, const char *fetchAllRadiusIp, const char *fetchAllRadiusIpWhere) {
	if(fetchAllRadiusNames)		this->query_fetchAllRadiusNames = fetchAllRadiusNames;
	if(fetchAllRadiusIp)		this->query_fetchAllRadiusIp = fetchAllRadiusIp;
	if(fetchAllRadiusIpWhere)	this->query_fetchAllRadiusIpWhere = fetchAllRadiusIpWhere;
}

int CustIpCache::connect() {
	if(!this->okParams()) {
		return(0);
	}
	if(!this->sqlDb) {
		SqlDb_odbc *sqlDb_odbc = new FILE_LINE(12011) SqlDb_odbc();
		sqlDb_odbc->setOdbcVersion(SQL_OV_ODBC3);
		sqlDb_odbc->setSubtypeDb(this->odbcDriver);
		this->sqlDb = sqlDb_odbc;
		this->sqlDb->setConnectParameters(this->odbcDsn, this->odbcUser, this->odbcPassword);
	}
	if(!this->sqlDbRadius && this->radiusHost.length()) {
		SqlDb_mysql *sqlDb_mysql = new FILE_LINE(12012) SqlDb_mysql();
		this->sqlDbRadius = sqlDb_mysql;
		this->sqlDbRadius->setConnectParameters(this->radiusHost, this->radiusUser, this->radiusPassword, this->radiusDb);
		if(this->radiusDisableSecureAuth) {
			this->sqlDbRadius->setDisableSecureAuth();
		}
	}
	return(this->sqlDb->connect() && 
	       (this->sqlDbRadius ? this->sqlDbRadius->connect() : true));
}

bool CustIpCache::okParams() {
	return(this->sqlDriver.length() &&
	       this->odbcDsn.length() &&
	       this->odbcUser.length() &&
	       this->odbcDriver.length() &&
	       (this->query_getIp.length() ||
	        this->query_fetchAllIp.length()));
}

int CustIpCache::getCustByIp(vmIP ip) {
	if(!this->okParams()) {
		return(0);
	}
	if(!this->sqlDb) {
		this->connect();
	}
	if(this->query_fetchAllIp.length()) {
		if(this->doFlushVect) {
			this->fetchAllIpQueryFromDb();
			this->doFlushVect = false;
		}
		if(!this->custCacheVect.size()) {
			return(0);
		}
		return(this->getCustByIpFromCacheVect(ip));
	} else if(this->query_getIp.length()) {
		int cust_id = 0;
		cust_id = this->getCustByIpFromCacheMap(ip);
		if(cust_id < 0) {
			cust_id = this->getCustByIpFromDb(ip, true);
		}
		return(cust_id);
	}
	return(0);
}

int CustIpCache::getCustByIpFromDb(vmIP ip, bool saveToCache) {
	if(!this->query_getIp.length()) {
		return(-1);
	}
	string query_str = this->query_getIp;
	size_t query_pos_ip = query_str.find("_IP_");
	if(query_pos_ip != std::string::npos) {
		int cust_id = 0;
		query_str.replace(query_pos_ip, 4, ip.getString());
		this->sqlDb->query(query_str);
		SqlDb_row row = sqlDb->fetchRow();
		if(row) {
			const char *cust_id_str = row["ID"].c_str();
			if(cust_id_str && cust_id_str[0]) {
				cust_id = atol(cust_id_str);
			}
		}
		if(saveToCache) {
			cust_cache_item cache_rec;
			cache_rec.cust_id = cust_id;
			cache_rec.add_timestamp = time(NULL);
			this->custCacheMap[ip] = cache_rec;
		}
		return(cust_id);
	} else {
		return(-1);
	}
}

int CustIpCache::fetchAllIpQueryFromDb() {
	if(!this->query_fetchAllIp.length()) {
		return(-1);
	}
	int _start_time = time(NULL);
	if(this->sqlDb->query(this->query_fetchAllIp)) {
		this->custCacheVect.clear();
		SqlDb_row row;
		while((row = this->sqlDb->fetchRow())) {
			cust_cache_rec rec;
			vmIP _ip;
			_ip.setFromString(row["IP"].c_str());
			rec.ip = _ip;
			rec.cust_id = atol(row["ID"].c_str());
			this->custCacheVect.push_back(rec);
		}
		if(this->sqlDbRadius && this->sqlDb->query(this->query_fetchAllRadiusNames)) {
			map<string, unsigned int> radiusUsers;
			string condRadiusUsers;
			SqlDb_row row;
			while((row = this->sqlDb->fetchRow())) {
				radiusUsers[row["radius_username"]] = atol(row["ID"].c_str());
				if(condRadiusUsers.length()) {
					condRadiusUsers += ",";
				}
				condRadiusUsers += string("'") + row["radius_username"] + "'";
			}
			if(radiusUsers.size() &&
			   this->sqlDbRadius->query(
					this->query_fetchAllRadiusIp + " " +
					this->query_fetchAllRadiusIpWhere + "(" + condRadiusUsers + ")")) {
				SqlDb_row row;
				while((row = this->sqlDbRadius->fetchRow())) {
					cust_cache_rec rec;
					vmIP _ip;
					_ip.setFromString(row["IP"].c_str());
					rec.ip = _ip;
					rec.cust_id = radiusUsers[row["radius_username"]];
					this->custCacheVect.push_back(rec);
				}
			}
		}
		if(this->custCacheVect.size()) {
			std::sort(this->custCacheVect.begin(), this->custCacheVect.end());
		}
		if(verbosity > 0) {
			int _diff_time = time(NULL) - _start_time;
			cout << "IPACC load customers " << _diff_time << " s" << endl;
		}
	}
	return(this->custCacheVect.size());
}

int CustIpCache::getCustByIpFromCacheMap(vmIP ip) {
	cust_cache_item cache_rec = this->custCacheMap[ip];
	if((cache_rec.cust_id || cache_rec.add_timestamp) &&
	   (time(NULL) - cache_rec.add_timestamp) < 3600) {
		return(cache_rec.cust_id);
	}
	return(-1);
}

int CustIpCache::getCustByIpFromCacheVect(vmIP ip) {
  	vector<cust_cache_rec>::iterator findRecIt;
  	findRecIt = std::lower_bound(this->custCacheVect.begin(), this->custCacheVect.end(), ip);
  	if(findRecIt != this->custCacheVect.end() && (*findRecIt).ip == ip) {
  		return((*findRecIt).cust_id);
  	}
	return(0);
}

void CustIpCache::flush() {
	if(get_customer_by_ip_flush_period > 0 && this->flushCounter > 0 &&
	   (get_customer_by_ip_flush_period == 1 ||
	    !(this->flushCounter % get_customer_by_ip_flush_period))) {
		this->custCacheMap.clear();
		this->doFlushVect = true;
	}
	++this->flushCounter;
}

void CustIpCache::clear() {
	this->custCacheVect.clear();
	this->custCacheMap.clear();
}

string CustIpCache::printVect() {
	string rslt;
	for(size_t i = 0; i < this->custCacheVect.size(); i++) {
		char rsltRec[100];
		snprintf(rsltRec, sizeof(rsltRec), "%s -> %u\n", this->custCacheVect[i].ip.getString().c_str(), this->custCacheVect[i].cust_id);
		rslt += rsltRec;
	}
	return(rslt);
}

NextIpCache::NextIpCache() {
	this->flushCounter = 0;
	this->doFlush = false;
}

NextIpCache::~NextIpCache() {
	if(this->sqlDb) {
		delete this->sqlDb;
	}
}

int NextIpCache::connect() {
	if(isSqlDriver("mysql")) {
		this->sqlDb = new FILE_LINE(12013) SqlDb_mysql();
		sqlDb->setConnectParameters(mysql_host, mysql_user, mysql_password, mysql_database, opt_mysql_port, mysql_socket, true, &optMySsl);
		return(this->sqlDb->connect());
	}
	return(0);
}

bool NextIpCache::isIn(vmIP ip) {
	if(this->doFlush) {
		this->fetch();
		this->doFlush = false;
	}
	if(!this->nextCache.size()) {
		return(false);
	}
	next_cache_rec rec;
	vector<next_cache_rec>::iterator findRecIt;
	for(unsigned int mask = 32; mask >= 16; --mask) {
		rec.ip = ip;
		rec.mask = mask;
		if(!rec.mask) {
			rec.mask = 32;
		}
		if(rec.mask < 32) {
			rec.ip = rec.ip.network(rec.mask);
		}
		findRecIt = std::lower_bound(this->nextCache.begin(), this->nextCache.end(), rec);
		if(findRecIt != this->nextCache.end() && (*findRecIt).ip == rec.ip) {
			//cout << endl << (*findRecIt).ip << "/" << mask << endl;
			return(true);
		}
	}
	return(false);
}

void NextIpCache::fetch() {
	if(!this->sqlDb->existsTable("ipacc_capt_ip")) {
		this->nextCache.clear();
		return;
	}
	if(this->sqlDb->query("select ip, mask from ipacc_capt_ip where enable")) {
		this->nextCache.clear();
		SqlDb_row row;
		while((row = this->sqlDb->fetchRow())) {
			next_cache_rec rec;
			rec.ip.setIP(&row, "ip");
			rec.mask = atol(row["mask"].c_str());
			if(!rec.mask) {
				rec.mask = 32;
			}
			if(rec.mask < 32) {
				rec.ip = rec.ip.network(rec.mask);
			}
			this->nextCache.push_back(rec);
		}
		if(this->nextCache.size()) {
			std::sort(this->nextCache.begin(), this->nextCache.end());
		}
		if(verbosity > 1) {
			cout << "IPACC load next IP" << endl;
		}
	}
}

void NextIpCache::flush() {
	if(get_customer_by_ip_flush_period > 0 && this->flushCounter > 0 &&
	   (get_customer_by_ip_flush_period == 1 ||
	    !(this->flushCounter % get_customer_by_ip_flush_period))) {
		this->doFlush = true;
	}
	++this->flushCounter;
}

CustPhoneNumberCache::CustPhoneNumberCache() {
	this->sqlDb = NULL;
	this->flushCounter = 0;
	this->doFlush = false;
}

CustPhoneNumberCache::~CustPhoneNumberCache() {
	if(this->sqlDb) {
		delete this->sqlDb;
	}
}

void CustPhoneNumberCache::setConnectParams(const char* sqlDriver, const char* odbcDsn, const char* odbcUser, const char* odbcPassword, const char* odbcDriver) {
	if(sqlDriver) 		this->sqlDriver = sqlDriver;
	if(odbcDsn) 		this->odbcDsn = odbcDsn;
	if(odbcUser) 		this->odbcUser = odbcUser;
	if(odbcPassword)	this->odbcPassword = odbcPassword;
	if(odbcDriver) 		this->odbcDriver = odbcDriver;
}

void CustPhoneNumberCache::setQueryes(const char* fetchPhoneNumbers) {
	this->query_fetchPhoneNumbers = fetchPhoneNumbers;
}

int CustPhoneNumberCache::connect() {
	if(!this->okParams()) {
		return(0);
	}
	if(!this->sqlDb) {
		SqlDb_odbc *sqlDb_odbc = new FILE_LINE(12014) SqlDb_odbc();
		sqlDb_odbc->setOdbcVersion(SQL_OV_ODBC3);
		sqlDb_odbc->setSubtypeDb(this->odbcDriver);
		this->sqlDb = sqlDb_odbc;
		this->sqlDb->setConnectParameters(this->odbcDsn, this->odbcUser, this->odbcPassword);
	}
	return(this->sqlDb->connect());
}

bool CustPhoneNumberCache::okParams() {
	return(this->sqlDriver.length() &&
	       this->odbcDsn.length() &&
	       this->odbcUser.length() &&
	       this->odbcDriver.length() &&
	       this->query_fetchPhoneNumbers.length());
}

cust_reseller CustPhoneNumberCache::getCustomerByPhoneNumber(char* number) {
	cust_reseller rslt;
	if(!this->okParams()) {
		return(rslt);
	}
	if(!this->sqlDb) {
		this->connect();
	}
	if(this->query_fetchPhoneNumbers.length()) {
		if(this->doFlush) {
			this->fetchPhoneNumbersFromDb();
			this->doFlush = false;
		}
		if(!this->custCache.size()) {
			return(rslt);
		}
		for(uint i = 0; i < opt_national_prefix.size() + 1; i++) {
			string findNumber = number;
			if(i > 0 && opt_national_prefix[i - 1] == findNumber.substr(0, opt_national_prefix[i - 1].length())) {
				findNumber = findNumber.substr(opt_national_prefix[i - 1].length());
			}
			vector<cust_pn_cache_rec>::iterator findRecIt;
			findRecIt = std::lower_bound(this->custCache.begin(), this->custCache.end(), findNumber);
			if(findRecIt != this->custCache.end() && (*findRecIt).cust_id) {
				if(findRecIt != this->custCache.begin() && (*findRecIt).numberFrom > findNumber) {
					--findRecIt;
				}
				if((*findRecIt).cust_id && (*findRecIt).numberFrom <= findNumber && 
				   (*findRecIt).numberTo >= findNumber.substr(0, (*findRecIt).numberTo.length())) {
					rslt.cust_id = (*findRecIt).cust_id;
					rslt.reseller_id = (*findRecIt).reseller_id;
					break;
				}
			}
		}
	}
	return(rslt);
}

int CustPhoneNumberCache::fetchPhoneNumbersFromDb() {
	if(!this->query_fetchPhoneNumbers.length()) {
		return(-1);
	}
	int _start_time = time(NULL);
	if(this->sqlDb->query(this->query_fetchPhoneNumbers)) {
		this->custCache.clear();
		SqlDb_row row;
		while((row = this->sqlDb->fetchRow())) {
			cust_pn_cache_rec rec;
			rec.numberFrom = row["numberFrom"];
			rec.numberTo = row["numberTo"];
			rec.cust_id = atol(row["cust_id"].c_str());
			rec.reseller_id = row["reseller_id"];
			this->custCache.push_back(rec);
		}
		if(this->custCache.size()) {
			std::sort(this->custCache.begin(), this->custCache.end());
		}
		if(verbosity > 0) {
			int _diff_time = time(NULL) - _start_time;
			cout << "CDR load customers phone numbers " << _diff_time << " s" << endl;
		}
	}
	return(this->custCache.size());
}

void CustPhoneNumberCache::flush() {
	if(get_customer_by_ip_flush_period > 0 && this->flushCounter > 0 &&
	   (get_customer_by_ip_flush_period == 1 ||
	    !(this->flushCounter % get_customer_by_ip_flush_period))) {
		this->doFlush = true;
	}
	++this->flushCounter;
}

CustIpCustomerCache::CustIpCustomerCache() {
	flushCounter = 0;
	cache_sync = 0;
	load_sync = 0;
}

u_int32_t CustIpCustomerCache::getCustomerId(vmIP ip) {
	u_int32_t rslt = 0;
	lock_cache();
	if(custCacheMap.size()) {
		map<vmIP, u_int32_t>::iterator iter = custCacheMap.find(ip);
		if(iter != custCacheMap.end()) {
			rslt = iter->second;
		}
	}
	if(!rslt && custCache.size()) {
		for(list<customer>::iterator iter = custCache.begin(); iter != custCache.end(); iter++) {
			if(iter->list_ip.checkIP(ip)) {
				rslt = iter->id;
				break;
			}
		}
	}
	unlock_cache();
	return(rslt);
}

int CustIpCustomerCache::load(bool useLock, bool exitIfLock) {
	if(useLock) {
		if(exitIfLock && load_sync) {
			return(-1);
		}
		lock_load();
	}
	map<vmIP, u_int32_t> custCacheMap;
	list<customer> custCache;
	_load(&custCacheMap, &custCache);
	lock_cache();
	this->custCacheMap = custCacheMap;
	this->custCache = custCache;
	unlock_cache();
	if(useLock) {
		unlock_load();
	}
	return(custCache.size());
}

void CustIpCustomerCache::_load(map<vmIP, u_int32_t> *custCacheMap, list<customer> *custCache) {
	SqlDb *sqlDb = createSqlObject();
	for(int pass = 0; pass < 2; pass++) {
		string customers_table = "cust_customers";
		string users_table = "users";
		string table;
		if(pass == 0) {
			if(sqlDb->existsTable(customers_table) && !sqlDb->emptyTable(customers_table)) {
				table = customers_table;
			}
		} else {
			if(sqlDb->existsTable(users_table) && !sqlDb->emptyTable(users_table) &&
			   sqlDb->existsColumn(users_table, "customer_id")) {
				table = users_table;
			}
		}
		if(table.empty()) {
			continue;
		}
		custCacheMap->clear();
		custCache->clear();
		sqlDb->query("select ip, customer_id, id from " + table + " where ip is not null and trim(ip) <> ''");
		SqlDb_row row;
		while((row = sqlDb->fetchRow())) {
			u_int32_t customer_id = atol(row["customer_id"].c_str());
			if(!customer_id) {
				customer_id = atol(row["id"].c_str());;
			}
			ListIP list_ip;
			list_ip.add(row["ip"].c_str());
			customer cust;
			cust.list_ip = list_ip;
			cust.id = customer_id;
			custCache->push_back(cust);
			vector<IP> *vect_ip = list_ip.get_list_ip();
			for(vector<IP>::iterator iter = vect_ip->begin(); iter != vect_ip->end(); iter++) {
				(*custCacheMap)[iter->ip] = customer_id;
			}
		}
		if(custCache->size()) {
			break;
		}
	}
	delete sqlDb;
}

void CustIpCustomerCache::flush() {
	if(get_customer_by_ip_flush_period > 0 && this->flushCounter > 0 &&
	   (get_customer_by_ip_flush_period == 1 ||
	    !(this->flushCounter % get_customer_by_ip_flush_period))) {
		this->load(true, true);
	}
	++this->flushCounter;
}

void octects_live_t::setFilter(const char *ipfilter) {
	string temp_ipfilter = ipfilter;
	char *ip = (char*)temp_ipfilter.c_str();
	while(ip && *ip) {
		char *separator = strchr(ip, ',');
		if(separator) {
			*separator = '\0';
		}
		vmIP _ip;
		_ip.setFromString(ip);
		this->ipfilter.push_back(_ip);
		if(separator) {
			ip = separator + 1;
		} else {
			ip = NULL;
		}
	}
	std::sort(this->ipfilter.begin(), this->ipfilter.end());
}

CustIpCache *getCustIpCache() {
	return(IPACC ? IPACC->getCustIpCache() : NULL);
}

CustPhoneNumberCache *getCustPnCache() {
	return(IPACC ? IPACC->getCustPnCache() : NULL);
}

int refreshCustIpCache() {
	return(IPACC ? IPACC->refreshCustIpCache() : 0);
}

unsigned int lengthIpaccBuffer() {
	return(IPACC ? IPACC->lengthBuffer() : 0);
}

unsigned int sizeIpaccBuffer() {
	return(IPACC ? IPACC->sizeBuffer() : 0);
}

string getIpaccCpuUsagePerc() {
	if(IPACC) {
		return(IPACC->getCpuUsagePerc());
	}
	return("");
}

void initIpacc() {
	IPACC = new FILE_LINE(12015) Ipacc;
}

void termIpacc() {
	delete IPACC;
}

void ipaccStartThread() {
	if(IPACC) {
		IPACC->startThread();
	}
}

void ipaccStopThread() {
	if(IPACC) {
		IPACC->stopThread();
	}
}
