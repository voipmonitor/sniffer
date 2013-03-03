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
#include <endian.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <syslog.h>
#include <semaphore.h>
#include <algorithm>

#include "ipaccount.h"
#include "flags.h"
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
extern int get_customer_by_ip_flush_period;

extern queue<string> mysqlquery;
extern pthread_mutex_t mysqlquery_lock;

extern SqlDb *sqlDb;

map<unsigned int, octects_live_t*> ipacc_live;

static map<string, octects_t*> ipacc_buffer;
static unsigned int last_flush_interval_time = 0;
static CustIpCache *custIpCache = NULL;


void ipacc_save(unsigned int interval_time_limit = 0) {
	if(custIpCache) {
		custIpCache->flush();
	} else {
		if(get_customer_by_ip_sql_driver[0]) {
			custIpCache = new CustIpCache;
			custIpCache->setConnectParams(
				get_customer_by_ip_sql_driver, 
				get_customer_by_ip_odbc_dsn, 
				get_customer_by_ip_odbc_user, 
				get_customer_by_ip_odbc_password, 
				get_customer_by_ip_odbc_driver);
			custIpCache->setQueryes(
				get_customer_by_ip_query, 
				get_customers_ip_query);
		}
	}
	
	octects_t *ipacc_data;
	char keycb[64], 
	     *keyc, *tmp;
	unsigned int saddr,
		     src_id_customer,
		     daddr,
		     dst_id_customer,
		     port,
		     proto;
	map<unsigned int,IpaccAgreg*> agreg;
	map<unsigned int, IpaccAgreg*>::iterator agregIter;
	char insertQueryBuff[1000];
	pthread_mutex_lock(&mysqlquery_lock);
	map<string, octects_t*>::iterator iter;
	for (iter = ipacc_buffer.begin(); iter != ipacc_buffer.end(); ++iter) {
		ipacc_data = iter->second;
		if(iter->second->octects > 0 && 
		   (!interval_time_limit ||  iter->second->interval_time <= interval_time_limit)) {
			
			strcpy(keycb, iter->first.c_str());
			keyc = keycb;
			
			tmp = strchr(keyc, 'D');
			*tmp = '\0';
			saddr = atol(keyc);
			src_id_customer = custIpCache ? custIpCache->getCustByIp(htonl(saddr)) : 0;

			keyc = tmp + 1;
			tmp = strchr(keyc, 'E');
			*tmp = '\0';
			daddr = atol(keyc);
			dst_id_customer = custIpCache ? custIpCache->getCustByIp(htonl(daddr)) : 0;

			keyc = tmp + 1;
			tmp = strchr(keyc, 'P');
			*tmp = '\0';
			port = atoi(keyc);

			keyc = tmp + 1;
			proto = atoi(keyc);

			if(!custIpCache || 
			   !opt_ipacc_agregate_only_customers_on_any_side ||
  			   src_id_customer || dst_id_customer) {
				if(isTypeDb("mysql")) {
					sprintf(insertQueryBuff,
						"insert into ipacc ("
							"interval_time, saddr, src_id_customer, daddr, dst_id_customer, proto, port, "
							"octects, numpackets, voip, do_agr_trigger"
						") values ("
							"'%s', %u, %u, %u, %u, %u, %u, %u, %u, %u, %u)",
						sqlDateTimeString(ipacc_data->interval_time).c_str(),
						saddr,
						src_id_customer,
						daddr,
						dst_id_customer,
						proto,
						port,
						ipacc_data->octects,
						ipacc_data->numpackets,
						ipacc_data->voippacket,
						opt_ipacc_sniffer_agregate ? 0 : 1);
					mysqlquery.push(insertQueryBuff);
					//sqlDb->query(insertQueryBuff);////
				} else {
					SqlDb_row row;
					row.add(sqlDateTimeString(ipacc_data->interval_time).c_str(), "interval_time");
					row.add(saddr, "saddr");
					if(src_id_customer) {
						row.add(src_id_customer, "src_id_customer");
					}
					row.add(daddr, "daddr");
					if(dst_id_customer) {
						row.add(dst_id_customer, "dst_id_customer");
					}
					row.add(proto, "proto");
					row.add(port, "port");
					row.add(ipacc_data->octects, "octects");
					row.add(ipacc_data->numpackets, "numpackets");
					row.add(ipacc_data->voippacket, "voip");
					row.add(opt_ipacc_sniffer_agregate ? 0 : 1, "do_agr_trigger");
					sqlDb->insert("ipacc", row);
				}
				
				if(opt_ipacc_sniffer_agregate) {
					agregIter = agreg.find(ipacc_data->interval_time);
					if(agregIter == agreg.end()) {
						agreg[ipacc_data->interval_time] = new IpaccAgreg;
						agregIter = agreg.find(ipacc_data->interval_time);
					}
					agregIter->second->add(
						saddr, daddr, 
						src_id_customer, dst_id_customer, 
						proto, port,
						ipacc_data->octects, ipacc_data->numpackets, ipacc_data->voippacket);
				}
			}
			
			//reset octects 
			iter->second->octects = 0;
			iter->second->numpackets = 0;
		}
	}
	if(opt_ipacc_sniffer_agregate) {
		for(agregIter = agreg.begin(); agregIter != agreg.end(); ++agregIter) {
			agregIter->second->save(agregIter->first);
			delete agregIter->second;
		}
	}
	pthread_mutex_unlock(&mysqlquery_lock);

	//printf("flush\n");
	
}

void ipacc_add_octets(time_t timestamp, unsigned int saddr, unsigned int daddr, int port, int proto, int packetlen, int voippacket) {
	string key;
	char buf[100];
	octects_t *ports;
	unsigned int cur_interval_time = timestamp / opt_ipacc_interval * opt_ipacc_interval;
	
	sprintf(buf, "%uD%uE%dP%d", htonl(saddr), htonl(daddr), port, proto);
	key = buf;

	if(last_flush_interval_time != cur_interval_time) {
		ipacc_save(last_flush_interval_time);
		last_flush_interval_time = cur_interval_time;
	}
	
	map<string, octects_t*>::iterator iter;
	iter = ipacc_buffer.find(key);
	if(iter == ipacc_buffer.end()) {
		// not found;
		ports = new octects_t;
		ports->octects += packetlen;
		ports->numpackets++;
		ports->interval_time = cur_interval_time;
		ports->voippacket = voippacket;
		ipacc_buffer[key] = ports;
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

	return;
	
	map<unsigned int, octects_live_t*>::iterator it;
	octects_live_t *data;
	for(it = ipacc_live.begin(); it != ipacc_live.end(); it++) {
		data = it->second;
		
		if((time(NULL) - data->fetch_timestamp) > 120) {
			if(verbosity > 0) {
				cout << "FORCE STOP LIVE IPACC id: " << it->first << endl; 
			}
			free(it->second);
			ipacc_live.erase(it);
		} else if(data->all) {
			data->all_octects += packetlen;
			data->all_numpackets++;
			if(voippacket) {
				data->voipall_octects += packetlen;
				data->voipall_numpackets++;
			}
		} else if(saddr == data->ipfilter) {
			data->src_octects += packetlen;
			data->src_numpackets++;
			if(voippacket) {
				data->voipsrc_octects += packetlen;
				data->voipsrc_numpackets++;
			}
		} else if(daddr == data->ipfilter) {
			data->dst_octects += packetlen;
			data->dst_numpackets++;
			if(voippacket) {
				data->voipdst_octects += packetlen;
				data->voipdst_numpackets++;
			}
		}
		//cout << saddr << "  " << daddr << "  " << port << "  " << proto << "   " << packetlen << endl;
	}
}

void ipaccount(time_t timestamp, struct iphdr *header_ip, int packetlen, int voippacket){
	struct udphdr2 *header_udp;
	struct tcphdr *header_tcp;

	if (header_ip->protocol == IPPROTO_UDP) {
		// prepare packet pointers 
		header_udp = (struct udphdr2 *) ((char *) header_ip + sizeof(*header_ip));

		if(ipaccountportmatrix[htons(header_udp->source)]) {
			ipacc_add_octets(timestamp, header_ip->saddr, header_ip->daddr, htons(header_udp->source), IPPROTO_TCP, packetlen, voippacket);
		} else if (ipaccountportmatrix[htons(header_udp->dest)]) {
			ipacc_add_octets(timestamp, header_ip->saddr, header_ip->daddr, htons(header_udp->dest), IPPROTO_TCP, packetlen, voippacket);
		} else {
			ipacc_add_octets(timestamp, header_ip->saddr, header_ip->daddr, 0, IPPROTO_TCP, packetlen, voippacket);
		}
	} else if (header_ip->protocol == IPPROTO_TCP) {
		header_tcp = (struct tcphdr *) ((char *) header_ip + sizeof(*header_ip));

		if(ipaccountportmatrix[htons(header_tcp->source)]) {
			ipacc_add_octets(timestamp, header_ip->saddr, header_ip->daddr, htons(header_tcp->source), IPPROTO_TCP, packetlen, voippacket);
		} else if (ipaccountportmatrix[htons(header_tcp->dest)]) {
			ipacc_add_octets(timestamp, header_ip->saddr, header_ip->daddr, htons(header_tcp->dest), IPPROTO_TCP, packetlen, voippacket);
		} else {
			ipacc_add_octets(timestamp, header_ip->saddr, header_ip->daddr, 0, IPPROTO_TCP, packetlen, voippacket);
		}
	} else {
		ipacc_add_octets(timestamp, header_ip->saddr, header_ip->daddr, 0, header_ip->protocol, packetlen, voippacket);
	}

}

IpaccAgreg::~IpaccAgreg() {
	map<AgregIP, AgregData*>::iterator iter1;
	for(iter1 = this->map1.begin(); iter1 != this->map1.end(); ++iter1) {
		delete iter1->second;
	}
	map<AgregIP2, AgregData*>::iterator iter2;
	for(iter2 = this->map2.begin(); iter2 != this->map2.end(); ++iter2) {
		delete iter2->second;
	}
}

void IpaccAgreg::add(unsigned int src, unsigned int dst,
		     unsigned int src_id_customer, unsigned int dst_id_customer,
		     unsigned int proto, unsigned int port,
		     unsigned int traffic, unsigned int packets, bool voip) {
	AgregIP srcA(src, proto, port), dstA(dst, proto, port);
	map<AgregIP, AgregData*>::iterator iter1;
	if(src_id_customer || !opt_ipacc_agregate_only_customers_on_main_side) {
		iter1 = this->map1.find(srcA);
		if(iter1 == this->map1.end()) {
			AgregData *agregData = new AgregData;
			agregData->id_customer = src_id_customer;
			agregData->addOut(traffic, packets, voip);
			this->map1[srcA] = agregData;
		} else {
			iter1->second->addOut(traffic, packets, voip);
		}
	}
	if(dst_id_customer || !opt_ipacc_agregate_only_customers_on_main_side) {
		iter1 = this->map1.find(dstA);
		if(iter1 == this->map1.end()) {
			AgregData *agregData = new AgregData;
			agregData->id_customer = dst_id_customer;
			agregData->addIn(traffic, packets, voip);
			this->map1[dstA] = agregData;
		} else {
			iter1->second->addIn(traffic, packets, voip);
		}
	}
	AgregIP2 srcDstA(src, dst, proto, port), dstSrcA(dst, src, proto, port);
	map<AgregIP2, AgregData*>::iterator iter2;
	if(src_id_customer || !opt_ipacc_agregate_only_customers_on_main_side) {
		iter2 = this->map2.find(srcDstA);
		if(iter2 == this->map2.end()) {
			AgregData *agregData = new AgregData;
			agregData->id_customer = src_id_customer;
			agregData->id_customer2 = dst_id_customer;
			agregData->addOut(traffic, packets, voip);
			this->map2[srcDstA] = agregData;
		} else {
			iter2->second->addOut(traffic, packets, voip);
		}
	}
	if(dst_id_customer || !opt_ipacc_agregate_only_customers_on_main_side) {
		iter2 = this->map2.find(dstSrcA);
		if(iter2 == this->map2.end()) {
			AgregData *agregData = new AgregData;
			agregData->id_customer = dst_id_customer;
			agregData->id_customer2 = src_id_customer;
			agregData->addIn(traffic, packets, voip);
			this->map2[dstSrcA] = agregData;
		} else {
			iter2->second->addIn(traffic, packets, voip);
		}
	}
}

void IpaccAgreg::save(unsigned int time_interval) {
	char insertQueryBuff[10000];
	const char *agreg_table;
	const char *agreg_time_field;
	char agreg_time[100];
	
	map<AgregIP, AgregData*>::iterator iter1;
	for(int i = 0; i < 2; i++) {
		agreg_table = i == 0 ? "ipacc_agr_hour" : "ipacc_agr_day";
		agreg_time_field = i == 0 ? "time_hour" : "date_day";
		strcpy(agreg_time,
		       i == 0 ?
				sqlDateTimeString(time_interval / 3600 * 3600).c_str() :
				sqlDateString(time_interval).c_str());
	for(iter1 = this->map1.begin(); iter1 != this->map1.end(); iter1++) {
		sprintf(insertQueryBuff,
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
				"addr = %u and customer_id = %u and "
				"proto = %u and port = %u; "
			"if(row_count() <= 0) then "
				"insert into %s ("
						"%s, addr, customer_id, proto, port, "
						"traffic_in, traffic_out, traffic_sum, "
						"packets_in, packets_out, packets_sum, "
						"traffic_voip_in, traffic_voip_out, traffic_voip_sum, "
						"packets_voip_in, packets_voip_out, packets_voip_sum"
					") values ("
						"'%s', %u, %u, %u, %u, "
						"%lu, %lu, %lu, "
						"%lu, %lu, %lu, "
						"%lu, %lu, %lu, "
						"%lu, %lu, %lu);"
			"end if",
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
			iter1->first.ip,
			iter1->second->id_customer,
			iter1->first.proto,
			iter1->first.port,
			agreg_table,
			agreg_time_field,
			agreg_time,
			iter1->first.ip,
			iter1->second->id_customer,
			iter1->first.proto,
			iter1->first.port,
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
		mysqlquery.push(insertQueryBuff);
		//sqlDb->query("drop procedure if exists __eee;");////
		//sqlDb->query(string("create procedure __eee() begin ") + insertQueryBuff + "; end;");////
		//sqlDb->query("call __eee();");////
	}}
	
	map<AgregIP2, AgregData*>::iterator iter2;
	for(int i = 0; i < 1; i++) {
		agreg_table = i == 0 ? "ipacc_agr2_hour" : "ipacc_agr2_day";
		agreg_time_field = i == 0 ? "time_hour" : "date_day";
		strcpy(agreg_time,
		       i == 0 ?
				sqlDateTimeString(time_interval / 3600 * 3600).c_str() :
				sqlDateString(time_interval).c_str());
	for(iter2 = this->map2.begin(); iter2 != this->map2.end(); iter2++) {
		sprintf(insertQueryBuff,
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
				"addr = %u and addr2 = %u  and customer_id = %u and "
				"proto = %u and port = %u; "
			"if(row_count() <= 0) then "
				"insert into %s ("
						"%s, addr, addr2, customer_id, proto, port, "
						"traffic_in, traffic_out, traffic_sum, "
						"packets_in, packets_out, packets_sum, "
						"traffic_voip_in, traffic_voip_out, traffic_voip_sum, "
						"packets_voip_in, packets_voip_out, packets_voip_sum"
					") values ("
						"'%s', %u, %u, %u, %u, %u, "
						"%lu, %lu, %lu, "
						"%lu, %lu, %lu, "
						"%lu, %lu, %lu, "
						"%lu, %lu, %lu);"
			"end if",
			agreg_table,
			iter2->second->traffic_in,
			iter2->second->traffic_out,
			iter2->second->traffic_in + iter2->second->traffic_out,
			iter2->second->packets_in,
			iter2->second->packets_out,
			iter2->second->packets_in + iter2->second->packets_out,
			iter2->second->traffic_voip_in,
			iter2->second->traffic_voip_out,
			iter2->second->traffic_voip_in + iter2->second->traffic_voip_out,
			iter2->second->packets_voip_in,
			iter2->second->packets_voip_out,
			iter2->second->packets_voip_in + iter2->second->packets_voip_out,
			agreg_time_field,
			agreg_time,
			iter2->first.ip1,
			iter2->first.ip2,
			iter2->second->id_customer,
			iter2->first.proto,
			iter2->first.port,
			agreg_table,
			agreg_time_field,
			agreg_time,
			iter2->first.ip1,
			iter2->first.ip2,
			iter2->second->id_customer,
			iter2->first.proto,
			iter2->first.port,
			iter2->second->traffic_in,
			iter2->second->traffic_out,
			iter2->second->traffic_in + iter2->second->traffic_out,
			iter2->second->packets_in,
			iter2->second->packets_out,
			iter2->second->packets_in + iter2->second->packets_out,
			iter2->second->traffic_voip_in,
			iter2->second->traffic_voip_out,
			iter2->second->traffic_voip_in + iter2->second->traffic_voip_out,
			iter2->second->packets_voip_in,
			iter2->second->packets_voip_out,
			iter2->second->packets_voip_in + iter2->second->packets_voip_out);
		mysqlquery.push(insertQueryBuff);
		//sqlDb->query("drop procedure if exists __eee;");////
		//sqlDb->query(string("create procedure __eee() begin ") + insertQueryBuff + "; end;");////
		//sqlDb->query("call __eee();");////
	}}
}

CustIpCache::CustIpCache() {
	this->sqlDb = NULL;
	this->flushCounter = 0;
}

CustIpCache::~CustIpCache() {
	if(this->sqlDb) {
		delete this->sqlDb;
	}
}

void CustIpCache::setConnectParams(const char *sqlDriver, const char *odbcDsn, const char *odbcUser, const char *odbcPassword, const char *odbcDriver) {
	if(sqlDriver) 		this->sqlDriver = sqlDriver;
	if(odbcDsn) 		this->odbcDsn = odbcDsn;
	if(odbcUser) 		this->odbcUser = odbcUser;
	if(odbcPassword)	this->odbcPassword = odbcPassword;
	if(odbcDriver) 		this->odbcDriver = odbcDriver;
}

void CustIpCache::setQueryes(const char *getIp, const char *fetchAllIp) {
	if(getIp)		this->query_getIp = getIp;
	if(fetchAllIp)		this->query_fetchAllIp = fetchAllIp;
}

int CustIpCache::connect() {
	if(!this->okParams()) {
		return(false);
	}
	if(!this->sqlDb) {
		SqlDb_odbc *sqlDb_odbc = new SqlDb_odbc();
		sqlDb_odbc->setOdbcVersion(SQL_OV_ODBC3);
		sqlDb_odbc->setSubtypeDb(this->odbcDriver);
		this->sqlDb = sqlDb_odbc;
		this->sqlDb->setConnectParameters(this->odbcDsn, this->odbcUser, this->odbcPassword);
	}
	return(this->sqlDb->connect());
}

bool CustIpCache::okParams() {
	return(this->sqlDriver.length() &&
	       this->odbcDsn.length() &&
	       this->odbcUser.length() &&
	       this->odbcDriver.length() &&
	       (this->query_getIp.length() ||
	        this->query_fetchAllIp.length()));
}

int CustIpCache::getCustByIp(unsigned int ip) {
	if(!this->okParams()) {
		return(0);
	}
	if(!this->sqlDb) {
		this->connect();
	}
	if(this->query_fetchAllIp.length()) {
		if(!this->custCacheVect.size()) {
			this->fetchAllIpQueryFromDb();
		}
		return(this->getCustByIpFromCacheVect(ip));
	} else {
		int cust_id = 0;
		cust_id = this->getCustByIpFromCacheMap(ip);
		if(cust_id < 0) {
			cust_id = this->getCustByIpFromDb(ip, true);
		}
		return(cust_id);
	}
}

int CustIpCache::getCustByIpFromDb(unsigned int ip, bool saveToCache) {
	if(!this->query_getIp.length()) {
		return(-1);
	}
	string query_str = this->query_getIp;
	size_t query_pos_ip = query_str.find("_IP_");
	if(query_pos_ip != std::string::npos) {
		int cust_id = 0;
		char ip_str[18];
		in_addr ips;
		ips.s_addr = ip;
		strcpy(ip_str, inet_ntoa(ips));
		query_str.replace(query_pos_ip, 4, ip_str);
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
	this->custCacheVect.clear();
	this->sqlDb->query(this->query_fetchAllIp);
	SqlDb_row row;
	while(row = sqlDb->fetchRow()) {
		cust_cache_rec rec;
		in_addr ips;
		inet_aton(row["IP"].c_str(), &ips);
		rec.ip = ips.s_addr;
		rec.cust_id = atol(row["ID"].c_str());
		this->custCacheVect.push_back(rec);
	}
	if(this->custCacheVect.size()) {
		std::sort(this->custCacheVect.begin(), this->custCacheVect.end());
	}
	if(verbosity > 0) {
		int _diff_time = time(NULL) - _start_time;
		cout << "IPACC load customers " << _diff_time << " s" << endl;
	}
	return(this->custCacheVect.size());
}

int CustIpCache::getCustByIpFromCacheMap(unsigned int ip) {
	cust_cache_item cache_rec = this->custCacheMap[ip];
	if((cache_rec.cust_id || cache_rec.add_timestamp) &&
	   (time(NULL) - cache_rec.add_timestamp) < 3600) {
		return(cache_rec.cust_id);
	}
	return(-1);
}

int CustIpCache::getCustByIpFromCacheVect(unsigned int ip) {
  	vector<cust_cache_rec>::iterator findRecIt;
  	findRecIt = std::lower_bound(this->custCacheVect.begin(), this->custCacheVect.end(), ip);
  	if((*findRecIt).ip == ip) {
  		return((*findRecIt).cust_id);
  	}
	return(0);
}

void CustIpCache::flush() {
	if(get_customer_by_ip_flush_period > 0&&
	   !(this->flushCounter%get_customer_by_ip_flush_period)) {
		this->custCacheMap.clear();
		this->custCacheVect.clear();
	}
	++this->flushCounter;
}

void freeMemIpacc() {
	if(custIpCache) {
		delete custIpCache;
	}
	map<string, octects_t*>::iterator iter;
	for(iter = ipacc_buffer.begin(); iter != ipacc_buffer.end(); ++iter) {
		delete iter->second;
	}
}
