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

#include <pcap.h>

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

extern "C" {
#include "liblfds.6/inc/liblfds.h"
}

using namespace std;

#ifndef MAX
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif

extern int calls;
extern int opt_saveSIP;	  	// save SIP packets to pcap file?
extern int opt_saveRTP;	 	// save RTP packets to pcap file?
extern int opt_saveRTCP;	// save RTCP packets to pcap file?
extern int opt_saveRAW;	 	
extern int opt_saveWAV;	 	
extern int opt_packetbuffered;	  // Make .pcap files writing ‘‘packet-buffered’’
extern int opt_rtcp;		  // Make .pcap files writing ‘‘packet-buffered’’
extern int verbosity;
extern int terminating;
extern int opt_rtp_firstleg;
extern int opt_sip_register;
extern int opt_norecord_header;
extern char *ipaccountmatrix;
extern pcap_t *handle;
extern read_thread *threads;
extern int opt_norecord_dtmf;
extern int opt_onlyRTPheader;
extern int opt_sipoverlap;
extern int readend;
extern int opt_dup_check;
extern char opt_match_header[128];
extern int opt_domainport;
extern int opt_mirrorip;
extern char opt_scanpcapdir[2048];

extern IPfilter *ipfilter;
extern IPfilter *ipfilter_reload;
extern int ipfilter_reload_do;

extern TELNUMfilter *telnumfilter;
extern TELNUMfilter *telnumfilter_reload;
extern int telnumfilter_reload_do;

extern int rtp_threaded;
extern int opt_pcap_threaded;

extern int opt_rtpnosip;
extern char opt_cachedir[1024];

extern int opt_savewav_force;
extern int opt_saveudptl;

extern nat_aliases_t nat_aliases;

extern pcap_packet *qring;
extern volatile unsigned int readit;
extern volatile unsigned int writeit;
extern unsigned int qringmax;

extern char *ipaccountportmatrix;
extern int opt_pcapdump;

extern char get_customer_by_ip_sql_driver[256];
extern char get_customer_by_ip_odbc_dsn[256];
extern char get_customer_by_ip_odbc_user[256];
extern char get_customer_by_ip_odbc_password[256];
extern char get_customer_by_ip_odbc_driver[256];
extern char get_customer_by_ip_query[1024];
extern char get_customers_ip_query[1024];
extern int get_customer_by_ip_flush_period;

typedef struct {
	unsigned int octects;
	unsigned int numpackets;
	unsigned int lasttimestamp;
	int voippacket;
} octects_t;

map<string, octects_t*> ipacc_protos;
map<string, octects_t*>::iterator ipacc_protosIT;

map<string, octects_t*> ipacc_ports;
map<string, octects_t*>::iterator ipacc_portsIT;

map<unsigned int, octects_live_t*> ipacc_live;

extern queue<string> mysqlquery;
extern pthread_mutex_t mysqlquery_lock;

unsigned int last_flush = 0;
unsigned int last_flush_ports = 0;

extern SqlDb *sqlDb;

extern int opt_ipacc_interval;

static CustIpCache *custIpCache = NULL;


void flush_octets_ports() {
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
	char *tmp;
	char keycb[64], *keyc;
	octects_t *proto;
	char buf[64];
	pthread_mutex_lock(&mysqlquery_lock);
	for (ipacc_portsIT = ipacc_ports.begin(); ipacc_portsIT != ipacc_ports.end(); ++ipacc_portsIT) {
		string query;
		proto = ipacc_portsIT->second;
		if(ipacc_portsIT->second->octects > 0) {
			SqlDb_row row;
			
			strcpy(keycb, ipacc_portsIT->first.c_str());
			keyc = keycb;
			
			tmp = strchr(keyc, 'D');
			*tmp = '\0';
			row.add(keyc, "saddr");
			if(custIpCache) {
				row.add(custIpCache->getCustByIp(htonl(atol(keyc))), "src_id_customer");
			}

			keyc = tmp + 1;
			tmp = strchr(keyc, 'E');
			*tmp = '\0';
			row.add(keyc, "daddr");
			if(custIpCache) {
				row.add(custIpCache->getCustByIp(htonl(atol(keyc))), "dst_id_customer");
			}

			keyc = tmp + 1;
			tmp = strchr(keyc, 'P');
			*tmp = '\0';
			row.add(keyc, "port");

			keyc = tmp + 1;
			row.add(keyc, "proto");

			row.add(proto->octects, "octects");
			row.add(sqlDateTimeString(proto->lasttimestamp * opt_ipacc_interval).c_str(), "interval_time");
			row.add(proto->numpackets, "numpackets");
			row.add(proto->voippacket, "voip");

			if(isTypeDb("mysql")) {
				mysqlquery.push(sqlDb->insertQuery("ipacc", row));
			} else {
				sqlDb->insert("ipacc", row);
			}
			//reset octects 
			ipacc_portsIT->second->octects = 0;
			ipacc_portsIT->second->numpackets = 0;
		}
	}
	pthread_mutex_unlock(&mysqlquery_lock);

	//printf("flush\n");
	
}

void add_octects_ipport(time_t timestamp, unsigned int saddr, unsigned int daddr, int port, int proto, int packetlen, int voippacket) {
	string key;
	char buf[100];
	octects_t *ports;
	unsigned int cur_interval = timestamp / opt_ipacc_interval;
	
	sprintf(buf, "%uD%uE%dP%d", htonl(saddr), htonl(daddr), port, proto);
	key = buf;

	if(last_flush_ports != cur_interval) {
		flush_octets_ports();
		//printf("%u | %u | %u | %u\n", timestamp, last_flush, cur_interval, timestamp / opt_ipacc_interval);
		last_flush_ports = cur_interval;
	}

	ipacc_portsIT = ipacc_ports.find(key);
	if(ipacc_portsIT == ipacc_ports.end()) {
		// not found;
		ports = (octects_t*)calloc(1, sizeof(octects_t));
		ports->octects += packetlen;
		ports->numpackets++;
		ports->lasttimestamp = timestamp / opt_ipacc_interval;
		ports->voippacket = voippacket;
		ipacc_ports[key] = ports;
//		printf("key: %s\n", buf);
	} else {
		//found
		octects_t *tmp = ipacc_portsIT->second;
		tmp->octects += packetlen;
		tmp->numpackets++;
		tmp->lasttimestamp = timestamp / opt_ipacc_interval;
		tmp->voippacket = voippacket;
//		printf("key[%s] %u\n", key.c_str(), tmp->octects);
	}

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
			add_octects_ipport(timestamp, header_ip->saddr, header_ip->daddr, htons(header_udp->source), IPPROTO_TCP, packetlen, voippacket);
		} else if (ipaccountportmatrix[htons(header_udp->dest)]) {
			add_octects_ipport(timestamp, header_ip->saddr, header_ip->daddr, htons(header_udp->dest), IPPROTO_TCP, packetlen, voippacket);
		} else {
			add_octects_ipport(timestamp, header_ip->saddr, header_ip->daddr, 0, IPPROTO_TCP, packetlen, voippacket);
		}
	} else if (header_ip->protocol == IPPROTO_TCP) {
		header_tcp = (struct tcphdr *) ((char *) header_ip + sizeof(*header_ip));

		if(ipaccountportmatrix[htons(header_tcp->source)]) {
			add_octects_ipport(timestamp, header_ip->saddr, header_ip->daddr, htons(header_tcp->source), IPPROTO_TCP, packetlen, voippacket);
		} else if (ipaccountportmatrix[htons(header_tcp->dest)]) {
			add_octects_ipport(timestamp, header_ip->saddr, header_ip->daddr, htons(header_tcp->dest), IPPROTO_TCP, packetlen, voippacket);
		} else {
			add_octects_ipport(timestamp, header_ip->saddr, header_ip->daddr, 0, IPPROTO_TCP, packetlen, voippacket);
		}
	} else {
		add_octects_ipport(timestamp, header_ip->saddr, header_ip->daddr, 0, header_ip->protocol, packetlen, voippacket);
	}

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
