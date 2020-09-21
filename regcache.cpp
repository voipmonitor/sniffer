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
#include "voipmonitor.h"

#ifdef FREEBSD
#include <machine/endian.h>
#else
#include <malloc.h>
#include <endian.h>
#endif

#include <sys/times.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <netinet/tcp.h>
#include <syslog.h>
#include <semaphore.h>

#include <sstream>

#include <pcap.h>


#include "tools.h"
#include "regcache.h"
#include "voipmonitor.h"
#include "sql_db.h"

using namespace std;

extern MySqlStore *sqlStore;
extern int opt_mysqlstore_max_threads_register;

int
regcache::check(vmIP saddr, vmIP daddr, unsigned int timestamp, unsigned int *count) {

	lock();

	d_item<vmIP> key(saddr, daddr);
	
	t_regcache_buffer::iterator iter;
	iter = regcache_buffer.find(key);
	if(iter != regcache_buffer.end()) {
		//found
		iter->second.counter++;
		*count = iter->second.counter;
		if(iter->second.timestamp + 60 <= timestamp) {
			iter->second.counter = 0;
			iter->second.timestamp = timestamp;
			unlock();
			return 0;
		} else {
			unlock();
			return 1;
		}
	} else {
		//not found
		regcachenode_t regcachenode;
		regcachenode.timestamp = timestamp;
		regcachenode.counter = 1;
		regcache_buffer[key] = regcachenode;
		*count = 1;

		unlock();
		return 0;
	}
	unlock();
	return 0;
}

void 
regcache::prune(unsigned int timestamp) {
	lock();
	t_regcache_buffer::iterator iter;
	for(iter = regcache_buffer.begin(); iter != regcache_buffer.end();) {
		if(timestamp == 0 or timestamp > iter->second.timestamp + 300) {

			stringstream ts, cntr;
			ts << iter->second.timestamp;
			cntr << iter->second.counter;

			string query = 
				string("UPDATE register_failed SET ") + 
				"created_at = FROM_UNIXTIME(" + ts.str() + "), " +
				"counter = counter + " + cntr.str() + " " + 
				"WHERE " + 
				"sipcallerip = " + iter->first.items[0].getStringForMysqlIpColumn("register_failed", "sipcallerip") + " AND " + 
				"sipcalledip = " + iter->first.items[1].getStringForMysqlIpColumn("register_failed", "sipcallerip") + " AND " + 
				"created_at >= SUBTIME(FROM_UNIXTIME(" + ts.str() + "), '01:00:00')"; 

			static unsigned int counterSqlStore = 0;
			sqlStore->query_lock(query.c_str(),
					     STORE_PROC_ID_REGISTER,
					     opt_mysqlstore_max_threads_register > 1 &&
					     sqlStore->getSize(STORE_PROC_ID_REGISTER, 0) > 1000 ? 
					      counterSqlStore % opt_mysqlstore_max_threads_register : 
					      0);
			++counterSqlStore;
			regcache_buffer.erase(iter++);
		} else {
			iter++;
		}
	}
	unlock();
}

void
regcache::prunecheck(unsigned int timestamp) {
	if(lastprune + 10 < timestamp) {
		prune(timestamp);
		lastprune = timestamp;
	}
}

regcache::~regcache() {
	prune(0);
	pthread_mutex_destroy(&buf_lock);
}
