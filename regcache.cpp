#include <memory.h>
#include <netdb.h>
#include <pthread.h>
#include <pcap.h>
#include <deque>
#include <queue>
#include <string>
#include <sstream>
#include <vector>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/syscall.h>

#include "tools.h"
#include "regcache.h"
#include "voipmonitor.h"

using namespace std;

int
regcache::check(unsigned int saddr, unsigned int daddr, unsigned int timestamp, unsigned int *count) {

	char buf[32];
	sprintf(buf, "%uD%u", saddr, daddr);
	string key = buf;
	
	t_regcache_buffer::iterator iter;
	iter = regcache_buffer.find(key);
	if(iter != regcache_buffer.end()) {
		//found
		iter->second.counter++;
		*count = iter->second.counter;
		if(iter->second.timestamp + 1 <= timestamp) {
			iter->second.counter = 0;
			iter->second.timestamp = timestamp;
			return 0;
		} else {
			return 1;
		}
	} else {
		//not found
		regcachenode_t regcachenode;
		regcachenode.timestamp = timestamp;
		regcachenode.counter = 1;
		regcache_buffer[key] = regcachenode;
		*count = 1;

		return 0;
	}
}

void 
regcache::prune(unsigned int timestamp) {
	t_regcache_buffer::iterator iter;
	for(iter = regcache_buffer.begin(); iter != regcache_buffer.end();) {
		if(timestamp == 0 or timestamp > iter->second.timestamp + 5) {
			vector<std::string> res = split(iter->first, 'D');

			stringstream ts, cntr;
			ts << iter->second.timestamp;
			cntr << iter->second.counter;

			string query = string("UPDATE register_failed SET created_at = FROM_UNIXTIME(") + ts.str() + "), counter = counter + " + cntr.str() + " WHERE sipcallerip = " + res[0].c_str() + " AND sipcalledip = " + res[1].c_str() + " AND created_at >= SUBTIME(FROM_UNIXTIME(" + ts.str() + "), '01:00:00')"; 

			mysqlquerypush(query);

			regcache_buffer.erase(iter++);
		} else {
			iter++;
		}
	}
}

regcache::~regcache() {
	prune(0);
}
