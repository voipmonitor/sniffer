#ifndef PCAP_REQCACHE_H
#define PCAP_REGCACHE_H


#include <memory.h>
#include <netdb.h>
#include <pthread.h>
#include <pcap.h>
#include <deque>
#include <queue>
#include <map>
#include <string>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/syscall.h>

using namespace std;

struct regcachenode_t {
	unsigned int timestamp;
	unsigned int counter;
};

typedef map<string, regcachenode_t> t_regcache_buffer;

class regcache {
public:
	t_regcache_buffer regcache_buffer;

	int check(unsigned int srcip, unsigned int dstip, unsigned int timestamp, unsigned int *count);
	
	void prune(unsigned int timestamp);
	
	~regcache();

};
#endif
