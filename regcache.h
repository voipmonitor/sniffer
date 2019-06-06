#ifndef REGCACHE_H
#define REGCACHE_H


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
#include <pthread.h>

using namespace std;

struct regcachenode_t {
	unsigned int timestamp;
	unsigned int counter;
};

typedef map<d_item<vmIP>, regcachenode_t> t_regcache_buffer;

class regcache {
public:
	t_regcache_buffer regcache_buffer;
	pthread_mutex_t buf_lock;
	unsigned int lastprune;

	int check(vmIP srcip, vmIP dstip, unsigned int timestamp, unsigned int *count);
	
	void prune(unsigned int timestamp);
	void prunecheck(unsigned int timestmp);

//	void lock() { pthread_mutex_lock(&buf_lock); };
//	void unlock() { pthread_mutex_unlock(&buf_lock); };

	void lock() {}; // do nothing
	void unlock() {}; // do nothing

	regcache() { 
		pthread_mutex_init(&buf_lock, NULL);
		lastprune = 0;
	};
	~regcache();

};


#endif //REGCACHE_H
