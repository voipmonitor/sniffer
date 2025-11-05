#ifndef RIBBONSBC_H
#define RIBBONSBC_H


#include "cloud_router/cloud_router_base.h"

#include "tools.h"


class cRibbonSbc_ProcessData : public cTimer {
public:
	cRibbonSbc_ProcessData();
	void processData(u_char *data, size_t dataLen, vmIP ip = 0, vmPort port = 0);
private:
	bool checkCompleteData(u_char *data, size_t dataLen);
	void createPacket(u_char *data, size_t dataLen,
			  vmIP src_ip, vmPort src_port, vmIP dst_ip, vmPort dst_port);
	void pushPacket(pcap_pkthdr *header, u_char *packet, unsigned dataLen, bool tcp,
			vmIP src_ip, vmPort src_port, vmIP dst_ip, vmPort dst_port,
			int dlink, int pcap_handle_index);
	void evTimer(u_int32_t time_s, int typeTimer, void *data);
	void block_store_lock() {
		__SYNC_LOCK_USLEEP(block_store_sync, 50);
	}
	void block_store_unlock() {
		__SYNC_UNLOCK(block_store_sync);
	}
private:
	SimpleBuffer data_buffer;
	unsigned data_buffer_add_counter;
	struct pcap_block_store *block_store;
	volatile int block_store_sync;
};
 
class cRibbonSbc_Server : public cServer, public cRibbonSbc_ProcessData {
public:
	cRibbonSbc_Server(bool udp);
	virtual ~cRibbonSbc_Server();
	void createConnection(cSocket *socket);
	void evData(u_char *data, size_t dataLen, vmIP ip, vmPort port, vmIP local_ip, vmPort local_port, cSocket *socket);
};

class cRibbonSbc_Connection : public cServerConnection, public cRibbonSbc_ProcessData {
public:
	cRibbonSbc_Connection(cSocket *socket);
	virtual ~cRibbonSbc_Connection();
	void evData(u_char *data, size_t dataLen);
	void connection_process();
};


class cRibbonSbcCounter {
public:
	void inc(vmIP ip) {
		lock();
		ip_counter[ip]++;
		unlock();
	}
	void reset() {
		lock();
		ip_counter.clear();
		unlock();
	}
	string get_ip_counter();
	u_int64_t get_sum_counter();
private:
	void lock() {
		__SYNC_LOCK(sync);
	}
	void unlock() {
		__SYNC_UNLOCK(sync);
	}
private:
	map<vmIP, u_int64_t> ip_counter;
	volatile int sync;
};


void RibbonSbc_ServerStart(const char *host, int port, bool udp);
void RibbonSbc_ServerStop();

void RibbonSbc_client_emulation(const char *pcap, vmIP client_ip, vmIP server_ip, vmIP destination_ip, vmPort destination_port, bool udp);


#endif //RIBBONSBC_H
