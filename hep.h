#ifndef HEP_H
#define HEP_H


#include "cloud_router/cloud_router_base.h"

#include "tools.h"


enum eHEP_ProtocolType {
	_hep_prot_SIP = 0x01,
	_hep_prot_XMPP = 0x02,
	_hep_prot_SDP = 0x03,
	_hep_prot_RTP = 0x04,
	_hep_prot_RTCP_JSON = 0x05,
	_hep_prot_MGCP = 0x06,
	_hep_prot_MEGACO = 0x07,
	_hep_prot_M2UA = 0x08,
	_hep_prot_M3UA = 0x09,
	_hep_prot_IAX = 0x0a,
	_hep_prot_H3222 = 0x0b,
	_hep_prot_H321 = 0x0c,
	_hep_prot_M2PA = 0x0d,
	_hep_prot_MOS_full_report_JSON = 0x22,
	_hep_prot_MOS_short_report = 0x23,
	_hep_prot_SIP_JSON = 0x32,
	_hep_prot_DNS_JSON = 0x35,
	_hep_prot_M3UA_ISUP_JSON = 0x36,
	_hep_prot_RTSP = 0x37,
	_hep_prot_DIAMETER = 0x38,
	_hep_prot_GSM_MAP = 0x39,
	_hep_prot_RTCP_PION = 0x3a,
	_hep_prot_CDR =	0x3c
};

enum eHEP_VendorType {
	_hep_vendor_FreeSWITCH = 1,
	_hep_vendor_Kamailio = 2,
	_hep_vendor_OpenSIPS = 3,
	_hep_vendor_Asterisk = 4,
	_hep_vendor_Homer = 5,
	_hep_vendor_SipXecs = 6,
	_hep_vendor_Yeti = 7,
	_hep_vendor_Genesys = 8
};

enum eHEP_ChunkType {
	_hep_chunk_ip_protocol_family = 0x01,
	_hep_chunk_ip_protocol_id = 0x02,
	_hep_chunk_ip_source_address_v4 = 0x03,
	_hep_chunk_ip_destination_address_v4 = 0x04,
	_hep_chunk_ip_source_address_v6 = 0x05,
	_hep_chunk_ip_destination_address_v6 = 0x06,
	_hep_chunk_protocol_source_port = 0x07,
	_hep_chunk_protocol_destination_port = 0x08,
	_hep_chunk_timestamp_seconds = 0x09,
	_hep_chunk_timestamp_microseconds = 0x0a,
	_hep_chunk_protocol_type = 0x0b,
	_hep_chunk_capture_agent_id = 0x0c,
	_hep_chunk_keep_alive_timer = 0x0d,
	_hep_chunk_authenticate_key = 0x0e,
	_hep_chunk_captured_packet_payload = 0x0f,
	_hep_chunk_captured_packet_payload_compressed = 0x10,
	_hep_chunk_internal_correlation_id = 0x11,
	_hep_chunk_vlan_id = 0x12,
	_hep_chunk_group_id = 0x13,
	_hep_chunk_source_mac = 0x14,
	_hep_chunk_destination_mac = 0x15,
	_hep_chunk_ethernet_type = 0x16,
	_hep_chunk_tcp_flag = 0x17,
	_hep_chunk_ip_tos = 0x18,
	_hep_chunk_mos_value = 0x20,
	_hep_chunk_r_factor = 0x21,
	_hep_chunk_geo_location = 0x22,
	_hep_chunk_jitter = 0x23,
	_hep_chunk_transaction_type = 0x24,
	_hep_chunk_payload_json_keys = 0x25,
	_hep_chunk_tags_values = 0x26,
	_hep_chunk_tag_type = 0x27
};

struct sHEP_Data {
	inline sHEP_Data() {
		set_flags = 0;
	}
	string dump();
	u_int64_t set_flags;
	u_int8_t ip_protocol_family;
	u_int8_t ip_protocol_id;
	vmIP ip_source_address;
	vmIP ip_destination_address;
	vmPort protocol_source_port;
	vmPort protocol_destination_port;
	u_int32_t timestamp_seconds;
	u_int32_t timestamp_microseconds;
	u_int8_t protocol_type;
	u_int32_t capture_agent_id;
	u_int16_t keep_alive_timer;
	SimpleBuffer authenticate_key;
	SimpleBuffer captured_packet_payload;
	//SimpleBuffer captured_compressed_payload;
	SimpleBuffer internal_correlation_id;
	u_int16_t vlan_id;
	SimpleBuffer group_id;
	u_int64_t source_mac;
	u_int64_t destination_mac;
	u_int16_t ethernet_type;
	u_int8_t tcp_flag;
	u_int8_t ip_tos;
	u_int16_t mos_value;
	u_int16_t r_factor;
	SimpleBuffer geo_location;
	u_int32_t jitter;
	SimpleBuffer transaction_type;
	SimpleBuffer payload_json_keys;
	SimpleBuffer tags_values;
	u_int16_t tag_type;
};

class cHEP_ProcessData : public cTimer {
public:
	cHEP_ProcessData();
	void processData(u_char *data, size_t dataLen, vmIP ip = 0);
protected:
	bool isCompleteHep(u_char *data, size_t dataLen);
	bool isBeginHep(u_char *data, size_t dataLen);
	u_int16_t hepLength(u_char *data, size_t dataLen);
	unsigned processHeps(u_char *data, size_t dataLen, vmIP ip);
	void processHep(u_char *data, size_t dataLen, vmIP ip);
	u_int16_t chunkVendor(u_char *data, size_t dataLen);
	u_int16_t chunkType(u_char *data, size_t dataLen);
	u_int16_t chunkLength(u_char *data, size_t dataLen);
	void processChunks(u_char *data, size_t dataLen, sHEP_Data *hepData);
	void processChunk(u_char *data, size_t dataLen, sHEP_Data *hepData);
private:
	void pushPacket(sHEP_Data *hepData, pcap_pkthdr *header, u_char *packet, unsigned payload_len, bool tcp,
			int dlink, int pcap_handle_index);
	void evTimer(u_int32_t time_s, int typeTimer, void *data);
	void block_store_lock() {
		__SYNC_LOCK_USLEEP(block_store_sync, 50);
	}
	void block_store_unlock() {
		__SYNC_UNLOCK(block_store_sync);
	}
public:
	SimpleBuffer hep_buffer;
private:
	struct pcap_block_store *block_store;
	volatile int block_store_sync;
};
 
class cHEP_Server : public cServer, public cHEP_ProcessData {
public:
	cHEP_Server(bool udp);
	virtual ~cHEP_Server();
	void createConnection(cSocket *socket);
	void evData(u_char *data, size_t dataLen, vmIP ip, cSocket *socket);
};

class cHEP_Connection : public cServerConnection, public cHEP_ProcessData {
public:
	cHEP_Connection(cSocket *socket);
	virtual ~cHEP_Connection();
	void evData(u_char *data, size_t dataLen);
	void connection_process();
};


class cHepCounter {
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


void HEP_ServerStart(const char *host, int port, bool udp);
void HEP_ServerStop();

void HEP_client_emulation(const char *pcap, vmIP client_ip, vmIP server_ip, vmIP destination_ip, vmPort destination_port, bool udp);


#endif //HEP_H
