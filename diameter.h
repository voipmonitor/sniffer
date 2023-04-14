#ifndef DIAMETER_H
#define DIAMETER_H

#include "tcpreassembly.h"


#define DIAMETER_VERSION_1 1


class DiameterTcpData : public TcpReassemblyProcessData {
public:
	DiameterTcpData();
	virtual ~DiameterTcpData();
	void processData(vmIP ip_src, vmIP ip_dst,
			 vmPort port_src, vmPort port_dst,
			 TcpReassemblyData *data,
 			 u_char *ethHeader, u_int32_t ethHeaderLength,
			 u_int16_t handle_index, int dlt, int sensor_id, vmIP sensor_ip, sPacketInfoData pid,
			 void *uData, void *uData2, void *uData2_last, TcpReassemblyLink *reassemblyLink,
			 std::ostream *debugStream);
};


bool checkOkDiameter(u_char *data, u_int32_t datalen);
inline bool check_diameter(u_char *data, u_int32_t datalen) {
	return(checkOkDiameter(data, datalen));
}


class cDiameterAvpDataItem {
public:
	cDiameterAvpDataItem();
	~cDiameterAvpDataItem();
public:
	u_int32_t code;
	u_int32_t length;
	SimpleBuffer *payload;
};

class cDiameterAvpDataItems {
public:
	cDiameterAvpDataItems();
	~cDiameterAvpDataItems();
	void push(cDiameterAvpDataItem *dataItem);
	void print();
public:
	list<cDiameterAvpDataItem*> items;
};

class cDiameterAvp {
public:
	enum eFlags {
		_flag_vendor = 1 << 7
	};
	struct sHeader {
		u_int32_t code;
		u_int8_t flags;
		u_int32_t length : 24;
	} __attribute__((packed));
public:
	cDiameterAvp(u_char *data, unsigned datalen);
	void parse(cDiameterAvpDataItems *dataItems);
	u_int32_t code();
	u_int8_t flags();
	u_int32_t header_length();
	u_int32_t length();
	u_int32_t real_length();
	u_int32_t vendor_id();
	u_char *payload();
	u_int32_t payload_len();
	bool isGroup();
	bool headerLengthIsOk();
	bool lengthIsOk();
private:
	u_char *data;
	unsigned datalen;
};

class cDiameter {
public:
	enum eFlags {
		_flag_request = 1 << 7
	};
	struct sHeader {
		u_int8_t version;
		u_int32_t length : 24;
		u_int8_t flags;
		u_int32_t command_code : 24;
		u_int32_t application_id;
		u_int32_t hop_by_hop_id;
		u_int32_t end_to_end_id;
	} __attribute__((packed));
public:
	cDiameter(u_char *data, unsigned datalen);
	string getPublicIdentity(cDiameterAvpDataItems *dataItems = NULL);
	string getSessionId(cDiameterAvpDataItems *dataItems = NULL);
	string getCallingPartyAddress(cDiameterAvpDataItems *dataItems = NULL);
	string getValue(unsigned code, cDiameterAvpDataItems *dataItems = NULL);
	int getValues(unsigned code, list<string> *values, cDiameterAvpDataItems *dataItems = NULL);
	void parse(cDiameterAvpDataItems *dataItems);
	u_int8_t version();
	u_int32_t length();
	u_int8_t flags();
	u_int32_t command_code();
	u_int32_t application_id();
	u_int32_t hop_by_hop_id();
	u_int32_t end_to_end_id();
	u_char *payload();
	u_int32_t payload_len();
	bool isRequest();
	bool versionIsOk();
	bool headerLengthIsOk();
	bool lengthIsOk();
private:
	u_char *data;
	unsigned datalen;
};

class cDiameterPacketStack {
public:
	enum eTypeRetrieve {
		_tr_from,
		_tr_to
	};
	struct sPacket {
		void *packet;
		bool is_request;
		u_int32_t hbh_id;
		u_int64_t time_us;
		void destroy_packet();
		unsigned age_s(u_int64_t time_us) {
			return(this->time_us < time_us ?
				TIME_US_TO_S(time_us - this->time_us) :
				0);
		}
		bool operator == (const sPacket& other) const { 
			return(this->time_us == other.time_us); 
		}
		bool operator < (const sPacket& other) const { 
			return(this->time_us < other.time_us); 
		}
	};
	struct sQueuePacketsId {
		string public_identity;
		string session_id;
		string calling_party_address;
		void set(cDiameterAvpDataItems *dataItems);
		string print(void *packets) const;
		bool isSet() {
			return(!public_identity.empty() ||
			       !session_id.empty() ||
			       !calling_party_address.empty());
		}
		bool operator == (const sQueuePacketsId& other) const { 
			return(this->public_identity == other.public_identity &&
			       this->session_id == other.session_id &&
			       this->calling_party_address == other.calling_party_address); 
		}
		bool operator < (const sQueuePacketsId& other) const { 
			return(this->public_identity < other.public_identity ? true : 
			       this->public_identity > other.public_identity ? false :
			       this->session_id < other.session_id ? true : 
			       this->session_id > other.session_id ? false :
			       this->calling_party_address < other.calling_party_address); 
		}
	};
	class cQueuePackets {
	public:
		cQueuePackets();
		void add(void *packet, bool is_request, u_int32_t hbh_id, u_int64_t time_us);
		unsigned age_s(u_int64_t time_us);
		void destroy_packets();
		string hbh_str();
	public:
		sQueuePacketsId id;
		list<sPacket> packets;
	};
public:
	cDiameterPacketStack();
	~cDiameterPacketStack();
	bool add(void *packet, bool is_request, u_int32_t hbh_id, sQueuePacketsId *queue_packets_id, u_int64_t time_us);
	bool retrieve(eTypeRetrieve type_retrieve, const char *identity, list<sPacket> *packets, u_int64_t from_time, u_int64_t to_time);
	bool retrieve(eTypeRetrieve type_retrieve, list<string> *identity, list<sPacket> *packets, u_int64_t from_time, u_int64_t to_time);
	bool retrieve(eTypeRetrieve type_retrieve, list<string> *identity, cQueuePackets *packets, u_int64_t from_time, u_int64_t to_time);
	bool retrieve_from_sip(list<string> *from_sip, cQueuePackets *packets, u_int64_t from_time, u_int64_t to_time);
	bool retrieve_to_sip(list<string> *to_sip, cQueuePackets *packets, u_int64_t from_time, u_int64_t to_time);
	void cleanup(u_int64_t time_us = 0);
	string print_packets_stack();
private:
	bool check_used(const sQueuePacketsId *queue_packets_id);
	void addFindIndexes(cQueuePackets *queue_packets);
	void addFindIndex(cQueuePackets *queue_packets, map<string, list<cQueuePackets*>> *dia_map, const char *index);
	void eraseFindIndexes(cQueuePackets *queue_packets);
	void eraseFindIndex(cQueuePackets *queue_packets, map<string, list<cQueuePackets*>> *dia_map, const char *index);
private:
	void lock() {
		__SYNC_LOCK(_sync_lock);
	}
	void unlock() {
		__SYNC_UNLOCK(_sync_lock);
	}
public:
	map<sQueuePacketsId, cQueuePackets*> packet_stack;
	map<string, list<cQueuePackets*>> packet_stack_by_from;
	map<string, list<cQueuePackets*>> packet_stack_by_to;
	map<u_int32_t, cQueuePackets*> hbh_id_to_queue_packets_id;
	unsigned age_expiration_s;
	unsigned cleanup_period_s;
	unsigned last_cleanup_s;
	volatile int _sync_lock;
};


#endif
