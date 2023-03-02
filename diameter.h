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
	struct sPacket {
		void *packet;
		bool is_request;
		u_int32_t hbh_id;
		u_int64_t time_us;
		void destroy_packet();
		bool operator == (const sPacket& other) const { 
			return(this->time_us == other.time_us); 
		}
		bool operator < (const sPacket& other) const { 
			return(this->time_us < other.time_us); 
		}
	};
	class cQueuePackets {
	public:
		cQueuePackets();
		void add(void *packet, bool is_request, u_int32_t hbh_id, u_int64_t time_us);
		unsigned age_s(u_int64_t time_us);
		void destroy_packets();
	public:
		string public_identity;
		list<sPacket> packets;
		bool confirmed;
	};
public:
	cDiameterPacketStack();
	~cDiameterPacketStack();
	bool add(void *packet, bool is_request, u_int32_t hbh_id, const char *public_identity, u_int64_t time_us);
	bool retrieve(const char *public_identity, list<sPacket> *packets);
	bool retrieve(list<string> *public_identity, list<sPacket> *packets);
	bool retrieve(list<string> *public_identity, cQueuePackets *packets);
	void cleanup(u_int64_t time_us = 0);
private:
	bool confirm_public_identity(const char *public_identity);
private:
	void lock() {
		__SYNC_LOCK(_sync_lock);
	}
	void unlock() {
		__SYNC_UNLOCK(_sync_lock);
	}
public:
	map<string, cQueuePackets*> packet_stack;
	map<u_int32_t, string> hbh_id_to_public_identity;
	unsigned age_expiration_s;
	unsigned cleanup_period_s;
	unsigned last_cleanup_s;
	volatile int _sync_lock;
};


#endif
