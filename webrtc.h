#ifndef WEBRTC_H
#define WEBRTC_H

//#include "pcap_queue_block.h"
#include "tcpreassembly.h"


enum eWebrtcOpcode {
	opcode_continuePayload		= 0x00,
	opcode_textData    		= 0x01,
	opcode_binaryData		= 0x02,
	opcode_terminatesConnection	= 0x08,
	opcode_ping			= 0x09,
	opcode_pong			= 0x10,
	opcode_NA			= 0xFF
};

class WebrtcDataItem {
public:
	WebrtcDataItem(eWebrtcOpcode opcode = opcode_NA, u_char *data = NULL, u_int32_t datalen = 0) {
		this->opcode = opcode;
		if(data && !datalen && opcode == opcode_textData) {
			datalen = strlen((char*)data);
		}
		if(data && datalen) {
			this->data = new u_char[datalen + 1];
			memcpy(this->data, data, datalen);
			this->data[datalen] = 0;
			this->datalen = datalen;
		} else {
			this->data = NULL;
			this->datalen = 0;
		}
	}
	WebrtcDataItem(const WebrtcDataItem &dataItem) {
		if(dataItem.data && dataItem.datalen) {
			this->data = new u_char[dataItem.datalen + 1];
			memcpy(this->data, dataItem.data, dataItem.datalen);
			this->data[dataItem.datalen] = 0;
			this->datalen = dataItem.datalen;
		} else {
			this->data = NULL;
			this->datalen = 0;
		}
		this->opcode = dataItem.opcode;
	}
	~WebrtcDataItem() {
		if(this->data) {
			delete [] this->data;
		}
	}
	WebrtcDataItem& operator = (const WebrtcDataItem &dataItem) {
		if(this->data) {
			delete [] this->data;
		}
		this->opcode = dataItem.opcode;
		if(dataItem.data && dataItem.datalen) {
			this->data = new u_char[dataItem.datalen + 1];
			memcpy(this->data, dataItem.data, dataItem.datalen);
			this->data[dataItem.datalen] = 0;
			this->datalen = dataItem.datalen;
		} else {
			this->data = NULL;
			this->datalen = 0;
		}
		return(*this);
	}
	bool operator == (const WebrtcDataItem& other) const {
		return(this->opcode == other.opcode &&
		       this->datalen == other.datalen &&
		       !memcmp(this->data, other.data, this->datalen));
	}
	bool operator < (const WebrtcDataItem& other) const {
		return((this->opcode < other.opcode) ? 1 : (this->opcode > other.opcode) ? 0 :
		       (this->datalen < other.datalen) ? 1 : (this->datalen > other.datalen) ? 0 :
		       (this->datalen ? memcmp(this->data, other.data, this->datalen) : 0));
	}
	bool operator > (const WebrtcDataItem& other) const {
		return(!(this->opcode == other.opcode || this->opcode < other.opcode));
	}
public:
	eWebrtcOpcode opcode;
	u_char *data;
	u_int32_t datalen;
};

struct WebrtcDataCache_id {
	WebrtcDataCache_id(u_int32_t ip_src, u_int32_t ip_dst,
			   u_int16_t port_src, u_int16_t port_dst,
			   WebrtcDataItem *data,
			   WebrtcDataItem *data_master) {
		this->ip_src = ip_src;
		this->ip_dst = ip_dst;
		this->port_src = port_src; 
		this->port_dst = port_dst;
		if(data) {
			this->data = *data;
		}
		if(data_master) {
			this->data_master = *data_master;
		}
	}
	u_int32_t ip_src;
	u_int32_t ip_dst;
	u_int16_t port_src;
	u_int16_t port_dst;
	WebrtcDataItem data;
	WebrtcDataItem data_master;
	bool operator < (const WebrtcDataCache_id& other) const {
		return((this->ip_src < other.ip_src) ? 1 : (this->ip_src > other.ip_src) ? 0 :
		       (this->ip_dst < other.ip_dst) ? 1 : (this->ip_dst > other.ip_dst) ? 0 :
		       (this->port_src < other.port_src) ? 1 : (this->port_src > other.port_src) ? 0 :
		       (this->port_dst < other.port_dst) ? 1 : (this->port_dst > other.port_dst) ? 0 :
		       (this->data < other.data) ? 1 : (this->data > other.data) ? 0 :
		       (this->data_master < other.data_master));
	}
};

struct WebrtcDataCache {
	WebrtcDataCache(u_int64_t timestamp = 0) {
		this->timestamp = timestamp;
		this->timestamp_clock = getTimeMS()/1000;
	}
	u_int64_t timestamp;
	u_int64_t timestamp_clock;
};

class WebrtcCache {
public:
	WebrtcCache();
	WebrtcDataCache get(u_int32_t ip_src, u_int32_t ip_dst,
			    u_int16_t port_src, u_int16_t port_dst,
			    WebrtcDataItem *data,
			    WebrtcDataItem *data_master = NULL);
	void add(u_int32_t ip_src, u_int32_t ip_dst,
		 u_int16_t port_src, u_int16_t port_dst,
		 WebrtcDataItem *data,
		 WebrtcDataItem *data_master,
		 u_int64_t timestamp);
	void cleanup(bool force = false);
	void clear();
	u_int32_t getSize() {
		return(this->cache.size());
	}
private:
	map<WebrtcDataCache_id, WebrtcDataCache> cache;
	u_int64_t cleanupCounter;
	u_int64_t lastAddTimestamp;
};

class WebrtcData : public TcpReassemblyProcessData {
public:
	struct WebrtcHeader {
		unsigned int opcode : 4;
		unsigned int reserved : 3;
		unsigned int fin : 1;
		unsigned int payload_length : 7;
		unsigned int mask : 1;
	};
	class WebrtcDecodeData {
	public:
		WebrtcDecodeData() {
			opcode = opcode_NA;
			masking_key = 0;
			payload_length = 0;
			data = NULL;
		}
		~WebrtcDecodeData() {
			if(data) {
				delete [] data;
			}
		}
		unsigned int decode(u_char *data, unsigned int data_length);
		void clear() {
			opcode = opcode_NA;
			masking_key = 0;
			payload_length = 0;
			if(data) {
				delete [] data;
				data = NULL;
			}
		}
	public:
		eWebrtcOpcode opcode;
		unsigned int masking_key;
		unsigned int payload_length;
		u_char *data;
		string method;
		string deviceId;
		string commCorrelationId;
	};
public:
	WebrtcData();
	virtual ~WebrtcData();
	void processData(u_int32_t ip_src, u_int32_t ip_dst,
			 u_int16_t port_src, u_int16_t port_dst,
			 TcpReassemblyData *data,
			 bool debugSave);
	void printContentSummary();
private:
	unsigned int counterProcessData;
	WebrtcCache cache;
};

#endif
