#ifndef WEBRTC_H
#define WEBRTC_H

//#include "pcap_queue_block.h"
#include "tcpreassembly.h"


struct WebrtcDataCache_id {
	WebrtcDataCache_id(vmIP ip_src, vmIP ip_dst,
			   vmPort port_src, vmPort port_dst,
			   string data_md5) {
		this->ip_src = ip_src;
		this->ip_dst = ip_dst;
		this->port_src = port_src; 
		this->port_dst = port_dst;
		this->data_md5 = data_md5;
	}
	vmIP ip_src;
	vmIP ip_dst;
	vmPort port_src;
	vmPort port_dst;
	string data_md5;
	bool operator < (const WebrtcDataCache_id& other) const {
		return((this->ip_src < other.ip_src) ? 1 : (this->ip_src > other.ip_src) ? 0 :
		       (this->ip_dst < other.ip_dst) ? 1 : (this->ip_dst > other.ip_dst) ? 0 :
		       (this->port_src < other.port_src) ? 1 : (this->port_src > other.port_src) ? 0 :
		       (this->port_dst < other.port_dst) ? 1 : (this->port_dst > other.port_dst) ? 0 :
		       this->data_md5 < other.data_md5);
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
	WebrtcDataCache get(vmIP ip_src, vmIP ip_dst,
			    vmPort port_src, vmPort port_dst,
			    string data_md5);
	void add(vmIP ip_src, vmIP ip_dst,
		 vmPort port_src, vmPort port_dst,
		 string data_md5,
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
	enum eWebrtcOpcode {
		opcode_continuePayload		= 0x00,
		opcode_textData    		= 0x01,
		opcode_binaryData		= 0x02,
		opcode_terminatesConnection	= 0x08,
		opcode_ping			= 0x09,
		opcode_pong			= 0x10,
		opcode_NA			= 0xFF
	};
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
		unsigned int decode(u_char *data, unsigned int data_length, bool checkOkOnly = false);
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
		string type;
		string deviceId;
		string commCorrelationId;
	};
public:
	WebrtcData();
	virtual ~WebrtcData();
	void processData(vmIP ip_src, vmIP ip_dst,
			 vmPort port_src, vmPort port_dst,
			 TcpReassemblyData *data,
 			 u_char *ethHeader, u_int32_t ethHeaderLength,
			 u_int16_t handle_index, int dlt, int sensor_id, vmIP sensor_ip, sPacketInfoData pid,
			 void *uData, void *uData2, void *uData2_last, TcpReassemblyLink *reassemblyLink,
			 std::ostream *debugStream);
	void printContentSummary();
private:
	unsigned int counterProcessData;
	WebrtcCache cache;
};


bool checkOkWebrtcHttpData(u_char *data, u_int32_t datalen);
bool checkOkWebrtcData(u_char *data, u_int32_t datalen);


#endif
