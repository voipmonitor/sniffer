#ifndef DTLS_H
#define DTLS_H


#include <map>
#include <string>

#include "ip.h"
#include "tools_global.h"

#if defined(HAVE_OPENSSL101) and defined(HAVE_LIBGNUTLS)
#include <openssl/ssl.h>
#else
    #ifndef SSL3_MASTER_SECRET_SIZE
    #define SSL3_MASTER_SECRET_SIZE 48
    #endif
#endif


using namespace std;


#define DTLS_RANDOM_SIZE 32

#define DTLS_CONTENT_TYPE_HANDSHAKE 22

#define DTLS_HANDSHAKE_TYPE_CLIENT_HELLO 1
#define DTLS_HANDSHAKE_TYPE_SERVER_HELLO 2


class cDtlsLink {
public:
	struct sDtlsLinkId {
		vmIPport server;
		vmIPport client;
		sDtlsLinkId(cDtlsLink *link) 
			: server(link->server.ip, link->server.port), 
			  client(link->client.ip, link->client.port) {
		}
		sDtlsLinkId(vmIP server_ip, vmPort server_port,
			    vmIP client_ip, vmPort client_port) 
			: server(server_ip, server_port), 
			  client(client_ip, client_port) {
		}
		inline bool operator == (const sDtlsLinkId& other) const {
			return(this->server == other.server &&
			       this->client == other.client);
		}
		inline bool operator < (const sDtlsLinkId& other) const { 
			return(this->server < other.server ||
			       (this->server == other.server && this->client < other.client));
		}
	};
	struct sDtlsServerId {
		vmIPport server;
		sDtlsServerId(cDtlsLink *link) 
			: server(link->server.ip, link->server.port) {
		}
		sDtlsServerId(vmIP server_ip, vmPort server_port) 
			: server(server_ip, server_port) {
		}
		inline bool operator == (const sDtlsServerId& other) const {
			return(this->server == other.server);
		}
		inline bool operator < (const sDtlsServerId& other) const { 
			return(this->server < other.server);
		}
	};
	struct sDtlsClientId {
		vmIPport client;
		sDtlsClientId(cDtlsLink *link)
			: client(link->client.ip, link->client.port) {
		}
		sDtlsClientId(vmIP client_ip, vmPort client_port) 
			: client(client_ip, client_port) {
		}
		inline bool operator == (const sDtlsClientId& other) const {
			return(this->client == other.client);
		}
		inline bool operator < (const sDtlsClientId& other) const { 
			return(this->client < other.client);
		}
	};
	struct sSrtpKeys {
		string server_key;
		string client_key;
		vmIPport server;
		vmIPport client;
		string cipher;
		inline bool operator == (const sSrtpKeys& other) const {
			return(this->server_key == other.server_key &&
			       this->client_key == other.client_key &&
			       this->server == other.server &&
			       this->client == other.client &&
			       this->cipher == other.cipher);
		}
	};
	struct sHeader {
		u_int8_t content_type;
		u_int16_t version;
		u_int16_t epoch;
		u_int16_t sequence_number_filler;
		u_int32_t sequence_number;
		u_int16_t length;
		unsigned length_() {
			return(ntohs(length));
		}
	} __attribute__((packed));
	struct sHeaderHandshake {
		u_int8_t handshake_type;
		u_int8_t length_upper;
		u_int16_t length;
		u_int16_t message_sequence;
		u_int8_t fragment_offset_upper;
		u_int16_t fragment_offset;
		u_int8_t fragment_length_upper;
		u_int16_t fragment_length;
		unsigned length_() {
			return(ntohs(length) + (length_upper << 16));
		}
		unsigned fragment_offset_() {
			return(ntohs(fragment_offset) + (fragment_offset_upper << 16));
		}
		unsigned fragment_length_() {
			return(ntohs(fragment_length) + (fragment_length_upper << 16));
		}
		unsigned content_length() {
			return(fragment_length_() ? fragment_length_() : length_());
		}
	} __attribute__((packed));
	struct sHeaderHandshakeHello : public sHeaderHandshake {
		u_int16_t version;
		u_char random[DTLS_RANDOM_SIZE];
	} __attribute__((packed));
	struct sHeaderHandshakeDefragmenter {
		u_int8_t handshake_type;
		unsigned length;
		map<unsigned, SimpleBuffer> fragments;
		bool empty() {
			return(fragments.size() == 0);
		}
		void clear() {
			fragments.clear();
		}
		bool isComplete() {
			unsigned offset = 0;
			for(map<unsigned, SimpleBuffer>::iterator iter = fragments.begin(); iter != fragments.end(); iter++) {
				if(offset != ((sHeaderHandshake*)iter->second.data())->fragment_offset_()) {
					return(false);
				}
				offset += ((sHeaderHandshake*)iter->second.data())->fragment_length_();
			}
			return(offset == length);
		}
		u_char *complete() {
			u_char *hs = new u_char[sizeof(sHeaderHandshake) + length];
			unsigned offset = 0;
			for(map<unsigned, SimpleBuffer>::iterator iter = fragments.begin(); iter != fragments.end(); iter++) {
				if(!offset) {
					memcpy(hs, iter->second.data(), 
					       sizeof(sHeaderHandshake) + ((sHeaderHandshake*)iter->second.data())->fragment_length_());
					offset += sizeof(sHeaderHandshake);
				} else {
					memcpy(hs + offset, iter->second.data() + sizeof(sHeaderHandshake), 
					       ((sHeaderHandshake*)iter->second.data())->fragment_length_());
				}
				offset += ((sHeaderHandshake*)iter->second.data())->fragment_length_();
			}
			return(hs);
		}
	};
	enum eCipherType {
		_ct_na = 0,
		_ct_SRTP_AES128_CM_HMAC_SHA1_80 = 0x0001,
		_ct_SRTP_AES128_CM_HMAC_SHA1_32 =  0x0002,
		_ct_SRTP_NULL_HMAC_SHA1_80 = 0x0005,
		_ct_SRTP_NULL_HMAC_SHA1_32 = 0x0006,
		_ct_SRTP_AEAD_AES_128_GCM = 0x0007,
		_ct_SRTP_AEAD_AES_256_GCM = 0x0008
	};
	struct sHandshakeData {
		sHandshakeData() {
			client_random_set = false;
			server_random_set = false;
		}
		void init() {
			client_random_set = false;
			server_random_set = false;
			cipher_types.clear();
		}
		bool isComplete() {
			return(client_random_set && server_random_set &&
			       cipher_types.size() > 0);
		}
		u_char client_random[DTLS_RANDOM_SIZE];
		bool client_random_set;
		u_char server_random[DTLS_RANDOM_SIZE];
		bool server_random_set;
		list<eCipherType> cipher_types;
	};
public:
	cDtlsLink(vmIP server_ip, vmPort server_port,
		  vmIP client_ip, vmPort client_port);
	~cDtlsLink();
	void processHandshake(sHeaderHandshake *handshake, u_int64_t time_us);
	bool findSrtpKeys(list<sSrtpKeys*> *keys, class Call *call,
			  bool enable_handshake_safe, bool use_handshake_safe);
private:
	void init();
	void setClientRandom(u_char *client_random);
	void setServerRandom(u_char *server_random);
	bool findMasterSecret();
	bool cipherTypeIsOK(unsigned ct) {
		return(ct == _ct_SRTP_AES128_CM_HMAC_SHA1_80 ||
		       ct == _ct_SRTP_AES128_CM_HMAC_SHA1_32 ||
		       ct == _ct_SRTP_NULL_HMAC_SHA1_80 ||
		       ct == _ct_SRTP_NULL_HMAC_SHA1_32 ||
		       ct == _ct_SRTP_AEAD_AES_128_GCM ||
		       ct == _ct_SRTP_AEAD_AES_256_GCM);
	}
	bool cipherIsSupported(unsigned ct) {
		return(ct == _ct_SRTP_AES128_CM_HMAC_SHA1_80 ||
		       ct == _ct_SRTP_AES128_CM_HMAC_SHA1_32 ||
		       ct == _ct_SRTP_AEAD_AES_128_GCM ||
		       ct == _ct_SRTP_AEAD_AES_256_GCM);
	}
	string cipherName(unsigned ct) {
		return(ct == _ct_SRTP_AES128_CM_HMAC_SHA1_80 ? "AES_CM_128_HMAC_SHA1_80" :
		       ct == _ct_SRTP_AES128_CM_HMAC_SHA1_32 ? "AES_CM_128_HMAC_SHA1_32" :
		       ct == _ct_SRTP_AEAD_AES_128_GCM ? "AEAD_AES_128_GCM" :
		       ct == _ct_SRTP_AEAD_AES_256_GCM ? "AEAD_AES_256_GCM" :
		       cipherTypeIsOK(ct) ? "unsupported" :"unknown");
	}
	unsigned cipherSrtpKeyLen(unsigned ct) {
		return(ct == _ct_SRTP_AES128_CM_HMAC_SHA1_80 ? 16 :
		       ct == _ct_SRTP_AES128_CM_HMAC_SHA1_32 ? 16 :
		       ct == _ct_SRTP_AEAD_AES_256_GCM ? 32 :
		       ct == _ct_SRTP_AEAD_AES_128_GCM ? 16 :
		       0);
	}
	unsigned cipherSrtpSaltLen(unsigned ct) {
		return(ct == _ct_SRTP_AES128_CM_HMAC_SHA1_80 ? 14 :
		       ct == _ct_SRTP_AES128_CM_HMAC_SHA1_32 ? 14 :
		       ct == _ct_SRTP_AEAD_AES_256_GCM ? 12 :
		       ct == _ct_SRTP_AEAD_AES_128_GCM ? 12 :
		       0);
	}
private:
	vmIPport server;
	vmIPport client;
	sHandshakeData handshake_data;
	u_char master_secret[SSL3_MASTER_SECRET_SIZE];
	u_int16_t master_secret_length;
	u_int16_t keys_block_attempts;
	u_int16_t max_keys_block_attempts;
	sHeaderHandshakeDefragmenter defragmenter;
	u_int64_t last_time_us;
friend class cDtls;
};

class cDtls {
public:
	cDtls();
	~cDtls();
	void setNeedLock(bool need_lock);
	bool processHandshake(vmIP src_ip, vmPort src_port,
			      vmIP dst_ip, vmPort dst_port,
			      u_char *data, unsigned data_len,
			      u_int64_t time_us);
	bool findSrtpKeys(vmIP src_ip, vmPort src_port,
			  vmIP dst_ip, vmPort dst_port,
			  list<cDtlsLink::sSrtpKeys*> *keys,
			  int8_t *direction, int8_t *node,
			  class Call *call,
			  bool enable_handshake_safe, bool use_handshake_safe);
	bool getHandshakeData(vmIP server_ip, vmPort server_port,
			      vmIP client_ip, vmPort client_port,
			      cDtlsLink::sHandshakeData *handshake_data);
	void cleanup();
private:
	void lock();
	void unlock();
private:
	list<cDtlsLink*> links;
	map<cDtlsLink::sDtlsLinkId, cDtlsLink*> links_by_link_id;
	map<cDtlsLink::sDtlsServerId, cDtlsLink*> links_by_server_id;
	map<cDtlsLink::sDtlsClientId, cDtlsLink*> links_by_client_id;
	int debug_flags[2];
	bool need_lock;
	volatile int _sync;
	u_int32_t last_cleanup_at_s;
	u_int32_t cleanup_interval_s;
	u_int32_t link_expiration_s;
friend class RTP;
};


#endif //DTLS_H
