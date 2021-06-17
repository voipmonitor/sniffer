#ifndef DTLS_H
#define DTLS_H


#include <map>
#include <string>

#include "ip.h"

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
	struct sSrtpKeys {
		string server_key;
		string client_key;
		vmIPport server;
		vmIPport client;
		string cipher;
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
		u_int8_t length_top;
		u_int16_t length;
		u_int16_t message_sequence;
		u_int8_t fragment_offset_top;
		u_int16_t fragment_offset;
		u_int8_t fragment_length_top;
		u_int16_t fragment_length;
		unsigned length_() {
			return(ntohs(length) + (length_top << 16));
		}
	} __attribute__((packed));
	struct sHeaderHandshakeHello : public sHeaderHandshake {
		u_int16_t version;
		u_char random[DTLS_RANDOM_SIZE];
	} __attribute__((packed));
	enum eCipherType {
		_ct_na = 0,
		_ct_SRTP_AES128_CM_HMAC_SHA1_80 = 0x0001,
		_ct_SRTP_AES128_CM_HMAC_SHA1_32 =  0x0002,
		_ct_SRTP_NULL_HMAC_SHA1_80 = 0x0005,
		_ct_SRTP_NULL_HMAC_SHA1_32 = 0x0006,
		_ct_SRTP_AEAD_AES_128_GCM = 0x0007,
		_ct_SRTP_AEAD_AES_256_GCM = 0x0008
	};
public:
	cDtlsLink(vmIP server_ip, vmPort server_port,
		  vmIP client_ip, vmPort client_port);
	~cDtlsLink();
	void processHandshake(sHeaderHandshake *handshake);
	bool findSrtpKeys(sSrtpKeys *keys);
private:
	void init();
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
		       ct == _ct_SRTP_AES128_CM_HMAC_SHA1_32);
	}
	string cipherName(unsigned ct) {
		return(ct == _ct_SRTP_AES128_CM_HMAC_SHA1_80 ? "AES_CM_128_HMAC_SHA1_80" :
		       ct == _ct_SRTP_AES128_CM_HMAC_SHA1_32 ? "AES_CM_128_HMAC_SHA1_32" :
		       cipherTypeIsOK(ct) ? "unsupported" :"unknown");
	}
	unsigned cipherSrtpKeyLen(unsigned ct) {
		return(ct == _ct_SRTP_AES128_CM_HMAC_SHA1_80 ? 16 :
		       ct == _ct_SRTP_AES128_CM_HMAC_SHA1_32 ? 16 :
		       0);
	}
	unsigned cipherSrtpSaltLen(unsigned /*ct*/) {
		return(14);
	}
private:
	vmIPport server;
	vmIPport client;
	u_char client_random[DTLS_RANDOM_SIZE];
	bool client_random_set;
	u_char server_random[DTLS_RANDOM_SIZE];
	bool server_random_set;
	eCipherType cipher_type;
	u_char master_secret[SSL3_MASTER_SECRET_SIZE];
	u_int16_t master_secret_length;
	u_int16_t keys_block_attempts;
	u_int16_t max_keys_block_attempts;
};

class cDtls {
public:
	cDtls();
	~cDtls();
	bool processHandshake(vmIP src_ip, vmPort src_port,
			      vmIP dst_ip, vmPort dst_port,
			      u_char *data, unsigned data_len);
	bool findSrtpKeys(vmIP src_ip, vmPort src_port,
			  vmIP dst_ip, vmPort dst_port,
			  cDtlsLink::sSrtpKeys *keys);
private:
	map<cDtlsLink::sDtlsLinkId, cDtlsLink*> links;
};


#endif //DTLS_H
