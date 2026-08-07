#ifndef ESP_DECRYPT_H
#define ESP_DECRYPT_H

#include "config.h"

#include <sys/time.h>
#include <map>
#include <string>

#include "ip.h"
#include "sync.h"


struct sEspCounters {
	u_int64_t key_found;
	u_int64_t sa_created;
	u_int64_t decrypt_ok;
	u_int64_t decrypt_no_key;
	u_int64_t decrypt_failed;
	u_int64_t packet_bad;
	u_int64_t decrypt_learned_spi;
	u_int64_t reassembly_used;
	u_int64_t incomplete_header;
	u_int64_t expires_updated;
};


#if defined(HAVE_OPENSSL)


class ReassemblyBuffer;


#define ESP_CK_MAX_LENGTH 16
#define ESP_IK_MAX_LENGTH 16
#define ESP_PORTS_MAX 4
#define ESP_PORTS_SIDE_MAX 2
#define ESP_SPI_MAX 2
#define ESP_AES_CBC_IV_LENGTH 16
#define ESP_KEY_SET_TIMEOUT 300
#define ESP_SA_TIMEOUT_DEFAULT 86400
#define ESP_SA_TIMEOUT_MIN 300
#define ESP_SA_TIMEOUT_MAX 2592000
#define ESP_SA_EXPIRES_MARGIN 60
#define ESP_CLEANUP_INTERVAL 60
#define ESP_DELETE_OLD_SA_INTERVAL 3600
#define ESP_DELETE_OLD_SA_MARGIN 3600


class SqlDb;


class cEspDecrypt {
public:
	enum eEncAlg {
		_ealg_na,
		_ealg_null,
		_ealg_aes_cbc
	};
	struct sSaId {
		sSaId(u_int32_t spi = 0, vmIP dst_ip = 0) {
			this->spi = spi;
			this->dst_ip = dst_ip;
		}
		u_int32_t spi;
		vmIP dst_ip;
		bool operator < (const sSaId& other) const {
			return((this->spi < other.spi) ? 1 : (this->spi > other.spi) ? 0 :
			       (this->dst_ip < other.dst_ip));
		}
	};
	struct sIpPair {
		sIpPair(vmIP ip1 = 0, vmIP ip2 = 0) {
			if(ip2 < ip1) {
				this->ip1 = ip2;
				this->ip2 = ip1;
			} else {
				this->ip1 = ip1;
				this->ip2 = ip2;
			}
		}
		vmIP ip1;
		vmIP ip2;
		bool operator < (const sIpPair& other) const {
			return((this->ip1 < other.ip1) ? 1 : (this->ip1 > other.ip1) ? 0 :
			       (this->ip2 < other.ip2));
		}
	};
	struct sSaData {
		sSaData() {
			memset((void*)this, 0, sizeof(*this));
			timeout = ESP_SA_TIMEOUT_DEFAULT;
		}
		bool operator == (const sSaData &other) const {
			return(ck_length == other.ck_length &&
			       !memcmp(ck, other.ck, ck_length) &&
			       ealg == other.ealg &&
			       icv_length == other.icv_length &&
			       timeout == other.timeout &&
			       ue_ip == other.ue_ip &&
			       pcscf_ip == other.pcscf_ip &&
			       ports_count == other.ports_count &&
			       !memcmp(ports, other.ports, ports_count * sizeof(ports[0])));
		}
		bool checkPort(u_int16_t port1, u_int16_t port2) const {
			for(unsigned i = 0; i < ports_count; i++) {
				if(ports[i] == port1 || ports[i] == port2) {
					return(true);
				}
			}
			return(false);
		}
		u_char ck[ESP_CK_MAX_LENGTH];
		unsigned ck_length;
		eEncAlg ealg;
		unsigned icv_length;
		u_int16_t ports[ESP_PORTS_MAX];
		unsigned ports_count;
		u_int32_t timeout;
		vmIP ue_ip;
		vmIP pcscf_ip;
	};
	struct sSa {
		sSa() {
			set_at = 0;
			last_store_at = 0;
		}
		sSaData data;
		u_int32_t set_at;
		u_int32_t last_store_at;
	};
	struct sStoreSaItem {
		sStoreSaItem() {
			spi = 0;
		}
		u_int32_t spi;
		vmIP dst_ip;
		sSa sa;
	};
	struct sKeySet {
		sKeySet() {
			memset((void*)this, 0, sizeof(*this));
		}
		void addPort(u_int16_t *ports, unsigned *ports_count, u_int16_t port) {
			if(!port) {
				return;
			}
			for(unsigned i = 0; i < *ports_count; i++) {
				if(ports[i] == port) {
					return;
				}
			}
			if(*ports_count < ESP_PORTS_SIDE_MAX) {
				ports[(*ports_count)++] = port;
			}
		}
		u_char ck[ESP_CK_MAX_LENGTH];
		unsigned ck_length;
		u_char ik[ESP_IK_MAX_LENGTH];
		unsigned ik_length;
		eEncAlg ealg;
		unsigned icv_length;
		u_int32_t spi_to_pcscf[ESP_SPI_MAX];
		unsigned spi_to_pcscf_count;
		u_int32_t spi_to_ue[ESP_SPI_MAX];
		unsigned spi_to_ue_count;
		u_int16_t ports_ue[ESP_PORTS_SIDE_MAX];
		unsigned ports_ue_count;
		u_int16_t ports_pcscf[ESP_PORTS_SIDE_MAX];
		unsigned ports_pcscf_count;
		u_int32_t expires;
		vmIP ue_ip;
		vmIP pcscf_ip;
		u_int32_t set_at;
		u_int32_t ck_cseq;
		u_int32_t spi_cseq;
	};
public:
	cEspDecrypt();
	~cEspDecrypt();
	void collectKeys(u_char *data, unsigned datalen,
			 vmIP saddr, vmPort sport, vmIP daddr, vmPort dport,
			 u_int32_t seq, u_int32_t ack, timeval time);
	bool decrypt(iphdr2 *header_ip, unsigned max_len);
	void updateExpires(const char *call_id, unsigned call_id_length, u_int32_t expires, u_int32_t time_s);
	void loadSa();
	void cleanup(u_int32_t time_s);
	void getCounters(sEspCounters *counters);
private:
	void parseMessage(u_char *data, unsigned datalen, vmIP saddr, vmIP daddr, u_int32_t time_s);
	bool parseWwwAuthenticate(u_char *value, unsigned value_length, sKeySet *key_set, u_int32_t cseq);
	bool parseSecurityServer(u_char *value, unsigned value_length, sKeySet *key_set, u_int32_t cseq);
	bool parseSecurityClient(u_char *value, unsigned value_length, sKeySet *key_set);
	bool completedKeySet(sKeySet *key_set);
	void completeKeySet(sKeySet *key_set, u_int32_t time_s);
	bool findSa(u_int32_t spi, vmIP src_ip, vmIP dst_ip, sSa *sa, bool *from_ip_map);
	void storeSa(u_int32_t spi, vmIP dst_ip, sSa *sa);
	void deleteOldSa(u_int32_t time_s);
	std::string storeSaTableName();
	bool decryptAesCbc(u_char *ck, u_char *iv, u_char *data, unsigned datalen, u_char *out);
	bool checkTrailer(u_char *trailer, unsigned trailer_length, unsigned enc_length, u_int8_t *pad_length, u_int8_t *next_header);
	u_int32_t saTimeout(u_int32_t expires);
	static u_char *findHeader(u_char *data, unsigned datalen, const char *header, unsigned *value_length);
	static u_char *findParam(u_char *data, unsigned datalen, const char *param, unsigned *value_length);
	static u_int32_t parseUInt(u_char *data, unsigned datalen);
	static std::string normalizeCallId(const char *call_id, unsigned call_id_length);
	void lock_sa() {
		__SYNC_LOCK(this->_sync_sa);
	}
	void unlock_sa() {
		__SYNC_UNLOCK(this->_sync_sa);
	}
	void lock_collect() {
		__SYNC_LOCK(this->_sync_collect);
	}
	void unlock_collect() {
		__SYNC_UNLOCK(this->_sync_collect);
	}
private:
	std::map<sSaId, sSa> sa_map;
	std::map<sIpPair, sSa> ip_map;
	std::map<std::string, sKeySet> key_set_map;
	ReassemblyBuffer *reassembly;
	SqlDb *sqlDb;
	bool exists_sa_table;
	volatile int _sync_sa;
	volatile int _sync_collect;
	u_int32_t last_cleanup_at;
	u_int32_t last_delete_old_sa_at;
public:
	u_int64_t count_key_found;
	u_int64_t count_sa_created;
	u_int64_t count_decrypt_ok;
	u_int64_t count_decrypt_no_key;
	u_int64_t count_decrypt_failed;
	u_int64_t count_packet_bad;
	u_int64_t count_decrypt_learned_spi;
	u_int64_t count_reassembly_used;
	u_int64_t count_incomplete_header;
	u_int64_t count_expires_updated;
};


#endif //HAVE_OPENSSL


void esp_collect_keys(u_char *data, unsigned datalen,
		      vmIP saddr, vmPort sport, vmIP daddr, vmPort dport,
		      u_int32_t seq, u_int32_t ack, timeval time);
bool esp_decrypt_packet(iphdr2 *header_ip, unsigned max_len);
void esp_decrypt_init();
void esp_decrypt_update_expires(const char *call_id, unsigned call_id_length, u_int32_t expires, u_int32_t time_s);
void esp_decrypt_counters(sEspCounters *counters);


#endif
