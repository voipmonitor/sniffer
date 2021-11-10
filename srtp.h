#ifndef VM_SRTP_H
#define VM_SRTP_H

#include <string>
#include <vector>

#if HAVE_LIBGNUTLS
#include <gcrypt.h>
#endif

#if HAVE_LIBSRTP
#include <srtp/srtp.h>
#endif

#include "dtls.h"


class RTPsecure {
public:
	enum eError {
		err_na,
		err_unsupported_suite,
		err_bad_sdes_length,
		err_bad_sdes_content,
		err_bad_tag_size,
		err_gcrypt_init,
		err_cipher_open,
		err_md_open,
		err_set_key
	};
	enum eMode {
		mode_native,
		mode_libsrtp
	};
	enum eDeriveLabel {
		SRTP_CRYPT,
		SRTP_AUTH,
		SRTP_SALT,
		SRTCP_CRYPT,
		SRTCP_AUTH,
		SRTCP_SALT
	};
	struct sCryptoConfig {
		sCryptoConfig() {
			error = err_na;
			attempts_rtp = 0;
			attempts_rtcp = 0;
		}
		bool init();
		bool keyDecode();
		inline unsigned sdes_ok_length() {
			return(key_size == 128 ? 40 : 64);
		}
		inline unsigned key_len() {
			return(key_size == 128 ? 16 : 32);
		}
		inline unsigned salt_len() {
			return(14);
		}
		unsigned tag;
		std::string suite;
		std::string sdes;
		u_int64_t from_time_us;
		u_char key_salt[46];
		u_char key[32];
		u_char salt[14];
		unsigned tag_size;
		unsigned key_size;
		int cipher;
		int md;
		eError error;
		int attempts_rtp;
		int attempts_rtcp;
	};
	struct sDecrypt {
		sDecrypt() {
			#if HAVE_LIBGNUTLS
			cipher = NULL;
			md = NULL;
			#endif
			window = 0;
			for(unsigned i = 0; i < sizeof(salt) / sizeof(salt[0]); i++) {
				salt[i] = 0;
			}
			counter_packets = 0;
			#if HAVE_LIBSRTP
			srtp_ctx = NULL;
			memset(&policy, 0, sizeof(policy));
			#endif
		}
		~sDecrypt() {
			#if HAVE_LIBGNUTLS
			if(cipher) {
				gcry_cipher_close(cipher);
			}
			if(md) {
				gcry_md_close(md);
			}
			#endif
			#if HAVE_LIBSRTP
			if(srtp_ctx) {
				srtp_dealloc(srtp_ctx);
			}
			#endif
		}
		#if HAVE_LIBGNUTLS
		gcry_cipher_hd_t cipher;
		gcry_md_hd_t md;
		#endif
		uint64_t window;
		uint32_t salt[4];
		uint64_t counter_packets;
		#if HAVE_LIBSRTP
		srtp_t srtp_ctx;
		srtp_policy_t policy;
		#endif
	};
public:
	RTPsecure(eMode mode, class Call *call, unsigned index_ip_port);
	~RTPsecure();
	bool setCryptoConfig();
	void addCryptoConfig(unsigned tag, const char *suite, const char *sdes, u_int64_t from_time_us);
	bool existsNewerCryptoConfig(u_int64_t time_us);
	inline bool need_prepare_decrypt() {
		return(!cryptoConfigVector.size());
	}
	void prepare_decrypt(vmIP saddr, vmIP daddr, vmPort sport, vmPort dport);
	bool is_dtls();
	bool decrypt_rtp(u_char *data, unsigned *data_len, u_char *payload, unsigned *payload_len, u_int64_t time_us);
	bool decrypt_rtp_native(u_char *data, unsigned *data_len, u_char *payload, unsigned *payload_len);
	bool decrypt_rtp_libsrtp(u_char *data, unsigned *data_len, u_char *payload, unsigned *payload_len);
	bool decrypt_rtcp(u_char *data, unsigned *data_len, u_int64_t time_us);
	bool decrypt_rtcp_native(u_char *data, unsigned *data_len);
	bool decrypt_rtcp_libsrtp(u_char *data, unsigned *data_len);
	void setError(eError error);
	void clearError();
	bool isOK() {
		return(error == err_na);
	}
	bool isOK_decrypt_rtp() {
		return(decrypt_rtp_ok > 0);
	}
	bool isOK_decrypt_rtcp() {
		return(decrypt_rtcp_ok > 0);
	}
private:
	bool init();
	bool init_native();
	bool init_libsrtp();
	void term();
	bool rtpDecrypt(u_char *payload, unsigned payload_len, uint16_t seq, uint32_t ssrc);
	bool rtcpDecrypt(u_char *data, unsigned data_len);
	int rtp_decrypt(u_char *data, unsigned data_len, uint32_t ssrc, uint32_t roc, uint16_t seq);
	int rtcp_decrypt(u_char *data, unsigned data_len, uint32_t ssrc, uint32_t index);
	uint32_t compute_rtp_roc(uint16_t seq);
	u_char *rtp_digest(u_char *data, size_t data_len, uint32_t roc);
	u_char *rtcp_digest(u_char *data, size_t data_len);
	#if HAVE_LIBGNUTLS
	int do_derive(gcry_cipher_hd_t cipher, u_char *r, unsigned rlen, uint8_t label, u_char *out, unsigned outlen);
	int do_ctr_crypt (gcry_cipher_hd_t cipher, u_char *ctr, u_char *data, unsigned len);
	#endif
	uint16_t get_seq_rtp(u_char *data) {
		return(htons(*(uint16_t*)(data + 2)));
	}
	uint32_t get_ssrc_rtp(u_char *data) {
		return(htonl(*(uint32_t*)(data + 8)));
	}
	uint32_t get_ssrc_rtcp(u_char *data) {
		return(htonl(*(uint32_t*)(data + 4)));
	}
	unsigned tag_size() {
	       return(cryptoConfigVector[cryptoConfigActiveIndex].tag_size);
	}
	unsigned key_size() {
	       return(cryptoConfigVector[cryptoConfigActiveIndex].key_size);
	}
	int cipher() {
	       return(cryptoConfigVector[cryptoConfigActiveIndex].cipher);
	}
	int md() {
	       return(cryptoConfigVector[cryptoConfigActiveIndex].md);
	}
	u_char *key_salt() {
	       return(cryptoConfigVector[cryptoConfigActiveIndex].key_salt);
	}
	u_char *key() {
	       return(cryptoConfigVector[cryptoConfigActiveIndex].key);
	}
	u_char *salt() {
	       return(cryptoConfigVector[cryptoConfigActiveIndex].salt);
	}
	unsigned key_len() {
	       return(cryptoConfigVector[cryptoConfigActiveIndex].key_len());
	}
	unsigned salt_len() {
	       return(cryptoConfigVector[cryptoConfigActiveIndex].salt_len());
	}
private:
	eMode mode;
	Call *call;
	unsigned index_ip_port;
	vector<sCryptoConfig> cryptoConfigVector;
	unsigned cryptoConfigCallSize;
	unsigned cryptoConfigActiveIndex;
	uint32_t rtcp_index;
	uint32_t rtp_roc;
	uint16_t rtp_seq;
	uint16_t rtp_rcc;
	bool rtp_seq_init;
	sDecrypt *rtp;
	sDecrypt *rtcp;
	eError error;
	int rtcp_unencrypt_header_len;
	int rtcp_unencrypt_footer_len;
	unsigned decrypt_rtp_ok;
	unsigned decrypt_rtp_failed;
	unsigned decrypt_rtcp_ok;
	unsigned decrypt_rtcp_failed;
};


#endif //VM_SRTP_H
