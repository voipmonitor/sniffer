#ifndef VM_SRTP_H
#define VM_SRTP_H

#include <string>
#include <vector>
#include <gcrypt.h>

#if HAVE_LIBSRTP
#include <srtp/srtp.h>
#endif


class RTPsecure {
public:
	enum eError {
		err_na,
		err_unsupported_suite,
		err_bad_sdes_length,
		err_bad_sdes_content,
		err_bad_tag_len,
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
		unsigned tag;
		std::string suite;
		std::string sdes;
		u_char key_salt[30];
		u_char key[16]; 
		u_char salt[14];
		unsigned tag_len;
		unsigned key_len;
		int cipher;
		int md;
		eError error;
		int attempts_rtp;
		int attempts_rtcp;
	};
	struct sDecrypt {
		sDecrypt() {
			cipher = NULL;
			md = NULL;
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
			if(cipher) {
				gcry_cipher_close(cipher);
			}
			if(md) {
				gcry_md_close(md);
			}
			#if HAVE_LIBSRTP
			if(srtp_ctx) {
				free(srtp_ctx);
			}
			#endif
		}
		gcry_cipher_hd_t cipher;
		gcry_md_hd_t md;
		uint64_t window;
		uint32_t salt[4];
		uint64_t counter_packets;
		#if HAVE_LIBSRTP
		srtp_t srtp_ctx;
		srtp_policy_t policy;
		#endif
	};
public:
	RTPsecure(eMode mode);
	~RTPsecure();
	void addCryptoConfig(unsigned tag, const char *suite, const char *sdes);
	bool decrypt_rtp(u_char *data, unsigned *data_len, u_char *payload, unsigned *payload_len);
	bool decrypt_rtp_native(u_char *data, unsigned *data_len, u_char *payload, unsigned *payload_len);
	bool decrypt_rtp_libsrtp(u_char *data, unsigned *data_len, u_char *payload, unsigned *payload_len);
	bool decrypt_rtcp(u_char *data, unsigned *data_len);
	bool decrypt_rtcp_native(u_char *data, unsigned *data_len);
	bool decrypt_rtcp_libsrtp(u_char *data, unsigned *data_len);
	void setError(eError error);
	void clearError();
	bool isOK() {
	     return(error == err_na);
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
	int do_derive(gcry_cipher_hd_t cipher, u_char *r, unsigned rlen, uint8_t label, u_char *out, unsigned outlen);
	int do_ctr_crypt (gcry_cipher_hd_t cipher, u_char *ctr, u_char *data, unsigned len);
	uint16_t get_seq_rtp(u_char *data) {
		return(htons(*(uint16_t*)(data + 2)));
	}
	uint32_t get_ssrc_rtp(u_char *data) {
		return(htonl(*(uint32_t*)(data + 8)));
	}
	uint32_t get_ssrc_rtcp(u_char *data) {
		return(htonl(*(uint32_t*)(data + 4)));
	}
	unsigned tag_len() {
	       return(cryptoConfigVector[cryptoConfigActiveIndex].tag_len);
	}
	unsigned key_len() {
	       return(cryptoConfigVector[cryptoConfigActiveIndex].key_len);
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
	unsigned sizeof_key() {
	       return(sizeof(cryptoConfigVector[cryptoConfigActiveIndex].key));
	}
	unsigned sizeof_salt() {
	       return(sizeof(cryptoConfigVector[cryptoConfigActiveIndex].salt));
	}
private:
	eMode mode;
	vector<sCryptoConfig> cryptoConfigVector;
	unsigned cryptoConfigActiveIndex;
	uint32_t rtcp_index;
	uint32_t rtp_roc;
	uint16_t rtp_seq;
	uint16_t rtp_rcc;
	sDecrypt *rtp;
	sDecrypt *rtcp;
	eError error;
	int rtcp_unencrypt_header_len;
	int rtcp_unencrypt_footer_len;
};


#endif //VM_SRTP_H
