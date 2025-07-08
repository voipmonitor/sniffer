#include <iostream>
#include <netinet/in.h>

#include "config.h"
#include "tools.h"

#include "srtp.h"
#include "calltable.h"
#include "ssl_dssl.h"


extern int opt_ssl_dtls_handshake_safe;
extern cDtls dtls_handshake_safe_links;


#if HAVE_LIBGNUTLS
static struct {
	string crypro_suite;
	int key_size;
	int tag_size;
	int cipher;
	int md;
	bool is_aead;
} srtp_crypto_suites[]= {
	{ "AES_CM_128_HMAC_SHA1_32", 128, 4, GCRY_CIPHER_AES, GCRY_MD_SHA1, false },
	{ "AES_CM_128_HMAC_SHA1_80", 128, 10, GCRY_CIPHER_AES, GCRY_MD_SHA1, false },
	{ "AES_128_CM_HMAC_SHA1_32", 128, 4, GCRY_CIPHER_AES, GCRY_MD_SHA1, false },
	{ "AES_128_CM_HMAC_SHA1_80", 128, 10, GCRY_CIPHER_AES, GCRY_MD_SHA1, false },
	{ "AES_CM_256_HMAC_SHA1_32", 256, 4, GCRY_CIPHER_AES256, GCRY_MD_SHA1, false },
	{ "AES_CM_256_HMAC_SHA1_80", 256, 10, GCRY_CIPHER_AES256, GCRY_MD_SHA1, false },
	{ "AES_256_CM_HMAC_SHA1_32", 256, 4, GCRY_CIPHER_AES256, GCRY_MD_SHA1, false },
	{ "AES_256_CM_HMAC_SHA1_80", 256, 10, GCRY_CIPHER_AES256, GCRY_MD_SHA1, false },
	{ "AEAD_AES_256_GCM", 256, 16, GCRY_CIPHER_AES256, GCRY_MD_NONE, true },
	{ "AEAD_AES_128_GCM", 128, 16, GCRY_CIPHER_AES256, GCRY_MD_NONE, true }
};
#endif


bool RTPsecure::sCryptoConfig::init() {
	#if HAVE_LIBGNUTLS
	if(suite.length()) {
		for(unsigned i = 0; i < sizeof(srtp_crypto_suites) / sizeof(srtp_crypto_suites[0]); i++) {
			if(suite == srtp_crypto_suites[i].crypro_suite) {
				tag_size = srtp_crypto_suites[i].tag_size;
				key_size = srtp_crypto_suites[i].key_size;
				cipher = srtp_crypto_suites[i].cipher;
				md = srtp_crypto_suites[i].md;
				is_aead = srtp_crypto_suites[i].is_aead;
				return(true);
			}
		}
	}
	error = err_unsupported_suite;
	#endif
	return(false);
}

bool RTPsecure::sCryptoConfig::keyDecode() {
	if(sverb.dtls && ssl_sessionkey_enable()) {
		string log_str;
		log_str += "keyDecode: SUITE: " + suite + " KEY: " + sdes;
		ssl_sessionkey_log(log_str);
	}
	if(sdes.length() != sdes_ok_length()) {
		if(sdes.length() < sdes_ok_length() && sdes.length() >= sdes_ok_length() - 2 &&
		   sdes[sdes.length() - 1] != '=') {
			while(sdes.length() < sdes_ok_length()) {
				sdes += '=';
			}
		} else {
			error = err_bad_sdes_length;
			return(false);
		}
	}
	u_char sdes_raw[100];
	if(base64decode(sdes_raw, sdes.c_str(), key_len() + salt_len()) != (int)(key_len() + salt_len())) {
		error = err_bad_sdes_content;
		return(false);
	}
	memcpy(key_salt, sdes_raw, key_len() + salt_len());
	memcpy(key, sdes_raw, key_len());
	memcpy(salt, sdes_raw + key_len(), salt_len());
	/*
	cout << "key / salt" << endl;
	hexdump(key, key_len());
	hexdump(salt, salt_len());
	*/
	return(true);
}

RTPsecure::RTPsecure(eMode mode, Call *call, CallBranch *c_branch, int index_ip_port, bool local) {
	#if HAVE_LIBSRTP
		this->mode = mode;
	#else
		if(mode == mode_libsrtp) {
			missingLibSrtpLog();
		}
		this->mode = mode_native;
	#endif
	this->call = call;
	this->c_branch = c_branch;
	this->index_ip_port = index_ip_port;
	this->local = local;
	cryptoConfigCallSize = 0;
	cryptoConfigActiveIndex = 0;
	rtcp_index = 0;
	rtp_roc = 0;
	rtp_find_roc_max = 100;
	rtp_find_roc_attempts_max = 5;
	rtp_seq = 0;
	rtp_rcc = 1;
	rtp_seq_init = false;
	rtp = NULL;
	rtcp = NULL;
	error = err_na;
	rtcp_unencrypt_header_len = 8;
	rtcp_unencrypt_footer_len = 4;
	decrypt_rtp_ok = 0;
	decrypt_rtp_failed = 0;
	decrypt_rtcp_ok = 0;
	decrypt_rtcp_failed = 0;
	last_client_random_at_us = 0;
}

RTPsecure::~RTPsecure() {
	term();
}

bool RTPsecure::setCryptoConfig(u_int64_t time_us) {
	if(!call || !c_branch) {
		return(false);
	}
	if(local && !decrypt_rtp_ok && decrypt_rtp_failed > 0 &&
	   call->dtls_keys_count() * 2 > cryptoConfigVector.size()) {
		unsigned call_keys_count = call->dtls_keys_count();
		for(unsigned i = 0; i < call_keys_count; i++) {
			cDtlsLink::sSrtpKeys *keys_item = call->dtls_keys_get(i);
			if(keys_item) {
				if(addCryptoConfig(0, keys_item->cipher.c_str(), keys_item->server_key.c_str(), time_us)) {
					clearError();
				}
				if(addCryptoConfig(0, keys_item->cipher.c_str(), keys_item->client_key.c_str(), time_us)) {
					clearError();
				}
			}
		}
	}
	extern bool opt_srtp_use_all_keys;
	if(!opt_srtp_use_all_keys &&
	   index_ip_port >= 0 && index_ip_port < c_branch->ipport_n &&
	   c_branch->ip_port[index_ip_port].srtp_crypto_config_list &&
	   cryptoConfigCallSize != c_branch->ip_port[index_ip_port].srtp_crypto_config_list->size()) {
		for(list<srtp_crypto_config>::iterator iter = c_branch->ip_port[index_ip_port].srtp_crypto_config_list->begin();
		    iter != c_branch->ip_port[index_ip_port].srtp_crypto_config_list->end();
		    iter++) {
			this->addCryptoConfig(iter->tag, iter->suite.c_str(), iter->key.c_str(), iter->from_time_us);
		}
		cryptoConfigCallSize = c_branch->ip_port[index_ip_port].srtp_crypto_config_list->size();
		return(true);
	} else if(index_ip_port < 0 || opt_srtp_use_all_keys) {
		unsigned sum_srtp_crypto_config_list_size = 0;
		for(int i = 0; i < c_branch->ipport_n; i++) {
			if(c_branch->ip_port[i].srtp_crypto_config_list) {
				sum_srtp_crypto_config_list_size += c_branch->ip_port[i].srtp_crypto_config_list->size();
			}
		}
		if(cryptoConfigCallSize != sum_srtp_crypto_config_list_size) {
			for(int i = 0; i < c_branch->ipport_n; i++) {
				if(c_branch->ip_port[i].srtp_crypto_config_list) {
					for(list<srtp_crypto_config>::iterator iter = c_branch->ip_port[i].srtp_crypto_config_list->begin();
					    iter != c_branch->ip_port[i].srtp_crypto_config_list->end();
					    iter++) {
						this->addCryptoConfig(iter->tag, iter->suite.c_str(), iter->key.c_str(), iter->from_time_us);
					}
				}
			}
			cryptoConfigCallSize = sum_srtp_crypto_config_list_size;
			return(true);
		}
	}
	return(false);
}

bool RTPsecure::addCryptoConfig(unsigned tag, const char *suite, const char *sdes, u_int64_t from_time_us) {
	for(unsigned i = 0; i < cryptoConfigVector.size(); i++) {
		if(cryptoConfigVector[i].suite == suite && 
		   cryptoConfigVector[i].sdes == sdes) {
			 return(false);
		}
	}
	sCryptoConfig cryptoConfig;
	cryptoConfig.tag = tag;
	cryptoConfig.suite = suite;
	cryptoConfig.sdes = sdes;
	cryptoConfig.from_time_us = from_time_us;
	if(cryptoConfig.init() && cryptoConfig.keyDecode()) {
		cryptoConfigVector.push_back(cryptoConfig);
		if(sverb.dtls && ssl_sessionkey_enable()) {
			string log_str;
			log_str += string("add crypto config for call: ") + call->call_id;
			log_str += "; cipher: " + string(suite);
			log_str += "; key: " + hexdump_to_string_from_base64(sdes);
			ssl_sessionkey_log(log_str);
		}
		return(true);
	}
	return(false);
}

bool RTPsecure::existsNewerCryptoConfig(u_int64_t time_us) {
	for(unsigned i = 0; i < cryptoConfigVector.size(); i++) {
		if(i != cryptoConfigActiveIndex &&
		   cryptoConfigVector[i].from_time_us >= cryptoConfigVector[cryptoConfigActiveIndex].from_time_us &&
		   time_us > cryptoConfigVector[i].from_time_us) {
			return(true);
		}
	}
	return(false);
}

void RTPsecure::prepare_decrypt(vmIP saddr, vmIP daddr, vmPort sport, vmPort dport, bool callFromRtcp, u_int64_t time_us) {
	if(sverb.dtls && ssl_sessionkey_enable()) {
		string log_str;
		log_str += string("do prepare_decrypt for call: ") + call->call_id + " " + (callFromRtcp ? "rtcp" : "rtp");
		log_str += "; stream: " + saddr.getString() + ":" + sport.getString() + " -> " + daddr.getString() + ":" + dport.getString() +
			   "; is_dtls: " + intToString(is_dtls()) + " cryptoConfigVector.size: " + intToString(cryptoConfigVector.size());
		ssl_sessionkey_log(log_str);
	}
	if(is_dtls() && 
	   (!cryptoConfigVector.size() || 
	    (call->dtls && call->dtls->getLastClientRandomAt_us() > last_client_random_at_us))) {
		for(int pass_source_dtls_object = 0; pass_source_dtls_object < (opt_ssl_dtls_handshake_safe >= 2 ? 2 : 1); pass_source_dtls_object++) {
			cDtls *source_dtls_object = pass_source_dtls_object == 0 ? call->dtls : &dtls_handshake_safe_links;
			if(source_dtls_object) {
				list<cDtlsLink::sSrtpKeys*> keys;
				int8_t direction; int8_t node;
				if(source_dtls_object->findSrtpKeys(saddr, sport, daddr, dport, &keys, &direction, &node, call,
								    pass_source_dtls_object == 0, pass_source_dtls_object == 1)) {
					for(list<cDtlsLink::sSrtpKeys*>::iterator iter_keys = keys.begin(); iter_keys != keys.end(); iter_keys++) {
						cDtlsLink::sSrtpKeys *keys_item = *iter_keys;
						if(direction == 0) {
							if(sverb.dtls && ssl_sessionkey_enable()) {
								string log_str;
								log_str += string("set crypto config for call: ") + call->call_id + " " + (callFromRtcp ? "rtcp" : "rtp");
								log_str += "; stream: " + saddr.getString() + ":" + sport.getString() + " -> " + daddr.getString() + ":" + dport.getString() + " d" + intToString(direction);
								log_str += "; cipher: " + keys_item->cipher;
								log_str += "; key: " + hexdump_to_string_from_base64(keys_item->server_key.c_str());
								log_str += "; node: " + string(node == 1 ? "server" : (node == 2 ? "client" : "both"));
								log_str += "; source: " + string(pass_source_dtls_object == 0 ? "call" : "safe");
								ssl_sessionkey_log(log_str);
							}
							if(addCryptoConfig(0, keys_item->cipher.c_str(), keys_item->server_key.c_str(), time_us)) {
								clearError();
								if(call->dtls && call->dtls->getLastClientRandomAt_us() > last_client_random_at_us) {
									last_client_random_at_us = call->dtls->getLastClientRandomAt_us();
								}
							}
						} else if(direction == 1) {
							if(sverb.dtls && ssl_sessionkey_enable()) {
								string log_str;
								log_str += string("set crypto config for call: ") + call->call_id + " " + (callFromRtcp ? "rtcp" : "rtp");
								log_str += "; stream: " + saddr.getString() + ":" + sport.getString() + " -> " + daddr.getString() + ":" + dport.getString() + " d" + intToString(direction);
								log_str += "; cipher: " + keys_item->cipher;
								log_str += "; key: " + hexdump_to_string_from_base64(keys_item->client_key.c_str());
								log_str += "; node: " + string(node == 1 ? "server" : (node == 2 ? "client" : "both"));
								log_str += "; source: " + string(pass_source_dtls_object == 0 ? "call" : "safe");
								ssl_sessionkey_log(log_str);
							}
							if(addCryptoConfig(0, keys_item->cipher.c_str(), keys_item->client_key.c_str(), time_us)) {
								clearError();
								if(call->dtls && call->dtls->getLastClientRandomAt_us() > last_client_random_at_us) {
									last_client_random_at_us = call->dtls->getLastClientRandomAt_us();
								}
							}
						}
						delete keys_item;
					}
				}
			}
		}
	}
}

bool RTPsecure::is_dtls() {
	return((call && call->dtls_exists) ||
	       (index_ip_port >= 0 &&
		(c_branch && c_branch->ip_port[index_ip_port].srtp && 
		 (c_branch->ip_port[index_ip_port].srtp_fingerprint || !c_branch->ip_port[index_ip_port].srtp_crypto_config_list))));
}

bool RTPsecure::decrypt_rtp(u_char *data, unsigned *data_len, u_char *payload, unsigned *payload_len, u_int64_t time_us,
			    vmIP saddr, vmIP daddr, vmPort sport, vmPort dport, RTP *stream) {
	unsigned failed_log_limit = 20;
	setCryptoConfig(time_us);
	if(!cryptoConfigVector.size()) {
		#if not EXPERIMENTAL_LITE_RTP_MOD
		++decrypt_rtp_failed;
		if(stream) ++stream->decrypt_srtp_failed;
		if(is_dtls() && sverb.dtls && ssl_sessionkey_enable() && stream && stream->decrypt_srtp_failed < failed_log_limit) {
			string log_str;
			log_str += string("decrypt_rtp failed ") + intToString(stream->decrypt_srtp_failed) + 
				   " (empty cryptoConfigVector) for call: " + call->call_id;
			log_str += "; stream: " + saddr.getString() + ":" + sport.getString() + " -> " + daddr.getString() + ":" + dport.getString() + " ssrc_index " + intToString(stream->ssrc_index);
			ssl_sessionkey_log(log_str);
		}
		#endif
		return(false);
	}
	if(!rtp && cryptoConfigVector.size() == 1) {
		cryptoConfigActiveIndex = 0;
		init();
	}
	if(!isOK()) {
		++decrypt_rtp_failed;
		#if not EXPERIMENTAL_LITE_RTP_MOD
		if(stream) ++stream->decrypt_srtp_failed;
		if(is_dtls() && sverb.dtls && ssl_sessionkey_enable() && stream && stream->decrypt_srtp_failed < failed_log_limit) {
			string log_str;
			log_str += string("decrypt_rtp failed ") + intToString(stream->decrypt_srtp_failed)  + 
				   " (not isOK) for call: " + call->call_id;
			log_str += "; stream: " + saddr.getString() + ":" + sport.getString() + " -> " + daddr.getString() + ":" + dport.getString() + " ssrc_index " + intToString(stream->ssrc_index);
			ssl_sessionkey_log(log_str);
		}
		#endif
		return(false);
	}
	if(rtp) {
		if(*payload_len > tag_size()) {
			++rtp->counter_packets;
			if(mode == mode_native ?
			    decrypt_rtp_native(data, data_len, payload, payload_len) :
			    decrypt_rtp_libsrtp(data, data_len, payload, payload_len)) {
				#if not EXPERIMENTAL_LITE_RTP_MOD
				if(call && is_dtls() && sverb.dtls && ssl_sessionkey_enable() && stream && !stream->decrypt_srtp_ok) {
					string log_str;
					log_str += string("decrypt_rtp ok 1 (") + (mode == mode_native ? "native" : "libsrtp") + ") for call: " + call->call_id;
					log_str += "; stream: " + saddr.getString() + ":" + sport.getString() + " -> " + daddr.getString() + ":" + dport.getString() + " ssrc_index " + intToString(stream->ssrc_index);
					ssl_sessionkey_log(log_str);
				}
				#endif
				++decrypt_rtp_ok;
				#if not EXPERIMENTAL_LITE_RTP_MOD
				if(stream) ++stream->decrypt_srtp_ok;
				#endif
				return(true);
			} else {
				prepare_decrypt(saddr, daddr, sport, dport, false, time_us);
				if(cryptoConfigVector.size() > 1 && existsNewerCryptoConfig(time_us)) {
					term();
				}
				#if not EXPERIMENTAL_LITE_RTP_MOD
				if(call && is_dtls() && sverb.dtls && ssl_sessionkey_enable() && stream && stream->decrypt_srtp_failed < failed_log_limit) {
					string log_str;
					log_str += string("decrypt_rtp failed 1/") + intToString(stream->decrypt_srtp_failed) + 
						   " (" + (mode == mode_native ? "native" : "libsrtp") + ") for call: " + call->call_id;
					log_str += "; stream: " + saddr.getString() + ":" + sport.getString() + " -> " + daddr.getString() + ":" + dport.getString() + " ssrc_index " + intToString(stream->ssrc_index);
					ssl_sessionkey_log(log_str);
				}
				#endif
			}
		}
	}
	if(!rtp) {
		bool counter_packet_inc = false;
		for(int tryCryptoConfigActiveIndex = cryptoConfigVector.size() - 1; tryCryptoConfigActiveIndex >= 0; tryCryptoConfigActiveIndex--) {
			if(cryptoConfigVector[tryCryptoConfigActiveIndex].attempts_rtp > 50) {
				continue;
			}
			++cryptoConfigVector[tryCryptoConfigActiveIndex].attempts_rtp;
			if(*payload_len > tag_size()) {
				unsigned cryptoConfigActiveIndex_old = cryptoConfigActiveIndex;
				cryptoConfigActiveIndex = tryCryptoConfigActiveIndex;
				if(!init()) {
					term();
					continue;
				}
				if(!counter_packet_inc) {
					++rtp->counter_packets;
					counter_packet_inc = true;
				}
				bool rslt_decrypt = mode == mode_native ?
						     decrypt_rtp_native(data, data_len, payload, payload_len) :
						     decrypt_rtp_libsrtp(data, data_len, payload, payload_len);
				if(!rslt_decrypt) {
					term();
					#if not EXPERIMENTAL_LITE_RTP_MOD
					if(is_dtls() && sverb.dtls && ssl_sessionkey_enable() && stream && stream->decrypt_srtp_failed < failed_log_limit) {
						string log_str;
						log_str += string("decrypt_rtp failed 2/") + intToString(stream->decrypt_srtp_failed) + 
							   " (" + (mode == mode_native ? "native" : "libsrtp") + ") for call: " + call->call_id;
						log_str += "; stream: " + saddr.getString() + ":" + sport.getString() + " -> " + daddr.getString() + ":" + dport.getString() + " ssrc_index " + intToString(stream->ssrc_index);
						log_str += "; try key: " + hexdump_to_string_from_base64(cryptoConfigVector[tryCryptoConfigActiveIndex].sdes.c_str());
						ssl_sessionkey_log(log_str);
					}
					#endif
					cryptoConfigActiveIndex = cryptoConfigActiveIndex_old;
					continue;
				}
				#if not EXPERIMENTAL_LITE_RTP_MOD
				if(is_dtls() && sverb.dtls && ssl_sessionkey_enable() && stream && !stream->decrypt_srtp_ok) {
					string log_str;
					log_str += string("decrypt_rtp ok 2 (") + (mode == mode_native ? "native" : "libsrtp") + ") for call: " + call->call_id;
					log_str += "; stream: " + saddr.getString() + ":" + sport.getString() + " -> " + daddr.getString() + ":" + dport.getString() + " ssrc_index " + intToString(stream->ssrc_index);
					ssl_sessionkey_log(log_str);
				}
				#endif
				++decrypt_rtp_ok;
				#if not EXPERIMENTAL_LITE_RTP_MOD
				if(stream) ++stream->decrypt_srtp_ok;
				#endif
				return(true);
			}
		}
	}
	++decrypt_rtp_failed;
	#if not EXPERIMENTAL_LITE_RTP_MOD
	if(stream) ++stream->decrypt_srtp_failed;
	if(is_dtls() && sverb.dtls && ssl_sessionkey_enable() && stream && stream->decrypt_srtp_failed < failed_log_limit) {
		string log_str;
		log_str += string("decrypt_rtp failed 3/") + intToString(stream->decrypt_srtp_failed) + 
			   " (" + (mode == mode_native ? "native" : "libsrtp") + ") for call: " + call->call_id;
		log_str += "; stream: " + saddr.getString() + ":" + sport.getString() + " -> " + daddr.getString() + ":" + dport.getString() + " ssrc_index " + intToString(stream->ssrc_index);
		ssl_sessionkey_log(log_str);
	}
	#endif
	return(false);
}

bool RTPsecure::decrypt_rtp_native(u_char *data, unsigned *data_len, u_char *payload, unsigned *payload_len) {
	#if HAVE_LIBGNUTLS
	uint16_t seq = get_seq_rtp(data);
	uint32_t ssrc = get_ssrc_rtp(data);
	if(!rtp_seq_init) {
		rtp_seq = seq;
		rtp_seq_init = true;
	}
	uint32_t roc = compute_rtp_roc(seq);
	if(is_aead()) {
		u_char decrypted[*data_len];
		unsigned decrypted_len;
		bool rslt = rtpDecryptAead(data, *data_len, payload, *payload_len,
					   seq, ssrc, roc,
					   decrypted, &decrypted_len);
		if(!rslt) {
			if(rtp_find_roc_attempts_max) {
				if(!rtp_roc_ok[cryptoConfigActiveIndex] && rtp_find_roc_attempts[cryptoConfigActiveIndex] < rtp_find_roc_attempts_max) {
					++rtp_find_roc_attempts[cryptoConfigActiveIndex];
					unsigned rtp_roc_old = rtp_roc;
					unsigned roc_try_max = 100;
					for(unsigned roc_try = 0; roc_try < roc_try_max; roc_try++) {
						rtp_roc = roc_try;
						roc = compute_rtp_roc(seq);
						rslt = rtpDecryptAead(data, *data_len, payload, *payload_len,
								      seq, ssrc, roc,
								      decrypted, &decrypted_len);
						if(rslt) {
							rtp_roc_ok[cryptoConfigActiveIndex] = true;
							break;
						}
					}
					if(!rtp_roc_ok[cryptoConfigActiveIndex]) {
						rtp_roc = rtp_roc_old;
						return(false);
					}
				} else {
					return(false);
				}
			} else {
				return(false);
			}
		}
		memcpy(payload, decrypted, decrypted_len);
		*data_len -= tag_size();
		*payload_len -= tag_size();
		rtp_seq = seq;
		rtp_roc = roc;
		rtp_roc_ok[cryptoConfigActiveIndex] = true;
		return(true);
	} else {
		u_char *tag = rtp_digest(data, *data_len - tag_size(), roc);
		if(!memcmp(data + *data_len - tag_size(), tag, tag_size())) {
			this->rtp_roc_ok[cryptoConfigActiveIndex] = true;
		} else if(rtp_find_roc_attempts_max) {
			//cout << rtp->counter_packets << " err (tag)" << endl;
			//hexdump(data + *data_len - tag_size(), tag_size());
			//hexdump(tag, tag_size());
			if(!this->rtp_roc_ok[cryptoConfigActiveIndex] && this->rtp_find_roc_attempts[cryptoConfigActiveIndex] < rtp_find_roc_attempts_max) {
				++this->rtp_find_roc_attempts[cryptoConfigActiveIndex];
				unsigned rtp_roc_old = this->rtp_roc;
				unsigned roc_try_max = 100;
				for(unsigned roc_try = 0; roc_try < roc_try_max; roc_try++) {
					this->rtp_roc = roc_try;
					roc = compute_rtp_roc(seq);
					tag = rtp_digest(data, *data_len - tag_size(), roc);
					if(!memcmp(data + *data_len - tag_size(), tag, tag_size())) {
						this->rtp_roc_ok[cryptoConfigActiveIndex] = true;
						break;
					}
				}
				if(!this->rtp_roc_ok[cryptoConfigActiveIndex]) {
					this->rtp_roc = rtp_roc_old;
					return(false);
				}
			} else {
				return(false);
			}
		}
		//hexdump(data, *data_len - tag_size());
		if(!rtpDecrypt(payload, *payload_len - tag_size(), seq, ssrc)) {
			//cout << rtp->counter_packets << " err (decrypt)" << endl;
			return(false);
		}
		*data_len -= tag_size();
		*payload_len -= tag_size();
	}
	//cout << rtp->counter_packets << " ok" << endl;
	//hexdump(data, *data_len - tag_size());
	return(true);
	#else
	return(false);
	#endif
}

bool RTPsecure::decrypt_rtp_libsrtp(u_char *data, unsigned *data_len, u_char */*payload*/, unsigned *payload_len) {
	bool rslt = false;
	#if HAVE_LIBSRTP
	int _data_len = *data_len;
	bool init_ctx = false;
	for(unsigned pass = 0; pass < 2 && !rslt && !init_ctx; pass ++) {
		if(!rtp->srtp_ctx || pass == 1) {
			if(rtp->srtp_ctx) {
				srtp_dealloc(rtp->srtp_ctx);
				rtp->srtp_ctx = NULL;
			}
			rtp->policy.ssrc.value = get_ssrc_rtp(data);
			srtp_create(&rtp->srtp_ctx, &rtp->policy);
			init_ctx = true;
		}
		if(srtp_unprotect(rtp->srtp_ctx, data, &_data_len) == 0) {
			int diff_len = *data_len - _data_len;
			*data_len = _data_len;
			*payload_len -= diff_len;
			rslt = true;
		}
	}
	#else
	missingLibSrtpLog();
	#endif
	//cout << rtp->counter_packets << (rslt ? " ok" : " err") << endl;
	return(rslt);
}

bool RTPsecure::decrypt_rtcp(u_char *data, unsigned *data_len, u_int64_t time_us) {
	setCryptoConfig(time_us);
	if(!cryptoConfigVector.size()) {
		++decrypt_rtcp_failed;
		return(false);
	}
	if(!rtcp && cryptoConfigVector.size() == 1) {
		cryptoConfigActiveIndex = 0;
		init();
	}
	if(!isOK()) {
		++decrypt_rtcp_failed;
		return(false);
	}
	if(rtcp) {
		if(*data_len > (tag_size() + rtcp_unencrypt_header_len + rtcp_unencrypt_footer_len)) {
			++rtcp->counter_packets;
			if(mode == mode_native ?
			    decrypt_rtcp_native(data, data_len) :
			    decrypt_rtcp_libsrtp(data, data_len)) {
				++decrypt_rtcp_ok;
				return(true);
			} else if(cryptoConfigVector.size() > 1 && existsNewerCryptoConfig(time_us)) {
				term();
			}
		} 
	}
	if(!rtcp) {
		bool counter_packet_inc = false;
		for(cryptoConfigActiveIndex = 0; cryptoConfigActiveIndex < cryptoConfigVector.size(); cryptoConfigActiveIndex++) {
			if(cryptoConfigVector[cryptoConfigActiveIndex].attempts_rtcp > 20) {
				continue;
			}
			++cryptoConfigVector[cryptoConfigActiveIndex].attempts_rtcp;
			if(*data_len > (tag_size() + rtcp_unencrypt_header_len + rtcp_unencrypt_footer_len)) {
				if(!init()) {
					term();
					continue;
				}
				if(!counter_packet_inc) {
					++rtcp->counter_packets;
					counter_packet_inc = true;
				}
				if(!(mode == mode_native ?
				      decrypt_rtcp_native(data, data_len) :
				      decrypt_rtcp_libsrtp(data, data_len))) {
					term();
					continue;
				}
				++decrypt_rtcp_ok;
				return(true);
			}
		}
	}
	++decrypt_rtcp_failed;
	return(false);
}

bool RTPsecure::decrypt_rtcp_native(u_char *data, unsigned *data_len) {
	#if HAVE_LIBGNUTLS
	if(is_aead()) {
		u_char decrypted[*data_len];
		unsigned decrypted_len;
		bool rslt = rtcpDecryptAead(data, *data_len,
					    decrypted, &decrypted_len);
		if(!rslt) {
			return(false);
		}
		memcpy(data + rtcp_unencrypt_header_len, decrypted, decrypted_len);
		*data_len -= tag_size();
	} else {
		u_char *tag = rtcp_digest(data, *data_len - tag_size());
		if(memcmp(data + *data_len - tag_size(), tag, tag_size())) {
			return(false);
		}
		if(!rtcpDecrypt(data, *data_len - tag_size())) {
			return(false);
		}
		*data_len -= tag_size();
	}
	return(true);
	#else
	return(false);
	#endif
}

bool RTPsecure::decrypt_rtcp_libsrtp(u_char *data, unsigned *data_len) {
	bool rslt = false;
	#if HAVE_LIBSRTP
	int _data_len = *data_len;
	bool init_ctx = false;
	for(unsigned pass = 0; pass < 2 && !rslt && !init_ctx; pass ++) {
		if(!rtcp->srtp_ctx || pass == 1) {
			if(rtcp->srtp_ctx) {
				srtp_dealloc(rtcp->srtp_ctx);
				rtcp->srtp_ctx = NULL;
			}
			rtcp->policy.ssrc.value = get_ssrc_rtcp(data);
			srtp_create(&rtcp->srtp_ctx, &rtcp->policy);
			init_ctx = true;
		}
		if(srtp_unprotect_rtcp(rtcp->srtp_ctx, data, &_data_len) == 0) {
			*data_len = _data_len;
			rslt = true;
		}
	}
	#else
	missingLibSrtpLog();
	#endif
	return(rslt);
}

void RTPsecure::setError(eError error) {
	this->error = error;
}

void RTPsecure::clearError() {
	this->error = err_na;
}

bool RTPsecure::isOkCryptoSuite(const char *crypto_suite) {
	#if HAVE_LIBGNUTLS
	if(crypto_suite && *crypto_suite) {
		for(unsigned i = 0; i < sizeof(srtp_crypto_suites) / sizeof(srtp_crypto_suites[0]); i++) {
			if(crypto_suite == srtp_crypto_suites[i].crypro_suite) {
				return(true);
			}
		}
	}
	#endif
	return(false);

}

bool RTPsecure::init() {
	if(rtp && rtcp) {
		return(true);
	}
	term();
	rtcp_index = 0;
	rtp_roc = 0;
	rtp_seq = 0;
	rtp_rcc = 1;
	rtp_seq_init = false;
	rtp = new FILE_LINE(0) sDecrypt;
	rtcp = new FILE_LINE(0) sDecrypt;
	if(mode == mode_native) {
		return(init_native());
	} else {
		return(init_libsrtp());
	}
}

void RTPsecure::term() {
	if(rtp) {
		delete rtp;
		rtp = NULL;
	}
	if(rtcp) {
		delete rtcp;
		rtcp = NULL;
	}
	clearError();
}

bool RTPsecure::init_native() {
	#if HAVE_LIBGNUTLS
	if(is_aead()) {
		#if HAVE_OPENSSL
		derive_key_aead(key(), salt(), 0x00, rtp->session_key, key_len());
		derive_key_aead(key(), salt(), 0x02, rtp->session_salt, salt_len());
		rtp->ctx = EVP_CIPHER_CTX_new();
		EVP_DecryptInit_ex(rtp->ctx, key_size() == 256 ? EVP_aes_256_gcm() : EVP_aes_128_gcm(), NULL, NULL, NULL);
		EVP_CIPHER_CTX_ctrl(rtp->ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
		derive_key_aead(key(), salt(), 0x03, rtcp->session_key, key_len());
		derive_key_aead(key(), salt(), 0x04, rtcp->session_salt, salt_len());
		rtcp->ctx = EVP_CIPHER_CTX_new();
		EVP_DecryptInit_ex(rtcp->ctx, key_size() == 256 ? EVP_aes_256_gcm() : EVP_aes_128_gcm(), NULL, NULL, NULL);
		EVP_CIPHER_CTX_ctrl(rtcp->ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
		#endif
	} else {
		extern bool init_lib_gcrypt();
		if(!init_lib_gcrypt()) {
			setError(err_gcrypt_init);
			return(false);
		}
		if(cryptoConfigVector.size() && cryptoConfigActiveIndex < cryptoConfigVector.size() &&
		   cryptoConfigVector[cryptoConfigActiveIndex].tag_size > gcry_md_get_algo_dlen(cryptoConfigVector[cryptoConfigActiveIndex].md)) {
			setError(err_bad_tag_size);
			return(false);
		}
		if(gcry_cipher_open(&rtp->cipher, cipher(), GCRY_CIPHER_MODE_CTR, 0)) {
			setError(err_cipher_open);
			return(false);
		}
		if(gcry_md_open(&rtp->md, md(), GCRY_MD_FLAG_HMAC)) {
			setError(err_md_open);
			return(false);
		}
		if(gcry_cipher_open(&rtcp->cipher, cipher(), GCRY_CIPHER_MODE_CTR, 0)) {
			setError(err_cipher_open);
			return(false);
		}
		if(gcry_md_open(&rtcp->md, md(), GCRY_MD_FLAG_HMAC)) {
			setError(err_md_open);
			return(false);
		}
		gcry_cipher_hd_t _cipher;
		if(gcry_cipher_open(&_cipher, key_size() == 256 ? GCRY_CIPHER_AES256 : GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CTR, 0) ||
		   gcry_cipher_setkey(_cipher, key(), key_len())) {
			setError(err_set_key);
			return(false);
		}
		// SRTP key derivation
		u_char r[6];
		u_char keybuf[100];
		memset(r, 0, sizeof(r));
		memset(keybuf, 0, sizeof (keybuf));
		if(do_derive(_cipher, r, 6, SRTP_CRYPT, keybuf, key_len()) ||
		   gcry_cipher_setkey(rtp->cipher, keybuf, key_len()) ||
		   do_derive(_cipher, r, 6, SRTP_AUTH, keybuf, 20) ||
		   gcry_md_setkey(rtp->md, keybuf, 20) ||
		   do_derive (_cipher, r, 6, SRTP_SALT, (u_char*)rtp->salt, salt_len())) {
			setError(err_set_key);
			gcry_cipher_close(_cipher);
			return(false);
		}
		// SRTCP key derivation
		uint32_t _rtcp_index = htonl(this->rtcp_index);
		memcpy(r, &_rtcp_index, 4);
		if(do_derive(_cipher, r, 6, SRTCP_CRYPT, keybuf, key_len()) ||
		   gcry_cipher_setkey(rtcp->cipher, keybuf, key_len()) ||
		   do_derive(_cipher, r, 6, SRTCP_AUTH, keybuf, 20) ||
		   gcry_md_setkey (rtcp->md, keybuf, 20) ||
		   do_derive (_cipher, r, 6, SRTCP_SALT, (u_char*)rtcp->salt, salt_len())) {
			setError(err_set_key);
			gcry_cipher_close(_cipher);
			return(false);
		}
		gcry_cipher_close(_cipher);
	}
    return(true);
	#else
	return(false);
	#endif
}

bool RTPsecure::init_libsrtp() {
	#if HAVE_LIBSRTP
	extern void init_lib_srtp();
	init_lib_srtp();
	for(int i = 0; i < 2; i++) {
		srtp_policy_t *policy = i == 0 ? &rtp->policy : &rtcp->policy;
		memset(policy, 0x0, sizeof(srtp_policy_t));
		if(is_aead()) {
			switch (key_size()) {
			case 128:
				srtp_crypto_policy_set_aes_gcm_128_16_auth(&policy->rtp);
				srtp_crypto_policy_set_aes_gcm_128_16_auth(&policy->rtcp);
				break;
			case 256:
				srtp_crypto_policy_set_aes_gcm_256_16_auth(&policy->rtp);
				srtp_crypto_policy_set_aes_gcm_256_16_auth(&policy->rtcp);
				break;
			}
		} else {
			switch(key_size()) {
			case 128:
				switch(tag_size()) {
				case 10:
					srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy->rtp);
					srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy->rtcp);
					break;
				case 4:
					srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&policy->rtp);
					srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&policy->rtcp);
					break;
				}
				break;
			case 256:
				switch(tag_size()) {
				case 10:
					srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(&policy->rtp);
					srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(&policy->rtcp);
					break;
				case 4:
					srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(&policy->rtp);
					srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(&policy->rtcp);
					break;
				}
				break;
			}
		}
		policy->key = key_salt();
		policy->ssrc.type = ssrc_specific;
		policy->next = NULL;
		policy->window_size = 128;
		policy->rtp.sec_serv = sec_serv_conf_and_auth;
		policy->rtp.auth_tag_len = tag_size();
		policy->rtcp.sec_serv = sec_serv_conf_and_auth;
		policy->rtcp.auth_tag_len = tag_size();
	}
	#endif
	return(true);
}

bool RTPsecure::rtpDecrypt(u_char *payload, unsigned payload_len, uint16_t seq, uint32_t ssrc) {
	uint32_t roc = compute_rtp_roc(seq);
	// Updates ROC and sequence (it's safe now)
	int16_t diff = seq - this->rtp_seq;
	if(diff > 0) {
		// Sequence in the future, good
		rtp->window = rtp->window << diff;
		rtp->window |= 1;
		rtp_seq = seq;
		rtp_roc = roc;
	} else {
		// Sequence in the past/present, bad
		diff = -diff;
		if((diff >= 64) || ((rtp->window >> diff) & 1)) {
			return(false); // Replay attack
		}
		rtp->window |= 1 << diff;
	}
	#if HAVE_LIBGNUTLS
	if(rtp_decrypt(payload, payload_len, ssrc, roc, seq)) {
		return(false);
	}
	#endif
	return(true);
}

bool RTPsecure::rtcpDecrypt(u_char *data, unsigned data_len) {
	uint32_t index;
	memcpy(&index, data + data_len - rtcp_unencrypt_footer_len, 4);
	index = ntohl (index);
	index &= ~(1 << 31); // clear E-bit for counter
	// Updates SRTCP index (safe here)
	int32_t diff = index - this->rtcp_index;
	if (diff > 0) {
		// Packet in the future, good
		rtcp->window = rtcp->window << diff;
		rtcp->window |= 1;
		rtcp_index = index;
	} else {
		// Packet in the past/present, bad
		diff = -diff;
		if ((diff >= 64) || ((rtcp->window >> diff) & 1)) {
			return(false); // replay attack!
		}
		rtcp->window |= 1 << diff;
	}
	#if HAVE_LIBGNUTLS
	if(rtcp_decrypt(data + rtcp_unencrypt_header_len, data_len - rtcp_unencrypt_header_len - rtcp_unencrypt_footer_len, get_ssrc_rtcp(data), index)) {
		return(false);
	}
	#endif
	return(true);
}

bool RTPsecure::rtpDecryptAead(u_char *data, unsigned data_len, u_char *payload, unsigned payload_len,
			       uint16_t seq, uint32_t ssrc, uint32_t roc,
			       u_char *decrypted, unsigned *decrypted_len) {
	#if HAVE_OPENSSL
	u_char iv[12];
	compute_aead_iv(rtp->session_salt, ssrc, seq, roc, iv);
	/*
	cout << "PACKET:" << endl;
	hexdump(data, data_len);
	cout << "IV:" << endl;
	hexdump(iv, 12);
	cout << "AAD" << endl;
	hexdump(data, 12);
	cout << "SESSION KEY" << endl;
	hexdump(rtp->session_key, key_len());
	*/
	int len;
	EVP_DecryptInit_ex(rtp->ctx, NULL, NULL, rtp->session_key, iv);
	EVP_DecryptUpdate(rtp->ctx, NULL, &len, data, data_len - payload_len);
	EVP_DecryptUpdate(rtp->ctx, decrypted, &len, payload, payload_len - tag_size());
	*decrypted_len = len;
	EVP_CIPHER_CTX_ctrl(rtp->ctx, EVP_CTRL_GCM_SET_TAG, tag_size(), payload + payload_len - tag_size());
	int rslt = EVP_DecryptFinal_ex(rtp->ctx, decrypted + *decrypted_len, &len);
	*decrypted_len += len;
	/*
	if(rslt > 0) {
		hexdump(decrypted, decrypted_len);
	}
	*/
	return(rslt > 0);
	#else
	missingOpensslLogForAead();
	return(false);
	#endif
}

bool RTPsecure::rtcpDecryptAead(u_char *data, unsigned data_len,
				u_char *decrypted, unsigned *decrypted_len) {
	#if HAVE_OPENSSL
	uint32_t index;
	memcpy(&index, data + data_len - rtcp_unencrypt_footer_len - tag_size(), 4);
	index = ntohl (index);
	bool e = index & 0x80000000;
	index &= 0x7fffffff;
	if(!e) {
		return(false);
	}
	u_char iv[12];
	compute_aead_iv_rtcp(rtcp->session_salt, get_ssrc_rtcp(data), index, iv);
	int len;
	EVP_DecryptInit_ex(rtcp->ctx, NULL, NULL, rtcp->session_key, iv);
	EVP_DecryptUpdate(rtcp->ctx, NULL, &len, data, rtcp_unencrypt_header_len);
	EVP_DecryptUpdate(rtcp->ctx, decrypted, &len, data + rtcp_unencrypt_header_len, data_len - rtcp_unencrypt_header_len - rtcp_unencrypt_footer_len - tag_size());
	*decrypted_len = len;
	EVP_CIPHER_CTX_ctrl(rtcp->ctx, EVP_CTRL_GCM_SET_TAG, tag_size(), data + data_len - tag_size());
	int rslt = EVP_DecryptFinal_ex(rtcp->ctx, decrypted + *decrypted_len, &len);
	*decrypted_len += len;
	return(rslt > 0);
	#else
	missingOpensslLogForAead();
	return(false);
	#endif
}

uint32_t RTPsecure::compute_rtp_roc(uint16_t seq) {
	uint32_t roc = this->rtp_roc;
	if(((seq - this->rtp_seq) & 0xffff) < 0x8000) {
		// Sequence is ahead, good
		if(seq < this->rtp_seq)
			roc++; // Sequence number wrap
	} else {
		// Sequence is late, bad
		if(seq > this->rtp_seq) {
			roc--; // Wrap back
		}
	}
	return(roc);
}

u_char *RTPsecure::rtp_digest(u_char *data, size_t data_len, uint32_t roc) {
	#if HAVE_LIBGNUTLS
	gcry_md_reset(rtp->md);
	gcry_md_write(rtp->md, data, data_len);
	roc = htonl(roc);
	gcry_md_write(rtp->md, &roc, 4);
	return(gcry_md_read(rtp->md, 0));
	#else
	return(NULL);
	#endif
}

u_char *RTPsecure::rtcp_digest(u_char *data, size_t data_len) {
	#if HAVE_LIBGNUTLS
	gcry_md_reset(rtcp->md);
	gcry_md_write(rtcp->md, data, data_len);
	return(gcry_md_read(rtcp->md, 0));
	#else
	return(NULL);
	#endif
}

#if HAVE_LIBGNUTLS
int RTPsecure::rtp_decrypt(u_char *data, unsigned data_len, uint32_t ssrc, uint32_t roc, uint16_t seq) {
	// Determines cryptographic counter (IV)
	uint32_t counter[4];
	counter[0] = rtp->salt[0];
	counter[1] = rtp->salt[1] ^ htonl(ssrc);
	counter[2] = rtp->salt[2] ^ htonl(roc);
	counter[3] = rtp->salt[3] ^ htonl(seq << 16);
	// Decryption
	return(do_ctr_crypt(rtp->cipher, (u_char*)counter, data, data_len));
}

int RTPsecure::rtcp_decrypt(u_char *data, unsigned data_len, uint32_t ssrc, uint32_t index) {
	uint32_t counter[4];
	counter[0] = rtcp->salt[0];
	counter[1] = rtcp->salt[1] ^ htonl(ssrc);
	counter[2] = rtcp->salt[2] ^ htonl(index >> 16);
	counter[3] = rtcp->salt[3] ^ htonl((index & 0xffff) << 16);
	// Decryption
	return(do_ctr_crypt(rtcp->cipher, (u_char*)counter, data, data_len));
}

int RTPsecure::do_derive(gcry_cipher_hd_t cipher, u_char *r, unsigned rlen, uint8_t label, u_char *out, unsigned outlen) {
	u_char iv[16];
	memset(iv, 0, sizeof(iv));
	memcpy(iv, salt(), salt_len());
	iv[salt_len() - 1 - rlen] ^= label;
	for(unsigned i = 0; i < rlen; i++) {
		iv[sizeof(iv) - rlen + i] ^= r[i];
	}
	memset(out, 0, outlen);
	return(do_ctr_crypt(cipher, iv, out, outlen));
}

int RTPsecure::do_ctr_crypt (gcry_cipher_hd_t cipher, u_char *ctr, u_char *data, unsigned len) {
	unsigned ctrlen = 16;
	div_t d = div((int)len, (int)ctrlen);
	if(gcry_cipher_setctr(cipher, ctr, ctrlen) ||
	   gcry_cipher_decrypt(cipher, data, d.quot * ctrlen, NULL, 0)) {
		return -1;
	}
	if(d.rem) {
		// Truncated last block */
		u_char dummy[ctrlen];
		data += d.quot * ctrlen;
		memcpy(dummy, data, d.rem);
		memset(dummy + d.rem, 0, ctrlen - d.rem);
		if(gcry_cipher_decrypt(cipher, dummy, ctrlen, NULL, 0)) {
			return -1;
		}
		memcpy(data, dummy, d.rem);
	}
	return(0);
}
#endif

#if HAVE_OPENSSL
void RTPsecure::derive_key_aead(u_char *master_key, u_char *master_salt, uint8_t label, u_char *out, unsigned out_len) {
	u_char block[16] = {0};
	AES_KEY aes_key;
	AES_set_encrypt_key(master_key, key_size(), &aes_key);
	for (int i = 0; i < 12; i++) block[i] ^= master_salt[i];
	block[7] ^= label;
	unsigned generated = 0;
	uint8_t counter = 0;
	while(generated < out_len) {
		block[15] = counter++;
		u_char encrypted[16];
		AES_encrypt(block, encrypted, &aes_key);
		unsigned copy = (out_len - generated > 16) ? 16 : out_len - generated;
		memcpy(out + generated, encrypted, copy);
		generated += copy;
	}
}

void RTPsecure::compute_aead_iv(u_char *salt, uint32_t ssrc, uint16_t seq, uint32_t roc, u_char *out_iv) {
	u_char input[12] = {0};
	input[2] = (ssrc >> 24) & 0xff;
	input[3] = (ssrc >> 16) & 0xff;
	input[4] = (ssrc >> 8) & 0xff;
	input[5] = ssrc & 0xff;
	input[6] = (roc >> 24) & 0xff;
	input[7] = (roc >> 16) & 0xff;
	input[8] = (roc >> 8) & 0xff;
	input[9] = roc & 0xff;
	input[10] = (seq >> 8) & 0xff;
	input[11] = seq & 0xff;
	for(int i = 0; i < 12; i++) {
		out_iv[i] = input[i] ^ salt[i];
	}
}

void RTPsecure::compute_aead_iv_rtcp(u_char *salt, uint32_t ssrc, uint32_t index, u_char *out_iv) {
	u_char input[12] = {0};
	input[4] = (ssrc >> 24) & 0xff;
	input[5] = (ssrc >> 16) & 0xff;
	input[6] = (ssrc >> 8) & 0xff;
	input[7] = ssrc & 0xff;
	input[8] = (index >> 24) & 0xff;
	input[9] = (index >> 16) & 0xff;
	input[10] = (index >> 8) & 0xff;
	input[11] = index & 0xff;
	for(int i = 0; i < 12; i++) {
		out_iv[i] = input[i] ^ salt[i];
	}
}
#endif

void RTPsecure::missingOpensslLogForAead() {
	static volatile int logged;
	if(!logged) {
		syslog(LOG_ERR, "To decrypt aead, a build including the openssl library must be used.");
		logged = true;
	}
}

void RTPsecure::missingLibSrtpLog() {
	static volatile int logged;
	if(!logged) {
		syslog(LOG_ERR, "To decrypt with the libsrtp=yes option, you must use a build that includes the libsrtp library.");
		logged = true;
	}
}
