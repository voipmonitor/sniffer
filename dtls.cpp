#include "dtls.h"

#include "tools.h"
#include "ssl_dssl.h"
#include "calltable.h"


static bool dtls_srtp_keys_block(SimpleBuffer *secret, const char *usage, SimpleBuffer* rnd1, SimpleBuffer* rnd2, SimpleBuffer* out, unsigned out_len);


extern int opt_ssl_dtls_handshake_safe;
extern cDtls dtls_handshake_safe_links;


cDtlsLink::cDtlsLink(vmIP server_ip, vmPort server_port,
		     vmIP client_ip, vmPort client_port) 
	: server(server_ip, server_port),
	  client(client_ip, client_port) {
	init();
}

cDtlsLink::~cDtlsLink() {
	if(handshake_data.client_random_set) {
		erase_client_random(handshake_data.client_random);
	}
}

void cDtlsLink::processHandshake(sHeaderHandshake *handshake, u_int64_t time_us) {
	sHeaderHandshake *defragmented_handshake= NULL;
	if((handshake->handshake_type == DTLS_HANDSHAKE_TYPE_CLIENT_HELLO ||
	    handshake->handshake_type == DTLS_HANDSHAKE_TYPE_SERVER_HELLO) &&
	   handshake->fragment_length_() &&
	   handshake->fragment_length_() < handshake->length_()) {
		if(defragmenter.empty() ||
		   defragmenter.handshake_type != handshake->handshake_type ||
		   defragmenter.length != handshake->length_()) {
			defragmenter.clear();
			defragmenter.handshake_type = handshake->handshake_type;
			defragmenter.length = handshake->length_();
		}
		defragmenter.fragments[handshake->fragment_offset_()].set(handshake, sizeof(cDtlsLink::sHeaderHandshake) + handshake->fragment_length_());
		if(defragmenter.isComplete()) {
			defragmented_handshake = (sHeaderHandshake*)defragmenter.complete();
			handshake = defragmented_handshake;
		} else {
			return;
		}
	}
	if(handshake->handshake_type == DTLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
		cDtlsLink::sHeaderHandshakeHello *handshake_hello = (cDtlsLink::sHeaderHandshakeHello*)handshake;
		setClientRandom(handshake_hello->random);
		unsigned len = handshake->length_() + sizeof(cDtlsLink::sHeaderHandshake);
		unsigned offset = sizeof(sHeaderHandshakeHello);
		unsigned i = 0;
		while(offset < len) {
			switch(i) {
			case 0: // session id length;
				offset += 1 + *(u_int8_t*)((u_char*)handshake + offset);
				break;
			case 1: // cookie length
				offset += 1 + *(u_int8_t*)((u_char*)handshake + offset);
				break;
			case 2: // cipher suite length
				offset += 2 + ntohs(*(u_int16_t*)((u_char*)handshake + offset));
				break;
			case 3: // compression method length
				offset += 1 + *(u_int8_t*)((u_char*)handshake + offset);
				break;
			}
			if(i == 3) {
				break;
			}
			++i;
		}
		if(i == 3) {
			unsigned ext_len = ntohs(*(u_int16_t*)((u_char*)handshake + offset));
			if(ext_len) {
				u_char *ext = (u_char*)handshake + offset + 2;
				unsigned ext_offset = 0;
				while(offset + 2 + ext_offset < len - 4 &&
				      ext_offset < ext_len - 4) {
					u_int16_t e_type = ntohs(*(u_int16_t*)(ext + ext_offset));
					u_int16_t e_len = ntohs(*(u_int16_t*)(ext + ext_offset + 2));
					if(e_type == 14) { // use_srtp
						u_int16_t prot_prof_len = ntohs(*(u_int16_t*)(ext + ext_offset + 4));
						u_int16_t prot_prof = _ct_na;
						if(prot_prof_len == 1) {
							prot_prof = *(u_int8_t*)(ext + ext_offset + 6);
							if(cipherIsSupported(prot_prof)) {
								handshake_data.cipher_types.push_back((eCipherType)prot_prof);
							}
						} else if(prot_prof_len == 2) {
							prot_prof = ntohs(*(u_int16_t*)(ext + ext_offset + 6));
							if(cipherIsSupported(prot_prof)) {
								handshake_data.cipher_types.push_back((eCipherType)prot_prof);
							}
						} else if(prot_prof_len > 2) {
							u_int16_t _offset = 0;
							while(_offset <= prot_prof_len - 2) {
								u_int16_t prot_prof = ntohs(*(u_int16_t*)(ext + ext_offset + 6 + _offset));
								if(cipherIsSupported(prot_prof)) {
									if(cipherIsSupported(prot_prof)) {
										handshake_data.cipher_types.push_back((eCipherType)prot_prof);
									}
								}
								_offset += 2;
							}
						}
						//u_int8_t mki_len = *(u_int8_t*)(ext + ext_offset + 6 + prot_prof_len);
					}
					ext_offset += 4 + e_len;
				}
			}
		}
	} else if(handshake->handshake_type == DTLS_HANDSHAKE_TYPE_SERVER_HELLO) {
		cDtlsLink::sHeaderHandshakeHello *handshake_hello = (cDtlsLink::sHeaderHandshakeHello*)handshake;
		setServerRandom(handshake_hello->random);
	}
	if(sverb.dtls && ssl_sessionkey_enable()) {
		if((handshake->handshake_type == DTLS_HANDSHAKE_TYPE_CLIENT_HELLO && handshake_data.client_random_set) ||
		   (handshake->handshake_type == DTLS_HANDSHAKE_TYPE_SERVER_HELLO && handshake_data.server_random_set)) {
			string log_str;
			log_str += string(handshake->handshake_type == DTLS_HANDSHAKE_TYPE_CLIENT_HELLO ? "detect client random" : "detect server random");
			if(handshake_data.client_random_set) {
				log_str += "; client random: ";
				log_str += hexdump_to_string(handshake_data.client_random, DTLS_RANDOM_SIZE);
			}
			if(handshake_data.server_random_set) {
				log_str += "; server random: ";
				log_str += hexdump_to_string(handshake_data.server_random, DTLS_RANDOM_SIZE);
			}
			ssl_sessionkey_log(log_str);
		}
	}
	if(defragmented_handshake) {
		delete [] ((u_char*)defragmented_handshake);
	}
	last_time_us = time_us;
}

bool cDtlsLink::findSrtpKeys(list<sSrtpKeys*> *keys, Call *call, 
			     bool enable_handshake_safe, bool use_handshake_safe) {
	string log_str;
	if(sverb.dtls && ssl_sessionkey_enable()) {
		log_str += string("find srtp key for call: ") + (call ? call->call_id : "unknown");
		if(use_handshake_safe) {
			log_str += " (use safe handshake)";
		}
	}
	if(opt_ssl_dtls_handshake_safe && enable_handshake_safe) {
		if((opt_ssl_dtls_handshake_safe == 2 || handshake_data.client_random_set || handshake_data.server_random_set) &&
		   (!handshake_data.client_random_set || !handshake_data.server_random_set)) {
			sHandshakeData handshake_data_;
			if(dtls_handshake_safe_links.getHandshakeData(server.ip, server.port,
								      client.ip, client.port,
								      &handshake_data_)) {
				if(handshake_data.client_random_set) {
					if(!memcmp(handshake_data.client_random, handshake_data_.client_random, DTLS_RANDOM_SIZE)) {
						handshake_data = handshake_data_;
						if(sverb.dtls && ssl_sessionkey_enable()) {
							log_str += "; apply server random from safe handshake";
						}
					}
				} else if(handshake_data.server_random_set) {
					if(!memcmp(handshake_data.server_random, handshake_data_.server_random, DTLS_RANDOM_SIZE)) {
						handshake_data = handshake_data_;
						if(sverb.dtls && ssl_sessionkey_enable()) {
							log_str += "; apply client random from safe handshake";
						}
					}
				} else if(opt_ssl_dtls_handshake_safe == 2) {
					handshake_data = handshake_data_;
					if(sverb.dtls && ssl_sessionkey_enable()) {
						log_str += "; force apply safe handshake";
					}
				}
			}
		}
	}
	if(!handshake_data.client_random_set || !handshake_data.server_random_set) {
		if(sverb.dtls && ssl_sessionkey_enable()) {
			if(!handshake_data.client_random_set) {
				log_str += "; missing client_random";
			}
			if(!handshake_data.server_random_set) {
				log_str += "; missing server_random";
			}
			ssl_sessionkey_log(log_str);
		}
		return(false);
	}
	if(sverb.dtls && ssl_sessionkey_enable()) {
		log_str += "; client random: ";
		log_str += hexdump_to_string(handshake_data.client_random, DTLS_RANDOM_SIZE);
		log_str += "; server random: ";
		log_str += hexdump_to_string(handshake_data.server_random, DTLS_RANDOM_SIZE);
	}
	if(!handshake_data.cipher_types.size()) {
		if(sverb.dtls && ssl_sessionkey_enable()) {
			log_str += "; missing cipher_types";
			ssl_sessionkey_log(log_str);
		}
		return(false);
	}
	if(!master_secret_length && !findMasterSecret()) {
		if(sverb.dtls && ssl_sessionkey_enable()) {
			log_str += "; master secret not found";
			ssl_sessionkey_log(log_str);
		}
		return(false);
	}
	if(sverb.dtls && ssl_sessionkey_enable()) {
		log_str += "; master secret: ";
		log_str += hexdump_to_string(master_secret, master_secret_length);
	}
	if(keys_block_attempts > max_keys_block_attempts) {
		if(sverb.dtls && ssl_sessionkey_enable()) {
			log_str += "; the max_keys_block_attempts limit has been reached";
			ssl_sessionkey_log(log_str);
		}
		return(false);
	}
	SimpleBuffer secret;
	secret.set(master_secret, master_secret_length);
	SimpleBuffer rnd1;
	rnd1.set(handshake_data.client_random, DTLS_RANDOM_SIZE);
	SimpleBuffer rnd2;
	rnd2.set(handshake_data.server_random, DTLS_RANDOM_SIZE);
	SimpleBuffer out;
	++keys_block_attempts;
	if(!dtls_srtp_keys_block(&secret, "EXTRACTOR-dtls_srtp", &rnd1, &rnd2, &out, 60)) {
		if(sverb.dtls && ssl_sessionkey_enable()) {
			log_str += "; dtls_srtp_keys_block failed";
			ssl_sessionkey_log(log_str);
		}
		return(false);
	}
	if(sverb.dtls && ssl_sessionkey_enable()) {
		log_str += "; out: ";
		log_str += hexdump_to_string(out.data(), 60);
	}
	for(list<eCipherType>::iterator iter_cipher_type = handshake_data.cipher_types.begin(); iter_cipher_type != handshake_data.cipher_types.end(); iter_cipher_type++) {
		eCipherType cipher_type = *iter_cipher_type;
		SimpleBuffer server_key;
		SimpleBuffer client_key;
		unsigned srtp_key_len = cipherSrtpKeyLen(cipher_type);
		unsigned srtp_salt_len = cipherSrtpSaltLen(cipher_type);
		server_key.add(out.data(), srtp_key_len);
		client_key.add(out.data() + srtp_key_len, srtp_key_len);
		server_key.add(out.data() + srtp_key_len * 2, srtp_salt_len);
		client_key.add(out.data() + srtp_key_len * 2 + srtp_salt_len, srtp_salt_len);
		if(sverb.dtls && ssl_sessionkey_enable()) {
			log_str += "; server key: ";
			log_str += hexdump_to_string(server_key.data(), srtp_key_len + srtp_salt_len);
			log_str += "; client key: ";
			log_str += hexdump_to_string(client_key.data(), srtp_key_len + srtp_salt_len);
		}
		sSrtpKeys *keys_item = new FILE_LINE(0) sSrtpKeys;
		keys_item->server_key = base64_encode(server_key.data(), srtp_key_len + srtp_salt_len);
		keys_item->client_key = base64_encode(client_key.data(), srtp_key_len + srtp_salt_len);
		keys_item->server = server;
		keys_item->client = client;
		keys_item->cipher = cipherName(cipher_type);
		bool exists = false;
		for(list<cDtlsLink::sSrtpKeys*>::iterator iter = keys->begin(); iter != keys->end(); iter++) {
			if(*(*iter) == *keys_item) {
				exists = true;
				break;
			}
		}
		if(!exists) {
			keys->push_back(keys_item);
			call->dtls_keys_add(keys_item);
		}
	}
	if(sverb.dtls && ssl_sessionkey_enable()) {
		ssl_sessionkey_log(log_str);
	}
	return(true);
}

void cDtlsLink::init() {
	handshake_data.init();
	master_secret_length = 0;
	keys_block_attempts = 0;
	max_keys_block_attempts = 20;
	last_time_us = 0;
}

void cDtlsLink::setClientRandom(u_char *client_random) {
	if(!handshake_data.client_random_set) {
		memcpy(handshake_data.client_random, client_random, DTLS_RANDOM_SIZE);
		handshake_data.client_random_set = true;
	} else if(memcmp(handshake_data.client_random, client_random, DTLS_RANDOM_SIZE)) {
		memcpy(handshake_data.client_random, client_random, DTLS_RANDOM_SIZE);
		master_secret_length = 0;
	}
}

void cDtlsLink::setServerRandom(u_char *server_random) {
	if(!handshake_data.server_random_set) {
		memcpy(handshake_data.server_random, server_random, DTLS_RANDOM_SIZE);
		handshake_data.server_random_set = true;
	} else if(memcmp(handshake_data.server_random, server_random, DTLS_RANDOM_SIZE)) {
		memcpy(handshake_data.server_random, server_random, DTLS_RANDOM_SIZE);
		master_secret_length = 0;
	}
}

bool cDtlsLink::findMasterSecret() {
	if(!handshake_data.client_random_set || !handshake_data.server_random_set) {
		return(false);
	}
	unsigned _master_secret_length;
	bool rslt = find_master_secret(handshake_data.client_random, master_secret, &_master_secret_length);
	if(rslt) {
		master_secret_length = _master_secret_length;
	}
	return(rslt);
}

cDtls::cDtls() {
	memset(debug_flags, 0, sizeof(debug_flags));
	need_lock = false;
	_sync = 0;
	last_cleanup_at_s = 0;
	cleanup_interval_s = 120;
	link_expiration_s = 30;
}

cDtls::~cDtls() {
	for(list<cDtlsLink*>::iterator iter = links.begin(); iter != links.end(); iter++) {
		delete *iter;
	}
}

void cDtls::setNeedLock(bool need_lock) {
	this->need_lock = need_lock;
}

bool cDtls::processHandshake(vmIP src_ip, vmPort src_port,
			     vmIP dst_ip, vmPort dst_port,
			     u_char *data, unsigned data_len,
			     u_int64_t time_us) {
	if(data[0] != DTLS_CONTENT_TYPE_HANDSHAKE) {
		return(false);
	}
	if(data_len < sizeof(cDtlsLink::sHeader)) {
		return(false);
	}
	unsigned offset = 0;
	while(offset < data_len - sizeof(cDtlsLink::sHeader)) {
		cDtlsLink::sHeader *header = (cDtlsLink::sHeader*)(data + offset);
		if(!header->length_() || header->length_() > data_len - offset) {
			return(false);
		}
		if(header->content_type == DTLS_CONTENT_TYPE_HANDSHAKE && header->length_() >= sizeof(cDtlsLink::sHeaderHandshake)) {
			u_char *hs_begin = data + offset + sizeof(cDtlsLink::sHeader);
			unsigned hs_len = header->length_();
			unsigned hs_offset = 0;
			while(hs_offset < hs_len - sizeof(cDtlsLink::sHeaderHandshake)) {
				cDtlsLink::sHeaderHandshake *hs_header = (cDtlsLink::sHeaderHandshake*)(hs_begin + hs_offset);
				if(hs_header->content_length() > hs_len - hs_offset) {
					return(false);
				}
				if(hs_header->handshake_type == DTLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
					lock();
					cDtlsLink *link = NULL;
					cDtlsLink::sDtlsLinkId linkId(dst_ip, dst_port, src_ip, src_port);
					cDtlsLink::sDtlsServerId serverId(dst_ip, dst_port);
					map<cDtlsLink::sDtlsLinkId, cDtlsLink*>::iterator link_iter = links_by_link_id.find(linkId);
					if(link_iter != links_by_link_id.end()) {
						link = link_iter->second;
					} else {
						map<cDtlsLink::sDtlsServerId, cDtlsLink*>::iterator link_iter = links_by_server_id.find(serverId);
						if(link_iter != links_by_server_id.end()) {
							link = link_iter->second;
						} 
					}
					if(!link) {
						link = new FILE_LINE(0) cDtlsLink(dst_ip, dst_port, src_ip, src_port);
						links_by_link_id[linkId] = link;
						links_by_server_id[serverId] = link;
						links.push_back(link);
					}
					link->processHandshake(hs_header, time_us);
					unlock();
				} else if(hs_header->handshake_type == DTLS_HANDSHAKE_TYPE_SERVER_HELLO) {
					lock();
					cDtlsLink *link = NULL;
					cDtlsLink::sDtlsLinkId linkId(src_ip, src_port, dst_ip, dst_port);
					cDtlsLink::sDtlsServerId serverId(src_ip, src_port);
					map<cDtlsLink::sDtlsLinkId, cDtlsLink*>::iterator link_iter = links_by_link_id.find(linkId);
					if(link_iter != links_by_link_id.end()) {
						link = link_iter->second;
					} else {
						map<cDtlsLink::sDtlsServerId, cDtlsLink*>::iterator link_iter = links_by_server_id.find(serverId);
						if(link_iter != links_by_server_id.end()) {
							link = link_iter->second;
						}
					}
					if(!link) {
						link = new FILE_LINE(0) cDtlsLink(src_ip, src_port, dst_ip, dst_port);
						links_by_link_id[linkId] = link;
						links_by_server_id[serverId] = link;
						links.push_back(link);
					}
					if(link) {
						link->processHandshake(hs_header, time_us);
					}
					unlock();
				}
				hs_offset += sizeof(cDtlsLink::sHeaderHandshake) + hs_header->content_length();
			}
		}
		offset += sizeof(cDtlsLink::sHeader) + header->length_();
	}
	return(true);
}

bool cDtls::findSrtpKeys(vmIP src_ip, vmPort src_port,
			 vmIP dst_ip, vmPort dst_port,
			 list<cDtlsLink::sSrtpKeys*> *keys,
			 int8_t *direction, bool *oneNode,
			 Call *call,
			 bool enable_handshake_safe, bool use_handshake_safe) {
	bool existsLink = false;
	for(int pass_type = 0; pass_type < 2; pass_type++) {
		if(use_handshake_safe) {
			lock();
		}
		for(int pass_direction = 0; pass_direction < 2; pass_direction++) {
			cDtlsLink *link = NULL;
			if(pass_type == 0) {
				cDtlsLink::sDtlsLinkId linkId(pass_direction == 0 ? dst_ip : src_ip,
							      pass_direction == 0 ? dst_port : src_port,
							      pass_direction == 0 ? src_ip : dst_ip,
							      pass_direction == 0 ? src_port : dst_port);
				map<cDtlsLink::sDtlsLinkId, cDtlsLink*>::iterator link_iter = links_by_link_id.find(linkId);
				if(link_iter != links_by_link_id.end()) {
					link = link_iter->second;
					if(direction) {
						*direction = pass_direction;
					}
					if(oneNode) {
						*oneNode = false;
					}
				}
			} else {
				cDtlsLink::sDtlsServerId serverId(pass_direction == 0 ? dst_ip : src_ip,
								  pass_direction == 0 ? dst_port : src_port);
				map<cDtlsLink::sDtlsServerId, cDtlsLink*>::iterator link_iter = links_by_server_id.find(serverId);
				if(link_iter != links_by_server_id.end()) {
					link = link_iter->second;
					if(direction) {
						*direction = pass_direction;
					}
					if(oneNode) {
						*oneNode = true;
					}
				}
			}
			if(link && (!use_handshake_safe || link->handshake_data.isComplete())) {
				existsLink = true;
				if(link->findSrtpKeys(keys, call, enable_handshake_safe, use_handshake_safe)) {
					if(use_handshake_safe) {
						unlock();
					}
					return(true);
				}
			}
		}
		if(use_handshake_safe) {
			unlock();
		}
	}
	if(sverb.dtls && ssl_sessionkey_enable()) {
		string log_str;
		log_str += string("failed findSrtpKeys for call: ") + (call ? call->call_id : "unknown");
		log_str += "; stream: " + src_ip.getString() + ":" + src_port.getString() + " -> " + dst_ip.getString() + ":" + dst_port.getString() +
			   "; exists_link: " + (existsLink ? "Y" : "N");
		ssl_sessionkey_log(log_str);
	}
	return(false);
}

bool cDtls::getHandshakeData(vmIP server_ip, vmPort server_port,
			     vmIP client_ip, vmPort client_port,
			     cDtlsLink::sHandshakeData *handshake_data) {
	bool rslt = false;
	lock();
	for(int pass_type = 0; pass_type < 2; pass_type++) {
		cDtlsLink *link = NULL;
		if(pass_type == 0) {
			cDtlsLink::sDtlsLinkId linkId(server_ip, server_port,
						      client_ip, client_port);
			map<cDtlsLink::sDtlsLinkId, cDtlsLink*>::iterator link_iter = links_by_link_id.find(linkId);
			if(link_iter != links_by_link_id.end()) {
				link = link_iter->second;
			}
		} else {
			cDtlsLink::sDtlsServerId serverId(server_ip, server_port);
			map<cDtlsLink::sDtlsServerId, cDtlsLink*>::iterator link_iter = links_by_server_id.find(serverId);
			if(link_iter != links_by_server_id.end()) {
				link = link_iter->second;
			}
		}
		if(link && link->handshake_data.isComplete()) {
			rslt = true;
			*handshake_data = link->handshake_data;
			break;
		}
	}
	unlock();
	return(rslt);
}

void cDtls::cleanup() {
	u_int32_t time_s = getTimeS_rdtsc();
	if(last_cleanup_at_s + cleanup_interval_s < time_s) {
		return;
	}
	lock();
	for(list<cDtlsLink*>::iterator iter = links.begin(); iter != links.end(); ) {
		if((*iter)->last_time_us + link_expiration_s < time_s) {
			cDtlsLink *link = *iter;
			cDtlsLink::sDtlsLinkId linkId(link);
			cDtlsLink::sDtlsServerId serverId(link);
			map<cDtlsLink::sDtlsLinkId, cDtlsLink*>::iterator link_iter = links_by_link_id.find(linkId);
			if(link_iter != links_by_link_id.end()) {
				links_by_link_id.erase(link_iter);
			}
			map<cDtlsLink::sDtlsServerId, cDtlsLink*>::iterator link_iter_s = links_by_server_id.find(serverId);
			if(link_iter_s != links_by_server_id.end()) {
				links_by_server_id.erase(link_iter_s);
			} 
			links.erase(iter++);
			delete link;
		} else {
			iter++;
		}
	}
	last_cleanup_at_s = time_s;
	unlock();
}

void cDtls::lock() {
	if(need_lock) {
		__SYNC_LOCK(_sync);
	}
}

void cDtls::unlock() {
	if(need_lock) {
		__SYNC_UNLOCK(_sync);
	}
}


#if defined(HAVE_OPENSSL101) and defined(HAVE_LIBGNUTLS)

#include <gcrypt.h>

#define DIGEST_MAX_SIZE 48


static bool gcry_read(gcry_md_hd_t* md, u_char *data, unsigned *datalen) {
	int algo = gcry_md_get_algo (*(md));
	unsigned len  = gcry_md_get_algo_dlen(algo);
	if(len > *datalen) {
		return(false);
	}
	memcpy(data, gcry_md_read(*(md), algo), len);
	*datalen = len;
	return(true);
}

static bool tls_hash(SimpleBuffer *secret, SimpleBuffer *seed, int md, SimpleBuffer *out, unsigned out_len) {
	/* RFC 2246 5. HMAC and the pseudorandom function
	 * '+' denotes concatenation.
	 * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
	 *                        HMAC_hash(secret, A(2) + seed) + ...
	 * A(0) = seed
	 * A(i) = HMAC_hash(secret, A(i - 1))
	 */
	u_char *ptr;
	unsigned left, tocpy;
	u_char *A;
	u_char _A[DIGEST_MAX_SIZE], tmp[DIGEST_MAX_SIZE];
	unsigned A_l, tmp_l;
	gcry_md_hd_t  hm;

	ptr  = out->data();
	left = out_len;

	//ssl_print_string("tls_hash: hash secret", secret);
	//ssl_print_string("tls_hash: hash seed", seed);
	/* A(0) = seed */
	A = seed->data();
	A_l = seed->data_capacity();

	while (left) {
		/* A(i) = HMAC_hash(secret, A(i-1)) */
		
		if(gcry_md_open(&hm, md, GCRY_MD_FLAG_HMAC)) {
			return(false);
		}
		gcry_md_setkey(hm, secret->data(), secret->data_len());
		gcry_md_write(hm, A, A_l);
		A_l = sizeof(_A); /* upper bound len for hash output */
		bool read_rslt = gcry_read(&hm, _A, &A_l);
		gcry_md_close(hm);
		if(!read_rslt) {
			return(false);
		}
		A = _A;

		/* HMAC_hash(secret, A(i) + seed) */
		if(gcry_md_open(&hm, md, GCRY_MD_FLAG_HMAC)) {
			return(false);
		}
		gcry_md_setkey(hm, secret->data(), secret->data_len());
		gcry_md_write(hm, A, A_l);
		gcry_md_write(hm, seed->data(), seed->data_capacity());
		tmp_l = sizeof(tmp); /* upper bound len for hash output */
		read_rslt = gcry_read(&hm, tmp, &tmp_l);
		gcry_md_close(hm);
		if(!read_rslt) {
			return(false);
		}

		/* ssl_hmac_final puts the actual digest output size in tmp_l */
		tocpy = min(left, tmp_l);
		memcpy(ptr, tmp, tocpy);
		ptr += tocpy;
		left -= tocpy;
	}
	return(true);
}

#endif //defined(HAVE_OPENSSL101) and defined(HAVE_LIBGNUTLS)

static bool dtls_srtp_keys_block(SimpleBuffer *secret, const char *label, SimpleBuffer* rnd1, SimpleBuffer* rnd2, SimpleBuffer* out, unsigned out_len) {
	#if defined(HAVE_OPENSSL101) and defined(HAVE_LIBGNUTLS)
	out->set_data_capacity(out_len);
	size_t label_len = strlen(label);
	SimpleBuffer label_seed;
	label_seed.set_data_capacity(label_len + rnd1->data_len() + (rnd2 ? rnd2->data_len() : 0));
	memcpy(label_seed.data(), label, label_len);
	memcpy(label_seed.data() + label_len, rnd1->data(), rnd1->data_len());
	if(rnd2) {
		memcpy(label_seed.data() + label_len+  rnd1->data_len(), rnd2->data(), rnd2->data_len());
	}
	if(sverb.dtls && !sverb.ssl_sessionkey_to_file) {
		string log_str;
		log_str += "seed: ";
		log_str += hexdump_to_string(label_seed.data(), label_seed.data_capacity());
		ssl_sessionkey_log(log_str);
	}
	return(tls_hash(secret, &label_seed, GCRY_MD_SHA256, out, out_len));
	#else
	return(false);
	#endif
}
