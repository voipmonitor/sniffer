#include "dtls.h"

#include "tools.h"
#include "ssl_dssl.h"


static bool dtls_srtp_keys_block(SimpleBuffer *secret, const char *usage, SimpleBuffer* rnd1, SimpleBuffer* rnd2, SimpleBuffer* out, unsigned out_len);


cDtlsLink::cDtlsLink(vmIP server_ip, vmPort server_port,
		     vmIP client_ip, vmPort client_port) 
	: server(server_ip, server_port),
	  client(client_ip, client_port) {
	init();
}

cDtlsLink::~cDtlsLink() {
	if(client_random_set) {
		erase_client_random(client_random);
	}
}

void cDtlsLink::processHandshake(sHeaderHandshake *handshake) {
	if(handshake->handshake_type == DTLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
		cDtlsLink::sHeaderHandshakeHello *handshake_hello = (cDtlsLink::sHeaderHandshakeHello*)handshake;
		memcpy(client_random, handshake_hello->random, DTLS_RANDOM_SIZE);
		client_random_set = true;
		unsigned len = handshake->length_();
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
						u_int16_t prot_prof = prot_prof_len == 2 ? ntohs(*(u_int16_t*)(ext + ext_offset + 6)) :
								      prot_prof_len == 1 ? *(u_int8_t*)(ext + ext_offset + 6) : 0;
						//u_int8_t mki_len = *(u_int8_t*)(ext + ext_offset + 6 + prot_prof_len);
						if(cipherIsSupported(prot_prof)) {
							cipher_type = (eCipherType)prot_prof;
						}
					}
					ext_offset += 4 + e_len;
				}
			}
		}
		
	} else if(handshake->handshake_type == DTLS_HANDSHAKE_TYPE_SERVER_HELLO) {
		cDtlsLink::sHeaderHandshakeHello *handshake_hello = (cDtlsLink::sHeaderHandshakeHello*)handshake;
		memcpy(server_random, handshake_hello->random, DTLS_RANDOM_SIZE);
		server_random_set = true;
	}
}

bool cDtlsLink::findSrtpKeys(sSrtpKeys *keys) {
	if(!cipherIsSupported(cipher_type) || !client_random_set || !server_random_set) {
		return(false);
	}
	if(!master_secret_length && !findMasterSecret()) {
		 return(false);
	}
	if(keys_block_attempts > max_keys_block_attempts) {
		return(false);
	}
	if(sverb.dtls) {
		puts("client random");
		hexdump(client_random, DTLS_RANDOM_SIZE);
		puts("server random");
		hexdump(server_random, DTLS_RANDOM_SIZE);
		puts("master secret");
		hexdump(master_secret, master_secret_length);
	}
	SimpleBuffer secret;
	secret.set(master_secret, master_secret_length);
	SimpleBuffer rnd1;
	rnd1.set(client_random, DTLS_RANDOM_SIZE);
	SimpleBuffer rnd2;
	rnd2.set(server_random, DTLS_RANDOM_SIZE);
	SimpleBuffer out;
	++keys_block_attempts;
	if(!dtls_srtp_keys_block(&secret, "EXTRACTOR-dtls_srtp", &rnd1, &rnd2, &out, 60)) {
		return(false);
	}
	if(sverb.dtls) {
		puts("out");
		hexdump(out.data(), 60);
	}
	SimpleBuffer server_key;
	SimpleBuffer client_key;
	unsigned srtp_key_len = cipherSrtpKeyLen(cipher_type);
	unsigned srtp_salt_len = cipherSrtpSaltLen(cipher_type);
	server_key.add(out.data(), srtp_key_len);
	client_key.add(out.data() + srtp_key_len, srtp_key_len);
	server_key.add(out.data() + srtp_key_len * 2, srtp_salt_len);
	client_key.add(out.data() + srtp_key_len * 2 + srtp_salt_len, srtp_salt_len);
	if(sverb.dtls) {
		puts("server key");
		hexdump(server_key.data(), srtp_key_len + srtp_salt_len);
		puts("client key");
		hexdump(client_key.data(), srtp_key_len + srtp_salt_len);
	}
	keys->server_key = base64_encode(server_key.data(), srtp_key_len + srtp_salt_len);
	keys->client_key = base64_encode(client_key.data(), srtp_key_len + srtp_salt_len);
	keys->server = server;
	keys->client = client;
	keys->cipher = cipherName(cipher_type);
	return(true);
}

void cDtlsLink::init() {
	client_random_set = false;
	server_random_set = false;
	cipher_type = _ct_na;
	master_secret_length = 0;
	keys_block_attempts = 0;
	max_keys_block_attempts = 4;
}

bool cDtlsLink::findMasterSecret() {
	if(!client_random_set || !server_random_set) {
		return(false);
	}
	unsigned _master_secret_length;
	bool rslt = find_master_secret(client_random, master_secret, &_master_secret_length);
	if(rslt) {
		master_secret_length = _master_secret_length;
	}
	return(rslt);
}

cDtls::cDtls() {
}

cDtls::~cDtls() {
	for(map<cDtlsLink::sDtlsLinkId, cDtlsLink*>::iterator iter = links.begin(); iter != links.end(); iter++) {
		delete iter->second;
	}
}

bool cDtls::processHandshake(vmIP src_ip, vmPort src_port,
			     vmIP dst_ip, vmPort dst_port,
			     u_char *data, unsigned data_len) {
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
				if(hs_header->length_() > hs_len - hs_offset) {
					return(false);
				}
				if(hs_header->handshake_type == DTLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
					cDtlsLink::sDtlsLinkId linkId(dst_ip, dst_port, src_ip, src_port);
					map<cDtlsLink::sDtlsLinkId, cDtlsLink*>::iterator link_iter = links.find(linkId);
					cDtlsLink *link;
					if(link_iter != links.end()) {
						link = link_iter->second;
					} else {
						link = new FILE_LINE(0) cDtlsLink(dst_ip, dst_port, src_ip, src_port);
						links[linkId] = link;
					}
					link->processHandshake(hs_header);
				} else if(hs_header->handshake_type == DTLS_HANDSHAKE_TYPE_SERVER_HELLO) {
					cDtlsLink::sDtlsLinkId linkId(src_ip, src_port, dst_ip, dst_port);
					map<cDtlsLink::sDtlsLinkId, cDtlsLink*>::iterator link_iter = links.find(linkId);
					if(link_iter != links.end()) {
						link_iter->second->processHandshake(hs_header);
					}
				}
				hs_offset += sizeof(cDtlsLink::sHeaderHandshake) + hs_header->length_();
			}
		}
		offset += sizeof(cDtlsLink::sHeader) + header->length_();
	}
	return(true);
}

bool cDtls::findSrtpKeys(vmIP src_ip, vmPort src_port,
			 vmIP dst_ip, vmPort dst_port,
			 cDtlsLink::sSrtpKeys *keys) {
	for(int pass = 0; pass < 2; pass++) {
		cDtlsLink::sDtlsLinkId linkId(pass == 0 ? src_ip : dst_ip,
					      pass == 0 ? src_port : dst_port,
					      pass == 0 ? dst_ip : src_ip,
					      pass == 0 ? dst_port : src_port);
		map<cDtlsLink::sDtlsLinkId, cDtlsLink*>::iterator link_iter = links.find(linkId);
		if(link_iter != links.end()) {
			if(link_iter->second->findSrtpKeys(keys)) {
				return(true);
			}
		}
	}
	return(false);
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
	if(sverb.dtls) {
		puts("seed");
		hexdump(label_seed.data(), label_seed.data_capacity());
	}
	return(tls_hash(secret, &label_seed, GCRY_MD_SHA256, out, out_len));
	#else
	return(false);
	#endif
}
