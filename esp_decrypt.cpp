#include "esp_decrypt.h"
#include "tools.h"
#include "sql_db.h"


#if defined(HAVE_OPENSSL)


#include <openssl/evp.h>

#include "sniff_proc_class.h"


extern MySqlStore *sqlStore;

cEspDecrypt EspDecrypt;


cEspDecrypt::cEspDecrypt() {
	reassembly = new FILE_LINE(0) ReassemblyBuffer;
	sqlDb = NULL;
	exists_sa_table = false;
	last_delete_old_sa_at = 0;
	_sync_sa = 0;
	_sync_collect = 0;
	last_cleanup_at = 0;
	count_key_found = 0;
	count_sa_created = 0;
	count_decrypt_ok = 0;
	count_decrypt_no_key = 0;
	count_decrypt_failed = 0;
	count_packet_bad = 0;
	count_decrypt_learned_spi = 0;
	count_reassembly_used = 0;
	count_incomplete_header = 0;
	count_expires_updated = 0;
}

cEspDecrypt::~cEspDecrypt() {
	delete reassembly;
	if(sqlDb) {
		delete sqlDb;
	}
}

void cEspDecrypt::collectKeys(u_char *data, unsigned datalen,
			      vmIP saddr, vmPort sport, vmIP daddr, vmPort dport,
			      u_int32_t seq, u_int32_t ack, timeval time) {
	if(!data || !datalen) {
		return;
	}
	cleanup(time.tv_sec);
	bool is_sip_start = (datalen >= 11 && !memcmp(data, "SIP/2.0 401", 11)) ||
			    (datalen >= 9 && !memcmp(data, "REGISTER ", 9));
	u_char *sip_start = NULL;
	if(is_sip_start) {
		sip_start = data;
	} else {
		sip_start = (u_char*)memmem(data, datalen, "\nSIP/2.0 401", 12);
		if(!sip_start) {
			sip_start = (u_char*)memmem(data, datalen, "\nREGISTER ", 10);
		}
		if(sip_start) {
			++sip_start;
		}
	}
	if(sip_start) {
		unsigned sip_start_length = datalen - (sip_start - data);
		list<d_u_int32_t> offsets;
		bool parsed = false;
		if(TcpReassemblySip::_checkSip(sip_start, sip_start_length, TcpReassemblySip::_chssm_na, &offsets)) {
			for(list<d_u_int32_t>::iterator iter = offsets.begin(); iter != offsets.end(); iter++) {
				u_char *message = sip_start + (*iter)[0];
				unsigned message_length = (*iter)[1];
				if(message_length >= 11 &&
				   (!memcmp(message, "SIP/2.0 401", 11) ||
				    !memcmp(message, "REGISTER ", 9))) {
					parseMessage(message, message_length, saddr, daddr, time.tv_sec);
					parsed = true;
				}
			}
		}
		if(parsed) {
			return;
		}
	}
	lock_collect();
	list<ReassemblyBuffer::sDataRslt> rslt;
	reassembly->cleanup(time, &rslt);
	bool exists_stream = reassembly->existsStream(saddr, sport, daddr, dport);
	if(is_sip_start || exists_stream) {
		sPacketInfoData pid;
		pid.clear();
		reassembly->processPacket(NULL, 0,
					  saddr, sport, daddr, dport,
					  ReassemblyBuffer::_sip_incomplete, data, datalen, !exists_stream,
					  time, ack, seq,
					  0, 0, 0, 0, pid,
					  &rslt);
		++count_reassembly_used;
	}
	unlock_collect();
	for(list<ReassemblyBuffer::sDataRslt>::iterator iter = rslt.begin(); iter != rslt.end(); iter++) {
		if(iter->data && iter->dataLength) {
			parseMessage(iter->data, iter->dataLength, iter->saddr, iter->daddr, iter->time.tv_sec);
		}
		if(iter->dataAlloc && iter->data) {
			delete [] iter->data;
		}
		if(iter->ethHeaderAlloc && iter->ethHeader) {
			delete [] iter->ethHeader;
		}
	}
}

bool cEspDecrypt::decrypt(iphdr2 *header_ip, unsigned max_len) {
	if(header_ip->_get_protocol() != IPPROTO_ESP) {
		++count_packet_bad;
		return(false);
	}
	unsigned frag_strip_len = 0;
	#if VM_IPV6
	if(header_ip->version != 4 && ((ip6hdr2*)header_ip)->is_ext_headers()) {
		ip6hdr2 *header_ip6 = (ip6hdr2*)header_ip;
		ip6_frag *frag = header_ip6->nxt == IPPROTO_FRAGMENT ?
				  (ip6_frag*)header_ip6->get_ext_header(IPPROTO_FRAGMENT) :
				  NULL;
		u_int16_t plen = frag ? ntohs(header_ip6->plen) : 0;
		if(!frag || frag->ip6f_offlg ||
		   ip6hdr2::is_ext_header(frag->ip6f_nxt) ||
		   plen < sizeof(ip6_frag) ||
		   sizeof(ip6hdr2) + plen > max_len) {
			++count_packet_bad;
			return(false);
		}
		frag_strip_len = sizeof(ip6_frag);
	}
	#endif
	u_int32_t tot_len = header_ip->get_tot_len();
	if(!tot_len || tot_len > max_len) {
		++count_packet_bad;
		return(false);
	}
	u_int16_t hdr_size = header_ip->get_hdr_size();
	if(hdr_size == (u_int16_t)-1 || hdr_size < IPPROTO_ESP_HEADER_SIZE) {
		++count_packet_bad;
		return(false);
	}
	u_int16_t ip_hdr_size = hdr_size - IPPROTO_ESP_HEADER_SIZE;
	if(tot_len < (u_int32_t)ip_hdr_size + IPPROTO_ESP_HEADER_SIZE) {
		++count_packet_bad;
		return(false);
	}
	u_char *esp = (u_char*)header_ip + ip_hdr_size;
	u_int32_t spi = ntohl(*(u_int32_t*)esp);
	vmIP src_ip = header_ip->get_saddr();
	vmIP dst_ip = header_ip->get_daddr();
	sSa sa;
	bool from_ip_map;
	if(!findSa(spi, src_ip, dst_ip, &sa, &from_ip_map)) {
		++count_decrypt_no_key;
		if(sverb.esp_decrypt) {
			cout << "*** ESP no key"
			     << " / spi 0x" << hex << spi << dec
			     << " / " << src_ip.getString() << " -> " << dst_ip.getString() << endl;
		}
		return(false);
	}
	unsigned iv_length = sa.data.ealg == _ealg_aes_cbc ? ESP_AES_CBC_IV_LENGTH : 0;
	unsigned enc_offset = ip_hdr_size + IPPROTO_ESP_HEADER_SIZE + iv_length;
	if(tot_len < enc_offset + sa.data.icv_length + 2) {
		++count_decrypt_failed;
		return(false);
	}
	unsigned enc_length = tot_len - enc_offset - sa.data.icv_length;
	u_char *enc = (u_char*)header_ip + enc_offset;
	u_int8_t pad_length;
	u_int8_t next_header;
	if(sa.data.ealg == _ealg_aes_cbc) {
		if(enc_length % ESP_AES_CBC_IV_LENGTH) {
			++count_decrypt_failed;
			return(false);
		}
		u_char tail[2 * ESP_AES_CBC_IV_LENGTH];
		unsigned tail_length = enc_length < sizeof(tail) ? enc_length : sizeof(tail);
		u_char *tail_enc = enc + enc_length - tail_length;
		if(!decryptAesCbc(sa.data.ck, tail_enc > enc ? tail_enc - ESP_AES_CBC_IV_LENGTH : enc - iv_length,
				  tail_enc, tail_length, tail) ||
		   !checkTrailer(tail, tail_length, enc_length, &pad_length, &next_header)) {
			++count_decrypt_failed;
			return(false);
		}
		if(from_ip_map) {
			u_char head[ESP_AES_CBC_IV_LENGTH];
			u_char *head_plain = tail_enc > enc ? head : tail;
			if(enc_length - pad_length - 2 < 4 || !sa.data.ports_count ||
			   (head_plain == head && !decryptAesCbc(sa.data.ck, enc - iv_length, enc, ESP_AES_CBC_IV_LENGTH, head)) ||
			   !sa.data.checkPort(ntohs(*(u_int16_t*)head_plain), ntohs(*(u_int16_t*)(head_plain + 2)))) {
				++count_decrypt_failed;
				return(false);
			}
		}
		if(!decryptAesCbc(sa.data.ck, enc - iv_length, enc, enc_length, NULL)) {
			++count_decrypt_failed;
			return(false);
		}
	} else {
		if(!checkTrailer(enc, enc_length, enc_length, &pad_length, &next_header)) {
			++count_decrypt_failed;
			return(false);
		}
		if(from_ip_map) {
			if(enc_length - pad_length - 2 < 4 || !sa.data.ports_count ||
			   !sa.data.checkPort(ntohs(*(u_int16_t*)enc), ntohs(*(u_int16_t*)(enc + 2)))) {
				++count_decrypt_failed;
				return(false);
			}
		}
	}
	unsigned payload_length = enc_length - pad_length - 2;
	unsigned ip_hdr_size_out = ip_hdr_size - frag_strip_len;
	memmove((u_char*)header_ip + ip_hdr_size_out, enc, payload_length);
	header_ip->set_protocol(next_header);
	header_ip->set_tot_len(ip_hdr_size_out + payload_length);
	header_ip->set_check(0);
	if(from_ip_map) {
		lock_sa();
		sa_map[sSaId(spi, dst_ip)] = sa;
		unlock_sa();
		++count_decrypt_learned_spi;
	}
	++count_decrypt_ok;
	if(sverb.esp_decrypt) {
		cout << "*** ESP decrypted"
		     << " / spi 0x" << hex << spi << dec
		     << " / " << src_ip.getString() << " -> " << dst_ip.getString()
		     << " / proto " << (int)next_header
		     << " / len " << payload_length
		     << (from_ip_map ? " / spi learned" : "") << endl;
	}
	if(sverb.esp_decrypt_content) {
		u_char *payload = (u_char*)header_ip + ip_hdr_size_out;
		vmPort sport, dport;
		unsigned transport_hdr_length;
		if(next_header == IPPROTO_TCP) {
			tcphdr2 *header_tcp = (tcphdr2*)payload;
			sport = header_tcp->get_source();
			dport = header_tcp->get_dest();
			transport_hdr_length = header_tcp->doff * 4;
		} else {
			udphdr2 *header_udp = (udphdr2*)payload;
			sport = header_udp->get_source();
			dport = header_udp->get_dest();
			transport_hdr_length = sizeof(udphdr2);
		}
		cout << "--- ESP content begin ---" << endl
		     << src_ip.getString(true) << ":" << sport.getString()
		     << " -> " << dst_ip.getString(true) << ":" << dport.getString()
		     << " / " << (next_header == IPPROTO_TCP ? "TCP" : "UDP")
		     << " / spi 0x" << hex << spi << dec
		     << " / data " << (payload_length > transport_hdr_length ? payload_length - transport_hdr_length : 0) << endl;
		if(payload_length > transport_hdr_length) {
			cout << string((char*)payload + transport_hdr_length, payload_length - transport_hdr_length) << endl;
		}
		cout << "--- ESP content end ---" << endl;
	}
	return(true);
}

void cEspDecrypt::updateExpires(const char *call_id, unsigned call_id_length, u_int32_t expires, u_int32_t time_s) {
	if(!call_id || !call_id_length || !expires) {
		return;
	}
	string call_id_str = normalizeCallId(call_id, call_id_length);
	if(call_id_str.empty()) {
		return;
	}
	lock_collect();
	map<string, sKeySet>::iterator iter = key_set_map.find(call_id_str);
	if(iter == key_set_map.end()) {
		unlock_collect();
		return;
	}
	sKeySet *key_set = &iter->second;
	key_set->expires = expires;
	key_set->set_at = time_s;
	u_int32_t timeout = saTimeout(expires);
	vmIP ue_ip = key_set->ue_ip;
	vmIP pcscf_ip = key_set->pcscf_ip;
	sStoreSaItem store_items[ESP_SPI_MAX * 2];
	unsigned store_items_count = 0;
	lock_sa();
	for(unsigned i = 0; i < key_set->spi_to_pcscf_count && store_items_count < ESP_SPI_MAX * 2; i++) {
		map<sSaId, sSa>::iterator iter_sa = sa_map.find(sSaId(key_set->spi_to_pcscf[i], pcscf_ip));
		if(iter_sa != sa_map.end()) {
			bool store_sa = iter_sa->second.data.timeout != timeout ||
					time_s >= iter_sa->second.last_store_at + iter_sa->second.data.timeout / 2;
			iter_sa->second.data.timeout = timeout;
			iter_sa->second.set_at = time_s;
			if(store_sa) {
				iter_sa->second.last_store_at = time_s;
				store_items[store_items_count].spi = key_set->spi_to_pcscf[i];
				store_items[store_items_count].dst_ip = pcscf_ip;
				store_items[store_items_count].sa = iter_sa->second;
				++store_items_count;
			}
		}
	}
	for(unsigned i = 0; i < key_set->spi_to_ue_count && store_items_count < ESP_SPI_MAX * 2; i++) {
		map<sSaId, sSa>::iterator iter_sa = sa_map.find(sSaId(key_set->spi_to_ue[i], ue_ip));
		if(iter_sa != sa_map.end()) {
			bool store_sa = iter_sa->second.data.timeout != timeout ||
					time_s >= iter_sa->second.last_store_at + iter_sa->second.data.timeout / 2;
			iter_sa->second.data.timeout = timeout;
			iter_sa->second.set_at = time_s;
			if(store_sa) {
				iter_sa->second.last_store_at = time_s;
				store_items[store_items_count].spi = key_set->spi_to_ue[i];
				store_items[store_items_count].dst_ip = ue_ip;
				store_items[store_items_count].sa = iter_sa->second;
				++store_items_count;
			}
		}
	}
	map<sIpPair, sSa>::iterator iter_ip = ip_map.find(sIpPair(ue_ip, pcscf_ip));
	if(iter_ip != ip_map.end()) {
		iter_ip->second.data.timeout = timeout;
		iter_ip->second.set_at = time_s;
	}
	unlock_sa();
	for(unsigned i = 0; i < store_items_count; i++) {
		storeSa(store_items[i].spi, store_items[i].dst_ip, &store_items[i].sa);
	}
	unlock_collect();
	++count_expires_updated;
	if(sverb.esp_decrypt) {
		cout << "*** ESP expires update"
		     << " / ue " << ue_ip.getString()
		     << " / pcscf " << pcscf_ip.getString()
		     << " / timeout " << timeout << "s" << endl;
	}
}

void cEspDecrypt::loadSa() {
	extern int opt_esp_store_sa;
	extern int opt_nocdr;
	extern int opt_id_sensor;
	if(!opt_esp_store_sa || opt_nocdr) {
		return;
	}
	if(!sqlDb) {
		sqlDb = createSqlObject();
	}
	syslog(LOG_NOTICE, "try load esp sa from table %s", storeSaTableName().c_str());
	exists_sa_table = sqlDb->existsTable(storeSaTableName());
	if(!exists_sa_table) {
		syslog(LOG_NOTICE, "esp sa table %s is missing", storeSaTableName().c_str());
		return;
	}
	sqlDb->isIPv6Column(storeSaTableName(), "dst_ip");
	u_int32_t time_s = getTimeS();
	list<SqlDb_condField> cond;
	cond.push_back(SqlDb_condField("id_sensor", intToString(opt_id_sensor < 0 ? 0 : opt_id_sensor)));
	sqlDb->select(storeSaTableName(), (list<SqlDb_field>*)NULL, &cond);
	SqlDb_row row;
	unsigned sa_rows = 0;
	while((row = sqlDb->fetchRow())) {
		sSa sa;
		sa.set_at = stringToTime(row["set_at"].c_str());
		sa.last_store_at = sa.set_at;
		sa.data.timeout = atol(row["timeout"].c_str());
		if(!sa.set_at || !sa.data.timeout || sa.set_at + sa.data.timeout < time_s) {
			continue;
		}
		string ck = row["ck"];
		if(ck.length() != ESP_CK_MAX_LENGTH * 2 ||
		   hexdecode(sa.data.ck, ck.c_str(), ESP_CK_MAX_LENGTH) != ESP_CK_MAX_LENGTH) {
			continue;
		}
		sa.data.ck_length = ESP_CK_MAX_LENGTH;
		sa.data.ealg = (eEncAlg)atoi(row["ealg"].c_str());
		sa.data.icv_length = atoi(row["icv_length"].c_str());
		sa.data.ue_ip = mysql_ip_2_vmIP(&row, "ue_ip");
		sa.data.pcscf_ip = mysql_ip_2_vmIP(&row, "pcscf_ip");
		string ports = row["ports"];
		size_t ports_pos = 0;
		while(ports_pos < ports.length() && sa.data.ports_count < ESP_PORTS_MAX) {
			size_t ports_sep = ports.find(',', ports_pos);
			u_int16_t port = atoi(ports.substr(ports_pos, ports_sep == string::npos ? string::npos : ports_sep - ports_pos).c_str());
			if(port) {
				sa.data.ports[sa.data.ports_count++] = port;
			}
			if(ports_sep == string::npos) {
				break;
			}
			ports_pos = ports_sep + 1;
		}
		u_int32_t spi = atoll(row["spi"].c_str());
		vmIP dst_ip = mysql_ip_2_vmIP(&row, "dst_ip");
		lock_sa();
		sa_map[sSaId(spi, dst_ip)] = sa;
		if(sa.data.ue_ip.isSet() && sa.data.pcscf_ip.isSet()) {
			sIpPair ip_pair(sa.data.ue_ip, sa.data.pcscf_ip);
			map<sIpPair, sSa>::iterator iter_ip = ip_map.find(ip_pair);
			if(iter_ip == ip_map.end() || iter_ip->second.set_at < sa.set_at) {
				ip_map[ip_pair] = sa;
			}
		}
		unlock_sa();
		++sa_rows;
	}
	if(sa_rows) {
		syslog(LOG_NOTICE, "load %u esp sa", sa_rows);
	} else {
		syslog(LOG_NOTICE, "there are no stored esp sa");
	}
}

void cEspDecrypt::cleanup(u_int32_t time_s) {
	u_int32_t last_cleanup = SAFE_ATOMIC_LOAD(last_cleanup_at);
	if(last_cleanup && time_s < last_cleanup + ESP_CLEANUP_INTERVAL) {
		return;
	}
	if(!__sync_bool_compare_and_swap(&last_cleanup_at, last_cleanup, time_s)) {
		return;
	}
	lock_collect();
	for(map<string, sKeySet>::iterator iter = key_set_map.begin(); iter != key_set_map.end(); ) {
		u_int32_t timeout = completedKeySet(&iter->second) ?
				     saTimeout(iter->second.expires) :
				     ESP_KEY_SET_TIMEOUT;
		if(iter->second.set_at + timeout < time_s) {
			key_set_map.erase(iter++);
		} else {
			iter++;
		}
	}
	unlock_collect();
	lock_sa();
	for(map<sSaId, sSa>::iterator iter = sa_map.begin(); iter != sa_map.end(); ) {
		u_int32_t set_at = iter->second.set_at;
		if(iter->second.data.ue_ip.isSet() && iter->second.data.pcscf_ip.isSet()) {
			map<sIpPair, sSa>::iterator iter_ip = ip_map.find(sIpPair(iter->second.data.ue_ip, iter->second.data.pcscf_ip));
			if(iter_ip != ip_map.end() && iter_ip->second.set_at > set_at &&
			   iter_ip->second.data.ck_length == iter->second.data.ck_length &&
			   !memcmp(iter_ip->second.data.ck, iter->second.data.ck, iter->second.data.ck_length)) {
				set_at = iter_ip->second.set_at;
			}
		}
		if(set_at + iter->second.data.timeout < time_s) {
			sa_map.erase(iter++);
		} else {
			iter++;
		}
	}
	for(map<sIpPair, sSa>::iterator iter = ip_map.begin(); iter != ip_map.end(); ) {
		if(iter->second.set_at + iter->second.data.timeout < time_s) {
			ip_map.erase(iter++);
		} else {
			iter++;
		}
	}
	unlock_sa();
}

void cEspDecrypt::getCounters(sEspCounters *counters) {
	counters->key_found = count_key_found;
	counters->sa_created = count_sa_created;
	counters->decrypt_ok = count_decrypt_ok;
	counters->decrypt_no_key = count_decrypt_no_key;
	counters->decrypt_failed = count_decrypt_failed;
	counters->packet_bad = count_packet_bad;
	counters->decrypt_learned_spi = count_decrypt_learned_spi;
	counters->reassembly_used = count_reassembly_used;
	counters->incomplete_header = count_incomplete_header;
	counters->expires_updated = count_expires_updated;
}

void cEspDecrypt::parseMessage(u_char *data, unsigned datalen, vmIP saddr, vmIP daddr, u_int32_t time_s) {
	unsigned value_length;
	u_char *call_id = findHeader(data, datalen, "Call-ID:", &value_length);
	if(!call_id) {
		call_id = findHeader(data, datalen, "i:", &value_length);
	}
	if(!call_id || !value_length || value_length > 255) {
		return;
	}
	string call_id_str = normalizeCallId((char*)call_id, value_length);
	if(call_id_str.empty()) {
		return;
	}
	unsigned www_authenticate_length = 0;
	u_char *www_authenticate = findHeader(data, datalen, "WWW-Authenticate:", &www_authenticate_length);
	unsigned security_server_length = 0;
	u_char *security_server = findHeader(data, datalen, "Security-Server:", &security_server_length);
	unsigned security_client_length = 0;
	u_char *security_client = findHeader(data, datalen, "Security-Client:", &security_client_length);
	if(!www_authenticate && !security_server && !security_client) {
		return;
	}
	unsigned cseq_length = 0;
	u_char *cseq_str = findHeader(data, datalen, "CSeq:", &cseq_length);
	u_int32_t cseq = cseq_str ? parseUInt(cseq_str, cseq_length) : 0;
	lock_collect();
	map<string, sKeySet>::iterator iter_key_set = key_set_map.find(call_id_str);
	sKeySet key_set_work;
	if(iter_key_set != key_set_map.end()) {
		key_set_work = iter_key_set->second;
	}
	sKeySet *key_set = &key_set_work;
	bool update = false;
	bool ck_found = false;
	if(www_authenticate &&
	   parseWwwAuthenticate(www_authenticate, www_authenticate_length, key_set, cseq)) {
		++count_key_found;
		ck_found = true;
		update = true;
	}
	if(security_server && parseSecurityServer(security_server, security_server_length, key_set, cseq)) {
		key_set->ue_ip = daddr;
		key_set->pcscf_ip = saddr;
		update = true;
	}
	if(security_client && parseSecurityClient(security_client, security_client_length, key_set)) {
		key_set->ue_ip = saddr;
		key_set->pcscf_ip = daddr;
		update = true;
	}
	if(!ck_found && !security_server && !security_client) {
		++count_incomplete_header;
	}
	if(update) {
		key_set_work.set_at = time_s;
		if(iter_key_set != key_set_map.end()) {
			iter_key_set->second = key_set_work;
			key_set = &iter_key_set->second;
		} else {
			key_set = &key_set_map[call_id_str];
			*key_set = key_set_work;
		}
		completeKeySet(key_set, time_s);
	}
	unlock_collect();
}

bool cEspDecrypt::parseWwwAuthenticate(u_char *value, unsigned value_length, sKeySet *key_set, u_int32_t cseq) {
	unsigned ck_length;
	u_char *ck = findParam(value, value_length, "ck=\"", &ck_length);
	if(!ck || ck_length != ESP_CK_MAX_LENGTH * 2) {
		return(false);
	}
	char ck_hex[ESP_CK_MAX_LENGTH * 2 + 1];
	memcpy(ck_hex, ck, ck_length);
	ck_hex[ck_length] = 0;
	u_char ck_bin[ESP_CK_MAX_LENGTH];
	if(hexdecode(ck_bin, ck_hex, ESP_CK_MAX_LENGTH) != ESP_CK_MAX_LENGTH) {
		return(false);
	}
	memcpy(key_set->ck, ck_bin, ESP_CK_MAX_LENGTH);
	key_set->ck_length = ESP_CK_MAX_LENGTH;
	key_set->ck_cseq = cseq;
	unsigned ik_length;
	u_char *ik = findParam(value, value_length, "ik=\"", &ik_length);
	if(ik && ik_length == ESP_IK_MAX_LENGTH * 2) {
		char ik_hex[ESP_IK_MAX_LENGTH * 2 + 1];
		memcpy(ik_hex, ik, ik_length);
		ik_hex[ik_length] = 0;
		if(hexdecode(key_set->ik, ik_hex, ESP_IK_MAX_LENGTH) == ESP_IK_MAX_LENGTH) {
			key_set->ik_length = ESP_IK_MAX_LENGTH;
		}
	}
	return(true);
}

bool cEspDecrypt::parseSecurityServer(u_char *value, unsigned value_length, sKeySet *key_set, u_int32_t cseq) {
	unsigned param_length;
	u_char *param = findParam(value, value_length, "ealg=", &param_length);
	if(!param) {
		return(false);
	}
	eEncAlg ealg;
	if(param_length == 4 && !strncasecmp((char*)param, "null", 4)) {
		ealg = _ealg_null;
	} else if(param_length == 7 && !strncasecmp((char*)param, "aes-cbc", 7)) {
		ealg = _ealg_aes_cbc;
	} else {
		syslog(LOG_NOTICE, "esp_decrypt: unsupported ealg %.*s", (int)param_length, (char*)param);
		return(false);
	}
	unsigned icv_length;
	param = findParam(value, value_length, "alg=", &param_length);
	if(!param ||
	   (param_length == 13 && !strncasecmp((char*)param, "hmac-sha-1-96", 13)) ||
	   (param_length == 11 && !strncasecmp((char*)param, "hmac-md5-96", 11))) {
		icv_length = 12;
	} else if(param_length == 16 && !strncasecmp((char*)param, "hmac-sha-256-128", 16)) {
		icv_length = 16;
	} else {
		syslog(LOG_NOTICE, "esp_decrypt: unsupported alg %.*s", (int)param_length, (char*)param);
		return(false);
	}
	key_set->ealg = ealg;
	key_set->icv_length = icv_length;
	key_set->spi_cseq = cseq;
	key_set->spi_to_pcscf_count = 0;
	key_set->ports_pcscf_count = 0;
	param = findParam(value, value_length, "spi-c=", &param_length);
	if(param && param_length) {
		key_set->spi_to_pcscf[key_set->spi_to_pcscf_count++] = parseUInt(param, param_length);
	}
	param = findParam(value, value_length, "spi-s=", &param_length);
	if(param && param_length) {
		key_set->spi_to_pcscf[key_set->spi_to_pcscf_count++] = parseUInt(param, param_length);
	}
	param = findParam(value, value_length, "port-c=", &param_length);
	if(param && param_length) {
		key_set->addPort(key_set->ports_pcscf, &key_set->ports_pcscf_count, parseUInt(param, param_length));
	}
	param = findParam(value, value_length, "port-s=", &param_length);
	if(param && param_length) {
		key_set->addPort(key_set->ports_pcscf, &key_set->ports_pcscf_count, parseUInt(param, param_length));
	}
	return(key_set->spi_to_pcscf_count > 0);
}

bool cEspDecrypt::parseSecurityClient(u_char *value, unsigned value_length, sKeySet *key_set) {
	unsigned param_length;
	key_set->spi_to_ue_count = 0;
	key_set->ports_ue_count = 0;
	u_char *param = findParam(value, value_length, "spi-c=", &param_length);
	if(param && param_length) {
		key_set->spi_to_ue[key_set->spi_to_ue_count++] = parseUInt(param, param_length);
	}
	param = findParam(value, value_length, "spi-s=", &param_length);
	if(param && param_length) {
		key_set->spi_to_ue[key_set->spi_to_ue_count++] = parseUInt(param, param_length);
	}
	param = findParam(value, value_length, "port-c=", &param_length);
	if(param && param_length) {
		key_set->addPort(key_set->ports_ue, &key_set->ports_ue_count, parseUInt(param, param_length));
	}
	param = findParam(value, value_length, "port-s=", &param_length);
	if(param && param_length) {
		key_set->addPort(key_set->ports_ue, &key_set->ports_ue_count, parseUInt(param, param_length));
	}
	return(key_set->spi_to_ue_count > 0);
}

bool cEspDecrypt::completedKeySet(sKeySet *key_set) {
	return(key_set->ck_length &&
	       (key_set->spi_to_pcscf_count || key_set->spi_to_ue_count) &&
	       key_set->ealg != _ealg_na && key_set->pcscf_ip.isSet() &&
	       key_set->ck_cseq == key_set->spi_cseq);
}

void cEspDecrypt::completeKeySet(sKeySet *key_set, u_int32_t time_s) {
	if(!completedKeySet(key_set)) {
		return;
	}
	sSa sa;
	memcpy(sa.data.ck, key_set->ck, key_set->ck_length);
	sa.data.ck_length = key_set->ck_length;
	sa.data.ealg = key_set->ealg;
	sa.data.icv_length = key_set->icv_length;
	sa.data.ports_count = 0;
	for(unsigned i = 0; i < key_set->ports_ue_count && sa.data.ports_count < ESP_PORTS_MAX; i++) {
		sa.data.ports[sa.data.ports_count++] = key_set->ports_ue[i];
	}
	for(unsigned i = 0; i < key_set->ports_pcscf_count && sa.data.ports_count < ESP_PORTS_MAX; i++) {
		if(!sa.data.checkPort(key_set->ports_pcscf[i], key_set->ports_pcscf[i])) {
			sa.data.ports[sa.data.ports_count++] = key_set->ports_pcscf[i];
		}
	}
	sa.data.ue_ip = key_set->ue_ip;
	sa.data.pcscf_ip = key_set->pcscf_ip;
	sa.data.timeout = saTimeout(key_set->expires);
	sa.set_at = time_s;
	sa.last_store_at = time_s;
	sStoreSaItem store_items[ESP_SPI_MAX * 2];
	unsigned store_items_count = 0;
	bool sa_changed = false;
	lock_sa();
	for(unsigned i = 0; i < key_set->spi_to_pcscf_count; i++) {
		sSaId sa_id(key_set->spi_to_pcscf[i], key_set->pcscf_ip);
		map<sSaId, sSa>::iterator iter_sa = sa_map.find(sa_id);
		sSa sa_item = sa;
		bool store_sa = true;
		if(iter_sa != sa_map.end() && iter_sa->second.data == sa.data) {
			if(time_s < iter_sa->second.last_store_at + iter_sa->second.data.timeout / 2) {
				sa_item.last_store_at = iter_sa->second.last_store_at;
				store_sa = false;
			}
		} else {
			sa_changed = true;
		}
		sa_map[sa_id] = sa_item;
		if(store_sa && store_items_count < ESP_SPI_MAX * 2) {
			store_items[store_items_count].spi = key_set->spi_to_pcscf[i];
			store_items[store_items_count].dst_ip = key_set->pcscf_ip;
			store_items[store_items_count].sa = sa_item;
			++store_items_count;
		}
	}
	if(key_set->ue_ip.isSet()) {
		for(unsigned i = 0; i < key_set->spi_to_ue_count; i++) {
			sSaId sa_id(key_set->spi_to_ue[i], key_set->ue_ip);
			map<sSaId, sSa>::iterator iter_sa = sa_map.find(sa_id);
			sSa sa_item = sa;
			bool store_sa = true;
			if(iter_sa != sa_map.end() && iter_sa->second.data == sa.data) {
				if(time_s < iter_sa->second.last_store_at + iter_sa->second.data.timeout / 2) {
					sa_item.last_store_at = iter_sa->second.last_store_at;
					store_sa = false;
				}
			} else {
				sa_changed = true;
			}
			sa_map[sa_id] = sa_item;
			if(store_sa && store_items_count < ESP_SPI_MAX * 2) {
				store_items[store_items_count].spi = key_set->spi_to_ue[i];
				store_items[store_items_count].dst_ip = key_set->ue_ip;
				store_items[store_items_count].sa = sa_item;
				++store_items_count;
			}
		}
		ip_map[sIpPair(key_set->ue_ip, key_set->pcscf_ip)] = sa;
	}
	unlock_sa();
	for(unsigned i = 0; i < store_items_count; i++) {
		storeSa(store_items[i].spi, store_items[i].dst_ip, &store_items[i].sa);
	}
	if(!sa_changed) {
		return;
	}
	++count_sa_created;
	if(sverb.esp_decrypt) {
		ostringstream outStr;
		outStr << "*** ESP new sa"
		       << " / ue " << key_set->ue_ip.getString()
		       << " / pcscf " << key_set->pcscf_ip.getString()
		       << " / ck " << hexencode(key_set->ck, key_set->ck_length)
		       << " / ik " << (key_set->ik_length ? hexencode(key_set->ik, key_set->ik_length) : "-")
		       << " / ealg " << (key_set->ealg == _ealg_aes_cbc ? "aes-cbc" : "null")
		       << " / icv " << key_set->icv_length
		       << " / spi to pcscf";
		for(unsigned i = 0; i < key_set->spi_to_pcscf_count; i++) {
			outStr << " 0x" << hex << key_set->spi_to_pcscf[i] << dec;
		}
		outStr << " / spi to ue";
		for(unsigned i = 0; i < key_set->spi_to_ue_count; i++) {
			outStr << " 0x" << hex << key_set->spi_to_ue[i] << dec;
		}
		outStr << " / ports";
		for(unsigned i = 0; i < key_set->ports_ue_count; i++) {
			outStr << " " << key_set->ports_ue[i];
		}
		for(unsigned i = 0; i < key_set->ports_pcscf_count; i++) {
			outStr << " " << key_set->ports_pcscf[i];
		}
		outStr << " / timeout " << sa.data.timeout << "s"
		       << (key_set->expires ? " (from register expires)" : " (default)");
		cout << outStr.str() << endl;
	}
}

bool cEspDecrypt::findSa(u_int32_t spi, vmIP src_ip, vmIP dst_ip, sSa *sa, bool *from_ip_map) {
	*from_ip_map = false;
	lock_sa();
	map<sSaId, sSa>::iterator iter = sa_map.find(sSaId(spi, dst_ip));
	if(iter != sa_map.end()) {
		*sa = iter->second;
		unlock_sa();
		return(true);
	}
	map<sIpPair, sSa>::iterator iter_ip = ip_map.find(sIpPair(src_ip, dst_ip));
	if(iter_ip != ip_map.end()) {
		*sa = iter_ip->second;
		*from_ip_map = true;
		unlock_sa();
		return(true);
	}
	unlock_sa();
	return(false);
}

void cEspDecrypt::storeSa(u_int32_t spi, vmIP dst_ip, sSa *sa) {
	extern int opt_esp_store_sa;
	extern int opt_nocdr;
	extern int opt_id_sensor;
	if(!opt_esp_store_sa || opt_nocdr || !exists_sa_table || !sa->set_at) {
		return;
	}
	if(!sqlDb) {
		sqlDb = createSqlObject();
	}
	string ports;
	for(unsigned i = 0; i < sa->data.ports_count; i++) {
		if(i) {
			ports += ",";
		}
		ports += intToString(sa->data.ports[i]);
	}
	SqlDb_row row_insert;
	row_insert.add(opt_id_sensor < 0 ? 0 : opt_id_sensor, "id_sensor");
	row_insert.add(spi, "spi");
	row_insert.add(dst_ip, "dst_ip", false, sqlDb, storeSaTableName().c_str());
	row_insert.add(sa->data.ue_ip, "ue_ip", false, sqlDb, storeSaTableName().c_str());
	row_insert.add(sa->data.pcscf_ip, "pcscf_ip", false, sqlDb, storeSaTableName().c_str());
	row_insert.add(hexencode(sa->data.ck, sa->data.ck_length), "ck");
	row_insert.add((int)sa->data.ealg, "ealg");
	row_insert.add(sa->data.icv_length, "icv_length");
	row_insert.add(ports, "ports");
	row_insert.add(sa->data.timeout, "timeout");
	time_t set_at = sa->set_at;
	struct tm set_at_tm = time_r(&set_at, "local");
	string set_at_str = sqlDateTimeString(set_at_tm);
	row_insert.add(set_at_str, "set_at");
	SqlDb_row row_update;
	row_update.add(sa->data.ue_ip, "ue_ip", false, sqlDb, storeSaTableName().c_str());
	row_update.add(sa->data.pcscf_ip, "pcscf_ip", false, sqlDb, storeSaTableName().c_str());
	row_update.add(hexencode(sa->data.ck, sa->data.ck_length), "ck");
	row_update.add((int)sa->data.ealg, "ealg");
	row_update.add(sa->data.icv_length, "icv_length");
	row_update.add(ports, "ports");
	row_update.add(sa->data.timeout, "timeout");
	row_update.add(set_at_str, "set_at");
	sqlStore->query_lock(MYSQL_ADD_QUERY_END(
			     sqlDb->insertOrUpdateQuery(storeSaTableName(), row_insert, row_update, true, true)),
			     STORE_PROC_ID_OTHER, 0);
	deleteOldSa(sa->set_at);
}

void cEspDecrypt::deleteOldSa(u_int32_t time_s) {
	extern int opt_esp_store_sa;
	extern int opt_nocdr;
	extern int opt_id_sensor;
	if(!opt_esp_store_sa || opt_nocdr || !exists_sa_table) {
		return;
	}
	if(last_delete_old_sa_at && last_delete_old_sa_at > time_s - ESP_DELETE_OLD_SA_INTERVAL) {
		return;
	}
	if(!sqlDb) {
		sqlDb = createSqlObject();
	}
	list<SqlDb_condField> cond;
	cond.push_back(SqlDb_condField("id_sensor", intToString(opt_id_sensor < 0 ? 0 : opt_id_sensor)));
	time_t delete_old_at = time_s > ESP_DELETE_OLD_SA_MARGIN ? time_s - ESP_DELETE_OLD_SA_MARGIN : 0;
	struct tm delete_old_tm = time_r(&delete_old_at, "local");
	sqlStore->query_lock(MYSQL_ADD_QUERY_END(
			     "delete from " + storeSaTableName() +
			     " where " + sqlDb->getCondStr(&cond) +
			     " and set_at + interval timeout second < " + sqlEscapeStringBorder(sqlDateTimeString(delete_old_tm))),
			     STORE_PROC_ID_OTHER, 0);
	last_delete_old_sa_at = time_s;
}

string cEspDecrypt::storeSaTableName() {
	extern int opt_esp_store_sa;
	return(opt_esp_store_sa == 1 ? "esp_sa_mem" :
	       opt_esp_store_sa == 2 ? "esp_sa" : "");
}

bool cEspDecrypt::decryptAesCbc(u_char *ck, u_char *iv, u_char *data, unsigned datalen, u_char *out) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if(!ctx) {
		return(false);
	}
	bool rslt = false;
	if(EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, ck, iv)) {
		EVP_CIPHER_CTX_set_padding(ctx, 0);
		int out_length = 0;
		if(EVP_DecryptUpdate(ctx, out ? out : data, &out_length, data, datalen) &&
		   (unsigned)out_length == datalen) {
			rslt = true;
		}
	}
	EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);
	return(rslt);
}

bool cEspDecrypt::checkTrailer(u_char *trailer, unsigned trailer_length, unsigned enc_length, u_int8_t *pad_length, u_int8_t *next_header) {
	if(trailer_length < 2) {
		return(false);
	}
	*pad_length = trailer[trailer_length - 2];
	*next_header = trailer[trailer_length - 1];
	if((unsigned)*pad_length + 2 > enc_length) {
		return(false);
	}
	if(*next_header != IPPROTO_TCP && *next_header != IPPROTO_UDP) {
		return(false);
	}
	if(enc_length - *pad_length - 2 < (*next_header == IPPROTO_TCP ? sizeof(tcphdr2) : sizeof(udphdr2))) {
		return(false);
	}
	unsigned check_length = (unsigned)*pad_length + 2 <= trailer_length ? *pad_length : trailer_length - 2;
	for(unsigned i = 0; i < check_length; i++) {
		if(trailer[trailer_length - 2 - check_length + i] != *pad_length - check_length + i + 1) {
			return(false);
		}
	}
	return(true);
}

u_int32_t cEspDecrypt::saTimeout(u_int32_t expires) {
	if(!expires || expires > ESP_SA_TIMEOUT_MAX) {
		return(ESP_SA_TIMEOUT_DEFAULT);
	}
	return(max(expires + ESP_SA_EXPIRES_MARGIN, (u_int32_t)ESP_SA_TIMEOUT_MIN));
}

u_char *cEspDecrypt::findHeader(u_char *data, unsigned datalen, const char *header, unsigned *value_length) {
	unsigned header_length = strlen(header);
	for(unsigned i = 0; i + header_length + 1 < datalen; i++) {
		if(data[i] == '\n' &&
		   !strncasecmp((char*)data + i + 1, header, header_length)) {
			unsigned pos = i + 1 + header_length;
			while(pos < datalen && (data[pos] == ' ' || data[pos] == '\t')) {
				pos++;
			}
			unsigned end = pos;
			while(end < datalen && data[end] != '\r' && data[end] != '\n') {
				end++;
			}
			*value_length = end - pos;
			return(data + pos);
		}
	}
	*value_length = 0;
	return(NULL);
}

u_char *cEspDecrypt::findParam(u_char *data, unsigned datalen, const char *param, unsigned *value_length) {
	unsigned param_length = strlen(param);
	for(unsigned i = 0; i + param_length <= datalen; i++) {
		if(i > 0 &&
		   data[i - 1] != ' ' && data[i - 1] != ';' && data[i - 1] != ',' && data[i - 1] != '\t') {
			continue;
		}
		if(!strncasecmp((char*)data + i, param, param_length)) {
			unsigned pos = i + param_length;
			unsigned end = pos;
			while(end < datalen &&
			      data[end] != ',' && data[end] != ';' && data[end] != '"' &&
			      data[end] != ' ' && data[end] != '\t') {
				end++;
			}
			*value_length = end - pos;
			return(data + pos);
		}
	}
	*value_length = 0;
	return(NULL);
}

u_int32_t cEspDecrypt::parseUInt(u_char *data, unsigned datalen) {
	u_int32_t rslt = 0;
	for(unsigned i = 0; i < datalen; i++) {
		if(!isdigit(data[i])) {
			break;
		}
		rslt = rslt * 10 + (data[i] - '0');
	}
	return(rslt);
}

string cEspDecrypt::normalizeCallId(const char *call_id, unsigned call_id_length) {
	while(call_id_length && (*call_id == ' ' || *call_id == '\t')) {
		++call_id;
		--call_id_length;
	}
	while(call_id_length &&
	      (call_id[call_id_length - 1] == ' ' || call_id[call_id_length - 1] == '\t' ||
	       call_id[call_id_length - 1] == '\r' || call_id[call_id_length - 1] == '\n')) {
		--call_id_length;
	}
	return(string(call_id, call_id_length));
}

#endif //HAVE_OPENSSL


void esp_collect_keys(u_char *data, unsigned datalen,
		      vmIP saddr, vmPort sport, vmIP daddr, vmPort dport,
		      u_int32_t seq, u_int32_t ack, timeval time) {
	#if defined(HAVE_OPENSSL)
	EspDecrypt.collectKeys(data, datalen, saddr, sport, daddr, dport, seq, ack, time);
	#endif //HAVE_OPENSSL
}

bool esp_decrypt_packet(iphdr2 *header_ip, unsigned max_len) {
	#if defined(HAVE_OPENSSL)
	return(EspDecrypt.decrypt(header_ip, max_len));
	#else
	return(false);
	#endif //HAVE_OPENSSL
}

void esp_decrypt_init() {
	#if defined(HAVE_OPENSSL)
	EspDecrypt.loadSa();
	#endif //HAVE_OPENSSL
}

void esp_decrypt_update_expires(const char *call_id, unsigned call_id_length, u_int32_t expires, u_int32_t time_s) {
	#if defined(HAVE_OPENSSL)
	EspDecrypt.updateExpires(call_id, call_id_length, expires, time_s);
	#endif //HAVE_OPENSSL
}

void esp_decrypt_counters(sEspCounters *counters) {
	#if defined(HAVE_OPENSSL)
	EspDecrypt.getCounters(counters);
	#else
	memset(counters, 0, sizeof(*counters));
	#endif //HAVE_OPENSSL
}
