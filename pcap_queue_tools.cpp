#include "pcap_queue.h"
#include "tools_global.h"
#include "rrd.h"
#include "tcmalloc_hugetables.h"
#include "heap_chunk.h"
#include "ipaccount.h"
#include "calltable.h"
#include "server.h"
#include "ipfix.h"
#include "hep.h"
#include "ribbonsbc.h"
#include "tcpreassembly.h"
#include "tar.h"
#include "transcribe.h"

#if HAVE_LIBTCMALLOC
#include <gperftools/malloc_extension.h>
#endif


using namespace std;


static sPcapStatData::sLoadState load_state;


void reset_pcap_stat_load_state() {
	load_state.reset();
	extern vm_atomic<sPcapStatData> pbStatData;
	pbStatData = sPcapStatData();
}


static void appendSection(string &out, const string &s) {
	if(s.empty()) {
		return;
	}
	if(!out.empty() && out[out.size() - 1] != ' ') {
		out += " ";
	}
	out += s;
}


#define SECTIONS_LIST(X) \
	X(calls)             \
	X(audio)             \
	X(transcribe)        \
	X(ss7)               \
	X(ps)                \
	X(sqlf)              \
	X(sqlq)              \
	X(heap)              \
	X(deq)               \
	X(drop)              \
	X(pb_disk_buffer)    \
	X(pb_compress)       \
	X(traffic)           \
	X(disk_io)           \
	X(cdq)               \
	X(tar_queue)         \
	X(tar_copy_queue)    \
	X(tar_chunk_buffer)  \
	X(file_buffer)       \
	X(tar_cpu)           \
	X(read_threads)      \
	X(t0)                \
	X(t1)                \
	X(t2)                \
	X(rtp)               \
	X(http)              \
	X(webrtc)            \
	X(ssl)               \
	X(ssl_ws)            \
	X(dtls)              \
	X(sip_tcp)           \
	X(ipfix)             \
	X(hep)               \
	X(ribbonsbc)         \
	X(async_close_cpu)   \
	X(async_close_queue) \
	X(storing)           \
	X(charts)            \
	X(ipacc)             \
	X(ipacc_buffer)      \
	X(rrd)               \
	X(dedup)             \
	X(rss_vsz)           \
	X(hugepages)         \
	X(tcm_alloc)         \
	X(heap_hugepage)     \
	X(heap_hashtable)    \
	X(load_avg)          \
	X(tlb)               \
	X(version)           \
	X(external_error)


string sPcapStatData::render() {
	initialized = true;
	string out;
	if(mode == _mode_database_backup) {
		out = "database backup: ";
	}
#define X(name) appendSection(out, name.render());
	SECTIONS_LIST(X)
#undef X
	return(out);
}

void sPcapStatData::get_sections_all(vector<sValue> &out, eSectionNameBy by) const {
	out.push_back(sValue("mode", mode == _mode_database_backup ? "database_backup" : "standard"));
#define X(_n) { \
	size_t before = out.size(); \
	_n.get_sections(out); \
	if(by == _section_id_by_varname && out.size() == before + 1 && string(#_n) != "read_threads") { \
		out[before].name = #_n; \
	} \
}
	SECTIONS_LIST(X)
#undef X
}

void sPcapStatData::get_values_all(vector<sSectionValues> &out, eSectionNameBy by) const {
	sSectionValues mode_section("mode");
	mode_section.values.push_back(sValue("mode", mode == _mode_database_backup ? "database_backup" : "standard"));
	out.push_back(mode_section);
#define X(name) { \
	sSectionValues g(by == _section_id_by_varname ? string(#name) : name.title()); \
	name.get_values(g.values); \
	if(!g.values.empty()) out.push_back(g); \
}
	SECTIONS_LIST(X)
#undef X
}

string sPcapStatData::get_sections_all_json(eSectionNameBy by) const {
	vector<sValue> sections;
	get_sections_all(sections, by);
	JsonExport json;
	for(size_t i = 0; i < sections.size(); i++) {
		json.add(sections[i].name.c_str(), sections[i].value);
	}
	return(json.getJson());
}

string sPcapStatData::get_values_all_json(eSectionNameBy by) const {
	vector<sSectionValues> groups;
	get_values_all(groups, by);
	JsonExport json;
	for(size_t i = 0; i < groups.size(); i++) {
		JsonExport *section = json.addArray(groups[i].sect_id.c_str());
		for(size_t j = 0; j < groups[i].values.size(); j++) {
			const sValue &val = groups[i].values[j];
			JsonExport *item = section->addObject(NULL);
			item->add("name", val.name);
			item->add("value", val.value);
			if(!val.unit.empty()) {
				item->add("unit", val.unit);
			}
		}
	}
	return(json.getJson());
}

void sPcapStatData::rrd_all() const {
	calls.rrd();
	ps.rrd();
	sqlf.rrd();
	sqlq.rrd();
	heap.rrd();
	drop.rrd();
	traffic.rrd();
	disk_io.rrd();
	tar_cpu.rrd();
	t0.rrd();
	t1.rrd();
	t2.rrd();
	async_close_cpu.rrd();
	rss_vsz.rrd();
	load_avg.rrd();
}


void sPcapStatData::sCalls::load() {
	extern Calltable *calltable;
	extern volatile int calls_counter;
	extern volatile int calls_for_store_counter;
	extern volatile int registers_counter;
	extern volatile int storing_cdr_next_threads_count;
	active = calltable->getCountCalls();
	registers_active = calltable->registers_listMAP.size();
	#if EXPERIMENTAL_SEPARATE_PROCESSSING
	if(separate_processing() == 2) {
		total = calltable->calls_queue.size();
	} else {
		total = calls_counter;
	}
	#else
	total = calls_counter;
	#endif
	if(storing_cdr_next_threads_count > 1 && calls_for_store_counter > 0) {
		storing = calls_for_store_counter;
		calls_for_store_counter = 0;
	}
	registers_total = registers_counter;
	valid = true;
}

string sPcapStatData::sCalls::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) {
		out += title() + "[" + intToString(active) + ",r:" + intToString(registers_active) + "][" + intToString(total);
		if(storing) {
			out += "(s" + intToString(storing) + ")";
		}
		out += ",r:" + intToString(registers_total) + "]";
	} else {
		out += intToString(active) + ",r:" + intToString(registers_active) + "/" + intToString(total);
		if(storing) {
			out += "(s" + intToString(storing) + ")";
		}
		out += ",r:" + intToString(registers_total);
	}
	return(out);
}

void sPcapStatData::sCalls::get_sections(vector<sValue> &out) const {
	if(!valid) {
		return;
	}
	out.push_back(sValue("calls_active", intToString(active) + ",r:" + intToString(registers_active)));
	string v = intToString(total);
	if(storing) {
		v += "(s" + intToString(storing) + ")";
	}
	v += ",r:" + intToString(registers_total);
	out.push_back(sValue("calls_total", v));
}

void sPcapStatData::sCalls::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("active", intToString(active)));
	out.push_back(sValue("registers_active", intToString(registers_active)));
	out.push_back(sValue("total", intToString(total)));
	if(storing) {
		out.push_back(sValue("storing", intToString(storing)));
	}
	out.push_back(sValue("registers_total", intToString(registers_total)));
}

void sPcapStatData::sCalls::rrd() const {
	if(!valid) return;
	rrd_set_value(RRD_VALUE_inv, active);
	rrd_set_value(RRD_VALUE_reg, registers_active);
}

void sPcapStatData::sAudio::load() {
	extern Calltable *calltable;
	calltable->lock_calls_audioqueue();
	size_t audioQueueSize = calltable->audio_queue.size();
	if(audioQueueSize) {
		queue_size = audioQueueSize;
		threads = calltable->getCountActiveAudioQueueThreads(false);
		valid = true;
	}
	calltable->unlock_calls_audioqueue();
}

string sPcapStatData::sAudio::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += intToString(queue_size) + "/" + intToString(threads);
	if(with_title) out += "]";
	return(out);
}

void sPcapStatData::sAudio::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("queue_size", intToString(queue_size)));
	out.push_back(sValue("threads", intToString(threads)));
}

void sPcapStatData::sTranscribe::load() {
	unsigned qs, ct;
	if(transcribeQueueStat(&qs, &ct)) {
		queue_size = qs;
		count_threads = ct;
		valid = true;
	}
}

string sPcapStatData::sTranscribe::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string body = intToString(queue_size) + "/" + intToString(count_threads);
	if(with_title) {
		return(title() + "[" + body + "]");
	}
	return(body);
}

void sPcapStatData::sTranscribe::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("queue_size", intToString(queue_size)));
	out.push_back(sValue("count_threads", intToString(count_threads)));
}

void sPcapStatData::sSS7::load() {
	extern Calltable *calltable;
	listmap_size = calltable->ss7_listMAP.size();
	queue_size = calltable->ss7_queue.size();
	valid = true;
}

string sPcapStatData::sSS7::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += intToString(listmap_size) + "/" + intToString(queue_size);
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sSS7::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("listmap_size", intToString(listmap_size)));
	out.push_back(sValue("queue_size", intToString(queue_size)));
}

void sPcapStatData::sPS::load() {
	extern u_int64_t counter_calls;
	extern u_int64_t counter_calls_clean;
	extern volatile u_int64_t counter_calls_save_1;
	extern volatile u_int64_t counter_calls_save_2;
	extern u_int64_t counter_registers;
	extern u_int64_t counter_registers_clean;
	extern u_int64_t counter_sip_packets[2];
	extern u_int64_t counter_sip_register_packets;
	extern u_int64_t counter_sip_message_packets;
	extern u_int64_t counter_rtp_packets[2];
	extern u_int64_t counter_all_packets;
	extern volatile u_int64_t counter_user_packets[5];
	u_int64_t now_ms = getTimeMS();
	double elapsed_s = load_state.ps.old_time_ms && now_ms > load_state.ps.old_time_ms ? (double)(now_ms - load_state.ps.old_time_ms) / 1000.0 : 0;
	if(elapsed_s > 0) {
		if(load_state.ps.counter_calls_old) {
			calls_new = (unsigned long)((counter_calls - load_state.ps.counter_calls_old) / elapsed_s);
			calls_new_valid = true;
		}
		if(load_state.ps.counter_calls_clean_old) {
			calls_cleanup = (unsigned long)((counter_calls_clean - load_state.ps.counter_calls_clean_old) / elapsed_s);
			calls_cleanup_valid = true;
		}
		if(load_state.ps.counter_calls_save_1_old) {
			calls_for_save = (unsigned long)((counter_calls_save_1 - load_state.ps.counter_calls_save_1_old) / elapsed_s);
			calls_for_save_valid = true;
		}
		if(load_state.ps.counter_calls_save_2_old) {
			calls_saved = (unsigned long)((counter_calls_save_2 - load_state.ps.counter_calls_save_2_old) / elapsed_s);
			calls_saved_valid = true;
		}
		if(load_state.ps.counter_registers_old) {
			registers_new = (unsigned long)((counter_registers - load_state.ps.counter_registers_old) / elapsed_s);
			registers_new_valid = true;
		}
		if(load_state.ps.counter_registers_clean_old) {
			registers_cleanup = (unsigned long)((counter_registers_clean - load_state.ps.counter_registers_clean_old) / elapsed_s);
			registers_cleanup_valid = true;
		}
		if(load_state.ps.counter_sip_packets_old[0]) {
			packets_sip_all = (unsigned long)((counter_sip_packets[0] - load_state.ps.counter_sip_packets_old[0]) / elapsed_s);
			packets_sip_all_valid = true;
		}
		if(load_state.ps.counter_sip_packets_old[1]) {
			packets_sip_all_parsed = (unsigned long)((counter_sip_packets[1] - load_state.ps.counter_sip_packets_old[1]) / elapsed_s);
			packets_sip_all_parsed_valid = true;
		}
		if(load_state.ps.counter_sip_register_packets_old) {
			packets_sip_register = (unsigned long)((counter_sip_register_packets - load_state.ps.counter_sip_register_packets_old) / elapsed_s);
			packets_sip_register_valid = true;
		}
		if(load_state.ps.counter_sip_message_packets_old) {
			packets_sip_message = (unsigned long)((counter_sip_message_packets - load_state.ps.counter_sip_message_packets_old) / elapsed_s);
			packets_sip_message_valid = true;
		}
		if(load_state.ps.counter_rtp_packets_old[0]) {
			packets_rtp = (unsigned long)((counter_rtp_packets[0] - load_state.ps.counter_rtp_packets_old[0]) / elapsed_s);
			packets_rtp_valid = true;
		}
		if(load_state.ps.counter_rtp_packets_old[1]) {
			packets_rtp_sdp_multi = (unsigned long)((counter_rtp_packets[1] - load_state.ps.counter_rtp_packets_old[1]) / elapsed_s);
			packets_rtp_sdp_multi_valid = true;
		}
		if(load_state.ps.counter_all_packets_old) {
			packets_all = (unsigned long)((counter_all_packets - load_state.ps.counter_all_packets_old) / elapsed_s);
			packets_all_valid = true;
		}
		for(unsigned i = 0; i < sizeof(load_state.ps.counter_user_packets_old) / sizeof(load_state.ps.counter_user_packets_old[0]); i++) {
			if(counter_user_packets[i] && load_state.ps.counter_user_packets_old[i]) {
				packets_debug[i] = (unsigned long)((counter_user_packets[i] - load_state.ps.counter_user_packets_old[i]) / elapsed_s);
			}
		}
		valid = true;
	}
	load_state.ps.counter_calls_old = counter_calls;
	load_state.ps.counter_calls_clean_old = counter_calls_clean;
	load_state.ps.counter_calls_save_1_old = counter_calls_save_1;
	load_state.ps.counter_calls_save_2_old = counter_calls_save_2;
	load_state.ps.counter_registers_old = counter_registers;
	load_state.ps.counter_registers_clean_old = counter_registers_clean;
	load_state.ps.counter_sip_packets_old[0] = counter_sip_packets[0];
	load_state.ps.counter_sip_packets_old[1] = counter_sip_packets[1];
	load_state.ps.counter_sip_register_packets_old = counter_sip_register_packets;
	load_state.ps.counter_sip_message_packets_old = counter_sip_message_packets;
	load_state.ps.counter_rtp_packets_old[0] = counter_rtp_packets[0];
	load_state.ps.counter_rtp_packets_old[1] = counter_rtp_packets[1];
	load_state.ps.counter_all_packets_old = counter_all_packets;
	for(unsigned i = 0; i < sizeof(load_state.ps.counter_user_packets_old) / sizeof(load_state.ps.counter_user_packets_old[0]); i++) {
		load_state.ps.counter_user_packets_old[i] = counter_user_packets[i];
	}
	load_state.ps.old_time_ms = now_ms;
}

string sPcapStatData::sPS::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += "C:";
	out += calls_new_valid ? intToString(calls_new) : "-";
	out += "/";
	out += calls_cleanup_valid ? "-" + intToString(calls_cleanup) : "-";
	if(calls_for_save_valid || calls_saved_valid) {
		out += "(";
		out += calls_for_save_valid ? intToString(calls_for_save) : "-";
		out += "/";
		out += calls_saved_valid ? intToString(calls_saved) : "-";
		out += ")";
	}
	out += " r:";
	out += registers_new_valid ? intToString(registers_new) : "-";
	out += "/";
	out += registers_cleanup_valid ? "-" + intToString(registers_cleanup) : "-";
	out += " S:";
	out += packets_sip_all_valid ? intToString(packets_sip_all) : "-";
	out += "/";
	out += packets_sip_all_parsed_valid ? intToString(packets_sip_all_parsed) : "-";
	out += " SR:";
	out += packets_sip_register_valid ? intToString(packets_sip_register) : "-";
	out += " SM:";
	out += packets_sip_message_valid ? intToString(packets_sip_message) : "-";
	out += " R:";
	out += packets_rtp_valid ? intToString(packets_rtp) : "-";
	out += "/";
	out += packets_rtp_sdp_multi_valid ? intToString(packets_rtp_sdp_multi) : "-";
	out += " A:";
	out += packets_all_valid ? intToString(packets_all) : "-";
	for(size_t i = 0; i < packets_debug.size(); i++) {
		if(packets_debug.isSet(i)) {
			out += " U" + intToString(i) + ":" + intToString(packets_debug[i]);
		}
	}
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sPS::get_values(vector<sValue> &out) const {
	if(!valid) return;
	if(calls_new_valid) out.push_back(sValue("calls_new", intToString(calls_new)));
	if(calls_cleanup_valid) out.push_back(sValue("calls_cleanup", intToString(calls_cleanup)));
	if(calls_for_save_valid) out.push_back(sValue("calls_for_save", intToString(calls_for_save)));
	if(calls_saved_valid) out.push_back(sValue("calls_saved", intToString(calls_saved)));
	if(registers_new_valid) out.push_back(sValue("registers_new", intToString(registers_new)));
	if(registers_cleanup_valid) out.push_back(sValue("registers_cleanup", intToString(registers_cleanup)));
	if(packets_sip_all_valid) out.push_back(sValue("packets_sip_all", intToString(packets_sip_all)));
	if(packets_sip_all_parsed_valid) out.push_back(sValue("packets_sip_all_parsed", intToString(packets_sip_all_parsed)));
	if(packets_sip_register_valid) out.push_back(sValue("packets_sip_register", intToString(packets_sip_register)));
	if(packets_sip_message_valid) out.push_back(sValue("packets_sip_message", intToString(packets_sip_message)));
	if(packets_rtp_valid) out.push_back(sValue("packets_rtp", intToString(packets_rtp)));
	if(packets_rtp_sdp_multi_valid) out.push_back(sValue("packets_rtp_sdp_multi", intToString(packets_rtp_sdp_multi)));
	if(packets_all_valid) out.push_back(sValue("packets_all", intToString(packets_all)));
	for(size_t i = 0; i < packets_debug.size(); i++) {
		if(packets_debug.isSet(i)) {
			out.push_back(sValue("packets_debug_" + intToString(i), intToString(packets_debug[i])));
		}
	}
}

void sPcapStatData::sPS::rrd() const {
	if(!valid) return;
	if(calls_new_valid) rrd_set_value(RRD_VALUE_PS_C, calls_new);
	if(packets_sip_all_valid) rrd_set_value(RRD_VALUE_PS_S0, packets_sip_all);
	if(packets_sip_all_parsed_valid) rrd_set_value(RRD_VALUE_PS_S1, packets_sip_all_parsed);
	if(packets_sip_register_valid) rrd_set_value(RRD_VALUE_PS_SR, packets_sip_register);
	if(packets_sip_message_valid) rrd_set_value(RRD_VALUE_PS_SM, packets_sip_message);
	if(packets_rtp_valid) rrd_set_value(RRD_VALUE_PS_R, packets_rtp);
	if(packets_all_valid) rrd_set_value(RRD_VALUE_PS_A, packets_all);
}

void sPcapStatData::sSqlF::load() {
	extern MySqlStore *loadFromQFiles;
	if(!loadFromQFiles) return;
	vector<MySqlStore::sLoadFromQFilesStatItem> stat_items;
	loadFromQFiles->getLoadFromQFilesStat(&stat_items);
	vector<MySqlStore::sLoadFromQFilesStatItem> stat_proc_items;
	if(sverb.qfiles) {
		loadFromQFiles->getLoadFromQFilesStat(&stat_proc_items, true);
	}
	avg_delay = SqlDb::getAvgDelayQuery(SqlDb::_tq_store);
	query_count = loadFromQFiles->getLoadFromQFilesCount();
	SqlDb::resetDelayQuery(SqlDb::_tq_store);
	if(!stat_items.empty()) {
		for(size_t i = 0; i < stat_items.size(); i++) {
			sItem item;
			item.id_main = stat_items[i].id_main;
			item.id_main_str = stat_items[i].id_main_str;
			item.id_2 = stat_items[i].id_2;
			item.count = stat_items[i].count;
			items.push_back(item);
		}
		valid = true;
		for(size_t i = 0; i < stat_proc_items.size(); i++) {
			sItem item;
			item.id_main = stat_proc_items[i].id_main;
			item.id_main_str = stat_proc_items[i].id_main_str;
			item.id_2 = stat_proc_items[i].id_2;
			item.count = stat_proc_items[i].count;
			items_proc.push_back(item);
		}
	}
}

string sPcapStatData::sSqlF::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	bool first = true;
	for(size_t i = 0; i < items.size(); i++) {
		if(items.isSet(i)) {
			if(!first) out += ", ";
			out += string(items[i].id_main_str) + ": " + intToString(items[i].count);
			first = false;
		}
	}
	if(avg_delay) {
		out += " / " + floatToString((double)avg_delay / 1000, (unsigned)3) + "s";
	}
	if(items_proc.size()) {
		out += " / ";
		first = true;
		for(size_t i = 0; i < items_proc.size(); i++) {
			if(items_proc.isSet(i)) {
				if(!first) out += ",";
				out += intToString(items_proc[i].id_main) + "_" + intToString(items_proc[i].id_2) + ":" + intToString(items_proc[i].count);
				first = false;
			}
		}
	}
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sSqlF::get_values(vector<sValue> &out) const {
	if(!valid) return;
	for(size_t i = 0; i < items.size(); i++) {
		if(items.isSet(i)) {
			out.push_back(sValue(string(items[i].id_main_str), intToString(items[i].count)));
		}
	}
	if(avg_delay) {
		out.push_back(sValue("avg_delay", floatToString((double)avg_delay / 1000, (unsigned)3), "s"));
	}
	if(query_count) {
		out.push_back(sValue("query_count", intToString(query_count)));
	}
	for(size_t i = 0; i < items_proc.size(); i++) {
		if(items_proc.isSet(i)) {
			out.push_back(sValue(intToString(items_proc[i].id_main) + "_" + intToString(items_proc[i].id_2), intToString(items_proc[i].count)));
		}
	}
}

void sPcapStatData::sSqlF::rrd() const {
	if(avg_delay || query_count) {
		rrd_set_value(RRD_VALUE_SQLf_D, avg_delay);
		rrd_set_value(RRD_VALUE_SQLf_C, query_count);
	}
}

void sPcapStatData::sSqlQ::load() {
	extern bool opt_save_query_main_to_files;
	extern MySqlStore *loadFromQFiles;
	extern MySqlStore *sqlStore;
	if(loadFromQFiles && opt_save_query_main_to_files && !sverb.force_log_sqlq) {
		return;
	}
	u_int64_t now_ms = getTimeMS();
	bool filled = false;
	if(isCloud()) {
		int sizeSQLq = sqlStore->getSize(1, 0) +
			       (loadFromQFiles ? loadFromQFiles->getSize(1, 0) : 0);
		cloud_mode = true;
		cloud_size = sizeSQLq >= 0 ? sizeSQLq : 0;
		filled = true;
	} else {
		map<int, int> size_map;
		map<int, int> size_map_by_id_2;
		sqlStore->fillSizeMap(&size_map, &size_map_by_id_2);
		if(loadFromQFiles) {
			loadFromQFiles->fillSizeMap(&size_map, &size_map_by_id_2);
		}
		for(map<int, int>::iterator iter = size_map_by_id_2.begin(); iter != size_map_by_id_2.end(); iter++) {
			int id_main = iter->first / 100;
			int id_2 = iter->first % 100;
			int size = iter->second;
			string id_main_str =
				id_main == STORE_PROC_ID_CDR ? "C" :
				id_main == STORE_PROC_ID_CDR_REDIRECT ? "Cr" :
				id_main == STORE_PROC_ID_CHARTS_CACHE  ? "ch" :
				id_main == STORE_PROC_ID_MESSAGE ? "M" :
				id_main == STORE_PROC_ID_SIP_MSG ? "SM" :
				id_main == STORE_PROC_ID_REGISTER ? "R" :
				id_main == STORE_PROC_ID_SS7 ? "7" :
				id_main == STORE_PROC_ID_SAVE_PACKET_SQL ? "L" :
				id_main == STORE_PROC_ID_CLEANSPOOL ? "Cl" :
				id_main == STORE_PROC_ID_HTTP ? "H" :
				id_main == STORE_PROC_ID_OTHER ? "O" :
				("i" + intToString(id_main) + "_");
			sItem item;
			item.id_main = id_main;
			item.id_main_str = id_main_str;
			item.id_2 = id_2 + 1;
			item.size = size;
			items.push_back(item);
			filled = true;
		}
	}
	if(filled) {
		valid = true;
		double elapsed_s = load_state.sql_q.old_time_ms && now_ms > load_state.sql_q.old_time_ms ? (double)(now_ms - load_state.sql_q.old_time_ms) / 1000.0 : 0;
		for(int i = 0; i < 2; i++) {
			SqlDb::eTypeQuery typeQuery = i == 0 ? SqlDb::_tq_std : SqlDb::_tq_redirect;
			u_int32_t avgDelayQuery = SqlDb::getAvgDelayQuery(typeQuery);
			if(avgDelayQuery) {
				if(i == 0) {
					avg_delay_std = avgDelayQuery;
				} else {
					avg_delay_redirect = avgDelayQuery;
				}
			}
			u_int32_t countQuery = SqlDb::getCountQuery(typeQuery);
			if(countQuery && elapsed_s > 0) {
				if(i == 0) {
					count_std = (u_int32_t)(countQuery / elapsed_s);
				} else {
					count_redirect = (u_int32_t)(countQuery / elapsed_s);
				}
			}
			SqlDb::resetDelayQuery(typeQuery);
		}
		u_int64_t insertCount = SqlDb::getCountInsert();
		if(insertCount && elapsed_s > 0) {
			u_int64_t per_s = (u_int64_t)(insertCount / elapsed_s);
			if(per_s) {
				insert_count = per_s;
			}
			SqlDb::resetCountInsert();
		}
	}
	load_state.sql_q.old_time_ms = now_ms;
}

string sPcapStatData::sSqlQ::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	if(cloud_mode) {
		out += intToString(cloud_size);
	} else {
		bool first = true;
		for(size_t i = 0; i < items.size(); i++) {
			if(items.isSet(i)) {
				if(!first) {
					out += " ";
				}
				out += string(items[i].id_main_str) + intToString(items[i].id_2) + ":" + intToString(items[i].size);
				first = false;
			}
		}
	}
	if(avg_delay_std) {
		out += " / " + floatToString((double)avg_delay_std / 1000, (unsigned)3) + "s";
	}
	if(count_std) {
		out += " / " + intToString(count_std) + "q/s";
	}
	if(avg_delay_redirect) {
		out += " / R" + floatToString((double)avg_delay_redirect / 1000, (unsigned)3) + "s";
	}
	if(count_redirect) {
		out += " / R" + intToString(count_redirect) + "q/s";
	}
	if(insert_count) {
		out += " / " + intToString(insert_count) + "i/s";
	}
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sSqlQ::get_values(vector<sValue> &out) const {
	if(!valid) return;
	if(cloud_mode) {
		out.push_back(sValue("cloud_size", intToString(cloud_size)));
	} else {
		for(size_t i = 0; i < items.size(); i++) {
			if(items.isSet(i)) {
				out.push_back(sValue(string(items[i].id_main_str) + intToString(items[i].id_2), intToString(items[i].size)));
			}
		}
	}
	if(avg_delay_std) {
		out.push_back(sValue("avg_delay_std", floatToString((double)avg_delay_std / 1000, (unsigned)3), "s"));
	}
	if(count_std) {
		out.push_back(sValue("count_std", intToString(count_std), "q/s"));
	}
	if(avg_delay_redirect) {
		out.push_back(sValue("avg_delay_redirect", floatToString((double)avg_delay_redirect / 1000, (unsigned)3), "s"));
	}
	if(count_redirect) {
		out.push_back(sValue("count_redirect", intToString(count_redirect), "q/s"));
	}
	if(insert_count) {
		out.push_back(sValue("insert_count", intToString(insert_count), "i/s"));
	}
}

void sPcapStatData::sSqlQ::rrd() const {
	if(!valid) return;
	for(size_t i = 0; i < items.size(); i++) {
		const char *id_main_rrd_str =
			items[i].id_main == STORE_PROC_ID_CDR ? RRD_VALUE_SQLq_C :
			items[i].id_main == STORE_PROC_ID_MESSAGE ? RRD_VALUE_SQLq_M :
			items[i].id_main == STORE_PROC_ID_SIP_MSG ? RRD_VALUE_SQLq_SM :
			items[i].id_main == STORE_PROC_ID_REGISTER ? RRD_VALUE_SQLq_R :
			items[i].id_main == STORE_PROC_ID_HTTP ? RRD_VALUE_SQLq_H :
			NULL;
		if(id_main_rrd_str) {
			rrd_add_value(id_main_rrd_str, items[i].size);
		}
	}
}

void sPcapStatData::sHeap::load() {
	extern cBuffersControl buffersControl;
	all_perc = buffersControl.getPerc_pb();
	used_perc = buffersControl.getPerc_pb_used();
	trash_perc = buffersControl.getPerc_pb_trash();
	valid = true;
	if(sverb.heap_use_time) {
		unsigned long trashMinTime;
		unsigned long trashMaxTime;
		buffersControl.PcapQueue_readFromFifo__blockStoreTrash_time_get(&trashMinTime, &trashMaxTime);
		buffersControl.PcapQueue_readFromFifo__blockStoreTrash_time_clear();
		if(trashMinTime || trashMaxTime) {
			trash_min_time = trashMinTime;
			trash_max_time = trashMaxTime;
			trash_time_valid = true;
		}
	}
	extern bool opt_use_dpdk;
	extern bool opt_dpdk_rotate_packetbuffer;
	extern bool opt_dpdk_copy_packetbuffer;
	extern bool opt_dpdk_prealloc_packetbuffer;
	if(opt_use_dpdk && opt_dpdk_rotate_packetbuffer &&
	   (opt_dpdk_copy_packetbuffer || opt_dpdk_prealloc_packetbuffer)) {
		pool_perc = buffersControl.getPerc_pb_pool();
		pool_valid = true;
	}
	double useAsyncWriteBuffer = buffersControl.getPerc_asyncwrite();
	if(useAsyncWriteBuffer > 0) {
		async_write_perc = useAsyncWriteBuffer;
		async_valid = true;
	}
}

string sPcapStatData::sHeap::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += "u" + floatToString(used_perc, (unsigned)0) + "|t" + floatToString(trash_perc, (unsigned)0);
	if(trash_time_valid) {
		out += "(" + intToString(trash_min_time) + "-" + intToString(trash_max_time) + "ms)";
	}
	if(pool_valid) {
		out += "|p" + floatToString(pool_perc, (unsigned)0);
	}
	if(async_valid) {
		out += "|a" + floatToString(async_write_perc, (unsigned)0);
	}
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sHeap::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("all_perc", floatToString(all_perc, (unsigned)0), "%"));
	out.push_back(sValue("used_perc", floatToString(used_perc, (unsigned)0), "%"));
	out.push_back(sValue("trash_perc", floatToString(trash_perc, (unsigned)0), "%"));
	if(trash_time_valid) {
		out.push_back(sValue("trash_min_time", intToString(trash_min_time), "ms"));
		out.push_back(sValue("trash_max_time", intToString(trash_max_time), "ms"));
	}
	if(pool_valid) {
		out.push_back(sValue("pool_perc", floatToString(pool_perc, (unsigned)0), "%"));
	}
	if(async_valid) {
		out.push_back(sValue("async_write_perc", floatToString(async_write_perc, (unsigned)0), "%"));
	}
}

void sPcapStatData::sHeap::rrd() const {
	if(!valid) return;
	rrd_set_value(RRD_VALUE_buffer, all_perc);
	if(async_valid) {
		rrd_set_value(RRD_VALUE_ratio, async_write_perc);
	}
}

void sPcapStatData::sDeq::load() {
	extern cBuffersControl buffersControl;
	double used = buffersControl.getPerc_pb_used_dequeu();
	unsigned int dequeu_time = buffersControl.get_dequeu_time();
	if(used > 0 || dequeu_time) {
		used_perc = used;
		window = dequeu_time;
		valid = true;
	}
}

string sPcapStatData::sDeq::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += floatToString(used_perc, (unsigned)0) + "/" + intToString(window);
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sDeq::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("used_perc", floatToString(used_perc, (unsigned)0), "%"));
	out.push_back(sValue("window", intToString(window)));
}

void sPcapStatData::sDrop::load(unsigned long bypass, const vector<sDropItem> &drops, u_int64_t count) {
	if(!bypass && drops.empty()) return;
	valid = true;
	if(bypass) {
		bypass_buffer_exceeded = bypass;
	}
	if(!drops.empty()) {
		packet_drops_count = count;
		for(size_t i = 0; i < drops.size(); i++) {
			packet_drops.push_back(drops[i]);
		}
	}
}

string sPcapStatData::sDrop::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	if(bypass_buffer_exceeded) {
		out += "H:" + intToString(bypass_buffer_exceeded);
	}
	if(packet_drops.size()) {
		if(bypass_buffer_exceeded) {
			out += " ";
		}
		bool first = true;
		for(size_t i = 0; i < packet_drops.size(); i++) {
			if(packet_drops.isSet(i)) {
				if(!first) out += " ";
				out += "I-" + string(packet_drops[i].interface_alias) + ":" + intToString(packet_drops[i].count);
				first = false;
			}
		}
	}
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sDrop::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("bypass_buffer_exceeded", intToString(bypass_buffer_exceeded)));
	if(packet_drops.size()) {
		sValue interfaces("interfaces", "");
		for(size_t i = 0; i < packet_drops.size(); i++) {
			if(packet_drops.isSet(i)) {
				interfaces.childs.push_back(sValue(string(packet_drops[i].interface_alias), intToString(packet_drops[i].count)));
			}
		}
		out.push_back(interfaces);
	}
	if(packet_drops_count) {
		out.push_back(sValue("packet_drops_count", intToString(packet_drops_count)));
	}
}

void sPcapStatData::sDrop::rrd() const {
	if(!valid) return;
	if(bypass_buffer_exceeded) {
		rrd_set_value(RRD_VALUE_exceeded, bypass_buffer_exceeded);
	}
	if(!packet_drops.empty()) {
		rrd_set_value(RRD_VALUE_packets, packet_drops_count);
	}
}

void sPcapStatData::sPbDiskBuffer::load(double mb, double perc) {
	if(mb < 0) return;
	this->mb = mb;
	this->perc = perc;
	valid = true;
}

string sPcapStatData::sPbDiskBuffer::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += floatToString(mb, (unsigned)1) + "MB " + floatToString(perc, (unsigned)1) + "%";
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sPbDiskBuffer::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("mb", floatToString(mb, (unsigned)1), "MB"));
	out.push_back(sValue("perc", floatToString(perc, (unsigned)0), "%"));
}

void sPcapStatData::sPbCompress::load(double value) {
	if(value < 0) return;
	this->value = value;
	valid = true;
}

string sPcapStatData::sPbCompress::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += floatToString(value, (unsigned)0);
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sPbCompress::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("value", floatToString(value, (unsigned)2)));
}

void sPcapStatData::sTraffic::load(PcapQueue *instance) {
	if(!instance) return;
	extern double last_traffic;
	u_int64_t now_ms = getTimeMS();
	u_int64_t divide_ms = load_state.traffic.old_time_ms && now_ms > load_state.traffic.old_time_ms ? now_ms - load_state.traffic.old_time_ms : 1000ULL;
	double speed_mb_s = instance->pcapStat_get_speed_mb_s(divide_ms);
	double speed_out_mb_s = instance->pcapStat_get_speed_out_mb_s(divide_ms);
	#if LOG_PACKETS_PER_SEC
	double speed_packets_s = instance->pcapStat_get_speed_packets_s(divide_ms);
	double speed_out_packets_s = instance->pcapStat_get_speed_out_packets_s(divide_ms);
	#endif
	if(speed_mb_s >= 0 || speed_out_mb_s >= 0) {
		valid = true;
		if(speed_mb_s >= 0) {
			mbps_in = speed_mb_s;
			mbps_in_valid = true;
		}
		if(speed_out_mb_s >= 0) {
			mbps_out = speed_out_mb_s;
			mbps_out_valid = true;
		}
		#if LOG_PACKETS_PER_SEC
		if(speed_packets_s >= 0) {
			pps_in = speed_packets_s;
			pps_in_valid = true;
		}
		if(speed_out_packets_s >= 0) {
			pps_out = speed_out_packets_s;
			pps_out_valid = true;
		}
		#endif
		#if LOG_PACKETS_SUM
		extern unsigned long long sumPacketsCount[3];
		extern unsigned long long sumPacketsCountOut[3];
		if(sumPacketsCount[0] > 0) {
			packets_in_sum = sumPacketsCount[0];
			packets_sum_valid = true;
		}
		if(sumPacketsCountOut[0] > 0) {
			packets_out_sum = sumPacketsCountOut[0];
			packets_sum_valid = true;
		}
		#endif
		last_traffic = speed_mb_s;
	}
	load_state.traffic.old_time_ms = now_ms;
}

string sPcapStatData::sTraffic::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	if(mbps_in <= 0 && mbps_out <= 0) {
		return("");
	}
	string out;
	if(with_title) out += "[";
	bool needSeparator = false;
	if(mbps_in_valid || mbps_out_valid) {
		out += mbps_in_valid ? floatToString(mbps_in, (unsigned)1) : "-";
		if(mbps_out_valid) {
			out += "/" + floatToString(mbps_out, (unsigned)1);
		}
		out += "Mb/s";
		needSeparator = true;
	}
	if(pps_in_valid || pps_out_valid) {
		if(needSeparator) {
			out += " ";
			needSeparator = false;
		}
		out += pps_in_valid ? floatToString(pps_in, (unsigned)0) : "-";
		if(pps_out_valid) {
			out += "/" + floatToString(pps_out, (unsigned)0);
		}
		out += "p/s";
		needSeparator = true;
	}
	if(packets_sum_valid) {
		if(needSeparator) {
			out += " ";
			needSeparator = false;
		}
		out += packets_in_sum > 0 ? intToString(packets_in_sum) : "-";
		out += "/";
		out += packets_out_sum > 0 ? intToString(packets_out_sum) : "-";
		out += "p";
	}
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sTraffic::get_values(vector<sValue> &out) const {
	if(!valid) return;
	if(mbps_in_valid) out.push_back(sValue("mbps_in", floatToString(mbps_in, (unsigned)1), "Mb/s"));
	if(mbps_out_valid) out.push_back(sValue("mbps_out", floatToString(mbps_out, (unsigned)1), "Mb/s"));
	if(pps_in_valid) out.push_back(sValue("pps_in", floatToString(pps_in, (unsigned)0), "p/s"));
	if(pps_out_valid) out.push_back(sValue("pps_out", floatToString(pps_out, (unsigned)0), "p/s"));
	if(packets_sum_valid) {
		out.push_back(sValue("packets_in_sum", intToString(packets_in_sum)));
		out.push_back(sValue("packets_out_sum", intToString(packets_out_sum)));
	}
}

void sPcapStatData::sTraffic::rrd() const {
	if(!valid) return;
	rrd_set_value(RRD_VALUE_mbs, mbps_in);
}

void sPcapStatData::sIo::load(double useAsyncWriteBuffer) {
	if(!diskIOMonitor.isActive() && !diskIOMonitor.isCalibrating()) return;
	diskIOMonitor.update(useAsyncWriteBuffer);
	active = diskIOMonitor.isActive();
	calibrating = diskIOMonitor.isCalibrating();
	status_string = diskIOMonitor.formatStatusString();
	if(active) {
		metrics = diskIOMonitor.getMetrics();
	}
	if(calibrating) {
		calibration_progress = diskIOMonitor.getCalibrationProgress();
	}
}

string sPcapStatData::sIo::render(bool with_title) const {
	if(!active && !calibrating) {
		return("");
	}
	if(status_string.empty()) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += status_string;
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sIo::get_values(vector<sValue> &out) const {
	if(!active && !calibrating) return;
	out.push_back(sValue("active", active ? "1" : "0"));
	out.push_back(sValue("calibrating", calibrating ? "1" : "0"));
	if(calibration_progress) {
		out.push_back(sValue("calibration_progress", intToString(calibration_progress)));
	}
	if(!status_string.empty()) {
		out.push_back(sValue("status_string", status_string));
	}
}

void sPcapStatData::sIo::rrd() const {
	if(!active) return;
	rrd_set_value(RRD_VALUE_io_latency, metrics.write_latency_ms);
	rrd_set_value(RRD_VALUE_io_qdepth, metrics.queue_depth);
	rrd_set_value(RRD_VALUE_io_util, metrics.utilization_pct);
	rrd_set_value(RRD_VALUE_io_capacity, metrics.capacity_pct);
	rrd_set_value(RRD_VALUE_io_write_throughput, metrics.write_throughput_mbs);
	rrd_set_value(RRD_VALUE_io_read_throughput, metrics.read_throughput_mbs);
	rrd_set_value(RRD_VALUE_io_write_iops, metrics.write_iops);
	rrd_set_value(RRD_VALUE_io_read_iops, metrics.read_iops);
}

void sPcapStatData::sCacheDirQ::load() {
	extern unsigned long long cachedirtransfered;
	extern Calltable *calltable;
	u_int64_t now_ms = getTimeMS();
	if(load_state.cache_dir_q.old_time_ms && now_ms > load_state.cache_dir_q.old_time_ms) {
		mBps = (double)(cachedirtransfered - load_state.cache_dir_q.last_transfered) / 1024.0 / 1024.0 / ((double)(now_ms - load_state.cache_dir_q.old_time_ms) / 1000);
	}
	files_queue = calltable->files_queue.size();
	valid = true;
	load_state.cache_dir_q.last_transfered = cachedirtransfered;
	load_state.cache_dir_q.old_time_ms = now_ms;
}

string sPcapStatData::sCacheDirQ::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += intToString(files_queue) + "/" + floatToString(mBps) + " MB/s";
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sCacheDirQ::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("files_queue", intToString(files_queue)));
	out.push_back(sValue("mBps", floatToString(mBps), "MB/s"));
}

void sPcapStatData::sTarQueue::load() {
	extern volatile unsigned int glob_tar_queued_files;
	count = glob_tar_queued_files;
	valid = true;
}

string sPcapStatData::sTarQueue::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += intToString(count);
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sTarQueue::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("count", intToString(count)));
}

void sPcapStatData::sTarCopyQueue::load() {
	extern TarCopy *tarCopy;
	if(!tarCopy) return;
	length = tarCopy->queueLength();
	valid = true;
}

string sPcapStatData::sTarCopyQueue::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += intToString(length);
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sTarCopyQueue::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("length", intToString(length)));
}

void sPcapStatData::sTarChunkBuffer::load() {
	u_int64_t tarBufferSize = ChunkBuffer::getChunkBuffersSumcapacity();
	if(tarBufferSize > 0) {
		mb = tarBufferSize / 1024 / 1024.;
		valid = true;
	}
}

string sPcapStatData::sTarChunkBuffer::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += floatToString(mb, (unsigned)1) + "MB";
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sTarChunkBuffer::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("mb", floatToString(mb, (unsigned)1), "MB"));
}

void sPcapStatData::sFileBuffer::load() {
	u_int64_t fileBufferSize = FileZipHandler::getBuffersSumcapacity();
	if(fileBufferSize) {
		mb = fileBufferSize / 1024 / 1024.;
		valid = true;
	}
}

string sPcapStatData::sFileBuffer::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += floatToString(mb, (unsigned)1) + "MB";
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sFileBuffer::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("mb", floatToString(mb, (unsigned)1), "MB"));
}

void sPcapStatData::sTarCPU::load(int pstatDataIndex) {
	extern TarQueue *tarQueue[2];
	for(int i = 0; i < 2; i++) {
		if(!tarQueue[i]) continue;
		for(int j = 0; j < tarQueue[i]->maxthreads; j++) {
			double tar_cpu = tarQueue[i]->getCpuUsagePerc(j, pstatDataIndex);
			if(tar_cpu > 0) {
				if(i == 0) {
					cpu_spool1.push_back(tar_cpu);
				} else {
					cpu_spool2.push_back(tar_cpu);
				}
			}
		}
	}
}

string sPcapStatData::sTarCPU::render(bool with_title) const {
	string out;
	bool any = false;
	if(cpu_spool1.size() > 0) {
		if(with_title) out += "tarCPU[";
		bool first = true;
		for(size_t i = 0; i < cpu_spool1.size(); i++) {
			if(cpu_spool1.isSet(i)) {
				if(!first) {
					out += "|";
				}
				out += floatToString(cpu_spool1[i], (unsigned)1);
				first = false;
			}
		}
		if(with_title) {
			out += "%] ";
		} else {
			out += "%";
		}
		any = true;
	}
	if(cpu_spool2.size() > 0) {
		if(with_title) {
			out += "tarCPU-spool2[";
		} else if(any) {
			out += ";";
		}
		bool first = true;
		for(size_t i = 0; i < cpu_spool2.size(); i++) {
			if(cpu_spool2.isSet(i)) {
				if(!first) {
					out += "|";
				}
				out += floatToString(cpu_spool2[i], (unsigned)1);
				first = false;
			}
		}
		if(with_title) {
			out += "%] ";
		} else {
			out += "%";
		}
		any = true;
	}
	return(any ? out : string(""));
}

void sPcapStatData::sTarCPU::get_sections(vector<sValue> &out) const {
	if(cpu_spool1.size() > 0) {
		string v;
		bool first = true;
		for(size_t i = 0; i < cpu_spool1.size(); i++) {
			if(cpu_spool1.isSet(i)) {
				if(!first) {
					v += "|";
				}
				v += floatToString(cpu_spool1[i], (unsigned)1);
				first = false;
			}
		}
		out.push_back(sValue("tarCPU", v + "%"));
	}
	if(cpu_spool2.size() > 0) {
		string v;
		bool first = true;
		for(size_t i = 0; i < cpu_spool2.size(); i++) {
			if(cpu_spool2.isSet(i)) {
				if(!first) {
					v += "|";
				}
				v += floatToString(cpu_spool2[i], (unsigned)1);
				first = false;
			}
		}
		out.push_back(sValue("tarCPU-spool2", v + "%"));
	}
}

void sPcapStatData::sTarCPU::get_values(vector<sValue> &out) const {
	for(size_t i = 0; i < cpu_spool1.size(); i++) {
		if(cpu_spool1.isSet(i)) {
			out.push_back(sValue("cpu_spool1_" + intToString(i), floatToString(cpu_spool1[i], (unsigned)1), "%"));
		}
	}
	for(size_t i = 0; i < cpu_spool2.size(); i++) {
		if(cpu_spool2.isSet(i)) {
			out.push_back(sValue("cpu_spool2_" + intToString(i), floatToString(cpu_spool2[i], (unsigned)1), "%"));
		}
	}
}

void sPcapStatData::sTarCPU::rrd() const {
	for(size_t i = 0; i < cpu_spool1.size(); i++) {
		rrd_add_value(RRD_VALUE_tarCPU, cpu_spool1[i]);
	}
	for(size_t i = 0; i < cpu_spool2.size(); i++) {
		rrd_add_value(RRD_VALUE_tarCPU, cpu_spool2[i]);
	}
}

string sPcapStatData::sReadThreads::sReadThread::title() const {
	return(string("t0i_") + string(interface_alias) + "_CPU");
}

string sPcapStatData::sReadThreads::sReadThread::render(bool with_title) const {
	string out;
	if(with_title) out += title() + "[";
	out += floatToString(mbps, (unsigned)1) + "Mb/s";
	if(cpu_main_valid) {
		out += ";main:" + floatToString(cpu_main, (unsigned)1);
	}
	if(aloc_stack || alloc_alloc) {
		out += "%%a" + intToString(aloc_stack) + ":" + intToString(alloc_alloc) + ":";
		if(aloc_stack + alloc_alloc) {
			out += intToString(aloc_stack * 100 / (aloc_stack + alloc_alloc));
		} else {
			out += "-";
		}
	}
	if(cpu_dpdk_worker_valid) {
		out += "%/dpdk_worker:" + floatToString(cpu_dpdk_worker, (unsigned)1);
	}
	for(size_t i = 0; i < cpu_dpdk_rte_read.size(); i++) {
		if(cpu_dpdk_rte_read.isSet(i)) {
			out += "%/dpdk_rte_read:" + floatToString(cpu_dpdk_rte_read[i], (unsigned)1);
		}
	}
	if(cpu_dpdk_rte_worker_valid) {
		out += "%/dpdk_rte_worker:" + floatToString(cpu_dpdk_rte_worker, (unsigned)1);
		if(cpu_dpdk_rte_worker_slave_valid) {
			out += "/" + floatToString(cpu_dpdk_rte_worker_slave, (unsigned)1);
		}
	}
	if(cpu_dpdk_rte_worker2_valid) {
		out += "%/dpdk_rte_worker2:" + floatToString(cpu_dpdk_rte_worker2, (unsigned)1);
	}
	if(cpu_detach_valid) {
		out += "%/detach:" + floatToString(cpu_detach, (unsigned)1);
		if(detach_aloc_stack || detach_alloc_alloc) {
			out += "%%a" + intToString(detach_aloc_stack) + ":" + intToString(detach_alloc_alloc) + ":";
			if(detach_aloc_stack + detach_alloc_alloc) {
				out += intToString(detach_aloc_stack * 100 / (detach_aloc_stack + detach_alloc_alloc));
			} else {
				out += "-";
			}
		}
	}
	if(cpu_pcap_process_valid) {
		out += "%/pcap_process:" + floatToString(cpu_pcap_process, (unsigned)1);
	}
	if(cpu_defrag_valid) {
		out += "%/defrag:" + floatToString(cpu_defrag, (unsigned)1);
	}
	if(cpu_md1_valid) {
		out += "%/md1:" + floatToString(cpu_md1, (unsigned)1);
	}
	if(cpu_md2_valid) {
		out += "%/md2:" + floatToString(cpu_md2, (unsigned)1);
	}
	if(cpu_dedup_valid) {
		out += "%/dedup:" + floatToString(cpu_dedup, (unsigned)1);
	}
	if(cpu_service_valid) {
		out += "%/service:" + floatToString(cpu_service, (unsigned)1);
	}
	if(with_title) {
		out += "%] ";
	} else {
		out += "%";
	}
	return(out);
}

void sPcapStatData::sReadThreads::sReadThread::get_values(vector<sValue> &out) const {
	out.push_back(sValue("mbps", floatToString(mbps, (unsigned)1), "Mb/s"));
	if(cpu_main_valid) out.push_back(sValue("cpu_main", floatToString(cpu_main, (unsigned)1), "%"));
	if(aloc_stack || alloc_alloc) {
		out.push_back(sValue("aloc_stack", intToString(aloc_stack)));
		out.push_back(sValue("alloc_alloc", intToString(alloc_alloc)));
	}
	if(cpu_dpdk_worker_valid) out.push_back(sValue("cpu_dpdk_worker", floatToString(cpu_dpdk_worker, (unsigned)1), "%"));
	for(size_t i = 0; i < cpu_dpdk_rte_read.size(); i++) {
		if(cpu_dpdk_rte_read.isSet(i)) {
			out.push_back(sValue("cpu_dpdk_rte_read_" + intToString(i), floatToString(cpu_dpdk_rte_read[i], (unsigned)1), "%"));
		}
	}
	if(cpu_dpdk_rte_worker_valid) out.push_back(sValue("cpu_dpdk_rte_worker", floatToString(cpu_dpdk_rte_worker, (unsigned)1), "%"));
	if(cpu_dpdk_rte_worker_slave_valid) out.push_back(sValue("cpu_dpdk_rte_worker_slave", floatToString(cpu_dpdk_rte_worker_slave, (unsigned)1), "%"));
	if(cpu_dpdk_rte_worker2_valid) out.push_back(sValue("cpu_dpdk_rte_worker2", floatToString(cpu_dpdk_rte_worker2, (unsigned)1), "%"));
	if(cpu_detach_valid) out.push_back(sValue("cpu_detach", floatToString(cpu_detach, (unsigned)1), "%"));
	if(detach_aloc_stack || detach_alloc_alloc) {
		out.push_back(sValue("detach_aloc_stack", intToString(detach_aloc_stack)));
		out.push_back(sValue("detach_alloc_alloc", intToString(detach_alloc_alloc)));
	}
	if(cpu_pcap_process_valid) out.push_back(sValue("cpu_pcap_process", floatToString(cpu_pcap_process, (unsigned)1), "%"));
	if(cpu_defrag_valid) out.push_back(sValue("cpu_defrag", floatToString(cpu_defrag, (unsigned)1), "%"));
	if(cpu_md1_valid) out.push_back(sValue("cpu_md1", floatToString(cpu_md1, (unsigned)1), "%"));
	if(cpu_md2_valid) out.push_back(sValue("cpu_md2", floatToString(cpu_md2, (unsigned)1), "%"));
	if(cpu_dedup_valid) out.push_back(sValue("cpu_dedup", floatToString(cpu_dedup, (unsigned)1), "%"));
	if(cpu_service_valid) out.push_back(sValue("cpu_service", floatToString(cpu_service, (unsigned)1), "%"));
}

void sPcapStatData::sReadThreads::load(PcapQueue *instance, int pstatDataIndex) {
	if(!instance) return;
	u_int64_t now_ms = getTimeMS();
	u_int64_t divide_ms = load_state.read_threads.old_time_ms && now_ms > load_state.read_threads.old_time_ms ? now_ms - load_state.read_threads.old_time_ms : 1000ULL;
	instance->pcapStatString_cpuUsageReadThreads(&sum_max, &count_threads_sum_max, divide_ms, pstatDataIndex, &threads);
	load_state.read_threads.old_time_ms = now_ms;
}

string sPcapStatData::sReadThreads::render(bool with_title) const {
	string out;
	for(size_t i = 0; i < threads.size(); i++) {
		if(threads.isSet(i)) {
			appendSection(out, threads[i].render(with_title));
		}
	}
	return(out);
}

void sPcapStatData::sReadThreads::get_sections(vector<sValue> &out) const {
	for(size_t i = 0; i < threads.size(); i++) {
		if(threads.isSet(i)) {
			threads[i].get_sections(out);
		}
	}
}

void sPcapStatData::sReadThreads::get_values(vector<sValue> &out) const {
	for(size_t i = 0; i < threads.size(); i++) {
		if(threads.isSet(i)) {
			sValue iface(string(threads[i].interface_alias), "");
			threads[i].get_values(iface.childs);
			out.push_back(iface);
		}
	}
}

string sPcapStatData::sT0::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += floatToString(cpu_capture, (unsigned)1);
	if(cpu_write_valid) {
		out += "/" + floatToString(cpu_write, (unsigned)1);
	}
	for(size_t i = 0; i < cpu_next.size(); i++) {
		if(cpu_next.isSet(i)) {
			out += "/" + floatToString(cpu_next[i], (unsigned)1);
		}
	}
	out += with_title ? "%] " : "%";
	return(out);
}

void sPcapStatData::sT0::rrd() const {
	if(!valid) return;
	rrd_set_value(RRD_VALUE_tCPU_t0, cpu_capture);
}

void sPcapStatData::sT0::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("cpu_capture", floatToString(cpu_capture, (unsigned)1), "%"));
	if(cpu_write_valid) out.push_back(sValue("cpu_write", floatToString(cpu_write, (unsigned)1), "%"));
	for(size_t i = 0; i < cpu_next.size(); i++) {
		if(cpu_next.isSet(i)) {
			out.push_back(sValue("cpu_next_" + intToString(i), floatToString(cpu_next[i], (unsigned)1), "%"));
		}
	}
}

string sPcapStatData::sT1::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	if(!cpu_string.empty()) {
		if(with_title) {
			return(string(cpu_string) + " ");
		}
		string s = cpu_string;
		size_t b1 = s.find('[');
		size_t b2 = s.rfind(']');
		if(b1 != string::npos && b2 != string::npos && b1 < b2) {
			return(s.substr(b1 + 1, b2 - b1 - 1));
		}
		return(s);
	}
	string out;
	if(with_title) out += title() + "[";
	out += floatToString(cpu_perc, (unsigned)1) + "%";
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sT1::rrd() const {
	if(!valid) return;
	if(cpu_string.empty()) {
		rrd_set_value(RRD_VALUE_tCPU_t1, cpu_perc);
	}
}

void sPcapStatData::sT1::get_values(vector<sValue> &out) const {
	if(!valid) return;
	if(!cpu_string.empty()) {
		out.push_back(sValue("cpu_string", cpu_string));
	} else {
		out.push_back(sValue("cpu_perc", floatToString(cpu_perc, (unsigned)1), "%"));
	}
}

string sPcapStatData::sT2::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	if(cpu_mirror_valid) {
		out += floatToString(cpu_mirror, (unsigned)1);
	} else if(cpu_pb_valid) {
		out += "pb:" + floatToString(cpu_pb, (unsigned)1);
		if(cpu_detach_valid) {
			out += "/detach:" + floatToString(cpu_detach, (unsigned)1);
			for(size_t i = 0; i < cpu_detach_next.size(); i++) {
				if(cpu_detach_next.isSet(i)) {
					out += "|" + floatToString(cpu_detach_next[i], (unsigned)1);
				}
			}
		}
		if(cpu_defrag_valid) {
			out += "/defrag:" + floatToString(cpu_defrag, (unsigned)1);
			for(size_t i = 0; i < cpu_defrag_next.size(); i++) {
				if(cpu_defrag_next.isSet(i)) {
					out += "|" + floatToString(cpu_defrag_next[i], (unsigned)1);
				}
			}
		}
		if(cpu_dedup_valid) {
			out += "/dedup:" + floatToString(cpu_dedup, (unsigned)1);
		}
		if(cpu_detach2_valid) {
			out += "/detach2:" + floatToString(cpu_detach2, (unsigned)1);
			for(size_t i = 0; i < cpu_detach2_next.size(); i++) {
				if(cpu_detach2_next.isSet(i)) {
					out += "|" + floatToString(cpu_detach2_next[i], (unsigned)1);
				}
			}
		}
		if(cpu_ipacc_valid) {
			out += "/ipacc:" + floatToString(cpu_ipacc, (unsigned)1);
		}
		for(size_t i = 0; i < preproc.size(); i++) {
			if(!preproc.isSet(i)) {
				continue;
			}
			const sPreproc &p = preproc[i];
			out += "/" + string(p.name) + ":" + floatToString(p.cpu, (unsigned)1);
			if(p.aloc_stack || p.alloc_alloc) {
				out += "a" + intToString(p.aloc_stack) + ":" + intToString(p.alloc_alloc) + ":";
				if(p.aloc_stack + p.alloc_alloc) {
					out += intToString(p.aloc_stack * 100 / (p.aloc_stack + p.alloc_alloc)) + "%";
				} else {
					out += "-";
				}
			}
			for(size_t j = 0; j < p.cpu_next.size(); j++) {
				if(p.cpu_next.isSet(j)) {
					out += "|" + floatToString(p.cpu_next[j], (unsigned)1);
				}
			}
		}
		if(cpu_rtp_rh_main_valid) {
			out += "/rh:" + floatToString(cpu_rtp_rh_main, (unsigned)1);
			for(size_t i = 0; i < cpu_rtp_rh_next.size(); i++) {
				if(cpu_rtp_rh_next.isSet(i)) {
					out += "|" + floatToString(cpu_rtp_rh_next[i], (unsigned)1);
				}
			}
		}
		if(cpu_rtp_rd.size() > 0) {
			bool first = true;
			for(size_t i = 0; i < cpu_rtp_rd.size(); i++) {
				if(cpu_rtp_rd.isSet(i)) {
					if(first) {
						out += "/rd:" + floatToString(cpu_rtp_rd[i], (unsigned)1);
						first = false;
					} else {
						out += "|" + floatToString(cpu_rtp_rd[i], (unsigned)1);
					}
				}
			}
		}
		if(threads_count > 1) {
			out += "/S:" + floatToString(cpu_sum, (unsigned)1);
		}
	}
	if(with_title) {
		out += "%] ";
	} else {
		out += "%";
	}
	return(out);
}

void sPcapStatData::sT2::rrd() const {
	if(!valid) return;
	rrd_set_value(RRD_VALUE_tCPU_t2, cpu_sum);
}

void sPcapStatData::sT2::get_values(vector<sValue> &out) const {
	if(!valid) return;
	if(cpu_mirror_valid) {
		out.push_back(sValue("cpu_mirror", floatToString(cpu_mirror, (unsigned)1), "%"));
	} else if(cpu_pb_valid) {
		out.push_back(sValue("cpu_pb", floatToString(cpu_pb, (unsigned)1), "%"));
		if(cpu_detach_valid) {
			out.push_back(sValue("cpu_detach", floatToString(cpu_detach, (unsigned)1), "%"));
			for(size_t i = 0; i < cpu_detach_next.size(); i++) {
				if(cpu_detach_next.isSet(i)) {
					out.push_back(sValue("cpu_detach_next_" + intToString(i), floatToString(cpu_detach_next[i], (unsigned)1), "%"));
				}
			}
		}
		if(cpu_defrag_valid) {
			out.push_back(sValue("cpu_defrag", floatToString(cpu_defrag, (unsigned)1), "%"));
			for(size_t i = 0; i < cpu_defrag_next.size(); i++) {
				if(cpu_defrag_next.isSet(i)) {
					out.push_back(sValue("cpu_defrag_next_" + intToString(i), floatToString(cpu_defrag_next[i], (unsigned)1), "%"));
				}
			}
		}
		if(cpu_dedup_valid) {
			out.push_back(sValue("cpu_dedup", floatToString(cpu_dedup, (unsigned)1), "%"));
		}
		if(cpu_detach2_valid) {
			out.push_back(sValue("cpu_detach2", floatToString(cpu_detach2, (unsigned)1), "%"));
			for(size_t i = 0; i < cpu_detach2_next.size(); i++) {
				if(cpu_detach2_next.isSet(i)) {
					out.push_back(sValue("cpu_detach2_next_" + intToString(i), floatToString(cpu_detach2_next[i], (unsigned)1), "%"));
				}
			}
		}
		if(cpu_ipacc_valid) {
			out.push_back(sValue("cpu_ipacc", floatToString(cpu_ipacc, (unsigned)1), "%"));
		}
		for(size_t i = 0; i < preproc.size(); i++) {
			if(!preproc.isSet(i)) continue;
			const sPreproc &p = preproc[i];
			string pname = p.name;
			out.push_back(sValue("cpu_" + pname, floatToString(p.cpu, (unsigned)1), "%"));
			if(p.aloc_stack || p.alloc_alloc) {
				out.push_back(sValue(pname + "_aloc_stack", intToString(p.aloc_stack)));
				out.push_back(sValue(pname + "_alloc_alloc", intToString(p.alloc_alloc)));
			}
			for(size_t j = 0; j < p.cpu_next.size(); j++) {
				if(p.cpu_next.isSet(j)) {
					out.push_back(sValue("cpu_" + pname + "_next_" + intToString(j), floatToString(p.cpu_next[j], (unsigned)1), "%"));
				}
			}
		}
		if(cpu_rtp_rh_main_valid) {
			out.push_back(sValue("cpu_rtp_rh_main", floatToString(cpu_rtp_rh_main, (unsigned)1), "%"));
			for(size_t i = 0; i < cpu_rtp_rh_next.size(); i++) {
				if(cpu_rtp_rh_next.isSet(i)) {
					out.push_back(sValue("cpu_rtp_rh_next_" + intToString(i), floatToString(cpu_rtp_rh_next[i], (unsigned)1), "%"));
				}
			}
		}
		for(size_t i = 0; i < cpu_rtp_rd.size(); i++) {
			if(cpu_rtp_rd.isSet(i)) {
				out.push_back(sValue("cpu_rtp_rd_" + intToString(i), floatToString(cpu_rtp_rd[i], (unsigned)1), "%"));
			}
		}
		if(threads_count > 1) {
			out.push_back(sValue("cpu_sum", floatToString(cpu_sum, (unsigned)1), "%"));
		}
	}
}

string sPcapStatData::sRTP::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += floatToString(cpu_sum, (unsigned)1) + "%/";
	if(!extend.empty()) {
		out += string(extend) + "/";
	} else {
		out += floatToString(cpu_max, (unsigned)1) + "m/";
	}
	out += intToString(threads_active) + "t";
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sRTP::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("cpu_sum", floatToString(cpu_sum, (unsigned)1), "%"));
	out.push_back(sValue("cpu_max", floatToString(cpu_max, (unsigned)1), "%"));
	out.push_back(sValue("cpu_min", floatToString(cpu_min, (unsigned)1), "%"));
	if(!extend.empty()) {
		out.push_back(sValue("extend", extend));
	}
	out.push_back(sValue("threads_active", intToString(threads_active)));
}

void sPcapStatData::sHttp::load(int pstatDataIndex) {
	extern TcpReassembly *tcpReassemblyHttp;
	if(!tcpReassemblyHttp) return;
	string cpuUsagePerc = tcpReassemblyHttp->getCpuUsagePerc(pstatDataIndex);
	if(!cpuUsagePerc.empty()) {
		cpu_perc = cpuUsagePerc;
		valid = true;
	}
}

string sPcapStatData::sHttp::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	return(with_title ? title() + "[" + string(cpu_perc) + "] " : string(cpu_perc));
}

void sPcapStatData::sHttp::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("cpu_perc", cpu_perc, "%"));
}

void sPcapStatData::sWebrtc::load(int pstatDataIndex) {
	extern TcpReassembly *tcpReassemblyWebrtc;
	if(!tcpReassemblyWebrtc) return;
	string cpuUsagePerc = tcpReassemblyWebrtc->getCpuUsagePerc(pstatDataIndex);
	if(!cpuUsagePerc.empty()) {
		cpu_perc = cpuUsagePerc;
		valid = true;
	}
}

string sPcapStatData::sWebrtc::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	return(with_title ? title() + "[" + string(cpu_perc) + "] " : string(cpu_perc));
}

void sPcapStatData::sWebrtc::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("cpu_perc", cpu_perc, "%"));
}

void sPcapStatData::sSsl::load(int pstatDataIndex) {
	extern TcpReassembly *tcpReassemblySsl;
	if(!tcpReassemblySsl) return;
	string cpuUsagePerc = tcpReassemblySsl->getCpuUsagePerc(pstatDataIndex);
	if(!cpuUsagePerc.empty()) {
		cpu_perc = cpuUsagePerc;
		valid = true;
	}
}

string sPcapStatData::sSsl::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	return(with_title ? title() + "[" + string(cpu_perc) + "] " : string(cpu_perc));
}

void sPcapStatData::sSsl::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("cpu_perc", cpu_perc, "%"));
}

void sPcapStatData::sSslWs::load() {
	extern bool getSslStat(unsigned *calls, unsigned *sessions_size);
	unsigned c, s;
	if(getSslStat(&c, &s)) {
		calls = c;
		sessions_size = s;
		valid = true;
	}
}

string sPcapStatData::sSslWs::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += intToString(calls) + "|" + intToString(sessions_size);
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sSslWs::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("calls", intToString(calls)));
	out.push_back(sValue("sessions_size", intToString(sessions_size)));
}

void sPcapStatData::sDtls::load() {
	extern link_packets_queue dtls_queue;
	u_int32_t links = dtls_queue.countLinks();
	u_int32_t packets = dtls_queue.countPackets();
	if(links > 0 || packets > 0) {
		queue_links = links;
		queue_packets = packets;
		valid = true;
	}
}

string sPcapStatData::sDtls::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += "l:" + intToString(queue_links) + "/p:" + intToString(queue_packets);
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sDtls::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("queue_links", intToString(queue_links)));
	out.push_back(sValue("queue_packets", intToString(queue_packets)));
}

void sPcapStatData::sSipTcp::load(int pstatDataIndex) {
	extern TcpReassembly *tcpReassemblySipExt;
	if(!tcpReassemblySipExt) return;
	string cpuUsagePerc = tcpReassemblySipExt->getCpuUsagePerc(pstatDataIndex);
	if(!cpuUsagePerc.empty()) {
		cpu_perc = cpuUsagePerc;
		valid = true;
	}
}

string sPcapStatData::sSipTcp::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	return(with_title ? title() + "[" + string(cpu_perc) + "] " : string(cpu_perc));
}

void sPcapStatData::sSipTcp::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("cpu_perc", cpu_perc, "%"));
}

void sPcapStatData::sIpfix::load() {
	extern cIpFixCounter ipfix_counter;
	string rslt = ipfix_counter.get_ip_counter();
	if(!rslt.empty()) {
		ipfix_counter.reset();
		value = rslt;
	}
}

string sPcapStatData::sIpfix::render(bool with_title) const {
	if(value.empty()) {
		return("");
	}
	if(with_title) {
		return(title() + "[" + string(value) + "]");
	}
	return(value);
}

void sPcapStatData::sIpfix::get_values(vector<sValue> &out) const {
	if(value.empty()) return;
	out.push_back(sValue("value", value));
}

void sPcapStatData::sHep::load() {
	extern cHepCounter hep_counter;
	string rslt = hep_counter.get_ip_counter();
	if(!rslt.empty()) {
		hep_counter.reset();
		value = rslt;
	}
}

string sPcapStatData::sHep::render(bool with_title) const {
	if(value.empty()) {
		return("");
	}
	if(with_title) {
		return(title() + "[" + string(value) + "]");
	}
	return(value);
}

void sPcapStatData::sHep::get_values(vector<sValue> &out) const {
	if(value.empty()) return;
	out.push_back(sValue("value", value));
}

void sPcapStatData::sRibbonsbc::load() {
	extern cRibbonSbcCounter ribbonsbc_counter;
	string rslt = ribbonsbc_counter.get_ip_counter();
	if(!rslt.empty()) {
		ribbonsbc_counter.reset();
		value = rslt;
	}
}

string sPcapStatData::sRibbonsbc::render(bool with_title) const {
	if(value.empty()) {
		return("");
	}
	if(with_title) {
		return(title() + "[" + string(value) + "]");
	}
	return(value);
}

void sPcapStatData::sRibbonsbc::get_values(vector<sValue> &out) const {
	if(value.empty()) return;
	out.push_back(sValue("value", value));
}

void sPcapStatData::sAsyncCloseCPU::load(int pstatDataIndex) {
	extern AsyncClose *asyncClose;
	if(!asyncClose) return;
	for(int i = 0; i < asyncClose->getCountThreads(); i++) {
		double tac_cpu = asyncClose->getCpuUsagePerc(i, pstatDataIndex);
		if(tac_cpu >= 0) {
			cpu_perc.push_back(tac_cpu);
			valid = true;
		}
	}
}

string sPcapStatData::sAsyncCloseCPU::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	bool first = true;
	for(size_t i = 0; i < cpu_perc.size(); i++) {
		if(cpu_perc.isSet(i)) {
			if(!first) {
				out += "|";
			}
			out += floatToString(cpu_perc[i], (unsigned)1);
			first = false;
		}
	}
	out += with_title ? "%] " : "%";
	return(out);
}

void sPcapStatData::sAsyncCloseCPU::get_values(vector<sValue> &out) const {
	if(!valid) return;
	for(size_t i = 0; i < cpu_perc.size(); i++) {
		if(cpu_perc.isSet(i)) {
			out.push_back(sValue("cpu_perc_" + intToString(i), floatToString(cpu_perc[i], (unsigned)1), "%"));
		}
	}
}

void sPcapStatData::sAsyncCloseCPU::rrd() const {
	if(!valid) return;
	for(size_t i = 0; i < cpu_perc.size(); i++) {
		rrd_add_value(RRD_VALUE_zipCPU, cpu_perc[i]);
	}
}

void sPcapStatData::sAsyncCloseQueue::load() {
	extern AsyncClose *asyncClose;
	if(!asyncClose) return;
	vector<unsigned> queue_size;
	asyncClose->getQueueSize(&queue_size, true);
	if(queue_size.size()) {
		queue = queue_size;
		valid = true;
	}
}

string sPcapStatData::sAsyncCloseQueue::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	bool first = true;
	for(size_t i = 0; i < queue.size(); i++) {
		if(queue.isSet(i)) {
			if(!first) {
				out += "|";
			}
			out += intToString(queue[i]);
			first = false;
		}
	}
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sAsyncCloseQueue::get_values(vector<sValue> &out) const {
	if(!valid) return;
	for(size_t i = 0; i < queue.size(); i++) {
		if(queue.isSet(i)) {
			out.push_back(sValue("queue_" + intToString(i), intToString(queue[i])));
		}
	}
}

void sPcapStatData::sStoring::load(int pstatDataIndex) {
	extern void storing_cdr_getCpuUsagePerc(vector<double> *cpu_perc, int pstatDataIndex);
	vector<double> cpu;
	storing_cdr_getCpuUsagePerc(&cpu, pstatDataIndex);
	if(!cpu.empty()) {
		for(size_t i = 0; i < cpu.size(); i++) {
			cpu_perc.push_back(cpu[i]);
		}
		valid = true;
	}
}

string sPcapStatData::sStoring::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	bool first = true;
	for(size_t i = 0; i < cpu_perc.size(); i++) {
		if(cpu_perc.isSet(i)) {
			if(!first) out += "/";
			out += floatToString(cpu_perc[i], (unsigned)1);
			first = false;
		}
	}
	out += "%";
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sStoring::get_values(vector<sValue> &out) const {
	if(!valid) return;
	for(size_t i = 0; i < cpu_perc.size(); i++) {
		if(cpu_perc.isSet(i)) {
			out.push_back(sValue("cpu_" + intToString(i), floatToString(cpu_perc[i], (unsigned)1), "%"));
		}
	}
}

void sPcapStatData::sCharts::load(int pstatDataIndex) {
	extern Calltable *calltable;
	double chc_cpu_avg;
	string chc_cpu = calltable->processCallsInChartsCache_cpuUsagePerc(&chc_cpu_avg, pstatDataIndex);
	size_t ch_q = calltable->calls_charts_cache_queue.size();
	size_t chs_q_s = getRemoteChartServerQueueSize();
	extern u_int32_t counter_charts_cache;
	extern u_int64_t counter_charts_cache_delay_us;
	if(chc_cpu.empty() && !(counter_charts_cache && counter_charts_cache_delay_us) &&
	   ch_q == 0 && chs_q_s == 0) {
		return;
	}
	valid = true;
	if(!chc_cpu.empty()) {
		cpu_perc = chc_cpu;
		cpu_valid = true;
	}
	if(counter_charts_cache && counter_charts_cache_delay_us) {
		requests = counter_charts_cache;
		delay_us = counter_charts_cache_delay_us;
		requests_valid = true;
	}
	if(ch_q > 0) {
		queue_size = ch_q;
		queue_valid = true;
	}
	if(chs_q_s > 0) {
		remote_queue_size = chs_q_s;
		remote_queue_valid = true;
	}
	counter_charts_cache = 0;
	counter_charts_cache_delay_us = 0;
}

string sPcapStatData::sCharts::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	if(cpu_valid) {
		out += string(cpu_perc) + "%";
	}
	if(requests_valid) {
		if(cpu_valid) {
			out += "/";
		}
		out += intToString(requests) + "r/" + intToString(delay_us > 0 ? requests * 1000000ull / delay_us : 0) + "ps";
	}
	if(queue_valid) {
		if(cpu_valid) {
			out += "/";
		}
		out += intToString(queue_size) + "q";
	}
	if(remote_queue_valid) {
		if(cpu_valid) {
			out += "/";
		}
		out += intToString(remote_queue_size) + "qr";
	}
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sCharts::get_values(vector<sValue> &out) const {
	if(!valid) return;
	if(cpu_valid) out.push_back(sValue("cpu_perc", cpu_perc, "%"));
	if(requests_valid) {
		out.push_back(sValue("requests", intToString(requests), "r"));
		out.push_back(sValue("requests_per_s", intToString(delay_us > 0 ? requests * 1000000ull / delay_us : 0), "ps"));
	}
	if(queue_valid) out.push_back(sValue("queue_size", intToString(queue_size), "q"));
	if(remote_queue_valid) out.push_back(sValue("remote_queue_size", intToString(remote_queue_size), "qr"));
}

void sPcapStatData::sIpacc::load() {
	string ipaccCpu = getIpaccCpuUsagePerc(0);
	if(!ipaccCpu.empty()) {
		cpu_perc = ipaccCpu;
		valid = true;
	}
}

string sPcapStatData::sIpacc::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	return(with_title ? title() + "[" + string(cpu_perc) + "] " : string(cpu_perc));
}

void sPcapStatData::sIpacc::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("cpu_perc", cpu_perc, "%"));
}

void sPcapStatData::sIpaccBuffer::load() {
	buffer_length = lengthIpaccBuffer();
	buffer_size = sizeIpaccBuffer();
	valid = true;
}

string sPcapStatData::sIpaccBuffer::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += intToString(buffer_length) + "/" + intToString(buffer_size);
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sIpaccBuffer::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("buffer_length", intToString(buffer_length)));
	out.push_back(sValue("buffer_size", intToString(buffer_size)));
}

void sPcapStatData::sRrd::load(int pstatDataIndex) {
	extern RrdCharts *rrd_charts;
	if(!rrd_charts) return;
	double rrd_charts_cpu = rrd_charts->getCpuUsageQueueThreadPerc(pstatDataIndex);
	if(rrd_charts_cpu > 0) {
		cpu_perc = rrd_charts_cpu;
		valid = true;
	}
}

string sPcapStatData::sRrd::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += floatToString(cpu_perc, (unsigned)1) + "%";
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sRrd::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("cpu_perc", floatToString(cpu_perc, (unsigned)1), "%"));
}

void sPcapStatData::sDedup::load() {
	extern u_int64_t duplicate_counter;
	extern u_int64_t duplicate_counter_collisions;
	if(duplicate_counter) {
		counter = duplicate_counter;
		valid = true;
		if(duplicate_counter_collisions) {
			collisions = duplicate_counter_collisions;
		}
	}
}

string sPcapStatData::sDedup::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += intToString(counter);
	if(collisions) {
		out += "/" + intToString(collisions);
	}
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sDedup::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("counter", intToString(counter)));
	out.push_back(sValue("collisions", intToString(collisions)));
}

void sPcapStatData::sRssVsz::load() {
	pstat_data data;
	if(!pstat_get_data(0, &data)) return;
	if(data.rss > 0) {
		rss_mb = (u_int64_t)round((double)data.rss/1024/1024);
		valid = true;
	}
	if(data.vsize > 0) {
		vsz_mb = (u_int64_t)round((double)data.vsize/1024/1024);
		valid = true;
	}
}

string sPcapStatData::sRssVsz::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	if(rss_mb > 0) {
		out += intToString(rss_mb);
	}
	if(vsz_mb > 0) {
		if(rss_mb > 0) {
			out += "|";
		}
		out += intToString(vsz_mb);
	}
	out += with_title ? "]MB " : "MB";
	return(out);
}

void sPcapStatData::sRssVsz::rrd() const {
	if(!valid) return;
	if(rss_mb > 0) {
		rrd_set_value(RRD_VALUE_RSS, (double)rss_mb);
	}
}

void sPcapStatData::sRssVsz::get_values(vector<sValue> &out) const {
	if(!valid) return;
	if(rss_mb > 0) out.push_back(sValue("rss_mb", intToString(rss_mb), "MB"));
	if(vsz_mb > 0) out.push_back(sValue("vsz_mb", intToString(vsz_mb), "MB"));
}

void sPcapStatData::sHugepages::load() {
	u_int64_t hugepages_base = HugetlbSysAllocator_base();
	if(hugepages_base) {
		base_mb = (u_int64_t)round((double)hugepages_base/1024/1024);
		valid = true;
	}
}

string sPcapStatData::sHugepages::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += intToString(base_mb);
	out += with_title ? "]MB " : "MB";
	return(out);
}

void sPcapStatData::sHugepages::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("base_mb", intToString(base_mb), "MB"));
}

void sPcapStatData::sTcmAlloc::load() {
#if HAVE_LIBTCMALLOC
	const char *tcm_status_types[] = {
		"generic.heap_size",
		"generic.current_allocated_bytes",
		"tcmalloc.pageheap_free_bytes",
		"tcmalloc.pageheap_unmapped_bytes",
		"tcmalloc.current_total_thread_cache_bytes"
	};
	u_int64_t tcm_mb[5] = {0, 0, 0, 0, 0};
	for(unsigned i = 0; i < sizeof(tcm_status_types)/sizeof(tcm_status_types[0]); i++) {
		size_t tcm_bytes = 0;
		MallocExtension::instance()->GetNumericProperty(tcm_status_types[i], &tcm_bytes);
		tcm_mb[i] = (u_int64_t)round((double)tcm_bytes/1024/1024);
		if(tcm_mb[i] > 0) {
			valid = true;
		}
	}
	heap = tcm_mb[0];
	alloc = tcm_mb[1];
	free = tcm_mb[2];
	unmapped = tcm_mb[3];
	thread_cache = tcm_mb[4];
#endif
}

string sPcapStatData::sTcmAlloc::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	bool first = true;
	if(heap > 0) {
		out += "h:" + intToString(heap);
		first = false;
	}
	if(alloc > 0) {
		if(!first) {
			out += "/";
		}
		out += "a:" + intToString(alloc);
		first = false;
	}
	if(free > 0) {
		if(!first) {
			out += "/";
		}
		out += "f:" + intToString(free);
		first = false;
	}
	if(unmapped > 0) {
		if(!first) {
			out += "/";
		}
		out += "u:" + intToString(unmapped);
		first = false;
	}
	if(thread_cache > 0) {
		if(!first) {
			out += "/";
		}
		out += "tc:" + intToString(thread_cache);
		first = false;
	}
	if(with_title) {
		out += "]MB ";
	} else {
		out += "MB";
	}
	return(out);
}

void sPcapStatData::sTcmAlloc::get_values(vector<sValue> &out) const {
	if(!valid) return;
	if(heap > 0) out.push_back(sValue("heap", intToString(heap), "MB"));
	if(alloc > 0) out.push_back(sValue("alloc", intToString(alloc), "MB"));
	if(free > 0) out.push_back(sValue("free", intToString(free), "MB"));
	if(unmapped > 0) out.push_back(sValue("unmapped", intToString(unmapped), "MB"));
	if(thread_cache > 0) out.push_back(sValue("thread_cache", intToString(thread_cache), "MB"));
}

void sPcapStatData::sHeapHugepage::load() {
#if SEPARATE_HEAP_FOR_HUGETABLE
	extern cHeap *heap_vm_hp;
	if(heap_vm_hp) {
		u_int64_t hugepages_vm_heap_size = heap_vm_hp->getSumSize();
		if(hugepages_vm_heap_size) {
			mb = (u_int64_t)round((double)hugepages_vm_heap_size/(1024*1024));
			valid = true;
		}
	}
#endif
}

string sPcapStatData::sHeapHugepage::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += intToString(mb);
	out += with_title ? "]MB " : "MB";
	return(out);
}

void sPcapStatData::sHeapHugepage::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("mb", intToString(mb), "MB"));
}

#if SEPARATE_HEAP_FOR_HASHTABLE
extern cHeap *heap_hashtable;
#endif

void sPcapStatData::sHeapHashtable::load() {
#if SEPARATE_HEAP_FOR_HASHTABLE
	if(::heap_hashtable) {
		u_int64_t hashtable_heap_size = ::heap_hashtable->getSumSize();
		u_int64_t hashtable_alloc_size = ::heap_hashtable->getAllocSize();
		alloc_mb = (u_int64_t)round((double)hashtable_alloc_size/(1024*1024));
		size_mb = (u_int64_t)round((double)hashtable_heap_size/(1024*1024));
		valid = true;
	}
#endif
}

string sPcapStatData::sHeapHashtable::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) out += title() + "[";
	out += intToString(alloc_mb) + "/" + intToString(size_mb);
	out += with_title ? "]MB " : "MB";
	return(out);
}

void sPcapStatData::sHeapHashtable::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("alloc_mb", intToString(alloc_mb), "MB"));
	out.push_back(sValue("size_mb", intToString(size_mb), "MB"));
}

void sPcapStatData::sLoadAvg::load() {
	double la_arr[3] = {0, 0, 0};
	getLoadAvg(&la_arr[0], &la_arr[1], &la_arr[2]);
	int vm_cpu_count = get_cpu_count();
	bool vm_cpu_ht = get_cpu_ht();
	bool overload = false;
	for(int i = 0; i < 3; i++) {
		if(la_arr[i] > ((double)vm_cpu_count * (vm_cpu_ht ? 3./4 : 1))) {
			overload = true;
		}
	}
	la1 = la_arr[0];
	la5 = la_arr[1];
	la15 = la_arr[2];
	uptime_hours = (u_int64_t)getUptime() / 3600;
	cpu_count = vm_cpu_count;
	cpu_ht = vm_cpu_ht;
	overload_indicator = overload;
	valid = true;
}

string sPcapStatData::sLoadAvg::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string body = floatToString(la1, (unsigned)2) + " " +
		      floatToString(la5, (unsigned)2) + " " +
		      floatToString(la15, (unsigned)2) + "|" +
		      intToString(cpu_count) + (cpu_ht ? "h" : "");
	if(with_title) {
		return((overload_indicator ? string("*") : "") + title() + "[" + body + "] ");
	}
	return(body);
}

void sPcapStatData::sLoadAvg::rrd() const {
	if(!valid) return;
	rrd_set_value(RRD_VALUE_LA_m1, la1);
	rrd_set_value(RRD_VALUE_LA_m5, la5);
	rrd_set_value(RRD_VALUE_LA_m15, la15);
}

void sPcapStatData::sLoadAvg::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("la1", floatToString(la1, (unsigned)2)));
	out.push_back(sValue("la5", floatToString(la5, (unsigned)2)));
	out.push_back(sValue("la15", floatToString(la15, (unsigned)2)));
	out.push_back(sValue("cpu_count", intToString(cpu_count)));
	out.push_back(sValue("cpu_ht", cpu_ht ? "1" : "0"));
	out.push_back(sValue("uptime_hours", intToString(uptime_hours), "h"));
	out.push_back(sValue("overload_indicator", overload_indicator ? "1" : "0"));
}

void sPcapStatData::sTlb::load() {
	map<string, pair<string, u_int64_t> > counters;
	get_interrupts_counters(&counters);
	if(!counters["tlb"].second) return;
	u_int64_t now_ms = getTimeMS();
	if(load_state.tlb.old_count_tlb && now_ms > load_state.tlb.old_time_ms) {
		unsigned delta = (unsigned)((double)(counters["tlb"].second - load_state.tlb.old_count_tlb) / ((double)(now_ms - load_state.tlb.old_time_ms) / 1000));
		count = delta;
		tlb_high_indicator = delta > 10000;
		valid = true;
	}
	load_state.tlb.old_count_tlb = counters["tlb"].second;
	load_state.tlb.old_time_ms = now_ms;
}

string sPcapStatData::sTlb::render(bool with_title) const {
	if(!valid) {
		return("");
	}
	string out;
	if(with_title) {
		if(tlb_high_indicator) {
			out += "*";
		}
		out += title() + "[";
	}
	out += intToString(count);
	if(with_title) out += "] ";
	return(out);
}

void sPcapStatData::sTlb::get_values(vector<sValue> &out) const {
	if(!valid) return;
	out.push_back(sValue("count", intToString(count)));
	out.push_back(sValue("tlb_high_indicator", tlb_high_indicator ? "1" : "0"));
}

void sPcapStatData::sVersion::load() {
	value = getVersionWithBuild();
}

string sPcapStatData::sVersion::render(bool with_title) const {
	if(value.empty()) {
		return("");
	}
	if(with_title) {
		return(title() + string(value) + " ");
	}
	return(value);
}

void sPcapStatData::sVersion::get_values(vector<sValue> &out) const {
	if(value.empty()) return;
	out.push_back(sValue("value", value));
}

void sPcapStatData::sExternalError::load(const string &error) {
	value = error;
}

string sPcapStatData::sExternalError::render(bool with_title) const {
	if(value.empty()) {
		return("");
	}
	return(value);
}

void sPcapStatData::sExternalError::get_values(vector<sValue> &out) const {
	if(value.empty()) return;
	out.push_back(sValue("value", value));
}
