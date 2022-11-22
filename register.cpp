#include "voipmonitor.h"
#include "register.h"
#include "sql_db.h"
#include "record_array.h"
#include "fraud.h"
#include "sniff.h"


#define NEW_REGISTERS_DEBUG_PERIOD false
#define NEW_REGISTER_CLEANUP_PERIOD (NEW_REGISTERS_DEBUG_PERIOD ? 1 : 30)
#define NEW_REGISTER_UPDATE_PERIOD (NEW_REGISTERS_DEBUG_PERIOD ? 1 : 30)
#define NEW_REGISTER_ERASE_TIMEOUT_FAILED 60
#define NEW_REGISTER_ERASE_TIMEOUT 2*3600


extern char sql_cdr_ua_table[256];
extern int opt_mysqlstore_max_threads_register;
extern MySqlStore *sqlStore;
extern int opt_nocdr;
extern int opt_enable_fraud;
extern int opt_save_ip_from_encaps_ipheader;

extern bool opt_sip_register_compare_sipcallerip;
extern bool opt_sip_register_compare_sipcalledip;
extern bool opt_sip_register_compare_sipcallerip_encaps;
extern bool opt_sip_register_compare_sipcalledip_encaps;
extern bool opt_sip_register_compare_sipcallerport;
extern bool opt_sip_register_compare_sipcalledport;
extern bool opt_sip_register_compare_to_domain;
extern bool opt_sip_register_compare_vlan;

extern bool opt_sip_register_state_compare_from_num;
extern bool opt_sip_register_state_compare_from_name;
extern bool opt_sip_register_state_compare_from_domain;
extern bool opt_sip_register_state_compare_contact_num;
extern bool opt_sip_register_state_compare_contact_domain;
extern bool opt_sip_register_state_compare_digest_realm;
extern bool opt_sip_register_state_compare_ua;
extern bool opt_sip_register_state_compare_sipalg;
extern bool opt_sip_register_state_compare_vlan;
extern bool opt_sipalg_detect;

extern int opt_sip_register_state_timeout;
extern int opt_sip_register_failed_max_details_per_minute;

extern int opt_save_ip_from_encaps_ipheader;
extern bool opt_time_precision_in_ms;
extern bool opt_sip_register_save_eq_states_time;

extern int opt_mysql_enable_multiple_rows_insert;
extern int opt_mysql_max_multiple_rows_insert;

extern Calltable *calltable;

extern sExistsColumns existsColumns;

extern cSqlDbData *dbData;

Registers registers;


struct RegisterFields {
	eRegisterField filedType;
	const char *fieldName;
} registerFields[] = {
	{ rf_id, "ID" },
	{ rf_id_sensor, "id_sensor" },
	{ rf_fname, "fname" },
	{ rf_calldate, "calldate" },
	{ rf_sipcallerip, "sipcallerip" },
	{ rf_sipcalledip, "sipcalledip" },
	{ rf_sipcallerip_encaps, "sipcallerip_encaps" },
	{ rf_sipcalledip_encaps, "sipcalledip_encaps" },
	{ rf_sipcallerip_encaps_prot, "sipcallerip_encaps_prot" },
	{ rf_sipcalledip_encaps_prot, "sipcalledip_encaps_prot" },
	{ rf_sipcallerport, "sipcallerport" },
	{ rf_sipcalledport, "sipcalledport" },
	{ rf_from_num, "from_num" },
	{ rf_from_name, "from_name" },
	{ rf_from_domain, "from_domain" },
	{ rf_to_num, "to_num" },
	{ rf_to_domain, "to_domain" },
	{ rf_contact_num, "contact_num" },
	{ rf_contact_domain, "contact_domain" },
	{ rf_digestusername, "digestusername" },
	{ rf_digestrealm, "digestrealm" },
	{ rf_expires, "expires" },
	{ rf_expires_at, "expires_at" },
	{ rf_state, "state" },
	{ rf_ua, "ua" },
	{ rf_rrd_avg, "rrd_avg" },
	{ rf_spool_index, "spool_index" },
	{ rf_is_sipalg_detected, "is_sipalg_detected" },
	{ rf_vlan, "vlan" }
};

SqlDb *sqlDbSaveRegister = NULL;


RegisterId::RegisterId(Register *reg) {
	this->reg = reg;
}

bool RegisterId:: operator == (const RegisterId& other) const {
	return((!opt_sip_register_compare_sipcallerip || !opt_save_ip_from_encaps_ipheader || this->reg->sipcallerip == other.reg->sipcallerip) &&
	       (!opt_sip_register_compare_sipcalledip || !opt_save_ip_from_encaps_ipheader || this->reg->sipcalledip == other.reg->sipcalledip) &&
	       (!opt_sip_register_compare_sipcallerip_encaps || this->reg->sipcallerip_encaps == other.reg->sipcallerip_encaps) &&
	       (!opt_sip_register_compare_sipcalledip_encaps || this->reg->sipcalledip_encaps == other.reg->sipcalledip_encaps) &&
	       (!opt_sip_register_compare_sipcallerport || this->reg->sipcallerport == other.reg->sipcallerport) &&
	       (!opt_sip_register_compare_sipcalledport || this->reg->sipcalledport == other.reg->sipcalledport) &&
	       (!opt_sip_register_compare_vlan || this->reg->vlan == other.reg->vlan) &&
	       REG_EQ_STR(this->reg->to_num, other.reg->to_num) &&
	       (!opt_sip_register_compare_to_domain || REG_EQ_STR(this->reg->to_domain, other.reg->to_domain)) &&
	       //REG_EQ_STR(this->reg->contact_num, other.reg->contact_num) &&
	       //REG_EQ_STR(this->reg->contact_domain, other.reg->contact_domain) &&
	       REG_EQ0_STR(this->reg->digest_username, other.reg->digest_username));
}

bool RegisterId:: operator < (const RegisterId& other) const { 
	int rslt_cmp_to_num;
	int rslt_cmp_to_domain;
	//int rslt_cmp_contact_num;
	//int rslt_cmp_contact_domain;
	int rslt_cmp_digest_username;
	return((opt_sip_register_compare_sipcallerip && this->reg->sipcallerip < other.reg->sipcallerip) ? 1 : (opt_sip_register_compare_sipcallerip && this->reg->sipcallerip > other.reg->sipcallerip) ? 0 :
	       (opt_sip_register_compare_sipcalledip && this->reg->sipcalledip < other.reg->sipcalledip) ? 1 : (opt_sip_register_compare_sipcalledip && this->reg->sipcalledip > other.reg->sipcalledip) ? 0 :
	       (opt_sip_register_compare_sipcallerip_encaps && opt_save_ip_from_encaps_ipheader && this->reg->sipcallerip_encaps < other.reg->sipcallerip_encaps) ? 1 : (opt_sip_register_compare_sipcallerip_encaps && opt_save_ip_from_encaps_ipheader && this->reg->sipcallerip_encaps > other.reg->sipcallerip_encaps) ? 0 :
	       (opt_sip_register_compare_sipcalledip_encaps && opt_save_ip_from_encaps_ipheader && this->reg->sipcalledip_encaps < other.reg->sipcalledip_encaps) ? 1 : (opt_sip_register_compare_sipcalledip_encaps && opt_save_ip_from_encaps_ipheader && this->reg->sipcalledip_encaps > other.reg->sipcalledip_encaps) ? 0 :
	       (opt_sip_register_compare_sipcallerport && this->reg->sipcallerport < other.reg->sipcallerport) ? 1 : (opt_sip_register_compare_sipcallerport && this->reg->sipcallerport > other.reg->sipcallerport) ? 0 :
	       (opt_sip_register_compare_sipcalledport && this->reg->sipcalledport < other.reg->sipcalledport) ? 1 : (opt_sip_register_compare_sipcalledport && this->reg->sipcalledport > other.reg->sipcalledport) ? 0 :
	       (opt_sip_register_compare_vlan && this->reg->vlan < other.reg->vlan) ? 1 : (opt_sip_register_compare_vlan && this->reg->vlan > other.reg->vlan) ? 0 :
	       ((rslt_cmp_to_num = REG_CMP_STR(this->reg->to_num, other.reg->to_num)) < 0) ? 1 : (rslt_cmp_to_num > 0) ? 0 :
	       (opt_sip_register_compare_to_domain && (rslt_cmp_to_domain = REG_CMP_STR(this->reg->to_domain, other.reg->to_domain)) < 0) ? 1 : (opt_sip_register_compare_to_domain && rslt_cmp_to_domain > 0) ? 0 :
	       //((rslt_cmp_contact_num = REG_CMP_STR(this->reg->contact_num, other.reg->contact_num)) < 0) ? 1 : (rslt_cmp_contact_num > 0) ? 0 :
	       //((rslt_cmp_contact_domain = REG_CMP_STR(this->reg->contact_domain, other.reg->contact_domain)) < 0) ? 1 : (rslt_cmp_contact_domain > 0) ? 0 :
	       ((rslt_cmp_digest_username = REG_CMP0_STR(this->reg->digest_username, other.reg->digest_username)) < 0));
}


bool RegisterFailedId:: operator == (const RegisterFailedId& other) const {
	return(this->id_sensor == other.id_sensor &&
	       this->sipcallerip == other.sipcallerip &&
	       this->sipcalledip == other.sipcalledip &&
	       (!opt_sip_register_compare_sipcallerip_encaps || this->sipcallerip_encaps == other.sipcallerip_encaps) &&
	       (!opt_sip_register_compare_sipcalledip_encaps || this->sipcalledip_encaps == other.sipcalledip_encaps));
}

bool RegisterFailedId:: operator < (const RegisterFailedId& other) const {
	return(this->id_sensor < other.id_sensor ? 1 : this->id_sensor > other.id_sensor ? 0 :
	       this->sipcallerip < other.sipcallerip ? 1 : this->sipcallerip > other.sipcallerip ? 0 :
	       this->sipcalledip < other.sipcalledip ? 1 : this->sipcalledip > other.sipcalledip ? 0 :
	       (opt_sip_register_compare_sipcallerip_encaps && opt_save_ip_from_encaps_ipheader && this->sipcallerip_encaps < other.sipcallerip_encaps) ? 1 : (opt_sip_register_compare_sipcallerip_encaps && opt_save_ip_from_encaps_ipheader && this->sipcallerip_encaps > other.sipcallerip_encaps) ? 0 :
	       (opt_sip_register_compare_sipcalledip_encaps && opt_save_ip_from_encaps_ipheader && this->sipcalledip_encaps < other.sipcalledip_encaps) ? 1 : (opt_sip_register_compare_sipcalledip_encaps && opt_save_ip_from_encaps_ipheader && this->sipcalledip_encaps > other.sipcalledip_encaps) ? 0 : 0);
}


RegisterFailedCount::RegisterFailedCount(Call *call) {
	id_sensor = call->useSensorId;
	CallBranch *c_branch = call->branch_main();
	sipcallerip = c_branch->sipcallerip[0];
	sipcalledip = c_branch->sipcalledip[0];
	if(opt_save_ip_from_encaps_ipheader) {
		sipcallerip_encaps = c_branch->sipcallerip_encaps;
		sipcalledip_encaps = c_branch->sipcalledip_encaps;
		sipcallerip_encaps_prot = c_branch->sipcallerip_encaps_prot;
		sipcalledip_encaps_prot = c_branch->sipcalledip_encaps_prot;
	} else {
		sipcallerip_encaps_prot = 0xFF;
		sipcalledip_encaps_prot = 0xFF;
	}
	count = 0;
	count_saved = 0;
}

void RegisterFailedCount::saveToDb(u_int32_t time_interval) {
	if(opt_nocdr) {
		return;
	}
	if(!sqlDbSaveRegister) {
		sqlDbSaveRegister = createSqlObject();
		sqlDbSaveRegister->setEnableSqlStringInContent(true);
	}
	if(count > count_saved) {
		string register_table = "register_time_info";
		SqlDb_row reg;
		reg.add("failed", "type_info");
		if(id_sensor > -1) {
			reg.add(id_sensor, "id_sensor");
		}
		reg.add(sqlDateTimeString(time_interval), "created_at");
		reg.add(sipcallerip, "sipcallerip", false, sqlDbSaveRegister, register_table.c_str());
		reg.add(sipcalledip, "sipcalledip", false, sqlDbSaveRegister, register_table.c_str());
		reg.add(count - count_saved, "counter");
		if(count > (unsigned)opt_sip_register_failed_max_details_per_minute &&
		   count - opt_sip_register_failed_max_details_per_minute > count_saved) {
			reg.add(count - opt_sip_register_failed_max_details_per_minute - count_saved, "counter_2");
		}
		if(isSqlDriver("mysql")) {
			string query_str;
			query_str += MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT_GROUP +
				     sqlDbSaveRegister->insertQuery(register_table, reg, false, false, true));
			static unsigned int counterSqlStore = 0;
			sqlStore->query_lock(query_str.c_str(),
					     STORE_PROC_ID_REGISTER,
					     opt_mysqlstore_max_threads_register > 1 &&
					     sqlStore->getSize(STORE_PROC_ID_REGISTER, 0) > 1000 ? 
					      counterSqlStore % opt_mysqlstore_max_threads_register : 
					      0);
			++counterSqlStore;
		} else {
			sqlDbSaveRegister->insert(register_table, reg);
		}
		count_saved = count;
	}
}


RegisterFailedInterval::RegisterFailedInterval(u_int32_t time_interval) {
	this->time_interval = time_interval;
}

RegisterFailedInterval::~RegisterFailedInterval() {
	for(map<RegisterFailedId, RegisterFailedCount*>::iterator iter = failed_count.begin(); iter != failed_count.end(); iter++) {
		delete iter->second;
	}
}

bool RegisterFailedInterval::add(Call *call) {
	RegisterFailedId id;
	id.id_sensor = call->useSensorId;
	CallBranch *c_branch = call->branch_main();
	id.sipcallerip = c_branch->sipcallerip[0];
	id.sipcalledip = c_branch->sipcalledip[0];
	if(opt_save_ip_from_encaps_ipheader) {
		id.sipcallerip_encaps = c_branch->sipcallerip_encaps;
		id.sipcalledip_encaps = c_branch->sipcalledip_encaps;
	}
	map<RegisterFailedId, RegisterFailedCount*>::iterator iter = failed_count.find(id);
	u_int32_t count = 0;
	if(iter == failed_count.end()) {
		RegisterFailedCount *failedCound = new FILE_LINE(0) RegisterFailedCount(call);
		count = failedCound->count = 1;
		failed_count[id] = failedCound;
	} else {
		count = ++iter->second->count;
	}
	return(count <= (unsigned)opt_sip_register_failed_max_details_per_minute);
}

void RegisterFailedInterval::saveToDb() {
	for(map<RegisterFailedId, RegisterFailedCount*>::iterator iter = failed_count.begin(); iter != failed_count.end(); iter++) {
		iter->second->saveToDb(time_interval);
	}
}


RegisterFailed::RegisterFailed() {
	_sync_failed_intervals = 0;
}

RegisterFailed::~RegisterFailed() {
	for(map<u_int32_t, RegisterFailedInterval*>::iterator iter = failed_intervals.begin(); iter != failed_intervals.end(); iter++) {
		delete iter->second;
	}
}

bool RegisterFailed::add(Call *call) {
	lock();
	u_int32_t time = call->calltime_s();
	u_int32_t time_interval = time / 60 * 60;
	map<u_int32_t, RegisterFailedInterval*>::iterator iter = failed_intervals.find(time_interval);
	if(iter == failed_intervals.end()) {
		RegisterFailedInterval *failedInterval = new FILE_LINE(0) RegisterFailedInterval(time_interval);
		failed_intervals[time_interval] = failedInterval;
	}
	bool rslt = failed_intervals[time_interval]->add(call);
	unlock();
	return(rslt);
}

void RegisterFailed::cleanup(bool force) {
	lock();
	u_int32_t actTimeS = getTimeS_rdtsc();
	int limit_oldinterval_for_save = 2 * 60;
	int limit_oldinterval_for_clean = 5 * 60;
	for(map<u_int32_t, RegisterFailedInterval*>::iterator iter = failed_intervals.begin(); iter != failed_intervals.end(); ) {
		if(actTimeS / 60 * 60 > iter->first + limit_oldinterval_for_save || force) {
			iter->second->saveToDb();
		}
		if(actTimeS / 60 * 60 > iter->first + limit_oldinterval_for_clean || force) {
			delete iter->second;
			failed_intervals.erase(iter++);
		} else {
			iter++;
		}
	}
	unlock();
}


void RegisterActive::saveToDb(u_int32_t time_s) {
	if(opt_nocdr) {
		return;
	}
	if(!sqlDbSaveRegister) {
		sqlDbSaveRegister = createSqlObject();
		sqlDbSaveRegister->setEnableSqlStringInContent(true);
	}
	map<int, u_int32_t> count;
	registers.getCountActiveBySensors(&count);
	for(map<int, u_int32_t>::iterator iter = count.begin(); iter != count.end(); iter++) {
		string register_table = "register_time_info";
		SqlDb_row reg;
		reg.add("active", "type_info");
		if(iter->first > -1) {
			reg.add(iter->first, "id_sensor");
		}
		reg.add(sqlDateTimeString(time_s), "created_at");
		reg.add((const char *)NULL, "sipcallerip");
		reg.add((const char *)NULL, "sipcalledip");
		reg.add(iter->second, "counter");
		if(isSqlDriver("mysql")) {
			string query_str;
			query_str += MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT_GROUP +
				     sqlDbSaveRegister->insertQuery(register_table, reg, false, false, true));
			static unsigned int counterSqlStore = 0;
			sqlStore->query_lock(query_str.c_str(),
					     STORE_PROC_ID_REGISTER,
					     opt_mysqlstore_max_threads_register > 1 &&
					     sqlStore->getSize(STORE_PROC_ID_REGISTER, 0) > 1000 ? 
					      counterSqlStore % opt_mysqlstore_max_threads_register : 
					      0);
			++counterSqlStore;
		} else {
			sqlDbSaveRegister->insert(register_table, reg);
		}
	}
}


RegisterState::RegisterState(Call *call, Register *reg) {
	if(call) {
		char *tmp_str;
		state_from_us = state_to_us = call->calltime_us();
		time_shift_ms = call->time_shift_ms;
		state = convRegisterState(call);
		zombie = false;
		CallBranch *c_branch = call->branch_main();
		contact_num = reg->contact_num && REG_EQ_STR(c_branch->contact_num.c_str(), reg->contact_num) ?
			       EQ_REG :
			       REG_NEW_STR(c_branch->contact_num.c_str());
		contact_domain = reg->contact_domain && REG_EQ_STR(c_branch->contact_domain.c_str(), reg->contact_domain) ?
				  EQ_REG :
				  REG_NEW_STR(c_branch->contact_domain.c_str());
		from_num = reg->from_num && REG_EQ_STR(c_branch->caller.c_str(), reg->from_num) ?
			    EQ_REG :
			    REG_NEW_STR(c_branch->caller.c_str());
		from_name = reg->from_name && REG_EQ_STR(c_branch->callername.c_str(), reg->from_name) ?
			     EQ_REG :
			     REG_NEW_STR(c_branch->callername.c_str());
		from_domain = reg->from_domain && REG_EQ_STR(c_branch->caller_domain.c_str(), reg->from_domain) ?
			       EQ_REG :
			       REG_NEW_STR(c_branch->caller_domain.c_str());
		digest_realm = reg->digest_realm && REG_EQ_STR(c_branch->digest_realm.c_str(), reg->digest_realm) ?
				EQ_REG :
				REG_NEW_STR(c_branch->digest_realm.c_str());
		ua = reg->ua && REG_EQ_STR(c_branch->a_ua.c_str(), reg->ua) ?
		      EQ_REG :
		      REG_NEW_STR(c_branch->a_ua.c_str());
		spool_index = call->getSpoolIndex();
		fname = fname_last = call->fname_register;
		expires = call->reg.register_expires;
		id_sensor = call->useSensorId;
		is_sipalg_detected = c_branch->is_sipalg_detected;
		vlan = c_branch->vlan;
	} else {
		state_from_us = state_to_us = 0;
		time_shift_ms = 0;
		state = rs_na;
		zombie = false;
		contact_num = NULL;
		contact_domain = NULL;
		from_num = NULL;
		from_name = NULL;
		from_domain = NULL;
		digest_realm = NULL;
		spool_index = 0;
		fname = fname_last = 0;
		expires = 0;
		id_sensor = 0;
		ua = NULL;
		is_sipalg_detected = false;
		vlan = VLAN_UNSET;
	}
	db_id = 0;
	save_at_us = 0;
	next_states_saved = 0;
}

RegisterState::~RegisterState() {
	REG_FREE_STR(contact_num);
	REG_FREE_STR(contact_domain);
	REG_FREE_STR(from_num);
	REG_FREE_STR(from_name);
	REG_FREE_STR(from_domain);
	REG_FREE_STR(digest_realm);
	REG_FREE_STR(ua);
}

void RegisterState::copyFrom(const RegisterState *src) {
	*this = *src;
	char *tmp_str;
	contact_num = REG_NEW_STR(src->contact_num);
	contact_domain = REG_NEW_STR(src->contact_domain);
	from_num = REG_NEW_STR(src->from_num);
	from_name = REG_NEW_STR(src->from_name);
	from_domain = REG_NEW_STR(src->from_domain);
	digest_realm = REG_NEW_STR(src->digest_realm);
	ua = REG_NEW_STR(src->ua);
	spool_index = src->spool_index;
	is_sipalg_detected = src->is_sipalg_detected;
	vlan = src->vlan;
}

bool RegisterState::isEq(Call *call, Register *reg, bool *exp_state) {
	/*
	if(state == convRegisterState(call)) cout << "ok state" << endl;
	//if(REG_EQ_STR(contact_num == EQ_REG ? reg->contact_num : contact_num, call->contact_num)) cout << "ok contact_num" << endl;
	//if(REG_EQ_STR(contact_domain == EQ_REG ? reg->contact_domain : contact_domain, call->contact_domain)) cout << "ok contact_domain" << endl;
	if(!opt_sip_register_state_compare_from_num) cout << "skip from_num" << endl;
	else if(REG_EQ_STR(from_num == EQ_REG ? reg->from_num : from_num, call->caller)) cout << "ok from_num" << endl;
	if(!opt_sip_register_state_compare_from_name) cout << "skip from_name" << endl;
	else if(REG_EQ_STR(from_name == EQ_REG ? reg->from_name : from_name, call->callername)) cout << "ok from_name" << endl;
	if(!opt_sip_register_state_compare_from_domain) cout << "skip from_domain" << endl;
	else if(REG_EQ_STR(from_domain == EQ_REG ? reg->from_domain : from_domain, call->caller_domain)) cout << "ok from_domain" << endl;
	if(!opt_sip_register_state_compare_digest_realm) cout << "skip digest_realm" << endl;
	else if(REG_EQ_STR(digest_realm == EQ_REG ? reg->digest_realm : digest_realm, call->digest_realm)) cout << "ok digest_realm" << endl;
	if(!opt_sip_register_state_compare_ua) cout << "skip ua" << endl;
	else if(REG_EQ_STR(ua == EQ_REG ? reg->ua : ua, call->a_ua)) cout << "ok ua" << endl;
	*/
	CallBranch *c_branch = call->branch_main();
	bool eq = state == convRegisterState(call) &&
		  (!opt_sip_register_state_compare_contact_num || REG_EQ_STR(contact_num == EQ_REG ? reg->contact_num : contact_num, c_branch->contact_num.c_str())) &&
		  (!opt_sip_register_state_compare_contact_domain || REG_EQ_STR(contact_domain == EQ_REG ? reg->contact_domain : contact_domain, c_branch->contact_domain.c_str())) &&
		  (!opt_sip_register_state_compare_from_num || REG_EQ_STR(from_num == EQ_REG ? reg->from_num : from_num, c_branch->caller.c_str())) &&
		  (!opt_sip_register_state_compare_from_name || REG_EQ_STR(from_name == EQ_REG ? reg->from_name : from_name, c_branch->callername.c_str())) &&
		  (!opt_sip_register_state_compare_from_domain || REG_EQ_STR(from_domain == EQ_REG ? reg->from_domain : from_domain, c_branch->caller_domain.c_str())) &&
		  (!opt_sip_register_state_compare_digest_realm || REG_EQ_STR(digest_realm == EQ_REG ? reg->digest_realm : digest_realm, c_branch->digest_realm.c_str())) &&
		  (!opt_sip_register_state_compare_ua || REG_EQ_STR(ua == EQ_REG ? reg->ua : ua, c_branch->a_ua.c_str())) &&
		  (!opt_sip_register_state_compare_sipalg || (!opt_sipalg_detect || is_sipalg_detected == c_branch->is_sipalg_detected)) &&
		  (!opt_sip_register_state_compare_vlan || (vlan == c_branch->vlan)) &&
		  id_sensor == call->useSensorId;
	if(exp_state) {
		if(eq) {
			*exp_state = opt_sip_register_state_timeout && 
				     call->calltime_us() > state_from_us && 
				     (call->calltime_us() - state_from_us) / 1000000 > (unsigned)opt_sip_register_state_timeout;
		} else {
			*exp_state = false;
		}
	}
	return(eq);
}


RegisterStates::RegisterStates() {
	for(unsigned i = 0; i < NEW_REGISTER_MAX_STATES; i++) {
		states[i] = NULL;
	}
	count = 0;
}

RegisterStates::~RegisterStates() {
	clean();
}

void RegisterStates::add(RegisterState *state) {
	shift();
	states[0] = state;
	++count;
}

void RegisterStates::shift() {
	if(count == NEW_REGISTER_MAX_STATES) {
		delete states[NEW_REGISTER_MAX_STATES - 1];
		-- count;
	}
	for(unsigned i = count; i > 0; i--) {
		states[i] = states[i - 1];
	}
}

void RegisterStates::clean() {
	for(unsigned i = 0; i < count; i++) {
		delete states[i];
	}
	count = 0;
}

bool RegisterStates::eqLast(Call *call, Register *reg, bool *exp_state) { 
	RegisterState *state = last();
	if(state && state->isEq(call, reg, exp_state)) {
		return(true);
	}
	return(false);
}


Register::Register(Call *call) {
	lock_id();
	id = ++_id;
	unlock_id();
	CallBranch *c_branch = call->branch_main();
	sipcallerip = c_branch->sipcallerip[0];
	sipcalledip = c_branch->sipcalledip[0];
	if(opt_save_ip_from_encaps_ipheader) {
		sipcallerip_encaps = c_branch->sipcallerip_encaps;
		sipcalledip_encaps = c_branch->sipcalledip_encaps;
		sipcallerip_encaps_prot = c_branch->sipcallerip_encaps_prot;
		sipcalledip_encaps_prot = c_branch->sipcalledip_encaps_prot;
	} else {
		sipcallerip_encaps_prot = 0xFF;
		sipcalledip_encaps_prot = 0xFF;
	}
	sipcallerport = c_branch->sipcallerport[0];
	sipcalledport = c_branch->sipcalledport[0];
	char *tmp_str;
	to_num = REG_NEW_STR(call->get_called(c_branch));
	to_domain = REG_NEW_STR(call->get_called_domain(c_branch));
	contact_num = REG_NEW_STR(c_branch->contact_num.c_str());
	contact_domain = REG_NEW_STR(c_branch->contact_domain.c_str());
	digest_username = REG_NEW_STR(c_branch->digest_username.c_str());
	from_num = REG_NEW_STR(c_branch->caller.c_str());
	from_name = REG_NEW_STR(c_branch->callername.c_str());
	from_domain = REG_NEW_STR(c_branch->caller_domain.c_str());
	digest_realm = REG_NEW_STR(c_branch->digest_realm.c_str());
	ua = REG_NEW_STR(c_branch->a_ua.c_str());
	vlan = c_branch->vlan;
	rrd_sum = 0;
	rrd_count = 0;
	reg_call_id = call->call_id;
	if(call->reg.reg_tcp_seq) {
		reg_tcp_seq = *call->reg.reg_tcp_seq;
	}
	_sync_states = 0;
}

Register::~Register() {
	REG_FREE_STR(to_num);
	REG_FREE_STR(to_domain);
	REG_FREE_STR(contact_num);
	REG_FREE_STR(contact_domain);
	REG_FREE_STR(digest_username);
	REG_FREE_STR(from_num);
	REG_FREE_STR(from_name);
	REG_FREE_STR(from_domain);
	REG_FREE_STR(digest_realm);
	REG_FREE_STR(ua);
	clean_all();
}

void Register::update(Call *call) {
	char *tmp_str;
	CallBranch *c_branch = call->branch_main();
	if(!opt_sip_register_state_compare_contact_num &&
	   !contact_num && !c_branch->contact_num.empty()) {
		contact_num = REG_NEW_STR(c_branch->contact_num.c_str());
	}
	if(!opt_sip_register_state_compare_contact_domain &&
	   !contact_domain && !c_branch->contact_domain.empty()) {
		contact_domain = REG_NEW_STR(c_branch->contact_domain.c_str());
	}
	if(!digest_username && !c_branch->digest_username.empty()) {
		digest_username = REG_NEW_STR(c_branch->digest_username.c_str());
	}
	if(!opt_sip_register_state_compare_from_num &&
	   !from_num && !c_branch->caller.empty()) {
		from_num = REG_NEW_STR(c_branch->caller.c_str());
	}
	if(!opt_sip_register_state_compare_from_name &&
	   !from_name && !c_branch->callername.empty()) {
		from_name = REG_NEW_STR(c_branch->callername.c_str());
	}
	if(!opt_sip_register_state_compare_from_domain &&
	   !from_domain && !c_branch->caller_domain.empty()) {
		from_domain = REG_NEW_STR(c_branch->caller_domain.c_str());
	}
	if(!opt_sip_register_state_compare_digest_realm &&
	   !digest_realm && !c_branch->digest_realm.empty()) {
		digest_realm = REG_NEW_STR(c_branch->digest_realm.c_str());
	}
	if(!opt_sip_register_state_compare_ua &&
	   !ua && !c_branch->a_ua.empty()) {
		ua = REG_NEW_STR(c_branch->a_ua.c_str());
	}
	sipcallerip = c_branch->sipcallerip[0];
	sipcalledip = c_branch->sipcalledip[0];
	if(opt_save_ip_from_encaps_ipheader) {
		sipcallerip_encaps = c_branch->sipcallerip_encaps;
		sipcalledip_encaps = c_branch->sipcalledip_encaps;
		sipcallerip_encaps_prot = c_branch->sipcallerip_encaps_prot;
		sipcalledip_encaps_prot = c_branch->sipcalledip_encaps_prot;
	} else {
		sipcallerip_encaps_prot = 0xFF;
		sipcalledip_encaps_prot = 0xFF;
	}
	sipcallerport = c_branch->sipcallerport[0];
	sipcalledport = c_branch->sipcalledport[0];
	vlan = c_branch->vlan;
	reg_call_id = call->call_id;
	if(call->reg.reg_tcp_seq) {
		reg_tcp_seq = *call->reg.reg_tcp_seq;
	} else {
		reg_tcp_seq.clear();
	}
}

void Register::addState(Call *call) {
	lock_states();
	bool isFailed = convRegisterState(call) != rs_Failed;
	RegisterStates *states = isFailed ? &states_state : &states_failed;
	bool exp_state = false;
	if(states->eqLast(call, this, &exp_state)) {
		if(!exp_state) {
			updateLastState(call, states);
		} else {
			saveStateToDb(states->last(), _ss_exp_state, 0, 
				      __FILE__, __LINE__);
			resetLastState(call, states);
			saveStateToDb(states->last(), _ss_reset, 0, 
				      __FILE__, __LINE__);
		}
	} else {
		states->add(new FILE_LINE(20002) RegisterState(call, this));
		RegisterState *prevState = states->prev();
		if(prevState) {
			saveStateToDb(prevState, _ss_end, 0, 
				      __FILE__, __LINE__);
		}
		saveStateToDb(states->last(), _ss_init, 0, 
			      __FILE__, __LINE__);
	}
	if(!isFailed) {
		RegisterState *state = states->last();
		if(state->isOK() && call->reg.regrrddiff > 0) {
			rrd_sum += call->reg.regrrddiff;
			++rrd_count;
		}
		if(opt_enable_fraud && isFraudReady()) {
			RegisterState *prevState = states->prev();
			fraudRegister(call, state->state, prevState ? prevState->state : rs_na, prevState ? prevState->state_to_us : 0);
		}
	}
	unlock_states();
}

void Register::expire(bool need_lock_states) {
	if(need_lock_states) {
		lock_states();
	}
	RegisterState *lastState = states_state.last();
	if(lastState && lastState->isOK()) {
		saveStateToDb(lastState, _ss_update_force, 0, 
			      __FILE__, __LINE__);
		RegisterState *newState = new FILE_LINE(20003) RegisterState(NULL, NULL);
		newState->copyFrom(lastState);
		newState->state = rs_Expired;
		newState->zombie = false;
		newState->expires = 0;
		newState->state_from_us = newState->state_to_us = lastState->state_to_us + TIME_S_TO_US(lastState->expires);
		newState->save_at_us = 0;
		newState->next_states.clear();
		newState->next_states_saved = 0;
		states_state.add(newState);
		saveStateToDb(newState, _ss_save, 0, 
			      __FILE__, __LINE__);
		if(opt_enable_fraud && isFraudReady()) {
			RegisterState *prevState = states_state.prev();
			fraudRegister(this, prevState, rs_Expired, prevState ? prevState->state : rs_na, prevState ? prevState->state_to_us : 0);
		}
	}
	if(need_lock_states) {
		unlock_states();
	}
}

void Register::updateLastState(Call *call, RegisterStates *states) {
	RegisterState *state = states->last();
	if(state) {
		if(state->zombie) {
			state->state_from_us = call->calltime_us();
			state->fname = call->fname_register;
			state->id_sensor = call->useSensorId;
		}
		state->state_to_us = call->calltime_us();
		state->time_shift_ms = call->time_shift_ms;
		state->fname_last = call->fname_register;
		CallBranch *c_branch = call->branch_main();
		state->expires = call->reg.register_expires;
		if(!opt_sip_register_state_compare_digest_realm && 
		   !state->digest_realm && !c_branch->digest_realm.empty() && this->digest_realm) {
			state->digest_realm = EQ_REG;
		}
		if(!opt_sip_register_state_compare_contact_num) {
			this->updateLastStateItem(c_branch->contact_num.c_str(), this->contact_num, &state->contact_num);
		}
		if(!opt_sip_register_state_compare_contact_domain) {
			this->updateLastStateItem(c_branch->contact_domain.c_str(), this->contact_domain, &state->contact_domain);
		}
		if(!opt_sip_register_state_compare_from_num) {
			this->updateLastStateItem(c_branch->caller.c_str(), this->from_num, &state->from_num);
		}
		if(!opt_sip_register_state_compare_from_name) {
			this->updateLastStateItem(c_branch->callername.c_str(), this->from_name, &state->from_name);
		}
		if(!opt_sip_register_state_compare_from_domain) {
			this->updateLastStateItem(c_branch->caller_domain.c_str(), this->from_domain, &state->from_domain);
		}
		if(!opt_sip_register_state_compare_digest_realm) {
			this->updateLastStateItem(c_branch->digest_realm.c_str(), this->digest_realm, &state->digest_realm);
		}
		if(!opt_sip_register_state_compare_ua) {
			this->updateLastStateItem(c_branch->a_ua.c_str(), this->ua, &state->ua);
		}
		if(c_branch->is_sipalg_detected) {
			state->is_sipalg_detected = true;
		}
		if(!state->zombie) {
			state->next_states.push_back(RegisterState::NextState(call->calltime_us(), call->fname_register, call->useSensorId));
		}
		if(state->zombie) {
			state->zombie = false;
		}
	}
}

void Register::resetLastState(Call *call, RegisterStates *states) {
	RegisterState *state = states->last();
	if(state) {
		if(sverb.registers_save) {
			cout << " *** Register::resetLastState "
			     << " c: " << this->contact_num
			     << " t: " << sqlDateTimeString_us2ms(state->state_from_us) << " - " << sqlDateTimeString_us2ms(state->state_to_us)
			     << " n: " << state->next_states.size()
			     << endl;
		}
		updateLastState(call, states);
		state->state_from_us = state->state_to_us = call->calltime_us();
		state->fname = state->fname_last = call->fname_register;
		state->db_id = 0;
		state->save_at_us = 0;
		state->next_states.clear();
		state->next_states_saved = 0;
	}
}

void Register::updateLastStateItem(const char *callItem, const char *registerItem, char **stateItem) {
	if(callItem && callItem[0] && registerItem && registerItem[0] &&
	   !REG_EQ_STR(*stateItem == EQ_REG ? registerItem : *stateItem, callItem)) {
		char *tmp_str;
		if(*stateItem && *stateItem != EQ_REG) {
			REG_FREE_STR(*stateItem);
		}
		if(!strcmp(registerItem, callItem)) {
			*stateItem = EQ_REG;
		} else {
			*stateItem = REG_NEW_STR(callItem);
		}
	}
}

void Register::clean_all() {
	lock_states();
	states_state.clean();
	states_failed.clean();
	unlock_states();
}

u_int8_t Register::saveNewStateToDb(RegisterState *state) {
	if(opt_nocdr || sverb.disable_save_register) {
		return(0);
	}
	if(registers.isEnabledDeferredSave(state) ? state->zombie : state->save_at_us) {
		return(0);
	}
	string adj_ua = REG_CONV_STR(state->ua == EQ_REG ? ua : state->ua);
	adjustUA(&adj_ua);
	SqlDb_row reg;
	u_int64_t flags = 0;
	string register_table = state->state == rs_Failed ? "register_failed" : "register_state";
	reg.add_calldate(state->state_from_us, "created_at", state->state == rs_Failed ? existsColumns.register_failed_created_at_ms : existsColumns.register_state_created_at_ms);
	reg.add(sipcallerip, "sipcallerip", false, sqlDbSaveRegister, register_table.c_str());
	reg.add(sipcalledip, "sipcalledip", false, sqlDbSaveRegister, register_table.c_str());
	if(opt_save_ip_from_encaps_ipheader && existsColumns.register_state_sipcallerdip_encaps) {
		reg.add(sipcallerip_encaps, "sipcallerip_encaps", !sipcallerip_encaps.isSet(), sqlDbSaveRegister, register_table.c_str());
		reg.add(sipcalledip_encaps, "sipcalledip_encaps", !sipcalledip_encaps.isSet(), sqlDbSaveRegister, register_table.c_str());
		reg.add(sipcallerip_encaps_prot, "sipcallerip_encaps_prot", sipcallerip_encaps_prot == 0xFF);
		reg.add(sipcalledip_encaps_prot, "sipcalledip_encaps_prot", sipcalledip_encaps_prot == 0xFF);
	}
	reg.add(sqlEscapeString(REG_CONV_STR(state->from_num == EQ_REG ? from_num : state->from_num)), "from_num");
	reg.add(sqlEscapeString(REG_CONV_STR(to_num)), "to_num");
	reg.add(sqlEscapeString(REG_CONV_STR(state->contact_num == EQ_REG ? contact_num : state->contact_num)), "contact_num");
	reg.add(sqlEscapeString(REG_CONV_STR(state->contact_domain == EQ_REG ? contact_domain : state->contact_domain)), "contact_domain");
	reg.add(sqlEscapeString(REG_CONV_STR(to_domain)), "to_domain");
	reg.add(sqlEscapeString(REG_CONV_STR(digest_username)), "digestusername");
	reg.add(state->fname, "fname");
	if(state->state == rs_Failed) {
		if(registers.isEnabledIdAssignment(state)) {
			state->db_id = registers.getNewRegisterFailedId(state->id_sensor);
			reg.add(state->db_id, "ID");
			flags |= REG_ID_COMB;
		} else {
			flags |= REG_ID_SIMPLE;
		}
		reg.add(state->next_states.size() + 1, "counter");
		if(existsColumns.register_state_flags) {
			if(state->is_sipalg_detected) {
				flags |= REG_SIPALG_DETECTED;
			}
			reg.add(flags, "flags");
		}
		if(existsColumns.register_failed_vlan && VLAN_IS_SET(vlan)) {
			reg.add(vlan, "vlan");
		}
		if (existsColumns.register_failed_digestrealm) {
			reg.add(sqlEscapeString(REG_CONV_STR(digest_realm)), "digestrealm");
		}
	} else {
		if(registers.isEnabledIdAssignment(state)) {
			state->db_id = registers.getNewRegisterStateId(state->id_sensor);
			reg.add(state->db_id, "ID");
			flags |= REG_ID_COMB;
		} else {
			flags |= REG_ID_SIMPLE;
		}
		if(existsColumns.register_state_counter) {
			reg.add(state->next_states.size() + 1, "counter");
		}
		reg.add(state->expires, "expires");
		reg.add(state->state <= rs_Expired ? state->state : rs_OK, "state");
		if(existsColumns.register_state_flags) {
			if(state->is_sipalg_detected) {
				flags |= REG_SIPALG_DETECTED;
			}
			reg.add(flags, "flags");
		}
		if(existsColumns.register_state_vlan && VLAN_IS_SET(vlan)) {
			reg.add(vlan, "vlan");
		}
		if (existsColumns.register_state_digestrealm) {
			reg.add(sqlEscapeString(REG_CONV_STR(digest_realm)), "digestrealm");
		}
	}
	if(state->id_sensor > -1) {
		reg.add(state->id_sensor, "id_sensor");
	}
	if(state->spool_index && 
	   (state->state == rs_Failed ? existsColumns.register_failed_spool_index : existsColumns.register_state_spool_index)) {
		reg.add(state->spool_index, "spool_index");
	}
	if(isSqlDriver("mysql")) {
		string query_str;
		if(!adj_ua.empty()) {
			if(useSetId()) {
				reg.add(MYSQL_CODEBOOK_ID(cSqlDbCodebook::_cb_ua, adj_ua), "ua_id");
			} else {
				unsigned _cb_id = dbData->getCbId(cSqlDbCodebook::_cb_ua, adj_ua.c_str(), false, true);
				if(_cb_id) {
					reg.add(_cb_id, "ua_id");
				} else {
					query_str += MYSQL_ADD_QUERY_END(string("set @ua_id = ") + 
						     "getIdOrInsertUA(" + sqlEscapeStringBorder(adj_ua) + ")");
					reg.add(MYSQL_VAR_PREFIX + "@ua_id", "ua_id");
				}
			}
		}
		if(registers.isEnabledDeferredSave(state)) {
			if(useNewStore()) {
				if(useSetId()) {
					reg.add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "ID");
				} else {
					query_str += MYSQL_GET_MAIN_INSERT_ID_OLD;
				}
			}
			query_str += MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT + 
				     sqlDbSaveRegister->insertQuery(register_table, reg));
			if(state->next_states.size()) {
				if(useNewStore()) {
					if(!useSetId()) {
						query_str += MYSQL_GET_MAIN_INSERT_ID + 
							     MYSQL_IF_MAIN_INSERT_ID;
					}
				} else {
					query_str += "if row_count() > 0 then\n" +
						     MYSQL_GET_MAIN_INSERT_ID;
				}
				query_str += getQueryStringForSaveEqNext(state);
				if(useNewStore()) {
					if(!useSetId()) {
						query_str += MYSQL_ENDIF_QE;
					}
				} else {
					query_str += "end if";
				}
			}
		} else {
			query_str += MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT_GROUP +
				     sqlDbSaveRegister->insertQuery(register_table, reg, false, false, state->state == rs_Failed));
		}
		static unsigned int counterSqlStore = 0;
		sqlStore->query_lock(query_str.c_str(),
				     STORE_PROC_ID_REGISTER,
				     opt_mysqlstore_max_threads_register > 1 &&
				     sqlStore->getSize(STORE_PROC_ID_REGISTER, 0) > 1000 ? 
				      counterSqlStore % opt_mysqlstore_max_threads_register : 
				      0);
		++counterSqlStore;
	} else {
		if(!adj_ua.empty()) {
			reg.add(dbData->getCbId(cSqlDbCodebook::_cb_ua, adj_ua.c_str(), true), "ua_id");
		}
		sqlDbSaveRegister->insert(register_table, reg);
	}
	state->save_at_us = state->state_to_us;
	state->next_states_saved += state->next_states.size();
	if(registers.isEnabledDeferredSave(state)) {
		state->setZombie();
	} else {
		state->next_states.clear();
	}
	return(1);
}

u_int8_t Register::saveDeferredStateToDb(RegisterState *state) {
	return(saveNewStateToDb(state));
}

u_int8_t Register::saveUpdateStateToDb(RegisterState *state) {
	if(opt_nocdr || sverb.disable_save_register) {
		return(0);
	}
	if(!state->db_id || !state->next_states.size()) {
		return(0);
	}
	string query_str;
	string register_table = state->state == rs_Failed ? "register_failed" : "register_state";
	if(state->state == rs_Failed || existsColumns.register_state_counter) {
		SqlDb_row reg;
		reg.add(state->next_states_saved + state->next_states.size() + 1, "counter");
		if(isSqlDriver("mysql")) {
			query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT + 
				     sqlDbSaveRegister->updateQuery(register_table, reg, 
								    ("ID = " + intToString(state->db_id)).c_str()));
		} else {
			sqlDbSaveRegister->update(register_table, reg, 
						  ("ID = " + intToString(state->db_id)).c_str());
		}
	}
	if(opt_sip_register_save_eq_states_time) {
		query_str += getQueryStringForSaveEqNext(state);
	}
	if(!query_str.empty()) {
		static unsigned int counterSqlStore = 0;
		sqlStore->query_lock(query_str,
				     STORE_PROC_ID_REGISTER,
				     opt_mysqlstore_max_threads_register > 1 &&
				     sqlStore->getSize(STORE_PROC_ID_REGISTER, 0) > 1000 ? 
				      counterSqlStore % opt_mysqlstore_max_threads_register : 
				      0);
		++counterSqlStore;
	}
	state->save_at_us = state->state_to_us;
	state->next_states_saved += state->next_states.size();
	state->next_states.clear();
	return(2);
}

string Register::getQueryStringForSaveEqNext(RegisterState *state) {
	string query_str;
	if(opt_sip_register_save_eq_states_time) {
		string register_table_eq_next = state->state == rs_Failed ? "register_failed_eq_next" : "register_state_eq_next";
		string register_table_eq_next_id = state->state == rs_Failed ? "register_failed_ID" : "register_state_ID";
		vector<SqlDb_row> time_rows;
		for(unsigned i = 0; i < state->next_states.size(); i++) {
			SqlDb_row time_row;
			if(registers.isEnabledDeferredSave(state)) {
				time_row.add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, register_table_eq_next_id);
			} else {
				time_row.add(state->db_id, register_table_eq_next_id);
			}
			time_row.add(state->next_states_saved + i + 1, "order");
			if(state->state == rs_Failed ? existsColumns.register_failed_eq_next_created_at : existsColumns.register_state_eq_next_created_at) {
				time_row.add_calldate(state->state_from_us, "created_at", state->state == rs_Failed ? existsColumns.register_failed_eq_next_created_at_ms : existsColumns.register_state_created_at_ms);
			}
			time_row.add_calldate(state->next_states[i].at, "next_at", state->state == rs_Failed ? existsColumns.register_failed_eq_next_next_at_ms : existsColumns.register_state_eq_next_next_at_ms);
			time_row.add(state->next_states[i].fname, "fname");
			if(state->next_states[i].id_sensor > -1) {
				time_row.add(state->next_states[i].id_sensor, "id_sensor");
			}
			if(opt_mysql_enable_multiple_rows_insert) {
				time_rows.push_back(time_row);
			} else {
				query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT + 
					     sqlDbSaveRegister->insertQuery(register_table_eq_next, time_row));
			}
		}
		if(opt_mysql_enable_multiple_rows_insert && time_rows.size()) {
			query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT_GROUP + 
				     sqlDbSaveRegister->insertQueryWithLimitMultiInsert(register_table_eq_next, &time_rows, opt_mysql_max_multiple_rows_insert, 
											MYSQL_QUERY_END.c_str(), MYSQL_QUERY_END_SUBST.c_str()), false);
		}
	}
	return(query_str);
}

void Register::saveStateToDb(RegisterState *state, eTypeSaveState typeSaveState, u_int32_t actTimeS, 
			     const char *file, int line) {
	string registers_info;
	if(sverb.registers_save) {
		ostringstream outStr;
		outStr << (state->state == rs_Failed ? "failed" : "state")
		       << " c: " << this->contact_num
		       << " t: " << sqlDateTimeString_us2ms(state->state_from_us) << " - " << sqlDateTimeString_us2ms(state->state_to_us)
		       << " n: " << state->next_states.size();
		if(state->next_states.size()) {
			outStr << " (";
			for(unsigned i = 0; i < state->next_states.size(); i++) {
				if(i) {
					outStr << ", ";
				}
				outStr << sqlDateTimeString_us2ms(state->next_states[i].at);
			}
			outStr << ")";
		}
		registers_info = outStr.str();
	}
	u_int8_t saved = false;
	if(!sqlDbSaveRegister) {
		sqlDbSaveRegister = createSqlObject();
		sqlDbSaveRegister->setEnableSqlStringInContent(true);
	}
	switch(typeSaveState) {
	case _ss_init:
	case _ss_reset:
		if(!registers.isEnabledDeferredSave(state)) {
			saved = saveNewStateToDb(state);
		} else if(state->state == rs_Unregister) {
			saved = saveDeferredStateToDb(state);
		}
		break;
	case _ss_update:
		if(!registers.isEnabledDeferredSave(state)) {
			if(actTimeS > TIME_US_TO_S(state->save_at_us ? state->save_at_us : state->state_from_us) &&
			   actTimeS - TIME_US_TO_S(state->save_at_us ? state->save_at_us : state->state_from_us) > NEW_REGISTER_UPDATE_PERIOD) {
				saved = saveUpdateStateToDb(state);
			}
		} else {
			if(opt_sip_register_state_timeout) {
				if(!state->zombie &&
				   actTimeS > TIME_US_TO_S(state->state_from_us) &&
				   actTimeS - TIME_US_TO_S(state->state_from_us) > (unsigned)opt_sip_register_state_timeout) {
					saved = saveDeferredStateToDb(state);
				}
			}
		}
		break;
	case _ss_save:
		if(!registers.isEnabledDeferredSave(state)) {
			saved = saveNewStateToDb(state);
		} else {
			saved = saveDeferredStateToDb(state);
		}
		break;
	case _ss_update_force:
	case _ss_exp_state:
	case _ss_end:
		if(!registers.isEnabledDeferredSave(state)) {
			saved = saveUpdateStateToDb(state);
		} else {
			saved = saveDeferredStateToDb(state);
		}
		break;
	}
	if(sverb.registers_save && saved) {
		cout << " *** Register::saveStateToDb "
		     << (saved == 1 ? "insert" : "update")
		     << " " << typeSaveStateToString(typeSaveState)
		     << " " << registers_info
		     << " f: " << file << ":" << line
		     << endl;
	}
}

RegisterState* Register::getLastState() {
	RegisterState *last_state = states_state.last();
	RegisterState *last_failed = states_failed.last();
	return(!last_failed ? last_state :
	       !last_state ? last_failed :
	       (last_state->isOK() || last_state->state_to_us >= last_failed->state_to_us ? last_state : last_failed));
}

eRegisterState Register::getState() {
	lock_states();
	RegisterState *state = getLastState();
	eRegisterState rslt_state = state ? state->state : rs_na;
	unlock_states();
	return(rslt_state);
}

bool Register::stateIsOK() {
	lock_states();
	RegisterState *state = getLastState();
	bool rslt_state = state ? state->isOK() : false;
	unlock_states();
	return(rslt_state);
}

u_int32_t Register::getStateFrom_s() {
	lock_states();
	RegisterState *state = getLastState();
	u_int32_t state_from = state->state_from_us ? TIME_US_TO_S(state->state_from_us) : 0;
	unlock_states();
	return(state_from);
}

bool Register::getDataRow(RecordArray *rec) {
	lock_states();
	RegisterState *state = getLastState();
	if(!state) {
		unlock_states();
		return(false);
	}
	rec->fields[rf_id].set(id);
	rec->fields[rf_sipcallerip].set(sipcallerip, RecordArrayField::tf_ip_n4);
	rec->fields[rf_sipcalledip].set(sipcalledip, RecordArrayField::tf_ip_n4);
	if(opt_save_ip_from_encaps_ipheader) {
		rec->fields[rf_sipcallerip_encaps].set(sipcallerip_encaps, RecordArrayField::tf_ip_n4);
		rec->fields[rf_sipcalledip_encaps].set(sipcalledip_encaps, RecordArrayField::tf_ip_n4);
		rec->fields[rf_sipcallerip_encaps_prot].set(sipcallerip_encaps_prot);
		rec->fields[rf_sipcalledip_encaps_prot].set(sipcalledip_encaps_prot);
	}
	rec->fields[rf_sipcallerport].set(sipcallerport, RecordArrayField::tf_port);
	rec->fields[rf_sipcalledport].set(sipcalledport, RecordArrayField::tf_port);
	rec->fields[rf_to_num].set(to_num);
	rec->fields[rf_to_domain].set(to_domain);
	rec->fields[rf_contact_num].set(state->contact_num == EQ_REG ? contact_num : state->contact_num);
	rec->fields[rf_contact_domain].set(state->contact_domain == EQ_REG ? contact_domain : state->contact_domain);
	rec->fields[rf_digestusername].set(digest_username);
	rec->fields[rf_id_sensor].set(state->id_sensor);
	rec->fields[rf_fname].set(state->fname_last);
	if(opt_time_precision_in_ms) {
		rec->fields[rf_calldate].set(state->state_to_us, RecordArrayField::tf_time_ms);
	} else {
		rec->fields[rf_calldate].set(TIME_US_TO_S(state->state_to_us), RecordArrayField::tf_time);
	}
	rec->fields[rf_from_num].set(state->from_num == EQ_REG ? from_num : state->from_num);
	rec->fields[rf_from_name].set(state->from_name == EQ_REG ? from_name : state->from_name);
	rec->fields[rf_from_domain].set(state->from_domain == EQ_REG ? from_domain : state->from_domain);
	rec->fields[rf_digestrealm].set(state->digest_realm == EQ_REG ? digest_realm : state->digest_realm);
	rec->fields[rf_expires].set(state->expires);
	rec->fields[rf_expires_at].set(TIME_US_TO_S(state->state_to_us) + state->expires, RecordArrayField::tf_time);
	rec->fields[rf_state].set(state->state);
	rec->fields[rf_ua].set(state->ua == EQ_REG ? ua : state->ua);
	if(rrd_count) {
		rec->fields[rf_rrd_avg].set(rrd_sum / rrd_count);
	}
	rec->fields[rf_spool_index].set(state->spool_index);
	if(VLAN_IS_SET(state->vlan)) {
		rec->fields[rf_vlan].set(state->vlan);
	}
	rec->fields[rf_is_sipalg_detected].set(states_state.isSipAlg());
	unlock_states();
	return(true);
}

string Register::typeSaveStateToString(eTypeSaveState typeSaveState) {
	struct {
		eTypeSaveState typeSaveState;
		const char *str;
	} typeSaveState_table[] = {
		{ _ss_init, "init" },
		{ _ss_reset, "reset" },
		{ _ss_update, "update" },
		{ _ss_save, "save" },
		{ _ss_update_force, "update_force" },
		{ _ss_exp_state, "exp_state" },
		{ _ss_end, "end" },
		{ _ss_init, NULL }
	};
	for(unsigned i = 0; typeSaveState_table[i].str; i++) {
		if(typeSaveState_table[i].typeSaveState == typeSaveState) {
			return(typeSaveState_table[i].str);
		}
	}
	return("");
}

volatile u_int64_t Register::_id = 0;
volatile int Register::_sync_id = 0;


RegistersTimer::RegistersTimer(Registers *registers) : cTimer(registers) {
}

void RegistersTimer::evTimer(u_int32_t time_s, int typeTimer, void *data) {
	((Registers*)data)->evTimer(time_s, typeTimer);
	((Registers*)data)->cleanup_from_timer(time_s);
}


Registers::Registers() 
 : timer(this) {
	_sync_registers = 0;
	_sync_registers_erase = 0;
	register_state_id = 0;
	register_failed_id = 0;
	_sync_register_state_id = 0;
	_sync_register_failed_id = 0;
	last_cleanup_time = 0;
}

Registers::~Registers() {
	clean_all();
}

int Registers::getCount() {
	return(registers.size());
}

void Registers::getCountActiveBySensors(map<int, u_int32_t> *count) {
	lock_registers_erase();
	lock_registers();
	for(map<RegisterId, Register*>::iterator iter_reg = registers.begin(); iter_reg != registers.end(); iter_reg++) {
		iter_reg->second->lock_states();
		RegisterState *state = iter_reg->second->getLastState();
		if(state && state->isOK()) {
			++(*count)[state->id_sensor];
		}
		iter_reg->second->unlock_states();
	}
	unlock_registers();
	unlock_registers_erase();
}

void Registers::add(Call *call) {
 
	/*
	string digest_username_orig = call->digest_username;
	for(int q = 1; q <= 3; q++) {
	snprintf(call->digest_username, sizeof(call->digest_username), "%s-%i", digest_username_orig.c_str(), q);
	*/
	
	eRegisterState state = convRegisterState(call);
	if(!state) {
		return;
	} else if(state == rs_Failed) {
	 
		/*
		static int _c;
		cout << " *** FAILED " << (++_c) 
		     << " " << sqlDateTimeString_us2ms(call->calltime_us()) 
		     << " " << call->contact_num
		     << endl;
		*/
	 
		if(!registers_failed.add(call)) {
			return;
		}
	}
	Register *reg = new FILE_LINE(20004) Register(call);
	/*
	cout 
		<< "* sipcallerip:" << reg->sipcallerip << " / "
		<< "* sipcalledip:" << reg->sipcalledip << " / "
		<< "* to_num:" << (reg->to_num ? reg->to_num : "") << " / "
		<< "* to_domain:" << (reg->to_domain ? reg->to_domain : "") << " / "
		<< "contact_num:" << (reg->contact_num ? reg->contact_num : "") << " / "
		<< "contact_domain:" << (reg->contact_domain ? reg->contact_domain : "") << " / "
		<< "* digest_username:" << (reg->digest_username ? reg->digest_username : "") << " / "
		<< "from_num:" << (reg->from_num ? reg->from_num : "") << " / "
		<< "from_name:" << (reg->from_name ? reg->from_name : "") << " / "
		<< "from_domain:" << (reg->from_domain ? reg->from_domain : "") << " / "
		<< "digest_realm:" << (reg->digest_realm ? reg->digest_realm : "") << " / "
		<< "ua:" << (reg->ua ? reg->ua : "") << endl;
	*/
	RegisterId rid(reg);
	lock_registers();
	map<RegisterId, Register*>::iterator iter = registers.find(rid);
	if(iter == registers.end()) {
		reg->addState(call);
		registers[rid] = reg;
		unlock_registers();
	} else {
		Register *existsReg = iter->second;
		existsReg->lock_states();
		RegisterState *regstate = existsReg->getLastState();
		if(regstate && regstate->isOK() && regstate->expires &&
		   TIME_US_TO_S(regstate->state_to_us) + regstate->expires < call->calltime_s()) {
			existsReg->expire(false);
		}
		existsReg->unlock_states();
		existsReg->update(call);
		unlock_registers();
		existsReg->addState(call);
		delete reg;
	}
	
	/*
	}
	strcpy(call->digest_username, digest_username_orig.c_str());
	*/
	
	cleanup(false, 30);
	
	/*
	eRegisterState states[] = {
		rs_OK,
		rs_UnknownMessageOK,
		rs_na
	};
	cout << getDataTableJson(states, 0, rf_calldate, false) << endl;
	*/
}

bool Registers::existsDuplTcpSeqInRegOK(Call *call, u_int32_t seq) {
	if(!seq) {
		return(false);
	}
	Register *reg = new FILE_LINE(20004) Register(call);
	RegisterId rid(reg);
	bool rslt = false;
	lock_registers();
	map<RegisterId, Register*>::iterator iter = registers.find(rid);
	if(iter != registers.end()) {
		Register *existsReg = iter->second;
		if(existsReg->stateIsOK() &&
		   existsReg->reg_call_id == call->call_id &&
		   existsReg->reg_tcp_seq.size() &&
		   std::find(existsReg->reg_tcp_seq.begin(), existsReg->reg_tcp_seq.end(), seq) != existsReg->reg_tcp_seq.end()) {
			rslt = true;
		}
	}
	unlock_registers();
	delete reg;
	return(rslt);
}

void Registers::cleanup(bool force, int expires_add) {
	u_int32_t actTimeS = getTimeS_rdtsc();
	if(!last_cleanup_time) {
		last_cleanup_time = actTimeS;
		return;
	}
	if(actTimeS > last_cleanup_time + NEW_REGISTER_CLEANUP_PERIOD || force) {
		lock_registers();
		map<RegisterId, Register*>::iterator iter;
		for(iter = registers.begin(); iter != registers.end(); ) {
			Register *reg = iter->second;
			reg->lock_states();
			RegisterState *state_state = reg->states_state.last();
			if(state_state) {
				u_int32_t actTimeS_unshift = state_state->unshiftSystemTime_s(actTimeS);
				if(state_state->isOK() && state_state->expires &&
				   TIME_US_TO_S(state_state->state_to_us) + state_state->expires + expires_add < actTimeS_unshift) {
					reg->expire(false);
				} else {
					reg->saveStateToDb(state_state, force ? Register::_ss_update_force : Register::_ss_update, actTimeS_unshift,
							   __FILE__, __LINE__);
				}
			}
			RegisterState *state_failed = reg->states_failed.last();
			if(state_failed) {
				u_int32_t actTimeS_unshift = state_failed->unshiftSystemTime_s(actTimeS);
				reg->saveStateToDb(state_failed, force ? Register::_ss_update_force : Register::_ss_update, actTimeS_unshift,
						   __FILE__, __LINE__);
			}
			bool eraseRegister = false;
			if(!_sync_registers_erase) {
				RegisterState *state_last = reg->getLastState();
				if(state_last) {
					u_int32_t actTimeS_unshift = state_last->unshiftSystemTime_s(actTimeS);
					if(state_last->state == rs_Failed && reg->states_state.count == 0 &&
					   TIME_US_TO_S(state_last->state_to_us) + NEW_REGISTER_ERASE_TIMEOUT_FAILED < actTimeS_unshift) {
						eraseRegister = true;
						// cout << "erase failed" << endl;
					} else if(TIME_US_TO_S(state_last->state_to_us) + NEW_REGISTER_ERASE_TIMEOUT < actTimeS_unshift) {
						eraseRegister = true;
						// cout << "erase" << endl;
					}
				}
			}
			reg->unlock_states();
			if(force || eraseRegister) {
				lock_registers_erase();
				delete iter->second;
				registers.erase(iter++);
				unlock_registers_erase();
			} else {
				iter++;
			}
		}
		registers_failed.cleanup(force);
		unlock_registers();
		last_cleanup_time = actTimeS;
	}
}

void Registers::cleanup_from_timer(u_int32_t time_s) {
	if(time_s > last_cleanup_time + NEW_REGISTER_CLEANUP_PERIOD * 2) {
		cleanup(false, 30);
	}
}

void Registers::clean_all() {
	lock_registers();
	while(registers.size()) {
		delete registers.begin()->second;
		registers.erase(registers.begin());
	}
	unlock_registers();
}

u_int64_t Registers::getNewRegisterId(int sensorId, bool failed) {
	u_int64_t id = 0;
	if(failed) {
		lock_register_failed_id();
		if(!register_failed_id) {
			SqlDb *db = createSqlObject();
			db->query("select max(id) as id from register_failed");
			SqlDb_row row = db->fetchRow();
			if(row) {
				register_failed_id = atoll(row["id"].c_str());
			}
			delete db;
		}
		id = register_failed_id = ((register_failed_id / 100000 + 1) * 100000) + (sensorId >= 0 ? sensorId : 99999);
		unlock_register_failed_id();
	} else {
		lock_register_state_id();
		if(!register_state_id) {
			SqlDb *db = createSqlObject();
			db->query("select max(id) as id from register_state");
			SqlDb_row row = db->fetchRow();
			if(row) {
				register_state_id = atoll(row["id"].c_str());
			}
			delete db;
		}
		id = register_state_id = ((register_state_id / 100000 + 1) * 100000) + (sensorId >= 0 ? sensorId : 99999);
		unlock_register_state_id();
	}
	return(id);
}

u_int64_t Registers::getNewRegisterStateId(int sensorId) {
	return(getNewRegisterId(sensorId, false));
}

u_int64_t Registers::getNewRegisterFailedId(int sensorId) {
	return(getNewRegisterId(sensorId, true));
}

string Registers::getDataTableJson(char *params, bool *zip) {
 
	JsonItem jsonParams;
	jsonParams.parse(params);
	
	eRegisterState states[10];
	memset(states, 0, sizeof(states));
	unsigned states_count = 0;
	string states_str = jsonParams.getValue("states");
	if(!states_str.empty()) {
		vector<string> states_str_vect = split(states_str, ',');
		for(unsigned i = 0; i < states_str_vect.size(); i++) {
			if(states_str_vect[i] == "OK") {			states[states_count++] = rs_OK;
			} else if(states_str_vect[i] == "Failed") {		states[states_count++] = rs_Failed;
			} else if(states_str_vect[i] == "UnknownMessageOK") {	states[states_count++] = rs_UnknownMessageOK;
			} else if(states_str_vect[i] == "ManyRegMessages") {	states[states_count++] = rs_ManyRegMessages;
			} else if(states_str_vect[i] == "Expired") {		states[states_count++] = rs_Expired;
			} else if(states_str_vect[i] == "Unregister") {		states[states_count++] = rs_Unregister;
			}
		}
	}
	
	u_int32_t limit = atol(jsonParams.getValue("limit").c_str());
	string sortBy = jsonParams.getValue("sort_field");
	eRegisterField sortById = convRegisterFieldToFieldId(sortBy.c_str());
	string sortDir = jsonParams.getValue("sort_dir");
	std::transform(sortDir.begin(), sortDir.end(), sortDir.begin(), ::tolower);
	bool sortDesc = sortDir.substr(0, 4) == "desc";
	
	u_int32_t stateFromLe = atol(jsonParams.getValue("state_from_le").c_str());
	string duplicityOnlyBy = jsonParams.getValue("duplicity_only_by");
	eRegisterField duplicityOnlyById = convRegisterFieldToFieldId(duplicityOnlyBy.c_str());
	string duplicityOnlyCheck = jsonParams.getValue("duplicity_only_check");
	eRegisterField duplicityOnlyCheckId = convRegisterFieldToFieldId(duplicityOnlyCheck.c_str());
	u_int32_t rrdGe = atol(jsonParams.getValue("rrd_ge").c_str());
	
	if(zip) {
		string zipParam = jsonParams.getValue("zip");
		std::transform(zipParam.begin(), zipParam.end(), zipParam.begin(), ::tolower);
		*zip = zipParam == "yes";
	}
 
	lock_registers_erase();
	lock_registers();
	
	u_int32_t list_registers_size = registers.size();
	u_int32_t list_registers_count = 0;
	Register **list_registers = new FILE_LINE(20005) Register*[list_registers_size];
	
	//cout << "**** 001 " << getTimeMS() << endl;
	
	for(map<RegisterId, Register*>::iterator iter_reg = registers.begin(); iter_reg != registers.end(); iter_reg++) {
		if(states_count) {
			bool okState = false;
			eRegisterState state = iter_reg->second->getState();
			for(unsigned i = 0; i < states_count; i++) {
				if(states[i] == state) {
					okState = true;
					break;
				}
			}
			if(!okState) {
				continue;
			}
		}
		if(stateFromLe) {
			u_int32_t stateFrom = iter_reg->second->getStateFrom_s();
			if(!stateFrom || stateFrom > stateFromLe) {
				continue;
			}
		}
		if(rrdGe) {
			if(!iter_reg->second->rrd_count ||
			   iter_reg->second->rrd_sum / iter_reg->second->rrd_count < rrdGe) {
				continue;
			}
		}
		list_registers[list_registers_count++] = iter_reg->second;
	}
	
	//cout << "**** 002 " << getTimeMS() << endl;
	
	unlock_registers();
	
	list<RecordArray> records;
	for(unsigned i = 0; i < list_registers_count; i++) {
		RecordArray rec(rf__max);
		if(list_registers[i]->getDataRow(&rec)) {
			rec.sortBy = sortById;
			rec.sortBy2 = rf_id;
			records.push_back(rec);
		}
	}
	delete [] list_registers;
	
	unlock_registers_erase();
	
	string table;
	string header = "[";
	for(unsigned i = 0; i < sizeof(registerFields) / sizeof(registerFields[0]); i++) {
		if(i) {
			header += ",";
		}
		header += '"' + string(registerFields[i].fieldName) + '"';
	}
	header += "]";
	table = "[" + header;
	if(records.size()) {
		string filter = jsonParams.getValue("filter");
		string filter_user_restr = jsonParams.getValue("filter_user_restr");
		if(!filter.empty() || !filter_user_restr.empty()) {
			cRegisterFilter *regFilter = new FILE_LINE(0) cRegisterFilter(filter.c_str());
			if(!filter.empty()) {
				// cout << "FILTER: " << filter << endl;
				regFilter->setFilter(filter.c_str());
			}
			if(!filter_user_restr.empty()) {
				// cout << "FILTER (user_restr): " << filter_user_restr << endl;
				regFilter->setFilter(filter_user_restr.c_str());
			}
			for(list<RecordArray>::iterator iter_rec = records.begin(); iter_rec != records.end(); ) {
				if(!regFilter->check(&(*iter_rec))) {
					iter_rec->free();
					records.erase(iter_rec++);
				} else {
					iter_rec++;
				}
			}
			delete regFilter;
		}
	}
	if(records.size() && duplicityOnlyById && duplicityOnlyCheckId) {
		map<RecordArrayField2, list<RecordArrayField2> > dupl_map;
		map<RecordArrayField2, list<RecordArrayField2> >::iterator dupl_map_iter;
		for(list<RecordArray>::iterator iter_rec = records.begin(); iter_rec != records.end(); iter_rec++) {
			RecordArrayField2 duplBy(&iter_rec->fields[duplicityOnlyById]);
			RecordArrayField2 duplCheck(&iter_rec->fields[duplicityOnlyCheckId]);
			dupl_map_iter = dupl_map.find(duplBy);
			if(dupl_map_iter == dupl_map.end()) {
				dupl_map[duplBy].push_back(duplCheck);
			} else {
				list<RecordArrayField2> *l = &dupl_map_iter->second;
				bool exists = false;
				for(list<RecordArrayField2>::iterator iter = l->begin(); iter != l->begin(); iter++) {
					if(*iter == duplCheck) {
						exists = true;
						break;
					}
				}
				if(!exists) {
					l->push_back(duplCheck);
				}
			}
		}
		for(list<RecordArray>::iterator iter_rec = records.begin(); iter_rec != records.end(); ) {
			RecordArrayField2 duplBy(&iter_rec->fields[duplicityOnlyById]);
			dupl_map_iter = dupl_map.find(duplBy);
			if(dupl_map_iter != dupl_map.end() &&
			   dupl_map_iter->second.size() > 1) {
				iter_rec++;
			} else {
				iter_rec->free();
				records.erase(iter_rec++);
			}
		}
	}
	if(records.size()) {
		table += string(", [{\"total\": ") + intToString(records.size()) + "}]";
		if(sortById) {
			records.sort();
		}
		list<RecordArray>::iterator iter_rec = sortDesc ? records.end() : records.begin();
		if(sortDesc) {
			iter_rec--;
		}
		u_int32_t counter = 0;
		while(counter < records.size() && iter_rec != records.end()) {
			string rec_json = iter_rec->getJson();
			extern cUtfConverter utfConverter;
			if(!utfConverter.check(rec_json.c_str())) {
				rec_json = utfConverter.remove_no_ascii(rec_json.c_str());
			}
			table += "," + rec_json;
			if(sortDesc) {
				if(iter_rec != records.begin()) {
					iter_rec--;
				} else {
					break;
				}
			} else {
				iter_rec++;
			}
			++counter;
			if(limit && counter >= limit) {
				break;
			}
		}
		for(iter_rec = records.begin(); iter_rec != records.end(); iter_rec++) {
			iter_rec->free();
		}
	}
	table += "]";
	return(table);
}

void Registers::cleanupByJson(char *params) {

	JsonItem jsonParams;
	jsonParams.parse(params);

	eRegisterState states[10];
	memset(states, 0, sizeof(states));
	unsigned states_count = 0;
	string states_str = jsonParams.getValue("states");
	if(!states_str.empty()) {
		vector<string> states_str_vect = split(states_str, ',');
		for(unsigned i = 0; i < states_str_vect.size(); i++) {
			if(states_str_vect[i] == "OK") {			states[states_count++] = rs_OK;
			} else if(states_str_vect[i] == "Failed") {		states[states_count++] = rs_Failed;
			} else if(states_str_vect[i] == "UnknownMessageOK") {	states[states_count++] = rs_UnknownMessageOK;
			} else if(states_str_vect[i] == "ManyRegMessages") {	states[states_count++] = rs_ManyRegMessages;
			} else if(states_str_vect[i] == "Expired") {		states[states_count++] = rs_Expired;
			} else if(states_str_vect[i] == "Unregister") {		states[states_count++] = rs_Unregister;
			}
		}
	}
	
	lock_registers_erase();
	lock_registers();
	
	for(map<RegisterId, Register*>::iterator iter_reg = registers.begin(); iter_reg != registers.end(); ) {
		bool okState = false;
		if(states_count) {
			eRegisterState state = iter_reg->second->getState();
			for(unsigned i = 0; i < states_count; i++) {
				if(states[i] == state) {
					okState = true;
					break;
				}
			}
		} else {
			okState = true;
		}
		if(okState) {
			delete iter_reg->second;
			registers.erase(iter_reg++);
		} else {
			iter_reg++;
		}
	}
	
	unlock_registers();
	unlock_registers_erase();
}

void Registers::startTimer() {
	timer.start();
}

void Registers::stopTimer() {
	timer.stop();
}

void Registers::evTimer(u_int32_t time_s, int typeTimer) {
	if(typeTimer & cTimer::_tt_min) {
		register_active.saveToDb(time_s);
	}
}


eRegisterState convRegisterState(Call *call) {
	CallBranch *c_branch = call->branch_main();
	return(call->reg.msgcount <= 1 ||
	       c_branch->lastSIPresponseNum == 401 || c_branch->lastSIPresponseNum == 403 || c_branch->lastSIPresponseNum == 404 ?
		rs_Failed :
	       call->reg.regstate == rs_OK && !call->reg.register_expires ?
		rs_Unregister :
		(eRegisterState)call->reg.regstate);
}

eRegisterField convRegisterFieldToFieldId(const char *field) {
	for(unsigned i = 0; i < sizeof(registerFields) / sizeof(registerFields[0]); i++) {
		if(!strcmp(field, registerFields[i].fieldName)) {
			return(registerFields[i].filedType);
		}
	}
	return((eRegisterField)0);
}


void initRegisters() {
	registers.startTimer();
}

void termRegisters() {
	registers.stopTimer();
}
