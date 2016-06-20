#include "voipmonitor.h"
#include "register.h"
#include "sql_db.h"


#define NEW_REGISTER_CLEAN_PERIOD 30
#define NEW_REGISTER_UPDATE_FAILED_PERIOD 20
#define NEW_REGISTER_ERASE_FAILED_TIMEOUT 60
#define NEW_REGISTER_ERASE_TIMEOUT 6*3600


extern char sql_cdr_ua_table[256];
extern int opt_mysqlstore_max_threads_register;
extern MySqlStore *sqlStore;
extern int opt_nocdr;

#if NEW_REGISTERS
Registers registers;
#endif


#define REG_NEW_STR(src)		((src) && *(src) ? (tmp_str = new FILE_LINE char[strlen(src) + 1], strcpy(tmp_str, src), tmp_str) : NULL)
#define REG_FREE_STR(str)		((str) ? (delete [] (str), str = NULL, true) : false)
#define REG_EQ_STR(str1, str2)		((!(str1) || !*(str1)) && (!(str2) || !*(str2)) ? true : (!(str1) || !*(str1)) || (!(str2) || !*(str2)) ? false : !strcasecmp(str1, str2))
#define REG_CMP_STR(str1, str2)		((!(str1) || !*(str1)) && (!(str2) || !*(str2)) ? 0 : (!(str1) || !*(str1)) ? -1 : (!(str2) || !*(str2)) ? 1 : strcasecmp(str1, str2))
#define REG_CONV_STR(str)		((str) ? string(str) : string())


struct RegisterField {
	enum eTypeField {
		tf_na,
		tf_int,
		tf_time,
		tf_string
	};
	RegisterField() {
		tf = tf_na;
		i = 0;
		s = NULL;
	}
	void free() {
		if(s) {
			delete [] s;
			s = NULL;
		}
	}
	void set(u_int64_t i, eTypeField tf = tf_int) {
		this->tf = tf;
		this->i = i;
	}
	void set(const char *s) {
		tf = tf_string;
		if(s && *s) {
			this->s = new FILE_LINE char[strlen(s) + 1];
			strcpy(this->s, s);
		} else {
			this->s = NULL;
		}
		this->i = 0;
	}
	string getJson();
	bool operator == (const RegisterField& other) const {
		return(i == other.i &&
		       REG_EQ_STR(s, other.s));
	}
	bool operator < (const RegisterField& other) const {
		return(i < other.i ? 1 : i > other.i ? 0 :
		       REG_CMP_STR(s, other.s) < 0);
	}
	bool operator > (const RegisterField& other) const {  
		return(!(*this < other || *this == other));
	}
	eTypeField tf;
	u_int64_t i;
	char *s;
};

struct RegisterRecord {
	void free();
	string getJson();
	bool operator == (const RegisterRecord& other) const {  
		return(fields[sortBy] == other.fields[sortBy] &&
		       fields[rf_id] == other.fields[rf_id]);
	}
	bool operator < (const RegisterRecord& other) const {  
		return(fields[sortBy] < other.fields[sortBy] ? 1 : fields[sortBy] > other.fields[sortBy] ? 0 :
		       fields[rf_id] < other.fields[rf_id]);
	}
	RegisterField fields[rf__max];
	eRegisterField sortBy;
};


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
	{ rf_rrd_avg, "rrd_avg" }
};

SqlDb *sqlDbSaveRegister = NULL;


string RegisterField::getJson() {
	switch(tf) {
	case tf_int:
		return(intToString(i));
	case tf_time:
		return('"' + sqlDateTimeString(i) + '"');
	case tf_string:
		if(s) {
			return('"' + json_encode(s) + '"');
		}
	case tf_na:
		return("null");
	}
	return("null");
}

void RegisterRecord::free() {
	for(unsigned i = 0; i < (sizeof(fields) / sizeof(fields[0])); i++) {
		fields[i].free();
	}
}

string RegisterRecord::getJson() {
	string json = "[";
	for(unsigned i = 0; i < (sizeof(fields) / sizeof(fields[0])); i++) {
		if(i) {
			json += ",";
		}
		json += fields[i].getJson();
	}
	json += "]";
	return(json);
}


RegisterId::RegisterId(Register *reg) {
	this->reg = reg;
}

bool RegisterId:: operator == (const RegisterId& other) const {
	return(this->reg->sipcallerip == other.reg->sipcallerip &&
	       this->reg->sipcalledip == other.reg->sipcalledip &&
	       REG_EQ_STR(this->reg->to_num, other.reg->to_num) &&
	       REG_EQ_STR(this->reg->to_domain, other.reg->to_domain) &&
	       REG_EQ_STR(this->reg->contact_num, other.reg->contact_num) &&
	       REG_EQ_STR(this->reg->contact_domain, other.reg->contact_domain) &&
	       REG_EQ_STR(this->reg->digest_username, other.reg->digest_username));
}

bool RegisterId:: operator < (const RegisterId& other) const { 
	int rslt_cmp_to_num;
	int rslt_cmp_to_domain;
	int rslt_cmp_contact_num;
	int rslt_cmp_contact_domain;
	int rslt_cmp_digest_username;
	return((this->reg->sipcallerip < other.reg->sipcallerip) ? 1 : (this->reg->sipcallerip > other.reg->sipcallerip) ? 0 :
	       (this->reg->sipcalledip < other.reg->sipcalledip) ? 1 : (this->reg->sipcalledip > other.reg->sipcalledip) ? 0 :
	       ((rslt_cmp_to_num = REG_CMP_STR(this->reg->to_num, other.reg->to_num)) < 0) ? 1 : (rslt_cmp_to_num > 0) ? 0 :
	       ((rslt_cmp_to_domain = REG_CMP_STR(this->reg->to_domain, other.reg->to_domain)) < 0) ? 1 : (rslt_cmp_to_domain > 0) ? 0 :
	       ((rslt_cmp_contact_num = REG_CMP_STR(this->reg->contact_num, other.reg->contact_num)) < 0) ? 1 : (rslt_cmp_contact_num > 0) ? 0 :
	       ((rslt_cmp_contact_domain = REG_CMP_STR(this->reg->contact_domain, other.reg->contact_domain)) < 0) ? 1 : (rslt_cmp_contact_domain > 0) ? 0 :
	       ((rslt_cmp_digest_username = REG_CMP_STR(this->reg->digest_username, other.reg->digest_username)) < 0));
}


RegisterState::RegisterState(Call *call, Register *reg) {
	if(call) {
		char *tmp_str;
		state_from = state_to = call->calltime();
		counter = 1;
		state = convRegisterState(call);
		from_num = REG_EQ_STR(call->caller, reg->from_num) ?
			    NULL :
			    REG_NEW_STR(call->caller);
		from_name = REG_EQ_STR(call->callername, reg->from_name) ?
			     NULL :
			     REG_NEW_STR(call->callername);
		from_domain = REG_EQ_STR(call->caller_domain, reg->from_domain) ?
			       NULL :
			       REG_NEW_STR(call->caller_domain);
		digest_realm = REG_EQ_STR(call->digest_realm, reg->digest_realm) ?
				NULL :
				REG_NEW_STR(call->digest_realm);
		ua = REG_EQ_STR(call->a_ua, reg->ua) ?
		      NULL :
		      REG_NEW_STR(call->a_ua);
		fname = call->fname2;
		expires = call->register_expires;
		id_sensor = call->useSensorId;
	} else {
		state_from = state_to = 0;
		counter = 0;
		from_num = NULL;
		from_name = NULL;
		from_domain = NULL;
		digest_realm = NULL;
		ua = NULL;
	}
	db_id = 0;
	save_at = 0;
	save_at_counter = 0;
}

RegisterState::~RegisterState() {
	REG_FREE_STR(from_num);
	REG_FREE_STR(from_name);
	REG_FREE_STR(from_domain);
	REG_FREE_STR(digest_realm);
	REG_FREE_STR(ua);
}

void RegisterState::copyFrom(const RegisterState *src) {
	*this = *src;
	char *tmp_str;
	from_num = REG_NEW_STR(from_num);
	from_name = REG_NEW_STR(from_name);
	from_domain = REG_NEW_STR(from_domain);
	digest_realm = REG_NEW_STR(digest_realm);
	ua = REG_NEW_STR(ua);
}

bool RegisterState::isEq(Call *call, Register *reg) {
	/*
	if(state == convRegisterState(call)) cout << "ok state" << endl;
	if(REG_EQ_STR(from_num ? from_num : reg->from_num, call->caller)) cout << "ok from_num" << endl;
	if(REG_EQ_STR(from_name ? from_name : reg->from_name, call->callername)) cout << "ok from_name" << endl;
	if(REG_EQ_STR(from_domain ? from_domain : reg->from_domain, call->caller_domain)) cout << "ok from_domain" << endl;
	if(REG_EQ_STR(digest_realm ? digest_realm : reg->digest_realm, call->digest_realm)) cout << "ok digest_realm" << endl;
	if(REG_EQ_STR(ua ? ua : reg->ua, call->a_ua)) cout << "ok ua" << endl;
	*/
	return(state == convRegisterState(call) &&
	       REG_EQ_STR(from_num ? from_num : reg->from_num, call->caller) &&
	       REG_EQ_STR(from_name ? from_name : reg->from_name, call->callername) &&
	       REG_EQ_STR(from_domain ? from_domain : reg->from_domain, call->caller_domain) &&
	       REG_EQ_STR(digest_realm ? digest_realm : reg->digest_realm, call->digest_realm) &&
	       REG_EQ_STR(ua ? ua : reg->ua, call->a_ua) &&
	       fname == call->fname2 &&
	       id_sensor == call->useSensorId);
}


Register::Register(Call *call) {
	lock_id();
	id = ++_id;
	unlock_id();
	sipcallerip = call->sipcallerip[0];
	sipcalledip = call->sipcalledip[0];
	char *tmp_str;
	to_num = REG_NEW_STR(call->called);
	to_domain = REG_NEW_STR(call->called_domain);
	contact_num = REG_NEW_STR(call->contact_num);
	contact_domain = REG_NEW_STR(call->contact_domain);
	digest_username = REG_NEW_STR(call->digest_username);
	from_num = REG_NEW_STR(call->caller);
	from_name = REG_NEW_STR(call->callername);
	from_domain = REG_NEW_STR(call->caller_domain);
	digest_realm = REG_NEW_STR(call->digest_realm);
	ua = REG_NEW_STR(call->a_ua);
	for(unsigned i = 0; i < NEW_REGISTER_MAX_STATES; i++) {
		states[i] = 0;
	}
	countStates = 0;
	rrd_sum = 0;
	rrd_count = 0;
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

void Register::addState(Call *call) {
	lock_states();
	if(eqLastState(call) && convRegisterState(call) == rs_Failed) {
		updateLastState(call);
	} else {
		shiftStates();
		states[0] = new FILE_LINE RegisterState(call, this);
		++countStates;
	}
	RegisterState *state = states_last();
	if((state->state == rs_OK || state->state == rs_UnknownMessageOK) &&
	   call->regrrddiff > 0) {
		rrd_sum += call->regrrddiff;
		++rrd_count;
	}
	if(state->state == rs_Failed) {
		saveFailedToDb(state);
	} else {
		saveStateToDb(state);
		RegisterState *prevState = states_prev_last();
		if(prevState && prevState->state == rs_Failed) {
			saveFailedToDb(state, true);
		}
	}
	unlock_states();
}

void Register::shiftStates() {
	if(countStates == NEW_REGISTER_MAX_STATES) {
		delete states[NEW_REGISTER_MAX_STATES - 1];
		-- countStates;
	}
	for(unsigned i = countStates; i > 0; i--) {
		states[i] = states[i - 1];
	}
}

void Register::expire(bool need_lock_states) {
	if(need_lock_states) {
		lock_states();
	}
	RegisterState *lastState = states_last();
	if(lastState && (lastState->state == rs_OK || lastState->state == rs_UnknownMessageOK)) {
		shiftStates();
		RegisterState *newState = new FILE_LINE RegisterState(NULL, NULL);
		newState->copyFrom(lastState);
		newState->state = rs_Expired;
		newState->expires = 0;
		newState->state_from = newState->state_to = lastState->state_to + lastState->expires;
		states[0] = newState;
		++countStates;
		saveStateToDb(newState);
	}
	if(need_lock_states) {
		unlock_states();
	}
}

void Register::updateLastState(Call *call) {
	RegisterState *state = states_last();
	if(state) {
		state->state_to = call->calltime();
		++state->counter;
	}
}

bool Register::eqLastState(Call *call) {
	RegisterState *state = states_last();
	if(state && state->isEq(call, this)) {
		return(true);
	}
	return(false);
}

void Register::clean_all() {
	lock_states();
	for(unsigned i = 0; i < countStates; i++) {
		delete states[i];
	}
	countStates = 0;
	unlock_states();
}

void Register::saveStateToDb(RegisterState *state, bool enableBatchIfPossible) {
	if(opt_nocdr) {
		return;
	}
	if(!sqlDbSaveRegister) {
		sqlDbSaveRegister = createSqlObject();
		sqlDbSaveRegister->setEnableSqlStringInContent(true);
	}
	string adj_ua = REG_CONV_STR(state->ua ? state->ua : ua);
	adjustUA((char*)adj_ua.c_str());
	SqlDb_row cdr_ua;
	if(adj_ua[0]) {
		cdr_ua.add(sqlEscapeString(adj_ua), "ua");
	}
	SqlDb_row reg;
	reg.add(sqlEscapeString(sqlDateTimeString(state->state_from).c_str()), "created_at");
	reg.add(htonl(sipcallerip), "sipcallerip");
	reg.add(htonl(sipcalledip), "sipcalledip");
	reg.add(sqlEscapeString(REG_CONV_STR(state->from_num ? state->from_num : from_num)), "from_num");
	reg.add(sqlEscapeString(REG_CONV_STR(to_num)), "to_num");
	reg.add(sqlEscapeString(REG_CONV_STR(contact_num)), "contact_num");
	reg.add(sqlEscapeString(REG_CONV_STR(contact_domain)), "contact_domain");
	reg.add(sqlEscapeString(REG_CONV_STR(to_domain)), "to_domain");
	reg.add(sqlEscapeString(REG_CONV_STR(digest_username)), "digestusername");
	reg.add(state->fname, "fname");
	if(state->state == rs_Failed) {
		reg.add(state->counter, "counter");
		#if NEW_REGISTERS
		state->db_id = registers.getNewRegisterFailedId(state->id_sensor);
		#endif
		reg.add(state->db_id, "ID");
	} else {
		reg.add(state->expires, "expires");
		reg.add(state->state <= rs_Expired ? state->state : rs_OK, "state");
	}
	if(state->id_sensor > -1) {
		reg.add(state->id_sensor, "id_sensor");
	}
	string register_table = state->state == rs_Failed ? "register_failed" : "register_state";
	if(enableBatchIfPossible && isSqlDriver("mysql")) {
		string query_str;
		if(adj_ua[0]) {
			query_str += string("set @ua_id = ") +  "getIdOrInsertUA(" + sqlEscapeStringBorder(adj_ua) + ");\n";
			reg.add("_\\_'SQL'_\\_:@ua_id", "ua_id");
		}
		query_str += sqlDbSaveRegister->insertQuery(register_table, reg) + ";\n";
		static unsigned int counterSqlStore = 0;
		int storeId = STORE_PROC_ID_REGISTER_1 + 
			      (opt_mysqlstore_max_threads_register > 1 &&
			       sqlStore->getSize(STORE_PROC_ID_CDR_1) > 1000 ? 
				counterSqlStore % opt_mysqlstore_max_threads_register : 
				0);
		++counterSqlStore;
		sqlStore->query_lock(query_str.c_str(), storeId);
	} else {
		reg.add(sqlDbSaveRegister->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua), "ua_id");
		sqlDbSaveRegister->insert(register_table, reg);
	}
}

void Register::saveFailedToDb(RegisterState *state, bool force, bool enableBatchIfPossible) {
	if(state->counter == 1) {
		saveStateToDb(state);
	} else if((force || (state->state_to - state->save_at) > NEW_REGISTER_UPDATE_FAILED_PERIOD) &&
		  state->counter > state->save_at_counter) {
		if(opt_nocdr) {
			return;
		}
		if(!sqlDbSaveRegister) {
			sqlDbSaveRegister = createSqlObject();
			sqlDbSaveRegister->setEnableSqlStringInContent(true);
		}
		SqlDb_row row;
		row.add(state->counter, "counter");
		if(enableBatchIfPossible && isSqlDriver("mysql")) {
			string query_str = sqlDbSaveRegister->updateQuery("register_failed", row, 
									  ("ID = " + intToString(state->db_id)).c_str());
			static unsigned int counterSqlStore = 0;
			int storeId = STORE_PROC_ID_REGISTER_1 + 
				      (opt_mysqlstore_max_threads_register > 1 &&
				       sqlStore->getSize(STORE_PROC_ID_CDR_1) > 1000 ? 
					counterSqlStore % opt_mysqlstore_max_threads_register : 
					0);
			++counterSqlStore;
			sqlStore->query_lock(query_str.c_str(), storeId);
		} else {
			sqlDbSaveRegister->update("register_failed", row, 
						  ("ID = " + intToString(state->db_id)).c_str());
		}
	}
	state->save_at = state->state_to;
	state->save_at_counter = state->counter;
}

eRegisterState Register::getState() {
	lock_states();
	RegisterState *state = states_last();
	eRegisterState rslt_state = state ? state->state : rs_na;
	unlock_states();
	return(rslt_state);
}

bool Register::getDataRow(RegisterRecord *rec) {
	lock_states();
	RegisterState *state = states_last();
	if(!state) {
		unlock_states();
		return(false);
	}
	rec->fields[rf_id].set(id);
	rec->fields[rf_sipcallerip].set(sipcallerip);
	rec->fields[rf_sipcalledip].set(sipcalledip);
	rec->fields[rf_to_num].set(to_num);
	rec->fields[rf_to_domain].set(to_domain);
	rec->fields[rf_contact_num].set(contact_num);
	rec->fields[rf_contact_domain].set(contact_domain);
	rec->fields[rf_digestusername].set(digest_username);
	if(state->id_sensor >= 0) {
		rec->fields[rf_id_sensor].set(state->id_sensor);
	}
	rec->fields[rf_fname].set(state->fname);
	rec->fields[rf_calldate].set(state->state_from, RegisterField::tf_time);
	rec->fields[rf_from_num].set(state->from_num ? state->from_num : from_num);
	rec->fields[rf_from_name].set(state->from_name ? state->from_name : from_name);
	rec->fields[rf_from_domain].set(state->from_domain ? state->from_domain : from_domain);
	rec->fields[rf_digestrealm].set(state->digest_realm ? state->digest_realm : digest_realm);
	rec->fields[rf_expires].set(state->expires);
	rec->fields[rf_expires_at].set(state->state_from + state->expires, RegisterField::tf_time);
	rec->fields[rf_state].set(state->state);
	rec->fields[rf_ua].set(state->ua ? state->ua : ua);
	if(rrd_count) {
		rec->fields[rf_rrd_avg].set(rrd_sum / rrd_count);
	}
	unlock_states();
	return(true);
}

volatile u_int64_t Register::_id = 0;
volatile int Register::_sync_id = 0;


Registers::Registers() {
	_sync_registers = 0;
	_sync_registers_erase = 0;
	register_failed_id = 0;
	_sync_register_failed_id = 0;
	last_cleanup_time = 0;
}

Registers::~Registers() {
	clean_all();
}

void Registers::add(Call *call) {
 
	/*
	string digest_username_orig = call->digest_username;
	for(int q = 1; q <= 3; q++) {
	sprintf(call->digest_username, "%s-%i", digest_username_orig.c_str(), q);
	*/
 
	if(!convRegisterState(call)) {
		return;
	}
	Register *reg = new FILE_LINE Register(call);
	RegisterId rid(reg);
	lock_registers();
	map<RegisterId, Register*>::iterator iter = registers.find(rid);
	if(iter == registers.end()) {
		reg->addState(call);
		registers[rid] = reg;
		unlock_registers();
	} else {
		unlock_registers();
		iter->second->addState(call);
		delete reg;
	}
	
	/*
	}
	strcpy(call->digest_username, digest_username_orig.c_str());
	*/
	
	cleanup(call->calltime());
	
	/*
	eRegisterState states[] = {
		rs_OK,
		rs_UnknownMessageOK,
		rs_na
	};
	cout << getDataTableJson(states, 0, rf_calldate, false) << endl;
	*/
}

void Registers::cleanup(u_int32_t act_time) {
	if(!last_cleanup_time) {
		last_cleanup_time = act_time;
		return;
	}
	if(act_time > last_cleanup_time + NEW_REGISTER_CLEAN_PERIOD) {
		lock_registers();
		map<RegisterId, Register*>::iterator iter;
		for(iter = registers.begin(); iter != registers.end(); ) {
			Register *reg = iter->second;
			reg->lock_states();
			RegisterState *regstate = reg->states_last();
			bool eraseRegister = false;
			bool eraseRegisterFailed = false;
			if(regstate) {
				if(regstate->state == rs_OK || regstate->state == rs_UnknownMessageOK) {
					if(regstate->expires &&
					   regstate->state_to + regstate->expires < act_time) {
						reg->expire(false);
						// cout << "expire" << endl;
					}
				} else if(!_sync_registers_erase) {
					if(regstate->state == rs_Failed && reg->countStates == 1 &&
					   regstate->state_to + NEW_REGISTER_ERASE_FAILED_TIMEOUT < act_time) {
						eraseRegisterFailed = true;
						// cout << "erase failed" << endl;
					} else if(regstate->state_to + NEW_REGISTER_ERASE_TIMEOUT < act_time) {
						eraseRegister = true;
						// cout << "erase" << endl;
					}
				}
			}
			reg->unlock_states();
			if(eraseRegister || eraseRegisterFailed) {
				lock_registers_erase();
				registers.erase(iter++);
				unlock_registers_erase();
			} else {
				iter++;
			}
		}
		unlock_registers();
		last_cleanup_time = act_time;
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

u_int64_t Registers::getNewRegisterFailedId(int sensorId) {
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
	u_int64_t id = register_failed_id = ((register_failed_id / 100000 + 1) * 100000) + (sensorId >= 0 ? sensorId : 99999);
	unlock_register_failed_id();
	return(id);
}

string Registers::getDataTableJson(eRegisterState *states, u_int32_t limit, eRegisterField sortBy, bool desc, char *filter) {
	lock_registers_erase();
	lock_registers();
	
	u_int32_t list_registers_size = registers.size();
	u_int32_t list_registers_count = 0;
	Register **list_registers = new FILE_LINE Register*[list_registers_size];
	
	//cout << "**** 001 " << getTimeMS() << endl;
	
	for(map<RegisterId, Register*>::iterator iter_reg = registers.begin(); iter_reg != registers.end(); iter_reg++) {
		bool okState = false;
		if(states) {
			eRegisterState state = iter_reg->second->getState();
			for(unsigned i = 0; states[i]; i++) {
				if(states[i] == state) {
					okState = true;
					break;
				}
			}
		} else {
			okState = true;
		}
		if(okState) {
			list_registers[list_registers_count++] = iter_reg->second;
		}
	}
	
	//cout << "**** 002 " << getTimeMS() << endl;
	
	unlock_registers();
	
	list<RegisterRecord> records;
	for(unsigned i = 0; i < list_registers_count; i++) {
		RegisterRecord rec;
		if(list_registers[i]->getDataRow(&rec)) {
			rec.sortBy = sortBy;
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
		cRegisterFilter *regFilter = NULL;
		if(filter && *filter) {
			//cout << "FILTER: " << filter << endl;
			regFilter = new cRegisterFilter(filter);
			for(list<RegisterRecord>::iterator iter_rec = records.begin(); iter_rec != records.end(); ) {
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
	if(records.size()) {
		table += string(", [{\"total\": ") + intToString(records.size()) + "}]";
		if(sortBy) {
			records.sort();
		}
		list<RegisterRecord>::iterator iter_rec = desc ? records.end() : records.begin();
		if(desc) {
			iter_rec--;
		}
		u_int32_t counter = 0;
		while(counter < records.size() && iter_rec != records.end()) {
			table += "," + iter_rec->getJson();
			if(desc) {
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


void cRegisterFilterItem_base::setCodebook(const char *table, const char *column) {
	codebook_table = table;
	codebook_column = column;
}

string cRegisterFilterItem_base::getCodebookValue(u_int32_t id) {
	/*
	if(opt_nocdr) {
		return("");
	}
	*/
	SqlDb *sqlDb = createSqlObject();
	sqlDb->query("select " + codebook_column + " as value from " + codebook_table + " where id = " + intToString(id));
	SqlDb_row row = sqlDb->fetchRow();
	string rslt;
	if(row) {
		rslt = row["value"];
	}
	delete sqlDb;
	return(rslt);
}

bool cRegisterFilterItem_calldate::check(RegisterRecord *rec) {
	if((from && rec->fields[registerField].i < calldate) ||
	   (!from && rec->fields[registerField].i >= calldate)) {
		return(false);
	}
	return(true);
}

bool cRegisterFilterItem_CheckString::check(RegisterRecord *rec) {
	if(!rec->fields[registerField].s ||
	   !checkStringData.check(rec->fields[registerField].s)) {
		return(false);
	}
	return(true);
}

bool cRegisterFilterItem_IP::check(RegisterRecord *rec) {
	if(!ipData.checkIP(rec->fields[registerField].i)) {
		return(false);
	}
	return(true);
}

bool cRegisterFilterItem_numInterval::check(RegisterRecord *rec) {
	if((from && rec->fields[registerField].i < num) ||
	   (!from && rec->fields[registerField].i >= num)) {
		return(false);
	}
	return(true);
}

bool cRegisterFilterItem_numList::check(RegisterRecord *rec) {
	if(nums.size()) {
		for(list<u_int64_t>::iterator iter = nums.begin(); iter != nums.begin(); iter++) {
			if(*iter == rec->fields[registerField].i) {
				return(true);
			}
		}
		return(false);
	}
	return(true);
}

void cRegisterFilterItems::addFilter(cRegisterFilterItem_base *filter) {
	fItems.push_back(filter);
}

bool cRegisterFilterItems::check(struct RegisterRecord *rec) {
	list<cRegisterFilterItem_base*>::iterator iter;
	for(iter = fItems.begin(); iter !=fItems.end(); iter++) {
		if((*iter)->check(rec)) {
			return(true);
		}
	}
	return(false);
}

void cRegisterFilterItems::free() {
	list<cRegisterFilterItem_base*>::iterator iter;
	for(iter = fItems.begin(); iter !=fItems.end(); iter++) {
		delete *iter;
	}
}

cRegisterFilter::cRegisterFilter(char *filter) {
	JsonItem jsonData;
	jsonData.parse(filter);
	map<string, string> filterData;
	for(unsigned int i = 0; i < jsonData.getLocalCount(); i++) {
		JsonItem *item = jsonData.getLocalItem(i);
		string filterTypeName = item->getLocalName();
		string filterValue = item->getLocalValue();
		if(filterValue.empty()) {
			continue;
		}
		filterData[filterTypeName] = filterValue;
	}
	if(!filterData["calldate_from"].empty()) {
		cRegisterFilterItem_calldate *filter = new cRegisterFilterItem_calldate(rf_calldate, atol(filterData["calldate_from"].c_str()), true);
		addFilter(filter);
	}
	if(!filterData["calldate_to"].empty()) {
		cRegisterFilterItem_calldate *filter = new cRegisterFilterItem_calldate(rf_calldate, atol(filterData["calldate_to"].c_str()), false);
		addFilter(filter);
	}
	if(!filterData["sipcallerip"].empty() &&
	   filterData["sipcallerdip_type"] == "0") {
		cRegisterFilterItem_IP *filter1 =  new cRegisterFilterItem_IP(rf_sipcallerip);
		filter1->addWhite(filterData["sipcallerip"].c_str());
		cRegisterFilterItem_IP *filter2 = new cRegisterFilterItem_IP(rf_sipcalledip);
		filter2->addWhite(filterData["sipcallerip"].c_str());
		addFilter(filter1, filter2);
	} else {
		if(!filterData["sipcallerip"].empty()) {
			cRegisterFilterItem_IP *filter = new cRegisterFilterItem_IP(rf_sipcallerip);
			filter->addWhite(filterData["sipcallerip"].c_str());
			addFilter(filter);
		}
		if(!filterData["sipcalledip"].empty()) {
			cRegisterFilterItem_IP *filter = new cRegisterFilterItem_IP(rf_sipcalledip);
			filter->addWhite(filterData["sipcalledip"].c_str());
			addFilter(filter);
		}
	}
	if(!filterData["from_num"].empty() &&
	   filterData["numFTC_type"] == "0") {
		cRegisterFilterItem_CheckString *filter1 = new cRegisterFilterItem_CheckString(rf_from_num);
		filter1->addWhite(filterData["from_num"].c_str());
		cRegisterFilterItem_CheckString *filter2 = new cRegisterFilterItem_CheckString(rf_to_num);
		filter2->addWhite(filterData["from_num"].c_str());
		cRegisterFilterItem_CheckString *filter3 = new cRegisterFilterItem_CheckString(rf_contact_num);
		filter3->addWhite(filterData["from_num"].c_str());
		addFilter(filter1, filter2, filter3);
	} else {
		if(!filterData["from_num"].empty()) {
			cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(rf_from_num);
			filter->addWhite(filterData["from_num"].c_str());
			addFilter(filter);
		}
		if(!filterData["to_num"].empty()) {
			cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(rf_to_num);
			filter->addWhite(filterData["to_num"].c_str());
			addFilter(filter);
		}
		if(!filterData["contact_num"].empty()) {
			cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(rf_contact_num);
			filter->addWhite(filterData["contact_num"].c_str());
			addFilter(filter);
		}
	}
	if(!filterData["from_name"].empty()) {
		cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(rf_from_name);
		filter->addWhite(filterData["from_name"].c_str());
		addFilter(filter);
	}
	if(!filterData["from_domain"].empty() &&
	   filterData["domainFTC_type"] == "0") {
		cRegisterFilterItem_CheckString *filter1 = new cRegisterFilterItem_CheckString(rf_from_domain);
		filter1->addWhite(filterData["from_domain"].c_str());
		cRegisterFilterItem_CheckString *filter2 = new cRegisterFilterItem_CheckString(rf_to_domain);
		filter2->addWhite(filterData["from_domain"].c_str());
		cRegisterFilterItem_CheckString *filter3 = new cRegisterFilterItem_CheckString(rf_contact_domain);
		filter3->addWhite(filterData["from_domain"].c_str());
		addFilter(filter1, filter2, filter3);
	} else {
		if(!filterData["from_domain"].empty()) {
			cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(rf_from_domain);
			filter->addWhite(filterData["from_domain"].c_str());
			addFilter(filter);
		}
		if(!filterData["to_domain"].empty()) {
			cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(rf_to_domain);
			filter->addWhite(filterData["to_domain"].c_str());
			addFilter(filter);
		}
		if(!filterData["contact_domain"].empty()) {
			cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(rf_contact_domain);
			filter->addWhite(filterData["contact_domain"].c_str());
			addFilter(filter);
		}
	}
	if(!filterData["from_domain_group_id"].empty() &&
	   filterData["domainFTC_group_id_type"] == "0") {
		cRegisterFilterItem_CheckString *filter1 = new cRegisterFilterItem_CheckString(rf_from_domain);
		filter1->addWhite("cb_domain_groups", "domain", filterData["from_domain_group_id"].c_str());
		cRegisterFilterItem_CheckString *filter2 = new cRegisterFilterItem_CheckString(rf_to_domain);
		filter2->addWhite("cb_domain_groups", "domain", filterData["from_domain_group_id"].c_str());
		cRegisterFilterItem_CheckString *filter3 = new cRegisterFilterItem_CheckString(rf_contact_domain);
		filter3->addWhite("cb_domain_groups", "domain", filterData["from_domain_group_id"].c_str());
		addFilter(filter1, filter2, filter3);
	} else {
		if(!filterData["from_domain_group_id"].empty()) {
			cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(rf_from_domain);
			filter->addWhite("cb_domain_groups", "domain", filterData["from_domain_group_id"].c_str());
			addFilter(filter);
		}
		if(!filterData["to_domain_group_id"].empty()) {
			cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(rf_to_domain);
			filter->addWhite("cb_domain_groups", "domain", filterData["to_domain_group_id"].c_str());
			addFilter(filter);
		}
		if(!filterData["contact_domain_group_id"].empty()) {
			cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(rf_contact_domain);
			filter->addWhite("cb_domain_groups", "domain", filterData["contact_domain_group_id"].c_str());
			addFilter(filter);
		}
	}
	if(!filterData["digestusername"].empty()) {
		cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(rf_digestusername);
		filter->addWhite(filterData["digestusername"].c_str());
		addFilter(filter);
	}
	if(!filterData["digest_realm"].empty()) {
		cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(rf_digestrealm);
		filter->addWhite(filterData["digest_realm"].c_str());
		addFilter(filter);
	}
	if(!filterData["rrd_avg_ge"].empty()) {
		cRegisterFilterItem_numInterval *filter = new cRegisterFilterItem_numInterval(rf_rrd_avg, atol(filterData["rrd_avg_ge"].c_str()), true);
		addFilter(filter);
	}
	if(!filterData["rrd_avg_lt"].empty()) {
		cRegisterFilterItem_numInterval *filter = new cRegisterFilterItem_numInterval(rf_rrd_avg, atol(filterData["rrd_avg_lt"].c_str()), false);
		addFilter(filter);
	}
	if(!filterData["expires_ge"].empty()) {
		cRegisterFilterItem_numInterval *filter = new cRegisterFilterItem_numInterval(rf_expires, atol(filterData["expires_ge"].c_str()), true);
		addFilter(filter);
	}
	if(!filterData["expires_lt"].empty()) {
		cRegisterFilterItem_numInterval *filter = new cRegisterFilterItem_numInterval(rf_expires, atol(filterData["expires_lt"].c_str()), false);
		addFilter(filter);
	}
	if(!filterData["expires_at_from"].empty()) {
		cRegisterFilterItem_calldate *filter = new cRegisterFilterItem_calldate(rf_expires_at, atol(filterData["expires_at_from"].c_str()), true);
		addFilter(filter);
	}
	if(!filterData["expires_at_to"].empty()) {
		cRegisterFilterItem_calldate *filter = new cRegisterFilterItem_calldate(rf_expires_at, atol(filterData["expires_at_to"].c_str()), false);
		addFilter(filter);
	}
	if(!filterData["ua"].empty()) {
		cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(rf_ua);
		filter->addWhite(filterData["ua"].c_str());
		addFilter(filter);
	}
	if(!filterData["ua_group_id"].empty()) {
		cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(rf_ua);
		filter->addWhite("cb_ua_groups", "ua", filterData["ua_group_id"].c_str());
		addFilter(filter);
	}
	if(!filterData["sensor_id"].empty()) {
		cRegisterFilterItem_numList *filter = new cRegisterFilterItem_numList(rf_id_sensor);
		filter->addNum(atol(filterData["sensor_id"].c_str()));
		addFilter(filter);
	}
}

cRegisterFilter::~cRegisterFilter() {
	list<cRegisterFilterItems>::iterator iter;
	for(iter = fItems.begin(); iter !=fItems.end(); iter++) {
		iter->free();
	}
}

void cRegisterFilter::addFilter(cRegisterFilterItem_base *filter1, cRegisterFilterItem_base *filter2, cRegisterFilterItem_base *filter3) {
	cRegisterFilterItems fSubItems;
	fSubItems.addFilter(filter1);
	if(filter2) {
		fSubItems.addFilter(filter2);
	}
	if(filter3) {
		fSubItems.addFilter(filter3);
	}
	fItems.push_back(fSubItems);
}

bool cRegisterFilter::check(struct RegisterRecord *rec) {
	list<cRegisterFilterItems>::iterator iter;
	for(iter = fItems.begin(); iter !=fItems.end(); iter++) {
		if(!iter->check(rec)) {
			return(false);
		}
	}
	return(true);
}


eRegisterState convRegisterState(Call *call) {
	return(call->msgcount <= 1 ||
	       call->lastSIPresponseNum == 401 || call->lastSIPresponseNum == 403 || call->lastSIPresponseNum == 404 ?
		rs_Failed :
	       call->regstate == 1 && !call->register_expires ?
		rs_Unregister :
		(eRegisterState)call->regstate);
}

eRegisterField convRegisterFieldToFieldId(const char *field) {
	for(unsigned i = 0; i < sizeof(registerFields) / sizeof(registerFields[0]); i++) {
		if(!strcmp(field, registerFields[i].fieldName)) {
			return(registerFields[i].filedType);
		}
	}
	return((eRegisterField)0);
}
