#include <syslog.h>
#include <string.h>
#include "voipmonitor.h"

#include "filter_mysql.h"
#include "calltable.h"
#include "odbc.h"
#include "sql_db.h"
#include <math.h>
#include <vector>

using namespace std;

extern int opt_nocdr;


bool is_number(const std::string& s) {
	for (unsigned int i = 0; i < s.length(); i++) {
		if (!std::isdigit(s[i]))
			return false;
		}
	return true;
}

bool isStringNull(string &str) {
	return(str == "" || str == "\\N");
}

void filter_base::loadBaseDataRow(SqlDb_row *sqlRow, filter_db_row_base *baseRow) {
	baseRow->direction = sqlRow->isNull("direction") ? 0 : atoi((*sqlRow)["direction"].c_str());
	baseRow->rtp = sqlRow->isNull("rtp") ? -1 : atoi((*sqlRow)["rtp"].c_str());
	baseRow->rtcp = sqlRow->isNull("rtcp") ? -1 : atoi((*sqlRow)["rtcp"].c_str());
	baseRow->sip = sqlRow->isNull("sip") ? -1 : atoi((*sqlRow)["sip"].c_str());
	baseRow->reg = sqlRow->isNull("register") ? -1 : atoi((*sqlRow)["register"].c_str());
	baseRow->dtmf = sqlRow->isNull("dtmf") ? -1 : atoi((*sqlRow)["dtmf"].c_str());
	baseRow->graph = sqlRow->isNull("graph") ? -1 : atoi((*sqlRow)["graph"].c_str());
	baseRow->wav = sqlRow->isNull("wav") ? -1 : atoi((*sqlRow)["wav"].c_str());
	baseRow->skip = sqlRow->isNull("skip") ? -1 : atoi((*sqlRow)["skip"].c_str());
	baseRow->script = sqlRow->isNull("script") ? -1 : atoi((*sqlRow)["script"].c_str());
	baseRow->mos_lqo = sqlRow->isNull("mos_lqo") ? -1 : atoi((*sqlRow)["mos_lqo"].c_str());
	baseRow->hide_message = sqlRow->isNull("hide_message") ? -1 : atoi((*sqlRow)["hide_message"].c_str());
	baseRow->spool_2 = sqlRow->isNull("spool_2") ? 0 : atoi((*sqlRow)["spool_2"].c_str());
}

void filter_base::loadBaseDataRow(map<string, string> *row, filter_db_row_base *baseRow) {
	baseRow->direction = isStringNull((*row)["direction"]) ? 0 : atoi((*row)["direction"].c_str());
	baseRow->rtp = isStringNull((*row)["rtp"]) ? -1 : atoi((*row)["rtp"].c_str());
	baseRow->rtcp = isStringNull((*row)["rtcp"]) ? -1 : atoi((*row)["rtcp"].c_str());
	baseRow->sip = isStringNull((*row)["sip"]) ? -1 : atoi((*row)["sip"].c_str());
	baseRow->reg = isStringNull((*row)["register"]) ? -1 : atoi((*row)["register"].c_str());
	baseRow->dtmf = isStringNull((*row)["dtmf"]) ? -1 : atoi((*row)["dtmf"].c_str());
	baseRow->graph = isStringNull((*row)["graph"]) ? -1 : atoi((*row)["graph"].c_str());
	baseRow->wav = isStringNull((*row)["wav"]) ? -1 : atoi((*row)["wav"].c_str());
	baseRow->skip = isStringNull((*row)["skip"]) ? -1 : atoi((*row)["skip"].c_str());
	baseRow->script = isStringNull((*row)["script"]) ? -1 : atoi((*row)["script"].c_str());
	baseRow->mos_lqo = isStringNull((*row)["mos_lqo"]) ? -1 : atoi((*row)["mos_lqo"].c_str());
	baseRow->hide_message = isStringNull((*row)["hide_message"]) ? -1 : atoi((*row)["hide_message"].c_str());
	baseRow->spool_2 = isStringNull((*row)["spool_2"]) ? 0 : atoi((*row)["spool_2"].c_str());
}

unsigned int filter_base::getFlagsFromBaseData(filter_db_row_base *baseRow) {
	unsigned int flags = 0;
	
	if(baseRow->rtp == 1)			flags |= FLAG_RTP_ALL;
	else if(baseRow->rtp == 2)		flags |= FLAG_RTP_HEAD;
	else if(baseRow->rtp == 0)		flags |= FLAG_NORTP;
	
	if(baseRow->rtcp == 1)			flags |= FLAG_RTCP;
	else if(baseRow->rtcp == 0)		flags |= FLAG_NORTCP;
	
	if(baseRow->sip == 1)			flags |= FLAG_SIP;
	else if(baseRow->sip == 0)		flags |= FLAG_NOSIP;
	
	if(baseRow->reg == 1)			flags |= FLAG_REGISTER;
	else if(baseRow->reg == 0)		flags |= FLAG_NOREGISTER;

	if(baseRow->dtmf == 1)			flags |= FLAG_DTMF;
	else if(baseRow->dtmf == 0)		flags |= FLAG_NODTMF;
	
	if(baseRow->graph == 1)			flags |= FLAG_GRAPH;
	else if(baseRow->graph == 0)		flags |= FLAG_NOGRAPH;
	
	if(baseRow->wav == 1)			flags |= FLAG_AUDIO;
	else if(baseRow->wav == 2)		flags |= FLAG_AUDIO_WAV;
	else if(baseRow->wav == 3)		flags |= FLAG_AUDIO_OGG;
	else if(baseRow->wav == 0)		flags |= FLAG_NOWAV;
	
	if(baseRow->skip == 1)			flags |= FLAG_SKIP;
	else if(baseRow->skip == 0)		flags |= FLAG_NOSKIP;
	
	if(baseRow->script == 1)		flags |= FLAG_SCRIPT;
	else if(baseRow->script == 0)		flags |= FLAG_NOSCRIPT;
	
	if(baseRow->mos_lqo == 1)		flags |= FLAG_AMOSLQO;
	else if(baseRow->mos_lqo == 2)		flags |= FLAG_BMOSLQO;
	else if(baseRow->mos_lqo == 3)		flags |= FLAG_ABMOSLQO;
	else if(baseRow->mos_lqo == 0)		flags |= FLAG_NOMOSLQO;
	
	if(baseRow->hide_message == 1)		flags |= FLAG_HIDEMSG;
	else if(baseRow->hide_message == 0)	flags |= FLAG_SHOWMSG;
	
	if(baseRow->spool_2)			flags |= FLAG_SPOOL_2;
	
	return(flags);
}

void filter_base::setCallFlagsFromFilterFlags(volatile unsigned int *callFlags, unsigned int filterFlags) {
	if(filterFlags & FLAG_RTP_ALL)					{*callFlags |= FLAG_SAVERTP; *callFlags &= ~FLAG_SAVERTPHEADER;}
	if(filterFlags & FLAG_RTP_HEAD)					{*callFlags |= FLAG_SAVERTPHEADER; *callFlags &= ~FLAG_SAVERTP;}
	if(filterFlags & FLAG_NORTP) 					{*callFlags &= ~FLAG_SAVERTP; *callFlags &= ~FLAG_SAVERTPHEADER;}
	
	if(filterFlags & FLAG_RTCP)					*callFlags |= FLAG_SAVERTCP;
	if(filterFlags & FLAG_NORTCP)					*callFlags &= ~FLAG_SAVERTCP;
	
	if(filterFlags & FLAG_SIP)					*callFlags |= FLAG_SAVESIP;
	if(filterFlags & FLAG_NOSIP)					*callFlags &= ~FLAG_SAVESIP;
	
	if(filterFlags & FLAG_REGISTER)					*callFlags |= FLAG_SAVEREGISTER;
	if(filterFlags & FLAG_NOREGISTER)				*callFlags &= ~FLAG_SAVEREGISTER;

	if(filterFlags & FLAG_DTMF)					*callFlags |= FLAG_SAVEDTMF;
	if(filterFlags & FLAG_NODTMF)					*callFlags &= ~FLAG_SAVEDTMF;
	
	if(filterFlags & FLAG_AUDIO)					*callFlags |= FLAG_SAVEAUDIO;
	if(filterFlags & FLAG_AUDIO_WAV)				{*callFlags |= FLAG_SAVEAUDIO_WAV; *callFlags &= ~FLAG_FORMATAUDIO_OGG;}
	if(filterFlags & FLAG_AUDIO_OGG)				{*callFlags |= FLAG_SAVEAUDIO_OGG; *callFlags &= ~FLAG_FORMATAUDIO_WAV;}
	if(filterFlags & FLAG_NOWAV)					*callFlags &= ~FLAG_SAVEAUDIO;
	
	if(filterFlags & FLAG_GRAPH)					*callFlags |= FLAG_SAVEGRAPH;
	if(filterFlags & FLAG_NOGRAPH)					*callFlags &= ~FLAG_SAVEGRAPH;
	
	if(filterFlags & FLAG_SKIP)					*callFlags |= FLAG_SKIPCDR;
	if(filterFlags & FLAG_NOSKIP)					*callFlags &= ~FLAG_SKIPCDR;
	
	if(filterFlags & FLAG_SCRIPT)					*callFlags |= FLAG_RUNSCRIPT;
	if(filterFlags & FLAG_NOSCRIPT)					*callFlags &= ~FLAG_RUNSCRIPT;

	if(filterFlags & FLAG_AMOSLQO)					{*callFlags |= FLAG_RUNAMOSLQO; *callFlags &= ~FLAG_RUNBMOSLQO;}
	if(filterFlags & FLAG_BMOSLQO)					{*callFlags |= FLAG_RUNBMOSLQO; *callFlags &= ~FLAG_RUNAMOSLQO;}
	if(filterFlags & FLAG_ABMOSLQO)					{*callFlags |= FLAG_RUNAMOSLQO|FLAG_RUNBMOSLQO;}
	if(filterFlags & FLAG_NOMOSLQO) 				{*callFlags &= ~FLAG_RUNAMOSLQO; *callFlags &= ~FLAG_RUNBMOSLQO;}
	
	if(filterFlags & FLAG_HIDEMSG)					*callFlags |= FLAG_HIDEMESSAGE;
	if(filterFlags & FLAG_SHOWMSG)					*callFlags &= ~FLAG_HIDEMESSAGE;
	
	if(filterFlags & FLAG_SPOOL_2)					*callFlags |= FLAG_USE_SPOOL_2;
}

/* IPfilter class */

// constructor
IPfilter::IPfilter() {
	first_node = NULL;
	count = 0;
};

// destructor
IPfilter::~IPfilter() {
	t_node *node = first_node;
	while(node != NULL) {
		t_node *node_next = node->next;
		delete node;
		node = node_next;
	}
};

void IPfilter::load(SqlDb *sqlDb) {
	if(opt_nocdr || is_sender() || is_client_packetbuffer_sender()) {
		return;
	}
	vector<db_row> vectDbRow;
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	sqlDb->query("SELECT * FROM filter_ip");
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	SqlDb_row row;
	while((row = rows.fetchRow())) {
		count++;
		db_row* filterRow = new FILE_LINE(4001) db_row;
		filterRow->ip = (unsigned int)strtoul(row["ip"].c_str(), NULL, 0);
		filterRow->mask = atoi(row["mask"].c_str());
		this->loadBaseDataRow(&row, filterRow);
		vectDbRow.push_back(*filterRow);
		delete filterRow;
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	t_node *node;
	for (size_t i = 0; i < vectDbRow.size(); ++i) {
		node = new(t_node);
		node->direction = vectDbRow[i].direction;
		node->flags = this->getFlagsFromBaseData(&vectDbRow[i]);
		node->next = NULL;
		node->ip = vectDbRow[i].ip;
		node->mask = vectDbRow[i].mask;

		// add node to the first position
		node->next = first_node;
		first_node = node;
	}
};

int IPfilter::_add_call_flags(volatile unsigned int *flags, unsigned int saddr, unsigned int daddr) {
	
	if (this->count == 0) {
		// no filters, return 
		return 0;
	}

	int last_mask = 0;
	char found = 0;

	t_node *node;
	long double mask;
	for(node = first_node; node != NULL; node = node->next) {

		mask = (pow(2, (long double)(node->mask)) - 1) * pow(2, (long double)(32 - node->mask));

		unsigned int origflags = *flags;

		if(((node->direction == 0 or node->direction == 2) and ((daddr & (unsigned int)mask) == (node->ip & (unsigned int)mask))) || 
			((node->direction == 0 or node->direction == 1) and ((saddr & (unsigned int)mask) == (node->ip & (unsigned int)mask)))) {

			*flags = origflags;
		
			if(node->mask < last_mask) {
				// continue 
				last_mask = node->mask;
				continue;
			}
	
			last_mask = node->mask;
			
			this->setCallFlagsFromFilterFlags(flags, node->flags);

			found = 1;
		}
	}

	return found;
}

void IPfilter::dump() {
	t_node *node;
	for(node = first_node; node != NULL; node = node->next) {
		printf("ip[%u] mask[%d] flags[%u]\n", node->ip, node->mask, node->flags);
	}
}

void IPfilter::dump2man(ostringstream &oss) {
	t_node *node;
	char ip[16];
	lock();
	for(node = filter_active->first_node; node != NULL; node = node->next) {
		ntoa(ip, ntohl(node->ip));
		oss << "ip[" << ip << "/" << node->mask << "] direction[" << node->direction << "] flags[0x" << hex << node->flags << "]" << endl;
	}
	unlock();
}

int IPfilter::add_call_flags(volatile unsigned int *flags, unsigned int saddr, unsigned int daddr, bool enableReload) {
	int rslt = 0;
	if(enableReload && reload_do) {
		applyReload();
	}
	lock();
	if(filter_active) {
		rslt = filter_active->_add_call_flags(flags, saddr, daddr);
	}
	unlock();
	return(rslt);
}

void IPfilter::loadActive(SqlDb *sqlDb) {
	lock();
	filter_active = new FILE_LINE(4002) IPfilter();
	filter_active->load(sqlDb);
	unlock();
}

void IPfilter::freeActive() {
	lock();
	if(filter_active) {
		delete filter_active;
		filter_active = NULL;
	}
	unlock();
}

void IPfilter::prepareReload() {
	reload_do = false;
	lock_reload();
	if(filter_reload) {
		delete filter_reload;
	}
	filter_reload = new FILE_LINE(4003) IPfilter;
	filter_reload->load();
	reload_do = 1;
	syslog(LOG_NOTICE, "IPfilter::prepareReload");
	unlock_reload();
}

void IPfilter::applyReload() {
	if(reload_do) {
		lock_reload();
		lock();
		delete filter_active;
		filter_active = filter_reload;
		unlock();
		filter_reload = NULL;
		reload_do = false;
		syslog(LOG_NOTICE, "IPfilter::applyReload");
		unlock_reload();
	}
}

IPfilter *IPfilter::filter_active = NULL;
IPfilter *IPfilter::filter_reload = NULL;
volatile bool IPfilter::reload_do = 0;
volatile int IPfilter::_sync = 0;
volatile int IPfilter::_sync_reload = 0;

/* TELNUMfilter class */

// constructor
TELNUMfilter::TELNUMfilter() {
        first_node = new(t_node_tel);
        first_node->payload = NULL;
        for(int i = 0; i < 256; i++) {
                first_node->nodes[i] = NULL;
	}
	count = 0;
};

// destructor
TELNUMfilter::~TELNUMfilter() {
        // je nutne uvolnit t_payload strukturu a t_node
        // algoritmus musi projit strom a postupne odmazavat za pomoci fronty
        // (prohledavani do sirky)
        //
        // do fronty se prida first_node
        // DO WHILE (dokud neni prazdna fronta )
        //      pro kazdy prvek se projdou naslednici a zaradi se nakonec fronty
        //      zpracovavany t_node se odstrani ze predu fronty a uvolni se pamet
        // ENDWHILE

        deque<t_node_tel*> fronta;
        fronta.push_back(first_node);
        t_node_tel *node;
        while( !fronta.empty() ) {
                node = fronta.front();
                if(node->payload) {
                        // nektera cisla nemaji payload
                        delete(node->payload);
                }

                for(int i = 0; i < 256; i++) {
                        if(node->nodes[i]) {
                                // vsichni nenulovi naslednici zaradime na konec fronty
                                fronta.push_back(node->nodes[i]);
                        }
                }
                //otce muzeme vymazat z fronty a nasledne dealokovat pamet
                fronta.pop_front();
                delete(node);
        }
};

void TELNUMfilter::add_payload(t_payload *payload) {
	t_node_tel *tmp = first_node;

	for(unsigned int i = 0; i < strlen(payload->prefix); i++) {
		if(!tmp->nodes[(int)payload->prefix[i]]) {
			t_node_tel *node = new(t_node_tel);
			node->payload = NULL;
			for(int j = 0; j < 256; j++) {
				node->nodes[j] = NULL;
			}
			tmp->nodes[(int)payload->prefix[i]] = node;
		}
		tmp = tmp->nodes[(int)payload->prefix[i]];      // shift

	}

	tmp->payload = payload;
};


void TELNUMfilter::load(SqlDb *sqlDb) {
	this->loadFile();
	if(opt_nocdr || is_sender() || is_client_packetbuffer_sender()) {
		return;
	}
	vector<db_row> vectDbRow;
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	sqlDb->query("SELECT * FROM filter_telnum");
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	SqlDb_row row;
	while((row = rows.fetchRow())) {
		count++;
		db_row* filterRow = new(db_row);
		strcpy_null_term(filterRow->prefix, trim_str(row["prefix"]).c_str());
		this->loadBaseDataRow(&row, filterRow);
		vectDbRow.push_back(*filterRow);
		delete filterRow;
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	for (size_t i = 0; i < vectDbRow.size(); ++i) {
		t_payload *np = new(t_payload);
		np->direction = vectDbRow[i].direction;
		np->flags = this->getFlagsFromBaseData(&vectDbRow[i]);;
		strcpy_null_term(np->prefix, vectDbRow[i].prefix);
		add_payload(np);
	}
};

void TELNUMfilter::loadFile() {
	extern char opt_capture_rules_telnum_file[1024];
	if(is_sender() || is_client_packetbuffer_sender() || !opt_capture_rules_telnum_file[0]) {
		return;
	}
	cCsv csv;
	csv.setFirstRowContainFieldNames();
	csv.load(opt_capture_rules_telnum_file);
	unsigned rowsCount = csv.getRowsCount();
	vector<db_row> vectDbRow;
	for(unsigned i = 1; i <= rowsCount; i++) {
		map<string, string> row;
		csv.getRow(i, &row);
		count++;
		db_row* filterRow = new(db_row);
		strcpy_null_term(filterRow->prefix, trim_str(row["prefix"]).c_str());
		this->loadBaseDataRow(&row, filterRow);
		vectDbRow.push_back(*filterRow);
		delete filterRow;
	}
	for (size_t i = 0; i < vectDbRow.size(); ++i) {
		t_payload *np = new(t_payload);
		np->direction = vectDbRow[i].direction;
		np->flags = this->getFlagsFromBaseData(&vectDbRow[i]);
		strcpy_null_term(np->prefix, vectDbRow[i].prefix);
		add_payload(np);
	}
}

int TELNUMfilter::_add_call_flags(volatile unsigned int *flags, char *telnum_src, char *telnum_dst) {

	int lastdirection = 0;
	
	if (this->count == 0) {
		// no filters, return 
		return 0;
	}

        //search src telnum
        t_node_tel *tmp = first_node;
        t_payload *lastpayload = NULL;
        for(unsigned int i = 0; i < strlen(telnum_src); i++) {
		unsigned char checkChar = telnum_src[i];
		if(checkChar == '%' && !strncmp(telnum_src + i, "%23", 3)) {
			checkChar = '#';
			i += 2;
		}
                if(!tmp->nodes[checkChar]) {
                        break;
                }
                tmp = tmp->nodes[checkChar];
                if(tmp && tmp->payload) {
			lastdirection = tmp->payload->direction;
                        lastpayload = tmp->payload;
                }
        }
	if(lastdirection == 2) {
		//src found but we want only dst 
		lastpayload = NULL;
	}
	if(!lastpayload) {
		tmp = first_node;
		lastpayload = NULL;
		//src not found or src found , try dst
		for(unsigned int i = 0; i < strlen(telnum_dst); i++) {
			unsigned char checkChar = telnum_dst[i];
			if(checkChar == '%' && !strncmp(telnum_dst + i, "%23", 3)) {
				checkChar = '#';
				i += 2;
			}
			if(!tmp->nodes[checkChar]) {
				break;
			}
			tmp = tmp->nodes[checkChar];
			if(tmp && tmp->payload) {
				lastdirection = tmp->payload->direction;
				lastpayload = tmp->payload;
			}
		}
		if(lastdirection == 1) {
			// dst found but we want only src
			lastpayload = NULL;
		}
	}

        if(lastpayload) {
		this->setCallFlagsFromFilterFlags(flags, lastpayload->flags);
		return 1;
        }

	return 0;
}

void TELNUMfilter::dump(t_node_tel *node) {
	if(!node) {
		node = first_node;
	}
	if(node->payload) {
		printf("prefix[%s] flags[%u]\n", node->payload->prefix, node->payload->flags);
	}
	for(int i = 0; i < 256; i++) {
		if(node->nodes[i]) {
			this->dump(node->nodes[i]);
		}
	}
}

void TELNUMfilter::dump2man(ostringstream &oss, t_node_tel *node) {
	if(!node) {
		lock();
		node = filter_active->first_node;
	}
	if(node->payload) {
		oss << "prefix[" << node->payload->prefix << "] direction[" << node->payload->direction << "] flags[0x" << hex << node->payload->flags << "]" << endl;
	}
	for(int i = 0; i < 256; i++) {
		if(node->nodes[i]) {
			dump2man(oss, node->nodes[i]);
		}
	}
	if (node == filter_active->first_node)
		unlock();
}

int TELNUMfilter::add_call_flags(volatile unsigned int *flags, char *telnum_src, char *telnum_dst, bool enableReload) {
	int rslt = 0;
	if(enableReload && reload_do) {
		applyReload();
	}
	lock();
	if(filter_active) {
		rslt = filter_active->_add_call_flags(flags, telnum_src, telnum_dst);
	}
	unlock();
	return(rslt);
}

void TELNUMfilter::loadActive(SqlDb *sqlDb) {
	lock();
	filter_active = new FILE_LINE(4004) TELNUMfilter();
	filter_active->load(sqlDb);
	unlock();
}

void TELNUMfilter::freeActive() {
	lock();
	if(filter_active) {
		delete filter_active;
		filter_active = NULL;
	}
	unlock();
}

void TELNUMfilter::prepareReload() {
	reload_do = false;
	lock_reload();
	if(filter_reload) {
		delete filter_reload;
	}
	filter_reload = new FILE_LINE(4005) TELNUMfilter;
	filter_reload->load();
	reload_do = 1;
	syslog(LOG_NOTICE, "TELNUMfilter::prepareReload");
	unlock_reload();
}

void TELNUMfilter::applyReload() {
	if(reload_do) {
		lock_reload();
		lock();
		delete filter_active;
		filter_active = filter_reload;
		unlock();
		filter_reload = NULL;
		reload_do = false; 
		syslog(LOG_NOTICE, "TELNUMfilter::applyReload");
		unlock_reload();
	}
}

TELNUMfilter *TELNUMfilter::filter_active = NULL;
TELNUMfilter *TELNUMfilter::filter_reload = NULL;
volatile bool TELNUMfilter::reload_do = 0;
volatile int TELNUMfilter::_sync = 0;
volatile int TELNUMfilter::_sync_reload = 0;

/* DOMAINfilter class */

// constructor
DOMAINfilter::DOMAINfilter() {
	first_node = NULL;
	count = 0;
};

// destructor
DOMAINfilter::~DOMAINfilter() {
	t_node *node = first_node;
	while(node != NULL) {
		t_node *node_next = node->next;
		delete node;
		node = node_next;
	}
};

void DOMAINfilter::load(SqlDb *sqlDb) {
	if(opt_nocdr || is_sender() || is_client_packetbuffer_sender()) {
		return;
	}
	vector<db_row> vectDbRow;
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	sqlDb->query("SELECT * FROM filter_domain");
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	SqlDb_row row;
	while((row = rows.fetchRow())) {
		count++;
		db_row* filterRow = new FILE_LINE(4006) db_row;
		filterRow->domain = trim_str(row["domain"]);
		this->loadBaseDataRow(&row, filterRow);
		vectDbRow.push_back(*filterRow);
		delete filterRow;
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	t_node *node;
	for (size_t i = 0; i < vectDbRow.size(); ++i) {
		node = new(t_node);
		node->direction = vectDbRow[i].direction;
		node->flags = this->getFlagsFromBaseData(&vectDbRow[i]);
		node->next = NULL;
		node->domain = vectDbRow[i].domain;

		// add node to the first position
		node->next = first_node;
		first_node = node;
	}
};

int
DOMAINfilter::_add_call_flags(volatile unsigned int *flags, char *domain_src, char *domain_dst) {
	
	if (this->count == 0) {
		// no filters, return 
		return 0;
	}

	t_node *node;
	for(node = first_node; node != NULL; node = node->next) {

		if(((node->direction == 0 or node->direction == 2) and (domain_dst == node->domain)) || 
			((node->direction == 0 or node->direction == 1) and (domain_src == node->domain))) {
			this->setCallFlagsFromFilterFlags(flags, node->flags);
			return 1;
		}
	}

	return 0;
}

void DOMAINfilter::dump() {
	t_node *node;
	for(node = first_node; node != NULL; node = node->next) {
		printf("domain[%s] flags[%u]\n", node->domain.c_str(), node->flags);
	}
}

void DOMAINfilter::dump2man(ostringstream &oss) {
	t_node *node;
	lock();
	for(node = filter_active->first_node; node != NULL; node = node->next) {
		oss << "domain[" << node->domain << "] direction[" << node->direction << "] flags[0x" << hex << node->flags << "]" << endl;
	}
	unlock();
}

int DOMAINfilter::add_call_flags(volatile unsigned int *flags, char *domain_src, char *domain_dst, bool enableReload) {
	int rslt = 0;
	if(enableReload && reload_do) {
		applyReload();
	}
	lock();
	if(filter_active) {
		rslt = filter_active->_add_call_flags(flags, domain_src, domain_dst);
	}
	unlock();
	return(rslt);
}

void DOMAINfilter::loadActive(SqlDb *sqlDb) {
	lock();
	filter_active = new FILE_LINE(4007) DOMAINfilter();
	filter_active->load(sqlDb);
	unlock();
}

void DOMAINfilter::freeActive() {
	lock();
	if(filter_active) {
		delete filter_active;
		filter_active = NULL;
	}
	unlock();
}

void DOMAINfilter::prepareReload() {
	reload_do = false;
	lock_reload();
	if(filter_reload) {
		delete filter_reload;
	}
	filter_reload = new FILE_LINE(4008) DOMAINfilter;
	filter_reload->load();
	reload_do = 1;
	syslog(LOG_NOTICE, "DOMAINfilter::prepareReload");
	unlock_reload();
}

void DOMAINfilter::applyReload() {
	if(reload_do) {
		lock_reload();
		lock();
		delete filter_active;
		filter_active = filter_reload;
		unlock();
		filter_reload = NULL;
		reload_do = false; 
		syslog(LOG_NOTICE, "DOMAINfilter::applyReload");
		unlock_reload();
	}
}

DOMAINfilter *DOMAINfilter::filter_active = NULL;
DOMAINfilter *DOMAINfilter::filter_reload = NULL;
volatile bool DOMAINfilter::reload_do = 0;
volatile int DOMAINfilter::_sync = 0;
volatile int DOMAINfilter::_sync_reload = 0;

/* SIP_HEADERfilter class */

// constructor
SIP_HEADERfilter::SIP_HEADERfilter() {
	count = 0;
	loadTime = 0;
}

// destructor
SIP_HEADERfilter::~SIP_HEADERfilter() {
}

void SIP_HEADERfilter::load(SqlDb *sqlDb) {
	if(opt_nocdr || is_sender() || is_client_packetbuffer_sender()) {
		return;
	}
	vector<db_row> vectDbRow;
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	sqlDb->query("SELECT * FROM filter_sip_header");
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	SqlDb_row row;
	while((row = rows.fetchRow())) {
		count++;
		db_row* filterRow = new FILE_LINE(4009) db_row;
		filterRow->header = trim_str(row["header"]);
		filterRow->content = trim_str(row["content"]);
		filterRow->prefix = row["content_type"] == "prefix";
		filterRow->regexp = row["content_type"] == "regexp";
		this->loadBaseDataRow(&row, filterRow);
		vectDbRow.push_back(*filterRow);
		delete filterRow;
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	for (size_t i = 0; i < vectDbRow.size(); ++i) {
		item_data item;
		item.direction = 0;
		item.prefix = vectDbRow[i].prefix;
		item.regexp = vectDbRow[i].regexp;
		item.flags = this->getFlagsFromBaseData(&vectDbRow[i]);
		if(item.regexp) {
			data[vectDbRow[i].header].regexp[vectDbRow[i].content] = item;
		} else {
			data[vectDbRow[i].header].strict_prefix[vectDbRow[i].content] = item;
		}
		++count;
	}
	loadTime = getTimeMS();
	if(sverb.capture_filter) {
		syslog(LOG_NOTICE, "SIP_HEADERfilter::load");
	}
}

int SIP_HEADERfilter::_add_call_flags(ParsePacket::ppContentsX *parseContents, volatile unsigned int *flags) {
	
	if (this->count == 0) {
		// no filters, return 
		return 0;
	}
	
	for(map<std::string, header_data>::iterator it_header = this->data.begin(); it_header != this->data.end(); it_header++) {
		header_data *data = &it_header->second;
		string content = parseContents->getContentString((it_header->first + ":").c_str());
		if(content.empty()) {
			continue;
		}
		if(data->strict_prefix.size()) {
			map<std::string, item_data>::iterator it_content = data->strict_prefix.lower_bound(content);
			if(it_content != data->strict_prefix.end() &&
			   it_content->first == content) {
				this->setCallFlagsFromFilterFlags(flags, it_content->second.flags);
				if(sverb.capture_filter) {
					syslog(LOG_NOTICE, "SIP_HEADERfilter::add_call_flags - strict (eq) : %s",  it_content->first.c_str());
				}
				return 1;
			}
			if(it_content != data->strict_prefix.begin()) {
				--it_content;
			}
			if(it_content->second.prefix &&
			   !strncmp(it_content->first.c_str(), content.c_str(), it_content->first.length())) {
				this->setCallFlagsFromFilterFlags(flags, it_content->second.flags);
				if(sverb.capture_filter) {
					syslog(LOG_NOTICE, "SIP_HEADERfilter::add_call_flags - prefix : %s",  it_content->first.c_str());
				}
				return 1;
			}
		}
		if(data->regexp.size()) {
			for(map<std::string, item_data>::iterator it_content = data->regexp.begin(); it_content != data->regexp.end(); it_content++) {
				if(reg_match(content.c_str(), it_content->first.c_str(), __FILE__, __LINE__)) {
					this->setCallFlagsFromFilterFlags(flags, it_content->second.flags);
					if(sverb.capture_filter) {
						syslog(LOG_NOTICE, "SIP_HEADERfilter::add_call_flags - regexp : %s",  it_content->first.c_str());
					}
					return 1;
				}
			}
		}
	 
	}
	
	return 0;
}

void SIP_HEADERfilter::dump() {
	for(map<std::string, header_data>::iterator it_header = this->data.begin(); it_header != this->data.end(); it_header++) {
		header_data *data = &it_header->second;
		for(map<std::string, item_data>::iterator it_content = data->regexp.begin(); it_content != data->regexp.end(); it_content++) {
			printf("header[%s] content[%s] regexp[0] prefix[%u] flags[%u]\n", it_header->first.c_str(), it_content->first.c_str(), it_content->second.prefix, it_content->second.flags);
		}
		for(map<std::string, item_data>::iterator it_content = data->regexp.begin(); it_content != data->regexp.end(); it_content++) {
			printf("header[%s] content[%s] regexp[1] prefix[0] flags[%u]\n", it_header->first.c_str(), it_content->first.c_str(), it_content->second.flags);
		}
	}
}

void SIP_HEADERfilter::dump2man(ostringstream &oss) {
	lock();
	for(map<std::string, header_data>::iterator it_header = filter_active->data.begin(); it_header != filter_active->data.end(); it_header++) {
		header_data *data = &it_header->second;
		for(map<std::string, item_data>::iterator it_content = data->regexp.begin(); it_content != data->regexp.end(); it_content++) {
			oss << "Regex header[" << it_header->first << "] content[" << it_content->first << "] direction[" << it_content->second.direction << "] flags[0x" << hex << it_content->second.flags << "]" << endl;
		}
		for(map<std::string, item_data>::iterator it_content = data->strict_prefix.begin(); it_content != data->strict_prefix.end(); it_content++) {
			oss << "Prefix header[" << it_header->first << "] content[" << it_content->first << "] direction[" << it_content->second.direction << "] flags[0x" << hex << it_content->second.flags << "]" << endl;
		}
	}
	unlock();
}

void SIP_HEADERfilter::_addNodes(ParsePacket *parsePacket) {
	for(map<std::string, header_data>::iterator it_header = this->data.begin(); it_header != this->data.end(); it_header++) {
		parsePacket->addNode((it_header->first + ":").c_str(), ParsePacket::typeNode_custom);
	}
}

int SIP_HEADERfilter::add_call_flags(ParsePacket::ppContentsX *parseContents, volatile unsigned int *flags, bool enableReload) {
	int rslt = 0;
	if(enableReload && reload_do) {
		applyReload();
	}
	lock();
	if(filter_active) {
		rslt = filter_active->_add_call_flags(parseContents, flags);
	}
	unlock();
	return(rslt);
}

void SIP_HEADERfilter::addNodes(ParsePacket *parsePacket) {
	if(reload_do) {
		applyReload();
	}
	lock();
	if(filter_active) {
		filter_active->_addNodes(parsePacket);
	}
	unlock();
}

void SIP_HEADERfilter::loadActive(SqlDb *sqlDb) {
	lock();
	filter_active = new FILE_LINE(4010) SIP_HEADERfilter();
	filter_active->load(sqlDb);
	unlock();
}

void SIP_HEADERfilter::freeActive() {
	lock();
	if(filter_active) {
		delete filter_active;
		filter_active = NULL;
	}
	unlock();
}

void SIP_HEADERfilter::prepareReload() {
	reload_do = false;
	lock_reload();
	if(filter_reload) {
		delete filter_reload;
	}
	filter_reload = new FILE_LINE(4011) SIP_HEADERfilter;
	filter_reload->load();
	reload_do = 1;
	syslog(LOG_NOTICE, "SIP_HEADERfilter::prepareReload");
	unlock_reload();
}

void SIP_HEADERfilter::applyReload() {
	if(reload_do) {
		lock_reload();
		lock();
		delete filter_active;
		filter_active = filter_reload;
		unlock();
		filter_reload = NULL;
		reload_do = false; 
		syslog(LOG_NOTICE, "SIP_HEADERfilter::applyReload");
		unlock_reload();
	}
}

SIP_HEADERfilter *SIP_HEADERfilter::filter_active = NULL;
SIP_HEADERfilter *SIP_HEADERfilter::filter_reload = NULL;
volatile bool SIP_HEADERfilter::reload_do = 0;
volatile unsigned long SIP_HEADERfilter::loadTime = 0;
volatile int SIP_HEADERfilter::_sync = 0;
volatile int SIP_HEADERfilter::_sync_reload = 0;
