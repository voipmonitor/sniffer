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

bool is_number(const std::string& s) {
	for (unsigned int i = 0; i < s.length(); i++) {
		if (!std::isdigit(s[i]))
			return false;
		}
	return true;
}

void filter_base::loadBaseDataRow(SqlDb_row *sqlRow, filter_db_row_base *baseRow) {
	baseRow->direction = sqlRow->isNull("direction") ? 0 : atoi((*sqlRow)["direction"].c_str());
	baseRow->rtp = sqlRow->isNull("rtp") ? -1 : atoi((*sqlRow)["rtp"].c_str());
	baseRow->sip = sqlRow->isNull("sip") ? -1 : atoi((*sqlRow)["sip"].c_str());
	baseRow->reg = sqlRow->isNull("register") ? -1 : atoi((*sqlRow)["register"].c_str());
	baseRow->graph = sqlRow->isNull("graph") ? -1 : atoi((*sqlRow)["graph"].c_str());
	baseRow->wav = sqlRow->isNull("wav") ? -1 : atoi((*sqlRow)["wav"].c_str());
	baseRow->skip = sqlRow->isNull("skip") ? -1 : atoi((*sqlRow)["skip"].c_str());
	baseRow->script = sqlRow->isNull("script") ? -1 : atoi((*sqlRow)["script"].c_str());
	baseRow->mos_lqo = sqlRow->isNull("mos_lqo") ? -1 : atoi((*sqlRow)["mos_lqo"].c_str());
	baseRow->hide_message = sqlRow->isNull("hide_message") ? -1 : atoi((*sqlRow)["hide_message"].c_str());
}

unsigned int filter_base::getFlagsFromBaseData(filter_db_row_base *baseRow) {
	unsigned int flags = 0;
	
	if(baseRow->rtp == 1)			flags |= FLAG_RTP;
	else if(baseRow->rtp == 0)		flags |= FLAG_NORTP;
	
	if(baseRow->sip == 1)			flags |= FLAG_SIP;
	else if(baseRow->sip == 0)		flags |= FLAG_NOSIP;
	
	if(baseRow->reg == 1)			flags |= FLAG_REGISTER;
	else if(baseRow->reg == 0)		flags |= FLAG_NOREGISTER;
	
	if(baseRow->graph == 1)			flags |= FLAG_GRAPH;
	else if(baseRow->graph == 0)		flags |= FLAG_NOGRAPH;
	
	if(baseRow->wav == 1)			flags |= FLAG_WAV;
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
	
	return(flags);
}

void filter_base::setCallFlagsFromFilterFlags(unsigned int *callFlags, unsigned int filterFlags) {
	if(filterFlags & FLAG_RTP)					*callFlags |= FLAG_SAVERTP;
	if(filterFlags & FLAG_NORTP) 					{*callFlags &= ~FLAG_SAVERTP; *callFlags &= ~FLAG_SAVERTPHEADER;}
	
	if(filterFlags & FLAG_SIP)					*callFlags |= FLAG_SAVESIP;
	if(filterFlags & FLAG_NOSIP)					*callFlags &= ~FLAG_SAVESIP;
	
	if(filterFlags & FLAG_REGISTER)					*callFlags |= FLAG_SAVEREGISTER;
	if(filterFlags & FLAG_NOREGISTER)				*callFlags &= ~FLAG_SAVEREGISTER;
	
	if(filterFlags & FLAG_WAV)					*callFlags |= FLAG_SAVEWAV;
	if(filterFlags & FLAG_NOWAV)					*callFlags &= ~FLAG_SAVEWAV;
	
	if(filterFlags & FLAG_GRAPH)					*callFlags |= FLAG_SAVEGRAPH;
	if(filterFlags & FLAG_NOGRAPH)					*callFlags &= ~FLAG_SAVEGRAPH;
	
	if(filterFlags & FLAG_SKIP)					*callFlags |= FLAG_SKIPCDR;
	if(filterFlags & FLAG_NOSKIP)					*callFlags &= ~FLAG_SKIPCDR;
	
	if(filterFlags & FLAG_SCRIPT)					*callFlags |= FLAG_RUNSCRIPT;
	if(filterFlags & FLAG_NOSCRIPT)					*callFlags &= ~FLAG_RUNSCRIPT;

	if(filterFlags & FLAG_AMOSLQO || filterFlags & FLAG_ABMOSLQO)	{*callFlags |= FLAG_RUNAMOSLQO; *callFlags |= FLAG_SAVEWAV;}
	if(filterFlags & FLAG_BMOSLQO || filterFlags & FLAG_ABMOSLQO)	{*callFlags |= FLAG_RUNBMOSLQO; *callFlags |= FLAG_SAVEWAV;}
	if(filterFlags & FLAG_NOMOSLQO) 				{*callFlags &= ~FLAG_RUNAMOSLQO; *callFlags &= ~FLAG_RUNBMOSLQO;}
	
	if(filterFlags & FLAG_HIDEMSG)					*callFlags |= FLAG_HIDEMESSAGE;
	if(filterFlags & FLAG_SHOWMSG)					*callFlags &= ~FLAG_HIDEMESSAGE;
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

void
IPfilter::load() {
	vector<db_row> vectDbRow;
	SqlDb *sqlDb = createSqlObject();
	SqlDb_row row;
	sqlDb->query("SELECT * FROM filter_ip");
	while((row = sqlDb->fetchRow())) {
		count++;
		db_row* filterRow = new db_row;
		filterRow->ip = (unsigned int)strtoul(row["ip"].c_str(), NULL, 0);
		filterRow->mask = atoi(row["mask"].c_str());
		this->loadBaseDataRow(&row, filterRow);
		vectDbRow.push_back(*filterRow);
		delete filterRow;
	}
	delete sqlDb;
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

int
IPfilter::add_call_flags(unsigned int *flags, unsigned int saddr, unsigned int daddr) {
	
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

void
IPfilter::dump() {
	t_node *node;
	for(node = first_node; node != NULL; node = node->next) {
		printf("ip[%u] mask[%d] flags[%u]\n", node->ip, node->mask, node->flags);
	}
}

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

void
TELNUMfilter::add_payload(t_payload *payload) {
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


void
TELNUMfilter::load() {
	vector<db_row> vectDbRow;
	SqlDb *sqlDb = createSqlObject();
	SqlDb_row row;
	sqlDb->query("SELECT * FROM filter_telnum");
	while((row = sqlDb->fetchRow())) {
		count++;
		db_row* filterRow = new(db_row);
		strncpy(filterRow->prefix, row["prefix"].c_str(), MAX_PREFIX);
		this->loadBaseDataRow(&row, filterRow);
		vectDbRow.push_back(*filterRow);
		delete filterRow;
	}
	delete sqlDb;
	for (size_t i = 0; i < vectDbRow.size(); ++i) {
		t_payload *np = new(t_payload);
		np->direction = vectDbRow[i].direction;
		np->flags = this->getFlagsFromBaseData(&vectDbRow[i]);;
		strncpy(np->prefix, vectDbRow[i].prefix, MAX_PREFIX);

		add_payload(np);
	}
};

int
TELNUMfilter::add_call_flags(unsigned int *flags, char *telnum_src, char *telnum_dst) {

	int lastdirection = 0;
	
	if (this->count == 0) {
		// no filters, return 
		return 0;
	}

        //search src telnum
        t_node_tel *tmp = first_node;
        t_payload *lastpayload = NULL;
        for(unsigned int i = 0; i < strlen(telnum_src); i++) {
                if(!tmp->nodes[(unsigned char)telnum_src[i]]) {
                        break;
                }
                tmp = tmp->nodes[(unsigned char)telnum_src[i]];
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
			if(!tmp->nodes[(unsigned char)telnum_dst[i]]) {
				break;
			}
			tmp = tmp->nodes[(unsigned char)telnum_dst[i]];
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

void
TELNUMfilter::dump(t_node_tel *node) {
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

void
DOMAINfilter::load() {
	vector<db_row> vectDbRow;
	SqlDb *sqlDb = createSqlObject();
	SqlDb_row row;
	sqlDb->query("SELECT * FROM filter_domain");
	while((row = sqlDb->fetchRow())) {
		count++;
		db_row* filterRow = new db_row;
		filterRow->domain = row["domain"];
		this->loadBaseDataRow(&row, filterRow);
		vectDbRow.push_back(*filterRow);
		delete filterRow;
	}
	delete sqlDb;
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
DOMAINfilter::add_call_flags(unsigned int *flags, char *domain_src, char *domain_dst) {
	
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

void
DOMAINfilter::dump() {
	t_node *node;
	for(node = first_node; node != NULL; node = node->next) {
		printf("domain[%s] flags[%u]\n", node->domain.c_str(), node->flags);
	}
}

/* SIP_HEADERfilter class */

// constructor
SIP_HEADERfilter::SIP_HEADERfilter() {
	count = 0;
	loadTime = 0;
}

// destructor
SIP_HEADERfilter::~SIP_HEADERfilter() {
}

void
SIP_HEADERfilter::load() {
	vector<db_row> vectDbRow;
	SqlDb *sqlDb = createSqlObject();
	SqlDb_row row;
	sqlDb->query("SELECT * FROM filter_sip_header");
	while((row = sqlDb->fetchRow())) {
		count++;
		db_row* filterRow = new db_row;
		filterRow->header = row["header"];
		filterRow->content = row["content"];
		filterRow->prefix = row["content_type"] == "prefix";
		filterRow->regexp = row["content_type"] == "regexp";
		this->loadBaseDataRow(&row, filterRow);
		vectDbRow.push_back(*filterRow);
		delete filterRow;
	}
	delete sqlDb;
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

int
SIP_HEADERfilter::add_call_flags(ParsePacket *parsePacket, unsigned int *flags, char *domain_src, char *domain_dst) {
	
	if (this->count == 0) {
		// no filters, return 
		return 0;
	}
	
	for(map<std::string, header_data>::iterator it_header = this->data.begin(); it_header != this->data.end(); it_header++) {
		header_data *data = &it_header->second;
		string content = parsePacket->getContentString((it_header->first + ":").c_str());
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
				if(reg_match(content.c_str(), it_content->first.c_str())) {
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

void 
SIP_HEADERfilter::addNodes(ParsePacket *parsePacket) {
	for(map<std::string, header_data>::iterator it_header = this->data.begin(); it_header != this->data.end(); it_header++) {
		parsePacket->addNode((it_header->first + ":").c_str());
	}
}

void
SIP_HEADERfilter::dump() {
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

volatile int SIP_HEADERfilter::_sync = 0;