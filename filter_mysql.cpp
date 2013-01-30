#include <syslog.h>
#include <string.h>

#include "filter_mysql.h"
#include "calltable.h"
#include "odbc.h"
#include "sql_db.h"
#include <math.h>
#include <vector>

using namespace std;

extern SqlDb *sqlDb;

bool is_number(const std::string& s) {
	for (unsigned int i = 0; i < s.length(); i++) {
		if (!std::isdigit(s[i]))
			return false;
		}
	return true;
}

/* IPfilter class */

// constructor
IPfilter::IPfilter() {
	first_node = NULL;
	count = 0;
};

// destructor
IPfilter::~IPfilter() {
	t_node *node;
	for(node = first_node; node != NULL; node = node->next) {
		delete(node);
	}
};

void
IPfilter::load() {
	vector<db_row> vectDbRow;
	SqlDb_row row;
	sqlDb->query("SELECT * FROM filter_ip");
	while((row = sqlDb->fetchRow())) {
		count++;
		db_row* filterRow = new db_row;
		memset(filterRow,0,sizeof(db_row));
		filterRow->ip = (unsigned int)atoi(row["ip"].c_str());
		filterRow->mask = atoi(row["mask"].c_str());
		filterRow->direction = atoi(row["direction"].c_str());
		filterRow->rtp = atoi(row["rtp"].c_str());
		filterRow->sip = atoi(row["sip"].c_str());
		filterRow->reg = atoi(row["register"].c_str());
		filterRow->graph = atoi(row["graph"].c_str());
		filterRow->wav = atoi(row["wav"].c_str());
		vectDbRow.push_back(*filterRow);
		delete filterRow;
	}
	t_node *node;
	for (size_t i = 0; i < vectDbRow.size(); ++i) {
		node = new(t_node);
		node->direction = vectDbRow[i].direction;
		node->flags = 0;
		node->next = NULL;
		node->ip = vectDbRow[i].ip;
		node->mask = vectDbRow[i].mask;
		if(vectDbRow[i].rtp)	node->flags |= FLAG_RTP;
			else		node->flags |= FLAG_NORTP;
		if(vectDbRow[i].sip)	node->flags |= FLAG_SIP;
			else		node->flags |= FLAG_NOSIP;
		if(vectDbRow[i].reg)	node->flags |= FLAG_REGISTER;
			else		node->flags |= FLAG_NOREGISTER;
		if(vectDbRow[i].graph)	node->flags |= FLAG_GRAPH;
			else		node->flags |= FLAG_NOGRAPH;
		if(vectDbRow[i].wav)	node->flags |= FLAG_WAV;
			else		node->flags |= FLAG_NOWAV;
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

	t_node *node;
	long double mask;
	for(node = first_node; node != NULL; node = node->next) {

		mask = (pow(2, (long double)(node->mask)) - 1) * pow(2, (long double)(32 - node->mask));

		if(((node->direction == 0 or node->direction == 2) and ((daddr & (unsigned int)mask) == (node->ip & (unsigned int)mask))) || 
			((node->direction == 0 or node->direction == 1) and ((saddr & (unsigned int)mask) == (node->ip & (unsigned int)mask)))) {

			if(node->flags & FLAG_RTP) {
				*flags |= FLAG_SAVERTP;
			}
			if(node->flags & FLAG_NORTP) {
				*flags &= ~FLAG_SAVERTP;
			}
			if(node->flags & FLAG_SIP) {
				*flags |= FLAG_SAVESIP;
			}
			if(node->flags & FLAG_NOSIP) {
				*flags &= ~FLAG_SAVESIP;
			}
			if(node->flags & FLAG_REGISTER) {
				*flags |= FLAG_SAVEREGISTER;
			}
			if(node->flags & FLAG_NOREGISTER) {
				*flags &= ~FLAG_SAVEREGISTER;
			}
			if(node->flags & FLAG_WAV) {
				*flags |= FLAG_SAVEWAV;
			}
			if(node->flags & FLAG_NOWAV) {
				*flags &= ~FLAG_SAVEWAV;
			}
			if(node->flags & FLAG_GRAPH) {
				*flags |= FLAG_SAVEGRAPH;
			}
			if(node->flags & FLAG_NOGRAPH) {
				*flags &= ~FLAG_SAVEGRAPH;
			}
			return 1;
		}
	}

	return 0;
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
	SqlDb_row row;
	sqlDb->query("SELECT * FROM filter_telnum");
	while((row = sqlDb->fetchRow())) {
		count++;
		db_row* filterRow = new(db_row);
		memset(filterRow,0,sizeof(db_row));
		strncpy(filterRow->prefix, row["prefix"].c_str(), MAX_PREFIX);
		filterRow->direction = atoi(row["direction"].c_str());
		filterRow->rtp = atoi(row["rtp"].c_str());
		filterRow->sip = atoi(row["sip"].c_str());
		filterRow->reg = atoi(row["register"].c_str());
		filterRow->graph = atoi(row["graph"].c_str());
		filterRow->wav = atoi(row["wav"].c_str());
		vectDbRow.push_back(*filterRow);
		delete filterRow;
	}
	for (size_t i = 0; i < vectDbRow.size(); ++i) {
		t_payload *np = new(t_payload);
		np->direction = vectDbRow[i].direction;
		np->flags = 0;
		strncpy(np->prefix, vectDbRow[i].prefix, MAX_PREFIX);
		if(vectDbRow[i].rtp)	np->flags |= FLAG_RTP;
			else		np->flags |= FLAG_NORTP;
		if(vectDbRow[i].sip)	np->flags |= FLAG_SIP;
			else		np->flags |= FLAG_NOSIP;
		if(vectDbRow[i].reg)	np->flags |= FLAG_REGISTER;
			else		np->flags |= FLAG_NOREGISTER;
		if(vectDbRow[i].graph)	np->flags |= FLAG_GRAPH;
			else		np->flags |= FLAG_NOGRAPH;
		if(vectDbRow[i].wav)	np->flags |= FLAG_WAV;
			else		np->flags |= FLAG_NOWAV;
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
		if(telnum_src[i] > 256) {
			//check if it is in 0-256 ascii
			break;
		}
                if(!tmp->nodes[(int)telnum_src[i]]) {
                        break;
                }
                tmp = tmp->nodes[(int)telnum_src[i]];
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
		//src not found or src found , try dst
		for(unsigned int i = 0; i < strlen(telnum_dst); i++) {
			if(telnum_dst[i] > 256) {
				//check if it is in 0-256 ascii
				break;
			}
			if(!tmp->nodes[(int)telnum_dst[i]]) {
				break;
			}
			tmp = tmp->nodes[(int)telnum_dst[i]];
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
		if(lastpayload->flags & FLAG_RTP) {
			*flags |= FLAG_SAVERTP;
		}
		if(lastpayload->flags & FLAG_NORTP) {
			*flags &= ~FLAG_SAVERTP;
		}
		if(lastpayload->flags & FLAG_SIP) {
			*flags |= FLAG_SAVESIP;
		}
		if(lastpayload->flags & FLAG_NOSIP) {
			*flags &= ~FLAG_SAVESIP;
		}
		if(lastpayload->flags & FLAG_REGISTER) {
			*flags |= FLAG_SAVEREGISTER;
		}
		if(lastpayload->flags & FLAG_NOREGISTER) {
			*flags &= ~FLAG_SAVEREGISTER;
		}
		if(lastpayload->flags & FLAG_WAV) {
			*flags |= FLAG_SAVEWAV;
		}
		if(lastpayload->flags & FLAG_NOWAV) {
			*flags &= ~FLAG_SAVEWAV;
		}
		if(lastpayload->flags & FLAG_GRAPH) {
			*flags |= FLAG_SAVEGRAPH;
		}
		if(lastpayload->flags & FLAG_NOGRAPH) {
			*flags &= ~FLAG_SAVEGRAPH;
		}
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


