#include <syslog.h>

#include "filter_mysql.h"
#include "calltable.h"
#include <math.h>

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

	extern char mysql_host[256];
	extern char mysql_host[256];
	extern char mysql_database[256];
	extern char mysql_user[256];
	extern char mysql_password[256];

	t_node *node;

	mysqlpp::Connection con(false);
	con.connect(mysql_database, mysql_host, mysql_user, mysql_password);
	if(!con) {
		syslog(LOG_ERR,"Database connection failed: %s", con.error());
		//cerr << "Database connection failed: " << con.error() << endl;
		return;
	}

	mysqlpp::Query query = con.query();
	query << "SELECT * FROM filter_ip";
	mysqlpp::StoreQueryResult res = query.store();
	mysqlpp::Row row;
	count = res.num_rows();
	stringstream strValue;
	for (size_t i = 0; i < res.num_rows(); ++i) {
		row = res.at(i);
		node = new(t_node);
		node->flags = 0;
		node->next = NULL;
		strValue << row["ip"];;
		strValue >> node->ip;

		node->mask = atoi(row["mask"]);

		if(atoi(row["rtp"])) {
			node->flags |= FLAG_RTP;
		} else {
			node->flags |= FLAG_NORTP;
		}

		if(atoi(row["sip"])) {
			node->flags |= FLAG_SIP;
		} else {
			node->flags |= FLAG_NOSIP;
		}

		if(atoi(row["register"])) {
			node->flags |= FLAG_REGISTER;
		} else {
			node->flags |= FLAG_NOREGISTER;
		}

		if(atoi(row["graph"])) {
			node->flags |= FLAG_GRAPH;
		} else {
			node->flags |= FLAG_NOGRAPH;
		}

		if(atoi(row["wav"])) {
			node->flags |= FLAG_WAV;
		} else {
			node->flags |= FLAG_NOWAV;
		}
	
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
		if(((saddr & (unsigned int)mask) == (node->ip & (unsigned int)mask)) || ((daddr & (unsigned int)mask) == (node->ip & (unsigned int)mask))) {

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
        for(int i = 0; i < 10; i++)
                first_node->nodes[i] = NULL;

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

                for(int i = 0; i < 10; i++) {
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
		if(!tmp->nodes[payload->prefix[i] - 48]) {
			t_node_tel *node = new(t_node_tel);
			node->payload = NULL;
			for(int j = 0; j < 10; j++)
				node->nodes[j] = NULL;
			tmp->nodes[payload->prefix[i] - 48] = node;
		}
		tmp = tmp->nodes[payload->prefix[i] - 48];      // shift

	}

	tmp->payload = payload;
};


void
TELNUMfilter::load() {

	extern char mysql_host[256];
	extern char mysql_host[256];
	extern char mysql_database[256];
	extern char mysql_user[256];
	extern char mysql_password[256];

	mysqlpp::Connection con(false);
	con.connect(mysql_database, mysql_host, mysql_user, mysql_password);
	if(!con) {
		syslog(LOG_ERR,"Database connection failed: %s", con.error());
		//cerr << "Database connection failed: " << con.error() << endl;
		return;
	}

	mysqlpp::Query query = con.query();
	query << "SELECT * FROM filter_telnum";
	mysqlpp::StoreQueryResult res = query.store();
	mysqlpp::Row row;
	count = res.num_rows();
	stringstream strValue;
	for (size_t i = 0; i < res.num_rows(); ++i) {
		row = res.at(i);

		if(!is_number((std::string)row["prefix"]))
			continue;

		t_payload *np = new(t_payload);

		np->flags = 0;
		strcpy(np->prefix, row["prefix"]);

		if(atoi(row["rtp"])) {
			np->flags |= FLAG_RTP;
		} else {
			np->flags |= FLAG_NORTP;
		}

		if(atoi(row["sip"])) {
			np->flags |= FLAG_SIP;
		} else {
			np->flags |= FLAG_NOSIP;
		}

		if(atoi(row["register"])) {
			np->flags |= FLAG_REGISTER;
		} else {
			np->flags |= FLAG_NOREGISTER;
		}

		if(atoi(row["graph"])) {
			np->flags |= FLAG_GRAPH;
		} else {
			np->flags |= FLAG_NOGRAPH;
		}

		if(atoi(row["wav"])) {
			np->flags |= FLAG_WAV;
		} else {
			np->flags |= FLAG_NOWAV;
		}
	
		// add node to the first position
		add_payload(np);
	}
};

int
TELNUMfilter::add_call_flags(unsigned int *flags, char *telnum_src, char *telnum_dst) {
	
	if (this->count == 0) {
		// no filters, return 
		return 0;
	}

        //search src telnum
        t_node_tel *tmp = first_node;
        t_payload *lastpayload = NULL;
        for(unsigned int i = 0; i < strlen(telnum_src); i++) {
		if(telnum_dst[i] < 48 || telnum_dst[i] > 57) {
			//stop on non digit
			break;
		}
                if(!tmp->nodes[telnum_src[i] - 48]) {
                        break;
                }
                tmp = tmp->nodes[telnum_src[i] - 48];
                if(tmp && tmp->payload) {
                        lastpayload = tmp->payload;
                }
        }
	if(!lastpayload) {
		//src not found, try dst
		for(unsigned int i = 0; i < strlen(telnum_dst); i++) {
			if(telnum_dst[i] < 48 || telnum_dst[i] > 57) {
				//stop on non digit
				break;
			}
			if(!tmp->nodes[telnum_dst[i] - 48]) {
				break;
			}
			tmp = tmp->nodes[telnum_dst[i] - 48];
			if(tmp && tmp->payload) {
				lastpayload = tmp->payload;
			}
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
TELNUMfilter::dump() {
}


