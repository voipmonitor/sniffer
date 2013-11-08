#include <algorithm>
#include <errno.h>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>

#include "sql_db.h"
#include "tools.h"
#include "cleanspool.h"

using namespace std;


void rename_file(const char *src, const char *dst);
void mysqlquerypush(string q);


extern char opt_chdir[1024];
extern int debugclean;
extern int opt_id_sensor;
extern char configfile[1024];

extern unsigned int opt_maxpoolsize;
extern unsigned int opt_maxpooldays;
extern unsigned int opt_maxpoolsipsize;
extern unsigned int opt_maxpoolsipdays;
extern unsigned int opt_maxpoolrtpsize;
extern unsigned int opt_maxpoolrtpdays;
extern unsigned int opt_maxpoolgraphsize;
extern unsigned int opt_maxpoolgraphdays;
extern unsigned int opt_maxpoolaudiosize;
extern unsigned int opt_maxpoolaudiodays;
extern int opt_cleanspool_interval;
extern int opt_cleanspool_sizeMB;

extern SqlDb *sqlDb;
extern char mysql_host[256];
extern char mysql_database[256];
extern char mysql_table[256];
extern char mysql_user[256];
extern char mysql_password[256];

extern queue<string> mysqlquery;
extern pthread_mutex_t mysqlquery_lock;


void unlinkfileslist(string fname) {
	char buf[4092];

	FILE *fd = fopen(fname.c_str(), "r");
	if(fd) {
		while(fgets(buf, 4092, fd) != NULL) {
			char *pos;
			if ((pos = strchr(buf, '\n')) != NULL) {
				*pos = '\0';
			}
			char *posSizeSeparator;
			if ((posSizeSeparator = strrchr(buf, ':')) != NULL) {
				bool isSize = true;
				pos = posSizeSeparator + 1;
				while(*pos) {
					if(*pos < '0' || *pos > '9') {
						isSize = false;
						break;
					}
					++pos;
				}
				if(isSize) {
					*posSizeSeparator = '\0';
				}
			}
			unlink(buf);
		}
		fclose(fd);
		unlink(fname.c_str());
	}
	return;
}

void unlink_dirs(string datehour, bool all, bool sip, bool rtp, bool graph, bool audio, bool reg) {

	//unlink all directories
	stringstream fname;

	for(int i = 0; i < 60; i++) {
		char min[8];
		sprintf(min, "%02d", i);

		if(all) {
			fname.str( std::string() );
			fname.clear();
			fname << datehour.substr(0,4) << "-" << datehour.substr(4,2) << "-" << datehour.substr(6,2) << "/" << datehour.substr(8,2) << "/" << min << "/ALL";
			rmdir(fname.str().c_str());
		}

		if(sip) {
			fname.str( std::string() );
			fname.clear();
			fname << datehour.substr(0,4) << "-" << datehour.substr(4,2) << "-" << datehour.substr(6,2) << "/" << datehour.substr(8,2) << "/" << min << "/SIP";
			rmdir(fname.str().c_str());
		}

		if(rtp) {
			fname.str( std::string() );
			fname.clear();
			fname << datehour.substr(0,4) << "-" << datehour.substr(4,2) << "-" << datehour.substr(6,2) << "/" << datehour.substr(8,2) << "/" << min << "/RTP";
			rmdir(fname.str().c_str());
		}

		if(graph) {
			fname.str( std::string() );
			fname.clear();
			fname << datehour.substr(0,4) << "-" << datehour.substr(4,2) << "-" << datehour.substr(6,2) << "/" << datehour.substr(8,2) << "/" << min << "/GRAPH";
			rmdir(fname.str().c_str());
		}

		if(audio) {
			fname.str( std::string() );
			fname.clear();
			fname << datehour.substr(0,4) << "-" << datehour.substr(4,2) << "-" << datehour.substr(6,2) << "/" << datehour.substr(8,2) << "/" << min << "/AUDIO";
			rmdir(fname.str().c_str());
		}

		if(reg) {
			fname.str( std::string() );
			fname.clear();
			fname << datehour.substr(0,4) << "-" << datehour.substr(4,2) << "-" << datehour.substr(6,2) << "/" << datehour.substr(8,2) << "/" << min << "/REG";
			rmdir(fname.str().c_str());
		}

		// remove minute
		fname.str( std::string() );
		fname.clear();
		fname << datehour.substr(0,4) << "-" << datehour.substr(4,2) << "-" << datehour.substr(6,2) << "/" << datehour.substr(8,2) << "/" << min;
		rmdir(fname.str().c_str());
	}
	
	// remove hour
	fname.str( std::string() );
	fname.clear();
	fname << datehour.substr(0,4) << "-" << datehour.substr(4,2) << "-" << datehour.substr(6,2) << "/" << datehour.substr(8,2);
	rmdir(fname.str().c_str());

	// remove day
	fname.str( std::string() );
	fname.clear();
	fname << datehour.substr(0,4) << "-" << datehour.substr(4,2) << "-" << datehour.substr(6,2);
	rmdir(fname.str().c_str());
}

void clean_maxpoolsize() {

	if(opt_maxpoolsize == 0) {
		return;
	}

	if(debugclean) cout << "clean_maxpoolsize\n";

	// check total size
	SqlDb *sqlDb = new SqlDb_mysql();
	sqlDb->setConnectParameters(mysql_host, mysql_user, mysql_password, mysql_database, 0);
	sqlDb->connect();
	stringstream q;
	q << "SELECT SUM(sipsize) AS sipsize, SUM(rtpsize) AS rtpsize, SUM(graphsize) as graphsize, SUM(audiosize) AS audiosize, SUM(regsize) AS regsize FROM files WHERE id_sensor = " 
		<< (opt_id_sensor > 0 ? opt_id_sensor : 0);
	sqlDb->query(q.str());
	SqlDb_row row0 = sqlDb->fetchRow();
	uint64_t sipsize = strtoull(row0["sipsize"].c_str(), NULL, 0);
	uint64_t rtpsize = strtoull(row0["rtpsize"].c_str(), NULL, 0);
	uint64_t graphsize = strtoull(row0["graphsize"].c_str(), NULL, 0);
	uint64_t audiosize = strtoull(row0["audiosize"].c_str(), NULL, 0);
	uint64_t regsize = strtoull(row0["regsize"].c_str(), NULL, 0);
	uint64_t total = sipsize + rtpsize + graphsize + audiosize + regsize;

	total /= 1024 * 1024;
	if(debugclean) cout << q.str() << "\n";
	if(debugclean) cout << "total[" << total << "] = " << sipsize << " + " << rtpsize << " + " << graphsize << " + " << audiosize << " + " << regsize << " opt_maxpoolsize[" << opt_maxpoolsize << "]\n";
	while(total > opt_maxpoolsize) {
		// walk all rows ordered by datehour and delete everything 
		stringstream q;
		q << "SELECT datehour FROM files WHERE id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0) << " ORDER BY datehour LIMIT 1";
		if(debugclean) cout << q.str() << "\n";
		sqlDb->query(q.str());
		SqlDb_row row = sqlDb->fetchRow();
		if(!row) {
			break;
		}

		ostringstream fname;

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/sipsize/" << row["datehour"];
		unlinkfileslist(fname.str());

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/rtpsize/" << row["datehour"];
		unlinkfileslist(fname.str());

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/graphsize/" << row["datehour"];
		unlinkfileslist(fname.str());

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/audiosize/" << row["datehour"];
		unlinkfileslist(fname.str());

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/regsize/" << row["datehour"];
		unlinkfileslist(fname.str());

		unlink_dirs(row["datehour"], 1, 1, 1, 1, 1, 1);

		q.str( std::string() );
		q.clear();
		q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
		if(debugclean) cout << q.str() << "\n";
		sqlDb->query(q.str());

		q.str( std::string() );
		q.clear();
		q << "SELECT SUM(sipsize) AS sipsize, SUM(rtpsize) AS rtpsize, SUM(graphsize) AS graphsize, SUM(regsize) AS regsize FROM files WHERE id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
		if(debugclean) cout << q.str() << "\n";
		sqlDb->query(q.str());
		SqlDb_row row2 = sqlDb->fetchRow();
		if(!row2) {
			break;
		}
		sipsize = strtoull(row2["sipsize"].c_str(), NULL, 0);
		rtpsize = strtoull(row2["rtpsize"].c_str(), NULL, 0);
		graphsize = strtoull(row2["graphsize"].c_str(), NULL, 0);
		audiosize = strtoull(row2["audiosize"].c_str(), NULL, 0);
		regsize = strtoull(row2["regsize"].c_str(), NULL, 0);
		total = sipsize + rtpsize + graphsize + audiosize + regsize;
		total /= 1024 * 1024;
	}


	delete sqlDb;
}

void clean_maxpoolsipsize() {

	if(opt_maxpoolsipsize == 0) {
		return;
	}

	// check total size
	SqlDb *sqlDb = new SqlDb_mysql();
	sqlDb->setConnectParameters(mysql_host, mysql_user, mysql_password, mysql_database, 0);
	sqlDb->connect();
	stringstream q;
	q << "SELECT SUM(sipsize) AS sipsize, SUM(regsize) AS regsize FROM files WHERE id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
	sqlDb->query(q.str());
	SqlDb_row row0 = sqlDb->fetchRow();
	uint64_t sipsize = strtoull(row0["sipsize"].c_str(), NULL, 0);
	uint64_t regsize = strtoull(row0["regsize"].c_str(), NULL, 0);
	uint64_t total = sipsize + regsize;

	total /= 1024 * 1024;
	while(total > opt_maxpoolsipsize) {
		// walk all rows ordered by datehour and delete everything 
	
		q.str( std::string() );
		q.clear();
		q << "SELECT * FROM files WHERE id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0) << " AND (sipsize > 0 or regsize > 0) ORDER BY datehour LIMIT 1";
		sqlDb->query(q.str());

		SqlDb_row row = sqlDb->fetchRow();
		if(!row) {
			break;
		}

		uint64_t sipsize = strtoull(row["sipsize"].c_str(), NULL, 0);
		uint64_t rtpsize = strtoull(row["rtpsize"].c_str(), NULL, 0);
		uint64_t graphsize = strtoull(row["graphsize"].c_str(), NULL, 0);
		uint64_t audiosize = strtoull(row["audiosize"].c_str(), NULL, 0);
		uint64_t regsize = strtoull(row["regsize"].c_str(), NULL, 0);

		ostringstream fname;

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/sipsize/" << row["datehour"];
		unlinkfileslist(fname.str());

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/regsize/" << row["datehour"];
		unlinkfileslist(fname.str());

		unlink_dirs(row["datehour"], 1, 1, 1, 1, 1, 1);

		if(rtpsize + graphsize + audiosize > 0) {
			q.str( std::string() );
			q.clear();
			q << "UPDATE files SET sipsize = 0, regsize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
			mysqlquerypush(q.str());
		} else {
			q.str( std::string() );
			q.clear();
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
			mysqlquerypush(q.str());
		}

		
		q.str( std::string() );
		q.clear();
		q << "SELECT SUM(sipsize) AS sipsize, SUM(regsize) AS regsize FROM files WHERE id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
		sqlDb->query(q.str());
		SqlDb_row row2 = sqlDb->fetchRow();
		if(!row2) {
			break;
		}
		sipsize = strtoull(row2["sipsize"].c_str(), NULL, 0);
		regsize = strtoull(row2["regsize"].c_str(), NULL, 0);
		total = sipsize + regsize;
		total /= 1024 * 1024;
	}

	delete sqlDb;
}

void clean_maxpoolrtpsize() {

	if(opt_maxpoolrtpsize == 0) {
		return;
	}

	// check total size
	SqlDb *sqlDb = new SqlDb_mysql();
	sqlDb->setConnectParameters(mysql_host, mysql_user, mysql_password, mysql_database, 0);
	sqlDb->connect();
	stringstream q;
	q << "SELECT SUM(rtpsize) AS rtpsize FROM files WHERE id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
	sqlDb->query(q.str());
	SqlDb_row row0 = sqlDb->fetchRow();
	uint64_t rtpsize = strtoull(row0["rtpsize"].c_str(), NULL, 0);
	uint64_t total = rtpsize;

	total /= 1024 * 1024;
	while(total > opt_maxpoolrtpsize) {
		// walk all rows ordered by datehour and delete everything 
	
		q.str( std::string() );
		q.clear();
		q << "SELECT * FROM files WHERE id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0) << " AND (rtpsize > 0) ORDER BY datehour LIMIT 1";
		sqlDb->query(q.str());

		SqlDb_row row = sqlDb->fetchRow();
		if(!row) {
			break;
		}

		uint64_t rtpsize = strtoull(row["rtpsize"].c_str(), NULL, 0);
		uint64_t sipsize = strtoull(row["sipsize"].c_str(), NULL, 0);
		uint64_t regsize = strtoull(row["regsize"].c_str(), NULL, 0);
		uint64_t graphsize = strtoull(row["graphsize"].c_str(), NULL, 0);
		uint64_t audiosize = strtoull(row["audiosize"].c_str(), NULL, 0);

		ostringstream fname;

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/rtpsize/" << row["datehour"];
		unlinkfileslist(fname.str());

		unlink_dirs(row["datehour"], 1, 1, 1, 1, 1, 1);

		if(sipsize + regsize + graphsize + audiosize > 0) {
			q.str( std::string() );
			q.clear();
			q << "UPDATE files SET rtpsize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
			mysqlquerypush(q.str());
		} else {
			q.str( std::string() );
			q.clear();
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
			mysqlquerypush(q.str());
		}

		
		q.str( std::string() );
		q.clear();
		q << "SELECT SUM(rtpsize) AS rtpsize FROM files WHERE id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
		sqlDb->query(q.str());
		SqlDb_row row2 = sqlDb->fetchRow();
		if(!row2) {
			break;
		}
		rtpsize = strtoull(row2["rtpsize"].c_str(), NULL, 0);
		total = rtpsize;
		total /= 1024 * 1024;
	}

	delete sqlDb;
}

void clean_maxpoolgraphsize() {

	if(opt_maxpoolgraphsize == 0) {
		return;
	}

	// check total size
	SqlDb *sqlDb = new SqlDb_mysql();
	sqlDb->setConnectParameters(mysql_host, mysql_user, mysql_password, mysql_database, 0);
	sqlDb->connect();
	stringstream q;
	q << "SELECT SUM(graphsize) AS graphsize FROM files WHERE id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
	sqlDb->query(q.str());
	SqlDb_row row0 = sqlDb->fetchRow();
	uint64_t graphsize = strtoull(row0["graphsize"].c_str(), NULL, 0);
	uint64_t total = graphsize;

	total /= 1024 * 1024;
	while(total > opt_maxpoolgraphsize) {
		// walk all rows ordered by datehour and delete everything 
	
		q.str( std::string() );
		q.clear();
		q << "SELECT * FROM files WHERE id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0) << " AND (graphsize > 0) ORDER BY datehour LIMIT 1";
		sqlDb->query(q.str());

		SqlDb_row row = sqlDb->fetchRow();
		if(!row) {
			break;
		}

		uint64_t rtpsize = strtoull(row["rtpsize"].c_str(), NULL, 0);
		uint64_t sipsize = strtoull(row["sipsize"].c_str(), NULL, 0);
		uint64_t regsize = strtoull(row["regsize"].c_str(), NULL, 0);
		uint64_t graphsize = strtoull(row["graphsize"].c_str(), NULL, 0);
		uint64_t audiosize = strtoull(row["audiosize"].c_str(), NULL, 0);

		ostringstream fname;

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/graphsize/" << row["datehour"];
		unlinkfileslist(fname.str());

		unlink_dirs(row["datehour"], 1, 1, 1, 1, 1, 1);

		if(sipsize + regsize + rtpsize + audiosize > 0) {
			q.str( std::string() );
			q.clear();
			q << "UPDATE files SET graphsize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
			mysqlquerypush(q.str());
		} else {
			q.str( std::string() );
			q.clear();
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
			mysqlquerypush(q.str());
		}

		
		q.str( std::string() );
		q.clear();
		q << "SELECT SUM(graphsize) AS graphsize FROM files WHERE id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
		sqlDb->query(q.str());
		SqlDb_row row2 = sqlDb->fetchRow();
		if(!row2) {
			break;
		}
		graphsize = strtoull(row2["graphsize"].c_str(), NULL, 0);
		total = graphsize;
		total /= 1024 * 1024;
	}

	delete sqlDb;
}

void clean_maxpoolaudiosize() {

	if(opt_maxpoolaudiosize == 0) {
		return;
	}

	// check total size
	SqlDb *sqlDb = new SqlDb_mysql();
	sqlDb->setConnectParameters(mysql_host, mysql_user, mysql_password, mysql_database, 0);
	sqlDb->connect();
	stringstream q;
	q << "SELECT SUM(audiosize) AS audiosize FROM files WHERE id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
	sqlDb->query(q.str());
	SqlDb_row row0 = sqlDb->fetchRow();
	uint64_t audiosize = strtoull(row0["audiosize"].c_str(), NULL, 0);
	uint64_t total = audiosize;

	total /= 1024 * 1024;
	while(total > opt_maxpoolaudiosize) {
		// walk all rows ordered by datehour and delete everything 
	
		q.str( std::string() );
		q.clear();
		q << "SELECT * FROM files WHERE id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0) << " AND (audiosize > 0) ORDER BY datehour LIMIT 1";
		sqlDb->query(q.str());

		SqlDb_row row = sqlDb->fetchRow();
		if(!row) {
			break;
		}

		uint64_t rtpsize = strtoull(row["rtpsize"].c_str(), NULL, 0);
		uint64_t sipsize = strtoull(row["sipsize"].c_str(), NULL, 0);
		uint64_t regsize = strtoull(row["regsize"].c_str(), NULL, 0);
		uint64_t graphsize = strtoull(row["graphsize"].c_str(), NULL, 0);
		uint64_t audiosize = strtoull(row["audiosize"].c_str(), NULL, 0);

		ostringstream fname;

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/audiosize/" << row["datehour"];
		unlinkfileslist(fname.str());

		unlink_dirs(row["datehour"], 1, 1, 1, 1, 1, 1);

		if(sipsize + regsize + rtpsize + graphsize > 0) {
			q.str( std::string() );
			q.clear();
			q << "UPDATE files SET audiosize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
			mysqlquerypush(q.str());
		} else {
			q.str( std::string() );
			q.clear();
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
			mysqlquerypush(q.str());
		}

		
		q.str( std::string() );
		q.clear();
		q << "SELECT SUM(audiosize) AS audiosize FROM files WHERE id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
		sqlDb->query(q.str());
		SqlDb_row row2 = sqlDb->fetchRow();
		if(!row2) {
			break;
		}
		audiosize = strtoull(row2["audiosize"].c_str(), NULL, 0);
		total = audiosize;
		total /= 1024 * 1024;
	}

	delete sqlDb;
}


void clean_maxpooldays() {

	if(opt_maxpooldays == 0) {
		return;
	}

	// check total size
	SqlDb *sqlDb = new SqlDb_mysql();
	sqlDb->setConnectParameters(mysql_host, mysql_user, mysql_password, mysql_database, 0);
	sqlDb->connect();

	stringstream q;
	q << "SELECT * FROM files WHERE id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0) <<  " AND (datehour < DATE_FORMAT(DATE_SUB(NOW(), INTERVAL " << opt_maxpooldays << " DAY), '%Y%m%d%k')" << ") ORDER BY datehour";
	sqlDb->query(q.str());
	SqlDb_row row;
	while(row = sqlDb->fetchRow()) {
		ostringstream fname;

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/sipsize/" << row["datehour"];
		unlinkfileslist(fname.str());

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/rtpsize/" << row["datehour"];
		unlinkfileslist(fname.str());

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/graphsize/" << row["datehour"];
		unlinkfileslist(fname.str());

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/audiosize/" << row["datehour"];
		unlinkfileslist(fname.str());

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/regsize/" << row["datehour"];
		unlinkfileslist(fname.str());

		unlink_dirs(row["datehour"], 1, 1, 1, 1, 1, 1);

		q.str( std::string() );
		q.clear();
		q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
		mysqlquerypush(q.str());
	}

	delete sqlDb;
	return;
}

void clean_maxpoolsipdays() {

	if(opt_maxpoolsipdays == 0) {
		return;
	}

	SqlDb *sqlDb = new SqlDb_mysql();
	sqlDb->setConnectParameters(mysql_host, mysql_user, mysql_password, mysql_database, 0);
	sqlDb->connect();

	stringstream q;
	q << "SELECT * FROM files WHERE id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0) <<  " AND (sipsize > 0 or regsize > 0) AND (datehour < DATE_FORMAT(DATE_SUB(NOW(), INTERVAL " << opt_maxpoolsipdays << " DAY), '%Y%m%d%k')" << ") ORDER BY datehour";
	sqlDb->query(q.str());
	SqlDb_row row;
	while(row = sqlDb->fetchRow()) {
		ostringstream fname;

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/sipsize/" << row["datehour"];
		unlinkfileslist(fname.str());

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/regsize/" << row["datehour"];
		unlinkfileslist(fname.str());

		unlink_dirs(row["datehour"], 1, 1, 1, 1, 1, 1);

		uint64_t rtpsize = strtoull(row["rtpsize"].c_str(), NULL, 0);
		uint64_t graphsize = strtoull(row["graphsize"].c_str(), NULL, 0);
		uint64_t audiosize = strtoull(row["audiosize"].c_str(), NULL, 0);

		if(rtpsize + graphsize + audiosize > 0) {
			stringstream q;
			q << "UPDATE files SET sipsize = 0, regsize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
			mysqlquerypush(q.str());
		} else {
			stringstream q;
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
			mysqlquerypush(q.str());
		}
	}

	delete sqlDb;
	return;
}

void clean_maxpoolrtpdays() {

	if(opt_maxpoolrtpdays == 0) {
		return;
	}

	SqlDb *sqlDb = new SqlDb_mysql();
	sqlDb->setConnectParameters(mysql_host, mysql_user, mysql_password, mysql_database, 0);
	sqlDb->connect();

	stringstream q;
	q << "SELECT * FROM files WHERE id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0) <<  " AND (rtpsize > 0) AND (datehour < DATE_FORMAT(DATE_SUB(NOW(), INTERVAL " << opt_maxpoolrtpdays << " DAY), '%Y%m%d%k')" << ") ORDER BY datehour";
	sqlDb->query(q.str());
	SqlDb_row row;
	while(row = sqlDb->fetchRow()) {
		ostringstream fname;

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/rtpsize/" << row["datehour"];
		unlinkfileslist(fname.str());

		unlink_dirs(row["datehour"], 1, 1, 1, 1, 1, 1);

		uint64_t sipsize = strtoull(row["sipsize"].c_str(), NULL, 0);
		uint64_t regsize = strtoull(row["regsize"].c_str(), NULL, 0);
		uint64_t graphsize = strtoull(row["graphsize"].c_str(), NULL, 0);
		uint64_t audiosize = strtoull(row["audiosize"].c_str(), NULL, 0);

		if(sipsize + regsize + graphsize + audiosize > 0) {
			stringstream q;
			q << "UPDATE files SET rtpsize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
			mysqlquerypush(q.str());
		} else {
			stringstream q;
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
			mysqlquerypush(q.str());
		}
	}

	delete sqlDb;
	return;
}

void clean_maxpoolgraphdays() {

	if(opt_maxpoolgraphdays == 0) {
		return;
	}

	SqlDb *sqlDb = new SqlDb_mysql();
	sqlDb->setConnectParameters(mysql_host, mysql_user, mysql_password, mysql_database, 0);
	sqlDb->connect();

	stringstream q;
	q << "SELECT * FROM files WHERE id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0) <<  " AND (graphsize > 0) AND (datehour < DATE_FORMAT(DATE_SUB(NOW(), INTERVAL " << opt_maxpoolgraphdays << " DAY), '%Y%m%d%k')" << ") ORDER BY datehour";
	if(debugclean) cout << q.str() << "\n";
	sqlDb->query(q.str());
	SqlDb_row row;
	while(row = sqlDb->fetchRow()) {
		ostringstream fname;

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/graphsize/" << row["datehour"];
		if(debugclean) cout << "reading: " << fname.str() << "\n";
		unlinkfileslist(fname.str());

		unlink_dirs(row["datehour"], 1, 1, 1, 1, 1, 1);

		uint64_t sipsize = strtoull(row["sipsize"].c_str(), NULL, 0);
		uint64_t rtpsize = strtoull(row["rtpsize"].c_str(), NULL, 0);
		uint64_t regsize = strtoull(row["regsize"].c_str(), NULL, 0);
		uint64_t audiosize = strtoull(row["audiosize"].c_str(), NULL, 0);

		if(sipsize + regsize + rtpsize + audiosize > 0) {
			stringstream q;
			q << "UPDATE files SET graphsize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
			mysqlquerypush(q.str());
			if(debugclean) cout << q.str() << "\n";
		} else {
			stringstream q;
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
			mysqlquerypush(q.str());
			if(debugclean) cout << q.str() << "\n";
		}
	}

	delete sqlDb;
	return;
}

void clean_maxpoolaudiodays() {

	if(opt_maxpoolaudiodays == 0) {
		return;
	}

	SqlDb *sqlDb = new SqlDb_mysql();
	sqlDb->setConnectParameters(mysql_host, mysql_user, mysql_password, mysql_database, 0);
	sqlDb->connect();

	stringstream q;
	q << "SELECT * FROM files WHERE id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0) <<  " AND (audiosize > 0) AND (datehour < DATE_FORMAT(DATE_SUB(NOW(), INTERVAL " << opt_maxpoolaudiodays << " DAY), '%Y%m%d%k')" << ") ORDER BY datehour";
	sqlDb->query(q.str());
	SqlDb_row row;
	while(row = sqlDb->fetchRow()) {
		ostringstream fname;

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/audiosize/" << row["datehour"];
		unlinkfileslist(fname.str());

		unlink_dirs(row["datehour"], 1, 1, 1, 1, 1, 1);

		uint64_t sipsize = strtoull(row["sipsize"].c_str(), NULL, 0);
		uint64_t rtpsize = strtoull(row["rtpsize"].c_str(), NULL, 0);
		uint64_t regsize = strtoull(row["regsize"].c_str(), NULL, 0);
		uint64_t graphsize = strtoull(row["graphsize"].c_str(), NULL, 0);

		if(sipsize + regsize + rtpsize + graphsize > 0) {
			stringstream q;
			q << "UPDATE files SET audiosize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
			mysqlquerypush(q.str());
		} else {
			stringstream q;
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor > 0 ? opt_id_sensor : 0);
			mysqlquerypush(q.str());
		}
	}

	delete sqlDb;
	return;
}

void convert_filesindex() {
	string path = "./";
	dirent* de;
	DIR* dp;
	errno = 0;
	dp = opendir( path.empty() ? "." : path.c_str() );
	if (!dp) {
		return;
	}

	mysqlquerypush("DELETE FROM files");

	while (true) {
		errno = 0;
		de = readdir( dp );
		if (de == NULL) break;
		if (string(de->d_name) == ".." or string(de->d_name) == ".") continue;

		if(de->d_name[0] == '2') {
			syslog(LOG_NOTICE, "reindexing files in [%s]\n", de->d_name);
			//cycle through 24 hours
			for(int h = 0; h < 24; h++) {
				char hour[8];
				sprintf(hour, "%02d", h);

				string ymd = de->d_name;
				string ymdh = string(ymd.substr(0,4)) + ymd.substr(5,2) + ymd.substr(8,2) + hour;
				string fname = string("filesindex/sipsize/") + ymdh;
				ofstream sipfile(fname.c_str(), ios::app | ios::out);
				fname = string("filesindex/rtpsize/") + ymdh;
				ofstream rtpfile(fname.c_str(), ios::app | ios::out);
				fname = string("filesindex/graphsize/") + ymdh;
				ofstream graphfile(fname.c_str(), ios::app | ios::out);
				fname = string("filesindex/audiosize/") + ymdh;
				ofstream audiofile(fname.c_str(), ios::app | ios::out);

				unsigned long long sipsize = 0;
				unsigned long long rtpsize = 0;
				unsigned long long graphsize = 0;
				unsigned long long audiosize = 0;

				for(int m = 0; m < 60; m++) {

					//SIP
					stringstream t;
					char min[8];
					sprintf(min, "%02d", m);
					t << de->d_name << "/" << hour << "/" << min << "/SIP";
					DIR* dp;
					dp = opendir( t.str().c_str());
					dirent* de2;
					if(dp) {
						while (true) {
							de2 = readdir( dp );
							if (de2 == NULL) break;
							if (string(de2->d_name) == ".." or string(de2->d_name) == ".") continue;
							stringstream fn;
							fn << de->d_name << "/" << hour << "/" << min << "/SIP/" << de2->d_name;
							unsigned long long size = GetFileSizeDU(fn.str());
							if(size == 0) size = 1;
							sipsize += size;
							sipfile << fn.str() << ":" << size << "\n";
						}
						closedir(dp);
					}
					rmdir(t.str().c_str());
					//RTP
					t.str( std::string() );
					t.clear();
					sprintf(min, "%02d", m);
					t << de->d_name << "/" << hour << "/" << min << "/RTP";
					dp = opendir( t.str().c_str());
					if(dp) {
						while (true) {
							de2 = readdir( dp );
							if (de2 == NULL) break;
							if (string(de2->d_name) == ".." or string(de2->d_name) == ".") continue;
							stringstream fn;
							fn << de->d_name << "/" << hour << "/" << min << "/RTP/" << de2->d_name;
							unsigned long long size = GetFileSizeDU(fn.str());
							if(size == 0) size = 1;
							rtpsize += size;
							rtpfile << fn.str() << ":" << size << "\n";
						}
						closedir(dp);
					}
					rmdir(t.str().c_str());
					//GRAPH
					t.str( std::string() );
					t.clear();
					sprintf(min, "%02d", m);
					t << de->d_name << "/" << hour << "/" << min << "/GRAPH";
					dp = opendir( t.str().c_str());
					if(dp) {
						while (true) {
							de2 = readdir( dp );
							//if (de2 == NULL or string(de2->d_name) == ".." or string(de2->d_name) == ".") break;
							if (de2 == NULL) break;
							if (string(de2->d_name) == ".." or string(de2->d_name) == ".") continue;
							stringstream fn;
							fn << de->d_name << "/" << hour << "/" << min << "/GRAPH/" << de2->d_name;
							unsigned long long size = GetFileSizeDU(fn.str());
							if(size == 0) size = 1;
							graphsize += size;
							graphfile << fn.str() << ":" << size << "\n";
						}
						closedir(dp);
					}
					rmdir(t.str().c_str());
					//AUDIO
					t.str( std::string() );
					t.clear();
					t << de->d_name << "/" << hour << "/" << min << "/AUDIO";
					dp = opendir( t.str().c_str());
					if(dp) {
						while (true) {
							de2 = readdir( dp );
							if (de2 == NULL) break;
							if (string(de2->d_name) == ".." or string(de2->d_name) == ".") continue;
							stringstream fn;
							fn << de->d_name << "/" << hour << "/" << min << "/AUDIO/" << de2->d_name;
							unsigned long long size = GetFileSizeDU(fn.str());
							if(size == 0) size = 1;
							audiosize += size;
							audiofile << fn.str() << ":" << size << "\n";
						}
						closedir(dp);
					}
					rmdir(t.str().c_str());

					t.str( std::string() );
					t.clear();
					t << de->d_name << "/" << hour << "/" << min << "/ALL";
					rmdir(t.str().c_str());

					t.str( std::string() );
					t.clear();
					t << de->d_name << "/" << hour << "/" << min << "/REG";
					rmdir(t.str().c_str());

					t.str( std::string() );
					t.clear();
					t << de->d_name << "/" << hour << "/" << min;
					rmdir(t.str().c_str());
				}

				stringstream t;
				t.str( std::string() );
				t.clear();
				t << de->d_name << "/" << hour;
				rmdir(t.str().c_str());

				if(sipsize + rtpsize + graphsize + audiosize > 0) {
					stringstream query;
					int id_sensor = opt_id_sensor == -1 ? 0 : opt_id_sensor;
					query << "INSERT INTO files SET files.datehour = " << ymdh << ", id_sensor = " << id_sensor << ", "
						<< "sipsize = " << sipsize << ", rtpsize = " << rtpsize << ", graphsize = " << graphsize << ", audiosize = " << audiosize << 
						" ON DUPLICATE KEY UPDATE sipsize = sipsize";
					pthread_mutex_lock(&mysqlquery_lock);
					mysqlquery.push(query.str());
					pthread_mutex_unlock(&mysqlquery_lock);

				}

				sipfile.close();
				rtpfile.close();
				graphfile.close();
				audiofile.close();

				if(sipsize == 0) {
					fname = string("filesindex/sipsize/") + ymdh;
					unlink(fname.c_str());
				}
				if(rtpsize == 0) {
					fname = string("filesindex/rtpsize/") + ymdh;
					unlink(fname.c_str());
				}
				if(graphsize == 0) {
					fname = string("filesindex/graphsize/") + ymdh;
					unlink(fname.c_str());
				}
				if(audiosize == 0) {
					fname = string("filesindex/audiosize/") + ymdh;
					unlink(fname.c_str());
				}
			}
		
			rmdir(de->d_name);
		}
	}
	syslog(LOG_NOTICE, "reindexing done\n");
	closedir( dp );
	return;
}

void check_spooldir_filesindex(const char *path, const char *dirfilter) {
	const char *typeFilesIndex[] = {
		"sip",
		"rtp",
		"graph",
		"audio"
	};
	const char *typeFilesFolder[] = {
		"SIP",
		"RTP",
		"GRAPH",
		"AUDIO",
		"ALL",
		"REG",
		""
	};
	
	if(!path) {
		path = opt_chdir;
	}
	DIR* dp = opendir(path);
	if (!dp) {
		return;
	}
	dirent* de;
	string basedir = path;
	while (true) {
		errno = 0;
		de = readdir(dp);
		if (de == NULL) break;
		if (string(de->d_name) == ".." or string(de->d_name) == ".") continue;
		
		if(de->d_name[0] == '2' &&
		   (!dirfilter || strstr(de->d_name, dirfilter))) {
			//cycle through 24 hours
			syslog(LOG_NOTICE, "check files in [%s]", de->d_name);
			for(int h = 0; h < 24; h++) {
				unsigned long long sumSizeMissingFilesInIndex[2] = {0, 0};
				char hour[8];
				sprintf(hour, "%02d", h);
				syslog(LOG_NOTICE, " - hour [%s]", hour);
				string ymd = de->d_name;
				string ymdh = string(ymd.substr(0,4)) + ymd.substr(5,2) + ymd.substr(8,2) + hour;
				long long sumSize[2][sizeof(typeFilesIndex) / sizeof(typeFilesIndex[0])];
				for(uint i = 0; i < sizeof(typeFilesFolder) / sizeof(typeFilesFolder[0]); i++) {
					vector<string> filesInIndex;
				        if(i < sizeof(typeFilesIndex) / sizeof(typeFilesIndex[0])) {
						sumSize[0][i] = 0;
						sumSize[1][i] = 0;
						FILE *fd = fopen((basedir + "/filesindex/" + typeFilesIndex[i] + "size/" + ymdh).c_str(), "r");
						if(fd) {
							char buf[4092];
							while(fgets(buf, 4092, fd) != NULL) {
								char *pos;
								if ((pos = strchr(buf, '\n')) != NULL) {
									*pos = '\0';
								}
								char *posSizeSeparator;
								if ((posSizeSeparator = strrchr(buf, ':')) != NULL) {
									bool isSize = true;
									pos = posSizeSeparator + 1;
									while(*pos) {
										if(*pos < '0' || *pos > '9') {
											isSize = false;
											break;
										}
										++pos;
									}
									if(isSize) {
										*posSizeSeparator = '\0';
									} else {
										posSizeSeparator = NULL;
									}
								}
								filesInIndex.push_back(buf);
								long long unsigned size = posSizeSeparator ? atoll(posSizeSeparator + 1) : 0;
								long long unsigned fileSize = GetFileSizeDU((basedir + "/" + buf).c_str());
								if(fileSize == 0) {
									fileSize = 1;
								}
								sumSize[0][i] += size;
								sumSize[1][i] += fileSize;
								if(fileSize == (long long unsigned)-1) {
									syslog(LOG_NOTICE, "ERROR - missing file from index [%s]", buf);
								} else {
									
									if(size != fileSize) {
										syslog(LOG_NOTICE, "ERROR - diff file size [%s - %llu i / %llu r]", buf, size, fileSize);
									}
								}
							}
							fclose(fd);
						}
					}
					if(filesInIndex.size()) {
						std::sort(filesInIndex.begin(), filesInIndex.end());
					}
					vector<string> filesInFolder;
					for(int m = 0; m < 60; m++) {
						char min[8];
						sprintf(min, "%02d", m);
						string timetypedir = string(de->d_name) + "/" + hour + "/" + min + "/" + typeFilesFolder[i];
						DIR* dp = opendir((basedir + "/" + timetypedir).c_str());
						if(!dp) {
							continue;
						}
						dirent* de2;
						while (true) {
							de2 = readdir( dp );
							if (de2 == NULL) break;
							if (de2->d_type == 4 or string(de2->d_name) == ".." or string(de2->d_name) == ".") continue;
							filesInFolder.push_back(timetypedir + "/" + de2->d_name);
						}
						closedir(dp);
					}
					for(uint j = 0; j < filesInFolder.size(); j++) {
						if(!std::binary_search(filesInIndex.begin(), filesInIndex.end(), filesInFolder[j])) {
							unsigned long long size = GetFileSize((string(opt_chdir) + "/" + filesInFolder[j]).c_str());
							unsigned long long sizeDU = GetFileSizeDU((string(opt_chdir) + "/" + filesInFolder[j]).c_str());
							sumSizeMissingFilesInIndex[0] += size;
							sumSizeMissingFilesInIndex[1] += sizeDU;
							syslog(LOG_NOTICE,
							       i < sizeof(typeFilesIndex) / sizeof(typeFilesIndex[0]) ?
								"ERROR - missing file in index [%s] - %llu / %llu" :
								"ERROR - unknown file [%s] - %llu / %llu", 
							       filesInFolder[j].c_str(),
							       size,
							       sizeDU);
						}
					}
				}
				
				if(sumSize[0][0] || sumSize[0][1] || sumSize[0][2] || sumSize[0][3] ||
				   sumSize[1][0] || sumSize[1][1] || sumSize[1][2] || sumSize[1][3]) {
					char id_sensor_str[10];
					sprintf(id_sensor_str, "%i", opt_id_sensor > 0 ? opt_id_sensor : 0);
					sqlDb->query(string(
						"SELECT SUM(sipsize) AS sipsize,\
							SUM(rtpsize) AS rtpsize,\
							SUM(graphsize) AS graphsize,\
							SUM(audiosize) AS audiosize,\
							count(*) as cnt\
						 FROM files\
						 WHERE datehour like '") + string(de->d_name).substr(0, 4) + 
									   string(de->d_name).substr(5, 2) + 
									   string(de->d_name).substr(8, 2) + hour + "%' and \
						       id_sensor = " + id_sensor_str);
					SqlDb_row rowSum = sqlDb->fetchRow();
					if(rowSum && atol(rowSum["cnt"].c_str()) > 0) {
						if(atoll(rowSum["sipsize"].c_str()) == sumSize[0][0] &&
						   atoll(rowSum["rtpsize"].c_str()) == sumSize[0][1] &&
						   atoll(rowSum["graphsize"].c_str()) == sumSize[0][2] &&
						   atoll(rowSum["audiosize"].c_str()) == sumSize[0][3] &&
						   atoll(rowSum["sipsize"].c_str()) == sumSize[1][0] &&
						   atoll(rowSum["rtpsize"].c_str()) == sumSize[1][1] &&
						   atoll(rowSum["graphsize"].c_str()) == sumSize[1][2] &&
						   atoll(rowSum["audiosize"].c_str()) == sumSize[1][3]) {
							syslog(LOG_NOTICE, " # OK sum in files by index");
						} else {
							if(atoll(rowSum["sipsize"].c_str()) != sumSize[0][0]) {
								syslog(LOG_NOTICE, " # ERROR sum sipsize in files [ %llu ii / %llu f ]", sumSize[0][0], atoll(rowSum["sipsize"].c_str()));
							}
							if(atoll(rowSum["sipsize"].c_str()) != sumSize[1][0]) {
								syslog(LOG_NOTICE, " # ERROR sum sipsize in files [ %llu ri / %llu f ]", sumSize[1][0], atoll(rowSum["sipsize"].c_str()));
							}
							if(atoll(rowSum["rtpsize"].c_str()) != sumSize[0][1]) {
								syslog(LOG_NOTICE, " # ERROR sum rtpsize in files [ %llu ii / %llu f ]", sumSize[0][1], atoll(rowSum["rtpsize"].c_str()));
							}
							if(atoll(rowSum["rtpsize"].c_str()) != sumSize[1][1]) {
								syslog(LOG_NOTICE, " # ERROR sum rtpsize in files [ %llu ri / %llu f ]", sumSize[1][1], atoll(rowSum["rtpsize"].c_str()));
							}
							if(atoll(rowSum["graphsize"].c_str()) != sumSize[0][2]) {
								syslog(LOG_NOTICE, " # ERROR sum graphsize in files [ %llu ii / %llu f ]", sumSize[0][2], atoll(rowSum["graphsize"].c_str()));
							}
							if(atoll(rowSum["graphsize"].c_str()) != sumSize[1][2]) {
								syslog(LOG_NOTICE, " # ERROR sum graphsize in files [ %llu ri / %llu f ]", sumSize[1][2], atoll(rowSum["graphsize"].c_str()));
							}
							if(atoll(rowSum["audiosize"].c_str()) != sumSize[0][3]) {
								syslog(LOG_NOTICE, " # ERROR sum audiosize in files [ %llu ii / %llu f ]", sumSize[0][3], atoll(rowSum["audiosize"].c_str()));
							}
							if(atoll(rowSum["audiosize"].c_str()) != sumSize[1][3]) {
								syslog(LOG_NOTICE, " # ERROR sum audiosize in files [ %llu ri / %llu f ]", sumSize[1][3], atoll(rowSum["audiosize"].c_str()));
							}
						}
					} else {
						syslog(LOG_NOTICE, " # MISSING record in files");
					}
				}
				
				if(sumSizeMissingFilesInIndex[0] || sumSizeMissingFilesInIndex[1]) {
					syslog(LOG_NOTICE, "sum size of missing file in index: %llu / %llu", sumSizeMissingFilesInIndex[0], sumSizeMissingFilesInIndex[1]);
				}
			}
		}
	}
	closedir(dp);
}

void *clean_spooldir_run(void *dummy) {

	if(opt_cleanspool_interval and opt_cleanspool_sizeMB > 0) {
		opt_maxpoolsize = opt_cleanspool_sizeMB;
		// if old cleanspool interval is defined convert the config to new config 
		if(FileExists(configfile)) {

			syslog(LOG_NOTICE, "converting [%s] cleanspool_interval and cleanspool_size to maxpoolsize\n", configfile);

			convert_filesindex();

			string tmpf = "/tmp/VM_pRjSYLAyx.conf";
			FILE *fdr = fopen(configfile, "r");
			FILE *fdw = fopen(tmpf.c_str(), "w");
			if(!fdr or !fdw) {
				syslog(LOG_ERR, "cannot open config file [%s]\n", configfile);
				return NULL;
			}
			char buffer[4092];
			while(!feof(fdr)) {
				if(fgets(buffer, 4092, fdr) != NULL) {
					if(memmem(buffer, strlen("cleanspool_interval"), "cleanspool_interval", strlen("cleanspool_interval")) == NULL) {
						if(memmem(buffer, strlen("cleanspool_size"), "cleanspool_size", strlen("cleanspool_size")) == NULL) {
							fwrite(buffer, 1, strlen(buffer), fdw);
						} else {
						}
					} else {
						stringstream tmp;
						tmp << "\n\n#this is new cleaning implementation\nmaxpoolsize            = " << opt_cleanspool_sizeMB << "\n#maxpooldays            =\n#maxpoolsipsize         =\n#maxpoolsipdays         =\n#maxpoolrtpsize         =\n#maxpoolrtpdays         =\n#maxpoolgraphsize       =\n#maxpoolgraphdays       =\n";
						fwrite(tmp.str().c_str(), 1, tmp.str().length(), fdw);
					}
				}
			}
			
			fclose(fdr);
			fclose(fdw);
			rename_file(tmpf.c_str(), configfile);
			unlink(tmpf.c_str());

		}
	}

	clean_maxpoolsize();
	clean_maxpooldays();

	clean_maxpoolsipsize();
	clean_maxpoolsipdays();

	clean_maxpoolrtpsize();
	clean_maxpoolrtpdays();

	clean_maxpoolgraphsize();
	clean_maxpoolgraphdays();

	clean_maxpoolaudiosize();
	clean_maxpoolaudiodays();

	return NULL;
}
