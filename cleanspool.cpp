#include "voipmonitor.h"
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


static void check_index_date(string date);
static void reindex_date_hour_start_syslog(string date, string hour);


extern char opt_chdir[1024];
extern int debugclean;
extern int opt_id_sensor_cleanspool;
extern char configfile[1024];
extern int terminating;
extern int terminating2;

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
extern int opt_maxpool_clean_obsolete;
extern int opt_cleanspool_interval;
extern int opt_cleanspool_sizeMB;
extern int opt_autocleanspool;
extern int opt_autocleanspoolminpercent;
extern int opt_autocleanmingb;

extern MySqlStore *sqlStore;

SqlDb *sqlDbCleanspool = NULL;
pthread_t cleanspool_thread = 0;
bool suspendCleanspool = false;


void unlinkfileslist(string fname, string callFrom) {
	if(suspendCleanspool) {
		return;
	}
 
	syslog(LOG_NOTICE, "cleanspool: call unlinkfileslist(%s) from %s", fname.c_str(), callFrom.c_str());

	char buf[4092];

	FILE *fd = fopen(fname.c_str(), "r");
	if(fd) {
		while(fgets(buf, 4092, fd) != NULL) {
			char *pos;
			if((pos = strchr(buf, '\n')) != NULL) {
				*pos = '\0';
			}
			char *posSizeSeparator;
			if((posSizeSeparator = strrchr(buf, ':')) != NULL) {
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
			if(suspendCleanspool) {
				fclose(fd);
				return;
			}
		}
		fclose(fd);
		unlink(fname.c_str());
	}
	return;
}

void unlink_dirs(string datehour, int all, int sip, int rtp, int graph, int audio, int reg, string callFrom) {
	if(suspendCleanspool) {
		return;
	}

	syslog(LOG_NOTICE, "cleanspool: call unlink_dirs(%s,%s,%s,%s,%s,%s,%s) from %s", 
	       datehour.c_str(), 
	       all == 2 ? "ALL" : all == 1 ? "all" : "---",
	       sip == 2 ? "SIP" : sip == 1 ? "sip" : "---",
	       rtp == 2 ? "RTP" : rtp == 1 ? "rtp" : "---",
	       graph == 2 ? "GRAPH" : graph == 1 ? "graph" : "---",
	       audio == 2 ? "AUDIO" : audio == 1 ? "audio" : "---",
	       reg == 2 ? "REG" : reg == 1 ? "reg" : "---",
	       callFrom.c_str());

	//unlink all directories
	stringstream fname;

	for(int i = 0; i < 60 && !suspendCleanspool; i++) {
		char min[8];
		sprintf(min, "%02d", i);

		if(all) {
			fname.str( std::string() );
			fname.clear();
			fname << datehour.substr(0,4) << "-" << datehour.substr(4,2) << "-" << datehour.substr(6,2) << "/" << datehour.substr(8,2) << "/" << min << "/ALL";
			if(all == 2) {
				rmdir_r(fname.str().c_str());
			} else {
				rmdir(fname.str().c_str());
			}
		}

		if(sip) {
			fname.str( std::string() );
			fname.clear();
			fname << datehour.substr(0,4) << "-" << datehour.substr(4,2) << "-" << datehour.substr(6,2) << "/" << datehour.substr(8,2) << "/" << min << "/SIP";
			if(sip == 2) {
				rmdir_r(fname.str().c_str());
			} else {
				rmdir(fname.str().c_str());
			}
		}

		if(rtp) {
			fname.str( std::string() );
			fname.clear();
			fname << datehour.substr(0,4) << "-" << datehour.substr(4,2) << "-" << datehour.substr(6,2) << "/" << datehour.substr(8,2) << "/" << min << "/RTP";
			if(rtp == 2) {
				rmdir_r(fname.str().c_str());
			} else {
				rmdir(fname.str().c_str());
			}
		}

		if(graph) {
			fname.str( std::string() );
			fname.clear();
			fname << datehour.substr(0,4) << "-" << datehour.substr(4,2) << "-" << datehour.substr(6,2) << "/" << datehour.substr(8,2) << "/" << min << "/GRAPH";
			if(graph == 2) {
				rmdir_r(fname.str().c_str());
			} else {
				rmdir(fname.str().c_str());
			}
		}

		if(audio) {
			fname.str( std::string() );
			fname.clear();
			fname << datehour.substr(0,4) << "-" << datehour.substr(4,2) << "-" << datehour.substr(6,2) << "/" << datehour.substr(8,2) << "/" << min << "/AUDIO";
			if(audio == 2) {
				rmdir_r(fname.str().c_str());
			} else {
				rmdir(fname.str().c_str());
			}
		}

		if(reg) {
			fname.str( std::string() );
			fname.clear();
			fname << datehour.substr(0,4) << "-" << datehour.substr(4,2) << "-" << datehour.substr(6,2) << "/" << datehour.substr(8,2) << "/" << min << "/REG";
			if(reg == 2) {
				rmdir_r(fname.str().c_str());
			} else {
				rmdir(fname.str().c_str());
			}
		}

		// remove minute
		fname.str( std::string() );
		fname.clear();
		fname << datehour.substr(0,4) << "-" << datehour.substr(4,2) << "-" << datehour.substr(6,2) << "/" << datehour.substr(8,2) << "/" << min;
		if(rmdir(fname.str().c_str()) == 0) {
			syslog(LOG_NOTICE, "cleanspool: unlink_dirs: remove %s", fname.str().c_str());
		}
	}
	
	// remove hour
	fname.str( std::string() );
	fname.clear();
	fname << datehour.substr(0,4) << "-" << datehour.substr(4,2) << "-" << datehour.substr(6,2) << "/" << datehour.substr(8,2);
	if(rmdir(fname.str().c_str()) == 0) {
		syslog(LOG_NOTICE, "cleanspool: unlink_dirs: remove %s", fname.str().c_str());
	}

	// remove day
	fname.str( std::string() );
	fname.clear();
	fname << datehour.substr(0,4) << "-" << datehour.substr(4,2) << "-" << datehour.substr(6,2);
	if(rmdir(fname.str().c_str()) == 0) {
		syslog(LOG_NOTICE, "cleanspool: unlink_dirs: remove %s", fname.str().c_str());
	}
}

void clean_maxpoolsize() {

	if(opt_maxpoolsize == 0) {
		return;
	}

	if(debugclean) cout << "clean_maxpoolsize\n";

	// check total size
	if(!sqlDbCleanspool) {
		sqlDbCleanspool = createSqlObject();
	}
	stringstream q;
	q << "SELECT SUM(sipsize) AS sipsize, SUM(rtpsize) AS rtpsize, SUM(graphsize) as graphsize, SUM(audiosize) AS audiosize, SUM(regsize) AS regsize FROM files WHERE id_sensor = " 
		<< (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
	sqlDbCleanspool->query(q.str());
	SqlDb_row row0 = sqlDbCleanspool->fetchRow();
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
		q << "SELECT datehour FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0) << " ORDER BY datehour LIMIT 1";
		if(debugclean) cout << q.str() << "\n";
		sqlDbCleanspool->query(q.str());
		SqlDb_row row = sqlDbCleanspool->fetchRow();
		if(!row) {
			break;
		}

		ostringstream fname;

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/sipsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpoolsize");
		if(suspendCleanspool) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/rtpsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpoolsize");
		if(suspendCleanspool) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/graphsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpoolsize");
		if(suspendCleanspool) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/audiosize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpoolsize");
		if(suspendCleanspool) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/regsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpoolsize");
		if(suspendCleanspool) {
			break;
		}

		unlink_dirs(row["datehour"], 2, 2, 2, 2, 2, 2, "clean_maxpoolsize");
		if(suspendCleanspool) {
			break;
		}

		q.str( std::string() );
		q.clear();
		q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
		if(debugclean) cout << q.str() << "\n";
		sqlDbCleanspool->query(q.str());

		q.str( std::string() );
		q.clear();
		q << "SELECT SUM(sipsize) AS sipsize, SUM(rtpsize) AS rtpsize, SUM(graphsize) AS graphsize, SUM(regsize) AS regsize FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
		if(debugclean) cout << q.str() << "\n";
		sqlDbCleanspool->query(q.str());
		SqlDb_row row2 = sqlDbCleanspool->fetchRow();
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
}

void clean_maxpoolsipsize() {

	if(opt_maxpoolsipsize == 0) {
		return;
	}

	// check total size
	if(!sqlDbCleanspool) {
		sqlDbCleanspool = createSqlObject();
	}
	stringstream q;
	q << "SELECT SUM(sipsize) AS sipsize, SUM(regsize) AS regsize FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
	sqlDbCleanspool->query(q.str());
	SqlDb_row row0 = sqlDbCleanspool->fetchRow();
	uint64_t sipsize = strtoull(row0["sipsize"].c_str(), NULL, 0);
	uint64_t regsize = strtoull(row0["regsize"].c_str(), NULL, 0);
	uint64_t total = sipsize + regsize;

	total /= 1024 * 1024;
	while(total > opt_maxpoolsipsize) {
		// walk all rows ordered by datehour and delete everything 
	
		q.str( std::string() );
		q.clear();
		q << "SELECT * FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0) << " AND (sipsize > 0 or regsize > 0) ORDER BY datehour LIMIT 1";
		sqlDbCleanspool->query(q.str());

		SqlDb_row row = sqlDbCleanspool->fetchRow();
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
		unlinkfileslist(fname.str(), "clean_maxpoolsipsize");
		if(suspendCleanspool) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/regsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpoolsipsize");
		if(suspendCleanspool) {
			break;
		}

		unlink_dirs(row["datehour"], 1, 2, 1, 1, 1, 2, "clean_maxpoolsipsize");
		if(suspendCleanspool) {
			break;
		}

		if(rtpsize + graphsize + audiosize > 0) {
			q.str( std::string() );
			q.clear();
			q << "UPDATE files SET sipsize = 0, regsize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlStore->query_lock(q.str().c_str(), STORE_PROC_ID_CLEANSPOOL);
		} else {
			q.str( std::string() );
			q.clear();
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlStore->query_lock(q.str().c_str(), STORE_PROC_ID_CLEANSPOOL);
		}

		
		q.str( std::string() );
		q.clear();
		q << "SELECT SUM(sipsize) AS sipsize, SUM(regsize) AS regsize FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
		sqlDbCleanspool->query(q.str());
		SqlDb_row row2 = sqlDbCleanspool->fetchRow();
		if(!row2) {
			break;
		}
		sipsize = strtoull(row2["sipsize"].c_str(), NULL, 0);
		regsize = strtoull(row2["regsize"].c_str(), NULL, 0);
		total = sipsize + regsize;
		total /= 1024 * 1024;
	}
}

void clean_maxpoolrtpsize() {

	if(opt_maxpoolrtpsize == 0) {
		return;
	}

	// check total size
	if(!sqlDbCleanspool) {
		sqlDbCleanspool = createSqlObject();
	}
	stringstream q;
	q << "SELECT SUM(rtpsize) AS rtpsize FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
	sqlDbCleanspool->query(q.str());
	SqlDb_row row0 = sqlDbCleanspool->fetchRow();
	uint64_t rtpsize = strtoull(row0["rtpsize"].c_str(), NULL, 0);
	uint64_t total = rtpsize;

	total /= 1024 * 1024;
	while(total > opt_maxpoolrtpsize) {
		// walk all rows ordered by datehour and delete everything 
	
		q.str( std::string() );
		q.clear();
		q << "SELECT * FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0) << " AND (rtpsize > 0) ORDER BY datehour LIMIT 1";
		sqlDbCleanspool->query(q.str());

		SqlDb_row row = sqlDbCleanspool->fetchRow();
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
		unlinkfileslist(fname.str(), "clean_maxpoolrtpsize");
		if(suspendCleanspool) {
			break;
		}

		unlink_dirs(row["datehour"], 1, 1, 2, 1, 1, 1, "clean_maxpoolrtpsize");
		if(suspendCleanspool) {
			break;
		}

		if(sipsize + regsize + graphsize + audiosize > 0) {
			q.str( std::string() );
			q.clear();
			q << "UPDATE files SET rtpsize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlStore->query_lock(q.str().c_str(), STORE_PROC_ID_CLEANSPOOL);
		} else {
			q.str( std::string() );
			q.clear();
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlStore->query_lock(q.str().c_str(), STORE_PROC_ID_CLEANSPOOL);
		}

		
		q.str( std::string() );
		q.clear();
		q << "SELECT SUM(rtpsize) AS rtpsize FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
		sqlDbCleanspool->query(q.str());
		SqlDb_row row2 = sqlDbCleanspool->fetchRow();
		if(!row2) {
			break;
		}
		rtpsize = strtoull(row2["rtpsize"].c_str(), NULL, 0);
		total = rtpsize;
		total /= 1024 * 1024;
	}
}

void clean_maxpoolgraphsize() {

	if(opt_maxpoolgraphsize == 0) {
		return;
	}

	// check total size
	if(!sqlDbCleanspool) {
		sqlDbCleanspool = createSqlObject();
	}
	stringstream q;
	q << "SELECT SUM(graphsize) AS graphsize FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
	sqlDbCleanspool->query(q.str());
	SqlDb_row row0 = sqlDbCleanspool->fetchRow();
	uint64_t graphsize = strtoull(row0["graphsize"].c_str(), NULL, 0);
	uint64_t total = graphsize;

	total /= 1024 * 1024;
	while(total > opt_maxpoolgraphsize) {
		// walk all rows ordered by datehour and delete everything 
	
		q.str( std::string() );
		q.clear();
		q << "SELECT * FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0) << " AND (graphsize > 0) ORDER BY datehour LIMIT 1";
		sqlDbCleanspool->query(q.str());

		SqlDb_row row = sqlDbCleanspool->fetchRow();
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
		unlinkfileslist(fname.str(), "clean_maxpoolgraphsize");
		if(suspendCleanspool) {
			break;
		}

		unlink_dirs(row["datehour"], 1, 1, 1, 2, 1, 1, "clean_maxpoolgraphsize");
		if(suspendCleanspool) {
			break;
		}

		if(sipsize + regsize + rtpsize + audiosize > 0) {
			q.str( std::string() );
			q.clear();
			q << "UPDATE files SET graphsize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlStore->query_lock(q.str().c_str(), STORE_PROC_ID_CLEANSPOOL);
		} else {
			q.str( std::string() );
			q.clear();
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlStore->query_lock(q.str().c_str(), STORE_PROC_ID_CLEANSPOOL);
		}

		
		q.str( std::string() );
		q.clear();
		q << "SELECT SUM(graphsize) AS graphsize FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
		sqlDbCleanspool->query(q.str());
		SqlDb_row row2 = sqlDbCleanspool->fetchRow();
		if(!row2) {
			break;
		}
		graphsize = strtoull(row2["graphsize"].c_str(), NULL, 0);
		total = graphsize;
		total /= 1024 * 1024;
	}
}

void clean_maxpoolaudiosize() {

	if(opt_maxpoolaudiosize == 0) {
		return;
	}

	// check total size
	if(!sqlDbCleanspool) {
		sqlDbCleanspool = createSqlObject();
	}
	stringstream q;
	q << "SELECT SUM(audiosize) AS audiosize FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
	sqlDbCleanspool->query(q.str());
	SqlDb_row row0 = sqlDbCleanspool->fetchRow();
	uint64_t audiosize = strtoull(row0["audiosize"].c_str(), NULL, 0);
	uint64_t total = audiosize;

	total /= 1024 * 1024;
	while(total > opt_maxpoolaudiosize) {
		// walk all rows ordered by datehour and delete everything 
	
		q.str( std::string() );
		q.clear();
		q << "SELECT * FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0) << " AND (audiosize > 0) ORDER BY datehour LIMIT 1";
		sqlDbCleanspool->query(q.str());

		SqlDb_row row = sqlDbCleanspool->fetchRow();
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
		unlinkfileslist(fname.str(), "clean_maxpoolaudiosize");
		if(suspendCleanspool) {
			break;
		}

		unlink_dirs(row["datehour"], 1, 1, 1, 1, 2, 1, "clean_maxpoolaudiosize");
		if(suspendCleanspool) {
			break;
		}

		if(sipsize + regsize + rtpsize + graphsize > 0) {
			q.str( std::string() );
			q.clear();
			q << "UPDATE files SET audiosize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlStore->query_lock(q.str().c_str(), STORE_PROC_ID_CLEANSPOOL);
		} else {
			q.str( std::string() );
			q.clear();
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlStore->query_lock(q.str().c_str(), STORE_PROC_ID_CLEANSPOOL);
		}

		
		q.str( std::string() );
		q.clear();
		q << "SELECT SUM(audiosize) AS audiosize FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
		sqlDbCleanspool->query(q.str());
		SqlDb_row row2 = sqlDbCleanspool->fetchRow();
		if(!row2) {
			break;
		}
		audiosize = strtoull(row2["audiosize"].c_str(), NULL, 0);
		total = audiosize;
		total /= 1024 * 1024;
	}
}


void clean_maxpooldays() {

	if(opt_maxpooldays == 0) {
		return;
	}

	// check total size
	if(!sqlDbCleanspool) {
		sqlDbCleanspool = createSqlObject();
	}

	stringstream q;
	q << "SELECT * FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0) <<  " AND (datehour < DATE_FORMAT(DATE_SUB(NOW(), INTERVAL " << opt_maxpooldays << " DAY), '%Y%m%d%k')" << ") ORDER BY datehour";
	sqlDbCleanspool->query(q.str());
	SqlDb_row row;
	while(row = sqlDbCleanspool->fetchRow()) {
		ostringstream fname;

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/sipsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpooldays");
		if(suspendCleanspool) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/rtpsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpooldays");
		if(suspendCleanspool) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/graphsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpooldays");
		if(suspendCleanspool) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/audiosize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpooldays");
		if(suspendCleanspool) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/regsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpooldays");
		if(suspendCleanspool) {
			break;
		}

		unlink_dirs(row["datehour"], 2, 2, 2, 2, 2, 2, "clean_maxpooldays");
		if(suspendCleanspool) {
			break;
		}

		q.str( std::string() );
		q.clear();
		q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
		sqlStore->query_lock(q.str().c_str(), STORE_PROC_ID_CLEANSPOOL);
	}
}

void clean_maxpoolsipdays() {

	if(opt_maxpoolsipdays == 0) {
		return;
	}

	if(!sqlDbCleanspool) {
		sqlDbCleanspool = createSqlObject();
	}

	stringstream q;
	q << "SELECT * FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0) <<  " AND (sipsize > 0 or regsize > 0) AND (datehour < DATE_FORMAT(DATE_SUB(NOW(), INTERVAL " << opt_maxpoolsipdays << " DAY), '%Y%m%d%k')" << ") ORDER BY datehour";
	sqlDbCleanspool->query(q.str());
	SqlDb_row row;
	while(row = sqlDbCleanspool->fetchRow()) {
		ostringstream fname;

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/sipsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpoolsipdays");
		if(suspendCleanspool) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/regsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpoolsipdays");
		if(suspendCleanspool) {
			break;
		}

		unlink_dirs(row["datehour"], 1, 2, 1, 1, 1, 2, "clean_maxpoolsipdays");
		if(suspendCleanspool) {
			break;
		}

		uint64_t rtpsize = strtoull(row["rtpsize"].c_str(), NULL, 0);
		uint64_t graphsize = strtoull(row["graphsize"].c_str(), NULL, 0);
		uint64_t audiosize = strtoull(row["audiosize"].c_str(), NULL, 0);

		if(rtpsize + graphsize + audiosize > 0) {
			stringstream q;
			q << "UPDATE files SET sipsize = 0, regsize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlStore->query_lock(q.str().c_str(), STORE_PROC_ID_CLEANSPOOL);
		} else {
			stringstream q;
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlStore->query_lock(q.str().c_str(), STORE_PROC_ID_CLEANSPOOL);
		}
	}
}

void clean_maxpoolrtpdays() {

	if(opt_maxpoolrtpdays == 0) {
		return;
	}

	if(!sqlDbCleanspool) {
		sqlDbCleanspool = createSqlObject();
	}

	stringstream q;
	q << "SELECT * FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0) <<  " AND (rtpsize > 0) AND (datehour < DATE_FORMAT(DATE_SUB(NOW(), INTERVAL " << opt_maxpoolrtpdays << " DAY), '%Y%m%d%k')" << ") ORDER BY datehour";
	sqlDbCleanspool->query(q.str());
	SqlDb_row row;
	while(row = sqlDbCleanspool->fetchRow()) {
		ostringstream fname;

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/rtpsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpoolrtpdays");
		if(suspendCleanspool) {
			break;
		}

		unlink_dirs(row["datehour"], 1, 1, 2, 1, 1, 1, "clean_maxpoolrtpdays");
		if(suspendCleanspool) {
			break;
		}

		uint64_t sipsize = strtoull(row["sipsize"].c_str(), NULL, 0);
		uint64_t regsize = strtoull(row["regsize"].c_str(), NULL, 0);
		uint64_t graphsize = strtoull(row["graphsize"].c_str(), NULL, 0);
		uint64_t audiosize = strtoull(row["audiosize"].c_str(), NULL, 0);

		if(sipsize + regsize + graphsize + audiosize > 0) {
			stringstream q;
			q << "UPDATE files SET rtpsize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlStore->query_lock(q.str().c_str(), STORE_PROC_ID_CLEANSPOOL);
		} else {
			stringstream q;
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlStore->query_lock(q.str().c_str(), STORE_PROC_ID_CLEANSPOOL);
		}
	}
}

void clean_maxpoolgraphdays() {

	if(opt_maxpoolgraphdays == 0) {
		return;
	}

	if(!sqlDbCleanspool) {
		sqlDbCleanspool = createSqlObject();
	}

	stringstream q;
	q << "SELECT * FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0) <<  " AND (graphsize > 0) AND (datehour < DATE_FORMAT(DATE_SUB(NOW(), INTERVAL " << opt_maxpoolgraphdays << " DAY), '%Y%m%d%k')" << ") ORDER BY datehour";
	if(debugclean) cout << q.str() << "\n";
	sqlDbCleanspool->query(q.str());
	SqlDb_row row;
	while(row = sqlDbCleanspool->fetchRow()) {
		ostringstream fname;

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/graphsize/" << row["datehour"];
		if(debugclean) cout << "reading: " << fname.str() << "\n";
		unlinkfileslist(fname.str(), "clean_maxpoolgraphdays");
		if(suspendCleanspool) {
			break;
		}

		unlink_dirs(row["datehour"], 1, 1, 1, 2, 1, 1, "clean_maxpoolgraphdays");
		if(suspendCleanspool) {
			break;
		}

		uint64_t sipsize = strtoull(row["sipsize"].c_str(), NULL, 0);
		uint64_t rtpsize = strtoull(row["rtpsize"].c_str(), NULL, 0);
		uint64_t regsize = strtoull(row["regsize"].c_str(), NULL, 0);
		uint64_t audiosize = strtoull(row["audiosize"].c_str(), NULL, 0);

		if(sipsize + regsize + rtpsize + audiosize > 0) {
			stringstream q;
			q << "UPDATE files SET graphsize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlStore->query_lock(q.str().c_str(), STORE_PROC_ID_CLEANSPOOL);
			if(debugclean) cout << q.str() << "\n";
		} else {
			stringstream q;
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlStore->query_lock(q.str().c_str(), STORE_PROC_ID_CLEANSPOOL);
			if(debugclean) cout << q.str() << "\n";
		}
	}
}

void clean_maxpoolaudiodays() {

	if(opt_maxpoolaudiodays == 0) {
		return;
	}

	if(!sqlDbCleanspool) {
		sqlDbCleanspool = createSqlObject();
	}

	stringstream q;
	q << "SELECT * FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0) <<  " AND (audiosize > 0) AND (datehour < DATE_FORMAT(DATE_SUB(NOW(), INTERVAL " << opt_maxpoolaudiodays << " DAY), '%Y%m%d%k')" << ") ORDER BY datehour";
	sqlDbCleanspool->query(q.str());
	SqlDb_row row;
	while(row = sqlDbCleanspool->fetchRow()) {
		ostringstream fname;

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/audiosize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpoolaudiodays");
		if(suspendCleanspool) {
			break;
		}

		unlink_dirs(row["datehour"], 1, 1, 1, 1, 2, 1, "clean_maxpoolaudiodays");
		if(suspendCleanspool) {
			break;
		}

		uint64_t sipsize = strtoull(row["sipsize"].c_str(), NULL, 0);
		uint64_t rtpsize = strtoull(row["rtpsize"].c_str(), NULL, 0);
		uint64_t regsize = strtoull(row["regsize"].c_str(), NULL, 0);
		uint64_t graphsize = strtoull(row["graphsize"].c_str(), NULL, 0);

		if(sipsize + regsize + rtpsize + graphsize > 0) {
			stringstream q;
			q << "UPDATE files SET audiosize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlStore->query_lock(q.str().c_str(), STORE_PROC_ID_CLEANSPOOL);
		} else {
			stringstream q;
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlStore->query_lock(q.str().c_str(), STORE_PROC_ID_CLEANSPOOL);
		}
	}
}

void clean_obsolete_dirs(const char *path) {
	const char *typeFilesIndex[] = {
		"sip",
		"rtp",
		"graph",
		"audio"
	};
	unsigned int maxDays[] = {
		opt_maxpoolsipdays ? opt_maxpoolsipdays : opt_maxpooldays,
		opt_maxpoolrtpdays ? opt_maxpoolrtpdays : opt_maxpooldays,
		opt_maxpoolgraphdays ? opt_maxpoolgraphdays : opt_maxpooldays,
		opt_maxpoolaudiodays ? opt_maxpoolaudiodays : opt_maxpooldays
	};
	for(unsigned int i = 0; i < sizeof(maxDays) / sizeof(maxDays[0]); i++) {
		if(!maxDays[i]) {
			maxDays[i] = 14;
		}
	}
	const char *typeFilesFolder[] = {
		"SIP",
		"RTP",
		"GRAPH",
		"AUDIO",
		"ALL",
		"REG"
	};
	
	if(!path) {
		path = opt_chdir;
	}
	DIR* dp = opendir(path);
	if(!dp) {
		return;
	}
	
	if(!sqlDbCleanspool) {
		sqlDbCleanspool = createSqlObject();
	}
	
	dirent* de;
	string basedir = path;
	while (true) {
		de = readdir(dp);
		if(de == NULL) break;
		if(string(de->d_name) == ".." or string(de->d_name) == ".") continue;
		
		if(de->d_name[0] == '2' && strlen(de->d_name) == 10) {
			int numberOfDayToNow = getNumberOfDayToNow(de->d_name);
			if(numberOfDayToNow > 0) {
				string daydir = basedir + "/" + de->d_name;
				bool removeHourDir = false;
				for(int h = 0; h < 24; h++) {
					char hour[8];
					sprintf(hour, "%02d", h);
					string hourdir = daydir + "/" + hour;
					if(file_exists((char*)hourdir.c_str())) {
						char id_sensor_str[10];
						sprintf(id_sensor_str, "%i", opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
						sqlDbCleanspool->query((string("SELECT * FROM files where id_sensor = ") + id_sensor_str +
									       " and datehour = '" + find_and_replace(de->d_name, "-", "") + hour + "'").c_str());
						SqlDb_row row = sqlDbCleanspool->fetchRow();
						bool removeMinDir = false;
						for(int m = 0; m < 60; m++) {
							char min[8];
							sprintf(min, "%02d", m);
							string mindir = hourdir + "/" + min;
							if(file_exists((char*)mindir.c_str())) {
								bool removeMinTypeDir = false;
								bool keepMainMinTypeFolder = false;
								for(uint i = 0; i < sizeof(typeFilesIndex) / sizeof(typeFilesIndex[0]); i++) {
									string mintypedir = mindir + "/" + typeFilesFolder[i];
									if(file_exists((char*)mintypedir.c_str())) {
										if(row ?
										    !atoi(row[string(typeFilesIndex[i]) + "size"].c_str()) :
										    (unsigned int)numberOfDayToNow > maxDays[i]) {
											rmdir_r(mintypedir.c_str());
											syslog(LOG_NOTICE, "cleanspool: clean obsolete dir %s", mintypedir.c_str());
											removeMinTypeDir = true;
										} else {
											keepMainMinTypeFolder = true;
										}
									}
								}
								if(!keepMainMinTypeFolder) {
									for(uint i = sizeof(typeFilesIndex) / sizeof(typeFilesIndex[0]); i < sizeof(typeFilesFolder) / sizeof(typeFilesFolder[0]); i++) {
										string mintypedir = mindir + "/" + typeFilesFolder[i];
										if(file_exists((char*)mintypedir.c_str())) {
											rmdir_r(mintypedir.c_str());
											syslog(LOG_NOTICE, "cleanspool: clean obsolete dir %s", mintypedir.c_str());
											removeMinTypeDir = true;
										}
									}
								}
								if(removeMinTypeDir) {
									if(rmdir(mindir.c_str()) == 0) {
										syslog(LOG_NOTICE, "cleanspool: clean obsolete dir %s", mindir.c_str());
									}
									removeMinDir = true;
								}
							}
						}
						if(removeMinDir) {
							if(rmdir(hourdir.c_str()) == 0) {
								syslog(LOG_NOTICE, "cleanspool: clean obsolete dir %s", hourdir.c_str());
							}
							removeHourDir = true;
						}
					}
				}
				if(removeHourDir) {
					if(rmdir(daydir.c_str()) == 0) {
						syslog(LOG_NOTICE, "cleanspool: clean obsolete dir %s", daydir.c_str());
					}
				}
			}
		}
	}
	closedir(dp);
}

void convert_filesindex() {
	string path = "./";
	dirent* de;
	DIR* dp;
	errno = 0;
	dp = opendir(path.empty() ? "." : path.c_str());
	if(!dp) {
		return;
	}
	syslog(LOG_NOTICE, "reindexing start");
	char id_sensor_str[10];
	sprintf(id_sensor_str, "%i", opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
	string q = string("DELETE FROM files WHERE id_sensor=") + id_sensor_str;
	sqlStore->query_lock(q.c_str(), STORE_PROC_ID_CLEANSPOOL);
	rmdir_r("filesindex", true, true);
	mkdir_r("filesindex/sipsize", 0777);
	mkdir_r("filesindex/rtpsize", 0777);
	mkdir_r("filesindex/graphsize", 0777);
	mkdir_r("filesindex/audiosize", 0777);
	mkdir_r("filesindex/regsize", 0777);

	while(!terminating) {
		errno = 0;
		de = readdir( dp );
		if(de == NULL) break;
		if(string(de->d_name) == ".." or string(de->d_name) == ".") continue;

		if(de->d_name[0] == '2' && strlen(de->d_name) == 10) {
			reindex_date(de->d_name);
		}
	}
	syslog(LOG_NOTICE, "reindexing done");
	closedir( dp );
}

void check_filesindex() {
	string path = "./";
	dirent* de;
	DIR* dp;
	errno = 0;
	dp = opendir(path.empty() ? "." : path.c_str());
	if(!dp) {
		return;
	}
	syslog(LOG_NOTICE, "check indexes start");

	while(!terminating) {
		errno = 0;
		de = readdir( dp );
		if(de == NULL) break;
		if(string(de->d_name) == ".." or string(de->d_name) == ".") continue;

		if(de->d_name[0] == '2' && strlen(de->d_name) == 10) {
			check_index_date(de->d_name);
		}
	}
	syslog(LOG_NOTICE, "check indexes done");
	closedir( dp );
}

long long reindex_date(string date) {
	long long sumDaySize = 0;
	for(int h = 0; h < 24 && !terminating; h++) {
		sumDaySize += reindex_date_hour(date, h);
	}
	if(!sumDaySize && !terminating) {
		rmdir(date.c_str());
	}
	return(sumDaySize);
}

void check_index_date(string date) {
	if(!sqlDbCleanspool) {
		sqlDbCleanspool = createSqlObject();
	}
	char id_sensor_str[10];
	sprintf(id_sensor_str, "%i", opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
	for(int h = 0; h < 24 && !terminating; h++) {
		char hour[8];
		sprintf(hour, "%02d", h);
		string ymdh = string(date.substr(0,4)) + date.substr(5,2) + date.substr(8,2) + hour;
		map<string, long long> typeSize;
		reindex_date_hour(date, h, true, &typeSize, true);
		if(typeSize["sip"] || typeSize["rtp"] || typeSize["graph"] || typeSize["audio"]) {
			bool needReindex = false;
			sqlDbCleanspool->query(string("select * from files where datehour ='") + ymdh + "'" +
					       " and id_sensor = " + id_sensor_str);
			SqlDb_row row = sqlDbCleanspool->fetchRow();
			if(row) {
				if((typeSize["sip"] && !atoll(row["sipsize"].c_str())) ||
				   (typeSize["rtp"] && !atoll(row["rtpsize"].c_str())) ||
				   (typeSize["graph"] && !atoll(row["graphsize"].c_str())) ||
				   (typeSize["audio"] && !atoll(row["audiosize"].c_str()))) {
					needReindex = true;
				}
			} else {
				needReindex = true;
			}
			if(!needReindex &&
			   ((typeSize["sip"] && !file_exists((string("filesindex/sipsize/") + ymdh).c_str())) ||
			    (typeSize["rtp"] && !file_exists((string("filesindex/rtpsize/") + ymdh).c_str())) ||
			    (typeSize["graph"] && !file_exists((string("filesindex/graphsize/") + ymdh).c_str())) ||
			    (typeSize["audio"] && !file_exists((string("filesindex/audiosize/") + ymdh).c_str())))) {
				needReindex = true;
			}
			if(needReindex) {
				reindex_date_hour(date, h);
			}
		}
	}
}

long long reindex_date_hour(string date, int h, bool readOnly, map<string, long long> *typeSize, bool quickCheck) {
 
	bool syslog_start = false;
			
	char hour[8];
	sprintf(hour, "%02d", h);

	string ymd = date;
	string ymdh = string(ymd.substr(0,4)) + ymd.substr(5,2) + ymd.substr(8,2) + hour;
	
	ofstream *sipfile = NULL;
	ofstream *rtpfile = NULL;
	ofstream *graphfile = NULL;
	ofstream *audiofile = NULL;
	if(!readOnly) {
		sipfile = new ofstream((string("filesindex/sipsize/") + ymdh).c_str(), ios::trunc | ios::out);
		rtpfile = new ofstream((string("filesindex/rtpsize/") + ymdh).c_str(), ios::trunc | ios::out);
		graphfile = new ofstream((string("filesindex/graphsize/") + ymdh).c_str(), ios::trunc | ios::out);
		audiofile = new ofstream((string("filesindex/audiosize/") + ymdh).c_str(), ios::trunc | ios::out);
	}

	long long sipsize = 0;
	long long rtpsize = 0;
	long long graphsize = 0;
	long long audiosize = 0;
	if(typeSize) {
		(*typeSize)["sip"] = 0;
		(*typeSize)["rtp"] = 0;
		(*typeSize)["graph"] = 0;
		(*typeSize)["audio"] = 0;
	}

	for(int m = 0; m < 60; m++) {

		char min[8];
		sprintf(min, "%02d", m);
		DIR* dp;
		dirent* de2;
		bool existsFilesInMinute = false;
	 
		//SIP
		if(!quickCheck || !typeSize || !(*typeSize)["sip"]) {
			bool existsFilesInMinuteType = false;
			string dhmt = date + "/" + hour + "/" + min + "/SIP";
			if(file_exists(dhmt.c_str())) {
				dp = opendir(dhmt.c_str());
				if(dp) {
					while (true) {
						de2 = readdir( dp );
						if(de2 == NULL) break;
						if(string(de2->d_name) == ".." or string(de2->d_name) == ".") continue;
						existsFilesInMinuteType = true;
						if(!syslog_start && !readOnly) {
							reindex_date_hour_start_syslog(date, hour);
							syslog_start = true;
						}
						if(quickCheck && typeSize) {
							(*typeSize)["sip"] = 1;
							break;
						}
						string dhmtf = dhmt + '/' + de2->d_name;
						long long size = GetFileSizeDU(dhmtf);
						if(size == 0) size = 1;
						sipsize += size;
						if(!readOnly) {
							(*sipfile) << dhmtf << ":" << size << "\n";
						}
					}
					closedir(dp);
				}
				if(existsFilesInMinuteType) {
					existsFilesInMinute = true;
				} else if(!readOnly) {
					rmdir(dhmt.c_str());
				}
			}
		}
		//RTP
		if(!quickCheck || !typeSize || !(*typeSize)["rtp"]) {
			bool existsFilesInMinuteType = false;
			string dhmt = date + "/" + hour + "/" + min + "/RTP";
			if(file_exists(dhmt.c_str())) {
				dp = opendir(dhmt.c_str());
				if(dp) {
					while (true) {
						de2 = readdir( dp );
						if(de2 == NULL) break;
						if(string(de2->d_name) == ".." or string(de2->d_name) == ".") continue;
						existsFilesInMinuteType = true;
						if(!syslog_start && !readOnly) {
							reindex_date_hour_start_syslog(date, hour);
							syslog_start = true;
						}
						if(quickCheck && typeSize) {
							(*typeSize)["rtp"] = 1;
							break;
						}
						string dhmtf = dhmt + '/' + de2->d_name;
						long long size = GetFileSizeDU(dhmtf);
						if(size == 0) size = 1;
						rtpsize += size;
						if(!readOnly) {
							(*rtpfile) << dhmtf << ":" << size << "\n";
						}
					}
					closedir(dp);
				}
				if(existsFilesInMinuteType) {
					existsFilesInMinute = true;
				} else if(!readOnly) {
					rmdir(dhmt.c_str());
				}
			}
		}
		//GRAPH
		if(!quickCheck || !typeSize || !(*typeSize)["graph"]) {
			bool existsFilesInMinuteType = false;
			string dhmt = date + "/" + hour + "/" + min + "/GRAPH";
			if(file_exists(dhmt.c_str())) {
				dp = opendir(dhmt.c_str());
				if(dp) {
					while (true) {
						de2 = readdir( dp );
						if(de2 == NULL) break;
						if(string(de2->d_name) == ".." or string(de2->d_name) == ".") continue;
						existsFilesInMinuteType = true;
						if(!syslog_start && !readOnly) {
							reindex_date_hour_start_syslog(date, hour);
							syslog_start = true;
						}
						if(quickCheck && typeSize) {
							(*typeSize)["graph"] = 1;
							break;
						}
						string dhmtf = dhmt + '/' + de2->d_name;
						long long size = GetFileSizeDU(dhmtf);
						if(size == 0) size = 1;
						graphsize += size;
						if(!readOnly) {
							(*graphfile) << dhmtf << ":" << size << "\n";
						}
					}
					closedir(dp);
				}
				if(existsFilesInMinuteType) {
					existsFilesInMinute = true;
				} else if(!readOnly) {
					rmdir(dhmt.c_str());
				}
			}
		}
		//AUDIO
		if(!quickCheck || !typeSize || !(*typeSize)["audio"]) {
			bool existsFilesInMinuteType = false;
			string dhmt = date + "/" + hour + "/" + min + "/AUDIO";
			if(file_exists(dhmt.c_str())) {
				dp = opendir(dhmt.c_str());
				if(dp) {
					while (true) {
						de2 = readdir( dp );
						if(de2 == NULL) break;
						if(string(de2->d_name) == ".." or string(de2->d_name) == ".") continue;
						existsFilesInMinuteType = true;
						if(!syslog_start && !readOnly) {
							reindex_date_hour_start_syslog(date, hour);
							syslog_start = true;
						}
						if(quickCheck && typeSize) {
							(*typeSize)["audio"] = 1;
							break;
						}
						string dhmtf = dhmt + '/' + de2->d_name;
						long long size = GetFileSizeDU(dhmtf);
						if(size == 0) size = 1;
						audiosize += size;
						if(!readOnly) {
							(*audiofile) << dhmtf << ":" << size << "\n";
						}
					}
					closedir(dp);
				}
				if(existsFilesInMinuteType) {
					existsFilesInMinute = true;
				} else if(!readOnly) {
					rmdir(dhmt.c_str());
				}
			}
		}

		if(!readOnly) {
			// remove obsolete directories
			stringstream t;
			t.str( std::string() );
			t.clear();
			t << date << "/" << hour << "/" << min << "/ALL";
			rmdir(t.str().c_str());
			t.str( std::string() );
			t.clear();
			t << date << "/" << hour << "/" << min << "/REG";
			rmdir(t.str().c_str());

			if(!existsFilesInMinute) {
				t.str( std::string() );
				t.clear();
				t << date << "/" << hour << "/" << min;
				rmdir(t.str().c_str());
			}
		}
	}

	if(!readOnly) {
		if(sipsize + rtpsize + graphsize + audiosize) {
			stringstream query;
			int id_sensor = opt_id_sensor_cleanspool == -1 ? 0 : opt_id_sensor_cleanspool;
			query << "INSERT INTO files SET files.datehour = " << ymdh << ", id_sensor = " << id_sensor << ", "
			      << "sipsize = " << sipsize << ", rtpsize = " << rtpsize << ", graphsize = " << graphsize << ", audiosize = " << audiosize << " " 
			      << "ON DUPLICATE KEY UPDATE "
			      << "sipsize = " << sipsize << ", rtpsize = " << rtpsize << ", graphsize = " << graphsize << ", audiosize = " << audiosize << ";"; 
			sqlStore->query_lock(query.str().c_str(), STORE_PROC_ID_CLEANSPOOL);

		} else {
			stringstream query;
			int id_sensor = opt_id_sensor_cleanspool == -1 ? 0 : opt_id_sensor_cleanspool;
			query << "DELETE FROM files WHERE datehour = " << ymdh << " AND " << "id_sensor = " << id_sensor << ";";
			sqlStore->query_lock(query.str().c_str(), STORE_PROC_ID_CLEANSPOOL);
			stringstream t;
			t.str( std::string() );
			t.clear();
			t << date << "/" << hour;
			rmdir(t.str().c_str());
		}

		sipfile->close();
		rtpfile->close();
		graphfile->close();
		audiofile->close();
		if(sipsize == 0) {
			unlink((string("filesindex/sipsize/") + ymdh).c_str());
		}
		if(rtpsize == 0) {
			unlink((string("filesindex/rtpsize/") + ymdh).c_str());
		}
		if(graphsize == 0) {
			unlink((string("filesindex/graphsize/") + ymdh).c_str());
		}
		if(audiosize == 0) {
			unlink((string("filesindex/audiosize/") + ymdh).c_str());
		}
		
		if(sipsize + rtpsize + graphsize + audiosize) {
			syslog(LOG_NOTICE, "reindexing files in [%s/%s] done", date.c_str(), hour);
		}
	}
	if(typeSize && !quickCheck) {
		(*typeSize)["sip"] = sipsize;
		(*typeSize)["rtp"] = rtpsize;
		(*typeSize)["graph"] = graphsize;
		(*typeSize)["audio"] = audiosize;
	}
	
	return(sipsize + rtpsize + graphsize + audiosize);
}

void reindex_date_hour_start_syslog(string date, string hour) {
	syslog(LOG_NOTICE, "reindexing files in [%s/%s] start", date.c_str(), hour.c_str());
}

void check_disk_free_run(bool enableRunCleanSpoolThread) {
	double freeSpacePercent = (double)GetFreeDiskSpace(opt_chdir, true) / 100;
	double freeSpaceGB = (double)GetFreeDiskSpace(opt_chdir) / (1024 * 1024 * 1024);
	double totalSpaceGB = (double)GetTotalDiskSpace(opt_chdir) / (1024 * 1024 * 1024);
	if(freeSpacePercent < opt_autocleanspoolminpercent && freeSpaceGB < opt_autocleanmingb) {
		syslog(LOG_NOTICE, "low spool disk space - executing filesindex");
		convert_filesindex();
		freeSpacePercent = (double)GetFreeDiskSpace(opt_chdir, true) / 100;
		freeSpaceGB = (double)GetFreeDiskSpace(opt_chdir) / (1024 * 1024 * 1024);
		if(freeSpacePercent < opt_autocleanspoolminpercent) {
			SqlDb *sqlDb = createSqlObject();
			stringstream q;
			q << "SELECT SUM(sipsize + rtpsize + graphsize + audiosize) as sum_size FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlDb->query(q.str());
			SqlDb_row row = sqlDb->fetchRow();
			if(row) {
				double usedSizeGB = atol(row["sum_size"].c_str()) / (1024 * 1024 * 1024);
				opt_maxpoolsize = (usedSizeGB + freeSpaceGB - min(totalSpaceGB * opt_autocleanspoolminpercent / 100, (double)opt_autocleanmingb)) * 1024;
				syslog(LOG_NOTICE, "low spool disk space - maxpoolsize set to new value: %u MB", opt_maxpoolsize);
				if(enableRunCleanSpoolThread) {
					runCleanSpoolThread();
				}
			}
			delete sqlDb;
		}
	}
}

static pthread_mutex_t check_disk_free_mutex;
static bool check_disk_free_mutex_init = false;

void *check_disk_free_thread(void*) {
	check_disk_free_run(true);
	pthread_mutex_unlock(&check_disk_free_mutex);
	return(NULL);
}

void run_check_disk_free_thread() {
	if(cleanspool_thread) {
		return;
	}
	if(!check_disk_free_mutex_init) {
		pthread_mutex_init(&check_disk_free_mutex, NULL);
		check_disk_free_mutex_init = true;
	}
	if(pthread_mutex_trylock(&check_disk_free_mutex) == 0) {
		pthread_t thread;
		pthread_create(&thread, NULL, check_disk_free_thread, NULL);
	}
}

bool check_exists_act_records_in_files() {
	bool ok = false;
	if(!sqlDbCleanspool) {
		sqlDbCleanspool = createSqlObject();
	}
	char id_sensor_str[10];
	sprintf(id_sensor_str, "%i", opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
	sqlDbCleanspool->query(string("select max(calldate) as max_calldate from cdr where calldate > date_add(now(), interval -1 day) and ") +
			       "id_sensor " + (opt_id_sensor_cleanspool > 0 ? string("=") + id_sensor_str : "is null"));
	SqlDb_row row = sqlDbCleanspool->fetchRow();
	if(!row || !row["max_calldate"].length()) {
		return(true);
	}
	time_t maxCdrTime = stringToTime(row["max_calldate"].c_str());
	for(int i = 0; i < 12; i++) {
		time_t checkTime = maxCdrTime - i * 60 * 60;
		struct tm *checkTimeInfo = localtime(&checkTime);
		char datehour[20];
		strftime(datehour, 20, "%Y%m%d%H", checkTimeInfo);
		sqlDbCleanspool->query(string("select * from files where datehour ='") + datehour + "'" +
				       " and id_sensor = " + id_sensor_str);
		if(sqlDbCleanspool->fetchRow()) {
			ok = true;
			break;
		}
	}
	return(ok);
}

bool check_exists_act_files_in_filesindex() {
	bool ok = false;
	if(!sqlDbCleanspool) {
		sqlDbCleanspool = createSqlObject();
	}
	char id_sensor_str[10];
	sprintf(id_sensor_str, "%i", opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
	sqlDbCleanspool->query(string("select max(calldate) as max_calldate from cdr where calldate > date_add(now(), interval -1 day) and ") +
			       "id_sensor " + (opt_id_sensor_cleanspool > 0 ? string("=") + id_sensor_str : "is null"));
	SqlDb_row row = sqlDbCleanspool->fetchRow();
	if(!row || !row["max_calldate"].length()) {
		return(true);
	}
	time_t maxCdrTime = stringToTime(row["max_calldate"].c_str());
	for(int i = 0; i < 12; i++) {
		time_t checkTime = maxCdrTime - i * 60 * 60;
		struct tm *checkTimeInfo = localtime(&checkTime);
		char date[20];
		strftime(date, 20, "%Y%m%d", checkTimeInfo);
		for(int j = 0; j < 24; j++) {
			char datehour[20];
			strcpy(datehour, date);
			sprintf(datehour + strlen(datehour), "%02i", j);
			if(FileExists((char*)(string(opt_chdir) + "/filesindex/sipsize/" + datehour).c_str())) {
				ok = true;
				break;
			}
		}
		if(ok) {
			break;
		}
	}
	return(ok);
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
	if(!dp) {
		return;
	}
	dirent* de;
	string basedir = path;
	if(!sqlDbCleanspool) {
		sqlDbCleanspool = createSqlObject();
	}
	while (true) {
		errno = 0;
		de = readdir(dp);
		if(de == NULL) break;
		if(string(de->d_name) == ".." or string(de->d_name) == ".") continue;
		
		if(de->d_name[0] == '2' && strlen(de->d_name) == 10 &&
		   (!dirfilter || strstr(de->d_name, dirfilter))) {
			//cycle through 24 hours
			syslog(LOG_NOTICE, "check files in [%s]", de->d_name);
			for(int h = 0; h < 24; h++) {
				long long sumSizeMissingFilesInIndex[2] = {0, 0};
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
								if((pos = strchr(buf, '\n')) != NULL) {
									*pos = '\0';
								}
								char *posSizeSeparator;
								if((posSizeSeparator = strrchr(buf, ':')) != NULL) {
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
							if(de2 == NULL) break;
							if(de2->d_type == 4 or string(de2->d_name) == ".." or string(de2->d_name) == ".") continue;
							filesInFolder.push_back(timetypedir + "/" + de2->d_name);
						}
						closedir(dp);
					}
					for(uint j = 0; j < filesInFolder.size(); j++) {
						if(!std::binary_search(filesInIndex.begin(), filesInIndex.end(), filesInFolder[j])) {
							long long size = GetFileSize((string(opt_chdir) + "/" + filesInFolder[j]).c_str());
							long long sizeDU = GetFileSizeDU((string(opt_chdir) + "/" + filesInFolder[j]).c_str());
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
					sprintf(id_sensor_str, "%i", opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
					sqlDbCleanspool->query(string(
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
					SqlDb_row rowSum = sqlDbCleanspool->fetchRow();
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

volatile int clean_spooldir_run_processing = 0;

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
			move_file(tmpf.c_str(), configfile);

		}
	}
	
	if(!check_exists_act_records_in_files() ||
	   !check_exists_act_files_in_filesindex()) {
		convert_filesindex();
	}
	
	clean_spooldir_run_processing = 1;

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
	
	if(opt_maxpool_clean_obsolete) {
		clean_obsolete_dirs();
	}
	
	clean_spooldir_run_processing = 0;

	return NULL;
}

bool isSetCleanspoolParameters() {
	return(opt_maxpoolsize ||
	       opt_maxpooldays ||
	       opt_maxpoolsipsize ||
	       opt_maxpoolsipdays ||
	       opt_maxpoolrtpsize ||
	       opt_maxpoolrtpdays ||
	       opt_maxpoolgraphsize ||
	       opt_maxpoolgraphdays ||
	       opt_maxpoolaudiosize ||
	       opt_maxpoolaudiodays ||
	       opt_cleanspool_interval ||
	       opt_cleanspool_sizeMB);
}

void *clean_spooldir(void *dummy) {
	if(debugclean) syslog(LOG_ERR, "run clean_spooldir()");
	while(!terminating2) {
		if(!suspendCleanspool) {
			if(debugclean) syslog(LOG_ERR, "run clean_spooldir_run");
			clean_spooldir_run(NULL);
			check_disk_free_run(false);
		}
		for(int i = 0; i < 300 && !terminating2; i++) {
			sleep(1);
		}
	}
	return NULL;
}

void runCleanSpoolThread() {
	if(!cleanspool_thread) {
		if(debugclean) syslog(LOG_ERR, "pthread_create(clean_spooldir)");
		pthread_create(&cleanspool_thread, NULL, clean_spooldir, NULL);
	}
}