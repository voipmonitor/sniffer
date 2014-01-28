#include <syslog.h>
#include <string.h>
#include <math.h>
#include <vector>
#include <algorithm>

#include "voipmonitor.h"
#include "config_mysql.h"
#include "calltable.h"
#include "odbc.h"
#include "sql_db.h"
#include "tools.h"

using namespace std;

void
config_load_mysql() {
#if 0
	SqlDb *sqlDb = createSqlObject();
	SqlDb_row row;
	stringstream q;
	if(opt_id_sensor) {
		q << "SELECT * FROM sensor_conf WHERE id_sensor = " << opt_id_sensor << " LIMIT 1";
	} else {
		q << "SELECT * FROM sensor_conf WHERE id_sensor IS NULL LIMIT 1";
	}
	sqlDb->query(q.str());

	while((row = sqlDb->fetchRow())) {
		syslog(LOG_NOTICE, "Found configuration in database for id_sensor:[%d] - loading\n", opt_id_sensor);


// sipport
		{
		vector<string>ports = split(row["sipport"].c_str(), split(",|;|\t|\r|\n", "|"), true);
		sipportmatrix[5060] = 0;
		for(size_t i = 0; i < ports.size(); i++) {
                        sipportmatrix[atoi(ports[i].c_str())] = 1;
                }
		}
// httport 
		{
		vector<string>ports = split(row["httpport"].c_str(), split(",|;|\t|\r|\n", "|"), true);
		httpportmatrix[5060] = 0;
		for(size_t i = 0; i < ports.size(); i++) {
                        httpportmatrix[atoi(ports[i].c_str())] = 1;
                }
		}

		{
		vector<string>httpipvec = split(row["httpip"].c_str(), split(",|;|\t|\r|\n", "|"), true);
		for(size_t i = 0; i < httpipvec.size(); i++) {
			u_int32_t ip;
			int lengthMask = 32;
			char *pointToSeparatorLengthMask = strchr((char*)httpipvec[i].c_str(), '/');
			if(pointToSeparatorLengthMask) {
				*pointToSeparatorLengthMask = 0;
				ip = htonl(inet_addr(httpipvec[i].c_str()));
				lengthMask = atoi(pointToSeparatorLengthMask + 1);
			} else {
				ip = htonl(inet_addr(httpipvec[i].c_str()));
			}
			if(lengthMask < 32) {
				ip = ip >> (32 - lengthMask) << (32 - lengthMask);
			}
			if(ip) {
				if(lengthMask < 32) {
					httpnet.push_back(d_u_int32_t(ip, lengthMask));
				} else {
					httpip.push_back(ip);
				}
			}
                }
                if(httpip.size() > 1) {
                        std::sort(httpip.begin(), httpip.end());
                }
		}

// ipaccountport
		{
		vector<string>ports = split(row["ipaccountport"].c_str(), split(",|;|\t|\r|\n", "|"), true);
		if(ports.size() and !ipaccountportmatrix) {
			ipaccountportmatrix = (char*)calloc(1, sizeof(char) * 65537);
			ipaccountportmatrix[5060] = 0;
		}
		for(size_t i = 0; i < ports.size(); i++) {
                        ipaccountportmatrix[atoi(ports[i].c_str())] = 1;
                }
		}

// natalias 
		{
		vector<string>natalias = split(row["natalias"].c_str(), split(",|;|\t|\r|\n", "|"), true);

		char local_ip[30], extern_ip[30];
		in_addr_t nlocal_ip, nextern_ip;
		int len, j = 0;
		char *s = local_ip;

		for(size_t i = 0; i < natalias.size(); i++) {
			s = local_ip;
			j = 0;
			for(int ii = 0; ii < 30; ii++) {
				local_ip[ii] = '\0';
				extern_ip[ii] = '\0';
			}       
				
			len = strlen(natalias[i].c_str());
			for(int ii = 0; ii < len; ii++) {
				if(natalias[i].c_str()[ii] == ' ' or natalias[i].c_str()[ii] == ':' or natalias[i].c_str()[ii] == '=' or natalias[i].c_str()[ii] == ' ') {
					// moving s to b pointer (write to b ip
					s = extern_ip; 
					j = 0;
				} else {
					s[j] = natalias[i].c_str()[ii];
					j++;
				}       
			}	       
			if ((int32_t)(nlocal_ip = inet_addr(local_ip)) != -1 && (int32_t)(nextern_ip = inet_addr(extern_ip)) != -1 ){
				nat_aliases[nlocal_ip] = nextern_ip;
				if(verbosity > 3) printf("adding local_ip[%s][%u] = extern_ip[%s][%u]\n", local_ip, nlocal_ip, extern_ip, nextern_ip);
			}      
		}	      
		}     
	
// interface
		if(row["interface"] != "") {
			std::size_t length = row["interface"].copy(ifname, 1023, 0);
			ifname[length]='\0';
		}

		if(row["cleandatabase"] != "") {
			opt_cleandatabase_cdr = opt_cleandatabase_register_state = opt_cleandatabase_register_failed = atoi(row["cleandatabase"].c_str());
		}

		if(row["cleandatabase_cdr"] != "") {
			opt_cleandatabase_cdr = atoi(row["cleandatabase_cdr"].c_str());
		}

		if(row["cleandatabase_register_state"] != "") {
			opt_cleandatabase_register_failed = atoi(row["cleandatabase_register_state"].c_str());
		}

		if(row["cleandatabase_register_failed"] != "") {
			opt_cleandatabase_register_failed = atoi(row["cleandatabase_register_failed"].c_str());
		}


		if(row["maxpoolsize"] != "") {
			opt_maxpoolsize = atoi(row["maxpoolsize"].c_str());
		}

		if(row["maxpooldays"] != "") {
			opt_maxpooldays = atoi(row["maxpooldays"].c_str());
		}

		if(row["maxpoolsipsize"] != "") {
			opt_maxpoolsipsize = atoi(row["opt_maxpoolsipsize"].c_str());
		}

		if(row["maxpooldays"] != "") {
			opt_maxpooldays = atoi(row["maxpooldays"].c_str());
		}

		if(row["maxpoolsipsize"] != "") {
			opt_maxpoolsipsize = atoi(row["maxpoolsipsize"].c_str());
		}

		if(row["maxpoolsipdays"] != "") {
			opt_maxpoolsipdays = atoi(row["maxpoolsipdays"].c_str());
		}

		if(row["maxpoolrtpsize"] != "") {
			opt_maxpoolrtpsize = atoi(row["maxpoolrtpsize"].c_str());
		}

		if(row["maxpoolsipdays"] != "") {
			opt_maxpoolsipdays = atoi(row["maxpoolsipdays"].c_str());
		}

		if(row["maxpoolrtpsize"] != "") {
			opt_maxpoolrtpsize = atoi(row["maxpoolrtpsize"].c_str());
		}

		if(row["maxpoolrtpdays"] != "") {
			opt_maxpoolrtpdays = atoi(row["maxpoolrtpdays"].c_str());
		}

		if(row["maxpoolgraphsize"] != "") {
			opt_maxpoolgraphsize = atoi(row["maxpoolgraphsize"].c_str());
		}

		if(row["maxpoolgraphdays"] != "") {
			opt_maxpoolgraphsize = atoi(row["maxpoolgraphdays"].c_str());
		}

		if(row["maxpoolgraphdays"] != "") {
			opt_maxpoolgraphdays = atoi(row["maxpoolgraphdays"].c_str());
		}

		if(row["maxpoolaudiosize"] != "") {
			opt_maxpoolaudiosize = atoi(row["maxpoolaudiosize"].c_str());
		}

		if(row["maxpoolaudiodays"] != "") {
			opt_maxpoolaudiodays = atoi(row["maxpoolaudiodays"].c_str());
		}

		if(row["maxpool_clean_obsolete"] != "") {
			opt_maxpool_clean_obsolete = atoi(row["maxpool_clean_obsolete"].c_str());
		}

		if(row["pcapcommand"] != "") {
			std::size_t length = row["pcapcommand"].copy(pcapcommand, 4091, 0);
			pcapcommand[length]='\0';
		}

		if(row["filtercommand"] != "") {
			std::size_t length = row["filtercommand"].copy(filtercommand, 4091, 0);
			filtercommand[length]='\0';
		}

		if(row["ringbuffer"] != "") {
			opt_ringbuffer = MIN(atoi(row["ringbuffer"].c_str()), 2000);
		}

		if(row["rtpthreads"] != "") {
			num_threads = atoi(row["rtpthreads"].c_str());
		}

		if(row["rtptimeout"] != "") {
			rtptimeout = atoi(row["rtptimeout"].c_str());
		}

		if(row["rtpthread-buffer"] != "") {
			rtpthreadbuffer = atoi(row["rtpthread-buffer"].c_str());
		}

		if(row["rtp-firstleg"] != "") {
			opt_rtp_firstleg = atoi(row["rtp-firstleg"].c_str());
		}

		if(row["allow-zerossrc"] != "") {
			opt_allow_zerossrc = atoi(row["allow-zerossrc"].c_str());
		}

		if(row["sip-register"] != "") {
			opt_sip_register = atoi(row["sip-register"].c_str());
		}

		if(row["sip-register-active-nologbin"] != "") {
			opt_sip_register_active_nologbin = atoi(row["sip-register-active-nologbin"].c_str());
		}

		if(row["deduplicate"] != "") {
			opt_dup_check = atoi(row["deduplicate"].c_str());
		}

		if(row["deduplicate_ipheader"] != "") {
			opt_dup_check_ipheader = atoi(row["deduplicate_ipheader"].c_str());
		}

		if(row["dscp"] != "") {
			opt_dscp = atoi(row[""].c_str());
		}

		if(row["cdrproxy"] != "") {
			opt_cdrproxy = atoi(row["cdrproxy"].c_str());
		}

		if(row["mos_g729"] != "") {
			opt_mos_g729 = atoi(row["mos_g729"].c_str());
		}

		if(row["nocdr"] != "") {
			opt_nocdr = atoi(row["nocdr"].c_str());
		}

		if(row["skipdefault"] != "") {
			opt_skipdefault = atoi(row["skipdefault"].c_str());
		}

		if(row["skinny"] != "") {
			opt_skinny = atoi(row["skinny"].c_str());
		}

		if(row["cdr_partition"] != "") {
			opt_cdr_partition = atoi(row["cdr_partition"].c_str());
		}

		if(row["cdr_sipport"] != "") {
			opt_cdr_sipport = atoi(row["cdr_sipport"].c_str());
		}

		if(row["create_old_partitions"] != "") {
			opt_create_old_partitions = atoi(row["create_old_partitions"].c_str());
		}

		if(row["create_old_partitions_from"] != "") {
			opt_create_old_partitions = getNumberOfDayToNow(row["create_old_partitions_from"].c_str());
		}

		if(row["database_backup_from_date"] != "") {
			opt_create_old_partitions = getNumberOfDayToNow(row["database_backup_from_date"].c_str());
			std::size_t length = row["database_backup_from_date"].copy(filtercommand, sizeof(opt_database_backup_from_date), 0);
			filtercommand[length]='\0';
		}

		if(row["disable_partition_operations"] != "") {
			= atoi(row["disable_partition_operations"].c_str());
		}

		if(row["cdr_ua_enable"] != "") {
			opt_cdr_ua_enable = atoi(row["cdr_ua_enable"].c_str());
		}

// custom headers 
		for(int i = 0; i < 2; i++) {
			if(i == 0 ?
				(value = ini.GetValue("general", "custom_headers_cdr", NULL)) ||
				(value = ini.GetValue("general", "custom_headers", NULL)) :
				(value = ini.GetValue("general", "custom_headers_message", NULL)) != NULL) {
				char *pos = (char*)value;
				while(pos && *pos) {
					char *posSep = strchr(pos, ';');
					if(posSep) {
						*posSep = 0;
					}
					string custom_header = pos;
					custom_header.erase(custom_header.begin(), std::find_if(custom_header.begin(), custom_header.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
					custom_header.erase(std::find_if(custom_header.rbegin(), custom_header.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), custom_header.end());
					string custom_header_field = "custom_header__" + custom_header;
					std::replace(custom_header_field.begin(), custom_header_field.end(), ' ', '_');
					if(i == 0) {
						opt_custom_headers_cdr.push_back(dstring(custom_header, custom_header_field));
					} else {
						opt_custom_headers_message.push_back(dstring(custom_header, custom_header_field));
					}
					pos = posSep ? posSep + 1 : NULL;
				}
			}
		}


		if(row[""] != "") {
			= atoi(row[""].c_str());
		}

		if(row[""] != "") {
			= atoi(row[""].c_str());
		}

		if(row[""] != "") {
			= atoi(row[""].c_str());
		}

		if(row[""] != "") {
			= atoi(row[""].c_str());
		}

		if(row[""] != "") {
			= atoi(row[""].c_str());
		}

		if(row[""] != "") {
			= atoi(row[""].c_str());
		}

		if(row[""] != "") {
			= atoi(row[""].c_str());
		}

		if(row[""] != "") {
			= atoi(row[""].c_str());
		}

		if(row[""] != "") {
			= atoi(row[""].c_str());
		}

		if(row[""] != "") {
			= atoi(row[""].c_str());
		}

		if(row[""] != "") {
			= atoi(row[""].c_str());
		}

		if(row[""] != "") {
			= atoi(row[""].c_str());
		}

		if(row[""] != "") {
			= atoi(row[""].c_str());
		}

		if(row[""] != "") {
			= atoi(row[""].c_str());
		}

		if(row[""] != "") {
			= atoi(row[""].c_str());
		}

		if(row[""] != "") {
			= atoi(row[""].c_str());
		}

		if(row[""] != "") {
			= atoi(row[""].c_str());
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		if(row[""] != "") {
		}

		

/*
		filterRow->ip = (unsigned int)strtoul(row["ip"].c_str(), NULL, 0);
		filterRow->mask = atoi(row["mask"].c_str());
		filterRow->direction = row.isNull("direction") ? 0 : atoi(row["direction"].c_str());
		filterRow->rtp = row.isNull("rtp") ? -1 : atoi(row["rtp"].c_str());
*/
	}
	delete sqlDb;
	#endif
}
