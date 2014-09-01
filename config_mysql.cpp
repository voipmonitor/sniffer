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
			opt_disable_partition_operations = atoi(row["disable_partition_operations"].c_str());
		}

		if(row["cdr_ua_enable"] != "") {
			opt_cdr_ua_enable = atoi(row["cdr_ua_enable"].c_str());
		}

// custom headers 
		{
		char *custom_headers = NULL;	
		char cusheaders[16000];
		if(!row.isNull("custom_headers") and row["custom_headers"] != "") {
			row["custom_headers"].copy(cusheaders, sizeof(cusheaders), 0);
			custom_headers = cusheaders;
		} else if(!row.isNull("custom_headers_cdr") and row["custom_headers_cdr"] != "") {
			row["custom_headers_cdr"].copy(cusheaders, sizeof(cusheaders), 0);
			custom_headers = cusheaders;
		}
		char *custom_headers_message = NULL;	
		char cusheadersmsg[16000];
		if(!row.isNull("custom_headers_message") and row["custom_headers_message"] != "") {
			row["custom_headers_message"].copy(cusheadersmsg, sizeof(cusheadersmsg), 0);
			custom_headers_message = cusheadersmsg;
		}
		char *value = NULL;
		for(int i = 0; i < 2; i++) {
			if(i == 0)
				value = custom_headers;
			else 
				value = custom_headers_message;
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

		if(row["savesip"] != "") {
			opt_saveSIP = atoi(row["savesip"].c_str());
		}

		if(row["savertp"] != "") {
			switch(row["savertp"][0]) {
			case 'y':
			case 'Y':
			case '1':
				opt_saveRTP = 1;
				break;
			case 'h':
			case 'H':
				opt_onlyRTPheader = 1;
				break;
			}
		}

		if(row["saverfc2833"] != "") {
			opt_saverfc2833 = atoi(row["saverfc2833"].c_str());
		}

		if(row["dtmf2db"] != "") {
			opt_dbdtmf = atoi(row["dtmf2db"].c_str());
		}

		if(row["saveudptl"] != "") {
			opt_saveudptl = atoi(row["saveudptl"].c_str());
		}

		if(row["norecord-header"] != "") {
			opt_norecord_header = atoi(row["norecord-header"].c_str());
		}

		if(row["vmbuffer"] != "") {
			qringmax = (unsigned int)((unsigned int)MIN(atoi(row["vmbuffer"].c_str()), 4000) * 1024 * 1024 / (unsigned int)sizeof(pcap_packet));
		}

		if(row["matchheader"] != "") {
			row["matchheader"].copy(opt_match_header, sizeof(opt_match_header), 0);
		}

		if(row["domainport"] != "") {
			opt_domainport = atoi(row["domainport"].c_str());
		}

		if(row["managerport"] != "") {
			opt_manager_port = atoi(row["managerport"].c_str());
		}

		if(row["managerip"] != "") {
			row["managerip"].copy(opt_manager_ip, sizeof(opt_manager_ip), 0);
		}

		if(row["managerclient"] != "") {
			row["managerclient"].copy(opt_clientmanager, sizeof(opt_clientmanager), 0);
		}

		if(row["managerclientport"] != "") {
			opt_clientmanagerport = atoi(row["managerclientport"].c_str());
		}

		if(row["savertcp"] != "") {
			opt_saveRTCP = atoi(row["savertcp"].c_str());
		}

		if(row["saveaudio"] != "") {
			switch(row["saveaudio"][0]) {
			case 'y':
			case '1':
			case 'w':
				opt_saveWAV = 1;
				opt_audio_format = FORMAT_WAV;
				break;
			case 'o':
				opt_saveWAV = 1;
				opt_audio_format = FORMAT_OGG;
				break;
			}
		}

		if(row["savegraph"] != "") {
			switch(row["savegraph"][0]) {
			case 'y':
			case '1':
			case 'p':
				opt_saveGRAPH = 1;
				break;
			case 'g':
				opt_saveGRAPH = 1;
				opt_gzipGRAPH = 1;
				break;
			}      
		}

		if(row["filter"] != "") {
			row["filter"].copy(user_filter, sizeof(user_filter), 0);
		}

		if(row["cachedir"] != "") {
			row["cachedir"].copy(opt_cachedir, sizeof(opt_cachedir), 0);
			mkdir_r(opt_cachedir, 0777);
		}

		if(row["spooldir"] != "") {
			row["spooldir"].copy(opt_chdir, sizeof(opt_chdir), 0);
			mkdir_r(opt_chdir, 0777);
		}

		if(row["spooldiroldschema"] != "") {
			opt_newdir = !atoi(row["spooldiroldschema"].c_str());
		}

		if(row["pcapsplit"] != "") {
			opt_pcap_split = atoi(row["pcapsplit"].c_str());
		}

		if(row["scanpcapdir"] != "") {
			row["scanpcapdir"].copy(opt_scanpcapdir, sizeof(opt_scanpcapdir), 0);
		}

#ifndef FREEBSD
		if(row["scanpcapmethod"] != "") {
			opt_scanpcapmethod = (row["scanpcapmethod"][0] == 'r') ? IN_MOVED_TO : IN_CLOSE_WRITE;
		}      
#endif 
		if(row["promisc"] != "") {
			opt_promisc = atoi(row["promisc"].c_str());
		}


		if(row["national_prefix"] != "") {
			char *pos = (char*)row["national_prefix"].c_str();
			while(pos && *pos) {
				char *posSep = strchr(pos, ';');
				if(posSep) {
					*posSep = 0;
				}      
				opt_national_prefix.push_back(pos);
				pos = posSep ? posSep + 1 : NULL;
			} 
		}

		if(row["sipoverlap"] != "") {
			opt_sipoverlap = atoi(row["sipoverlap"].c_str());
		}

		if(row["jitterbuffer_f1"] != "") {
			opt_jitterbuffer_f1 = atoi(row["jitterbuffer_f1"].c_str());
		}
		if(row["jitterbuffer_f2"] != "") {
			opt_jitterbuffer_f2 = atoi(row["jitterbuffer_f2"].c_str());
		}
		if(row["jitterbuffer_adapt"] != "") {
			opt_jitterbuffer_adapt = atoi(row["jitterbuffer_adapt"].c_str());
		}

		if(row["sqlcallend"] != "") {
			opt_callend = atoi(row["sqlcallend"].c_str());
		}

		if(row["destination_number_mode"] != "") {
			opt_destination_number_mode = atoi(row["destination_number_mode"].c_str());
		}

		if(row["cdronlyanswered"] != "") {
			opt_cdronlyanswered = atoi(row["cdronlyanswered"].c_str());
		}

		if(row["cdronlyrtp"] != "") {
			opt_cdronlyrtp = atoi(row["cdronlyrtp"].c_str());
		}

		if(row["callslimit"] != "") {
			opt_callslimit = atoi(row["callslimit"].c_str());
		}

		if(row["pauserecordingdtmf"] != "") {
			row["pauserecordingdtmf"].copy(opt_silencedmtfseq, sizeof(opt_silencedmtfseq), 0);
		}

		if(row["keycheck"] != "") {
			row["keycheck"].copy(opt_keycheck, sizeof(opt_keycheck), 0);
		}

		if(row["convertchar"] != "") {
			row["convertchar"].copy(opt_convert_char, sizeof(opt_convert_char), 0);
		}

		if(row["openfile_max"] != "") {
			opt_openfile_max = atoi(row["openfile_max"].c_str());
		}

		if(row["packetbuffer_enable"] != "") {
			opt_pcap_queue = atoi(row["packetbuffer_enable"].c_str());
		}

		if(row["packetbuffer_total_maxheap"] != "") {
			opt_pcap_queue_store_queue_max_memory_size = atoi(row["packetbuffer_total_maxheap"].c_str());
		}

		if(row["packetbuffer_file_totalmaxsize"] != "") {
			opt_pcap_queue_store_queue_max_disk_size = atoi(row["packetbuffer_file_totalmaxsize"].c_str());
		}

		if(row["packetbuffer_file_path"] != "") {
			opt_pcap_queue_disk_folder = row["packetbuffer_file_path"];
		}

		if(row["packetbuffer_compress"] != "") {
			opt_pcap_queue_compress = atoi(row["packetbuffer_compress"].c_str());
		}

		if(row["mirror_destination_ip"] != "" and row["mirror_destination_port"] != "") {
			opt_pcap_queue_send_to_ip_port.set_ip(row["mirror_destination_ip"]);
			opt_pcap_queue_receive_from_ip_port.set_port(atoi(row["mirror_destination_port"].c_str()));
		}

		if(row["mirror_destination"] != "") {
			char *pointToPortSeparator = (char*)strchr(row["mirror_destination"].c_str(), ':');
			if(pointToPortSeparator) {
				*pointToPortSeparator = 0;
				int port = atoi(pointToPortSeparator + 1);
				if(row["mirror_destination"][0] && port) {
					opt_pcap_queue_send_to_ip_port.set_ip(row["mirror_destination"].c_str());
					opt_pcap_queue_send_to_ip_port.set_port(port);
				}
			}
		}

		if(row["mirror_bind_ip"] != "" and row["mirror_bind_port"] != "") {
			opt_pcap_queue_receive_from_ip_port.set_ip(row["mirror_bind_ip"].c_str());
			opt_pcap_queue_receive_from_ip_port.set_port(atoi(row["mirror_bind_port"].c_str()));
		}

		if(row["mirror_bind"] != "") {
			char *pointToPortSeparator = (char*)strchr(row["mirror_bind"].c_str(), ':');
			if(pointToPortSeparator) {
				*pointToPortSeparator = 0;
				int port = atoi(pointToPortSeparator + 1);
				if(row["mirror_bind"][0] && port) {
					opt_pcap_queue_receive_from_ip_port.set_ip(row["mirror_bind"].c_str());
					opt_pcap_queue_receive_from_ip_port.set_port(port);
				}
			}
		}

		if(row["mirror_bind_dlt"] != "") {
			opt_pcap_queue_receive_dlt = atoi(row["mirror_bind_dlt"].c_str());
		}

		if(row["convert_dlt_sll2en10"] != "") {
			opt_convert_dlt_sll_to_en10 = atoi(row["convert_dlt_sll2en10"].c_str());
		}

		if(row["threading_mod"] != "") {
			switch(atoi(row["threading_mod"].c_str())) {
			case 2: 
				opt_pcap_queue_iface_separate_threads = 1;
				break;
			case 3: 
				opt_pcap_queue_iface_separate_threads = 1;
				opt_pcap_queue_iface_dedup_separate_threads = 1;
				break;
			case 4: 
				opt_pcap_queue_iface_separate_threads = 1;
				opt_pcap_queue_iface_dedup_separate_threads = 1;
				opt_pcap_queue_iface_dedup_separate_threads_extend = 1;
				break;
			}      
		}

		if(!opt_pcap_queue_iface_separate_threads && strchr(ifname, ',')) {
			opt_pcap_queue_iface_separate_threads = 1;
		}

		if(row["maxpcapsize"] != "") {
			opt_maxpcapsize_mb = atoi(row["maxpcapsize"].c_str());
		}
		if(row["upgrade_try_http_if_https_fail"] != "") {
			opt_upgrade_try_http_if_https_fail = atoi(row["upgrade_try_http_if_https_fail"].c_str());
		}
		if(row["sdp_reverse_ipport"] != "") {
			opt_sdp_reverse_ipport = atoi(row["sdp_reverse_ipport"].c_str());
		}
		if(row["mos_lqo"] != "") {
			opt_mos_lqo = atoi(row["mos_lqo"].c_str());
		}
		if(row["mos_lqo_bin"] != "") {
			opt_mos_lqo_bin = row["mos_lqo_bin"];
		}
		if(row["mos_lqo_ref"] != "") {
			opt_mos_lqo_ref = atoi(row["mos_lqo_ref"].c_str());
		}
		if(row["mos_lqo_ref16"] != "") {
			opt_mos_lqo_ref = row["mos_lqo_ref"];
		}
		if(row["php_path"] != "") {
			row["php_path"].copy(opt_php_path, sizeof(opt_php_path), 0);
		}
		if(row["onewaytimeout"] != "") {
			opt_onewaytimeout = atoi(row["onewaytimeout"].c_str());
		}
		if(row["saveaudio_reversestereo"] != "") {
			opt_saveaudio_reversestereo = atoi(row["saveaudio_reversestereo"].c_str());
		}

		/*
		
		packetbuffer default configuration
		
		packetbuffer_enable	     = no
		packetbuffer_block_maxsize      = 500   #kB
		packetbuffer_block_maxtime      = 500   #ms
		packetbuffer_total_maxheap      = 500   #MB
		packetbuffer_thread_maxheap     = 500   #MB
		packetbuffer_file_totalmaxsize  = 20000 #MB
		packetbuffer_file_path	  = /var/spool/voipmonitor/packetbuffer
		packetbuffer_file_maxfilesize   = 1000  #MB
		packetbuffer_file_maxtime       = 5000  #ms
		packetbuffer_compress	   = yes
		#mirror_destination_ip	  =
		#mirror_destination_port	=
		#mirror_source_ip	       =
		#mirror_source_port	     =
		*/

#ifdef QUEUE_NONBLOCK2
		if(opt_scanpcapdir[0] != '\0') {
			opt_pcap_queue = 0;
		}
#else   
		opt_pcap_queue = 0;
#endif

		if(opt_pcap_queue) {
			if(!opt_pcap_queue_disk_folder.length() || !opt_pcap_queue_store_queue_max_disk_size) {
				// disable disc save
				if(opt_pcap_queue_compress) {
					// enable compress - maximum thread0 buffer = 100MB, minimum = 50MB
					opt_pcap_queue_bypass_max_size = opt_pcap_queue_store_queue_max_memory_size / 8;
					if(opt_pcap_queue_bypass_max_size > 100 * 1024 * 1024) {
						opt_pcap_queue_bypass_max_size = 100 * 1024 * 1024;
					} else if(opt_pcap_queue_bypass_max_size < 50 * 1024 * 1024) {
						opt_pcap_queue_bypass_max_size = 50 * 1024 * 1024;
					}      
				} else {
					// disable compress - thread0 buffer = 50MB
					opt_pcap_queue_bypass_max_size = 50 * 1024 * 1024;
				}      
			} else {
				// disable disc save - maximum thread0 buffer = 500MB
				opt_pcap_queue_bypass_max_size = opt_pcap_queue_store_queue_max_memory_size / 4;
				if(opt_pcap_queue_bypass_max_size > 500 * 1024 * 1024) {
					opt_pcap_queue_bypass_max_size = 500 * 1024 * 1024;
				}      
			}      
			if(opt_pcap_queue_store_queue_max_memory_size < opt_pcap_queue_bypass_max_size * 2) {
				opt_pcap_queue_store_queue_max_memory_size = opt_pcap_queue_bypass_max_size * 2;
			} else {
				opt_pcap_queue_store_queue_max_memory_size -= opt_pcap_queue_bypass_max_size;
			}      
		}      

	}
	delete sqlDb;
}
