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
#include <fts.h>

#include "sql_db.h"
#include "tools.h"
#include "cleanspool.h"
#include "tar.h"


using namespace std;


extern CleanSpool *cleanSpool[2];
extern MySqlStore *sqlStore;
extern int opt_newdir;
extern int opt_pcap_split;
extern int opt_pcap_dump_tar;
extern bool opt_cleanspool_use_files;


#define DISABLE_CLEANSPOOL ((suspended && !critical_low_space) || do_convert_filesindex_flag)
#define ENCODE_FIELD_SEPARATOR ";"
#define ENCODE_DATA_SEPARATOR "|"
#define CACHE_NAME ".cleanspool_cache"


string CleanSpool::sSpoolDataDirIndex::encode_hour() {
	string str;
	str = intToString(minute) + ENCODE_FIELD_SEPARATOR +
	      type + ENCODE_FIELD_SEPARATOR +
	      intToString(_type);
	return(str);
}

void CleanSpool::sSpoolDataDirIndex::decode_hour(string str) {
	vector<string> fields = split(str.c_str(), ENCODE_FIELD_SEPARATOR, false, true);
	if(fields.size() == 3) {
		minute = atoi(fields[0].c_str());
		type = fields[1];
		_type = (eTypeSpoolFile)atoi(fields[2].c_str());
	}
}

string CleanSpool::sSpoolDataDirItem::encode() {
	string str;
	str = path + ENCODE_FIELD_SEPARATOR +
	      intToString(size) + ENCODE_FIELD_SEPARATOR +
	      intToString(is_dir);
	return(str);
}

void CleanSpool::sSpoolDataDirItem::decode(string str) {
	vector<string> fields = split(str.c_str(), ENCODE_FIELD_SEPARATOR, false, true);
	if(fields.size() == 3) {
		path = fields[0];
		size = atoll(fields[1].c_str());
		is_dir = atoi(fields[2].c_str());
	}
}

long long CleanSpool::cSpoolData::getSumSize() {
	long long size = 0;
	for(map<sSpoolDataDirIndex, sSpoolDataDirItem>::iterator iter = data.begin(); iter != data.end(); iter++) {
		size += iter->second.size;
	}
	return(size);
}

long long CleanSpool::cSpoolData::getSplitSumSize(long long *sip, long long *rtp, long long *graph, long long *audio) {
	long long size = 0;
	if(sip) {
		*sip = 0;
	}
	if(rtp) {
		*rtp = 0;
	}
	if(graph) {
		*graph = 0;
	}
	if(audio) {
		*audio = 0;
	}
	for(map<sSpoolDataDirIndex, sSpoolDataDirItem>::iterator iter = data.begin(); iter != data.end(); iter++) {
		switch(iter->first._type) {
		case tsf_rtp:
			if(rtp) {
				*rtp += iter->second.size;
			}
			break;
		case tsf_graph:
			if(graph) {
				*graph += iter->second.size;
			}
			break;
		case tsf_audio:
			if(audio) {
				*audio += iter->second.size;
			}
			break;
		default:
			if(sip) {
				*sip += iter->second.size;
			}
			break;
		}
		size += iter->second.size;
	}
	return(size);
}

void CleanSpool::cSpoolData::getSumSizeByDate(map<string, long long> *sizeByDate) {
	sizeByDate->clear();
	for(map<sSpoolDataDirIndex, sSpoolDataDirItem>::iterator iter = data.begin(); iter != data.end(); iter++) {
		(*sizeByDate)[iter->first.date] += iter->second.size;
	}
}

map<CleanSpool::sSpoolDataDirIndex, CleanSpool::sSpoolDataDirItem>::iterator CleanSpool::cSpoolData::getBegin() {
	return(data.begin());
}

map<CleanSpool::sSpoolDataDirIndex, CleanSpool::sSpoolDataDirItem>::iterator CleanSpool::cSpoolData::getMin(bool sip, bool rtp, bool graph, bool audio) {
	for(map<sSpoolDataDirIndex, sSpoolDataDirItem>::iterator iter = data.begin(); iter != data.end(); iter++) {
		if(!iter->second.is_dir) {
			switch(iter->first._type) {
			case tsf_rtp:
				if(rtp) {
					return(iter);
				}
				break;
			case tsf_graph:
				if(graph) {
					return(iter);
				}
				break;
			case tsf_audio:
				if(audio) {
					return(iter);
				}
				break;
			default:
				if(sip) {
					return(iter);
				}
				break;
			}
		}
	}
	return(data.end());
}

bool CleanSpool::cSpoolData::existsFileIndex(CleanSpool::sSpoolDataDirIndex *dirIndex) {
	for(map<sSpoolDataDirIndex, sSpoolDataDirItem>::iterator iter = data.begin(); iter != data.end(); iter++) {
		if(!iter->second.is_dir &&
		   dirIndex->eqSettedItems(iter->first)) {
			return(true);
		}
	}
	return(false);
}

void CleanSpool::cSpoolData::removeLastDateHours(int hours) {
	if(!data.size()) {
		return;
	}
	map<sSpoolDataDirIndex, sSpoolDataDirItem>::iterator iter = data.end();
	--iter;
	while(iter != data.begin()) {
		if(getNumberOfHourToNow(iter->first.date.c_str(), iter->first.hour) > hours) {
			break;
		} else {
			data.erase(iter--);
		}
	}
}

bool CleanSpool::cSpoolData::saveHourCacheFile(sSpoolDataDirIndex index) {
	if(!index.isHour()) {
		for(map<sSpoolDataDirIndex, sSpoolDataDirItem>::iterator iter = data.begin(); iter != data.end(); iter++) {
			if(index.eqHour(iter->first)) {
				index = iter->first;
				break;
			}
		}
	}
	if(data.find(index) != data.end() && index.isHour()) {
		bool existsHourData = false;
		for(map<sSpoolDataDirIndex, sSpoolDataDirItem>::iterator iter = data.begin(); iter != data.end(); iter++) {
			if(index.eqHour(iter->first) && !(index == iter->first) && !iter->second.is_dir) {
				 existsHourData = true;
			}
		}
		if(existsHourData) {
			string path = data[index].path;
			syslog(LOG_NOTICE, "cleanspool cache: save %s", (path + '/' + CACHE_NAME).c_str());
			FILE *cachef = fopen((path + '/' + CACHE_NAME).c_str(), "w");
			if(cachef) {
				for(map<sSpoolDataDirIndex, sSpoolDataDirItem>::iterator iter = data.begin(); iter != data.end(); iter++) {
					if(index.eqHour(iter->first) && !(index == iter->first)) {
						 sSpoolDataDirIndex index = iter->first;
						 sSpoolDataDirItem item = iter->second;
						 item.path = item.path.substr(path.length() + 1);
						 fputs((index.encode_hour() + ENCODE_DATA_SEPARATOR + item.encode() + "\n").c_str(), cachef);
					}
				}
				fputs("END", cachef);
				fclose(cachef);
				return(true);
			}
		}
	}
	return(false);
}

bool CleanSpool::cSpoolData::loadHourCacheFile(sSpoolDataDirIndex index, string pathHour) {
	bool okLoad = false;
	FILE *cachef = fopen((pathHour + '/' + CACHE_NAME).c_str(), "r");
	if(cachef) {
		char line[1024];
		while(fgets(line, sizeof(line), cachef)) {
			if(!strcmp(line, "END")) {
				okLoad = true;
				break;
			}
			vector<string> indexItemStr = split(line, ENCODE_DATA_SEPARATOR);
			if(indexItemStr.size() == 2) {
				sSpoolDataDirIndex _index = index;
				sSpoolDataDirItem item;
				_index.decode_hour(indexItemStr[0]);
				item.decode(indexItemStr[1]);
				item.path = pathHour + '/' + item.path;
				data[_index] = item;
			}
		}
		fclose(cachef);
	}
	return(okLoad);
}

bool CleanSpool::cSpoolData::existsHourCacheFile(sSpoolDataDirIndex index, string pathHour) {
	if(!index.isHour()) {
		for(map<sSpoolDataDirIndex, sSpoolDataDirItem>::iterator iter = data.begin(); iter != data.end(); iter++) {
			if(index.eqHour(iter->first)) {
				index = iter->first;
				pathHour = iter->second.path;
				break;
			}
		}
	}
	return(index.isHour() && file_exists(pathHour + '/' + CACHE_NAME));
}

bool CleanSpool::cSpoolData::deleteHourCacheFile(sSpoolDataDirIndex index) {
	if(!index.isHour()) {
		for(map<sSpoolDataDirIndex, sSpoolDataDirItem>::iterator iter = data.begin(); iter != data.end(); iter++) {
			if(index.eqHour(iter->first)) {
				index = iter->first;
				break;
			}
		}
	}
	if(index.isHour() && file_exists(data[index].path + '/'+ CACHE_NAME)) {
		syslog(LOG_NOTICE, "cleanspool cache: delete %s", (data[index].path + '/'+ CACHE_NAME).c_str());
		unlink((data[index].path + '/'+ CACHE_NAME).c_str());
		list_delete_hour_cache_files.push_back(index);
		return(true);
	}
	return(false);
}

void CleanSpool::cSpoolData::fillDateHoursCheckMap() {
	date_hours_map.clear();
	for(map<sSpoolDataDirIndex, sSpoolDataDirItem>::iterator iter = data.begin(); iter != data.end(); iter++) {
		uint64_t dh = CleanSpool::date_to_int(iter->first.date.c_str()) * 100ull + iter->first.hour;
		date_hours_map[dh] = true;
	}
}

void CleanSpool::cSpoolData::clearDateHoursCheckMap() {
	date_hours_map.clear();
}

bool CleanSpool::cSpoolData::existsDateHourInCheckMap(const char *date, int hour) {
	uint64_t dh = CleanSpool::date_to_int(date) * 100ull + hour;
	return(date_hours_map.find(dh) != date_hours_map.end());
}

void CleanSpool::cSpoolData::saveDeletedHourCacheFiles() {
	for(list<sSpoolDataDirIndex>::iterator iter = list_delete_hour_cache_files.begin(); iter != list_delete_hour_cache_files.end(); iter++) {
		saveHourCacheFile(*iter);
	}
	list_delete_hour_cache_files.clear();
}

void CleanSpool::cSpoolData::eraseDir(string dir) {
	for(map<sSpoolDataDirIndex, sSpoolDataDirItem>::iterator iter = data.begin(); iter != data.end(); iter++) {
		if(iter->second.is_dir &&
		   iter->second.path == dir) {
			data.erase(iter);
			break;
		}
	}
}


CleanSpool::CleanSpool(int spoolIndex) {
	this->spoolIndex = spoolIndex;
	this->loadOpt();
	sqlDb = NULL;
	maxpoolsize_set = 0;
	critical_low_space = false;
	do_convert_filesindex_flag = false;
	do_convert_filesindex_reason = NULL;
	clean_thread = 0;
	lastCall_reindex_all = 0;
	suspended = false;
	clean_spooldir_run_processing = 0;
	lastRunLoadSpoolDataDir = 0;
	counterLoadSpoolDataDir = 0;
	force_reindex_spool_flag = false;
}

CleanSpool::~CleanSpool() {
	termCleanThread();
	if(sqlDb) {
		delete sqlDb;
	}
}

void CleanSpool::addFile(const char *ymdh, eTypeSpoolFile typeSpoolFile, const char *file, long long int size) {
	if(!opt_newdir || !opt_cleanspool_use_files) {
		return;
	}
	string column = string(getSpoolTypeFilesIndex(typeSpoolFile, true)) + "size";
	sqlStore->lock(STORE_PROC_ID_CLEANSPOOL, spoolIndex);
	sqlStore->query(MYSQL_ADD_QUERY_END(
	       "INSERT INTO files \
		SET datehour = " + string(ymdh) + ", \
		    spool_index = " + getSpoolIndex_string() + ", \
		    id_sensor = " + getIdSensor_string() + ", \
		    " + column + " = " + intToString(size) + " \
		ON DUPLICATE KEY UPDATE \
		    " + column + " = " + column + " + " + intToString(size)),
		STORE_PROC_ID_CLEANSPOOL, spoolIndex);
	string fname = getSpoolDir_string(tsf_main) + "/filesindex/" + column + '/' + ymdh;
	ofstream fname_stream;
	for(int passOpen = 0; passOpen < 2; passOpen++) {
		if(passOpen == 1) {
			size_t posLastDirSeparator = fname.rfind('/');
			if(posLastDirSeparator != string::npos) {
				string fname_path = fname.substr(0, posLastDirSeparator);
				spooldir_mkdir(fname_path);
			} else {
				break;
			}
		}
		bool fname_exists = file_exists(fname);
		fname_stream.open(fname.c_str(), ios::app | ios::out);
		if(fname_stream.is_open()) {
			if(!fname_exists) {
				spooldir_file_chmod_own(fname);
			}
			break;
		}
	}
	if(fname_stream.is_open()) {
		fname_stream << skipSpoolDir(typeSpoolFile, spoolIndex, file) << ":" << size << "\n";
		fname_stream.close();
	} else {
		syslog(LOG_ERR, "error write to %s", fname.c_str());
	}
	sqlStore->unlock(STORE_PROC_ID_CLEANSPOOL, spoolIndex);
}

void CleanSpool::run() {
	runCleanThread();
}

void CleanSpool::do_convert_filesindex(const char *reason) {
	do_convert_filesindex_flag = true;
	do_convert_filesindex_reason = reason;
}

void CleanSpool::check_filesindex() {
	list<string> date_dirs;
	this->readSpoolDateDirs(&date_dirs);
	if(!date_dirs.size()) {
		return;
	}
	SqlDb *sqlDb = createSqlObject();
	syslog(LOG_NOTICE, "cleanspool[%i]: check_filesindex start", spoolIndex);
	for(list<string>::iterator iter_date_dir = date_dirs.begin(); iter_date_dir != date_dirs.end(); iter_date_dir++) {
		check_index_date(*iter_date_dir, sqlDb);
	}
	syslog(LOG_NOTICE, "cleanspool[%i]: check_filesindex done", spoolIndex);
	delete sqlDb;
}

void CleanSpool::check_index_date(string date, SqlDb *sqlDb) {
	for(int h = 0; h < 24 && !is_terminating(); h++) {
		char hour[8];
		snprintf(hour, sizeof(hour), "%02d", h);
		string ymdh = string(date.substr(0,4)) + date.substr(5,2) + date.substr(8,2) + hour;
		map<string, long long> typeSize;
		reindex_date_hour(date, h, true, &typeSize, true);
		if(typeSize["sip"] || 
		   typeSize["reg"] || 
		   typeSize["skinny"] || 
		   typeSize["mgcp"] || 
		   typeSize["ss7"] || 
		   typeSize["rtp"] || 
		   typeSize["graph"] || 
		   typeSize["audio"]) {
			bool needReindex = false;
			sqlDb->query(
			       "select * \
				from files \
				where datehour = '" + ymdh + "' and \
				      spool_index = " + getSpoolIndex_string() + " and \
				      id_sensor = " + getIdSensor_string());
			SqlDb_row row = sqlDb->fetchRow();
			if(row) {
				if((typeSize["sip"] && !atoll(row["sipsize"].c_str())) ||
				   (typeSize["reg"] && !atoll(row["regsize"].c_str())) ||
				   (typeSize["skinny"] && !atoll(row["skinnysize"].c_str())) ||
				   (typeSize["mgcp"] && !atoll(row["mgcpsize"].c_str())) ||
				   (typeSize["ss7"] && !atoll(row["ss7size"].c_str())) ||
				   (typeSize["rtp"] && !atoll(row["rtpsize"].c_str())) ||
				   (typeSize["graph"] && !atoll(row["graphsize"].c_str())) ||
				   (typeSize["audio"] && !atoll(row["audiosize"].c_str()))) {
					needReindex = true;
				}
			} else {
				needReindex = true;
			}
			if(!needReindex &&
			   ((typeSize["sip"] && !file_exists(getSpoolDir_string(tsf_main) + "/filesindex/sipsize/" + ymdh)) ||
			    (typeSize["reg"] && !file_exists(getSpoolDir_string(tsf_main) + "/filesindex/regsize/" + ymdh)) ||
			    (typeSize["skinny"] && !file_exists(getSpoolDir_string(tsf_main) + "/filesindex/skinnysize/" + ymdh)) ||
			    (typeSize["mgcp"] && !file_exists(getSpoolDir_string(tsf_main) + "/filesindex/mgcpsize/" + ymdh)) ||
			    (typeSize["ss7"] && !file_exists(getSpoolDir_string(tsf_main) + "/filesindex/ss7size/" + ymdh)) ||
			    (typeSize["rtp"] && !file_exists(getSpoolDir_string(tsf_main) + "/filesindex/rtpsize/" + ymdh)) ||
			    (typeSize["graph"] && !file_exists(getSpoolDir_string(tsf_main) + "/filesindex/graphsize/" + ymdh)) ||
			    (typeSize["audio"] && !file_exists(getSpoolDir_string(tsf_main) + "/filesindex/audiosize/" + ymdh)))) {
				needReindex = true;
			}
			if(needReindex) {
				reindex_date_hour(date, h);
			}
		}
	}
}

string CleanSpool::getMaxSpoolDate() {
	list<string> date_dirs;
	this->readSpoolDateDirs(&date_dirs);
	if(!date_dirs.size()) {
		return("");
	}
	u_int32_t maxDate = 0;
	for(list<string>::iterator iter_date_dir = date_dirs.begin(); iter_date_dir != date_dirs.end(); iter_date_dir++) {
		u_int32_t date = atol((*iter_date_dir).c_str()) * 10000 +
				 atol((*iter_date_dir).c_str() + 5) * 100 +
				 atol((*iter_date_dir).c_str() + 8);
		if(date > maxDate) {
			maxDate = date;
		}
	}
	if(maxDate) {
		char maxDate_str[20];
		snprintf(maxDate_str, sizeof(maxDate_str), "%4i-%02i-%02i", maxDate / 10000, maxDate % 10000 / 100, maxDate % 100);
		return(maxDate_str);
	} else {
		return("");
	}
}

void CleanSpool::getSumSizeByDate(map<string, long long> *sizeByDate) {
	spoolData.getSumSizeByDate(sizeByDate);
}

string CleanSpool::printSumSizeByDate() {
	map<string, long long> sizeByDate;
	getSumSizeByDate(&sizeByDate);
	ostringstream outStr;
	for(map<string, long long>::iterator iter = sizeByDate.begin(); iter != sizeByDate.end(); iter++) {
		outStr << iter->first << " : " << iter->second << endl;
	}
	return(outStr.str());
}

string CleanSpool::getOldestDate() {
	string oldestDate;
	list<string> spool_dirs;
	this->getSpoolDirs(&spool_dirs);
	for(list<string>::iterator iter_sd = spool_dirs.begin(); iter_sd != spool_dirs.end(); iter_sd++) {
		DIR* dp = opendir(iter_sd->c_str());
		if(dp) {
			dirent* de;
			while((de = readdir(dp)) != NULL) {
				if(string(de->d_name) == ".." or string(de->d_name) == ".") continue;
				if(is_dir(de, iter_sd->c_str()) &&
				   check_date_dir(de->d_name)) {
					if(oldestDate.empty() ||
					   oldestDate > de->d_name) {
						oldestDate = de->d_name;
					}
				}
			}
			closedir(dp);
		}
	}
	return(oldestDate);
}

void CleanSpool::run_cleanProcess(int spoolIndex) {
	for(int i = 0; i < 2; i++) {
		if(cleanSpool[i] &&
		   (spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex)) {
			cleanSpool[i]->cleanThreadProcess();
		}
	}
}

void CleanSpool::run_clean_obsolete(int spoolIndex) {
	for(int i = 0; i < 2; i++) {
		if(cleanSpool[i] &&
		   (spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex)) {
			cleanSpool[i]->clean_obsolete_dirs();
		}
	}
}

void CleanSpool::run_test_load(string type, int spoolIndex) {
	for(int i = 0; i < 2; i++) {
		if(cleanSpool[i] &&
		   (spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex)) {
			cleanSpool[i]->test_load(type);
		}
	}
}

void CleanSpool::run_reindex_all(const char *reason, int spoolIndex) {
	for(int i = 0; i < 2; i++) {
		if(cleanSpool[i] &&
		   (spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex)) {
			cleanSpool[i]->reindex_all(reason);
		}
	}
}

void CleanSpool::run_reindex_date(string date, int spoolIndex) {
	for(int i = 0; i < 2; i++) {
		if(cleanSpool[i] &&
		   (spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex)) {
			cleanSpool[i]->reindex_date(date);
		}
	}
}

void CleanSpool::run_reindex_date_hour(string date, int hour, int spoolIndex) {
	for(int i = 0; i < 2; i++) {
		if(cleanSpool[i] &&
		   (spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex)) {
			cleanSpool[i]->reindex_date_hour(date, hour);
		}
	}
}

bool CleanSpool::suspend(int spoolIndex) {
	bool changeState = false;
	for(int i = 0; i < 2; i++) {
		if(cleanSpool[i] &&
		   (spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex) &&
		   !cleanSpool[i]->suspended) {
			cleanSpool[i]->suspended = true;
			changeState = true;
		}
	}
	return(changeState);
}

bool CleanSpool::resume(int spoolIndex) {
	bool changeState = false;
	for(int i = 0; i < 2; i++) {
		if(cleanSpool[i] &&
		   (spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex) &&
		   cleanSpool[i]->suspended) {
			cleanSpool[i]->suspended = false;
			changeState = true;
		}
	}
	return(changeState);
}

void CleanSpool::run_check_filesindex(int spoolIndex) {
	for(int i = 0; i < 2; i++) {
		if(cleanSpool[i] &&
		   (spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex)) {
			cleanSpool[i]->check_filesindex();
		}
	}
}

void CleanSpool::run_check_spooldir_filesindex(const char *dirfilter, int spoolIndex) {
	for(int i = 0; i < 2; i++) {
		if(cleanSpool[i] &&
		   (spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex)) {
			cleanSpool[i]->check_spooldir_filesindex(dirfilter);
		}
	}
}

void CleanSpool::run_reindex_spool(int spoolIndex) {
	if(opt_cleanspool_use_files) {
		return;
	}
	for(int i = 0; i < 2; i++) {
		if(cleanSpool[i] &&
		   (spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex)) {
			cleanSpool[i]->force_reindex_spool();
		}
	}
}

string CleanSpool::run_print_spool(int spoolIndex) {
	if(opt_cleanspool_use_files) {
		return("");
	}
	string rslt;
	for(int i = 0; i < 2; i++) {
		if(cleanSpool[i] &&
		   (spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex)) {
			rslt += cleanSpool[i]->print_spool();
		}
	}
	return(rslt);
}

string CleanSpool::get_oldest_date(int spoolIndex) {
	string oldestDate;
	for(int i = 0; i < 2; i++) {
		if(isSetSpoolDir(i)) {
			CleanSpool cs(i);
			list<string> spool_dirs;
			string _oldestDate = cs.getOldestDate();
			if(!_oldestDate.empty() &&
			    (oldestDate.empty() ||
			     oldestDate > _oldestDate)) {
				oldestDate = _oldestDate;
			}
		}
	}
	return(oldestDate);
}

bool CleanSpool::isSetCleanspoolParameters(int spoolIndex) {
	extern bool opt_cleanspool;
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
	extern unsigned int opt_maxpoolsize_2;
	extern unsigned int opt_maxpooldays_2;
	extern unsigned int opt_maxpoolsipsize_2;
	extern unsigned int opt_maxpoolsipdays_2;
	extern unsigned int opt_maxpoolrtpsize_2;
	extern unsigned int opt_maxpoolrtpdays_2;
	extern unsigned int opt_maxpoolgraphsize_2;
	extern unsigned int opt_maxpoolgraphdays_2;
	extern unsigned int opt_maxpoolaudiosize_2;
	extern unsigned int opt_maxpoolaudiodays_2;
	extern int opt_cleanspool_interval;
	extern int opt_cleanspool_sizeMB;
	extern int opt_autocleanspoolminpercent;
	extern int opt_autocleanmingb;
	return(opt_cleanspool &&
	       ((spoolIndex == 0 ?
		  opt_maxpoolsize ||
		  opt_maxpooldays ||
		  opt_maxpoolsipsize ||
		  opt_maxpoolsipdays ||
		  opt_maxpoolrtpsize ||
		  opt_maxpoolrtpdays ||
		  opt_maxpoolgraphsize ||
		  opt_maxpoolgraphdays ||
		  opt_maxpoolaudiosize ||
		  opt_maxpoolaudiodays :
		  opt_maxpoolsize_2 ||
		  opt_maxpooldays_2 ||
		  opt_maxpoolsipsize_2 ||
		  opt_maxpoolsipdays_2 ||
		  opt_maxpoolrtpsize_2 ||
		  opt_maxpoolrtpdays_2 ||
		  opt_maxpoolgraphsize_2 ||
		  opt_maxpoolgraphdays_2 ||
		  opt_maxpoolaudiosize_2 ||
		  opt_maxpoolaudiodays_2) ||
		opt_cleanspool_interval ||
		opt_cleanspool_sizeMB ||
		opt_autocleanspoolminpercent ||
		opt_autocleanmingb));
}

bool CleanSpool::isSetCleanspool(int spoolIndex) {
	return(cleanSpool[spoolIndex] != NULL);
}

bool CleanSpool::check_datehour(const char *datehour) {
	if(!datehour || strlen(datehour) != 10) {
		return(false);
	}
	u_int64_t datehour_i = atoll(datehour);
	return(datehour_i / 1000000 > 2000 &&
	       datehour_i / 10000 % 100 >= 1 && datehour_i / 10000 % 100 <= 12 && 
	       datehour_i / 100 % 100 >= 1 && datehour_i / 100 % 100 <= 31 && 
	       datehour_i % 100 < 60);
}

bool CleanSpool::check_date_dir(const char *datedir) {
	return(strlen(datedir) == 10 &&
	       datedir[4] == '-' && datedir[7] == '-' &&
	       atoi(datedir) > 2000 &&
	       atoi(datedir + 5) >= 1 && atoi(datedir + 5) <= 12 &&
	       atoi(datedir + 8) >= 1 && atoi(datedir + 8) <= 31);
}

bool CleanSpool::check_hour_dir(const char *hourdir) {
	return(strlen(hourdir) == 2 &&
	       atoi(hourdir) >= 0 && atoi(hourdir) <= 23);
}

bool CleanSpool::check_minute_dir(const char *minutedir) {
	return(strlen(minutedir) == 2 &&
	       atoi(minutedir) >= 0 && atoi(minutedir) <= 59);
}

bool CleanSpool::check_type_dir(const char *typedir) {
	return(getSpoolTypeFile(typedir) != tsf_na);
}

unsigned CleanSpool::date_to_int(const char *date) {
	return(atoi(date) * 10000ul +
	       atoi(date + 5) * 100ul +
	       atoi(date + 8));
}

void CleanSpool::reloadSpoolDataDir(bool enableCacheLoad, bool enableCacheSave) {
	int no_cache_last_hours = 12 + (lastRunLoadSpoolDataDir ? (time(NULL) - lastRunLoadSpoolDataDir) / (60 * 60) : 0);
	spoolData.lock();
	spoolData.clearAll();
	spoolData.clearDateHoursCheckMap();
	sLoadParams params;
	params.enable_cache_load = enableCacheLoad;
	params.enable_cache_save = enableCacheSave;
	params.no_cache_last_hours = no_cache_last_hours;
	sSpoolDataDirIndex index;
	loadSpoolDataDir(&spoolData, index, "", params);
	spoolData.unlock();
	lastRunLoadSpoolDataDir = time(NULL);
	++counterLoadSpoolDataDir;
}

void CleanSpool::updateSpoolDataDir() {
	if(force_reindex_spool_flag) {
		reloadSpoolDataDir(false, true);
		return;
	} else if(!lastRunLoadSpoolDataDir || spoolData.isEmpty()) {
		reloadSpoolDataDir(true, true);
		return;
	} else {
		time_t now;
		time(&now);
		struct tm dateTime = time_r(&now);
		if(dateTime.tm_hour >= 2 && dateTime.tm_hour < 4 &&
		   counterLoadSpoolDataDir && !(counterLoadSpoolDataDir % 10)) {
			reloadSpoolDataDir(false, true);
			return;
		}
	}
	int no_cache_last_hours = 12 + (lastRunLoadSpoolDataDir ? (time(NULL) - lastRunLoadSpoolDataDir) / (60 * 60) : 0);
	spoolData.lock();
	spoolData.removeLastDateHours(no_cache_last_hours);
	spoolData.fillDateHoursCheckMap();
	sLoadParams params;
	params.enable_cache_load = true;
	params.enable_cache_save = true;
	params.no_cache_last_hours = no_cache_last_hours;
	sSpoolDataDirIndex index;
	loadSpoolDataDir(&spoolData, index, "", params);
	spoolData.unlock();
	lastRunLoadSpoolDataDir = time(NULL);
	++counterLoadSpoolDataDir;
}

void CleanSpool::loadSpoolDataDir(cSpoolData *spoolData, sSpoolDataDirIndex index, string path, sLoadParams params) {
	if(!index.getSettedItems()) {
		list<string> spool_dirs;
		this->getSpoolDirs(&spool_dirs);
		for(list<string>::iterator iter_sd = spool_dirs.begin(); iter_sd != spool_dirs.end(); iter_sd++) {
			sSpoolDataDirIndex _index = index;
			_index.spool = *iter_sd;
			this->loadSpoolDataDir(spoolData, _index, (path.length() ? path + '/' : "" ) + *iter_sd, params);
		}
		return;
	}
	DIR* dp = opendir(path.c_str());
	if(dp) {
		list<string> de_dirs;
		list<string> de_files;
		dirent* de;
		while((de = readdir(dp)) != NULL && !is_terminating()) {
			if(string(de->d_name) == ".." or string(de->d_name) == ".") continue;
			if(is_dir(de, path.c_str())) {
				de_dirs.push_back(de->d_name);
			} else {
				de_files.push_back(de->d_name);
			}
		}
		de_dirs.sort();
		for(list<string>::iterator iter_dir = de_dirs.begin(); iter_dir != de_dirs.end() && !is_terminating(); iter_dir++) {
			if(index.getSettedItems() == sSpoolDataDirIndex::_ti_spool &&
			   !check_date_dir(iter_dir->c_str())) {
				sSpoolDataDirIndex _index = index;
				_index.spool = *iter_dir;
				this->loadSpoolDataDir(spoolData, _index, path + '/' + *iter_dir, params);
			} else if((index.getSettedItems() == sSpoolDataDirIndex::_ti_spool ||
				   index.getSettedItems() == (sSpoolDataDirIndex::_ti_spool|sSpoolDataDirIndex::_ti_sensor)) &&
				  check_date_dir(iter_dir->c_str())) {
				sSpoolDataDirIndex _index = index;
				_index.date = *iter_dir;
				this->loadSpoolDataDir(spoolData, _index, path + '/' + *iter_dir, params);
			} else if(index.getSettedItems() & sSpoolDataDirIndex::_ti_date &&
				  !(index.getSettedItems() & sSpoolDataDirIndex::_ti_hour) &&
				  check_hour_dir(iter_dir->c_str())) {
				unsigned hour = atoi(iter_dir->c_str());
			    #if true // speed optimization
				string pathHour = path + '/' + *iter_dir;
				sSpoolDataDirIndex indexHour = index;
				indexHour.hour = hour;
				sSpoolDataDirItem itemHour;
				itemHour.path = pathHour;
				itemHour.size = GetDirSizeDU(0);
				itemHour.is_dir = true;
				bool enableCache = true;
				if(params.no_cache_last_hours) {
					int hoursToNow = getNumberOfHourToNow(indexHour.date.c_str(), indexHour.hour);
					if(hoursToNow <= params.no_cache_last_hours) {
						enableCache = false;
					}
				}
				if(spoolData->existsDateHourInCheckMap(index.date.c_str(), hour)) {
					if(enableCache &&
					   params.enable_cache_save &&
					   !spoolData->existsHourCacheFile(indexHour, pathHour)) {
						spoolData->saveHourCacheFile(indexHour);
					}
					continue;
				}
				if(enableCache &&
				   params.enable_cache_load &&
				   spoolData->existsHourCacheFile(indexHour, pathHour) &&
				   spoolData->loadHourCacheFile(indexHour, pathHour)) {
					spoolData->add(indexHour, itemHour);
					continue;
				}
				u_int64_t start = getTimeMS();
				char *fts_path[2] = { (char*)pathHour.c_str(), NULL };
				FTS *tree = fts_open(fts_path, FTS_NOCHDIR, 0);
				if(!tree) {
					continue;
				}
				FTSENT *node;
				string lastDir;
				int minute = -1;
				string type;
				eTypeSpoolFile _type = tsf_na;
				unsigned countFiles = 0;
				long long sumSize = 0;
				while((node = fts_read(tree)) && !is_terminating()) {
					if(node->fts_info == FTS_D) {
						if(countFiles) {
							sSpoolDataDirIndex _index = index;
							_index.hour = hour;
							_index.minute = minute;
							_index.type = type;
							_index._type = _type;
							sSpoolDataDirItem item;
							item.path = lastDir;
							item.size = sumSize + GetDirSizeDU(countFiles);
							spoolData->add(_index, item);
							sumSize = 0;
							countFiles = 0;
						}
						const char *dir = node->fts_path + pathHour.length();
						if(!*dir) {
							continue;
						}
						++dir;
						const char *dir_last = dir;
						const char *dir_temp_pointer = dir;
						while(*dir_temp_pointer) {
							if(*dir_temp_pointer == '/') {
								dir_last = dir_temp_pointer + 1;
							}
							++dir_temp_pointer;
						}
						if(check_minute_dir(dir_last)) {
							minute = atoi(dir_last);
							sSpoolDataDirIndex indexMinute = index;
							indexMinute.hour = hour;
							indexMinute.minute = minute;
							sSpoolDataDirItem itemMinute;
							itemMinute.path = node->fts_path;
							itemMinute.size = GetDirSizeDU(0);
							itemMinute.is_dir = true;
							spoolData->add(indexMinute, itemMinute);
						} else if(check_type_dir(dir_last)) {
							type = dir_last;
							_type = getSpoolTypeFile(dir_last);
						}
						lastDir = node->fts_path;
					} else if(node->fts_info == FTS_F && strcmp(node->fts_name, CACHE_NAME)) {
						long long fileSize = node->fts_statp->st_size;
						int bs = node->fts_statp->st_blksize;
						if(bs > 0) {
							if(fileSize == 0) {
								fileSize = bs;
							} else {
								fileSize = (fileSize / bs * bs) + (fileSize % bs ? bs : 0);
							}
						}
						sumSize += fileSize;
						++countFiles;
					}
				}
				fts_close(tree);
				if(!is_terminating()) {
					u_int64_t end = getTimeMS();
					USLEEP((end - start) * 1000);
					syslog(LOG_NOTICE, "cleanspool[%i]: load date/hour - %s/%i", spoolIndex, indexHour.date.c_str(), indexHour.hour);
					if(countFiles) {
						sSpoolDataDirIndex _index = index;
						_index.hour = hour;
						_index.minute = minute;
						_index.type = type;
						_index._type = _type;
						sSpoolDataDirItem item;
						item.path = lastDir;
						item.size = sumSize + GetDirSizeDU(countFiles);
						spoolData->add(_index, item);
						sumSize = 0;
						countFiles = 0;
					}
					spoolData->add(indexHour, itemHour);
					if(enableCache &&
					   params.enable_cache_save) {
						spoolData->saveHourCacheFile(indexHour);
					}
				}
			    #else
				if(spoolData->existsDateHourInCheckMap(index.date.c_str(), hour)) {
					continue;
				}
				sSpoolDataDirIndex _index = index;
				_index.hour = hour;
				this->loadSpoolDataDir(spoolData, _index, path + '/' + *iter_dir);
			    #endif
			} else if(index.getSettedItems() & sSpoolDataDirIndex::_ti_hour &&
				  !(index.getSettedItems() & sSpoolDataDirIndex::_ti_minute) &&
				  check_minute_dir(iter_dir->c_str())) {
				sSpoolDataDirIndex _index = index;
				_index.minute = atoi(iter_dir->c_str());
				this->loadSpoolDataDir(spoolData, _index, path + '/' + *iter_dir, params);
			} else if(check_type_dir(iter_dir->c_str())) {
				sSpoolDataDirIndex _index = index;
				_index.type = *iter_dir;
				_index._type = getSpoolTypeFile(iter_dir->c_str());
				this->loadSpoolDataDir(spoolData, _index, path + '/' + *iter_dir, params);
			}
		}
		if(index.getSettedItems() & sSpoolDataDirIndex::_ti_date &&
		   de_files.size()) {
			long long size = 0;
			for(list<string>::iterator iter_file = de_files.begin(); iter_file != de_files.end(); iter_file++) {
				size += GetFileSizeDU(path + '/' + *iter_file, index.getTypeSpoolFile(), spoolIndex, 0);
			}
			size += GetDirSizeDU(de_files.size());
			sSpoolDataDirItem item;
			item.path = path;
			item.size = size;
			spoolData->add(index, item);
		} else if(index.getSettedItems() & sSpoolDataDirIndex::_ti_hour ||
			  index.getSettedItems() & sSpoolDataDirIndex::_ti_minute) {
			sSpoolDataDirItem item;
			item.path = path;
			item.size = GetDirSizeDU(0);
			item.is_dir = true;
			spoolData->add(index, item);
		}
		closedir(dp);
	}
}

void CleanSpool::loadOpt() {
	extern char opt_spooldir_main[1024];
	extern char opt_spooldir_rtp[1024];
	extern char opt_spooldir_graph[1024];
	extern char opt_spooldir_audio[1024];
	extern char opt_spooldir_2_main[1024];
	extern char opt_spooldir_2_rtp[1024];
	extern char opt_spooldir_2_graph[1024];
	extern char opt_spooldir_2_audio[1024];
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
	extern unsigned int opt_maxpoolsize_2;
	extern unsigned int opt_maxpooldays_2;
	extern unsigned int opt_maxpoolsipsize_2;
	extern unsigned int opt_maxpoolsipdays_2;
	extern unsigned int opt_maxpoolrtpsize_2;
	extern unsigned int opt_maxpoolrtpdays_2;
	extern unsigned int opt_maxpoolgraphsize_2;
	extern unsigned int opt_maxpoolgraphdays_2;
	extern unsigned int opt_maxpoolaudiosize_2;
	extern unsigned int opt_maxpoolaudiodays_2;
	extern int opt_maxpool_clean_obsolete;
	extern int opt_cleanspool_interval;
	extern int opt_cleanspool_sizeMB;
	extern int opt_autocleanspoolminpercent;
	extern int opt_autocleanmingb;
	extern int opt_cleanspool_enable_run_hour_from;
	extern int opt_cleanspool_enable_run_hour_to;
	opt_dirs.main = spoolIndex == 0 ? opt_spooldir_main : opt_spooldir_2_main;
	opt_dirs.rtp = spoolIndex == 0 ? opt_spooldir_rtp : opt_spooldir_2_rtp;
	opt_dirs.graph = spoolIndex == 0 ? opt_spooldir_graph : opt_spooldir_2_graph;
	opt_dirs.audio = spoolIndex == 0 ? opt_spooldir_audio : opt_spooldir_2_audio;
	opt_max.maxpoolsize = spoolIndex == 0 ? opt_maxpoolsize : opt_maxpoolsize_2;
	opt_max.maxpooldays = spoolIndex == 0 ? opt_maxpooldays : opt_maxpooldays_2;
	opt_max.maxpoolsipsize = spoolIndex == 0 ? opt_maxpoolsipsize : opt_maxpoolsipsize_2;
	opt_max.maxpoolsipdays = spoolIndex == 0 ? opt_maxpoolsipdays : opt_maxpoolsipdays_2;
	opt_max.maxpoolrtpsize = spoolIndex == 0 ? opt_maxpoolrtpsize : opt_maxpoolrtpsize_2;
	opt_max.maxpoolrtpdays = spoolIndex == 0 ? opt_maxpoolrtpdays : opt_maxpoolrtpdays_2;
	opt_max.maxpoolgraphsize = spoolIndex == 0 ? opt_maxpoolgraphsize : opt_maxpoolgraphsize_2;
	opt_max.maxpoolgraphdays = spoolIndex == 0 ? opt_maxpoolgraphdays : opt_maxpoolgraphdays_2;
	opt_max.maxpoolaudiosize = spoolIndex == 0 ? opt_maxpoolaudiosize : opt_maxpoolaudiosize_2;
	opt_max.maxpoolaudiodays = spoolIndex == 0 ? opt_maxpoolaudiodays : opt_maxpoolaudiodays_2;
	opt_other.maxpool_clean_obsolete = opt_maxpool_clean_obsolete;
	opt_other.cleanspool_interval = opt_cleanspool_interval;
	opt_other.cleanspool_sizeMB = opt_cleanspool_sizeMB;
	opt_other.autocleanspoolminpercent = opt_autocleanspoolminpercent;
	opt_other.autocleanmingb = opt_autocleanmingb;
	opt_other.cleanspool_enable_run_hour_from = opt_cleanspool_enable_run_hour_from;
	opt_other.cleanspool_enable_run_hour_to = opt_cleanspool_enable_run_hour_to;
}

void CleanSpool::runCleanThread() {
	if(!clean_thread) {
		if(sverb.cleanspool) { 
			syslog(LOG_NOTICE, "cleanspool[%i]: pthread_create - cleanThread", spoolIndex);
		}
		vm_pthread_create("cleanspool",
				  &clean_thread, NULL, cleanThread, this, __FILE__, __LINE__);
	}
}

void CleanSpool::termCleanThread() {
	if(clean_thread) {
		pthread_join(clean_thread, NULL);
		clean_thread = 0;
	}
}

void *CleanSpool::cleanThread(void *cleanSpool) {
	((CleanSpool*)cleanSpool)->cleanThread();
	return(NULL);
}

void CleanSpool::cleanThread() {
	if(sverb.cleanspool) {
		syslog(LOG_NOTICE, "cleanspool[%i]: run cleanThread", spoolIndex);
	}
	while(!is_terminating()) {
		cleanThreadProcess();
		for(int i = 0; i < 2; i++) {
			if(cleanSpool[i] &&
			   cleanSpool[i]->spoolIndex != this->spoolIndex &&
			   !cleanSpool[i]->clean_thread) {
				cleanSpool[i]->cleanThreadProcess();
			}
		}
		force_reindex_spool_flag = false;
		for(int i = 0; i < 300 && !is_terminating() && !do_convert_filesindex_flag; i++) {
			if(force_reindex_spool_flag) {
				break;
			}
			sleep(1);
		}
	}
}

void CleanSpool::cleanThreadProcess() {
	if(!opt_cleanspool_use_files) {
		updateSpoolDataDir();
	}
	if(opt_cleanspool_use_files &&
	   (do_convert_filesindex_flag ||
	    !check_exists_act_records_in_files() ||
	    !check_exists_act_files_in_filesindex())) {
		const char *reason = do_convert_filesindex_flag ? 
				      (do_convert_filesindex_reason ? do_convert_filesindex_reason : "set do_convert_filesindex_flag") :
				      "call from clean_spooldir - not exists act records in files and act files in filesindex";
		do_convert_filesindex_flag = false;
		do_convert_filesindex_reason = NULL;
		reindex_all(reason);
	}
	bool timeOk = false;
	if(opt_other.cleanspool_enable_run_hour_from >= 0 &&
	   opt_other.cleanspool_enable_run_hour_to >= 0) {
		time_t now;
		time(&now);
		struct tm dateTime = time_r(&now);
		if(opt_other.cleanspool_enable_run_hour_to >= opt_other.cleanspool_enable_run_hour_from) {
			if(dateTime.tm_hour >= opt_other.cleanspool_enable_run_hour_from &&
			   dateTime.tm_hour <= opt_other.cleanspool_enable_run_hour_to) {
				timeOk = true;
			}
		} else {
			if((dateTime.tm_hour >= opt_other.cleanspool_enable_run_hour_from && dateTime.tm_hour < 24) ||
			   dateTime.tm_hour <= opt_other.cleanspool_enable_run_hour_to) {
				timeOk = true;
			}
		}
	} else {
		timeOk = true;
	}
	bool criticalLowSpace = false;
	long int maxpoolsize = 0;
	if((opt_other.autocleanspoolminpercent || opt_other.autocleanmingb) &&
	   (!opt_dirs.rtp.length() || opt_dirs.rtp == opt_dirs.main) && 
	   (!opt_dirs.graph.length() || opt_dirs.graph == opt_dirs.main) && 
	   (!opt_dirs.audio.length() || opt_dirs.audio == opt_dirs.main)) {
		double totalSpaceGB = (double)GetTotalDiskSpace(getSpoolDir(tsf_main)) / (1024 * 1024 * 1024);
		double freeSpacePercent = (double)GetFreeDiskSpace(getSpoolDir(tsf_main), true) / 100;
		double freeSpaceGB = (double)GetFreeDiskSpace(getSpoolDir(tsf_main)) / (1024 * 1024 * 1024);
		int _minPercentForAutoReindex = 1;
		int _minGbForAutoReindex = 5;
		if(freeSpacePercent < _minPercentForAutoReindex && 
		   freeSpaceGB < _minGbForAutoReindex) {
			if(opt_cleanspool_use_files) {
				syslog(LOG_NOTICE, "cleanspool[%i]: low spool disk space - executing reindex_all", spoolIndex);
				reindex_all("call from clean_spooldir - low spool disk space");
			} else {
				syslog(LOG_NOTICE, "cleanspool[%i]: low spool disk space - executing reloadSpoolDataDir", spoolIndex);
				reloadSpoolDataDir(false, true);
			}
			freeSpacePercent = (double)GetFreeDiskSpace(getSpoolDir(tsf_main), true) / 100;
			freeSpaceGB = (double)GetFreeDiskSpace(getSpoolDir(tsf_main)) / (1024 * 1024 * 1024);
			criticalLowSpace = true;
		}
		if(freeSpacePercent < opt_other.autocleanspoolminpercent ||
		   freeSpaceGB < opt_other.autocleanmingb) {
			double usedSizeGB = 0;
			if(opt_cleanspool_use_files) {
				SqlDb *sqlDb = createSqlObject();
				sqlDb->query(
				       "SELECT SUM(coalesce(sipsize,0) + \
						   coalesce(regsize,0) + \
						   coalesce(skinnysize,0) + \
						   coalesce(mgcpsize,0) + \
						   coalesce(ss7size,0) + \
						   coalesce(rtpsize,0) + \
						   coalesce(graphsize,0) + \
						   coalesce(audiosize,0)) as sum_size \
					FROM files \
					WHERE spool_index = " + getSpoolIndex_string() + " and \
					      id_sensor = " + getIdSensor_string());
				SqlDb_row row = sqlDb->fetchRow();
				if(row) {
					usedSizeGB = atol(row["sum_size"].c_str()) / (1024 * 1024 * 1024);
				}
				delete sqlDb;
			} else {
				usedSizeGB = (double)spoolData.getSumSize() / (1024 * 1024 * 1024);
			}
			maxpoolsize = (usedSizeGB + freeSpaceGB - min(totalSpaceGB * opt_other.autocleanspoolminpercent / 100, (double)opt_other.autocleanmingb)) * 1024;
			if(maxpoolsize > 1000 &&
			   (!opt_max.maxpoolsize || maxpoolsize < opt_max.maxpoolsize)) {
				if(opt_max.maxpoolsize && 
				   opt_max.maxpoolsize < totalSpaceGB * 1024 * 1.05 &&
				   maxpoolsize < opt_max.maxpoolsize * 0.8) {
					maxpoolsize = opt_max.maxpoolsize * 0.8;
				}
				syslog(LOG_NOTICE, "cleanspool[%i]: %s: %li MB", 
				       spoolIndex,
				       opt_max.maxpoolsize ?
					"low spool disk space - maxpoolsize set to new value" :
					"maxpoolsize set to value",
				       maxpoolsize);
			} else {
				char criticalLowSpoolSpace_str[1024];
				snprintf(criticalLowSpoolSpace_str, sizeof(criticalLowSpoolSpace_str),
					 "cleanspool[%i]: Critical low disk space in spool %s. Used size: %.2lf GB Free space: %.2lf GB",
					 spoolIndex,
					 getSpoolDir(tsf_main),
					 usedSizeGB,
					 freeSpaceGB);
				cLogSensor::log(cLogSensor::critical, criticalLowSpoolSpace_str);
				maxpoolsize = 0;
			}
			criticalLowSpace = true;
		}
	}
	if((timeOk && !suspended) || criticalLowSpace) {
		if(sverb.cleanspool) {
			syslog(LOG_NOTICE, "cleanspool[%i]: run clean_spooldir", spoolIndex);
		}
		if(maxpoolsize > 1000) {
			maxpoolsize_set = maxpoolsize;
		}
		critical_low_space = criticalLowSpace;
		clean_spooldir_run();
		maxpoolsize_set = 0;
		critical_low_space = false;
	}
}

bool CleanSpool::check_exists_act_records_in_files() {
	bool ok = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
	}
	string condIdSensor_cdr = getCondIdSensor_cdr();
	sqlDb->query("select max(calldate) as max_calldate from cdr "
		     "where calldate > date_add(now(), interval -1 day) " + 
		     (condIdSensor_cdr.empty() ? "" : " and " + condIdSensor_cdr));
	SqlDb_row row = sqlDb->fetchRow();
	if(!row || !row["max_calldate"].length()) {
		return(true);
	}
	time_t maxCdrTime = stringToTime(row["max_calldate"].c_str());
	for(int i = 0; i < 12; i++) {
		time_t checkTime = maxCdrTime - i * 60 * 60;
		struct tm checkTimeInfo = time_r(&checkTime);
		char datehour[20];
		strftime(datehour, 20, "%Y%m%d%H", &checkTimeInfo);
		sqlDb->query(
		       "select * \
			from files \
			where datehour ='" + string(datehour) + "' and \
			      spool_index = " + getSpoolIndex_string() + " and \
			      id_sensor = " + getIdSensor_string());
		if(sqlDb->fetchRow()) {
			ok = true;
			break;
		}
	}
	return(ok);
}

bool CleanSpool::check_exists_act_files_in_filesindex() {
	bool ok = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
	}
	string condIdSensor_cdr = getCondIdSensor_cdr();
	sqlDb->query("select max(calldate) as max_calldate from cdr "
		     "where calldate > date_add(now(), interval -1 day) " + 
		     (condIdSensor_cdr.empty() ? "" : " and " + condIdSensor_cdr));
	SqlDb_row row = sqlDb->fetchRow();
	if(!row || !row["max_calldate"].length()) {
		return(true);
	}
	time_t maxCdrTime = stringToTime(row["max_calldate"].c_str());
	for(int i = 0; i < 12; i++) {
		time_t checkTime = maxCdrTime - i * 60 * 60;
		struct tm checkTimeInfo = time_r(&checkTime);
		char date[20];
		strftime(date, 20, "%Y%m%d", &checkTimeInfo);
		for(int j = 0; j < 24; j++) {
			char datehour[20];
			strcpy_null_term(datehour, date);
			snprintf(datehour + strlen(datehour), sizeof(datehour) - strlen(datehour), "%02i", j);
			if(file_exists(getSpoolDir_string(tsf_main) + "/filesindex/sipsize/" + datehour)) {
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

void CleanSpool::reindex_all(const char *reason) {
	if(!opt_cleanspool_use_files) {
		return;
	}
	u_long actTime = getTimeS();
	if(actTime - lastCall_reindex_all < 5 * 60) {
		syslog(LOG_NOTICE,"cleanspool[%i]: suppress run reindex_all - last run before %lus", spoolIndex, actTime - lastCall_reindex_all);
		return;
	}
	lastCall_reindex_all = actTime;
	list<string> date_dirs;
	this->readSpoolDateDirs(&date_dirs);
	if(!date_dirs.size()) {
		return;
	}
	syslog(LOG_NOTICE, "cleanspool[%i]: reindex_all start%s%s", spoolIndex, reason ? " - " : "", reason ? reason : "");
	sqlStore->query_lock(MYSQL_ADD_QUERY_END(
	       "DELETE FROM files \
		WHERE spool_index = " + getSpoolIndex_string() + " and \
		      id_sensor = " + getIdSensor_string()),
		STORE_PROC_ID_CLEANSPOOL, spoolIndex);
	rmdir_r(getSpoolDir_string(tsf_main) + "/filesindex", true, true);
	for(list<string>::iterator iter_date_dir = date_dirs.begin(); iter_date_dir != date_dirs.end(); iter_date_dir++) {
		reindex_date(*iter_date_dir);
	}
	syslog(LOG_NOTICE, "cleanspool[%i]: reindex_all done", spoolIndex);
	// wait for flush sql store
	while(sqlStore->getSize(STORE_PROC_ID_CLEANSPOOL, spoolIndex) > 0) {
		USLEEP(100000);
	}
	sleep(1);
}

long long CleanSpool::reindex_date(string date) {
	if(!opt_cleanspool_use_files) {
		return(0);
	}
	long long sumDaySize = 0;
	for(int h = 0; h < 24 && !is_terminating(); h++) {
		sumDaySize += reindex_date_hour(date, h);
	}
	if(!sumDaySize && !is_terminating()) {
		rmdir(date.c_str());
	}
	return(sumDaySize);
}

long long CleanSpool::reindex_date_hour(string date, int h, bool readOnly, map<string, long long> *typeSize, bool quickCheck) {
	if(!opt_cleanspool_use_files) {
		return(0);
	}
	char hour[3];
	snprintf(hour, 3, "%02d", h);
	if(typeSize) {
		(*typeSize)["sip"] = 0;
		(*typeSize)["reg"] = 0;
		(*typeSize)["skinny"] = 0;
		(*typeSize)["mgcp"] = 0;
		(*typeSize)["ss7"] = 0;
		(*typeSize)["rtp"] = 0;
		(*typeSize)["graph"] = 0;
		(*typeSize)["audio"] = 0;
	}
	map<unsigned, bool> fillMinutes;
	bool existsDhDir[MAX_TYPE_SPOOL_FILE];
	for(int i = 0; i < MAX_TYPE_SPOOL_FILE; i++) {
		existsDhDir[i] = false;
	}
	long long sipsize = reindex_date_hour_type(date, h, "sip", readOnly, quickCheck, &fillMinutes, &existsDhDir[tsf_sip]);
	long long regsize = reindex_date_hour_type(date, h, "reg", readOnly, quickCheck, &fillMinutes, &existsDhDir[tsf_reg]);
	long long skinnysize = reindex_date_hour_type(date, h, "skinny", readOnly, quickCheck, &fillMinutes, &existsDhDir[tsf_skinny]);
	long long mgcpsize = reindex_date_hour_type(date, h, "mgcp", readOnly, quickCheck, &fillMinutes, &existsDhDir[tsf_mgcp]);
	long long ss7size = reindex_date_hour_type(date, h, "ss7", readOnly, quickCheck, &fillMinutes, &existsDhDir[tsf_ss7]);
	long long rtpsize = reindex_date_hour_type(date, h, "rtp", readOnly, quickCheck, &fillMinutes, &existsDhDir[tsf_rtp]);
	long long graphsize = reindex_date_hour_type(date, h, "graph", readOnly, quickCheck, &fillMinutes, &existsDhDir[tsf_graph]);
	long long audiosize = reindex_date_hour_type(date, h, "audio", readOnly, quickCheck, &fillMinutes, &existsDhDir[tsf_audio]);
	if((sipsize + regsize + skinnysize + mgcpsize + ss7size + rtpsize + graphsize + audiosize) && !readOnly) {
		string dh = date + '/' + hour;
		syslog(LOG_NOTICE, "cleanspool[%i]: reindex_date_hour - %s/%s", spoolIndex, getSpoolDir(tsf_main), dh.c_str());
	}
	if(!readOnly) {
		for(int typeSpoolFile = tsf_sip; typeSpoolFile < tsf_all; ++typeSpoolFile) {
			if(existsDhDir[typeSpoolFile]) {
				for(unsigned m = 0; m < 60; m++) {
					char min[3];
					snprintf(min, 3, "%02d", m);
					string dhm = getSpoolDir_string((eTypeSpoolFile)typeSpoolFile) + '/' + date + '/' + hour + '/' + min;
					if(!fillMinutes[m]) {
						rmdir_r(dhm);
					}
				}
			}
		}
		string ymdh = string(date.substr(0,4)) + date.substr(5,2) + date.substr(8,2) + hour;
		if(sipsize + regsize + skinnysize + mgcpsize + ss7size + rtpsize + graphsize + audiosize) {
			sqlStore->query_lock(MYSQL_ADD_QUERY_END(
			       "INSERT INTO files \
				SET datehour = " + ymdh + ", \
				    spool_index = " + getSpoolIndex_string() + ", \
				    id_sensor = " + getIdSensor_string() + ", \
				    sipsize = " + intToString(sipsize) + ", \
				    regsize = " + intToString(regsize) + ", \
				    skinnysize = " + intToString(skinnysize) + ", \
				    mgcpsize = " + intToString(mgcpsize) + ", \
				    ss7size = " + intToString(ss7size) + ", \
				    rtpsize = " + intToString(rtpsize) + ", \
				    graphsize = " + intToString(graphsize) + ", \
				    audiosize = " + intToString(audiosize) + " \
				ON DUPLICATE KEY UPDATE \
				    sipsize = " + intToString(sipsize) + ", \
				    regsize = " + intToString(regsize) + ", \
				    skinnysize = " + intToString(skinnysize) + ", \
				    mgcpsize = " + intToString(mgcpsize) + ", \
				    ss7size = " + intToString(ss7size) + ", \
				    rtpsize = " + intToString(rtpsize) + ", \
				    graphsize = " + intToString(graphsize) + ", \
				    audiosize = " + intToString(audiosize)),
				STORE_PROC_ID_CLEANSPOOL, spoolIndex);
		} else {
			sqlStore->query_lock(MYSQL_ADD_QUERY_END(
			       "DELETE FROM files \
				WHERE datehour = " + ymdh + " and \
				      spool_index = " + getSpoolIndex_string() + " and \
				      id_sensor = " + getIdSensor_string()),
				STORE_PROC_ID_CLEANSPOOL, spoolIndex);
			for(int typeSpoolFile = tsf_sip; typeSpoolFile < tsf_all; ++typeSpoolFile) {
				rmdir_r(getSpoolDir_string((eTypeSpoolFile)typeSpoolFile) + '/' + date + '/' + hour);
			}
		}
	}
	if(typeSize) {
		(*typeSize)["sip"] = sipsize;
		(*typeSize)["reg"] = regsize;
		(*typeSize)["skinny"] = skinnysize;
		(*typeSize)["mgcp"] = mgcpsize;
		(*typeSize)["ss7"] = ss7size;
		(*typeSize)["rtp"] = rtpsize;
		(*typeSize)["graph"] = graphsize;
		(*typeSize)["audio"] = audiosize;
	}
	return(sipsize + regsize + skinnysize + mgcpsize + ss7size + rtpsize + graphsize + audiosize);
}

long long CleanSpool::reindex_date_hour_type(string date, int h, string type, bool readOnly, bool quickCheck, 
					     map<unsigned, bool> *fillMinutes, bool *existsDhDir) {
	if(!opt_cleanspool_use_files) {
		return(0);
	}
	long long sumsize = 0;
	string filesIndexDirName;
	string spoolDirTypeName;
	string alterSpoolDirTypeName;
	eTypeSpoolFile typeSpoolFile = tsf_main;
	if(type == "sip") {
		filesIndexDirName = "sipsize";
		spoolDirTypeName = "SIP";
		alterSpoolDirTypeName = "ALL";
		typeSpoolFile = tsf_sip;
	} else if(type == "reg") {
		filesIndexDirName = "regsize";
		spoolDirTypeName = "REG";
		typeSpoolFile = tsf_reg;
	} else if(type == "skinny") {
		filesIndexDirName = "skinnysize";
		spoolDirTypeName = "SKINNY";
		typeSpoolFile = tsf_skinny;
	} else if(type == "mgcp") {
		filesIndexDirName = "mgcpsize";
		spoolDirTypeName = "MGCP";
		typeSpoolFile = tsf_mgcp;
	} else if(type == "ss7") {
		filesIndexDirName = "ss7size";
		spoolDirTypeName = "SS7";
		typeSpoolFile = tsf_ss7;
	} else if(type == "rtp") {
		filesIndexDirName = "rtpsize";
		spoolDirTypeName = "RTP";
		typeSpoolFile = tsf_rtp;
	} else if(type == "graph") {
		filesIndexDirName = "graphsize";
		spoolDirTypeName = "GRAPH";
		typeSpoolFile = tsf_graph;
	} else if(type == "audio") {
		filesIndexDirName = "audiosize";
		spoolDirTypeName = "AUDIO";
		typeSpoolFile = tsf_audio;
	}
	char hour[3];
	snprintf(hour, 3, "%02d", h);
	string spool_fileindex_path = getSpoolDir_string(tsf_main) + "/filesindex/" + filesIndexDirName;
	string ymdh = string(date.substr(0,4)) + date.substr(5,2) + date.substr(8,2) + hour;
	string spool_fileindex = spool_fileindex_path + '/' + ymdh;
	ofstream spool_fileindex_stream;
	extern TarQueue *tarQueue[2];
	list<string> listOpenTars;
	if(tarQueue[spoolIndex]) {
		listOpenTars = tarQueue[spoolIndex]->listOpenTars();
	}
	string dh = date + '/' + hour;
	string spool_dh = this->findExistsSpoolDirFile(typeSpoolFile, dh);
	if(file_exists(spool_dh)) {
		*existsDhDir = true;
		for(unsigned m = 0; m < 60; m++) {
			char min[3];
			snprintf(min, 3, "%02d", m);
			string dhmt = date + '/' + hour + '/' + min + '/' + spoolDirTypeName;
			string spool_dhmt = this->findExistsSpoolDirFile(typeSpoolFile, dhmt);
			bool exists_spool_dhmt = file_exists(spool_dhmt);
			if(!exists_spool_dhmt && !alterSpoolDirTypeName.empty()) {
				dhmt = date + '/' + hour + '/' + min + '/' + alterSpoolDirTypeName;
				spool_dhmt = this->findExistsSpoolDirFile(typeSpoolFile, dhmt);
				exists_spool_dhmt = file_exists(spool_dhmt);
			}
			if(exists_spool_dhmt) {
				bool existsFile = false;
				DIR* dp = opendir(spool_dhmt.c_str());
				if(dp) {
					while(true) {
						dirent *de = readdir(dp);
						if(de == NULL) break;
						if(string(de->d_name) == ".." or string(de->d_name) == ".") continue;
						existsFile = true;
						if(quickCheck) {
							sumsize = 1;
							break;
						}
						string dhmt_file = dhmt + '/' + de->d_name;
						string spool_dhmt_file = spool_dhmt + '/' + de->d_name;
						if(!tarQueue[spoolIndex] ||
						   !fileIsOpenTar(listOpenTars, spool_dhmt_file)) {
							long long size = GetFileSizeDU(spool_dhmt_file, typeSpoolFile, spoolIndex);
							if(size == 0) size = 1;
							sumsize += size;
							if(!readOnly) {
								if(!spool_fileindex_stream.is_open()) {
									spooldir_mkdir(spool_fileindex_path);
									spool_fileindex_stream.open(spool_fileindex.c_str(), ios::trunc | ios::out);
									spooldir_file_chmod_own(spool_fileindex);
								}
								spool_fileindex_stream << dhmt_file << ":" << size << "\n";
							}
						}
					}
					closedir(dp);
				}
				if(existsFile) {
					(*fillMinutes)[m] = true;
					if(quickCheck) {
						break;
					}
				} else if(!readOnly) {
					rmdir_r(spool_dhmt);
				}
			}
		}
	}
	if(!readOnly) {
		spool_fileindex_stream.close();
		if(!sumsize) {
			unlink(spool_fileindex.c_str());
		}
	}
	return(sumsize);
}

void CleanSpool::unlinkfileslist(eTypeSpoolFile typeSpoolFile, string fname, string callFrom) {
	if(DISABLE_CLEANSPOOL) {
		return;
	}
	syslog(LOG_NOTICE, "cleanspool[%i]: call unlinkfileslist(%s) from %s", spoolIndex, fname.c_str(), callFrom.c_str());
	if(sverb.cleanspool_disable_rm) {
		return;
	}
	char buf[4092];
	FILE *fd = fopen((getSpoolDir_string(tsf_main) + '/' + fname).c_str(), "r");
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
			unlink(this->findExistsSpoolDirFile(typeSpoolFile, buf).c_str());
			if(DISABLE_CLEANSPOOL) {
				fclose(fd);
				return;
			}
		}
		fclose(fd);
		unlink((getSpoolDir_string(tsf_main) + '/' + fname).c_str());
	}
}

void CleanSpool::unlink_dirs(string datehour, int sip, int reg, int skinny, int mgcp, int ss7, int rtp, int graph, int audio, string callFrom) {
	if(DISABLE_CLEANSPOOL || !check_datehour(datehour.c_str())) {
		return;
	}
	syslog(LOG_NOTICE, "cleanspool[%i]: call unlink_dirs(%s,%s,%s,%s,%s,%s,%s,%s, %s) from %s", 
	       spoolIndex,
	       datehour.c_str(), 
	       sip == 2 ? "SIP" : sip == 1 ? "sip" : "---",
	       reg == 2 ? "REG" : reg == 1 ? "reg" : "---",
	       skinny == 2 ? "SKINNY" : skinny == 1 ? "skinny" : "---",
	       mgcp == 2 ? "MGCP" : mgcp == 1 ? "mgcp" : "---",
	       ss7 == 2 ? "SS7" : ss7 == 1 ? "ss7" : "---",
	       rtp == 2 ? "RTP" : rtp == 1 ? "rtp" : "---",
	       graph == 2 ? "GRAPH" : graph == 1 ? "graph" : "---",
	       audio == 2 ? "AUDIO" : audio == 1 ? "audio" : "---",
	       callFrom.c_str());
	if(sverb.cleanspool_disable_rm) {
		return;
	}
	string d = datehour.substr(0,4) + "-" + datehour.substr(4,2) + "-" + datehour.substr(6,2);
	string dh =  d + '/' + datehour.substr(8,2);
	list<string> spool_dirs;
	this->getSpoolDirs(&spool_dirs);
	for(unsigned m = 0; m < 60 && !DISABLE_CLEANSPOOL; m++) {
		char min[3];
		snprintf(min, 3, "%02d", m);
		string dhm = dh + '/' + min;
		if(sip) {
			rmdir_if_r(this->findExistsSpoolDirFile(tsf_sip,'/' + dhm + "/SIP"),
				   sip == 2);
			rmdir_if_r(this->findExistsSpoolDirFile(tsf_sip,'/' + dhm + "/ALL"),
				   sip == 2);
		}
		if(reg) {
			rmdir_if_r(this->findExistsSpoolDirFile(tsf_reg,'/' + dhm + "/REG"),
				   reg == 2);
		}
		if(skinny) {
			rmdir_if_r(this->findExistsSpoolDirFile(tsf_skinny,'/' + dhm + "/SKINNY"),
				   skinny == 2);
		}
		if(mgcp) {
			rmdir_if_r(this->findExistsSpoolDirFile(tsf_mgcp,'/' + dhm + "/MGCP"),
				   mgcp == 2);
		}
		if(ss7) {
			rmdir_if_r(this->findExistsSpoolDirFile(tsf_ss7,'/' + dhm + "/SS7"),
				   ss7 == 2);
		}
		if(rtp) {
			rmdir_if_r(this->findExistsSpoolDirFile(tsf_rtp, '/' + dhm + "/RTP"),
				   rtp == 2);
		}
		if(graph) {
			rmdir_if_r(this->findExistsSpoolDirFile(tsf_graph, '/' + dhm + "/GRAPH"),
				   graph == 2);
		}
		if(audio) {
			rmdir_if_r(this->findExistsSpoolDirFile(tsf_audio, '/' + dhm + "/AUDIO"),
				   audio == 2);
		}
		// remove minute
		for(list<string>::iterator iter_sd = spool_dirs.begin(); iter_sd != spool_dirs.end(); iter_sd++) {
			if(rmdir((*iter_sd + '/' + dhm).c_str()) == 0) {
				syslog(LOG_NOTICE, "cleanspool[%i]: unlink_dirs: remove %s/%s", spoolIndex, (*iter_sd).c_str(), dhm.c_str());
			}
		}
	}
	// remove hour
	for(list<string>::iterator iter_sd = spool_dirs.begin(); iter_sd != spool_dirs.end(); iter_sd++) {
		if(rmdir((*iter_sd + '/' + dh).c_str()) == 0) {
			syslog(LOG_NOTICE, "cleanspool[%i]: unlink_dirs: remove %s/%s", spoolIndex, (*iter_sd).c_str(), dh.c_str());
		}
	}
	// remove day
	for(list<string>::iterator iter_sd = spool_dirs.begin(); iter_sd != spool_dirs.end(); iter_sd++) {
		if(rmdir((*iter_sd + '/' + d).c_str()) == 0) {
			syslog(LOG_NOTICE, "cleanspool[%i]: unlink_dirs: remove %s/%s", spoolIndex, (*iter_sd).c_str(), d.c_str());
		}
	}
}

void CleanSpool::erase_dir(string dir, sSpoolDataDirIndex index, string callFrom) {
	if(DISABLE_CLEANSPOOL) {
		return;
	}
	syslog(LOG_NOTICE, "cleanspool[%i]: call erase_dir(%s) from %s", spoolIndex, dir.c_str(), callFrom.c_str());
	spoolData.deleteHourCacheFile(index);
	DIR* dp = opendir(dir.c_str());
	if(dp) {
		dirent* de;
		while((de = readdir(dp)) != NULL) {
			if(string(de->d_name) == ".." or string(de->d_name) == ".") continue;
			if(!is_dir(de, dir.c_str())) {
				if(!sverb.cleanspool_disable_rm) {
					unlink((string(dir) + "/" + de->d_name).c_str());
				}
			}
		}
		closedir(dp);
	}
	erase_dir_if_empty(dir);
}

void CleanSpool::erase_dir_if_empty(string dir, string callFrom) {
	if(DISABLE_CLEANSPOOL) {
		return;
	}
	if(!callFrom.empty()) {
		syslog(LOG_NOTICE, "cleanspool[%i]: call erase_dir_if_empty(%s) from %s", spoolIndex, dir.c_str(), callFrom.c_str());
	}
	if(dir_is_empty(dir, true)) {
		if(!sverb.cleanspool_disable_rm) {
			rmdir_r(dir.c_str(), true);
		}
		string redukDir = dir;
		string lastDir;
		while(true) {
			redukDir = reduk_dir(redukDir.c_str(), &lastDir);
			if(redukDir.length() && lastDir.length()) {
				if(dir_is_empty(redukDir.c_str())) {
					if(!sverb.cleanspool_disable_rm) {
						rmdir(redukDir.c_str());
					}
					spoolData.eraseDir(redukDir);
					if(check_date_dir(lastDir.c_str())) {
						break;
					}
				} else {
					break;
				}
			} else {
				break;
			}
		}
	}
}

bool CleanSpool::dir_is_empty(string dir, bool enableRecursion) {
	DIR* dp = opendir(dir.c_str());
	if(!dp) {
		return(false);
	}
	bool empty = true;
	dirent* de;
	while((de = readdir(dp)) != NULL) {
		if(string(de->d_name) == ".." or string(de->d_name) == ".") continue;
		if(enableRecursion && is_dir(de, dir.c_str())) {
			if(!dir_is_empty(dir + "/" + de->d_name, enableRecursion)) {
				empty = false;
				break;
			}
		} else {
			empty = false;
			break;
		}
	}
	closedir(dp);
	return(empty);
}

string CleanSpool::reduk_dir(string dir, string *last_dir) {
	size_t lastDirSep = dir.rfind('/');
	if(lastDirSep == string::npos) {
		return("");
	}
	*last_dir = dir.substr(lastDirSep + 1);
	while(lastDirSep > 0 && dir[lastDirSep - 1] == '/') {
		--lastDirSep;
	}
	if(lastDirSep == 0) {
		return("");
	}
	return(dir.substr(0, lastDirSep));
}

void CleanSpool::clean_spooldir_run() {
	if(opt_other.cleanspool_interval && opt_other.cleanspool_sizeMB > 0) {
		opt_max.maxpoolsize = opt_other.cleanspool_sizeMB;
		// if old cleanspool interval is defined convert the config to new config 
		extern char configfile[1024];
		if(file_exists(configfile)) {
			syslog(LOG_NOTICE, "cleanspool[%i]: converting [%s] cleanspool_interval and cleanspool_size to maxpoolsize", spoolIndex, configfile);
			if(opt_cleanspool_use_files) {
				reindex_all("convert configuration");
			}
			string tmpf = "/tmp/VM_pRjSYLAyx.conf";
			FILE *fdr = fopen(configfile, "r");
			FILE *fdw = fopen(tmpf.c_str(), "w");
			if(!fdr or !fdw) {
				syslog(LOG_ERR, "cleanspool[%i]: cannot open config file [%s]", spoolIndex, configfile);
				return;
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
						tmp << "\n\n"
						    << "#this is new cleaning implementation\n"
						    << "maxpoolsize            = " << opt_other.cleanspool_sizeMB << "\n"
						    << "#maxpooldays            =\n"
						    << "#maxpoolsipsize         =\n"
						    << "#maxpoolsipdays         =\n"
						    << "#maxpoolrtpsize         =\n"
						    << "#maxpoolrtpdays         =\n"
						    << "#maxpoolgraphsize       =\n"
						    << "#maxpoolgraphdays       =\n";
						fwrite(tmp.str().c_str(), 1, tmp.str().length(), fdw);
					}
				}
			}
			fclose(fdr);
			fclose(fdw);
			move_file(tmpf.c_str(), configfile);

		}
	}
	
	clean_spooldir_run_processing = 1;

	clean_maxpoolsize_sip();
	clean_maxpooldays_sip();

	clean_maxpoolsize_rtp();
	clean_maxpooldays_rtp();

	clean_maxpoolsize_graph();
	clean_maxpooldays_graph();

	clean_maxpoolsize_audio();
	clean_maxpooldays_audio();
	
	clean_maxpoolsize_all();
	clean_maxpooldays_all();

	if(opt_other.maxpool_clean_obsolete) {
		clean_obsolete_dirs();
	}
	
	clean_spooldir_run_processing = 0;
}

void CleanSpool::clean_maxpoolsize(bool sip, bool rtp, bool graph, bool audio) {
	bool all = sip && rtp && graph && audio;
	unsigned int maxpoolsize = all ?
				    opt_max.maxpoolsize :
				   sip ?
				    opt_max.maxpoolsipsize :
				   rtp ?
				    opt_max.maxpoolrtpsize :
				   graph ?
				    opt_max.maxpoolgraphsize :
				   audio ?
				    opt_max.maxpoolaudiosize :
				    0;
	if(maxpoolsize == 0 && maxpoolsize_set == 0) {
		return;
	}
	if(sverb.cleanspool)  {
		cout << "clean_maxpoolsize\n";
	}
	if(opt_cleanspool_use_files) {
		if(!sqlDb) {
			sqlDb = createSqlObject();
		}
		while(!is_terminating() && !DISABLE_CLEANSPOOL) {
			sqlDb->query(
			       "SELECT SUM(sipsize) AS sipsize, \
				       SUM(regsize) AS regsize, \
				       SUM(skinnysize) AS skinnysize, \
				       SUM(mgcpsize) AS mgcpsize, \
				       SUM(ss7size) AS ss7size, \
				       SUM(rtpsize) AS rtpsize, \
				       SUM(graphsize) as graphsize, \
				       SUM(audiosize) AS audiosize \
				FROM files \
				WHERE spool_index = " + getSpoolIndex_string() + " and \
				      id_sensor = " + getIdSensor_string());
			SqlDb_row row = sqlDb->fetchRow();
			uint64_t sipsize_total = strtoull(row["sipsize"].c_str(), NULL, 0) + 
						 strtoull(row["regsize"].c_str(), NULL, 0) + 
						 strtoull(row["skinnysize"].c_str(), NULL, 0) + 
						 strtoull(row["mgcpsize"].c_str(), NULL, 0) + 
						 strtoull(row["ss7size"].c_str(), NULL, 0);
			uint64_t rtpsize_total = strtoull(row["rtpsize"].c_str(), NULL, 0);
			uint64_t graphsize_total = strtoull(row["graphsize"].c_str(), NULL, 0);
			uint64_t audiosize_total = strtoull(row["audiosize"].c_str(), NULL, 0);
			double total = ((sip ? sipsize_total : 0) + 
					(rtp ? rtpsize_total : 0) + 
					(graph ? graphsize_total : 0) + 
					(audio ? audiosize_total : 0)) / (double)(1024 * 1024);
			if(sverb.cleanspool) {
				cout << "total[" << total << "] = " 
				     << (sip ? intToString(sipsize_total) : "na") << " + " 
				     << (rtp ? intToString(rtpsize_total) : "na") << " + " 
				     << (graph ? intToString(graphsize_total) : "na") << " + " 
				     << (audio ? intToString(audiosize_total) : "na")
				     << " maxpoolsize[" << maxpoolsize;
				if(maxpoolsize_set) {
					cout << " / reduk: " << maxpoolsize_set;
				}
				cout << "]\n";
			}
			unsigned int reduk_maxpoolsize = sip && rtp && graph && audio ? 
							  get_reduk_maxpoolsize(maxpoolsize) :
							  maxpoolsize;
			if(reduk_maxpoolsize == 0 ||
			   total <= reduk_maxpoolsize) {
				break;
			}
			// walk all rows ordered by datehour and delete everything 
			string sizeCond;
			if(!(sip && rtp && graph && audio)) {
				sizeCond = sip ? "(sipsize > 0 or regsize > 0 or skinnysize > 0 or mgcpsize > 0 or ss7size > 0)" :
					   rtp ? "rtpsize > 0" :
					   graph ? "graphsize > 0" :
						   "audiosize > 0";
				sizeCond = " and " + sizeCond;
			}
			sqlDb->query(
			       "SELECT * \
				FROM files \
				WHERE spool_index = " + getSpoolIndex_string() + " and \
				      id_sensor = " + getIdSensor_string() + " \
				      " + sizeCond + " \
				ORDER BY datehour LIMIT 1");
			row = sqlDb->fetchRow();
			if(!row) {
				break;
			}
			if(!check_datehour(row["datehour"].c_str())) {
				sqlDb->query(
				       "DELETE FROM files \
					WHERE datehour = " + row["datehour"] + " and \
					      spool_index = " + getSpoolIndex_string() + " and \
					      id_sensor = " + getIdSensor_string());
				continue;
			}
			uint64_t sipsize = strtoull(row["sipsize"].c_str(), NULL, 0) +
					   strtoull(row["regsize"].c_str(), NULL, 0) + 
					   strtoull(row["skinnysize"].c_str(), NULL, 0) + 
					   strtoull(row["mgcpsize"].c_str(), NULL, 0) + 
					   strtoull(row["ss7size"].c_str(), NULL, 0);
			uint64_t rtpsize = strtoull(row["rtpsize"].c_str(), NULL, 0);
			uint64_t graphsize = strtoull(row["graphsize"].c_str(), NULL, 0);
			uint64_t audiosize = strtoull(row["audiosize"].c_str(), NULL, 0);
			if(sip) {
				unlinkfileslist(tsf_sip, "filesindex/sipsize/" + row["datehour"], "clean_maxpoolsize");
				unlinkfileslist(tsf_reg, "filesindex/regsize/" + row["datehour"], "clean_maxpoolsize");
				unlinkfileslist(tsf_skinny, "filesindex/skinnysize/" + row["datehour"], "clean_maxpoolsize");
				unlinkfileslist(tsf_mgcp, "filesindex/mgcpsize/" + row["datehour"], "clean_maxpoolsize");
				unlinkfileslist(tsf_ss7, "filesindex/ss7size/" + row["datehour"], "clean_maxpoolsize");
				if(DISABLE_CLEANSPOOL) {
					break;
				}
			}
			if(rtp) {
				unlinkfileslist(tsf_rtp, "filesindex/rtpsize/" + row["datehour"], "clean_maxpoolsize");
				if(DISABLE_CLEANSPOOL) {
					break;
				}
			}
			if(graph) {
				unlinkfileslist(tsf_graph, "filesindex/graphsize/" + row["datehour"], "clean_maxpoolsize");
				if(DISABLE_CLEANSPOOL) {
					break;
				}
			}
			if(audio) {
				unlinkfileslist(tsf_audio, "filesindex/audiosize/" + row["datehour"], "clean_maxpoolsize");
				if(DISABLE_CLEANSPOOL) {
					break;
				}
			}
			if(sip && rtp && graph && audio) {
				unlink_dirs(row["datehour"], 2, 2, 2, 2, 2, 2, 2, 2, "clean_maxpoolsize");
			} else {
				unlink_dirs(row["datehour"],
					    sip ? 2 : 1, 
					    sip ? 2 : 1, 
					    sip ? 2 : 1, 
					    sip ? 2 : 1, 
					    sip ? 2 : 1, 
					    rtp ? 2 : 1, 
					    graph ? 2 : 1, 
					    audio ? 2 : 1, 
					    "clean_maxpoolsize");
			}
			if((sip && rtp && graph && audio) ||
			   ((sip ? 0 : sipsize) + 
			    (rtp ? 0 : rtpsize) + 
			    (graph ? 0 : graphsize) +
			    (audio ? 0 : audiosize)) == 0) {
				sqlDb->query(
				       "DELETE FROM files \
					WHERE datehour = " + row["datehour"] + " and \
					      spool_index = " + getSpoolIndex_string() + " and \
					      id_sensor = " + getIdSensor_string());
			} else {
				string columnSetNul = sip ? "sipsize = 0, regsize = 0, skinnysize = 0, mgcpsize = 0, ss7size = 0" :
						      rtp ? "rtpsize = 0" :
						      graph ? "graphsize = 0" : "audiosize = 0";
				sqlDb->query(
				       "UPDATE files \
					SET " + columnSetNul + " \
					WHERE datehour = " + row["datehour"] + " and \
					      spool_index = " + getSpoolIndex_string() + " and \
					      id_sensor = " + getIdSensor_string());
			}
		}
	} else {
		this->spoolData.lock();
		while(!is_terminating() && !DISABLE_CLEANSPOOL) {
			long long allsize_total;
			long long sipsize_total;
			long long rtpsize_total;
			long long graphsize_total;
			long long audiosize_total;
			allsize_total = this->spoolData.getSplitSumSize(&sipsize_total, &rtpsize_total, &graphsize_total, &audiosize_total);
			double total = (all ? 
					 allsize_total : 
					 ((sip ? sipsize_total : 0) + 
					  (rtp ? rtpsize_total : 0) + 
					  (graph ? graphsize_total : 0) + 
					  (audio ? audiosize_total : 0))) / (double)(1024 * 1024);
			if(sverb.cleanspool) {
				cout << "total[" << total << "] = " 
				     << (sip ? intToString(sipsize_total) : "na") << " + " 
				     << (rtp ? intToString(rtpsize_total) : "na") << " + " 
				     << (graph ? intToString(graphsize_total) : "na") << " + " 
				     << (audio ? intToString(audiosize_total) : "na")
				     << " maxpoolsize[" << maxpoolsize;
				if(maxpoolsize_set) {
					cout << " / reduk: " << maxpoolsize_set;
				}
				cout << "]\n";
			}
			unsigned int reduk_maxpoolsize = all ? 
							  get_reduk_maxpoolsize(maxpoolsize) :
							  maxpoolsize;
			if(reduk_maxpoolsize == 0 ||
			   total <= reduk_maxpoolsize) {
				break;
			}
			map<sSpoolDataDirIndex, sSpoolDataDirItem>::iterator iter = this->spoolData.getBegin();
			if(iter != this->spoolData.end() &&
			   iter->second.is_dir &&
			   !this->spoolData.existsFileIndex((sSpoolDataDirIndex*)&iter->first)) {
				erase_dir_if_empty(iter->second.path.c_str(), "clean_maxpoolsize");
			} else {
				iter = this->spoolData.getMin(sip, rtp, graph, audio);
				if(iter == this->spoolData.end()) {
					break;
				}
				erase_dir(iter->second.path.c_str(), iter->first, "clean_maxpoolsize");
			}
			this->spoolData.erase(iter);
		}
		this->spoolData.saveDeletedHourCacheFiles();
		this->spoolData.unlock();
	}
}

void CleanSpool::clean_maxpooldays(bool sip, bool rtp, bool graph, bool audio) {
	bool all = sip && rtp && graph && audio;
	unsigned int maxpooldays = all ?
				    opt_max.maxpooldays :
				   sip ?
				    opt_max.maxpoolsipdays :
				   rtp ?
				    opt_max.maxpoolrtpdays :
				   graph ?
				    opt_max.maxpoolgraphdays :
				   audio ?
				    opt_max.maxpoolaudiodays :
				    0;
	if(maxpooldays == 0) {
		return;
	}
	if(sverb.cleanspool)  {
		cout << "clean_maxpooldays\n";
	}
	if(!sqlDb) {
		sqlDb = createSqlObject();
	}
	if(opt_cleanspool_use_files) {
		while(!is_terminating() && !DISABLE_CLEANSPOOL) {
			string sizeCond;
			if(!(sip && rtp && graph && audio)) {
				sizeCond = sip ? "(sipsize > 0 or regsize > 0 or skinnysize > 0 or mgcpsize > 0 or ss7size > 0)" :
					   rtp ? "rtpsize > 0" :
					   graph ? "graphsize > 0" :
						   "audiosize > 0";
				sizeCond = " and " + sizeCond;
			}
			sqlDb->query(
			       "SELECT * \
				FROM files \
				WHERE spool_index = " + getSpoolIndex_string() + " and \
				      id_sensor = " + getIdSensor_string() + " and \
				      datehour < DATE_FORMAT(DATE_SUB(NOW(), INTERVAL " + intToString(maxpooldays) + " DAY), '%Y%m%d%H') \
				      " + sizeCond + " \
				      ORDER BY datehour");
			SqlDb_row row = sqlDb->fetchRow();
			if(!row) {
				break;
			}
			uint64_t sipsize = strtoull(row["sipsize"].c_str(), NULL, 0) + 
					   strtoull(row["regsize"].c_str(), NULL, 0) + 
					   strtoull(row["skinnysize"].c_str(), NULL, 0) + 
					   strtoull(row["mgcpsize"].c_str(), NULL, 0) + 
					   strtoull(row["ss7size"].c_str(), NULL, 0);
			uint64_t rtpsize = strtoull(row["rtpsize"].c_str(), NULL, 0);
			uint64_t graphsize = strtoull(row["graphsize"].c_str(), NULL, 0);
			uint64_t audiosize = strtoull(row["audiosize"].c_str(), NULL, 0);
			if(sip) {
				unlinkfileslist(tsf_sip, "filesindex/sipsize/" + row["datehour"], "clean_maxpooldays");
				unlinkfileslist(tsf_sip, "filesindex/regsize/" + row["datehour"], "clean_maxpooldays");
				unlinkfileslist(tsf_sip, "filesindex/skinnysize/" + row["datehour"], "clean_maxpooldays");
				unlinkfileslist(tsf_sip, "filesindex/mgcpsize/" + row["datehour"], "clean_maxpooldays");
				unlinkfileslist(tsf_sip, "filesindex/ss7size/" + row["datehour"], "clean_maxpooldays");
				if(DISABLE_CLEANSPOOL) {
					break;
				}
			}
			if(rtp) {
				unlinkfileslist(tsf_rtp, "filesindex/rtpsize/" + row["datehour"], "clean_maxpooldays");
				if(DISABLE_CLEANSPOOL) {
					break;
				}
			}
			if(graph) {
				unlinkfileslist(tsf_graph, "filesindex/graphsize/" + row["datehour"], "clean_maxpooldays");
				if(DISABLE_CLEANSPOOL) {
					break;
				}
			}
			if(audio) {
				unlinkfileslist(tsf_audio, "filesindex/audiosize/" + row["datehour"], "clean_maxpooldays");
				if(DISABLE_CLEANSPOOL) {
					break;
				}
			}
			if(sip && rtp && graph && audio) {
				unlink_dirs(row["datehour"], 2, 2, 2, 2, 2, 2, 2, 2, "clean_maxpooldays");
			} else {
				unlink_dirs(row["datehour"],
					    sip ? 2 : 1, 
					    sip ? 2 : 1, 
					    sip ? 2 : 1, 
					    sip ? 2 : 1, 
					    sip ? 2 : 1, 
					    rtp ? 2 : 1, 
					    graph ? 2 : 1, 
					    audio ? 2 : 1, 
					    "clean_maxpooldays");
			}
			if((sip && rtp && graph && audio) ||
			   ((sip ? 0 : sipsize) + 
			    (rtp ? 0 : rtpsize) + 
			    (graph ? 0 : graphsize) +
			    (audio ? 0 : audiosize)) == 0) {
				sqlDb->query(
				       "DELETE FROM files \
					WHERE datehour = " + row["datehour"] + " and \
					      spool_index = " + getSpoolIndex_string() + " and \
					      id_sensor = " + getIdSensor_string());
			} else {
				string columnSetNul = sip ? "sipsize = 0, regsize = 0, skinnysize = 0, mgcpsize = 0, ss7size = 0" :
						      rtp ? "rtpsize = 0" :
						      graph ? "graphsize = 0" : "audiosize = 0";
				sqlDb->query(
				       "UPDATE files \
					SET " + columnSetNul + " \
					WHERE datehour = " + row["datehour"] + " and \
					      spool_index = " + getSpoolIndex_string() + " and \
					      id_sensor = " + getIdSensor_string());
			}
		}
	} else {
		this->spoolData.lock();
		while(!is_terminating() && !DISABLE_CLEANSPOOL) {
			map<sSpoolDataDirIndex, sSpoolDataDirItem>::iterator iter = this->spoolData.getBegin();
			if(iter != this->spoolData.end() &&
			   iter->second.is_dir &&
			   !this->spoolData.existsFileIndex((sSpoolDataDirIndex*)&iter->first)) {
				erase_dir_if_empty(iter->second.path.c_str(), "clean_maxpooldays");
			} else {
				iter = this->spoolData.getMin(sip, rtp, graph, audio);
				if(iter == this->spoolData.end()) {
					break;
				}
				if(getNumberOfDayToNow(iter->first.date.c_str()) <= (int)maxpooldays) {
					break;
				}
				erase_dir(iter->second.path.c_str(), iter->first, "clean_maxpooldays");
			}
			this->spoolData.erase(iter);
		}
		this->spoolData.saveDeletedHourCacheFiles();
		this->spoolData.unlock();
	}
}

void CleanSpool::clean_obsolete_dirs() {
	if(!opt_cleanspool_use_files) {
		return;
	}
	unsigned int maxDays[10];
	unsigned int defaultMaxPolDays = opt_max.maxpooldays ? opt_max.maxpooldays : 14;
	maxDays[(int)tsf_sip] = opt_max.maxpoolsipdays ? opt_max.maxpoolsipdays : defaultMaxPolDays;
	maxDays[(int)tsf_reg] = opt_max.maxpoolsipdays ? opt_max.maxpoolsipdays : defaultMaxPolDays;
	maxDays[(int)tsf_skinny] = opt_max.maxpoolsipdays ? opt_max.maxpoolsipdays : defaultMaxPolDays;
	maxDays[(int)tsf_mgcp] = opt_max.maxpoolsipdays ? opt_max.maxpoolsipdays : defaultMaxPolDays;
	maxDays[(int)tsf_ss7] = opt_max.maxpoolsipdays ? opt_max.maxpoolsipdays : defaultMaxPolDays;
	maxDays[(int)tsf_rtp] = opt_max.maxpoolrtpdays ? opt_max.maxpoolrtpdays : defaultMaxPolDays;
	maxDays[(int)tsf_graph] = opt_max.maxpoolgraphdays ? opt_max.maxpoolgraphdays : defaultMaxPolDays;
	maxDays[(int)tsf_audio] = opt_max.maxpoolaudiodays ? opt_max.maxpoolaudiodays : defaultMaxPolDays;
	
	list<string> spool_dirs;
	this->getSpoolDirs(&spool_dirs);
	list<string> date_dirs;
	this->readSpoolDateDirs(&date_dirs);
	if(!date_dirs.size()) {
		return;
	}
	if(!sqlDb) {
		sqlDb = createSqlObject();
	}
	for(list<string>::iterator iter_date_dir = date_dirs.begin(); iter_date_dir != date_dirs.end() && !is_terminating() && !DISABLE_CLEANSPOOL; iter_date_dir++) {
		string dateDir = *iter_date_dir;
		int numberOfDayToNow = getNumberOfDayToNow(dateDir.c_str());
		if(numberOfDayToNow > 0) {
			string day_sub_dir = '/' + dateDir;
			bool removeHourDir = false;
			for(int h = 0; h < 24; h++) {
				char hour[3];
				snprintf(hour, 3, "%02d", h);
				string hour_sub_dir = day_sub_dir + '/' + hour;
				bool existsHourDir = false;
				for(list<string>::iterator iter_sd = spool_dirs.begin(); iter_sd != spool_dirs.end(); iter_sd++) {
					if(file_exists(*iter_sd + hour_sub_dir)) {
						existsHourDir = true;
					}
				}
				if(existsHourDir) {
					sqlDb->query(
					       "SELECT * \
						FROM files \
						where spool_index = " + getSpoolIndex_string() + " and \
						      id_sensor = " + getIdSensor_string() + " and \
						      datehour = '" + find_and_replace(dateDir.c_str(), "-", "") + hour + "'");
					SqlDb_row row = sqlDb->fetchRow();
					bool removeMinDir = false;
					for(int m = 0; m < 60; m++) {
						char min[3];
						snprintf(min, 3, "%02d", m);
						string min_sub_dir = hour_sub_dir + '/' + min;
						bool existsMinDir = false;
						for(list<string>::iterator iter_sd = spool_dirs.begin(); iter_sd != spool_dirs.end(); iter_sd++) {
							if(file_exists(*iter_sd + min_sub_dir)) {
								existsMinDir = true;
							}
						}
						if(existsMinDir) {
							bool removeMinTypeDir = false;
							bool keepMainMinTypeFolder = false;
							for(int typeSpoolFile = tsf_sip; typeSpoolFile < tsf_all; ++typeSpoolFile) {
								string mintype_sub_dir = min_sub_dir + '/' + getSpoolTypeDir((eTypeSpoolFile)typeSpoolFile);
								string mintype_dir = getSpoolDir_string((eTypeSpoolFile)typeSpoolFile) + '/' + mintype_sub_dir;
								if(file_exists(mintype_dir)) {
									if(row ?
									    !atoi(row[string(getSpoolTypeFilesIndex((eTypeSpoolFile)typeSpoolFile, false)) + "size"].c_str()) :
									    (unsigned int)numberOfDayToNow > maxDays[(int)typeSpoolFile]) {
										rmdir_r(mintype_dir);
										syslog(LOG_NOTICE, "cleanspool[%i]: clean obsolete dir %s", spoolIndex, mintype_dir.c_str());
										removeMinTypeDir = true;
									} else {
										keepMainMinTypeFolder = true;
									}
								}
							}
							if(!keepMainMinTypeFolder) {
								for(int typeSpoolFile = tsf_sip; typeSpoolFile < tsf_all; ++typeSpoolFile) {
									string mintype_sub_dir = min_sub_dir + '/' + getSpoolTypeDir((eTypeSpoolFile)typeSpoolFile);
									string mintype_dir = getSpoolDir_string((eTypeSpoolFile)typeSpoolFile) + '/' + mintype_sub_dir;
									if(file_exists(mintype_dir)) {
										rmdir_r(mintype_dir);
										syslog(LOG_NOTICE, "cleanspool[%i]: clean obsolete dir %s", spoolIndex, mintype_dir.c_str());
										removeMinTypeDir = true;
									}
								}
							}
							if(removeMinTypeDir) {
								removeMinDir = true;
								for(list<string>::iterator iter_sd = spool_dirs.begin(); iter_sd != spool_dirs.end(); iter_sd++) {
									string remove_dir = *iter_sd + '/' + min_sub_dir;
									if(file_exists(remove_dir)) {
										if(rmdir(remove_dir.c_str()) == 0) {
											syslog(LOG_NOTICE, "cleanspool[%i]: clean obsolete dir %s", spoolIndex, remove_dir.c_str());
										} else {
											removeMinDir = false;
										}
									}
								}
							}
						}
					}
					if(removeMinDir) {
						removeHourDir = true;
						for(list<string>::iterator iter_sd = spool_dirs.begin(); iter_sd != spool_dirs.end(); iter_sd++) {
							string remove_dir = *iter_sd + '/' + hour_sub_dir;
							if(file_exists(remove_dir)) {
								if(rmdir(remove_dir.c_str()) == 0) {
									syslog(LOG_NOTICE, "cleanspool[%i]: clean obsolete dir %s", spoolIndex, remove_dir.c_str());
								} else {
									removeHourDir = false;
								}
							}
						}
					}
				}
			}
			if(removeHourDir) {
				for(list<string>::iterator iter_sd = spool_dirs.begin(); iter_sd != spool_dirs.end(); iter_sd++) {
					string remove_dir = *iter_sd + '/' + day_sub_dir;
					if(file_exists(remove_dir)) {
						if(rmdir(remove_dir.c_str()) == 0) {
							syslog(LOG_NOTICE, "cleanspool[%i]: clean obsolete dir %s", spoolIndex, remove_dir.c_str());
						}
					}
				}
			}
		}
	}
}

void CleanSpool::test_load(string type) {
	if(type == "all" || type == "all-refresh-cache") {
		cout << "reloadSpoolDataDir without load cache" <<  endl;
		unsigned long start = getTimeMS();
		reloadSpoolDataDir(false, type == "all-refresh-cache");
		if(is_terminating()) {
			return;
		}
		unsigned long end = getTimeMS();
		cout << (end - start) / 1000. << "s" << endl;
		cout << spoolData.getSumSize() << endl;
		cout << printSumSizeByDate();
		//
		cout << "reloadSpoolDataDir with load cache" <<  endl;
		start = getTimeMS();
		reloadSpoolDataDir(true, type == "all-refresh-cache");
		if(is_terminating()) {
			return;
		}
		end = getTimeMS();
		cout << (end - start) / 1000. << "s" << endl;
		cout << spoolData.getSumSize() << endl;
		cout << printSumSizeByDate();
		//
		cout << "updateSpoolDataDir" <<  endl;
		start = getTimeMS();
		updateSpoolDataDir();
		if(is_terminating()) {
			return;
		}
		end = getTimeMS();
		cout << (end - start) / 1000. << "s" << endl;
		cout << spoolData.getSumSize() << endl;
		cout << printSumSizeByDate();
	} else if(type == "cache" || type == "no-cache" || type == "refresh-cache") {
		unsigned long start = getTimeMS();
		reloadSpoolDataDir(type == "cache", type == "refresh-cache");
		if(is_terminating()) {
			return;
		}
		unsigned long end = getTimeMS();
		cout << (end - start) / 1000. << "s" << endl;
		cout << spoolData.getSumSize() << endl;
		cout << printSumSizeByDate();
	}
}

void CleanSpool::check_spooldir_filesindex(const char *dirfilter) {
	if(!opt_cleanspool_use_files) {
		return;
	}
	list<string> spool_dirs;
	this->getSpoolDirs(&spool_dirs);
	list<string> date_dirs;
	this->readSpoolDateDirs(&date_dirs);
	if(!date_dirs.size()) {
		return;
	}
	if(!sqlDb) {
		sqlDb = createSqlObject();
	}
	for(list<string>::iterator iter_date_dir = date_dirs.begin(); iter_date_dir != date_dirs.end() && !is_terminating() && !DISABLE_CLEANSPOOL; iter_date_dir++) {
		string dateDir = *iter_date_dir;
		if((!dirfilter || strstr(dateDir.c_str(), dirfilter))) {
			syslog(LOG_NOTICE, "cleanspool[%i]: check files in %s", spoolIndex, dateDir.c_str());
			for(int h = 0; h < 24; h++) {
				long long sumSizeMissingFilesInIndex[2] = {0, 0};
				char hour[8];
				snprintf(hour, sizeof(hour), "%02d", h);
				syslog(LOG_NOTICE, "cleanspool[%i]: - hour %s", spoolIndex, hour);
				string ymd = dateDir;
				string ymdh = string(ymd.substr(0,4)) + ymd.substr(5,2) + ymd.substr(8,2) + hour;
				long long sumSize[2][10];
				for(int typeSpoolFile = tsf_sip; typeSpoolFile < tsf_all; ++typeSpoolFile) {
					vector<string> filesInIndex;
					sumSize[0][(int)typeSpoolFile] = 0;
					sumSize[1][(int)typeSpoolFile] = 0;
					if(getSpoolTypeFilesIndex((eTypeSpoolFile)typeSpoolFile, false)) {
						FILE *fd = fopen((getSpoolDir_string(tsf_main) + "/filesindex/" + getSpoolTypeFilesIndex((eTypeSpoolFile)typeSpoolFile, false) + "size/" + ymdh).c_str(), "r");
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
								string file = buf;
								filesInIndex.push_back(file);
								long long unsigned size = posSizeSeparator ? atoll(posSizeSeparator + 1) : 0;
								eTypeSpoolFile rsltTypeSpoolFile;
								long long unsigned fileSize = GetFileSizeDU(this->findExistsSpoolDirFile((eTypeSpoolFile)typeSpoolFile, file, &rsltTypeSpoolFile), rsltTypeSpoolFile, spoolIndex);
								if(fileSize == 0) {
									fileSize = 1;
								}
								sumSize[0][(int)typeSpoolFile] += size;
								sumSize[1][(int)typeSpoolFile] += fileSize;
								if(fileSize == (long long unsigned)-1) {
									syslog(LOG_NOTICE, "cleanspool[%i]: ERROR - missing file from index %s", spoolIndex, file.c_str());
								} else {
									if(size != fileSize) {
										syslog(LOG_NOTICE, "cleanspool[%i]: ERROR - diff file size [%s - %llu i / %llu r]", spoolIndex, file.c_str(), size, fileSize);
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
						snprintf(min, sizeof(min), "%02d", m);
						string timetypedir = dateDir + '/' + hour + '/' + min + '/' + getSpoolTypeDir((eTypeSpoolFile)typeSpoolFile);
						string dir = this->findExistsSpoolDirFile((eTypeSpoolFile)typeSpoolFile, timetypedir).c_str();
						DIR* dp = opendir(dir.c_str());
						if(!dp) {
							continue;
						}
						dirent* de2;
						while((de2 = readdir(dp)) != NULL) {
							if(!is_dir(de2, dir.c_str()) && string(de2->d_name) != ".." && string(de2->d_name) != ".") {
								filesInFolder.push_back(timetypedir + '/' + de2->d_name);
							}
						}
						closedir(dp);
					}
					for(uint j = 0; j < filesInFolder.size(); j++) {
						if(!std::binary_search(filesInIndex.begin(), filesInIndex.end(), filesInFolder[j])) {
							long long size = GetFileSize(getSpoolDir_string((eTypeSpoolFile)typeSpoolFile) + '/' + filesInFolder[j]);
							long long sizeDU = GetFileSizeDU(getSpoolDir_string((eTypeSpoolFile)typeSpoolFile) + '/' + filesInFolder[j], (eTypeSpoolFile)typeSpoolFile, spoolIndex);
							sumSizeMissingFilesInIndex[0] += size;
							sumSizeMissingFilesInIndex[1] += sizeDU;
							syslog(LOG_NOTICE, "cleanspool[%i]: ERROR - %s %s - %llu / %llu",
							       spoolIndex,
							       "missing file in index", 
							       filesInFolder[j].c_str(),
							       size,
							       sizeDU);
						}
					}
				}
				if(sumSize[0][(int)tsf_sip] || sumSize[0][(int)tsf_reg] || sumSize[0][(int)tsf_skinny] || sumSize[0][(int)tsf_mgcp] || sumSize[0][(int)tsf_ss7] ||
				   sumSize[0][(int)tsf_rtp] || sumSize[0][(int)tsf_graph] || sumSize[0][(int)tsf_audio] ||
				   sumSize[1][(int)tsf_sip] || sumSize[1][(int)tsf_reg] || sumSize[1][(int)tsf_skinny] || sumSize[1][(int)tsf_mgcp] || sumSize[1][(int)tsf_ss7] ||
				   sumSize[1][(int)tsf_rtp] || sumSize[1][(int)tsf_graph] || sumSize[1][(int)tsf_audio]) {
					sqlDb->query(
					       "SELECT SUM(sipsize) AS sipsize,\
						       SUM(regsize) AS regsize,\
						       SUM(skinnysize) AS skinnysize,\
						       SUM(mgcpsize) AS mgcpsize,\
						       SUM(ss7size) AS ss7size,\
						       SUM(rtpsize) AS rtpsize,\
						       SUM(graphsize) AS graphsize,\
						       SUM(audiosize) AS audiosize,\
						       count(*) as cnt\
						FROM files\
						WHERE datehour like '" + dateDir.substr(0, 4) + 
									 dateDir.substr(5, 2) + 
									 dateDir.substr(8, 2) + hour + "%' and \
						      spool_index = " + getSpoolIndex_string() + " and \
						      id_sensor = " + getIdSensor_string());
					SqlDb_row rowSum = sqlDb->fetchRow();
					if(rowSum && atol(rowSum["cnt"].c_str()) > 0) {
						if(atoll(rowSum["sipsize"].c_str()) == sumSize[0][(int)tsf_sip] &&
						   atoll(rowSum["regsize"].c_str()) == sumSize[0][(int)tsf_reg] &&
						   atoll(rowSum["skinnysize"].c_str()) == sumSize[0][(int)tsf_skinny] &&
						   atoll(rowSum["mgcpsize"].c_str()) == sumSize[0][(int)tsf_mgcp] &&
						   atoll(rowSum["ss7size"].c_str()) == sumSize[0][(int)tsf_ss7] &&
						   atoll(rowSum["rtpsize"].c_str()) == sumSize[0][(int)tsf_rtp] &&
						   atoll(rowSum["graphsize"].c_str()) == sumSize[0][(int)tsf_graph] &&
						   atoll(rowSum["audiosize"].c_str()) == sumSize[0][(int)tsf_audio] &&
						   atoll(rowSum["sipsize"].c_str()) == sumSize[1][(int)tsf_sip] &&
						   atoll(rowSum["regsize"].c_str()) == sumSize[1][(int)tsf_reg] &&
						   atoll(rowSum["skinnysize"].c_str()) == sumSize[1][(int)tsf_skinny] &&
						   atoll(rowSum["mgcpsize"].c_str()) == sumSize[1][(int)tsf_mgcp] &&
						   atoll(rowSum["ss7size"].c_str()) == sumSize[1][(int)tsf_ss7] &&
						   atoll(rowSum["rtpsize"].c_str()) == sumSize[1][(int)tsf_rtp] &&
						   atoll(rowSum["graphsize"].c_str()) == sumSize[1][(int)tsf_graph] &&
						   atoll(rowSum["audiosize"].c_str()) == sumSize[1][(int)tsf_audio]) {
							syslog(LOG_NOTICE, "cleanspool[%i]: # OK sum in files by index", spoolIndex);
						} else {
							if(atoll(rowSum["sipsize"].c_str()) != sumSize[0][(int)tsf_sip]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum sipsize in files [ %llu ii / %llu f ]", spoolIndex, sumSize[0][(int)tsf_sip], atoll(rowSum["sipsize"].c_str()));
							}
							if(atoll(rowSum["sipsize"].c_str()) != sumSize[1][(int)tsf_sip]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum sipsize in files [ %llu ri / %llu f ]", spoolIndex, sumSize[1][(int)tsf_sip], atoll(rowSum["sipsize"].c_str()));
							}
							if(atoll(rowSum["regsize"].c_str()) != sumSize[0][(int)tsf_reg]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum regsize in files [ %llu ii / %llu f ]", spoolIndex, sumSize[0][(int)tsf_reg], atoll(rowSum["regsize"].c_str()));
							}
							if(atoll(rowSum["skinnysize"].c_str()) != sumSize[1][(int)tsf_skinny]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum skinnysize in files [ %llu ri / %llu f ]", spoolIndex, sumSize[1][(int)tsf_skinny], atoll(rowSum["skinnysize"].c_str()));
							}
							if(atoll(rowSum["mgcpsize"].c_str()) != sumSize[1][(int)tsf_mgcp]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum mgcpsize in files [ %llu ri / %llu f ]", spoolIndex, sumSize[1][(int)tsf_mgcp], atoll(rowSum["mgcpsize"].c_str()));
							}
							if(atoll(rowSum["ss7size"].c_str()) != sumSize[1][(int)tsf_ss7]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum ss7size in files [ %llu ri / %llu f ]", spoolIndex, sumSize[1][(int)tsf_ss7], atoll(rowSum["ss7size"].c_str()));
							}
							if(atoll(rowSum["rtpsize"].c_str()) != sumSize[0][(int)tsf_rtp]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum rtpsize in files [ %llu ii / %llu f ]", spoolIndex, sumSize[0][(int)tsf_rtp], atoll(rowSum["rtpsize"].c_str()));
							}
							if(atoll(rowSum["rtpsize"].c_str()) != sumSize[1][(int)tsf_rtp]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum rtpsize in files [ %llu ri / %llu f ]", spoolIndex, sumSize[1][(int)tsf_rtp], atoll(rowSum["rtpsize"].c_str()));
							}
							if(atoll(rowSum["graphsize"].c_str()) != sumSize[0][(int)tsf_graph]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum graphsize in files [ %llu ii / %llu f ]", spoolIndex, sumSize[0][(int)tsf_graph], atoll(rowSum["graphsize"].c_str()));
							}
							if(atoll(rowSum["graphsize"].c_str()) != sumSize[1][(int)tsf_graph]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum graphsize in files [ %llu ri / %llu f ]", spoolIndex, sumSize[1][(int)tsf_graph], atoll(rowSum["graphsize"].c_str()));
							}
							if(atoll(rowSum["audiosize"].c_str()) != sumSize[0][(int)tsf_audio]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum audiosize in files [ %llu ii / %llu f ]", spoolIndex, sumSize[0][(int)tsf_audio], atoll(rowSum["audiosize"].c_str()));
							}
							if(atoll(rowSum["audiosize"].c_str()) != sumSize[1][(int)tsf_audio]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum audiosize in files [ %llu ri / %llu f ]", spoolIndex, sumSize[1][(int)tsf_audio], atoll(rowSum["audiosize"].c_str()));
							}
						}
					} else {
						syslog(LOG_NOTICE, "cleanspool[%i]: # MISSING record in files", spoolIndex);
					}
				}
				
				if(sumSizeMissingFilesInIndex[0] || sumSizeMissingFilesInIndex[1]) {
					syslog(LOG_NOTICE, "cleanspool[%i]: sum size of missing file in index: %llu / %llu", spoolIndex, sumSizeMissingFilesInIndex[0], sumSizeMissingFilesInIndex[1]);
				}
			}
		}
	}
}

void CleanSpool::force_reindex_spool() {
	force_reindex_spool_flag = true;
}

string CleanSpool::print_spool() {
	return(intToString(spoolData.getSumSize()) + "\r\n" + printSumSizeByDate());
}

unsigned int CleanSpool::get_reduk_maxpoolsize(unsigned int maxpoolsize) {
	unsigned int reduk_maxpoolsize = maxpoolsize_set ? maxpoolsize_set : 
					 maxpoolsize ? maxpoolsize : opt_max.maxpoolsize;
	if(opt_cleanspool_use_files) {
		extern TarQueue *tarQueue[2];
		if(tarQueue[spoolIndex]) {
			unsigned int open_tars_size = tarQueue[spoolIndex]->sumSizeOpenTars() / (1204 * 1024);
			if(open_tars_size < reduk_maxpoolsize) {
				reduk_maxpoolsize -= open_tars_size;
			} else {
				return(0);
			}
		}
	}
	return(reduk_maxpoolsize);
}

bool CleanSpool::fileIsOpenTar(list<string> &listOpenTars, string &file) {
	list<string>::iterator iter;
	for(iter = listOpenTars.begin(); iter != listOpenTars.end(); iter++) {
		if(iter->find(file) != string::npos) {
			return(true);
		}
	}
	return(false);
}

void CleanSpool::readSpoolDateDirs(list<string> *dirs) {
	dirs->clear();
	list<string> spool_dirs;
	this->getSpoolDirs(&spool_dirs);
	for(list<string>::iterator iter_sd = spool_dirs.begin(); iter_sd != spool_dirs.end(); iter_sd++) {
		DIR* dp = opendir((*iter_sd).c_str());
		if(dp) {
			dirent* de;
			while((de = readdir(dp)) != NULL) {
				if(de->d_name[0] == '2' && strlen(de->d_name) == 10) {
					bool exists = false;
					for(list<string>::iterator iter_dir = (*dirs).begin(); iter_dir != (*dirs).end(); iter_dir++) {
						if(de->d_name == *iter_dir) {
							exists = true;
							break;
						}
					}
					if(!exists) {
						dirs->push_back(de->d_name);
					}
				}
			}
			closedir(dp);
		}
	}
}

void CleanSpool::getSpoolDirs(list<string> *spool_dirs) {
	spool_dirs->clear();
	for(int typeSpoolFile = tsf_sip; typeSpoolFile < tsf_all; ++typeSpoolFile) {
		string spoolDir = getSpoolDir((eTypeSpoolFile)typeSpoolFile);
		bool exists = false;
		for(list<string>::iterator iter_sd = spool_dirs->begin(); iter_sd != spool_dirs->end(); iter_sd++) {
			if(spoolDir == *iter_sd) {
				exists = true;
				break;
			}
		}
		if(!exists) {
			spool_dirs->push_back(spoolDir);
		}
	}
}

string CleanSpool::findExistsSpoolDirFile(eTypeSpoolFile typeSpoolFile, string pathFile, eTypeSpoolFile *rsltTypeSpoolFile) {
	if(rsltTypeSpoolFile) {
		*rsltTypeSpoolFile = typeSpoolFile;
	}
	string spool_dir;
	for(int i = 0; i < 2; i++) {
		eTypeSpoolFile checkTypeSpoolFile = i == 0 ? typeSpoolFile : tsf_main;
		if(i == 1 && rsltTypeSpoolFile) {
			*rsltTypeSpoolFile = checkTypeSpoolFile;
		}
		spool_dir = getSpoolDir_string(checkTypeSpoolFile) + '/' + pathFile;
		if(i == 0 && file_exists(spool_dir)) {
			break;
		}
	}
	return(spool_dir);
}
