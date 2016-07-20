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
#include "tar.h"


using namespace std;


extern CleanSpool *cleanSpool[2];
extern MySqlStore *sqlStore;


#define DISABLE_CLEANSPOOL ((suspended && !critical_low_space) || do_convert_filesindex_flag)


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
}

CleanSpool::~CleanSpool() {
	if(sqlDb) {
		delete sqlDb;
	}
	termCleanThread();
}

void CleanSpool::addFile(const char *ymdh, const char *column, const char *file, long long int size) {
	sqlStore->lock(STORE_PROC_ID_CLEANSPOOL + spoolIndex);
	sqlStore->query( 
	       "INSERT INTO files \
		SET datehour = " + string(ymdh) + ", \
		    spool_index = " + getSpoolIndex_string() + ", \
		    id_sensor = " + getIdSensor_string() + ", \
		    " + column + " = " + intToString(size) + " \
		ON DUPLICATE KEY UPDATE \
		    " + column + " = " + column + " + " + intToString(size),
		STORE_PROC_ID_CLEANSPOOL + spoolIndex);
	string fname = getSpoolDir_string() + "/filesindex/" + column + '/' + ymdh;
	ofstream fname_stream(fname.c_str(), ios::app | ios::out);
	if(fname_stream.is_open()) {
		fname_stream << skipSpoolDir(spoolIndex, file) << ":" << size << "\n";
		fname_stream.close();
	} else {
		syslog(LOG_ERR, "error write to %s", fname.c_str());
	}
	sqlStore->unlock(STORE_PROC_ID_CLEANSPOOL + spoolIndex);
}

void CleanSpool::run() {
	runCleanThread();
}

void CleanSpool::do_convert_filesindex(const char *reason) {
	do_convert_filesindex_flag = true;
	do_convert_filesindex_reason = reason;
}

void CleanSpool::check_filesindex() {
	DIR* dp = opendir(getSpoolDir());
	if(!dp) {
		return;
	}
	SqlDb *sqlDb = createSqlObject();
	syslog(LOG_NOTICE, "cleanspool[%i]: check_filesindex start", spoolIndex);
	while(!is_terminating()) {
		dirent* de = readdir(dp);
		if(de == NULL) break;
		if(string(de->d_name) == ".." or string(de->d_name) == ".") continue;
		if(de->d_name[0] == '2' && strlen(de->d_name) == 10) {
			check_index_date(de->d_name, sqlDb);
		}
	}
	syslog(LOG_NOTICE, "cleanspool[%i]: check_filesindex done", spoolIndex);
	delete sqlDb;
	closedir(dp);
}

void CleanSpool::check_index_date(string date, SqlDb *sqlDb) {
	for(int h = 0; h < 24 && !is_terminating(); h++) {
		char hour[8];
		sprintf(hour, "%02d", h);
		string ymdh = string(date.substr(0,4)) + date.substr(5,2) + date.substr(8,2) + hour;
		map<string, long long> typeSize;
		reindex_date_hour(date, h, true, &typeSize, true);
		if(typeSize["sip"] || typeSize["rtp"] || typeSize["graph"] || typeSize["audio"]) {
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
				   (typeSize["rtp"] && !atoll(row["rtpsize"].c_str())) ||
				   (typeSize["graph"] && !atoll(row["graphsize"].c_str())) ||
				   (typeSize["audio"] && !atoll(row["audiosize"].c_str()))) {
					needReindex = true;
				}
			} else {
				needReindex = true;
			}
			if(!needReindex &&
			   ((typeSize["sip"] && !file_exists(getSpoolDir_string() + "/filesindex/sipsize/" + ymdh)) ||
			    (typeSize["rtp"] && !file_exists(getSpoolDir_string() + "/filesindex/rtpsize/" + ymdh)) ||
			    (typeSize["graph"] && !file_exists(getSpoolDir_string() + "/filesindex/graphsize/" + ymdh)) ||
			    (typeSize["audio"] && !file_exists(getSpoolDir_string() + "/filesindex/audiosize/" + ymdh)))) {
				needReindex = true;
			}
			if(needReindex) {
				reindex_date_hour(date, h);
			}
		}
	}
}

string CleanSpool::getMaxSpoolDate() {
	DIR* dp = opendir(getSpoolDir());
	if(!dp) {
		return("");
	}
	u_int32_t maxDate = 0;
	dirent* de;
	while((de = readdir(dp)) != NULL) {
		if(de == NULL) break;
		if(string(de->d_name) == ".." or string(de->d_name) == ".") continue;
		if(de->d_name[0] == '2' && strlen(de->d_name) == 10) {
			u_int32_t date = atol(de->d_name) * 10000 +
					 atol(de->d_name + 5) * 100 +
					 atol(de->d_name + 8);
			if(date > maxDate) {
				maxDate = date;
			}
		}
	}
	closedir(dp);
	if(maxDate) {
		char maxDate_str[20];
		sprintf(maxDate_str, "%4i-%02i-%02i", maxDate / 10000, maxDate % 10000 / 100, maxDate % 100);
		return(maxDate_str);
	} else {
		return("");
	}
}

void CleanSpool::run_cleanProcess(int spoolIndex) {
	for(int i = 0; i < 2; i++) {
		if((spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex) &&
		   cleanSpool[i]) {
			cleanSpool[i]->cleanThreadProcess();
		}
	}
}

void CleanSpool::run_reindex_all(const char *reason, int spoolIndex) {
	for(int i = 0; i < 2; i++) {
		if((spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex) &&
		   cleanSpool[i]) {
			cleanSpool[i]->reindex_all(reason);
		}
	}
}

void CleanSpool::run_reindex_date(string date, int spoolIndex) {
	for(int i = 0; i < 2; i++) {
		if((spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex) &&
		   cleanSpool[i]) {
			cleanSpool[i]->reindex_date(date);
		}
	}
}

void CleanSpool::run_reindex_date_hour(string date, int hour, int spoolIndex) {
	for(int i = 0; i < 2; i++) {
		if((spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex) &&
		   cleanSpool[i]) {
			cleanSpool[i]->reindex_date_hour(date, hour);
		}
	}
}

bool CleanSpool::suspend(int spoolIndex) {
	bool changeState = false;
	for(int i = 0; i < 2; i++) {
		if((spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex) &&
		   cleanSpool[i] && !cleanSpool[i]->suspended) {
			cleanSpool[i]->suspended = true;
			changeState = true;
		}
	}
	return(changeState);
}

bool CleanSpool::resume(int spoolIndex) {
	bool changeState = false;
	for(int i = 0; i < 2; i++) {
		if((spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex) &&
		   cleanSpool[i] && cleanSpool[i]->suspended) {
			cleanSpool[i]->suspended = false;
			changeState = true;
		}
	}
	return(changeState);
}

void CleanSpool::run_check_filesindex(int spoolIndex) {
	for(int i = 0; i < 2; i++) {
		if((spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex) &&
		   cleanSpool[i]) {
			cleanSpool[i]->check_filesindex();
		}
	}
}

void CleanSpool::run_check_spooldir_filesindex(const char *dirfilter, int spoolIndex) {
	for(int i = 0; i < 2; i++) {
		if((spoolIndex == -1 || spoolIndex == cleanSpool[i]->spoolIndex) &&
		   cleanSpool[i]) {
			cleanSpool[i]->check_spooldir_filesindex(dirfilter);
		}
	}
}

bool CleanSpool::isSetCleanspoolParameters(int spoolIndex) {
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
	return((spoolIndex == 0 ?
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
	       opt_autocleanmingb);
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

void CleanSpool::loadOpt() {
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
		for(int i = 0; i < 300 && !is_terminating() && !do_convert_filesindex_flag; i++) {
			sleep(1);
		}
	}
}

void CleanSpool::cleanThreadProcess() {
	if(do_convert_filesindex_flag ||
	   !check_exists_act_records_in_files() ||
	   !check_exists_act_files_in_filesindex()) {
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
	if(opt_other.autocleanspoolminpercent || opt_other.autocleanmingb) {
		double totalSpaceGB = (double)GetTotalDiskSpace(getSpoolDir()) / (1024 * 1024 * 1024);
		double freeSpacePercent = (double)GetFreeDiskSpace(getSpoolDir(), true) / 100;
		double freeSpaceGB = (double)GetFreeDiskSpace(getSpoolDir()) / (1024 * 1024 * 1024);
		int _minPercentForAutoReindex = 1;
		int _minGbForAutoReindex = 5;
		if(freeSpacePercent < _minPercentForAutoReindex && 
		   freeSpaceGB < _minGbForAutoReindex) {
			syslog(LOG_NOTICE, "cleanspool[%i]: low spool disk space - executing convert_filesindex", spoolIndex);
			reindex_all("call from clean_spooldir - low spool disk space");
			freeSpacePercent = (double)GetFreeDiskSpace(getSpoolDir(), true) / 100;
			freeSpaceGB = (double)GetFreeDiskSpace(getSpoolDir()) / (1024 * 1024 * 1024);
			criticalLowSpace = true;
		}
		if(freeSpacePercent < opt_other.autocleanspoolminpercent ||
		   freeSpaceGB < opt_other.autocleanmingb) {
			SqlDb *sqlDb = createSqlObject();
			sqlDb->query(
			       "SELECT SUM(coalesce(sipsize,0) + \
					   coalesce(rtpsize,0) + \
					   coalesce(graphsize,0) + \
					   coalesce(audiosize,0)) as sum_size \
				FROM files \
				WHERE spool_index = " + getSpoolIndex_string() + " and \
				      id_sensor = " + getIdSensor_string());
			SqlDb_row row = sqlDb->fetchRow();
			if(row) {
				double usedSizeGB = atol(row["sum_size"].c_str()) / (1024 * 1024 * 1024);
				maxpoolsize = (usedSizeGB + freeSpaceGB - min(totalSpaceGB * opt_other.autocleanspoolminpercent / 100, (double)opt_other.autocleanmingb)) * 1024;
				if(maxpoolsize > 1000 &&
				   (!opt_max.maxpoolsize || maxpoolsize < opt_max.maxpoolsize)) {
					if(opt_max.maxpoolsize && maxpoolsize < opt_max.maxpoolsize * 0.8) {
						maxpoolsize = opt_max.maxpoolsize * 0.8;
					}
					syslog(LOG_NOTICE, "cleanspool[%i]: %s: %li MB", 
					       spoolIndex,
					       opt_max.maxpoolsize ?
						"low spool disk space - maxpoolsize set to new value" :
						"maxpoolsize set to value",
					       maxpoolsize);
				} else {
					syslog(LOG_ERR, "cleanspool[%i]: incorrect set autocleanspoolminpercent and autocleanspoolmingb", spoolIndex);
					maxpoolsize = 0;
				}
			}
			delete sqlDb;
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
	sqlDb->query("select max(calldate) as max_calldate from cdr where calldate > date_add(now(), interval -1 day)");
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
	sqlDb->query("select max(calldate) as max_calldate from cdr where calldate > date_add(now(), interval -1 day)");
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
			strcpy(datehour, date);
			sprintf(datehour + strlen(datehour), "%02i", j);
			if(FileExists((char*)(getSpoolDir_string() + "/filesindex/sipsize/" + datehour).c_str())) {
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
	u_long actTime = getTimeS();
	if(actTime - lastCall_reindex_all < 5 * 60) {
		syslog(LOG_NOTICE,"cleanspool[%i]: suppress run reindex_all - last run before %lus", spoolIndex, actTime - lastCall_reindex_all);
		return;
	}
	lastCall_reindex_all = actTime;
 
	DIR* dp = opendir(getSpoolDir());
	if(!dp) {
		return;
	}
	syslog(LOG_NOTICE, "cleanspool[%i]: reindex_all start%s%s", spoolIndex, reason ? " - " : "", reason ? reason : "");
	sqlStore->query_lock(
	       "DELETE FROM files \
		WHERE spool_index = " + getSpoolIndex_string() + " and \
		      id_sensor = " + getIdSensor_string(),
		STORE_PROC_ID_CLEANSPOOL_SERVICE + spoolIndex);
	rmdir_r(getSpoolDir_string() + "/filesindex", true, true);
	mkdir_r(getSpoolDir_string() + "/filesindex/sipsize", 0777);
	mkdir_r(getSpoolDir_string() + "/filesindex/rtpsize", 0777);
	mkdir_r(getSpoolDir_string() + "/filesindex/graphsize", 0777);
	mkdir_r(getSpoolDir_string() + "/filesindex/audiosize", 0777);
	while(!is_terminating()) {
		dirent *de = readdir(dp);
		if(de == NULL) break;
		if(string(de->d_name) == ".." or string(de->d_name) == ".") continue;
		if(de->d_name[0] == '2' && strlen(de->d_name) == 10) {
			reindex_date(de->d_name);
		}
	}
	syslog(LOG_NOTICE, "cleanspool[%i]: reindex_all done", spoolIndex);
	closedir(dp);
	// wait for flush sql store
	while(sqlStore->getSize(STORE_PROC_ID_CLEANSPOOL_SERVICE + spoolIndex) > 0) {
		usleep(100000);
	}
	sleep(1);
}

long long CleanSpool::reindex_date(string date) {
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
	char hour[3];
	snprintf(hour, 3, "%02d", h);
	if(typeSize) {
		(*typeSize)["sip"] = 0;
		(*typeSize)["rtp"] = 0;
		(*typeSize)["graph"] = 0;
		(*typeSize)["audio"] = 0;
	}
	map<unsigned, bool> fillMinutes;
	long long sipsize = reindex_date_hour_type(date, h, "sip", readOnly, quickCheck, &fillMinutes);
	long long rtpsize = reindex_date_hour_type(date, h, "rtp", readOnly, quickCheck, &fillMinutes);
	long long graphsize = reindex_date_hour_type(date, h, "graph", readOnly, quickCheck, &fillMinutes);
	long long audiosize = reindex_date_hour_type(date, h, "audio", readOnly, quickCheck, &fillMinutes);
	if((sipsize + rtpsize + graphsize + audiosize) && !readOnly) {
		string dh = date + '/' + hour;
		syslog(LOG_NOTICE, "cleanspool[%i]: reindex_date_hour - %s/%s", spoolIndex, getSpoolDir(), dh.c_str());
	}
	if(!readOnly) {
		for(unsigned m = 0; m < 60; m++) {
			char min[3];
			snprintf(min, 3, "%02d", m);
			string dhm = date + '/' + hour + '/' + min;
			if(!fillMinutes[m]) {
				rmdir_r(dhm);
			} else {
				// remove obsolete directories
				rmdir_r(dhm + "/ALL");
				rmdir_r(dhm + "/REG");
			}
		}
		string ymdh = string(date.substr(0,4)) + date.substr(5,2) + date.substr(8,2) + hour;
		if(sipsize + rtpsize + graphsize + audiosize) {
			sqlStore->query_lock(
			       "INSERT INTO files \
				SET datehour = " + ymdh + ", \
				    spool_index = " + getSpoolIndex_string() + ", \
				    id_sensor = " + getIdSensor_string() + ", \
				    sipsize = " + intToString(sipsize) + ", \
				    rtpsize = " + intToString(rtpsize) + ", \
				    graphsize = " + intToString(graphsize) + ", \
				    audiosize = " + intToString(audiosize) + " \
				ON DUPLICATE KEY UPDATE \
				    sipsize = sipsize + " + intToString(sipsize) + ", \
				    rtpsize = rtpsize + " + intToString(rtpsize) + ", \
				    graphsize = graphsize + " + intToString(graphsize) + ", \
				    audiosize = audiosize + " + intToString(audiosize),
				STORE_PROC_ID_CLEANSPOOL_SERVICE + spoolIndex);
		} else {
			sqlStore->query_lock(
			       "DELETE FROM files \
				WHERE datehour = " + ymdh + " and \
				      spool_index = " + getSpoolIndex_string() + " and \
				      id_sensor = " + getIdSensor_string(),
				STORE_PROC_ID_CLEANSPOOL_SERVICE + spoolIndex);
			rmdir_r(getSpoolDir_string() + '/' + date + '/' + hour);
		}
	}
	if(typeSize) {
		(*typeSize)["sip"] = sipsize;
		(*typeSize)["rtp"] = rtpsize;
		(*typeSize)["graph"] = graphsize;
		(*typeSize)["audio"] = audiosize;
	}
	return(sipsize + rtpsize + graphsize + audiosize);
}

long long CleanSpool::reindex_date_hour_type(string date, int h, string type, bool readOnly, bool quickCheck, map<unsigned, bool> *fillMinutes) {
	long long sumsize = 0;
	string filesIndexDirName;
	string spoolDirTypeName;
	if(type == "sip") {
		filesIndexDirName = "sipsize";
		spoolDirTypeName = "SIP";
	} else if(type == "rtp") {
		filesIndexDirName = "rtpsize";
		spoolDirTypeName = "RTP";
	} else if(type == "graph") {
		filesIndexDirName = "graphsize";
		spoolDirTypeName = "GRAPH";
	} else if(type == "audio") {
		filesIndexDirName = "audiosize";
		spoolDirTypeName = "AUDIO";
	}
	char hour[3];
	snprintf(hour, 3, "%02d", h);
	string ymdh = string(date.substr(0,4)) + date.substr(5,2) + date.substr(8,2) + hour;
	string spool_fileindex = getSpoolDir_string() + "/filesindex/" + filesIndexDirName + '/' + ymdh;
	ofstream *spool_fileindex_stream = NULL;
	if(!readOnly) {
		spool_fileindex_stream = new FILE_LINE ofstream(spool_fileindex.c_str(), ios::trunc | ios::out);
	}
	extern TarQueue *tarQueue[2];
	list<string> listOpenTars;
	if(tarQueue[spoolIndex]) {
		listOpenTars = tarQueue[spoolIndex]->listOpenTars();
	}
	for(unsigned m = 0; m < 60; m++) {
		char min[3];
		snprintf(min, 3, "%02d", m);
		string dhmt = date + '/' + hour + '/' + min + '/' + spoolDirTypeName;
		string spool_dhmt = getSpoolDir_string() + '/' + dhmt;
		if(file_exists(spool_dhmt.c_str())) {
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
						long long size = GetFileSizeDU(spool_dhmt_file);
						if(size == 0) size = 1;
						sumsize += size;
						if(!readOnly) {
							(*spool_fileindex_stream) << dhmt_file << ":" << size << "\n";
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
				rmdir_r(spool_dhmt.c_str());
			}
		}
	}
	if(!readOnly) {
		spool_fileindex_stream->close();
		delete spool_fileindex_stream;
		if(!sumsize) {
			unlink(spool_fileindex.c_str());
		}
	}
	return(sumsize);
}

void CleanSpool::unlinkfileslist(string fname, string callFrom) {
	if(DISABLE_CLEANSPOOL) {
		return;
	}
	syslog(LOG_NOTICE, "cleanspool[%i]: call unlinkfileslist(%s) from %s", spoolIndex, fname.c_str(), callFrom.c_str());
	char buf[4092];
	FILE *fd = fopen((getSpoolDir_string() + '/' + fname).c_str(), "r");
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
			unlink((getSpoolDir_string() + '/' + buf).c_str());
			if(DISABLE_CLEANSPOOL) {
				fclose(fd);
				return;
			}
		}
		fclose(fd);
		unlink((getSpoolDir_string() + '/' + fname).c_str());
	}
}

void CleanSpool::unlink_dirs(string datehour, int sip, int rtp, int graph, int audio, string callFrom) {
	if(DISABLE_CLEANSPOOL || !check_datehour(datehour.c_str())) {
		return;
	}
	syslog(LOG_NOTICE, "cleanspool[%i]: call unlink_dirs(%s,%s,%s,%s,%s) from %s", 
	       spoolIndex,
	       datehour.c_str(), 
	       sip == 2 ? "SIP" : sip == 1 ? "sip" : "---",
	       rtp == 2 ? "RTP" : rtp == 1 ? "rtp" : "---",
	       graph == 2 ? "GRAPH" : graph == 1 ? "graph" : "---",
	       audio == 2 ? "AUDIO" : audio == 1 ? "audio" : "---",
	       callFrom.c_str());
	string d = datehour.substr(0,4) + "-" + datehour.substr(4,2) + "-" + datehour.substr(6,2);
	string dh =  d + '/' + datehour.substr(8,2);
	for(unsigned m = 0; m < 60 && !DISABLE_CLEANSPOOL; m++) {
		char min[3];
		snprintf(min, 3, "%02d", m);
		string dhm = dh + '/' + min;
		if(sip) {
			rmdir_if_r(getSpoolDir_string() + '/' + dhm + "/SIP",
				   sip == 2);
		}
		if(rtp) {
			rmdir_if_r(getSpoolDir_string() + '/' + dhm + "/RTP",
				   rtp == 2);
		}
		if(graph) {
			rmdir_if_r(getSpoolDir_string() + '/' + dhm + "/GRAPH",
				   graph == 2);
		}
		if(audio) {
			rmdir_if_r(getSpoolDir_string() + '/' + dhm + "/AUDIO",
				   audio == 2);
		}
		// remove minute
		if(rmdir((getSpoolDir_string() + '/' + dhm).c_str()) == 0) {
			syslog(LOG_NOTICE, "cleanspool[%i]: unlink_dirs: remove %s/%s", spoolIndex, getSpoolDir(), dhm.c_str());
		}
	}
	// remove hour
	if(rmdir((getSpoolDir_string() + '/' + dh).c_str()) == 0) {
		syslog(LOG_NOTICE, "cleanspool[%i]: unlink_dirs: remove %s/%s", spoolIndex, getSpoolDir(), dh.c_str());
	}
	// remove day
	if(rmdir((getSpoolDir_string() + '/' + d).c_str()) == 0) {
		syslog(LOG_NOTICE, "cleanspool[%i]: unlink_dirs: remove %s/%s", spoolIndex, getSpoolDir(), d.c_str());
	}
}

void CleanSpool::clean_spooldir_run() {
	if(opt_other.cleanspool_interval && opt_other.cleanspool_sizeMB > 0) {
		opt_max.maxpoolsize = opt_other.cleanspool_sizeMB;
		// if old cleanspool interval is defined convert the config to new config 
		extern char configfile[1024];
		if(FileExists(configfile)) {
			syslog(LOG_NOTICE, "cleanspool[%i]: converting [%s] cleanspool_interval and cleanspool_size to maxpoolsize", spoolIndex, configfile);
			reindex_all("convert configuration");
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

	clean_maxpoolsize_all();
	clean_maxpooldays_all();

	clean_maxpoolsize_sip();
	clean_maxpooldays_sip();

	clean_maxpoolsize_rtp();
	clean_maxpooldays_rtp();

	clean_maxpoolsize_graph();
	clean_maxpooldays_graph();

	clean_maxpoolsize_audio();
	clean_maxpooldays_audio();
	
	if(opt_other.maxpool_clean_obsolete) {
		clean_obsolete_dirs();
	}
	
	clean_spooldir_run_processing = 0;
}

void CleanSpool::clean_maxpoolsize(bool sip, bool rtp, bool graph, bool audio) {
	unsigned int maxpoolsize = sip && rtp && graph && audio ?
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
	if(!sqlDb) {
		sqlDb = createSqlObject();
	}
	while(true) {
		sqlDb->query(
		       "SELECT SUM(sipsize) AS sipsize, \
			       SUM(rtpsize) AS rtpsize, \
			       SUM(graphsize) as graphsize, \
			       SUM(audiosize) AS audiosize \
			FROM files \
			WHERE spool_index = " + getSpoolIndex_string() + " and \
			      id_sensor = " + getIdSensor_string());
		SqlDb_row row = sqlDb->fetchRow();
		uint64_t sipsize_total = strtoull(row["sipsize"].c_str(), NULL, 0);
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
			sizeCond = sip ? "sipsize > 0" :
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
		uint64_t sipsize = strtoull(row["sipsize"].c_str(), NULL, 0);
		uint64_t rtpsize = strtoull(row["rtpsize"].c_str(), NULL, 0);
		uint64_t graphsize = strtoull(row["graphsize"].c_str(), NULL, 0);
		uint64_t audiosize = strtoull(row["audiosize"].c_str(), NULL, 0);
		if(sip) {
			unlinkfileslist("filesindex/sipsize/" + row["datehour"], "clean_maxpoolsize");
			if(DISABLE_CLEANSPOOL) {
				break;
			}
		}
		if(rtp) {
			unlinkfileslist("filesindex/rtpsize/" + row["datehour"], "clean_maxpoolsize");
			if(DISABLE_CLEANSPOOL) {
				break;
			}
		}
		if(graph) {
			unlinkfileslist("filesindex/graphsize/" + row["datehour"], "clean_maxpoolsize");
			if(DISABLE_CLEANSPOOL) {
				break;
			}
		}
		if(audio) {
			unlinkfileslist("filesindex/audiosize/" + row["datehour"], "clean_maxpoolsize");
			if(DISABLE_CLEANSPOOL) {
				break;
			}
		}
		if(sip && rtp && graph && audio) {
			unlink_dirs(row["datehour"], 2, 2, 2, 2, "clean_maxpoolsize");
		} else {
			unlink_dirs(row["datehour"],
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
			string columnSetNul = sip ? "sipsize" :
					      rtp ? "rtpsize" :
					      graph ? "graphsize" : "audiosize";
			sqlDb->query(
			       "UPDATE files \
				SET " + columnSetNul + " = 0 \
				WHERE datehour = " + row["datehour"] + " and \
				      spool_index = " + getSpoolIndex_string() + " and \
				      id_sensor = " + getIdSensor_string());
		}
	}
}

void CleanSpool::clean_maxpooldays(bool sip, bool rtp, bool graph, bool audio) {
	unsigned int maxpooldays = sip && rtp && graph && audio ?
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
	while(true) {
		string sizeCond;
		if(!(sip && rtp && graph && audio)) {
			sizeCond = sip ? "sipsize > 0" :
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
		uint64_t sipsize = strtoull(row["sipsize"].c_str(), NULL, 0);
		uint64_t rtpsize = strtoull(row["rtpsize"].c_str(), NULL, 0);
		uint64_t graphsize = strtoull(row["graphsize"].c_str(), NULL, 0);
		uint64_t audiosize = strtoull(row["audiosize"].c_str(), NULL, 0);
		if(sip) {
			unlinkfileslist("filesindex/sipsize/" + row["datehour"], "clean_maxpooldays");
			if(DISABLE_CLEANSPOOL) {
				break;
			}
		}
		if(rtp) {
			unlinkfileslist("filesindex/rtpsize/" + row["datehour"], "clean_maxpooldays");
			if(DISABLE_CLEANSPOOL) {
				break;
			}
		}
		if(graph) {
			unlinkfileslist("filesindex/graphsize/" + row["datehour"], "clean_maxpooldays");
			if(DISABLE_CLEANSPOOL) {
				break;
			}
		}
		if(audio) {
			unlinkfileslist("filesindex/audiosize/" + row["datehour"], "clean_maxpooldays");
			if(DISABLE_CLEANSPOOL) {
				break;
			}
		}
		if(sip && rtp && graph && audio) {
			unlink_dirs(row["datehour"], 2, 2, 2, 2, "clean_maxpooldays");
		} else {
			unlink_dirs(row["datehour"],
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
			string columnSetNul = sip ? "sipsize" :
					      rtp ? "rtpsize" :
					      graph ? "graphsize" : "audiosize";
			sqlDb->query(
			       "UPDATE files \
				SET " + columnSetNul + " = 0 \
				WHERE datehour = " + row["datehour"] + " and \
				      spool_index = " + getSpoolIndex_string() + " and \
				      id_sensor = " + getIdSensor_string());
		}
	}
}

void CleanSpool::clean_obsolete_dirs() {
	const char *typeFilesIndex[] = {
		"sip",
		"rtp",
		"graph",
		"audio"
	};
	unsigned int maxDays[] = {
		opt_max.maxpoolsipdays,
		opt_max.maxpoolrtpdays,
		opt_max.maxpoolgraphdays,
		opt_max.maxpoolaudiodays
	};
	for(unsigned int i = 0; i < sizeof(maxDays) / sizeof(maxDays[0]); i++) {
		if(!maxDays[i]) {
			maxDays[i] = opt_max.maxpooldays ? opt_max.maxpooldays : 14;
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
	DIR* dp = opendir(getSpoolDir());
	if(!dp) {
		return;
	}
	if(!sqlDb) {
		sqlDb = createSqlObject();
	}
	while (true) {
		dirent *de = readdir(dp);
		if(de == NULL) break;
		if(string(de->d_name) == ".." or string(de->d_name) == ".") continue;
		if(de->d_name[0] == '2' && strlen(de->d_name) == 10) {
			int numberOfDayToNow = getNumberOfDayToNow(de->d_name);
			if(numberOfDayToNow > 0) {
				string daydir = getSpoolDir_string() + '/' + de->d_name;
				bool removeHourDir = false;
				for(int h = 0; h < 24; h++) {
					char hour[3];
					snprintf(hour, 3, "%02d", h);
					string hourdir = daydir + '/' + hour;
					if(file_exists((char*)hourdir.c_str())) {
						sqlDb->query(
						       "SELECT * \
							FROM files \
							where spool_index = " + getSpoolIndex_string() + " and \
							      id_sensor = " + getIdSensor_string() + " and \
							      datehour = '" + find_and_replace(de->d_name, "-", "") + hour + "'");
						SqlDb_row row = sqlDb->fetchRow();
						bool removeMinDir = false;
						for(int m = 0; m < 60; m++) {
							char min[3];
							snprintf(min, 3, "%02d", m);
							string mindir = hourdir + '/' + min;
							if(file_exists((char*)mindir.c_str())) {
								bool removeMinTypeDir = false;
								bool keepMainMinTypeFolder = false;
								for(uint i = 0; i < sizeof(typeFilesIndex) / sizeof(typeFilesIndex[0]); i++) {
									string mintypedir = mindir + '/' + typeFilesFolder[i];
									if(file_exists((char*)mintypedir.c_str())) {
										if(row ?
										    !atoi(row[string(typeFilesIndex[i]) + "size"].c_str()) :
										    (unsigned int)numberOfDayToNow > maxDays[i]) {
											rmdir_r(mintypedir.c_str());
											syslog(LOG_NOTICE, "cleanspool[%i]: clean obsolete dir %s", spoolIndex, mintypedir.c_str());
											removeMinTypeDir = true;
										} else {
											keepMainMinTypeFolder = true;
										}
									}
								}
								if(!keepMainMinTypeFolder) {
									for(uint i = sizeof(typeFilesIndex) / sizeof(typeFilesIndex[0]); i < sizeof(typeFilesFolder) / sizeof(typeFilesFolder[0]); i++) {
										string mintypedir = mindir + '/' + typeFilesFolder[i];
										if(file_exists((char*)mintypedir.c_str())) {
											rmdir_r(mintypedir.c_str());
											syslog(LOG_NOTICE, "cleanspool[%i]: clean obsolete dir %s", spoolIndex, mintypedir.c_str());
											removeMinTypeDir = true;
										}
									}
								}
								if(removeMinTypeDir) {
									if(rmdir(mindir.c_str()) == 0) {
										syslog(LOG_NOTICE, "cleanspool[%i]: clean obsolete dir %s", spoolIndex, mindir.c_str());
									}
									removeMinDir = true;
								}
							}
						}
						if(removeMinDir) {
							if(rmdir(hourdir.c_str()) == 0) {
								syslog(LOG_NOTICE, "cleanspool[%i]: clean obsolete dir %s", spoolIndex, hourdir.c_str());
							}
							removeHourDir = true;
						}
					}
				}
				if(removeHourDir) {
					if(rmdir(daydir.c_str()) == 0) {
						syslog(LOG_NOTICE, "cleanspool[%i]: clean obsolete dir %s", spoolIndex, daydir.c_str());
					}
				}
			}
		}
	}
	closedir(dp);
}

void CleanSpool::check_spooldir_filesindex(const char *dirfilter) {
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
	DIR* dp = opendir(getSpoolDir());
	if(!dp) {
		return;
	}
	if(!sqlDb) {
		sqlDb = createSqlObject();
	}
	while(true) {
		dirent *de = readdir(dp);
		if(de == NULL) break;
		if(string(de->d_name) == ".." or string(de->d_name) == ".") continue;
		
		if(de->d_name[0] == '2' && strlen(de->d_name) == 10 &&
		   (!dirfilter || strstr(de->d_name, dirfilter))) {
			//cycle through 24 hours
			syslog(LOG_NOTICE, "cleanspool[%i]: check files in %s", spoolIndex, de->d_name);
			for(int h = 0; h < 24; h++) {
				long long sumSizeMissingFilesInIndex[2] = {0, 0};
				char hour[8];
				sprintf(hour, "%02d", h);
				syslog(LOG_NOTICE, "cleanspool[%i]: - hour %s", spoolIndex, hour);
				string ymd = de->d_name;
				string ymdh = string(ymd.substr(0,4)) + ymd.substr(5,2) + ymd.substr(8,2) + hour;
				long long sumSize[2][sizeof(typeFilesIndex) / sizeof(typeFilesIndex[0])];
				for(uint i = 0; i < sizeof(typeFilesFolder) / sizeof(typeFilesFolder[0]); i++) {
					vector<string> filesInIndex;
				        if(i < sizeof(typeFilesIndex) / sizeof(typeFilesIndex[0])) {
						sumSize[0][i] = 0;
						sumSize[1][i] = 0;
						FILE *fd = fopen((getSpoolDir_string() + "/filesindex/" + typeFilesIndex[i] + "size/" + ymdh).c_str(), "r");
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
								long long unsigned fileSize = GetFileSizeDU((getSpoolDir_string() + '/' + buf).c_str());
								if(fileSize == 0) {
									fileSize = 1;
								}
								sumSize[0][i] += size;
								sumSize[1][i] += fileSize;
								if(fileSize == (long long unsigned)-1) {
									syslog(LOG_NOTICE, "cleanspool[%i]: ERROR - missing file from index %s", spoolIndex, buf);
								} else {
									if(size != fileSize) {
										syslog(LOG_NOTICE, "cleanspool[%i]: ERROR - diff file size [%s - %llu i / %llu r]", spoolIndex, buf, size, fileSize);
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
						string timetypedir = string(de->d_name) + '/' + hour + '/' + min + '/' + typeFilesFolder[i];
						DIR* dp = opendir((getSpoolDir_string() + '/' + timetypedir).c_str());
						if(!dp) {
							continue;
						}
						dirent* de2;
						while (true) {
							de2 = readdir( dp );
							if(de2 == NULL) break;
							if(de2->d_type == 4 or string(de2->d_name) == ".." or string(de2->d_name) == ".") continue;
							filesInFolder.push_back(timetypedir + '/' + de2->d_name);
						}
						closedir(dp);
					}
					for(uint j = 0; j < filesInFolder.size(); j++) {
						if(!std::binary_search(filesInIndex.begin(), filesInIndex.end(), filesInFolder[j])) {
							long long size = GetFileSize((getSpoolDir_string() + '/' + filesInFolder[j]).c_str());
							long long sizeDU = GetFileSizeDU((getSpoolDir_string() + '/' + filesInFolder[j]).c_str());
							sumSizeMissingFilesInIndex[0] += size;
							sumSizeMissingFilesInIndex[1] += sizeDU;
							syslog(LOG_NOTICE, "cleanspool[%i]: ERROR - %s %s - %llu / %llu",
							       spoolIndex,
							       i < sizeof(typeFilesIndex) / sizeof(typeFilesIndex[0]) ?
								"missing file in index" :
								"unknown file", 
							       filesInFolder[j].c_str(),
							       size,
							       sizeDU);
						}
					}
				}
				
				if(sumSize[0][0] || sumSize[0][1] || sumSize[0][2] || sumSize[0][3] ||
				   sumSize[1][0] || sumSize[1][1] || sumSize[1][2] || sumSize[1][3]) {
					sqlDb->query(
					       "SELECT SUM(sipsize) AS sipsize,\
						       SUM(rtpsize) AS rtpsize,\
						       SUM(graphsize) AS graphsize,\
						       SUM(audiosize) AS audiosize,\
						       count(*) as cnt\
						FROM files\
						WHERE datehour like '" + string(de->d_name).substr(0, 4) + 
									 string(de->d_name).substr(5, 2) + 
									 string(de->d_name).substr(8, 2) + hour + "%' and \
						      spool_index = " + getSpoolIndex_string() + " and \
						      id_sensor = " + getIdSensor_string());
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
							syslog(LOG_NOTICE, "cleanspool[%i]: # OK sum in files by index", spoolIndex);
						} else {
							if(atoll(rowSum["sipsize"].c_str()) != sumSize[0][0]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum sipsize in files [ %llu ii / %llu f ]", spoolIndex, sumSize[0][0], atoll(rowSum["sipsize"].c_str()));
							}
							if(atoll(rowSum["sipsize"].c_str()) != sumSize[1][0]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum sipsize in files [ %llu ri / %llu f ]", spoolIndex, sumSize[1][0], atoll(rowSum["sipsize"].c_str()));
							}
							if(atoll(rowSum["rtpsize"].c_str()) != sumSize[0][1]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum rtpsize in files [ %llu ii / %llu f ]", spoolIndex, sumSize[0][1], atoll(rowSum["rtpsize"].c_str()));
							}
							if(atoll(rowSum["rtpsize"].c_str()) != sumSize[1][1]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum rtpsize in files [ %llu ri / %llu f ]", spoolIndex, sumSize[1][1], atoll(rowSum["rtpsize"].c_str()));
							}
							if(atoll(rowSum["graphsize"].c_str()) != sumSize[0][2]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum graphsize in files [ %llu ii / %llu f ]", spoolIndex, sumSize[0][2], atoll(rowSum["graphsize"].c_str()));
							}
							if(atoll(rowSum["graphsize"].c_str()) != sumSize[1][2]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum graphsize in files [ %llu ri / %llu f ]", spoolIndex, sumSize[1][2], atoll(rowSum["graphsize"].c_str()));
							}
							if(atoll(rowSum["audiosize"].c_str()) != sumSize[0][3]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum audiosize in files [ %llu ii / %llu f ]", spoolIndex, sumSize[0][3], atoll(rowSum["audiosize"].c_str()));
							}
							if(atoll(rowSum["audiosize"].c_str()) != sumSize[1][3]) {
								syslog(LOG_NOTICE, "cleanspool[%i]: # ERROR sum audiosize in files [ %llu ri / %llu f ]", spoolIndex, sumSize[1][3], atoll(rowSum["audiosize"].c_str()));
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
	closedir(dp);
}

unsigned int CleanSpool::get_reduk_maxpoolsize(unsigned int maxpoolsize) {
	unsigned int reduk_maxpoolsize = maxpoolsize_set ? maxpoolsize_set : 
					 maxpoolsize ? maxpoolsize : opt_max.maxpoolsize;
	extern TarQueue *tarQueue[2];
	if(tarQueue[spoolIndex]) {
		unsigned int open_tars_size = tarQueue[spoolIndex]->sumSizeOpenTars() / (1204 * 1024);
		if(open_tars_size < reduk_maxpoolsize) {
			reduk_maxpoolsize -= open_tars_size;
		} else {
			return(0);
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


/*

// OK
void unlinkfileslist(string fname, string callFrom) {
	if(DISABLE_CLEANSPOOL) {
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
			if(DISABLE_CLEANSPOOL) {
				fclose(fd);
				return;
			}
		}
		fclose(fd);
		unlink(fname.c_str());
	}
	return;
}

// OK
void unlink_dirs(string datehour, int all, int sip, int rtp, int graph, int audio, int reg, string callFrom) {
	if(!check_datehour(datehour.c_str())) {
		return;
	}
 
	if(DISABLE_CLEANSPOOL) {
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

	for(int i = 0; i < 60 && !DISABLE_CLEANSPOOL; i++) {
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

// OK
unsigned int get_reduk_maxpoolsize() {
	unsigned int reduk_maxpoolsize = maxpoolsize_set ? maxpoolsize_set : opt_maxpoolsize;
	extern TarQueue *tarQueue[2];
	for(int i = 0; i < 2; i++) {
		if(tarQueue[i]) {
			unsigned int open_tars_size = tarQueue[i]->sumSizeOpenTars() / (1204 * 1024);
			if(open_tars_size < reduk_maxpoolsize) {
				reduk_maxpoolsize -= open_tars_size;
			} else {
				return(0);
			}
		}
	}
	return(reduk_maxpoolsize);
}

// OK
void clean_maxpoolsize() {

	if(opt_maxpoolsize == 0 && maxpoolsize_set == 0) {
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
	if(debugclean) {
		cout << q.str() << "\n";
		cout << "total[" << total << "] = " << sipsize << " + " << rtpsize << " + " << graphsize << " + " << audiosize << " + " << regsize 
		     << " opt_maxpoolsize[" << opt_maxpoolsize;
		if(maxpoolsize_set) {
			cout << " / reduk: " << maxpoolsize_set;
		}
		cout << "]\n";
	}
	unsigned int reduk_maxpoolsize;
	while((reduk_maxpoolsize = get_reduk_maxpoolsize()) > 0 &&
	      total > reduk_maxpoolsize) {
		// walk all rows ordered by datehour and delete everything 
		stringstream q;
		q << "SELECT datehour FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0) << " ORDER BY datehour LIMIT 1";
		sqlDbCleanspool->query(q.str());
		SqlDb_row row = sqlDbCleanspool->fetchRow();
		if(!row) {
			break;
		}
		
		if(!check_datehour(row["datehour"].c_str())) {
			q.str( std::string() );
			q.clear();
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlDbCleanspool->query(q.str());
			continue;
		}

		ostringstream fname;

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/sipsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpoolsize");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/rtpsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpoolsize");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/graphsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpoolsize");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/audiosize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpoolsize");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/regsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpoolsize");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		unlink_dirs(row["datehour"], 2, 2, 2, 2, 2, 2, "clean_maxpoolsize");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		q.str( std::string() );
		q.clear();
		q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
		sqlDbCleanspool->query(q.str());

		q.str( std::string() );
		q.clear();
		q << "SELECT SUM(sipsize) AS sipsize, SUM(rtpsize) AS rtpsize, SUM(graphsize) as graphsize, SUM(audiosize) AS audiosize, SUM(regsize) AS regsize FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
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

// OK
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
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/regsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpoolsipsize");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		unlink_dirs(row["datehour"], 1, 2, 1, 1, 1, 2, "clean_maxpoolsipsize");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		if(rtpsize + graphsize + audiosize > 0) {
			q.str( std::string() );
			q.clear();
			q << "UPDATE files SET sipsize = 0, regsize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlDbCleanspool->query(q.str());
		} else {
			q.str( std::string() );
			q.clear();
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlDbCleanspool->query(q.str());
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

// OK
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
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		unlink_dirs(row["datehour"], 1, 1, 2, 1, 1, 1, "clean_maxpoolrtpsize");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		if(sipsize + regsize + graphsize + audiosize > 0) {
			q.str( std::string() );
			q.clear();
			q << "UPDATE files SET rtpsize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlDbCleanspool->query(q.str());
		} else {
			q.str( std::string() );
			q.clear();
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlDbCleanspool->query(q.str());
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

// OK
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
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		unlink_dirs(row["datehour"], 1, 1, 1, 2, 1, 1, "clean_maxpoolgraphsize");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		if(sipsize + regsize + rtpsize + audiosize > 0) {
			q.str( std::string() );
			q.clear();
			q << "UPDATE files SET graphsize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlDbCleanspool->query(q.str());
		} else {
			q.str( std::string() );
			q.clear();
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlDbCleanspool->query(q.str());
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

// OK
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
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		unlink_dirs(row["datehour"], 1, 1, 1, 1, 2, 1, "clean_maxpoolaudiosize");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		if(sipsize + regsize + rtpsize + graphsize > 0) {
			q.str( std::string() );
			q.clear();
			q << "UPDATE files SET audiosize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlDbCleanspool->query(q.str());
		} else {
			q.str( std::string() );
			q.clear();
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlDbCleanspool->query(q.str());
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

// OK
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
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/rtpsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpooldays");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/graphsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpooldays");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/audiosize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpooldays");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/regsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpooldays");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		unlink_dirs(row["datehour"], 2, 2, 2, 2, 2, 2, "clean_maxpooldays");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		q.str( std::string() );
		q.clear();
		q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
		sqlDbCleanspool->query(q.str());
	}
}

// OK
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
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/regsize/" << row["datehour"];
		unlinkfileslist(fname.str(), "clean_maxpoolsipdays");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		unlink_dirs(row["datehour"], 1, 2, 1, 1, 1, 2, "clean_maxpoolsipdays");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		uint64_t rtpsize = strtoull(row["rtpsize"].c_str(), NULL, 0);
		uint64_t graphsize = strtoull(row["graphsize"].c_str(), NULL, 0);
		uint64_t audiosize = strtoull(row["audiosize"].c_str(), NULL, 0);

		if(rtpsize + graphsize + audiosize > 0) {
			stringstream q;
			q << "UPDATE files SET sipsize = 0, regsize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlDbCleanspool->query(q.str());
		} else {
			stringstream q;
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlDbCleanspool->query(q.str());
		}
	}
}

// OK
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
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		unlink_dirs(row["datehour"], 1, 1, 2, 1, 1, 1, "clean_maxpoolrtpdays");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		uint64_t sipsize = strtoull(row["sipsize"].c_str(), NULL, 0);
		uint64_t regsize = strtoull(row["regsize"].c_str(), NULL, 0);
		uint64_t graphsize = strtoull(row["graphsize"].c_str(), NULL, 0);
		uint64_t audiosize = strtoull(row["audiosize"].c_str(), NULL, 0);

		if(sipsize + regsize + graphsize + audiosize > 0) {
			stringstream q;
			q << "UPDATE files SET rtpsize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlDbCleanspool->query(q.str());
		} else {
			stringstream q;
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlDbCleanspool->query(q.str());
		}
	}
}

// OK
void clean_maxpoolgraphdays() {

	if(opt_maxpoolgraphdays == 0) {
		return;
	}

	if(!sqlDbCleanspool) {
		sqlDbCleanspool = createSqlObject();
	}

	stringstream q;
	q << "SELECT * FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0) <<  " AND (graphsize > 0) AND (datehour < DATE_FORMAT(DATE_SUB(NOW(), INTERVAL " << opt_maxpoolgraphdays << " DAY), '%Y%m%d%k')" << ") ORDER BY datehour";
	sqlDbCleanspool->query(q.str());
	SqlDb_row row;
	while(row = sqlDbCleanspool->fetchRow()) {
		ostringstream fname;

		fname.str( std::string() );
		fname.clear();
		fname << "filesindex/graphsize/" << row["datehour"];
		if(debugclean) cout << "reading: " << fname.str() << "\n";
		unlinkfileslist(fname.str(), "clean_maxpoolgraphdays");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		unlink_dirs(row["datehour"], 1, 1, 1, 2, 1, 1, "clean_maxpoolgraphdays");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		uint64_t sipsize = strtoull(row["sipsize"].c_str(), NULL, 0);
		uint64_t rtpsize = strtoull(row["rtpsize"].c_str(), NULL, 0);
		uint64_t regsize = strtoull(row["regsize"].c_str(), NULL, 0);
		uint64_t audiosize = strtoull(row["audiosize"].c_str(), NULL, 0);

		if(sipsize + regsize + rtpsize + audiosize > 0) {
			stringstream q;
			q << "UPDATE files SET graphsize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlDbCleanspool->query(q.str());
		} else {
			stringstream q;
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlDbCleanspool->query(q.str());
		}
	}
}

// OK
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
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		unlink_dirs(row["datehour"], 1, 1, 1, 1, 2, 1, "clean_maxpoolaudiodays");
		if(DISABLE_CLEANSPOOL) {
			break;
		}

		uint64_t sipsize = strtoull(row["sipsize"].c_str(), NULL, 0);
		uint64_t rtpsize = strtoull(row["rtpsize"].c_str(), NULL, 0);
		uint64_t regsize = strtoull(row["regsize"].c_str(), NULL, 0);
		uint64_t graphsize = strtoull(row["graphsize"].c_str(), NULL, 0);

		if(sipsize + regsize + rtpsize + graphsize > 0) {
			stringstream q;
			q << "UPDATE files SET audiosize = 0 WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlDbCleanspool->query(q.str());
		} else {
			stringstream q;
			q << "DELETE FROM files WHERE datehour = " << row["datehour"] << " AND id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
			sqlDbCleanspool->query(q.str());
		}
	}
}

// OK
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

// OK (reindex_all)
void convert_filesindex(const char *reason) {
	static u_long lastCall_convert_filesindex = 0; 
	u_long actTime = getTimeS();
	if(actTime - lastCall_convert_filesindex < 5 * 60) {
		syslog(LOG_NOTICE,"suppress run convert_filesindex - last run before %lus", actTime - lastCall_convert_filesindex);
		return;
	}
	lastCall_convert_filesindex = actTime;
 
	string path = "./";
	dirent* de;
	DIR* dp;
	errno = 0;
	dp = opendir(path.empty() ? "." : path.c_str());
	if(!dp) {
		return;
	}
	syslog(LOG_NOTICE, "reindexing start%s%s", reason ? " - " : "", reason ? reason : "");
	char id_sensor_str[10];
	sprintf(id_sensor_str, "%i", opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
	string q = string("DELETE FROM files WHERE id_sensor=") + id_sensor_str;
	sqlStore->query_lock(q.c_str(), STORE_PROC_ID_CLEANSPOOL_SERVICE);
	rmdir_r("filesindex", true, true);
	mkdir_r("filesindex/sipsize", 0777);
	mkdir_r("filesindex/rtpsize", 0777);
	mkdir_r("filesindex/graphsize", 0777);
	mkdir_r("filesindex/audiosize", 0777);
	mkdir_r("filesindex/regsize", 0777);
	while(!is_terminating()) {
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
	// wait for flush sql store
	while(sqlStore->getSize(STORE_PROC_ID_CLEANSPOOL_SERVICE) > 0) {
		usleep(100000);
	}
	sleep(1);
}

// OK
void do_convert_filesindex(const char *reason) {
	do_convert_filesindex_flag = true;
	do_convert_filesindex_reason = reason;
}

// OK
void check_filesindex() {
	string path = "./";
	dirent* de;
	DIR* dp;
	errno = 0;
	dp = opendir(path.empty() ? "." : path.c_str());
	if(!dp) {
		return;
	}
	SqlDb *sqlDb = createSqlObject();
	syslog(LOG_NOTICE, "check indexes start");
	while(!is_terminating()) {
		errno = 0;
		de = readdir( dp );
		if(de == NULL) break;
		if(string(de->d_name) == ".." or string(de->d_name) == ".") continue;
		if(de->d_name[0] == '2' && strlen(de->d_name) == 10) {
			check_index_date(de->d_name, sqlDb);
		}
	}
	syslog(LOG_NOTICE, "check indexes done");
	closedir( dp );
	delete sqlDb;
}

// OK
long long reindex_date(string date) {
	long long sumDaySize = 0;
	for(int h = 0; h < 24 && !is_terminating(); h++) {
		sumDaySize += reindex_date_hour(date, h);
	}
	if(!sumDaySize && !is_terminating()) {
		rmdir(date.c_str());
	}
	return(sumDaySize);
}

// OK
void check_index_date(string date, SqlDb *sqlDb) {
	char id_sensor_str[10];
	sprintf(id_sensor_str, "%i", opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
	for(int h = 0; h < 24 && !is_terminating(); h++) {
		char hour[8];
		sprintf(hour, "%02d", h);
		string ymdh = string(date.substr(0,4)) + date.substr(5,2) + date.substr(8,2) + hour;
		map<string, long long> typeSize;
		reindex_date_hour(date, h, true, &typeSize, true);
		if(typeSize["sip"] || typeSize["rtp"] || typeSize["graph"] || typeSize["audio"]) {
			bool needReindex = false;
			sqlDb->query(string("select * from files where datehour ='") + ymdh + "'" +
				     " and id_sensor = " + id_sensor_str);
			SqlDb_row row = sqlDb->fetchRow();
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

// OK
bool fileIsOpenTar(list<string> &listOpenTars, string &file) {
	list<string>::iterator iter;
	for(iter = listOpenTars.begin(); iter != listOpenTars.end(); iter++) {
		if(iter->find(file) != string::npos) {
			return(true);
		}
	}
	return(false);
}

// OK
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
		sipfile = new FILE_LINE ofstream((string("filesindex/sipsize/") + ymdh).c_str(), ios::trunc | ios::out);
		rtpfile = new FILE_LINE ofstream((string("filesindex/rtpsize/") + ymdh).c_str(), ios::trunc | ios::out);
		graphfile = new FILE_LINE ofstream((string("filesindex/graphsize/") + ymdh).c_str(), ios::trunc | ios::out);
		audiofile = new FILE_LINE ofstream((string("filesindex/audiosize/") + ymdh).c_str(), ios::trunc | ios::out);
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
	
	extern TarQueue *tarQueue;
	list<string> listOpenTars;
	if(tarQueue) {
		listOpenTars = tarQueue->listOpenTars();
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
						if(!tarQueue ||
						   !fileIsOpenTar(listOpenTars, dhmtf)) {
							long long size = GetFileSizeDU(dhmtf);
							if(size == 0) size = 1;
							sipsize += size;
							if(!readOnly) {
								(*sipfile) << dhmtf << ":" << size << "\n";
							}
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
						if(!tarQueue ||
						   !fileIsOpenTar(listOpenTars, dhmtf)) {
							long long size = GetFileSizeDU(dhmtf);
							if(size == 0) size = 1;
							rtpsize += size;
							if(!readOnly) {
								(*rtpfile) << dhmtf << ":" << size << "\n";
							}
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
						if(!tarQueue ||
						   !fileIsOpenTar(listOpenTars, dhmtf)) {
							long long size = GetFileSizeDU(dhmtf);
							if(size == 0) size = 1;
							graphsize += size;
							if(!readOnly) {
								(*graphfile) << dhmtf << ":" << size << "\n";
							}
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
			sqlStore->query_lock(query.str().c_str(), STORE_PROC_ID_CLEANSPOOL_SERVICE);

		} else {
			stringstream query;
			int id_sensor = opt_id_sensor_cleanspool == -1 ? 0 : opt_id_sensor_cleanspool;
			query << "DELETE FROM files WHERE datehour = " << ymdh << " AND " << "id_sensor = " << id_sensor << ";";
			sqlStore->query_lock(query.str().c_str(), STORE_PROC_ID_CLEANSPOOL_SERVICE);
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
		delete sipfile;
		delete rtpfile;
		delete graphfile;
		delete audiofile;
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

// remove
void reindex_date_hour_start_syslog(string date, string hour) {
	syslog(LOG_NOTICE, "reindexing files in [%s/%s] start", date.c_str(), hour.c_str());
}

// OK
bool check_exists_act_records_in_files() {
	bool ok = false;
	if(!sqlDbCleanspool) {
		sqlDbCleanspool = createSqlObject();
	}
	char id_sensor_str[10];
	sprintf(id_sensor_str, "%i", opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
	sqlDbCleanspool->query("select max(calldate) as max_calldate from cdr where calldate > date_add(now(), interval -1 day)");
	SqlDb_row row = sqlDbCleanspool->fetchRow();
	if(!row || !row["max_calldate"].length()) {
		return(true);
	}
	time_t maxCdrTime = stringToTime(row["max_calldate"].c_str());
	for(int i = 0; i < 12; i++) {
		time_t checkTime = maxCdrTime - i * 60 * 60;
		struct tm checkTimeInfo = time_r(&checkTime);
		char datehour[20];
		strftime(datehour, 20, "%Y%m%d%H", &checkTimeInfo);
		sqlDbCleanspool->query(string("select * from files where datehour ='") + datehour + "'" +
				       " and id_sensor = " + id_sensor_str);
		if(sqlDbCleanspool->fetchRow()) {
			ok = true;
			break;
		}
	}
	return(ok);
}

// OK
bool check_exists_act_files_in_filesindex() {
	bool ok = false;
	if(!sqlDbCleanspool) {
		sqlDbCleanspool = createSqlObject();
	}
	char id_sensor_str[10];
	sprintf(id_sensor_str, "%i", opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
	sqlDbCleanspool->query("select max(calldate) as max_calldate from cdr where calldate > date_add(now(), interval -1 day)");
	SqlDb_row row = sqlDbCleanspool->fetchRow();
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

// OK
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

// OK
void clean_spooldir_run() {

	if(opt_cleanspool_interval and opt_cleanspool_sizeMB > 0) {
		opt_maxpoolsize = opt_cleanspool_sizeMB;
		// if old cleanspool interval is defined convert the config to new config 
		if(FileExists(configfile)) {

			syslog(LOG_NOTICE, "converting [%s] cleanspool_interval and cleanspool_size to maxpoolsize\n", configfile);

			convert_filesindex("convert configuration");

			string tmpf = "/tmp/VM_pRjSYLAyx.conf";
			FILE *fdr = fopen(configfile, "r");
			FILE *fdw = fopen(tmpf.c_str(), "w");
			if(!fdr or !fdw) {
				syslog(LOG_ERR, "cannot open config file [%s]\n", configfile);
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

	return;
}

// OK
bool isSetCleanspoolParameters(int spoolIndex) {
	return((spoolIndex == 0 ?
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
	       opt_autocleanmingb);
}

// OK
void *clean_spooldir(void *dummy) {
	if(debugclean) syslog(LOG_ERR, "run clean_spooldir()");
	while(!is_terminating()) {
		if(do_convert_filesindex_flag ||
		   !check_exists_act_records_in_files() ||
		   !check_exists_act_files_in_filesindex()) {
			const char *reason = do_convert_filesindex_flag ? 
					      (do_convert_filesindex_reason ? do_convert_filesindex_reason : "set do_convert_filesindex_flag") :
					      "call from clean_spooldir - not exists act records in files and act files in filesindex";
			do_convert_filesindex_flag = false;
			do_convert_filesindex_reason = NULL;
			convert_filesindex(reason);
		}
		bool timeOk = false;
		if(opt_cleanspool_enable_run_hour_from >= 0 &&
		   opt_cleanspool_enable_run_hour_to >= 0) {
			time_t now;
			time(&now);
			struct tm dateTime = time_r(&now);
			if(opt_cleanspool_enable_run_hour_to >= opt_cleanspool_enable_run_hour_from) {
				if(dateTime.tm_hour >= opt_cleanspool_enable_run_hour_from &&
				   dateTime.tm_hour <= opt_cleanspool_enable_run_hour_to) {
					timeOk = true;
				}
			} else {
				if((dateTime.tm_hour >= opt_cleanspool_enable_run_hour_from && dateTime.tm_hour < 24) ||
				   dateTime.tm_hour <= opt_cleanspool_enable_run_hour_to) {
					timeOk = true;
				}
			}
		} else {
			timeOk = true;
		}
		bool criticalLowSpace = false;
		long int maxpoolsize = 0;
		if(opt_autocleanspoolminpercent || opt_autocleanmingb) {
			double totalSpaceGB = (double)GetTotalDiskSpace(opt_chdir) / (1024 * 1024 * 1024);
			double freeSpacePercent = (double)GetFreeDiskSpace(opt_chdir, true) / 100;
			double freeSpaceGB = (double)GetFreeDiskSpace(opt_chdir) / (1024 * 1024 * 1024);
			int _minPercentForAutoReindex = 1;
			int _minGbForAutoReindex = 5;
			if(freeSpacePercent < _minPercentForAutoReindex && 
			   freeSpaceGB < _minGbForAutoReindex) {
				syslog(LOG_NOTICE, "low spool disk space - executing convert_filesindex");
				convert_filesindex("call from clean_spooldir - low spool disk space");
				freeSpacePercent = (double)GetFreeDiskSpace(opt_chdir, true) / 100;
				freeSpaceGB = (double)GetFreeDiskSpace(opt_chdir) / (1024 * 1024 * 1024);
				criticalLowSpace = true;
			}
			if(freeSpacePercent < opt_autocleanspoolminpercent ||
			   freeSpaceGB < opt_autocleanmingb) {
				SqlDb *sqlDb = createSqlObject();
				stringstream q;
				q << "SELECT SUM(coalesce(sipsize,0) + coalesce(rtpsize,0) + coalesce(graphsize,0) + coalesce(audiosize,0)) as sum_size FROM files WHERE id_sensor = " << (opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0);
				sqlDb->query(q.str());
				SqlDb_row row = sqlDb->fetchRow();
				if(row) {
					double usedSizeGB = atol(row["sum_size"].c_str()) / (1024 * 1024 * 1024);
					maxpoolsize = (usedSizeGB + freeSpaceGB - min(totalSpaceGB * opt_autocleanspoolminpercent / 100, (double)opt_autocleanmingb)) * 1024;
					if(maxpoolsize > 1000 &&
					   (!opt_maxpoolsize || maxpoolsize < opt_maxpoolsize)) {
						if(opt_maxpoolsize && maxpoolsize < opt_maxpoolsize * 0.8) {
							maxpoolsize = opt_maxpoolsize * 0.8;
						}
						syslog(LOG_NOTICE, "%s: %li MB", 
						       opt_maxpoolsize ?
							"low spool disk space - maxpoolsize set to new value" :
							"maxpoolsize set to value",
						       maxpoolsize);
					} else {
						syslog(LOG_ERR, "incorrect set autocleanspoolminpercent and autocleanspoolmingb");
						maxpoolsize = 0;
					}
				}
				delete sqlDb;
			}
		}
		if((timeOk && !suspendCleanspool) || criticalLowSpace) {
			if(debugclean) syslog(LOG_ERR, "run clean_spooldir_run");
			if(maxpoolsize > 1000) {
				maxpoolsize_set = maxpoolsize;
			}
			critical_low_space = criticalLowSpace;
			clean_spooldir_run();
			maxpoolsize_set = 0;
			critical_low_space = false;
		}
		for(int i = 0; i < 300 && !is_terminating() && !do_convert_filesindex_flag; i++) {
			sleep(1);
		}
	}
	return NULL;
}

// OK
void runCleanSpoolThread() {
	if(!cleanspool_thread) {
		if(debugclean) syslog(LOG_ERR, "pthread_create(clean_spooldir)");
		vm_pthread_create("cleanspool",
				  &cleanspool_thread, NULL, clean_spooldir, NULL, __FILE__, __LINE__);
	}
}

// OK
void termCleanSpoolThread() {
	if(cleanspool_thread) {
		pthread_join(cleanspool_thread, NULL);
		cleanspool_thread = 0;
	}
}

string getMaxSpoolDate() {
	string path = "./";
	dirent* de;
	DIR* dp;
	dp = opendir(path.empty() ? "." : path.c_str());
	if(!dp) {
		return("");
	}
	u_int32_t maxDate = 0;
	while((de = readdir(dp)) != NULL) {
		if(de == NULL) break;
		if(string(de->d_name) == ".." or string(de->d_name) == ".") continue;
		if(de->d_name[0] == '2' && strlen(de->d_name) == 10) {
			u_int32_t date = atol(de->d_name) * 10000 +
					 atol(de->d_name + 5) * 100 +
					 atol(de->d_name + 8);
			if(date > maxDate) {
				maxDate = date;
			}
		}
	}
	closedir( dp );
	
	if(maxDate) {
		char maxDate_str[20];
		sprintf(maxDate_str, "%4i-%02i-%02i", maxDate / 10000, maxDate % 10000 / 100, maxDate % 100);
		return(maxDate_str);
	} else {
		return("");
	}
}

// OK
bool check_datehour(const char *datehour) {
	if(!datehour || strlen(datehour) != 10) {
		return(false);
	}
	u_int64_t datehour_i = atoll(datehour);
	return(datehour_i / 1000000 > 2000 &&
	       datehour_i / 10000 % 100 >= 1 && datehour_i / 10000 % 100 <= 12 && 
	       datehour_i / 100 % 100 >= 1 && datehour_i / 100 % 100 <= 31 && 
	       datehour_i % 100 < 60);
}
*/