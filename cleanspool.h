#ifndef CLEANSPOOL_H
#define CLEANSPOOL_H


#include "voipmonitor.h"
#include "sql_db.h"


class CleanSpool {
public:
	struct CleanSpoolDirs {
		string main;
		string rtp;
		string graph;
		string audio;
	};
	struct CleanSpoolOptMax {
		unsigned int maxpoolsize;
		unsigned int maxpooldays;
		unsigned int maxpoolsipsize;
		unsigned int maxpoolsipdays;
		unsigned int maxpoolrtpsize;
		unsigned int maxpoolrtpdays;
		unsigned int maxpoolgraphsize;
		unsigned int maxpoolgraphdays;
		unsigned int maxpoolaudiosize;
		unsigned int maxpoolaudiodays;
	};
	struct CleanSpoolOptOther {
		int maxpool_clean_obsolete;
		int cleanspool_interval;
		int cleanspool_sizeMB;
		int autocleanspoolminpercent;
		int autocleanmingb;
		int cleanspool_enable_run_hour_from;
		int cleanspool_enable_run_hour_to;
	};
public:
	CleanSpool(int spoolIndex);
	~CleanSpool();
	void addFile(const char *datehour, const char *column, eTypeSpoolFile typeSpoolFile, const char *file, long long int size);
	void run();
	void do_convert_filesindex(const char *reason);
	void check_filesindex();
	void check_index_date(string date, SqlDb *sqlDb);
	string getMaxSpoolDate();
	static void run_cleanProcess(int spoolIndex = -1);
	static void run_clean_obsolete(int spoolIndex = -1);
	static void run_reindex_all(const char *reason, int spoolIndex = -1);
	static void run_reindex_date(string date, int spoolIndex = -1);
	static void run_reindex_date_hour(string date, int hour, int spoolIndex = -1);
	static void run_check_filesindex(int spoolIndex = -1);
	static void run_check_spooldir_filesindex(const char *dirfilter = NULL, int spoolIndex = -1);
	static bool suspend(int spoolIndex = -1);
	static bool resume(int spoolIndex = -1);
	static bool isSetCleanspoolParameters(int spoolIndex);
	static bool isSetCleanspool(int spoolIndex);
	static bool check_datehour(const char *datehour);
private:
	void loadOpt();
	void runCleanThread();
	void termCleanThread();
	static void *cleanThread(void *cleanSpool);
	void cleanThread();
	void cleanThreadProcess();
	bool check_exists_act_records_in_files();
	bool check_exists_act_files_in_filesindex();
	void reindex_all(const char *reason);
	long long reindex_date(string date);
	long long reindex_date_hour(string date, int h, bool readOnly = false, map<string, long long> *typeSize = NULL, bool quickCheck = false);
	long long reindex_date_hour_type(string date, int h, string type, bool readOnly, bool quickCheck, map<unsigned, bool> *fillMinutes);
	void unlinkfileslist(eTypeSpoolFile typeSpoolFile, string fname, string callFrom);
	void unlink_dirs(string datehour, int sip, int rtp, int graph, int audio, string callFrom);
	void clean_spooldir_run();
	void clean_maxpoolsize(bool sip, bool rtp, bool graph, bool audio);
	void clean_maxpoolsize_all() {
		clean_maxpoolsize(true, true, true, true);
	}
	void clean_maxpoolsize_sip() {
		clean_maxpoolsize(true, false, false, false);
	}
	void clean_maxpoolsize_rtp() {
		clean_maxpoolsize(false, true, false, false);
	}
	void clean_maxpoolsize_graph() {
		clean_maxpoolsize(false, false, true, false);
	}
	void clean_maxpoolsize_audio() {
		clean_maxpoolsize(false, false, false, true);
	}
	void clean_maxpooldays(bool sip, bool rtp, bool graph, bool audio);
	void clean_maxpooldays_all() {
		clean_maxpooldays(true, true, true, true);
	}
	void clean_maxpooldays_sip() {
		clean_maxpooldays(true, false, false, false);
	}
	void clean_maxpooldays_rtp() {
		clean_maxpooldays(false, true, false, false);
	}
	void clean_maxpooldays_graph() {
		clean_maxpooldays(false, false, true, false);
	}
	void clean_maxpooldays_audio() {
		clean_maxpooldays(false, false, false, true);
	}
	void clean_obsolete_dirs();
	void check_spooldir_filesindex(const char *dirfilter);
	unsigned int get_reduk_maxpoolsize(unsigned int maxpoolsize);
	bool fileIsOpenTar(list<string> &listOpenTars, string &file);
	void readSpoolDateDirs(list<string> *dirs);
	void getSpoolDirs(list<string> *spool_dirs);
	string findExistsSpoolDirFile(eTypeSpoolFile typeSpoolFile, string pathFile, 
				      eTypeSpoolFile *rsltTypeSpoolFile = NULL);
	const char *getSpoolDir(eTypeSpoolFile typeSpoolFile) {
		return(::getSpoolDir(typeSpoolFile, spoolIndex));
	}
	string getSpoolDir_string(eTypeSpoolFile typeSpoolFile) {
		return(::getSpoolDir(typeSpoolFile, spoolIndex));
	}
	string getSpoolIndex_string() {
		return(intToString(spoolIndex));
	}
	string getIdSensor_string() {
		extern int opt_id_sensor_cleanspool;
		return(intToString(opt_id_sensor_cleanspool > 0 ? opt_id_sensor_cleanspool : 0));
	}
private:
	int spoolIndex;
	CleanSpoolDirs opt_dirs;
	CleanSpoolOptMax opt_max;
	CleanSpoolOptOther opt_other;
	SqlDb *sqlDb;
	unsigned int maxpoolsize_set;
	bool critical_low_space;
	bool do_convert_filesindex_flag;
	const char *do_convert_filesindex_reason;
	pthread_t clean_thread;
	u_long lastCall_reindex_all;
	bool suspended;
	volatile int clean_spooldir_run_processing;
};

/*
void check_spooldir_filesindex(const char *path = NULL, const char *dirfilter = NULL);
void convert_filesindex(const char *reason);
void do_convert_filesindex(const char *reason);
long long reindex_date(string date);
long long reindex_date_hour(string date, int h, bool readOnly = false, map<string, long long> *typeSize = NULL, bool quickCheck = false);
void check_filesindex();
bool check_exists_act_records_in_files();
bool check_exists_act_files_in_filesindex();
void clean_obsolete_dirs(const char *path = NULL);
bool isSetCleanspoolParameters(int spoolIndex);
void runCleanSpoolThread();
void termCleanSpoolThread();
string getMaxSpoolDate();
bool check_datehour(const char *datehour);
*/

#endif

