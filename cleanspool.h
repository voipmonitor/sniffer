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
	struct sSpoolDataDirIndex {
		enum eTypeItem {
			_ti_spool  = 1,
			_ti_sensor = 2,
			_ti_date   = 4,
			_ti_hour   = 8,
			_ti_minute = 16,
			_ti_type   = 32
		};
		sSpoolDataDirIndex() {
			hour = -1;
			minute = -1;
			_type = tsf_na;
		}
		unsigned getSettedItems() {
			unsigned typeItem = 0;
			if(spool.length())	typeItem |= _ti_spool;
			if(sensor.length())	typeItem |= _ti_sensor;
			if(date.length())	typeItem |= _ti_date;
			if(hour >= 0)		typeItem |= _ti_hour;
			if(minute >= 0)		typeItem |= _ti_minute;
			if(type.length())	typeItem |= _ti_type;
			return(typeItem);
		}
		eTypeSpoolFile getTypeSpoolFile() {
			if(type.length()) {
				return(_type);
			}
			return(tsf_na);
		}
		bool operator == (const sSpoolDataDirIndex& other) const {
			return(this->date == other.date &&
			       this->hour == other.hour &&
			       this->minute == other.minute &&
			       this->spool == other.spool &&
			       this->sensor == other.sensor &&
			       this->type == other.type);
		}
		bool operator < (const sSpoolDataDirIndex& other) const { 
			return(this->date < other.date ? 1 : this->date > other.date ? 0 :
			       this->hour < other.hour ? 1 : this->hour > other.hour ? 0 :
			       this->minute < other.minute ? 1 : this->minute > other.minute ? 0 :
			       this->spool < other.spool ? 1 : this->spool > other.spool ? 0 :
			       this->sensor < other.sensor ? 1 : this->sensor > other.sensor ? 0 :
			       this->type < other.type);
		}
		friend ostream& operator << (ostream& os, const sSpoolDataDirIndex& index) {
			if(index.spool.length())	os << "spool: " << index.spool << " ";
			if(index.sensor.length())	os << "sensor: " << index.sensor << " ";
			if(index.date.length())		os << "date: " << index.date << " ";
			if(index.hour >= 0)		os << "hour: " << index.hour << " ";
			if(index.minute >= 0)		os << "minute: " << index.minute << " ";
			if(index.type.length())		os << "type: " << index.type << " ";
			return(os);
		}
		string spool;
		string sensor;
		string date;
		int hour;
		int minute;
		string type;
		eTypeSpoolFile _type;
	};
	struct sSpoolDataDirItem {
		string path;
		long long size;
	};
	class cSpoolData {
	public:
		cSpoolData() {
			_sync = 0;
		}
		void add(sSpoolDataDirIndex &index, sSpoolDataDirItem &item) {
			data[index] = item;
		}
		long long getSumSize();
		long long getSplitSumSize(long long *sip, long long *rtp, long long *graph, long long *audio);
		map<sSpoolDataDirIndex, sSpoolDataDirItem>::iterator getMin(bool sip, bool rtp, bool graph, bool audio);
		void erase(map<sSpoolDataDirIndex, sSpoolDataDirItem>::iterator iter) {
			data.erase(iter);
		}
		map<sSpoolDataDirIndex, sSpoolDataDirItem>::iterator end() {
			return(data.end());
		}
		void removeLastDateHours(int hours);
		void clearAll() {
			data.clear();
		}
		bool isEmpty() {
			return(data.size() == 0);
		}
		void fillDateHoursMap();
		void clearDateHoursMap();
		bool existsDateHour(const char *date, int hour);
		void lock() {
			while(__sync_lock_test_and_set(&_sync, 1));
		}
		void unlock() {
			__sync_lock_release(&_sync);
		}
	private:
		map<sSpoolDataDirIndex, sSpoolDataDirItem> data;
		map<uint64_t, bool> date_hours_map;
		volatile int _sync;
	};
public:
	CleanSpool(int spoolIndex);
	~CleanSpool();
	void addFile(const char *datehour, eTypeSpoolFile typeSpoolFile, const char *file, long long int size);
	void run();
	void do_convert_filesindex(const char *reason);
	void check_filesindex();
	void check_index_date(string date, SqlDb *sqlDb);
	string getMaxSpoolDate();
	static void run_cleanProcess(int spoolIndex = -1);
	static void run_clean_obsolete(int spoolIndex = -1);
	static void run_test_load(int spoolIndex = -1);
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
	static bool check_date_dir(const char *datedir);
	static bool check_hour_dir(const char *hourdir);
	static bool check_minute_dir(const char *minutedir);
	static bool check_type_dir(const char *typedir);
	static unsigned date_to_int(const char *date);
private:
	void reloadSpoolDataDir();
	void updateSpoolDataDir();
	void loadSpoolDataDir(cSpoolData *spoolData, sSpoolDataDirIndex index, string path);
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
	long long reindex_date_hour_type(string date, int h, string type, bool readOnly, bool quickCheck, 
					 map<unsigned, bool> *fillMinutes, bool *existsDhDir);
	void unlinkfileslist(eTypeSpoolFile typeSpoolFile, string fname, string callFrom);
	void unlink_dirs(string datehour, int sip, int reg, int skinny, int mgcp, int ss7, int rtp, int graph, int audio, string callFrom);
	void erase_dir(string dir, sSpoolDataDirIndex index, string callFrom);
	bool dir_is_empty(string dir);
	string reduk_dir(string dir, string *last_dir);
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
	void test_load();
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
	string getCondIdSensor_cdr() {
		if(is_receiver()) {
			return("");
		}
		extern int opt_id_sensor_cleanspool;
		return(opt_id_sensor_cleanspool > 0 ?
			"id_sensor = " + intToString(opt_id_sensor_cleanspool) :
			"id_sensor is null");
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
	cSpoolData spoolData;
};


#endif

