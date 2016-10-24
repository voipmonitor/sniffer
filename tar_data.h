#ifndef TAR_DATA_H
#define TAR_DATA_H


#include <string>


extern std::string intToString(int i);


struct data_tar_time {
	int year, mon, day, hour, minute;
	inline void clear() {
		year = mon = day = hour = minute = 0;
	}
	inline std::string getTimeString() {
		char buf[100];
		snprintf(buf, sizeof(buf), "%04i-%02i-%02i %02i:%02i", year, mon, day, hour, minute);
		return(buf);
	}
	inline u_int64_t decTime() const {
		return(year * 100000000ull +
		       mon *  1000000ull +
		       day *  10000ull + 
		       hour * 100ull +
		       minute);
	}
	inline bool operator == (const data_tar_time& other) const { 
		return(this->decTime() == other.decTime()); 
	}
	inline bool operator != (const data_tar_time& other) const { 
		return(this->decTime() != other.decTime()); 
	}
	inline bool operator < (const data_tar_time& other) const { 
		return(this->decTime() < other.decTime()); 
	}
};

struct data_tar : public data_tar_time {
	std::string sensorName;
	std::string type;
	std::string filename;
	inline void parseFileName(const char *filename, const char *spoolDir) {
		char sensorName[1024];
		unsigned int year, mon, day, hour, minute;
		char type[12];
		char fbasename[2*1024];
		extern int opt_spooldir_by_sensor;
		extern int opt_spooldir_by_sensorname;
		const char *pointToFilenameAfterBaseSpooldir = filename;
		unsigned spoolDirLength = strlen(spoolDir);
		if(!strncmp(pointToFilenameAfterBaseSpooldir, spoolDir, spoolDirLength)) {
			pointToFilenameAfterBaseSpooldir += spoolDirLength;
		}
		while(*pointToFilenameAfterBaseSpooldir == '/') {
			++pointToFilenameAfterBaseSpooldir;
		}
		if((!opt_spooldir_by_sensor && !opt_spooldir_by_sensorname) ||
		   sscanf(pointToFilenameAfterBaseSpooldir, "%[^/]/%u-%u-%u/%u/%u/%[^/]/%s", sensorName, &year, &mon, &day, &hour, &minute, type, fbasename) != 8) {
			sscanf(pointToFilenameAfterBaseSpooldir, "%u-%u-%u/%u/%u/%[^/]/%s", &year, &mon, &day, &hour, &minute, type, fbasename);
			sensorName[0] = 0;
		}
		this->sensorName = sensorName;
		this->year = year;
		this->mon = mon;
		this->day = day;
		this->hour = hour;
		this->minute = minute;
		this->type = type;
		this->filename = fbasename;
	}
};


#endif //TAR_DATA_H
