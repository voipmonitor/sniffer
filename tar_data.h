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
	int typeSpoolFile;
	std::string filename;
	void set(int typeSpoolFile, class Call_abstract *call, const char *fileName);
};


#endif //TAR_DATA_H
