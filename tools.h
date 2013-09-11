#ifndef TOOLS_H
#define TOOLS_H

#include <string>
#include <sys/types.h>

using namespace std;

int getUpdDifTime(struct timeval *before);
int getDifTime(struct timeval *before);
int msleep(long msec);
int file_exists (char * fileName);
void set_mac();
int mkdir_r(std::string, mode_t);
double ts2double(unsigned int sec, unsigned int usec);
long GetFileSize(std::string filename);
bool FileExists(char *strFilename);
void ntoa(char *res, unsigned int addr);
string escapeshellR(string &);


class CircularBuffer
{
public:
	 CircularBuffer(size_t capacity);
	 ~CircularBuffer();

	 size_t size() const { return size_; }
	 size_t capacity() const { return capacity_; }
	 // Return number of bytes written.
	 size_t write(const char *data, size_t bytes);
	 // Return number of bytes read.
	 size_t read(char *data, size_t bytes);

private:
	 size_t beg_index_, end_index_, size_, capacity_;
	 char *data_;
};

struct dstring
{
	dstring() {
	}
	dstring(std::string str1, std::string str2) {
		str[0] = str1;
		str[1] = str2;
	}
	std::string operator [] (int indexStr) {
		return(str[indexStr]);
	}
	std::string str[2];
};

struct d_u_int32_t
{
	d_u_int32_t() {
	}
	d_u_int32_t(u_int32_t val1, u_int32_t val2) {
		val[0] = val1;
		val[1] = val2;
	}
	u_int32_t operator [] (int indexVal) {
		return(val[indexVal]);
	}
	u_int32_t val[2];
};

inline u_long getTimeMS() {
    timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return(time.tv_sec * 1000 + time.tv_nsec / 1000000);
}

inline unsigned long long getTimeNS() {
    timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return(time.tv_sec * 1000000000ull + time.tv_nsec);
}

#endif
