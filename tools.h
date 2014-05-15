#ifndef TOOLS_H
#define TOOLS_H

#include <string>
#include <vector>
#include <queue>
#include <sstream>
#include <utility>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <ctime>
#include <limits.h>
#include <list>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>
#include <zlib.h>
#include <pcap.h>
#include <netdb.h>

#include "pstat.h"

using namespace std;

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
	bool operator == (const dstring& other) const { 
		return(this->str[0] == other.str[0] &&
		       this->str[1] == other.str[1]); 
	}
	std::string str[2];
};

struct d_u_int32_t
{
	d_u_int32_t(u_int32_t val1 = 0, u_int32_t val2 = 0) {
		val[0] = val1;
		val[1] = val2;
	}
	u_int32_t operator [] (int indexVal) {
		return(val[indexVal]);
	}
	u_int32_t val[2];
};

int getUpdDifTime(struct timeval *before);
int getDifTime(struct timeval *before);
int msleep(long msec);
int file_exists (char * fileName);
void set_mac();
int mkdir_r(std::string, mode_t);
int rmdir_r(const char *dir, bool enableSubdir = false, bool withoutRemoveRoot = false);
unsigned long long cp_r(const char *src, const char *dst, bool move = false);
inline unsigned long long mv_r(const char *src, const char *dst) { return(cp_r(src, dst, true)); }  
unsigned long long copy_file(const char *src, const char *dst, bool move = false);
inline unsigned long long move_file(const char *src, const char *dst) { return(copy_file(src, dst, true)); }
bool get_url_file(const char *url, const char *toFile, string *error = NULL);
class SimpleBuffer {
public:
	SimpleBuffer(u_int32_t capacityReserve = 0) {
		buffer = NULL;
		bufferLength = 0;
		bufferCapacity = 0;
		this->capacityReserve = capacityReserve;
	}
	~SimpleBuffer() {
		destroy();
	}
	void add(void *data, u_int32_t dataLength) {
		if(!data || !dataLength) {
			return;
		}
		if(!buffer) {
			buffer = new u_char[dataLength + capacityReserve + 1];
			bufferCapacity = dataLength + capacityReserve + 1;
		} else if(bufferLength + dataLength > capacityReserve) {
			u_char *bufferNew = new u_char[bufferLength + dataLength + capacityReserve + 1];
			memcpy(bufferNew, buffer, bufferLength);
			delete [] buffer;
			buffer = bufferNew;
			bufferCapacity = bufferLength + dataLength + capacityReserve + 1;
		}
		memcpy(buffer + bufferLength, data, dataLength);
		bufferLength += dataLength;
	}
	u_char *data() {
		return(buffer);
	}
	u_int32_t size() {
		return(bufferLength);
	}
	void clear() {
		bufferLength = 0;
	}
	void destroy() {
		if(buffer) {
			delete [] buffer;
			buffer = 0;
		}
		bufferLength = 0;
		bufferCapacity = 0;
	}
	bool empty() {
		return(bufferLength == 0);
	}
	operator char*() {
		if(bufferLength == 0) {
			return((char*)"");
		} else {
			if(bufferCapacity <= bufferLength) {
				u_char *newBuffer = new u_char[bufferLength + 1];
				memcpy(newBuffer, buffer, bufferLength);
				delete [] buffer;
				buffer = newBuffer;
				++bufferCapacity;
			}
			buffer[bufferLength] = 0;
			return((char*)buffer);
		}
		return((char*)"");
	}
	bool isJsonObject() {
		return(bufferLength && buffer[0] == '{' && buffer[bufferLength - 1] == '}');
	}
private:
	u_char *buffer;
	u_int32_t bufferLength;
	u_int32_t bufferCapacity;
	u_int32_t capacityReserve;
};
bool get_url_response(const char *url, SimpleBuffer *response, vector<dstring> *postData, string *error = NULL);
double ts2double(unsigned int sec, unsigned int usec);
long long GetFileSize(std::string filename);
long long GetFileSizeDU(std::string filename);
long long GetDU(long long fileSize);
long long GetFreeDiskSpace(const char* absoluteFilePath, bool percent_mult_100 = false);
long long GetTotalDiskSpace(const char* absoluteFilePath);
string GetStringMD5(std::string str);
string GetFileMD5(std::string filename);
bool FileExists(char *strFilename);
void ntoa(char *res, unsigned int addr);
string escapeshellR(string &);
time_t stringToTime(const char *timeStr);
struct tm getDateTime(u_int64_t us);
struct tm getDateTime(time_t time);
struct tm getDateTime(const char *timeStr);
unsigned int getNumberOfDayToNow(const char *date);
string getActDateTimeF();
int get_unix_tid(void);
unsigned long getUptime();
std::string &trim(std::string &s);
std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems);
std::vector<std::string> split(const std::string &s, char delim);
std::vector<std::string> split(const char *s, const char *delim, bool enableTrim = false);
std::vector<std::string> split(const char *s, std::vector<std::string> delim, bool enableTrim = false);
int reg_match(const char *string, const char *pattern);
string reg_replace(const char *string, const char *pattern, const char *replace);
string inet_ntostring(u_int32_t ip);
void base64_init(void);
int base64decode(unsigned char *dst, const char *src, int max);

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

struct ip_port
{
	ip_port() {
		port = 0;
	}
	ip_port(string ip, int port) {
		this->ip = ip;
		this->port = port;
	}
	void set_ip(string ip) {
		this->ip = ip;
	}
	void set_port(int port) {
		this->port = port;
	}
	string get_ip() {
		return(ip);
	}
	int get_port() {
		return(port);
	}
	operator int() {
		return(ip.length() && port);
	}
	std::string ip;
	int port;
};

inline u_long getTimeMS() {
    timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return(time.tv_sec * 1000 + time.tv_nsec / 1000000);
}

inline unsigned long long getTimeUS() {
    timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return(time.tv_sec * 1000000ull + time.tv_nsec / 1000);
}

inline unsigned long long getTimeNS() {
    timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return(time.tv_sec * 1000000000ull + time.tv_nsec);
}

class FileZipHandler {
public:
	FileZipHandler(int bufferLength = 0, int enableAsyncWrite = 0, int enableZip = 0,
		       bool dumpHandler = false);
	~FileZipHandler();
	bool open(const char *fileName, int permission = 0666);
	void close();
	bool write(char *data, int length) {
		return(this->buffer ?
			this->writeToBuffer(data, length) :
			this->writeToFile(data, length));
	}
	bool flushBuffer(bool force = false);
	bool writeToBuffer(char *data, int length);
	bool writeToFile(char *data, int length, bool force = false);
	bool _writeToFile(char *data, int length, bool flush = false);
	bool __writeToFile(char *data, int length);
	bool initZip();
	bool _open();
	void setError(const char *error = NULL);
	bool okHandle() {
		return(fh > 0);
	}
public:
	string fileName;
	int permission;
	int fh;
	z_stream *zipStream;
	string error;
	int bufferLength;
	char *buffer;
	char *zipBuffer;
	int useBufferLength;
	bool enableAsyncWrite;
	bool enableZip;
	bool dumpHandler;
	u_int64_t size;
	u_int64_t counter;
	static u_int64_t scounter;
	u_int32_t userData;
};

pcap_dumper_t *__pcap_dump_open(pcap_t *p, const char *fname, int linktype, string *errorString = NULL);
void __pcap_dump(u_char *user, const struct pcap_pkthdr *h, const u_char *sp);
void __pcap_dump_close(pcap_dumper_t *p);
char *__pcap_geterr(pcap_t *p, pcap_dumper_t *pd = NULL);

class PcapDumper {
public:
	enum eTypePcapDump {
		na,
		sip,
		rtp
	};
	PcapDumper(eTypePcapDump type, class Call *call, bool updateFilesQueueAtClose = true);
	~PcapDumper();
	bool open(const char *fileName, const char *fileNameSpoolRelative, pcap_t *useHandle, int useDlt);
	void dump(pcap_pkthdr* header, const u_char *packet);
	void close(bool updateFilesQueue = true);
	void remove(bool updateFilesQueue = true);
	bool isOpen() {
		return(this->handle != NULL);
	}
private:
	string fileName;
	string fileNameSpoolRelative;
	eTypePcapDump type;
	class Call *call;
	bool updateFilesQueueAtClose;
	u_int64_t capsize;
	u_int64_t size;
	pcap_dumper_t *handle;
	bool openError;
	int openAttempts;
};

class RtpGraphSaver {
public:
	RtpGraphSaver(class RTP *rtp,bool updateFilesQueueAtClose = true);
	~RtpGraphSaver();
	bool open(const char *fileName, const char *fileNameSpoolRelative);
	void write(char *buffer, int length);
	void close(bool updateFilesQueue = true);
	bool isOpen() {
		return(this->handle != NULL);
	}
private:
	string fileName;
	string fileNameSpoolRelative;
	class RTP *rtp;
	bool updateFilesQueueAtClose;
	FileZipHandler *handle;
};

#define AsyncClose_maxPcapThreads 32

class AsyncClose {
public:
	class AsyncCloseItem {
	public:
		AsyncCloseItem(Call *call = NULL, const char *file = NULL,
			       const char *column = NULL, long long writeBytes = 0);
		virtual ~AsyncCloseItem() {}
		virtual void process() = 0;
		virtual void processClose() {}
	protected:
		void addtofilesqueue();
	protected:
		string file;
		string column;
		string dirnamesqlfiles;
		long long writeBytes;
		void *calltable;
		int dataLength;
	friend class AsyncClose;
	};
	class AsyncCloseItem_pcap : public AsyncCloseItem {
	public:
		AsyncCloseItem_pcap(pcap_dumper_t *handle,
				    Call *call = NULL, const char *file = NULL,
				    const char *column = NULL, long long writeBytes = 0)
		 : AsyncCloseItem(call, file, column, writeBytes) {
			this->handle = handle;
			extern int opt_pcap_dump_bufflength;
			if(opt_pcap_dump_bufflength) {
				this->dataLength = ((FileZipHandler*)handle)->useBufferLength;
			}
		}
		void process() {
			__pcap_dump_close(handle);
			this->addtofilesqueue();
		}
		void processClose() {
			__pcap_dump_close(handle);
		}
	private:
		pcap_dumper_t *handle;
	};
	class AsyncWriteItem_pcap : public AsyncCloseItem {
	public:
		AsyncWriteItem_pcap(pcap_dumper_t *handle,
				    char *data, int length) {
			this->handle = handle;
			this->data = new char[length];
			memcpy(this->data, data, length);
			this->dataLength = length;
		}
		~AsyncWriteItem_pcap() {
			delete [] data;
		}
		void process() {
			((FileZipHandler*)handle)->_writeToFile(data, dataLength);
		}
	private:
		pcap_dumper_t *handle;
		char *data;
	};
	class AsyncCloseItem_fileZipHandler  : public AsyncCloseItem{
	public:
		AsyncCloseItem_fileZipHandler(FileZipHandler *handle,
					      Call *call = NULL, const char *file = NULL,
					      const char *column = NULL, long long writeBytes = 0)
		 : AsyncCloseItem(call, file, column, writeBytes) {
			this->handle = handle;
			this->dataLength = handle->useBufferLength;
		}
		void process() {
			handle->close();
			delete handle;
			this->addtofilesqueue();
		}
		void processClose() {
			handle->close();
			delete handle;
		}
	private:
		FileZipHandler *handle;
	};
	class AsyncWriteItem_fileZipHandler : public AsyncCloseItem {
	public:
		AsyncWriteItem_fileZipHandler(FileZipHandler *handle,
					      char *data, int length) {
			this->handle = handle;
			this->data = new char[length];
			memcpy(this->data, data, length);
			this->dataLength = length;
		}
		~AsyncWriteItem_fileZipHandler() {
			delete [] data;
		}
		void process() {
			handle->_writeToFile(data, dataLength);
		}
	private:
		FileZipHandler *handle;
		char *data;
	};
	struct StartThreadData {
		int threadIndex;
		AsyncClose *asyncClose;
	};
public:
	AsyncClose();
	~AsyncClose();
	void startThreads(int countPcapThreads, int maxPcapThreads);
	void addThread();
	void removeThread();
	void add(pcap_dumper_t *handle,
		 Call *call = NULL, const char *file = NULL,
		 const char *column = NULL, long long writeBytes = 0) {
		extern int opt_pcap_dump_bufflength;
		for(int pass = 0; pass < 2; pass++) {
			if(pass) {
				((FileZipHandler*)handle)->userData = 0;
			}
			int useThreadOper = 0;
			if(opt_pcap_dump_bufflength) {
				if(((FileZipHandler*)handle)->userData) {
					useThreadOper = -1;
				} else {
					unsigned int size;
					unsigned int minSize = UINT_MAX;
					int minSizeIndex = 0;
					for(int i = 0; i < countPcapThreads; i++) {
						size = q[i].size();
						if(size < minSize) {
							minSize = size;
							minSizeIndex = i;
						}
					}
					((FileZipHandler*)handle)->userData = minSizeIndex + 1;
				}
			}
			if(add(new AsyncCloseItem_pcap(handle, call, file, column, writeBytes),
			       opt_pcap_dump_bufflength ?
				((FileZipHandler*)handle)->userData - 1 :
				0,
			       useThreadOper)) {
				break;
			}
		}
	}
	void addWrite(pcap_dumper_t *handle,
		      char *data, int length) {
		extern int opt_pcap_dump_bufflength;
		for(int pass = 0; pass < 2; pass++) {
			if(pass) {
				((FileZipHandler*)handle)->userData = 0;
			}
			int useThreadOper = 0;
			if(opt_pcap_dump_bufflength) {
				if(!((FileZipHandler*)handle)->userData) {
					useThreadOper = 1;
					unsigned int size;
					unsigned int minSize = UINT_MAX;
					int minSizeIndex = 0;
					for(int i = 0; i < countPcapThreads; i++) {
						size = q[i].size();
						if(size < minSize) {
							minSize = size;
							minSizeIndex = i;
						}
					}
					((FileZipHandler*)handle)->userData = minSizeIndex + 1;
				}
			}
			if(add(new AsyncWriteItem_pcap(handle, data, length),
			       opt_pcap_dump_bufflength ?
				((FileZipHandler*)handle)->userData - 1 :
				0,
			       useThreadOper)) {
				break;
			}
		}
	}
	void add(FileZipHandler *handle,
		 Call *call = NULL, const char *file = NULL,
		 const char *column = NULL, long long writeBytes = 0) {
		for(int pass = 0; pass < 2; pass++) {
			if(pass) {
				handle->userData = 0;
			}
			int useThreadOper = 0;
			if(handle->userData) {
				useThreadOper = -1;
			} else {
				unsigned int size;
				unsigned int minSize = UINT_MAX;
				int minSizeIndex = 0;
				for(int i = 0; i < countPcapThreads; i++) {
					size = q[i].size();
					if(size < minSize) {
						minSize = size;
						minSizeIndex = i;
					}
				}
				handle->userData = minSizeIndex + 1;
			}
			if(add(new AsyncCloseItem_fileZipHandler(handle, call, file, column, writeBytes),
			       handle->userData - 1,
			       useThreadOper)) {
				break;
			}
		}
	}
	void addWrite(FileZipHandler *handle,
		      char *data, int length) {
		for(int pass = 0; pass < 2; pass++) {
			if(pass) {
				handle->userData = 0;
			}
			int useThreadOper = 0;
			if(!handle->userData) {
				useThreadOper = 1;
				unsigned int size;
				unsigned int minSize = UINT_MAX;
				int minSizeIndex = 0;
				for(int i = 0; i < countPcapThreads; i++) {
					size = q[i].size();
					if(size < minSize) {
						minSize = size;
						minSizeIndex = i;
					}
				}
				handle->userData = minSizeIndex + 1;
			}
			if(add(new AsyncWriteItem_fileZipHandler(handle, data, length),
			       handle->userData - 1,
			       useThreadOper)) {
				break;
			}
		}
	}
	bool add(AsyncCloseItem *item, int threadIndex, int useThreadOper = 0) {
		extern int terminating;
		extern int opt_pcap_dump_asyncwrite_maxsize;
		while(sizeOfDataInMemory + item->dataLength > opt_pcap_dump_asyncwrite_maxsize * 1024ull * 1024ull && !terminating) {
			usleep(1000);
		}
		lock(threadIndex);
		if(!activeThread[threadIndex]) {
			unlock(threadIndex);
			return(false);
		}
		if(useThreadOper) {
			useThread[threadIndex] += useThreadOper;
		}
		q[threadIndex].push(item);
		add_sizeOfDataInMemory(item->dataLength);
		unlock(threadIndex);
		return(true);
	}
	void processTask(int threadIndex);
	void processAll(int threadIndex);
	void processAll() {
		for(int i = 0; i < getCountThreads(); i++) {
			processAll(i);
		}
	}
	void preparePstatData(int threadIndex);
	double getCpuUsagePerc(int threadIndex, bool preparePstatData = false);
	int getCountThreads() {
		return(countPcapThreads);
	}
	u_int64_t getSizeOfDataInMemory() {
		return(sizeOfDataInMemory);
	}
private:
	void lock(int threadIndex) {
		while(__sync_lock_test_and_set(&this->_sync[threadIndex], 1)) {
			usleep(10);
		}
	}
	void unlock(int threadIndex) {
		__sync_lock_release(&this->_sync[threadIndex]);
	}
	void add_sizeOfDataInMemory(size_t size) {
		__sync_fetch_and_add(&this->sizeOfDataInMemory, size);
	}
	void sub_sizeOfDataInMemory(size_t size) {
		__sync_fetch_and_sub(&this->sizeOfDataInMemory, size);
	}
private:
	int maxPcapThreads;
	int minPcapThreads;
	volatile int countPcapThreads;
	queue<AsyncCloseItem*> q[AsyncClose_maxPcapThreads];
	pthread_t thread[AsyncClose_maxPcapThreads];
	volatile int _sync[AsyncClose_maxPcapThreads];
	int threadId[AsyncClose_maxPcapThreads];
	pstat_data threadPstatData[AsyncClose_maxPcapThreads][2];
	StartThreadData startThreadData[AsyncClose_maxPcapThreads];
	volatile uint64_t sizeOfDataInMemory;
	volatile int removeThreadProcessed;
	volatile uint64_t useThread[AsyncClose_maxPcapThreads];
	volatile int activeThread[AsyncClose_maxPcapThreads];
	volatile int cpuPeak[AsyncClose_maxPcapThreads];
};

class RestartUpgrade {
public:
	RestartUpgrade(bool upgrade = false, const char *version = NULL, const char *url = NULL, const char *md5_32 = NULL, const char *md5_64 = NULL);
	bool runUpgrade();
	bool createRestartScript();
	bool checkReadyRestart();
	bool runRestart(int socket1, int socket2);
	bool isOk();
	string getErrorString();
	string getRsltString();
private:
	bool getUpgradeTempFileName();
	bool getRestartTempScriptFileName();
private:
	bool upgrade;
	string version;
	string url;
	string md5_32;
	string md5_64;
	string upgradeTempFileName;
	string restartTempScriptFileName;
	string errorString;
	bool _64bit;
};

std::string pexec(char*);

class IP {
public:
	IP(uint ip, uint mask_length = 32) {
		this->ip = ip;
		this->mask_length = mask_length;
	}
	IP(const char *ip) {
		char *maskSeparator =(char*)strchr(ip, '/');
		if(maskSeparator) {
			mask_length = atoi(maskSeparator + 1);
			*maskSeparator = 0;
			in_addr ips;
			inet_aton(ip, &ips);
			this->ip = htonl(ips.s_addr);
			*maskSeparator = '/';
		} else {
			in_addr ips;
			inet_aton(ip, &ips);
			this->ip = htonl(ips.s_addr);
			mask_length = 32;
			for(int i = 0; i < 32; i++) {
				if(this->ip == this->ip >> i << i) {
					mask_length = 32 - i;
				} else {
					break;
				}
			}
		}
	}
	bool checkIP(uint check_ip) {
		if(!mask_length || mask_length == 32) {
			return(check_ip == ip);
		} else {
			return(ip == check_ip >> (32 - mask_length) << (32 - mask_length));
		}
	}
	bool checkIP(const char *check_ip) {
		in_addr ips;
		inet_aton(check_ip, &ips);
		return(checkIP(htonl(ips.s_addr)));
	}
public:
	uint ip;
	uint mask_length;
};

class PhoneNumber {
public:
	PhoneNumber(const char *number, bool prefix = true) {
		this->number = number;
		this->prefix = prefix;
		this->lengthPrefix = prefix ? strlen(number) : 0;
	}
	bool checkNumber(const char *check_number) {
		if(prefix) {
			return(!strncmp(check_number, number.c_str(), lengthPrefix));
		} else {
			return(check_number == number);
		}
	}
public:
	std::string number;
	bool prefix;
	uint lengthPrefix;
};

class ListIP {
public:
	ListIP(bool autoLock = true) {
		this->autoLock = autoLock;
		_sync = 0;
	}
	void add(uint ip, uint mask_length = 32) {
		if(autoLock) lock();
		listIP.push_back(IP(ip, mask_length));
		if(autoLock) unlock();
	}
	void add(const char *ip) {
		if(autoLock) lock();
		listIP.push_back(IP(ip));
		if(autoLock) unlock();
	}
	void addComb(string &ip);
	void addComb(const char *ip);
	bool checkIP(uint check_ip) {
		bool rslt =  false;
		if(autoLock) lock();
		for(size_t i = 0; i < listIP.size(); i++) {
			if(listIP[i].checkIP(check_ip)) {
				rslt = true;
				break;
			}
		}
		if(autoLock) unlock();
		return(rslt);
	}
	bool checkIP(const char *check_ip) {
		in_addr ips;
		inet_aton(check_ip, &ips);
		return(checkIP(htonl(ips.s_addr)));
	}
	void clear() {
		if(autoLock) lock();
		listIP.clear();
		if(autoLock) unlock();
	}
	size_t size() {
		return(listIP.size());
	}
	void lock() {
		while(__sync_lock_test_and_set(&this->_sync, 1));
	}
	void unlock() {
		__sync_lock_release(&this->_sync);
	}
private:
	std::vector<IP> listIP;
	bool autoLock;
	volatile int _sync;
};

class ListPhoneNumber {
public:
	ListPhoneNumber(bool autoLock = true) {
		this->autoLock = autoLock;
		_sync = 0;
	}
	void add(const char *number, bool prefix = true) {
		if(autoLock) lock();
		listPhoneNumber.push_back(PhoneNumber(number, prefix));
		if(autoLock) unlock();
	}
	void addComb(string &number);
	void addComb(const char *number);
	bool checkNumber(const char *check_number) {
		bool rslt =  false;
		if(autoLock) lock();
		for(size_t i = 0; i < listPhoneNumber.size(); i++) {
			if(listPhoneNumber[i].checkNumber(check_number)) {
				rslt = true;
				break;
			}
		}
		if(autoLock) unlock();
		return(rslt);
	}
	void clear() {
		if(autoLock) lock();
		listPhoneNumber.clear();
		if(autoLock) unlock();
	}
	size_t size() {
		return(listPhoneNumber.size());
	}
	void lock() {
		while(__sync_lock_test_and_set(&this->_sync, 1));
	}
	void unlock() {
		__sync_lock_release(&this->_sync);
	}
private:
	std::vector<PhoneNumber> listPhoneNumber;
	bool autoLock;
	volatile int _sync;
};

class ListIP_wb {
public:
	ListIP_wb(bool autoLock = true);
	void addWhite(string &ip);
	void addWhite(const char *ip);
	void addBlack(string &ip);
	void addBlack(const char *ip);
	bool checkIP(uint check_ip) {
		return((!white.size() || white.checkIP(check_ip)) &&
		       !black.checkIP(check_ip));
	}
	bool checkIP(const char *check_ip) {
		in_addr ips;
		inet_aton(check_ip, &ips);
		return(checkIP(htonl(ips.s_addr)));
	}
private:
	ListIP white;
	ListIP black;
};

class ListPhoneNumber_wb {
public:
	ListPhoneNumber_wb(bool autoLock = true);
	void addWhite(string &number);
	void addWhite(const char *number);
	void addBlack(string &number);
	void addBlack(const char *number);
	bool checkNumber(const char *check_number) {
		return((!white.size() || white.checkNumber(check_number)) &&
		       !black.checkNumber(check_number));
	}
private:
	ListPhoneNumber white;
	ListPhoneNumber black;
};

class ParsePacket {
public:
	struct ppContent {
		ppContent() {
			content = NULL;
			length = 0;
			isContentLength = false;
		}
		void trim() {
			if(length <= 0) {
				content = NULL;
				length = 0;
			} else {
				while(length && content[length - 1] == ' ') {
					--length;
				}
				while(length && content[0] == ' ') {
					++content;
					--length;
				}
			}
		}
		const char *content;
		long length;
		bool isContentLength;
	};
	struct ppNode {
		ppNode() {
			for(int i = 0; i < 256; i++) {
				nodes[i] = 0;
			}
			leaf = false;
		}
		~ppNode() {
			for(int i = 0; i < 256; i++) {
				if(nodes[i]) {
					delete nodes[i];
				}
			}
		}
		void addNode(const char *nodeName, bool isContentLength = false) {
			while(*nodeName == '\n') {
				 ++nodeName;
			}
			if(*nodeName) {
				unsigned char nodeChar = (unsigned char)*nodeName;
				if(nodeChar >= 'A' && nodeChar <= 'Z') {
					nodeChar -= 'A' - 'a';
				}
				if(!nodes[nodeChar]) {
					nodes[nodeChar] = new ppNode;
				}
				nodes[nodeChar]->addNode(nodeName + 1, isContentLength);
			} else {
				leaf = true;
				if(isContentLength) {
					content.isContentLength = true;
				}
			}
		}
		ppContent *getContent(const char *nodeName, unsigned int *namelength, unsigned int namelength_limit = UINT_MAX) {
			if(!leaf) {
				if(!*nodeName) {
					return(NULL);
				}
				unsigned char nodeChar = (unsigned char)*nodeName;
				if(nodeChar >= 'A' && nodeChar <= 'Z') {
					nodeChar -= 'A' - 'a';
				}
				if(nodes[nodeChar]) {
					if(namelength) {
						++*namelength;
						if(*namelength > namelength_limit) {
							return(NULL);
						}
					}
					return(nodes[nodeChar]->getContent(nodeName + 1, namelength));
				} else {
					return(NULL);
				}
			} else {
				return(&content);
			}
		}
		void clear() {
			content.content = NULL;
			content.length = 0;
			for(int i = 0; i < 256; i++) {
				if(nodes[i]) {
					nodes[i]->clear();
				}
			}
		}
		void debugData(string nodeName) {
			if(leaf) {
				string _content;
				if(content.content && content.length > 0) {
					_content = string(content.content, content.length);
					if(nodeName[0] == '\n') {
						nodeName = nodeName.substr(1);
					}
					cout << nodeName << " : " << _content << " : L " << content.length << endl;
				}
			} else {
				for(int i = 0; i < 256; i++) {
					if(nodes[i]) {
						char i_str[2];
						i_str[0] = i;
						i_str[1] =0;
						nodes[i]->debugData(nodeName + i_str);
					}
				}
			}
		}
		ppNode *nodes[256];
		bool leaf;
		ppContent content;
	};
public:
	ParsePacket(bool stdParse = false) {
		doubleEndLine = NULL;
		contentLength = -1;
		parseDataPtr = NULL;
		contents_count = 0;
		sip = false;
	}
	void setStdParse() {
		addNode("content-length:", true);
		addNode("INVITE ");
		addNode("call-id:");
		addNode("i:");
		addNode("from:");
		addNode("f:");
		addNode("to:");
		addNode("t:");
		addNode("contact:");
		addNode("m:");
		addNode("remote-party-id:");
		addNode("geoposition:");
		addNode("user-agent:");
		addNode("authorization:");
		addNode("expires:");
		addNode("x-voipmonitor-norecord:");
		addNode("signal:");
		addNode("signal=");
		addNode("x-voipmonitor-custom1:");
		addNode("content-type:");
		addNode("c:");
		addNode("cseq:");
		addNode("supported:");
		addNode("proxy-authenticate:");
		addNode("m=audio ");
		addNode("a=rtpmap:");
		addNode("c=IN IP4 ");
		addNode("expires=");
		addNode("username=\"");
		addNode("realm=\"");
		
		extern char opt_match_header[128];
		if(opt_match_header[0] != '\0') {
			string findHeader = opt_match_header;
			if(findHeader[findHeader.length() - 1] != ':') {
				findHeader.append(":");
			}
			addNode(findHeader.c_str());
		}
		
		extern char opt_callidmerge_header[128];
		if(opt_callidmerge_header[0] != '\0') {
			string findHeader = opt_callidmerge_header;
			if(findHeader[findHeader.length() - 1] != ':') {
				findHeader.append(":");
			}
			addNode(findHeader.c_str());
		}
		
		extern vector<dstring> opt_custom_headers_cdr;
		extern vector<dstring> opt_custom_headers_message;
		for(int i = 0; i < 2; i++) {
			vector<dstring> *_customHeaders = i == 0 ? &opt_custom_headers_cdr : &opt_custom_headers_message;
			for(size_t iCustHeaders = 0; iCustHeaders < _customHeaders->size(); iCustHeaders++) {
				string findHeader = (*_customHeaders)[iCustHeaders][0];
				if(findHeader[findHeader.length() - 1] != ':') {
					findHeader.append(":");
				}
				addNode(findHeader.c_str());
			}
		}
		
		//RFC 3261
		addNodeCheckSip("SIP/2.0");
		addNodeCheckSip("INVITE");
		addNodeCheckSip("ACK");
		addNodeCheckSip("BYE");
		addNodeCheckSip("CANCEL");
		addNodeCheckSip("OPTIONS");
		addNodeCheckSip("REGISTER");
		//RFC 3262
		addNodeCheckSip("PRACK");
		addNodeCheckSip("SUBSCRIBE");
		addNodeCheckSip("NOTIFY");
		addNodeCheckSip("PUBLISH");
		addNodeCheckSip("INFO");
		addNodeCheckSip("REFER");
		addNodeCheckSip("MESSAGE");
		addNodeCheckSip("UPDATE");
	}
	void addNode(const char *nodeName, bool isContentLength = false) {
		root.addNode(nodeName, isContentLength);
	}
	void addNodeCheckSip(const char *nodeName) {
		rootCheckSip.addNode(nodeName);
	}
	ppContent *getContent(const char *nodeName, unsigned int *namelength = NULL, unsigned int namelength_limit = UINT_MAX) {
		if(namelength) {
			*namelength = 0;
		}
		return(root.getContent(nodeName, namelength, namelength_limit));
	}
	string getContentString(const char *nodeName) {
		while(*nodeName == '\n') {
			 ++nodeName;
		}
		ppContent *content = root.getContent(nodeName, NULL);
		if(content && content->content && content->length > 0) {
			return(string(content->content, content->length));
		} else {
			return("");
		}
	}
	const char *getContentData(const char *nodeName, long *dataLength) {
		while(*nodeName == '\n') {
			 ++nodeName;
		}
		ppContent *content = root.getContent(nodeName, NULL);
		if(content && content->content && content->length > 0) {
			if(dataLength) {
				*dataLength = content->length;
			}
			return(content->content);
		} else {
			if(dataLength) {
				*dataLength = 0;
			}
			return(NULL);
		}
	}
	bool isSipContent(const char *nodeName, unsigned int namelength_limit = UINT_MAX) {
		unsigned int namelength = 0;
		return(rootCheckSip.getContent(nodeName, &namelength, namelength_limit));
	}
	void parseData(char *data, unsigned long datalen, bool doClear = false);
	void clear() {
		for(unsigned int i = 0; i < contents_count; i++) {
			contents[i]->content = NULL;
			contents[i]->length = 0;
		}
		contents_count = 0;
		doubleEndLine = NULL;
		contentLength = -1;
		parseDataPtr = NULL;
		sip = false;
	}
	void debugData() {
		root.debugData("");
	}
	const char *getParseData() {
		return(parseDataPtr);
	}
	bool isSip() {
		return(sip);
	}
private:
	ppNode root;
	ppNode rootCheckSip;
	char *doubleEndLine;
	long contentLength;
	const char *parseDataPtr;
	ppContent *contents[100];
	unsigned int contents_count;
	bool sip;
};

class SafeAsyncQueue_base {
public:
	SafeAsyncQueue_base();
	~SafeAsyncQueue_base();
	static bool isRunTimerThread();
	static void stopTimerThread(bool wait = false);
protected:
	virtual void timerEv(unsigned long long timerCounter) = 0;
private:
	static void timerThread();
	static void lock_list_saq() {
		while(__sync_lock_test_and_set(&_sync_list_saq, 1));
	}
	static void unlock_list_saq() {
		__sync_lock_release(&_sync_list_saq);
	}
private:
	static list<SafeAsyncQueue_base*> list_saq;
	static pthread_t timer_thread;
	static unsigned long long timer_counter;
	static volatile int _sync_list_saq;
	static bool runTimerThread;
	static bool terminateTimerThread;
friend void *_SafeAsyncQueue_timerThread(void *arg);
};

template<class type_queue_item>
class SafeAsyncQueue : public SafeAsyncQueue_base {
public:
	SafeAsyncQueue(int shiftIntervalMult10S = 5);
	~SafeAsyncQueue();
	void push(type_queue_item &item);
	bool pop(type_queue_item *item, bool remove = true);
protected:
	void timerEv(unsigned long long timerCounter);
private:
	void shiftPush();
	void lock_queue() {
		while(__sync_lock_test_and_set(&_sync_queue, 1));
	}
	void unlock_queue() {
		__sync_lock_release(&_sync_queue);
	}
	void lock_push_queue() {
		while(__sync_lock_test_and_set(&_sync_push_queue, 1));
	}
	void unlock_push_queue() {
		__sync_lock_release(&_sync_push_queue);
	}
	void lock_pop_queue() {
		while(__sync_lock_test_and_set(&_sync_pop_queue, 1));
	}
	void unlock_pop_queue() {
		__sync_lock_release(&_sync_pop_queue);
	}
private:
	deque<type_queue_item> *push_queue;
	deque<type_queue_item> *pop_queue;
	deque<deque<type_queue_item>*> queue;
	int shiftIntervalMult10S;
	unsigned long long lastShiftTimerCounter;
	volatile int _sync_queue;
	volatile int _sync_push_queue;
	volatile int _sync_pop_queue;
};

template<class type_queue_item>
SafeAsyncQueue<type_queue_item>::SafeAsyncQueue(int shiftIntervalMult10S) {
	push_queue = NULL;
	pop_queue = NULL;
	this->shiftIntervalMult10S = shiftIntervalMult10S;
	lastShiftTimerCounter = 0;
	_sync_queue = 0;
	_sync_push_queue = 0;
	_sync_pop_queue = 0;
}

template<class type_queue_item>
SafeAsyncQueue<type_queue_item>::~SafeAsyncQueue() {
	lock_queue();
	lock_push_queue();
	lock_pop_queue();
	while(queue.size()) {
		delete queue.front();
		queue.pop_front();
	}
	if(push_queue) {
		delete push_queue;
	}
	if(pop_queue) {
		delete push_queue;
	}
}

template<class type_queue_item>
void SafeAsyncQueue<type_queue_item>::push(type_queue_item &item) {
	lock_push_queue();
	if(!push_queue) {
		push_queue = new deque<type_queue_item>;
	}
	push_queue->push_back(item);
	unlock_push_queue();
}

template<class type_queue_item>
bool SafeAsyncQueue<type_queue_item>::pop(type_queue_item *item, bool remove) {
	bool rslt = false;
	lock_pop_queue();
	if(!pop_queue || !pop_queue->size()) {
		if(pop_queue) {
			delete pop_queue;
			pop_queue = NULL;
		}
		lock_queue();
		if(queue.size()) {
			pop_queue = queue.front();
			queue.pop_front();
		}
		unlock_queue();
	}
	if(pop_queue && pop_queue->size()) {
		*item = pop_queue->front();
		rslt = true;
		if(remove) {
			pop_queue->pop_front();
			if(!pop_queue->size()) {
				delete pop_queue;
				pop_queue = NULL;
			}
		}
	}
	unlock_pop_queue();
	return(rslt);
}

template<class type_queue_item>
void SafeAsyncQueue<type_queue_item>::timerEv(unsigned long long timerCounter) {
	if(timerCounter - lastShiftTimerCounter >= shiftIntervalMult10S) {
		shiftPush();
		lastShiftTimerCounter = timerCounter;
	}
}

template<class type_queue_item>
void SafeAsyncQueue<type_queue_item>::shiftPush() {
	if(push_queue && push_queue->size()) {
		lock_push_queue();
		deque<type_queue_item> *_push_queue = push_queue;
		push_queue = NULL;
		unlock_push_queue();
		lock_queue();
		queue.push_back(_push_queue);
		unlock_queue();
	}
}

class JsonItem {
public:
	JsonItem(string name = "", string value = "");
	void parse(string valStr);
	JsonItem *getItem(string path, int index = -1);
	string getValue(string path, int index = -1);
	int getCount(string path);
	string getLocalName() { return(this->name); }
	string getLocalValue() { return(this->value); }
	JsonItem *getLocalItem(int index = -1) { return(index == -1 ? this : &this->items[index]); }
	size_t getLocalCount() { return(this->items.size()); }
private:
	JsonItem *getPathItem(string path);
	string getPathItemName(string path);
	string name;
	string value;
	vector<JsonItem> items;
};

class JsonExport {
public:
	enum eTypeItem {
		_number,
		_string
	};
	class JsonExportItem {
	public:
		virtual ~JsonExportItem() {}
		void setTypeItem(eTypeItem typeItem) {
			this->typeItem = typeItem;
		}
		void setName(const char *name) {
			this->name = name;
		}
		virtual string getStringItem() {
			return("");
		}
	protected:
		eTypeItem typeItem;
		string name;
	};
	template <class type_item>
	class JsonExportItem_template : public JsonExportItem {
	public:
		void setContent(type_item content) {
			this->content = content;
		}
		string getStringItem() {
			ostringstream outStr;
			outStr << '\"' << name << "\":";
			if(typeItem == _string) {
				outStr << '\"';
			}
			outStr << content;
			if(typeItem == _string) {
				outStr << '\"';
			}
			return(outStr.str());
		}
	private:
		type_item content;
	};
public:
	~JsonExport();
	string getJson();
	void add(const char *name, string content);
	void add(const char *name, const char *content);
	void add(const char *name, u_int64_t content);
private:
	vector<JsonExportItem*> items;
};

class AutoDeleteAtExit {
public:
	void add(const char *file);
	~AutoDeleteAtExit();
private:
	vector<string> files;
};

pcap_t* pcap_open_offline_zip(const char *filename, char *errbuff);
string gunzipToTemp(const char *zipFilename, string *error, bool autoDeleteAtExit);
string _gunzip_s(const char *zipFilename, const char *unzipFilename);
string __gunzip_s(FILE *zip, FILE *unzip);
int __gunzip(FILE *zip, FILE *unzip);
bool isGunzip(const char *zipFilename);

string url_encode(const string &value);

class SocketSimpleBufferWrite {
public:
	SocketSimpleBufferWrite(const char *name, ip_port ipPort, uint64_t maxSize = 100ul * 1024 * 1024);
	~SocketSimpleBufferWrite();
	void startWriteThread();
	void stopWriteThread();
	void addData(void *data1, u_int32_t dataLength1,
		     void *data2 = NULL, u_int32_t dataLength2 = 0);
private:
	void write();
	bool socketGetHost();
	bool socketConnect();
	bool socketClose();
	bool socketWrite(void *data, u_int32_t dataLength);
	void flushData();
	void lock_data() {
		while(__sync_lock_test_and_set(&this->_sync_data, 1));
	}
	void unlock_data() {
		__sync_lock_release(&this->_sync_data);
	}
	void add_size(size_t size) {
		__sync_fetch_and_add(&this->_size_all, size);
	}
	void sub_size(size_t size) {
		__sync_fetch_and_sub(&this->_size_all, size);
	}
private:
	string name;
	ip_port ipPort;
	u_int64_t maxSize;
	queue<SimpleBuffer*> data;
	hostent* socketHostEnt;
	int socketHandle;
	pthread_t writeThreadHandle;
	volatile int _sync_data;
	volatile uint64_t _size_all;
	u_long lastTimeSyslogFullData;
friend void *_SocketSimpleBufferWrite_writeFunction(void *arg);
};

#endif