#ifndef TOOLS_H
#define TOOLS_H

#include <pthread.h>
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
#include <iostream>
#include <zlib.h>
#ifdef HAVE_LIBLZ4
#include <lz4.h>
#endif //HAVE_LIBLZ4
#include <pcap.h>
#include <netdb.h>
#include <map>
#include <time.h>

#include "pstat.h"
#include "tools_dynamic_buffer.h"
#include "buffers_control.h"
#include "heap_safe.h"
#include "voipmonitor.h"

#include "tools_inline.h"

using namespace std;


#if defined(__i386__)
__inline__ unsigned long long rdtsc(void)
{
    unsigned long long int x;
    __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
    return x;
}
#elif defined(__x86_64__)
__inline__ unsigned long long rdtsc(void)
{
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}
#endif


struct TfileListElem {
    string filename;
    time_t mtime;
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
	bool operator == (const dstring& other) const { 
		return(this->str[0] == other.str[0] &&
		       this->str[1] == other.str[1]); 
	}
	bool operator < (const dstring& other) const { 
		return(this->str[0] < other.str[0] ||
		       (this->str[0] == other.str[0] && this->str[1] < other.str[1])); 
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
	bool operator == (const d_u_int32_t& other) const { 
		return(this->val[0] == other.val[0] &&
		       this->val[1] == other.val[1]); 
	}
	bool operator < (const d_u_int32_t& other) const { 
		return(this->val[0] < other.val[0] ||
		       (this->val[0] == other.val[0] && this->val[1] < other.val[1])); 
	}
	u_int32_t val[2];
};

template <class type_atomic>
class vm_atomic {
public:
	vm_atomic() {
		_sync = 0;
	}
	vm_atomic(vm_atomic& atomicClass) {
		_sync = 0;
		lock();
		this->atomicValue = atomicClass.atomicValue;
		unlock();
	}
	vm_atomic(type_atomic atomicValue) {
		_sync = 0;
		lock();
		this->atomicValue = atomicValue;
		unlock();
	}
	vm_atomic& operator = (const vm_atomic& atomicClass) {
		lock();
		this->atomicValue = atomicClass.atomicValue;
		unlock();
		return(*this);
	}
	vm_atomic& operator = (type_atomic atomicValue) {
		lock();
		this->atomicValue = atomicValue;
		unlock();
		return(*this);
	}
	operator type_atomic() {
		type_atomic tempAtomicValue;
		lock();
		tempAtomicValue = this->atomicValue;
		unlock();
		return(tempAtomicValue);
	}
	friend std::ostream& operator << (std::ostream& stream, vm_atomic& atomicClass) {
		type_atomic tempAtomicValue;
		atomicClass.lock();
		tempAtomicValue = atomicClass.atomicValue;
		atomicClass.unlock();
		stream << tempAtomicValue;
		return(stream);
	}
private:
	void lock() {
		while(__sync_lock_test_and_set(&this->_sync, 1)) {
			usleep(10);
		}
	}
	void unlock() {
		__sync_lock_release(&this->_sync);
	}
private:
	type_atomic atomicValue;
	volatile int _sync;
};

queue<string> listFilesDir(char * dir);
vector<string> explode(const string&, const char&);
int getUpdDifTime(struct timeval *before);
int getDifTime(struct timeval *before);
int msleep(long msec);
int file_exists (string filename);
int file_exists (char * fileName);
int file_exists (const char * fileName);
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
	SimpleBuffer(void *data, u_int32_t dataLength, u_int32_t capacityReserve = 0) {
		buffer = NULL;
		bufferLength = 0;
		bufferCapacity = 0;
		this->capacityReserve = capacityReserve;
		add(data, dataLength);
	}
	SimpleBuffer(const SimpleBuffer &other) {
		this->bufferLength = other.bufferLength;
		this->bufferCapacity = other.bufferCapacity;
		this->capacityReserve = other.capacityReserve;
		if(this->bufferLength) {
			this->buffer = new FILE_LINE u_char[this->bufferCapacity];
			memcpy(this->buffer, other.buffer, this->bufferLength);
		} else { 
			this->buffer = NULL;
		}
	}
	~SimpleBuffer() {
		destroy();
	}
	void add(void *data, u_int32_t dataLength) {
		if(!data || !dataLength) {
			return;
		}
		if(!buffer) {
			buffer = new FILE_LINE u_char[dataLength + capacityReserve + 1];
			bufferCapacity = dataLength + capacityReserve + 1;
		} else if(bufferLength + dataLength + 1 > capacityReserve) {
			u_char *bufferNew = new FILE_LINE u_char[bufferLength + dataLength + capacityReserve + 1];
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
			buffer = NULL;
		}
		bufferLength = 0;
		bufferCapacity = 0;
	}
	bool empty() {
		return(bufferLength == 0);
	}
	bool removeDataFromLeft(u_int32_t removeSize) {
		if(removeSize > bufferLength) {
			return(false);
		} else if(removeSize == bufferLength) {
			destroy();
		} else {
			u_char *bufferNew = new u_char[bufferCapacity];
			bufferLength -= removeSize;
			memcpy(bufferNew, buffer + removeSize, bufferLength);
			delete [] buffer;
			buffer = bufferNew;
		}
		return(true);
	}
	SimpleBuffer& operator = (const SimpleBuffer &other) {
		destroy();
		this->bufferLength = other.bufferLength;
		this->bufferCapacity = other.bufferCapacity;
		this->capacityReserve = other.capacityReserve;
		if(this->bufferLength) {
			this->buffer = new FILE_LINE u_char[this->bufferCapacity];
			memcpy(this->buffer, other.buffer, this->bufferLength);
		} else { 
			this->buffer = NULL;
		}
		return(*this);
	}
	operator char*() {
		if(bufferLength == 0) {
			return((char*)"");
		} else {
			if(bufferCapacity <= bufferLength) {
				u_char *newBuffer = new FILE_LINE u_char[bufferLength + 1];
				memcpy(newBuffer, buffer, bufferLength);
				delete [] buffer;
				buffer = newBuffer;
				bufferCapacity = bufferLength + 1;
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
string GetDataMD5(u_char *data, u_int32_t datalen);
string GetDataMD5(u_char *data, u_int32_t datalen,
		  u_char *data2, u_int32_t data2len,
		  u_char *data3 = NULL, u_int32_t data3len = 0);
string GetStringSHA256(std::string str);
bool DirExists(char *strFilename);
bool FileExists(char *strFilename, int *error_code = NULL);
void ntoa(char *res, unsigned int addr);
string escapeshellR(string &);
time_t stringToTime(const char *timeStr);
struct tm getDateTime(u_int64_t us);
struct tm getDateTime(time_t time);
struct tm getDateTime(const char *timeStr);
unsigned int getNumberOfDayToNow(const char *date);
string getActDateTimeF(bool useT_symbol = false);
unsigned long getUptime();
std::string &trim(std::string &s, const char *trimChars = NULL);
std::string trim_str(std::string s, const char *trimChars = NULL);
std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems);
std::vector<std::string> split(const std::string &s, char delim);
std::vector<std::string> split(const char *s, const char *delim, bool enableTrim = false);
std::vector<std::string> split(const char *s, std::vector<std::string> delim, bool enableTrim = false);
int reg_match(const char *string, const char *pattern, const char *file = NULL, int line = 0);
string reg_replace(const char *string, const char *pattern, const char *replace, const char *file = NULL, int line = 0);
string inet_ntostring(u_int32_t ip);
void base64_init(void);
int base64decode(unsigned char *dst, const char *src, int max);
void find_and_replace(string &source, const string find, string replace);
string find_and_replace(const char *source, const char *find, const char *replace);
bool isLocalIP(u_int32_t ip);
char *strlwr(char *string, u_int32_t maxLength = 0);
string intToString(int i);
string intToString(u_int64_t i);

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
	void clear() {
		ip = "";
		port = 0;
	}
	operator int() {
		return(ip.length() && port);
	}
	std::string ip;
	int port;
};

inline u_long getTimeS(pcap_pkthdr* header = NULL) {
    if(header) {
         return(header->ts.tv_sec);
    }
    timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return(time.tv_sec);
}

inline u_long getTimeMS(pcap_pkthdr* header = NULL) {
    if(header) {
         return(header->ts.tv_sec * 1000ul + header->ts.tv_usec / 1000);
    }
    timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return(time.tv_sec * 1000ul + time.tv_nsec / 1000000);
}

extern u_int64_t rdtsc_by_100ms;
inline u_long getTimeMS_rdtsc(pcap_pkthdr* header = NULL) {
    if(header) {
         return(header->ts.tv_sec * 1000ul + header->ts.tv_usec / 1000);
    }
    static u_long last_time;
    #if defined(__i386__) or defined(__x86_64__)
    static u_int32_t counter = 0;
    static u_int64_t last_rdtsc = 0;
    ++counter;
    if(rdtsc_by_100ms) {
         u_int64_t act_rdtsc = rdtsc();
         if(counter % 100 && last_rdtsc && last_time) {
             u_int64_t diff_rdtsc = act_rdtsc - last_rdtsc;
             if(diff_rdtsc < rdtsc_by_100ms / 10) {
                  last_rdtsc = act_rdtsc;
                  last_time = last_time + diff_rdtsc * 100 / rdtsc_by_100ms;
                  return(last_time);
             }
         }
         last_rdtsc = act_rdtsc;
    }
    #endif
    timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    last_time = time.tv_sec * 1000ul + time.tv_nsec / 1000000;
    return(last_time);
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

class FileZipHandler : public CompressStream_baseEv {
public:
	enum eTypeFile {
		na,
		pcap_sip,
		pcap_rtp,
		graph_rtp
	};
	enum eTypeCompress {
		compress_na,
		compress_default,
		gzip,
		snappy,
		lzo
	};
public:
	FileZipHandler(int bufferLength = 0, int enableAsyncWrite = 0, eTypeCompress typeCompress = compress_na,
		       bool dumpHandler = false, class Call *call = NULL,
		       eTypeFile typeFile = na);
	virtual ~FileZipHandler();
	bool open(const char *fileName, int permission = 0666);
	void close();
	bool write(char *data, int length, bool isHeader = false) {
		if(!isHeader && length) {
			existsData = true;
		}
		return(this->buffer ?
			this->writeToBuffer(data, length) :
			this->writeToFile(data, length));
	}
	bool flushBuffer(bool force = false);
	void flushTarBuffer();
	bool writeToBuffer(char *data, int length);
	bool writeToFile(char *data, int length, bool force = false);
	bool _writeToFile(char *data, int length, bool flush = false);
	bool _writeReady() {
		if(tarBuffer) {
			return(!tarBuffer->isFull());
		} else {
			return(true);
		}
	}
	bool __writeToFile(char *data, int length);
	//bool initZip();
	//bool initLz4();
	void initCompress();
	void initTarbuffer(bool useFileZipHandlerCompress = false);
	bool _open();
	void setError(const char *error = NULL);
	bool okHandle() {
		return(this->tar ? true : fh > 0);
	}
	static eTypeCompress convTypeCompress(const char *typeCompress);
	static const char *convTypeCompress(eTypeCompress typeCompress);
	static string getConfigMenuString();
private:
	virtual bool compress_ev(char *data, u_int32_t len, u_int32_t decompress_len, bool format_data = false);
	void setTypeCompressDefault();
public:
	string fileName;
	int permission;
	int fh;
	bool tar;
	CompressStream *compressStream;
	string error;
	int bufferLength;
	char *buffer;
	int useBufferLength;
	ChunkBuffer *tarBuffer;
	bool tarBufferCreated;
	bool enableAsyncWrite;
	eTypeCompress typeCompress;
	bool dumpHandler;
	Call *call;
	int time;
	u_int64_t size;
	bool existsData;
	u_int64_t counter;
	static u_int64_t scounter;
	u_int32_t userData;
	eTypeFile typeFile;
};

class PcapDumper {
public:
	enum eTypePcapDump {
		na,
		sip,
		rtp
	};
	enum eState {
		state_na,
		state_open,
		state_dump,
		state_do_close,
		state_close
	};
	PcapDumper(eTypePcapDump type = na, class Call *call = NULL);
	~PcapDumper();
	void setBuffLength(int bufflength) {
		_bufflength = bufflength;
	}
	void setEnableAsyncWrite(int asyncwrite) {
		_asyncwrite = asyncwrite;
	}
	void setTypeCompress(FileZipHandler::eTypeCompress typeCompress) {
		_typeCompress = typeCompress;
	}
	bool open(const char *fileName, const char *fileNameSpoolRelative, pcap_t *useHandle, int useDlt);
	bool open(const char *fileName, int dlt) {
		return(this->open(fileName, NULL, NULL, dlt));
	}
	void dump(pcap_pkthdr* header, const u_char *packet, int dlt, bool allPackets = false, 
		  u_char *data = NULL, unsigned int datalen = 0,
		  unsigned int saddr = 0, unsigned int daddr = 0, int source = 0, int dest = 0,
		  bool istcp = false);
	void close(bool updateFilesQueue = true);
	void flush();
	void remove();
	bool isOpen() {
		return(this->handle != NULL);
	}
	bool isClose() {
		return(this->state == state_na || this->state == state_close);
	}
	bool isExistsContent() {
		return(this->existsContent);
	}
	void setStateClose() {
		this->state = state_close;
	}
private:
	string fileName;
	string fileNameSpoolRelative;
	eTypePcapDump type;
	class Call *call;
	u_int64_t capsize;
	u_int64_t size;
	pcap_dumper_t *handle;
	bool openError;
	int openAttempts;
	eState state;
	bool existsContent;
	int dlt;
	u_long lastTimeSyslog;
	int _bufflength;
	int _asyncwrite;
	FileZipHandler::eTypeCompress _typeCompress;
};

pcap_dumper_t *__pcap_dump_open(pcap_t *p, const char *fname, int linktype, string *errorString = NULL,
				int _bufflength = -1 , int _asyncwrite = -1, FileZipHandler::eTypeCompress _typeCompress = FileZipHandler::compress_na,
				Call *call = NULL, PcapDumper::eTypePcapDump type = PcapDumper::na);
void __pcap_dump(u_char *user, const struct pcap_pkthdr *h, const u_char *sp, bool allPackets = false);
void __pcap_dump_close(pcap_dumper_t *p);
void __pcap_dump_flush(pcap_dumper_t *p);
char *__pcap_geterr(pcap_t *p, pcap_dumper_t *pd = NULL);
void createSimpleUdpDataPacket(u_int header_ip_offset, pcap_pkthdr **header, u_char **packet,
			       u_char *source_packet, u_char *data, unsigned int datalen,
			       unsigned int saddr, unsigned int daddr, int source, int dest,
			       u_int32_t time_sec, u_int32_t time_usec);

class RtpGraphSaver {
public:
	RtpGraphSaver(class RTP *rtp);
	~RtpGraphSaver();
	bool open(const char *fileName, const char *fileNameSpoolRelative);
	void auto_open(const char *fileName, const char *fileNameSpoolRelative);
	void write(char *buffer, int length);
	void close(bool updateFilesQueue = true);
	void clearAutoOpen();
	bool isOpen() {
		return(this->handle != NULL);
	}
	bool isOpenOrEnableAutoOpen() {
		return(isOpen() || this->enableAutoOpen);
	}
	bool isClose() {
		return(!this->enableAutoOpen && this->handle == NULL);
	}
	bool isExistsContent() {
		return(this->existsContent);
	}
private:
	string fileName;
	string fileNameSpoolRelative;
	class RTP *rtp;
	FileZipHandler *handle;
	bool existsContent;
	bool enableAutoOpen;
	int _asyncwrite;
};

#define AsyncClose_maxPcapThreads 32

class AsyncClose {
public:
	class AsyncCloseItem {
	public:
		AsyncCloseItem(Call *call = NULL, PcapDumper *pcapDumper = NULL, const char *file = NULL,
			       const char *column = NULL, long long writeBytes = 0);
		virtual ~AsyncCloseItem() {}
		virtual void process() = 0;
		virtual bool process_ready() = 0;
		virtual void processClose() {}
		virtual FileZipHandler *getHandler() = 0;
	protected:
		void addtofilesqueue();
	protected:
		Call *call;
		string call_dirnamesqlfiles;
		PcapDumper *pcapDumper;
		string file;
		string column;
		long long writeBytes;
		int dataLength;
	friend class AsyncClose;
	};
	class AsyncCloseItem_pcap : public AsyncCloseItem {
	public:
		AsyncCloseItem_pcap(pcap_dumper_t *handle, bool updateFilesQueue = false,
				    Call *call = NULL, PcapDumper *pcapDumper = NULL, const char *file = NULL,
				    const char *column = NULL, long long writeBytes = 0)
		 : AsyncCloseItem(call, pcapDumper, file, column, writeBytes) {
			this->handle = handle;
			this->updateFilesQueue = updateFilesQueue;
			extern int opt_pcap_dump_bufflength;
			if(opt_pcap_dump_bufflength) {
				this->dataLength = ((FileZipHandler*)handle)->useBufferLength;
			}
		}
		void process() {
			__pcap_dump_close(handle);
			if(updateFilesQueue) {
				this->addtofilesqueue();
			}
			if(pcapDumper) {
				pcapDumper->setStateClose();
			}
		}
		bool process_ready() {
			return(true);
		}
		void processClose() {
			__pcap_dump_close(handle);
		}
		FileZipHandler *getHandler() {
			return((FileZipHandler*)handle);
		}
	private:
		pcap_dumper_t *handle;
		bool updateFilesQueue;
	};
	class AsyncWriteItem_pcap : public AsyncCloseItem {
	public:
		AsyncWriteItem_pcap(pcap_dumper_t *handle,
				    char *data, int length) {
			this->handle = handle;
			this->data = new FILE_LINE char[length];
			memcpy(this->data, data, length);
			this->dataLength = length;
		}
		~AsyncWriteItem_pcap() {
			delete [] data;
		}
		void process() {
			((FileZipHandler*)handle)->_writeToFile(data, dataLength);
		}
		bool process_ready() {
			return(((FileZipHandler*)handle)->_writeReady());
		}
		FileZipHandler *getHandler() {
			return((FileZipHandler*)handle);
		}
	private:
		pcap_dumper_t *handle;
		char *data;
	};
	class AsyncCloseItem_fileZipHandler  : public AsyncCloseItem{
	public:
		AsyncCloseItem_fileZipHandler(FileZipHandler *handle, bool updateFilesQueue = false,
					      Call *call = NULL, const char *file = NULL,
					      const char *column = NULL, long long writeBytes = 0)
		 : AsyncCloseItem(call, NULL, file, column, writeBytes) {
			this->handle = handle;
			this->updateFilesQueue = updateFilesQueue;
			this->dataLength = handle->useBufferLength;
		}
		void process() {
			handle->close();
			delete handle;
			if(this->updateFilesQueue) {
				this->addtofilesqueue();
			}
		}
		bool process_ready() {
			return(true);
		}
		void processClose() {
			handle->close();
			delete handle;
		}
		FileZipHandler *getHandler() {
			return(handle);
		}
	private:
		FileZipHandler *handle;
		bool updateFilesQueue;
	};
	class AsyncWriteItem_fileZipHandler : public AsyncCloseItem {
	public:
		AsyncWriteItem_fileZipHandler(FileZipHandler *handle,
					      char *data, int length) {
			this->handle = handle;
			this->data = new FILE_LINE char[length];
			memcpy(this->data, data, length);
			this->dataLength = length;
		}
		~AsyncWriteItem_fileZipHandler() {
			delete [] data;
		}
		void process() {
			handle->_writeToFile(data, dataLength);
		}
		bool process_ready() {
			return(handle->_writeReady());
		}
		FileZipHandler *getHandler() {
			return(handle);
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
	void add(pcap_dumper_t *handle, bool updateFilesQueue = false,
		 Call *call = NULL, PcapDumper *pcapDumper = NULL, const char *file = NULL,
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
			if(add(new FILE_LINE AsyncCloseItem_pcap(handle, updateFilesQueue, call, pcapDumper, file, column, writeBytes),
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
			if(add(new FILE_LINE AsyncWriteItem_pcap(handle, data, length),
			       opt_pcap_dump_bufflength ?
				((FileZipHandler*)handle)->userData - 1 :
				0,
			       useThreadOper)) {
				break;
			}
		}
	}
	void add(FileZipHandler *handle, bool updateFilesQueue = false,
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
			if(add(new FILE_LINE AsyncCloseItem_fileZipHandler(handle, updateFilesQueue, call, file, column, writeBytes),
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
			if(add(new FILE_LINE AsyncWriteItem_fileZipHandler(handle, data, length),
			       handle->userData - 1,
			       useThreadOper)) {
				break;
			}
		}
	}
	bool add(AsyncCloseItem *item, int threadIndex, int useThreadOper = 0) {
		extern cBuffersControl buffersControl;
		while(!buffersControl.check__AsyncClose__add(item->dataLength) && !is_terminating()) {
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
		q[threadIndex].push_back(item);
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
	void safeTerminate();
	void preparePstatData(int threadIndex);
	double getCpuUsagePerc(int threadIndex, bool preparePstatData = false);
	int getCountThreads() {
		return(countPcapThreads);
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
		extern cBuffersControl buffersControl;
		buffersControl.add__AsyncClose__sizeOfDataInMemory(size);
	}
	void sub_sizeOfDataInMemory(size_t size) {
		extern cBuffersControl buffersControl;
		buffersControl.sub__AsyncClose__sizeOfDataInMemory(size);
	}
private:
	int maxPcapThreads;
	int minPcapThreads;
	volatile int countPcapThreads;
	deque<AsyncCloseItem*> q[AsyncClose_maxPcapThreads];
	pthread_t thread[AsyncClose_maxPcapThreads];
	volatile int _sync[AsyncClose_maxPcapThreads];
	int threadId[AsyncClose_maxPcapThreads];
	pstat_data threadPstatData[AsyncClose_maxPcapThreads][2];
	StartThreadData startThreadData[AsyncClose_maxPcapThreads];
	volatile int removeThreadProcessed;
	volatile uint64_t useThread[AsyncClose_maxPcapThreads];
	volatile int activeThread[AsyncClose_maxPcapThreads];
	volatile int cpuPeak[AsyncClose_maxPcapThreads];
};

class RestartUpgrade {
public:
	RestartUpgrade(bool upgrade = false, const char *version = NULL, const char *url = NULL, 
		       const char *md5_32 = NULL, const char *md5_64 = NULL, const char *md5_arm = NULL);
	bool runUpgrade();
	bool createRestartScript();
	bool checkReadyRestart();
	bool runRestart(int socket1, int socket2);
	bool runGitUpgrade(const char *cmd);
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
	string md5_arm;
	string upgradeTempFileName;
	string restartTempScriptFileName;
	string errorString;
	bool _64bit;
	bool _arm;
};

std::string pexec(char*, int *exitCode = NULL);

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

class UA {
public:
	UA(const char *ua) {
		this->ua = ua;
		if(this->ua.length() && this->ua[0] == '%') {
			this->ua = this->ua.substr(1);
			this->boundLeft = false;
		} else {
			this->boundLeft = true;
		}
		if(this->ua.length() && this->ua[this->ua.length() - 1] == '%') {
			this->ua = this->ua.substr(0, this->ua.length() - 1);
			this->boundRight = false;
		} else {
			this->boundRight = true;
		}
		this->ua_length = this->ua.length();
	}
	bool checkUA(const char *ua) {
		if(!this->ua_length) {
			return(false);
		}
		if(this->boundLeft && this->boundRight) {
			return(!strcasecmp(ua, this->ua.c_str()));
		} else if(this->boundLeft) {
			return(!strncasecmp(ua, this->ua.c_str(), this->ua_length));
		} else if(this->boundRight) {
			uint length = strlen(ua);
			if(length >= this->ua_length) {
				return(!strcasecmp(ua + length - this->ua_length, this->ua.c_str()));
			} else {
				return(false);
			}
		} else {
			return(strcasestr(ua, this->ua.c_str()));
		}
	}
public:
	std::string ua;
	uint ua_length;
	bool boundLeft;
	bool boundRight;
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
	void addComb(string &ip, ListIP *negList = NULL);
	void addComb(const char *ip, ListIP *negList = NULL);
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
	void addComb(string &number, ListPhoneNumber *negList = NULL);
	void addComb(const char *number, ListPhoneNumber *negList = NULL);
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

class ListUA {
public:
	ListUA(bool autoLock = true) {
		this->autoLock = autoLock;
		_sync = 0;
	}
	void add(const char *ua) {
		if(autoLock) lock();
		listUA.push_back(UA(ua));
		if(autoLock) unlock();
	}
	void addComb(string &ua, ListUA *negList = NULL);
	void addComb(const char *ua, ListUA *negList = NULL);
	bool checkUA(const char *check_ua) {
		bool rslt =  false;
		if(autoLock) lock();
		for(size_t i = 0; i < listUA.size(); i++) {
			if(listUA[i].checkUA(check_ua)) {
				rslt = true;
				break;
			}
		}
		if(autoLock) unlock();
		return(rslt);
	}
	void clear() {
		if(autoLock) lock();
		listUA.clear();
		if(autoLock) unlock();
	}
	size_t size() {
		return(listUA.size());
	}
	void lock() {
		while(__sync_lock_test_and_set(&this->_sync, 1));
	}
	void unlock() {
		__sync_lock_release(&this->_sync);
	}
private:
	std::vector<UA> listUA;
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

class ListUA_wb {
public:
	ListUA_wb(bool autoLock = true);
	void addWhite(string &ua);
	void addWhite(const char *ua);
	void addBlack(string &ua);
	void addBlack(const char *ua);
	bool checkUA(const char *check_ua) {
		return((!white.size() || white.checkUA(check_ua)) &&
		       !black.checkUA(check_ua));
	}
private:
	ListUA white;
	ListUA black;
};

#define ParsePacket_std_max 100
#define ParsePacket_custom_max 100

class ParsePacket {
public:
	enum eTypeNode {
		typeNode_std,
		typeNode_checkSip,
		typeNode_custom
	};
	struct ppContentItemX {
		ppContentItemX() {
			offset = 0;
			length = 0;
		}
		void trim(const char *data) {
			while(length && data[offset + length - 1] == ' ') {
				--length;
			}
			while(length && data[offset] == ' ') {
				++offset;
				--length;
			}
		}
		u_int32_t offset;
		u_int32_t length;
	};
	struct ppContentsX {
		ppContentsX(ParsePacket *parser) {
			this->parser = parser;
			clean();
		}
		void clean() {
			memset(&std, 0, sizeof(std));
			memset(&custom, 0, sizeof(custom));
			doubleEndLine = NULL;
			contentLength = -1;
			parseDataPtr = NULL;
			sip = false;
		}
		u_int32_t parse(char *data, unsigned long datalen, bool clean) {
			if(clean) {
				this->clean();
			}
			return(this->parser->parseData(data, datalen, this));
		}
		const char *getContentData(const char *nodeName, u_int32_t *dataLength) {
			while(*nodeName == '\n') {
				++nodeName;
			}
			ppNode *node = parser->getNode(nodeName, 0, NULL);
			if(node) {
				ppContentItemX *contentItem = node->getPointerToItem(this);
				if(contentItem->length) {
					*dataLength = contentItem->length;
					return(parseDataPtr + contentItem->offset);
				}
			}
			*dataLength = 0;
			return(NULL);
		}
		std::string getContentString(const char *nodeName) {
			u_int32_t dataLength = 0;
			const char *contentData = getContentData(nodeName, &dataLength);
			if(contentData && dataLength) {
				return(std::string(contentData, dataLength));
			}
			return("");
		}
		const char *getParseData() {
			return(parseDataPtr);
		}
		bool isSip() {
			return(sip);
		}
		void debugData() {
			parser->debugData(this);
		}
		ppContentItemX std[ParsePacket_std_max];
		ppContentItemX custom[ParsePacket_custom_max];
		char *doubleEndLine;
		int32_t contentLength;
		const char *parseDataPtr;
		bool sip;
		ParsePacket *parser;
	};
	struct ppNode {
		ppNode();
		~ppNode();
		void addNode(const char *nodeName, eTypeNode typeNode, int nodeIndex, bool isContentLength);
		ppContentItemX *getContent(const char *nodeName, ppContentsX *contents, ppNode **node_rslt, u_int32_t *namelength_rslt = NULL, 
					   u_int32_t namelength = 0, u_int32_t namelength_limit = UINT_MAX) {
			if(!leaf) {
				if(!*nodeName) {
					return(NULL);
				}
				unsigned char nodeChar = (unsigned char)*nodeName;
				if(nodeChar >= 'A' && nodeChar <= 'Z') {
					nodeChar -= 'A' - 'a';
				}
				if(nodes[nodeChar]) {
					++namelength;
					if(namelength_limit && namelength > namelength_limit) {
						return(NULL);
					}
					ppNode *node = (ppNode*)nodes[nodeChar];
					return(node->getContent(nodeName + 1, contents, node_rslt, namelength_rslt, 
								namelength, namelength_limit));
				} else {
					return(NULL);
				}
			} else {
				if(namelength_rslt) {
					*namelength_rslt = namelength;
				}
				if(node_rslt) {
					*node_rslt = this;
				}
				if(contents) {
					switch(typeNode) {
					case typeNode_std:
						return(contents->std[nodeIndex].offset ? &contents->std[nodeIndex] : NULL);
					case typeNode_custom:
						return(contents->custom[nodeIndex].offset ? &contents->custom[nodeIndex] : NULL);
					case typeNode_checkSip:
						return(NULL);
					}
				} else {
					return((ppContentItemX*)true);
				}
			}
			return(NULL);
		}
		bool isSetNode(ppContentsX *contents) {
			return((typeNode == typeNode_std && contents->std[this->nodeIndex].length) ||
			       (typeNode == typeNode_custom && contents->custom[this->nodeIndex].length));
		}
		ppContentItemX *getPointerToItem(ppContentsX *contents) {
			return(typeNode == typeNode_std ? &contents->std[this->nodeIndex] :
			       typeNode == typeNode_custom ? &contents->custom[this->nodeIndex] : NULL);
		}
		void debugData(ppContentsX *contents, ParsePacket *parsePacket);
		volatile ppNode *nodes[256];
		bool leaf;
		eTypeNode typeNode;
		int nodeIndex;
		bool isContentLength;
	};
public:
	ParsePacket();
	~ParsePacket();
	void setStdParse();
	void addNode(const char *nodeName, eTypeNode typeNode, bool isContentLength = false);
	void addNodeCheckSip(const char *nodeName);
	ppNode *getNode(const char *data, u_int32_t datalength, u_int32_t *namelength_rslt) {
		ppNode *node;
		if(root->getContent(data, NULL, &node, namelength_rslt, 
				    0, datalength)) {
			return(node);
		}
		return(NULL);
	}
	bool isSipContent(const char *data, u_int32_t datalength) {
		if(rootCheckSip &&
		   rootCheckSip->getContent(data, NULL, NULL, NULL,
					    0, datalength)) {
			return(true);
		}
		return(false);
	}
	u_int32_t parseData(char *data, unsigned long datalen, ppContentsX *contents);
	void free();
	void debugData(ppContentsX *contents);
private:
	std::vector<string> nodesStd;
	std::vector<string> nodesCheckSip;
	std::vector<string> nodesCustom;
	ppNode *root;
	ppNode *rootCheckSip;
	unsigned long timeSync_SIP_HEADERfilter;
	unsigned long timeSync_custom_headers_cdr;
	unsigned long timeSync_custom_headers_message;
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
	deque<deque<type_queue_item>*> queueItems;
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
	while(queueItems.size()) {
		delete queueItems.front();
		queueItems.pop_front();
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
		push_queue = new FILE_LINE deque<type_queue_item>;
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
		if(queueItems.size()) {
			pop_queue = queueItems.front();
			queueItems.pop_front();
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
	if(timerCounter - lastShiftTimerCounter >= (unsigned)shiftIntervalMult10S) {
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
		queueItems.push_back(_push_queue);
		unlock_queue();
	}
}

class JsonItem {
public:
	JsonItem(string name = "", string value = "", bool null = false);
	void parse(string valStr);
	JsonItem *getItem(string path, int index = -1);
	string getValue(string path, int index = -1);
	int getCount(string path);
	string getLocalName() { return(this->name); }
	string getLocalValue() { return(this->value); }
	bool localValueIsNull() { return(this->null); }
	JsonItem *getLocalItem(int index = -1) { return(index == -1 ? this : &this->items[index]); }
	size_t getLocalCount() { return(this->items.size()); }
private:
	JsonItem *getPathItem(string path);
	string getPathItemName(string path);
	string name;
	string value;
	bool null;
	vector<JsonItem> items;
};

class JsonExport {
public:
	enum eTypeItem {
		_number,
		_string,
		_json
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
	void addJson(const char *name, const string &content);
	void addJson(const char *name, const char *content);
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
string json_encode(const char *str);
string json_encode(const string &value);

class SocketSimpleBufferWrite {
public:
	SocketSimpleBufferWrite(const char *name, ip_port ipPort, bool udp = false, uint64_t maxSize = 100ul * 1024 * 1024);
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
	bool udp;
	u_int64_t maxSize;
	queue<SimpleBuffer*> data;
	u_int32_t socketHostIPl;
	int socketHandle;
	pthread_t writeThreadHandle;
	volatile int _sync_data;
	volatile uint64_t _size_all;
	u_long lastTimeSyslogFullData;
friend void *_SocketSimpleBufferWrite_writeFunction(void *arg);
};

class BogusDumper {
public:
	BogusDumper(const char *path);
	~BogusDumper();
	void dump(pcap_pkthdr* header, u_char* packet, int dlt, const char *interfaceName);
private:
	void lock() {
		while(__sync_lock_test_and_set(&this->_sync, 1));
	}
	void unlock() {
		__sync_lock_release(&this->_sync);
	}
private:
	map<string, PcapDumper*> dumpers;
	string path;
	string time;
	volatile int _sync;
};

string base64_encode(const unsigned char *data, size_t input_length);
char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length);

inline struct tm localtime_r(const time_t *timep, const char *timezone = NULL) {
	static volatile int _sync;
	extern void *fraudAlerts;
	char oldTZ[1024] = "";
	bool lockTZ = false;
	if(fraudAlerts) {
		while(__sync_lock_test_and_set(&_sync, 1));
		if(timezone && timezone[0]) {
			const char *_oldTZ = getenv("TZ");
			if(_oldTZ) {
				strncpy(oldTZ, _oldTZ, sizeof(oldTZ));
			} else {
				oldTZ[0] = 0;
			}
			setenv("TZ", timezone, 1);
			tzset();
		}
		lockTZ = true;
	}
	struct tm rslt;
	::localtime_r(timep, &rslt);
	if(lockTZ) {
		if(timezone && timezone[0]) {
			if(oldTZ[0]) {
				setenv("TZ", oldTZ, 1);
			} else {
				unsetenv("TZ");
			}
			tzset();
		}
		__sync_lock_release(&_sync);
	}
	return(rslt);
}
inline struct tm gmtime_r(const time_t *timep) {
	struct tm rslt;
	::gmtime_r(timep, &rslt);
	return(rslt);
}
inline struct tm time_r(const time_t *timep, const char *timezone = NULL) {
	if(timezone && timezone[0]) {
		return(localtime_r(timep, timezone));
	}
	extern bool opt_sql_time_utc;
	extern bool is_cloud;
	return(opt_sql_time_utc || is_cloud ?
		gmtime_r(timep) :
		localtime_r(timep));
}

u_int32_t octal_decimal(u_int32_t n);

bool vm_pexec(const char *cmdLine, SimpleBuffer *out, SimpleBuffer *err = NULL, int *exitCode = NULL, unsigned timeout_sec = 10, unsigned timout_select_sec = 1);
std::vector<std::string> parse_cmd_line(const char *cmdLine);

u_int64_t getTotalMemory();

string ascii_str(string str);
int yesno(const char *arg);

class SensorsMap {
public:
	struct sSensorName {
		string name;
		string name_file;
	};
public:
	SensorsMap();
	void fillSensors(class SqlDb *sqlDb = NULL);
	void setSensorName(int sensorId, const char *sensorName);
	string getSensorName(int sensorId, bool file = false);
	string getSensorNameFile(int sensorId) {
		return(getSensorName(sensorId, true));
	}
private:
	void lock() {
		while(__sync_lock_test_and_set(&this->_sync, 1));
	}
	void unlock() {
		__sync_lock_release(&this->_sync);
	}
private:
	map<int, sSensorName> sensors;
	volatile int _sync;
};

void prepare_string_to_filename(char *str, unsigned int str_length = 0);

class conv7bit {
public:
	static unsigned char *encode(unsigned char *data, unsigned int length, unsigned int &rsltLength);
	static unsigned char *decode(unsigned char *data, unsigned int length, unsigned int &rsltLength);
	static unsigned int encode_length(unsigned int length);
	static unsigned int decode_length(unsigned int length);
};


class cPng {
public:
	struct pixel_hsv {
		pixel_hsv(u_int16_t h = 0, u_int8_t s = 0, u_int8_t v = 0) {
			hue = h;
			saturation = s;
			value = v;
		}
		u_int16_t hue;
		u_int8_t saturation;
		u_int8_t value;
	};
	struct pixel {
		pixel(u_int8_t r = 0, u_int8_t g = 0, u_int8_t b = 0) {
			red = r;
			green = g;
			blue = b;
		}
		void setFromHsv(pixel_hsv p_hsv);
		u_int8_t red;
		u_int8_t green;
		u_int8_t blue;
	};
public:
	cPng(size_t width, size_t height);
	~cPng();
	void setPixel(size_t x, size_t y, u_int8_t red, u_int8_t green, u_int8_t blue);
	void setPixel(size_t x, size_t y, pixel p);
	pixel getPixel(size_t x, size_t y);
	pixel *getPixelPointer(size_t x, size_t y);
	bool write(const char *filePathName, std::string *error = NULL);
	size_t getWidth() {
		return(width);
	}
	size_t getHeight() {
		return(height);
	}
private:
	size_t width;
	size_t height;
	pixel *pixels;
	int pixel_size;
	int depth;
};

bool create_waveform_from_raw(const char *rawInput,
			      size_t sampleRate, size_t msPerPixel, u_int8_t channels,
			      const char waveformOutput[][1024]);
bool create_spectrogram_from_raw(const char *rawInput,
				 size_t sampleRate, size_t msPerPixel, size_t height, u_int8_t channels,
				 const char spectrogramOutput[][1024]);

int vm_pthread_create(pthread_t *thread, pthread_attr_t *attr,
		      void *(*start_routine) (void *), void *arg, 
		      const char *src_file, int src_file_line,
		      bool autodestroy = false);
int vm_pthread_create_autodestroy(pthread_t *thread, pthread_attr_t *attr,
				  void *(*start_routine) (void *), void *arg, 
				  const char *src_file, int src_file_line) {
	return(vm_pthread_create(thread, attr,
				 start_routine, arg, 
				 src_file, src_file_line,
				 true));
}

 
#endif
