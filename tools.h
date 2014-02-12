#ifndef TOOLS_H
#define TOOLS_H

#include <string>
#include <vector>
#include <sstream>
#include <utility>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <ctime>
#include <limits.h>

#include <sys/types.h>
#include <pcap.h>

#include "gzstream/gzstream.h"

using namespace std;

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
double ts2double(unsigned int sec, unsigned int usec);
long long GetFileSize(std::string filename);
long long GetFileSizeDU(std::string filename);
long long GetDU(long long fileSize);
string GetStringMD5(std::string str);
string GetFileMD5(std::string filename);
bool FileExists(char *strFilename);
void ntoa(char *res, unsigned int addr);
string escapeshellR(string &);
time_t stringToTime(const char *timeStr);
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

inline unsigned long long getTimeNS() {
    timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return(time.tv_sec * 1000000000ull + time.tv_nsec);
}

class PcapDumper {
public:
	enum eTypePcapDump {
		na,
		sip,
		rtp
	};
	PcapDumper(eTypePcapDump type, class Call *call, bool updateFilesQueueAtClose = true);
	~PcapDumper();
	bool open(const char *fileName, const char *fileNameSpoolRelative);
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
		extern int opt_gzipGRAPH;
		return(opt_gzipGRAPH ? this->streamgz.is_open() : this->stream.is_open());
	}
private:
	string fileName;
	string fileNameSpoolRelative;
	class RTP *rtp;
	bool updateFilesQueueAtClose;
	u_int64_t size;
	ofstream stream;
	ogzstream streamgz;
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
			return(check_number == number);
		} else {
			return(!strncmp(check_number, number.c_str(), lengthPrefix));
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
		return(ListPhoneNumber().size());
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

#endif
