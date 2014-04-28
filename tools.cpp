#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <poll.h>
#include <unistd.h>
#include <string>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <netdb.h>
#include <resolv.h>
#include <regex.h>
#include <sys/time.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <syslog.h>
#include <sys/ioctl.h> 
#include <sys/syscall.h>
#include <sys/statvfs.h>
#include <curl/curl.h>
#include <cerrno>

#include "voipmonitor.h"

#ifdef FREEBSD
#include <sys/uio.h>
#include <sys/thr.h>
#else
#include <sys/sendfile.h>
#endif

#include <algorithm> // for std::min
#include <iostream>

#include "calltable.h"
#include "rtp.h"
#include "tools.h"
#include "md5.h"

extern char mac[32];
extern int verbosity;
extern int terminating;
extern int opt_pcap_dump_bufflength;
extern int opt_pcap_dump_asyncwrite;
extern int opt_pcap_dump_zip;
extern int opt_pcap_dump_ziplevel;


using namespace std;

AsyncClose asyncClose;


int getUpdDifTime(struct timeval *before)
{
	int dif = getDifTime(before);

	gettimeofday(before,0);

	return dif;
}

int getDifTime(struct timeval *before)
{
	struct timeval now;
	gettimeofday(&now,0);

	return (((int)now.tv_sec)*1000000+now.tv_usec) - (((int)before->tv_sec)*1000000+before->tv_usec);
}

int msleep(long msec)
{
	struct timeval tv;

	tv.tv_sec=(int)((float)msec/1000000);
	tv.tv_usec=msec-tv.tv_sec*1000000;
	return select(0,0,0,0,&tv);
}

int file_exists (char * fileName)
{
	struct stat buf;
	/* File found */
	if (stat(fileName, &buf) == 0) {
		return buf.st_size;
	}
	return 0;
}

bool FileExists(char *strFilename) {
	struct stat stFileInfo;
	int intStat;

	// Attempt to get the file attributes 
	intStat = stat(strFilename, &stFileInfo);
	if(intStat == 0) {
		// We were able to get the file attributes 
		// so the file obviously exists. 
		return true;
	} else {
		// We were not able to get the file attributes. 
		// This may mean that we don't have permission to 
		// access the folder which contains this file. If you 
		// need to do that level of checking, lookup the 
		// return values of stat which will give you 
		// more details on why stat failed. 
		return false;
	}
}

void
set_mac() {   
#ifndef FREEBSD
	int s;
	struct ifreq buffer;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if(s == -1) {
		printf("Opening socket failed\n");
		return;
	}
	memset(&buffer, 0x00, sizeof(buffer));
	strcpy(buffer.ifr_name, "eth0");
	ioctl(s, SIOCGIFHWADDR, &buffer);
	close(s);

	sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
		0xff & buffer.ifr_hwaddr.sa_data[0],
		0xff & buffer.ifr_hwaddr.sa_data[1],
		0xff & buffer.ifr_hwaddr.sa_data[2],
		0xff & buffer.ifr_hwaddr.sa_data[3],
		0xff & buffer.ifr_hwaddr.sa_data[4],
		0xff & buffer.ifr_hwaddr.sa_data[5]);
#endif
}

/*
int mkdir_r(const char* file_path, mode_t mode) {
	if(!file_path) return 0;

	char buf[1024];
	strncpy(buf, file_path, 1023);
	char *p = buf;
	for (p = buf; p; p = strchr(p + 1, '/')) {
		*p = '\0';
		mkdir(file_path, mode);
		*p = '/';
	}
	return 0;
}
*/

int
mkdir_r(std::string s, mode_t mode)
{
	size_t pre = 0, pos;
	std::string dir;
	int mdret = 0;

	if(s[s.size() - 1 ] != '/'){
		// force trailing / so we can handle everything in loop
		s += '/';
	}

	while((pos = s.find_first_of('/', pre)) != std::string::npos) {
		dir = s.substr(0, pos++);
		pre = pos;
		if(dir.size() == 0) continue; // if leading / first time is 0 length
		if((mdret = mkdir(dir.c_str(), mode)) && errno != EEXIST){
			return mdret;
		}
	}
	return mdret;
}

int rmdir_r(const char *dir, bool enableSubdir, bool withoutRemoveRoot) {
	if(!file_exists((char*)dir)) {
		return(0);
	}
	DIR* dp = opendir(dir);
	if (!dp) {
		return(1);
	}
	dirent* de;
	while (true) {
		de = readdir(dp);
		if (de == NULL) break;
		if (string(de->d_name) == ".." or string(de->d_name) == ".") continue;
		if(de->d_type == DT_DIR) {
			if(enableSubdir) {
				string dirWithSubdir = string(dir) + "/" + de->d_name;
				rmdir_r(dirWithSubdir.c_str(), enableSubdir);
			}
		} else {
			unlink((string(dir) + "/" + de->d_name).c_str());
		}
	}
	closedir(dp);
	if(withoutRemoveRoot) {
		return(0);
	} else {
		return(rmdir(dir));
	}
}

unsigned long long cp_r(const char *src, const char *dst, bool move) {
	if(!file_exists((char*)src)) {
		return(0);
	}
	DIR* dp = opendir(src);
	if (!dp) {
		return(0);
	}
	unsigned long long bytestransfered = 0;
	dirent* de;
	while (true) {
		de = readdir(dp);
		if (de == NULL) break;
		if (string(de->d_name) == ".." or string(de->d_name) == ".") continue;
		if(de->d_type == DT_DIR) {
			string srcWithSubdir = string(src) + "/" + de->d_name;
			string dstWithSubdir = string(dst) + "/" + de->d_name;
			mkdir(dstWithSubdir.c_str(), 0777);
			bytestransfered += cp_r(srcWithSubdir.c_str(), dstWithSubdir.c_str(), move);
			if(move) {
				rmdir(srcWithSubdir.c_str());
			}
		} else {
			copy_file((string(src) + "/" + de->d_name).c_str(), (string(dst) + "/" + de->d_name).c_str(), move);
		}
	}
	closedir(dp);
	return(bytestransfered);
}

unsigned long long copy_file(const char *src, const char *dst, bool move) {
	int read_fd = 0;
	int write_fd = 0;
	struct stat stat_buf;
	off_t offset = 0;
	int renamedebug = 0;

	//check if the file exists
	if(!FileExists((char*)src)) {
		return(0);
	}

	/* Open the input file. */
	read_fd = open (src, O_RDONLY);
	if(read_fd == -1) {
		syslog(LOG_ERR, "Cannot open file for reading [%s]\n", src);
		return(0);
	}
		
	/* Stat the input file to obtain its size. */
	fstat (read_fd, &stat_buf);
	/*
As you can see we are calling fdatasync right before calling posix_fadvise, this makes sure that all data associated with the file handle has been committed to disk. This is not done because there is any danger of loosing data. But it makes sure that that the posix_fadvise has an effect. Since the posix_fadvise function is advisory, the OS will simply ignore it, if it can not comply. At least with Linux, the effect of calling posix_fadvise(fd,0,0,POSIX_FADV_DONTNEED) is immediate. This means if you write a file and call posix_fadvise right after writing a chunk of data, it will probably have no effect at all since the data in question has not been committed to disk yet, and therefore can not be released from cache.
	*/
#ifndef FREEBSD
	fdatasync(read_fd);
#endif
	posix_fadvise(read_fd, 0, 0, POSIX_FADV_DONTNEED);

	/* Open the output file for writing, with the same permissions as the source file. */
	write_fd = open (dst, O_WRONLY | O_CREAT, stat_buf.st_mode);
	if(write_fd == -1) {
		char buf[4092];
		strerror_r(errno, buf, 4092);
		syslog(LOG_ERR, "Cannot open file for writing [%s] (error:[%s]) leaving the source file [%s] undeleted\n", dst, buf, src);
		close(read_fd);
		return(0);
	}
#ifndef FREEBSD
	fdatasync(write_fd);
#endif
	posix_fadvise(write_fd, 0, 0, POSIX_FADV_DONTNEED);
	/* Blast the bytes from one file to the other. */
#ifndef FREEBSD
	int res = sendfile(write_fd, read_fd, &offset, stat_buf.st_size);
	unsigned long long bytestransfered = stat_buf.st_size;
#else
	int res = -1;
	unsigned long long bytestransfered = 0;
#endif
	if(res == -1) {
		if(renamedebug) {
			syslog(LOG_ERR, "sendfile failed src[%s]", src);
			
		}
		// fall back to portable way if sendfile fails 
		char buf[8192];	// if this is 8kb it will stay in L1 cache on most CPUs. Dont know if higher buffer is better for sequential write	
		ssize_t result;
		int res;
		while (1) {
			result = read(read_fd, &buf[0], sizeof(buf));
			if (!result) break;
			res = write(write_fd, &buf[0], result);
			if(res == -1) {
				char buf[4092];
				strerror_r(errno, buf, 4092);
				syslog(LOG_ERR, "write failed src[%s] error[%s]", src, buf);
				break;
			}
			bytestransfered += res;
		}
	}
	
	/* clean */
	close (read_fd);
	close (write_fd);
	if(move) {
		unlink(src);
	}
	return(bytestransfered);
}

size_t _get_url_file_writer_function(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t written = fwrite(ptr, size, nmemb, stream);
	return written;
}
bool get_url_file(const char *url, const char *toFile, string *error) {
	if(error) {
		*error = "";
	}
	bool rslt = false;
	CURL *curl = curl_easy_init();
	if(curl) {
		struct curl_slist *headers = NULL;
		FILE *fp = fopen(toFile, "wb");
		if(!fp) {
			if(error) {
				*error = string("open / create file ") + toFile + " failed";
			}
		} else {
			char errorBuffer[1024];
			curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _get_url_file_writer_function);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);
			char *urlPathSeparator = (char*)strchr(url + 8, '/');
			string path = urlPathSeparator ? urlPathSeparator : "/";
			string host = urlPathSeparator ? string(url).substr(0, urlPathSeparator - url) : url;
			string hostProtPrefix;
			size_t posEndHostProtPrefix = host.rfind('/');
			if(posEndHostProtPrefix != string::npos) {
				hostProtPrefix = host.substr(0, posEndHostProtPrefix + 1);
				host = host.substr(posEndHostProtPrefix + 1);
			}
			extern map<string, string> hosts;
			map<string, string>::iterator iter = hosts.find(host.c_str());
			if(iter != hosts.end()) {
				string hostIP = iter->second;
				headers = curl_slist_append(headers, ("Host: " + host).c_str());
				curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
				curl_easy_setopt(curl, CURLOPT_URL, (hostProtPrefix +  hostIP + path).c_str());
			} else {
				curl_easy_setopt(curl, CURLOPT_URL, url);
			}
			extern char opt_curlproxy[256];
			if(opt_curlproxy[0]) {
				curl_easy_setopt(curl, CURLOPT_PROXY, opt_curlproxy);
			}
			if(curl_easy_perform(curl) == CURLE_OK) {
				rslt = true;
			} else {
				if(error) {
					*error = errorBuffer;
				}
			}
			fclose(fp);
		}
		if(headers) {
			curl_slist_free_all(headers);
		}
		curl_easy_cleanup(curl);
	} else {
		if(error) {
			*error = "initialize curl failed";
		}
	}
	return(rslt);
}

/* circular buffer implementation */
CircularBuffer::CircularBuffer(size_t capacity)
	: beg_index_(0)
	, end_index_(0)
	, size_(0)
	, capacity_(capacity)
{
	data_ = new char[capacity];
}

CircularBuffer::~CircularBuffer()
{
	delete [] data_;
}

size_t CircularBuffer::write(const char *data, size_t bytes)
{
	if (bytes == 0) return 0;

	size_t capacity = capacity_;
	size_t bytes_to_write = std::min(bytes, capacity - size_);

	// Write in a single step
	if (bytes_to_write <= capacity - end_index_)
	{
		memcpy(data_ + end_index_, data, bytes_to_write);
		end_index_ += bytes_to_write;
		if (end_index_ == capacity) end_index_ = 0;
	}
	// Write in two steps
	else
	{
		size_t size_1 = capacity - end_index_;
		memcpy(data_ + end_index_, data, size_1);
		size_t size_2 = bytes_to_write - size_1;
		memcpy(data_, data + size_1, size_2);
		end_index_ = size_2;
	}

	size_ += bytes_to_write;
	return bytes_to_write;
}

size_t CircularBuffer::read(char *data, size_t bytes)
{
	if (bytes == 0) return 0;

	size_t capacity = capacity_;
	size_t bytes_to_read = std::min(bytes, size_);

	// Read in a single step
	if (bytes_to_read <= capacity - beg_index_)
	{
		memcpy(data, data_ + beg_index_, bytes_to_read);
		beg_index_ += bytes_to_read;
		if (beg_index_ == capacity) beg_index_ = 0;
	}
	// Read in two steps
	else
	{
		size_t size_1 = capacity - beg_index_;
		memcpy(data, data_ + beg_index_, size_1);
		size_t size_2 = bytes_to_read - size_1;
		memcpy(data + size_1, data_, size_2);
		beg_index_ = size_2;
	}

	size_ -= bytes_to_read;
	return bytes_to_read;
}

double ts2double(unsigned int sec, unsigned int usec) {
	double fpart = usec;
	while(fpart > 1) fpart /= 10;
	return sec + fpart;
}

long long GetFileSize(std::string filename)
{
	struct stat stat_buf;
	int rc = stat(filename.c_str(), &stat_buf);
	return rc == 0 ? stat_buf.st_size : -1;
}

long long GetFileSizeDU(std::string filename)
{
	return(GetDU(GetFileSize(filename)));
}

long long GetDU(long long fileSize) {
	static int block_size = -1;
	if(block_size == -1) {
		extern char opt_chdir[1024];
		struct stat fi;
		if(!stat(opt_chdir, &fi)) {
			block_size = fi.st_blksize;
		} else {
			block_size = 0;
		}
	}
	if(fileSize >= 0 && block_size) {
		if(fileSize == 0) {
			fileSize = block_size;
		} else {
			fileSize = (fileSize / block_size * block_size) + (fileSize % block_size ? block_size : 0);
		}
		fileSize += 100; // inode / directory item size
	}
	return(fileSize);
}

long long GetFreeDiskSpace(const char* absoluteFilePath, bool percent_mult_100) {
	struct statvfs buf;
	if(!statvfs(absoluteFilePath, &buf)) {
		unsigned long long blksize, blocks, freeblks, disk_size, free;
		blksize = buf.f_bsize;
		blocks = buf.f_blocks;
		freeblks = buf.f_bfree;

		disk_size = blocks*blksize;
		free = freeblks*blksize;

		return percent_mult_100 ?
			(long long)((double)free / disk_size * 10000) :
			free;
	} else {
		return -1;
	}
}

long long GetTotalDiskSpace(const char* absoluteFilePath) {
	struct statvfs buf;
	if(!statvfs(absoluteFilePath, &buf)) {
		unsigned long long blksize, blocks, disk_size;
		blksize = buf.f_bsize;
		blocks = buf.f_blocks;

		disk_size = blocks*blksize;

		return disk_size;
	} else {
		return -1;
	}
}

string GetStringMD5(std::string str) {
	string md5;
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, (void*)str.c_str(), str.length());
	unsigned char _md5[MD5_DIGEST_LENGTH];
	MD5_Final(_md5, &ctx);
	return(MD5_String(_md5));
}

string GetFileMD5(std::string filename) {
	string md5;
	long long fileSize = GetFileSize(filename);
	if(!fileSize) {
		return(md5);
	}
	FILE *fileHandle = fopen(filename.c_str(), "rb");
	if(!fileHandle) {
		return(md5);
	}
	MD5_CTX ctx;
	MD5_Init(&ctx);
	char *fileBuffer = new char[fileSize];
	fread(fileBuffer, 1, fileSize, fileHandle);
	fclose(fileHandle);
	MD5_Update(&ctx, fileBuffer, fileSize);
	delete [] fileBuffer;
	unsigned char _md5[MD5_DIGEST_LENGTH];
	MD5_Final(_md5, &ctx);
	return(MD5_String(_md5));
}

void ntoa(char *res, unsigned int addr) {
	struct in_addr in;                                
	in.s_addr = addr;
	strcpy(res, inet_ntoa(in));
}

string escapeshellR(string &buf) {
        for(unsigned int i = 0; i < buf.length(); i++) {
                if(!(buf[i] == '/' || buf[i] == '#' || buf[i] == '+' || buf[i] == ' ' || buf[i] == ':' || buf[i] == '-' || buf[i] == '.' || buf[i] == '@' || isalnum(buf[i])) ) {   
                        buf[i] = '_';
                }
        }
	return buf;
}

time_t stringToTime(const char *timeStr) {
	int year, month, day, hour, min, sec;
	hour = min = sec = 0;
	sscanf(timeStr, "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &min, &sec);
	time_t now;
	time(&now);
	struct tm dateTime;
	dateTime = *localtime(&now);
	dateTime.tm_year = year - 1900;
	dateTime.tm_mon = month - 1;  
	dateTime.tm_mday = day;
	dateTime.tm_wday = 0;
	dateTime.tm_hour = hour; 
	dateTime.tm_min = min; 
	dateTime.tm_sec = sec;
	return(mktime(&dateTime));
}

struct tm getDateTime(u_int64_t us) {
	return(getDateTime((time_t)(us / 1000000)));
}

struct tm getDateTime(time_t time) {
	struct tm dateTime;
	dateTime = *localtime(&time);
	return(dateTime);
}

struct tm getDateTime(const char *timeStr) {
	return(getDateTime(stringToTime(timeStr)));
}

unsigned int getNumberOfDayToNow(const char *date) {
	int year, month, day;
	sscanf(date, "%d-%d-%d", &year, &month, &day);
	time_t now;
	time(&now);
	struct tm dateTime;
	dateTime = *localtime(&now);
	dateTime.tm_year = year - 1900;
	dateTime.tm_mon = month - 1;  
	dateTime.tm_mday = day;
	dateTime.tm_wday = 0;
	dateTime.tm_hour = 0; 
	dateTime.tm_min = 0; 
	dateTime.tm_sec = 0;
	return(difftime(now, mktime(&dateTime)) / (24 * 60 * 60));
}

string getActDateTimeF() {
	time_t actTime = time(NULL);
	struct tm *actTimeInfo = localtime(&actTime);
	char dateTimeF[20];
	strftime(dateTimeF, 20, "%Y-%m-%d %T", actTimeInfo);
	return(dateTimeF);
}

unsigned long getUptime() {
	extern time_t startTime;
	time_t actTime;
	time(&actTime);
	return(actTime - startTime);
}


PcapDumper::PcapDumper(eTypePcapDump type, class Call *call, bool updateFilesQueueAtClose) {
	this->type = type;
	this->call = call;
	this->updateFilesQueueAtClose = updateFilesQueueAtClose;
	this->capsize = 0;
	this->size = 0;
	this->handle = NULL;
	this->openError = false;
	this->openAttempts = 0;
}

PcapDumper::~PcapDumper() {
	if(this->handle) {
		this->close(this->updateFilesQueueAtClose);
	}
}

bool PcapDumper::open(const char *fileName, const char *fileNameSpoolRelative, pcap_t *useHandle, int useDlt) {
	if(this->type == rtp && this->openAttempts >= 10) {
		return(false);
	}
	if(this->handle) {
		this->close(this->updateFilesQueueAtClose);
		syslog(LOG_NOTICE, "pcapdumper: reopen %s -> %s", this->fileName.c_str(), fileName);
	}
	if(file_exists((char*)fileName)) {
		if(verbosity > 2) {
			syslog(LOG_NOTICE,"pcapdumper: [%s] already exists, not overwriting", fileName);
		}
	}
	extern pcap_t *global_pcap_handle_dead_EN10MB;
	extern int opt_convert_dlt_sll_to_en10;
	pcap_t *_handle = useDlt == DLT_LINUX_SLL && opt_convert_dlt_sll_to_en10 && global_pcap_handle_dead_EN10MB ? 
			   global_pcap_handle_dead_EN10MB : 
			   useHandle;
	this->capsize = 0;
	this->size = 0;
	string errorString;
	this->handle = __pcap_dump_open(_handle, fileName,
					useDlt == DLT_LINUX_SLL && opt_convert_dlt_sll_to_en10 ? DLT_EN10MB : useDlt,
					&errorString);
	++this->openAttempts;
	if(!this->handle) {
		if(this->type != rtp || !this->openError) {
			syslog(LOG_NOTICE, "pcapdumper: error open dump handle to file %s - %s", fileName, 
			       opt_pcap_dump_bufflength ?
				errorString.c_str() : 
				__pcap_geterr(_handle));
		}
		this->openError = true;
	}
	this->fileName = fileName;
	this->fileNameSpoolRelative = fileNameSpoolRelative;
	return(this->handle != NULL);
}

#define PCAP_DUMPER_PACKET_HEADER_SIZE 16
#define PCAP_DUMPER_HEADER_SIZE 24

void PcapDumper::dump(pcap_pkthdr* header, const u_char *packet) {
	extern unsigned int opt_maxpcapsize_mb;
	if(this->handle && 
	   (!opt_maxpcapsize_mb || this->capsize < opt_maxpcapsize_mb * 1024 * 1024)) {
		__pcap_dump((u_char*)this->handle, header, packet);
		extern int opt_packetbuffered;
		if(opt_packetbuffered) {
			pcap_dump_flush(this->handle);
		}
		this->capsize += header->caplen + PCAP_DUMPER_PACKET_HEADER_SIZE;
		this->size += header->len + PCAP_DUMPER_PACKET_HEADER_SIZE;
	}
}

void PcapDumper::close(bool updateFilesQueue) {
	if(this->handle) {
		if(updateFilesQueue && this->call) {
			asyncClose.add(this->handle, this->call,
				       this->fileNameSpoolRelative.c_str(), 
				       type == rtp ? "rtpsize" : 
				       this->call->type == REGISTER ? "regsize" : "sipsize",
				       0/*this->capsize + PCAP_DUMPER_HEADER_SIZE ignore size counter - header->capsize can contain -1*/);
		} else {
			asyncClose.add(this->handle);
		}
		this->handle = NULL;
	}
}

void PcapDumper::remove(bool updateFilesQueue) {
	if(this->handle) {
		this->close(false);
		unlink(this->fileName.c_str());
	}
}


extern int opt_gzipGRAPH;

RtpGraphSaver::RtpGraphSaver(RTP *rtp, bool updateFilesQueueAtClose) {
	this->rtp = rtp;
	this->updateFilesQueueAtClose = updateFilesQueueAtClose;
	this->handle = NULL;
}

RtpGraphSaver::~RtpGraphSaver() {
	if(this->isOpen()) {
		this->close(this->updateFilesQueueAtClose);
	}
}

bool RtpGraphSaver::open(const char *fileName, const char *fileNameSpoolRelative) {
	if(this->handle) {
		this->close(this->updateFilesQueueAtClose);
		syslog(LOG_NOTICE, "graphsaver: reopen %s -> %s", this->fileName.c_str(), fileName);
	}
	if(file_exists((char*)fileName)) {
		if(verbosity > 2) {
			syslog(LOG_NOTICE,"graphsaver: [%s] already exists, not overwriting", fileName);
		}
	}
	this->handle = new FileZipHandler(opt_pcap_dump_bufflength, opt_pcap_dump_asyncwrite, opt_gzipGRAPH);
	if(!this->handle->open(fileName)) {
		syslog(LOG_NOTICE, "graphsaver: error open file %s - %s", fileName, this->handle->error.c_str());
		delete this->handle;
		this->handle = NULL;
	}
	this->fileName = fileName;
	this->fileNameSpoolRelative = fileNameSpoolRelative;
	return(this->isOpen());

}

void RtpGraphSaver::write(char *buffer, int length) {
	if(this->isOpen()) {
		this->handle->write(buffer, length);
	}
}

void RtpGraphSaver::close(bool updateFilesQueue) {
	if(this->isOpen()) {
		Call *call = (Call*)this->rtp->call_owner;
		if(updateFilesQueue && call) {
			asyncClose.add(this->handle, call,
				       this->fileNameSpoolRelative.c_str(), 
				       "graphsize", 
				       this->handle->size);
		} else {
			asyncClose.add(this->handle);
		}
		this->handle = NULL;
		if(updateFilesQueue && !call) {
			syslog(LOG_ERR, "graphsaver: gfilename[%s] does not have owner", this->fileNameSpoolRelative.c_str());
		}
	}
}

AsyncClose::AsyncCloseItem::AsyncCloseItem(Call *call, const char *file, const char *column, long long writeBytes) {
	if(call) {
		this->file = file;
		this->column = column;
		this->dirnamesqlfiles = call->dirnamesqlfiles();
		this->writeBytes = writeBytes;
		this->calltable = call->calltable;
	}
	this->dataLength = 0;
}

void AsyncClose::AsyncCloseItem::addtofilesqueue() {
	Call::_addtofilesqueue(this->file, this->column, this->dirnamesqlfiles, this->writeBytes);
	extern char opt_cachedir[1024];
	if(opt_cachedir[0] != '\0') {
		Call::_addtocachequeue(this->file, this->calltable);
	}
}

void *AsyncClose_process(void *_startThreadData) {
	AsyncClose::StartThreadData *startThreadData = (AsyncClose::StartThreadData*)_startThreadData;
	startThreadData->asyncClose->processTask(startThreadData->threadIndex);
	return(NULL);
}

AsyncClose::AsyncClose() {
	for(int i = 0; i < AsyncClose_maxPcapTheads + 1; i++) {
		_sync[i] = 0;
		threadId[i] = 0;
		memset(this->threadPstatData[i], 0, sizeof(this->threadPstatData[i]));
	}
	sizeOfDataInMemory = 0;
}

void AsyncClose::startThreads(int countPcapThreads) {
	this->countPcapThreads = opt_pcap_dump_bufflength ?
				  min(AsyncClose_maxPcapTheads, countPcapThreads) :
				  1;
	for(int i = 0; i < this->countPcapThreads; i++) {
		startThreadData[i].threadIndex = i;
		startThreadData[i].asyncClose = this;
		pthread_create(&this->thread[i], NULL, AsyncClose_process, &startThreadData[i]);
	}
}

void AsyncClose::processTask(int threadIndex) {
	this->threadId[threadIndex] = get_unix_tid();
	do {
		processAll(threadIndex);
		usleep(10000);
	} while(!terminating);
}

void AsyncClose::processAll(int threadIndex) {
	while(true) {
		lock(threadIndex);
		if(q[threadIndex].size()) {
			AsyncCloseItem *item = q[threadIndex].front();
			q[threadIndex].pop();
			unlock(threadIndex);
			item->process();
			sub_sizeOfDataInMemory(item->dataLength);
			delete item;
		} else {
			unlock(threadIndex);
			break;
		}
	}
}

void AsyncClose::preparePstatData(int threadIndex) {
	if(this->threadId[threadIndex]) {
		if(this->threadPstatData[threadIndex][0].cpu_total_time) {
			this->threadPstatData[threadIndex][1] = this->threadPstatData[threadIndex][0];
		}
		pstat_get_data(this->threadId[threadIndex], this->threadPstatData[threadIndex]);
	}
}

double AsyncClose::getCpuUsagePerc(int threadIndex, bool preparePstatData) {
	if(preparePstatData) {
		this->preparePstatData(threadIndex);
	}
	if(this->threadId[threadIndex]) {
		double ucpu_usage, scpu_usage;
		if(this->threadPstatData[threadIndex][0].cpu_total_time && this->threadPstatData[threadIndex][1].cpu_total_time) {
			pstat_calc_cpu_usage_pct(
				&this->threadPstatData[threadIndex][0], &this->threadPstatData[threadIndex][1],
				&ucpu_usage, &scpu_usage);
			return(ucpu_usage + scpu_usage);
		}
	}
	return(-1);
}

RestartUpgrade::RestartUpgrade(bool upgrade, const char *version, const char *url, const char *md5_32, const char *md5_64) {
	this->upgrade = upgrade;
	if(version) {
		this->version = version;
	}
	if(url) {
		this->url = url;
	}
	if(md5_32) {
		this->md5_32 = md5_32;
	}
	if(md5_64) {
		this->md5_64 = md5_64;
	}
	#ifdef __x86_64__
		this->_64bit = true;
	#else
		this->_64bit = false;
	#endif
}

bool RestartUpgrade::runUpgrade() {
	bool okUrl;
	string urlHttp;
	if(url.find("http://voipmonitor.org") == 0 ||
	   url.find("http://www.voipmonitor.org") == 0 ||
	   url.find("http://download.voipmonitor.org") == 0) {
		urlHttp = url;
		url = "https" + url.substr(4);
		okUrl = true;
	} else if(url.find("https://voipmonitor.org") == 0 ||
		  url.find("https://www.voipmonitor.org") == 0 ||
		  url.find("https://download.voipmonitor.org") == 0) {
		urlHttp = "http" + url.substr(5);
		okUrl = true;
	}
	if(!okUrl) {
		this->errorString = "url " + url + " not allowed";
		return(false);
	}
	if(!this->upgradeTempFileName.length() && !this->getUpgradeTempFileName()) {
		this->errorString = "failed create temp name for new binary";
		return(false);
	}
	if(mkdir(this->upgradeTempFileName.c_str(), 0700)) {
		this->errorString = "failed create folder " + this->upgradeTempFileName;
		return(false);
	}
	unlink(this->upgradeTempFileName.c_str());
	char outputStdoutErr[L_tmpnam+1];
	if(!tmpnam(outputStdoutErr)) {
		this->errorString = "failed create temp name for output curl and gunzip";
		return(false);
	}
	string binaryFilepathName = this->upgradeTempFileName + "/voipmonitor";
	string binaryGzFilepathName = this->upgradeTempFileName + "/voipmonitor.gz";
	extern int opt_upgrade_try_http_if_https_fail;
	for(int pass = 0; pass < (opt_upgrade_try_http_if_https_fail ? 2 : 1); pass++) {
		string error;
		string _url = (pass == 1 ? urlHttp : url) + 
			      "/voipmonitor.gz." + (this->_64bit ? "64" : "32");
		if(get_url_file(_url.c_str(), binaryGzFilepathName.c_str(), &error)) {
			this->errorString = "";
			break;
		} else {
			this->errorString = "failed download upgrade: " + error;
			if(pass || !opt_upgrade_try_http_if_https_fail) {
				rmdir_r(this->upgradeTempFileName.c_str());
				return(false);
			}
		}
		/* obsolete
		string wgetCommand = string("wget --no-cache ") + 
				     (pass == 0 ? "--no-check-certificate " : "") +
				     (pass == 1 ? urlHttp : url) + 
				     "/voipmonitor.gz." + (this->_64bit ? "64" : "32") + 
				     " -O " + binaryGzFilepathName +
				     " >" + outputStdoutErr + " 2>&1";
		syslog(LOG_NOTICE, wgetCommand.c_str());
		if(system(wgetCommand.c_str()) != 0) {
			this->errorString = "failed run wget";
			FILE *fileHandle = fopen(outputStdoutErr, "r");
			if(fileHandle) {
				size_t sizeOfOutputWgetBuffer = 10000;
				char *outputStdoutErrBuffer = new char[sizeOfOutputWgetBuffer];
				size_t readSize = fread(outputStdoutErrBuffer, 1, sizeOfOutputWgetBuffer, fileHandle);
				if(readSize > 0) {
					outputStdoutErrBuffer[min(readSize, sizeOfOutputWgetBuffer) - 1] = 0;
					this->errorString += ": " + string(outputStdoutErrBuffer);
				}
				fclose(fileHandle);
			}
			unlink(outputStdoutErr);
			if(pass || !opt_upgrade_try_http_if_https_fail) {
				rmdir_r(this->upgradeTempFileName.c_str());
				return(false);
			}
		} else {
			this->errorString = "";
			break;
		}
		*/
	}
	if(!FileExists((char*)binaryGzFilepathName.c_str())) {
		this->errorString = "failed download - missing destination file";
		rmdir_r(this->upgradeTempFileName.c_str());
		return(false);
	}
	if(!GetFileSize(binaryGzFilepathName.c_str())) {
		this->errorString = "failed download - zero size of destination file";
		rmdir_r(this->upgradeTempFileName.c_str());
		return(false);
	}
	string unzipCommand = "gunzip " + binaryGzFilepathName +
			      " >" + outputStdoutErr + " 2>&1";
	if(system(unzipCommand.c_str()) != 0) {
		this->errorString = "failed run gunzip";
		FILE *fileHandle = fopen(outputStdoutErr, "r");
		if(fileHandle) {
			size_t sizeOfOutputWgetBuffer = 10000;
			char *outputStdoutErrBuffer = new char[sizeOfOutputWgetBuffer];
			size_t readSize = fread(outputStdoutErrBuffer, 1, sizeOfOutputWgetBuffer, fileHandle);
			if(readSize > 0) {
				outputStdoutErrBuffer[min(readSize, sizeOfOutputWgetBuffer) - 1] = 0;
				this->errorString += ": " + string(outputStdoutErrBuffer);
			}
			fclose(fileHandle);
		}
		
		FILE *f = fopen(binaryGzFilepathName.c_str(), "rt");
		char buff[10000];
		while(fgets(buff, sizeof(buff), f)) {
			cout << buff << endl;
		}
		
		unlink(outputStdoutErr);
		rmdir_r(this->upgradeTempFileName.c_str());
		return(false);
	}
	string md5 = GetFileMD5(binaryFilepathName);
	if((this->_64bit ? md5_64 : md5_32) != md5) {
		this->errorString = "failed download - bad md5: " + md5 + " <> " + (this->_64bit ? md5_64 : md5_32);
		rmdir_r(this->upgradeTempFileName.c_str());
		return(false);
	}
	unlink("/usr/local/sbin/voipmonitor");
	if(!copy_file(binaryFilepathName.c_str(), "/usr/local/sbin/voipmonitor", true)) {
		this->errorString = "failed copy new binary to /usr/local/sbin";
		rmdir_r(this->upgradeTempFileName.c_str());
		return(false);
	}
	if(chmod("/usr/local/sbin/voipmonitor", 0755)) {
		this->errorString = "failed chmod 0755 voipmonitor";
		rmdir_r(this->upgradeTempFileName.c_str());
		return(false);
	}
	rmdir_r(this->upgradeTempFileName.c_str());
	return(true);
}

bool RestartUpgrade::createRestartScript() {
	if(!this->restartTempScriptFileName.length() && !this->getRestartTempScriptFileName()) {
		this->errorString = "failed create temp name for restart script";
		return(false);
	}
	FILE *fileHandle = fopen(this->restartTempScriptFileName.c_str(), "wt");
	if(fileHandle) {
		fputs("#!/bin/bash\n", fileHandle);
		fputs("/etc/init.d/voipmonitor start\n", fileHandle);
		fprintf(fileHandle, "rm %s\n", this->restartTempScriptFileName.c_str());
		fclose(fileHandle);
		if(chmod(this->restartTempScriptFileName.c_str(), 0755)) {
			this->errorString = "failed chmod 0755 for restart script";
		}
		return(true);
	} else {
		this->errorString = "failed create restart script";
	}
	return(false);
}

bool RestartUpgrade::checkReadyRestart() {
	if(!FileExists((char*)this->restartTempScriptFileName.c_str())) {
		this->errorString = "failed check restart script - script missing";
		return(false);
	}
	if(!this->restartTempScriptFileName.length()) {
		this->errorString = "failed check restart script - zero size of restart script";
		unlink(this->restartTempScriptFileName.c_str());
		return(false);
	}
	return(true);
}

bool RestartUpgrade::runRestart(int socket1, int socket2) {
	if(!this->checkReadyRestart()) {
		return(false);
	}
	close(socket1);
	close(socket2);
	int rsltExec = execl(this->restartTempScriptFileName.c_str(), "Command-line", 0, NULL);
	if(rsltExec) {
		this->errorString = "failed execution restart script";
		return(false);
	} else {
		return(true);
	}
}

bool RestartUpgrade::isOk() {
	return(!this->errorString.length());
}

string RestartUpgrade::getErrorString() {
	return(this->errorString);
}

string RestartUpgrade::getRsltString() {
	return(this->isOk() ?
		(this->upgrade ? "upgraded" : "restarted") :
		this->errorString);
}

bool RestartUpgrade::getUpgradeTempFileName() {
	char upgradeTempFileName[L_tmpnam+1];
	if(tmpnam(upgradeTempFileName)) {
		this->upgradeTempFileName = upgradeTempFileName;
		return(true);
	}
	return(false);
}

bool RestartUpgrade::getRestartTempScriptFileName() {
	char restartTempScriptFileName[L_tmpnam+1];
	if(tmpnam(restartTempScriptFileName)) {
		this->restartTempScriptFileName = restartTempScriptFileName;
		return(true);
	}
	return(false);
}

int get_unix_tid(void) {
	 int ret = -1;
#ifdef HAVE_PTHREAD_GETTHREADID_NP
	ret = pthread_getthreadid_np();
#elif defined(linux)
	ret = syscall(SYS_gettid);
#elif defined(__sun)
	ret = pthread_self();
#elif defined(__APPLE__)
	ret = mach_thread_self();
	mach_port_deallocate(mach_task_self(), ret);
#elif defined(__NetBSD__)
	ret = _lwp_self();
#elif defined(__FreeBSD__)
	long lwpid;
	thr_self( &lwpid );
	ret = lwpid;
#elif defined(__DragonFly__)
	ret = lwp_gettid();
#endif
	return ret;
}

std::string pexec(char* cmd) {
	FILE* pipe = popen(cmd, "r");
	if (!pipe) return "ERROR";
	char buffer[128];
	std::string result = "";
	while(!feof(pipe)) {
		if(fgets(buffer, 128, pipe) != NULL)
			result += buffer;
	}
	pclose(pipe);
	return result;
}


std::string &trim(std::string &s) {
	if(!s.length()) {
		 return(s);
	}
	size_t length = s.length();
	size_t trimCharsLeft = 0;
	while(trimCharsLeft < length && strchr("\r\n\t ", s[trimCharsLeft])) {
		++trimCharsLeft;
	}
	if(trimCharsLeft) {
		s = s.substr(trimCharsLeft);
		length = s.length();
	}
	size_t trimCharsRight = 0;
	while(trimCharsRight < length && strchr("\r\n\t ", s[length - trimCharsRight - 1])) {
		++trimCharsRight;
	}
	if(trimCharsRight) {
		s = s.substr(0, length - trimCharsRight);
	}
	return(s);
}

std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}

std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, elems);
    return elems;
}

std::vector<std::string> split(const char *s, const char *delim, bool enableTrim) {
	std::vector<std::string> elems;
	char *p = (char*)s;
	int delim_length = strlen(delim);
	while(p) {
		char *next_delim = strstr(p, delim);
		string elem = next_delim ?
			       std::string(p).substr(0, next_delim - p) :
			       std::string(p);
		if(enableTrim) {
			trim(elem);
		}
		if(elem.length()) {
			elems.push_back(elem);
		}
		p = next_delim ? next_delim + delim_length : NULL;
	}
	return elems;
}

std::vector<std::string> split(const char *s, std::vector<std::string> delim, bool enableTrim) {
	vector<std::string> elems;
	string elem = s;
	trim(elem);
	elems.push_back(elem);
	for(size_t i = 0; i < delim.size(); i++) {
		vector<std::string> _elems;
		for(size_t j = 0; j < elems.size(); j++) {
			vector<std::string> __elems = split(elems[j].c_str(), delim[i].c_str(), enableTrim);
			for(size_t k = 0; k < __elems.size(); k++) {
				_elems.push_back(__elems[k]);
			}
		}
		elems = _elems;
	}
	return(elems);
}


int reg_match(const char *string, const char *pattern) {
	int status;
	regex_t re;
	if(regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB) != 0) {
		syslog(LOG_ERR, "regcomp %s error", pattern);
		return(0);
	}
	status = regexec(&re, string, (size_t)0, NULL, 0);
	regfree(&re);
	return(status == 0);
}

string reg_replace(const char *str, const char *pattern, const char *replace) {
	int status;
	regex_t re;
	if(regcomp(&re, pattern, REG_EXTENDED) != 0) {
		syslog(LOG_ERR, "regcomp %s error", pattern);
		return("");
	}
	int match_max = 20;
	regmatch_t match[match_max];
	memset(match, 0, sizeof(match));
	status = regexec(&re, str, match_max, match, 0);
	regfree(&re);
	if(status == 0) {
		string rslt = replace;
		int match_count = 0;
		for(int i = 0; i < match_max; i ++) {
			if(match[i].rm_so == -1 && match[i].rm_eo == -1) {
				break;
			}
			++match_count;
		}
		for(int i = match_count - 1; i > 0; i--) {
			for(int j = 0; j < 2; j++) {
				char findStr[10];
				sprintf(findStr, j ? "{$%i}" : "$%i", i);
				size_t findPos;
				while((findPos = rslt.find(findStr)) != string::npos) {
					rslt.replace(findPos, strlen(findStr), string(str).substr(match[i].rm_so, match[i].rm_eo - match[i].rm_so));
				}
			}
		}
		return(rslt);
	}
	return("");
}

string inet_ntostring(u_int32_t ip) {
	struct in_addr in;
	in.s_addr = ip;
	return(inet_ntoa(in));
}


void ListIP::addComb(string &ip) {
	addComb(ip.c_str());
}

void ListIP::addComb(const char *ip) {
	vector<string>ip_elems = split(ip, split(",|;|\t|\r|\n", "|"), true);
	for(size_t i = 0; i < ip_elems.size(); i++) {
		add(ip_elems[i].c_str());
	}
}

void ListPhoneNumber::addComb(string &number) {
	addComb(number.c_str());
}

void ListPhoneNumber::addComb(const char *number) {
	vector<string>number_elems = split(number, split(",|;|\t|\r|\n", "|"), true);
	for(size_t i = 0; i < number_elems.size(); i++) {
		add(number_elems[i].c_str());
	}
}

ListIP_wb::ListIP_wb(bool autoLock)
 : white(autoLock),
   black(autoLock) {
}

void ListIP_wb::addWhite(string &ip) {
	white.addComb(ip);
}

void ListIP_wb::addWhite(const char *ip) {
	white.addComb(ip);
}

void ListIP_wb::addBlack(string &ip) {
	black.addComb(ip);
}

void ListIP_wb::addBlack(const char *ip) {
	black.addComb(ip);
}

ListPhoneNumber_wb::ListPhoneNumber_wb(bool autoLock)
 : white(autoLock),
   black(autoLock) {
}

void ListPhoneNumber_wb::addWhite(string &number) {
	white.addComb(number);
}

void ListPhoneNumber_wb::addWhite(const char *number) {
	white.addComb(number);
}

void ListPhoneNumber_wb::addBlack(string &number) {
	black.addComb(number);
}

void ListPhoneNumber_wb::addBlack(const char *number) {
	black.addComb(number);
}


void ParsePacket::parseData(char *data, unsigned long datalen, bool doClear) {
	if(doClear) {
		clear();
	}
	sip = datalen ? isSipContent(data, datalen - 1) : false;
	ppContent *content;
	unsigned int namelength;
	for(unsigned long i = 0; i < datalen; i++) {
		if(!doubleEndLine && 
		   data[i] == '\r' && i < datalen - 3 && 
		   data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
			doubleEndLine = data + i;
			if(contentLength > -1) {
				unsigned long modify_datalen = doubleEndLine + 4 - data + contentLength;
				if(modify_datalen < datalen) {
					datalen = modify_datalen;
				}
			}
			i += 2;
		} else if(i == 0 || data[i - 1] == '\n') {
			content = getContent(data + i, &namelength, datalen - i - 1);
			if(content && !content->content) {
				contents[contents_count++] = content;
				content->content = data + i + namelength;
				i += namelength;
				for(; i < datalen; i++) {
					if(data[i] == '\r' || data[i] == '\n') {
						content->length = data + i - content->content;
						content->trim();
						if(content->isContentLength && content->content) {
							contentLength = atoi(content->content);
						}
						--i;
						break;
					}
				 
				}
			}
		}
	}
	parseDataPtr = data;
}


void *_SafeAsyncQueue_timerThread(void *arg) {
	((SafeAsyncQueue_base*)arg)->timerThread();
	return(NULL);
}

SafeAsyncQueue_base::SafeAsyncQueue_base() {
	if(!timer_thread) {
		pthread_create(&timer_thread, NULL, _SafeAsyncQueue_timerThread, NULL);
	}
	lock_list_saq();
	list_saq.push_back(this);
	unlock_list_saq();
}

SafeAsyncQueue_base::~SafeAsyncQueue_base() {
	lock_list_saq();
	list_saq.remove(this);
	unlock_list_saq();
}

bool SafeAsyncQueue_base::isRunTimerThread() {
	return(runTimerThread);
}

void SafeAsyncQueue_base::stopTimerThread(bool wait) {
	terminateTimerThread = true;
	while(wait && runTimerThread) {
		usleep(100000);
	}
}

void SafeAsyncQueue_base::timerThread() {
	runTimerThread = true;
	while(!terminateTimerThread) {
		usleep(100000);
		lock_list_saq();
		list<SafeAsyncQueue_base*>::iterator iter;
		for(iter = list_saq.begin(); iter != list_saq.end(); iter++) {
			(*iter)->timerEv(timer_counter);
		}
		unlock_list_saq();
		++timer_counter;
	}
	runTimerThread = false;
}

list<SafeAsyncQueue_base*> SafeAsyncQueue_base::list_saq;

pthread_t SafeAsyncQueue_base::timer_thread = 0;

unsigned long long SafeAsyncQueue_base::timer_counter = 0;

volatile int SafeAsyncQueue_base::_sync_list_saq = 0;

bool SafeAsyncQueue_base::runTimerThread = false;

bool SafeAsyncQueue_base::terminateTimerThread = false;


JsonExport::~JsonExport() {
	while(items.size()) {
		delete (*items.begin());
		items.erase(items.begin());
	}
}

string JsonExport::getJson() {
	ostringstream outStr;
	outStr << '{';
	vector<JsonExportItem*>::iterator iter;
	for(iter = items.begin(); iter != items.end(); iter++) {
		if(iter != items.begin()) {
			outStr << ',';
		}
		outStr << (*iter)->getStringItem();
	}
	outStr << '}';
	return(outStr.str());
}

void JsonExport::add(const char *name, string content) {
	this->add(name, content.c_str());
}

void JsonExport::add(const char *name, const char *content) {
	JsonExportItem_template<string> *item = new JsonExportItem_template<string>;
	item->setTypeItem(_string);
	item->setName(name);
	item->setContent(string(content));
	items.push_back(item);
}

void JsonExport::add(const char *name, u_int64_t content) {
	JsonExportItem_template<u_int64_t> *item = new JsonExportItem_template<u_int64_t>;
	item->setTypeItem(_number);
	item->setName(name);
	item->setContent(content);
	items.push_back(item);
}


//------------------------------------------------------------------------------
// pcap_dump_open with set buffer

FileZipHandler::FileZipHandler(int bufferLength, int enableAsyncWrite, int enableZip,
			       bool dumpHandler) {
	if(bufferLength <= 0) {
		enableAsyncWrite = 0;
		enableZip = 0;
	}
	this->fh = 0;
	if(enableZip) {
		this->zipStream =  new z_stream;
		this->zipStream->zalloc = Z_NULL;
		this->zipStream->zfree = Z_NULL;
		this->zipStream->opaque = Z_NULL;
		if(deflateInit2(this->zipStream, opt_pcap_dump_ziplevel, Z_DEFLATED, MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
			deflateEnd(this->zipStream);
			delete this->zipStream;
			this->zipStream = NULL;
		}
	} else {
		this->zipStream = NULL;
	}
	this->bufferLength = bufferLength;
	if(bufferLength) {
		this->buffer = new char[bufferLength];
	} else {
		this->buffer = NULL;
	}
	if(bufferLength && enableZip) {
		this->zipBuffer = new char[bufferLength];
	} else {
		this->zipBuffer = NULL;
	}
	this->useBufferLength = 0;
	this->enableAsyncWrite = enableAsyncWrite;
	this->enableZip = enableZip;
	this->dumpHandler = dumpHandler;
	this->size = 0;
	this->counter = ++scounter;
}

FileZipHandler::~FileZipHandler() {
	this->close();
	if(this->buffer) {
		delete [] this->buffer;
	}
	if(this->zipBuffer) {
		delete [] this->zipBuffer;
	}
	if(this->zipStream) {
		deflateEnd(this->zipStream);
		delete this->zipStream;
	}
}

bool FileZipHandler::open(const char *fileName, int permission) {
	this->fileName = fileName;
	if(this->enableZip && !this->zipStream) {
		this->setError("zip initialize failed");
		return(false);
	}
	this->fh = ::open(fileName, O_WRONLY | O_CREAT | O_TRUNC, permission);
	if(this->okHandle()) {
		return(true);
	} else {
		this->setError();
		return(false);
	}
}

void FileZipHandler::close() {
	if(this->okHandle()) {
		this->flushBuffer(true);
		::close(this->fh);
		this->fh = 0;
	}
}

bool FileZipHandler::flushBuffer(bool force) {
	if(!this->buffer || !this->useBufferLength) {
		return(true);
	}
	bool rsltWrite = this->writeToFile(this->buffer, this->useBufferLength, force);
	this->useBufferLength = 0;
	return(rsltWrite);
}

bool FileZipHandler::writeToBuffer(char *data, int length) {
	if(!this->buffer) {
		return(false);
	}
	if(this->useBufferLength && this->useBufferLength + length > this->bufferLength) {
		flushBuffer();
	}
	if(length <= this->bufferLength) {
		memcpy(this->buffer + this->useBufferLength, data, length);
		this->useBufferLength += length;
		return(true);
	} else {
		return(this->writeToFile(data, length));
	}
}

bool FileZipHandler::writeToFile(char *data, int length, bool force) {
	if(enableAsyncWrite && !force) {
		if(dumpHandler) {
			asyncClose.addWrite((pcap_dumper_t*)this, data, length);
		} else {
			asyncClose.addWrite(this, data, length);
		}
		return(true);
	} else {
		return(this->_writeToFile(data, length, force));
	}
}

bool FileZipHandler::_writeToFile(char *data, int length, bool flush) {
	if(!this->okHandle()) {
		return(false);
	}
	if(this->enableZip) {
		this->zipStream->avail_in = length;
		this->zipStream->next_in = (unsigned char*)data;
		do {
			this->zipStream->avail_out = this->bufferLength;
			this->zipStream->next_out = (unsigned char*)this->zipBuffer;
			if(deflate(this->zipStream, flush ? Z_FINISH : Z_NO_FLUSH) != Z_STREAM_ERROR) {
				int have = this->bufferLength - this->zipStream->avail_out;
				if(::write(this->fh, this->zipBuffer, have) <= 0) {
					this->setError();
					return(false);
				} else {
					this->size += length;
				}
			} else {
				this->setError("zip deflate failed");
				return(false);
			}
		} while(this->zipStream->avail_out == 0);
		return(true);
	} else {
		int rsltWrite = ::write(this->fh, data, length);
		if(rsltWrite <= 0) {
			this->setError();
			return(false);
		} else {
			this->size += length;
			return(true);
		}
	}
}

void FileZipHandler::setError(const char *error) {
	if(error) {
		this->error = error;
	} else if(errno) {
		this->error = strerror(errno);
	}
}

u_int64_t FileZipHandler::scounter = 0;

#define TCPDUMP_MAGIC		0xa1b2c3d4
#define NSEC_TCPDUMP_MAGIC	0xa1b23c4d

pcap_dumper_t *__pcap_dump_open(pcap_t *p, const char *fname, int linktype, string *errorString) {
	if(opt_pcap_dump_bufflength) {
		FileZipHandler *handler = new FileZipHandler(opt_pcap_dump_bufflength, opt_pcap_dump_asyncwrite, opt_pcap_dump_zip, true);
		if(handler->open(fname)) {
			struct pcap_file_header hdr;
			/****
			hdr.magic = p->opt.tstamp_precision == PCAP_TSTAMP_PRECISION_NANO ? NSEC_TCPDUMP_MAGIC : TCPDUMP_MAGIC;
			****/
			hdr.magic = NSEC_TCPDUMP_MAGIC;
			hdr.version_major = PCAP_VERSION_MAJOR;
			hdr.version_minor = PCAP_VERSION_MINOR;
			/****
			hdr.thiszone = thiszone;
			hdr.snaplen = snaplen;
			****/
			hdr.thiszone = 0;
			hdr.snaplen = 0;
			hdr.sigfigs = 0;
			hdr.linktype = linktype;
			handler->write((char *)&hdr, sizeof(hdr));
			return((pcap_dumper_t*)handler);
		} else {
			handler->setError();
			if(errorString) {
				*errorString = handler->error;
			}
			delete handler;
			return(NULL);
		}
	} else {
		return(pcap_dump_open(p, fname));
	}
}

void __pcap_dump(u_char *user, const struct pcap_pkthdr *h, const u_char *sp) {
	if(opt_pcap_dump_bufflength) {
		struct pcap_timeval {
		    bpf_int32 tv_sec;		/* seconds */
		    bpf_int32 tv_usec;		/* microseconds */
		};
		struct pcap_sf_pkthdr {
		    struct pcap_timeval ts;	/* time stamp */
		    bpf_u_int32 caplen;		/* length of portion present */
		    bpf_u_int32 len;		/* length this packet (off wire) */
		};
		FileZipHandler *handler = (FileZipHandler*)user;
		struct pcap_sf_pkthdr sf_hdr;
		sf_hdr.ts.tv_sec  = h->ts.tv_sec;
		sf_hdr.ts.tv_usec = h->ts.tv_usec;
		sf_hdr.caplen     = h->caplen;
		sf_hdr.len        = h->len;
		handler->write((char*)&sf_hdr, sizeof(sf_hdr));
		handler->write((char*)sp, h->caplen);
	} else {
		pcap_dump(user, h, sp);
	}
}

void __pcap_dump_close(pcap_dumper_t *p) {
	if(opt_pcap_dump_bufflength) {
		FileZipHandler *handler = (FileZipHandler*)p;
		handler->close();
		delete handler;
	} else {
		pcap_dump_close(p);
	}
}

char *__pcap_geterr(pcap_t *p, pcap_dumper_t *pd) {
	if(opt_pcap_dump_bufflength && pd) {
		return((char*)((FileZipHandler*)pd)->error.c_str());
	} else {
		return(pcap_geterr(p));
	}
}
