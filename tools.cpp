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
#include <json/json.h>
#include <iomanip>
#include <openssl/sha.h>
#include <fcntl.h>

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
#include "pcap_queue.h"
#include "sql_db.h"

extern char mac[32];
extern int verbosity;
extern int terminating;
extern int opt_pcap_dump_bufflength;
extern int opt_pcap_dump_asyncwrite;
extern int opt_pcap_dump_zip;
extern int opt_pcap_dump_ziplevel;
extern int opt_read_from_file;

static char b2a[256];
static char base64[64];

using namespace std;

AsyncClose asyncClose;

//Sort files in given directory using mtime from oldest (files not already openned for write).
queue<string> listFilesDir (char * dir) {
	struct privListDir {          //sort by mtime asc. function
		static bool files_sorter_asc(TfileListElem const& lhs, TfileListElem const& rhs) {
			if (lhs.mtime != rhs.mtime)
				return lhs.mtime < rhs.mtime;
			return 1;
		}
		static bool file_mtimer(TfileListElem elem, int timeout) {
			time_t  actualTS;
			time(&actualTS);
			if ((elem.mtime + timeout) < actualTS) { //file is old enough
				return 1;
			}
			return 0;
		}
	};

	char filename[1024];
	vector<TfileListElem> tmpVec;   //vector for sorting
	TfileListElem elem;             //element of sorting
	queue<string> outQueue;         //sorted filenames list
	struct stat fileStats;          //for file stat
	struct dirent * ent;            //for dir ent
	DIR *dirP;
	unsigned char isFile =0x8;

	if ((dirP = opendir (dir)) != NULL) {
		while ((ent = readdir (dirP)) != NULL) {
			if ( ent->d_type != isFile) {
				//directory skipping
				continue;
			}
            snprintf (filename, sizeof(filename), "%s/%s", dir, ent->d_name);
			int fd = open(filename, O_RDONLY);
			if (fd < 0) {
				//skiping if unable to open a file
				syslog(LOG_ERR, "listFilesDir: unable to open %s.",filename);
				continue;
			}
			//elem.filename = ent->d_name;      //result are filenames only
			stat(filename,&fileStats);
			elem.filename = filename;           //result are pathnames
			elem.mtime = fileStats.st_mtime;

			if (fcntl(fd, F_SETLEASE, F_WRLCK) && EAGAIN == errno) {        //this test not work on tmpfs,nfs,ramfs as a workaround check mtime and actual date
                                                                            //if used one of fs above, test only mtime of a file and given timeout (120)
				if (!privListDir::file_mtimer(elem, 120)) {
					//skip this file, because it is already write locked
					close(fd);
					continue;
				}
			}
			fcntl(fd, F_SETLEASE, F_UNLCK);
			//add this file to list
			close(fd);
			tmpVec.push_back(elem);
		}
	}
	sort( tmpVec.begin(), tmpVec.begin() + tmpVec.size(), &privListDir::files_sorter_asc);
	for (unsigned n=0; n<tmpVec.size(); ++n) {
		outQueue.push(tmpVec.at(n).filename);
	}
	return outQueue;
}

vector<string> explode(const string& str, const char& ch) {
	string next;
    vector<string> result;

	for (string::const_iterator it = str.begin(); it != str.end(); it++) {
		if (*it == ch) {
			if (!next.empty()) {
				result.push_back(next);
				next.clear();
			}
		} else {
			next += *it;
		}
	}
	if (!next.empty())
		result.push_back(next);
	return result;
}

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

int file_exists (const char * fileName) {
	return(file_exists((char*)fileName));
}

bool DirExists(char *strFilename) {
	struct stat stFileInfo;
	int intStat;

	// Attempt to get the file attributes 
	intStat = stat(strFilename, &stFileInfo);
	if(intStat == 0 && S_ISDIR(stFileInfo.st_mode))  {
		// We were able to get the dir attributes 
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
			curl_easy_setopt(curl, CURLOPT_SSLVERSION, 3);
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
				if(verbosity > 1) {
					syslog(LOG_NOTICE, "get_url_file %s", (hostProtPrefix +  hostIP + path).c_str());
				}
			} else {
				curl_easy_setopt(curl, CURLOPT_URL, url);
				if(verbosity > 1) {
					syslog(LOG_NOTICE, "get_url_file %s", url);
				}
			}
			extern char opt_curlproxy[256];
			if(opt_curlproxy[0]) {
				curl_easy_setopt(curl, CURLOPT_PROXY, opt_curlproxy);
			}
			curl_easy_setopt(curl, CURLOPT_DNS_USE_GLOBAL_CACHE, 1);
			curl_easy_setopt(curl, CURLOPT_DNS_CACHE_TIMEOUT, -1);
			curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
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

size_t _get_url_response_writer_function(void *ptr, size_t size, size_t nmemb, SimpleBuffer *response) {
	response->add(ptr, size * nmemb);
	return size * nmemb;
}
bool get_url_response(const char *url, SimpleBuffer *response, vector<dstring> *postData, string *error) {
	if(error) {
		*error = "";
	}
	bool rslt = false;
	CURL *curl = curl_easy_init();
	if(curl) {
		struct curl_slist *headers = NULL;
		char errorBuffer[1024];
		curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _get_url_response_writer_function);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);
		curl_easy_setopt(curl, CURLOPT_SSLVERSION, 3);
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
		string postFields;
		if(postData) {
			for(size_t i = 0; i < postData->size(); i++) {
				if(!postFields.empty()) {
					postFields.append("&");
				}
				postFields.append((*postData)[i][0]);
				postFields.append("=");
				postFields.append(url_encode((*postData)[i][1]));
			}
			if(!postFields.empty()) {
				curl_easy_setopt(curl, CURLOPT_POST, 1);
				curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postFields.c_str());
			}
		}
		if(curl_easy_perform(curl) == CURLE_OK) {
			rslt = true;
		} else {
			if(error) {
				*error = errorBuffer;
			}
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
	return double((double)sec + (0.000001f * (double)usec));
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
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, (void*)str.c_str(), str.length());
	unsigned char _md5[MD5_DIGEST_LENGTH];
	MD5_Final(_md5, &ctx);
	return(MD5_String(_md5));
}

string GetFileMD5(std::string filename) {
	long long fileSize = GetFileSize(filename);
	if(!fileSize) {
		return("");
	}
	FILE *fileHandle = fopen(filename.c_str(), "rb");
	if(!fileHandle) {
		return("");
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

string GetDataMD5(u_char *data, u_int32_t datalen) {
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, data, datalen);
	unsigned char _md5[MD5_DIGEST_LENGTH];
	MD5_Final(_md5, &ctx);
	return(MD5_String(_md5));
}

string GetStringSHA256(std::string str) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, str.c_str(), str.length());
	SHA256_Final(hash, &sha256);
	char outputBuffer[65];
	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
	}
	outputBuffer[64] = 0;
	return(outputBuffer);
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

string getActDateTimeF(bool useT_symbol) {
	time_t actTime = time(NULL);
	struct tm *actTimeInfo = localtime(&actTime);
	char dateTimeF[20];
	strftime(dateTimeF, 20, 
		 useT_symbol ? "%Y-%m-%dT%T" : "%Y-%m-%d %T", 
		 actTimeInfo);
	return(dateTimeF);
}

unsigned long getUptime() {
	extern time_t startTime;
	time_t actTime;
	time(&actTime);
	return(actTime - startTime);
}


PcapDumper::PcapDumper(eTypePcapDump type, class Call *call) {
	this->type = type;
	this->call = call;
	this->capsize = 0;
	this->size = 0;
	this->handle = NULL;
	this->openError = false;
	this->openAttempts = 0;
	this->state = state_na;
	this->dlt = -1;
	this->lastTimeSyslog = 0;
	this->_bufflength = -1;
	this->_asyncwrite = -1;
	this->_zip = -1;
}

PcapDumper::~PcapDumper() {
	if(this->handle) {
		this->close();
	}
}

bool PcapDumper::open(const char *fileName, const char *fileNameSpoolRelative, pcap_t *useHandle, int useDlt) {
	if(this->type == rtp && this->openAttempts >= 10) {
		return(false);
	}
	if(this->handle) {
		this->close();
		syslog(LOG_NOTICE, "pcapdumper: reopen %s -> %s", this->fileName.c_str(), fileName);
	}
	/* disable - too slow
	if(file_exists((char*)fileName)) {
		if(verbosity > 2) {
			syslog(LOG_NOTICE,"pcapdumper: [%s] already exists, not overwriting", fileName);
		}
	}
	*/
	extern pcap_t *global_pcap_handle_dead_EN10MB;
	extern int opt_convert_dlt_sll_to_en10;
	pcap_t *_handle = useDlt == (DLT_LINUX_SLL && opt_convert_dlt_sll_to_en10 && global_pcap_handle_dead_EN10MB) || !useHandle ?
			   global_pcap_handle_dead_EN10MB : 
			   useHandle;
	this->capsize = 0;
	this->size = 0;
	string errorString;
	this->dlt = useDlt == DLT_LINUX_SLL && opt_convert_dlt_sll_to_en10 ? DLT_EN10MB : useDlt;
	this->handle = __pcap_dump_open(_handle, fileName, this->dlt, &errorString,
					_bufflength, _asyncwrite, _zip);
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
	if(fileNameSpoolRelative) {
		this->fileNameSpoolRelative = fileNameSpoolRelative;
	}
	if(this->handle != NULL) {
		this->state = state_open;
		return(true);
	} else {
		return(false);
	}
}

#define PCAP_DUMPER_PACKET_HEADER_SIZE 16
#define PCAP_DUMPER_HEADER_SIZE 24

bool incorrectCaplenDetected = false;

void PcapDumper::dump(pcap_pkthdr* header, const u_char *packet, int dlt) {
	extern int opt_convert_dlt_sll_to_en10;
	if((dlt == DLT_LINUX_SLL && opt_convert_dlt_sll_to_en10 ? DLT_EN10MB : dlt) != this->dlt) {
		u_long actTime = getTimeMS();
		if(actTime - 1000 > lastTimeSyslog) {
			syslog(LOG_NOTICE, "warning - use dlt (%i) for pcap %s created for dlt (%i)",
			       dlt, this->fileName.c_str(), this->dlt);
			lastTimeSyslog = actTime;
		}
		return;
	}
	extern unsigned int opt_maxpcapsize_mb;
	if(this->handle) {
		if(header->caplen > 0 && header->caplen <= header->len) {
			if(!opt_maxpcapsize_mb || this->capsize < opt_maxpcapsize_mb * 1024 * 1024) {
				__pcap_dump((u_char*)this->handle, header, packet);
				extern int opt_packetbuffered;
				if(opt_packetbuffered) {
					this->flush();
				}
				this->capsize += header->caplen + PCAP_DUMPER_PACKET_HEADER_SIZE;
				this->size += header->len + PCAP_DUMPER_PACKET_HEADER_SIZE;
			}
		} else {
			syslog(LOG_NOTICE, "pcapdumper: incorrect caplen/len (%u/%u) in %s", header->caplen, header->len, fileName.c_str());
			incorrectCaplenDetected = true;
		}
		this->state = state_dump;
	}
}

void PcapDumper::close(bool updateFilesQueue) {
	if(this->handle) {
		if(this->_asyncwrite == 0) {
			__pcap_dump_close(this->handle);
			this->handle = NULL;
			this->state = state_close;
		} else {
			if(this->call) {
				asyncClose.add(this->handle, updateFilesQueue,
					       this->call, this,
					       this->fileNameSpoolRelative.c_str(), 
					       type == rtp ? "rtpsize" : 
					       this->call->type == REGISTER ? "regsize" : "sipsize",
					       0/*this->capsize + PCAP_DUMPER_HEADER_SIZE ignore size counter - header->capsize can contain -1*/);
			} else {
				asyncClose.add(this->handle);
			}
			this->handle = NULL;
			this->state = state_do_close;
		}
	}
}

void PcapDumper::flush() {
	__pcap_dump_flush(this->handle);
}

void PcapDumper::remove() {
	if(this->handle) {
		this->close(false);
		unlink(this->fileName.c_str());
	}
}


extern int opt_gzipGRAPH;

RtpGraphSaver::RtpGraphSaver(RTP *rtp) {
	this->rtp = rtp;
	this->handle = NULL;
}

RtpGraphSaver::~RtpGraphSaver() {
	if(this->isOpen()) {
		this->close();
	}
}

bool RtpGraphSaver::open(const char *fileName, const char *fileNameSpoolRelative) {
	if(this->handle) {
		this->close();
		syslog(LOG_NOTICE, "graphsaver: reopen %s -> %s", this->fileName.c_str(), fileName);
	}
	/* disable - too slow
	if(file_exists((char*)fileName)) {
		if(verbosity > 2) {
			syslog(LOG_NOTICE,"graphsaver: [%s] already exists, not overwriting", fileName);
		}
	}
	*/
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
		if(call) {
			asyncClose.add(this->handle, updateFilesQueue,
				       call,
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

AsyncClose::AsyncCloseItem::AsyncCloseItem(Call *call, PcapDumper *pcapDumper, const char *file, const char *column, long long writeBytes) {
	this->call = call;
	if(call) {
		this->call_dirnamesqlfiles = call->dirnamesqlfiles();
	}
	this->pcapDumper = pcapDumper;
	if(file) {
		this->file = file;
	}
	if(column) {
		this->column = column;
	}
	this->writeBytes = writeBytes;
	this->dataLength = 0;
}

void AsyncClose::AsyncCloseItem::addtofilesqueue() {
	if(!call) {
		return;
	}
	Call::_addtofilesqueue(this->file, this->column, call_dirnamesqlfiles, this->writeBytes);
	extern char opt_cachedir[1024];
	if(opt_cachedir[0] != '\0') {
		Call::_addtocachequeue(this->file);
	}
}

void *AsyncClose_process(void *_startThreadData) {
	AsyncClose::StartThreadData *startThreadData = (AsyncClose::StartThreadData*)_startThreadData;
	startThreadData->asyncClose->processTask(startThreadData->threadIndex);
	return(NULL);
}

AsyncClose::AsyncClose() {
	maxPcapThreads = min((int)sysconf(_SC_NPROCESSORS_ONLN), AsyncClose_maxPcapThreads);
	countPcapThreads = 1;
	minPcapThreads = 1;
	for(int i = 0; i < AsyncClose_maxPcapThreads; i++) {
		_sync[i] = 0;
		threadId[i] = 0;
		memset(this->threadPstatData[i], 0, sizeof(this->threadPstatData[i]));
		useThread[i] = 0;
		activeThread[i] = 0;
		cpuPeak[i] = 0;
	}
	sizeOfDataInMemory = 0;
	removeThreadProcessed = 0;
}

AsyncClose::~AsyncClose() {
	for(int i = 0; i < AsyncClose_maxPcapThreads; i++) {
		while(q[i].size()) {
			AsyncCloseItem *item = q[i].front();
			item->processClose();
			delete item;
			q[i].pop();
		}
	}
}

void AsyncClose::startThreads(int countPcapThreads, int maxPcapThreads) {
	if(maxPcapThreads < this->maxPcapThreads) {
		this->maxPcapThreads = maxPcapThreads;
	}
	this->countPcapThreads = opt_pcap_dump_bufflength ?
				  min(this->maxPcapThreads, countPcapThreads) :
				  1;
	this->minPcapThreads = this->countPcapThreads;
	for(int i = 0; i < this->countPcapThreads; i++) {
		startThreadData[i].threadIndex = i;
		startThreadData[i].asyncClose = this;
		activeThread[i] = 1;
		pthread_create(&this->thread[i], NULL, AsyncClose_process, &startThreadData[i]);
	}
}

void AsyncClose::addThread() {
	if(opt_pcap_dump_bufflength && countPcapThreads < maxPcapThreads &&
	   !removeThreadProcessed) {
		startThreadData[countPcapThreads].threadIndex = countPcapThreads;
		startThreadData[countPcapThreads].asyncClose = this;
		useThread[countPcapThreads] = 0;
		activeThread[countPcapThreads] = 1;
		cpuPeak[countPcapThreads] = 0;
		memset(this->threadPstatData[countPcapThreads], 0, sizeof(this->threadPstatData[countPcapThreads]));
		pthread_create(&this->thread[countPcapThreads], NULL, AsyncClose_process, &startThreadData[countPcapThreads]);
		++countPcapThreads;
	}
}

void AsyncClose::removeThread() {
	if(opt_pcap_dump_bufflength && countPcapThreads > minPcapThreads &&
	   !removeThreadProcessed && cpuPeak[countPcapThreads - 1] > 10) {
		removeThreadProcessed = 1;
		--countPcapThreads;
	}
}

void AsyncClose::processTask(int threadIndex) {
	this->threadId[threadIndex] = get_unix_tid();
	do {
		processAll(threadIndex);
		if(removeThreadProcessed && threadIndex >= countPcapThreads) {
			lock(threadIndex);
			if(!useThread[threadIndex] || !q[threadIndex].size()) {
				activeThread[threadIndex] = 0;
				unlock(threadIndex);
				removeThreadProcessed = 0;
				break;
			}
			unlock(threadIndex);
		}
		usleep(10000);
	} while(!terminating);
}

void AsyncClose::processAll(int threadIndex) {
	while(true) {
		lock(threadIndex);
		if(q[threadIndex].size()) {
			AsyncCloseItem *item = q[threadIndex].front();
			q[threadIndex].pop();
			sub_sizeOfDataInMemory(item->dataLength);
			unlock(threadIndex);
			item->process();
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
			double rslt = ucpu_usage + scpu_usage;
			if(rslt > cpuPeak[threadIndex]) {
				cpuPeak[threadIndex] = rslt;
			}
			return(rslt);
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
	if(sizeof(int *) == 8) {
		this->_64bit = true;
	} else {
		this->_64bit = false;
	}
}

bool RestartUpgrade::runUpgrade() {
	if(verbosity > 0) {
		syslog(LOG_NOTICE, "start upgrade from: '%s'", url.c_str());
	}
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
		if(verbosity > 0) {
			syslog(LOG_ERR, "upgrade failed - %s", this->errorString.c_str());
		}
		return(false);
	}
	if(!this->upgradeTempFileName.length() && !this->getUpgradeTempFileName()) {
		this->errorString = "failed create temp name for new binary";
		if(verbosity > 0) {
			syslog(LOG_ERR, "upgrade failed - %s", this->errorString.c_str());
		}
		return(false);
	}
	if(mkdir(this->upgradeTempFileName.c_str(), 0700)) {
		this->errorString = "failed create folder " + this->upgradeTempFileName;
		if(verbosity > 0) {
			syslog(LOG_ERR, "upgrade failed - %s", this->errorString.c_str());
		}
		return(false);
	}
	unlink(this->upgradeTempFileName.c_str());
	char outputStdoutErr[L_tmpnam+1];
	if(!tmpnam(outputStdoutErr)) {
		this->errorString = "failed create temp name for output curl and gunzip";
		if(verbosity > 0) {
			syslog(LOG_ERR, "upgrade failed - %s", this->errorString.c_str());
		}
		return(false);
	}
	string binaryFilepathName = this->upgradeTempFileName + "/voipmonitor";
	string binaryGzFilepathName = this->upgradeTempFileName + "/voipmonitor.gz";
	extern int opt_upgrade_try_http_if_https_fail;
	for(int pass = 0; pass < (opt_upgrade_try_http_if_https_fail ? 2 : 1); pass++) {
		string error;
		string _url = (pass == 1 ? urlHttp : url) + 
			      "/voipmonitor.gz." + (this->_64bit ? "64" : "32");
		if(verbosity > 0) {
			syslog(LOG_NOTICE, "try download file: '%s'", _url.c_str());
		}
		if(get_url_file(_url.c_str(), binaryGzFilepathName.c_str(), &error)) {
			syslog(LOG_NOTICE, "download file '%s' finished", _url.c_str());
			this->errorString = "";
			break;
		} else {
			this->errorString = "failed download upgrade: " + error;
			if(pass || !opt_upgrade_try_http_if_https_fail) {
				rmdir_r(this->upgradeTempFileName.c_str());
				if(verbosity > 0) {
					syslog(LOG_ERR, "upgrade failed - %s", this->errorString.c_str());
				}
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
		if(verbosity > 0) {
			syslog(LOG_ERR, "upgrade failed - %s", this->errorString.c_str());
		}
		return(false);
	}
	long long binaryGzFilepathNameSize = GetFileSize(binaryGzFilepathName.c_str()); 
	if(!binaryGzFilepathNameSize) {
		this->errorString = "failed download - zero size of destination file";
		rmdir_r(this->upgradeTempFileName.c_str());
		if(verbosity > 0) {
			syslog(LOG_ERR, "upgrade failed - %s", this->errorString.c_str());
		}
		return(false);
	}
	string unzipCommand = "gunzip " + binaryGzFilepathName +
			      " >" + outputStdoutErr + " 2>&1";
	if(verbosity > 0) {
		syslog(LOG_NOTICE, "try unzip command: '%s'", unzipCommand.c_str());
	}
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
			char sizeInfo[200];
			sprintf(sizeInfo, "size of file %s: %lli", binaryGzFilepathName.c_str(), binaryGzFilepathNameSize);
			this->errorString += string("\n") + sizeInfo;
		}
		if(verbosity > 1) {
			FILE *f = fopen(binaryGzFilepathName.c_str(), "rt");
			char buff[10000];
			while(fgets(buff, sizeof(buff), f)) {
				cout << buff << endl;
			}
		}
		unlink(outputStdoutErr);
		if(verbosity < 2) {
			rmdir_r(this->upgradeTempFileName.c_str());
		}
		if(verbosity > 0) {
			syslog(LOG_ERR, "upgrade failed - %s", this->errorString.c_str());
		}
		return(false);
	} else {
		if(verbosity > 0) {
			syslog(LOG_NOTICE, "unzip finished");
		}
	}
	string md5 = GetFileMD5(binaryFilepathName);
	if((this->_64bit ? md5_64 : md5_32) != md5) {
		this->errorString = "failed download - bad md5: " + md5 + " <> " + (this->_64bit ? md5_64 : md5_32);
		rmdir_r(this->upgradeTempFileName.c_str());
		if(verbosity > 0) {
			syslog(LOG_ERR, "upgrade failed - %s", this->errorString.c_str());
		}
		return(false);
	}
	unlink("/usr/local/sbin/voipmonitor");
	if(!copy_file(binaryFilepathName.c_str(), "/usr/local/sbin/voipmonitor", true)) {
		this->errorString = "failed copy new binary to /usr/local/sbin";
		rmdir_r(this->upgradeTempFileName.c_str());
		if(verbosity > 0) {
			syslog(LOG_ERR, "upgrade failed - %s", this->errorString.c_str());
		}
		return(false);
	}
	if(chmod("/usr/local/sbin/voipmonitor", 0755)) {
		this->errorString = "failed chmod 0755 voipmonitor";
		rmdir_r(this->upgradeTempFileName.c_str());
		if(verbosity > 0) {
			syslog(LOG_ERR, "upgrade failed - %s", this->errorString.c_str());
		}
		return(false);
	}
	rmdir_r(this->upgradeTempFileName.c_str());
	return(true);
}

bool RestartUpgrade::createRestartScript() {
	if(verbosity > 0) {
		syslog(LOG_NOTICE, "create restart script");
	}
	if(!this->restartTempScriptFileName.length() && !this->getRestartTempScriptFileName()) {
		this->errorString = "failed create temp name for restart script";
		if(verbosity > 0) {
			syslog(LOG_ERR, "create restart script failed - %s", this->errorString.c_str());
		}
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
		if(verbosity > 0) {
			syslog(LOG_ERR, "create restart script failed - %s", this->errorString.c_str());
		}
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
	if(verbosity > 0) {
		syslog(LOG_NOTICE, "run restart script");
	}
	if(!this->checkReadyRestart()) {
		if(verbosity > 0) {
			syslog(LOG_ERR, "restart failed - %s", this->errorString.c_str());
		}
		return(false);
	}
	close(socket1);
	close(socket2);
	terminate_packetbuffer();
	sleep(2);

	// set to all descriptors flag CLOEXEC so exec* will close it and will not inherit it so the next voipmonitor instance will be not blocking it
	long maxfd = sysconf(_SC_OPEN_MAX);
	int flags;
	for(int fd = 3; fd < maxfd; fd++) {
		if((flags = fcntl(fd, F_GETFD)) != -1) {
			fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
		}
		close(fd);
	}

	int rsltExec = execl(this->restartTempScriptFileName.c_str(), "Command-line", 0, NULL);
	if(rsltExec) {
		this->errorString = "failed execution restart script";
		if(verbosity > 0) {
			syslog(LOG_ERR, "restart failed - %s", this->errorString.c_str());
		}
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

std::string pexec(char* cmd, int *exitCode) {
	FILE* pipe = popen(cmd, "r");
	if (!pipe) return "ERROR";
	char buffer[128];
	std::string result = "";
	while(!feof(pipe)) {
		if(fgets(buffer, 128, pipe) != NULL)
			result += buffer;
	}
	int _exitCode = pclose(pipe);
	if(exitCode) {
		*exitCode = _exitCode;
	}
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

std::string trim_str(std::string s) {
	return(trim(s));
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
	in.s_addr = htonl(ip);
	return(inet_ntoa(in));
}


void ListIP::addComb(string &ip, ListIP *negList) {
	addComb(ip.c_str(), negList);
}

void ListIP::addComb(const char *ip, ListIP *negList) {
	vector<string>ip_elems = split(ip, split(",|;|\t|\r|\n", "|"), true);
	for(size_t i = 0; i < ip_elems.size(); i++) {
		if(ip_elems[i][0] == '!') {
			if(negList) {
				negList->add(ip_elems[i].substr(1).c_str());
			}
		} else {
			add(ip_elems[i].c_str());
		}
	}
}

void ListPhoneNumber::addComb(string &number, ListPhoneNumber *negList) {
	addComb(number.c_str(), negList);
}

void ListPhoneNumber::addComb(const char *number, ListPhoneNumber *negList) {
	vector<string>number_elems = split(number, split(",|;|\t|\r|\n", "|"), true);
	for(size_t i = 0; i < number_elems.size(); i++) {
		if(number_elems[i][0] == '!') {
			if(negList) {
				negList->add(number_elems[i].substr(1).c_str());
			}
		} else {
			add(number_elems[i].c_str());
		}
	}
}

ListIP_wb::ListIP_wb(bool autoLock)
 : white(autoLock),
   black(autoLock) {
}

void ListIP_wb::addWhite(string &ip) {
	white.addComb(ip, &black);
}

void ListIP_wb::addWhite(const char *ip) {
	white.addComb(ip, &black);
}

void ListIP_wb::addBlack(string &ip) {
	black.addComb(ip, &white);
}

void ListIP_wb::addBlack(const char *ip) {
	black.addComb(ip, &white);
}

ListPhoneNumber_wb::ListPhoneNumber_wb(bool autoLock)
 : white(autoLock),
   black(autoLock) {
}

void ListPhoneNumber_wb::addWhite(string &number) {
	white.addComb(number, &black);
}

void ListPhoneNumber_wb::addWhite(const char *number) {
	white.addComb(number, &black);
}

void ListPhoneNumber_wb::addBlack(string &number) {
	black.addComb(number, &white);
}

void ListPhoneNumber_wb::addBlack(const char *number) {
	black.addComb(number, &white);
}


unsigned long ParsePacket::parseData(char *data, unsigned long datalen, bool doClear) {
	unsigned long rsltDataLen = datalen;
	if(doClear) {
		clear();
	}
	sip = datalen ? isSipContent(data, datalen - 1) : false;
	ppContent *content;
	unsigned int namelength;
	for(unsigned long i = 0; i < datalen; i++) {
		if(!doubleEndLine && 
		   datalen > 3 &&
		   data[i] == '\r' && i < datalen - 3 && 
		   data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
			doubleEndLine = data + i;
			if(contentLength > -1) {
				unsigned long modify_datalen = doubleEndLine + 4 - data + contentLength;
				if(modify_datalen < datalen) {
					datalen = modify_datalen;
					rsltDataLen = datalen;
				}
			} else {
				rsltDataLen = doubleEndLine + 4 - data;
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
	return(rsltDataLen);
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


JsonItem::JsonItem(string name, string value) {
	this->name = name;
	this->value = value;
	this->parse(value);
}

void JsonItem::parse(string valStr) {
	////cerr << "valStr: " << valStr << endl;
	if(valStr[0] != '{' && valStr[0] != '[') {
		return;
	}
	json_object * object = json_tokener_parse(valStr.c_str());
	json_type objectType = json_object_get_type(object);
	////cerr << "type: " << objectType << endl;
	if(objectType == json_type_object) {
		lh_table *objectItems = json_object_get_object(object);
		struct lh_entry *objectItem = objectItems->head;
		while(objectItem) {
			string fieldName = (char*)objectItem->k;
			string value = objectItem->v ?
					json_object_get_string((json_object*)objectItem->v) :
					"";
			////cerr << "objectItem: " << fieldName << " - " << value << endl;
			JsonItem newItem(fieldName, value);
			this->items.push_back(newItem);
			objectItem = objectItem->next;
		}
	} else if(objectType == json_type_array) {
		int length = json_object_array_length(object);
		for(int i = 0; i < length; i++) {
			json_object *obj = json_object_array_get_idx(object, i);
			string value;
			if(obj) {
				value = json_object_get_string(obj);
				////cerr << "arrayItem: " << i << " - " << value << endl;
			}
			stringstream streamIndexName;
			streamIndexName << i;
			JsonItem newItem(streamIndexName.str(), value);
			this->items.push_back(newItem);
		}
	}
}

JsonItem *JsonItem::getItem(string path, int index) {
	if(index >= 0) {
		stringstream streamIndexName;
		streamIndexName << index;
		path += '/' + streamIndexName.str();
	}
	JsonItem *item = this->getPathItem(path);
	if(item) {
		string pathItemName = this->getPathItemName(path);
		if(path.length()>pathItemName.length()) {
			return(item->getItem(path.substr(pathItemName.length()+1)));
		} else {
			return(item);
		}
	}
	return(NULL);
}

string JsonItem::getValue(string path, int index) {
	JsonItem *item = this->getItem(path, index);
	return(item ? item->value : "");
}

int JsonItem::getCount(string path) {
	JsonItem *item = this->getItem(path);
	return(item ? item->items.size() : 0);
}

JsonItem *JsonItem::getPathItem(string path) {
	string pathItemName = this->getPathItemName(path);
	for(int i = 0; i < (int)this->items.size(); i++) {
		if(this->items[i].name == pathItemName) {
			return(&this->items[i]);
		}
	}
	return(NULL);
}

string JsonItem::getPathItemName(string path) {
	string pathItemName = path;
	int sepPos = pathItemName.find('/');
	if(sepPos > 0) {
		pathItemName.resize(sepPos);
	}
	return(pathItemName);
}


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
	this->permission = 0;
	this->fh = 0;
	this->zipStream = NULL;
	this->bufferLength = bufferLength;
	if(bufferLength) {
		this->buffer = new char[bufferLength];
	} else {
		this->buffer = NULL;
	}
	this->zipBuffer = NULL;
	this->useBufferLength = 0;
	this->enableAsyncWrite = enableAsyncWrite && !opt_read_from_file;
	this->enableZip = enableZip;
	this->dumpHandler = dumpHandler;
	this->size = 0;
	this->counter = ++scounter;
	this->userData = 0;
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
	this->permission = permission;
	return(true);
}

void FileZipHandler::close() {
	this->flushBuffer(true);
	if(this->okHandle()) {
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
	if(!this->error.empty()) {
		return(false);
	}
	if(this->enableZip) {
		if(!this->zipStream && !this->initZip()) {
			return(false);
		}
		this->zipStream->avail_in = length;
		this->zipStream->next_in = (unsigned char*)data;
		do {
			this->zipStream->avail_out = this->bufferLength;
			this->zipStream->next_out = (unsigned char*)this->zipBuffer;
			if(deflate(this->zipStream, flush ? Z_FINISH : Z_NO_FLUSH) != Z_STREAM_ERROR) {
				int have = this->bufferLength - this->zipStream->avail_out;
				if(this->__writeToFile(this->zipBuffer, have) <= 0) {
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
		int rsltWrite = this->__writeToFile(data, length);
		if(rsltWrite <= 0) {
			this->setError();
			return(false);
		} else {
			this->size += length;
			return(true);
		}
	}
}

bool FileZipHandler::__writeToFile(char *data, int length) {
	if(!this->okHandle()) {
		if(!this->error.empty() || !this->_open()) {
			return(false);
		}
	}
	if(::write(this->fh, data, length) == length) {
		return(true);
	} else {
		bool oldError = !error.empty();
		this->setError();
		if(!oldError) {
			syslog(LOG_NOTICE, "error write to file %s - %s", fileName.c_str(), error.c_str());
		}
		return(false);
	}
}

bool FileZipHandler::initZip() {
	if(this->enableZip && !this->zipStream) {
		this->zipStream =  new z_stream;
		this->zipStream->zalloc = Z_NULL;
		this->zipStream->zfree = Z_NULL;
		this->zipStream->opaque = Z_NULL;
		if(deflateInit2(this->zipStream, opt_pcap_dump_ziplevel, Z_DEFLATED, MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
			deflateEnd(this->zipStream);
			this->setError("zip initialize failed");
			return(false);
		} else {
			this->zipBuffer = new char[bufferLength ? bufferLength : 8192];
		}
	}
	return(true);
}

bool FileZipHandler::_open() {
	for(int passOpen = 0; passOpen < 2; passOpen++) {
		if(passOpen == 1) {
			char *pointToLastDirSeparator = strrchr((char*)fileName.c_str(), '/');
			if(pointToLastDirSeparator) {
				*pointToLastDirSeparator = 0;
				mkdir_r(fileName.c_str(), 0777);
				*pointToLastDirSeparator = '/';
			} else {
				break;
			}
		}
		this->fh = ::open(fileName.c_str(), O_WRONLY | O_CREAT | O_TRUNC, permission);
		if(this->okHandle()) {
			break;
		}
	}
	if(this->okHandle()) {
		return(true);
	} else {
		this->setError();
		syslog(LOG_NOTICE, "error open handle to file %s - %s", fileName.c_str(), error.c_str());
		return(false);
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

pcap_dumper_t *__pcap_dump_open(pcap_t *p, const char *fname, int linktype, string *errorString,
				int _bufflength, int _asyncwrite, int _zip) {
	if(opt_pcap_dump_bufflength) {
		FileZipHandler *handler = new FileZipHandler(_bufflength < 0 ? opt_pcap_dump_bufflength : _bufflength, 
							     _asyncwrite < 0 ? opt_pcap_dump_asyncwrite : _asyncwrite, 
							     _zip < 0 ? opt_pcap_dump_zip : _zip, 
							     true);
		if(handler->open(fname)) {
			struct pcap_file_header hdr;
			hdr.magic = TCPDUMP_MAGIC;
			hdr.version_major = PCAP_VERSION_MAJOR;
			hdr.version_minor = PCAP_VERSION_MINOR;
			hdr.thiszone = 0;
			hdr.snaplen = 10000;
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
		FileZipHandler *handler = (FileZipHandler*)user;
		if(h->caplen > 0 && h->caplen <= h->len) {
			struct pcap_timeval {
			    bpf_int32 tv_sec;		/* seconds */
			    bpf_int32 tv_usec;		/* microseconds */
			};
			struct pcap_sf_pkthdr {
			    struct pcap_timeval ts;	/* time stamp */
			    bpf_u_int32 caplen;		/* length of portion present */
			    bpf_u_int32 len;		/* length this packet (off wire) */
			};
			
			struct pcap_sf_pkthdr sf_hdr;
			sf_hdr.ts.tv_sec  = h->ts.tv_sec;
			sf_hdr.ts.tv_usec = h->ts.tv_usec;
			sf_hdr.caplen     = h->caplen;
			sf_hdr.len        = h->len;
			handler->write((char*)&sf_hdr, sizeof(sf_hdr));
			handler->write((char*)sp, h->caplen);
		} else {
			syslog(LOG_NOTICE, "__pcap_dump: incorrect caplen/len (%u/%u) in %s", h->caplen, h->len, handler->fileName.c_str());
			incorrectCaplenDetected = true;
		}
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

void __pcap_dump_flush(pcap_dumper_t *p) {
	if(opt_pcap_dump_bufflength) {
		FileZipHandler *handler = (FileZipHandler*)p;
		handler->flushBuffer(true);
	} else {
		pcap_dump_flush(p);
	}
}

char *__pcap_geterr(pcap_t *p, pcap_dumper_t *pd) {
	if(opt_pcap_dump_bufflength && pd) {
		return((char*)((FileZipHandler*)pd)->error.c_str());
	} else {
		return(pcap_geterr(p));
	}
}

void base64_init(void)
{
        int x;
        memset(b2a, -1, sizeof(b2a));
        /* Initialize base-64 Conversion table */
        for (x = 0; x < 26; x++) {
                /* A-Z */
                base64[x] = 'A' + x;
                b2a['A' + x] = x;
                /* a-z */
                base64[x + 26] = 'a' + x;
                b2a['a' + x] = x + 26;
                /* 0-9 */
                if (x < 10) {
                        base64[x + 52] = '0' + x;
                        b2a['0' + x] = x + 52;
                }      
        }      
        base64[62] = '+';
        base64[63] = '/';
        b2a[(int)'+'] = 62;
        b2a[(int)'/'] = 63;
}      

/*! \brief decode BASE64 encoded text */
int base64decode(unsigned char *dst, const char *src, int max)
{
        int cnt = 0;
        unsigned int byte = 0;
        unsigned int bits = 0;
        int incnt = 0;
        while(*src && *src != '=' && (cnt < max)) {
                /* Shift in 6 bits of input */
                byte <<= 6;
                byte |= (b2a[(int)(*src)]) & 0x3f;
                bits += 6;
                src++;
                incnt++;
                /* If we have at least 8 bits left over, take that character 
                   off the top */
                if (bits >= 8)  {
                        bits -= 8;
                        *dst = (byte >> bits) & 0xff;
                        dst++;
                        cnt++;
                }
        }
        /* Dont worry about left over bits, they're extra anyway */
        return cnt;
}

void find_and_replace(string &source, const string find, string replace) {
 	size_t j;
	for ( ; (j = source.find( find )) != string::npos ; ) {
		source.replace( j, find.length(), replace );
	}
}

string find_and_replace(const char *source, const char *find, const char *replace) {
	string s_source = source;
	find_and_replace(s_source, find, replace);
	return(s_source);
}

bool isLocalIP(u_int32_t ip) {
	const char *net_str[] = {
		"192.168.0.0/16",
		"10.0.0.0/8",
		"172.16.0.0/20"
	};
	static u_int32_t net_mask[3] = { 0, 0, 0 };
	if(!net_mask[0]) {
		for(int i = 0; i < 3; i++) {
			vector<string> ip_net = split(net_str[i], '/');
			in_addr ips;
			inet_aton(ip_net[0].c_str(), &ips);
			u_int32_t ip = htonl(ips.s_addr);
			u_int32_t mask = -1;
			mask <<= (32 - atoi(ip_net[1].c_str()));
			net_mask[i] = ip & mask;
		}
	}
	for(int i = 0; i < 3; i++) {
		if((ip & net_mask[i]) == net_mask[i]) {
			return(true);
		}
	}
	return(false);
}

AutoDeleteAtExit GlobalAutoDeleteAtExit;

void AutoDeleteAtExit::add(const char *file) {
	files.push_back(file);
}

AutoDeleteAtExit::~AutoDeleteAtExit() {
	vector<string>::iterator iter;
	for(iter = files.begin(); iter != files.end(); ++iter) {
		unlink((*iter).c_str());
	}
}

pcap_t* pcap_open_offline_zip(const char *filename, char *errbuff) {
	if(isGunzip(filename)) {
		string error;
		string unzip = gunzipToTemp(filename, &error, true);
		if(!unzip.empty()) {
			return(pcap_open_offline(unzip.c_str(), errbuff));
		} else {
			strcpy(errbuff, error.c_str());
			return(NULL);
		}
	} else {
		return(pcap_open_offline(filename, errbuff));
	}
}

string gunzipToTemp(const char *zipFilename, string *error, bool autoDeleteAtExit) {
	char unzipTempFileName[L_tmpnam+1];
	if(tmpnam(unzipTempFileName)) {
		if(autoDeleteAtExit) {
			GlobalAutoDeleteAtExit.add(unzipTempFileName);
		}
		string _error = _gunzip_s(zipFilename, unzipTempFileName);
		if(error) {
		       *error = _error;
		}
		return(_error.empty() ? unzipTempFileName : "");
	} else {
		if(error) {
			*error = "create template file for unzip failed";
		}
		return("");
	}
}

string _gunzip_s(const char *zipFilename, const char *unzipFilename) {
	string error = "";
	FILE *zip = fopen(zipFilename, "r");
	if(zip) {
		FILE *unzip = fopen(unzipFilename, "w");
		if(unzip) {
			error = __gunzip_s(zip, unzip);
			fclose(unzip);
			fclose(zip);
		} else {
			char buf[4092];
			strerror_r(errno, buf, 4092);
			fclose(zip);
			return(buf);
		}
	} else {
		char buf[4092];
		strerror_r(errno, buf, 4092);
		return(buf);
	}
	return(error.empty() ? "" : ("unzip failed: " + error));
}

string __gunzip_s(FILE *zip, FILE *unzip) {
	int ret = __gunzip(zip, unzip);
	return ret ? zError(ret) : "";
}

#define GUNZIP_CHUNK 16384
int __gunzip(FILE *zip, FILE *unzip) {
	int ret;
	unsigned have;
	z_stream strm;
	unsigned char in[GUNZIP_CHUNK];
	unsigned char out[GUNZIP_CHUNK];

	/* allocate inflate state */
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = 0;
	strm.next_in = Z_NULL;
	ret = inflateInit2(&strm, MAX_WBITS + 16);
	if (ret != Z_OK)
		return ret;

	/* decompress until deflate stream ends or end of file */
	do {
		strm.avail_in = fread(in, 1, GUNZIP_CHUNK, zip);
		if (ferror(zip)) {
			(void)inflateEnd(&strm);
			return Z_ERRNO;
		}
		if (strm.avail_in == 0)
			break;
		strm.next_in = in;

		/* run inflate() on input until output buffer not full */
		do {
			strm.avail_out = GUNZIP_CHUNK;
			strm.next_out = out;
			ret = inflate(&strm, Z_NO_FLUSH);
			switch (ret) {
			case Z_NEED_DICT:
				ret = Z_DATA_ERROR;     /* and fall through */
			case Z_DATA_ERROR:
			case Z_MEM_ERROR:
			case Z_STREAM_ERROR:
				(void)inflateEnd(&strm);
				return ret;
			}
			have = GUNZIP_CHUNK - strm.avail_out;
			if (fwrite(out, 1, have, unzip) != have || ferror(unzip)) {
				(void)inflateEnd(&strm);
				return Z_ERRNO;
			}
		} while (strm.avail_out == 0);

		/* done when inflate() says it's done */
	} while (ret != Z_STREAM_END);

	/* clean up and return */
	(void)inflateEnd(&strm);
	return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

bool isGunzip(const char *zipFilename) {
	bool ret = false;
	FILE *zip = fopen(zipFilename, "r");
	if(zip) {
		unsigned char buff[2];
		if(fread(buff, 1, 2, zip) == 2) {
			ret = buff[0] == 0x1F && buff[1] == 0x8B;
		}
		fclose(zip);
	}
	return(ret);
}

string url_encode(const string &value) {
	ostringstream escaped;
	escaped.fill('0');
	escaped << hex;
	for (string::const_iterator i = value.begin(), n = value.end(); i != n; ++i) {
		string::value_type c = (*i);
		if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
			escaped << c;
		}
		else if (c == ' ')  {
			escaped << '+';
		}
		else {
			escaped << '%' << setw(2) << ((int) c) << setw(0);
		}
	}
	return escaped.str();
}

SocketSimpleBufferWrite::SocketSimpleBufferWrite(const char *name, ip_port ipPort, uint64_t maxSize) {
	this->name = name;
	this->ipPort = ipPort;
	this->maxSize = maxSize;
	socketHostEnt = NULL;
	socketHandle = 0;
	writeThreadHandle = 0;
	_sync_data = 0;
	_size_all = 0;
	lastTimeSyslogFullData = 0;
}

SocketSimpleBufferWrite::~SocketSimpleBufferWrite() {
	stopWriteThread();
	flushData();
	socketClose();
}

void *_SocketSimpleBufferWrite_writeFunction(void *arg) {
	usleep(1000);
	((SocketSimpleBufferWrite*)arg)->write();
	return(NULL);
}
void SocketSimpleBufferWrite::startWriteThread() {
	pthread_create(&writeThreadHandle, NULL, _SocketSimpleBufferWrite_writeFunction, this);
}

void SocketSimpleBufferWrite::stopWriteThread() {
	if(writeThreadHandle) {
		pthread_t _writeThreadHandle = writeThreadHandle;
		writeThreadHandle = 0;
		pthread_join(_writeThreadHandle, NULL);
	}
}

void SocketSimpleBufferWrite::addData(void *data1, u_int32_t dataLength1,
				      void *data2, u_int32_t dataLength2) {
	if(!data1 || !dataLength1) {
		return;
	}
	if(_size_all + (dataLength1 + dataLength2) > maxSize) {
		u_long actTime = getTimeMS();
		if(!lastTimeSyslogFullData || actTime > lastTimeSyslogFullData + 1000) {
			syslog(LOG_NOTICE, "socketwrite %s: data buffer is full", name.c_str());
			lastTimeSyslogFullData = actTime;
		}
	}
	SimpleBuffer *simpleBuffer = new SimpleBuffer(dataLength2);
	simpleBuffer->add(data1, dataLength1);
	simpleBuffer->add(data2, dataLength2);
	lock_data();
	this->data.push(simpleBuffer);
	add_size(dataLength1 + dataLength2);
	unlock_data();
}

void SocketSimpleBufferWrite::write() {
	socketConnect();
	while(!terminating && writeThreadHandle) {
		SimpleBuffer *simpleBuffer = NULL;
		lock_data();
		if(data.size()) {
			simpleBuffer = data.front();
			data.pop();
			sub_size(simpleBuffer->size());
		}
		unlock_data();
		if(simpleBuffer) {
			socketWrite(simpleBuffer->data(), simpleBuffer->size());
			delete simpleBuffer;
		} else {
			usleep(1000);
		}
	}
}

bool SocketSimpleBufferWrite::socketGetHost() {
	socketHostEnt = NULL;
	while(!socketHostEnt) {
		socketHostEnt = gethostbyname(ipPort.get_ip().c_str());
		if(!socketHostEnt) {
			syslog(LOG_ERR, "socketwrite %s: cannot resolv: %s: host [%s] - trying again", name.c_str(), hstrerror(h_errno), ipPort.get_ip().c_str());  
			sleep(1);
		}
	}
	return(true);
}

bool SocketSimpleBufferWrite::socketConnect() {
	if(!socketHostEnt) {
		socketGetHost();
	}
	if((socketHandle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		syslog(LOG_NOTICE, "socketwrite %s: cannot create socket", name.c_str());
		return(false);
	}
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(ipPort.get_port());
	addr.sin_addr.s_addr = *(long*)socketHostEnt->h_addr_list[0];
	while(connect(socketHandle, (struct sockaddr *)&addr, sizeof(addr)) == -1 && !terminating) {
		syslog(LOG_NOTICE, "socketwrite %s: failed to connect to server [%s] error:[%s] - trying again", name.c_str(), inet_ntoa(*(struct in_addr *)socketHostEnt->h_addr_list[0]), strerror(errno));
		sleep(1);
	}
	return(true);
}

bool SocketSimpleBufferWrite::socketClose() {
	if(socketHandle) {
		close(socketHandle);
		socketHandle = 0;
	}
	return(true);
}

bool SocketSimpleBufferWrite::socketWrite(void *data, u_int32_t dataLength) {
	if(!socketHandle) {
		socketConnect();
	}
	size_t dataLengthWrited = 0;
	while(dataLengthWrited < dataLength && !terminating) {
		ssize_t _dataLengthWrited = send(socketHandle, (u_char*)data + dataLengthWrited, dataLength - dataLengthWrited, 0);
		if(_dataLengthWrited == -1) {
			socketConnect();
		} else {
			dataLengthWrited += _dataLengthWrited;
		}
	}
	return(true);
}

void SocketSimpleBufferWrite::flushData() {
	SimpleBuffer *simpleBuffer = NULL;
	lock_data();
	while(data.size()) {
		simpleBuffer = data.front();
		data.pop();
		delete simpleBuffer;
	}
	unlock_data();
}


BogusDumper::BogusDumper(const char *path) {
	this->path = path;
	time = getActDateTimeF(true);
}

BogusDumper::~BogusDumper() {
	map<string, PcapDumper*>::iterator iter;
	for(iter = dumpers.begin(); iter != dumpers.end(); iter++) {
		iter->second->close();
		delete iter->second;
	}
}

void BogusDumper::dump(pcap_pkthdr* header, u_char* packet, int dlt, const char *interfaceName) {
	if(!strncmp(interfaceName, "interface", 9)) {
		interfaceName += 9;
	}
	while(*interfaceName == ' ') {
		++interfaceName;
	}
	PcapDumper *dumper;
	map<string, PcapDumper*>::iterator iter = dumpers.find(interfaceName);
	if(iter != dumpers.end()) {
		dumper = dumpers[interfaceName];
	} else {
		dumper = new PcapDumper(PcapDumper::na, NULL);
		dumper->setEnableAsyncWrite(false);
		dumper->setEnableZip(false);
		string dumpFileName = path + "/bogus_" + 
				      find_and_replace(find_and_replace(interfaceName, " ", "").c_str(), "/", "|") + 
				      "_" + time + ".pcap";
		if(dumper->open(dumpFileName.c_str(), dlt)) {
			dumpers[interfaceName] = dumper;
		} else {
			delete dumper;
			dumper = NULL;
		}
	}
	if(dumper) {
		dumper->dump(header, packet, dlt);
		dumper->flush();
	}
}


string base64_encode(const unsigned char *data, size_t input_length) {
	if(!input_length) {
		input_length = strlen((char*)data);
	}
	size_t output_length;
	char *encoded_data = base64_encode(data, input_length, &output_length);
	if(encoded_data) {
		string encoded_string = encoded_data;
		delete [] encoded_data;
		return(encoded_string);
	} else {
		return("");
	}
}

char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
	char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
				 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
				 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
				 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
				 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
				 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
				 'w', 'x', 'y', 'z', '0', '1', '2', '3',
				 '4', '5', '6', '7', '8', '9', '+', '/'};
	int mod_table[] = {0, 2, 1};
	*output_length = 4 * ((input_length + 2) / 3);
	char *encoded_data = new char[*output_length + 1];
	if(encoded_data == NULL) return NULL;
	for(size_t i = 0, j = 0; i < input_length;) {
	    uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
	    uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
	    uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;
	    uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
	    encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
	    encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
	    encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
	    encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}
	for(int i = 0; i < mod_table[input_length % 3]; i++)
		encoded_data[*output_length - 1 - i] = '=';
	encoded_data[*output_length] = 0;
	return encoded_data;
}
