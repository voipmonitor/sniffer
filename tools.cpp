#include "config.h"
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
#include <sys/statvfs.h>
#include <curl/curl.h>
#include <cerrno>
#include <iomanip>
#ifdef HAVE_OPENSSL
#include <openssl/sha.h>
#endif
#include <fcntl.h>
#include <math.h>
#include <signal.h>

#include "voipmonitor.h"

#ifdef HAVE_LIBPNG
#include <png.h>
#endif //HAVE_LIBPNG
#ifdef HAVE_LIBFFT
#include <fftw3.h>
#endif //HAVE_LIBFFT

#ifdef FREEBSD
#include <sys/uio.h>
#include <sys/thr.h>
#include <sys/sysctl.h>
#define SCRIPT_SHELL "#!/usr/local/bin/bash\n"
#else
#include <sys/sendfile.h>
#include <sys/sysinfo.h>
#define SCRIPT_SHELL "#!/bin/bash\n"
#endif

#include <algorithm> // for std::min
#include <iostream>

#ifndef FREEBSD
#include <malloc.h>
#endif

#if HAVE_LIBTCMALLOC    
#include <gperftools/malloc_extension.h>
#endif

#if HAVE_LIBJEMALLOC
#include <jemalloc/jemalloc.h>
#endif

#ifndef SIZE_MAX
# ifdef __SIZE_MAX__
#  define SIZE_MAX __SIZE_MAX__
# else
#  define SIZE_MAX (static_cast<size_t>(-1))
# endif
#endif

#include "calltable.h"
#include "rtp.h"
#include "tools.h"
#include "md5.h"
#include "pcap_queue.h"
#include "sql_db.h"
#include "tar.h"
#include "filter_mysql.h"
#include "sniff_inline.h"
#include "sql_db.h"
#include "config_param.h"
#include "websocket.h"
#include "mgcp.h"

#ifndef SIZE_MAX
# ifdef __SIZE_MAX__
#  define SIZE_MAX __SIZE_MAX__
# else
#  define SIZE_MAX (static_cast<size_t>(-1))
# endif
#endif

extern char mac[32];
extern int verbosity;
extern int opt_pcap_dump_bufflength;
extern int opt_pcap_dump_asyncwrite;
extern FileZipHandler::eTypeCompress opt_pcap_dump_zip_sip;
extern FileZipHandler::eTypeCompress opt_pcap_dump_zip_rtp;
extern FileZipHandler::eTypeCompress opt_pcap_dump_zip_graph;
extern int opt_pcap_dump_ziplevel_sip;
extern int opt_pcap_dump_ziplevel_rtp;
extern int opt_pcap_dump_ziplevel_graph;
extern int opt_pcap_dump_tar;
extern int opt_active_check;
extern int opt_cloud_activecheck_period;
extern int cloud_activecheck_timeout;
extern volatile bool cloud_activecheck_inprogress;
extern timeval cloud_last_activecheck;
extern string appname;
extern string binaryNameWithPath;
extern char configfile[1024];
extern int ownPidStart;
extern int ownPidFork;
extern vector<string> ifnamev;
pid_t mysqlPid = 0;

extern TarQueue *tarQueue[2];
using namespace std;

AsyncClose *asyncClose;

//Sort files in given directory using mtime from oldest (files not already openned for write).
queue<string> listFilesDir (char * dir) {
	struct privListDir {          //sort by mtime asc. function
		static bool files_sorter_asc(TfileListElem const& lhs, TfileListElem const& rhs) {
			return lhs.mtime < rhs.mtime;
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
#ifndef FREEBSD
			if (fcntl(fd, F_SETLEASE, F_WRLCK) && EAGAIN == errno)  //this test not work on tmpfs,nfs,ramfs as a workaround check mtime and actual date
#endif
			{
                                                                            //if used one of fs above, test only mtime of a file and given timeout (120)
				if (!privListDir::file_mtimer(elem, 120)) {
					//skip this file, because it is already write locked
					close(fd);
					continue;
				}
			}
#ifndef FREEBSD
			fcntl(fd, F_SETLEASE, F_UNLCK);
#endif
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

vector<string> listDir(string path, bool withDir) {
	vector<string> rslt;
	DIR* dp = opendir(path.c_str());
	if(dp) {
		dirent* de;
		while((de = readdir(dp)) != NULL && !is_terminating()) {
			if(string(de->d_name) == ".." or string(de->d_name) == ".") continue;
			if(de->d_type != DT_DIR || withDir) {
				rslt.push_back(de->d_name);
			}
		}
		closedir(dp);
	}
	return(rslt);
}

vector<string> explode(const char *str, const char ch) {
	vector<string> result;
	if(!str) {
		return(result);
	} else {
		return(explode(string(str), ch));
	}
}

vector<string> explode(const string& str, const char ch) {
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

string implode(vector<string> vect, const char *sep) {
	string rslt;
	for(unsigned i = 0; i < vect.size(); i++) {
		if(i) {
			rslt += sep;
		}
		rslt += vect[i];
	}
	return(rslt);
}

string implode(list<u_int64_t> *items, const char *sep) {
	string rslt;
	unsigned i = 0;
	for(list<u_int64_t>::iterator iter = items->begin(); iter != items->end(); iter++) {
		if(i) {
			rslt += sep;
		}
		rslt += intToString(*iter);
		++i;
	}
	return(rslt);
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

bool file_exists(const char * fileName, int *error_code) {
	struct stat buf;
	int rsltStat = stat(fileName, &buf);
	if(rsltStat == 0) {
		if(error_code) {
			*error_code = 0;
		}
		return(true);
	}
	if(error_code) {
		*error_code = errno;
	}
	return(false);
}

u_int64_t file_size(const char * fileName) {
	long long size = GetFileSize(fileName);
	return(size > 0 ? size : 0);
}

bool is_dir(const char * fileName) {
	struct stat buf;
	if(stat(fileName, &buf) == 0) {
		return(S_ISDIR(buf.st_mode));
	}
	return(false);
}

bool is_dir(dirent *de, const char *path) {
	return(de->d_type == DT_DIR ||
	       (de->d_type == DT_UNKNOWN && is_dir(string(path) + '/' + de->d_name)));
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

	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
		0xff & buffer.ifr_hwaddr.sa_data[0],
		0xff & buffer.ifr_hwaddr.sa_data[1],
		0xff & buffer.ifr_hwaddr.sa_data[2],
		0xff & buffer.ifr_hwaddr.sa_data[3],
		0xff & buffer.ifr_hwaddr.sa_data[4],
		0xff & buffer.ifr_hwaddr.sa_data[5]);
#endif
}

int
mkdir_r(std::string s, mode_t mode, unsigned uid, unsigned gid)
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
		if((mdret = mkdir(dir.c_str(), mode))) {
			if(errno != EEXIST) {
				return mdret;
			}
		} else {
			if(uid || gid) {
				chown(dir.c_str(), uid, gid);
			}
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

int rmdir_r(std::string dir, bool enableSubdir, bool withoutRemoveRoot) {
	return(rmdir_r(dir.c_str(), enableSubdir, withoutRemoveRoot));
}

int rmdir_if_r(std::string dir, bool if_r, bool enableSubdir, bool withoutRemoveRoot) {
	return(if_r ?
		rmdir_r(dir, enableSubdir, withoutRemoveRoot) :
		rmdir(dir.c_str()));
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

unsigned long long copy_file(const char *src, const char *dst, bool move, bool auto_create_dst_dir) {
	int read_fd = 0;
	int write_fd = 0;
	struct stat stat_buf;
	int renamedebug = 0;

	//check if the file exists
	if(!file_exists(src)) {
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
	for(int passOpen = 0; passOpen < 2; passOpen++) {
		if(passOpen == 1) {
			char *pointToLastDirSeparator = strrchr((char*)dst, '/');
			if(pointToLastDirSeparator) {
				*pointToLastDirSeparator = 0;
				mkdir_r(dst, 0777);
				*pointToLastDirSeparator = '/';
			} else {
				break;
			}
		}
		write_fd = open (dst, O_WRONLY | O_CREAT, stat_buf.st_mode);
		if(write_fd > 0 || !auto_create_dst_dir) {
			break;
		}
	}
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
	off_t offset = 0;
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
			//curl_easy_setopt(curl, CURLOPT_SSLVERSION, 3);
			curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_0);
			curl_easy_setopt(curl, CURLOPT_DNS_USE_GLOBAL_CACHE, 1);
			curl_easy_setopt(curl, CURLOPT_DNS_CACHE_TIMEOUT, -1);
			curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
			char *urlPathSeparator = (char*)strchr(url + 8, '/');
			string path = urlPathSeparator ? urlPathSeparator : "/";
			string host = urlPathSeparator ? string(url).substr(0, urlPathSeparator - url) : url;
			string hostProtPrefix;
			size_t posEndHostProtPrefix = host.rfind('/');
			if(posEndHostProtPrefix != string::npos) {
				hostProtPrefix = host.substr(0, posEndHostProtPrefix + 1);
				host = host.substr(posEndHostProtPrefix + 1);
			}
			extern char opt_curlproxy[256];
			if(opt_curlproxy[0]) {
				curl_easy_setopt(curl, CURLOPT_PROXY, opt_curlproxy);
			}
			extern cResolver resolver;
			std::vector<string> hostIPs = resolver.resolve_allips_str(host.c_str(), 0, cResolver::_typeResolve_default);
			if(hostIPs.size()) {
				headers = curl_slist_append(headers, ("Host: " + host).c_str());
				curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
				for (std::size_t i = 0; i < hostIPs.size(); i++) {
					string ipurl;
					if (hostIPs[i].find(':') != std::string::npos) {
						ipurl = hostProtPrefix + "[" + hostIPs[i] + "]" + path;
					} else {
						ipurl = hostProtPrefix + hostIPs[i] + path;
					}
					curl_easy_setopt(curl, CURLOPT_URL, ipurl.c_str());
					if(verbosity > 1) {
						syslog(LOG_NOTICE, "get_url_file %s", ipurl.c_str());
					}
					if(curl_easy_perform(curl) == CURLE_OK) {
						rslt = true;
						break;
					}
				}
			} else {
				curl_easy_setopt(curl, CURLOPT_URL, url);
				if(verbosity > 1) {
					syslog(LOG_NOTICE, "get_url_file %s", url);
				}
				if(curl_easy_perform(curl) == CURLE_OK) {
					rslt = true;
				}
			}
			if (!rslt) {
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

bool get_url_response(const char *url, SimpleBuffer *response, vector<dstring> *postData, string *error, s_get_url_response_params *params) {
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
		curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_0);
		curl_easy_setopt(curl, CURLOPT_DNS_USE_GLOBAL_CACHE, 1);
		curl_easy_setopt(curl, CURLOPT_DNS_CACHE_TIMEOUT, -1);
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
		if(params && params->timeout_sec) {
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, params->timeout_sec);
		}
		char *urlPathSeparator = (char*)strchr(url + 8, '/');
		string path = urlPathSeparator ? urlPathSeparator : "/";
		string host = urlPathSeparator ? string(url).substr(0, urlPathSeparator - url) : url;
		string hostProtPrefix;
		size_t posEndHostProtPrefix = host.rfind('/');
		if(posEndHostProtPrefix != string::npos) {
			hostProtPrefix = host.substr(0, posEndHostProtPrefix + 1);
			host = host.substr(posEndHostProtPrefix + 1);
		}
		string hostIP = cResolver::resolve_str(host, 0, cResolver::_typeResolve_system_host); 
		if(!hostIP.empty()) {
			headers = curl_slist_append(headers, ("Host: " + host).c_str());
			curl_easy_setopt(curl, CURLOPT_URL, (hostProtPrefix +  hostIP + path).c_str());
		} else {
			curl_easy_setopt(curl, CURLOPT_URL, url);
		}
		if(params && params->headers) {
			for(unsigned i = 0; i < params->headers->size(); i++) {
				headers = curl_slist_append(headers, ((*params->headers)[i][0] + ": " + (*params->headers)[i][1]).c_str());
			}
		}
		if(headers) {
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		}
		extern char opt_curlproxy[256];
		if(opt_curlproxy[0]) {
			curl_easy_setopt(curl, CURLOPT_PROXY, opt_curlproxy);
		}
		if(params && (params->auth_user || params->auth_password)) {
			curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
			curl_easy_setopt(curl, CURLOPT_USERPWD, 
					 ((params->auth_user ? *params->auth_user : "") + 
					  ":" + 
					  (params->auth_password ? *params->auth_password : "")).c_str());
		}
		string postFields;
		if(postData) {
			for(size_t i = 0; i < postData->size(); i++) {
				if(!postFields.empty()) {
					postFields.append("&");
				}
				postFields.append((*postData)[i][0]);
				postFields.append("=");
				postFields.append(params && params->suppress_parameters_encoding ? (*postData)[i][1] : url_encode((*postData)[i][1]));
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

bool post_url_response(const char *url, SimpleBuffer *response, string *postData, string *error, s_get_url_response_params *params) {
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
		curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_0);
		curl_easy_setopt(curl, CURLOPT_DNS_USE_GLOBAL_CACHE, 1);
		curl_easy_setopt(curl, CURLOPT_DNS_CACHE_TIMEOUT, -1);
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
		if(params && params->timeout_sec) {
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, params->timeout_sec);
		}
		char *urlPathSeparator = (char*)strchr(url + 8, '/');
		string path = urlPathSeparator ? urlPathSeparator : "/";
		string host = urlPathSeparator ? string(url).substr(0, urlPathSeparator - url) : url;
		string hostProtPrefix;
		size_t posEndHostProtPrefix = host.rfind('/');
		if(posEndHostProtPrefix != string::npos) {
			hostProtPrefix = host.substr(0, posEndHostProtPrefix + 1);
			host = host.substr(posEndHostProtPrefix + 1);
		}
		string hostIP = cResolver::resolve_str(host, 0, cResolver::_typeResolve_system_host); 
		if(!hostIP.empty()) {
			headers = curl_slist_append(headers, ("Host: " + host).c_str());
			curl_easy_setopt(curl, CURLOPT_URL, (hostProtPrefix +  hostIP + path).c_str());
		} else {
			curl_easy_setopt(curl, CURLOPT_URL, url);
		}
		if(params && params->headers) {
			for(unsigned i = 0; i < params->headers->size(); i++) {
				headers = curl_slist_append(headers, ((*params->headers)[i][0] + ": " + (*params->headers)[i][1]).c_str());
			}
		}
		if(headers) {
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		}
		extern char opt_curlproxy[256];
		if(opt_curlproxy[0]) {
			curl_easy_setopt(curl, CURLOPT_PROXY, opt_curlproxy);
		}
		if(params && (params->auth_user || params->auth_password)) {
			curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
			curl_easy_setopt(curl, CURLOPT_USERPWD,
					 ((params->auth_user ? *params->auth_user : "") +
					  ":" +
					  (params->auth_password ? *params->auth_password : "")).c_str());
		}
		string postFields;
		if(postData) {
			curl_easy_setopt(curl, CURLOPT_POST, 1);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData->c_str());
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
	data_ = new FILE_LINE(38001) char[capacity];
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

long long GetFileSize(std::string filename)
{
	struct stat stat_buf;
	int rc = stat(filename.c_str(), &stat_buf);
	return rc == 0 ? stat_buf.st_size : -1;
}

time_t GetFileCreateTime(std::string filename)
{
	struct stat stat_buf;
	int rc = stat(filename.c_str(), &stat_buf);
	return rc == 0 ? stat_buf.st_ctime : -1;
}

long long GetFileSizeDU(std::string filename, eTypeSpoolFile typeSpoolFile, int spool_index, int dirItemSize)
{
	return(GetDU(GetFileSize(filename), typeSpoolFile, spool_index, dirItemSize));
}

long long GetDirSizeDU(unsigned countFiles)
{
	return(max(4096u, countFiles * 100));
}

long long GetDU(long long fileSize, eTypeSpoolFile typeSpoolFile, int spool_index, int dirItemSize) {
	static int block_size[MAX_COUNT_TYPE_SPOOL_FILE][MAX_COUNT_SPOOL_INDEX];
	if(!block_size[typeSpoolFile][spool_index]) {
		extern char opt_spooldir_main[1024];
		struct stat fi;
		if(!stat(opt_spooldir_main, &fi)) {
			block_size[typeSpoolFile][spool_index] = fi.st_blksize;
		} else {
			block_size[typeSpoolFile][spool_index] = -1;
		}
	}
	if(fileSize >= 0) {
		if(block_size[typeSpoolFile][spool_index] > 0) {
			int bs = block_size[typeSpoolFile][spool_index];
			if(fileSize == 0) {
				fileSize = bs;
			} else {
				fileSize = (fileSize / bs * bs) + (fileSize % bs ? bs : 0);
			}
		}
		fileSize += (dirItemSize == -1 ? 100 : dirItemSize); // inode / directory item size
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

bool lseek(int fd, u_int64_t seekPos) {
	if(sizeof(int*) == 4) {
		int counterSeek = 0;
		while(seekPos) {
			u_int64_t _seek = min((unsigned long long)seekPos, 2000000000ull);
			if(lseek(fd, _seek, counterSeek ? SEEK_CUR : SEEK_SET) == -1) {
				return(false);
			}
			seekPos -= _seek;
			++counterSeek;
		}
	} else {
		if(lseek(fd, seekPos, SEEK_SET) == -1) {
			return(false);
		}
	}
	return(true);
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
	char *fileBuffer = new FILE_LINE(38002) char[fileSize];
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

string GetDataMD5(u_char *data, u_int32_t datalen,
		  u_char *data2, u_int32_t data2len,
		  u_char *data3, u_int32_t data3len) {
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, data, datalen);
	if(data2 && data2len) {
		MD5_Update(&ctx, data2, data2len);
	}
	if(data3 && data3len) {
		MD5_Update(&ctx, data3, data3len);
	}
	unsigned char _md5[MD5_DIGEST_LENGTH];
	MD5_Final(_md5, &ctx);
	return(MD5_String(_md5));
}

string GetStringSHA256(std::string str) {
	#ifdef HAVE_OPENSSL
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
	#else
	return("");
	#endif
}

#pragma GCC push_options
#pragma GCC optimize ("-O3")
u_int32_t checksum32buf(char *buf, size_t len) {
	register u_int16_t cheksum32 = 0;
	for(size_t i = 0; i < len; i++, buf++) {
		cheksum32 += (signed char)*buf;
	}
	return(cheksum32);
}
#pragma GCC pop_options

string escapeShellArgument(string str) {
	string rslt = "'";
        for(unsigned i = 0; i < str.length(); i++) {
		switch(str[i]) {
		case '\'':
			rslt += "\\'";
			break;
		default:
			rslt += str[i];
		}
        }
        rslt += "'";
	return(rslt);
}

tm stringToTm(const char *timeStr) {
	int year, month, day, hour, min, sec;
	hour = min = sec = 0;
	sscanf(timeStr, "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &min, &sec);
	struct tm dateTime;
	memset(&dateTime, 0, sizeof(dateTime));
	dateTime.tm_year = year - 1900;
	dateTime.tm_mon = month - 1;  
	dateTime.tm_mday = day;
	dateTime.tm_wday = 0;
	dateTime.tm_hour = hour; 
	dateTime.tm_min = min; 
	dateTime.tm_sec = sec;
	mktime(&dateTime);
	return(dateTime);
}

time_t stringToTime(const char *timeStr, bool useGlobalTimeCache) {
	int year, month, day, hour, min, sec;
	hour = min = sec = 0;
	sscanf(timeStr, "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &min, &sec);
	time_t now;
	time(&now);
	struct tm dateTime = time_r(&now, NULL, useGlobalTimeCache);
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
	return(time_r(&time));
}

struct tm getDateTime(const char *timeStr) {
	return(getDateTime(stringToTime(timeStr)));
}

int getNumberOfDayToNow(const char *date) {
	int year, month, day;
	sscanf(date, "%d-%d-%d", &year, &month, &day);
	time_t now;
	time(&now);
	struct tm dateTime = time_r(&now);
	dateTime.tm_year = year - 1900;
	dateTime.tm_mon = month - 1;  
	dateTime.tm_mday = day;
	dateTime.tm_wday = 0;
	dateTime.tm_hour = 0; 
	dateTime.tm_min = 0; 
	dateTime.tm_sec = 0;
	return(difftime(now, mktime(&dateTime)) / (24 * 60 * 60));
}

int getNumberOfHourToNow(const char *date, int hour) {
	int year, month, day;
	sscanf(date, "%d-%d-%d", &year, &month, &day);
	time_t now;
	time(&now);
	struct tm dateTime = time_r(&now);
	dateTime.tm_year = year - 1900;
	dateTime.tm_mon = month - 1;  
	dateTime.tm_mday = day;
	dateTime.tm_wday = 0;
	dateTime.tm_hour = hour; 
	dateTime.tm_min = 0; 
	dateTime.tm_sec = 0;
	return(difftime(now, mktime(&dateTime)) / (60 * 60));
}

string getActDateTimeF(bool useT_symbol) {
	time_t actTime = time(NULL);
	struct tm actTimeInfo = time_r(&actTime);
	char dateTimeF[20];
	strftime(dateTimeF, 20, 
		 useT_symbol ? "%Y-%m-%dT%T" : "%Y-%m-%d %T", 
		 &actTimeInfo);
	return(dateTimeF);
}

tm getEasterMondayDate(unsigned year, int decDays, const char *timezone) {
	tm rslt;
	memset(&rslt, 0, sizeof(rslt));
	if(year < 1900 || year > 2099) {
		return(rslt);
	}
	int m = 24;
	int n = 5;
	int a = year % 19;
	int b = year % 4;
	int c = year % 7;
	int d = (19 * a + m) % 30;
	int e = (2 * b + 4 * c + 6 * d + n) % 7;
	int v = 81 + d + e;
	if(v > 115 || (v == 115 && d == 28 && e == 6 && a > 10)) {
		v = v - 7;
	}
	if(!(year % 4) && (year % 100 || !(year % 400))) {
		v++;
	}
	rslt.tm_year = year - 1900;
	rslt.tm_mon = 0;  
	rslt.tm_mday = 1;
	rslt.tm_wday = 0;
	rslt.tm_hour = 0; 
	rslt.tm_min = 0; 
	rslt.tm_sec = 0;
	time_t time_s = mktime(&rslt, timezone);
	time_s += (v - decDays) * 60 * 60 * 24;
	rslt = time_r(&time_s, timezone ? timezone : "local");
	return(rslt);
}

bool isEasterMondayDate(tm &date, int decDays, const char *timezone) {
	tm ed = getEasterMondayDate(date.tm_year + 1900, decDays, timezone);
	return(ed.tm_year == date.tm_year &&
	       ed.tm_mon == date.tm_mon &&
	       ed.tm_mday == date.tm_mday);
}

tm getBeginDate(tm dateTime, const char *timezone) {
	tm rslt = dateTime;
	rslt.tm_hour = 0;
	rslt.tm_min = 0;
	rslt.tm_sec = 0;
	time_t time_s = mktime(&rslt, timezone);
	rslt = time_r(&time_s, timezone ? timezone : "local");
	rslt.tm_hour = 0;
	rslt.tm_min = 0;
	rslt.tm_sec = 0;
	return(rslt);
}

tm getNextBeginDate(tm dateTime, const char *timezone) {
	tm rslt = dateTime;
	rslt.tm_hour = 0;
	rslt.tm_min = 0;
	rslt.tm_sec = 0;
	time_t time_s = mktime(&rslt, timezone);
	time_s += 60 * 60 * 36;
	rslt = time_r(&time_s, timezone ? timezone : "local");
	rslt.tm_hour = 0;
	rslt.tm_min = 0;
	rslt.tm_sec = 0;
	return(rslt);
}

tm getPrevBeginDate(tm dateTime, const char *timezone) {
	tm rslt = dateTime;
	rslt.tm_hour = 0;
	rslt.tm_min = 0;
	rslt.tm_sec = 0;
	time_t time_s = mktime(&rslt, timezone);
	time_s -= 60 * 60 * 12;
	rslt = time_r(&time_s, timezone ? timezone : "local");
	rslt.tm_hour = 0;
	rslt.tm_min = 0;
	rslt.tm_sec = 0;
	return(rslt);
}

tm getNextBeginHour(tm dateTime, const char *timezone) {
	tm rslt = dateTime;
	rslt.tm_min = 0;
	rslt.tm_sec = 0;
	time_t time_s = mktime(&rslt, timezone);
	time_s += 60 * 60;
	rslt = time_r(&time_s, timezone ? timezone : "local");
	rslt.tm_min = 0;
	rslt.tm_sec = 0;
	return(rslt);
}

tm dateTimeAdd(tm dateTime, unsigned add_s, const char *timezone) {
	time_t time_s = mktime(&dateTime, timezone);
	time_s += add_s;
	return(time_r(&time_s, timezone ? timezone : "local"));
}

double diffTime(tm time1, tm time0, const char *timezone) {
	return(difftime(mktime(&time1, timezone), mktime(&time0, timezone)));
}

unsigned long getUptime() {
	extern time_t startTime;
	time_t actTime;
	time(&actTime);
	return(actTime - startTime);
}


PcapDumper::PcapDumper(eTypePcapDump type, Call_abstract *call) {
	this->typeSpoolFile = tsf_na;
	this->type = type;
	this->call = call;
	this->capsize = 0;
	this->size = 0;
	this->handle = NULL;
	this->openError = false;
	this->openAttempts = 0;
	this->state = state_na;
	this->existsContent = false;
	this->dlt = -1;
	this->lastTimeSyslog = 0;
	this->_bufflength = -1;
	this->_asyncwrite = type == na && !call ? 0 : -1;
	this->_typeCompress = FileZipHandler::compress_default;
}

PcapDumper::~PcapDumper() {
	if(this->handle) {
		this->close();
	}
}

bool PcapDumper::open(eTypeSpoolFile typeSpoolFile, const char *fileName, pcap_t *useHandle, int useDlt, string *error) {
	#if DEBUG_ASYNC_TAR_WRITE
	if((this->type == sip || this->type == rtp) && call) {
		call->addPFlag(this->type - 1, Call_abstract::_p_flag_dumper_open);
	}
	#endif
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
	pcap_t *_handle = enable_convert_dlt_sll_to_en10(useDlt) || !useHandle ?
			   global_pcap_handle_dead_EN10MB : 
			   useHandle;
	this->capsize = 0;
	this->size = 0;
	string errorString;
	this->dlt = convert_dlt_sll_to_en10(useDlt);
	this->handle = __pcap_dump_open(_handle, typeSpoolFile, fileName, this->dlt, &errorString,
					_bufflength, _asyncwrite, _typeCompress,
					call, this->type);
	++this->openAttempts;
	if(!this->handle) {
		if(this->type != rtp || !this->openError) {
			const char *openError = opt_pcap_dump_bufflength ?
						 errorString.c_str() : 
						 __pcap_geterr(_handle);
			if(error) {
				*error = openError;
			} else {
				syslog(LOG_NOTICE, "pcapdumper: error open dump handle to file %s - %s", fileName, openError);
			}
		}
		this->openError = true;
	}
	this->typeSpoolFile = typeSpoolFile,
	this->fileName = fileName;
	if(this->handle != NULL) {
		this->state = state_open;
		#if DEBUG_ASYNC_TAR_WRITE
		if((this->type == sip || this->type == rtp) && call) {
			call->addPFlag(this->type - 1, Call_abstract::_p_flag_dumper_open_ok);
		}
		#endif
		return(true);
	} else {
		return(false);
	}
}

#define PCAP_DUMPER_PACKET_HEADER_SIZE 16
#define PCAP_DUMPER_HEADER_SIZE 24

bool incorrectCaplenDetected = false;

void PcapDumper::dump(pcap_pkthdr* header, const u_char *packet, int dlt, bool allPackets,
		      u_char *data, unsigned int datalen,
		      vmIP saddr, vmIP daddr, vmPort source, vmPort dest,
		      bool istcp, u_int8_t forceVirtualUdp, timeval *ts) {
	extern int opt_convert_dlt_sll_to_en10;
	if(convert_dlt_sll_to_en10(dlt) != this->dlt) {
		static u_int64_t lastTimeDltSyslog = 0;
		u_int64_t actTime = getTimeMS();
		if(actTime - 1000 > lastTimeSyslog &&
		   actTime - 10000 > lastTimeDltSyslog) {
			syslog(LOG_NOTICE, "warning - use dlt (%i) for pcap %s created for dlt (%i) - packet will not be saved%s",
			       dlt, this->fileName.c_str(), this->dlt,
			       !opt_convert_dlt_sll_to_en10 && ((dlt == DLT_LINUX_SLL && this->dlt == DLT_EN10MB) || (dlt == DLT_EN10MB && this->dlt == DLT_LINUX_SLL)) ?
			        "; try configuration option convert_dlt_sll2en10 = yes" :
				"");
			lastTimeSyslog = actTime;
			lastTimeDltSyslog = actTime;
		}
		return;
	}
	#if DEBUG_ASYNC_TAR_WRITE
	if((this->type == sip || this->type == rtp) && call) {
		call->addPFlag(this->type - 1, Call_abstract::_p_flag_dumper_dump);
	}
	#endif
	extern unsigned int opt_maxpcapsize_mb;
	if(this->handle) {
		if(allPackets ||
		   (header->caplen > 0 && header->caplen <= header->len)) {
			if(!opt_maxpcapsize_mb || this->capsize < opt_maxpcapsize_mb * 1024 * 1024) {
				this->existsContent = true;
				extern bool opt_virtualudppacket;
				u_char *packets_alloc[2] = { NULL, NULL };
				pcap_pkthdr *headers_alloc[2] = { NULL, NULL };
				int packets_alloc_counter = 0;
				if(enable_convert_dlt_sll_to_en10(dlt) && header->caplen > 16) {
					u_char *packet_mod = new FILE_LINE(0) u_char[header->caplen];
					pcap_pkthdr *header_mod = new FILE_LINE(0) pcap_pkthdr;
					packet_convert_dlt_sll_to_en10(packet, packet_mod, header, header_mod);
					packet = packet_mod;
					header = header_mod;
					dlt = DLT_EN10MB;
					packets_alloc[packets_alloc_counter] = (u_char*)packet;
					headers_alloc[packets_alloc_counter] = header;
					++packets_alloc_counter;
				}
				if((opt_virtualudppacket || forceVirtualUdp) && data && datalen) {
					sll_header *header_sll = NULL;
					ether_header *header_eth = NULL;
					u_int16_t header_ip_offset = 0;
					u_int16_t protocol = 0;
					u_int16_t vlan = VLAN_UNSET;
					if(parseEtherHeader(dlt, (u_char*)packet, 
							    header_sll, header_eth, NULL,
							    header_ip_offset, protocol, vlan)) {
						unsigned iphdrSize = ((iphdr2*)(packet + header_ip_offset))->get_hdr_size();
						if((header_ip_offset +
						    iphdrSize +
						    (istcp ? 
						      ((tcphdr2*)(packet + header_ip_offset + iphdrSize))->doff * 4 : 
						      sizeof(udphdr2)) + 
						    datalen) != header->caplen ||
						   forceVirtualUdp == 2) {
							u_char *packet_mod;
							pcap_pkthdr *header_mod;
							createSimpleUdpDataPacket(header_ip_offset,  &header_mod, &packet_mod,
										  (u_char*)packet, data, datalen,
										  saddr, daddr, source, dest,
										  ts && isSetTimeval(ts) ? ts->tv_sec : header->ts.tv_sec, 
										  ts && isSetTimeval(ts) ? ts->tv_usec : header->ts.tv_usec);
							packet = packet_mod;
							header = header_mod;
							packets_alloc[packets_alloc_counter] = (u_char*)packet;
							headers_alloc[packets_alloc_counter] = header;
							++packets_alloc_counter;
						}
					}
				}
				__pcap_dump((u_char*)this->handle, header, packet, allPackets);
				extern int opt_packetbuffered;
				if(opt_packetbuffered) {
					this->flush();
				}
				this->capsize += header->caplen + PCAP_DUMPER_PACKET_HEADER_SIZE;
				this->size += header->len + PCAP_DUMPER_PACKET_HEADER_SIZE;
				if(packets_alloc_counter) {
					for(int i = 0; i < packets_alloc_counter; i++) {
						delete [] packets_alloc[i];
						delete headers_alloc[i];
					}
				}
			}
		} else {
			syslog(LOG_NOTICE, "pcapdumper: incorrect caplen/len (%u/%u) in %s", header->caplen, header->len, fileName.c_str());
			incorrectCaplenDetected = true;
		}
		this->state = state_dump;
		#if DEBUG_ASYNC_TAR_WRITE
		if((this->type == sip || this->type == rtp) && call) {
			call->addPFlag(this->type - 1, Call_abstract::_p_flag_dumper_dump_end);
		}
		#endif
	}
}

void PcapDumper::close(bool updateFilesQueue) {
	#if DEBUG_ASYNC_TAR_WRITE
	if((this->type == sip || this->type == rtp) && call) {
		call->addPFlag(this->type - 1, Call_abstract::_p_flag_dumper_dump_close);
	}
	#endif
	if(this->handle) {
		#if DEBUG_ASYNC_TAR_WRITE
		if((this->type == sip || this->type == rtp) && call) {
			call->addPFlag(this->type - 1, Call_abstract::_p_flag_dumper_dump_close_2);
		}
		#endif
		if((this->_asyncwrite < 0 ? opt_pcap_dump_asyncwrite : this->_asyncwrite) == 0) {
			#if DEBUG_ASYNC_TAR_WRITE
			if((this->type == sip || this->type == rtp) && call) {
				call->addPFlag(this->type - 1, Call_abstract::_p_flag_dumper_dump_close_not_async);
			}
			#endif
			__pcap_dump_close(this->handle);
			this->handle = NULL;
			this->state = state_close;
		} else {
			#if DEBUG_ASYNC_TAR_WRITE
			if((this->type == sip || this->type == rtp) && call) {
				call->addPFlag(this->type - 1, Call_abstract::_p_flag_dumper_dump_close_3);
			}
			#endif
			if(asyncClose) {
				#if DEBUG_ASYNC_TAR_WRITE
				if((this->type == sip || this->type == rtp) && call) {
					call->addPFlag(this->type - 1, Call_abstract::_p_flag_dumper_dump_close_4);
				}
				#endif
				if(this->call) {
					asyncClose->add(this->handle, updateFilesQueue,
							this->call, this,
							this->typeSpoolFile, this->fileName.c_str());
					#if DEBUG_ASYNC_TAR_WRITE
					if((this->type == sip || this->type == rtp) && call) {
						call->addPFlag(this->type - 1, Call_abstract::_p_flag_dumper_dump_close_5);
					}
					#endif
				} else {
					asyncClose->add(this->handle);
				}
			}
			this->handle = NULL;
			this->state = state_do_close;
			#if DEBUG_ASYNC_TAR_WRITE
			if((this->type == sip || this->type == rtp) && call) {
				call->addPFlag(this->type - 1, Call_abstract::_p_flag_dumper_dump_close_end);
			}
			#endif
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

void PcapDumper::setStateClose() {
	#if DEBUG_ASYNC_TAR_WRITE
	if((this->type == sip || this->type == rtp) && call) {
		call->addPFlag(this->type - 1, Call_abstract::_p_flag_dumper_set_state_close);
	}
	#endif
	this->state = state_close;
}


extern FileZipHandler::eTypeCompress opt_gzipGRAPH;

RtpGraphSaver::RtpGraphSaver(RTP *rtp) {
	this->typeSpoolFile = tsf_na;
	this->rtp = rtp;
	this->handle = NULL;
	this->existsContent = false;
	this->enableAutoOpen = false;
	this->_asyncwrite = opt_pcap_dump_asyncwrite ? 1 : 0;
	this->state_async_close = _sac_na;
}

RtpGraphSaver::~RtpGraphSaver() {
	if(this->isOpen()) {
		this->close();
	}
}

bool RtpGraphSaver::open(eTypeSpoolFile typeSpoolFile, const char *fileName) {
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
	this->handle = new FILE_LINE(38003) FileZipHandler(opt_pcap_dump_bufflength, this->_asyncwrite, opt_gzipGRAPH,
							   false, rtp && rtp->call_owner ? (Call*)rtp->call_owner : 0,
							   FileZipHandler::graph_rtp, rtp ? rtp->ssrc_index : 0);
	if(!this->handle->open(typeSpoolFile, fileName)) {
		syslog(LOG_NOTICE, "graphsaver: error open file %s - %s", fileName, this->handle->error.c_str());
		delete this->handle;
		this->handle = NULL;
	}
	this->typeSpoolFile = typeSpoolFile;
	this->fileName = fileName;
	return(this->isOpen());

}

void RtpGraphSaver::auto_open(eTypeSpoolFile typeSpoolFile, const char *fileName) {
	this->typeSpoolFile = typeSpoolFile;
	this->fileName = fileName;
	this->enableAutoOpen = true;
}

void RtpGraphSaver::write(char *buffer, int length) {
	if(!this->isOpen()) {
		if(this->enableAutoOpen) {
			bool rsltOpen = this->open(this->typeSpoolFile, this->fileName.c_str());
			this->enableAutoOpen = false;
			if(rsltOpen) {
				extern unsigned int graph_version;
				this->write((char*)&graph_version, 4);
			} else {
				return;
			}
		} else {
			return;
		}
	}
	this->existsContent = true;
	this->handle->write(buffer, length);
}

void RtpGraphSaver::close(bool updateFilesQueue) {
	this->enableAutoOpen = false;
	if(this->isOpen()) {
		uint16_t packetization = uint16_t(this->rtp->packetization);
		this->write((char*)&packetization, 2);
		if(this->_asyncwrite == 0) {
			this->handle->close();
			delete this->handle;
			this->handle = NULL;
		} else {
			Call *call = (Call*)this->rtp->call_owner;
			if(call) {
				asyncClose->add(this->handle, updateFilesQueue,
						call, this,
						this->typeSpoolFile, this->fileName.c_str(),
						this->handle->size);
			} else {
				asyncClose->add(this->handle);
			}
			state_async_close = _sac_sent;
			this->handle = NULL;
			if(updateFilesQueue && !call) {
				syslog(LOG_ERR, "graphsaver: gfilename[%s] does not have owner", this->fileName.c_str());
			}
		}
	}
}

void RtpGraphSaver::clearAutoOpen() {
	this->enableAutoOpen = false;
}

AsyncClose::AsyncCloseItem::AsyncCloseItem(Call_abstract *call, PcapDumper *pcapDumper, RtpGraphSaver *graphSaver,
					   eTypeSpoolFile typeSpoolFile, const char *file, 
					   long long writeBytes) {
	this->call = call;
	if(call) {
		this->call_dirnamesqlfiles = call->dirnamesqlfiles();
		this->call_spoolindex =  call->getSpoolIndex();
		this->call_spooldir =  call->getSpoolDir(typeSpoolFile);
	} else {
		this->call_spoolindex = 0;
	}
	this->pcapDumper = pcapDumper;
	this->graphSaver = graphSaver;
	this->typeSpoolFile = typeSpoolFile;
	if(file) {
		this->file = file;
	}
	this->writeBytes = writeBytes;
	this->dataLength = 0;
}

void AsyncClose::AsyncCloseItem::addtofilesqueue() {
	if(!call) {
		return;
	}
	Call::_addtofilesqueue(this->typeSpoolFile, this->file, call_dirnamesqlfiles, this->writeBytes, call_spoolindex);
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
	removeThreadProcessed = 0;
}

AsyncClose::~AsyncClose() {
	for(int i = 0; i < AsyncClose_maxPcapThreads; i++) {
		while(q[i].size()) {
			AsyncCloseItem *item = q[i].front();
			item->processClose();
			delete item;
			q[i].pop_front();
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
		vm_pthread_create("async store",
				  &this->thread[i], NULL, AsyncClose_process, &startThreadData[i], __FILE__, __LINE__);
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
		vm_pthread_create("async store",
				  &this->thread[countPcapThreads], NULL, AsyncClose_process, &startThreadData[countPcapThreads], __FILE__, __LINE__);
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
	extern int terminated_call_cleanup;
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
		USLEEP(10000);
	} while(!terminated_call_cleanup);
}

void AsyncClose::processAll(int threadIndex) {
	while(true) {
		lock(threadIndex);
		if(q[threadIndex].size()) {
			AsyncCloseItem *item = q[threadIndex].front();
			if(is_terminating() || item->process_ready()) {
				q[threadIndex].pop_front();
				sub_sizeOfDataInMemory(item->dataLength);
				unlock(threadIndex);
				item->process();
				delete item;
			} else {
				AsyncCloseItem *readyItem = NULL;
				FileZipHandler *readyHandler = NULL;
				deque<AsyncCloseItem*>::iterator iter;
				for(iter = q[threadIndex].begin(); iter != q[threadIndex].end(); iter++) {
					if((*iter)->process_ready() && (*iter)->getHandler() != item->getHandler()) {
						readyHandler = (*iter)->getHandler();
						break;
					}
				}
				if(readyHandler) {
					for(iter = q[threadIndex].begin(); iter != q[threadIndex].end();) {
						if((*iter)->getHandler() == readyHandler) {
							readyItem = *iter;
							q[threadIndex].erase(iter++);
							sub_sizeOfDataInMemory(readyItem->dataLength);
							break;
						} else {
							iter++;
						}
					}
				}
				unlock(threadIndex);
				if(readyItem) {
					readyItem->process();
					delete readyItem;
				} else {
					USLEEP(100000);
				}
			}
		} else {
			unlock(threadIndex);
			break;
		}
	}
}

void AsyncClose::safeTerminate() {
	extern int terminated_call_cleanup;
	while(!terminated_call_cleanup) {
		USLEEP(100000);
	}
	for(int i = 0; i < getCountThreads(); i++) {
		pthread_join(this->thread[i], NULL);
	}
	processAll();
	extern int terminated_async;
	terminated_async = 1;
	syslog(LOG_NOTICE, "terminated - async");
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

RestartUpgrade::RestartUpgrade(bool upgrade, const char *version, const char *url, const char *md5_32, const char *md5_64, const char *md5_arm, const char *md5_64_ws) {
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
	if(md5_64_ws) {
		this->md5_64_ws = md5_64_ws;
	}
	if(md5_arm) {
		this->md5_arm = md5_arm;
	}
	this->_64bit = false;
	this->_64bit_ws = false;
	this->_arm = false;
	#if defined(__arm__)
		this->_arm = true;
	#else
		if(sizeof(int *) == 8) {
			extern int opt_enable_ss7;
			if(opt_enable_ss7) {
				this->_64bit_ws = true;
			} else {
				this->_64bit = true;
			}
		}
	#endif
}

bool RestartUpgrade::runUpgrade() {
	if(verbosity > 0) {
		syslog(LOG_NOTICE, "start upgrade from: '%s'", url.c_str());
	}
	bool okUrl = false;
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
	string binaryFilepathName = this->upgradeTempFileName + "/" + appname;
	string binaryGzFilepathName = this->upgradeTempFileName + "/" + appname + ".gz";
	extern int opt_upgrade_try_http_if_https_fail;
	for(int pass = 0; pass < (opt_upgrade_try_http_if_https_fail ? 2 : 1); pass++) {
		string error;
		string _url = (pass == 1 ? urlHttp : url) + "/voipmonitor" +
			      (this->_64bit_ws ? 
				"-wireshark.gz.64" :
				(string(".gz.") + (this->_arm ? "armv6k" :
						   this->_64bit ? "64" : "32")));
		if(verbosity > 0) {
			syslog(LOG_NOTICE, "try download file: '%s'", _url.c_str());
		}
		bool get_url_file_rslt = get_url_file(_url.c_str(), binaryGzFilepathName.c_str(), &error);
		long long int get_url_file_size = 0;
		if(get_url_file_rslt) {
			get_url_file_size = GetFileSize(binaryGzFilepathName);
			if(get_url_file_size <= 0) {
				get_url_file_rslt = false;
			} else if(get_url_file_size < 10000) {
				FILE *check_file_handle = fopen(binaryGzFilepathName.c_str(), "r");
				if(check_file_handle) {
					char *check_file_buffer = new FILE_LINE(0) char[get_url_file_size + 1];
					if(fread(check_file_buffer, 1, get_url_file_size, check_file_handle) == (unsigned)get_url_file_size) {
						check_file_buffer[get_url_file_size] = 0;
						vector<string> matches;
						if(reg_match(check_file_buffer, "<title>(.*)</title>", &matches, true) ||
						   reg_match(check_file_buffer, "<h1>(.*)</h1>", &matches, true)) {
							error = matches[1];
							get_url_file_rslt = false;
						}
					} else {
						get_url_file_rslt = false;
					}
					delete [] check_file_buffer;
					fclose(check_file_handle);
				} else {
					error = "failed check of the download file";
					get_url_file_rslt = false;
				}
			}
		}
		if(get_url_file_rslt) {
			syslog(LOG_NOTICE, "download file '%s' finished (size: %lli)", _url.c_str(), GetFileSize(binaryGzFilepathName));
			this->errorString = "";
			break;
		} else {
			this->errorString = "failed download upgrade";
			if(!error.empty()) {
				this->errorString += ": " + error;
			}
			if(pass || !opt_upgrade_try_http_if_https_fail) {
				rmdir_r(this->upgradeTempFileName.c_str());
				if(verbosity > 0) {
					syslog(LOG_ERR, "upgrade failed - %s", this->errorString.c_str());
				}
				return(false);
			}
		}
	}
	if(!file_exists(binaryGzFilepathName)) {
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
	if(verbosity > 0) {
		syslog(LOG_NOTICE, "try unzip");
	}
	string unzip_rslt = _gunzip_s(binaryGzFilepathName.c_str(), binaryFilepathName.c_str());
	if(unzip_rslt.empty()) {
		if(verbosity > 0) {
			syslog(LOG_NOTICE, "unzip finished");
		}
	} else {
		this->errorString = unzip_rslt;
		if(verbosity > 1) {
			FILE *f = fopen(binaryGzFilepathName.c_str(), "rt");
			char buff[10000];
			while(fgets(buff, sizeof(buff), f)) {
				cout << buff << endl;
			}
		}
		if(verbosity < 2) {
			rmdir_r(this->upgradeTempFileName.c_str());
		}
		if(verbosity > 0) {
			syslog(LOG_ERR, "upgrade failed - %s", this->errorString.c_str());
		}
		return(false);
	}
	if(!this->getMD5().empty()) {
		string md5 = GetFileMD5(binaryFilepathName);
		if(this->getMD5() != md5) {
			this->errorString = "failed download - bad md5: " + md5 + " <> " + this->getMD5();
			rmdir_r(this->upgradeTempFileName.c_str());
			if(verbosity > 0) {
				syslog(LOG_ERR, "upgrade failed - %s", this->errorString.c_str());
			}
			return(false);
		}
	}
	unlink(binaryNameWithPath.c_str());
	if(!copy_file(binaryFilepathName.c_str(), binaryNameWithPath.c_str(), true)) {
		this->errorString = "failed copy new binary to " + binaryNameWithPath;
		rmdir_r(this->upgradeTempFileName.c_str());
		if(verbosity > 0) {
			syslog(LOG_ERR, "upgrade failed - %s", this->errorString.c_str());
		}
		return(false);
	}
	if(chmod(binaryNameWithPath.c_str(), 0755)) {
		this->errorString = "failed chmod 0755 " + binaryNameWithPath + " binary";
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
		fputs(SCRIPT_SHELL, fileHandle);
		fprintf(fileHandle, "cd '%s'\n%s\n", getRunDir().c_str(), getCmdLine().c_str());
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

bool RestartUpgrade::createSafeRunScript() {
	if(verbosity > 0) {
		syslog(LOG_NOTICE, "create safe run script");
	}
	if(!this->safeRunTempScriptFileName.length() && !this->getSafeRunTempScriptFileName()) {
		this->errorString = "failed create temp name for safe run script";
		if(verbosity > 0) {
			syslog(LOG_ERR, "create safe run script failed - %s", this->errorString.c_str());
		}
		return(false);
	}
	FILE *fileHandle = fopen(this->safeRunTempScriptFileName.c_str(), "wt");
	if(fileHandle) {
		fputs(SCRIPT_SHELL, fileHandle);
		fputs("sleep 60\n", fileHandle);
		fprintf(fileHandle, "if [[ \"`ps -A -o comm,pid | grep %i`\" == \"%s\"* ]]; then kill -9 %i; sleep 1; fi\n", getpid(), appname.c_str(), getpid());
		fprintf(fileHandle, "cd '%s'\n%s\n", getRunDir().c_str(), getCmdLine().c_str());
		fprintf(fileHandle, "rm %s\n", this->safeRunTempScriptFileName.c_str());
		fclose(fileHandle);
		if(chmod(this->safeRunTempScriptFileName.c_str(), 0755)) {
			this->errorString = "failed chmod 0755 for safe run script";
		}
		return(true);
	} else {
		this->errorString = "failed create safe run script";
		if(verbosity > 0) {
			syslog(LOG_ERR, "create safe run script failed - %s", this->errorString.c_str());
		}
	}
	return(false);
}

bool RestartUpgrade::checkReadyRestart() {
	if(!file_exists(this->restartTempScriptFileName)) {
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

bool RestartUpgrade::checkReadySafeRun() {
	if(!file_exists(this->safeRunTempScriptFileName)) {
		this->errorString = "failed check safe run script - script missing";
		return(false);
	}
	if(!this->safeRunTempScriptFileName.length()) {
		this->errorString = "failed check safe run script - zero size of safe run script";
		unlink(this->safeRunTempScriptFileName.c_str());
		return(false);
	}
	return(true);
}

bool RestartUpgrade::runRestart(int socket1, int socket2, cClient *c_client) {
	if(!this->checkReadyRestart()) {
		if(verbosity > 0) {
			syslog(LOG_ERR, "restart failed - %s", this->errorString.c_str());
		}
		return(false);
	}
	extern WDT *wdt;
	if(wdt) {
		delete wdt;
		wdt = NULL;
	}
	extern void semaphoreUnlink(int index = -1, bool force = false);
	extern void semaphoreClose(int index = -1, bool force = false);
	semaphoreUnlink();
	semaphoreClose();
	close(socket1);
	close(socket2);
	if(c_client) {
		c_client->writeFinal();
		delete c_client;
	}
	pid_t pidSafeRunScript = 0;
	if(!this->safeRunTempScriptFileName.empty() && this->checkReadySafeRun()) {
		pidSafeRunScript = fork();
		if(!pidSafeRunScript) {
			syslog(LOG_NOTICE, "run safe run script (%s)", this->safeRunTempScriptFileName.c_str());
			close_all_fd();
			if(execl(this->safeRunTempScriptFileName.c_str(), "Command-line", 0, NULL) == -1) {
				syslog(LOG_NOTICE, "run safe run script (%s) failed - %s", this->safeRunTempScriptFileName.c_str(), strerror(errno));
				kill(getpid(), SIGKILL);
			}
			return(true);
		}
	}
	extern int opt_nocdr;
	extern bool opt_autoload_from_sqlvmexport;
	if(!opt_nocdr) {
		extern MySqlStore *sqlStore;
		if(opt_autoload_from_sqlvmexport) {
			sqlStore->exportToFile(NULL, "auto", false, true);
		}
		sqlStore->queryToFilesTerminate();
	}
	set_readend();
	if(is_read_from_file_by_pb()) {
		vm_terminate();
	}
	sleep(2);
	terminate_packetbuffer();
	sleep(2);

	// set to all descriptors flag CLOEXEC so exec* will close it and will not inherit it so the next voipmonitor instance will be not blocking it
	close_all_fd();
	
	if(verbosity > 0) {
		syslog(LOG_NOTICE, "run restart script (%s)", this->restartTempScriptFileName.c_str());
	}
	
	int rsltExec = execl(this->restartTempScriptFileName.c_str(), "Command-line", 0, NULL);
	if(rsltExec) {
		this->errorString = "failed execution restart script";
		if(verbosity > 0) {
			syslog(LOG_ERR, "restart failed - %s", this->errorString.c_str());
		}
		if(pidSafeRunScript) {
			kill(pidSafeRunScript, 9);
			unlink(this->safeRunTempScriptFileName.c_str());
		}
		return(false);
	} else {
		return(true);
	}
}

bool RestartUpgrade::runGitUpgrade(const char *cmd) {
	syslog(LOG_NOTICE, "call runGitUpgrade command %s", cmd);
	extern char opt_git_folder[1024];
	extern char opt_configure_param[1024];
	extern bool opt_upgrade_by_git;
	SimpleBuffer out;
	SimpleBuffer err;
	int exitCode;
	string pexecCmd = string("sh -c 'cd \"") + opt_git_folder + "\";";
	if(!opt_upgrade_by_git) {
		this->errorString = "not enable upgrade by git";
		return(false);
	}
	if(cmd == string("check_git_directory")) {
		if(!file_exists(opt_git_folder)) {
			this->errorString = string("not exists git directory ") + opt_git_folder;
			syslog(LOG_NOTICE, "runGitUpgrade command %s FAILED: %s", cmd, this->errorString.c_str());
			return(false);
		}
		if(!file_exists(string(opt_git_folder) + "/.git")) {
			this->errorString = string("missing .git folder in ") + opt_git_folder;
			syslog(LOG_NOTICE, "runGitUpgrade command %s FAILED: %s", cmd, this->errorString.c_str());
			return(false);
		}
		syslog(LOG_NOTICE, "runGitUpgrade command %s OK", cmd);
		return(true);
	} else if(cmd == string("git_pull") ||
		  cmd == string("configure") ||
		  cmd == string("make_clean") ||
		  cmd == string("make") ||
		  cmd == string("install")) {
		if(cmd == string("git_pull")) {
			pexecCmd += "git pull";
		} else if(cmd == string("configure")) {
			pexecCmd += "./configure " + string(opt_configure_param);
		} else if(cmd == string("make_clean")) {
			pexecCmd += "make clean";
		} else if(cmd == string("make")) {
			pexecCmd += "make -j4";
		} else if(cmd == string("install")) {
			pexecCmd += "make install";
		}
		pexecCmd += ";'";
		vm_pexec(pexecCmd.c_str(), &out, &err, &exitCode, 600, 600);
		if(exitCode == 0) {
			syslog(LOG_NOTICE, "runGitUpgrade command %s OK", cmd);
			return(true);
		} else {
			this->errorString = string(out) + "\n" + string(err);
			syslog(LOG_NOTICE, "runGitUpgrade command %s FAILED: %s", cmd, this->errorString.c_str());
			return(false);
		}
	}
	this->errorString = string("unknown command ") + cmd;
	syslog(LOG_NOTICE, "runGitUpgrade command %s FAILED: %s", cmd, this->errorString.c_str());
	return(false);
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
	this->upgradeTempFileName = tmpnam();
	return(!this->upgradeTempFileName.empty());
}

bool RestartUpgrade::getRestartTempScriptFileName() {
	this->restartTempScriptFileName = tmpnam();
	return(!this->restartTempScriptFileName.empty());
}

bool RestartUpgrade::getSafeRunTempScriptFileName() {
	this->safeRunTempScriptFileName = tmpnam();
	return(!this->safeRunTempScriptFileName.empty());
}

string RestartUpgrade::getCmdLine() {
	extern string cmdline;
	return(cmdline);
}

string RestartUpgrade::getRunDir() {
	extern string rundir;
	return(rundir);
}

int findPIDinPSline (char *line) {
	while(*line && !isdigit(*line)) {
		++line;
	}
	return(atoi(line));
}

bool binaryFilePresence(const char *cmd, const char *searchstr) {
	FILE *cmd_pipe = popen(cmd, "r");
	char buffRslt[512];

	fgets(buffRslt, 512, cmd_pipe);
	pclose(cmd_pipe);
	return(strstr(buffRslt, searchstr) ? false : true);
}

bool isBashPresent(void) {
	return(binaryFilePresence("bash --version 2>&1", " bash:"));
}

bool isPSrightVersion(void) {
	return(binaryFilePresence("ps -V 2>&1", "ps:"));
}

bool isEthtoolInstalled(void) {
	return(binaryFilePresence("ethtool --version 2>&1", " ethtool:"));
}

list<int> getPids(string app, string grep_search) {
	string cmd;
	list<int> pids;
	char buffRslt[512];
#ifdef FREEBSD
	cmd = "ps -a -w -x -o pid,comm,args | grep -E '^ {0,}[[:digit:]]+ " + app + " ' | grep '" + grep_search + "'";
#else
	cmd = "ps -C '" + app.substr(0, 15) + "' -o pid,args | grep '" + grep_search + "'";
#endif
	FILE *cmd_pipe = popen(cmd.c_str(), "r");
	while(fgets(buffRslt, 512, cmd_pipe)) {
		int pid = findPIDinPSline(buffRslt);
		pids.push_back(pid);
	}
	pclose(cmd_pipe);
	return(pids);
}

bool existsPidProcess(int pid) {
	string cmd = "ps -p " + intToString(pid) + " -o pid";
	char buffRslt[512];
	bool exists = false;
	FILE *cmd_pipe = popen(cmd.c_str(), "r");
	while(fgets(buffRslt, 512, cmd_pipe)) {
		if(findPIDinPSline(buffRslt) == pid) {
			exists = true;
			break;
		}
	}
	pclose(cmd_pipe);
	return(exists);
}

bool existsAnotherInstance() {
	bool exists = false;
	list<int> pids = getPids(appname, configfile);
	for (list<int>::iterator checkPid = pids.begin(); checkPid != pids.end(); checkPid++) {
		if(*checkPid != ownPidStart && *checkPid != ownPidFork) {
			exists = true;
			break;
		}
	}
	return(exists);
}

WDT::WDT() {
	pid = 0;
	killOtherScript();
	if(createScript()) {
		runScript();
	}
}

WDT::~WDT() {
	killScript();
	unlinkScript();
}

void WDT::runScript() {
	pid = fork();
	if(!pid) {
		if(verbosity > 0) {
			syslog(LOG_NOTICE, "run watchdog script (pid %i)", getpid());
		}
		close_all_fd();
		bool okRun = false;
		for(int pass = 0; pass < 2; pass++) {
			int rsltExec = 0;
			switch(pass) {
			case 0:
				rsltExec = execl(getScriptFileName().c_str(), "Command-line", 0, NULL);
				break;
			case 1:
				syslog(LOG_NOTICE, "try run watchdog script via bash");
				rsltExec = execlp("bash", "bash", getScriptFileName().c_str(), NULL);
				break;
			}
			if(rsltExec == -1) {
				syslog(LOG_NOTICE, "run watchdog script (%s) failed - %s (%i)", getScriptFileName().c_str(), strerror(errno), errno);
			} else {
				okRun = true;
				break;
			}
		}
		if(!okRun) {
			kill(getpid(), SIGKILL);
		}
	}
}

void WDT::killScript() {
	if(pid) {
		syslog(LOG_NOTICE, "kill watchdog script (pid %i)", pid);
		kill(pid, 9);
	}
}

void WDT::killOtherScript() {
	for(int pass = 0; pass < 2; pass++) {
		list<int> pids = getPids(pass == 0 ? getScriptName() : "bash", pass == 0 ? getScriptName() +  "$" : getScriptFileName() + "$");
		for (list<int>::iterator pidOther = pids.begin(); pidOther != pids.end(); pidOther++) {
			syslog(LOG_NOTICE, "kill old watchdog script (pid %i)", *pidOther);
			kill(*pidOther, 9);
		}
	}
}

bool WDT::createScript() {
	FILE *fileHandle = fopen(getScriptFileName().c_str(), "wt");
	if(fileHandle) {
		fputs(SCRIPT_SHELL, fileHandle);
		fputs("while [ true ]\n", fileHandle);
		fputs("do\n", fileHandle);
		fputs("sleep 5\n", fileHandle);
		fprintf(fileHandle, 
			"if [[ \"`ps -p %i -o comm,pid | grep %i`\" != \"%s\"* ]]; "
			"then cd '%s'; %s; "
			"fi\n", 
			getpid(), getpid(), appname.c_str(),
			getRunDir().c_str(), 
			getCmdLine().c_str());
		fputs("done\n", fileHandle);
		fclose(fileHandle);
		if(!chmod(getScriptFileName().c_str(), 0755)) {
			return(true);
		} else {
			if(verbosity > 0) {
				syslog(LOG_ERR, "chmod 0755 for watchdog script failed");
			}
		}
	} else {
		if(verbosity > 0) {
			syslog(LOG_ERR, "create watchdog script failed");
		}
	}
	return(false);
}

void WDT::unlinkScript() {
	unlink(getScriptFileName().c_str());
}

string WDT::getScriptName() {
	string scriptName = appname + "_watchdog";
	if(getConfigFile().length()) {
		scriptName += '_' + getConfigFile();
	}
	return(scriptName);
}

string WDT::getScriptFileName() {
	char const *tmpPath = getenv("TMPDIR");
	if(!tmpPath) {
		tmpPath = "/tmp";
	}
	return(string(tmpPath) + '/' + getScriptName());
}

string WDT::getCmdLine() {
	extern string cmdline;
	return(cmdline);
}

string WDT::getRunDir() {
	extern string rundir;
	return(rundir);
}

string WDT::getConfigFile() {
	extern string configfilename;
	return(configfilename);
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


char *strnstr(const char *haystack, const char *needle, size_t len)
{
        int i;
        size_t needle_len;

        if (0 == (needle_len = strnlen(needle, len)))
                return (char *)haystack;

        for (i=0; i<=(int)(len-needle_len); i++)
        {
                if ((haystack[0] == needle[0]) &&
                        (0 == strncmp(haystack, needle, needle_len)))
                        return (char *)haystack;

                haystack++;
        }
        return NULL;
}

char *strncasestr(const char *haystack, const char *needle, size_t len)
{
        int i;
        size_t needle_len;

        if (0 == (needle_len = strnlen(needle, len)))
                return (char *)haystack;

        char firstNeedleUpperChar = toupper(*needle);
	
        for (i=0; i<=(int)(len-needle_len); i++)
        {
                if ((toupper(haystack[0]) == firstNeedleUpperChar) &&
                        (0 == strncasecmp(haystack, needle, needle_len)))
                        return (char *)haystack;

                haystack++;
        }
        return NULL;
}

char *strnchr(const char *haystack, char needle, size_t len)
{
        int i;

        for (i=0; i<=(int)(len-1); i++)
        {
                if (haystack[0] == needle)
                        return (char *)haystack;

                haystack++;
        }
        return NULL;
}

char *strncasechr(const char *haystack, char needle, size_t len)
{
        int i;
	
	needle = toupper(needle);

        for (i=0; i<=(int)(len-1); i++)
        {
                if (toupper(haystack[0]) == needle)
                        return (char *)haystack;

                haystack++;
        }
        return NULL;
}

int strcasecmp_wildcard(const char *str, const char *pattern, const char *wildcard) {
	return(strncasecmp_wildcard(str, pattern, SIZE_MAX, wildcard));
}

int strncasecmp_wildcard(const char *str, const char *pattern, size_t len, const char *wildcard) {
	size_t wildcard_lenght = strlen(wildcard);
	size_t cmp_len = 0;
	while((*str || *pattern) && cmp_len < len) {
		if(toupper(*str) != toupper(*pattern)) {
			if(*str && *pattern) {
				bool is_wildcard = false;
				for(unsigned i = 0; i < wildcard_lenght; i++) {
					if(*pattern == wildcard[i]) {
						is_wildcard = true;
					}
				}
				if(!is_wildcard) {
					return(*str - *pattern);
				}
			} else {
				return(*str - *pattern);
			}
		}
		++str;
		++pattern;
		++cmp_len;
	}
	return(0);
}


size_t strCaseEqLengthR(const char *str1, const char *str2, bool *eqMinLength) {
	if(eqMinLength) {
		*eqMinLength = false;
	}
	size_t str1_len = strlen(str1);
	size_t str2_len = strlen(str2);
	if(!str1_len || !str2_len) {
		return(0);
	}
	for(size_t i = 0; i < min(str1_len, str2_len); i++) {
		if(toupper(str1[str1_len - i - 1]) != toupper(str2[str2_len - i - 1])) {
			return(i);
		}
	}
	if(eqMinLength) {
		*eqMinLength = true;
	}
	return(min(str1_len, str2_len));
}

std::string string_size(const char *s, unsigned size) {
	std::string str(s);
	if(str.length() > size) {
		str.resize(size);
	}
	return(str);
}

bool string_is_numeric(const char *s) {
	if(!*s) {
		return(false);
	}
	while(*s) {
		if(!isdigit(*s)) {
			return(false);
		}
		++s;
	}
	return(true);
}

bool string_is_alphanumeric(const char *s) {
	if(!*s) {
		return(false);
	}
	while(*s) {
		if(!isdigit(*s) && !isalpha(*s)) {
			return(false);
		}
		++s;
	}
	return(true);
}


bool str_like(const char *str, const char *pattern) {
	unsigned str_length = strlen(str);
	unsigned pattern_length = strlen(pattern);
	if(pattern_length) {
		bool pattern_contain_wildcard = strchr(pattern, '_') ? true : false;
		bool rslt;
		if(pattern[0] == '%') {
			if(pattern[pattern_length - 1] == '%') {
				rslt = strcasestr(str, string(pattern).substr(1, pattern_length - 2).c_str()) != NULL;
			} else {
				rslt = str_length >= pattern_length - 1 &&
				       !(pattern_contain_wildcard ?
					  strncasecmp_wildcard(str + str_length - (pattern_length - 1), string(pattern).substr(1).c_str(), pattern_length - 1, "_") :
					  strncasecmp(str + str_length - (pattern_length - 1), string(pattern).substr(1).c_str(), pattern_length - 1));
			}
		} else if(pattern[pattern_length - 1] == '%') {
			rslt = !(pattern_contain_wildcard ?
				  strncasecmp_wildcard(str, pattern, pattern_length - 1, "_") :
				  strncasecmp(str, pattern, pattern_length - 1));
		} else {
			rslt = !(pattern_contain_wildcard ?
				  strcasecmp_wildcard(str, pattern, "_") :
				  strcasecmp(str, pattern));
		}
		return(rslt);
	}
	return(false);
}


bool check_ip_in(vmIP ip, vector<vmIP> *vect_ip, vector<vmIPmask> *vect_net, bool trueIfVectEmpty) {
	if(!vect_ip->size() && !vect_net->size()) {
		return(trueIfVectEmpty);
	}
	if(vect_ip->size()) {
		vector<vmIP>::iterator iterIp;
		iterIp = std::lower_bound(vect_ip->begin(), vect_ip->end(), ip);
		if(iterIp != vect_ip->end() && iterIp->mask(ip) == *iterIp) {
			return(true);
		}
	}
	if(vect_net->size()) {
		for(size_t i = 0; i < vect_net->size(); i++) {
			if((*vect_net)[i].ip.network((*vect_net)[i].mask) == ip.network((*vect_net)[i].mask)) {
				return(true);
			}
		}
	}
	return(false);
}

bool check_ip(vmIP ip, vmIP net, unsigned mask_length) {
	return(mask_length == 0 || mask_length == 32 ?
		ip == net :
		ip.network(mask_length) == net.network(mask_length));
}


void ListIP::addComb(string &ip, ListIP *negList) {
	addComb(ip.c_str(), negList);
}

void ListIP::addComb(const char *ip, ListIP *negList) {
	vector<string>ip_elems = split(ip, split(" |,|;|\t|\r|\n", "|"), true);
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

void ListIP::add(vector<vmIP> *ip) {
	for(unsigned i = 0; i < ip->size(); i++) {
		add((*ip)[i]);
	}
}

void ListIP::add(vector<vmIPmask> *net) {
	for(unsigned i = 0; i < net->size(); i++) {
		add((*net)[i].ip, (*net)[i].mask);
	}
}

GroupIP::GroupIP() {
	this->id = 0;
}

GroupIP::GroupIP(unsigned id, const char *descr, const char *ip) {
	this->id = id;
	this->descr = descr;
	this->white.addComb(ip, &this->black);
}

GroupsIP::GroupsIP() {
}

GroupsIP::~GroupsIP() {
	for(map<unsigned, GroupIP*>::iterator it = groups.begin(); it != groups.end(); it++) {
		delete it->second;
	}
}

void GroupsIP::load(SqlDb *sqlDb) {
	for(map<unsigned, GroupIP*>::iterator it = groups.begin(); it != groups.end(); it++) {
		delete it->second;
	}
	groups.clear();
	listIP.clear();
	listNet.clear();
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	sqlDb->query("select * from cb_ip_groups");
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	SqlDb_row row;
	while((row = rows.fetchRow())) {
		unsigned id = atoi(row["id"].c_str());
		GroupIP *group = new FILE_LINE(38004) GroupIP(id, row["descr"].c_str(), row["ip"].c_str());
		groups[id] = group;
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	for(map<unsigned, GroupIP*>::iterator it = groups.begin(); it != groups.end(); it++) {
		std::vector<IP> *src_IP = &it->second->white.listIP;
		std::vector<IP>::iterator it_src_IP = src_IP->begin();
		while(it_src_IP != src_IP->end()) {
			IP ip = *it_src_IP;
			listIP[ip] = it->first;
			++it_src_IP;
		}
		std::vector<IP> *src_Net = &it->second->white.listNet;
		std::vector<IP>::iterator it_src_Net = src_Net->begin();
		while(it_src_Net != src_Net->end()) {
			IP net = *it_src_Net;
			listNet[net] = it->first;
			++it_src_Net;
		}
	}
}

GroupIP *GroupsIP::getGroup(vmIP ip) {
	if(listIP.size()) {
		std::map<IP, unsigned>::iterator it_ip = listIP.lower_bound(IP(ip));
		if(it_ip != listIP.end()) {
			IP *_ip = (IP*)&it_ip->first;
			if(_ip->checkIP(ip)) {
				return(groups[it_ip->second]);
			}
		}
	}
	if(listNet.size()) {
		std::map<IP, unsigned>::iterator it_net = listNet.lower_bound(IP(ip));
		while(it_net != listNet.begin()) {
			--it_net;
			IP *_net = (IP*)&it_net->first;
			if(!_net->ip.mask(ip).isSet()) {
				break;
			}
			if(_net->checkIP(ip)) {
				return(groups[it_net->second]);
			}
		}
	}
	return(NULL);
}

void ListPhoneNumber::addComb(string &number, ListPhoneNumber *negList) {
	addComb(number.c_str(), negList);
}

void ListPhoneNumber::addComb(const char *number, ListPhoneNumber *negList) {
	vector<string>number_elems = split(number, split(" |,|;|\t|\r|\n", "|"), true);
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

void ListUA::addComb(string &ua, ListUA *negList) {
	addComb(ua.c_str(), negList);
}

void ListUA::addComb(const char *ua, ListUA *negList) {
	vector<string>ua_elems = split(ua, split(" |,|;|\t|\r|\n", "|"), true);
	for(size_t i = 0; i < ua_elems.size(); i++) {
		if(ua_elems[i][0] == '!') {
			if(negList) {
				negList->add(ua_elems[i].substr(1).c_str());
			}
		} else {
			add(ua_elems[i].c_str());
		}
	}
}

void ListCheckString::addComb(string &checkString, ListCheckString *negList) {
	addComb(checkString.c_str(), negList);
}

void ListCheckString::addComb(const char *checkString, ListCheckString *negList) {
	vector<string>checkString_elems = split(checkString, split(" |,|;|\t|\r|\n", "|"), true);
	for(size_t i = 0; i < checkString_elems.size(); i++) {
		if(checkString_elems[i][0] == '!') {
			if(negList) {
				negList->add(checkString_elems[i].substr(1).c_str());
			}
		} else {
			add(checkString_elems[i].c_str());
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

ListUA_wb::ListUA_wb(bool autoLock)
 : white(autoLock),
   black(autoLock) {
}

void ListUA_wb::addWhite(string &ua) {
	white.addComb(ua, &black);
}

void ListUA_wb::addWhite(const char *ua) {
	white.addComb(ua, &black);
}

void ListUA_wb::addBlack(string &ua) {
	black.addComb(ua, &white);
}

void ListUA_wb::addBlack(const char *ua) {
	black.addComb(ua, &white);
}

ListCheckString_wb::ListCheckString_wb(bool autoLock)
 : white(autoLock),
   black(autoLock) {
}

void ListCheckString_wb::addWhite(string &checkString) {
	white.addComb(checkString, &black);
}

void ListCheckString_wb::addWhite(const char *checkString) {
	white.addComb(checkString, &black);
}

void ListCheckString_wb::addBlack(string &checkString) {
	black.addComb(checkString, &white);
}

void ListCheckString_wb::addBlack(const char *checkString) {
	black.addComb(checkString, &white);
}


ParsePacket::ppNode::ppNode() {
	for(int i = 0; i < 256; i++) {
		nodes[i] = 0;
	}
	leaf = false;
	typeNode = typeNode_std;
	nodeIndex = 0;
	isContentLength = false;
}

ParsePacket::ppNode::~ppNode() {
	for(int i = 0; i < 256; i++) {
		if(nodes[i]) {
			delete nodes[i];
		}
	}
}

void ParsePacket::ppNode::addNode(const char *nodeName, eTypeNode typeNode, int nodeIndex, bool isContentLength) {
	while(*nodeName == '\n') {
		 ++nodeName;
	}
	if(*nodeName) {
		unsigned char nodeChar = (unsigned char)*nodeName;
		if(nodeChar >= 'A' && nodeChar <= 'Z') {
			nodeChar -= 'A' - 'a';
		}
		ppNode *node = (ppNode*)nodes[nodeChar];
		if(!node) {
			node = new FILE_LINE(38005) ppNode;
		}
		node->addNode(nodeName + 1, typeNode, nodeIndex, isContentLength);
		if(!nodes[nodeChar]) {
			nodes[nodeChar] = node;
		}
	} else {
		leaf = true;
		this->typeNode = typeNode;
		this->nodeIndex = nodeIndex;
		this->isContentLength = isContentLength;
	}
}
		
void ParsePacket::ppNode::debugData(ppContentsX *contents, ParsePacket *parsePacket) {
	if(leaf) {
		if(typeNode == typeNode_std && contents->std[nodeIndex].length > 0) {
			cout << "S " << parsePacket->nodesStd[nodeIndex] 
			     << " : " << string(contents->parseDataPtr +  contents->std[nodeIndex].offset, contents->std[nodeIndex].length)
			     << " : L " << contents->std[nodeIndex].length
			     << endl;
		} else if(typeNode == typeNode_custom && contents->custom[nodeIndex].length > 0) {
			cout << "C " << parsePacket->nodesCustom[nodeIndex] 
			     << " : " << string(contents->parseDataPtr +  contents->custom[nodeIndex].offset, contents->custom[nodeIndex].length)
			     << " : L " << contents->custom[nodeIndex].length
			     << endl;
		}
	} else {
		for(int i = 0; i < 256; i++) {
			if(nodes[i]) {
				ppNode *node = (ppNode*)nodes[i];
				node->debugData(contents, parsePacket);
			}
		}
	}
}

ParsePacket::ParsePacket() {
	root = NULL;
	rootCheckSip = NULL;
	timeSync_SIP_HEADERfilter = 0;
	timeSync_custom_headers_cdr = 0;
	timeSync_custom_headers_message = 0;
	timeSync_custom_headers_sip_msg = 0;
}

ParsePacket::~ParsePacket() {
	free();
}
	
void ParsePacket::setStdParse() {
	if(!root) {
		root = new FILE_LINE(38006) ppNode;
	}
	if(!rootCheckSip) {
		rootCheckSip = new FILE_LINE(38007) ppNode;
	}
	addNode("content-length:", typeNode_std, true);
	addNode("l:", typeNode_std, true);
	addNode("INVITE ", typeNode_std);
	addNode("MESSAGE ", typeNode_std);
	addNode("call-id:", typeNode_std);
	addNode("i:", typeNode_std);
	addNode("from:", typeNode_std);
	addNode("f:", typeNode_std);
	addNode("to:", typeNode_std);
	addNode("t:", typeNode_std);
	addNode("contact:", typeNode_std);
	addNode("m:", typeNode_std);
	addNode("remote-party-id:", typeNode_std);
	extern int opt_passertedidentity;
	if(opt_passertedidentity) {
		addNode("P-Asserted-Identity:", typeNode_std);
	}
	extern int opt_ppreferredidentity;
	if(opt_ppreferredidentity) {
		addNode("P-Preferred-Identity:", typeNode_std);
	}
	addNode("geoposition:", typeNode_std);
	addNode("user-agent:", typeNode_std);
	addNode("authorization:", typeNode_std);
	addNode("proxy-authorization:", typeNode_std);
	addNode("expires:", typeNode_std);
	addNode("x-voipmonitor-norecord:", typeNode_std);
	addNode("signal:", typeNode_std);
	addNode("signal=", typeNode_std);
	addNode("x-voipmonitor-custom1:", typeNode_std);
	addNode("content-type:", typeNode_std);
	addNode("c:", typeNode_std);
	addNode("cseq:", typeNode_std);
	addNode("supported:", typeNode_std);
	addNode("proxy-authenticate:", typeNode_std);
	addNode("via:", typeNode_std);
	addNode("v:", typeNode_std);
	extern sExistsColumns existsColumns;
	if(existsColumns.cdr_reason) {
		addNode("reason:", typeNode_std);
	}
	addNode("m=audio ", typeNode_std);
	addNode("a=rtpmap:", typeNode_std);
	addNode("o=", typeNode_std);
	addNode("c=IN IP4 ", typeNode_std);
	addNode("expires=", typeNode_std);
	addNode("username=\"", typeNode_std);
	addNode("realm=\"", typeNode_std);
	
	addNode("CallID:", typeNode_std);
	addNode("LocalAddr:", typeNode_std);
	addNode("RemoteAddr:", typeNode_std);
	addNode("QualityEst:", typeNode_std);
	addNode("PacketLoss:", typeNode_std);
	
	extern char opt_call_id_alternative[256];
	extern vector<string> opt_call_id_alternative_v;
	if(opt_call_id_alternative[0] && opt_call_id_alternative_v.size()) {
		for(unsigned i = 0; i < opt_call_id_alternative_v.size(); i++) {
			addNode(opt_call_id_alternative_v[i].c_str(), typeNode_std);
		}
	}
	
	extern char opt_fbasename_header[128];
	if(opt_fbasename_header[0] != '\0') {
		string findHeader = opt_fbasename_header;
		if(findHeader[findHeader.length() - 1] != ':') {
			findHeader.append(":");
		}
		addNode(findHeader.c_str(), typeNode_std);
	}
	
	extern char opt_match_header[128];
	if(opt_match_header[0] != '\0') {
		string findHeader = opt_match_header;
		if(findHeader[findHeader.length() - 1] != ':') {
			findHeader.append(":");
		}
		addNode(findHeader.c_str(), typeNode_std);
	}
	
	extern char opt_callidmerge_header[128];
	if(opt_callidmerge_header[0] != '\0') {
		string findHeader = opt_callidmerge_header;
		if(findHeader[findHeader.length() - 1] != ':') {
			findHeader.append(":");
		}
		addNode(findHeader.c_str(), typeNode_std);
	}
	
	extern char opt_energylevelheader[128];
	if(opt_energylevelheader[0] != '\0') {
		string findHeader = opt_energylevelheader;
		if(findHeader[findHeader.length() - 1] != ':') {
			findHeader.append(":");
		}
		addNode(findHeader.c_str(), typeNode_std);
	}

	extern char opt_silenceheader[128];
	if(opt_silenceheader[0] != '\0') {
		string findHeader = opt_silenceheader;
		if(findHeader[findHeader.length() - 1] != ':') {
			findHeader.append(":");
		}
		addNode(findHeader.c_str(), typeNode_std);
	}
	
	extern CustomHeaders *custom_headers_cdr;
	extern CustomHeaders *custom_headers_message;
	extern CustomHeaders *custom_headers_sip_msg;
	if(custom_headers_cdr) {
		custom_headers_cdr->addToStdParse(this);
		this->timeSync_custom_headers_cdr = custom_headers_cdr->getLoadTime();
	}
	if(custom_headers_message) {
		custom_headers_message->addToStdParse(this);
		this->timeSync_custom_headers_message = custom_headers_message->getLoadTime();
	}
	if(custom_headers_sip_msg) {
		custom_headers_sip_msg->addToStdParse(this);
		this->timeSync_custom_headers_sip_msg = custom_headers_sip_msg->getLoadTime();
	}
	
	extern vmIP opt_kamailio_dstip;
	if(opt_kamailio_dstip.isSet()) {
		addNode("X-Siptrace-Fromip:", typeNode_std);
		addNode("X-Siptrace-Toip:", typeNode_std);
		addNode("X-Siptrace-Time:", typeNode_std);
	}
	
	/* obsolete
	extern vector<dstring> opt_custom_headers_cdr;
	extern vector<dstring> opt_custom_headers_message;
	for(int i = 0; i < 2; i++) {
		vector<dstring> *_customHeaders = i == 0 ? &opt_custom_headers_cdr : &opt_custom_headers_message;
		for(size_t iCustHeaders = 0; iCustHeaders < _customHeaders->size(); iCustHeaders++) {
			string findHeader = (*_customHeaders)[iCustHeaders][0];
			if(findHeader.length()) {
				if(findHeader[findHeader.length() - 1] != ':') {
					findHeader.append(":");
				}
				addNode(findHeader.c_str());
			}
		}
	}
	*/
	
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
	
	SIP_HEADERfilter::addNodes(this);
	this->timeSync_SIP_HEADERfilter = SIP_HEADERfilter::getLoadTime();
}

void ParsePacket::addNode(const char *nodeName, eTypeNode typeNode, bool isContentLength) {
	std::vector<string> *listNodes = typeNode == typeNode_std ? &nodesStd :
					 typeNode == typeNode_custom ? &nodesCustom : NULL;
	if(!listNodes) {
		return;
	}
	string nodeNameUpper = string(*nodeName == '\n' ? nodeName + 1 : nodeName);
	std::transform(nodeNameUpper.begin(), nodeNameUpper.end(), nodeNameUpper.begin(), ::toupper);
	if(std::find(nodesStd.begin(), nodesStd.end(), nodeNameUpper) == nodesStd.end() &&
	   std::find(nodesCustom.begin(), nodesCustom.end(), nodeNameUpper) == nodesCustom.end()) {
		if(listNodes->size() < (typeNode == typeNode_std ? ParsePacket_std_max : ParsePacket_custom_max)) {
			listNodes->push_back(nodeNameUpper);
			if(!root) {
				root = new FILE_LINE(38008) ppNode;
			}
			root->addNode(nodeName, typeNode, listNodes->size() - 1, isContentLength);
		} else {
			syslog(LOG_WARNING, "too much sip nodes for ParsePacket");
		}
	}
}

void ParsePacket::addNodeCheckSip(const char *nodeName) {
	if(std::find(nodesCheckSip.begin(), nodesCheckSip.end(), nodeName) == nodesCheckSip.end()) {
		nodesCheckSip.push_back(nodeName);
		if(!rootCheckSip) {
			rootCheckSip = new FILE_LINE(38009) ppNode;
		}
		rootCheckSip->addNode(nodeName, typeNode_checkSip, nodesCheckSip.size() - 1, false);
	}
}

u_int32_t ParsePacket::parseData(char *data, unsigned long datalen, ppContentsX *contents) {
	extern CustomHeaders *custom_headers_cdr;
	extern CustomHeaders *custom_headers_message;
	extern CustomHeaders *custom_headers_sip_msg;
	if(!this->timeSync_SIP_HEADERfilter) {
		this->timeSync_SIP_HEADERfilter = SIP_HEADERfilter::getLoadTime();
	}
	bool reload_for_sipheaderfilter = false;
	bool reload_for_custom_headers_cdr = false;
	bool reload_for_custom_headers_message = false;
	bool reload_for_custom_headers_sip_msg = false;
	if(SIP_HEADERfilter::getLoadTime() > this->timeSync_SIP_HEADERfilter) {
		reload_for_sipheaderfilter = true;
	}
	if(custom_headers_cdr && custom_headers_cdr->getLoadTime() > this->timeSync_custom_headers_cdr) {
		reload_for_custom_headers_cdr = true;
	}
	if(custom_headers_message && custom_headers_message->getLoadTime() > this->timeSync_custom_headers_message) {
		reload_for_custom_headers_message = true;
	}
	if(custom_headers_sip_msg && custom_headers_sip_msg->getLoadTime() > this->timeSync_custom_headers_sip_msg) {
		reload_for_custom_headers_sip_msg = true;
	}
	if(reload_for_sipheaderfilter ||
	   reload_for_custom_headers_cdr ||
	   reload_for_custom_headers_message ||
	   reload_for_custom_headers_sip_msg) {
		this->setStdParse();
		if(reload_for_sipheaderfilter) {
			this->timeSync_SIP_HEADERfilter = SIP_HEADERfilter::getLoadTime();
			if(sverb.capture_filter) {
				syslog(LOG_NOTICE, "SIP_HEADERfilter - reload ParsePacket::parseData after load SIP_HEADERfilter");
			}
		}
		if(reload_for_custom_headers_cdr) {
			 this->timeSync_custom_headers_cdr = custom_headers_cdr->getLoadTime();
		}
		if(reload_for_custom_headers_sip_msg) {
			 this->timeSync_custom_headers_sip_msg = custom_headers_sip_msg->getLoadTime();
		}
	}
	unsigned long rsltDataLen = datalen;
	contents->sip = datalen ? isSipContent(data, datalen - 1) : false;
	unsigned int namelength;
	for(unsigned long i = 0; i < datalen; i++) {
		if(!contents->doubleEndLine && 
		   datalen > 3 &&
		   data[i] == '\r' && i < datalen - 3 && 
		   data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
			contents->doubleEndLine = data + i;
			if(contents->contentLength > -1) {
				unsigned long modify_datalen = contents->doubleEndLine + 4 - data + contents->contentLength;
				if(modify_datalen < datalen) {
					datalen = modify_datalen;
					rsltDataLen = datalen;
				}
			} else {
				rsltDataLen = contents->doubleEndLine + 4 - data;
				break;
			}
			i += 2;
		} else if(i == 0 || data[i - 1] == '\n') {
			ppNode *node = getNode(data + i, datalen - i - 1, &namelength);
			if(node && !node->isSetNode(contents)) {
				ppContentItemX *contentItem = node->getPointerToItem(contents);
				contentItem->offset = i + namelength;
				i += namelength;
				bool endLine = false;
				for(; i < datalen; i++) {
					if(data[i] == '\r' || data[i] == '\n') {
						endLine = true;
						break;
					}
				}
				if(endLine || i == datalen) {
					contentItem->length = i - contentItem->offset;
					contentItem->trim(data);
					if(node->isContentLength && contentItem->length) {
						if(contentItem->offset + contentItem->length == datalen) {
							char tempLength[10];
							int maxLengthLength = MIN(sizeof(tempLength) - 1, contentItem->length);
							strncpy(tempLength, data + contentItem->offset, maxLengthLength);
							tempLength[maxLengthLength] = 0;
							contents->contentLength = atoi(tempLength);
						} else {
							contents->contentLength = atoi(data + contentItem->offset);
						}
					}
					if(endLine) {
						--i;
					}
				}
			}
		}
	}
	contents->parseDataPtr = data;
	return(rsltDataLen);
}

void ParsePacket::free() {
	if(root) {
		delete root;
		root = NULL;
	}
	if(rootCheckSip) {
		delete rootCheckSip;
		rootCheckSip = NULL;
	}
}

void ParsePacket::debugData(ppContentsX *contents) {
	root->debugData(contents, this);
}


void *_SafeAsyncQueue_timerThread(void *arg) {
	((SafeAsyncQueue_base*)arg)->timerThread();
	return(NULL);
}

SafeAsyncQueue_base::SafeAsyncQueue_base() {
	if(!timer_thread) {
		vm_pthread_create("async queue",
				  &timer_thread, NULL, _SafeAsyncQueue_timerThread, NULL, __FILE__, __LINE__);
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
	if(wait) {
		while(runTimerThread) {
			USLEEP(100000);
		}
		terminateTimerThread = false;
	}
}

void SafeAsyncQueue_base::timerThread() {
	runTimerThread = true;
	while(!terminateTimerThread) {
		USLEEP(100000);
		lock_list_saq();
		list<SafeAsyncQueue_base*>::iterator iter;
		for(iter = list_saq.begin(); iter != list_saq.end(); iter++) {
			(*iter)->timerEv(timer_counter);
		}
		unlock_list_saq();
		++timer_counter;
	}
	runTimerThread = false;
	timer_thread = 0;
	timer_counter = 0;
}

list<SafeAsyncQueue_base*> SafeAsyncQueue_base::list_saq;

pthread_t SafeAsyncQueue_base::timer_thread = 0;

unsigned long long SafeAsyncQueue_base::timer_counter = 0;

volatile int SafeAsyncQueue_base::_sync_list_saq = 0;

bool SafeAsyncQueue_base::runTimerThread = false;

bool SafeAsyncQueue_base::terminateTimerThread = false;


//------------------------------------------------------------------------------
// pcap_dump_open with set buffer

#define DEFAULT_BUFFER_LENGTH		8192

FileZipHandler::FileZipHandler(int bufferLength, int enableAsyncWrite, eTypeCompress typeCompress,
			       bool dumpHandler, Call_abstract *call,
			       eTypeFile typeFile, unsigned indexFile) {
	this->mode = mode_na;
	this->typeSpoolFile = tsf_na;
	if(bufferLength <= 0) {
		enableAsyncWrite = 0;
		typeCompress = compress_na;
	}
	this->permission_file = 0;
	this->permission_dir = 0;
	this->uid = 0;
	this->gid = 0;
	this->fh = 0;
	this->tar = opt_pcap_dump_tar && call && typeFile != FileZipHandler::na ? 
		     (call->getSpoolIndex() + 1) :
		     0;
	this->tar_data.clear();
	this->compressStream = NULL;
	this->bufferLength = this->tar ?
			      (bufferLength ? bufferLength : DEFAULT_BUFFER_LENGTH) :
			      bufferLength;
	if(bufferLength) {
		this->buffer = new FILE_LINE(38015) char[bufferLength];
	} else {
		this->buffer = NULL;
	}
	this->useBufferLength = 0;
	this->tarBuffer = NULL;
	this->tarBufferCreated = false;
	this->enableAsyncWrite = enableAsyncWrite && !is_read_from_file_simple();
	this->typeCompress = typeCompress;
	this->dumpHandler = dumpHandler;
	this->call = call;
	this->time = call ? call->calltime_s() : 0;
	this->size = 0;
	this->existsData = false;
	this->counter = ++scounter;
	this->userData = 0;
	this->typeFile = typeFile;
	this->indexFile = indexFile;
	if(typeCompress == compress_default) {
		this->setTypeCompressDefault();
	}
	this->readBufferBeginPos = 0;
	this->eof = false;
}

FileZipHandler::~FileZipHandler() {
	this->close();
	if(this->buffer) {
		delete [] this->buffer;
	}
	if(this->tarBuffer) {
		delete this->tarBuffer;
	}
	if(this->compressStream) {
		delete this->compressStream;
	}
	if(this->tar && !this->tarBufferCreated) {
		if(this->tar_data.year) {
			tarQueue[this->tar - 1]->decreaseTartimemap(&this->tar_data);
			if(sverb.tar > 2) {
				syslog(LOG_NOTICE, "tartimemap decrease2: %s %s",
				       this->fileName.c_str(), this->tar_data.getTimeString().c_str());
			}
		}
	}
	for(unsigned i = 0; i < this->readBuffer.size(); i++) {
		delete [] this->readBuffer[i].buff;
	}
}

bool FileZipHandler::open(eTypeSpoolFile typeSpoolFile, const char *fileName, 
			  int permission_file, int permission_dir, unsigned uid, unsigned gid) {
	this->typeSpoolFile = typeSpoolFile;
	this->fileName = fileName;
	this->permission_file = permission_file ? permission_file : spooldir_file_permission();
	this->permission_dir = permission_dir ? permission_dir : spooldir_dir_permission();
	this->uid = uid ? uid : spooldir_owner_id();
	this->gid = gid ? gid : spooldir_group_id();
	if(this->tar) {
		if(this->call) {
			this->tar_data.set(typeSpoolFile, this->call, this->fileName.c_str());
			tarQueue[this->tar - 1]->increaseTartimemap(&this->tar_data);
		}
		if(sverb.tar > 2) {
			syslog(LOG_NOTICE, "FileZipHandler open: %s %s", 
			       fileName, this->tar_data.getTimeString().c_str());
			syslog(LOG_NOTICE, "tartimemap increase: %s %s", 
			       fileName, this->tar_data.getTimeString().c_str());
		}
	}
	return(true);
}

void FileZipHandler::close() {
	if(this->mode == mode_read) {
		if(this->okHandle()) {
			::close(this->fh);
			this->fh = 0;
		}
	} else {
		if(this->tar) {
			#if DEBUG_ASYNC_TAR_WRITE
			if(call) {
				call->addPFlag(typeFile - 1 + indexFile, Call_abstract::_p_flag_fzh_close);
			}
			#endif
			this->flushBuffer(true);
			this->flushTarBuffer();
		} else  {
			if(this->okHandle() || this->useBufferLength) {
				this->flushBuffer(true);
				if(this->okHandle()) {
					::close(this->fh);
					this->fh = 0;
				}
			}
		}
	}
}

bool FileZipHandler::read(unsigned length) {
	this->mode = mode_read;
	if(!this->okHandle()) {
		if(!this->error.empty() || !this->_open_read()) {
			return(false);
		}
	}
	if(this->eof) {
		return(true);
	}
	u_char *buffer = new FILE_LINE(38016) u_char[length];
	ssize_t read_length = ::read(this->fh, buffer, length);
	if(read_length > 0) {
		if(!this->compressStream) {
			this->initDecompress();
		}
		this->compressStream->decompress((char*)buffer, read_length, 0, false, this);
	} else if(read_length == 0) {
		if(this->compressStream) {
			this->compressStream->decompress(NULL, 0, 0, true, this);
		}
		this->eof = true;
	}
	delete [] buffer;
	return(read_length >= 0 && (!this->compressStream || this->compressStream->isOk()));
}

bool FileZipHandler::is_ok_decompress() {
	return(!this->compressStream || this->compressStream->isOk());
}

bool FileZipHandler::is_eof() {
	return(this->eof);
}

bool FileZipHandler::flushBuffer(bool force) {
	if(!this->buffer || !this->useBufferLength) {
		#if DEBUG_ASYNC_TAR_WRITE
		if(call) {
			call->addPFlag(typeFile - 1 + indexFile, Call_abstract::_p_flag_fzh_flushbuffer_1);
		}
		#endif
		if(force && this->existsData && !this->tar && this->okHandle() &&
		   this->compressStream && this->compressStream->getTypeCompress() != CompressStream::compress_na) {
			#if DEBUG_ASYNC_TAR_WRITE
			if(call) {
				call->addPFlag(typeFile - 1 + indexFile, Call_abstract::_p_flag_fzh_flushbuffer_2);
			}
			#endif
			this->compressStream->compress(NULL, 0, true, this);
		}
		return(true);
	}
	#if DEBUG_ASYNC_TAR_WRITE
	if(call) {
		call->addPFlag(typeFile - 1 + indexFile, Call_abstract::_p_flag_fzh_flushbuffer_3);
	}
	#endif
	bool rsltWrite = this->writeToFile(this->buffer, this->useBufferLength, force);
	this->useBufferLength = 0;
	return(rsltWrite);
}

void FileZipHandler::flushTarBuffer() {
	#if DEBUG_ASYNC_TAR_WRITE
	if(call) {
		call->addPFlag(typeFile - 1 + indexFile, Call_abstract::_p_flag_fzh_flushtar_1);
	}
	#endif
	if(!this->tarBuffer)
		return;
	#if DEBUG_ASYNC_TAR_WRITE
	if(call) {
		call->addPFlag(typeFile - 1 + indexFile, Call_abstract::_p_flag_fzh_flushtar_2);
	}
	#endif
	this->tarBuffer->close();
	#if DEBUG_ASYNC_TAR_WRITE
	if(call) {
		call->addPFlag(typeFile - 1 + indexFile, Call_abstract::_p_flag_fzh_flushtar_3);
	}
	#endif
	this->tarBuffer = NULL;
}

bool FileZipHandler::writeToBuffer(char *data, int length) {
	if(!this->buffer) {
		return(false);
	}
	if(this->useBufferLength && this->useBufferLength + length > this->bufferLength) {
		flushBuffer();
	}
	if(length <= this->bufferLength) {
		memcpy_heapsafe(this->buffer + this->useBufferLength, this->buffer,
				data, NULL,
				length,
				__FILE__, __LINE__);
		this->useBufferLength += length;
		return(true);
	} else {
		return(this->writeToFile(data, length));
	}
}

bool FileZipHandler::writeToFile(char *data, int length, bool force) {
	if(!existsData) {
		return(true);
	}
	if(enableAsyncWrite && !force) {
		if(dumpHandler) {
			asyncClose->addWrite((pcap_dumper_t*)this, data, length);
		} else {
			asyncClose->addWrite(this, data, length);
		}
		return(true);
	} else {
		return(this->_writeToFile(data, length, force));
	}
}

bool FileZipHandler::_writeToFile(char *data, int length, bool flush) {
	if(!existsData) {
		return(true);
	}
	if(!this->error.empty()) {
		return(false);
	}
	switch(this->typeCompress) {
	case compress_na:
		if(this->tar) {
			if(!this->tarBuffer) {
				this->initTarbuffer();
			}
			#if DEBUG_ASYNC_TAR_WRITE
			if(call) {
				call->addPFlag(typeFile - 1 + indexFile, Call_abstract::_p_flag_fzh_write_1);
			}
			#endif
			this->tarBuffer->add(data, length, flush);
			#if DEBUG_ASYNC_TAR_WRITE
			if(call) {
				call->addPFlag(typeFile - 1 + indexFile, Call_abstract::_p_flag_fzh_write_2);
			}
			#endif
			return(true);
		}
		{
		int rsltWrite = this->__writeToFile(data, length);
		if(rsltWrite <= 0) {
			this->setError();
			return(false);
		} else {
			this->size += length;
			return(true);
		}
		}
		break;
	case compress_default:
		this->setTypeCompressDefault();
	case gzip:
	case snappy:
	case lzo:
		if(!this->compressStream) {
			this->initCompress();
		}
		#if DEBUG_ASYNC_TAR_WRITE
		if(call) {
			call->addPFlag(typeFile - 1 + indexFile, Call_abstract::_p_flag_fzh_write_1);
		}
		#endif
		this->compressStream->compress(data, length, flush, this);
		#if DEBUG_ASYNC_TAR_WRITE
		if(call) {
			call->addPFlag(typeFile - 1 + indexFile, Call_abstract::_p_flag_fzh_write_2);
		}
		#endif
		break;
	}
	return(false);
}

bool FileZipHandler::__writeToFile(char *data, int length) {
	if(!this->okHandle()) {
		if(!this->error.empty() || !this->_open_write()) {
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

void FileZipHandler::initCompress() {
	this->compressStream =  new FILE_LINE(38017) CompressStream(this->typeCompress == gzip ? CompressStream::gzip :
							     this->typeCompress == snappy ? CompressStream::snappy :
							     this->typeCompress == lzo ? CompressStream::lzo : CompressStream::compress_na,
							     this->typeCompress == snappy || this->typeCompress == lzo ?
							      this->bufferLength :
							      8 * 1024, 
							     0);
	this->compressStream->setZipLevel(typeFile == pcap_sip ? opt_pcap_dump_ziplevel_sip : 
					  typeFile == pcap_rtp ? opt_pcap_dump_ziplevel_rtp : 
					  typeFile == graph_rtp ? opt_pcap_dump_ziplevel_graph : Z_DEFAULT_COMPRESSION);
	this->compressStream->enableAutoPrefixFile();
	this->compressStream->enableForceStream();
}

void FileZipHandler::initDecompress() {
	this->compressStream =  new FILE_LINE(38018) CompressStream(this->typeCompress == gzip ? CompressStream::gzip :
							     this->typeCompress == snappy ? CompressStream::snappy :
							     this->typeCompress == lzo ? CompressStream::lzo : CompressStream::compress_na,
							     8 * 1024,
							     0);
}

void FileZipHandler::initTarbuffer(bool useFileZipHandlerCompress) {
	#if DEBUG_ASYNC_TAR_WRITE
	if(call) {
		call->addPFlag(typeFile - 1 + indexFile, Call_abstract::_p_flag_init_tar_buffer);
	}
	#endif
	this->tarBufferCreated = true;
	this->tarBuffer = new FILE_LINE(38019) ChunkBuffer(this->time, this->tar_data, this->needTarPos(),
							   typeFile == pcap_sip ? 8 * 1024 : 
							   typeFile == pcap_rtp ? 32 * 1024 : 
							   typeFile == graph_rtp ? 16 * 1024 : 8 * 1024,
							   call, typeFile, indexFile,
							   this->fileName.c_str());
	if(sverb.tar > 2) {
		syslog(LOG_NOTICE, "chunkbufer create: %s %lx %s",
		       this->fileName.c_str(), (long)this->tarBuffer,
		       this->tar_data.getTimeString().c_str());
	}
	if(!useFileZipHandlerCompress) {
		extern CompressStream::eTypeCompress opt_pcap_dump_tar_internalcompress_sip;
		extern CompressStream::eTypeCompress opt_pcap_dump_tar_internalcompress_rtp;
		extern CompressStream::eTypeCompress opt_pcap_dump_tar_internalcompress_graph;
		extern int opt_pcap_dump_tar_internal_gzip_sip_level;
		extern int opt_pcap_dump_tar_internal_gzip_rtp_level;
		extern int opt_pcap_dump_tar_internal_gzip_graph_level;
		switch(typeFile) {
		case pcap_sip:
			if(opt_pcap_dump_tar_internalcompress_sip != CompressStream::compress_na) {
				this->tarBuffer->setTypeCompress(opt_pcap_dump_tar_internalcompress_sip, 8 * 1024, this->bufferLength);
				this->tarBuffer->setZipLevel(opt_pcap_dump_tar_internal_gzip_sip_level);
			}
			break;
		case pcap_rtp:
			if(opt_pcap_dump_tar_internalcompress_rtp != CompressStream::compress_na) {
				this->tarBuffer->setTypeCompress(opt_pcap_dump_tar_internalcompress_rtp, 8 * 1024, this->bufferLength);
				this->tarBuffer->setZipLevel(opt_pcap_dump_tar_internal_gzip_rtp_level);
			}
			break;
		case graph_rtp:
			if(opt_pcap_dump_tar_internalcompress_graph != CompressStream::compress_na) {
				this->tarBuffer->setTypeCompress(opt_pcap_dump_tar_internalcompress_graph, 8 * 1024, this->bufferLength);
				this->tarBuffer->setZipLevel(opt_pcap_dump_tar_internal_gzip_graph_level);
			}
			break;
		case na:
			break;
		}
	}
	tarQueue[this->tar - 1]->add(&this->tar_data, this->tarBuffer, this->time);
	#if DEBUG_ASYNC_TAR_WRITE
	if(call) {
		call->addPFlag(typeFile - 1 + indexFile, Call_abstract::_p_flag_init_tar_buffer_end);
	}
	#endif
}

bool FileZipHandler::_open_write() {
	if(this->tar) {
		return(true);
	}
	for(int passOpen = 0; passOpen < 2; passOpen++) {
		if(passOpen == 1) {
			char *pointToLastDirSeparator = strrchr((char*)fileName.c_str(), '/');
			if(pointToLastDirSeparator) {
				*pointToLastDirSeparator = 0;
				mkdir_r(fileName.c_str(), permission_dir, this->uid, this->gid);
				*pointToLastDirSeparator = '/';
			} else {
				break;
			}
		}
		this->fh = ::open(fileName.c_str(), O_WRONLY | O_CREAT | O_TRUNC, permission_file);
		if(this->okHandle()) {
			if(this->uid || this->gid) {
				fchown(this->fh, this->uid, this->gid);
			}
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

bool FileZipHandler::_open_read() {
	this->fh = ::open(fileName.c_str(), O_RDONLY);
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

FileZipHandler::eTypeCompress FileZipHandler::convTypeCompress(const char *typeCompress) {
	char _compress_method[20];
	strcpy_null_term(_compress_method, typeCompress);
	strlwr(_compress_method, sizeof(_compress_method));
	if(yesno(_compress_method)) {
		return(FileZipHandler::compress_default);
	} else if(!strcmp(_compress_method, "zip") ||
		  !strcmp(_compress_method, "gzip")) {
		return(FileZipHandler::gzip);
	} else if(!strcmp(_compress_method, "snappy")) {
		return(FileZipHandler::snappy);
	} else if(!strcmp(_compress_method, "lzo")) {
		return(FileZipHandler::lzo);
	}
	return(FileZipHandler::compress_na);
}

const char *FileZipHandler::convTypeCompress(eTypeCompress typeCompress) {
	switch(typeCompress) {
	case gzip:
		return("zip");
	case snappy:
		return("snappy");
	case lzo:
		return("lzo");
	case compress_default:
		return("yes");
	default:
		return("no");
	}
	return("no");
}

string FileZipHandler::getConfigMenuString() {
	ostringstream outStr;
	outStr << convTypeCompress(compress_default) << ':' << compress_default << '|'
	       << convTypeCompress(gzip) << ':' << gzip << '|'
	       << convTypeCompress(snappy) << ':' << snappy << '|'
	       << convTypeCompress(lzo) << ':' << lzo << '|'
	       << "no:0";
	return(outStr.str());
}

void FileZipHandler::setTypeCompressDefault() {
	if(typeCompress == compress_default) {
		typeCompress = getTypeCompressDefault();
	}
}

FileZipHandler::eTypeCompress FileZipHandler::getTypeCompressDefault() {
	switch(typeFile) {
	case pcap_sip:
		return(gzip);
	case pcap_rtp:
	case graph_rtp:
		return(lzo);
	default:
		return(gzip);
	}
}

bool FileZipHandler::needTarPos() {
	return(tar &&
	       (typeCompress == lzo ||
		(typeCompress == compress_default && getTypeCompressDefault() == lzo)));
}

bool FileZipHandler::compress_ev(char *data, u_int32_t len, u_int32_t /*decompress_len*/, bool /*format_data*/) {
	if(this->tar) {
		#if DEBUG_ASYNC_TAR_WRITE
		if(call) {
			call->addPFlag(typeFile - 1 + indexFile, Call_abstract::_p_flag_fzh_compress_ev_1);
		}
		#endif
		if(!this->tarBuffer) {
			this->initTarbuffer(true);
		}
		this->tarBuffer->add(data, len, false);
		#if DEBUG_ASYNC_TAR_WRITE
		if(call) {
			call->addPFlag(typeFile - 1 + indexFile, Call_abstract::_p_flag_fzh_compress_ev_2);
		}
		#endif
		return(true);
	}
	if(this->__writeToFile(data, len) <= 0) {
		this->setError();
		return(false);
	}
	return(true);
}

bool FileZipHandler::decompress_ev(char *data, u_int32_t len) {
	if(len) {
		this->addReadBuffer(data, len);
	}
	return(true);
}

void FileZipHandler::addReadBuffer(char *data, u_int32_t len) {
	sReadBufferItem readBufferItem;
	readBufferItem.buff = new FILE_LINE(38020) u_char[len];
	readBufferItem.length = len;
	memcpy(readBufferItem.buff, data, len);
	this->readBuffer.push_back(readBufferItem);
}

bool FileZipHandler::getLineFromReadBuffer(string *line) {
	u_char *endLinePos = NULL;
	unsigned endLinePosIndex = 0;
	for(unsigned i = 0; i < this->readBuffer.size(); i++) {
		u_char *findEndLinePos = (u_char*)memmem(this->readBuffer[i].buff + (i == 0 ? this->readBufferBeginPos : 0),
							 this->readBuffer[i].length - (i == 0 ? this->readBufferBeginPos : 0),
							 "\n", 1);
		if(findEndLinePos) {
			endLinePos = findEndLinePos;
			endLinePosIndex = i;
			break;
		}
	}
	if(!endLinePos && this->eof && this->readBuffer.size()) {
		endLinePos = (u_char*)-1;
		endLinePosIndex = this->readBuffer.size() - 1;
	}
	if(endLinePos) {
		SimpleBuffer tempBuffer;
		for(unsigned i = 0; i <= endLinePosIndex; i++) {
			u_char *buff = this->readBuffer[i].buff;
			u_int32_t length = this->readBuffer[i].length;
			if(i == endLinePosIndex && endLinePos != (u_char*)-1) {
				length = endLinePos - buff + 1;
			}
			if(i == 0 && this->readBufferBeginPos) {
				buff += this->readBufferBeginPos;
				length -= this->readBufferBeginPos;
			}
			tempBuffer.add(buff, length);
		}
		if(endLinePosIndex) {
			for(unsigned i = 0; i < endLinePosIndex; i++) {
				delete [] this->readBuffer[0].buff;
				this->readBuffer.pop_front();
			}
		}
		if(endLinePos != (u_char*)-1) {
			this->readBufferBeginPos = endLinePos - this->readBuffer[0].buff + 1;
		} else {
			this->readBufferBeginPos = 0;
			delete [] this->readBuffer[0].buff;
			this->readBuffer.pop_front();
		}
		if(tempBuffer.size()) {
			*line = string((char*)tempBuffer.data(), tempBuffer.size());
			return(true);
		}
	}
	return(false);
}

u_int64_t FileZipHandler::scounter = 0;

#define TCPDUMP_MAGIC		0xa1b2c3d4
#define NSEC_TCPDUMP_MAGIC	0xa1b23c4d

pcap_dumper_t *__pcap_dump_open(pcap_t *p, eTypeSpoolFile typeSpoolFile, const char *fname, int linktype, string *errorString,
				int _bufflength, int _asyncwrite, FileZipHandler::eTypeCompress _typeCompress,
				Call_abstract *call, PcapDumper::eTypePcapDump type) {
	if(opt_pcap_dump_bufflength) {
		FileZipHandler *handler = new FILE_LINE(38021) FileZipHandler(_bufflength < 0 ? opt_pcap_dump_bufflength : _bufflength, 
									      _asyncwrite < 0 ? opt_pcap_dump_asyncwrite : _asyncwrite, 
									      _typeCompress == FileZipHandler::compress_default ? 
									       (type == PcapDumper::sip ? opt_pcap_dump_zip_sip :
										type == PcapDumper::rtp ? opt_pcap_dump_zip_rtp :
													  opt_pcap_dump_zip_sip) :
									       _typeCompress, 
									      true, call,
									      type == PcapDumper::sip ? FileZipHandler::pcap_sip :
									      type == PcapDumper::rtp ? FileZipHandler::pcap_rtp :
													FileZipHandler::na);
		if(handler->open(typeSpoolFile, fname)) {
			struct pcap_file_header hdr;
			hdr.magic = TCPDUMP_MAGIC;
			hdr.version_major = PCAP_VERSION_MAJOR;
			hdr.version_minor = PCAP_VERSION_MINOR;
			hdr.thiszone = 0;
			hdr.snaplen = 10000;
			hdr.sigfigs = 0;
			hdr.linktype = linktype;
			handler->write((char *)&hdr, sizeof(hdr), true);
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

struct pcap_timeval {
    bpf_int32 tv_sec;		/* seconds */
    bpf_int32 tv_usec;		/* microseconds */
};
struct pcap_sf_pkthdr {
    pcap_timeval ts;		/* time stamp */
    bpf_u_int32 caplen;		/* length of portion present */
    bpf_u_int32 len;		/* length this packet (off wire) */
};

void __pcap_dump(u_char *user, const struct pcap_pkthdr *h, const u_char *sp, bool allPackets) {
	if(opt_pcap_dump_bufflength) {
		FileZipHandler *handler = (FileZipHandler*)user;
		if(allPackets ||
		   (h->caplen > 0 && h->caplen <= h->len)) {
			pcap_sf_pkthdr sf_hdr;
			sf_hdr.ts.tv_sec  = h->ts.tv_sec;
			sf_hdr.ts.tv_usec = h->ts.tv_usec;
			sf_hdr.caplen     = h->caplen;
			sf_hdr.len        = h->len;
			handler->write((char*)&sf_hdr, sizeof(sf_hdr));
			handler->write((char*)sp, sf_hdr.caplen);
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

void createSimpleUdpDataPacket(u_int ether_header_length, pcap_pkthdr **header, u_char **packet,
			       u_char *source_packet, u_char *data, unsigned int datalen,
			       vmIP saddr, vmIP daddr, vmPort source, vmPort dest,
			       u_int32_t time_sec, u_int32_t time_usec) {
	unsigned iphdr_size = 
		#if VM_IPV6
		saddr.is_v6() ? 
		 sizeof(ip6hdr2) : 
		#endif
		 sizeof(iphdr2);
	u_int32_t packet_length = ether_header_length + iphdr_size + sizeof(udphdr2) + datalen;
	*packet = new FILE_LINE(38022) u_char[packet_length];
	memcpy(*packet, source_packet, ether_header_length);
	#if VM_IPV6
	if(saddr.is_v6()) {
		ip6hdr2 iphdr;
		memset(&iphdr, 0, iphdr_size);
		iphdr.version = 6;
		iphdr.nxt = IPPROTO_UDP;
		iphdr.set_saddr(saddr);
		iphdr.set_daddr(daddr);
		iphdr.set_tot_len(iphdr_size + sizeof(udphdr2) + datalen);
		memcpy(*packet + ether_header_length, &iphdr, iphdr_size);
	} else  {
	#endif
		iphdr2 iphdr;
		memset(&iphdr, 0, iphdr_size);
		iphdr.version = 4;
		iphdr._ihl = 5;
		iphdr._protocol = IPPROTO_UDP;
		iphdr.set_saddr(saddr);
		iphdr.set_daddr(daddr);
		iphdr.set_tot_len(iphdr_size + sizeof(udphdr2) + datalen);
		iphdr._ttl = 50;
		memcpy(*packet + ether_header_length, &iphdr, iphdr_size);
	#if VM_IPV6
	}
	#endif
	udphdr2 udphdr;
	memset(&udphdr, 0, sizeof(udphdr2));
	udphdr.set_source(source);
	udphdr.set_dest(dest);
	udphdr.len = htons(sizeof(udphdr2) + datalen);
	memcpy(*packet + ether_header_length + iphdr_size, &udphdr, sizeof(udphdr2));
	memcpy(*packet + ether_header_length + iphdr_size + sizeof(udphdr2), data, datalen);
	*header = new FILE_LINE(38023) pcap_pkthdr;
	memset(*header, 0, sizeof(pcap_pkthdr));
	(*header)->ts.tv_sec = time_sec;
	(*header)->ts.tv_usec = time_usec;
	(*header)->caplen = packet_length;
	(*header)->len = packet_length;
}

void createSimpleTcpDataPacket(u_int ether_header_length, pcap_pkthdr **header, u_char **packet,
			       u_char *source_packet, u_char *data, unsigned int datalen,
			       vmIP saddr, vmIP daddr, vmPort source, vmPort dest,
			       u_int32_t seq, u_int32_t ack_seq, 
			       u_int32_t time_sec, u_int32_t time_usec, int dlt) {
	unsigned tcp_options_length = 12;
	unsigned tcp_doff = (sizeof(tcphdr2) + tcp_options_length) / 4 + ((sizeof(tcphdr2) + tcp_options_length) % 4 ? 1 : 0);
	unsigned iphdr_size = 
		#if VM_IPV6
		saddr.is_v6() ? 
		 sizeof(ip6hdr2) : 
		#endif
		 sizeof(iphdr2);
	u_int32_t packet_length = ether_header_length + iphdr_size + tcp_doff * 4 + datalen;
	*packet = new FILE_LINE(38024) u_char[packet_length];
	memcpy(*packet, source_packet, ether_header_length);
	#if VM_IPV6
	if(saddr.is_v6()) {
		ip6hdr2 iphdr;
		memset(&iphdr, 0, iphdr_size);
		iphdr.version = 6;
		iphdr.nxt = IPPROTO_TCP;
		iphdr.set_saddr(saddr);
		iphdr.set_daddr(daddr);
		iphdr.set_tot_len(iphdr_size + tcp_doff * 4 + datalen);
		memcpy(*packet + ether_header_length, &iphdr, iphdr_size);
	} else {
	#endif
		iphdr2 iphdr;
		memset(&iphdr, 0, iphdr_size);
		iphdr.version = 4;
		iphdr._ihl = 5;
		iphdr._protocol = IPPROTO_TCP;
		iphdr.set_saddr(saddr);
		iphdr.set_daddr(daddr);
		iphdr.set_tot_len(iphdr_size + tcp_doff * 4 + datalen);
		iphdr._ttl = 50;
		memcpy(*packet + ether_header_length, &iphdr, iphdr_size);
	#if VM_IPV6
	}
	#endif
	tcphdr2 tcphdr;
	memset(&tcphdr, 0, sizeof(tcphdr2));
	tcphdr.set_source(source);
	tcphdr.set_dest(dest);
	tcphdr.seq = htonl(seq);
	tcphdr.ack_seq = htonl(ack_seq);
	tcphdr.ack = 1;
	tcphdr.doff = tcp_doff;
	tcphdr.window = htons(0x8000);
	memcpy(*packet + ether_header_length + iphdr_size, &tcphdr, sizeof(tcphdr2));
	memset(*packet + ether_header_length + iphdr_size + sizeof(tcphdr2), 0, tcp_options_length);
	*(u_char*)(*packet + ether_header_length + iphdr_size + sizeof(tcphdr2)) = 1;
	*(u_char*)(*packet + ether_header_length + iphdr_size + sizeof(tcphdr2) + 1) = 1;
	*(u_char*)(*packet + ether_header_length + iphdr_size + sizeof(tcphdr2) + 2) = 8;
	*(u_char*)(*packet + ether_header_length + iphdr_size + sizeof(tcphdr2) + 3) = 10;
	memcpy(*packet + ether_header_length + iphdr_size + sizeof(tcphdr2) + tcp_options_length, data, datalen);
	*header = new FILE_LINE(38025) pcap_pkthdr;
	memset(*header, 0, sizeof(pcap_pkthdr));
	(*header)->ts.tv_sec = time_sec;
	(*header)->ts.tv_usec = time_usec;
	(*header)->caplen = packet_length;
	(*header)->len = packet_length;
	if(ether_header_length > sizeof(ether_header)) {
		sll_header *header_sll;
		ether_header *header_eth;
		u_char *header_ppp_o_e = NULL;
		u_int16_t header_ip_offset = 0;
		u_int16_t protocol = 0;
		u_int16_t vlan = VLAN_UNSET;
		if(parseEtherHeader(dlt, (u_char*)*packet, 
				    header_sll, header_eth, &header_ppp_o_e,
				    header_ip_offset, protocol, vlan) &&
		   header_ppp_o_e) {
			*(u_int16_t*)(header_ppp_o_e + 4) = htons(iphdr_size + tcp_doff * 4 + datalen + 2);
		}
	}
}

void convertAnonymousInPacket(sHeaderPacket *header_packet, pcapProcessData *ppd,
			pcap_pkthdr **header_new, u_char **packet_new,
			void *_net_map, void *_domain_map) {
	cConfigItem_net_map::t_net_map *net_map = (cConfigItem_net_map::t_net_map*)_net_map;
	cConfigItem_domain_map::t_domain_map *domain_map = (cConfigItem_domain_map::t_domain_map*)_domain_map;
	unsigned headers_ip_counter = 0;
	unsigned headers_ip_offset[20];
	unsigned header_ip_offset = header_packet->header_ip_encaps_offset;
	while(headers_ip_counter < sizeof(headers_ip_offset) / sizeof(headers_ip_offset[0]) - 1) {
		headers_ip_offset[headers_ip_counter] = header_ip_offset;
		++headers_ip_counter;
		int next_header_ip_offset = findNextHeaderIp((iphdr2*)(HPP(header_packet) + header_ip_offset), header_ip_offset,
							     HPP(header_packet), HPH(header_packet)->caplen, NULL);
		if(next_header_ip_offset > 0) {
			header_ip_offset += next_header_ip_offset;
		} else {
			break;
		}
	}
	unsigned caplen = HPH(header_packet)->caplen;
	iphdr2 *header_ip = ppd->header_ip;
	header_ip_offset = ppd->header_ip_offset;
	tcphdr2 *header_tcp = ppd->header_tcp;
	udphdr2 *header_udp = ppd->header_udp;
	u_char *payload_tcp_udp = NULL;
	u_char *payload_ip = NULL;
	unsigned payload_ip_length = MIN(header_ip->get_tot_len() - header_ip->get_hdr_size(),
					 caplen - header_ip_offset - header_ip->get_hdr_size());
	bool mod = false;
	if(header_tcp || header_udp) {
		unsigned header_tcp_udp_length = (header_tcp ? get_tcp_header_len(header_tcp) : get_udp_header_len(header_udp));
		unsigned payload_tcp_udp_length = payload_ip_length - header_tcp_udp_length;
		payload_tcp_udp = new FILE_LINE(0) u_char[payload_tcp_udp_length + 1];
		memcpy(payload_tcp_udp, (u_char*)header_ip + header_ip->get_hdr_size() + header_tcp_udp_length, payload_tcp_udp_length);
		payload_tcp_udp[payload_tcp_udp_length] = 0;
		extern int check_sip20(char *data, unsigned long len, ParsePacket::ppContentsX *parseContents, bool isTcp);
		bool do_convert_sip = false;
		if(check_sip20((char*)payload_tcp_udp, payload_tcp_udp_length, NULL, header_tcp != NULL)) {
			if(check_websocket(payload_tcp_udp, payload_tcp_udp_length, header_tcp != NULL ? cWebSocketHeader::_chdst_na : cWebSocketHeader::_chdst_ge_limit)) {
				cWebSocketHeader ws(payload_tcp_udp, payload_tcp_udp_length);
				if(payload_tcp_udp_length > ws.getHeaderLength()) {
					bool allocData;
					u_char *ws_data = ws.decodeData(&allocData, payload_tcp_udp_length);
					if(!ws_data) {
						delete [] payload_tcp_udp;
						payload_tcp_udp = NULL;
					}
					delete [] payload_tcp_udp;
					payload_tcp_udp_length =  header_tcp != NULL ?
								   min((u_int64_t)(header_tcp_udp_length - ws.getHeaderLength()),
								       ws.getDataLength()) :
								   ws.getDataLength();
					payload_tcp_udp = new FILE_LINE(0)u_char[payload_tcp_udp_length + 1];
					memcpy(payload_tcp_udp, ws_data, payload_tcp_udp_length);
					payload_tcp_udp[payload_tcp_udp_length] = 0;
					if(allocData) {
						delete [] ws_data;
					}
				}
			}
			if(payload_tcp_udp) {
				do_convert_sip = true;
			}
		} else if((header_tcp ?
			    ((unsigned)(header_tcp->get_source()) == opt_tcp_port_mgcp_gateway || (unsigned)(header_tcp->get_dest()) == opt_tcp_port_mgcp_gateway ||
			     (unsigned)(header_tcp->get_source()) == opt_tcp_port_mgcp_callagent || (unsigned)(header_tcp->get_dest()) == opt_tcp_port_mgcp_callagent) :
			    ((unsigned)(header_udp->get_source()) == opt_udp_port_mgcp_gateway || (unsigned)(header_udp->get_dest()) == opt_udp_port_mgcp_gateway ||
			     (unsigned)(header_udp->get_source()) == opt_udp_port_mgcp_callagent || (unsigned)(header_udp->get_dest()) == opt_udp_port_mgcp_callagent)) &&
			  check_mgcp((char*)payload_tcp_udp, payload_tcp_udp_length) &&
			  (strstr((char*)payload_tcp_udp, "\r\n\r\n") ||
			   strstr((char*)payload_tcp_udp, "\n\n"))) {
			do_convert_sip = true;
		}
		if(do_convert_sip) {
			u_char *payload_tcp_udp_mod;
			unsigned payload_tcp_udp_mod_length;
			if(convertAnonymous_sip(payload_tcp_udp, &payload_tcp_udp_mod, &payload_tcp_udp_mod_length, net_map, domain_map)) {
				delete payload_tcp_udp;
				payload_tcp_udp = payload_tcp_udp_mod;
				payload_tcp_udp_length = payload_tcp_udp_mod_length;
				mod = true;
			}
			payload_ip_length = header_tcp_udp_length + payload_tcp_udp_length;
			payload_ip = new FILE_LINE(0) u_char[payload_ip_length];
			memcpy(payload_ip, header_tcp ? (void*)header_tcp : (void*)header_udp, header_tcp_udp_length);
			memcpy(payload_ip + header_tcp_udp_length, payload_tcp_udp, payload_tcp_udp_length);
			if(header_udp) {
				((udphdr2*)payload_ip)->len = htons(payload_ip_length);
			}
		}
		delete [] payload_tcp_udp;
	} 
	if(!payload_ip) {
		payload_ip = new FILE_LINE(0) u_char[payload_ip_length];
		memcpy(payload_ip, (u_char*)header_ip + header_ip->get_hdr_size(), payload_ip_length);
	}
	iphdr2 *header_ip_dst = NULL;
	int header_ip_dst_mod = false;
	iphdr2 *header_ip_src = NULL;
	for(int header_ip_i = headers_ip_counter - 1; header_ip_i >= 0; header_ip_i--) {
		if(header_ip_dst) {
			iphdr2 *header_ip_src_next = (iphdr2*)(HPP(header_packet) + headers_ip_offset[header_ip_i]);
			unsigned between_ip_payload_length = (u_char*)header_ip_src - (u_char*)header_ip_src_next - header_ip_src_next->get_hdr_size();
			unsigned payload_ip_next_length = payload_ip_length + header_ip_dst->get_hdr_size() + between_ip_payload_length;
			u_char *payload_ip_next = new u_char[payload_ip_next_length];
			unsigned payload_ip_next_pos = 0;
			if(between_ip_payload_length > 0) {
				memcpy(payload_ip_next, (u_char*)header_ip_src_next + header_ip_src_next->get_hdr_size(), between_ip_payload_length);
				payload_ip_next_pos += between_ip_payload_length;
				if(header_ip_dst_mod == 2 && payload_ip_next_pos >= 2) {
					if(*(u_int16_t*)(payload_ip_next + payload_ip_next_pos - 2) == htons((header_ip_dst->version == 4 ? ETHERTYPE_IPV6 : ETHERTYPE_IP))) {
						*(u_int16_t*)(payload_ip_next + payload_ip_next_pos - 2) = htons(header_ip_dst->version == 4 ? ETHERTYPE_IP : ETHERTYPE_IPV6);
					}
				}
			}
			memcpy(payload_ip_next + payload_ip_next_pos, header_ip_dst, header_ip_dst->get_hdr_size());
			payload_ip_next_pos += header_ip_dst->get_hdr_size();
			memcpy(payload_ip_next + payload_ip_next_pos, payload_ip, payload_ip_length);
			delete [] payload_ip;
			payload_ip = payload_ip_next;
			payload_ip_length = payload_ip_next_length;
			delete header_ip_dst;
			if(header_ip_src_next->get_protocol() == IPPROTO_UDP) {
				((udphdr2*)payload_ip)->len = htons(payload_ip_length);
			}
		}
		header_ip_src = (iphdr2*)(HPP(header_packet) + headers_ip_offset[header_ip_i]);
		if((header_ip_dst_mod = convertIPs_header_ip(header_ip_src, &header_ip_dst, net_map, true))) {
			mod = true;
		}
		header_ip_dst->set_tot_len(payload_ip_length + header_ip_dst->get_hdr_size());
	}
	if(mod && payload_ip) {
		unsigned packet_new_length = header_packet->header_ip_encaps_offset + header_ip_dst->get_hdr_size() + payload_ip_length;
		*packet_new = new FILE_LINE(0) u_char[packet_new_length];
		unsigned packet_new_pos = 0;
		memcpy(*packet_new, HPP(header_packet), header_packet->header_ip_encaps_offset);
		packet_new_pos += header_packet->header_ip_encaps_offset;
		if(header_ip_dst_mod == 2 && packet_new_pos >= 2) {
			if(*(u_int16_t*)((*packet_new) + packet_new_pos - 2) == htons((header_ip_dst->version == 4 ? ETHERTYPE_IPV6 : ETHERTYPE_IP))) {
				*(u_int16_t*)((*packet_new) + packet_new_pos - 2) = htons(header_ip_dst->version == 4 ? ETHERTYPE_IP : ETHERTYPE_IPV6);
			}
		}
		memcpy(*packet_new + packet_new_pos, header_ip_dst, header_ip_dst->get_hdr_size());
		packet_new_pos += header_ip_dst->get_hdr_size();
		memcpy(*packet_new + packet_new_pos, payload_ip, payload_ip_length);
		*header_new = new FILE_LINE(0) pcap_pkthdr;
		memcpy(*header_new, HPH(header_packet), sizeof(pcap_pkthdr));
		(*header_new)->caplen = packet_new_length;
		(*header_new)->len = packet_new_length;
	} else {
		*header_new = NULL;
		*packet_new = NULL;
	}
	if(payload_ip) {
		delete [] payload_ip;
	}
	if(header_ip_dst) {
		delete header_ip_dst;
	}
}

bool convertAnonymous_sip(u_char *sip_src, u_char **sip_dst, unsigned *sip_dst_length, void *_net_map, void *_domain_map) {
	cConfigItem_net_map::t_net_map *net_map = (cConfigItem_net_map::t_net_map*)_net_map;
	cConfigItem_domain_map::t_domain_map *domain_map = (cConfigItem_domain_map::t_domain_map*)_domain_map;
	bool mod = false;
	vector<string> payload_lines = split((char*)sip_src, '\n');
	int i_line_content_length = -1;
	int i_line_content = -1;
	for(unsigned i_line = 0; i_line < payload_lines.size(); i_line++) {
		if(i_line_content == -1 &&
		   i_line < payload_lines.size() - 1 &&
		   (payload_lines[i_line] == "" || payload_lines[i_line] == "\r")) {
			i_line_content = i_line + 1;
		}
		if(i_line_content == -1 && i_line_content_length == -1 &&
		   (!strncasecmp(payload_lines[i_line].c_str(), "Content-Length:", 15) ||
		    !strncasecmp(payload_lines[i_line].c_str(), "l:", 2))) {
			i_line_content_length = i_line;
		}
		string payload_line_mod;
		if(convertIPs_string(payload_lines[i_line], &payload_line_mod, net_map)) {
			payload_lines[i_line] = payload_line_mod;
			mod = true;
		}
		if(convertDomains_string(payload_lines[i_line], payload_line_mod, domain_map)) {
			payload_lines[i_line] = payload_line_mod;
			mod = true;
		}
	}
	if(mod) {
		if(i_line_content_length != -1 && i_line_content != -1) {
			string content;
			for(unsigned i_line = i_line_content; i_line < payload_lines.size(); i_line++) {
				content += payload_lines[i_line];
				content += '\n';
			}
			string header;
			for(unsigned i_line = 0; (int)i_line < i_line_content; i_line++) {
				if((int)i_line == i_line_content_length) { 
					if(tolower(payload_lines[i_line][0]) == 'l' && payload_lines[i_line][1] == ':') {
						header += "l:" + intToString(content.length());
					} else {
						header += "Content-Length:" + intToString(content.length());
					}
					if(payload_lines[i_line][payload_lines[i_line].length() - 1] == '\r') {
						header += '\r';
					}
				} else {
					header += payload_lines[i_line];
				}
				header += '\n';
			}
			*sip_dst_length = header.length() + content.length();
			*sip_dst = new FILE_LINE(0) u_char[*sip_dst_length + 1];
			memcpy((*sip_dst), header.c_str(), header.length());
			memcpy((*sip_dst) + header.length(), content.c_str(), content.length());
			(*sip_dst)[*sip_dst_length] = 0;
		} else {
			string content;
			for(unsigned i_line = 0; i_line < payload_lines.size(); i_line++) {
				content += payload_lines[i_line];
				content += '\n';
			}
			*sip_dst_length = content.length();
			*sip_dst = new FILE_LINE(0) u_char[*sip_dst_length + 1];
			memcpy(*sip_dst, content.c_str(), content.length());
			(*sip_dst)[*sip_dst_length] = 0;
		}
	}
	return(mod);
}

bool convertIPs_string(string &src, string *dst, void *_net_map) {
	cConfigItem_net_map::t_net_map *net_map = (cConfigItem_net_map::t_net_map*)_net_map;
	bool mod = false;
	const char *src_p = src.c_str();
	unsigned src_length = src.length();
	unsigned src_i = 0;
	while(src_i < src_length && *src_p) {
		if(string_is_look_like_ip(src_p)) {
			vmIP ip;
			const char *ip_end;
			if(ip.setFromString(src_p, &ip_end)) {
				unsigned ip_length = ip_end - src_p;
				vmIP ip_mod = cConfigItem_net_map::convIP(ip, net_map);
				if(ip_mod != ip) {
					if(!mod) {
						*dst = src.substr(0, src_i);
						mod = true;
					}
					*dst += ip_mod.getString(*src_p == '[');
				} else if(mod) {
					*dst += src.substr(src_i, ip_length);
				}
				src_i += ip_length;
				src_p += ip_length;
				continue;
			}
		}
		if(mod) {
			*dst += *src_p;
		}
		++src_i;
		++src_p;
	}
	return(mod);
}

bool convertDomains_string(string &src, string &dst, void *_domain_map) {
	cConfigItem_domain_map::t_domain_map *domain_map = (cConfigItem_domain_map::t_domain_map*)_domain_map;
	bool mod = false;
	dst = src;
	for(cConfigItem_domain_map::t_domain_map::iterator iter = domain_map->begin(); iter != domain_map->end(); iter++) {
		string key = string(iter->first.c_str());
		string val = string(iter->second.c_str());
		while (true) {
			size_t pos = dst.find(key);
			if (pos == std::string::npos) {
				break;
			}
			dst.replace(pos, key.size(), val);
			mod = true;
		}
	}
	return(mod);
}

int convertIPs_header_ip(iphdr2 *src, iphdr2 **dst, void *_net_map, bool force_create) {
	cConfigItem_net_map::t_net_map *net_map = (cConfigItem_net_map::t_net_map*)_net_map;
	int mod = false;
	unsigned src_version = src->version;
	vmIP ip_src_src = src->get_saddr();
	vmIP ip_src_dst = src->get_daddr();
	vmIP ip_dst_src = cConfigItem_net_map::convIP(ip_src_src, net_map);
	vmIP ip_dst_dst = cConfigItem_net_map::convIP(ip_src_dst, net_map);
	unsigned dst_version = ip_dst_src.is_v6() || ip_dst_dst.is_v6() ? 6 : 4;
	if(ip_dst_src == ip_src_src && ip_dst_dst == ip_src_dst) {
		if(force_create) {
			*dst = iphdr2::create(dst_version);
			memcpy(*dst, src, src->get_hdr_size());
		}
	} else {
		mod = true;
		*dst = iphdr2::create(dst_version);
		if(dst_version == src_version) {
			mod = true;
			memcpy(*dst, src, src->get_hdr_size());
		} else {
			mod = 2;
			(*dst)->set_protocol(src->get_protocol());
		}
		(*dst)->set_saddr(ip_dst_src);
		(*dst)->set_daddr(ip_dst_dst);
	}
	return(mod);
}

int hexdecode(unsigned char *dst, const char *src, int max)
{
	unsigned src_length = strlen(src);
	char buff[3];
	buff[2] = 0;
	int cnt = 0;
	for(unsigned i = 0; i < src_length; i+=2) {
		buff[0] = src[i];
		buff[1] = src[i + 1];
		dst[cnt++] = strtol(buff, NULL, 16);
		if(cnt >= max) {
			break;
		}
	}
	return cnt;
}

string hexencode(unsigned char *src, int src_length)
{
	string rslt;
	for(int i = 0; i < src_length; i++) {
		for(unsigned j = 0; j < 2; j++) {
			unsigned char x = j == 0 ? src[i] >> 4 : src[i]  & 15;
			rslt += x < 10 ? '0' + x : 'A' + x - 10;
		}
	}
	return(rslt);
}

char *strlwr(char *string, u_int32_t maxLength) {
	char *string_pos = string;
	u_int32_t length = 0;
	while((!maxLength || length < maxLength) && *string_pos) {
		if(isupper(*string_pos)) {
			*string_pos = tolower(*string_pos);
		}
		string_pos++;
		++length;
	}
	return(string);
}

string strlwr(string str) {
	string rslt = str;
	for(size_t i = 0; i < rslt.length(); i++) {
		if(isupper(rslt[i])) {
			rslt[i] = tolower(rslt[i]);
		}
	}
	return(rslt);
}

bool isJsonObject(string str) {
	return(!str.empty() && str[0] == '{' && str[str.length() - 1] == '}');
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

pcap_t* pcap_open_offline_zip(const char *filename, char *errbuff, string *tempFileName) {
	if(isGunzip(filename)) {
		string error;
		string unzip = gunzipToTemp(filename, &error, !tempFileName, tempFileName);
		if(!unzip.empty()) {
			return(pcap_open_offline(unzip.c_str(), errbuff));
		} else {
			strncpy(errbuff, error.c_str(), PCAP_ERRBUF_SIZE);
			return(NULL);
		}
	} else {
		return(pcap_open_offline(filename, errbuff));
	}
}

string gunzipToTemp(const char *zipFilename, string *error, bool autoDeleteAtExit, string *tempFileName) {
	string unzipTempFileName = tmpnam();
	if(!unzipTempFileName.empty()) {
		if(autoDeleteAtExit) {
			GlobalAutoDeleteAtExit.add(unzipTempFileName.c_str());
		}
		if(tempFileName) {
			*tempFileName = unzipTempFileName;
		}
		string _error = _gunzip_s(zipFilename, unzipTempFileName.c_str());
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
			if(buf[0]) {
				error = buf;
			} else {
				error = string("open output file ") + unzipFilename + " failed";
			}
		}
	} else {
		char buf[4092];
		strerror_r(errno, buf, 4092);
		if(buf[0]) {
			error = buf;
		} else {
			error = string("open inut file ") + zipFilename + " failed";
		}
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

string json_encode(const char *str) {
	string _str = str;
	return(json_encode(_str));
}

string json_encode(const string &value) {
	ostringstream escaped;
	for (string::const_iterator i = value.begin(), n = value.end(); i != n; ++i) {
		switch (*i) {
			case '\\':	escaped << "\\\\"; break;
			case '"':	escaped << "\\\""; break;
			case '/':	escaped << "\\/"; break;
			case '\b':	escaped << "\\b"; break;
			case '\f':	escaped << "\\f"; break;
			case '\n':	escaped << "\\n"; break;
			case '\r':	escaped << "\\r"; break;
			case '\t':	escaped << "\\t"; break;
			default:	escaped << *i; break;
		}
	}
	return escaped.str();
}

char * gettag_json(const char *data, const char *tag, unsigned *contentlen, char *dest, unsigned destlen) {
	string _tag = "\"" + string(tag) + "\":";
	const char *ptrToBegin = data;
	while((ptrToBegin = strcasestr(ptrToBegin, _tag.c_str()))) {
		ptrToBegin += _tag.length();
		while(*ptrToBegin == ' ') {
			++ptrToBegin;
		}
		const char *ptrToEnd = NULL;
		if(*ptrToBegin == '"') {
			++ptrToBegin;
			ptrToEnd = ptrToBegin;
			while(*ptrToEnd && *ptrToEnd != '"' && *(ptrToEnd - 1) != '\\') {
				++ptrToEnd;
			}
		} else if(*ptrToBegin == '{') {
			ptrToEnd = ptrToBegin + 1;
			int countBrackets = 1;
			bool quotation = false;
			while(*ptrToEnd) {
				if(*ptrToEnd == '"' && *(ptrToEnd - 1) != '\\') {
					quotation = !quotation;
				} else if(!quotation) {
					if(*ptrToEnd == '{') {
						++countBrackets;
					} else if(*ptrToEnd == '}' && countBrackets > 0) {
						--countBrackets;
					}
				}
				++ptrToEnd;
				if(!countBrackets) {
					break;
				}
			}
		}
		if(ptrToEnd && ptrToEnd > ptrToBegin) {
			*contentlen = ptrToEnd - ptrToBegin;
			if(dest) {
				strncpy(dest, ptrToBegin, min(*contentlen, destlen - 1));
				dest[min(*contentlen, destlen - 1)] = 0;
			}
			return((char*)ptrToBegin);
		}
	}
	*contentlen = 0;
	if(dest) {
		*dest = 0;
	}
	return(NULL);
}

char * gettag_json(const char *data, const char *tag, string *dest) {
	unsigned contentlen;
	char *content = gettag_json(data, tag, &contentlen, NULL, 0);
	if(content && dest) {
		*dest = string(content, contentlen);
	}
	return(content);
}

char * gettag_json(const char *data, const char *tag, unsigned *dest, unsigned dest_not_exists) {
	unsigned contentlen;
	char *content = gettag_json(data, tag, &contentlen, NULL, 0);
	if(content) {
		if(dest) {
			*dest = atoi(string(content, contentlen).c_str());
		}
	} else if(dest && dest_not_exists) {
		*dest = dest_not_exists;
	}
	return(content);
}

int getbranch_xml(const char *branch, const char *str, list<string> *rslt) {
	const char *pos = str;
	while(pos) {
		const char *_pos_next_1 = strcasestr(pos, (string("<") + branch + " ").c_str());
		const char *_pos_next_2 = strcasestr(pos, (string("<") + branch + ">").c_str());
		pos = _pos_next_1 && _pos_next_2 ? min(_pos_next_1, _pos_next_2) : max(_pos_next_1, _pos_next_2);
		if(pos) {
			const char *pos_end = strcasestr(pos, (string("</") + branch + ">").c_str());
			if(pos_end) {
				rslt->push_back(string(pos, pos_end - pos + strlen(branch) + 3));
				pos = pos_end + 1;
			} else {
				break;
			}
		}
	}
	return(rslt->size());
}

string gettag_xml(const char *tag, const char *str) {
	const char *begin = strcasestr(str, (string(tag) + "=\"").c_str());
	if(begin) {
		begin += strlen(tag) + 2;
		const char *end = strcasestr(begin, "\"");
		if(end) {
			return(string(begin, end - begin));
		}
	}
	return("");
}

string getvalue_xml(const char *branch, const char *str) {
	list<string> rslt;
	if(getbranch_xml(branch, str, &rslt)) {
		string branch = *rslt.begin();
		size_t begin = branch.find('>');
		if(begin != string::npos) {
			size_t end = branch.find('<', begin);
			if(end != string::npos) {
				return(branch.substr(begin + 1, end - begin - 1));
			}
		}
	}
	return("");
}

SocketSimpleBufferWrite::SocketSimpleBufferWrite(const char *name, ip_port ipPort, bool udp, uint64_t maxSize) {
	this->name = name;
	this->ipPort = ipPort;
	this->udp = udp;
	this->maxSize = maxSize;
	socketHostIP.clear();
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
	USLEEP(1000);
	((SocketSimpleBufferWrite*)arg)->write();
	return(NULL);
}
void SocketSimpleBufferWrite::startWriteThread() {
	vm_pthread_create("socket write",
			  &writeThreadHandle, NULL, _SocketSimpleBufferWrite_writeFunction, this, __FILE__, __LINE__);
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
		u_int64_t actTime = getTimeMS();
		if(!lastTimeSyslogFullData || actTime > lastTimeSyslogFullData + 1000) {
			syslog(LOG_NOTICE, "socketwrite %s: data buffer is full", name.c_str());
			lastTimeSyslogFullData = actTime;
		}
	}
	SimpleBuffer *simpleBuffer = new FILE_LINE(38026) SimpleBuffer(dataLength2);
	simpleBuffer->add(data1, dataLength1);
	simpleBuffer->add(data2, dataLength2);
	lock_data();
	this->data.push(simpleBuffer);
	add_size(dataLength1 + dataLength2);
	unlock_data();
}

void SocketSimpleBufferWrite::write() {
	socketConnect();
	while(!is_terminating() && writeThreadHandle) {
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
			USLEEP(1000);
		}
	}
}

bool SocketSimpleBufferWrite::socketGetHost() {
	socketHostIP.clear();
	while(!socketHostIP.isSet()) {
		socketHostIP = cResolver::resolve_n(ipPort.get_ip().c_str());
		if(!socketHostIP.isSet()) {
			syslog(LOG_ERR, "socketwrite %s: cannot resolv: %s: host [%s] - trying again", name.c_str(), hstrerror(h_errno), ipPort.get_ip().c_str());  
			sleep(1);
		}
	}
	return(true);
}

bool SocketSimpleBufferWrite::socketConnect() {
	if(!socketHostIP.isSet()) {
		socketGetHost();
	}
	if((socketHandle = socket_create(socketHostIP, udp ? SOCK_DGRAM : SOCK_STREAM, udp ? IPPROTO_UDP : IPPROTO_TCP)) == -1) {
		syslog(LOG_NOTICE, "socketwrite %s: cannot create socket", name.c_str());
		return(false);
	}
	while(socket_connect(socketHandle, socketHostIP, ipPort.get_port()) == -1 && !is_terminating()) {
		syslog(LOG_NOTICE, "socketwrite %s: failed to connect to server [%s] error:[%s] - trying again", name.c_str(), socketHostIP.getString().c_str(), strerror(errno));
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
	while(dataLengthWrited < dataLength && !is_terminating()) {
		ssize_t _dataLengthWrited = send(socketHandle, (u_char*)data + dataLengthWrited, dataLength - dataLengthWrited, 0);
		if(_dataLengthWrited == -1) {
			socketClose();
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
	this->_sync = 0;
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
	this->lock();
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
		dumper = new FILE_LINE(38027) PcapDumper(PcapDumper::na, NULL);
		dumper->setEnableAsyncWrite(false);
		dumper->setTypeCompress(FileZipHandler::compress_na);
		string dumpFileName = path + "/bogus_" + 
				      find_and_replace(find_and_replace(interfaceName, " ", "").c_str(), "/", "|") + 
				      "_" + time + ".pcap";
		if(dumper->open(tsf_na, dumpFileName.c_str(), dlt)) {
			dumpers[interfaceName] = dumper;
		} else {
			delete dumper;
			dumper = NULL;
		}
	}
	if(dumper) {
		dumper->dump(header, packet, dlt, true);
		dumper->flush();
	}
	this->unlock();
}


volatile int _tz_sync;
map<unsigned int, sLocalTimeHourCache*> timeCacheMap;
volatile int timeCacheMap_sync;

void termTimeCacheForThread() {
	unsigned int tid = get_unix_tid();
	while(__sync_lock_test_and_set(&timeCacheMap_sync, 1));
	map<unsigned int, sLocalTimeHourCache*>::iterator iter = timeCacheMap.find(tid);
	if(iter != timeCacheMap.end()) {
		delete iter->second;
		timeCacheMap.erase(iter);
	}
	__sync_lock_release(&timeCacheMap_sync);
}

string getGuiTimezone(SqlDb *sqlDb) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	string gui_timezone;
	if(sqlDb->existsTable("system") && sqlDb->existsColumn("system", "content")) {
		sqlDb->select("system", "content", "type", "gui_timezone");
		SqlDb_row row = sqlDb->fetchRow();
		if(row) {
			gui_timezone = row["content"];
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	return(gui_timezone);
}

u_int32_t octal_decimal(u_int32_t n) {
	u_int32_t decimal = 0, 
		  i = 0, 
		  rem;
	while(n != 0) {
		rem = n % 10;
		n /= 10;
		decimal += rem * pow(8, i);
		++i;
	}
	return decimal;
}

bool vm_pexec(const char *cmdLine, SimpleBuffer *out, SimpleBuffer *err,
	      int *exitCode, unsigned timeout_sec, unsigned timout_select_sec) {
	if(exitCode) {
		*exitCode = -1;
	}
	std::vector<std::string> parseCmdLine = parse_cmd_line(cmdLine);
	char *exec_args[100];
	unsigned i = 0;
	for(i = 0; i < min(sizeof(exec_args) / sizeof(exec_args[0]) - 2, parseCmdLine.size()); i++) {
		parseCmdLine[i] = trim(parseCmdLine[i], " '\"");
		exec_args[i] = (char*)parseCmdLine[i].c_str();
	}
	exec_args[i] = NULL;
	int pipe_stdout[2];
	int pipe_stderr[2];
	pipe(pipe_stdout);
	pipe(pipe_stderr);
	int fork_rslt = vfork();
	if(fork_rslt == 0) {
		close(pipe_stdout[0]);
		close(pipe_stderr[0]);
		dup2(pipe_stdout[1], 1);
		dup2(pipe_stderr[1], 2);
		close(pipe_stdout[1]);
		close(pipe_stderr[1]);
		if(execvp(exec_args[0], exec_args) == -1) {
			char errmessage[1000];
			snprintf(errmessage, sizeof(errmessage), "exec failed: %s", exec_args[0]);
			write(2, errmessage, strlen(errmessage));
			kill(getpid(), SIGKILL);
		}
	} else if(fork_rslt > 0) {
		u_int64_t start_time = getTimeMS();
		SimpleBuffer bufferStdout;
		SimpleBuffer bufferStderr;
		close(pipe_stdout[1]);
		close(pipe_stderr[1]);
		while(true) {
			#if 0 //suppress select & FD_SET
				fd_set readfds;
				FD_ZERO(&readfds);
				FD_SET(pipe_stdout[0], &readfds);
				FD_SET(pipe_stderr[0], &readfds);
				timeval *timeout = NULL;
				timeval _timeout;
				if(timout_select_sec) {
					_timeout.tv_sec = timout_select_sec;
					_timeout.tv_usec = 0;
					timeout = &_timeout;
				}
				if(select(max(pipe_stdout[0], pipe_stderr[0]) + 1, &readfds, NULL, NULL, timeout) == -1) {
					break;
				}
				char buffer[1024];
				unsigned readStdoutLength = 0;
				unsigned readStderrLength = 0;
				if(FD_ISSET(pipe_stdout[0], &readfds)) {
					if((readStdoutLength = read(pipe_stdout[0], buffer, sizeof(buffer))) > 0) {
						bufferStdout.add(buffer, readStdoutLength);
					}
				}
				if(FD_ISSET(pipe_stderr[0], &readfds)) {
					if((readStderrLength = read(pipe_stderr[0], buffer, sizeof(buffer))) > 0) {
						bufferStderr.add(buffer, readStderrLength);
					}
				}
			#else
				pollfd fds[3];
				memset(fds, 0 , sizeof(fds));
				fds[0].fd = pipe_stdout[0];
				fds[0].events = POLLIN;
				fds[1].fd = pipe_stderr[0];
				fds[1].events = POLLIN;
				int rsltPool = poll(fds, 2, timout_select_sec * 1000);
				if(rsltPool < 0) {
					break;
				}
				char buffer[1024];
				unsigned readStdoutLength = 0;
				unsigned readStderrLength = 0;
				if(rsltPool > 0) {
					if(fds[0].revents) {
						if((readStdoutLength = read(pipe_stdout[0], buffer, sizeof(buffer))) > 0) {
							bufferStdout.add(buffer, readStdoutLength);
						}
					}
					if(fds[1].revents) {
						if((readStderrLength = read(pipe_stderr[0], buffer, sizeof(buffer))) > 0) {
							bufferStderr.add(buffer, readStderrLength);
						}
					}
				}
			#endif
			if(readStderrLength) {
				if(bufferStderr.size() && reg_match((char*)bufferStderr, "^exec failed", __FILE__, __LINE__)) {
					break;
				}
			} else if(!readStdoutLength) {
				bool isChildPidExit(unsigned pid);
				int getChildPidExitCode(unsigned pid);
				if(isChildPidExit(fork_rslt)) {
					if(exitCode) {
						*exitCode = getChildPidExitCode(fork_rslt);
					}
					break;
				} else {
					USLEEP(10000);
				}
			}
			if(timeout_sec && (getTimeMS() - start_time) > timeout_sec * 1000) {
				kill(fork_rslt, 9);
				break;
			}
		}
		close(pipe_stdout[0]);
		close(pipe_stderr[0]);
		if(out) {
			if(reg_match((char*)bufferStdout, "PID([0-9]+)\n", __FILE__, __LINE__)) {
				char *pointerToPidSeparator = strchr((char*)bufferStdout, '\n');
				out->clear();
				out->add(pointerToPidSeparator + 1, bufferStdout.size() - ((u_char*)pointerToPidSeparator - bufferStdout.data() + 1));
			} else {
				*out = bufferStdout;
			}
		}
		if(err) {
			*err = bufferStderr;
		}
		return(!(bufferStderr.size() && reg_match((char*)bufferStderr, "^exec failed", __FILE__, __LINE__)));
	} else {
		return(false);
	}
	return(true);
}

std::vector<std::string> parse_cmd_line(const char *cmdLine) {
	const char *cmdLinePointer = cmdLine;
	string param;
	char paramBracket = 0;
	std::vector<std::string> parse;
	while(*cmdLinePointer) {
		if(paramBracket && *cmdLinePointer == paramBracket) {
			paramBracket = 0;
			++cmdLinePointer;
		} else if(*cmdLinePointer == ' ' && !paramBracket) {
			if(param.length()) {
				parse.push_back(param);
			}
			param = "";
			paramBracket = 0;
			++cmdLinePointer;
			while(*cmdLinePointer == ' ') {
				++cmdLinePointer;
			}
		} else {
			if(!paramBracket && (*cmdLinePointer == '\'' || *cmdLinePointer == '"')) {
				paramBracket = *cmdLinePointer;
			} else {
				char appString[2];
				appString[0] = *cmdLinePointer;
				appString[1] = 0;
				param.append(appString);
			}
			++cmdLinePointer;
		}
	}
	if(param.length()) {
		parse.push_back(param);
	}
	for(unsigned i = 0; i < parse.size(); i++) {
		if(parse[i][0] == '"' && parse[i][parse[i].length() - 1] == '"') {
			parse[i] = parse[i].substr(1, parse[i].length() - 2);
		}
	}
	return(parse);
}

u_int64_t getTotalMemory() {
	#ifndef FREEBSD
	struct sysinfo sysInfo;
	sysinfo(&sysInfo);
	return((u_int64_t)sysInfo.totalram * (sysInfo.mem_unit ? sysInfo.mem_unit : 1));
	#else
	int mib[2];
	mib[0] = CTL_HW;
	mib[1] = HW_REALMEM;
	unsigned long rslt;
	size_t rslt_len = sizeof(rslt);
	sysctl(mib, 2, &rslt, &rslt_len, NULL, 0);
	return(rslt);
	#endif
}

string ascii_str(string str) {
	size_t last = 0;
	while(last < str.length() && str[last] >= ' ' && str[last] <= 127) {
		++last;
	}
	return(str.substr(0, last));
}

int yesno(const char *arg) {
	if(arg[0] == 'y' or arg[0] == 'Y' or arg[0] == '1') 
		return 1;
	else
		return 0;
}

SensorsMap::SensorsMap() {
	_sync = 0;
}

void SensorsMap::fillSensors(SqlDb *sqlDb) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		sqlDb->setSilentConnect();
		if(!sqlDb->connect()) {
			delete sqlDb;
			return;
		}
		_createSqlObject = true;
	}
	if(sqlDb->existsTable("sensors") && sqlDb->existsColumn("sensors", "id")) {
		sqlDb->query("select id_sensor, id, name from sensors");
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		lock();
		sensors.clear();
		while((row = rows.fetchRow())) {
			int idSensor = atoi(row["id_sensor"].c_str());
			sSensorData data;
			data.table_id = atoi(row["id"].c_str());
			data.name = row["name"];
			data.name_file = row["name"];
			prepare_string_to_filename((char*)data.name_file.c_str(), data.name_file.length());
			sensors[idSensor] = data;
		}
		unlock();
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
}

void SensorsMap::setSensorName(int sensorId, const char *sensorName) {
	lock();
	sSensorData data;
	data.table_id = 0;
	data.name = sensorName;
	data.name_file = sensorName;
	prepare_string_to_filename((char*)data.name_file.c_str(), data.name_file.length());
	sensors[sensorId] = data;
	unlock();
}

int SensorsMap::getSensorTableId(int sensorId) {
	if(sensorId <= 0) {
		return(sensorId);
	}
	int sensorTableId = 0;
	lock();
	if(sensors.find(sensorId) != sensors.end()) {
		sensorTableId = sensors[sensorId].table_id;
	}
	unlock();
	return(sensorTableId);
}

string SensorsMap::getSensorName(int sensorId, bool file) {
	extern int opt_id_sensor;
	extern char opt_name_sensor[256];
	if(sensorId == opt_id_sensor && opt_name_sensor[0]) {
		return(opt_name_sensor);
	}
	if(sensorId <= 0) {
		return(opt_name_sensor[0] ? opt_name_sensor : "local");
	}
	string sensorName;
	lock();
	if(sensors.find(sensorId) != sensors.end()) {
		sensorName = file ? sensors[sensorId].name_file : sensors[sensorId].name;
	} else {
		char sensorName_str[10];
		snprintf(sensorName_str, sizeof(sensorName_str), "%i", sensorId);
		sensorName = sensorName_str;
	}
	unlock();
	return(sensorName);
}

void prepare_string_to_filename(char *str, unsigned int str_length) {
	extern char opt_convert_char[256];
	if(!str_length) {
		str_length = strlen(str);
	}
	for(unsigned int i = 0; i < str_length; i++) {
		if(strchr(opt_convert_char, str[i]) || 
		   !(str[i] == ':' || str[i] == '-' || str[i] == '.' || str[i] == '@' || 
		     isalnum(str[i]))) {
			str[i] = '_';
		}
	}
}

void prepare_string_to_filename(string *str) {
	if(str->empty()) {
		return;
	}
	char *str_temp = new FILE_LINE(38029) char[str->length() + 1];
	strcpy(str_temp, str->c_str());
	prepare_string_to_filename(str_temp);
	*str = str_temp;
	delete [] str_temp;
}

unsigned char *conv7bit::encode(unsigned char *data, unsigned int length, unsigned int &rsltLength) {
	if(!length) {
		rsltLength = 0;
		return(NULL);
	}
	rsltLength = conv7bit::encode_length(length);
	unsigned char *rsltData = new FILE_LINE(38030) unsigned char[rsltLength + 1];
	memset(rsltData, 0, rsltLength + 1);
	for(unsigned int i = 0; i < length; i++) {
		int mainByteIndex = (i + 1) * 7 / 8;
		int mainByteBits = (i + 1) * 7 % 8;
		int prevByteIndex = mainByteIndex > 0 ? mainByteIndex - 1 : 0;
		int prevByteBits = 7 - mainByteBits;
		if(mainByteBits) {
			rsltData[mainByteIndex] |= (data[i] >> (7 - mainByteBits)) & 0xFF;
		}
		if(prevByteBits) {
			rsltData[prevByteIndex] |= (data[i] << (8 - prevByteBits)) & 0xFF;
		}
	}
	return(rsltData);
}

unsigned char *conv7bit::decode(unsigned char *data, unsigned int length, unsigned int &rsltLength) {
	if(!length) {
		rsltLength = 0;
		return(NULL);
	}
	rsltLength = conv7bit::decode_length(length);
	unsigned char *rsltData = new FILE_LINE(38031) unsigned char[rsltLength + 1];
	memset(rsltData, 0, rsltLength + 1);
	for(unsigned int i = 0; i < rsltLength; i++) {
		int mainByteIndex = (i + 1) * 7 / 8;
		int mainByteBits = (i + 1) * 7 % 8;
		int prevByteIndex = mainByteIndex > 0 ? mainByteIndex - 1 : 0;
		int prevByteBits = 7 - mainByteBits;
		unsigned char ch = 0;
		if(mainByteBits) {
			ch |= (data[mainByteIndex] & (0xFF >> (8 - mainByteBits))) & 0xFF;
		}
		if(prevByteBits) {
			ch <<= prevByteBits;
			ch |= (data[prevByteIndex] >> (8 - prevByteBits)) & 0xFF;
		}
		rsltData[i] = ch;
	}
	return(rsltData);
}

unsigned int conv7bit::encode_length(unsigned int length) {
	return(length * 7 / 8 + (length * 7 % 8 ? 1 : 0));
}

unsigned int conv7bit::decode_length(unsigned int length) {
	return(length * 8 / 7);
}


void cPng::pixel::setFromHsv(pixel_hsv p_hsv) {
	pixel pix;
	double h, s, v, f, p, q, t;
	u_int16_t hi;
	h = p_hsv.hue;
	s = (double)p_hsv.saturation / 100;
	v = (double)p_hsv.value / 100;
	hi = (int)(h/60) % 6;
	f = (h / 60) - hi;
	p = v * (1 - s);
	q = v * (1 - f * s);
	t = v * (1 - (1 - f) * s);
	switch(hi) {
		case 0: *this = pixel(v * 255, t * 255, p * 255); break;
		case 1: *this = pixel(q * 255, v * 255, p * 255); break;
		case 2: *this = pixel(p * 255, v * 255, t * 255); break;
		case 3: *this = pixel(p * 255, q * 255, v * 255); break;
		case 4: *this = pixel(t * 255 ,p * 255, v * 255); break;
		case 5: *this = pixel(v * 255, p * 255, q * 255); break;
	}
}

cPng::cPng(size_t width, size_t height) {
	this->width = width;
	this->height = height;
	pixels = new FILE_LINE(38032) pixel[width * height];
	pixel_size = 3;
	depth = 8;
}

cPng::~cPng() {
	delete [] pixels;
}

void cPng::setPixel(size_t x, size_t y, u_int8_t red, u_int8_t green, u_int8_t blue) {
	*getPixelPointer(x, y) = pixel(red, green, blue);
}

void cPng::setPixel(size_t x, size_t y, pixel p) {
	*getPixelPointer(x, y) = p;
}

cPng::pixel cPng::getPixel(size_t x, size_t y) {
	return(*getPixelPointer(x, y));
}

cPng::pixel *cPng::getPixelPointer(size_t x, size_t y) {
	return(pixels + width * y + x);
}

bool cPng::write(const char *filePathName, string *error) {
#ifdef HAVE_LIBPNG
	FILE *fp = fopen (filePathName, "wb");
	if(!fp) {
		if(error) {
			*error = string("open file ") + filePathName + " failed";
		}
		return(false);
	}

	png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	if(png_ptr == NULL) {
		if(error) {
			*error = "png_create_write_struct failed";
		}
		fclose(fp);
		return(false);
	}
	
	png_infop info_ptr = png_create_info_struct (png_ptr);
	if(info_ptr == NULL) {
		if(error) {
			*error = "png_create_info_struct failed";
		}
		png_destroy_write_struct(&png_ptr, NULL);
		fclose(fp);
		return(false);
	}
	
	png_set_IHDR (png_ptr,
		      info_ptr,
		      this->width,
		      this->height,
		      depth,
		      PNG_COLOR_TYPE_RGB,
		      PNG_INTERLACE_NONE,
		      PNG_COMPRESSION_TYPE_DEFAULT,
		      PNG_FILTER_TYPE_DEFAULT);
	
	png_byte ** row_pointers = (png_byte**)png_malloc (png_ptr, this->height * sizeof(png_byte*));
	for(size_t y = 0; y < this->height; y++) {
		png_byte *row = (png_byte*)png_malloc (png_ptr, sizeof (u_int8_t) * this->width * pixel_size);
		row_pointers[y] = row;
		for(size_t x = 0; x < this->width; x++) {
			pixel * pp = this->getPixelPointer(x, y);
			*row++ = pp->red;
			*row++ = pp->green;
			*row++ = pp->blue;
	    }
	}
	
	png_init_io(png_ptr, fp);
	png_set_rows(png_ptr, info_ptr, row_pointers);
	png_write_png(png_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, NULL);

	for(size_t y = 0; y < this->height; y++) {
		png_free(png_ptr, row_pointers[y]);
	}
	png_free(png_ptr, row_pointers);
	
	png_destroy_write_struct(&png_ptr, &info_ptr);
	
	return(true);
#else
	if(error) {
		*error = "missing png library";
	}
	return(false);
#endif //HAVE_LIBPNG
}


bool create_waveform_from_raw(const char *rawInput,
			      size_t sampleRate, size_t msPerPixel, u_int8_t channels,
			      const char waveformOutput[][1024]) {
	u_int8_t bytesPerSample = 2;
	
	long long int rawInputSize = GetFileSize(rawInput);
	if(rawInputSize <= 0) {
		return(false);
	}
	size_t rawSamples = rawInputSize / bytesPerSample / channels;
	if(rawSamples < 1) {
		return(false);
	}
	
	int16_t *raw[2] = { NULL, NULL };
	for(u_int8_t ch = 0; ch < channels; ch++) {
		raw[ch] = new FILE_LINE(38033) int16_t[rawSamples];
	}
 
	FILE *inputRawHandle = fopen(rawInput, "rb");
	char inputBuff[20000];
	size_t readLen;
	size_t counterSamples = 0;
	while((readLen = fread(inputBuff, 1, sizeof(inputBuff), inputRawHandle)) > 0) {
		for(size_t i = 0; i < readLen / bytesPerSample; i += channels) {
			for(u_int8_t ch = 0; ch < channels; ch++) {
				if(counterSamples < rawSamples) {
					raw[ch][counterSamples] = *(int16_t*)(inputBuff + i * bytesPerSample + ch * bytesPerSample);
				}
			}
			++counterSamples;
		}
	}
	fclose(inputRawHandle);
	
	size_t stepSamples = sampleRate * msPerPixel / 1000;
	size_t width = rawSamples / stepSamples;
	
	bool rsltWrite = false;
	
	for(u_int8_t ch = 0; ch < channels; ch++) {
	 
		FILE *waveformOutputHandle = fopen(waveformOutput[ch], "wb");
		if(waveformOutputHandle) {
			u_int16_t *peaks = new FILE_LINE(38034) u_int16_t[width + 10];
			size_t peaks_count = 0;
			u_int16_t peak = 0;
			int16_t v;
			for(size_t i = 0; i < rawSamples; i++) {
				if(!(i % stepSamples) && i) {
				       peaks[peaks_count++] = peak;
				       peak = 0;
				}
				v = raw[ch][i];
				if(v < 0) {
					v = -v;
				}
				if(v > peak) {
					peak = v;
				}
			}
			fwrite(peaks, sizeof(u_int16_t), peaks_count, waveformOutputHandle);
			fclose(waveformOutputHandle);
			delete [] peaks;
			rsltWrite = true;
		} else {
			rsltWrite = false;
		}
		
		if(!rsltWrite) {
			break;
		}
		
	}
	
	for(u_int8_t ch = 0; ch < channels; ch++) {
		if(raw[ch]) {
			delete [] raw[ch];
		}
	}
	
	return(rsltWrite);
}


bool create_spectrogram_from_raw(const char *rawInput,
				 size_t sampleRate, size_t msPerPixel, size_t height, u_int8_t channels,
				 const char spectrogramOutput[][1024]) {
#ifdef HAVE_LIBFFT
	u_int8_t bytesPerSample = 2;
	bool debug_out = false;
 
	long long int rawInputSize = GetFileSize(rawInput);
	if(rawInputSize <= 0) {
		return(false);
	}
	size_t rawSamples = rawInputSize / bytesPerSample / channels;
	if(rawSamples < 1) {
		return(false);
	}
	
	int16_t *raw[2] = { NULL, NULL };
	for(u_int8_t ch = 0; ch < channels; ch++) {
		raw[ch] = new FILE_LINE(38035) int16_t[rawSamples];
	}
 
	FILE *inputRawHandle = fopen(rawInput, "rb");
	char inputBuff[20000];
	size_t readLen;
	size_t counterSamples = 0;
	while((readLen = fread(inputBuff, 1, sizeof(inputBuff), inputRawHandle)) > 0) {
		for(size_t i = 0; i < readLen / bytesPerSample; i += channels) {
			for(u_int8_t ch = 0; ch < channels; ch++) {
				if(counterSamples < rawSamples) {
					raw[ch][counterSamples] = *(int16_t*)(inputBuff + i * bytesPerSample + ch * bytesPerSample);
				}
			}
			++counterSamples;
		}
	}
	fclose(inputRawHandle);
	
	size_t fftSize;
	if(height) {
		fftSize = height * 2;
	} else {
		fftSize = 128;
		height = fftSize / 2;
	}
	size_t stepSamples = sampleRate * msPerPixel / 1000;
	size_t width = rawSamples / stepSamples;
	
	bool rsltWrite = false;
	
	for(u_int8_t ch = 0; ch < channels; ch++) {
	
		map<size_t, map<size_t, u_int8_t> >  image;

		double *fftw_in = (double*)fftw_malloc(sizeof(double) * fftSize);
		fftw_complex *fftw_out = (fftw_complex*)fftw_malloc(sizeof(fftw_complex) * fftSize);
		fftw_plan fftw_pl = fftw_plan_dft_r2c_1d(fftSize, fftw_in, fftw_out, FFTW_ESTIMATE);
		
		cPng::pixel palette[256];
		for (int i=0; i < 32; i++)  {
		   palette[i].red = 0;
		   palette[i].green = 0;
		   palette[i].blue = i * 4;
		    
		   palette[i+32].red = 0;
		   palette[i+32].green = 0;
		   palette[i+32].blue = 128 + i * 4;
		    
		   palette[i+64].red = 0;
		   palette[i+64].green = i * 4;
		   palette[i+64].blue = 255;
		    
		   palette[i+96].red = 0;
		   palette[i+96].green = 128 + i * 4;
		   palette[i+96].blue = 255;
		    
		   palette[i+128].red = 0;
		   palette[i+128].green = 255;
		   palette[i+128].blue = 255 - i * 8;
		    
		   palette[i+160].red = i * 8;
		   palette[i+160].green = 255;
		   palette[i+160].blue = 0;
		    
		   palette[i+192].red = 255;
		   palette[i+192].green = 255 - i * 8;
		   palette[i+192].blue = 0;
		    
		   palette[i+224].red = 255;
		   palette[i+224].green = 0;
		   palette[i+224].blue = 0;
		}
		
		/*cPng::pixel palette[256];
		for(int i = 0; i < 255; i++) {
			cPng::pixel_hsv p_hsv(255 - i, 100, (int)(40 + 60 * i / 255.));
			palette[i].setFromHsv(p_hsv);
		}*/
		
		/*cPng::pixel palette[11];
		palette[1] = cPng::pixel(0,0,180);
		palette[2] = cPng::pixel(0,0,255);
		palette[3] = cPng::pixel(0,50,255);
		palette[4] = cPng::pixel(0,100,255);
		palette[5] = cPng::pixel(0,150,255);
		palette[6] = cPng::pixel(0,255,0);
		palette[7] = cPng::pixel(255,150,0);
		palette[8] = cPng::pixel(255,100,0);
		palette[9] = cPng::pixel(255,50,0);
		palette[10] = cPng::pixel(255,0,0);*/
		
		size_t palette_size = sizeof(palette) / sizeof(cPng::pixel);
		
		double *multipliers = new FILE_LINE(38036) double[fftSize];
		for(size_t i = 0; i < fftSize; i++) {
			multipliers[i] = 0.5 * (1 - cos(2. * M_PI * i / (fftSize - 1)));
		}
		
		double maxout = 0;
		double minout = 0;
		double maxout1 = 0;
		size_t maxout1i = 0;
		
		cPng png(width, height);
		
		for(size_t x = 0; x < width; x++) {
		 
			for(size_t i = 0; i < fftSize; i++) {
				fftw_in[i] = raw[ch][x * stepSamples + i] * multipliers[i];
			}
			fftw_execute(fftw_pl);
			
			for(size_t i = 0; i < height; i++) {
				double out = sqrt(fftw_out[i][0]*fftw_out[i][0] + fftw_out[i][1]*fftw_out[i][1]);
				out = log(max(1., out));
				if(debug_out) {
					if(out > maxout) {
						maxout = out;
					}
					if(out < minout) {
						minout = out;
					}
					if(out > maxout1) {
						maxout1 = out;
						maxout1i = i;
					}
					cout << out << ",";
				}
				png.setPixel(x, height - (i + 1), palette[(int)min((int)(out / 13.86 * palette_size), (int)palette_size - 1)]);
			}
			if(debug_out) {
				cout << endl << minout << " - " << maxout << " / " << maxout1 << " / " << maxout1i << endl;
			}
		} 
		if(debug_out) {
			cout << maxout << endl;
		}
		
		rsltWrite = png.write(spectrogramOutput[ch]);

		fftw_destroy_plan(fftw_pl);
		fftw_free(fftw_in); 
		fftw_free(fftw_out);
		
		delete [] multipliers;
		
		if(!rsltWrite) {
			break;
		}
		
	}
	
	for(u_int8_t ch = 0; ch < channels; ch++) {
		if(raw[ch]) {
			delete [] raw[ch];
		}
	}
	
	return(rsltWrite);
#else
	return(false);
#endif //HAVE_LIBFFT
}


/*uint64_t convert_srcmac_ll(ether_header *header_eth) {
	if (header_eth != NULL) {
		uint64_t converted = 0;
		converted += (unsigned char) header_eth->ether_shost[0];
		for (int i = 1; i < 6; i++) {
			converted <<= 8;
			converted += (unsigned char) header_eth->ether_shost[i];
		}
		return (converted);
	}
	//No ether header = src mac 0
	return (0);
}
*/


/* obsolete
bool cloud_now_activecheck() {
	struct timeval timenow;
	gettimeofday(&timenow,NULL);
	if (getDifTime(&cloud_last_activecheck) / 1000000 >= opt_cloud_activecheck_period) {	//in sec
		return(true);
	}
	return(false);
}

void cloud_activecheck_set() {
	gettimeofday(&cloud_last_activecheck, NULL);
}

void cloud_activecheck_start() {
	cloud_activecheck_inprogress = true;
}

void cloud_activecheck_stop() {
	cloud_activecheck_inprogress = false;
}
bool cloud_now_timeout() {
	if (!cloud_activecheck_inprogress) return false;				//check not started yet, thus no timeout possible

	struct timeval timenow;
	gettimeofday(&timenow,NULL);
	if (getDifTime(&cloud_last_activecheck) / 1000000 >= cloud_activecheck_timeout) {//in sec
		return(true);
	}
	return(false);
}

void cloud_activecheck_success() {
	if (verbosity) syslog(LOG_DEBUG, "Cloud activecheck Success - disabling activecheck for next %isec.",opt_cloud_activecheck_period);
	cloud_activecheck_stop();
}
*/


string getSystemTimezone(int method) {
	string timezone;
	for(int _method = 1; _method <= 3; _method++) {
		if(method && method != _method) {
			continue;
		}
		switch(_method) {
		case 1: {
			char link[1000];
			ssize_t sizeLink = readlink("/etc/localtime", link, sizeof(link));
			if(sizeLink > 0) {
				link[sizeLink] = 0;
				timezone = reg_replace(link, ".*zoneinfo/(.*)", "$1", __FILE__, __LINE__);
			}
			}
			break;
		case 2: {
			FILE *timezone_file = fopen("/etc/timezone", "r");
			if(timezone_file) {
				char tz[1000];
				if(fgets(tz, sizeof(tz), timezone_file)) {
					if(tz[strlen(tz) - 1] == '\n') {
						tz[strlen(tz) - 1] = 0;
					}
					if(tz[0]) {
						timezone  = tz;
					}
				}
				fclose(timezone_file);
			}
			}
			break;
		case 3: {
			FILE *clock_file = fopen("/etc/sysconfig/clock", "r");
			if(clock_file) {
				char line[1000];
				while(fgets(line, sizeof(line), clock_file)) {
					if(line[strlen(line) - 1] == '\n') {
						line[strlen(line) - 1] = 0;
					}
					if(!strncmp(line, "ZONE=", 5)) {
						timezone = reg_replace(line, "ZONE=\"(.*)\"", "$1", __FILE__, __LINE__);
						if(timezone.length()) {
							break;
						}
					}
				}
				fclose(clock_file);
			}
			}
			break;
		}
		if(timezone.length()) {
			timezone = trim(timezone);
			find_and_replace(timezone, " ", "_");
			break;
		}
	}
	return(timezone);
}


cThreadMonitor::cThreadMonitor() {
	_sync = 0;
}

void cThreadMonitor::registerThread(const char *description) {
	sThread thread;
	thread.tid = get_unix_tid();
	thread.description = description;
	memset(thread.pstat, 0, sizeof(thread.pstat));
	tm_lock();
	threads[thread.tid] = thread;
	tm_unlock();
}

string cThreadMonitor::output() {
	list<sDescrCpuPerc> descrPerc;
	double sum_cpu = 0;
	tm_lock();
	map<int, sThread>::iterator iter;
	for(iter = threads.begin(); iter != threads.end(); iter++) {
		double cpu_perc = this->getCpuUsagePerc(&iter->second);
		if(cpu_perc > 0) {
			sDescrCpuPerc dp;
			dp.description = iter->second.description;
			dp.tid = iter->second.tid;
			dp.cpu_perc = cpu_perc;
			descrPerc.push_back(dp);
			sum_cpu += cpu_perc;
		}
	}
	tm_unlock();
	ostringstream outStr;
	descrPerc.sort();
	list<sDescrCpuPerc>::iterator iter_dp;
	int counter = 0;
	for(iter_dp = descrPerc.begin(); iter_dp != descrPerc.end(); iter_dp++) {
		outStr << fixed
		       << setw(50) << iter_dp->description
		       << " (" << setw(5) << iter_dp->tid << ") : "
		       << setprecision(1) << setw(5) << iter_dp->cpu_perc;
		++counter;
		if(!(counter % 2)) {
			outStr << endl;
		}
	}
	if(counter % 2) {
		outStr << endl;
	}
	outStr << "SUM : " << setprecision(1) << setw(5) << sum_cpu << endl;
	return(outStr.str());
}

void cThreadMonitor::preparePstatData(sThread *thread) {
	if(thread->pstat[0].cpu_total_time) {
		thread->pstat[1] = thread->pstat[0];
	}
	pstat_get_data(thread->tid, thread->pstat);
}

double cThreadMonitor::getCpuUsagePerc(sThread *thread) {
	this->preparePstatData(thread);
	double ucpu_usage, scpu_usage;
	if(thread->pstat[0].cpu_total_time && thread->pstat[1].cpu_total_time) {
		pstat_calc_cpu_usage_pct(
			&thread->pstat[0], &thread->pstat[1],
			&ucpu_usage, &scpu_usage);
		return(ucpu_usage + scpu_usage);
	}
	return(-1);
}


void cCsv::sRow::dump() {
	for(unsigned i = 0; i < this->size(); i++) {
		cout << (*this)[i];
		cout << " | ";
	}
}

void cCsv::sTable::dump() {
	for(unsigned i = 0; i < this->size(); i++) {
		cout << (i + 1) << " : ";
		(*this)[i].dump();
		cout << endl;
	}
}

cCsv::cCsv() {
	fieldSeparator = ',';
	firstRowContainFieldNames = false;
}

void cCsv::setFirstRowContainFieldNames(bool firstRowContainFieldNames) {
	this->firstRowContainFieldNames = firstRowContainFieldNames;
}

void cCsv::setFieldSeparator(char fieldSeparator) {
	this->fieldSeparator = fieldSeparator;
}

int cCsv::load(const char *fileName, sTable *table) {
	if(!table) {
		table = &this->table;
	}
	table->clear();
	FILE *file = fopen(fileName, "r");
	if(!file) {
		return(-1);
	}
	unsigned inputRowBuffLength = 100000;
	char *inputRowBuff = new FILE_LINE(38037) char[inputRowBuffLength + 1];
	inputRowBuff[inputRowBuffLength] = 0;
	string inputRow;
	unsigned counterLines = 0;
	while(fgets(inputRowBuff, inputRowBuffLength, file)) {
		if(!counterLines) {
			if(strlen(inputRowBuff) > 4 && !strncmp(inputRowBuff, "sep=", 4) &&
			   (inputRowBuff[4] == ',' || inputRowBuff[4] == ';')) {
				fieldSeparator = inputRowBuff[4];
				++counterLines;
				continue;
			}
		}
		inputRow += inputRowBuff;
		sRow row;
		eExplodeRowResult elr = this->explodeRow(inputRow.c_str(), &row);
		switch(elr) {
		case elr_ok:
			table->push_back(row);
			inputRow.resize(0);
		case elr_incomplete:
			break;
		case elr_fail:
			inputRow.resize(0);
			break;
		}
		++counterLines;
	}
	delete [] inputRowBuff;
	fclose(file);
	return(table->size());
}

cCsv::eExplodeRowResult cCsv::explodeRow(const char *line, sRow *row) {
	bool incomplete = false;
	row->clear();
	unsigned lengthLine = strlen(line);
	while(lengthLine &&
	      (line[lengthLine - 1] == '\r' || line[lengthLine - 1] == '\n')) {
		--lengthLine;
	}
	unsigned pos = 0;
	while(pos < lengthLine) {
		string cell;
		string separator = string(1, fieldSeparator);
		if(line[pos] == '"') {
			separator = string(1, '"') + string(1, fieldSeparator);
			++pos;
		}
		const char *posSep_ptr = strstr(line + pos, separator.c_str());
		if(posSep_ptr) {
			unsigned posSep = posSep_ptr - line;
			cell = string(line + pos, posSep - pos);
			if(separator[0] == '"') {
				this->normalizeCellWithQuotationBorder(&cell);
			}
			row->push_back(cell);
			pos = posSep + separator.length();
		} else {
			cell = string(line + pos, lengthLine - pos);
			if(separator[0] == '"') {
				if(cell[cell.length() - 1] == '"') {
					cell.resize(cell.length() - 1);
				} else {
					incomplete = true;
				}
				this->normalizeCellWithQuotationBorder(&cell);
			}
			row->push_back(cell);
			break;
		}
	}
	return(row->size() ?
		(incomplete ? elr_incomplete : elr_ok) :
		elr_fail);
}

void cCsv::normalizeCellWithQuotationBorder(string *cell) {
	find_and_replace(*cell, "“", "\"");
	find_and_replace(*cell, "\"\"", "\"");
	if(cell->length() >= 3 &&
	   cell->substr(0, 2) == "=\"" &&
	   (*cell)[cell->length() - 1] == '"') {
		*cell = cell->substr(2, cell->length() - 3);
	}
}

unsigned cCsv::getRowsCount() {
	return(firstRowContainFieldNames ?
		(table.size() > 1 ? table.size() - 1 : 0) :
		table.size());
}

void cCsv::getRow(unsigned numRow, list<string> *row) {
	row->clear();
	if(numRow > getRowsCount()) {
		return;
	}
	sRow *selectedRow = &table[numRow - 1];
	for(unsigned i = 0; i < selectedRow->size(); i++) {
		row->push_back((*selectedRow)[i]);
	}
}

void cCsv::getRow(unsigned numRow, map<string, string> *row) {
	row->clear();
	if(numRow > getRowsCount() ||
	   !firstRowContainFieldNames) {
		return;
	}
	sRow *headerRow = &table[0];
	sRow *selectedRow = &table[numRow];
	for(unsigned i = 0; i < headerRow->size(); i++) {
		(*row)[(*headerRow)[i]] = i < selectedRow->size() ? (*selectedRow)[i] : "";
	}
}

void cCsv::dump() {
	table.dump();
}


void sDbString::substCB(cSqlDbData *dbData, list<string> *cb_inserts) {
	if((flags & SqlDb_row::_ift_base) >= SqlDb_row::_ift_cb_string) {
		string cb_insert;
		cb_id = dbData->getCbId((cSqlDbCodebook::eTypeCodebook)((flags & SqlDb_row::_ift_base) - SqlDb_row::_ift_cb_string), str, true, false,
					&cb_insert);
		if(!cb_insert.empty()) {
			cb_inserts->push_back(cb_insert);
		}
		//cout << "CB: " << flags << " / " << str << " / " << cb_id << endl;
	}
}

void sDbString::substAI(cSqlDbData *dbData, u_int64_t *ai_id, const char *table_name) {
	if(flags == SqlDb_row::_ift_sql &&
	   !strcmp(str, MYSQL_MAIN_INSERT_ID.c_str())) {
		if(!*ai_id) {
			*ai_id = dbData->getAiId(table_name);
		}
		this->ai_id = *ai_id;
		//cout << "AI: " << flags << " / " << str << " / " << *ai_id << endl;
	}
}

cDbStrings::cDbStrings(unsigned capacity, unsigned capacity_inc) {
	if(capacity) {
		strings = new FILE_LINE(0) sDbString[capacity];
		this->capacity = capacity;
		this->capacity_inc = capacity_inc ? capacity_inc : capacity;
	} else {
		strings = NULL;
		this->capacity = 0;
		this->capacity_inc = capacity_inc ? capacity_inc : 1;
	}
	size = 0;
	strings_map = NULL;
	zero_term_set = false;
}

cDbStrings::~cDbStrings() {
	if(strings_map) {
		delete strings_map;
	}
	if(strings) {
		delete [] strings;
	}
}

void cDbStrings::add(const char *begin, unsigned offset, unsigned length) {
	if(size == capacity) {
		sDbString *strings_new = new FILE_LINE(0) sDbString[capacity + capacity_inc];
		if(strings) {
			memcpy(strings_new, strings, size * sizeof(sDbString));
			delete [] strings;
		}
		strings = strings_new;
		capacity += capacity_inc;
	}
	strings[size].begin = begin;
	strings[size].offset = offset;
	strings[size].length = length;
	++size;
}

void cDbStrings::explodeCsv(const char *csv) {
	unsigned lengthCsv = strlen(csv);
	while(lengthCsv &&
	      (csv[lengthCsv - 1] == '\r' || csv[lengthCsv - 1] == '\n')) {
		--lengthCsv;
	}
	unsigned pos = 0;
	while(pos < lengthCsv) {
		bool is_string = csv[pos] == '"';
		const char *nextSep = strstr(csv + pos, is_string ? "\"," : ",");
		if(is_string) {
			while(nextSep && *(nextSep - 1) == '\\') {
				nextSep = strstr(nextSep + 1, is_string ? "\"," : ",");
			}
		}
		if(nextSep) {
			unsigned nextSepPos = nextSep - csv;
			if(is_string) {
				add(csv, pos + 1, nextSepPos - pos - 1);
			} else {
				add(csv, pos, nextSepPos - pos);
			}
			pos = nextSepPos + (is_string ? 2 : 1);
		} else {
			if(is_string) {
				add(csv, pos + 1, lengthCsv - pos - 2);
			} else {
				add(csv, pos, lengthCsv - pos);
			}
			break;
		}
	}
}

void cDbStrings::setZeroTerm() {
	for(unsigned i = 0; i < size; i++) {
		strings[i].setZeroTerm();
	}
	zero_term_set = true;
}

void cDbStrings::setNextData() {
	for(unsigned i = 0; i < size; i++) {
		strings[i].setNextData();
	}
}

void cDbStrings::createMap(bool icase) {
	strings_map = new FILE_LINE(0) map<sDbString, unsigned>;
	for(unsigned i = 0; i < size; i++) {
		strings[i].setStr();
		strings[i].icase = icase;
		(*strings_map)[strings[i]] = i;
	}
	icase_map = icase;
}

void cDbStrings::print() {
	for(unsigned i = 0; i < size; i++) {
		if(zero_term_set) {
			cout << '|' << string(strings[i].begin + strings[i].offset, strings[i].length) << '|' << endl;
		} else {
			cout << '|' << (strings[i].begin + strings[i].offset) << '|' << endl;
		}
	}
}

void cDbStrings::substCB(cSqlDbData *dbData, list<string> *cb_inserts) {
	for(unsigned i = 0; i < size; i++) {
		strings[i].substCB(dbData, cb_inserts);
	}
}

void cDbStrings::substAI(cSqlDbData *dbData, u_int64_t *ai_id, const char *table_name) {
	for(unsigned i = 0; i < size; i++) {
		strings[i].substAI(dbData, ai_id, table_name);
	}
}

string cDbStrings::implodeInsertColumns() {
	string separator = ",";
	string border = "`";
	string rslt;
	unsigned counter = 0;
	for(size_t i = 0; i < size; i++) {
		if(!strings[i].begin) {
			continue;
		}
		if(counter) { rslt += separator; }
		rslt += border + (strings[i].begin + strings[i].offset) + border;
		++counter;
	}
	return(rslt);
}

string cDbStrings::implodeInsertValues(const char *table, cDbStrings *header, SqlDb *sqlDb) {
	string separator = ",";
	string string_border = "'";
	string rslt = "( ";
	unsigned counter = 0;
	for(size_t i = 0; i < size; i++) {
		if(!strings[i].begin) {
			continue;
		}
		if(counter) { rslt += separator; }
		if(strings[i].flags & SqlDb_row::_ift_null) {
			rslt += "NULL";
		} else {
			switch(strings[i].flags & SqlDb_row::_ift_base) {
			case SqlDb_row::_ift_string:
				rslt += string_border + strings[i].str + string_border;
				break;
			case SqlDb_row::_ift_int:
			case SqlDb_row::_ift_int_u:
			case SqlDb_row::_ift_double:
				rslt += strings[i].str;
				break;
			case SqlDb_row::_ift_ip:
				if(VM_IPV6_B && sqlDb->isIPv6Column(table, header->strings[i].getStr())) {
					rslt += string("inet6_aton('") + strings[i].str + "')";
				} else {
					rslt += intToString(str_2_vmIP(strings[i].str).getIPv4());
				}
				break;
			case SqlDb_row::_ift_calldate:
				rslt += string_border + sqlEscapeString(sqlDateTimeString_us2ms(atoll(strings[i].str))) + string_border;
				break;
			case SqlDb_row::_ift_sql:
				if(strings[i].ai_id) {
					rslt += intToString(strings[i].ai_id);
				}
				break;
			default:
				if((strings[i].flags & SqlDb_row::_ift_base) >= SqlDb_row::_ift_cb_string && strings[i].cb_id) {
					rslt += intToString(strings[i].cb_id);
				} else {
					rslt += "NULL";
				}
			}
		}
		++counter;
	}
	rslt += " )";
	return(rslt);
}

cDbTableContent::cDbTableContent(const char *table_name) {
	this->table_name = table_name;
}

cDbTableContent::~cDbTableContent() {
	header.destroy();
	for(vector<sRow>::iterator iter = rows.begin(); iter != rows.end(); iter++) {
		iter->destroy();
	}
}

void cDbTableContent::addHeader(const char *source) {
	char *content = new FILE_LINE(0) char[strlen(source) + 1];
	strcpy(content, source);
	header.content = content;
	header.items = new FILE_LINE(0) cDbStrings(100);
	header.items->explodeCsv(content);
	header.items->setZeroTerm();
	header.items->createMap(true);
}

void cDbTableContent::addRow(const char *source) {
	char *content = new FILE_LINE(0) char[strlen(source) + 1];
	strcpy(content, source);
	sRow row;
	row.content = content;
	row.items = new FILE_LINE(0) cDbStrings(100);
	row.items->explodeCsv(content);
	row.items->setZeroTerm();
	row.items->setNextData();
	rows.push_back(row);
}

void cDbTableContent::substCB(class cSqlDbData *dbData, list<string> *cb_inserts) {
	for(vector<sRow>::iterator iter = rows.begin(); iter != rows.end(); iter++) {
		iter->items->substCB(dbData, cb_inserts);
	}
}

void cDbTableContent::substAI(class cSqlDbData *dbData, u_int64_t *ai_id) {
	//cout << "TABLE: " << table_name << endl;
	for(vector<sRow>::iterator iter = rows.begin(); iter != rows.end(); iter++) {
		iter->items->substAI(dbData, ai_id, table_name.c_str());
	}
}

string cDbTableContent::insertQuery(SqlDb *sqlDb) {
	string insert_str = "INSERT INTO " + table_name + " ( ";
	insert_str += header.items->implodeInsertColumns();
	insert_str += " ) VALUES ";
	unsigned counter = 0;
	for(vector<sRow>::iterator iter = rows.begin(); iter != rows.end(); iter++) {
		if(counter) {
			insert_str += ",";
		}
		insert_str += iter->items->implodeInsertValues(table_name.c_str(), header.items, sqlDb);
		++counter;
	}
	return(insert_str);
}

cDbTablesContent::cDbTablesContent() {
}

cDbTablesContent::~cDbTablesContent() {
	for(vector<cDbTableContent*>::iterator iter = tables.begin(); iter != tables.end(); iter++) {
		delete *iter;
	}
}

void cDbTablesContent::addCsvRow(const char *source) {
	bool header = false;
	bool row = false;
	string table;
	if(!strncmp(source, "csv_header:", 11)) {
		header = true;
		source += 11;
	} else if(!strncmp(source, "csv_row:", 8)) {
		row = true;
		source += 8;
	}
	if(row || header) {
		const char *tableEndSeparator = strchr(source, ':');
		if(tableEndSeparator) {
			table = string(source, tableEndSeparator - source);
			source = tableEndSeparator + 1;
			cDbTableContent *tableContent;
			map<string, cDbTableContent*>::iterator iter = tables_map.find(table);
			if(iter != tables_map.end()) {
				tableContent = iter->second;
			} else {
				tableContent = new FILE_LINE(0) cDbTableContent(table.c_str());
				tables.push_back(tableContent);
				tables_map[table] = tableContent;
				unsigned table_enum = Call::getTableEnumIndex(&table);
				if(table_enum) {
					tables_enum_map[table_enum] = tableContent;
				}
			}
			if(header) {
				tableContent->addHeader(source);
			} else if(row) {
				tableContent->addRow(source);
			}
		}
	}
}

void cDbTablesContent::substCB(class cSqlDbData *dbData, list<string> *cb_inserts) {
	for(vector<cDbTableContent*>::iterator iter = tables.begin(); iter != tables.end(); iter++) {
		(*iter)->substCB(dbData, cb_inserts);
	}
}

void cDbTablesContent::substAI(class cSqlDbData *dbData, u_int64_t *ai_id) {
	for(vector<cDbTableContent*>::iterator iter = tables.begin(); iter != tables.end(); iter++) {
		(*iter)->substAI(dbData, ai_id);
	}
}

string cDbTablesContent::getMainTable() {
	if(tables.size()) {
		return(tables[0]->table_name);
	}
	return("");
}

void cDbTablesContent::insertQuery(list<string> *dst, SqlDb *sqlDb) {
	for(vector<cDbTableContent*>::iterator iter = tables.begin(); iter != tables.end(); iter++) {
		dst->push_back((*iter)->insertQuery(sqlDb));
	}
}

sDbString *cDbTablesContent::findColumn(const char *table, const char *column, unsigned rowIndex, int *columnIndex) {
	map<string, cDbTableContent*>::iterator iter = tables_map.find(table);
	if(iter != tables_map.end() && rowIndex < iter->second->rows.size()) {
		int _columnIndex = iter->second->header.items->findIndex(column);
		if(columnIndex) {
			*columnIndex = _columnIndex;
		}
		if(_columnIndex >= 0 && _columnIndex < (int)iter->second->rows[rowIndex].items->size) {
			return(&iter->second->rows[rowIndex].items->strings[_columnIndex]);
		}
	} else {
		if(columnIndex) {
			*columnIndex = -2;
		}
	}
	return(NULL);
}

sDbString *cDbTablesContent::findColumn(unsigned table_enum, const char *column, unsigned rowIndex, int *columnIndex) {
	map<unsigned, cDbTableContent*>::iterator iter = tables_enum_map.find(table_enum);
	if(iter != tables_enum_map.end() && rowIndex < iter->second->rows.size()) {
		int _columnIndex = iter->second->header.items->findIndex(column);
		if(columnIndex) {
			*columnIndex = _columnIndex;
		}
		if(_columnIndex >= 0 && _columnIndex < (int)iter->second->rows[rowIndex].items->size) {
			return(&iter->second->rows[rowIndex].items->strings[_columnIndex]);
		}
	} else {
		if(columnIndex) {
			*columnIndex = -2;
		}
	}
	return(NULL);
}

int cDbTablesContent::getCountRows(const char *table) {
	map<string, cDbTableContent*>::iterator iter = tables_map.find(table);
	if(iter != tables_map.end()) {
		return(iter->second->rows.size());
	}
	return(-1);
}

int cDbTablesContent::getCountRows(unsigned table_enum) {
	map<unsigned, cDbTableContent*>::iterator iter = tables_enum_map.find(table_enum);
	if(iter != tables_enum_map.end()) {
		return(iter->second->rows.size());
	}
	return(-1);
}

const char *cDbTablesContent::getValue_str(unsigned table_enum, const char *column, bool *null, unsigned rowIndex, int *columnIndex) {
	map<unsigned, cDbTableContent*>::iterator iter = tables_enum_map.find(table_enum);
	if(iter != tables_enum_map.end() && rowIndex < iter->second->rows.size()) {
		int _columnIndex = iter->second->header.items->findIndex(column);
		if(columnIndex) {
			*columnIndex = _columnIndex;
		}
		if(_columnIndex >= 0 && _columnIndex < (int)iter->second->rows[rowIndex].items->size) {
			if(null) {
				*null = iter->second->rows[rowIndex].items->strings[_columnIndex].flags & SqlDb_row::_ift_null;
			}
			return(iter->second->rows[rowIndex].items->strings[_columnIndex].str);
		} else {
			if(null) {
				*null = true;
			}
		}
	} else {
		if(columnIndex) {
			*columnIndex = -2;
		}
	}
	return(NULL);
}

double cDbTablesContent::getMinMaxValue(unsigned table_enum, const char *columns[], bool min, bool onlyNotZero, bool *null) {
	double rslt = nan("0");
	if(null) {
		*null = true;
	}
	for(unsigned i = 0; columns[i]; i++) {
		double v;
		bool v_null;
		v = getValue_float(table_enum, columns[i], false, &v_null);
		if(!v_null &&
		   (!onlyNotZero || v != 0) &&
		   (isnan(rslt) ||
		    (min ? v < rslt : v > rslt))) {
			rslt = v;
			if(null) {
				*null = false;
			}
		}
	}
	return(rslt);
}

void cDbTablesContent::removeColumn(unsigned table_enum, const char *column) {
	map<unsigned, cDbTableContent*>::iterator iter = tables_enum_map.find(table_enum);
	if(iter != tables_enum_map.end()) {
		int columnIndex = iter->second->header.items->findIndex(column);
		if(columnIndex >= 0) {
			iter->second->header.items->strings[columnIndex].begin = NULL;
			for(unsigned i = 0; i < iter->second->rows.size(); i++) {
				iter->second->rows[i].items->strings[columnIndex].begin = NULL;
			}
		}
	}
}

void cDbTablesContent::removeColumn(unsigned table_enum, unsigned columnIndex) {
	map<unsigned, cDbTableContent*>::iterator iter = tables_enum_map.find(table_enum);
	if(iter != tables_enum_map.end()) {
		iter->second->header.items->strings[columnIndex].begin = NULL;
		for(unsigned i = 0; i < iter->second->rows.size(); i++) {
			iter->second->rows[i].items->strings[columnIndex].begin = NULL;
		}
	}
}

bool is_ok_pcap_header(pcap_sf_pkthdr *header, pcap_sf_pkthdr *prev_header) {
	return(header->ts.tv_sec >= prev_header->ts.tv_sec && 
	       header->ts.tv_sec < prev_header->ts.tv_sec + 60 * 60 && 
	       header->caplen > 0 && header->caplen <= 65535 &&
	       header->len > 0 && header->len <= 65535);
}

void print_pcap_header(pcap_sf_pkthdr *header, const char *head, unsigned counter, unsigned filePos) {
	cout << head << ": "
	     << counter << ";"
	     << " time: " << fixed << setprecision(6) << header->ts.tv_sec + (double)header->ts.tv_usec / 1000000 << ";"
	     << " length: " << header->caplen << " / " << header->len << ";"
	     << " filepos: " << filePos << ";"
	     << endl;
}

void read_pcap(const char *pcapFileName) {
	FILE *pcapFile = fopen(pcapFileName, "r");
	if(!pcapFile) {
		return;
	}
	unsigned long filePos = 0;
	pcap_file_header hdr;
	unsigned c = fread(&hdr, 1, sizeof(hdr), pcapFile);
	if(!c) {
		fclose(pcapFile);
		return;
	}
	filePos += sizeof(hdr);
	cout << "HEADER:"
	     << " magic: " << hdr.magic << ";"
	     << " version: " << hdr.version_major << " / " << hdr.version_minor  << ";"
	     << " snaplen: " << hdr.snaplen  << ";"
	     << " linktype: " << hdr.linktype << ";"
	     << endl;
	unsigned packetBufferLengthMax = 1000000;
	unsigned packetBufferLength = 0;
	char *packetBuffer = new FILE_LINE(38038) char[packetBufferLengthMax];
	char *packetBufferPos = packetBuffer;
	unsigned int packetCounter = 0;
	while(true) {
		if(packetBufferLength < packetBufferLengthMax / 2) {
			char *packetBufferCopy = new FILE_LINE(38039) char[packetBufferLengthMax];
			memcpy(packetBufferCopy, packetBufferPos, packetBufferLength);
			delete [] packetBuffer;
			packetBuffer = packetBufferCopy;
			packetBufferPos = packetBuffer;
			c = fread(packetBuffer + packetBufferLength, 1, packetBufferLengthMax - packetBufferLength, pcapFile);
			packetBufferLength += c;
		}
		if(packetBufferLength < sizeof(pcap_sf_pkthdr)) {
			break;
		}
		pcap_sf_pkthdr *phdr = (pcap_sf_pkthdr*)packetBufferPos;
		++packetCounter;
		print_pcap_header(phdr, "PACKET", packetCounter, filePos);
		unsigned ph_length = sizeof(pcap_sf_pkthdr) + phdr->caplen;
		if(packetBufferLength > ph_length) {
			pcap_sf_pkthdr *phdr_next = (pcap_sf_pkthdr*)(packetBufferPos + ph_length);
			if(!is_ok_pcap_header(phdr_next, phdr)) {
				bool find_xphdr = false;
				for(unsigned i = 1; i < packetBufferLength; i++) {
					pcap_sf_pkthdr *xphdr = (pcap_sf_pkthdr*)(packetBufferPos + i);
					if(is_ok_pcap_header(xphdr, phdr)) {
						print_pcap_header(xphdr, "find packet", i, filePos + i);
						cout << "correct caplen to: " 
						     << i - sizeof(pcap_sf_pkthdr) 
						     << " diff: " << ((int)ph_length - (int)i)
						     << endl;
						ph_length = i;
						find_xphdr = true;
						break;
					}
				}
				if(!find_xphdr) {
					cout << "bad next packet" << endl;
					print_pcap_header(phdr_next, "bad_packet", packetCounter + 1, filePos + ph_length);
				}
			}
			packetBufferPos += ph_length;
			packetBufferLength -= ph_length;
			filePos += ph_length;
		} else {
			break;
		}
	}
	fclose(pcapFile);
	delete [] packetBuffer;
}

void close_all_fd() {
	long maxfd = sysconf(_SC_OPEN_MAX);
	int flags;
	for(int fd = 3; fd < maxfd; fd++) {
		if((flags = fcntl(fd, F_GETFD)) != -1) {
			fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
		}
		close(fd);
	}
}


int spooldir_file_chmod_own(string filename) {
	return(spooldir_file_chmod_own(filename.c_str()));
}

int spooldir_file_chmod_own(const char *filename) {
	int rslt_chmod = spooldir_file_chmod(filename);
	int rslt_chown = spooldir_chown(filename);
	return(rslt_chmod ? rslt_chmod : rslt_chown);
}

int spooldir_dir_chmod_own(const char *filename) {
	int rslt_chmod = spooldir_dir_chmod(filename);
	int rslt_chown = spooldir_chown(filename);
	return(rslt_chmod ? rslt_chmod : rslt_chown);
}

int spooldir_file_chmod_own(FILE *file) {
	return(spooldir_file_chmod_own(fileno(file)));
}

int spooldir_file_chmod_own(int filehandle) {
	int rslt_chmod = spooldir_file_chmod(filehandle);
	int rslt_chown = spooldir_chown(filehandle);
	return(rslt_chmod ? rslt_chmod : rslt_chown);
}

int spooldir_file_chmod(const char *filename) {
	return(chmod(filename, spooldir_file_permission()));
}

int spooldir_dir_chmod(const char *filename) {
	return(chmod(filename, spooldir_dir_permission()));
}

int spooldir_chown(const char *filename) {
	if(spooldir_owner_id() || spooldir_group_id()) {
		return(chown(filename, spooldir_owner_id(), spooldir_group_id()));
	}
	return(0);
}

int spooldir_file_chmod(int filehandle) {
	return(fchmod(filehandle, spooldir_file_permission()));
}

int spooldir_chown(int filehandle) {
	if(spooldir_owner_id() || spooldir_group_id()) {
		return(fchown(filehandle, spooldir_owner_id(), spooldir_group_id()));
	}
	return(0);
}

int spooldir_mkdir(std::string dir) {
	return(mkdir_r(dir, spooldir_dir_permission(), spooldir_owner_id(), spooldir_group_id()));
}


void hexdump(u_char *data, unsigned size) {
	if(!data) {
		size = 0;
	}
	unsigned i, j;
	for(i = 0; i < size; i += 16) {
		printf("| ");
		for (j = 0; j < 16 && (i+j) < size; ++j) {
			printf("%.2x ", data[i+j]&255);
		}
		for (; j < 16; ++j) {
			printf("   ");
		}
		printf("| |");
		for (j = 0; j < 16 && (i+j) < size; ++j) {
			if(isprint(data[i+j])) {
				printf("%c", data[i+j]);
			} else {
				printf(".");
			}
		}
		for (; j < 16; ++j) {
			printf(" ");
		}
		printf("|\n");
	}
}

unsigned file_get_rows(const char *filename, vector<string> *rows) {
	unsigned countRows = 0;
	FILE *fh = fopen(filename, "r");
	if(fh) {
		char rowbuff[10000];
		while(fgets(rowbuff, sizeof(rowbuff), fh)) {
			char *lf = strchr(rowbuff, '\n');
			if(lf) {
				*lf = 0;
			}
			rows->push_back(rowbuff);
			++countRows;
		}
		fclose(fh);
	}
	return(countRows);
}

unsigned file_get_rows(string filename, vector<string> *rows) {
	return(file_get_rows(filename.c_str(), rows));
}

vector<string> findCoredumps(int pid) {
	vector<string> coredumps;
	FILE *corePatternFile = fopen("/proc/sys/kernel/core_pattern", "r");
	if(corePatternFile) {
		char buff[1000];
		if(fgets(buff, sizeof(buff), corePatternFile)) {
			if(strchr(buff, '\n')) {
				*strchr(buff, '\n') = 0;
			}
			string corePattern = buff;
			if(corePattern.length()) {
				if(corePattern == "core") {
					extern char opt_spooldir_main[1024];
					vector<string> files = listDir(opt_spooldir_main);
					for(unsigned i = 0; i < files.size(); i++) {
						vector<string> matches;
						if(files[i] == "core" ||
						   (reg_match(files[i].c_str(), "^core\\.([0-9]+)$", &matches, true) && matches.size() &&
						    matches[1] == intToString(pid))) {
							coredumps.push_back(string(opt_spooldir_main) + "/" + files[i]);
						}
					}
				} else if(corePattern[0] == '/') {
					size_t endDirSeparatorPos = corePattern.rfind('/');
					if(endDirSeparatorPos != string::npos) {
						string corePatternDir = corePattern.substr(0, endDirSeparatorPos);
						string corePatternFile = corePattern.substr(endDirSeparatorPos + 1);
						if(corePatternDir.length() && corePatternFile.length() &&
						   (corePatternFile.find("%p") != string::npos || corePatternFile.find("%P") != string::npos)) {
							vector<string> files = listDir(corePatternDir);
							for(unsigned i = 0; i < files.size(); i++) {
								if(files[i].find(intToString(pid)) != string::npos) {
									coredumps.push_back(corePatternDir + "/" + files[i]);
								}
							}
						}
					}
				}
			}
		}
		fclose(corePatternFile);
	}
	return(coredumps);
}


cStringCache::cStringCache() {
	_sync = 0;
}

cStringCache::~cStringCache() {
	clear();
}

u_int32_t cStringCache::getId(const char *str) {
	if(!str || !*str) {
		return(0);
	}
	u_int32_t rslt = 0;
	cItem str_item;
	str_item.str = new FILE_LINE(0) string(str);
	lock();
	map<cItem, u_int32_t>::iterator iter = map_items.find(str_item);
	if(iter != map_items.end()) {
		rslt = iter->second;
	} else {
		rslt = map_items.size() + 1;
		map_items[str_item] = rslt;
		map_ids[rslt] = str_item;
		str_item.str = NULL;
	}
	unlock();
	if(str_item.str) {
		delete str_item.str;
	}
	return(rslt);
}

const char *cStringCache::getStr(u_int32_t id) {
	if(!id) {
		return(NULL);
	}
	const char *rslt = NULL;
	lock();
	map<u_int32_t, cItem>::iterator iter = map_ids.find(id);
	if(iter != map_ids.end()) {
		rslt = iter->second.str->c_str();
	}
	unlock();
	return(rslt);
}

void cStringCache::clear() {
	lock();
	map<u_int32_t, cItem>::iterator iter;
	for(iter = map_ids.begin(); iter != map_ids.end(); iter++) {
		delete iter->second.str;
	}
	map_items.clear();
	map_ids.clear();
	unlock();
}


void cEvalFormula::sValue::setFromField(void *_field) {
	SqlDb_row::SqlDb_rowField *field = (SqlDb_row::SqlDb_rowField*)_field;
	null();
	switch(field->ifv.type) {
	case SqlDb_row::_ift_int:
		v_type = _v_int;
		v._int = field->ifv.v._int;
		break;
	case SqlDb_row::_ift_int_u:
		v_type = _v_int;
		v._int = field->ifv.v._int_u;
		break;
	case SqlDb_row::_ift_double:
		v_type = _v_float;
		v._float = field->ifv.v._double;
		break;
	case SqlDb_row::_ift_ip:
		if(field->ifv.v_ip.is_v6()) {
			v_type = _v_ip;
			v._ip = &field->ifv.v_ip;
		} else {
			v_type = _v_int;
			v._int = field->ifv.v_ip.ip.v4.n;
		}
		break;
	default:
		v_type = _v_string;
		v._string = &field->content;
		break;
	}
	if(field->null) {
		v_null = true;
	}
}

void cEvalFormula::sValue::setFromDbString(sDbString *dbString) {
	null();
	switch(dbString->flags) {
	case SqlDb_row::_ift_int:
		v_type = _v_int;
		v._int = atoll(dbString->str);
		break;
	case SqlDb_row::_ift_int_u:
		v_type = _v_int;
		v._int = atoll(dbString->str);
		break;
	case SqlDb_row::_ift_double:
		v_type = _v_float;
		v._float = atof(dbString->str);
		break;
	case SqlDb_row::_ift_ip:
		{
		vmIP ip;
		ip.setFromString(dbString->str);
		if(ip.is_v6()) {
			v_type = _v_ip;
			v._ip = &ip;
		} else {
			v_type = _v_int;
			v._int = ip.ip.v4.n;
		}
		}
		break;
	case SqlDb_row::_ift_calldate:
		// TODO
		break;
	case SqlDb_row::_ift_null:
		v_type = _v_int;
		v._int = 0;
		v_null = true;
		break;
	default:
		*this = sValue(dbString->str);
		break;
	}
}

cEvalFormula::sValue cEvalFormula::sValue::arithm(sValue &v2, string oper) {
	sValue rslt;
	if(this->v_type != _v_na && v2.v_type != _v_na) {
		if(this->v_type == v2.v_type) {
			rslt.v_type = this->v_type;
			if(oper == "*") {
				switch(this->v_type) {
				case _v_int:
					rslt.v._int = this->v._int * v2.v._int;
					break;
				case _v_float:
					rslt.v._float = this->v._float * v2.v._float;
					break;
				default:
					break;
				}
			} else if(oper == "/") {
				switch(this->v_type) {
				case _v_int:
					if(v2.v._int) {
						rslt.v._int = this->v._int / v2.v._int;
					}
					break;
				case _v_float:
					if(v2.v._float) {
						rslt.v._float = this->v._float / v2.v._float;
					}
					break;
				default:
					break;
				}
			} else if(oper == "+") {
				switch(this->v_type) {
				case _v_int:
					rslt.v._int = this->v._int + v2.v._int;
					break;
				case _v_float:
					rslt.v._float = this->v._float + v2.v._float;
					break;
				default:
					break;
				}
			} else if(oper == "-") {
				switch(this->v_type) {
				case _v_int:
					rslt.v._int = this->v._int - v2.v._int;
					break;
				case _v_float:
					rslt.v._float = this->v._float - v2.v._float;
					break;
				default:
					break;
				}
			}
		} else {
			if(oper == "*") {
				rslt.v._float = this->getFloat() * v2.getFloat();
				rslt.v_type = _v_float;
			} else if(oper == "/") {
				if(v2.getFloat()) {
					rslt.v._float = this->getFloat() / v2.getFloat();
					rslt.v_type = _v_float;
				}
			} else if(oper == "+") {
				rslt.v._float = this->getFloat() + v2.getFloat();
				rslt.v_type = _v_float;
			} else if(oper == "-") {
				rslt.v._float = this->getFloat() - v2.getFloat();
				rslt.v_type = _v_float;
			}
		}
	}
	return(rslt);
}

cEvalFormula::sValue cEvalFormula::sValue::like(sValue &pattern_v) {
	if(pattern_v.v_type == _v_string && pattern_v.v._string) {
		unsigned pattern_v_length = pattern_v.v._string->length();
		if(pattern_v_length) {
			if(!pattern_v.v_str_wildcard) {
				pattern_v.v_str_wildcard = (pattern_v.v._string->find('_') != string::npos) ? 2 : 1;
				size_t pos_enc_grid;
				if((pos_enc_grid = pattern_v.v._string->find("\\%23")) != string::npos) {
					string _str = pattern_v.v._string->substr(pos_enc_grid + 1);
					pattern_v.v._string->resize(pos_enc_grid);
					pattern_v.v._string->append(_str);
					--pattern_v_length;
				}
			}
			bool rslt;
			string str = this->getString().c_str();
			if((*pattern_v.v._string)[0] == '%') {
				if((*pattern_v.v._string)[pattern_v_length - 1] == '%') {
					rslt = strcasestr(str.c_str(), pattern_v.v._string->substr(1, pattern_v_length - 2).c_str()) != NULL;
				} else {
					rslt = str.length() >= pattern_v_length - 1 &&
					       !(pattern_v.v_str_wildcard == 2 ?
						  strncasecmp_wildcard(str.c_str() + str.length() - (pattern_v_length - 1), pattern_v.v._string->substr(1).c_str(), pattern_v_length - 1, "_") :
						  strncasecmp(str.c_str() + str.length() - (pattern_v_length - 1), pattern_v.v._string->substr(1).c_str(), pattern_v_length - 1));
				}
			} else if((*pattern_v.v._string)[pattern_v_length - 1] == '%') {
				rslt = !(pattern_v.v_str_wildcard == 2 ?
					  strncasecmp_wildcard(str.c_str(), pattern_v.v._string->c_str(), pattern_v_length - 1, "_") :
					  strncasecmp(str.c_str(), pattern_v.v._string->c_str(), pattern_v_length - 1));
			} else {
				rslt = !(pattern_v.v_str_wildcard == 2 ?
					  strcasecmp_wildcard(str.c_str(), pattern_v.v._string->c_str(), "_") :
					  strcasecmp(str.c_str(), pattern_v.v._string->c_str()));
			}
			return(sValue(rslt));
		}
	}
	return(sValue(false));
}

cEvalFormula::sValue cEvalFormula::e(const char *formula, unsigned pos, unsigned length, unsigned level, sSplitOperands *splitOperands,
				     int operator_level_lt, int *pos_return) {
	if(!length) {
		length = strlen(formula + pos);
	}
	unsigned pos_max = pos + length - 1;
	sValue operand1;
	while(pos <= pos_max) {
		if(debug) debug_output(level, string("*** ") + (formula + pos));
		unsigned pos_operand1_end = 0;
		sOperator *operand1_u_operator = NULL;
		sValueStr operand1_bb;
		sSplitOperands *splitOperand1 = NULL;
		if(operand1.isEmpty()) {
			operand1 = getOperand(formula, pos, pos_max, &pos_operand1_end, &operand1_u_operator, splitOperands ? &splitOperand1 : NULL);
			if(!operand1.isEmpty()) {
				if(splitOperands) {
					splitOperands->addOperand(splitOperand1);
				}
			} else {
				operand1_bb = getBracketsBlock(formula, pos, pos_max, &pos_operand1_end, &operand1_u_operator);
			}
		} else {
			pos_operand1_end = pos;
		}
		if(debug) {
			if(!operand1.isEmpty()) {
				debug_output(level, "operand_1: " + operand1.getString());
			} else if(!operand1_bb.isEmpty()) {
				debug_output(level, "operand_1: (" + operand1_bb.getString() + ")");
			}
		}
		if(!operand1_bb.isEmpty()) {
			if(specEvalBB(&operand1_bb, &operand1, level, splitOperands ? &splitOperand1 : NULL)) {
				if(splitOperands) {
					splitOperands->addOperand(splitOperand1);
				}
				if(debug) debug_output(level, "operand_1_rslt: " + operand1.getString());
			} else {
				if(splitOperands) {
					splitOperand1 = new FILE_LINE(0) sSplitOperands(0);
				}
				operand1 = e(operand1_bb.str, operand1_bb.pos, operand1_bb.length, level + 1, splitOperands ? splitOperand1 : NULL);
				if(splitOperands) {
					splitOperands->addOperand(splitOperand1);
				}
				if(debug) debug_output(level, "operand_1_rslt: " + operand1.getString());
			}
		}
		if(operand1.isEmpty()) {
			return(sValue());
		} else if(operand1_u_operator) {
			operand1 = e_u_operator(operand1, operand1_u_operator);
			if(splitOperands) {
				splitOperands->u_operators[splitOperands->operands_count - 1] = operand1_u_operator->e_oper;
			}
			if(debug) debug_output(level, "operand_1_rslt: (" + string(operand1_u_operator->oper) + ") " + operand1.getString());
		}
		unsigned pos_operator1_end = 0;
		sOperator *operator1 = getB_Operator(formula, pos_operand1_end, pos_max, &pos_operator1_end);
		if(!operator1) {
			return(operand1);
		} else {
			if(pos_return &&
			   operator_level_lt >= 0 &&
			   operator1->level >= (unsigned)operator_level_lt) {
				 *pos_return = pos_operand1_end;
				 if(debug) debug_output(level, "<-");
				 return(operand1);
			}
			if(splitOperands) {
				splitOperands->b_operators[splitOperands->operands_count - 1] = operator1->e_oper;
			}
			if(debug) debug_output(level, "operator_1: " + string(operator1->oper) + " / " + intToString(operator1->level));
		}
		if(!splitOperands &&
		   (((operator1->flags & sOperator::_short_eval_and) && !operand1.getBool()) ||
		    ((operator1->flags & sOperator::_short_eval_or) && operand1.getBool()))) {
			if(debug) debug_output(level, "RSLT (short eval): " + operand1.getString());
			return(operand1);
		}
		unsigned pos_operand2_end = 0;
		sOperator *operand2_u_operator = NULL;
		sValueStr operand2_bb;
		sSplitOperands *splitOperand2 = NULL;
		sValue operand2 = getOperand(formula, pos_operator1_end, pos_max, &pos_operand2_end, &operand2_u_operator, splitOperands ? &splitOperand2 : NULL);
		if(operand2.isEmpty()) {
			operand2_bb = getBracketsBlock(formula, pos_operator1_end, pos_max, &pos_operand2_end, &operand2_u_operator);
		}
		if(operand2.isEmpty() && operand2_bb.isEmpty()) {
			return(operand1);
		}
		if(debug) {
			if(!operand2.isEmpty()) {
				debug_output(level, "operand_2: " + operand2.getString());
			} else if(!operand2_bb.isEmpty()) {
				debug_output(level, "operand_2: (" + operand2_bb.getString() + ")");
			}
		}
		unsigned pos_operator2_end = 0; 
		sOperator *operator2 = getB_Operator(formula, pos_operand2_end, pos_max, &pos_operator2_end);
		if(!(operator2 && operator2->level < operator1->level)) {
			if(!operand2_bb.isEmpty()) {
				if(specEvalBB(&operand2_bb, &operand2, level, splitOperands ? &splitOperand2 : NULL)) {
					if(splitOperands) {
						splitOperands->addOperand(splitOperand2);
					}
					if(debug) debug_output(level, "operand_2_rslt: " + operand2.getString());
				} else {
					if(splitOperands) {
						splitOperand2 = new FILE_LINE(0) sSplitOperands(0);
					}
					operand2 = e(operand2_bb.str, operand2_bb.pos, operand2_bb.length, level + 1, splitOperands ? splitOperand2 : NULL);
					if(splitOperands) {
						splitOperands->addOperand(splitOperand2);
					}
					if(debug) debug_output(level, "operand_2_rslt: " + operand2.getString());
				}
			} else {
				if(splitOperands && splitOperand2) {
					splitOperands->addOperand(splitOperand2);
				}
			}
			if(operand2_u_operator) {
				operand2 = e_u_operator(operand2, operand2_u_operator);
				if(splitOperands) {
					splitOperands->u_operators[splitOperands->operands_count - 1] = operand2_u_operator->e_oper;
				}
				if(debug) debug_output(level, "operand_2_rslt: (" + string(operand2_u_operator->oper) + ") " + operand2.getString());
			}
		}
		if(operator2) {
			if(debug) debug_output(level, "operator_2: " + string(operator2->oper) + " / " + intToString(operator2->level));
			if(operator2->level < operator1->level) {
				if(splitOperands) {
					if(splitOperand2) {
						delete splitOperand2;
					}
					splitOperand2 = new FILE_LINE(0) sSplitOperands(0);
				}
				int pos_return = -1;
				operand2 = e(formula, pos_operator1_end, 0, level + 1, splitOperands ? splitOperand2 : NULL,
					     operator1->level, &pos_return);
				if(splitOperands) {
					splitOperands->addOperand(splitOperand2);
				}
				sValue rslt = e_b_operator(operand1, operand2, operator1);
				if(debug) debug_output(level, "RSLT: " + rslt.getString());
				if(pos_return != -1) {
					operand1 = rslt;
					pos = pos_return;
				} else {
					return(rslt);
				}
			} else {
				operand1 = e_b_operator(operand1, operand2, operator1);
				pos = pos_operand2_end;
			}
		} else {
			sValue rslt = e_b_operator(operand1, operand2, operator1);
			if(debug) debug_output(level, "RSLT: " + rslt.getString());
			return(rslt);
		}
	}
	return(sValue());
}

cEvalFormula::sValue cEvalFormula::e(sSplitOperands *splitOperands) {
	return(splitOperands->e(this));
}

bool cEvalFormula::e_opt(sSplitOperands *splitOperands) {
	bool existsSpecType = false;
	bool opt = false;
	splitOperands->e_opt(this, 0, &existsSpecType, &opt);
	return(opt);
}

#define DEBUG_SO_E_OPT false

cEvalFormula::sValue cEvalFormula::sSplitOperands::e_opt(cEvalFormula *f, unsigned level, bool *existsSpecType, bool *opt) {
	if(existsSpecType) *existsSpecType = false;
	if(opt) *opt = false;
	if(type == 0) {
		if(operands_count) {
			sValue rslt, operand, *operand_pt;
			for(unsigned i = 0; i < operands_count; i++) {
				operand_pt = NULL;
				if(operands[i]->type == 0 &&
				   !operands[i]->operands_count) {
					operand_pt = &operands[i]->value;
					if(u_operators[i]) {
						operand = f->e_u_operator(*operand_pt, u_operators[i]);
						operand_pt = NULL;
						u_operators[i] = _o_na;
						operands[i]->value = operand;
					}
				} else {
					bool _existsSpecType;
					bool _opt;
					operand = operands[i]->e_opt(f, level + 1, &_existsSpecType, &_opt);
					if(_existsSpecType) {
						if(existsSpecType) *existsSpecType = true;
					}
					if(_opt) {
						if(opt) *opt = true;
					}
				}
				#if DEBUG_SO_E_OPT
				if(f->debug) f->debug_output(level, "operand: " + (operand_pt ? operand_pt : &operand)->getString());
				#endif
				if(u_operators[i]) {
					operand = f->e_u_operator(operand, u_operators[i]);
					#if DEBUG_SO_E_OPT
					if(f->debug) f->debug_output(level, "operand_rslt: (" + intToString(u_operators[i]) + ") " + operand.getString());
					#endif
				}
				if(i == 0) {
					if(operand_pt) {
						rslt = *operand_pt;
					} else {
						rslt.moveFrom(&operand);
					}
				} else {
					if(operand_pt) {
						rslt = f->e_b_operator(rslt, *operand_pt, b_operators[i - 1]);
					} else {
						rslt = f->e_b_operator(rslt, operand, b_operators[i - 1]);
					}
					#if DEBUG_SO_E_OPT
					if(f->debug) {
						f->debug_output(level, "operator: " + intToString(b_operators[i - 1]));
						f->debug_output(level, "rslt: " + rslt.getString());
					}
					#endif
				}
			}
			if(existsSpecType && !*existsSpecType) {
				value = rslt;
				clearOperands();
				if(opt) *opt = true;
			}
			#if DEBUG_SO_E_OPT
			if(f->debug) f->debug_output(level, "RSLT: " + rslt.getString());
			#endif
			return(rslt);
		} else {
			return(value);
		}
	} else if(type == 1) {
		sValue value;
		if(f->sql_data) {
			if(subType == _st_field) {
				value = 1;
				#if DEBUG_SO_E_OPT
				if(f->debug) f->debug_output(level, "subst: " + table + "." + column + " -> " + value.getString());
				#endif
				if(existsSpecType) *existsSpecType = true;
				return(value);
			} else if(subType == _st_subselect) {
				f->evalSqlSubselect(&table, &column, &cond, columnType, &value, level, 
						    &cond_s);
				#if DEBUG_SO_E_OPT
				if(f->debug) f->debug_output(level, "subselect rslt: " + value.getString());
				#endif
				if(existsSpecType) *existsSpecType = true;
				return(value);
			}
		}
		value.v_null = true;
		if(existsSpecType) *existsSpecType = false;
		return(value);
	}
	sValue value;
	value.v_null = true;
	return(value);
}

#define DEBUG_SO_E false

cEvalFormula::sValue cEvalFormula::sSplitOperands::e(cEvalFormula *f, unsigned level) {
	if(type == 0) {
		if(operands_count) {
			sValue rslt, operand, *operand_pt;
			for(unsigned i = 0; i < operands_count; i++) {
				if(i > 0 && b_operators[i - 1] &&
				   ((b_operators[i - 1] == _o_and && !rslt.getBool()) ||
				    (b_operators[i - 1] == _o_or && rslt.getBool()))) {
					break;
				}
				operand_pt = NULL;
				if(operands[i]->type == 0 &&
				   !operands[i]->operands_count) {
					operand_pt = &operands[i]->value;
					if(u_operators[i]) {
						operand = f->e_u_operator(*operand_pt, u_operators[i]);
						operand_pt = NULL;
						u_operators[i] = _o_na;
						operands[i]->value = operand;
					}
				} else {
					operand = operands[i]->e(f, level + 1);
				}
				#if DEBUG_SO_E
				if(f->debug) f->debug_output(level, "operand: " + (operand_pt ? operand_pt : &operand)->getString());
				#endif
				if(u_operators[i]) {
					operand = f->e_u_operator(operand, u_operators[i]);
					#if DEBUG_SO_E
					if(f->debug) f->debug_output(level, "operand_rslt: (" + intToString(u_operators[i]) + ") " + operand.getString());
					#endif
				}
				if(i == 0) {
					if(operand_pt) {
						rslt = *operand_pt;
					} else {
						rslt.moveFrom(&operand);
					}
				} else {
					if(operand_pt) {
						if((b_operators[i - 1] == _o_or || b_operators[i - 1] == _o_sql_eq) && rslt.v_type == _v_int && operand_pt->v_type == _v_int) {
							rslt.v._int = b_operators[i - 1] == _o_or ?
								       rslt.v._int || operand_pt->v._int :
								       rslt.v._int == operand_pt->v._int;
						} else {
							rslt = f->e_b_operator(rslt, *operand_pt, b_operators[i - 1]);
						}
					} else {
						if((b_operators[i - 1] == _o_or || b_operators[i - 1] == _o_sql_eq) && rslt.v_type == _v_int && operand.v_type == _v_int) {
							rslt.v._int = b_operators[i - 1] == _o_or ?
								       rslt.v._int || operand.v._int :
								       rslt.v._int == operand.v._int;
						} else {
							rslt = f->e_b_operator(rslt, operand, b_operators[i - 1]);
						}
					}
					#if DEBUG_SO_E
					if(f->debug) {
						f->debug_output(level, "operator: " + intToString(b_operators[i - 1]));
						f->debug_output(level, "rslt: " + rslt.getString());
					}
					#endif
				}
			}
			#if DEBUG_SO_E
			if(f->debug) f->debug_output(level, "RSLT: " + rslt.getString());
			#endif
			return(rslt);
		} else {
			return(value);
		}
	} else if(type == 1) {
		sValue value;
		if(f->sql_data) {
			if(subType == _st_field) {
				map<u_int32_t, sValue> *value_map = &((sChartsCacheCallData*)f->sql_data2)->value_map;
				if(ord.u.i) {
					ord.u.s.child_index = f->sql_child_index;
					map<u_int32_t, sValue>::iterator iter = value_map->find(ord.u.i);
					if(iter != value_map->end()) {
						return(iter->second);
					}
				}
				if(f->sql_data_type == _estd_call &&
				   (((sChartsCallData*)(f->sql_data))->type == sChartsCallData::_call ?
				    ((sChartsCallData*)(f->sql_data))->call()->sqlFormulaOperandReplace(&value, &table, &column, f->sql_data2,
													f->sql_child_table ? f->sql_child_table : NULL, f->sql_child_index, NULL) :
				    Call::sqlFormulaOperandReplace(((sChartsCallData*)(f->sql_data))->tables_content(),
								   &value, &table, &column, f->sql_data2,
								   f->sql_child_table ? f->sql_child_table : NULL, f->sql_child_index, NULL))) {
					#if DEBUG_SO_E
					if(f->debug) f->debug_output(level, "subst: " + table + "." + column + " -> " + value.getString());
					#endif
					if(ord.u.i) {
						(*value_map)[ord.u.i] = value;
					}
					return(value);
				}
			} else if(subType == _st_subselect) {
				f->evalSqlSubselect(&table, &column, &cond, columnType, &value, level, 
						    &cond_s);
				#if DEBUG_SO_E
				if(f->debug) f->debug_output(level, "subselect rslt: " + value.getString());
				#endif
				return(value);
			}
		}
		value.v_null = true;
		return(value);
	}
	sValue value;
	value.v_null = true;
	return(value);
}

void cEvalFormula::sSplitOperands::addOperand(sSplitOperands *operand) {
	sSplitOperands** operands_new = new FILE_LINE(0) sSplitOperands*[operands_count + 1];
	eOperator *u_operators_new = new FILE_LINE(0) eOperator[operands_count + 1];
	eOperator *b_operators_new = new FILE_LINE(0) eOperator[operands_count + 1];
	for(unsigned i = 0; i < operands_count; i++) {
		operands_new[i] = operands[i];
		u_operators_new[i] = u_operators[i];
		b_operators_new[i] = b_operators[i];
	}
	operands_new[operands_count] = operand;
	u_operators_new[operands_count] = _o_na;
	b_operators_new[operands_count] = _o_na;
	++operands_count;
	if(operands) delete [] operands;
	operands = operands_new;
	if(u_operators) delete [] u_operators;
	u_operators = u_operators_new;
	if(b_operators) delete [] b_operators;
	b_operators = b_operators_new;
}

void cEvalFormula::sSplitOperands::clearOperands() {
	if(operands) {
		for(unsigned i = 0; i < operands_count; i++) {
			delete operands[i];
		}
		delete [] operands;
		operands = NULL;
	}
	if(u_operators) {
		delete [] u_operators;
		u_operators = NULL;
	}
	if(b_operators) {
		delete b_operators;
		b_operators = NULL;
	}
	operands_count = 0;
}

cEvalFormula::sValue cEvalFormula::e_u_operator(sValue &operand, eOperator oper) {
	switch(oper) {
	case _o_not:
		return(!operand);
	case _o_sql_inet_aton:
	case _o_sql_inet6_aton:
		{
		vmIP ip;
		ip.setFromString(operand.getString().c_str());
		if(ip.is_v6()) {
			return(sValue(ip));
		} else  {
			return(sValue(ip.ip.v4.n));
		}
		}
		break;
	case _o_sql_coalesce:
		if(operand.v_type == _v_list) {
			if(operand.v._list && EF_VECTOR_VALUES(operand.v._list)->size() > 0) {
				for(unsigned i = 0; i < EF_VECTOR_VALUES(operand.v._list)->size(); i++) {
					if(!(*EF_VECTOR_VALUES(operand.v._list))[i].v_null) {
						return((*EF_VECTOR_VALUES(operand.v._list))[i]);
					}
				}
			} else {
				sValue rslt;
				rslt.v_null = true;
				return(rslt);
			}
		} else {
			return(operand);
		}
		break;
	case _o_sql_greatest:
	case _o_sql_least:
		if(operand.v_type == _v_list) {
			if(operand.v._list && EF_VECTOR_VALUES(operand.v._list)->size() > 0) {
				sValue rslt = (*EF_VECTOR_VALUES(operand.v._list))[0];
				for(unsigned i = 1; i < EF_VECTOR_VALUES(operand.v._list)->size(); i++) {
					if((oper == _o_sql_greatest ? (*EF_VECTOR_VALUES(operand.v._list))[i] > rslt : (*EF_VECTOR_VALUES(operand.v._list))[i] < rslt).getBool()) {
						rslt = (*EF_VECTOR_VALUES(operand.v._list))[i];
					}
					return(rslt);
				}
			} else {
				sValue rslt;
				rslt.v_null = true;
				return(rslt);
			}
		} else {
			return(operand);
		}
		break;
	case _o_sql_if:
		if(operand.v_type == _v_list && operand.v._list && EF_VECTOR_VALUES(operand.v._list)->size() == 3) {
			return((*EF_VECTOR_VALUES(operand.v._list))[0].getBool() ? (*EF_VECTOR_VALUES(operand.v._list))[1] : (*EF_VECTOR_VALUES(operand.v._list))[2]);
		} else {
			sValue rslt;
			rslt.v_null = true;
			return(rslt);
		}
		break;
	default:
		break;
	}
	return(sValue());
}

cEvalFormula::sValue cEvalFormula::e_u_operator(sValue &operand, sOperator *oper) {
	return(e_u_operator(operand, oper->e_oper));
}

cEvalFormula::sValue cEvalFormula::e_b_operator(sValue &operand1, sValue &operand2, eOperator oper) {
	switch(oper) {
	case _o_shift_l:
		return(operand1 << operand2);
	case _o_shift_r:
		return(operand1 >> operand2);
	case _o_b_and:
		return(operand1 & operand2);
	case _o_b_or:
		return(operand1 | operand2);
	case _o_mult:
		return(operand1 * operand2);
	case _o_div:
		return(operand1 / operand2);
	case _o_add:
		return(operand1 + operand2);
	case _o_sub:
		return(operand1 - operand2);
	case _o_cmp_lt:
		return(operand1 < operand2);
	case _o_cmp_le:
		return(operand1 <= operand2);
	case _o_cmp_gt:
		return(operand1 > operand2);
	case _o_cmp_ge:
		return(operand1 >= operand2);
	case _o_cmp_eq:
		return(operand1 == operand2);
	case _o_cmp_neq:
		return(operand1 != operand2);
	case _o_like:
		return(operand1.like(operand2));
	case _o_not_like:
		{
		sValue rslt_like = operand1.like(operand2);
		return(!rslt_like);
		}
	case _o_and:
		return(operand1 && operand2);
	case _o_or:
		return(operand1 || operand2);
	case _o_sql_div:
		if(operand1.v_type == _v_int && operand2.v_type == _v_int && operand2.v._int) {
			sValue rslt;
			rslt.v_type = _v_float;
			rslt.v._float = (double)operand1.v._int / operand2.v._int;
		}
		return(operand1 / operand2);
	case _o_sql_eq:
		return(operand1 == operand2);
	case _o_sql_is:
		return(sValue(operand1.v_null == operand2.v_null));
	case _o_sql_is_not:
		return(sValue(operand1.v_null != operand2.v_null));
	case _o_sql_in:
	case _o_sql_not_in:
		if(operand2.v_type == _v_list && operand2.v._list) {
			for(unsigned i = 0; i < EF_VECTOR_VALUES(operand2.v._list)->size(); i++) {
				if((operand1 == (*EF_VECTOR_VALUES(operand2.v._list))[i]).getBool()) {
					if(oper == _o_sql_in) {
						return(sValue(true));
					}
				}
			}
		} else if((operand1 == operand2).getBool()) {
			return(sValue(oper == _o_sql_in));
		}
		return(sValue(oper == _o_sql_not_in));
	case _o_sql_comma:
		{
		sValue rslt;
		if(operand1.v_type == _v_list) {
			rslt = operand1;
		} else {
			rslt.v_type = _v_list;
			rslt.v._list =  new FILE_LINE(0) vector<sValue>;
			rslt.v_dyn = true;
			EF_VECTOR_VALUES(rslt.v._list)->push_back(operand1);
		}
		EF_VECTOR_VALUES(rslt.v._list)->push_back(operand2);
		return(rslt);
		}
	default:
		break;
	}
	return(sValue());
}

cEvalFormula::sValue cEvalFormula::e_b_operator(sValue &operand1, sValue &operand2, sOperator *oper) {
	return(e_b_operator(operand1, operand2, oper->e_oper));
}

cEvalFormula::sValue cEvalFormula::getOperand(const char *formula, unsigned pos, unsigned pos_max, unsigned *pos_end, sOperator **u_operator, sSplitOperands **splitOperands) {
 	while(pos <= pos_max && isSpace(formula[pos])) {
		++pos;
	}
	unsigned _pos_end = 0;
	*u_operator = getU_Operator(formula, pos, pos_max, &_pos_end);
	if(*u_operator) {
		pos = _pos_end;
	}
 	while(pos <= pos_max && isSpace(formula[pos])) {
		++pos;
	}
	char typeOperand = 0;
	if(isDigit(formula[pos])) {
		typeOperand = 'n';
	} else if(formula[pos] == '"' || formula[pos] == '\'') {
		typeOperand = 's';
	} else if(enableSqlOperandReplace()) {
		typeOperand = 'r';
	} else {
		return(sValue());
	}
	unsigned length = 0;
	for(unsigned i = 0; (pos + i) <= pos_max; i++) {
		bool end = false;
		switch(typeOperand) {
		case 'n':
			if(isDigit(formula[pos + i])) {
				++length;
			} else {
				end = true;;
			}
			break;
		case 's':
			++length;
			if(i > 0 && formula[pos + i] == formula[pos]) {
				end = true;
			}
			break;
		case 'r':
			if(isOperandChar(formula[pos + i], i)) {
				++length;
			} else {
				end = true;
			}
			break;
		}
		if(end) {
			break;
		}
	}
	if(length) {
		if(typeOperand == 'r') {
			sValue v;
			if(sqlOperandReplace(&v, string(formula + pos, length), splitOperands)) {
				*pos_end = pos + length;
				return(v);
			}
		} else {
			sValue v;
			v = typeOperand == 'n' ?
			     (string(formula + pos, length).find('.') != string::npos ? 
			       sValue(atof(string(formula + pos, length).c_str())) :
			       sValue((int64_t)atoll(string(formula + pos, length).c_str()))) :
			     sValue(string(formula + pos + 1, length - 2));
			*pos_end = pos + length;
			if(splitOperands) {
				*splitOperands = new FILE_LINE(0) sSplitOperands(0);
				(*splitOperands)->value = v;
			}
			return(v);
		}
	}
	return(sValue());
}

cEvalFormula::sValueStr cEvalFormula::getBracketsBlock(const char *formula, unsigned pos, unsigned pos_max, unsigned *pos_end, sOperator **u_operator) {
 	while(pos <= pos_max && isSpace(formula[pos])) {
		++pos;
	}
	if(!isLeftBracket(formula[pos])) {
		unsigned _pos_end = 0;
		*u_operator = getU_Operator(formula, pos, pos_max, &_pos_end);
		if(*u_operator) {
			pos = _pos_end;
		}
	} else {
		*u_operator = NULL;
	}
 	while(pos <= pos_max && isSpace(formula[pos])) {
		++pos;
	}
	unsigned length = 0;
	int brackets = 0;
	for(unsigned i = 0; (pos + i) <= pos_max; i++) {
		if(brackets == 0 && length == 0 && isLeftBracket(formula[pos + i])) {
			brackets = 1;
			++length;
		} else if(isLeftBracket(formula[pos + i])) {
			++brackets;
			++length;
		} else if(isRightBracket(formula[pos + i])) {
			--brackets;
			++length;
			if(brackets == 0) {
				break;
			}
		} else {
			++length;
		}
	}
	if(length && brackets == 0) {
		*pos_end = pos + length;
		return(sValueStr(formula, pos + 1, length - 2));
	} else {
		return(sValueStr());
	}
}

cEvalFormula::sOperator *cEvalFormula::getU_Operator(const char *formula, unsigned pos, unsigned pos_max, unsigned *pos_end) {
 	while(pos <= pos_max && isSpace(formula[pos])) {
		++pos;
	}
	sOperator *oper;
	if(!isEndOperator(*(formula + pos)) &&
	   isOperator_u(formula + pos, &oper)) {
		*pos_end = pos + oper->length;
		return(oper);
	}
	return(NULL);
}

cEvalFormula::sOperator *cEvalFormula::getB_Operator(const char *formula, unsigned pos, unsigned pos_max, unsigned *pos_end) {
 	while(pos <= pos_max && isSpace(formula[pos])) {
		++pos;
	}
	sOperator *oper;
	if(!isEndOperator(*(formula + pos)) &&
	   isOperator_b(formula + pos, &oper)) {
		*pos_end = pos + oper->length;
		return(oper);
	}
	return(NULL);
}

bool cEvalFormula::isOperator_u(const char *try_operator, sOperator **oper) {
	if(evalSpecType == _est_sql) {
		_isOperator(u_operators_sql, try_operator, oper);
		if(*oper != NULL) {
			return(true);
		}
	}
	_isOperator(u_operators, try_operator, oper);
	return(*oper != NULL);
}

bool cEvalFormula::isOperator_b(const char *try_operator, sOperator **oper) {
	if(evalSpecType == _est_sql) {
		_isOperator(b_operators_sql, try_operator, oper);
		if(*oper != NULL) {
			return(true);
		}
	}
	_isOperator(b_operators, try_operator, oper);
	return(*oper != NULL);
}

void cEvalFormula::_isOperator(sOperator *table, const char *try_operator, sOperator **oper) {
	if(!table[0].length) {
		for(unsigned i = 0; table[i].oper; i++) {
			table[i].length = strlen(table[i].oper);
		}
	}
	*oper = NULL;
	unsigned length = 0;
	for(unsigned i = 0; table[i].oper; i++) {
		if(!strncasecmp(try_operator, table[i].oper, table[i].length) &&
		   (!(table[i].flags & sOperator::_need_end) || isEndOperator(*(try_operator + table[i].length))) &&
		   (!length || table[i].length > length)) {
			*oper = &table[i];
		}
	}
}

bool cEvalFormula::specEvalBB(sValueStr *bb, sValue *bb_rslt, unsigned level, sSplitOperands **splitOperands) {
	if(evalSpecType == _est_sql) {
		const char *posToTable;
		const char *posToCond;
		if(!strncasecmp(bb->str_pos(), "select ", 7) &&
		   (posToTable = strncasestr(bb->str_pos(), " from ", bb->length)) != NULL &&
		   (posToCond = strncasestr(bb->str_pos(), " where ", bb->length)) != NULL) {
			string column;
			string table;
			string cond;
			column = strlwr(string(bb->str_pos() + 7, posToTable - bb->str_pos() - 7));
			sSplitOperands::eColumnType column_type = column == "cdr_id" ? sSplitOperands::_ct_id :
								  column == "count(*)" ? sSplitOperands::_ct_count : 
								  column.find("max(") != string::npos ? sSplitOperands::_ct_max :
								  column.find("min(") != string::npos ? sSplitOperands::_ct_min :
								  sSplitOperands::_ct_na;
			if(column_type == sSplitOperands::_ct_max || column_type == sSplitOperands::_ct_min) {
				size_t pos_end = column.find(')');
				if(pos_end != string::npos) {
					column = column.substr(4, pos_end - 4);
				}
			}
			posToTable += 6;
			const char *posEndTable = posToTable;
			while(!isSpace(*posEndTable)) {
				++posEndTable;
			}
			table = strlwr(string(posToTable, posEndTable - posToTable));
			cond = string(posToCond + 7, bb->length - (posToCond - bb->str_pos()) - 7);
			if(splitOperands) {
				sSplitOperands *splitSqlOperands = new FILE_LINE(0) sSplitOperands(1);
				splitSqlOperands->subType = sSplitOperands::_st_subselect;
				splitSqlOperands->columnType = column_type;
				splitSqlOperands->table = table;
				splitSqlOperands->column = column;
				splitSqlOperands->cond = cond;
				*splitOperands = splitSqlOperands;
			}
			evalSqlSubselect(&table, &column, &cond, column_type, bb_rslt, level, NULL);
			return(true);
		}
	}
	return(false);
}

bool cEvalFormula::sqlOperandReplace(sValue *value, string operand, sSplitOperands **splitOperands) {
	if(!strcasecmp(operand.c_str(), "null")) {
		*value = sValue(0);
		value->v_null = true;
		if(splitOperands) {
			*splitOperands = new FILE_LINE(0) sSplitOperands(0);
			(*splitOperands)->value = *value;
		}
		return(true);
	}
	if(sql_data_type == _estd_call && sql_data) {
		string table;
		string column;
		size_t tableSeparatorPos = operand.find('.');
		if(tableSeparatorPos != string::npos) {
			table = operand.substr(0, tableSeparatorPos);
			column = operand.substr(tableSeparatorPos + 1);
		} else {
			column = operand;
		}
		if(table[0] == '`' && table[table.length() - 1] == '`') {
			table = table.substr(1, table.length() - 2);
		}
		if(column[0] == '`' && column[column.length() - 1] == '`') {
			column = column.substr(1, column.length() - 2);
		}
		transform(table.begin(), table.end(), table.begin(), ::tolower);
		transform(column.begin(), column.end(), column.begin(), ::tolower);
		sOperandReplaceData ord;
		if(((sChartsCallData*)sql_data)->type == sChartsCallData::_call ?
		    ((sChartsCallData*)sql_data)->call()->sqlFormulaOperandReplace(value, &table, &column, sql_data2, 
										   sql_child_table ? sql_child_table : NULL, sql_child_index, &ord) :
		    Call::sqlFormulaOperandReplace(((sChartsCallData*)sql_data)->tables_content(),
						   value, &table, &column, sql_data2, 
						   sql_child_table ? sql_child_table : NULL, sql_child_index, &ord)) {
			if(splitOperands) {
				sSplitOperands *splitSqlOperands = new FILE_LINE(0) sSplitOperands(1);
				splitSqlOperands->subType = sSplitOperands::_st_field;
				splitSqlOperands->table = table;
				splitSqlOperands->column = column;
				splitSqlOperands->ord = ord;
				*splitOperands = splitSqlOperands;
			}
			return(true);
		}
	}
	*value = sValue(operand);
	if(splitOperands) {
		*splitOperands = new FILE_LINE(0) sSplitOperands(0);
		(*splitOperands)->value = *value;
	}
	return(true);
}

bool cEvalFormula::evalSqlSubselect(string *table, string *column, string *cond, sSplitOperands::eColumnType column_type, sValue *rslt, unsigned level,
				    cEvalFormula::sSplitOperands **cond_s) {
	int childTableSize = 0;
	if(((sChartsCallData*)sql_data)->type == sChartsCallData::_call) {
		childTableSize = ((sChartsCallData*)sql_data)->call()->sqlChildTableSize(table, sql_data2);
	} else {
		childTableSize = ((sChartsCallData*)sql_data)->tables_content()->getCountRows(table->c_str());
	}
	if(childTableSize > 0) {
		unsigned count = 0;
		sValue rslt_value;
		for(int i = 0; i < childTableSize; i++) {
			setSqlChildIndex(table, i);
			sValue rslt_cond;
			if(!cond_s) {
				rslt_cond = e(cond->c_str(), 0, 0, level + 1);
			} else {
				if(!*cond_s) {
					*cond_s = new FILE_LINE(0) cEvalFormula::sSplitOperands(0);
					rslt_cond = e(cond->c_str(), 0, 0, level + 1, *cond_s);
				} else {
					rslt_cond = e(*cond_s);
				}
			}
			if(rslt_cond.getBool()) {
				++count;
				if(column_type == sSplitOperands::_ct_id) {
					break;
				}
				if(column_type == sSplitOperands::_ct_max || column_type == sSplitOperands::_ct_min) {
					sValue rslt_column;
					if(((sChartsCallData*)sql_data)->type == sChartsCallData::_call) {
						((sChartsCallData*)sql_data)->call()->sqlFormulaOperandReplace(&rslt_column, table, column, sql_data2, 
													       sql_child_table ? sql_child_table : NULL, sql_child_index, NULL);
					} else {
						Call::sqlFormulaOperandReplace(((sChartsCallData*)sql_data)->tables_content(), 
									       &rslt_column, table, column, sql_data2,
									       sql_child_table ? sql_child_table : NULL, sql_child_index, NULL);
					}
					if(count == 1) {
						rslt_value = rslt_column;
					} else {
						if((column_type == sSplitOperands::_ct_max ? rslt_column > rslt_value : rslt_column < rslt_value).getBool()) {
							rslt_value = rslt_column;
						}
					}
				}
			}
		}
		clearSqlChildIndex();
		if(count > 0) {
			switch(column_type) {
			case sSplitOperands::_ct_id:
				*rslt = sValue(1);
				rslt->v_id = true;
				break;
			case sSplitOperands::_ct_count:
				*rslt = sValue(count);
				break;
			case sSplitOperands::_ct_max:
			case sSplitOperands::_ct_min:
				*rslt = rslt_value;
				break;
			default:
				break;
			}
			return(true);
		} else {
			*rslt = sValue(false);
		}
	} else {
		*rslt = sValue(false);
	}
	return(false);
}

cEvalFormula::sOperator cEvalFormula::b_operators[] = {
	{  5, "<<", _o_shift_l }, { 5, ">>", _o_shift_r },
	{ 10, "&", _o_b_and }, { 10, "|", _o_b_or },
	{ 20, "*", _o_mult }, { 20, "/", _o_div },
	{ 30, "+", _o_add }, { 30, "-", _o_sub },
	{ 40, "<", _o_cmp_lt }, { 40, "<=", _o_cmp_le }, { 40, ">", _o_cmp_gt }, { 40, ">=", _o_cmp_ge }, { 40, "==", _o_cmp_eq }, { 40, "!=", _o_cmp_neq }, { 40, "<>", _o_cmp_neq }, 
	{ 40, "like", _o_like, sOperator::_need_end }, { 40, "not like", _o_not_like, sOperator::_need_end },
	{ 50, "&&", _o_and, sOperator::_short_eval_and },
	{ 60, "||", _o_or, sOperator::_short_eval_or },
	{ 70, "and", _o_and, sOperator::_short_eval_and | sOperator::_need_end },
	{ 80, "or", _o_or, sOperator::_short_eval_or | sOperator::_need_end },
	{  0, NULL, _o_na }
};

cEvalFormula::sOperator cEvalFormula::u_operators[] = {
	{ 0, "not", _o_not, sOperator::_need_end },
	{ 0, NULL, _o_na }
};

cEvalFormula::sOperator cEvalFormula::b_operators_sql[] = {
	{  20, "/", _o_sql_div },
	{  41, "is", _o_sql_is, sOperator::_need_end }, {  41, "is not", _o_sql_is_not, sOperator::_need_end },
	{  42, "=", _o_sql_eq }, 
	{  42, "in", _o_sql_in, sOperator::_need_end }, {  42, "not in", _o_sql_not_in, sOperator::_need_end },
	{ 100, ",", _o_sql_comma },
	{   0, NULL, _o_na }
};

cEvalFormula::sOperator cEvalFormula::u_operators_sql[] = {
	{ 0, "inet_aton", _o_sql_inet_aton, sOperator::_need_end }, 
	{ 0, "inet6_aton", _o_sql_inet6_aton, sOperator::_need_end },
	{ 0, "coalesce", _o_sql_coalesce, sOperator::_need_end },
	{ 0, "greatest", _o_sql_greatest, sOperator::_need_end },
	{ 0, "least", _o_sql_least, sOperator::_need_end },
	{ 0, "if", _o_sql_if, sOperator::_need_end },
	{ 0, NULL, _o_na }
};


bool matchResponseCode(int code, int size, int testCode) {
	if(testCode > 0) {
		int lrn = testCode;
		while(lrn && (log10int(lrn) + 1) > size) {
			lrn /= 10;
		}
		if(lrn == code) {
			return(true);
		}
	} else if(testCode == 0 && code == 0) {
		return(true);
	}
	return(false);
}

bool matchResponseCodes(std::vector<pair<int, int> > & sipInfoCodes, int testCode) {
	for (uint i = 0; i < sipInfoCodes.size(); i++) {
		if (matchResponseCode(sipInfoCodes.at(i).first, sipInfoCodes.at(i).second, testCode)) {
			return(true);
		}
	}
	return(false);
}

std::vector<pair<int,int> > getResponseCodeSizes(std::vector<int> & Codes) {
	std::vector<pair<int, int> > elems;
	for (uint i = 0; i < Codes.size(); i++) {
		if (Codes.at(i) > 0) {
			elems.push_back(make_pair(Codes.at(i), log10int(Codes.at(i)) + 1));
		} else {
			elems.push_back(make_pair(Codes.at(i),1));
		}
	}
	return(elems);
}

int log10int(int v) {
    return (v >= 1000000000) ? 9 : (v >= 100000000) ? 8 :
        (v >= 10000000) ? 7 : (v >= 1000000) ? 6 :
        (v >= 100000) ? 5 : (v >= 10000) ? 4 :
        (v >= 1000) ? 3 : (v >= 100) ? 2 : (v >= 10) ? 1 : 0;
}

int log10int(long int v) {
	if (v <= 0) {
		return(0);
	}
	int l = 0;
	while(v > 0) {
		v /= 10;
		++l;
	}
	return(l - 1);
}


unsigned RTPSENSOR_VERSION_INT() {
	unsigned version_num = 0;
	vector<string> version_split = split(string(RTPSENSOR_VERSION), '.');
	if(version_split.size()) {
		for(unsigned i = 0; i < min((unsigned)version_split.size(), 3u); i++) {
			version_num += atoi(version_split[i].c_str()) * (i == 0 ? 1000000 : i == 1 ? 1000 : 1);
		}
	}
	return(version_num);
}


void rss_purge(bool force) {
	#ifndef FREEBSD
		malloc_trim(0);
		if(sverb.malloc_trim) {
			syslog(LOG_NOTICE, "malloc trim");
		}
	#endif
		
	#if HAVE_LIBTCMALLOC
		bool tcmalloc_need_purge = false;
		if(force) {
			tcmalloc_need_purge = true;
		} else {
			extern int opt_memory_purge_if_release_gt;
			extern u_int64_t all_ringbuffers_size;
			size_t allocated_bytes = 0;
			MallocExtension::instance()->GetNumericProperty("generic.current_allocated_bytes", &allocated_bytes);
			size_t rss = getRss();
			int64_t release_size = rss - all_ringbuffers_size - allocated_bytes;
			if(release_size > (int64_t)MIN(opt_memory_purge_if_release_gt * 1024 * 1024, getTotalMemory() / 10)) {
				tcmalloc_need_purge = true;
			}
		}
		if(tcmalloc_need_purge) {
			MallocExtension::instance()->ReleaseFreeMemory();
			if(sverb.malloc_trim) {
				syslog(LOG_NOTICE, "tcmalloc release free memory");
			}
		}
	#endif
		
	#if HAVE_LIBJEMALLOC
		size_t mib[3];
		size_t miblen = sizeof(mib)/sizeof(size_t);
		mallctlnametomib("arena.0.purge", mib, &miblen);
		mib[1] = MALLCTL_ARENAS_ALL; //(size_t)arena_ind
		mallctlbymib(mib, miblen, NULL, NULL, NULL, 0);
		if(sverb.malloc_trim) {
			syslog(LOG_NOTICE, "jemalloc purge memory");
		}
	#endif
}


void parse_cmd_str(const char *cmd_str, vector<string> *args) {
	char *ptr_cmd_str = (char*)cmd_str;
	char *ptr_arg = NULL;
	char border = 0;
	while(*ptr_cmd_str) {
		if(*ptr_cmd_str == ' ' || *ptr_cmd_str == '\t') {
			if(!border && ptr_arg) {
				args->push_back(string(ptr_arg, ptr_cmd_str - ptr_arg));
				ptr_arg = NULL;
			}
		} else if(*ptr_cmd_str == '"' || *ptr_cmd_str == '\'') {
			if(*ptr_cmd_str == border) {
				args->push_back(string(ptr_arg, ptr_cmd_str - ptr_arg));
				ptr_arg = NULL;
				border = 0;
			} else {
				ptr_arg = ptr_cmd_str + 1;
				border = *ptr_cmd_str;
			}
		} else if(!ptr_arg) {
			ptr_arg = ptr_cmd_str;
		}
		++ptr_cmd_str;
	}
	if(ptr_arg) {
		args->push_back(string(ptr_arg, ptr_cmd_str - ptr_arg));
	}
}

string tmpnam() {
	char tmpfilename_buffer[TMP_MAX];
	u_int64_t ns;
	struct stat sbuf;
	for (int i = 0; i < 3; i++) {
		ns = getTimeNS();
		snprintf(tmpfilename_buffer, sizeof(tmpfilename_buffer), "%s/VM%i_%lu", P_tmpdir, get_unix_tid(), ns);
		if (stat(tmpfilename_buffer, &sbuf) < 0 && errno == ENOENT) {
			return(tmpfilename_buffer);
		}
	}
	return("");
}

bool file_get_contents(const char *filename, SimpleBuffer *content, string *error) {
	FILE *file = fopen(filename, "r");
	if(!file) {
		if(error) {
			*error = string("failed open file: ") + filename;
		}
		return(false);
	}
	char buffer[10000];
	unsigned length;
	while((length = fread(buffer, 1, sizeof(buffer), file)) > 0) {
		content->add(buffer, length);
	}
	fclose(file);
	return(true);
}

bool file_put_contents(const char *filename, SimpleBuffer *content, string *error) {
	FILE *file = fopen(filename, "w");
	if(!file) {
		if(error) {
			*error = string("failed open file for write: ") + filename;
		}
		return(false);
	}
	unsigned write_length = 0;
	while(write_length < content->size()) {
		unsigned _write_length = fwrite(content->data() + write_length, 1, content->size() - write_length, file);
		if(_write_length > 0) {
			write_length += _write_length;
		} else {
			if(error) {
				*error = string("failed write to: ") + filename;
			}
			fclose(file);
			return(false);
		}
	}
	fclose(file);
	return(true);
}

bool getInterfaceOption(const char *param, const char *searchstr, const char *iface, char sep, char *result) {
	char buff[512];
	char *ret;
	snprintf(buff, sizeof(buff), "ethtool %s %s 2>&1", param, iface);
	FILE *cmd_pipe = popen(buff, "r");
	do {
		if(!fgets(buff, 512, cmd_pipe)) {
			ret = NULL;
			break;
		}
	} while (!(ret = strstr(buff, searchstr)));
	pclose(cmd_pipe);
	if (ret) {
		char *p = strrchr(buff, sep);
		if(p) {
			strncpy(result, ++p, 512);
			return(true);
		}
	}
	printf("Can't get value from 'ethtool %s %s'. This is not a fatal error. Some NICs don't support it.\n", param, iface);
	syslog(LOG_NOTICE, "Can't get value from 'ethtool %s %s'. This is not a fatal error. Some NICs don't support it.", param, iface);
	return(false);
}

void setInterfaceOption(const char *param, const char *option, const char *iface, int value) {
	char cmd[512];
	int retval;
	string buff;
	snprintf(cmd, sizeof(cmd), "ethtool %s %s %s %i 2>&1", param, iface, option, value);
	buff = pexec(cmd, &retval);
	if (retval == 0 || (retval / 0xff) == 80 /* same value */) {
		printf("'ethtool %s %s %s %i' successful.\n", param, iface, option, value);
		syslog(LOG_NOTICE, "'ethtool %s %s %s %i' successful.", param, iface, option, value);
	} else {
		printf("Can't set interface 'ethtool %s %s %s %i': %i. This is not a fatal error. Some NICs don't support it.\n", param, iface, option, value, retval);
		syslog(LOG_NOTICE, "Can't set interface 'ethtool %s %s %s %i': %i. This is not a fatal error. Some NICs don't support it.", param, iface, option, value, retval);
	}
}

void handleInterfaceOptions(void) {
	if(!ifnamev.size()) {
		return;
	}
	if(!isEthtoolInstalled()) {
		printf("ethtool binary is not installed - NIC's parameters can't be set. This is not a fatal error.\n");
		syslog(LOG_NOTICE, "ethtool binary is not installed - NIC's parameters can't be set. This is not a fatal error.");
		return;
	}
	for(std::vector<string>::iterator iface = ifnamev.begin(); iface != ifnamev.end(); iface++) {
		char rslt[512];
		if(getInterfaceOption("-g", "RX:", (*iface).c_str(), '\t', rslt)) {
			int maxval = atoi(rslt);
			if (maxval > 0) {
				setInterfaceOption("-G", "rx", (*iface).c_str(), maxval);
			}
		}
		if(getInterfaceOption("-c", "rx-usecs:", (*iface).c_str(), ' ', rslt)) {
			int curval = atoi(rslt);
			if(curval < 500) {
				setInterfaceOption("-C", "rx-usecs", (*iface).c_str(), 1022);
			}
		}
	}
}

long getSwapUsage(int pid) {
	char buff[128];
	snprintf(buff, sizeof(buff), "/proc/%i/smaps", pid);
	FILE *smaps = fopen(buff, "r");
	if(!smaps) {
		if(errno == EACCES) {
			return(-2);
		}
		syslog(LOG_ERR, "Can't open smaps file %s: errno %i", buff, errno);
		return(-1);
	}
	long swapSize = 0;
	while(fgets(buff, sizeof(buff), smaps)) {
		if(strstr(buff, "Swap:")) {
			char *p = strchr(buff, ' ');
			if (p) {
				unsigned int i = atoi(p);
				swapSize += i;
			}
		}
	}
	fclose(smaps);
	return(swapSize);
}

pid_t findMysqlProcess(void) {
	char buff[16];
	FILE *cmd_pipe = popen("pgrep 'mysqld$'", "r");
	int retval = 0;
	if(cmd_pipe) {
		if (fgets(buff, sizeof(buff), cmd_pipe)) {
			retval = atoi(buff);
		}
		pclose(cmd_pipe);
	}
	return(retval);
}

/* we have 10sec loop */
#define SEVEN_DAYS 60480
#define ONE_HOUR 360
void checkMysqlSwapUsage(void) {
	extern int swapMysqlDelayCount;
	if(!mysqlPid) {
		mysqlPid = findMysqlProcess();
		if(!mysqlPid) {
			syslog(LOG_INFO, "Mysql's pid not found so mysql's swap usage will not be checked for next seven days.");
			swapMysqlDelayCount = SEVEN_DAYS;
			return;
		}
	}
	long swapSize = getSwapUsage(mysqlPid);
	if(swapSize == -1) { /* mysql restart ?! zero pid  */
		mysqlPid = 0;
	} else if(swapSize == -2) {
		mysqlPid = 0;
		syslog(LOG_INFO, "I don't have privileges to read mysql's smaps file so mysql's swap usage will not be checkedi for next seven days.");
		swapMysqlDelayCount = SEVEN_DAYS;
	} else if (swapSize > 0) {
		char note[256];
		snprintf(note, sizeof(note), "The mysql's memory is in the swap (%li KB). This can lead to performance degradation. Please consider to disable the swap. For more info see http://www.voipmonitor.org/doc/Swap", swapSize);
		cLogSensor::log(cLogSensor::notice, note);
		swapMysqlDelayCount = SEVEN_DAYS;
	} else {
		swapMysqlDelayCount = ONE_HOUR;
	}
}

void checkSwapUsage(void) {
	extern int swapDelayCount;
	pid_t pid = getpid();
	long swapSize = getSwapUsage(pid);
	if (swapSize > 0) {
		char note[256];
		snprintf(note, sizeof(note), "The sensor's memory is in the swap (%li KB). This can lead to performance degradation. Please consider to disable the swap. For more info see http://www.voipmonitor.org/doc/Swap", swapSize);
		cLogSensor::log(cLogSensor::notice, note);
		swapDelayCount = SEVEN_DAYS;
	} else {
		swapDelayCount = ONE_HOUR;
	}
}
