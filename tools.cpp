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
#include <sys/time.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <syslog.h>
#include <sys/ioctl.h> 
#include <sys/sendfile.h>

#include <algorithm> // for std::min
#include <iostream>

#include "calltable.h"
#include "rtp.h"
#include "tools.h"
#include "md5.h"

extern char mac[32];
extern int verbosity;

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
	int s, res;
	struct ifreq buffer;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if(s == -1) {
		printf("Opening socket failed\n");
		return;
	}
	memset(&buffer, 0x00, sizeof(buffer));
	strcpy(buffer.ifr_name, "eth0");
	res = ioctl(s, SIOCGIFHWADDR, &buffer);
	close(s);

	sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
		0xff & buffer.ifr_hwaddr.sa_data[0],
		0xff & buffer.ifr_hwaddr.sa_data[1],
		0xff & buffer.ifr_hwaddr.sa_data[2],
		0xff & buffer.ifr_hwaddr.sa_data[3],
		0xff & buffer.ifr_hwaddr.sa_data[4],
		0xff & buffer.ifr_hwaddr.sa_data[5]);
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
	int renamedebug = 1;

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
	fdatasync(read_fd);
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
	fdatasync(write_fd);
	posix_fadvise(write_fd, 0, 0, POSIX_FADV_DONTNEED);
	/* Blast the bytes from one file to the other. */
	int res = sendfile(write_fd, read_fd, &offset, stat_buf.st_size);
	unsigned long long bytestransfered = stat_buf.st_size;
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

unsigned long long GetFileSize(std::string filename)
{
	struct stat stat_buf;
	int rc = stat(filename.c_str(), &stat_buf);
	return rc == 0 ? stat_buf.st_size : -1;
}

unsigned long long GetFileSizeDU(std::string filename)
{
	return(GetDU(GetFileSize(filename)));
}

unsigned long long GetDU(unsigned long long fileSize) {
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

string GetFileMD5(std::string filename) {
	string md5;
	unsigned long long fileSize = GetFileSize(filename);
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

bool PcapDumper::open(const char *fileName, const char *fileNameSpoolRelative) {
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
	extern int pcap_dlink;
	extern pcap_t *handle;
	extern pcap_t *handle_dead_EN10MB;
	extern int opt_convert_dlt_sll_to_en10;
	pcap_t *_handle = pcap_dlink ==DLT_LINUX_SLL && opt_convert_dlt_sll_to_en10 && handle_dead_EN10MB ? 
			   handle_dead_EN10MB : 
			   handle;
	this->capsize = 0;
	this->size = 0;
	this->handle = pcap_dump_open(_handle, fileName);
	++this->openAttempts;
	if(!this->handle) {
		if(this->type != rtp || !this->openError) {
			syslog(LOG_NOTICE, "pcapdumper: error open dump handle to file %s: %s", fileName, pcap_geterr(handle));
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
		pcap_dump((u_char*)this->handle, header, packet);
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
		pcap_dump_flush(this->handle);
		pcap_dump_close(this->handle);
		if(updateFilesQueue && this->call) {
			this->call->addtofilesqueue(this->fileNameSpoolRelative.c_str(), 
						    type == rtp ? "rtpsize" : 
						    call->type == REGISTER ? "regsize" : "sipsize",
						    this->capsize + PCAP_DUMPER_HEADER_SIZE);
			extern char opt_cachedir[1024];
			if(opt_cachedir[0] != '\0') {
				this->call->addtocachequeue(this->fileNameSpoolRelative.c_str());
			}
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
	this->size = 0;
}

RtpGraphSaver::~RtpGraphSaver() {
	if(this->isOpen()) {
		this->close(this->updateFilesQueueAtClose);
	}
}

bool RtpGraphSaver::open(const char *fileName, const char *fileNameSpoolRelative) {
	if(this->isOpen()) {
		this->close(this->updateFilesQueueAtClose);
		syslog(LOG_NOTICE, "graphsaver: reopen %s -> %s", this->fileName.c_str(), fileName);
	}
	if(file_exists((char*)fileName)) {
		if(verbosity > 2) {
			syslog(LOG_NOTICE,"graphsaver: [%s] already exists, not overwriting", fileName);
		}
	}
	if(opt_gzipGRAPH) {
		this->streamgz.open(fileName);
	} else {
		this->stream.open(fileName);
	}
	if(!this->isOpen()) {
		syslog(LOG_NOTICE, "graphsaver: error open file %s", fileName);
	}
	this->size = 0;
	this->fileName = fileName;
	this->fileNameSpoolRelative = fileNameSpoolRelative;
	return(this->isOpen());

}

void RtpGraphSaver::write(char *buffer, int length) {
	if(this->isOpen()) {
		if(opt_gzipGRAPH) {
			this->streamgz.write(buffer, length);
			//// !!!! size
		} else {
			this->stream.write(buffer, length);
			this->size += length;
		}
	}
}

void RtpGraphSaver::close(bool updateFilesQueue) {
	if(this->isOpen()) {
		if(opt_gzipGRAPH) {
			this->streamgz.close();
		} else {
			this->stream.close();
		}
		if(updateFilesQueue) {
			if(this->rtp->call_owner) { 
				((Call*)this->rtp->call_owner)->addtofilesqueue(this->fileNameSpoolRelative.c_str(), "graphsize", this->size);
				extern char opt_cachedir[1024];
				if(opt_cachedir[0] != '\0') {
					((Call*)this->rtp->call_owner)->addtocachequeue(this->fileNameSpoolRelative.c_str());
				}
			} else {
				syslog(LOG_ERR, "graphsaver: gfilename[%s] does not have owner", this->fileNameSpoolRelative.c_str());
			}
		}
	}
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
	if(url.find("http://voipmonitor.org") == 0 ||
	   url.find("http://www.voipmonitor.org") == 0) {
		url = "https" + url.substr(4);
		okUrl = true;
	} else if(url.find("https://voipmonitor.org") == 0 ||
		  url.find("https://www.voipmonitor.org") == 0) {
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
		this->errorString = "failed create temp name for output wget and gunzip";
		return(false);
	}
	string binaryFilepathName = this->upgradeTempFileName + "/voipmonitor";
	string binaryGzFilepathName = this->upgradeTempFileName + "/voipmonitor.gz";
	string wgetCommand = "wget " + url + "/voipmonitor.gz." + (this->_64bit ? "64" : "32") + 
			     " -O " + binaryGzFilepathName +
			     " --no-check-certificate" +
			     " >" + outputStdoutErr + " 2>&1";
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
		rmdir_r(this->upgradeTempFileName.c_str());
		return(false);
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
