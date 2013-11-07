#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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

#include <algorithm> // for std::min
#include <iostream>

#include "calltable.h"
#include "rtp.h"
#include "tools.h"

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
	}
	return(fileSize);
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


PcapDumper::PcapDumper(eTypePcapDump type, class Call *call, bool updateFilesQueueAtClose) {
	this->type = type;
	this->call = call;
	this->updateFilesQueueAtClose = updateFilesQueueAtClose;
	this->capsize = 0;
	this->size = 0;
	this->handle = NULL;
}

PcapDumper::~PcapDumper() {
	if(this->handle) {
		this->close(this->updateFilesQueueAtClose);
	}
}

bool PcapDumper::open(const char *fileName) {
	if(this->handle) {
		this->close(this->updateFilesQueueAtClose);
		syslog(LOG_NOTICE, "pcapdumper: reopen %s -> %s", this->fileName.c_str(), fileName);
	}
	if(file_exists((char*)fileName)) {
		if(verbosity > 2) {
			syslog(LOG_NOTICE,"pcapdumper: [%s] already exists, do not overwriting", fileName);
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
	if(!this->handle) {
		syslog(LOG_NOTICE, "pcapdumper: error open dump handle to file %s: %s", fileName, pcap_geterr(handle));
	}
	this->fileName = fileName;
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
			this->call->addtofilesqueue(this->fileName.c_str(), 
						    type == rtp ? "rtpsize" : 
						    call->type == REGISTER ? "regsize" : "sipsize",
						    this->capsize + PCAP_DUMPER_HEADER_SIZE);
			extern char opt_cachedir[1024];
			if(opt_cachedir[0] != '\0') {
				this->call->addtocachequeue(this->fileName.c_str());
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

bool RtpGraphSaver::open(const char *fileName) {
	if(this->isOpen()) {
		this->close(this->updateFilesQueueAtClose);
		syslog(LOG_NOTICE, "graphsaver: reopen %s -> %s", this->fileName.c_str(), fileName);
	}
	if(file_exists((char*)fileName)) {
		if(verbosity > 2) {
			syslog(LOG_NOTICE,"graphsaver: [%s] already exists, do not overwriting", fileName);
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
				((Call*)this->rtp->call_owner)->addtofilesqueue(this->fileName.c_str(), "graphsize", this->size);
				extern char opt_cachedir[1024];
				if(opt_cachedir[0] != '\0') {
					((Call*)this->rtp->call_owner)->addtocachequeue(this->fileName.c_str());
				}
			} else {
				syslog(LOG_ERR, "graphsaver: gfilename[%s] does not have owner", this->fileName.c_str());
			}
		}
	}
}