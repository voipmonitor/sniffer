#include "voipmonitor.h"

#ifdef FREEBSD
#include <sys/types.h>
#include <netinet/in.h>
#endif

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
#include <json.h>
#include <iomanip>
#include <openssl/sha.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>

#ifdef FREEBSD
#include <sys/uio.h>
#include <sys/thr.h>
#else
#include <sys/sendfile.h>
#endif

#include <algorithm> // for std::min
#include <iostream>

#include "tools_dynamic_buffer.h"
#include "calltable.h"
#include "rtp.h"
#include "tools.h"
#include "md5.h"
#include "pcap_queue.h"
#include "sql_db.h"
#include "tar.h"
#include "tools.h"
#include "config.h"
#include "cleanspool.h"


using namespace std;


volatile unsigned int glob_tar_queued_files;

extern int opt_pcap_dump_tar_compress_sip; //0 off, 1 gzip, 2 lzma
extern int opt_pcap_dump_tar_sip_level;
extern int opt_pcap_dump_tar_compress_rtp;
extern int opt_pcap_dump_tar_rtp_level;
extern int opt_pcap_dump_tar_compress_graph;
extern int opt_pcap_dump_tar_graph_level;
extern int opt_pcap_dump_tar_threads;

extern int opt_filesclean;
extern int opt_nocdr;
extern int verbosity;

extern MySqlStore *sqlStore;
extern int opt_blocktarwrite;

extern int terminated_async;
extern int terminated_tar_flush_queue[2];
extern int terminated_tar[2];


void data_tar::set(int typeSpoolFile, Call_abstract *call, const char *fileName) {
	this->sensorName = call->get_sensordir();
	struct tm t = time_r(&call->first_packet_time);
	this->year = t.tm_year + 1900;
	this->mon = t.tm_mon + 1;
	this->day = t.tm_mday;
	this->hour = t.tm_hour;
	this->minute = t.tm_min;
	this->typeSpoolFile = typeSpoolFile;
	const char *file = strrchr(fileName, '/');
	this->filename = file + 1;
}


/* magic, version, and checksum */
void
Tar::th_finish()
{
	int i, sum = 0;

	strncpy(tar.th_buf.magic, "ustar", 6);
	strncpy(tar.th_buf.version, "  ", 2);
//	strncpy(tar.th_buf.magic, "ustar  ", 8);

	for (i = 0; i < T_BLOCKSIZE; i++)
		sum += ((char *)(&(tar.th_buf)))[i];
	for (i = 0; i < 8; i++)
		sum += (' ' - tar.th_buf.chksum[i]);
	int_to_oct(sum, tar.th_buf.chksum, 8);
}

/* encode file path */
void
Tar::th_set_path(char *pathname, bool partSuffix)
{
#ifdef DEBUG
	printf("in th_set_path(th, pathname=\"%s\")\n", pathname);
#endif  

	if (tar.th_buf.gnu_longname != NULL)
		free(tar.th_buf.gnu_longname);
	tar.th_buf.gnu_longname = NULL;
	
	/* classic tar format */
	
	snprintf(tar.th_buf.name, 100, "%s", pathname);
	
	/*
	map<string, u_int32_t>::iterator it = partCounter.find(pathname);
	if(it == partCounter.end()) {
		partCounter[pathname] = 1;
		++partCounterSize;
	} else {
		++partCounter[pathname];
	}
	*/
	++partCounter;
	if(partSuffix) {
		char suffix[20];
		snprintf(suffix, sizeof(suffix), "#%lu", partCounter);
		if(strlen(tar.th_buf.name) + strlen(suffix) > 100 - 1) {
			tar.th_buf.name[100 - 1 - strlen(suffix)] = 0;
		}
		strcat(tar.th_buf.name, suffix);
	}
	       
#ifdef DEBUG   
	puts("returning from th_set_path()...");
#endif 
}

/* map a file mode to a typeflag */
void
Tar::th_set_type(mode_t /*mode*/)
{       
	tar.th_buf.typeflag = 0; // regular file
}


/* encode device info */
void
Tar::th_set_device(dev_t device)
{
#ifdef DEBUG
	printf("th_set_device(): major = %d, minor = %d\n",
	       major(device), minor(device));
#endif 
	int_to_oct(major(device), tar.th_buf.devmajor, 8);
	int_to_oct(minor(device), tar.th_buf.devminor, 8);
}


/* encode user info */
void
Tar::th_set_user(uid_t uid)
{
	/*  slow function getpwuid - disabled
	struct passwd *pw;

	pw = getpwuid(uid);
	if (pw != NULL)
		*((char *)mempcpy(tar.th_buf.uname, pw->pw_name, sizeof(tar.th_buf.uname))) = '\0';
	*/

	int_to_oct(uid, tar.th_buf.uid, 8);
}


/* encode group info */
void
Tar::th_set_group(gid_t gid)
{

/*
	struct group *gr;

	gr = getgrgid(gid);
	if (gr != NULL)
		*((char *)mempcpy(tar.th_buf.gname, gr->gr_name, sizeof(tar.th_buf.gname))) = '\0';
*/

	int_to_oct(gid, tar.th_buf.gid, 8);
}


/* encode file mode */
void
Tar::th_set_mode( mode_t fmode)
{      
	int_to_oct(fmode, tar.th_buf.mode, 8);
}


/* calculate header checksum */
int    
Tar::th_crc_calc()
{
	int i, sum = 0;

	for (i = 0; i < T_BLOCKSIZE; i++)
		sum += ((unsigned char *)(&(tar.th_buf)))[i];
	for (i = 0; i < 8; i++)
		sum += (' ' - (unsigned char)tar.th_buf.chksum[i]);
       
	return sum;
}      

	       
/* string-octal to integer conversion */
int
Tar::oct_to_int(char *oct)
{
	int i;
       
	sscanf(oct, "%o", &i);

	return i;
}


/* integer to string-octal conversion, no NULL */
void   
Tar::int_to_oct_nonull(int num, char *oct, size_t octlen)
{      
	snprintf(oct, (unsigned long)octlen, "%*lo", (int)octlen - 1, (unsigned long)num);
	oct[octlen - 1] = ' ';
}

int
Tar::tar_init(int oflags, int options)
{
	memset(&tar, 0, sizeof(TAR));
	
	tar.options = options;
//	tar.type = (type ? type : &default_type);
	tar.oflags = oflags;

/*
	if ((oflags & O_ACCMODE) == O_RDONLY)
		tar.h = libtar_hash_new(256, (libtar_hashfunc_t)path_hashfunc);
	else
		tar.h = libtar_hash_new(16, (libtar_hashfunc_t)dev_hash);
*/
	return 0;
}

/* open a new tarfile handle */
int     
Tar::tar_open(string pathname, int oflags, int options)
{       
	this->pathname = pathname;
	this->open_flags = oflags;
	if (tar_init(oflags, options) == -1)
		return -1;

	if ((options & TAR_NOOVERWRITE) && (oflags & O_CREAT))
		oflags |= O_EXCL;

	if((oflags & O_CREAT) && file_exists(pathname)) {
		int i = 1;
		while(i < 100) {
			stringstream newpathname;
			newpathname << this->pathname;
			newpathname << "." << i;
			if(file_exists(newpathname.str())) {
				++i;
				continue;
			} else {
				rename(pathname.c_str(), newpathname.str().c_str());
				if(sverb.tar) {
					syslog(LOG_NOTICE, "tar: renaming %s -> %s", pathname.c_str(), newpathname.str().c_str());
				}
				break;
			}
		}
	}
	tar.fd = open((char*)this->pathname.c_str(), 
		      oflags | 
		      #ifndef FREEBSD
		      O_LARGEFILE
		      #else
		      0
		      #endif
		      , spooldir_file_permission());
	if (tar.fd == -1)
	{
		return -1;
	}
	if(oflags & O_CREAT) {
		spooldir_chown(tar.fd);
	}
	return 0;
}

/* write a header block */
int
Tar::th_write()
{
	int i;
	th_finish();
	i = tar_block_write((const char*)&(tar.th_buf), T_BLOCKSIZE);
	if (i != T_BLOCKSIZE)
	{	       
//		if (i != -1)    
//			errno = EINVAL;
		return -1;
	}
		
#ifdef DEBUG    
	puts("th_write(): returning 0");
#endif	       
	return 0;      
}		       

/* add file contents to a tarchive */
int
Tar::tar_append_buffer(ChunkBuffer *buffer, size_t lenForProceed)
{
	buffer->chunkIterate(this, true, true, lenForProceed);
	return 0;
}

void 
Tar::chunkbuffer_iterate_ev(char *data, u_int32_t len, u_int32_t pos) {
	if(data) {
		tar_block_write(data, len);
	} else if(pos % T_BLOCKSIZE) {
		char zeroblock[T_BLOCKSIZE];
		memset(zeroblock, 0, T_BLOCKSIZE - pos % T_BLOCKSIZE);
		tar_block_write(zeroblock, T_BLOCKSIZE - pos % T_BLOCKSIZE);
	}
}

void
Tar::tar_read(const char *filename, const char *endFilename, u_int32_t recordId, const char *tableType, const char *tarPosString) {
	bool enableDetectTarPos = true;
	if(!reg_match(this->pathname.c_str(), "tar\\.gz", __FILE__, __LINE__) &&
	   !reg_match(this->pathname.c_str(), "tar\\.xz", __FILE__, __LINE__)) {
		this->readData.send_parameters_zip = false;
	} else {
		enableDetectTarPos = false;
		if(flushTar(this->pathname.c_str())) {
			syslog(LOG_NOTICE, "flush %s in tar_read", this->pathname.c_str());
		}
	}
	this->readData.null();
	this->readData.filename = filename;
	this->readData.endFilename = endFilename;
	this->readData.init(T_BLOCKSIZE * 64);
	CompressStream *decompressStream = new FILE_LINE(34001) CompressStream(reg_match(this->pathname.c_str(), "tar\\.gz", __FILE__, __LINE__) ?
									 CompressStream::gzip :
									reg_match(this->pathname.c_str(), "tar\\.xz", __FILE__, __LINE__) ?
									 CompressStream::lzma :
									 CompressStream::compress_na,
									this->readData.bufferBaseSize, 0);
	size_t read_position = 0;
	size_t read_size;
	char *read_buffer = new FILE_LINE(34002) char[T_BLOCKSIZE];
	bool decompressFailed = false;
	list<u_int64_t> tarPos;
	if(tarPosString && *tarPosString && *tarPosString != 'x') {
		vector<string> tarPosStr = split(tarPosString, ",");
		for(size_t i = 0; i < tarPosStr.size(); i++) {
			tarPos.push_back(atoll(tarPosStr[i].c_str()));
		}
	} else {
		if(recordId && tableType && !strcmp(tableType, "cdr") &&
		   enableDetectTarPos) {
			SqlDb *sqlDb = createSqlObject();
			sqlDb->setMaxQueryPass(2);
			SqlDb_row row;
			char queryBuff[1000];
			snprintf(queryBuff, sizeof(queryBuff), "SELECT calldate FROM cdr where id = %u", recordId);
			sqlDb->query(queryBuff);
			if((row = sqlDb->fetchRow())) {
				snprintf(queryBuff, sizeof(queryBuff),
					"SELECT pos FROM cdr_tar_part where cdr_id = %u and calldate = '%s' and type = %i", 
					recordId, row["calldate"].c_str(),
					strstr(this->pathname.c_str(), "/SIP/") ? 1 :
					strstr(this->pathname.c_str(), "/RTP/") ? 2 :
					strstr(this->pathname.c_str(), "/GRAPH/") ? 3 : 0);
				sqlDb->query(queryBuff);
				while((row = sqlDb->fetchRow())) {
					cout << "fetch tar position: " << atoll(row["pos"].c_str()) << endl;
					tarPos.push_back(atoll(row["pos"].c_str()));
				}
			}
			delete sqlDb;
		}
	}
	if(tarPos.size()) {
		for(list<u_int64_t>::iterator it = tarPos.begin(); it != tarPos.end(); it++) {
			if(sizeof(int) == 4) {
				int counterSeek = 0;
				u_int64_t seekPos = *it;
				while(seekPos) {
					u_int64_t _seek = min((unsigned long long)seekPos, 2000000000ull);
					if(lseek(tar.fd, _seek, counterSeek ? SEEK_CUR : SEEK_SET) == -1) {
						this->readData.error = true;
						break;
					}
					seekPos -= _seek;
					++counterSeek;
				}
			} else {
				if(lseek(tar.fd, *it, SEEK_SET) == -1) {
					this->readData.error = true;
				}
			}
			if(this->readData.error) {
				break;
			}
			read_position = *it;
			this->readData.oneFile = true;
			this->readData.end = false;
			this->readData.bufferLength = 0;
			while(!this->readData.end && !this->readData.error && (read_size = read(tar.fd, read_buffer, T_BLOCKSIZE)) > 0) {
				read_position += read_size;
				u_int32_t use_len = 0;
				unsigned int counter_pass = 0;
				while(use_len < read_size) {
					if(counter_pass) {
						decompressStream->termDecompress();
					}
					u_int32_t _use_len = 0;
					if(!decompressStream->decompress(read_buffer + use_len, read_size - use_len, 0, false, this, &_use_len)) {
						decompressFailed = true;
						break;
					}
					if(counter_pass && !_use_len) {
						break;
					}
					use_len += _use_len;
					++counter_pass;
				}
				if(decompressFailed) {
					break;
				}
			}
			if(decompressFailed || this->readData.error) {
				break;
			}
		}
	} else {
		bool tryNextDecompressBlock = false;
		while(!this->readData.end && !this->readData.error && (read_size = read(tar.fd, read_buffer, T_BLOCKSIZE)) > 0) {
			bool findNextDecompressBlock = false;
			size_t read_size_for_decompress = read_size;
			if(decompressStream->getTypeCompress() == CompressStream::gzip) {
				while(read_size_for_decompress > GZIP_HEADER_LENGTH + GZIP_HEADER_CHECK_LENGTH &&
				      GZIP_HEADER_CHECK(read_buffer, 0) &&
				      GZIP_HEADER_CHECK(read_buffer, GZIP_HEADER_LENGTH)) {
					char *new_read_buffer = new FILE_LINE(34003) char[T_BLOCKSIZE];
					memcpy(new_read_buffer, read_buffer + GZIP_HEADER_LENGTH, read_size - GZIP_HEADER_LENGTH);
					delete [] read_buffer;
					read_buffer = new_read_buffer;
					read_size_for_decompress -= GZIP_HEADER_LENGTH;
				}
				if(read_size > GZIP_HEADER_CHECK_LENGTH) {
					for(size_t pos = 1; pos < read_size - GZIP_HEADER_CHECK_LENGTH; pos ++) {
						if(GZIP_HEADER_CHECK(read_buffer, pos)) {
							read_size = pos;
							read_size_for_decompress = pos;
							lseek(tar.fd, read_position + read_size, SEEK_SET);
							findNextDecompressBlock = true;
							break;
						}
					}
				}
			}
			read_position += read_size;
			u_int32_t use_len = 0;
			unsigned int counter_pass = 0;
			while(use_len < read_size_for_decompress) {
				if(counter_pass) {
					decompressStream->termDecompress();
					if(decompressFailed && tryNextDecompressBlock) {
						decompressStream->clearError();
						decompressFailed = false;
						tryNextDecompressBlock = false;
						--counter_pass;
					}
				}
				u_int32_t _use_len = 0;
				if(decompressStream->decompress(read_buffer + use_len, read_size_for_decompress - use_len, 0, false, this, &_use_len)) {
					if(counter_pass && !_use_len) {
						break;
					}
					use_len += _use_len;
				} else {
					decompressFailed = true;
					if(counter_pass || !tryNextDecompressBlock) {
						break;
					}
				}
				++counter_pass;
			}
			if(decompressFailed && decompressStream->getTypeCompress() != CompressStream::gzip) {
				break;
			}
			tryNextDecompressBlock = findNextDecompressBlock;
		}
	}
	delete [] read_buffer;
	delete decompressStream;
	if(this->readData.compressStreamToGzip) {
		this->readData.compressStreamToGzip->compress(NULL, 0, true, &this->readData);
	}
	this->readData.term();
}

void 
Tar::tar_read_send_parameters(int client, void *sshchannel, void *c_client, bool zip) {
	this->readData.send_parameters_client = client;
	this->readData.send_parameters_sshchannel = sshchannel;
	this->readData.send_parameters_c_client = c_client;
	this->readData.send_parameters_zip = zip;
}

void 
Tar::tar_read_save_parameters(FILE *output_file_handle) {
	this->readData.output_file_handle = output_file_handle;
}

bool 
Tar::decompress_ev(char *data, u_int32_t len) {
	if(len != T_BLOCKSIZE ||
	   this->readData.bufferLength) {
		memcpy_heapsafe(this->readData.buffer + this->readData.bufferLength, this->readData.buffer,
				data, data,
				len,
				__FILE__, __LINE__);
		this->readData.bufferLength += len;
		if(this->readData.bufferLength >= T_BLOCKSIZE) {
			for(unsigned int i = 0; i < this->readData.bufferLength / T_BLOCKSIZE; i++) {
				this->tar_read_block_ev(this->readData.buffer + i * T_BLOCKSIZE);
				this->readData.position += len;
			}
			if(this->readData.bufferLength % T_BLOCKSIZE) {
				memcpy_heapsafe(this->readData.buffer, this->readData.buffer,
						this->readData.buffer + (this->readData.bufferLength - this->readData.bufferLength % T_BLOCKSIZE), this->readData.buffer,
						this->readData.bufferLength % T_BLOCKSIZE,
						__FILE__, __LINE__);
				this->readData.bufferLength = this->readData.bufferLength % T_BLOCKSIZE;
			} else {
				this->readData.bufferLength = 0;
			}
		}
	} else {
		this->tar_read_block_ev(data);
		this->readData.position += T_BLOCKSIZE;
	}
	return(true);
}

void 
Tar::tar_read_block_ev(char *data) {
	if(this->readData.end) {
		return;
	}
	if(this->readData.position &&
	   this->readData.fileSize < this->readData.fileHeader.get_size()) {
		size_t len = this->readData.fileSize + T_BLOCKSIZE > this->readData.fileHeader.get_size() ? 
			      this->readData.fileHeader.get_size() % T_BLOCKSIZE :
			      T_BLOCKSIZE;
		this->tar_read_file_ev(this->readData.fileHeader, data, this->readData.fileSize, len);
		this->readData.fileSize += len;
		if(this->readData.oneFile && this->readData.fileSize >= this->readData.fileHeader.get_size()) {
			this->readData.end = true;
		}
	} else {
		if(this->readData.position) {
			this->tar_read_file_ev(this->readData.fileHeader, NULL, this->readData.fileSize, 0);
			this->readData.nullFileHeader();
		}
		memcpy(&this->readData.fileHeader, data, min((u_int32_t)T_BLOCKSIZE, (u_int32_t)sizeof(this->readData.fileHeader)));
		/*
		cout << "tar_read_block_ev - header - file "
		     << this->readData.fileHeader.name
		     << " size "
		     << this->readData.fileHeader.get_size() << endl;
		*/
		this->readData.fileSize = 0;
	}
}

extern int _sendvm(int socket, void *channel, void *c_client, const char *buf, size_t len, int mode);
void 
Tar::tar_read_file_ev(tar_header fileHeader, char *data, u_int32_t /*pos*/, u_int32_t len) {
	int cmpLengthNameInTar = strlen(fileHeader.name);
	if(reg_match(fileHeader.name, "#[0-9]+$", __FILE__, __LINE__) ||
	   reg_match(fileHeader.name, "_[0-9]{1,6}$", __FILE__, __LINE__)) {
		while(isdigit(fileHeader.name[cmpLengthNameInTar - 1])) {
			--cmpLengthNameInTar;
		}
		--cmpLengthNameInTar;
	}
	if(strncmp(fileHeader.name, this->readData.filename.c_str(), cmpLengthNameInTar)) {
		return;
	}
	if(len) {
		if(!this->readData.decompressStreamFromLzo) {
			this->readData.decompressStreamFromLzo = new FILE_LINE(34004) CompressStream(CompressStream::compress_auto, 0, 0);
			this->readData.decompressStreamFromLzo->enableAutoPrefixFile();
			this->readData.decompressStreamFromLzo->enableForceStream();
		}
		if(!this->readData.compressStreamToGzip) {
			this->readData.compressStreamToGzip = new FILE_LINE(34005) CompressStream(this->readData.send_parameters_zip ? CompressStream::gzip : CompressStream::compress_na, 0, 0);
		}
		if(this->readData.decompressStreamFromLzo->isError() ||
		   this->readData.compressStreamToGzip->isError()) {
			this->readData.error = true;
		} else {
			this->readData.decompressStreamFromLzo->decompress(data, len, 0, false, &this->readData);
		}
	} else if(fileHeader.name[0]) {
		cout << "tar_read_block_ev - header - file "
		     << fileHeader.name
		     << " size "
		     << fileHeader.get_size() << endl;
	}
	if(*fileHeader.name && !len) {
		if(!this->readData.endFilename.empty()) {
			if(fileHeader.name == this->readData.endFilename) {
				this->readData.end = true;
			}
		} else if(!this->readData.filename.empty()) {
			if(fileHeader.name == this->readData.filename) {
				this->readData.end = true;
			}
		}
	}
}

int    
Tar::initZip() {
	if(!this->zipStream) {
		this->zipStream =  new FILE_LINE(34006) z_stream;
		this->zipStream->zalloc = Z_NULL;
		this->zipStream->zfree = Z_NULL;
		this->zipStream->opaque = Z_NULL;
		if(deflateInit2(this->zipStream, gziplevel, Z_DEFLATED, MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
			deflateEnd(this->zipStream);
			//this->setError("zip initialize failed");
			return(false);
		} else {
			this->zipBufferLength = 8192*4;
			this->zipBuffer = new FILE_LINE(34007) char[this->zipBufferLength];
		}
	}
	return(true);
}
       
bool
Tar::flushZip() {
	if(!writeCounter || writeCounterFlush >= writeCounter) {
		return(false);
	}
	do {
		this->zipStream->avail_out = this->zipBufferLength;
		this->zipStream->next_out = (unsigned char*)this->zipBuffer;
		if(deflate(this->zipStream, Z_FINISH)) {
			int have = this->zipBufferLength - this->zipStream->avail_out;
			if(::write(tar.fd, (const char*)this->zipBuffer, have) <= 0) {
				//this->setError();
				break;
			};
		}
	} while(this->zipStream->avail_out == 0);
	writeCounterFlush = writeCounter;
	return(true);
}	

int
Tar::writeZip(const void *buf, size_t len) {
	int flush = 0;
	if(!this->initZip()) {
		return(false);
	}      
	++writeCounter;
	this->zipStream->avail_in = len;
	this->zipStream->next_in = (unsigned char*)buf;
	do {
		this->zipStream->avail_out = this->zipBufferLength;
		this->zipStream->next_out = (unsigned char*)this->zipBuffer;

		if(deflate(this->zipStream, flush ? Z_FINISH : Z_NO_FLUSH) != Z_STREAM_ERROR) {
			int have = this->zipBufferLength - this->zipStream->avail_out;
			if(::write(tar.fd, (const char*)this->zipBuffer, have) <= 0) {
				//this->setError();
				return(false);
			};     
		} else {
			//this->setError("zip deflate failed");
			return(false);
		}      
	} while(this->zipStream->avail_out == 0);
	return(true);
}      

#ifdef HAVE_LIBLZMA
int
Tar::initLzma() {
	if(!this->lzmaStream) {
		/* initialize xz encoder */
		//uint32_t preset = LZMA_COMPRESSION_LEVEL | (LZMA_COMPRESSION_EXTREME ? LZMA_PRESET_EXTREME : 0);
		lzma_stream lzstmp = LZMA_STREAM_INIT;
		lzmaStream = new FILE_LINE(34008) lzma_stream;
		*lzmaStream = lzstmp;

		int ret_xz = lzma_easy_encoder (this->lzmaStream, lzmalevel, LZMA_CHECK_CRC64);
		if (ret_xz != LZMA_OK) {
			fprintf (stderr, "lzma_easy_encoder error: %d\n", (int) ret_xz);
			return(false);
		} else {
			this->zipBufferLength = 8192*4;
			this->zipBuffer = new FILE_LINE(34009) char[this->zipBufferLength];
		}
	}
	return(true);
}

bool 
Tar::flushLzma() {
	if(!writeCounter || writeCounterFlush >= writeCounter) {
		return(false);
	}
	int ret_xz;
//	this->lzmaStream->next_in = NULL;
//	this->lzmaStream->avail_in = 0;
	do {
		this->lzmaStream->avail_out = this->zipBufferLength;
		this->lzmaStream->next_out = (unsigned char*)this->zipBuffer;
		ret_xz = lzma_code(this->lzmaStream, LZMA_FINISH);
		if(ret_xz == LZMA_STREAM_END) {
			int have = this->zipBufferLength - this->lzmaStream->avail_out;
			if(::write(tar.fd, (const char*)this->zipBuffer, have) <= 0) {
				//this->setError();
				break;
			};
			break;
		}
		int have = this->zipBufferLength - this->lzmaStream->avail_out;
		if(::write(tar.fd, (const char*)this->zipBuffer, have) <= 0) {
			//this->setError();
			break;
		};
	} while(1);
	writeCounterFlush = writeCounter;
	return(true);
}	

int
Tar::writeLzma(const void *buf, size_t len) {
	int ret_xz;
	if(!this->initLzma()) {
		return(false);
	}
	++writeCounter;
	this->lzmaStream->next_in = (const uint8_t*)buf;
	this->lzmaStream->avail_in = len;
	do {
		this->lzmaStream->next_out = (unsigned char*)this->zipBuffer;
		this->lzmaStream->avail_out = this->zipBufferLength;

		/* compress data */
		ret_xz = lzma_code(lzmaStream, LZMA_RUN);

		if ((ret_xz != LZMA_OK) && (ret_xz != LZMA_STREAM_END)) {
			fprintf (stderr, "lzma_code error: %d\n", (int) ret_xz);
			return LZMA_RET_ERROR_COMPRESSION;
		} else {
			int have = this->zipBufferLength - this->lzmaStream->avail_out;
			if(::write(tar.fd, (const char*)this->zipBuffer, have) <= 0) {
				//this->setError();
				return(false);
			}
		}
	} while(this->lzmaStream->avail_out == 0);
	return(true);
}      
#endif

bool
Tar::flush() {
	tarlock();
	bool _flush = false;
#ifdef HAVE_LIBLZMA
	if(this->lzmaStream) {
		if(this->flushLzma()) {
			lzma_end(this->lzmaStream);
			delete this->lzmaStream;
			delete this->zipBuffer;
			this->lzmaStream = NULL;
			this->zipBuffer = NULL;
			this->initLzma();
			_flush = true;
		}
	}
#endif
	if(this->zipStream) {
		if(this->flushZip()) {
			deflateEnd(this->zipStream);
			delete this->zipStream;
			delete this->zipBuffer;
			this->zipStream = NULL;
			this->zipBuffer = NULL;
			this->initZip();
			_flush = true;
		}
	}
	if(_flush && sverb.tar) {
		syslog(LOG_NOTICE, "force flush %s", this->pathname.c_str());
	}
	tarunlock();
	return(_flush);
}

int
Tar::tar_block_write(const char *buf, u_int32_t len){
	while(opt_blocktarwrite) {
		sleep(1);
	}
	int zip = false;
	int lzma = false;
	switch(tar.qtype) {
	case 1:
		if(opt_pcap_dump_tar_compress_sip == 1) {
			gziplevel = opt_pcap_dump_tar_sip_level;
			zip = true;
		} else if(opt_pcap_dump_tar_compress_sip == 2) {
			lzmalevel = opt_pcap_dump_tar_sip_level;
			lzma = true;
		}
		break;
	case 2:
		if(opt_pcap_dump_tar_compress_rtp == 1) {
			gziplevel = opt_pcap_dump_tar_rtp_level;
			zip = true;
		} else if(opt_pcap_dump_tar_compress_rtp == 2) {
			lzmalevel = opt_pcap_dump_tar_rtp_level;
			lzma = true;
		}
		break;
	case 3:
		if(opt_pcap_dump_tar_compress_graph == 1) {
			gziplevel = opt_pcap_dump_tar_graph_level;
			zip = true;
		} else if(opt_pcap_dump_tar_compress_graph == 2) {
			lzmalevel = opt_pcap_dump_tar_graph_level;
			lzma = true;
		}
		break;
	}
	
	if(zip) {
		writeZip((char *)(buf), len);
	} else if(lzma){
		#ifdef HAVE_LIBLZMA
		writeLzma((char *)(buf), len);
		#endif //HAVE_LIBLZMA
	} else {
		::write(tar.fd, (char *)(buf), len);
	}
	
	this->lastWriteTime = getTimeS();
	this->tarLength += len;
	
	return(len);
};

void Tar::tar_close() {
	if(this->open_flags != O_RDONLY) {
		char zeroblock[T_BLOCKSIZE];
		memset(zeroblock, 0, T_BLOCKSIZE);
		tar_block_write(zeroblock, T_BLOCKSIZE);
		tar_block_write(zeroblock, T_BLOCKSIZE);
		if(this->zipStream) {
			flushZip();
			deflateEnd(this->zipStream);
			delete this->zipStream;
		}
	#ifdef HAVE_LIBLZMA
		if(this->lzmaStream) {
			flushLzma();
			lzma_end(this->lzmaStream);
			delete this->lzmaStream;
			this->lzmaStream = NULL;
		}
	#endif
		if(this->zipBuffer) {
			delete [] this->zipBuffer;
		}
		addtofilesqueue();
		if(sverb.tar) { 
			syslog(LOG_NOTICE, "tar %s destroyd (destructor)\n", pathname.c_str());
		}
	}
	close(tar.fd);
}

void Tar::addtofilesqueue() {

	if(!opt_filesclean or opt_nocdr or !isSqlDriver("mysql") or !CleanSpool::isSetCleanspoolParameters(spoolIndex)) return;

	long long size = 0;
	size = GetFileSizeDU(pathname.c_str(), typeSpoolFile, spoolIndex);

	if(size == (long long)-1) {
		//error or file does not exists
		char buf[4092];
		buf[0] = '\0';
		strerror_r(errno, buf, 4092);
		syslog(LOG_ERR, "addtofilesqueue ERROR file[%s] - error[%d][%s]", pathname.c_str(), errno, buf);
		return;
	}

	if(size == 0) {
		// if the file has 0 size we still need to add it to cleaning procedure
		size = 1;
	}

	extern CleanSpool *cleanSpool[2];
	if(cleanSpool[spoolIndex]) {
		char sdirname[12];
		snprintf(sdirname, 11, "%04d%02d%02d%02d",  time.year, time.mon, time.day, time.hour);
		sdirname[11] = 0;
		cleanSpool[spoolIndex]->addFile(sdirname, this->typeSpoolFile, pathname.c_str(), size);
	}
}

Tar::~Tar() {
	tar_close();
}

bool Tar::ReadData::decompress_ev(char *data, u_int32_t len) {
	this->compressStreamToGzip->compress(data, len, false, this);
	return(true);
}

bool Tar::ReadData::compress_ev(char *data, u_int32_t len, u_int32_t /*decompress_len*/, bool /*format_data*/) {
	if(this->output_file_handle) {
		fwrite(data, len, 1, this->output_file_handle);
	} else if(this->send_parameters_client || this->send_parameters_sshchannel || this->send_parameters_c_client) {
		if(_sendvm(this->send_parameters_client, this->send_parameters_sshchannel, this->send_parameters_c_client, data, len, 0) == -1) {
			this->compressStreamToGzip->setError("send error");
			return(false);
		}
	}
	return(true);
}

void			   
TarQueue::add(data_tar *tar_data, ChunkBuffer *buffer, unsigned int time){
	__sync_add_and_fetch(&glob_tar_queued_files, 1);
	data_t data;
	data.setDataTar(tar_data);
	data.buffer = buffer;
	data.time = time;
	lock();
	int queue_data_index = -1;
	switch(data.typeSpoolFile) {
	case tsf_sip:
	case tsf_reg:
	case tsf_skinny:
	case tsf_mgcp:
	case tsf_ss7:
		queue_data_index = 1;
		break;
	case tsf_rtp:
		queue_data_index = 2;
		break;
	case tsf_graph:
		queue_data_index = 3;
		break;
	}
	if(queue_data_index >= 0) {
		if(queue_data[queue_data_index].find(data) == queue_data[queue_data_index].end()) {
			queue_data[queue_data_index][data] = new FILE_LINE(0) vector<data_t>;
		}
		queue_data[queue_data_index][data]->push_back(data);
	}
	//if(sverb.tar) syslog(LOG_NOTICE, "adding tar %s len:%u\n", filename.c_str(), buffer->len);
	unlock();
}      

string
qtype2str(int qtype) {
	if(qtype == 1) return "sip";
	else if(qtype == 2) return "rtp";
	else if(qtype == 3) return "graph";
	else return "all";
}

string
qtype2strC(int qtype) {
	if(qtype == 1) return "SIP";
	else if(qtype == 2) return "RTP";
	else if(qtype == 3) return "GRAPH";
	else return "ALL";
}

eTypeSpoolFile
qtype2typeSpoolFile(int qtype) {
	if(qtype == 1) return tsf_sip;
	else if(qtype == 2) return tsf_rtp;
	else if(qtype == 3) return tsf_graph;
	else return tsf_all;
}


int			    
TarQueue::write(int qtype, data_t data) {
	stringstream tar_dir, tar_name;
	eTypeSpoolFile typeSpoolFile = qtype2typeSpoolFile(qtype);
	tar_dir << getSpoolDir(typeSpoolFile) << "/";
	if(!data.sensorName.empty()) {
		tar_dir << data.sensorName << "/";
	}
	tar_dir << setfill('0') 
		<< setw(4) << data.year << setw(1) << "-" << setw(2) << data.mon << setw(1) << "-" << setw(2) << data.day << setw(1) << "/" 
		<< setw(2) << data.hour << setw(1) << "/" 
		<< setw(2) << data.minute << setw(1) << "/" 
		<< setw(0) << qtype2strC(qtype);
	tar_name << tar_dir.str() << "/"
		 << qtype2str(qtype) << "_";
	if(!data.sensorName.empty()) {
		tar_name << data.sensorName << "_";
	}
	tar_name << setfill('0') 
		 << setw(4) << data.year << setw(1) << "-" << setw(2) << data.mon << setw(1) << "-" << setw(2) << data.day << setw(1) << "-" 
		 << setw(2) << data.hour << setw(1) << "-" << setw(2) << data.minute << ".tar";
	switch(qtype) {
	case 1:
		switch(opt_pcap_dump_tar_compress_sip) {
		case 1:
			tar_name << ".gz";
			break;
		case 2:
			tar_name << ".xz";
			break;
		}
		break;
	case 2:
		switch(opt_pcap_dump_tar_compress_rtp) {
		case 1:
			tar_name << ".gz";
			break;
		case 2:
			tar_name << ".xz";
			break;
		}
		break;
	case 3:
		switch(opt_pcap_dump_tar_compress_graph) {
		case 1:
			tar_name << ".gz";
			break;
		case 2:
			tar_name << ".xz";
			break;
		}
		break;
	}
	spooldir_mkdir(tar_dir.str());
	//printf("tar_name %s\n", tar_name.str().c_str());
       
	pthread_mutex_lock(&tarslock);
	Tar *tar = tars[tar_name.str()];
	if(!tar) {
		tar = new FILE_LINE(34010) Tar;
		tar->typeSpoolFile = typeSpoolFile;
		lock_okTarPointers();
		okTarPointers[tar] = getTimeS();
		unlock_okTarPointers();
		if(sverb.tar) {
			syslog(LOG_NOTICE, "new tar %s\n", tar_name.str().c_str());
			syslog(LOG_NOTICE, "add tar pointer %lx\n", (long)tar);
		}
		tars[tar_name.str()] = tar;
		pthread_mutex_unlock(&tarslock);
		tar->tar_open(tar_name.str(), O_WRONLY | O_CREAT | O_APPEND, TAR_GNU);
		tar->tar.qtype = qtype;
		tar->time = data;
		tar->created_at = data.time;
		tar->spoolIndex = spoolIndex;
		tar->sensorName = data.sensorName;
		
		tar->thread_id = tarThreadCounter[qtype] % maxthreads;
		++tarThreadCounter[qtype];
		
		if(sverb.tar) {
			syslog(LOG_NOTICE, "tar %s to thread %i", tar->pathname.c_str(), tar->thread_id);
		}
		
	} else {
		pthread_mutex_unlock(&tarslock);
	}
     
	data.tar = tar;
	tarthreads[tar->thread_id].qlock();
//	printf("push id:%u\n", tar->thread_id);
	if(tarthreads[tar->thread_id].queue_data.find(tar_name.str()) == tarthreads[tar->thread_id].queue_data.end()) {
		tarthreads[tar->thread_id].queue_data[tar_name.str()] = new FILE_LINE(0) tarthreads_tq;
	}
	tarthreads[tar->thread_id].queue_data[tar_name.str()]->push_back(data);
	tarthreads[tar->thread_id].qunlock();
	return 0;
}

#if TAR_PROF
unsigned long long __prof_processData_sum_1 = 0;
unsigned long long __prof_processData_sum_2 = 0;
unsigned long long __prof_processData_sum_3 = 0;
unsigned long long __prof_processData_sum_4 = 0;
unsigned long long __prof_processData_sum_5 = 0;
#endif

void *TarQueue::tarthreadworker(void *arg) {
	TarQueue *this2 = ((tarthreadworker_arg*)arg)->tq;
	tarthreads_t *tarthread = &this2->tarthreads[((tarthreadworker_arg*)arg)->i];
	tarthread->thread_id = ((tarthreadworker_arg*)arg)->i;
	delete (tarthreadworker_arg*)arg;

	tarthread->threadId = get_unix_tid();

	while(1) {
		int terminate_pass = terminated_tar_flush_queue[this2->spoolIndex];
		while(1) {
			bool doProcessData = false;
			if(tarthread->queue_data.empty()) { 
				if(this2->terminate) {
					return NULL;
				}
			} else {
				/*
				Tar *maxTar = tarthread->getTarWithMaxLen(2, false);
				if(!maxTar) {
					maxTar = tarthread->getTarWithMaxLen(false, false);
				}
				if(!maxTar) {
					break;
				}
				Tar *processTar = maxtar;
				*/
				
				#if TAR_PROF
				static unsigned counter;
				++counter;
				unsigned long long __prof_begin = rdtsc();
				unsigned long long __prof_sum_1 = 0;
				unsigned long long __prof_sum_2 = 0;
				unsigned long long __prof_sum_3 = 0;
				unsigned long long __prof_sum_4 = 0;
				unsigned long long __prof_sum_5 = 0;
				unsigned long long __prof_sum_6 = 0;
				__prof_processData_sum_1 = 0;
				__prof_processData_sum_2 = 0;
				__prof_processData_sum_3 = 0;
				__prof_processData_sum_4 = 0;
				__prof_processData_sum_5 = 0;
				#endif
				
				tarthread->qlock();
				list<string> listTars;
				std::map<string, tarthreads_tq*>::iterator it = tarthread->queue_data.begin();
				while(it != tarthread->queue_data.end()) {
					listTars.push_back(it->first);
					++it;
				}
				tarthread->qunlock();
				for(list<string>::iterator itTars = listTars.begin();  itTars != listTars.end(); itTars++) {
					string processTarName = *itTars;
					tarthreads_tq *processTarQueue = tarthread->queue_data[*itTars];
					bool doProcessDataTar = false;
					size_t index_list = 0;
					size_t length_list = processTarQueue->size();
					size_t count_empty = 0;
					for(std::list<data_t>::iterator it = processTarQueue->begin(); index_list < length_list;) {
						if(index_list++) ++it;
						if(!it->buffer) {
							++count_empty;
							continue;
						}
						data_t data = *it;
						/*
						if(data.buffer->isDecompressError()) {
							if(verbosity) {
								syslog(LOG_NOTICE, "tar: DECOMPRESS ERROR");
							}
							//tarthread->queue[processTar].erase(tarthread->queue[processTar].begin() + index_list);
							//--length_list;
							//--index_list;
							data.buffer = NULL;
							tarthread->queue[processTar][index_list].buffer = NULL;
							++count_empty;
							continue;
						}
						lock_okTarPointers();
						if(okTarPointers.find(data.tar) == okTarPointers.end()) {
							if(verbosity) {
								syslog(LOG_NOTICE, "tar: BAD TAR");
							}
							//tarthread->queue[processTar].erase(tarthread->queue[processTar].begin() + index_list);
							//--length_list;
							//--index_list;
							data.buffer = NULL;
							tarthread->queue[processTar][index_list].buffer = NULL;
							++count_empty;
							unlock_okTarPointers();
							continue;
						}
						unlock_okTarPointers();
						*/
						bool isClosed = data.buffer->isClosed();
						if(!isClosed && 
						   !data.buffer->isNewLastAddTimeForTar() && 
						   !data.buffer->isFull()) {
							continue;
						}
						data.buffer->copyLastAddTimeToTar();
						unsigned int bufferLastTarTime = data.buffer->getLastTarTime();
						if(!isClosed &&
						   bufferLastTarTime && bufferLastTarTime > getGlobalPacketTimeS() - 3 && 
						   !data.buffer->isFull()) {
							continue;
						}
						data.buffer->setLastTarTime(getGlobalPacketTimeS());
						#if TAR_PROF
						unsigned long long __prof_begin2 = rdtsc();
						#endif
						size_t lenForProceed = data.buffer->getChunkIterateLenForProceed();
						if(isClosed || lenForProceed > TAR_CHUNK_KB * 1024) {
							#if TAR_PROF
							unsigned long long __prof_i1 = rdtsc();
							#endif
							size_t lenForProceedSafe = isClosed ? 
										    lenForProceed :
										    data.buffer->getChunkIterateSafeLimitLength(lenForProceed);
							#if TAR_PROF
							unsigned long long __prof_i2 = rdtsc();
							#endif
							if(isClosed ||
							   lenForProceedSafe > TAR_CHUNK_KB * 1024) {
								doProcessData = true;
								doProcessDataTar = true;
								#if TAR_PROF
								unsigned long long __prof_i21 = rdtsc();
								#endif
								tarthread->processData(this2, processTarName.c_str(), 
										       &data, isClosed, lenForProceed, lenForProceedSafe);
								#if TAR_PROF
								unsigned long long __prof_i22 = rdtsc();
								__prof_sum_5 += __prof_i22 - __prof_i21;
								#endif
								if(isClosed && !lenForProceed) {
									//tarthread->queue[processTar].erase(tarthread->queue[processTar].begin() + index_list);
									//--length_list;
									//--index_list;
									data.buffer = NULL;
									it->buffer = NULL;
									++count_empty;
								}
								#if TAR_PROF
								unsigned long long __prof_i23 = rdtsc();
								__prof_sum_6 += __prof_i23 - __prof_i22;
								#endif
							}
						}
						#if TAR_PROF
						unsigned long long __prof_end2 = rdtsc();
						__prof_sum_1 += __prof_end2 - __prof_begin2;
						__prof_sum_2 += __prof_i1 - __prof_begin2;
						__prof_sum_3 += __prof_i2 - __prof_i1;
						__prof_sum_4 += __prof_end2 - __prof_i2;
						#endif
					}
					bool eraseTarQueueItem = false;
					//if(!tarthread->queue[processTar].size()) {
					if(processTarQueue->size() == count_empty) {
						pthread_mutex_lock(&this2->tarslock);
						if(this2->tars.find(processTarName) == this2->tars.end()) {
							delete tarthread->queue_data[processTarName];
							tarthread->queue_data.erase(processTarName);
							eraseTarQueueItem = true;
						}
						pthread_mutex_unlock(&this2->tarslock);
					}
					if(!eraseTarQueueItem) {
						if(count_empty > processTarQueue->size() / 5) {
							tarthread->qlock();
							for(std::list<data_t>::iterator it = processTarQueue->begin(); it != processTarQueue->end();) {
								if(!it->buffer) {
									processTarQueue->erase(it++);
								} else {
									it++;
								}
							}
							tarthread->qunlock();
						}
					}
					if(!doProcessDataTar) {
						unsigned int lastAddTime = 0;
						if(!eraseTarQueueItem) {
							tarthread->qlock();
							lastAddTime = processTarQueue->getLastAddTime();
							tarthread->qunlock();
						}
						if(!lastAddTime || 
						    lastAddTime < getGlobalPacketTimeS() - 30) {
							pthread_mutex_lock(&this2->tarslock);
							if(this2->tars.find(processTarName) != this2->tars.end()) {
								Tar *processTar = this2->tars[processTarName];
								if(processTar->lastWriteTime &&
								   processTar->lastWriteTime < getTimeS() - 30 &&
								   processTar->lastFlushTime < processTar->lastWriteTime - 30) {
									processTar->flush();
									processTar->lastFlushTime = getTimeS();
								}
							}
							pthread_mutex_unlock(&this2->tarslock);
						}
					}
				}
				#if TAR_PROF
				unsigned long long __prof_end = rdtsc();
				if(100 * __prof_sum_1 / (__prof_end - __prof_begin)) {
					cout << "**** " << counter << " : "
					     << (100 * __prof_sum_1 / (__prof_end - __prof_begin)) << "% " 
					     << (100 * __prof_sum_2 / (__prof_end - __prof_begin)) << "% " 
					     << (100 * __prof_sum_3 / (__prof_end - __prof_begin)) << "% " 
					     << (100 * __prof_sum_4 / (__prof_end - __prof_begin)) << "% " 
					     << (100 * __prof_sum_5 / (__prof_end - __prof_begin)) << "% " 
					     << (100 * __prof_sum_6 / (__prof_end - __prof_begin)) << "% " 
					     << " - "
					     << (100 * __prof_processData_sum_1 / (__prof_end - __prof_begin)) << "% " 
					     << (100 * __prof_processData_sum_2 / (__prof_end - __prof_begin)) << "% " 
					     << (100 * __prof_processData_sum_3 / (__prof_end - __prof_begin)) << "% " 
					     << (100 * __prof_processData_sum_4 / (__prof_end - __prof_begin)) << "% " 
					     << (100 * __prof_processData_sum_5 / (__prof_end - __prof_begin)) << "% " 
					     << endl;
				}
				#endif
			}
			if(!doProcessData) {
				break;
			}
		}
		// quque is empty - sleep before next run
		usleep(is_terminating() ? 100000 : 250000);
		if(terminate_pass) {
			break;
		}
	}
	tarthread->threadEnd = true;
	return NULL;
}

inline void
TarQueue::tarthreads_t::processData(TarQueue *tarQueue, const char *tarName,
				    data_t *data, bool isClosed, size_t lenForProceed, size_t lenForProceedSafe) {
 
	#if TAR_PROF
	unsigned long long __prof_begin = rdtsc();
	unsigned long long __prof_i1 = __prof_begin;
	unsigned long long __prof_i2 = __prof_begin;
	#endif
 
	Tar *tar = NULL;
	pthread_mutex_lock(&tarQueue->tarslock);
	if(tarQueue->tars.find(tarName) == tarQueue->tars.end()) {
		syslog(LOG_ERR, "try to write close tar: %s",  tarName);
	} else {
		tar = data->tar;
	}
	pthread_mutex_unlock(&tarQueue->tarslock);
	
	if(tar) {
	 
		if(tar->time != data->buffer->getTarTime()) {
			syslog(LOG_ERR, "BAD TAR (processData) time: %s vs chunkbuffer time: %s in tar: %s",
			       tar->time.getTimeString().c_str(), data->buffer->getTarTime().getTimeString().c_str(),
			       tar->pathname.c_str());
		}
	 
		tar->tarlock();
		if(lenForProceedSafe) {
			tar->writing = 1;
			data->buffer->addTarPosInCall(tar->tarLength);
		 
			//reset and set header
			memset(&(tar->tar.th_buf), 0, sizeof(struct Tar::tar_header));
			tar->th_set_type(0); //s->st_mode, 0 is regular file
			tar->th_set_user(0); //st_uid
			tar->th_set_group(0); //st_gid
			tar->th_set_mode(0444); //s->st_mode
			tar->th_set_mtime(data->time);
			tar->th_set_size(lenForProceedSafe);
			tar->th_set_path((char*)data->filename.c_str(), !isClosed);
			
			#if TAR_PROF
			__prof_i1 = rdtsc();
			#endif
		       
			// write header
			if (tar->th_write() == 0) {
				// if it's a regular file, write the contents as well
			 
				#if TAR_PROF
				__prof_i2 = rdtsc();
				#endif
			 
				tar->tar_append_buffer(data->buffer, lenForProceedSafe);
				
				if(sverb.chunk_buffer > 2) {
					cout << " *** " << data->buffer->getName() << " " << lenForProceedSafe << endl;
				}
			}
			tar->writing = 0;
		}
	}
	
	#if TAR_PROF
	unsigned long long __prof_i3 = rdtsc();
	#endif
	
	if(isClosed && !lenForProceed) {
		tarQueue->decreaseTartimemap(data);
		if(sverb.tar > 2 && tar) {
			syslog(LOG_NOTICE, "tartimemap decrease1: %s %s %s", 
			       tar->pathname.c_str(),
			       data->buffer->getName().c_str(), 
			       tar->time.getTimeString().c_str());
		}
		delete data->buffer;
		//tar->incClosedPartCounter();
		__sync_sub_and_fetch(&glob_tar_queued_files, 1);
	}
	
	if(tar) {
		tar->tarunlock();
	}
	
	#if TAR_PROF
	unsigned long long __prof_end = rdtsc();
	__prof_processData_sum_1 += __prof_end - __prof_begin;
	__prof_processData_sum_2 += __prof_i1 - __prof_begin;
	__prof_processData_sum_3 += __prof_i2 - __prof_i1;
	__prof_processData_sum_4 += __prof_i3 - __prof_i2;
	__prof_processData_sum_5 += __prof_end - __prof_i3;
	#endif
}

void
TarQueue::cleanTars(int terminate_pass) {
	// check if tar can be removed from map (check if there are still calls in memory) 
	if(!terminate_pass &&
	   (last_flushTars + 10) > getTimeS()) {
		// clean only each >10 seconds 
		return;
	}
	//if(sverb.tar) syslog(LOG_NOTICE, "cleanTars()");
	last_flushTars = getTimeS();
	map<string, Tar*>::iterator tars_it;
	pthread_mutex_lock(&tarslock);
	for(tars_it = tars.begin(); tars_it != tars.end();) {
		// walk through all tars
		Tar *tar = tars_it->second;
		pthread_mutex_lock(&tartimemaplock);
		// find the tar in tartimemap 
		if(!tar->_sync_lock &&
		   (tartimemap.find(tar->time) == tartimemap.end()) && 
		   (terminate_pass ||
		    getGlobalPacketTimeS() > (tar->created_at + 60 + 10) ||	// +10 seconds more in new period to be sure nothing is in buffers
		    getTimeS() > (tar->created_at + 60 + 2*60 + 10))) { 	// +2*60+10 seconds more in new period to be sure nothing is in buffers
			// there are no calls in this start time - clean it
			pthread_mutex_unlock(&tartimemaplock);
			if(tars_it->second->writing) {
				syslog(LOG_NOTICE, "fatal error! trying to close tar %s in the middle of writing data", tars_it->second->pathname.c_str());
			}
			if(sverb.tar) {
				syslog(LOG_NOTICE, "destroying tar %s / %lx - (no calls in mem)\n", tars_it->second->pathname.c_str(), (long)tar);
			}
			lock_okTarPointers();
			if(okTarPointers.find(tars_it->second) != okTarPointers.end()) {
				if(sverb.tar) {
					syslog(LOG_NOTICE, "delete tar pointer %lx\n", (long)tars_it->second);
				}
				okTarPointers.erase(tars_it->second);
			}
			if(sverb.tar <= 1) {
				delete tars_it->second;
			} else {
				tars_it->second->tar_close();
			}
			unlock_okTarPointers();
			tars.erase(tars_it++);
		} else {
			pthread_mutex_unlock(&tartimemaplock);
			tars_it++;
		}
	}
	pthread_mutex_unlock(&tarslock);
}

void   
TarQueue::flushQueue() {
	pthread_mutex_lock(&flushlock);
	// get candidate vector which has the biggest datalen in all files 
	int winner_qtype = 0;
	
	vector<data_t> *winner;
	data_tar_time winnertime;
	size_t maxlen = 0;
	map<data_tar_time, vector<data_t>* >::iterator it;
	// walk all maps

	while(1) {
		lock();
		winner = NULL;
		maxlen = 0;
		for(int i = 0; i < 4; i++) {
			//walk map
			for(it = queue_data[i].begin(); it != queue_data[i].end(); it++) {
				vector<data_t>::iterator itv;
				size_t sum = 0;
				for(itv = it->second->begin(); itv != it->second->end(); itv++) {
					sum += itv->buffer->getLen();
				}       
				if(sum > maxlen) {
					maxlen = sum;
					winnertime = it->first;
					winner = it->second;
					winner_qtype = i;
				}       
			}       
		}       

		if(winner) {
			queue_data[winner_qtype].erase(winnertime);
			unlock();
			vector<data_t>::iterator itv;
			for(itv = winner->begin(); itv != winner->end(); itv++) {
				this->write(winner_qtype, *itv);
			}
			delete winner;
			cleanTars();
			continue;
		} else {
			unlock();
			cleanTars();
			break;
		}
	}
	pthread_mutex_unlock(&flushlock);
}

int
TarQueue::queuelen() {
	int len = 0;
	for(int i = 0; i < 4; i++) {
		len += queue_data[i].size();
	}
	return len;
}

TarQueue::~TarQueue() {
	if(sverb.chunk_buffer > 1) { 
		cout << "destroy tar queue" << endl;
	}
	terminate = true;
	for(int i = 0; i < maxthreads; i++) { 
		pthread_join(tarthreads[i].thread, NULL);
	}

	pthread_mutex_destroy(&mutexlock);
	pthread_mutex_destroy(&flushlock);
	pthread_mutex_destroy(&tarslock);

	// destroy all tars
	for(map<string, Tar*>::iterator it = tars.begin(); it != tars.end(); it++) {
		delete(it->second);
	}
	
	// destroy all queue_data
	for(unsigned i = 0; i < sizeof(queue_data) / sizeof(queue_data[0]); i++) {
		for(map<data_tar_time, vector<data_t>* >::iterator it = queue_data[i].begin(); it != queue_data[i].end(); it++) {
			delete(it->second);
		}
	}

	pthread_mutex_destroy(&tartimemaplock);
}      

TarQueue::TarQueue(int spoolIndex) {
 
	this->spoolIndex = spoolIndex;

	terminate = false;
	maxthreads = opt_pcap_dump_tar_threads;
	
	for(int i = 0; i < 4; i++) {
		tarThreadCounter[i] = i;
	}

	pthread_mutex_init(&mutexlock, NULL);
	pthread_mutex_init(&flushlock, NULL);
	pthread_mutex_init(&tarslock, NULL);
	last_flushTars = 0;
	for(int i = 0; i < maxthreads; i++) {
		tarthreads[i].tarQueue = this;
		tarthreads[i].threadEnd = false;
		tarthreadworker_arg *arg = new FILE_LINE(34011) tarthreadworker_arg;
		arg->i = i;
		arg->tq = this;
		tarthreads[i].cpuPeak = 0;
		tarthreads[i]._sync_lock = 0;
		vm_pthread_create("tar",
				  &tarthreads[i].thread, NULL, &TarQueue::tarthreadworker, arg, __FILE__, __LINE__);
		memset(this->tarthreads[i].threadPstatData, 0, sizeof(this->tarthreads[i].threadPstatData));
		this->tarthreads[i].counter = 0;
	}

	_sync_okTarPointers = 0;
	pthread_mutex_init(&tartimemaplock, NULL);
	
	// create tarthreads
	
};	      

void TarQueue::preparePstatData(int threadIndex) {
	if(this->tarthreads[threadIndex].threadId) {
		if(this->tarthreads[threadIndex].threadPstatData[0].cpu_total_time) {
			this->tarthreads[threadIndex].threadPstatData[1] = this->tarthreads[threadIndex].threadPstatData[0];
		}
		pstat_get_data(this->tarthreads[threadIndex].threadId, this->tarthreads[threadIndex].threadPstatData);
	}
}

double TarQueue::getCpuUsagePerc(int threadIndex, bool preparePstatData) {
	if(preparePstatData) {
		this->preparePstatData(threadIndex);
	}
	if(this->tarthreads[threadIndex].threadId) {
		double ucpu_usage, scpu_usage;
		if(this->tarthreads[threadIndex].threadPstatData[0].cpu_total_time && this->tarthreads[threadIndex].threadPstatData[1].cpu_total_time) {
			pstat_calc_cpu_usage_pct(
				&this->tarthreads[threadIndex].threadPstatData[0], &this->tarthreads[threadIndex].threadPstatData[1],
				&ucpu_usage, &scpu_usage);
			double rslt = ucpu_usage + scpu_usage;
			if(rslt > this->tarthreads[threadIndex].cpuPeak) {
				this->tarthreads[threadIndex].cpuPeak = rslt;
			}
			return(rslt);
		}
	}
	return(-1);
}

bool TarQueue::allThreadsEnds() {
	for(int i = 0; i < maxthreads; i++) {
		if(!tarthreads[i].threadEnd) {
			return(false);
		}
	}
	return(true);
}

bool TarQueue::flushTar(const char *tarName) {
	bool rslt = false;
	string tarNameStr = find_and_replace(tarName, "//", "/");
	map<string, Tar*>::iterator tars_it;
	pthread_mutex_lock(&tarslock);
	for(tars_it = tars.begin(); tars_it != tars.end(); tars_it++) {
		Tar *tar = tars_it->second;
		if(tar->pathname.find(tarNameStr) != string::npos) {
			if(tar->flush()) {
				tar->lastFlushTime = getTimeS();
				rslt = true;
			}
		}
	}
	pthread_mutex_unlock(&tarslock);
	return(rslt);
}

unsigned TarQueue::flushAllTars() {
	unsigned countFlush = 0;
	map<string, Tar*>::iterator tars_it;
	pthread_mutex_lock(&tarslock);
	for(tars_it = tars.begin(); tars_it != tars.end(); tars_it++) {
		Tar *tar = tars_it->second;
		if(tar->flush()) {
			tar->lastFlushTime = getTimeS();
			++countFlush;
		}
	}
	pthread_mutex_unlock(&tarslock);
	return(countFlush);
}

u_int64_t TarQueue::sumSizeOpenTars() {
	u_int64_t sumSize = 0;
	map<string, Tar*>::iterator tars_it;
	pthread_mutex_lock(&tarslock);
	for(tars_it = tars.begin(); tars_it != tars.end(); tars_it++) {
		Tar *tar = tars_it->second;
		sumSize += GetFileSizeDU(tar->pathname.c_str(), tar->typeSpoolFile, tar->spoolIndex);
	}
	pthread_mutex_unlock(&tarslock);
	return(sumSize);
}

list<string> TarQueue::listOpenTars() {
	list<string> listTars;
	map<string, Tar*>::iterator tars_it;
	pthread_mutex_lock(&tarslock);
	for(tars_it = tars.begin(); tars_it != tars.end(); tars_it++) {
		Tar *tar = tars_it->second;
		listTars.push_back(tar->pathname);
	}
	pthread_mutex_unlock(&tarslock);
	return(listTars);
}

void TarQueue::decreaseTartimemap(data_tar_time *time){
	// decrease tartimemap
	pthread_mutex_lock(&tartimemaplock);
	map<data_tar_time, int>::iterator tartimemap_it = tartimemap.find(*time);
	if(tartimemap_it != tartimemap.end()) {
		tartimemap_it->second--;
		if(sverb.tar > 2) {
			syslog(LOG_NOTICE, "tartimemap decrease to: %s %i", 
			       time->getTimeString().c_str(), tartimemap_it->second);
		}
		if(tartimemap_it->second == 0){
			tartimemap.erase(tartimemap_it);
		}
	}
	pthread_mutex_unlock(&tartimemaplock);
}

void TarQueue::increaseTartimemap(data_tar_time *time){
	pthread_mutex_lock(&tartimemaplock);
	map<data_tar_time, int>::iterator tartimemap_it = tartimemap.find(*time);
	if(tartimemap_it != tartimemap.end()) {
		tartimemap_it->second++;
		if(sverb.tar > 2) {
			syslog(LOG_NOTICE, "tartimemap increase to: %s %i", 
			       time->getTimeString().c_str(), tartimemap_it->second);
		}
	} else {
		tartimemap[*time] = 1;
		if(sverb.tar > 2) {
			syslog(LOG_NOTICE, "tartimemap increase set: %s %i", 
			       time->getTimeString().c_str(), 1);
		}
	}
	pthread_mutex_unlock(&tartimemaplock);
}

void *TarQueueThread(void *_tarQueue) {
	// run each second flushQueue
	TarQueue *tarQueue = (TarQueue*)_tarQueue;
	while(1) {
		if(terminated_tar_flush_queue[tarQueue->getSpoolIndex()]) {
			if(tarQueue->allThreadsEnds()) {
				tarQueue->cleanTars(true);
				terminated_tar[tarQueue->getSpoolIndex()] = 1;
				syslog(LOG_NOTICE, "terminated - tar");
				break;
			}
		} else {
			int do_terminated_tar_flush_queue = terminated_async;
			tarQueue->flushQueue();
			if(do_terminated_tar_flush_queue) {
				 terminated_tar_flush_queue[tarQueue->getSpoolIndex()] = 1;
				 syslog(LOG_NOTICE, "terminated - tar - flush queue");
			}
		}
		if(is_terminating()) {
			usleep(100000);
		} else {
			sleep(1);
		}
	}      
	return NULL;
}      

int untar_gui(const char *args) {
	char tarFile[1024] = "";
	char destFile[1024] = "";
	char outputFile[1024] = "";
	char tarPos[100 * 1024];
	
	if(sscanf(args, "%s %s %s %s", tarFile, destFile, tarPos, outputFile) != 4) {
		cerr << "untar: bad arguments" << endl;
		return(1);
	}
	
	cout << tarFile << endl;
	cout << destFile << endl;
	cout << tarPos << endl;
	cout << outputFile << endl;
	
	Tar tar;
	if(tar.tar_open(tarFile, O_RDONLY) == -1) {
		cerr << "untar: open file " << tarFile << " failed" << endl;
		return(1);
	}
	FILE *outputFileHandle = fopen(outputFile, "wb");
	if(!outputFileHandle) {
		cerr << "untar: open output file " << outputFile << " failed" << endl;
		return(1);
	}
	tar.tar_read_save_parameters(outputFileHandle);
	string destFile_conv = destFile;
	prepare_string_to_filename((char*)destFile_conv.c_str());
	tar.tar_read((destFile_conv + ".*").c_str(), destFile, 0, NULL, tarPos);
	fclose(outputFileHandle);
	
	return(0);
 
}

class c_unlzo_gui_compress_to_gzip : public CompressStream_baseEv {
public:
	c_unlzo_gui_compress_to_gzip(FILE *outputFileHandle) {
		this->outputFileHandle = outputFileHandle;
	}
	bool compress_ev(char *data, u_int32_t len, u_int32_t /*decompress_len*/, bool /*format_data*/) {
		fwrite(data, 1, len, outputFileHandle);
		return(true);
	}
private:
	FILE *outputFileHandle;
};

class c_unlzo_gui_decompress_from_lzo : public CompressStream_baseEv {
public:
	c_unlzo_gui_decompress_from_lzo(CompressStream *compressStreamToGzip,
					c_unlzo_gui_compress_to_gzip *unlzo_gui_compress_to_gzip) {
		this->compressStreamToGzip = compressStreamToGzip;
		this->unlzo_gui_compress_to_gzip = unlzo_gui_compress_to_gzip;
	}
	bool decompress_ev(char *data, u_int32_t len) {
		compressStreamToGzip->compress(data, len, false, unlzo_gui_compress_to_gzip);
		return(true);
	}
private:
	CompressStream *compressStreamToGzip;
	c_unlzo_gui_compress_to_gzip *unlzo_gui_compress_to_gzip;
};

int unlzo_gui(const char *args) {
	char lzoFile[1024] = "";
	char outputFile[1024] = "";
	
	if(sscanf(args, "%s %s", lzoFile, outputFile) != 2) {
		cerr << "unlzo: bad arguments" << endl;
		return(1);
	}
	
	cout << lzoFile << endl;
	cout << outputFile << endl;
	
	FILE *lzoFileHandle = fopen(lzoFile, "rb");
	if(!lzoFileHandle) {
		cerr << "unlzo: open lzo file " << lzoFile << " failed" << endl;
		return(1);
	}
	FILE *outputFileHandle = fopen(outputFile, "wb");
	if(!outputFileHandle) {
		fclose(lzoFileHandle);
		cerr << "unlzo: open output file " << outputFile << " failed" << endl;
		return(1);
	}
	CompressStream *decompressStreamFromLzo = new FILE_LINE(34012) CompressStream(CompressStream::lzo, 1024 * 8, 0);
	decompressStreamFromLzo->enableForceStream();
	CompressStream *compressStreamToGzip = new FILE_LINE(34013) CompressStream(CompressStream::gzip, 1024 * 8, 0);
	c_unlzo_gui_compress_to_gzip *unlzo_gui_compress_to_gzip = new FILE_LINE(34014) c_unlzo_gui_compress_to_gzip(outputFileHandle);
	c_unlzo_gui_decompress_from_lzo *unlzo_gui_decompress_from_lzo = new FILE_LINE(34015) c_unlzo_gui_decompress_from_lzo(compressStreamToGzip, unlzo_gui_compress_to_gzip);
	while(!feof(lzoFileHandle)) {
		char buff[1024 * 8];
		size_t readSize = fread(buff, 1, sizeof(buff), lzoFileHandle);
		if(readSize) {
			decompressStreamFromLzo->decompress(buff, readSize, 0, false, unlzo_gui_decompress_from_lzo);
		} else {
			break;
		}
	}
	decompressStreamFromLzo->decompress(NULL, 0, 0, true, unlzo_gui_decompress_from_lzo);
	compressStreamToGzip->compress(NULL, 0, true, unlzo_gui_compress_to_gzip);
	delete unlzo_gui_decompress_from_lzo;
	delete unlzo_gui_compress_to_gzip;
	delete decompressStreamFromLzo;
	delete compressStreamToGzip;
	fclose(lzoFileHandle);
	fclose(outputFileHandle);
	
	return(0);
}

bool flushTar(const char *tarName) {
	extern TarQueue *tarQueue[2];
	bool useFlush = false;
	for(int i = 0; i < 2; i++) {
		if(tarQueue[i] &&
		   tarQueue[i]->flushTar(tarName)) {
			useFlush = true;
		}
	}
	return(useFlush);
}

unsigned flushAllTars() {
	extern TarQueue *tarQueue[2];
	unsigned countFlush = 0;
	for(int i = 0; i < 2; i++) {
		if(tarQueue[i]) {
			countFlush += tarQueue[i]->flushAllTars();
		}
	}
	return(countFlush);
}
