#ifndef TAR_H
#define TAR_H 

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string>
#include "config.h"
#ifdef HAVE_LIBLZMA
#include <lzma.h>
#endif

#include "tools.h"
#include "tools_dynamic_buffer.h"
#include "tar_data.h"

#define T_BLOCKSIZE		512
#define T_NAMELEN	       100
#define T_PREFIXLEN	     155
#define T_MAXPATHLEN	    (T_NAMELEN + T_PREFIXLEN)

/* GNU extensions for typeflag */
#define GNU_LONGNAME_TYPE       'L'
#define GNU_LONGLINK_TYPE       'K'

/* constant values for the TAR options field */
#define TAR_GNU		  1      /* use GNU extensions */
#define TAR_VERBOSE	      2      /* output file info to stdout */
#define TAR_NOOVERWRITE	  4      /* don't overwrite existing files */
#define TAR_IGNORE_EOT	   8      /* ignore double zero blocks as EOF */
#define TAR_CHECK_MAGIC	 16      /* check magic in file header */
#define TAR_CHECK_VERSION       32      /* check version in file header */
#define TAR_IGNORE_CRC	  64      /* ignore CRC in file header */

/* this is obsolete - it's here for backwards-compatibility only */
#define TAR_IGNORE_MAGIC	0

#define TAR_CHUNK_KB	128

#define TAR_FILENAME_LENGTH 100u
#define TAR_FILENAME_LENGTH_RESERVE 8u
#define TAR_FILENAME_RESERVE_LIMIT (TAR_FILENAME_LENGTH - TAR_FILENAME_LENGTH_RESERVE)
#define TAR_FILENAME_HASH_PREFIX "_hash_"
#define TAR_FILENAME_HASH_LENGTH (6 + 32)

using namespace std;

/* integer to NULL-terminated string-octal conversion */
inline void int_to_oct(unsigned long num, char *oct, int octlen) {
	#if __GNUC__ >= 8
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wformat-truncation"
	#endif
	snprintf((oct), (octlen), "%*lo ", (octlen) - 2, (unsigned long)(num));
	#if __GNUC__ >= 8
	#pragma GCC diagnostic pop
	#endif
}

class Tar : public ChunkBuffer_baseIterate, public CompressStream_baseEv {
public:
	/* our version of the tar header structure */
	struct tar_header
	{       
		char name[TAR_FILENAME_LENGTH];
		char mode[8];
		char uid[8];
		char gid[8];    
		char size[12];  
		char mtime[12]; 
		char chksum[8];
		char typeflag;
		char linkname[100];
		char magic[6];
		char version[2];
		char uname[32];
		char gname[32];
		char devmajor[8];
		char devminor[8];
		char prefix[155];
		char padding[12];
		char *gnu_longname;
		char *gnu_longlink;
		
		u_int32_t get_size() {
			char *size_pointer = size;
			while(*size_pointer == ' ') {
				++size_pointer;
			}
			return(octal_decimal((u_int32_t)atol(size_pointer)));
		}
	};
	typedef int (*openfunc_t)(const char *, int, ...);
	typedef int (*closefunc_t)(int);
	typedef ssize_t (*readfunc_t)(int, void *, size_t);
	typedef ssize_t (*writefunc_t)(int, const void *, size_t);

	eTypeSpoolFile typeSpoolFile;
	string pathname;
	int open_flags;

	typedef struct
	{
		long fd;
		int oflags;
		int options;
		struct tar_header th_buf;
		int qtype;
		//libtar_hash_t *h;
	}
	TAR;
	TAR tar;
	int spoolIndex;
	string sensorName;
	volatile int writing;

	data_tar_time time;
	unsigned int created_at;
	int thread_id;
	

	Tar() {    
		this->typeSpoolFile = tsf_na;
		this->zipStream = NULL;
#ifdef HAVE_LIBLZMA
		this->lzmaStream = NULL;
#endif
		this->zipBuffer = NULL;
		memset(&tar, 0, sizeof(tar));
		partCounter = 0;
		lastFlushTime = 0;
		lastWriteTime = 0;
		tarLength = 0;
		writeCounter = 0;
		writeCounterFlush = 0;
		this->writing = 0;
		this->_sync_lock = 0;
	};
	virtual ~Tar();

	//tar functions 
	int tar_init(int oflags, int options);
	int tar_open(string pathname, int oflags, int options = 0);
	void th_finish();
	int th_write();
	int tar_append_buffer(ChunkBuffer *buffer, size_t lenForProceed = 0);
	virtual void chunkbuffer_iterate_ev(char *data, u_int32_t len, u_int32_t pos);
	void tar_read(const char *filename, u_int32_t recordId = 0, const char *tableType = NULL, const char *tarPosString = NULL);
	void tar_read_send_parameters(int client, void *c_client, bool zip);
	void tar_read_save_parameters(FILE *output_file_handle);
	virtual bool decompress_ev(char *data, u_int32_t len);
	void tar_read_block_ev(char *data);
	void tar_read_file_ev(tar_header fileHeader, char *data, u_int32_t pos, u_int32_t len);
	int gziplevel;
	int lzmalevel;

	void th_set_type(mode_t mode);
	void th_set_path(char *pathname, bool partSuffix = false);
	void th_set_link(char *linkname);
	void th_set_device(dev_t device);
	void th_set_user(uid_t uid);
	void th_set_group(gid_t gid);
	void th_set_mode(mode_t fmode);

	void th_set_mtime(int fmtime){
		int_to_oct_nonull(fmtime, tar.th_buf.mtime, 12);
	};
	void th_set_size(int fsize){
		int_to_oct_nonull(fsize, tar.th_buf.size, 12);
	};
	int tar_block_write(const char *buf, u_int32_t len);
	void tar_close();
	
	string get_hashcomb_long_filename(const char *filename);

	void int_to_oct_nonull(int num, char *oct, size_t octlen);
	int th_crc_calc();
	int oct_to_int(char*);
	int initZip();
	int writeZip(const void *buf, size_t len);
	bool flushZip();
#ifdef HAVE_LIBLZMA
	int initLzma();
	bool flushLzma();
	int writeLzma(const void *buf, size_t len);
#endif
	bool flush();
	void addtofilesqueue();
	
	bool isReadError() {
		return(readData.error);
	}
	bool isReadEnd() {
		return(readData.end);
	}
	const char *getSpoolDir(eTypeSpoolFile typeSpoolFile) {
		return(::getSpoolDir(typeSpoolFile, spoolIndex));
	}

	void tarlock() {
		while(__sync_lock_test_and_set(&this->_sync_lock, 1));
	}
	void tarunlock() {
		__sync_lock_release(&this->_sync_lock);
	}
private:
	z_stream *zipStream;
	int zipBufferLength;
	char *zipBuffer;
	//map<string, u_int32_t> partCounter;
	unsigned long partCounter;
	//volatile u_int32_t partCounterSize;
	//volatile u_int32_t closedPartCounter;
	unsigned int lastFlushTime;
	unsigned int lastWriteTime;
	u_int64_t tarLength;
	volatile u_int32_t writeCounter;
	volatile u_int32_t writeCounterFlush;
	
	class ReadData : public CompressStream_baseEv {
	public:
		ReadData() {
			send_parameters_client = 0;
			send_parameters_c_client = NULL;
			send_parameters_zip = false;
			output_file_handle = NULL;
			null();
		}
		void null() {
			oneFile = false;
			end = false;
			error = false;
			filename = "";
			hash_filename = "";
			position = 0;
			buffer = NULL;
			bufferBaseSize = T_BLOCKSIZE;
			bufferLength = 0;
			fileSize = 0;
			decompressStreamFromLzo = NULL;
			compressStreamToGzip = NULL;
			nullFileHeader();
		}
		void nullFileHeader() {
			memset(&fileHeader, 0, sizeof(fileHeader));
		}
		void init(size_t bufferBaseSize) {
			this->bufferBaseSize = bufferBaseSize;
			buffer = new FILE_LINE(35001) char[bufferBaseSize + T_BLOCKSIZE];
		}
		void term() {
			delete [] buffer;
			if(decompressStreamFromLzo) {
				delete decompressStreamFromLzo;
			}
			if(compressStreamToGzip) {
				delete compressStreamToGzip;
			}
		}
		bool decompress_ev(char *data, u_int32_t len);
		bool compress_ev(char *data, u_int32_t len, u_int32_t decompress_len, bool format_data = false);
		bool oneFile;
		bool end;
		bool error;
		string filename;
		string hash_filename;
		size_t position;
		char *buffer;
		size_t bufferBaseSize;
		size_t bufferLength;
		tar_header fileHeader;
		size_t fileSize;
		int send_parameters_client;
		void *send_parameters_c_client;
		bool send_parameters_zip;
		FILE *output_file_handle;
		CompressStream *decompressStreamFromLzo;
		CompressStream *compressStreamToGzip;
	} readData;

#ifdef HAVE_LIBLZMA
	lzma_stream *lzmaStream;// = LZMA_STREAM_INIT; /* alloc and init lzma_stream struct */
	/* analogous to xz CLI options: -0 to -9 */
	#define LZMA_COMPRESSION_LEVEL 6
				
	/* boolean setting, analogous to xz CLI option: -e */
	#define LZMA_COMPRESSION_EXTREME true

	/* error codes */       
	#define LZMA_RET_OK		  0
	#define LZMA_RET_ERROR_INIT	  1
	#define LZMA_RET_ERROR_INPUT	 2
	#define LZMA_RET_ERROR_OUTPUT	3
	#define LZMA_RET_ERROR_COMPRESSION   4

#endif

	volatile int _sync_lock;

	friend class TarQueue;

};

class TarQueue {
public:		 

	#define TARQMAXTHREADS 32
        int maxthreads;


	TarQueue(int spoolIndex);
	~TarQueue();
	void lock() {pthread_mutex_lock(&mutexlock);};
	void unlock() {pthread_mutex_unlock(&mutexlock);};
	       
	struct data_t : public data_tar {
		ChunkBuffer *buffer;
		Tar *tar;
		time_t time;
		inline void setDataTar(data_tar *data) {
			*(data_tar*)this = *data;
		}
	};
	
	struct tarthreads_tq : public std::list<data_t> {
		size_t getLen(int forProceed = false) {
			size_t size = 0;
			std::list<data_t>::iterator it = this->begin();
			while(it != this->end()) {
				if(it->buffer) {
					size_t size_i = forProceed ? 
							 it->buffer->getChunkIterateLenForProceed() :
							 it->buffer->getLen();
					if(forProceed == 2) {
						if(it->buffer->isClosed()) {
							if(!size_i) {
								size_i = 1000;
							}
						} else {
							if(size_i < TAR_CHUNK_KB * 1024) {
								size_i = 0;
							}
						}
					}
					size += size_i;
				}
				++it;
			}
			return(size);
		}
		unsigned int getLastAddTime() {
			unsigned int lastAddTime = 0;
			std::list<data_t>::iterator it = this->begin();
			while(it != this->end()) {
				if(it->buffer) {
					unsigned int addTime = it->buffer->getLastAddTime();
					if(addTime > lastAddTime) {
						lastAddTime = addTime;
					}
				}
				++it;
			}
			return(lastAddTime);
		}
	};
	struct tarthreads_t {
		~tarthreads_t() {
			std::map<string, tarthreads_tq*>::iterator it = queue_data.begin();
			while(it != queue_data.end()) {
				delete it->second;
				++it;
			}
		}
		TarQueue *tarQueue;
		std::map<string, tarthreads_tq*> queue_data;
		pthread_t thread;
		int threadId;
		int thread_id;
		bool threadEnd;
		pstat_data threadPstatData[2];
		volatile int cpuPeak;
		unsigned int counter;
		volatile int _sync_lock;
		size_t getLen(int forProceed = false, bool lock = true) {
			if(lock) qlock();
			size_t size = 0;
			std::map<string, tarthreads_tq*>::iterator it = queue_data.begin();
			while(it != queue_data.end()) {
				size += it->second->getLen(forProceed);
				++it;
			}
			if(lock) qunlock();
			return(size);
		}
		Tar *getTarWithMaxLen(int forProceed = false, bool lock = true) {
			if(lock) qlock();
			size_t maxSize = 0;
			string maxTarName;
			std::map<string, tarthreads_tq*>::iterator it = queue_data.begin();
			while(it != queue_data.end()) {
				size_t size = it->second->getLen(forProceed);
				if(size > maxSize) {
					maxSize = size;
					maxTarName = it->first;
				}
				++it;
			}
			if(lock) qunlock();
			return(maxTarName.empty() ? NULL : tarQueue->tars[maxTarName]);
		}
		inline void qlock() {
			while(__sync_lock_test_and_set(&this->_sync_lock, 1));
		}
		inline void qunlock() {
			__sync_lock_release(&this->_sync_lock);
		}
		inline void processData(TarQueue *tarQueue, const char *tarName, 
					data_t *data, bool isClosed, size_t lenForProceed, size_t lenForProceedSafe);
	};

	struct tarthreadworker_arg {
		int i;
		TarQueue *tq;
	};

	bool terminate;

	tarthreads_t tarthreads[TARQMAXTHREADS];
	
	void add(data_tar *tar_data, ChunkBuffer *buffer, unsigned int time);
	void flushQueue();
	int write(int, data_t);
	int queuelen();
	unsigned int last_flushTars;
	void cleanTars(int term_pass = false);
	static void *tarthreadworker(void*);
	void preparePstatData(int threadIndex);
	double getCpuUsagePerc(int threadIndex, bool preparePstatData);
	bool allThreadsEnds();
	bool flushTar(const char *tarName);
	unsigned flushAllTars();
	u_int64_t sumSizeOpenTars();
	list<string> listOpenTars();
	void lock_okTarPointers() { while(__sync_lock_test_and_set(&_sync_okTarPointers, 1)); }
	void unlock_okTarPointers() { __sync_lock_release(&_sync_okTarPointers); }
	void decreaseTartimemap(data_tar_time *time);
	void increaseTartimemap(data_tar_time *time);
	int getSpoolIndex() {
		return(spoolIndex);
	}
	const char *getSpoolDir(eTypeSpoolFile typeSpoolFile) {
		return(::getSpoolDir(typeSpoolFile, spoolIndex));
	}
private:
	int spoolIndex;
	map<data_tar_time, vector<data_t>* > queue_data[4]; //queue for all, sip, rtp, graph
	unsigned long tarThreadCounter[4];
	pthread_mutex_t mutexlock;
	pthread_mutex_t flushlock;
	pthread_mutex_t tarslock;
	map<string, Tar*> tars; //queue for all, sip, rtp, graph
	map<void*, unsigned int> okTarPointers;
	volatile int _sync_okTarPointers;
	map<data_tar_time, int> tartimemap;
	pthread_mutex_t tartimemaplock;
};

void *TarQueueThread(void *dummy);

int untar_gui(const char *args);
int unlzo_gui(const char *args);
bool flushTar(const char *tarName);
unsigned flushAllTars();

#endif
