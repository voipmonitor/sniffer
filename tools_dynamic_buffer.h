#ifndef TOOLS_DYNAMIC_BUFFER_H
#define TOOLS_DYNAMIC_BUFFER_H

#include <list>
#include <string.h>
#include <string>
#include <iostream>
#include <sys/types.h>
#include <algorithm>
#include <zlib.h>
#ifdef HAVE_LIBLZMA
#include <lzma.h>
#endif //HAVE_LIBLZMA
#ifdef HAVE_LIBZSTD
#include <zstd.h>
#endif //HAVE_LIBZSTD
#ifdef HAVE_LIBLZ4
#include <lz4.h>
#endif //HAVE_LIBLZ4
#ifdef HAVE_LIBLZO
#include <lzo/lzo1x.h>
#endif //HAVE_LIBLZO
#include <snappy-c.h>
#include "sync.h"

#include "tar_data.h"


using namespace std;


#define GZIP_HEADER_LENGTH 10
#define GZIP_HEADER_CHECK_LENGTH 4
#define GZIP_HEADER_CHECK(buff, offset) ((u_char)buff[offset+0] == 0x1F && (u_char)buff[offset+1] == 0x8B && (u_char)buff[offset+2] == 0x08 && (u_char)buff[offset+3] == 0x00)


class CompressStream_baseEv {
public:
	virtual ~CompressStream_baseEv() {}
	virtual bool compress_ev(char */*data*/, u_int32_t /*len*/, u_int32_t /*decompress_len*/, bool /*format_data*/ = false) { return(true); }
	virtual bool decompress_ev(char */*data*/, u_int32_t /*len*/) { return(true); }
};

class CompressStream : public CompressStream_baseEv {
public:
	enum eTypeCompress {
		compress_na,
		zip,
		gzip,
		lzma,
		zstd,
		snappy,
		lzo,
		lz4,
		lz4_stream,
		compress_auto
	};
	struct sChunkSizeInfo {
		u_int32_t size;
		u_int32_t compress_size;
	};
public:
	CompressStream(eTypeCompress typeCompress, u_int32_t compressBufferLength, u_int32_t maxDataLength);
	virtual ~CompressStream();
	void setCompressLevel(int compressLevel);
	void setCompressZstdStrategy(int compressZstdStrategy);
	void enableAutoPrefixFile();
	void enableForceStream();
	void setSendParameters(class Mgmt_params *mgmt_params);
	void initCompress();
	void initDecompress(u_int32_t dataLen);
	void termCompress();
	void termDecompress();
	bool compress(char *data, u_int32_t len, bool flush, CompressStream_baseEv *baseEv);
	bool decompress(char *data, u_int32_t len, u_int32_t decompress_len, bool flush, CompressStream_baseEv *baseEv, 
			u_int32_t *use_len = NULL, u_int32_t *decompress_len_out = NULL);
	bool isNativeStream() {
		return(typeCompress == compress_na ||
		       typeCompress == zip ||
		       typeCompress == gzip ||
		       typeCompress == lzma);
	}
	void setError(const char *errorString) {
		if(errorString && *errorString) {
			this->errorString = errorString;
		}
	}
	void setError(string errorString) {
		setError(errorString.c_str());
	}
	bool isOk() {
		return(errorString.empty());
	}
	bool isError() {
		return(!errorString.empty());
	}
	void clearError() {
		errorString = "";
	}
	string getErrorString() {
		return(errorString);
	}
	void setTypeCompress(eTypeCompress typeCompress) {
		this->typeCompress = typeCompress;
	}
	eTypeCompress getTypeCompress() {
		return(typeCompress);
	}
	static eTypeCompress convTypeCompress(const char *typeCompress);
	static const char *convTypeCompress(eTypeCompress typeCompress);
	static string getConfigMenuString();
private:
	void createCompressBuffer();
	void createDecompressBuffer(u_int32_t bufferLen);
	bool compress_ev(char *data, u_int32_t len, u_int32_t decompress_len, bool format_data = false);
private:
	eTypeCompress typeCompress;
	char *compressBuffer;
	u_int32_t compressBufferLength;
	u_int32_t compressBufferBoundLength;
	char *decompressBuffer;
	u_int32_t decompressBufferLength;
	u_int32_t maxDataLength;
	z_stream *zipStream;
	z_stream *zipStreamDecompress;
	#ifdef HAVE_LIBLZMA
	lzma_stream *lzmaStream;
	lzma_stream *lzmaStreamDecompress;
	#endif //HAVE_LIBLZMA
	#ifdef HAVE_LIBZSTD
	ZSTD_CCtx *zstdCtx;
	ZSTD_DCtx *zstdCtxDecompress;
	#endif //HAVE_LIBZSTD
	#ifdef HAVE_LIBLZ4
	LZ4_stream_t *lz4Stream;
	LZ4_streamDecode_t *lz4StreamDecode;
	class SimpleBuffer *lz4DecompressData;
	#endif //HAVE_LIBLZ4
	#ifdef HAVE_LIBLZO
	u_char *lzoWrkmem;
	u_char *lzoWrkmemDecompress;
	class SimpleBuffer *lzoDecompressData;
	#endif //HAVE_LIBLZO
	class SimpleBuffer *snappyDecompressData;
	string errorString;
	int compressLevel;
	int compressZstdStrategy;
	bool autoPrefixFile;
	bool forceStream;
	u_int32_t processed_len;
	Mgmt_params *sendParameters;
friend class ChunkBuffer;
};

class RecompressStream : public CompressStream {
public:
	RecompressStream(eTypeCompress typeDecompress = compress_na, eTypeCompress typeCompress = compress_na);
	~RecompressStream();
	void setTypeDecompress(eTypeCompress typeDecompress, bool enableForceStream = false);
	void setTypeCompress(eTypeCompress typeCompress);
	void setSendParameters(Mgmt_params *mgmt_params);
	void processData(char *data, u_int32_t len);
	void end();
	bool isError();
protected:
	virtual bool decompress_ev(char *data, u_int32_t len);
private:
	CompressStream *compressStream;
};

class ChunkBuffer_baseIterate {
public:
	virtual void chunkbuffer_iterate_ev(char */*data*/, u_int32_t /*len*/, u_int32_t /*pos*/) {}
};

class ChunkBuffer : public CompressStream_baseEv {
public:
	enum eAddMethod {
		add_na,
		add_fill_fix_len,
		add_simple,
		add_fill_chunks,
		add_compress
	};
	struct sChunkLen {
		sChunkLen() {
			len = 0;
			decompress_len = 0;
		}
		u_int32_t len;
		u_int32_t decompress_len;
	};
	struct sChunk : sChunkLen {
		sChunk() {
			len = 0;
			decompress_len = 0;
		}
		void deleteChunk(ChunkBuffer *chunkBuffer) {
			if(chunk) {
				delete [] chunk;
				chunk = NULL;
				__SYNC_SUB(chunkBuffer->chunk_buffer_size, len);
				__SYNC_SUB(ChunkBuffer::chunk_buffers_sumsize, len);
			}
		}
		char *chunk;
	};
	struct sChunkIterateCompleteBufferInfo {
		sChunkIterateCompleteBufferInfo() {
			init();
		}
		void init() {
			buffer = NULL;
			bufferLen = 0;
			bufferPos = 0;
			counter = 0;
			allPos = 0;
			chunkPos = 0;
			chunkIndex = 0;
		}
		void addPos(u_int32_t add) {
			allPos += add;
			chunkPos += add;
		}
		char *buffer;
		u_int32_t bufferLen;
		u_int32_t bufferPos;
		u_int32_t counter;
		sChunkLen chunkLen;
		sChunkLen chunkLenBuff;
		u_int32_t allPos;
		u_int32_t chunkPos;
		u_int32_t chunkIndex;
	};
public:
	ChunkBuffer(int time, data_tar_time tar_time, bool need_tar_pos,
		    u_int32_t chunk_fix_len = 0, class Call_abstract *call = NULL, int typeContent = 0, int indexContent = 0,
		    const char *name = NULL);
	virtual ~ChunkBuffer();
	void setTypeCompress(CompressStream::eTypeCompress typeCompress, u_int32_t compressBufferLength, u_int32_t maxDataLength);
	void setCompressLevel(int compressLevel);
	CompressStream::eTypeCompress getTypeCompress();
	int getTime() {
		return(time);
	}
	data_tar_time getTarTime() {
		return(tar_time);
	}
	string getName() {
		return(this->name);
	}
	const char *getName_c_str() {
		return(this->name.c_str());
	}
	void add(char *data, u_int32_t len, bool flush = false, u_int32_t decompress_len = 0, bool directAdd = false);
	void close();
	bool isClosed() {
		return(closed);
	}
	bool isDecompressError() {
		return(decompressError);
	}
	u_int32_t getLen() {
		return(this->compressStream ? compress_orig_data_len : len);
	}
	u_int32_t getChunkIterateProceedLen() {
		return(this->chunkIterateProceedLen);
	}
	u_int32_t getChunkIterateLenForProceed() {
		return((this->compressStream ? compress_orig_data_len : len) - this->chunkIterateProceedLen);
	}
	unsigned int getLastAddTime() {
		return(last_add_time);
	}
	void setLastTarTime(unsigned int time) {
		last_tar_time = time;
	}
	unsigned int getLastTarTime() {
		return(last_tar_time);
	}
	void copyLastAddTimeToTar() {
		last_add_time_tar = last_add_time;
	}
	bool isNewLastAddTimeForTar() {
		return(last_add_time >= last_add_time_tar);
	}
	virtual bool compress_ev(char *data, u_int32_t len, u_int32_t decompress_len, bool format_data = false);
	virtual bool decompress_ev(char *data, u_int32_t len);
	void chunkIterate(ChunkBuffer_baseIterate *chunkbufferIterateEv, bool freeChunks = false, bool enableContinue = false, u_int32_t limitLength = 0);
	void deleteChunks();
	bool allChunksIsEmpty();
	u_int32_t getChunkIterateSafeLimitLength(u_int32_t limitLength);
	void lock_chunkBuffer() {
		__SYNC_LOCK(this->_sync_chunkBuffer);
	}
	void unlock_chunkBuffer() {
		__SYNC_UNLOCK(this->_sync_chunkBuffer);
	}
	void lock_compress() {
		__SYNC_LOCK(this->_sync_compress);
	}
	void unlock_compress() {
		__SYNC_UNLOCK(this->_sync_compress);
	}
	void addTarPosInCall(u_int64_t pos);
	bool isFull() {
		return(this->chunk_buffer_size > 4 * 128 * 1024);
	}
	static u_int64_t getChunkBuffersSumsize() {
		return(chunk_buffers_sumsize);
	}
	inline bool get_warning_try_write_to_closed_tar() {
		return(warning_try_write_to_closed_tar);
	}
	inline void set_warning_try_write_to_closed_tar() {
		warning_try_write_to_closed_tar = true;
	}
private:
	void strange_log(const char *error);
private:
	int time;
	data_tar_time tar_time;
	bool need_tar_pos;
	Call_abstract *call;
	int typeContent;
	int indexContent;
	string name;
	string fbasename;
	list<sChunk> chunkBuffer;
	volatile unsigned int chunkBuffer_countItems;
	volatile u_int32_t len;
	u_int32_t chunk_fix_len;
	volatile u_int32_t compress_orig_data_len;
	sChunk *lastChunk;
	CompressStream *compressStream;
	ChunkBuffer_baseIterate *decompress_chunkbufferIterateEv;
	u_int32_t decompress_pos;
	sChunkIterateCompleteBufferInfo chunkIterateCompleteBufferInfo;
	volatile u_int32_t chunkIterateProceedLen;
	volatile bool closed;
	bool decompressError;
	volatile int _sync_chunkBuffer;
	volatile int _sync_compress;
	unsigned int last_add_time;
	unsigned int last_add_time_tar;
	unsigned int last_tar_time;
	volatile u_int64_t chunk_buffer_size;
	u_int64_t created_at;
	bool warning_try_write_to_closed_tar;
static volatile u_int64_t chunk_buffers_sumsize;
};      


#endif
