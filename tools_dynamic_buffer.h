#ifndef TOOLS_DYNAMIC_BUFFER_H
#define TOOLS_DYNAMIC_BUFFER_H

#include <list>
#include <string.h>
#include <string>
#include <iostream>
#include <sys/types.h>
#include <algorithm>
#include <zlib.h>
#ifdef HAVE_LIBLZ4
#include <lz4.h>
#endif //HAVE_LIBLZ4
#include <snappy-c.h>


using namespace std;


/* not tested - obsolete ?
class DynamicBuffer {
public:
	class DynamicBufferItem {
	public:
		DynamicBufferItem(DynamicBuffer *owner, u_int32_t length = 0) {
			this->owner = owner;
			this->buffer_length = this->getBufferLength(length);
			if(this->buffer_length) {
				this->buffer = new u_char[this->buffer_length];
			} else {
				this->buffer = NULL;
			}
			this->length = 0;
			this->next = NULL;
		}
		DynamicBufferItem *add(u_char *buffer, u_int32_t length, u_int32_t offset = 0) {
			if(offset >= length) {
				return(this);
			}
			if(!this->buffer) {
				this->buffer_length = this->getBufferLength(length - offset);
				this->buffer = new u_char[this->buffer_length];
			}
			if(this->length < this->buffer_length) {
				if(length - offset <= this->buffer_length - this->length) {
					memcpy(this->buffer + this->length, buffer + offset, length - offset);
					this->length += length - offset;
					return(this);
				} else {
					memcpy(this->buffer + this->length, buffer + offset, this->buffer_length - this->length);
					offset += this->buffer_length - this->length;
					this->length = this->buffer_length;
				}
			}
			if(!this->next) {
				this->next = new DynamicBufferItem(this->owner, length - offset);
			}
			return(this->next->add(buffer, length, offset));
		}
		u_int32_t getBufferLength(u_int32_t length) {
			if(owner->min_item_buffer_length && length < owner->min_item_buffer_length) {
				length = owner->min_item_buffer_length;
			}
			if(owner->max_item_buffer_length && owner->max_item_buffer_length > owner->min_item_buffer_length &&
			   length > owner->max_item_buffer_length) {
				length = owner->max_item_buffer_length;
			}
			return(length);
		}
	public:
		u_int32_t buffer_length;
		u_char *buffer;
		u_int32_t length;
		DynamicBufferItem *next;
		DynamicBuffer *owner;
	};
public:
	DynamicBuffer() {
		this->first = NULL;
		this->last = NULL;
		this->min_item_buffer_length = 0;
		this->max_item_buffer_length = 0;
	}
	virtual ~DynamicBuffer() {
		this->free();
	}
	void add(u_char *buffer, u_int32_t length) {
		if(!length) {
			return;
		}
		if(!this->first) {
			this->first = new DynamicBufferItem(this, length);
			this->last = this->first;
		}
		this->last = this->last->add(buffer, length);
	}
	void free() {
		DynamicBufferItem *iter[2] = { this->first, NULL };
		while(iter[0]) {
			iter[1] = iter[0]->next;
			delete iter[0];
			iter[0] = iter[1];
		}
		this->first = NULL;
		this->last = NULL;
	}
	u_int32_t getSize() {
		u_int32_t size = 0;
		DynamicBufferItem *iter = this->first;
		while(iter) {
			size += iter->length;
			iter = iter->next;
		}
		return(size);
	}
	bool isEmpty() {
		return(!this->first);
	}
	void setMinItemBufferLength(u_int32_t min_item_buffer_length) {
		this->min_item_buffer_length = min_item_buffer_length;
	}
	void setMaxItemBufferLength(u_int32_t max_item_buffer_length) {
		this->max_item_buffer_length = max_item_buffer_length;
	}
	void cout(bool itemSeparator = false);
	u_char *getConcatBuffer();
	virtual void write(const char *fileName, int time) {}
private:
	DynamicBufferItem *first;
	DynamicBufferItem *last;
	u_int32_t min_item_buffer_length;
	u_int32_t max_item_buffer_length;
friend class DynamicBufferItem;
};

class DynamicBufferTar : public DynamicBuffer {
public:
	virtual void write(const char *fileName, int time);
};
*/


class CompressStream_baseEv {
public:
	virtual bool compress_ev(char *data, u_int32_t len, u_int32_t decompress_len) { return(true); }
	virtual bool decompress_ev(char *data, u_int32_t len) { return(true); }
};

class CompressStream {
public:
	enum eTypeCompress {
		compress_na,
		zip,
		gzip,
		lz4,
		lz4_stream,
		snappy
	};
public:
	CompressStream(eTypeCompress typeCompress, u_int32_t compressBufferLength, u_int32_t maxDataLength);
	~CompressStream();
	void setZipLevel(int zipLevel);
	void initCompress();
	void initDecompress(u_int32_t dataLen);
	void termCompress();
	void termDecompress();
	bool compress(char *data, u_int32_t len, bool flush, CompressStream_baseEv *baseEv);
	bool decompress(char *data, u_int32_t len, u_int32_t decompress_len, bool flush, CompressStream_baseEv *baseEv);
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
	static eTypeCompress convTypeCompress(const char *typeCompress);
private:
	void createCompressBuffer();
	void createDecompressBuffer(u_int32_t bufferLen);
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
	#ifdef HAVE_LIBLZ4
	LZ4_stream_t *lz4Stream;
	LZ4_streamDecode_t *lz4StreamDecode;
	#endif //HAVE_LIBLZ4
	string errorString;
	int zipLevel;
	u_int32_t processed_len;
friend class ChunkBuffer;
};

class ChunkBuffer_baseIterate {
public:
	virtual void chunkbuffer_iterate_ev(char *data, u_int32_t len, u_int32_t pos) {}
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
	struct eChunkLen {
		eChunkLen() {
			len = 0;
			decompress_len = 0;
		}
		u_int32_t len;
		u_int32_t decompress_len;
	};
	struct eChunk : eChunkLen {
		eChunk() {
			len = 0;
			decompress_len = 0;
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
		eChunkLen chunkLen;
		eChunkLen chunkLenBuff;
		u_int32_t allPos;
		u_int32_t chunkPos;
		u_int32_t chunkIndex;
	};
public:
	ChunkBuffer(u_int32_t chunk_fix_len = 0);
	virtual ~ChunkBuffer();
	void setTypeCompress(CompressStream::eTypeCompress typeCompress, u_int32_t compressBufferLength, u_int32_t maxDataLength);
	void setZipLevel(int zipLevel);
	void setName(const char *name);
	string getName() {
		return(this->name ? this->name : "");
	}
	void add(char *data, u_int32_t len, bool flush = false, u_int32_t decompress_len = 0, bool directAdd = false);
	void close() {
		this->closed = true;
	}
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
	virtual bool compress_ev(char *data, u_int32_t len, u_int32_t decompress_len);
	virtual bool decompress_ev(char *data, u_int32_t len);
	void chunkIterate(ChunkBuffer_baseIterate *chunkbufferIterateEv, bool freeChunks = false, bool enableContinue = false, u_int32_t limitLength = 0);
	u_int32_t getChunkIterateSafeLimitLength(u_int32_t limitLength);
	void lock_chunkBuffer() {
		while(__sync_lock_test_and_set(&this->_sync_chunkBuffer, 1));
	}
	void unlock_chunkBuffer() {
		__sync_lock_release(&this->_sync_chunkBuffer);
	}
	void lock_compress() {
		while(__sync_lock_test_and_set(&this->_sync_compress, 1));
	}
	void unlock_compress() {
		__sync_lock_release(&this->_sync_compress);
	}
private:
	list<eChunk> chunkBuffer;
	volatile u_int32_t len;
	u_int32_t chunk_fix_len;
	volatile u_int32_t compress_orig_data_len;
	eChunk *lastChunk;
	CompressStream *compressStream;
	u_int32_t iterate_index;
	ChunkBuffer_baseIterate *decompress_chunkbufferIterateEv;
	u_int32_t decompress_pos;
	sChunkIterateCompleteBufferInfo chunkIterateCompleteBufferInfo;
	volatile u_int32_t chunkIterateProceedLen;
	bool closed;
	bool decompressError;
	char *name;
	volatile int _sync_chunkBuffer;
	volatile int _sync_compress;
};      


#endif
