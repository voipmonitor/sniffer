#include "voipmonitor.h"
#include "tools.h"

#include "tools_dynamic_buffer.h"

#define MIN(x,y) ((x) < (y) ? (x) : (y))


/* not tested - obsolete ?
void DynamicBuffer::cout(bool itemSeparator) {
	DynamicBufferItem *iter = this->first;
	while(iter) {
		std::string str = std::string((char*)iter->buffer, iter->length);
		std::cout << str;
		if(itemSeparator) {
			std::cout << '|';
		}
		iter = iter->next;
	}
}

u_char *DynamicBuffer::getConcatBuffer() {
	u_int32_t size = this->getSize();
	if(!size) {
		return(NULL);
	}
	u_char *concatBuffer = new u_char[size + 1];
	u_int32_t length = 0;
	DynamicBufferItem *iter = this->first;
	while(iter) {
		memcpy(concatBuffer + length, iter->buffer, iter->length);
		length += iter->length;
		iter = iter->next;
	}
	concatBuffer[length] = 0;
	return(concatBuffer);
}

void DynamicBufferTar::write(const char *fileName, int time) {
	u_int32_t tarBufferSize = this->getSize();
	if(tarBufferSize) {
		u_char *concatTarBuffer = this->getConcatBuffer();
		if(concatTarBuffer) {
			
			//tarQueue->add(fileName, time, (char*)concatTarBuffer, tarBufferSize);
			delete [] concatTarBuffer;
		}
	}
}
*/


CompressStream::CompressStream(eTypeCompress typeCompress, u_int32_t compressBufferLength, u_int32_t maxDataLength) {
	this->typeCompress = typeCompress;
	this->compressBufferLength = compressBufferLength;
	this->compressBufferBoundLength = 0;
	this->compressBuffer = NULL;
	this->decompressBufferLength = compressBufferLength;
	this->decompressBuffer = NULL;
	this->maxDataLength = maxDataLength;
	this->zipStream = NULL;
	this->zipStreamDecompress = NULL;
	this->lz4Stream = NULL;
	this->lz4StreamDecode = NULL;
	this->zipLevel = Z_DEFAULT_COMPRESSION;
	this->processed_len = 0;
}

CompressStream::~CompressStream() {
	this->termCompress();
	this->termDecompress();
}

void CompressStream::setZipLevel(int zipLevel) {
	this->zipLevel = zipLevel;
}

void CompressStream::initCompress() {
	switch(this->typeCompress) {
	case compress_na:
		break;
	case zip:
	case gzip:
		if(!this->zipStream) {
			this->zipStream =  new z_stream;
			this->zipStream->zalloc = Z_NULL;
			this->zipStream->zfree = Z_NULL;
			this->zipStream->opaque = Z_NULL;
			if((this->typeCompress == zip ?
			     deflateInit(this->zipStream, this->zipLevel) :
			     deflateInit2(this->zipStream, this->zipLevel, Z_DEFLATED, MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY)) == Z_OK) {
				createCompressBuffer();
			} else {
				deflateEnd(this->zipStream);
				this->setError("zip initialize failed");
				break;
			}
		}
		break;
	case lz4:
		if(!this->compressBuffer) {
			createCompressBuffer();
		}
		break;
	case lz4_stream:
		if(!this->lz4Stream) {
			this->lz4Stream = LZ4_createStream();
			createCompressBuffer();
		}
		break;
	case snappy:
		if(!this->compressBuffer) {
			createCompressBuffer();
		}
		break;
	}
}

void CompressStream::initDecompress(u_int32_t dataLen) {
	switch(this->typeCompress) {
	case compress_na:
		break;
	case zip:
		if(!this->zipStreamDecompress) {
			this->zipStreamDecompress =  new z_stream;
			this->zipStreamDecompress->zalloc = Z_NULL;
			this->zipStreamDecompress->zfree = Z_NULL;
			this->zipStreamDecompress->opaque = Z_NULL;
			this->zipStreamDecompress->avail_in = 0;
			this->zipStreamDecompress->next_in = Z_NULL;
			if(inflateInit(this->zipStreamDecompress) == Z_OK) {
				createDecompressBuffer(this->decompressBufferLength);
			} else {
				inflateEnd(this->zipStreamDecompress);
				this->setError("unzip initialize failed");
			}
		}
		break;
	case lz4:
		createDecompressBuffer(dataLen);
		break;
	case lz4_stream:
		if(!this->lz4StreamDecode) {
			this->lz4StreamDecode = LZ4_createStreamDecode();
		}
		createDecompressBuffer(dataLen);
		break;
	case snappy:
		createDecompressBuffer(dataLen);
		break;
	case gzip:
		//not supported
		break;
	}
}

void CompressStream::termCompress() {
	if(this->zipStream) {
		deflateEnd(this->zipStream);
		delete this->zipStream;
		this->zipStream = NULL;
	}
	if(this->zipStreamDecompress) {
		inflateEnd(this->zipStreamDecompress);
		delete this->zipStreamDecompress;
		this->zipStreamDecompress = NULL;
	}
	if(this->lz4Stream) {
		LZ4_freeStream(this->lz4Stream);
		this->lz4Stream = NULL;
	}
	if(this->compressBuffer) {
		delete [] this->compressBuffer;
		this->compressBuffer = NULL;
	}
}

void CompressStream::termDecompress() {
	if(this->lz4StreamDecode) {
		LZ4_freeStreamDecode(this->lz4StreamDecode);
		this->lz4StreamDecode = NULL;
	}
	if(this->decompressBuffer) {
		delete [] this->decompressBuffer;
		this->decompressBuffer = NULL;
	}
}

bool CompressStream::compress(char *data, u_int32_t len, bool flush, CompressStream_baseEv *baseEv) {
	if(this->isError()) {
		return(false);
	}
	if(!(len || (flush && this->processed_len))) {
		return(true);
	}
	switch(this->typeCompress) {
	case compress_na:
		if(!baseEv->compress_ev(data, len, len)) {
			this->setError("compress_ev failed");
			return(false);
		}
		break;
	case zip: 
	case gzip: {
		if(!this->zipStream) {
			this->initCompress();
		}
		this->zipStream->avail_in = len;
		this->zipStream->next_in = (unsigned char*)data;
		do {
			this->zipStream->avail_out = this->compressBufferLength;
			this->zipStream->next_out = (unsigned char*)this->compressBuffer;
			int deflateRslt = deflate(this->zipStream, flush ? Z_FINISH : Z_NO_FLUSH);
			if(deflateRslt == Z_OK || deflateRslt == Z_STREAM_END) {
				int have = this->compressBufferLength - this->zipStream->avail_out;
				if(!baseEv->compress_ev(this->compressBuffer, have, 0)) {
					this->setError("zip compress_ev failed");
					return(false);
				}
			} else {
				this->setError(string("zip compress failed") + 
					       (this->zipStream->msg ?
						 string(" ") + this->zipStream->msg :
						 ""));
				return(false);
			}
		} while(this->zipStream->avail_out == 0);
		this->processed_len += len;
		}
		break;
	case lz4: {
		if(!this->compressBuffer) {
			this->initCompress();
		}
		size_t compressLength = LZ4_compress(data, this->compressBuffer, len);
		if(compressLength > 0) {
			if(baseEv->compress_ev(this->compressBuffer, compressLength, len)) {
				this->processed_len += len;
			} else {
				this->setError("lz4 compress_ev failed");
				return(false);
			}
		} else {
			this->setError("lz4 compress failed");
			return(false);
		}
		}
		break;
	case lz4_stream: {
		if(!this->lz4Stream) {
			this->initCompress();
		}
		u_int32_t pos = 0;
		while(pos < len) {
			u_int32_t inputLen = min(this->compressBufferLength, len - pos);
			u_int32_t have = LZ4_compress_continue(this->lz4Stream, data + pos, this->compressBuffer, inputLen);
			if(have > 0) {
				if(!baseEv->compress_ev(this->compressBuffer, have, inputLen)) {
					this->setError("lz4 compress_ev failed");
					return(false);
				}
			} else {
				break;
			}
			pos += this->compressBufferLength;
		}
		this->processed_len += len;
		}
		break;
	case snappy: {
		if(!this->compressBuffer) {
			this->initCompress();
		}
		size_t compressLength = this->compressBufferBoundLength;
		snappy_status snappyRslt = snappy_compress(data, len, this->compressBuffer, &compressLength);
		switch(snappyRslt) {
		case SNAPPY_OK:
			if(baseEv->compress_ev(this->compressBuffer, compressLength, len)) {
				this->processed_len += len;
			} else {
				this->setError("snappy compress_ev failed");
				return(false);
			}
			break;
		case SNAPPY_INVALID_INPUT:
			this->setError("snappy compress failed - invalid input");
			return(false);
		case SNAPPY_BUFFER_TOO_SMALL:
			this->setError("snappy compress failed - buffer is too small");
			return(false);
		default:
			this->setError("snappy compress failed -  unknown error");
			return(false);
		}
		}
		break;
	}
	return(true);
}

bool CompressStream::decompress(char *data, u_int32_t len, u_int32_t decompress_len, bool flush, CompressStream_baseEv *baseEv) {
	if(sverb.chunk_buffer) {
		cout << "decompress data " << len << " " << decompress_len << endl;
		for(u_int32_t i = 0; i < min(len, 20u); i++) {
			cout << (int)(unsigned char)data[i] << ",";
		}
		cout << endl;
	}
	if(this->isError()) {
		return(false);
	}
	if(!len) {
		return(true);
	}
	switch(this->typeCompress) {
	case compress_na:
		if(!baseEv->decompress_ev(data, len)) {
			this->setError("decompress_ev failed");
			return(false);
		}
		break;
	case zip:
		if(!this->zipStreamDecompress) {
			this->initDecompress(0);
		}
		this->zipStreamDecompress->avail_in = len;
		this->zipStreamDecompress->next_in = (unsigned char*)data;
		do {
			this->zipStreamDecompress->avail_out = this->decompressBufferLength;
			this->zipStreamDecompress->next_out = (unsigned char*)this->decompressBuffer;
			int inflateRslt = inflate(this->zipStreamDecompress, Z_NO_FLUSH);
			if(inflateRslt == Z_OK || inflateRslt == Z_STREAM_END) {
				int have = this->decompressBufferLength - this->zipStreamDecompress->avail_out;
				if(!baseEv->decompress_ev(this->decompressBuffer, have)) {
					this->setError("zip decompress_ev failed");
					return(false);
				}
			} else {
				this->setError(string("zip decompress failed") + 
					       (this->zipStreamDecompress->msg ?
						 string(" ") + this->zipStreamDecompress->msg :
						 ""));
				return(false);
			}
		} while(this->zipStreamDecompress->avail_out == 0);
		break;
	case lz4:
		if(!this->decompressBuffer || !this->maxDataLength) {
			this->initDecompress(decompress_len);
		}
		if(LZ4_decompress_fast(data, this->decompressBuffer, decompress_len)) {
			if(!baseEv->decompress_ev(this->decompressBuffer, decompress_len)) {
				this->setError("lz4 decompress_ev failed");
				return(false);
			}
		} else {
			this->setError("lz4 decompress failed");
			return(false);
		}
		break;
	case lz4_stream:
		if(!this->lz4StreamDecode) {
			this->initDecompress(decompress_len);
		}
		if(!this->decompressBuffer || !this->maxDataLength) {
			this->createDecompressBuffer(decompress_len);
		}
		if(LZ4_decompress_safe_continue(this->lz4StreamDecode, data, this->decompressBuffer, len, this->decompressBufferLength) > 0) {
			if(!baseEv->decompress_ev(this->decompressBuffer, decompress_len)) {
				this->setError("lz4 decompress_ev failed");
				return(false);
			}
		} else {
			this->setError("lz4 decompress failed");
			return(false);
		}
		break;
	case snappy: {
		if(!this->decompressBuffer || !this->maxDataLength) {
			this->initDecompress(decompress_len);
		}
		size_t decompressLength = this->decompressBufferLength;
		snappy_status snappyRslt = snappy_uncompress(data, len, this->decompressBuffer, &decompressLength);
		switch(snappyRslt) {
		case SNAPPY_OK:
			if(!baseEv->decompress_ev(this->decompressBuffer, decompress_len)) {
				this->setError("snappy decompress_ev failed");
				return(false);
			}
			break;
		case SNAPPY_INVALID_INPUT:
			this->setError("snappy decompress failed - invalid input");
			return(false);
		case SNAPPY_BUFFER_TOO_SMALL:
			this->setError("snappy decompress failed - buffer is too small");
			return(false);
		default:
			this->setError("snappy decompress failed - unknown error");
			return(false);
		}
		}
		break;
	case gzip:
		//not supported
		break;
	}
	return(true);
}

void CompressStream::createCompressBuffer() {
	if(this->compressBuffer) {
		return;
	}
	switch(this->typeCompress) {
	case compress_na:
		break;
	case zip:
	case gzip:
		this->compressBuffer = new char[this->compressBufferLength];
		break;
	case lz4:
	case lz4_stream:
		if(this->maxDataLength) {
			this->compressBufferLength = this->maxDataLength;
		}
		this->compressBufferBoundLength = LZ4_compressBound(this->compressBufferLength);
		this->compressBuffer = new char[this->compressBufferBoundLength];
		break;
	case snappy:
		if(this->maxDataLength) {
			this->compressBufferLength = this->maxDataLength;
		}
		this->compressBufferBoundLength = snappy_max_compressed_length(this->compressBufferLength);
		this->compressBuffer = new char[this->compressBufferBoundLength];
		break;
	}
}

void CompressStream::createDecompressBuffer(u_int32_t bufferLen) {
	if(this->decompressBuffer) {
		if(this->decompressBufferLength >= bufferLen) {
			return;
		} else {
			delete [] this->decompressBuffer;
			this->decompressBuffer = NULL;
		}
	}
	switch(this->typeCompress) {
	case compress_na:
		break;
	case zip:
		this->decompressBuffer = new char[this->decompressBufferLength];
		break;	
	case lz4:
	case lz4_stream:
	case snappy:
		this->decompressBufferLength = max(this->maxDataLength, bufferLen);
		this->decompressBuffer = new char[this->decompressBufferLength];
		break;
	case gzip:
		//not supported
		break;
	}
}

CompressStream::eTypeCompress CompressStream::convTypeCompress(const char *typeCompress) {
	char _compress_method[10];
	strncpy(_compress_method, typeCompress, sizeof(_compress_method));
	strlwr(_compress_method, sizeof(_compress_method));
	if(!strcmp(_compress_method, "zip")) {
		return(CompressStream::zip);
	} else if(!strcmp(_compress_method, "snappy")) {
		return(CompressStream::snappy);
	} else if(!strcmp(_compress_method, "lz4")) {
		return(CompressStream::lz4);
	} else if(!strcmp(_compress_method, "lz4_stream")) {
		return(CompressStream::lz4_stream);
	}
	return(CompressStream::compress_na);
}

ChunkBuffer::ChunkBuffer(u_int32_t chunk_fix_len) {
	this->len = 0;
	this->chunk_fix_len = chunk_fix_len;
	this->compress_orig_data_len = 0;
	this->lastChunk = NULL;
	this->compressStream = NULL;
}

ChunkBuffer::~ChunkBuffer() {
	list<eChunk>::iterator it = chunkBuffer.begin();
	for(it = chunkBuffer.begin(); it != chunkBuffer.end(); it++) {
		if(it->chunk) {
			delete [] it->chunk;
		}
	}
	if(this->compressStream) {
		delete this->compressStream;
	}
}

void ChunkBuffer::setTypeCompress(CompressStream::eTypeCompress typeCompress, u_int32_t compressBufferLength, u_int32_t maxDataLength) {
	switch(typeCompress) {
	case CompressStream::zip:
	case CompressStream::lz4:
	case CompressStream::lz4_stream:
	case CompressStream::snappy:
		this->compressStream = new CompressStream(typeCompress, compressBufferLength, maxDataLength);
		break;
	default:
		break;
	}
}

void ChunkBuffer::setZipLevel(int zipLevel) {
	if(this->compressStream) {
		this->compressStream->setZipLevel(zipLevel);
	}
}

#include <stdio.h>

void ChunkBuffer::add(char *data, u_int32_t datalen, bool flush, u_int32_t decompress_len, bool directAdd) {
	if(!datalen) {
		return;
	}
	if(sverb.chunk_buffer) {
		if(directAdd) {
			cout << "add compress data " << datalen << endl;
			for(u_int32_t i = 0; i < min(datalen, 20u); i++) {
				cout << (int)(unsigned char)data[i] << ",";
			}
			cout << endl;
		} else {
			cout << "add source data " << datalen << endl;
			for(u_int32_t i = 0; i < min(datalen, 20u); i++) {
				cout << (int)(unsigned char)data[i] << ",";
			}
			cout << endl;
		}
	}
	eAddMethod addMethod = add_na;
	if(directAdd) {
		if(this->chunk_fix_len) {
			if(this->compressStream->typeCompress == CompressStream::zip) {
				addMethod = add_fill_fix_len;
			} else {
				addMethod = add_fill_chunks;
			}
		} else {
			addMethod = add_simple;
		}
	} else {
		if(this->compressStream) {
			addMethod = add_compress;
		} else if(this->chunk_fix_len) {
			addMethod = add_fill_fix_len;
		} else {
			addMethod = add_simple;
		}
	}
	switch(addMethod) {
	case add_simple: {
		eChunk chunk;
		chunk.chunk = new char[datalen];
		memcpy(chunk.chunk, data, datalen);
		chunk.len = datalen;
		chunk.decompress_len = decompress_len;
		this->chunkBuffer.push_back(chunk);
		this->len += datalen;
		}
		break;
	case add_fill_chunks: {
		for(int i = 0; i < 2; i++) {
			char *_data;
			u_int32_t _len;
			eChunkLen chunkLen;
			if(i == 0) {
				chunkLen.len = datalen;
				chunkLen.decompress_len = decompress_len;
				_data = (char*)&chunkLen;
				_len = sizeof(chunkLen);
			} else {
				_data = data;
				_len = datalen;
			}
			u_int32_t pos = 0;
			while(pos < _len) {
				if(!this->lastChunk ||
				   this->lastChunk->len == this->chunk_fix_len) {
					eChunk chunk;
					chunk.chunk = new char[this->chunk_fix_len];
					chunk.len = 0;
					chunk.decompress_len = (u_int32_t)-1;
					this->chunkBuffer.push_back(chunk);
					this->lastChunk = &(*(--this->chunkBuffer.end()));
				}
				u_int32_t copied = min(_len - pos, this->chunk_fix_len - this->lastChunk->len);
				memcpy(this->lastChunk->chunk + this->lastChunk->len, _data + pos, copied);
				this->lastChunk->len += copied;
				this->len += copied;
				pos +=copied;
			}
		}
		}
		break;
	case add_fill_fix_len: {
		u_int32_t copied = 0;
		do {
			if(!(this->len % this->chunk_fix_len)) {
				eChunk chunk;
				chunk.chunk = new char[this->chunk_fix_len];
				this->chunkBuffer.push_back(chunk);
				this->lastChunk = &(*(--this->chunkBuffer.end()));
			}
			int whattocopy = MIN(this->chunk_fix_len - this->len % this->chunk_fix_len, datalen - copied);
			memcpy(this->lastChunk->chunk + this->len % this->chunk_fix_len, data + copied, whattocopy);
			copied += whattocopy;
			this->len += whattocopy;
			this->lastChunk->len += whattocopy;
		} while(datalen > copied);
		}
		break;
	case add_compress:
		this->compressStream->compress(data, datalen, flush, this);
		this->compress_orig_data_len += datalen;
		break;
	case add_na:
		break;
	}
}

bool ChunkBuffer::compress_ev(char *data, u_int32_t len, u_int32_t decompress_len) {
	this->add(data, len, false, decompress_len, true);
	return(true);
}

bool ChunkBuffer::decompress_ev(char *data, u_int32_t len) {
 	decompress_chunkbufferIterateEv->chunkbuffer_iterate_ev(data, len, this->decompress_pos);
	this->decompress_pos += len;
	if(sverb.chunk_buffer) {
		cout << "decompress ev " << len << " " << this->decompress_pos << " " << endl;
		for(u_int32_t i = 0; i < min(len, 10u); i++) {
			cout << (int)(unsigned char)data[i] << ",";
		}
		cout << endl;
	}
	return(true);
}

void ChunkBuffer::chunkIterate(ChunkBuffer_baseIterate *chunkbufferIterateEv, bool freeChunks) {
	if(this->compressStream) {
		this->decompress_chunkbufferIterateEv = chunkbufferIterateEv;
		this->decompress_pos = 0;
		list<eChunk>::iterator it = chunkBuffer.begin();
		size_t size = chunkBuffer.size();
		size_t counter = 0;
		char *completeBuffer = NULL;
		u_int32_t completeBufferLen = 0;
		u_int32_t completeBufferPos = 0;
		u_int32_t completeBufferCounter = 0;
		eChunkLen completeBufferChunkLen;
		eChunkLen completeBufferChunkLenBuff;
		u_int32_t allPos;
		for(it = chunkBuffer.begin(); it != chunkBuffer.end(); it++) {
			++counter;
			if(it->decompress_len == (u_int32_t)-1) {
				u_int32_t chunkPos = 0;
				while(chunkPos < it->len) {
					if(!completeBufferCounter) {
						completeBufferChunkLen = *(eChunkLen*)it->chunk;
						++completeBufferCounter;
						completeBufferLen = completeBufferChunkLen.len;
						completeBufferPos = 0;
						chunkPos += sizeof(eChunkLen);
						allPos += sizeof(eChunkLen);
					}
					if(!completeBufferPos) {
						if(completeBufferLen <= it->len - chunkPos) {
							if(completeBufferCounter % 2) {
								this->compressStream->decompress(it->chunk + chunkPos, completeBufferChunkLen.len, completeBufferChunkLen.decompress_len, 
												 allPos + completeBufferChunkLen.len == this->len, this);
								completeBufferLen = sizeof(eChunkLen);
								chunkPos += completeBufferChunkLen.len;
								allPos += completeBufferChunkLen.len;
							} else {
								completeBufferChunkLen = *(eChunkLen*)(it->chunk + chunkPos);
								completeBufferLen = completeBufferChunkLen.len;
								chunkPos += sizeof(eChunkLen);
								allPos += sizeof(eChunkLen);
							}
							++completeBufferCounter;
							completeBufferPos = 0;
						} else {
							completeBuffer = completeBufferCounter % 2 ?
									  new char[completeBufferLen] :
									  (char*)&completeBufferChunkLenBuff;
							u_int32_t copied = it->len - chunkPos;
							memcpy(completeBuffer, it->chunk + chunkPos, copied);
							completeBufferPos += copied;
							chunkPos += copied;
							allPos += copied;
						}
					} else {
						u_int32_t copied = min(it->len - chunkPos, completeBufferLen - completeBufferPos);
						memcpy(completeBuffer + completeBufferPos, it->chunk + chunkPos, copied);
						completeBufferPos += copied;
						chunkPos += copied;
						allPos += copied;
						if(completeBufferPos == completeBufferLen) {
							 if(completeBufferCounter % 2) {
								this->compressStream->decompress(completeBuffer, completeBufferChunkLen.len, completeBufferChunkLen.decompress_len, 
												 allPos == this->len, this);
								completeBufferLen = sizeof(eChunkLen);
							} else {
								completeBufferChunkLen = *(eChunkLen*)completeBuffer;
								completeBufferLen = completeBufferChunkLen.len;
							}
							++completeBufferCounter;
							completeBufferPos = 0;
							if(completeBuffer != (char*)&completeBufferChunkLenBuff) {
								delete [] completeBuffer;
							}
						}
					}
				}
			} else {
				this->compressStream->decompress(it->chunk, it->len, it->decompress_len, counter == size, this);
			}
			if(freeChunks) {
				delete it->chunk;
				it->chunk = NULL;
			}
		}
		chunkbufferIterateEv->chunkbuffer_iterate_ev(NULL, 0 , this->decompress_pos);
		this->compressStream->termDecompress();
	} else {
		u_int32_t pos = 0;
		list<eChunk>::iterator it = chunkBuffer.begin();
		for(it = chunkBuffer.begin(); it != chunkBuffer.end(); it++) {
			chunkbufferIterateEv->chunkbuffer_iterate_ev(it->chunk, it->len, pos);
			if(freeChunks) {
				delete it->chunk;
				it->chunk = NULL;
			}
			pos += it->len;
		}
		chunkbufferIterateEv->chunkbuffer_iterate_ev(NULL, 0, pos);
	}
}