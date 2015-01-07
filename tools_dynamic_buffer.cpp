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


CompressStream::CompressStream(eTypeCompress typeCompress, u_int32_t compressBufferLength) {
	this->typeCompress = typeCompress;
	this->compressBufferLength = compressBufferLength;
	this->compressBufferBoundLength = 0;
	this->compressBuffer = NULL;
	this->decompressBufferLength = 0;
	this->decompressBuffer = NULL;
	this->zipStream = NULL;
	this->lz4Stream = NULL;
	this->lz4StreamDecode = NULL;
	this->zipLevel = Z_DEFAULT_COMPRESSION;
	this->compress_len = 0;
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
		if(this->zipStream) {
			break;
		}
		this->zipStream =  new z_stream;
		this->zipStream->zalloc = Z_NULL;
		this->zipStream->zfree = Z_NULL;
		this->zipStream->opaque = Z_NULL;
		if(deflateInit2(this->zipStream, this->zipLevel, Z_DEFLATED, MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
			deflateEnd(this->zipStream);
			this->setError("zip initialize failed");
		} else {
			if(this->compressBufferLength) {
				this->compressBuffer = new char[this->compressBufferLength];
			}
		}
		break;
	case lz4:
		if(this->lz4Stream) {
			break;
		}
		this->lz4Stream = LZ4_createStream();
		if(this->compressBufferLength) {
			this->compressBufferBoundLength = LZ4_compressBound(this->compressBufferLength);
			this->compressBuffer = new char[this->compressBufferBoundLength];
		}
		break;
	}
}

void CompressStream::initDecompress() {
	switch(this->typeCompress) {
	case compress_na:
		break;
	case zip:
		break;
	case lz4:
		if(this->lz4StreamDecode) {
			break;
		}
		this->lz4StreamDecode = LZ4_createStreamDecode();
		break;
	}
}

void CompressStream::termCompress() {
	if(this->zipStream) {
		delete this->zipStream;
		this->zipStream = NULL;
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
	if(flush ? !this->compress_len : !len) {
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
		if(!this->zipStream) {
			this->initCompress();
		}
		if(!this->compressBuffer) {
			this->createCompressBuffer(len);
		}
		this->zipStream->avail_in = len;
		this->zipStream->next_in = (unsigned char*)data;
		do {
			this->zipStream->avail_out = this->compressBufferLength;
			this->zipStream->next_out = (unsigned char*)this->compressBuffer;
			if(deflate(this->zipStream, flush ? Z_FINISH : Z_NO_FLUSH) != Z_STREAM_ERROR) {
				int have = this->compressBufferLength - this->zipStream->avail_out;
				if(!baseEv->compress_ev(this->compressBuffer, have, 0)) {
					this->setError("zip compress_ev failed");
					return(false);
				}
			} else {
				this->setError("zip compress failed");
				return(false);
			}
		} while(this->zipStream->avail_out == 0);
		this->compress_len += len;
		break;
	case lz4:
		if(!this->lz4Stream) {
			this->initCompress();
		}
		if(!this->compressBuffer) {
			this->createCompressBuffer(len);
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
		this->compress_len += len;
		break;
	}
	return(true);
}

bool CompressStream::decompress(char *data, u_int32_t len, u_int32_t decompress_len, CompressStream_baseEv *baseEv) {
	/*
	cout << "decompress data " << len << " " << decompress_len << endl;
	for(u_int32_t i = 0; i < len; i++) {
		cout << (int)(unsigned char)data[i] << ",";
	}
	cout << endl;
	*/
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
		this->setError("zip decompress is temporary not supported");
		break;
	case lz4:
		if(!this->lz4StreamDecode) {
			this->initDecompress();
		}
		if(!this->decompressBuffer || this->decompressBufferLength < decompress_len) {
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
	}
	return(true);
}

void CompressStream::createCompressBuffer(u_int32_t dataLen) {
	if(this->compressBuffer) {
		delete [] this->compressBuffer;
		this->compressBuffer = NULL;
	}
	switch(this->typeCompress) {
	case compress_na:
		break;
	case zip:
		this->compressBufferLength = dataLen;
		if(this->compressBufferLength) {
			this->compressBuffer = new char[this->compressBufferLength];
		}
		break;
	case lz4:
		this->compressBufferLength = dataLen;
		if(this->compressBufferLength) {
			this->compressBufferBoundLength = LZ4_compressBound(this->compressBufferLength);
			this->compressBuffer = new char[this->compressBufferBoundLength];
		}
		break;
	}
}

void CompressStream::createDecompressBuffer(u_int32_t dataLen) {
	if(this->decompressBuffer) {
		delete [] this->decompressBuffer;
		this->decompressBuffer = NULL;
	}
	switch(this->typeCompress) {
	case compress_na:
		break;
	case zip:
		this->decompressBufferLength = dataLen;
		if(this->decompressBufferLength) {
			this->decompressBuffer = new char[this->decompressBufferLength];
		}
		break;
	case lz4:
		this->decompressBufferLength = dataLen;
		if(this->decompressBufferLength) {
			this->decompressBuffer = new char[this->decompressBufferLength];
		}
		break;
	}
}

ChunkBuffer::ChunkBuffer(u_int32_t chunk_fix_len) {
	this->lastChunk = NULL;;
	this->len = 0;
	this->chunk_fix_len = chunk_fix_len;
	this->compressStream = NULL;
}

ChunkBuffer::~ChunkBuffer() {
	list<eChunk>::iterator it = chunkBuffer.begin();
	for(it = chunkBuffer.begin(); it != chunkBuffer.end(); it++) {
		delete [] it->chunk;
	}
	if(this->compressStream) {
		delete this->compressStream;
	}
}

void ChunkBuffer::setTypeCompress(CompressStream::eTypeCompress typeCompress, u_int32_t compressBufferLength) {
	switch(typeCompress) {
	case CompressStream::zip:
	case CompressStream::lz4:
		this->compressStream = new CompressStream(typeCompress, compressBufferLength);
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
	/*
	if(!directAdd) {
	 
		FILE *debugOut = fopen("/home/jumbox/Plocha/testdata", "at");
		fprintf(debugOut, "%u\n", datalen);
		for(u_int32_t i = 0; i < datalen; i++) {
			fprintf(debugOut, "%u,", (int)(unsigned char)data[i]);
		}
		fprintf(debugOut, "\n");
		fclose(debugOut);
		
	 
		cout << "add data " << datalen << endl;
		for(u_int32_t i = 0; i < datalen; i++) {
			cout << (int)(unsigned char)data[i] << ",";
		}
		cout << endl;
	}
	*/
	if(!datalen) {
		return;
	}
	if(directAdd ||
	   (!this->compressStream && !this->chunk_fix_len)) {
		eChunk chunk;
		chunk.chunk = new char[datalen];
		memcpy(chunk.chunk, data, datalen);
		chunk.len = datalen;
		chunk.decompress_len = decompress_len;
		this->chunkBuffer.push_back(chunk);
	} else if(this->compressStream) {
		this->compressStream->compress(data, datalen, flush, this);
		this->len += datalen;
	} else if(this->chunk_fix_len) {
		u_int32_t copied = 0;
		do {
			if(!this->lastChunk ||
			   !(this->len % this->chunk_fix_len)) {
				this->lastChunk = new char[this->chunk_fix_len];
				eChunk chunk;
				chunk.chunk = this->lastChunk;
				this->chunkBuffer.push_back(chunk);
			}
			int whattocopy = MIN(this->chunk_fix_len - len % this->chunk_fix_len, datalen - copied);
			memcpy(this->lastChunk + this->len % this->chunk_fix_len, data + copied, whattocopy);
			copied += whattocopy;
			this->len += whattocopy;
		} while(datalen > copied);
	}
}

bool ChunkBuffer::compress_ev(char *data, u_int32_t len, u_int32_t decompress_len) {
	this->add(data, len, false, decompress_len, true);
	return(true);
}

bool ChunkBuffer::decompress_ev(char *data, u_int32_t len) {
	decompress_chunkbufferIterateEv->chunkbuffer_iterate_ev(data, len, this->decompress_pos);
	this->decompress_pos += len;
	/*
	cout << "decompress ev " << len << " " << this->decompress_pos << " " << endl;
	for(u_int32_t i = 0; i < len; i++) {
		cout << (int)(unsigned char)data[i] << ",";
	}
	cout << endl;
	*/
	return(true);
}

void ChunkBuffer::chunkIterate(ChunkBuffer_baseIterate *chunkbufferIterateEv) {
	if(this->compressStream) {
		this->decompress_chunkbufferIterateEv = chunkbufferIterateEv;
		this->decompress_pos = 0;
		list<eChunk>::iterator it = chunkBuffer.begin();
		for(it = chunkBuffer.begin(); it != chunkBuffer.end(); it++) {
			this->compressStream->decompress(it->chunk, it->len, it->decompress_len, this);
		}
		chunkbufferIterateEv->chunkbuffer_iterate_ev(NULL, 0 , this->decompress_pos);
		this->compressStream->termDecompress();
	} else {
		u_int32_t pos = 0;
		list<eChunk>::iterator it = chunkBuffer.begin();
		for(it = chunkBuffer.begin(); it != chunkBuffer.end(); it++) {
			u_int32_t len = this->chunk_fix_len ?
					 (pos + this->chunk_fix_len > this->len ? this->len - pos : this->chunk_fix_len) :
					 it->len;
			chunkbufferIterateEv->chunkbuffer_iterate_ev(it->chunk, len, pos);
			pos += len;
		}
		chunkbufferIterateEv->chunkbuffer_iterate_ev(NULL, 0, pos);
	}
}