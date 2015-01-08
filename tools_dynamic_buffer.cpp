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
		if(this->zipStream) {
			break;
		}
		this->zipStream =  new z_stream;
		this->zipStream->zalloc = Z_NULL;
		this->zipStream->zfree = Z_NULL;
		this->zipStream->opaque = Z_NULL;
		if((this->typeCompress == zip ?
		     deflateInit(this->zipStream, this->zipLevel) :
		     deflateInit2(this->zipStream, this->zipLevel, Z_DEFLATED, MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY)) != Z_OK) {
			deflateEnd(this->zipStream);
			this->setError("zip initialize failed");
		} else {
			if(!this->compressBufferLength) {
				this->compressBufferLength = 8 * 1024;
			}
			this->compressBuffer = new char[this->compressBufferLength];
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
	case snappy:
		if(this->compressBufferLength) {
			this->compressBufferBoundLength = snappy_max_compressed_length(this->compressBufferLength);
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
		if(this->zipStreamDecompress) {
			break;
		}
		this->zipStreamDecompress =  new z_stream;
		this->zipStreamDecompress->zalloc = Z_NULL;
		this->zipStreamDecompress->zfree = Z_NULL;
		this->zipStreamDecompress->opaque = Z_NULL;
		this->zipStreamDecompress->avail_in = 0;
		this->zipStreamDecompress->next_in = Z_NULL;
		if(inflateInit(this->zipStreamDecompress) != Z_OK) {
			inflateEnd(this->zipStreamDecompress);
			this->setError("unzip initialize failed");
		} else {
			if(!this->decompressBufferLength) {
				this->decompressBufferLength = 8 * 1024;
			}
			this->decompressBuffer = new char[this->decompressBufferLength];
		}
		break;
	case lz4:
		if(this->lz4StreamDecode) {
			break;
		}
		this->lz4StreamDecode = LZ4_createStreamDecode();
		break;
	case snappy:
		break;
	case gzip:
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
	if(flush ? !this->processed_len : !len) {
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
		if(!this->compressBuffer) {
			this->createCompressBuffer(this->compressBufferLength);
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
	case lz4:
		/*
		{
		if(!this->lz4Stream) {
			this->initCompress();
		}
		if(!this->compressBuffer) {
			this->createCompressBuffer(len);
		}
		u_int32_t pos = 0;
		while(pos < len) {
		 
			#include "/home/jumbox/Plocha/lz4/lz4-read-only/examples/test_data_1"
			}};
			#include "/home/jumbox/Plocha/lz4/lz4-read-only/examples/test_data_2"
			};
			static int _i;
			static LZ4_stream_t *_lz4Stream;
			static LZ4_stream_t *_lz4Stream2;
			if(!_i) {
				_lz4Stream = LZ4_createStream();
				_lz4Stream2 = LZ4_createStream();
			}
			char *_data = (char*)testData[_i];
			int _len = testDataLength[_i];
			++_i;
			
			u_int32_t _inputLen = min(this->compressBufferLength, _len - pos);
			u_int32_t inputLen = min(this->compressBufferLength, len - pos);
			
			cout << inputLen << " / " << _inputLen << " / " << pos << endl;
			extern string GetDataMD5(u_char *data, u_int32_t datalen);
			cout << GetDataMD5((unsigned char*)_data, inputLen) << endl;
			cout << GetDataMD5((unsigned char*)data, inputLen) << endl;

			char *__data = new char[inputLen + 100];
			memcpy(__data, data, inputLen);
			u_int32_t have = LZ4_compress_continue(_lz4Stream2, _data + pos, this->compressBuffer, inputLen);
			u_int32_t _have = LZ4_compress_continue(_lz4Stream, _data + pos, this->compressBuffer, inputLen);
			
			have = LZ4_compress(data, this->compressBuffer, inputLen);
			
			cout << have << " / " << _have << endl;
			if(memcmp(__data, data, inputLen)) {
				cout << "diff buffer" << endl;
			}
			cout << GetDataMD5((unsigned char*)_data, inputLen) << endl;
			cout << GetDataMD5((unsigned char*)data, inputLen) << endl;
			
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
		}
		*/
		break;
	case snappy: {
		if(!this->compressBuffer) {
			this->createCompressBuffer(len);
		}
		size_t compressLength = this->compressBufferLength;
		snappy_status snappyRslt = snappy_compress(data, len, this->compressBuffer, &compressLength);
		switch(snappyRslt) {
		case SNAPPY_OK:
			baseEv->compress_ev(this->compressBuffer, compressLength, len);
			this->processed_len += len;
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
		if(!this->zipStreamDecompress) {
			this->initDecompress();
		}
		if(!this->decompressBuffer) {
			this->createDecompressBuffer(this->decompressBufferLength);
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
		/*
		if(!this->lz4StreamDecode) {
			this->initDecompress();
		}
		if(!this->decompressBuffer || this->decompressBufferLength < decompress_len) {
			this->createDecompressBuffer(decompress_len);
		}
		//if(LZ4_decompress_safe_continue(this->lz4StreamDecode, data, this->decompressBuffer, len, this->decompressBufferLength) > 0) {
		if(LZ4_decompress_fast(data, this->decompressBuffer, decompress_len)) {
			if(!baseEv->decompress_ev(this->decompressBuffer, decompress_len)) {
				this->setError("lz4 decompress_ev failed");
				return(false);
			}
		} else {
			this->setError("lz4 decompress failed");
			return(false);
		}
		*/
		break;
	case snappy: {
		if(!this->decompressBuffer || this->decompressBufferLength < decompress_len) {
			this->createDecompressBuffer(decompress_len);
		}
		size_t have = this->decompressBufferLength;
		snappy_status snappyRslt = snappy_uncompress(data, len, this->decompressBuffer, &have);
		
		switch(snappyRslt) {
		case SNAPPY_OK:
			baseEv->decompress_ev(this->decompressBuffer, decompress_len);
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
	case gzip:
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
	case snappy:
		this->compressBufferLength = snappy_max_compressed_length(dataLen);
		if(this->compressBufferLength) {
			this->compressBuffer = new char[this->compressBufferLength];
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
	case lz4:
	case snappy:
		this->decompressBufferLength = dataLen;
		if(this->decompressBufferLength) {
			this->decompressBuffer = new char[this->decompressBufferLength];
		}
		break;
	case gzip:
		break;
	}
}

ChunkBuffer::ChunkBuffer(u_int32_t chunk_fix_len) {
	this->len = 0;
	this->chunk_fix_len = chunk_fix_len;
	this->compress_orig_data_len = 0;
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

void ChunkBuffer::setTypeCompress(CompressStream::eTypeCompress typeCompress, u_int32_t compressBufferLength) {
	switch(typeCompress) {
	case CompressStream::zip:
	case CompressStream::lz4:
	case CompressStream::snappy:
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
	if(!datalen) {
		return;
	}
	
	if(directAdd) {
		/*
		cout << "add compress data " << datalen << endl;
		for(u_int32_t i = 0; i < min(datalen, 20u); i++) {
			cout << (int)(unsigned char)data[i] << ",";
		}
		cout << endl;
		*/
	} else {
		/*
		cout << "add source data " << datalen << endl;
		for(u_int32_t i = 0; i < min(datalen, 20u); i++) {
			cout << (int)(unsigned char)data[i] << ",";
		}
		cout << endl;
		*/
	
		/*
		static int pass = 0;
	 
		FILE *debugOut = fopen("/home/jumbox/Plocha/lz4/lz4-read-only/examples/test_data_1", pass ? "at" : "wt");
		fprintf(debugOut, pass ? "\n},{\n" : "unsigned char testData[50][10000] = { { \n");
		for(u_int32_t i = 0; i < datalen; i++) {
			fprintf(debugOut, "%u,", (int)(unsigned char)data[i]);
		}
		fclose(debugOut);
		
		debugOut = fopen("/home/jumbox/Plocha/lz4/lz4-read-only/examples/test_data_2", pass ? "at" : "wt");
		fprintf(debugOut, pass ? "," : "int testDataLength[50] = { \n");
		fprintf(debugOut, "%u", datalen);
		fclose(debugOut);
		
		++pass;
		*/
	}
	eAddMethod addMethod = add_na;
	if(directAdd) {
		if(this->chunk_fix_len && this->compressStream->typeCompress == CompressStream::zip) {
			addMethod = add_fill_fix_len;
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
		memset(chunk.chunk, 0, datalen);
		memcpy(chunk.chunk, data, datalen);
		chunk.len = datalen;
		chunk.decompress_len = decompress_len;
		this->chunkBuffer.push_back(chunk);
		this->len += datalen;
		}
		break;
	case add_fill_fix_len: {
		u_int32_t copied = 0;
		do {
			if(!(this->len % this->chunk_fix_len)) {
				eChunk chunk;
				chunk.chunk = new char[this->chunk_fix_len];
				this->chunkBuffer.push_back(chunk);
				this->lastChunk = --this->chunkBuffer.end();
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
 
	/*
	extern string GetDataMD5(u_char *data, u_int32_t datalen);
	cout << GetDataMD5((u_char*)data, len) << endl;
	*/
	decompress_chunkbufferIterateEv->chunkbuffer_iterate_ev(data, len, this->decompress_pos);
	this->decompress_pos += len;
	/*
	cout << "decompress ev " << len << " " << this->decompress_pos << " " << endl;
	for(u_int32_t i = 0; i < min(len, 10u); i++) {
		cout << (int)(unsigned char)data[i] << ",";
	}
	cout << endl;
	*/
	/*
	cout << GetDataMD5((u_char*)data, len) << endl;
	*/

	return(true);
}

void ChunkBuffer::chunkIterate(ChunkBuffer_baseIterate *chunkbufferIterateEv, bool freeChunks) {
	if(this->compressStream) {
		this->decompress_chunkbufferIterateEv = chunkbufferIterateEv;
		this->decompress_pos = 0;
		list<eChunk>::iterator it = chunkBuffer.begin();
		size_t size = chunkBuffer.size();
		size_t counter = 0;
		for(it = chunkBuffer.begin(); it != chunkBuffer.end(); it++) {
			++counter;
			this->compressStream->decompress(it->chunk, it->len, it->decompress_len, counter == size, this);
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