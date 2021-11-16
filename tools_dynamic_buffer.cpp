#include <syslog.h>

#include "voipmonitor.h"
#include "tools.h"
#include "calltable.h"

#include "tools_dynamic_buffer.h"

#define MIN(x,y) ((x) < (y) ? (x) : (y))


extern int opt_pcap_dump_tar_sip_use_pos;
extern int opt_pcap_dump_tar_rtp_use_pos;
extern int opt_pcap_dump_tar_graph_use_pos;


bool lzo_1_11_compress = true;


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
	#ifdef HAVE_LIBLZMA
	this->lzmaStream = NULL;
	this->lzmaStreamDecompress = NULL;
	#endif //HAVE_LIBLZMA
	#ifdef HAVE_LIBLZ4
	this->lz4Stream = NULL;
	this->lz4StreamDecode = NULL;
	#endif //HAVE_LIBLZ4
	#ifdef HAVE_LIBLZO
	this->lzoWrkmem = NULL;
	this->lzoWrkmemDecompress = NULL;
	this->lzoDecompressData = NULL;
	#endif //HAVE_LIBLZO
	this->snappyDecompressData = NULL;
	this->zipLevel = Z_DEFAULT_COMPRESSION;
	this->lzmaLevel = 6;
	this->autoPrefixFile = false;
	this->forceStream = false;
	this->processed_len = 0;
	this->sendParameter_client = 0;
	this->sendParameter_c_client = NULL;
}

CompressStream::~CompressStream() {
	this->termCompress();
	this->termDecompress();
}

void CompressStream::setZipLevel(int zipLevel) {
	this->zipLevel = zipLevel;
}

void CompressStream::setLzmaLevel(int lzmaLevel) {
	this->lzmaLevel = lzmaLevel;
}

void CompressStream::enableAutoPrefixFile() {
	this->autoPrefixFile = true;
}

void CompressStream::enableForceStream() {
	this->forceStream = true;
}

void CompressStream::setSendParameters(int client, void *c_client) {
	this->sendParameter_client = client;
	this->sendParameter_c_client = c_client;
}

void CompressStream::initCompress() {
	switch(this->typeCompress) {
	case compress_na:
		break;
	case zip:
	case gzip:
		if(!this->zipStream) {
			this->zipStream =  new FILE_LINE(40001) z_stream;
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
	case lzma:
#ifdef HAVE_LIBLZMA
		if(!this->lzmaStream) {
			this->lzmaStream = new FILE_LINE(40002) lzma_stream;
			memset_heapsafe(this->lzmaStream, 0, sizeof(lzma_stream));
			int ret = lzma_easy_encoder(this->lzmaStream, this->lzmaLevel, LZMA_CHECK_CRC64);
			if(ret == LZMA_OK) {
				createCompressBuffer();
			} else {
				char error[1024];
				snprintf(error, sizeof(error), "lzma_easy_encoder error: %d", (int) ret);
				this->setError(error);
				break;
			}
		}
		break;
#endif
	case snappy:
		if(!this->compressBuffer) {
			createCompressBuffer();
		}
		break;
	case lzo:
		#ifdef HAVE_LIBLZO
		if(!this->lzoWrkmem) {
			this->lzoWrkmem = new FILE_LINE(40003) u_char[lzo_1_11_compress ? LZO1X_1_11_MEM_COMPRESS : LZO1X_1_MEM_COMPRESS];
			createCompressBuffer();
		}
		#endif //HAVE_LIBLZO
		break;
	case lz4:
		if(!this->compressBuffer) {
			createCompressBuffer();
		}
		break;
	case lz4_stream:
		#ifdef HAVE_LIBLZ4
		if(!this->lz4Stream) {
			this->lz4Stream = LZ4_createStream();
			createCompressBuffer();
		}
		#endif //HAVE_LIBLZ4
		break;
	case compress_auto:
		break;
	}
}

void CompressStream::initDecompress(u_int32_t dataLen) {
	switch(this->typeCompress) {
	case compress_na:
		break;
	case zip:
	case gzip:
		if(!this->zipStreamDecompress) {
			this->zipStreamDecompress =  new FILE_LINE(40004) z_stream;
			this->zipStreamDecompress->zalloc = Z_NULL;
			this->zipStreamDecompress->zfree = Z_NULL;
			this->zipStreamDecompress->opaque = Z_NULL;
			this->zipStreamDecompress->avail_in = 0;
			this->zipStreamDecompress->next_in = Z_NULL;
			if((this->typeCompress == zip ?
			     inflateInit(this->zipStreamDecompress) :
			     inflateInit2(this->zipStreamDecompress, MAX_WBITS + 16)) == Z_OK) {
				createDecompressBuffer(this->decompressBufferLength);
			} else {
				inflateEnd(this->zipStreamDecompress);
				this->setError("unzip initialize failed");
			}
		}
		break;
	case lzma:
#ifdef HAVE_LIBLZMA 
		if(!this->lzmaStreamDecompress) {
			this->lzmaStreamDecompress = new FILE_LINE(40005) lzma_stream;
			memset_heapsafe(this->lzmaStreamDecompress, 0, sizeof(lzma_stream));
			int ret = lzma_stream_decoder(this->lzmaStreamDecompress, UINT64_MAX, LZMA_CONCATENATED);
			if(ret == LZMA_OK) {
				createDecompressBuffer(this->decompressBufferLength);
			} else {
				char error[1024];
				snprintf(error, sizeof(error), "lzma_stream_decoder error: %d", (int) ret);
				this->setError(error);
			}
		}
		break;
#endif
	case snappy:
		if(!this->snappyDecompressData && this->forceStream) {
			this->snappyDecompressData = new FILE_LINE(40006) SimpleBuffer();
		}
		createDecompressBuffer(dataLen);
		break;
	case lzo:
		#ifdef HAVE_LIBLZO
		if(!this->lzoWrkmemDecompress) {
			this->lzoWrkmemDecompress = new FILE_LINE(40007) u_char[LZO1X_1_MEM_COMPRESS];
		}
		if(!this->lzoDecompressData && this->forceStream) {
			this->lzoDecompressData = new FILE_LINE(40008) SimpleBuffer();
		}
		createDecompressBuffer(dataLen);
		#endif //HAVE_LIBLZO
		break;
	case lz4:
		createDecompressBuffer(dataLen);
		break;
	case lz4_stream:
		#ifdef HAVE_LIBLZ4
		if(!this->lz4StreamDecode) {
			this->lz4StreamDecode = LZ4_createStreamDecode();
		}
		createDecompressBuffer(dataLen);
		#endif //HAVE_LIBLZ4
		break;
	case compress_auto:
		break;
	}
}

void CompressStream::termCompress() {
	if(this->zipStream) {
		deflateEnd(this->zipStream);
		delete this->zipStream;
		this->zipStream = NULL;
	}
	#ifdef HAVE_LIBLZMA
	if(this->lzmaStream) {
		lzma_end(this->lzmaStream);
		delete this->lzmaStream;
		this->lzmaStream = NULL;
	}
	#endif //ifdef HAVE_LIBLZMA
	#ifdef HAVE_LIBLZO
	if(this->lzoWrkmem) {
		delete [] this->lzoWrkmem;
		this->lzoWrkmem = NULL;
	}
	#endif //HAVE_LIBLZO
	#ifdef HAVE_LIBLZ4
	if(this->lz4Stream) {
		LZ4_freeStream(this->lz4Stream);
		this->lz4Stream = NULL;
	}
	#endif //ifdef HAVE_LIBLZ4
	if(this->compressBuffer) {
		delete [] this->compressBuffer;
		this->compressBuffer = NULL;
	}
}

void CompressStream::termDecompress() {
	if(this->zipStreamDecompress) {
		inflateEnd(this->zipStreamDecompress);
		delete this->zipStreamDecompress;
		this->zipStreamDecompress = NULL;
	}
	#ifdef HAVE_LIBLZMA
	if(this->lzmaStreamDecompress) {
		lzma_end(this->lzmaStreamDecompress);
		delete this->lzmaStreamDecompress;
		this->lzmaStreamDecompress = NULL;
	}
	#endif //ifdef HAVE_LIBLZMA
	if(this->snappyDecompressData) {
		delete this->snappyDecompressData;
		this->snappyDecompressData = NULL;
	}
	#ifdef HAVE_LIBLZO
	if(this->lzoDecompressData) {
		delete this->lzoDecompressData;
		this->lzoDecompressData = NULL;
	}
	if(this->lzoWrkmemDecompress) {
		delete [] this->lzoWrkmemDecompress;
		this->lzoWrkmemDecompress = NULL;
	}
	#endif //HAVE_LIBLZO
	#ifdef HAVE_LIBLZ4
	if(this->lz4StreamDecode) {
		LZ4_freeStreamDecode(this->lz4StreamDecode);
		this->lz4StreamDecode = NULL;
	}
	#endif //HAVE_LIBLZ4
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
	case lzma:
		{
		#ifdef HAVE_LIBLZMA
		if(!this->lzmaStream) {
			this->initCompress();
		}
		this->lzmaStream->avail_in = len;
		this->lzmaStream->next_in = (unsigned char*)data;
		do {
			this->lzmaStream->avail_out = this->compressBufferLength;
			this->lzmaStream->next_out = (unsigned char*)this->compressBuffer;
			int rslt = lzma_code(this->lzmaStream, flush ? LZMA_FINISH : LZMA_RUN);
			if(rslt == LZMA_OK || rslt == LZMA_STREAM_END) {
				int have = this->compressBufferLength - this->zipStream->avail_out;
				if(!baseEv->compress_ev(this->compressBuffer, have, 0)) {
					this->setError("lzma compress_ev failed");
					return(false);
				}
			} else {
				this->setError("lzma compress failed");
				return(false);
			}
		} while(this->lzmaStream->avail_out == 0);
		this->processed_len += len;
		#endif
		}
		break;
	case snappy: {
		if(!this->compressBuffer) {
			this->initCompress();
		}
		size_t chunk_offset = 0;
		while(chunk_offset < len) {
			size_t chunk_len = min((size_t)this->compressBufferLength, (size_t)(len - chunk_offset));
			size_t compressLength = this->compressBufferBoundLength;
			snappy_status snappyRslt = snappy_compress(data + chunk_offset, chunk_len, this->compressBuffer, &compressLength);
			switch(snappyRslt) {
			case SNAPPY_OK:
				if(!this->processed_len && this->autoPrefixFile) {
					if(!baseEv->compress_ev((char*)"SNA", 3, 0, true)) {
						this->setError("snappy compress_ev failed");
						return(false);
					}
				}
				if(this->forceStream) {
					sChunkSizeInfo sizeInfo;
					sizeInfo.compress_size = compressLength;
					sizeInfo.size = len;
					if(!baseEv->compress_ev((char*)&sizeInfo, sizeof(sizeInfo), 0, true)) {
						this->setError("snappy compress_ev failed");
						return(false);
					}
				}
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
			chunk_offset += chunk_len;
		}
		}
		break;
	case lzo: {
		#ifdef HAVE_LIBLZO
		if(!this->compressBuffer) {
			this->initCompress();
		}
		size_t chunk_offset = 0;
		while(chunk_offset < len) {
			size_t chunk_len = min((size_t)this->compressBufferLength, (size_t)(len - chunk_offset));
			lzo_uint compressLength = this->compressBufferBoundLength;
			int lzoRslt = lzo_1_11_compress ?
				       lzo1x_1_11_compress((const u_char*)data + chunk_offset, chunk_len, (u_char*)this->compressBuffer, &compressLength, this->lzoWrkmem) :
				       lzo1x_1_compress((const u_char*)data + chunk_offset, chunk_len, (u_char*)this->compressBuffer, &compressLength, this->lzoWrkmem);
			if(lzoRslt == LZO_E_OK) {
				extern unsigned int HeapSafeCheck;
				if(!this->processed_len && this->autoPrefixFile) {
					if(!baseEv->compress_ev(HeapSafeCheck & _HeapSafeErrorBeginEnd ? 
								 (char*)SimpleBuffer((char*)"LZO", 3).data() : 
								 (char*)"LZO", 
								3, 0, true)) {
						this->setError("lzo compress_ev failed");
						return(false);
					}
				}
				if(this->forceStream) {
					sChunkSizeInfo sizeInfo;
					sizeInfo.compress_size = compressLength;
					sizeInfo.size = len;
					if(!baseEv->compress_ev(HeapSafeCheck & _HeapSafeErrorBeginEnd ? 
								 (char*)SimpleBuffer(&sizeInfo, sizeof(sizeInfo)).data() :
								 (char*)&sizeInfo, 
								sizeof(sizeInfo), 0, true)) {
						this->setError("lzo compress_ev failed");
						return(false);
					}
				}
				if(baseEv->compress_ev(this->compressBuffer, compressLength, len)) {
					this->processed_len += len;
				} else {
					this->setError("lzo compress_ev failed");
					return(false);
				}
			} else {
				this->setError("lzo compress failed");
				return(false);
			}
			chunk_offset += chunk_len;
		}
		#endif //HAVE_LIBLZO
		}
		break;
	case lz4: {
		#ifdef HAVE_LIBLZ4
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
		#endif //HAVE_LIBLZ4
		}
		break;
	case lz4_stream: {
		#ifdef HAVE_LIBLZ4
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
		#endif //HAVE_LIBLZ4
		}
		break;
	case compress_auto:
		break;
	}
	return(true);
}

bool CompressStream::decompress(char *data, u_int32_t len, u_int32_t decompress_len, bool flush, CompressStream_baseEv *baseEv, u_int32_t *use_len) {
	if(sverb.chunk_buffer > 2) {
		cout << "decompress data " << len << " " << decompress_len << endl;
		for(u_int32_t i = 0; i < min(len, (u_int32_t)max(sverb.chunk_buffer, 200)); i++) {
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
	if(this->typeCompress == compress_auto && this->autoPrefixFile) {
		if(len >= 3 && !memcmp(data, "SNA", 3)) {
			this->typeCompress = snappy;
			data += 3;
			len -= 3;
		} else if(len >= 3 && !memcmp(data, "LZO", 3)) {
			this->typeCompress = lzo;
			data += 3;
			len -= 3;
		} else {
			this->typeCompress = compress_na;
		}
	}
	switch(this->typeCompress) {
	case compress_na:
		if(!baseEv->decompress_ev(data, len)) {
			this->setError("decompress_ev failed");
			return(false);
		}
		if(use_len) {
			*use_len = len;
		}
		break;
	case zip:
	case gzip:
		if(!this->zipStreamDecompress) {
			this->initDecompress(0);
		}
		this->zipStreamDecompress->avail_in = len;
		this->zipStreamDecompress->next_in = (unsigned char*)data;
		do {
			this->zipStreamDecompress->avail_out = this->decompressBufferLength;
			this->zipStreamDecompress->next_out = (unsigned char*)this->decompressBuffer;
			int inflateRslt = inflate(this->zipStreamDecompress, Z_NO_FLUSH);
			if(inflateRslt == Z_OK || inflateRslt == Z_STREAM_END || inflateRslt == Z_BUF_ERROR) {
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
		if(use_len) {
			*use_len = len - this->zipStreamDecompress->avail_in;
		}
		break;
	case lzma:
		#ifdef HAVE_LIBLZMA
		if(!this->lzmaStreamDecompress) {
			this->initDecompress(0);
		}
		this->lzmaStreamDecompress->avail_in = len;
		this->lzmaStreamDecompress->next_in = (unsigned char*)data;
		do {
			this->lzmaStreamDecompress->avail_out = this->decompressBufferLength;
			this->lzmaStreamDecompress->next_out = (unsigned char*)this->decompressBuffer;
			int rslt = lzma_code(this->lzmaStreamDecompress, flush ? LZMA_FINISH : LZMA_RUN);
			if(rslt == LZMA_OK || rslt == LZMA_STREAM_END) {
				int have = this->decompressBufferLength - this->lzmaStreamDecompress->avail_out;
				if(!baseEv->decompress_ev(this->decompressBuffer, have)) {
					this->setError("lzma decompress_ev failed");
					return(false);
				}
			} else {
				this->setError("lzma decompress failed");
				return(false);
			}
		} while(this->lzmaStreamDecompress->avail_out == 0);
		if(use_len) {
			*use_len = len - this->lzmaStreamDecompress->avail_in;
		}
		#endif
		break;
	case snappy: {
		if(this->forceStream) {
			this->initDecompress(0);
			if(len >= 3 && !memcmp(data, "SNA", 3) && !this->snappyDecompressData->size()) {
				data += 3;
				len -= 3;
			}
			this->snappyDecompressData->add(data, len);
		} else {
			this->initDecompress(decompress_len);
		}
		while(!this->forceStream ||
		      (this->snappyDecompressData->size() > sizeof(sChunkSizeInfo) &&
		       (sizeof(sChunkSizeInfo) + ((sChunkSizeInfo*)this->snappyDecompressData->data())->compress_size) <= this->snappyDecompressData->size())) {
			size_t decompressLength;
			if(this->forceStream) {
				this->initDecompress(((sChunkSizeInfo*)this->snappyDecompressData->data())->size);
				decompressLength = ((sChunkSizeInfo*)this->snappyDecompressData->data())->size;
			} else {
				decompressLength = decompress_len;
			}
			snappy_status snappyRslt = snappy_uncompress(this->forceStream ?
								      (const char*)(this->snappyDecompressData->data() + sizeof(sChunkSizeInfo)) :
								      data, 
								     this->forceStream ? 
								      ((sChunkSizeInfo*)this->snappyDecompressData->data())->compress_size : 
								      len, 
								     this->decompressBuffer, 
								     &decompressLength);
			if(snappyRslt == SNAPPY_OK && 
			   decompressLength == (this->forceStream ?
						 ((sChunkSizeInfo*)this->snappyDecompressData->data())->size :
						 decompress_len)) {
				if(!baseEv->decompress_ev(this->decompressBuffer, decompressLength)) {
					this->setError("snappy decompress_ev failed");
					return(false);
				}
			} else {
				switch(snappyRslt) {
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
			if(this->snappyDecompressData) {
				this->snappyDecompressData->removeDataFromLeft(sizeof(sChunkSizeInfo) + ((sChunkSizeInfo*)this->snappyDecompressData->data())->compress_size);
			} else {
				break;
			}
		}
		if(use_len) {
			*use_len = len;
		}
		}
		break;
	case lzo: {
		#ifdef HAVE_LIBLZO
		if(this->forceStream) {
			this->initDecompress(0);
			if(len >= 3 && !memcmp(data, "LZO", 3) && !this->lzoDecompressData->size()) {
				data += 3;
				len -= 3;
			}
			this->lzoDecompressData->add(data, len);
		} else {
			this->initDecompress(decompress_len);
		}
		while(!this->forceStream ||
		      (this->lzoDecompressData->size() > sizeof(sChunkSizeInfo) &&
		       (sizeof(sChunkSizeInfo) + ((sChunkSizeInfo*)this->lzoDecompressData->data())->compress_size) <= this->lzoDecompressData->size())) {
			lzo_uint decompressLength;
			if(this->forceStream) {
				this->initDecompress(((sChunkSizeInfo*)this->lzoDecompressData->data())->size);
				decompressLength = ((sChunkSizeInfo*)this->lzoDecompressData->data())->size;
			} else {
				decompressLength = decompress_len;
			}
			int lzoRslt = lzo1x_decompress_safe(this->forceStream ?
							     this->lzoDecompressData->data() + sizeof(sChunkSizeInfo) :
							     (u_char*)data, 
							    this->forceStream ?
							     ((sChunkSizeInfo*)this->lzoDecompressData->data())->compress_size :
							     len, 
							    (u_char*)this->decompressBuffer, 
							    &decompressLength, 
							    this->lzoWrkmemDecompress);
			if(lzoRslt == LZO_E_OK && 
			   decompressLength == (this->forceStream ?
						 ((sChunkSizeInfo*)this->lzoDecompressData->data())->size :
						 decompress_len)) {
				if(!baseEv->decompress_ev(this->decompressBuffer, decompressLength)) {
					this->setError("lzo decompress_ev failed");
					return(false);
				}
			} else {
				this->setError("lzo decompress failed");
				return(false);
			}
			if(this->lzoDecompressData) {
				this->lzoDecompressData->removeDataFromLeft(sizeof(sChunkSizeInfo) + ((sChunkSizeInfo*)this->lzoDecompressData->data())->compress_size);
			} else {
				break;
			}
		}
		if(use_len) {
			*use_len = len;
		}
		#endif //HAVE_LIBLZO
		}
		break;
	case lz4:
		#ifdef HAVE_LIBLZ4
		if(!this->decompressBuffer) {
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
		if(use_len) {
			*use_len = len;
		}
		#endif //HAVE_LIBLZ4
		break;
	case lz4_stream:
		#ifdef HAVE_LIBLZ4
		if(!this->lz4StreamDecode) {
			this->initDecompress(decompress_len);
		}
		if(!this->decompressBuffer) {
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
		if(use_len) {
			*use_len = len;
		}
		#endif //HAVE_LIBLZ4
		break;
	case compress_auto:
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
	case lzma:
		if(!this->compressBufferLength) {
			this->compressBufferLength = 8 * 1024;
		}
		this->compressBuffer = new FILE_LINE(40009) char[this->compressBufferLength];
		break;
	case snappy:
	case lzo:
	case lz4:
	case lz4_stream:
		if(this->maxDataLength > this->compressBufferLength) {
			this->compressBufferLength = this->maxDataLength;
		}
		if(!this->compressBufferLength) {
			this->compressBufferLength = 8 * 1024;
		}
		switch(this->typeCompress) {
		case snappy:
			this->compressBufferBoundLength = snappy_max_compressed_length(this->compressBufferLength);
			break;
		case lzo:
			this->compressBufferBoundLength = this->compressBufferLength + this->compressBufferLength/16 + 64 + 3;
			break;
		case lz4:
		case lz4_stream:
			#ifdef HAVE_LIBLZ4
			this->compressBufferBoundLength = LZ4_compressBound(this->compressBufferLength);
			#endif //HAVE_LIBLZ4
			break;
		default:
			break;
		}
		this->compressBuffer = new FILE_LINE(40010) char[this->compressBufferBoundLength];
		break;
	case compress_auto:
		break;
	}
}

void CompressStream::createDecompressBuffer(u_int32_t bufferLen) {
	if(this->decompressBuffer) {
		if(this->decompressBufferLength >= max(this->maxDataLength, bufferLen)) {
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
	case gzip:
	case lzma:
		if(!this->decompressBufferLength) {
			this->decompressBufferLength = 8 * 1024;
		}
		this->decompressBuffer = new FILE_LINE(40011) char[this->decompressBufferLength];
		break;	
	case snappy:
	case lzo:
	case lz4:
	case lz4_stream:
		if(max(this->maxDataLength, bufferLen) > this->decompressBufferLength) {
			this->decompressBufferLength = max(this->maxDataLength, bufferLen);
		}
		if(this->decompressBufferLength) {
			this->decompressBuffer = new FILE_LINE(40012) char[this->decompressBufferLength];
		}
		break;
	case compress_auto:
		break;
	}
}

extern int _sendvm(int socket, void *c_client, const char *buf, size_t len, int mode);
bool CompressStream::compress_ev(char *data, u_int32_t len, u_int32_t /*decompress_len*/, bool /*format_data*/) {
	if(this->sendParameter_client || this->sendParameter_c_client) {
		if(_sendvm(this->sendParameter_client, this->sendParameter_c_client, data, len, 0) == -1) {
			this->setError("send error");
			return(false);
		}
	}
	return(true);
}

CompressStream::eTypeCompress CompressStream::convTypeCompress(const char *typeCompress) {
	char _compress_method[20];
	strcpy_null_term(_compress_method, typeCompress);
	strlwr(_compress_method, sizeof(_compress_method));
	if(!strcmp(_compress_method, "zip") ||
	   !strcmp(_compress_method, "gzip")) {
		return(CompressStream::zip);
	} 
	#ifdef HAVE_LIBLZMA
	else if(!strcmp(_compress_method, "lzma")) {
		return(CompressStream::lzma);
	}
	#endif //HAVE_LIBLZMA
	else if(!strcmp(_compress_method, "snappy")) {
		return(CompressStream::snappy);
	} 
	else if(!strcmp(_compress_method, "lzo")) {
		return(CompressStream::lzo);
	} 
	#ifdef HAVE_LIBLZ4
	else if(!strcmp(_compress_method, "lz4")) {
		return(CompressStream::lz4);
	} else if(!strcmp(_compress_method, "lz4_stream")) {
		return(CompressStream::lz4_stream);
	}
	#endif //HAVE_LIBLZ4
	return(CompressStream::compress_na);
}

const char *CompressStream::convTypeCompress(eTypeCompress typeCompress) {
	switch(typeCompress) {
	case zip:
		return("zip");
	#ifdef HAVE_LIBLZMA
	case lzma:
		return("lzma");
	#endif //HAVE_LIBLZMA
	case snappy:
		return("snappy");
	case lzo:
		return("lzo");
	#ifdef HAVE_LIBLZ4
	case lz4:
		return("lz4");
	case lz4_stream:
		return("lz4_stream");
	#endif //HAVE_LIBLZ4
	default:
		return("no");
	}
	return("no");
}

string CompressStream::getConfigMenuString() {
	ostringstream outStr;
	outStr << convTypeCompress(zip) << ':' << zip << '|'
	       << convTypeCompress(lzma) << ':' << lzma << '|'
	       << convTypeCompress(snappy) << ':' << snappy << '|'
	       << convTypeCompress(lzo) << ':' << lzo << '|'
	       << "no:0";
	return(outStr.str());
}

RecompressStream::RecompressStream(eTypeCompress typeDecompress, eTypeCompress typeCompress) 
 : CompressStream(typeDecompress, 1024, 0) {
	this->compressStream = new FILE_LINE(0) CompressStream(typeCompress, 1024, 0);
}

RecompressStream::~RecompressStream() {
	this->end();
	delete this->compressStream;
}

void RecompressStream::setTypeDecompress(eTypeCompress typeDecompress, bool enableForceStream) {
	this->CompressStream::setTypeCompress(typeDecompress);
	if(enableForceStream) {
		this->enableForceStream();
	}
}

void RecompressStream::setTypeCompress(eTypeCompress typeCompress) {
	this->compressStream->setTypeCompress(typeCompress);
}

void RecompressStream::setSendParameters(int client, void *c_client) {
	this->compressStream->setSendParameters(client, c_client);
}

void RecompressStream::processData(char *data, u_int32_t len) {
	this->decompress(data, len, 0, false, this);
}

void RecompressStream::end() {
	this->decompress(NULL, 0, 0, true, this);
	this->compressStream->compress(NULL, 0, true, this->compressStream);
}

bool RecompressStream::isError() {
	return(this->CompressStream::isError() || this->compressStream->isError());
}

bool RecompressStream::decompress_ev(char *data, u_int32_t len) {
	return(this->compressStream->compress(data, len, false, this->compressStream));
}

ChunkBuffer::ChunkBuffer(int time, data_tar_time tar_time, bool need_tar_pos,
			 u_int32_t chunk_fix_len, Call_abstract *call, int typeContent, int indexContent,
			 const char *name) {
	this->time = time;
	this->tar_time = tar_time;
	this->need_tar_pos = need_tar_pos;
	this->call = call;
	this->typeContent = typeContent;
	this->indexContent =indexContent;
	if(name) this->name = name;
	this->fbasename = call->fbasename;
	this->chunkBuffer_countItems = 0;
	this->len = 0;
	this->chunk_fix_len = chunk_fix_len;
	this->compress_orig_data_len = 0;
	this->lastChunk = NULL;
	this->compressStream = NULL;
	this->chunkIterateProceedLen = 0;
	this->closed = false;
	this->decompressError = false;
	this->_sync_chunkBuffer = 0;
	this->_sync_compress = 0;
	this->last_add_time = 0;
	this->last_add_time_tar = 0;
	this->last_tar_time = 0;
	this->chunk_buffer_size = 0;
	this->created_at = getTimeUS();
	if(call) {
		#if DEBUG_ASYNC_TAR_WRITE
		if(!call->incChunkBuffers(typeContent - 1 + indexContent, this, this->name.c_str())) {
			strange_log("error inc chunk in create ChunkBuffer");
		}
		#else
		call->incChunkBuffers();
		#endif
	}
}

ChunkBuffer::~ChunkBuffer() {
	if(sverb.tar > 2) {
		syslog(LOG_NOTICE, "chunkbufer destroy: %s %lx %s", 
		       this->getName().c_str(), (long)this,
		       this->tar_time.getTimeString().c_str());
	}
	for(list<sChunk>::iterator it = chunkBuffer.begin(); it != chunkBuffer.end(); it++) {
		it->deleteChunk(this);
	}
	if(this->compressStream) {
		delete this->compressStream;
	}
	if(call) {
		#if DEBUG_ASYNC_TAR_WRITE
		if(call->isAllocFlagOK() && call->isChunkBuffersCountSyncOK_wait()) {
			if(call->created_at > this->created_at) {
				strange_log("overtaking in time in ~ChunkBuffer");
			} else if(call->fbasename != this->fbasename) {
				strange_log("mismatch fbasename in ~ChunkBuffer");
			} else if(call->decChunkBuffers(typeContent - 1 + indexContent, this, this->name.c_str())) {
				call->addPFlag(typeContent - 1 + indexContent, Call_abstract::_p_flag_destroy_tar_buffer);
			} else {
				strange_log("error dec chunk in ~ChunkBuffer");
			}
		} else {
			strange_log("access to strange call in ~ChunkBuffer");
		}
		#else
		if(call->isAllocFlagOK()) {
			if(call->created_at > this->created_at) {
				strange_log("overtaking in time in ~ChunkBuffer");
			} else if(call->fbasename != this->fbasename) {
				strange_log("mismatch fbasename in ~ChunkBuffer");
			}
		} else {
			strange_log("access to strange call in ~ChunkBuffer");
		}
		call->decChunkBuffers();
		#endif
	}
}

void ChunkBuffer::setTypeCompress(CompressStream::eTypeCompress typeCompress, u_int32_t compressBufferLength, u_int32_t maxDataLength) {
	if(typeCompress > CompressStream::compress_na) {
		this->compressStream = new FILE_LINE(40013) CompressStream(typeCompress, compressBufferLength, maxDataLength);
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
	if(sverb.chunk_buffer > 2) {
		if(directAdd) {
			cout << "add compress data " << datalen << endl;
			for(u_int32_t i = 0; i < min(datalen, (u_int32_t)max(sverb.chunk_buffer, 200)); i++) {
				cout << (int)(unsigned char)data[i] << ",";
			}
			cout << endl;
		} else {
			cout << "add source data " << datalen << endl;
			for(u_int32_t i = 0; i < min(datalen, (u_int32_t)max(sverb.chunk_buffer, 200)); i++) {
				cout << (int)(unsigned char)data[i] << ",";
			}
			cout << endl;
		}
	}
	eAddMethod addMethod = add_na;
	if(directAdd) {
		if(this->chunk_fix_len) {
			if(this->compressStream->isNativeStream()) {
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
	if(addMethod == add_compress) {
		this->lock_compress();
		this->compressStream->compress(data, datalen, flush, this);
		this->compress_orig_data_len += datalen;
		this->unlock_compress();
		return;
	}
	this->lock_chunkBuffer();
	switch(addMethod) {
	case add_simple: {
		sChunk chunk;
		chunk.chunk = new FILE_LINE(40015) char[datalen];
		memcpy_heapsafe(chunk.chunk, data, datalen,
				__FILE__, __LINE__);
		chunk.len = datalen;
		chunk.decompress_len = decompress_len;
		this->chunkBuffer.push_back(chunk);
		++this->chunkBuffer_countItems;
		this->len += datalen;
		__sync_fetch_and_add(&this->chunk_buffer_size, datalen);
		__sync_fetch_and_add(&ChunkBuffer::chunk_buffers_sumsize, datalen);
		}
		break;
	case add_fill_chunks: {
		if(sverb.chunk_buffer > 1) {
			cout << "chunkpos_add " << (this->lastChunk ? this->lastChunk->len : 0) << " / " << this->chunkBuffer_countItems << endl;
		}
		u_int32_t allcopied = 0;
		for(int i = 0; i < 2; i++) {
			char *_data;
			u_int32_t _len;
			sChunkLen chunkLen;
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
					sChunk chunk;
					chunk.chunk = new FILE_LINE(40016) char[this->chunk_fix_len];
					chunk.len = 0;
					chunk.decompress_len = (u_int32_t)-1;
					this->chunkBuffer.push_back(chunk);
					++this->chunkBuffer_countItems;
					this->lastChunk = &(*(--this->chunkBuffer.end()));
				}
				u_int32_t copied = min(_len - pos, this->chunk_fix_len - this->lastChunk->len);
				memcpy_heapsafe(this->lastChunk->chunk + this->lastChunk->len, this->lastChunk->chunk,
						_data + pos, i ? _data : NULL,
						copied,
						__FILE__, __LINE__);
				this->lastChunk->len += copied;
				allcopied += copied;
				pos +=copied;
			}
		}
		this->len += allcopied;
		__sync_fetch_and_add(&this->chunk_buffer_size, allcopied);
		__sync_fetch_and_add(&ChunkBuffer::chunk_buffers_sumsize, allcopied);
		}
		break;
	case add_fill_fix_len: {
		u_int32_t copied = 0;
		do {
			if(!(this->len % this->chunk_fix_len)) {
				sChunk chunk;
				chunk.chunk = new FILE_LINE(40017) char[this->chunk_fix_len];
				this->chunkBuffer.push_back(chunk);
				++this->chunkBuffer_countItems;
				this->lastChunk = &(*(--this->chunkBuffer.end()));
			}
			int whattocopy = MIN(this->chunk_fix_len - this->len % this->chunk_fix_len, datalen - copied);
			memcpy_heapsafe(this->lastChunk->chunk + this->len % this->chunk_fix_len, this->lastChunk->chunk,
					data + copied, data,
					whattocopy,
					__FILE__, __LINE__);
			copied += whattocopy;
			this->len += whattocopy;
			this->lastChunk->len += whattocopy;
			__sync_fetch_and_add(&this->chunk_buffer_size, whattocopy);
			__sync_fetch_and_add(&ChunkBuffer::chunk_buffers_sumsize, whattocopy);
		} while(datalen > copied);
		}
		break;
	case add_compress:
	case add_na:
		break;
	}
	this->unlock_chunkBuffer();
	this->last_add_time = getTimeS_rdtsc();
}

void ChunkBuffer::close() {
	if(sverb.tar > 2) {
		syslog(LOG_NOTICE, "chunkbufer close: %s %lx %s", 
		       this->getName().c_str(), (long)this,
		       this->tar_time.getTimeString().c_str());
	}
	this->closed = true;
}

bool ChunkBuffer::compress_ev(char *data, u_int32_t len, u_int32_t decompress_len, bool /*format_data*/) {
	this->add(data, len, false, decompress_len, true);
	return(true);
}

bool ChunkBuffer::decompress_ev(char *data, u_int32_t len) {
 	decompress_chunkbufferIterateEv->chunkbuffer_iterate_ev(data, len, this->decompress_pos);
	this->decompress_pos += len;
	if(sverb.chunk_buffer > 2) {
		cout << "decompress ev " << len << " " << this->decompress_pos << " " << endl;
		for(u_int32_t i = 0; i < min(len, (u_int32_t)max(sverb.chunk_buffer, 200)); i++) {
			cout << (int)(unsigned char)data[i] << ",";
		}
		cout << endl;
	}
	return(true);
}

void ChunkBuffer::chunkIterate(ChunkBuffer_baseIterate *chunkbufferIterateEv, bool freeChunks, bool enableContinue, u_int32_t limitLength) {
	if(sverb.chunk_buffer > 1) {
		cout << "### start chunkIterate " << this->chunkIterateProceedLen << endl;
	}
	if(!enableContinue) {
		this->chunkIterateProceedLen = 0;
		if(sverb.chunk_buffer > 1) {
			cout << "### reset chunkIterateProceedLen" << endl;
		}
	}
	size_t counterIterator = 0;
	size_t sizeChunkBuffer = chunkBuffer_countItems;
	u_int32_t chunkIterateProceedLen_start = this->chunkIterateProceedLen;
	if(this->compressStream) {
		this->decompress_chunkbufferIterateEv = chunkbufferIterateEv;
		this->decompress_pos = 0;
		if(!enableContinue) {
			this->chunkIterateCompleteBufferInfo.init();
		}
		bool _break = false;
		for(list<sChunk>::iterator it = chunkBuffer.begin(); counterIterator < sizeChunkBuffer && !_break;) {
			if(counterIterator++) ++it;
			if(!it->chunk || counterIterator <= this->chunkIterateCompleteBufferInfo.chunkIndex) {
				continue;
			}
			if(sverb.chunk_buffer > 1) {
				cout << "### chunkIterate 01" << endl;
			}
			if(it->decompress_len == (u_int32_t)-1) {
				while(this->chunkIterateCompleteBufferInfo.chunkPos < it->len && !_break) {
					if(!this->chunkIterateCompleteBufferInfo.counter) {
						this->chunkIterateCompleteBufferInfo.chunkLen = *(sChunkLen*)it->chunk;
						++this->chunkIterateCompleteBufferInfo.counter;
						this->chunkIterateCompleteBufferInfo.bufferLen = this->chunkIterateCompleteBufferInfo.chunkLen.len;
						this->chunkIterateCompleteBufferInfo.bufferPos = 0;
						this->chunkIterateCompleteBufferInfo.addPos(sizeof(sChunkLen));
					}
					if(!this->chunkIterateCompleteBufferInfo.bufferPos) {
						if(this->chunkIterateCompleteBufferInfo.bufferLen <= it->len - this->chunkIterateCompleteBufferInfo.chunkPos) {
							if(this->chunkIterateCompleteBufferInfo.counter % 2) {
								if(sverb.chunk_buffer > 1) {
									cout << "chunkpos_dec " << this->chunkIterateCompleteBufferInfo.chunkPos << " / " << counterIterator << endl;
								}
								if(!this->compressStream->decompress(it->chunk + this->chunkIterateCompleteBufferInfo.chunkPos, 
												     this->chunkIterateCompleteBufferInfo.chunkLen.len, 
												     this->chunkIterateCompleteBufferInfo.chunkLen.decompress_len, 
												     this->closed && counterIterator == sizeChunkBuffer &&
												      this->chunkIterateCompleteBufferInfo.allPos + this->chunkIterateCompleteBufferInfo.chunkLen.len == this->len, 
												     this)) {
									syslog(LOG_ERR, "chunkbuffer decompress error in %s", this->getName().c_str());
									this->decompressError = true;
									return;
								}
								this->chunkIterateProceedLen += this->chunkIterateCompleteBufferInfo.chunkLen.decompress_len;
								this->chunkIterateCompleteBufferInfo.bufferLen = sizeof(sChunkLen);
								this->chunkIterateCompleteBufferInfo.addPos(this->chunkIterateCompleteBufferInfo.chunkLen.len);
								if(sverb.chunk_buffer > 1) { 
									cout << " d1 " << this->chunkIterateProceedLen - chunkIterateProceedLen_start << endl;
								}
							} else {
								this->chunkIterateCompleteBufferInfo.chunkLen = *(sChunkLen*)(it->chunk + this->chunkIterateCompleteBufferInfo.chunkPos);
								this->chunkIterateCompleteBufferInfo.bufferLen = this->chunkIterateCompleteBufferInfo.chunkLen.len;
								this->chunkIterateCompleteBufferInfo.addPos(sizeof(sChunkLen));
								if(sverb.chunk_buffer > 1) { 
									cout << "chunkLen " << this->chunkIterateCompleteBufferInfo.chunkLen.len << " / " << this->chunkIterateCompleteBufferInfo.chunkLen.decompress_len << endl;
									cout << "chunkpos_len " << this->chunkIterateCompleteBufferInfo.chunkPos << " / " << counterIterator << endl;
								}
							}
							++this->chunkIterateCompleteBufferInfo.counter;
							this->chunkIterateCompleteBufferInfo.bufferPos = 0;
						} else {
							this->chunkIterateCompleteBufferInfo.buffer = 
								this->chunkIterateCompleteBufferInfo.counter % 2 ?
								 new FILE_LINE(40018) char[this->chunkIterateCompleteBufferInfo.bufferLen] :
								 (char*)&(this->chunkIterateCompleteBufferInfo.chunkLenBuff);
							u_int32_t copied = it->len - this->chunkIterateCompleteBufferInfo.chunkPos;
							if(sverb.chunk_buffer > 1) { 
								cout << (this->chunkIterateCompleteBufferInfo.counter % 2 ? "chunkpos_decI " : "chunkpos_lenI ")
								     << this->chunkIterateCompleteBufferInfo.chunkPos << " / " << this->chunkIterateCompleteBufferInfo.bufferPos << " / " << counterIterator << endl;
							}
							memcpy_heapsafe(this->chunkIterateCompleteBufferInfo.buffer, 
									this->chunkIterateCompleteBufferInfo.buffer != (char*)&(this->chunkIterateCompleteBufferInfo.chunkLenBuff) ?
										this->chunkIterateCompleteBufferInfo.buffer : NULL,
									it->chunk + this->chunkIterateCompleteBufferInfo.chunkPos, it->chunk,
									copied,
									__FILE__, __LINE__);
							this->chunkIterateCompleteBufferInfo.bufferPos += copied;
							this->chunkIterateCompleteBufferInfo.addPos(copied);
						}
					} else {
						u_int32_t copied = min(it->len - this->chunkIterateCompleteBufferInfo.chunkPos, 
								       this->chunkIterateCompleteBufferInfo.bufferLen - this->chunkIterateCompleteBufferInfo.bufferPos);
						if(sverb.chunk_buffer > 1) { 
							cout << (this->chunkIterateCompleteBufferInfo.counter % 2 ? "chunkpos_dec2 " : "chunkpos_len2 ")
							     << this->chunkIterateCompleteBufferInfo.chunkPos << " / " << this->chunkIterateCompleteBufferInfo.bufferPos << " / " << counterIterator << endl;
						}
						memcpy_heapsafe(this->chunkIterateCompleteBufferInfo.buffer + this->chunkIterateCompleteBufferInfo.bufferPos, 
								this->chunkIterateCompleteBufferInfo.buffer != (char*)&(this->chunkIterateCompleteBufferInfo.chunkLenBuff) ?
									this->chunkIterateCompleteBufferInfo.buffer : NULL,
								it->chunk + this->chunkIterateCompleteBufferInfo.chunkPos, it->chunk,
								copied,
								__FILE__, __LINE__);
						this->chunkIterateCompleteBufferInfo.bufferPos += copied;
						this->chunkIterateCompleteBufferInfo.addPos(copied);
						if(this->chunkIterateCompleteBufferInfo.bufferPos == this->chunkIterateCompleteBufferInfo.bufferLen) {
							 if(this->chunkIterateCompleteBufferInfo.counter % 2) {
								if(!this->compressStream->decompress(this->chunkIterateCompleteBufferInfo.buffer, 
												     this->chunkIterateCompleteBufferInfo.chunkLen.len, 
												     this->chunkIterateCompleteBufferInfo.chunkLen.decompress_len, 
												     this->closed && counterIterator == sizeChunkBuffer &&
												      this->chunkIterateCompleteBufferInfo.allPos == this->len, 
												     this)) {
									syslog(LOG_ERR, "chunkbuffer decompress error in %s", this->getName().c_str());
									this->decompressError = true;
									return;
								}
								this->chunkIterateProceedLen += this->chunkIterateCompleteBufferInfo.chunkLen.decompress_len;
								this->chunkIterateCompleteBufferInfo.bufferLen = sizeof(sChunkLen);
								if(sverb.chunk_buffer > 1) { 
									cout << " d2 " << this->chunkIterateProceedLen - chunkIterateProceedLen_start << endl;
								}
								
							} else {
								this->chunkIterateCompleteBufferInfo.chunkLen = *(sChunkLen*)this->chunkIterateCompleteBufferInfo.buffer;
								this->chunkIterateCompleteBufferInfo.bufferLen = this->chunkIterateCompleteBufferInfo.chunkLen.len;
								if(sverb.chunk_buffer > 1) { 
									cout << "chunkLen " << this->chunkIterateCompleteBufferInfo.chunkLen.len << " / " << this->chunkIterateCompleteBufferInfo.chunkLen.decompress_len << endl;
								}
							}
							++this->chunkIterateCompleteBufferInfo.counter;
							this->chunkIterateCompleteBufferInfo.bufferPos = 0;
							if(this->chunkIterateCompleteBufferInfo.buffer != (char*)&(this->chunkIterateCompleteBufferInfo.chunkLenBuff)) {
								delete [] this->chunkIterateCompleteBufferInfo.buffer;
							}
						}
					}
					if(!(this->chunkIterateCompleteBufferInfo.counter % 2) &&
					   limitLength && 
					   this->chunkIterateProceedLen - chunkIterateProceedLen_start >= limitLength) {
						if(sverb.chunk_buffer > 1) { 
							cout << "break" << endl;
						}
						_break = true;
					}
				}
				if(this->chunkIterateCompleteBufferInfo.chunkPos >= it->len && it->len == this->chunk_fix_len) {
					++this->chunkIterateCompleteBufferInfo.chunkIndex;
					this->chunkIterateCompleteBufferInfo.chunkPos = 0;
					if(freeChunks) {
						it->deleteChunk(this);
					}
				}
			} else {
				if(!this->compressStream->decompress(it->chunk, it->len, it->decompress_len, 
								     this->closed && counterIterator == sizeChunkBuffer,
								     this)) {
					syslog(LOG_ERR, "chunkbuffer decompress error in %s", this->getName().c_str());
					this->decompressError = true;
					return;
				}
				this->chunkIterateProceedLen += it->decompress_len;
				if(freeChunks) {
					it->deleteChunk(this);
				}
				if(limitLength && 
				   this->chunkIterateProceedLen - chunkIterateProceedLen_start >= limitLength) {
					break;
				}
				if(!this->closed && counterIterator >= sizeChunkBuffer + 1) {
					break;
				}
			}
		}
		chunkbufferIterateEv->chunkbuffer_iterate_ev(NULL, 0 , this->decompress_pos);
		if(!enableContinue) {
			this->compressStream->termDecompress();
		}
	} else {
		u_int32_t pos = 0;
		if(this->closed) {
			for(list<sChunk>::iterator it = chunkBuffer.begin(); counterIterator < sizeChunkBuffer;) {
				if(counterIterator++) ++it;
				if(it->chunk) {
					chunkbufferIterateEv->chunkbuffer_iterate_ev(it->chunk, it->len, 0);
					this->chunkIterateProceedLen += it->len;
					if(freeChunks) {
						it->deleteChunk(this);
					}
					pos += it->len;
				}
			}
			chunkbufferIterateEv->chunkbuffer_iterate_ev(NULL, 0, pos);
		} else {
			for(list<sChunk>::iterator it = chunkBuffer.begin(); counterIterator < sizeChunkBuffer;) {
				if(counterIterator++) ++it;
				if(!it->chunk) {
					continue;
				}
				chunkbufferIterateEv->chunkbuffer_iterate_ev(it->chunk, it->len, pos);
				this->chunkIterateProceedLen += it->len;
				if(freeChunks) {
					it->deleteChunk(this);
				}
				pos += it->len;
				if(limitLength && 
				   this->chunkIterateProceedLen - chunkIterateProceedLen_start >= limitLength) {
					break;
				}
				if(!this->closed && counterIterator >= sizeChunkBuffer - 1) {
					break;
				}
			}
			chunkbufferIterateEv->chunkbuffer_iterate_ev(NULL, 0, pos);
		}
	}
	if(sverb.chunk_buffer > 1) { 
		cout << "### end chunkIterate " << this->chunkIterateProceedLen << endl;
	}
}

u_int32_t ChunkBuffer::getChunkIterateSafeLimitLength(u_int32_t limitLength) {
	u_int32_t safeLimitLength = 0;
	size_t counterIterator = 0;
	size_t sizeChunkBuffer = chunkBuffer_countItems;
	if(this->compressStream) {
		for(list<sChunk>::iterator it = chunkBuffer.begin(); counterIterator < sizeChunkBuffer;) {
			if(counterIterator++) ++it;
			if(!it->chunk) {
				continue;
			}
			if(it->decompress_len == (u_int32_t)-1) {
				return(limitLength);
			} else {
				if(safeLimitLength + it->decompress_len >= limitLength) {
					break;
				}
				if(!this->closed && counterIterator >= sizeChunkBuffer - 1) {
					break;
				}
				safeLimitLength += it->decompress_len;
			}
		}
	} else {
		if(this->closed) {
			return(limitLength - this->chunkIterateProceedLen);
		} else {
			for(list<sChunk>::iterator it = chunkBuffer.begin(); counterIterator < sizeChunkBuffer;) {
				if(counterIterator++) ++it;
				if(!it->chunk) {
					continue;
				}
				if(safeLimitLength + it->len >= limitLength) {
					break;
				}
				if(!this->closed && counterIterator >= sizeChunkBuffer - 1) {
					break;
				}
				safeLimitLength += it->len;
			}
		}
	}
	return(safeLimitLength);
}

void ChunkBuffer::addTarPosInCall(u_int64_t pos) {
	if(call &&
	   (need_tar_pos || DEBUG_ASYNC_TAR_WRITE)) {
		#if DEBUG_ASYNC_TAR_WRITE
		if(call->isAllocFlagOK() && call->isChunkBuffersCountSyncOK_wait()) {
			call->addPFlag(typeContent - 1 + indexContent, Call_abstract::_p_flag_chb_add_tar_pos);
			call->addTarPos(pos, typeContent);
		} else {
			strange_log("access to strange call in ChunkBuffer::addTarPosInCall");
		}
		#else
		call->addTarPos(pos, typeContent);
		#endif
	}
}

void ChunkBuffer::strange_log(const char *error) {
	#if DEBUG_ASYNC_TAR_WRITE
	string dci;
	extern cDestroyCallsInfo *destroy_calls_info;
	if(destroy_calls_info) {
		dci = destroy_calls_info->find(this->fbasename, typeContent - 1 + indexContent);
	}
	#endif
	syslog(LOG_NOTICE, 
	       "%s : "
	       "chunk: %p, "
	       "chunk->fbasename: %s, "
	       "chunk->name: %s, "
	       "chunk->type: %i/%i, "
	       "chunk->created_at: %" int_64_format_prefix "lu, "
	       "call: %p, "
	       "call->fbasename: %s, "
	       "call->isAllocFlagOK(): %i/%i, "
	       #if DEBUG_ASYNC_TAR_WRITE
	       "call->isChunkBuffersCountSyncOK(): %i/%i, "
	       #endif
	       "call->created_at: %" int_64_format_prefix "lu, "
	       "time: %" int_64_format_prefix "lu"
	       #if DEBUG_ASYNC_TAR_WRITE
	       ", dci: %s"
	       #endif
	       ,
	       error,
	       this,
	       this->fbasename.c_str(),
	       this->name.c_str(),
	       this->typeContent,
	       this->indexContent,
	       this->created_at,
	       call,
	       call->fbasename,
	       call->isAllocFlagOK(), call->alloc_flag,
	       #if DEBUG_ASYNC_TAR_WRITE
	       call->isChunkBuffersCountSyncOK_wait(), call->chunkBuffersCount_sync,
	       #endif
	       call->created_at,
	       getTimeUS()
	       #if DEBUG_ASYNC_TAR_WRITE
	       ,dci.c_str()
	       #endif
	       );
}

volatile u_int64_t ChunkBuffer::chunk_buffers_sumsize = 0;
