#include "voipmonitor.h"

#include "tools.h"
#include "websocket.h"


u_char *cWebSocketHeader::decodeData(bool *allocData, unsigned dataLength) {
	if(isMask()) {
		if(dataLength) {
			if(dataLength > getHeaderLength()) {
				dataLength -= getHeaderLength();
				unsigned dataLengthMax = getDataLength();
				if(dataLength > dataLengthMax) {
					dataLength = dataLengthMax;
				}
			} else {
				*allocData = false;
				return(NULL);
			}
		} else {
			dataLength = getDataLength();
		}
		if(dataLength > 0 && dataLength <= 0xFFFF) {
			*allocData = true;
			u_char *data = new FILE_LINE(0) u_char[dataLength];
			memcpy(data, getData(), dataLength);
			xorData(data, dataLength, (const char*)getMask(), 4, 0);
			return(data);
		} else {
			*allocData = false;
			return(NULL);
		}
	} else {
		*allocData = false;
		return(getData());
	}
}

cWebSocketInflate::cWebSocketInflate() {
	zipStream = NULL;
}

cWebSocketInflate::~cWebSocketInflate() {
	destroyZipStream();
}

u_char *cWebSocketInflate::decompressFrame(u_char *frame, unsigned frameLength, unsigned *rsltFrameLength) {
	cWebSocketHeader ws(frame, frameLength);
	if(!ws.isHeaderSizeOk() ||
	   !ws.isDataSizeOk(cWebSocketHeader::_chdst_ge_unlimited) ||
	   !ws.isCompressed()) {
		return(NULL);
	}
	if(!zipStream) {
		zipStream = new FILE_LINE(0) z_stream;
		memset(zipStream, 0, sizeof(z_stream));
		if(inflateInit2(zipStream, -MAX_WBITS) != Z_OK) {
			delete zipStream;
			zipStream = NULL;
			return(NULL);
		}
	}
	bool allocData;
	u_char *data = ws.decodeData(&allocData);
	if(!data) {
		inflateReset(zipStream);
		return(NULL);
	}
	u_char tail[] = { 0x00, 0x00, 0xFF, 0xFF };
	u_char buffer[4096];
	SimpleBuffer rsltData;
	int rslt = Z_OK;
	for(int pass = 0; pass < 2 && rslt == Z_OK && rsltData.size() <= WEBSOCKET_DECOMPRESS_MAX_LENGTH; pass++) {
		zipStream->next_in = pass == 0 ? data : tail;
		zipStream->avail_in = pass == 0 ? ws.getDataLength() : sizeof(tail);
		do {
			zipStream->next_out = buffer;
			zipStream->avail_out = sizeof(buffer);
			rslt = inflate(zipStream, Z_SYNC_FLUSH);
			if(rslt == Z_BUF_ERROR) {
				rslt = Z_OK;
			}
			if(rslt == Z_OK || rslt == Z_STREAM_END) {
				rsltData.add(buffer, sizeof(buffer) - zipStream->avail_out);
			}
		} while(rslt == Z_OK && !zipStream->avail_out && rsltData.size() <= WEBSOCKET_DECOMPRESS_MAX_LENGTH);
	}
	if(allocData) {
		delete [] data;
	}
	bool decompressOk = (rslt == Z_OK || rslt == Z_STREAM_END) && rsltData.size() <= WEBSOCKET_DECOMPRESS_MAX_LENGTH;
	if(!decompressOk) {
		inflateReset(zipStream);
		return(NULL);
	}
	if(rslt == Z_STREAM_END) {
		destroyZipStream();
	}
	unsigned rsltHeaderLength = sizeof(cWebSocketHeader::sFixHeader) + (rsltData.size() < 126 ? 0 : 2);
	*rsltFrameLength = rsltHeaderLength + rsltData.size();
	u_char *rsltFrame = new FILE_LINE(0) u_char[*rsltFrameLength];
	cWebSocketHeader::sFixHeader *rsltFixHeader = (cWebSocketHeader::sFixHeader*)rsltFrame;
	*rsltFixHeader = *ws.getFixHeader();
	rsltFixHeader->res = 0;
	rsltFixHeader->mask = 0;
	if(rsltData.size() < 126) {
		rsltFixHeader->payload_len = rsltData.size();
	} else {
		rsltFixHeader->payload_len = 126;
		*(u_int16_t*)(rsltFrame + sizeof(cWebSocketHeader::sFixHeader)) = htons(rsltData.size());
	}
	if(rsltData.size()) {
		memcpy(rsltFrame + rsltHeaderLength, rsltData.data(), rsltData.size());
	}
	return(rsltFrame);
}

void cWebSocketInflate::destroyZipStream() {
	if(zipStream) {
		inflateEnd(zipStream);
		delete zipStream;
		zipStream = NULL;
	}
}


bool check_websocket_header(char *data, unsigned len, cWebSocketHeader::eCheckDataSizeType checkDataSizeType) {
	cWebSocketHeader ws_header((u_char*)data, len);
	return(ws_header.isHeaderSizeOk() &&
	       (checkDataSizeType == cWebSocketHeader::_chdst_na || ws_header.isDataSizeOk(checkDataSizeType)));
}

unsigned websocket_header_length(char *data, unsigned len) {
	cWebSocketHeader ws_header((u_char*)data, len);
	return(len < sizeof(cWebSocketHeader::sFixHeader) ?
		sizeof(cWebSocketHeader::sFixHeader) :
		ws_header.getHeaderLength());
}

void print_websocket_check(char *data, unsigned len) {
	cWebSocketHeader ws_header((u_char*)data, len);
	cout << "ws header size is ok: " << ws_header.isHeaderSizeOk() << endl;
	cout << "ws use mask: " << ws_header.isMask() << endl;
	cout << "ws header size: " << ws_header.getHeaderLength() << endl;
	cout << "ws data size: " << ws_header.getDataLength() << endl;
	cout << " * data size: " << len << endl;
	int diff = (int)(len - ws_header.getHeaderLength() - ws_header.getDataLength());
	cout << " * diff size: " << diff << endl;
	if(diff > 0) {
		hexdump(data + len - diff, diff);
	}
}
