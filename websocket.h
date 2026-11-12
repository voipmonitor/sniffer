#ifndef WEBSOCKET_H
#define WEBSOCKET_H


#include <zlib.h>


#define WEBSOCKET_DECOMPRESS_MAX_LENGTH 0xFFFF


class cWebSocketHeader {
public:
	enum eCheckDataSizeType {
		_chdst_na,
		_chdst_strict,
		_chdst_ge_limit,
		_chdst_ge_unlimited
	};
	struct sFixHeader {
	#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t opcode : 4;
	u_int8_t res : 3;
	u_int8_t fin : 1;
	u_int8_t payload_len : 7;
	u_int8_t mask : 1;
	#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t fin : 1;
	u_int8_t res : 3;
	u_int8_t opcode : 4;
	u_int8_t mask : 1;
	u_int8_t payload_len : 7;
	#endif
	};
public:
	cWebSocketHeader(char *header, unsigned size) {
		this->header = (u_char*)header;
		this->size = size;
	}
	cWebSocketHeader(u_char *header, unsigned size) {
		this->header = header;
		this->size = size;
	}
	sFixHeader *getFixHeader() {
		 return((sFixHeader*)header);
	}
	int isExtendedLength() {
		switch(((sFixHeader*)header)->payload_len) {
		case 126:
			return(1);
		case 127:
			return(2);
		}
		return(0);
	}
	unsigned getExtendedLengthSize() {
		switch(isExtendedLength()) {
		case 1:
			return(2);
		case 2:
			return(8);
		}
		return(0);
	}
	u_int64_t getDataLength() {
		switch(isExtendedLength()) {
		case 1:
			return(htons(*(u_int16_t*)(header + 2)));
		case 2:
			return(htonl(*(u_int64_t*)(header + 2)));
		}
		return(((sFixHeader*)header)->payload_len);
	}
	bool isMask() {
		return(((sFixHeader*)header)->mask);
	}
	bool isCompressed() {
		return(((sFixHeader*)header)->res & 0x04);
	}
	u_char *getMask() {
		return(isMask() ?
			header + sizeof(sFixHeader) + getExtendedLengthSize() :
			NULL);
	}
	unsigned getHeaderLength() {
		return(sizeof(sFixHeader) + 
		       getExtendedLengthSize() + 
		       (isMask() ? 4 : 0));
	}
	u_char *getData() {
		return(header + getHeaderLength());
	}
	u_char *decodeData(bool *allocData, unsigned dataLength = 0);
	bool isHeaderSizeOk() {
		return(size >= sizeof(sFixHeader) &&
		       size >= getHeaderLength());
	}
	bool isDataSizeOk(eCheckDataSizeType checkDataSizeType) {
		u_int64_t headerWithDataLength = getHeaderLength() + getDataLength();
		switch(checkDataSizeType) {
		case _chdst_na:
			return(true);
		case _chdst_strict:
			return(size == headerWithDataLength);
		case _chdst_ge_limit:
			return(size >= headerWithDataLength &&
			       size <= headerWithDataLength + 1);
		case _chdst_ge_unlimited:
			return(size >= headerWithDataLength);
		}
		return(false);
	}
public:
	u_char *header;
	unsigned size;
};


class cWebSocketInflate {
public:
	cWebSocketInflate();
	~cWebSocketInflate();
	u_char *decompressFrame(u_char *frame, unsigned frameLength, unsigned *rsltFrameLength);
	bool existsContext() {
		return(zipStream != NULL);
	}
private:
	void destroyZipStream();
private:
	z_stream *zipStream;
};


bool check_websocket_header(char *data, unsigned len, cWebSocketHeader::eCheckDataSizeType checkDataSizeType = cWebSocketHeader::_chdst_ge_limit);
unsigned websocket_header_length(char *data, unsigned len);
void print_websocket_check(char *data, unsigned len);

inline bool check_websocket_first_byte(char *data, unsigned len, bool enableCompressed = false) {
	return(len > 0 && ((u_char)data[0] == 0x81 || (enableCompressed && (u_char)data[0] == 0xC1)));
}
inline bool check_websocket_first_byte(u_char *data, unsigned len, bool enableCompressed = false) {
	return(check_websocket_first_byte((char*)data, len, enableCompressed));
}
inline bool check_websocket(char *data, unsigned len, cWebSocketHeader::eCheckDataSizeType checkDataSizeType = cWebSocketHeader::_chdst_ge_limit, bool enableCompressed = false) {
	return(check_websocket_first_byte(data, len, enableCompressed) &&
	       check_websocket_header(data, len, checkDataSizeType));
}
inline bool check_websocket(u_char *data, unsigned len, cWebSocketHeader::eCheckDataSizeType checkDataSizeType = cWebSocketHeader::_chdst_ge_limit, bool enableCompressed = false) {
	return(check_websocket((char*)data, len, checkDataSizeType, enableCompressed));
}


#endif //WEBSOCKET_H
