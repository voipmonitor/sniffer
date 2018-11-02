#ifndef WEBSOCKET_H
#define WEBSOCKET_H


class cWebSocketHeader {
public:
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
	bool isDataSizeOk() {
		return(size == (getHeaderLength() + getDataLength()));
	}
public:
	u_char *header;
	unsigned size;
};


bool check_websocket_header(char *data, unsigned len, bool checkDataSize = true);
unsigned websocket_header_length(char *data, unsigned len);

inline bool check_websocket_first_byte(char *data, unsigned len) {
	return(len > 0 && (u_char)data[0] == 0x81);
}
inline bool check_websocket_first_byte(u_char *data, unsigned len) {
	return(check_websocket_first_byte((char*)data, len));
}
inline bool check_websocket(char *data, unsigned len, bool checkDataSize = true) {
	return(check_websocket_first_byte(data, len) &&
	       check_websocket_header(data, len, checkDataSize));
}
inline bool check_websocket(u_char *data, unsigned len, bool checkDataSize = true) {
	return(check_websocket((char*)data, len, checkDataSize));
}


#endif //WEBSOCKET_H
