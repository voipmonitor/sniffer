#include "voipmonitor.h"

#include "tools.h"
#include "websocket.h"


u_char *cWebSocketHeader::decodeData(bool *allocData, unsigned dataLength) {
	if(isMask()) {
		if(dataLength) {
			if(dataLength > getHeaderLength()) {
				dataLength -= getHeaderLength();
			} else {
				*allocData = false;
				return(NULL);
			}
		} else {
			dataLength = getDataLength();
		}
		*allocData = true;
		u_char *data = new FILE_LINE(0) u_char[dataLength];
		memcpy(data, getData(), dataLength);
		xorData(data, dataLength, (const char*)getMask(), 4, 0);
		return(data);
	} else {
		*allocData = false;
		return(getData());
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
