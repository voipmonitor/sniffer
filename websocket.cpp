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


bool check_websocket_header(char *data, unsigned len, bool checkDataSize) {
	cWebSocketHeader ws_header((u_char*)data, len);
	return(ws_header.isHeaderSizeOk() &&
	       (!checkDataSize || ws_header.isDataSizeOk()));
}

unsigned websocket_header_length(char *data, unsigned len) {
	cWebSocketHeader ws_header((u_char*)data, len);
	return(len < sizeof(cWebSocketHeader::sFixHeader) ?
		sizeof(cWebSocketHeader::sFixHeader) :
		ws_header.getHeaderLength());
}
