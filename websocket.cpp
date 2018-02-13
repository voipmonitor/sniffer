#include "voipmonitor.h"

#include "tools.h"
#include "websocket.h"


u_char *cWebSocketHeader::decodeData(bool *allocData) {
	if(isMask()) {
		*allocData = true;
		u_char *data = new FILE_LINE(0) u_char[getDataLength()];
		memcpy(data, getData(), getDataLength());
		xorData(data, getDataLength(), (const char*)getMask(), 4, 0);
		return(data);
	} else {
		*allocData = false;
		return(getData());
	}
}


int check_websocket_header(char *data, unsigned len) {
	cWebSocketHeader ws_header((u_char*)data, len);
	return(ws_header.isOk());
}
