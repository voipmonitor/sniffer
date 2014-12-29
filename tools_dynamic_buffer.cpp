#include "tar.h"
#include "tools_dynamic_buffer.h"


extern TarQueue tarQueue;


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
			
			tarQueue.add(fileName, time, (char*)concatTarBuffer, tarBufferSize);
			delete [] concatTarBuffer;
		}
	}
}
