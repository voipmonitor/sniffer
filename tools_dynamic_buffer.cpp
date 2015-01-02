#include "tar.h"
#include "tools_dynamic_buffer.h"

#define MIN(x,y) ((x) < (y) ? (x) : (y))

extern TarQueue *tarQueue;


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



Bucketbuffer::Bucketbuffer() {
	this->bucketlen = 32*1024;
	buffer = new char[bucketlen];
	listbuffer.push_back(buffer);
	len = 0;
}

Bucketbuffer::Bucketbuffer(int bucketlen) {
	this->bucketlen = bucketlen;
	buffer = new char[bucketlen];
	listbuffer.push_back(buffer);
	len = 0;
}

void
Bucketbuffer::add(char *data, int datalen) {
	int copied = 0;
	do {   
		int whattocopy = MIN(bucketlen - len % bucketlen, datalen - copied);
		memcpy(buffer + len % bucketlen, data + copied, whattocopy);
		copied += whattocopy;
		len += whattocopy;
		if(!(len % bucketlen)) {
			buffer = new char[bucketlen];
			listbuffer.push_back(buffer);
		}
	} while(datalen > copied);
}

Bucketbuffer::~Bucketbuffer() {
	list<char*>::iterator it = listbuffer.begin();
	for(it = listbuffer.begin(); it != listbuffer.end(); it++) {
		delete *it;
	}
}
