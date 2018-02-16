#ifndef DTLS_H
#define DTLS_H


class cDtlsHeader {
public:
	#pragma pack(push, 1)
	struct sFixHeader {
	u_int8_t content_type;
	u_int16_t version;
	u_int16_t epoch;
	u_int16_t sequence_number_filler;
	u_int32_t sequence_number;
	u_int16_t length;
	};
	#pragma pack(pop)
public:
	cDtlsHeader(char *header, unsigned limitSize) {
		this->header = (u_char*)header;
		this->limitSize = limitSize;
	}
	cDtlsHeader(u_char *header, unsigned limitSize) {
		this->header = header;
		this->limitSize = limitSize;
	}
	sFixHeader getFixHeader() {
		sFixHeader fixHeader = *(sFixHeader*)header;
		fixHeader.version = htons(fixHeader.version);
		fixHeader.epoch = htons(fixHeader.epoch);
		fixHeader.sequence_number = htonl(fixHeader.sequence_number);
		fixHeader.length = htons(fixHeader.length);
		return(fixHeader);
	}
	unsigned getHeaderSize() {
		return(sizeof(sFixHeader));
	}
	unsigned getLength() {
		return(htons(((sFixHeader*)header)->length));
	}
	bool isOkHeaderSize() {
		return(limitSize >= getHeaderSize());
	}
	bool isOkLength() {
		return(limitSize >= getHeaderSize() + getLength());
	}
	bool isOk() {
		return(isOkHeaderSize() &&
		       isOkLength());
	}
public:
	u_char *header;
	unsigned limitSize;
};


#endif //DTLS_H
