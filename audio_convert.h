#ifndef AUDIO_CONVERT_H
#define AUDIO_CONVERT_H


#include <string.h>
#include <string>
#include <stdlib.h>
#include <vorbis/codec.h>
#include <vorbis/vorbisenc.h>

#include "endian.h"
#include "bswap.h"


class cAudioConvert {
public:
	enum eSrcDstType {
		_src,
		_dst
	};
	enum eFormatType {
		_format_raw,
		_format_wav,
		_format_ogg
	};
	enum eResult {
		_rslt_ok,
		_rslt_write_failed,
		_rslt_open_for_read_failed,
		_rslt_open_for_write_failed,
		_rslt_wav_read_header_failed,
		_rslt_wav_bad_header,
		_rslt_ogg_bad_ogg_file,
		_rslt_ogg_bad_bitstream,
		_rslt_ogg_bad_first_page,
		_rslt_ogg_bad_initial_header_packet,
		_rslt_ogg_missing_vorbis_audiodata,
		_rslt_ogg_corrupt_secondary_header,
		_rslt_ogg_missing_vorbis_headers,
		_rslt_ogg_failed_encode_initialization,
		_rslt_unknown_format
	};
	struct sAudioInfo {
		sAudioInfo() {
			memset(this, 0, sizeof(*this));
		}
		u_int32_t sampleRate;
		u_int16_t channels;
		u_int16_t bitsPerSample;
	} __attribute__((packed));
	struct sWavHeader {
		void null() {
			memset(this, 0, sizeof(*this));
		}
		void init() {
			#if __GNUC__ >= 8
			#pragma GCC diagnostic push
			#pragma GCC diagnostic ignored "-Wstringop-truncation"
			#endif
			strncpy(formatId1, "RIFF", 4);
			chunkSize = 0;
			strncpy(formatId2, "WAVEfmt ", 8);
			lengthFormatData = 16;
			format = 1;
			strncpy(dataId, "data", 4);
			dataSize = 0;
			#if __GNUC__ >= 8
			#pragma GCC diagnostic pop
			#endif
		}
		void setFromAudioInfo(sAudioInfo *audioInfo) {
			channels = audioInfo->channels;
			sampleRate = audioInfo->sampleRate;
			byteRate = audioInfo->sampleRate * audioInfo->channels * audioInfo->bitsPerSample / 8;
			bytesPerSample = audioInfo->channels * audioInfo->bitsPerSample / 8;
			bitsPerSampleChannel = audioInfo->bitsPerSample;
		}
		void setAudioInfo(sAudioInfo *audioInfo) {
			audioInfo->channels = channels;
			audioInfo->sampleRate = sampleRate;
			audioInfo->bitsPerSample = bitsPerSampleChannel;
		}
		void setFileSize(long int fileSize) {
			dataSize = fileSize - sizeof(sWavHeader);
			chunkSize = fileSize - 8;
		}
		void prepareAfterRead() {
			prepareEndian();
		}
		void prepareBeforeWrite() {
			prepareEndian();
		}
		void prepareEndian();
		bool checkHeader() {
			return(!strncmp(formatId1, "RIFF", 4));
		}
		char formatId1[4];
		u_int32_t chunkSize;
		char formatId2[8];
		u_int32_t lengthFormatData; // size of above
		u_int16_t format; // 1 as PCM
		u_int16_t channels;
		u_int32_t sampleRate;
		u_int32_t byteRate;
		u_int16_t bytesPerSample;
		u_int16_t bitsPerSampleChannel;
		char dataId[4];
		u_int32_t dataSize;
	} __attribute__((packed));
	struct sOgg {
		sOgg() {
			memset(this, 0, sizeof(*this));
		}
		~sOgg() {
			ogg_stream_clear(&os);
			vorbis_block_clear(&vb);
			vorbis_dsp_clear(&vd);
			vorbis_comment_clear(&vc);
			vorbis_info_clear(&vi);
		}
		ogg_sync_state   oy; /* sync and verify incoming physical bitstream */
		ogg_stream_state os; /* take physical pages, weld into a logical stream of packets */
		ogg_page         og; /* one Ogg bitstream page. Vorbis packets are inside */
		ogg_packet       op; /* one raw packet of data for decode */
		vorbis_info      vi; /* struct that stores all the static vorbis bitstream settings */
		vorbis_comment   vc; /* struct that stores all the bitstream user comments */
		vorbis_dsp_state vd; /* central working state for the packet->PCM decoder */
		vorbis_block     vb; /* local working space for packet->PCM decode */
		int eos;
	};
	struct sOggDecode {
		sOggDecode(unsigned sync_buffer_size) {
			memset(this, 0, sizeof(*this));
			this->sync_buffer_size = sync_buffer_size;
		}
		~sOggDecode() {
			if(conv_buffer) {
				delete [] conv_buffer;
			}
		}
		unsigned sync_buffer_size;
		char *sync_buffer;
		ogg_int16_t *conv_buffer;
	};
public:
	cAudioConvert();
	~cAudioConvert();
	eResult getAudioInfo();
	std::string jsonAudioInfo();
	eResult readRaw(sAudioInfo *audioInfo);
	eResult readWav();
	bool readWavHeader(sWavHeader *wavHeader);
	eResult writeWavHeader(long int size = 0);
	eResult writeWavData(u_char *data, unsigned datalen);
	eResult writeWavEnd();
	eResult readOgg();
	eResult writeOggHeader();
	eResult writeOggData(u_char *data, unsigned datalen);
	eResult writeOggEnd();
	eResult _writeOgg();
	eResult write(u_char *data, unsigned datalen);
	void test();
public:
	eSrcDstType srcDstType;
	eFormatType formatType;
	std::string fileName;
	FILE *fileHandle;
	cAudioConvert *destAudio;
	sAudioInfo audioInfo;
	float oggQuality;
	std::string comment;
	sOgg ogg;
	bool headerIsWrited;
	bool onlyGetAudioInfo;
};


#endif //AUDIO_CONVERT_H
