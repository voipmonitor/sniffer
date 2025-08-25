#ifndef AUDIO_CONVERT_H
#define AUDIO_CONVERT_H


#include <string.h>
#include <string>
#include <stdlib.h>
#include <vorbis/codec.h>
#include <vorbis/vorbisenc.h>

#if HAVE_LIBLAME
#include <lame/lame.h>
#endif

#if HAVE_LIBMPG123
#include <mpg123.h>
#endif

#if HAVE_LIBSAMPLERATE
#include <samplerate.h>
#endif

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
		#if HAVE_LIBLAME && HAVE_LIBMPG123
		,_format_mp3
		#endif
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
		_rslt_mp3_failed_create_lame,
		_rslt_mp3_failed_init_params,
		_rslt_mp3_failed_encode,
		_rslt_mpg123_failed_init,
		_rslt_mpg123_failed_create_handle,
		_rslt_mpg123_failed_open,
		_rslt_mpg123_failed_get_audioinfo,
		_rslt_failed_libsamplerate_init,
		_rslt_failed_libsamplerate_process,
		_rslt_unknown_format,
		_rslt_no_library_needed
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
			ogg_sync_clear(&oy);
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
	#if HAVE_LIBLAME && HAVE_LIBMPG123
	struct sMp3 {
		sMp3() {
			lame = NULL;
			mpg123 = NULL;
			buffer = NULL;
			buffer_size = 0;
		}
		~sMp3() {
			destroy();
		}
		void set_buffer(unsigned pcm_buffer_size, sAudioInfo *audioInfo);
		void destroy();
		lame_t lame;
		mpg123_handle *mpg123;
		u_char *buffer;
		unsigned buffer_size;
	};
	#endif
public:
	cAudioConvert();
	~cAudioConvert();
	eResult getAudioInfo();
	std::string jsonAudioInfo();
	eResult readRaw(sAudioInfo *audioInfo);
	eResult resampleRaw(sAudioInfo *audioInfo, const char *fileNameDst, unsigned sampleRateDst);
	eResult readWav();
	eResult loadWav(u_char **data, size_t *samples, bool pcm_float = false);
	bool readWavHeader(sWavHeader *wavHeader);
	eResult writeWavHeader(long int size = 0);
	eResult writeWavData(u_char *data, unsigned datalen);
	eResult writeWavEnd();
	eResult readOgg();
	eResult writeOggHeader();
	eResult writeOggData(u_char *data, unsigned datalen);
	eResult writeOggEnd();
	eResult _writeOgg();
	#if HAVE_LIBLAME && HAVE_LIBMPG123
	eResult readMp3();
	eResult initMp3();
	eResult writeMp3Data(u_char *data, unsigned datalen);
	eResult writeMp3End();
	#endif
	eResult write(u_char *data, unsigned datalen);
	bool open();
	bool open_for_write();
	void close();
	void linear_resample(int16_t* input, int16_t* output, int input_len, double ratio, int channels);
	static const char *getExtension(eFormatType format);
	static std::string getRsltStr(eResult rslt);
	static void test();
public:
	eSrcDstType srcDstType;
	eFormatType formatType;
	std::string fileName;
	FILE *fileHandle;
	cAudioConvert *destAudio;
	sAudioInfo audioInfo;
	float oggQuality;
	int mp3Quality;
	std::string comment;
	sOgg ogg;
	#if HAVE_LIBLAME && HAVE_LIBMPG123
	sMp3 mp3;
	#endif
	bool headerIsWrited;
	bool onlyGetAudioInfo;
	unsigned resample_chunk_length;
	bool destInSpool;
	u_char *write_buffer;
};


bool ac_file_mix(char *src1, char *src2, char *dest, cAudioConvert::eFormatType format,
		 unsigned sampleRate, bool stereo,  bool swap,
		 double quality, bool destInSpool);
void slinear_saturated_add(short *input, short *value);

#endif //AUDIO_CONVERT_H
