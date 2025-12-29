#include <iostream>
#include <ostream>
#include <stdio.h>
#include <math.h>

#include "config.h"

#include "audio_convert.h"
#include "tools_global.h"
#include "tools.h"


using namespace std;


void cAudioConvert::sWavHeader::prepareEndian() {
	#if __BYTE_ORDER == __BIG_ENDIAN
	_BSWAP(chunkSize);
	_BSWAP(lengthFormatData);
	_BSWAP(format);
	_BSWAP(channels);
	_BSWAP(sampleRate);
	_BSWAP(byteRate);
	_BSWAP(bytesPerSample);
	_BSWAP(bitsPerSampleChannel);
	_BSWAP(dataSize);
	#endif
}


#if HAVE_LIBLAME && HAVE_LIBMPG123
void cAudioConvert::sMp3::set_buffer(unsigned pcm_buffer_size, sAudioInfo *audioInfo) {
	unsigned need_buffer_size = pcm_buffer_size / (audioInfo->bitsPerSample / 8) * 1.25 + 7200;
	if(!buffer || buffer_size < need_buffer_size) {
		if(buffer) {
			delete [] buffer;
		}
		buffer_size = need_buffer_size;
		buffer = new FILE_LINE(0) u_char[buffer_size];
	}
}

void cAudioConvert::sMp3::destroy() {
	if(lame) {
		lame_close(lame);
		lame = NULL;
	}
	if(mpg123) {
		mpg123_close(mpg123);
		mpg123_delete(mpg123);
		mpg123_exit();
		mpg123 = NULL;
	}
	if(buffer) {
		delete [] buffer;
		buffer = 0;
		buffer_size = 0;
	}
}
#endif


cAudioConvert::cAudioConvert() {
	srcDstType = _src;
	formatType = _format_raw;
	fileHandle = NULL;
	destAudio = NULL;
	oggQuality = 0.4;
	mp3Quality = 5;
	headerIsWrited = false;
	onlyGetAudioInfo = false;
	resample_chunk_length = 100 * 1024;
	destInSpool = false;
	write_buffer = NULL;
}

cAudioConvert::~cAudioConvert() {
	if(fileHandle) {
		fclose(fileHandle);
	}
	if(write_buffer) {
		delete [] write_buffer;
	}
}

cAudioConvert::eResult cAudioConvert::getAudioInfo() {
	onlyGetAudioInfo = true;
	if(readWav() == _rslt_ok) {
		 formatType = _format_wav;
		 onlyGetAudioInfo = false;
		 return(_rslt_ok);
	}
	if(fileHandle) {
		fclose(fileHandle);
		fileHandle = NULL;
	}
	if(readOgg() == _rslt_ok) {
		 formatType = _format_ogg;
		 onlyGetAudioInfo = false;
		 return(_rslt_ok);
	}
	#if HAVE_LIBLAME && HAVE_LIBMPG123
	if(readMp3() == _rslt_ok) {
		 formatType = _format_mp3;
		 onlyGetAudioInfo = false;
		 return(_rslt_ok);
	}
	#endif
	onlyGetAudioInfo = false;
	return(_rslt_unknown_format);
}

string cAudioConvert::jsonAudioInfo() {
	JsonExport json_export;
	json_export.add("format", formatType == _format_raw ? "raw" :
				  formatType == _format_wav ? "wav" :
				  formatType == _format_ogg ? "ogg" :
				  #if HAVE_LIBLAME && HAVE_LIBMPG123
				  formatType == _format_mp3 ? "mp3" :
				  #endif
				  "unknown");
	json_export.add("sample_rate", audioInfo.sampleRate);
	json_export.add("channels", audioInfo.channels);
	json_export.add("bits_per_sample", audioInfo.bitsPerSample);
	json_export.add("bytes_per_sample", audioInfo.bitsPerSample / 8);
	return(json_export.getJson());
}

cAudioConvert::eResult cAudioConvert::readRaw(sAudioInfo *audioInfo) {
	if(!open()) {
		return(_rslt_open_for_read_failed);
	}
	this->audioInfo = *audioInfo;
	unsigned readbuffer_size = 1024;
	u_char *readbuffer = new FILE_LINE(0) u_char[readbuffer_size];
        int read_length;
	eResult rslt_write = _rslt_ok;
	while((read_length = fread(readbuffer, 1, readbuffer_size, fileHandle)) > 0) {
		rslt_write = write(readbuffer, read_length);
		if(rslt_write != _rslt_ok) {
			break;
		}
	}
	if(rslt_write == _rslt_ok) {
		rslt_write = write(NULL, 0);
	}
	delete [] readbuffer;
	return(rslt_write);
}

cAudioConvert::eResult cAudioConvert::resampleRaw(sAudioInfo *audioInfo, const char *fileNameDst, unsigned sampleRateDst) {
	FILE *infile = fopen(fileName.c_str(), "rb");
	if(!infile) {
		return(_rslt_open_for_read_failed);
	}
	FILE *outfile = fopen(fileNameDst, "wb");
	if(!outfile) {
		fclose(infile);
		return(_rslt_open_for_write_failed);
	}
	double src_ratio = (double)sampleRateDst / audioInfo->sampleRate;
	unsigned input_buffer_len = resample_chunk_length;
	unsigned output_buffer_len = input_buffer_len * src_ratio + 1024;
	int16_t *input_buffer = new FILE_LINE(0) int16_t[input_buffer_len];
	int16_t *output_buffer = new FILE_LINE(0) int16_t[output_buffer_len];
#if HAVE_LIBSAMPLERATE
	float *input_buffer_float = new FILE_LINE(0) float[input_buffer_len];
	float *output_buffer_float = new FILE_LINE(0) float[output_buffer_len];
	SRC_STATE *src_state = src_new(SRC_SINC_BEST_QUALITY, audioInfo->channels, NULL);
	if(!src_state) {
		fclose(infile);
		fclose(outfile);
		delete [] input_buffer_float;
		delete [] output_buffer_float;
		delete [] input_buffer;
		delete [] output_buffer;
		return(_rslt_failed_libsamplerate_init);
	}
	SRC_DATA src_data;
	src_data.data_in = input_buffer_float;
	src_data.data_out = output_buffer_float;
	src_data.input_frames = 0;
	src_data.output_frames = output_buffer_len / audioInfo->channels;
	src_data.src_ratio = src_ratio;
	src_data.end_of_input = 0;
	size_t readcount;
	while((readcount = fread(input_buffer, sizeof(int16_t), input_buffer_len, infile)) > 0) {
		for(size_t i = 0; i < readcount; i++) {
			input_buffer_float[i] = input_buffer[i] / 32768.0;
		}
		src_data.input_frames = readcount / audioInfo->channels;
		src_data.data_in = input_buffer_float;
		int error = src_process(src_state, &src_data);
		if(error) {
			src_delete(src_state);
			fclose(infile);
			fclose(outfile);
			delete [] input_buffer_float;
			delete [] output_buffer_float;
			delete [] input_buffer;
			delete [] output_buffer;
			return(_rslt_failed_libsamplerate_process);
		}
		for(int i = 0; i < src_data.output_frames_gen * audioInfo->channels; i++) {
			float sample = output_buffer_float[i];
			if(sample > 1.0) sample = 1.0;
			if(sample < -1.0) sample = -1.0;
			output_buffer[i] = (int16_t)(sample * 32767.0);
		}
		if(fwrite(output_buffer, sizeof(int16_t), src_data.output_frames_gen * audioInfo->channels, outfile) != (size_t)src_data.output_frames_gen) {
			src_delete(src_state);
			fclose(infile);
			fclose(outfile);
			delete [] input_buffer_float;
			delete [] output_buffer_float;
			delete [] input_buffer;
			delete [] output_buffer;
			return(_rslt_write_failed);
		}
	}
	src_delete(src_state);
	delete [] input_buffer_float;
	delete [] output_buffer_float;
#else 
	size_t readcount;
	while((readcount = fread(input_buffer, sizeof(int16_t), input_buffer_len, infile)) > 0) {
		int output_len = (int)(readcount * src_ratio) / audioInfo->channels;
		linear_resample(input_buffer, output_buffer, readcount, src_ratio, audioInfo->channels);
		if(fwrite(output_buffer, sizeof(int16_t), output_len * audioInfo->channels, outfile) != (size_t)(output_len * audioInfo->channels)) {
			fclose(infile);
			fclose(outfile);
			return(_rslt_write_failed);
		}
	}
#endif
	delete [] input_buffer;
	delete [] output_buffer;
	fclose(infile);
	fclose(outfile);
	return(_rslt_ok);
}

cAudioConvert::eResult cAudioConvert::readWav() {
	if(!open()) {
		return(_rslt_open_for_read_failed);
	}
	sWavHeader wavHeader;
	if(!readWavHeader(&wavHeader)) {
		return(_rslt_wav_read_header_failed);
	} else {
		if(!wavHeader.checkHeader()) {
			return(_rslt_wav_bad_header);
		}
		wavHeader.setAudioInfo(&audioInfo);
		if(onlyGetAudioInfo) {
			return(_rslt_ok);
		}
	}
	unsigned readbuffer_size = 1024;
	u_char *readbuffer = new FILE_LINE(0) u_char[readbuffer_size];
        size_t read_length;
	eResult rslt_write = _rslt_ok;
	while((read_length = fread(readbuffer, 1, readbuffer_size, fileHandle)) > 0) {
		rslt_write = write(readbuffer, read_length);
		if(rslt_write != _rslt_ok) {
			break;
		}
	}
	if(rslt_write == _rslt_ok) {
		rslt_write = write(NULL, 0);
	}
	delete [] readbuffer;
	return(rslt_write);
}

cAudioConvert::eResult cAudioConvert::loadWav(u_char **data, size_t *samples, bool pcm_float) {
	*data = NULL;
	*samples = 0;
	if(!open()) {
		return(_rslt_open_for_read_failed);
	}
	fseek(fileHandle, 0, SEEK_END);
	long file_size = ftell(fileHandle);
	fseek(fileHandle, 0, SEEK_SET);
	sWavHeader wavHeader;
	if(!readWavHeader(&wavHeader)) {
		return(_rslt_wav_read_header_failed);
	} else {
		if(!wavHeader.checkHeader()) {
			return(_rslt_wav_bad_header);
		}
		wavHeader.setAudioInfo(&audioInfo);
		if(onlyGetAudioInfo) {
			return(_rslt_ok);
		}
	}
	size_t data_size = (pcm_float ? sizeof(float) / sizeof(int16_t) : 1) * file_size;
	*data = new FILE_LINE(0) u_char[data_size];
	size_t data_pos = 0;
	size_t readbuffer_size = 1024;
	u_char *readbuffer = new FILE_LINE(0) u_char[readbuffer_size];
        size_t read_length;
	eResult rslt_write = _rslt_ok;
	while((read_length = fread(readbuffer, 1, readbuffer_size, fileHandle)) > 0) {
		if(pcm_float) {
			for(size_t i = 0; i < read_length; i += 2) {
				*(float*)(*data + data_pos) = *(int16_t*)(readbuffer + i) / 32768.0;
				data_pos += sizeof(float);
			}
		} else {
			memcpy(*data + data_pos, readbuffer, read_length);
			data_pos += read_length;
		}
	}
	*samples = data_pos / (pcm_float ? sizeof(float) : sizeof(int16_t));
	delete [] readbuffer;
	return(rslt_write);
}

bool cAudioConvert::readWavHeader(sWavHeader *wavHeader) {
	if(!open()) {
		return(false);
	}
	wavHeader->null();
	size_t readSize = fread(wavHeader, 1, sizeof(sWavHeader), fileHandle);
	if(readSize == sizeof(sWavHeader)) {
		wavHeader->prepareAfterRead();
		return(true);
	}
	return(false);
}

cAudioConvert::eResult cAudioConvert::writeWavHeader(long int size) {
	if(size == -1) {
		fseek(fileHandle, 0, SEEK_END);
		size = ftello(fileHandle);
	}
	sWavHeader wavHeader;
	wavHeader.init();
	wavHeader.setFromAudioInfo(&audioInfo);
	wavHeader.setFileSize(size);
	wavHeader.prepareBeforeWrite();
	if(size != 0) {
		fseek(fileHandle, 0, SEEK_SET);
	}
	return(write((u_char*)&wavHeader, sizeof(sWavHeader)));
}

cAudioConvert::eResult cAudioConvert::writeWavData(u_char *data, unsigned datalen) {
	return(fwrite(data, 1, datalen, fileHandle) == datalen ?
		_rslt_ok :
		_rslt_write_failed);
}

cAudioConvert::eResult cAudioConvert::writeWavEnd() {
	return(writeWavHeader(-1));
}

cAudioConvert::eResult cAudioConvert::readOgg() {
	if(!open()) {
		return(_rslt_open_for_read_failed);
	}
 
	sOggDecode oggDecode(4096);

	ogg_sync_init(&ogg.oy); /* Now we can read pages */

	while(1) { /* we repeat if the bitstream is chained */
		ogg.eos = 0;

		/* grab some data at the head of the stream. We want the first page
		   (which is guaranteed to be small and only contain the Vorbis
		   stream initial header) We need the first page to get the stream
		   serialno. */

		/* submit a 4k block to libvorbis' Ogg layer */
		oggDecode.sync_buffer = ogg_sync_buffer(&ogg.oy, oggDecode.sync_buffer_size);
		unsigned read_bytes = fread(oggDecode.sync_buffer, 1, oggDecode.sync_buffer_size, fileHandle);
		ogg_sync_wrote(&ogg.oy, read_bytes);

		/* Get the first page. */
		if(ogg_sync_pageout(&ogg.oy, &ogg.og) != 1) {
			/* have we simply run out of data?  If so, we're done. */
			if(read_bytes < oggDecode.sync_buffer_size) break;
			return(_rslt_ogg_bad_bitstream);
		}

		/* Get the serial number and set up the rest of decode. */
		/* serialno first; use it to set up a logical stream */
		ogg_stream_init(&ogg.os, ogg_page_serialno(&ogg.og));

		/* extract the initial header from the first page and verify that the
		   Ogg bitstream is in fact Vorbis data */

		/* I handle the initial header first instead of just having the code
		   read all three Vorbis headers at once because reading the initial
		   header is an easy way to identify a Vorbis bitstream and it's
		   useful to see that functionality seperated out. */

		vorbis_info_init(&ogg.vi);
		vorbis_comment_init(&ogg.vc);
		if(ogg_stream_pagein(&ogg.os, &ogg.og) < 0){
			return(_rslt_ogg_bad_first_page);
		}

		if(ogg_stream_packetout(&ogg.os, &ogg.op) != 1){
			return(_rslt_ogg_bad_initial_header_packet);
		}

		if(vorbis_synthesis_headerin(&ogg.vi, &ogg.vc, &ogg.op) < 0){
			return(_rslt_ogg_missing_vorbis_audiodata);
		}

		/* At this point, we're sure we're Vorbis. We've set up the logical
		   (Ogg) bitstream decoder. Get the comment and codebook headers and
		   set up the Vorbis decoder */

		/* The next two packets in order are the comment and codebook headers.
		   They're likely large and may span multiple pages. Thus we read
		   and submit data until we get our two packets, watching that no
		   pages are missing. If a page is missing, error out; losing a
		   header page is the only place where missing data is fatal. */

		int i = 0;
		while(i < 2) {
			while(i < 2) {
				int result=ogg_sync_pageout(&ogg.oy, &ogg.og);
				if(result==0) break; /* Need more data */
				/* Don't complain about missing or corrupt data yet. We'll
				   catch it at the packet output phase */
				if(result == 1) {
					ogg_stream_pagein(&ogg.os, &ogg.og); /* we can ignore any errors here
								       as they'll also become apparent
								       at packetout */
					while(i < 2) {
						result=ogg_stream_packetout(&ogg.os, &ogg.op);
						if(result == 0) break;
						if(result < 0){
							/* Uh oh; data at some point was corrupted or missing!
							   We can't tolerate that in a header.  Die. */
							return(_rslt_ogg_corrupt_secondary_header);
						}
						result = vorbis_synthesis_headerin(&ogg.vi, &ogg.vc, &ogg.op);
						if(result<0){
							return(_rslt_ogg_corrupt_secondary_header);
						}
						i++;
					}
				}
			}
			/* no harm in not checking before adding more */
			oggDecode.sync_buffer = ogg_sync_buffer(&ogg.oy, oggDecode.sync_buffer_size);
			unsigned read_bytes = fread(oggDecode.sync_buffer, 1, oggDecode.sync_buffer_size, fileHandle);
			if(read_bytes == 0 && i < 2){
				return(_rslt_ogg_missing_vorbis_headers);
			}
			ogg_sync_wrote(&ogg.oy, read_bytes);
		}

		/* Throw the comments plus a few lines about the bitstream we're
		   decoding */
		{
			char **ptr = ogg.vc.user_comments;
			while(*ptr){
				/*
				fprintf(stderr, "%s\n", *ptr);
				*/
				if(!comment.empty()) {
					comment += "\n";
				}
				comment += *ptr;
				++ptr;
			}
			audioInfo.channels = ogg.vi.channels;
			audioInfo.sampleRate = ogg.vi.rate;
			audioInfo.bitsPerSample = 16;
			if(onlyGetAudioInfo) {
				return(_rslt_ok);
			}
			/*
			fprintf(stderr, "\nBitstream is %d channel, %ldHz\n", ogg.vi.channels, ogg.vi.rate);
			fprintf(stderr, "Encoded by: %s\n\n", ogg.vc.vendor);
			*/
		}

		int convsize = oggDecode.sync_buffer_size / ogg.vi.channels;
		oggDecode.conv_buffer = new FILE_LINE(0) ogg_int16_t[convsize];

		/* OK, got and parsed all three headers. Initialize the Vorbis
		   packet->PCM decoder. */
		if(vorbis_synthesis_init(&ogg.vd, &ogg.vi) == 0) { /* central decode state */
			vorbis_block_init(&ogg.vd, &ogg.vb);          /* local state for most of the decode
								so multiple block decodes can
								proceed in parallel. We could init
								multiple vorbis_block structures
								for vd here */

			/* The rest is just a straight decode loop until end of stream */
			while(!ogg.eos) {
				while(!ogg.eos) {
					int result = ogg_sync_pageout(&ogg.oy, &ogg.og);
					if(result == 0) break; /* need more data */
					if(result < 0){ /* missing or corrupt data at this page position */
						/*
						fprintf(stderr, "Corrupt or missing data in bitstream; "
							"continuing...\n");
						*/
					} else {
						ogg_stream_pagein(&ogg.os, &ogg.og); /* can safely ignore errors at
									       this point */
						while(1) {
							result=ogg_stream_packetout(&ogg.os, &ogg.op);

							if(result==0) break; /* need more data */
							if(result<0) { /* missing or corrupt data at this page position */
							  /* no reason to complain; already complained above */
							} else {
								/* we have a packet.  Decode it */
								float **pcm;
								int samples;

								if(vorbis_synthesis(&ogg.vb, &ogg.op) == 0) /* test for success! */
								  vorbis_synthesis_blockin(&ogg.vd, &ogg.vb);
								/*

								**pcm is a multichannel float vector.  In stereo, for
								example, pcm[0] is left, and pcm[1] is right.  samples is
								the size of each channel.  Convert the float values
								(-1.<=range<=1.) to whatever PCM format and write it out */

								while((samples = vorbis_synthesis_pcmout(&ogg.vd, &pcm)) > 0){
									int j;
									/*
									int clipflag = 0;
									*/
									int bout = (samples < convsize ? samples : convsize);

									/* convert floats to 16 bit signed ints (host order) and
									   interleave */
									for(i = 0; i < ogg.vi.channels; i++){
										ogg_int16_t *ptr = oggDecode.conv_buffer + i;
										float *mono=pcm[i];
										for(j = 0; j < bout; j++){
							    
											int val = floor(mono[j]*32767.f+.5f);
								  
											/* might as well guard against clipping */
											if(val > 32767){
												val = 32767;
												/*
												clipflag = 1;
												*/
											}
											if(val<-32768){
												val = -32768;
												/*
												clipflag = 1;
												*/
											}
											*ptr = val;
											ptr += ogg.vi.channels;
										}
									}

									/*
									if(clipflag)
										fprintf(stderr, "Clipping in frame %ld\n", (long)(ogg.vd.sequence));
									*/

									eResult rslt_write = write((u_char*)oggDecode.conv_buffer, 2 * ogg.vi.channels * bout);
									if(rslt_write != _rslt_ok) {
										return(rslt_write);
									}
									//fwrite(convbuffer ,2*ogg.vi.channels, bout, stdout);

									vorbis_synthesis_read(&ogg.vd, bout); /* tell libvorbis how
													    many samples we
													    actually consumed */
								}
							}
						}
						if(ogg_page_eos(&ogg.og)) ogg.eos = 1;
					}
				}
				if(!ogg.eos) {
					oggDecode.sync_buffer = ogg_sync_buffer(&ogg.oy, oggDecode.sync_buffer_size);
					unsigned read_bytes = fread(oggDecode.sync_buffer, 1, oggDecode.sync_buffer_size, fileHandle);
					ogg_sync_wrote(&ogg.oy, read_bytes);
					if(read_bytes == 0) ogg.eos = 1;
				}
			}

			/* ogg_page and ogg_packet structs always point to storage in
			   libvorbis.  They're never freed or manipulated directly */

			vorbis_block_clear(&ogg.vb);
			vorbis_dsp_clear(&ogg.vd);
		} else {
			/*
			fprintf(stderr,"Error: Corrupt header during playback initialization.\n");
			*/
		}

		/* clean up this logical bitstream; before exit we see if we're
		   followed by another [chained] */

		ogg_stream_clear(&ogg.os);
		vorbis_comment_clear(&ogg.vc);
		vorbis_info_clear(&ogg.vi);  /* must be called last */
	}
	
	eResult rslt_write = write(NULL, 0);
	if(rslt_write != _rslt_ok) {
		return(rslt_write);
	}

	return(_rslt_ok);
}


cAudioConvert::eResult cAudioConvert::writeOggHeader() {
	ogg.eos = 0;
	
	vorbis_info_init(&ogg.vi);

	if(vorbis_encode_init_vbr(&ogg.vi, audioInfo.channels, audioInfo.sampleRate, oggQuality)) {
		return(_rslt_ogg_failed_encode_initialization);
	}
	
	if(!comment.empty()) {
		vorbis_comment_init(&ogg.vc);
		vorbis_comment_add_tag(&ogg.vc, "ENCODER", comment.c_str());
	}

	/* set up the analysis state and auxiliary encoding storage */
	vorbis_analysis_init(&ogg.vd, &ogg.vi);
	vorbis_block_init(&ogg.vd, &ogg.vb);

	/* set up our packet->stream encoder */
	/* pick a random serial number; that way we can more likely build
	   chained streams just by concatenation */
	srand(time(NULL));
	ogg_stream_init(&ogg.os, rand());

	/* Vorbis streams begin with three headers; the initial header (with
	   most of the codec setup parameters) which is mandated by the Ogg
	   bitstream spec.  The second header holds any comment fields.  The
	   third header holds the bitstream codebook.  We merely need to
	   make the headers, then pass them to libvorbis one at a time;
	   libvorbis handles the additional Ogg bitstream constraints */

	ogg_packet header;
	ogg_packet header_comm;
	ogg_packet header_code;

	vorbis_analysis_headerout(&ogg.vd, &ogg.vc, &header, &header_comm, &header_code);
	ogg_stream_packetin(&ogg.os, &header); /* automatically placed in its own page */
	ogg_stream_packetin(&ogg.os, &header_comm);
	ogg_stream_packetin(&ogg.os, &header_code);

	/* This ensures the actual
	 * audio data will start on a new page, as per spec
	 */
	while(ogg_stream_flush(&ogg.os ,&ogg.og) != 0) {
		eResult rslt_write = write(ogg.og.header, ogg.og.header_len);
		if(rslt_write != _rslt_ok) {
			return(rslt_write);
		}
		rslt_write = write(ogg.og.body, ogg.og.body_len);
		if(rslt_write != _rslt_ok) {
			return(rslt_write);
		}
		/*
		fwrite(ogg.og.header, 1, ogg.og.header_len, stdout);
		fwrite(ogg.og.body, 1, ogg.og.body_len, stdout);
		*/
	}
	
	return(_rslt_ok);
}

cAudioConvert::eResult cAudioConvert::writeOggData(u_char *data, unsigned datalen) {
	/* expose the buffer to submit data */
	float **analysis_buffer = vorbis_analysis_buffer(&ogg.vd, datalen);

	/* uninterleave samples */
	signed char *_data = (signed char*)data;
	for(unsigned i = 0; i < datalen / (audioInfo.channels*2); i++){
		analysis_buffer[0][i] = ((_data[i*(audioInfo.channels*2)+1]<<8)|
					(0x00ff&(int)_data[i*(audioInfo.channels*2)]))/32768.f;
		if(audioInfo.channels > 1) {
			analysis_buffer[1][i] = ((_data[i*4+3]<<8)|
						(0x00ff&(int)_data[i*4+2]))/32768.f;
		}
	}

	/* tell the library how much we actually submitted */
	vorbis_analysis_wrote(&ogg.vd, datalen / (audioInfo.channels*2));
	
	return(_writeOgg());
}

cAudioConvert::eResult cAudioConvert::writeOggEnd() {
	vorbis_analysis_wrote(&ogg.vd, 0);
	return(_writeOgg());
}

cAudioConvert::eResult cAudioConvert::_writeOgg() {
	/* vorbis does some data preanalysis, then divvies up blocks for
	   more involved (potentially parallel) processing.  Get a single
	   block for encoding now */
	while(vorbis_analysis_blockout(&ogg.vd, &ogg.vb) == 1) {

		/* analysis, assume we want to use bitrate management */
		vorbis_analysis(&ogg.vb, NULL);
		vorbis_bitrate_addblock(&ogg.vb);

		while(vorbis_bitrate_flushpacket(&ogg.vd, &ogg.op)) {

			/* weld the packet into the bitstream */
			ogg_stream_packetin(&ogg.os, &ogg.op);

			/* write out pages (if any) */
			while(ogg_stream_pageout(&ogg.os, &ogg.og) != 0) {
				eResult rslt_write = write(ogg.og.header, ogg.og.header_len);
				if(rslt_write != _rslt_ok) {
					return(rslt_write);
				}
				rslt_write = write(ogg.og.body, ogg.og.body_len);
				if(rslt_write != _rslt_ok) {
					return(rslt_write);
				}
				/*
				fwrite(ogg.og.header, 1, ogg.og.header_len, stdout);
				fwrite(ogg.og.body, 1, ogg.og.body_len, stdout);
				*/

				/* this could be set above, but for illustrative purposes, I do
				   it here (to show that vorbis does know where the stream ends) */

				if(ogg_page_eos(&ogg.og)) break;;
			}
		}
	}
	return(_rslt_ok);
}

#if HAVE_LIBLAME && HAVE_LIBMPG123
cAudioConvert::eResult cAudioConvert::readMp3() {
	if(mpg123_init() != MPG123_OK) {
		return(_rslt_mpg123_failed_init);
	}
	int error;
	mp3.mpg123 = mpg123_new(NULL, &error);
	if(mp3.mpg123 == NULL) {
		return(_rslt_mpg123_failed_create_handle);
	}
	if(mpg123_open(mp3.mpg123, fileName.c_str()) != MPG123_OK) {
		return(_rslt_mpg123_failed_open);
	}
	long sampleRate;
	int channels, encoding;
	if(mpg123_getformat(mp3.mpg123, &sampleRate, &channels, &encoding) != MPG123_OK) {
		return(_rslt_mpg123_failed_get_audioinfo);
	}
	audioInfo.channels = channels;
	audioInfo.sampleRate = sampleRate;
	audioInfo.bitsPerSample = 16;
	if(onlyGetAudioInfo) {
		return(_rslt_ok);
	}
	mp3.buffer_size = mpg123_outblock(mp3.mpg123);
	mp3.buffer = new FILE_LINE(0) u_char[mp3.buffer_size];
	size_t size = 0;
	while(mpg123_read(mp3.mpg123, mp3.buffer, mp3.buffer_size, &size) == MPG123_OK) {
		write(mp3.buffer, size);
	}
	eResult rslt_write = write(NULL, 0);
	if(rslt_write != _rslt_ok) {
		return(rslt_write);
	}
	return(_rslt_ok);
}

cAudioConvert::eResult cAudioConvert::initMp3() {
	mp3.lame = lame_init();
	if(!mp3.lame) {
		return(_rslt_mp3_failed_create_lame);
	}
	lame_set_in_samplerate(mp3.lame, audioInfo.sampleRate);
	lame_set_num_channels(mp3.lame, audioInfo.channels);
	lame_set_VBR(mp3.lame, vbr_default);
	lame_set_quality(mp3.lame, mp3Quality);
	if(lame_init_params(mp3.lame) < 0) {
		mp3.destroy();
		return(_rslt_mp3_failed_init_params);
	}
        return(_rslt_ok);
}

cAudioConvert::eResult cAudioConvert::writeMp3Data(u_char *data, unsigned datalen) {
	int size;
	unsigned samples = datalen / (audioInfo.bitsPerSample / 8) / audioInfo.channels;
	mp3.set_buffer(datalen, &audioInfo);
	if(audioInfo.channels == 2) {
		size = lame_encode_buffer_interleaved(mp3.lame, (short int*)data, samples, mp3.buffer, mp3.buffer_size);
        } else {
                size = lame_encode_buffer(mp3.lame, (short int*)data, NULL, samples, mp3.buffer, mp3.buffer_size);
        }
        if(size < 0) {
		return(_rslt_mp3_failed_encode);
	}
	if(size > 0) {
		write(mp3.buffer, size);
	}
	return(_rslt_ok);
}

cAudioConvert::eResult cAudioConvert::writeMp3End() {
	int size = lame_encode_flush(mp3.lame, mp3.buffer, mp3.buffer_size);
	if(size < 0) {
		return(_rslt_mp3_failed_encode);
	}
	if(size > 0) {
		write(mp3.buffer, size);
	}
	return(_rslt_ok);
}
#endif

cAudioConvert::eResult cAudioConvert::write(u_char *data, unsigned datalen) {
	if(destAudio) {
		eResult rslt = _rslt_ok;
		if(datalen) {
			if(!headerIsWrited) {
				destAudio->audioInfo = audioInfo;
				switch(destAudio->formatType) {
				case _format_raw:
					break;
				case _format_wav:
					rslt = destAudio->writeWavHeader();
					break;
				case _format_ogg:
					rslt = destAudio->writeOggHeader();
					break;
				#if HAVE_LIBLAME && HAVE_LIBMPG123
				case _format_mp3:
					rslt = destAudio->initMp3();
					break;
				#endif
				}
				headerIsWrited = true;
			}
			if(rslt == _rslt_ok) {
				switch(destAudio->formatType) {
				case _format_raw:
					rslt = destAudio->write(data, datalen);
					break;
				case _format_wav:
					rslt = destAudio->writeWavData(data, datalen);
					break;
				case _format_ogg:
					rslt = destAudio->writeOggData(data, datalen);
					break;
				#if HAVE_LIBLAME && HAVE_LIBMPG123
				case _format_mp3:
					rslt = destAudio->writeMp3Data(data, datalen);
					break;
				#endif
				}
				headerIsWrited = true;
			}
		} else {
			switch(destAudio->formatType) {
			case _format_raw:
				break;
			case _format_wav:
				rslt = destAudio->writeWavEnd();
				break;
			case _format_ogg:
				rslt = destAudio->writeOggEnd();
				break;
			#if HAVE_LIBLAME && HAVE_LIBMPG123
			case _format_mp3:
				rslt = destAudio->writeMp3End();
				break;
			#endif
			}
		}
	}
	if(srcDstType == _dst && !fileName.empty()) {
		if(!open_for_write()) {
			return(_rslt_open_for_write_failed);
		}
		if(fileHandle) {
			return(fwrite(data, 1, datalen, fileHandle) == datalen ?
				_rslt_ok :
				_rslt_write_failed);
		}
	}
	return(_rslt_ok);
}

bool cAudioConvert::open() {
	if(!fileHandle) {
		fileHandle = fopen(fileName.c_str(), "r");
		if(!fileHandle) {
			return(false);
		}
	} else {
		fseek(fileHandle, 0, SEEK_SET);
	}
	return(true);
}

bool cAudioConvert::open_for_write() {
	if(!fileHandle) {
		if(!destInSpool) {
			fileHandle = fopen(fileName.c_str(), "w");
			if(!fileHandle) {
				return(false);
			}
		} else {
			for(int passOpen = 0; passOpen < 2; passOpen++) {
				if(passOpen == 1) {
					char *pointToLastDirSeparator = (char*)strrchr(fileName.c_str(), '/');
					if(pointToLastDirSeparator) {
						*pointToLastDirSeparator = 0;
						spooldir_mkdir(fileName.c_str());
						*pointToLastDirSeparator = '/';
					} else {
						break;
					}
				}
				fileHandle = fopen(fileName.c_str(), "w");
				if(fileHandle) {
					spooldir_file_chmod_own(fileHandle);
					break;
				}
				if(write_buffer) {
					delete write_buffer;
				}
				unsigned write_buffer_size = 32768;
				write_buffer = new u_char[write_buffer_size];
				setvbuf(fileHandle, (char*)write_buffer, _IOFBF, write_buffer_size);
			}
		}
	}
	return(true);
}

void cAudioConvert::close() {
	if(fileHandle) {
		fclose(fileHandle);
		fileHandle = NULL;
	}
}

void cAudioConvert::linear_resample(int16_t* input, int16_t* output, int input_len, double ratio, int channels) {
	int output_len = (int)(input_len * ratio) / channels;
	for(int ch = 0; ch < channels; ++ch) {
		if(ratio >= 1) {
			for(int i = 0; i < output_len; ++i) {
				double src_index = i / ratio;
				int index = (int)src_index;
				double frac = src_index - index;
				if(index + 1 < input_len / channels) {
					output[i * channels + ch] = (int16_t)((1.0 - frac) * input[(index * channels) + ch] + frac * input[((index + 1) * channels) + ch]);
				} else {
					output[i * channels + ch] = input[(index * channels) + ch];
				}
			}
		} else {
			double inv_ratio = 1 / ratio;
			for(int i = 0; i < output_len; ++i) {
				double src_index_start = i * inv_ratio;
				double src_index_end = (i + 1) * inv_ratio;
				int index_start = (int)src_index_start;
				int index_end = (int)src_index_end;
				double sum = 0.0;
				int count = 0;
				for(int j = index_start; j < index_end && j < input_len / channels; ++j) {
					sum += input[(j * channels) + ch];
					count++;
				}
				if(count > 0) {
					output[i * channels + ch] = (int16_t)(sum / count);
				} else {
					output[i * channels + ch] = input[(index_start * channels) + ch];
				}
			}
		}
	}
}

const char *cAudioConvert::getExtension(eFormatType format) {
	return(format == _format_raw ? "raw" :
	       format == _format_wav ? "wav" :
	       format == _format_ogg ? "ogg" :
	       #if HAVE_LIBLAME && HAVE_LIBMPG123
	       format == _format_mp3 ? "mp3" :
	       #endif
	       "unknow");
}

string cAudioConvert::getRsltStr(eResult rslt) {
	switch(rslt) {
	case _rslt_ok: return("ok");
	case _rslt_write_failed: return("failed write");
	case _rslt_open_for_read_failed: return("failed open for read");
	case _rslt_open_for_write_failed: return("failed open for write");
	case _rslt_wav_read_header_failed: return("failed read wav header");
	case _rslt_wav_bad_header: return("bad wav header");
	case _rslt_ogg_bad_ogg_file: return("bad ogg file");
	case _rslt_ogg_bad_bitstream: return("bad ogg bitstrean");
	case _rslt_ogg_bad_first_page: return("bad ogg first page");
	case _rslt_ogg_bad_initial_header_packet: return("bad ogg initial header");
	case _rslt_ogg_missing_vorbis_audiodata: return("missing vorbis audiodata");
	case _rslt_ogg_corrupt_secondary_header: return("corrupt ogg secondary header");
	case _rslt_ogg_missing_vorbis_headers: return("missing vorbis header");
	case _rslt_ogg_failed_encode_initialization: return("failed ogg encode initialization");
	case _rslt_mp3_failed_create_lame: return("failed mp3 create lame");
	case _rslt_mp3_failed_init_params: return("failed mp3 init params");
	case _rslt_mp3_failed_encode: return("failed mp3 encode");
	case _rslt_mpg123_failed_init: return("failed mpg123 init");
	case _rslt_mpg123_failed_create_handle: return("failed mpg123 create handle");
	case _rslt_mpg123_failed_open: return("failed mpg123 create open");
	case _rslt_mpg123_failed_get_audioinfo: return("failed mpg123 get audio info");
	case _rslt_failed_libsamplerate_init: return("failed libsamplerate init");
	case _rslt_failed_libsamplerate_process: return("failed libsamplerate process");
	case _rslt_unknown_format: return("unknown format");
	case _rslt_no_library_needed: return("no library needed");
	}
	return("");
}

void cAudioConvert::test() {
 
	/*
	{
	cAudioConvert info;
	info.fileName = "/home/jumbox/Plocha/ac/1781060762.ogg";
	info.getAudioInfo();
	cout << info.jsonAudioInfo() <<  endl;
	}
 
	{
	cAudioConvert info;
	info.fileName = "/home/jumbox/Plocha/ac/1781060762.wav";
	info.getAudioInfo();
	cout << info.jsonAudioInfo() <<  endl;
	}
	
	{
	cAudioConvert src;
	src.fileName = "/home/jumbox/Plocha/ac/1781060762.ogg";
	cAudioConvert dst;
	dst.formatType = _format_wav;
	dst.srcDstType = _dst;
	dst.fileName = "/home/jumbox/Plocha/ac/1781060762-2.wav";
	src.destAudio = &dst;
	cout << "1: " << src.readOgg() << endl;
	}
	
	{
	cAudioConvert src;
	src.fileName = "/home/jumbox/Plocha/ac/1781060762-2.wav";
	cAudioConvert dst;
	dst.formatType = _format_ogg;
	dst.srcDstType = _dst;
	dst.fileName = "/home/jumbox/Plocha/ac/1781060762-2.ogg";
	src.destAudio = &dst;
	cout << "2: " << src.readWav() << endl;
	}
	
	{
	cAudioConvert src;
	src.fileName = "/home/jumbox/Plocha/ac/1781060762-2.wav";
	cAudioConvert dst;
	dst.formatType = _format_raw;
	dst.srcDstType = _dst;
	dst.fileName = "/home/jumbox/Plocha/ac/1781060762-2.raw";
	src.destAudio = &dst;
	cout << "3: " << src.readWav() << endl;
	}
	
	{
	cAudioConvert src;
	src.fileName = "/home/jumbox/Plocha/ac/1781060762-2.raw";
	cAudioConvert dst;
	dst.formatType = _format_wav;
	dst.srcDstType = _dst;
	dst.fileName = "/home/jumbox/Plocha/ac/1781060762-3.wav";
	src.destAudio = &dst;
	sAudioInfo ai;
	ai.sampleRate = 8000;
	ai.channels = 2;
	ai.bitsPerSample = 16;
	cout << "4: " << src.readRaw(&ai) << endl;
	}
	
	{
	cAudioConvert src;
	src.fileName = "/home/jumbox/Plocha/ac/1781060762-2.raw";
	cAudioConvert dst;
	dst.formatType = _format_ogg;
	dst.srcDstType = _dst;
	dst.fileName = "/home/jumbox/Plocha/ac/1781060762-3.ogg";
	src.destAudio = &dst;
	sAudioInfo ai;
	ai.sampleRate = 8000;
	ai.channels = 2;
	ai.bitsPerSample = 16;
	cout << "5: " << src.readRaw(&ai) << endl;
	}
	
	{
	cAudioConvert src;
	src.fileName = "/home/jumbox/Plocha/ac/test.raw";
	cAudioConvert dst;
	dst.formatType = _format_wav;
	dst.srcDstType = _dst;
	dst.fileName = "/home/jumbox/Plocha/ac/test.wav";
	src.destAudio = &dst;
	sAudioInfo ai;
	ai.sampleRate = 8000;
	ai.channels = 2;
	ai.bitsPerSample = 16;
	cout << "6: " << src.readRaw(&ai) << endl;
	}
	*/
	
	{
	cAudioConvert src;
	src.fileName = "/home/jumbox/Plocha/ac/1781060762.wav";
	cAudioConvert dst;
	dst.formatType = _format_ogg;
	dst.srcDstType = _dst;
	dst.fileName = "/home/jumbox/Plocha/ac/1781060762.ogg";
	src.destAudio = &dst;
	cout << "1: " << src.readWav() << endl;
	}
	
	#if HAVE_LIBLAME && HAVE_LIBMPG123
	{
	cAudioConvert src;
	src.fileName = "/home/jumbox/Plocha/ac/1781060762.wav";
	cAudioConvert dst;
	dst.formatType = _format_mp3;
	dst.srcDstType = _dst;
	dst.fileName = "/home/jumbox/Plocha/ac/1781060762.mp3";
	src.destAudio = &dst;
	cout << "2: " << src.readWav() << endl;
	}
	#endif
	
	#if HAVE_LIBLAME && HAVE_LIBMPG123
	{
	cAudioConvert src;
	src.fileName = "/home/jumbox/Plocha/ac/1781060762.mp3";
	cAudioConvert dst;
	dst.formatType = _format_wav;
	dst.srcDstType = _dst;
	dst.fileName = "/home/jumbox/Plocha/ac/1781060762-2.wav";
	src.destAudio = &dst;
	cout << "2: " << src.readMp3() << endl;
	}
	#endif
	
	{
	cAudioConvert info;
	info.fileName = "/home/jumbox/Plocha/ac/1781060762.wav";
	info.getAudioInfo();
	cout << info.jsonAudioInfo() <<  endl;
	}
	
	{
	cAudioConvert info;
	info.fileName = "/home/jumbox/Plocha/ac/1781060762.ogg";
	info.getAudioInfo();
	cout << info.jsonAudioInfo() <<  endl;
	}
	
	{
	cAudioConvert info;
	info.fileName = "/home/jumbox/Plocha/ac/1781060762.mp3";
	info.getAudioInfo();
	cout << info.jsonAudioInfo() <<  endl;
	}
}

bool ac_file_mix(char *src1, char *src2, char *dest, cAudioConvert::eFormatType format,
		 unsigned sampleRate, bool stereo,  bool swap,
		 double quality, bool destInSpool) {
	FILE *f_src[2] = { NULL, NULL };
	f_src[0] = fopen(src1, "r");
	if(!f_src[0]) {
		syslog(LOG_ERR,"File [%s] cannot be opened for read.\n", src1);
		return(false);
	}
	if(src2 != NULL) {
		f_src[1] = fopen(src2, "r");
		if(!f_src[1]) {
			fclose(f_src[0]);
			syslog(LOG_ERR,"File [%s] cannot be opened for read.\n", src2);
			return(false);
		}
	}
	
	cAudioConvert ac;
	ac.audioInfo.sampleRate = sampleRate;
	ac.audioInfo.channels = stereo ? 2 : 1;
	ac.audioInfo.bitsPerSample = 16;
	cAudioConvert ac_dest;
	ac_dest.formatType = format;
	ac_dest.srcDstType = cAudioConvert::_dst;
	ac_dest.fileName = dest;
	ac_dest.destInSpool = destInSpool;
	if(format == cAudioConvert::_format_ogg) {
		ac_dest.oggQuality = quality;
	}
	#if HAVE_LIBLAME && HAVE_LIBMPG123
	else if(format == cAudioConvert::_format_mp3) {
		ac_dest.mp3Quality = quality;
	}
	#endif
	ac.destAudio = &ac_dest;
	
	unsigned buff_length = 1024 * 1024;
	char *buff[2] = { NULL, NULL };
	unsigned read_length[2] = { 0, 0 };
	unsigned buff_pos[2] = { 0, 0 };
	char *p[2] = { NULL, NULL };
	for(unsigned i = 0; i < 2; i++) {
		if(f_src[i]) {
			buff[i] = new FILE_LINE(0) char[buff_length];
			read_length[i] = fread(buff[i], 1, buff_length, f_src[i]);
			if(read_length[i]) {
				p[i] = buff[i]; 
			}
		}
	}
	unsigned write_buffer_size = 1024 * 10;
	unsigned write_buffer_pos = 0;
	u_char *write_buffer = new FILE_LINE(0) u_char[write_buffer_size + 128];
	short int zero = 0;
	cAudioConvert::eResult write_rslt = cAudioConvert::_rslt_ok;
	while((p[0] || p[1]) && write_rslt == cAudioConvert::_rslt_ok) {
		if(p[0] && p[1]) {
			if(stereo) {
				if(swap) {
					memcpy(write_buffer + write_buffer_pos, p[1], 2); write_buffer_pos += 2;
					memcpy(write_buffer + write_buffer_pos, p[0], 2); write_buffer_pos += 2;
				} else {
					memcpy(write_buffer + write_buffer_pos, p[0], 2); write_buffer_pos += 2;
					memcpy(write_buffer + write_buffer_pos, p[1], 2); write_buffer_pos += 2;
				}
			} else {
				slinear_saturated_add((short int*)p[0], (short int*)p[1]);
				memcpy(write_buffer + write_buffer_pos, p[0], 2); write_buffer_pos += 2;
			}
			buff_pos[0] += 2;
			buff_pos[1] += 2;
		} else if(p[0]) {
			if(swap) {
				if(stereo) {
					memcpy(write_buffer + write_buffer_pos, &zero, 2); write_buffer_pos += 2;
				}
				memcpy(write_buffer + write_buffer_pos, p[0], 2); write_buffer_pos += 2;
			} else {
				memcpy(write_buffer + write_buffer_pos, p[0], 2); write_buffer_pos += 2;
				if(stereo) {
					memcpy(write_buffer + write_buffer_pos, &zero, 2); write_buffer_pos += 2;
				}
			}
			buff_pos[0] += 2;
		} else if(p[1]) {
			if(swap) {
				memcpy(write_buffer + write_buffer_pos, p[1], 2); write_buffer_pos += 2;
				if(stereo) {
					memcpy(write_buffer + write_buffer_pos, &zero, 2); write_buffer_pos += 2;
				}
			} else {
				if(stereo) {
					memcpy(write_buffer + write_buffer_pos, &zero, 2); write_buffer_pos += 2;
				}
				memcpy(write_buffer + write_buffer_pos, p[1], 2); write_buffer_pos += 2;
			}
			buff_pos[1] += 2;
		}
		for(unsigned i = 0; i < 2; i++) {
			if(read_length[i] > 0 && buff_pos[i] >= read_length[i]) {
				read_length[i] = fread(buff[i], 1, buff_length, f_src[i]);
				buff_pos[i] = 0;
			}
			if(read_length[i] > 0) {
				p[i] = buff[i] + buff_pos[i];
			} else {
				p[i] = NULL;
			}
		}
		if(write_buffer_pos >= write_buffer_size) {
			write_rslt = ac.write(write_buffer, write_buffer_pos);
			write_buffer_pos = 0;
		}
	}
	if(write_buffer_pos > 0 && write_rslt == cAudioConvert::_rslt_ok) {
		write_rslt = ac.write(write_buffer, write_buffer_pos);
		write_buffer_pos = 0;
	}
	if(write_rslt == cAudioConvert::_rslt_ok) {
		write_rslt = ac.write(NULL, 0);
	}
	
	if(write_rslt != cAudioConvert::_rslt_ok) {
		syslog(LOG_ERR, "Failed create audio file [%s] : %s\n", dest, cAudioConvert::getRsltStr(write_rslt).c_str());
	}
	
	delete [] write_buffer;
	for(unsigned i = 0; i < 2; i++) {
		if(f_src[i]) {
			fclose(f_src[i]);
		}
		if(buff[i]) {
			delete [] buff[i];
		}
	}

	return(write_rslt == cAudioConvert::_rslt_ok);
}

void slinear_saturated_add(short *input, short *value) {
	int res;

        res = (int) *input + *value;
        if (res > 32767)
                *input = 32767;
        else if (res < -32767)
                *input = -32767;
        else
                *input = (short) res;
}
