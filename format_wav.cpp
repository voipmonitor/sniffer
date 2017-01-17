#include <sys/stat.h>

#include "format_wav.h"
#include "format_slinear.h"
#include "tools.h"

// sample rate 8000, 12000, 16000, 24000
int wav_write_header(FILE *f, int samplerate, int stereo)
{
	unsigned int hz=htoll(samplerate);
	unsigned int bhz = htoll(samplerate*2*(stereo ? 2 : 1)); // 2 bytes per sample and 2 channels
	unsigned int hs = htoll(16);	// 16bit
	unsigned short fmt = htols(1);
	unsigned short chans = htols((stereo ? 2 : 1));
	unsigned short bysam = htols(2*(stereo ? 2 : 1));
	unsigned short bisam = htols(16);
	unsigned int size = htoll(0);
	/* Write a wav header, ignoring sizes which will be filled in later */
	fseek(f,0,SEEK_SET);
	if (fwrite("RIFF", 1, 4, f) != 4) {
		//log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite(&size, 1, 4, f) != 4) {
		//log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite("WAVEfmt ", 1, 8, f) != 8) {
		//log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite(&hs, 1, 4, f) != 4) {
		//log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite(&fmt, 1, 2, f) != 2) {
		//log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite(&chans, 1, 2, f) != 2) {
		//log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite(&hz, 1, 4, f) != 4) {
		///log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite(&bhz, 1, 4, f) != 4) {
		//log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite(&bysam, 1, 2, f) != 2) {
		//log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite(&bisam, 1, 2, f) != 2) {
		//log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite("data", 1, 4, f) != 4) {
		//log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite(&size, 1, 4, f) != 4) {
		//log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	return 0;
}

int wav_update_header(FILE *f)
{
	off_t cur,end;
	int datalen,filelen,bytes;

	cur = ftello(f);
	fseek(f, 0, SEEK_END);
	end = ftello(f);
	/* data starts 44 bytes in */
	bytes = end - 44;
	datalen = htoll(bytes);
	/* chunk size is bytes of data plus 36 bytes of header */
	filelen = htoll(36 + bytes);

	if (cur < 0) {
		//log(LOG_WARNING, "Unable to find our position\n");
		return -1;
	}
	if (fseek(f, 4, SEEK_SET)) {
		//log(LOG_WARNING, "Unable to set our position\n");
		return -1;
	}
	if (fwrite(&filelen, 1, 4, f) != 4) {
		//log(LOG_WARNING, "Unable to set write file size\n");
		return -1;
	}
	if (fseek(f, 40, SEEK_SET)) {
		//log(LOG_WARNING, "Unable to set our position\n");
		return -1;
	}
	if (fwrite(&datalen, 1, 4, f) != 4) {
		//log(LOG_WARNING, "Unable to set write datalen\n");
		return -1;
	}
	if (fseeko(f, cur, SEEK_SET)) {
		//log(LOG_WARNING, "Unable to return to position\n");
		return -1;
	}
	return 0;
}

int wav_mix(char *in1, char *in2, char *out, int samplerate, int swap, int stereo) {
	FILE *f_in1 = NULL;
	FILE *f_in2 = NULL;
	FILE *f_out = NULL;

	char *bitstream_buf1 = NULL;
	char *bitstream_buf2 = NULL;
	char *p1;
	char *f1;
	char *p2;
	char *f2;
	short int zero = 0;
	long file_size1;
	long file_size2 = 0;

	/* combine two wavs */
	f_in1 = fopen(in1, "r");
	if(!f_in1) {
		syslog(LOG_ERR,"File [%s] cannot be opened for read.\n", in1);
		return 1;
	}
	if(in2 != NULL) {
		f_in2 = fopen(in2, "r");
		if(!f_in2) {
			fclose(f_in1);
			syslog(LOG_ERR,"File [%s] cannot be opened for read.\n", in2);
			return 1;
		}
	}
	for(int passOpen = 0; passOpen < 2; passOpen++) {
		if(passOpen == 1) {
			char *pointToLastDirSeparator = strrchr(out, '/');
			if(pointToLastDirSeparator) {
				*pointToLastDirSeparator = 0;
				spooldir_mkdir(out);
				*pointToLastDirSeparator = '/';
			} else {
				break;
			}
		}
		f_out = fopen(out, "w");
		if(f_out) {
			spooldir_file_chmod_own(f_out);
			break;
		}
	}
	if(!f_out) {
		if(f_in1 != NULL)
			fclose(f_in1);
		if(f_in2 != NULL)
			fclose(f_in2);
		syslog(LOG_ERR,"File [%s] cannot be opened for write.\n", out);
		return 1;
	}
	char f_out_buffer[32768];
	setvbuf(f_out, f_out_buffer, _IOFBF, 32768);

	wav_write_header(f_out, samplerate, stereo);

	fseek(f_in1, 0, SEEK_END);
	file_size1 = ftell(f_in1);
	fseek(f_in1, 0, SEEK_SET);

	if(in2 != NULL) {
		fseek(f_in2, 0, SEEK_END);
		file_size2 = ftell(f_in2);
		fseek(f_in2, 0, SEEK_SET);
	}

	bitstream_buf1 = new FILE_LINE(6001) char[file_size1];
	if(!bitstream_buf1) {
		if(f_in1 != NULL)
			fclose(f_in1);
		if(f_in2 != NULL)
			fclose(f_in2);
		if(f_out != NULL)
			fclose(f_out);
		syslog(LOG_ERR,"Cannot malloc bitsream_buf1[%ld]", file_size1);
		return 1;
	}

	if(in2 != NULL) {
		bitstream_buf2 = new FILE_LINE(6002) char[file_size2];
		if(!bitstream_buf2) {
			fclose(f_in1);
			fclose(f_in2);
			fclose(f_out);
			delete [] bitstream_buf1;
			syslog(LOG_ERR,"Cannot malloc bitsream_buf2[%ld]", file_size1);
			return 1;
		}
	}
	fread(bitstream_buf1, file_size1, 1, f_in1);
	p1 = bitstream_buf1;
	f1 = bitstream_buf1 + file_size1;

	if(in2 != NULL) {
		fread(bitstream_buf2, file_size2, 1, f_in2);
		p2 = bitstream_buf2;
		f2 = bitstream_buf2 + file_size2;
	} else {
		p2 = f2 = 0;
	}

	while(p1 < f1 || p2 < f2 ) {
		if(p1 < f1 && p2 < f2) {
			if(stereo) {
			/* stereo */
				if(swap) {
					fwrite(p2, 2, 1, f_out);
					fwrite(p1, 2, 1, f_out);
				} else {
					fwrite(p1, 2, 1, f_out);
					fwrite(p2, 2, 1, f_out);
				}
			} else {
			/* mono */
				slinear_saturated_add((short int*)p1, (short int*)p2);
				fwrite(p1, 2, 1, f_out);
			}
			p1 += 2;
			p2 += 2;
		} else if ( p1 < f1 ) {
			if(swap) {
				if(stereo) {
					fwrite(&zero, 2, 1, f_out);
				}
				fwrite(p1, 2, 1, f_out);
			} else {
				fwrite(p1, 2, 1, f_out);
				if(stereo) {
					fwrite(&zero, 2, 1, f_out);
				}
			}
			p1 += 2;
		} else if ( p2 < f2 ) {
			if(swap) {
				fwrite(p2, 2, 1, f_out);
				if(stereo) {
					fwrite(&zero, 2, 1, f_out);
				}
			} else {
				if(stereo) {
					fwrite(&zero, 2, 1, f_out);
				}
				fwrite(p2, 2, 1, f_out);
			}
			p2 += 2;
		}
	}

	wav_update_header(f_out);
	if(bitstream_buf1)
		delete [] bitstream_buf1;
	if(bitstream_buf2)
		delete [] bitstream_buf2;
	fclose(f_out);
	fclose(f_in1);
	if(f_in2) fclose(f_in2);

	return 0;
}


