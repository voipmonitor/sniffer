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
	FILE *f_in[2] = { NULL, NULL };
	FILE *f_out = NULL;

	/* combine two wavs */
	f_in[0] = fopen(in1, "r");
	if(!f_in[0]) {
		syslog(LOG_ERR,"File [%s] cannot be opened for read.\n", in1);
		return 1;
	}
	if(in2 != NULL) {
		f_in[1] = fopen(in2, "r");
		if(!f_in[1]) {
			fclose(f_in[0]);
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
		if(f_in[0] != NULL)
			fclose(f_in[0]);
		if(f_in[1] != NULL)
			fclose(f_in[1]);
		syslog(LOG_ERR,"File [%s] cannot be opened for write.\n", out);
		return 1;
	}
	char f_out_buffer[32768];
	setvbuf(f_out, f_out_buffer, _IOFBF, 32768);

	wav_write_header(f_out, samplerate, stereo);
	
	unsigned buff_length = 1024 * 1024;
	char *buff[2] = { NULL, NULL };
	unsigned read_length[2] = { 0, 0 };
	unsigned buff_pos[2] = { 0, 0 };
	char *p[2] = { NULL, NULL };
	for (unsigned i = 0; i < 2; i++) {
		if (f_in[i]) {
			buff[i] = new FILE_LINE(0) char[buff_length];
			read_length[i] = fread(buff[i], 1, buff_length, f_in[i]);
			if (read_length[i]) {
				p[i] = buff[i]; 
			}
		}
	}
	
	short int zero = 0;
	while (p[0] || p[1]) {
		if (p[0] && p[1]) {
			if(stereo) {
			/* stereo */
				if(swap) {
					fwrite(p[1], 2, 1, f_out);
					fwrite(p[0], 2, 1, f_out);
				} else {
					fwrite(p[0], 2, 1, f_out);
					fwrite(p[1], 2, 1, f_out);
				}
			} else {
			/* mono */
				slinear_saturated_add((short int*)p[0], (short int*)p[1]);
				fwrite(p[0], 2, 1, f_out);
			}
			buff_pos[0] += 2;
			buff_pos[1] += 2;
		} else if (p[0]) {
			if(swap) {
				if(stereo) {
					fwrite(&zero, 2, 1, f_out);
				}
				fwrite(p[0], 2, 1, f_out);
			} else {
				fwrite(p[0], 2, 1, f_out);
				if(stereo) {
					fwrite(&zero, 2, 1, f_out);
				}
			}
			buff_pos[0] += 2;
		} else if (p[1]) {
			if(swap) {
				fwrite(p[1], 2, 1, f_out);
				if(stereo) {
					fwrite(&zero, 2, 1, f_out);
				}
			} else {
				if(stereo) {
					fwrite(&zero, 2, 1, f_out);
				}
				fwrite(p[1], 2, 1, f_out);
			}
			buff_pos[1] += 2;
		}
		for (unsigned i = 0; i < 2; i++) {
			if (read_length[i] > 0 && buff_pos[i] >= read_length[i]) {
				read_length[i] = fread(buff[i], 1, buff_length, f_in[i]);
				buff_pos[i] = 0;
			}
			if (read_length[i] > 0) {
				p[i] = buff[i] + buff_pos[i];
			} else {
				p[i] = NULL;
			}
		}
	}

	wav_update_header(f_out);
	fclose(f_out);
	
	for(unsigned i = 0; i < 2; i++) {
		if(f_in[i]) {
			fclose(f_in[i]);
		}
		if(buff[i]) {
			delete [] buff[i];
		}
	}

	return 0;
}


