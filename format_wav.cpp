#include "format_wav.h"

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

int wav_write_header(FILE *f)
{
				unsigned int hz=htoll(8000);
				unsigned int bhz = htoll(16000);
				unsigned int hs = htoll(16);
				unsigned short fmt = htols(1);
				unsigned short chans = htols(1);
				unsigned short bysam = htols(2);
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
