/*#include "format_wav.h"*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>

#include <vorbis/codec.h>
#include <vorbis/vorbisenc.h>

#include "format_slinear.h"
#include "format_ogg.h"
#include "tools.h"

int ogg_header(FILE *f, struct vorbis_desc *tmp, int stereo, int samplerate, float quality)
{
        ogg_packet header;
        ogg_packet header_comm;
        ogg_packet header_code;

        vorbis_info_init(&tmp->vi);

	//quality 0.4 
        if (vorbis_encode_init_vbr(&tmp->vi, (stereo ? 2 : 1), samplerate, quality)) {
                syslog(LOG_ERR, "Unable to initialize Vorbis encoder!\n");
                return -1;
        }

        vorbis_comment_init(&tmp->vc);
        vorbis_comment_add_tag(&tmp->vc, "ENCODER", "voipmonitor.org");
/*
        if (comment)
                vorbis_comment_add_tag(&tmp->vc, "COMMENT", (char *) comment);
*/

        vorbis_analysis_init(&tmp->vd, &tmp->vi);
        vorbis_block_init(&tmp->vd, &tmp->vb);

        ogg_stream_init(&tmp->os, random());

        vorbis_analysis_headerout(&tmp->vd, &tmp->vc, &header, &header_comm,
                                  &header_code);
        ogg_stream_packetin(&tmp->os, &header);
        ogg_stream_packetin(&tmp->os, &header_comm);
        ogg_stream_packetin(&tmp->os, &header_code);

	tmp->eos = 0;
        while (!tmp->eos) {
                if (ogg_stream_flush(&tmp->os, &tmp->og) == 0)
                        break;
                if (!fwrite(tmp->og.header, 1, tmp->og.header_len, f)) {
                        syslog(LOG_ERR, "fwrite() failed: %s\n", strerror(errno));
                }
                if (!fwrite(tmp->og.body, 1, tmp->og.body_len, f)) {
                        syslog(LOG_ERR, "fwrite() failed: %s\n", strerror(errno));
                }
                if (ogg_page_eos(&tmp->og))
                        tmp->eos = 1;
        }

        return 0;
}

int ogg_header_live(std::queue <char> *spybuffer, struct vorbis_desc *tmp)
{
        ogg_packet header;
        ogg_packet header_comm;
        ogg_packet header_code;

        vorbis_info_init(&tmp->vi);

        //if (vorbis_encode_init_vbr(&tmp->vi, 1, 8000, 0.4)) {
//        if (vorbis_encode_init_vbr(&tmp->vi, 1, 48000, 1.1)) {
//        if (vorbis_encode_init(&tmp->vi, 1, 8000, 64000, 32000, -1)) {
        //if (vorbis_encode_init(&tmp->vi, 1, 48000, 96000, 128000, 160000)) {
        if (vorbis_encode_init(&tmp->vi, 1, 8000, 96000, 128000, 160000)) {
                syslog(LOG_ERR, "Unable to initialize Vorbis encoder!\n");
                return -1;
        }

        vorbis_comment_init(&tmp->vc);
        vorbis_comment_add_tag(&tmp->vc, "ENCODER", "voipmonitor.org");
/*
        if (comment)
                vorbis_comment_add_tag(&tmp->vc, "COMMENT", (char *) comment);
*/

        vorbis_analysis_init(&tmp->vd, &tmp->vi);
        vorbis_block_init(&tmp->vd, &tmp->vb);

        ogg_stream_init(&tmp->os, random());

        vorbis_analysis_headerout(&tmp->vd, &tmp->vc, &header, &header_comm,
                                  &header_code);
        ogg_stream_packetin(&tmp->os, &header);
        ogg_stream_packetin(&tmp->os, &header_comm);
        ogg_stream_packetin(&tmp->os, &header_code);

        while (!tmp->eos) {
                if (ogg_stream_flush(&tmp->os, &tmp->og) == 0)
                        break;

#if 0
		FILE *fd = fopen("/tmp/test.ogg", "a");
		fwrite(tmp->og.header, 1, tmp->og.header_len, fd);
		fwrite(tmp->og.body, 1, tmp->og.body_len, fd);
		fclose(fd);
#endif


		for(int i = 0; i < tmp->og.header_len; i++) {
			spybuffer->push(tmp->og.header[i]);
		}
		for(int i = 0; i < tmp->og.body_len; i++) {
			spybuffer->push(tmp->og.body[i]);
		}
                if (ogg_page_eos(&tmp->og))
                        tmp->eos = 1;
        }

        return 0;
}


static void write_stream(struct vorbis_desc *s, FILE *f)
{
	int res;

        while (vorbis_analysis_blockout(&s->vd, &s->vb) == 1) {

                vorbis_analysis(&s->vb, NULL);
                vorbis_bitrate_addblock(&s->vb);


                while (vorbis_bitrate_flushpacket(&s->vd, &s->op)) {
                        res = ogg_stream_packetin(&s->os, &s->op);
			if(res == -1) 
				printf("ogg_stream_packetin error\n");
		
			while(ogg_stream_pageout(&s->os, &s->og)) {
                                if (!fwrite(s->og.header, 1, s->og.header_len, f)) {
					syslog(LOG_ERR, "fwrite() failed: %s\n", strerror(errno));
                                }
                                if (!fwrite(s->og.body, 1, s->og.body_len, f)) {
					syslog(LOG_ERR, "fwrite() failed: %s\n", strerror(errno));
                                }
                                if (ogg_page_eos(&s->og)) {
                                        return;
                                }
			}
                }
        }
}

static int ogg_write(struct vorbis_desc *s, FILE *f, short *data)
{
        float **buffer;

        buffer = vorbis_analysis_buffer(&s->vd, 1);

	buffer[0][0] = (double)*data / 32768.0;

        vorbis_analysis_wrote(&s->vd, 1);

        write_stream(s, f);

        return 0;
}

/* Requires little endian data (currently) */
static void ogg_write2(struct vorbis_desc *s, FILE *f, char *buf, int bytes, int bigendian)
{
	float **buffer;
	int i,j;
	int channels = s->vi.channels;
	int samples = bytes/(2*channels);

	buffer = vorbis_analysis_buffer(&s->vd, samples);

	if(bigendian)
	{
		for(i=0; i < samples; i++)
		{
			for(j=0; j < channels; j++)
			{
				buffer[j][i]=((buf[2*(i*channels + j)]<<8) |
						      (0x00ff&(int)buf[2*(i*channels + j)+1]))/32768.f;
			}
		}
	}
	else
	{
		for(i=0; i < samples; i++)
		{
			for(j=0; j < channels; j++)
			{
				buffer[j][i]=((buf[2*(i*channels + j) + 1]<<8) | (0x00ff&(int)buf[2*(i*channels + j)]))/32768.f;
			}
		}
	}

	vorbis_analysis_wrote(&s->vd, samples);

        write_stream(s, f);

}


void write_stream_live(struct vorbis_desc *s, std::queue <char> *spybuffer)
{
	int res;
	int i;

        while (vorbis_analysis_blockout(&s->vd, &s->vb) == 1) {

                vorbis_analysis(&s->vb, NULL);
                vorbis_bitrate_addblock(&s->vb);

                while (vorbis_bitrate_flushpacket(&s->vd, &s->op)) {
                        res = ogg_stream_packetin(&s->os, &s->op);
			if(res == -1) 
				printf("ogg_stream_packetin error\n");
		
			while(ogg_stream_pageout(&s->os, &s->og)) {
				for(i = 0; i < s->og.header_len; i++){
					spybuffer->push(s->og.header[i]);
				}
				for(i = 0; i < s->og.body_len; i++){
					spybuffer->push(s->og.body[i]);
				}
                                if (ogg_page_eos(&s->og)) {
                                        return;
                                }
			}
                }
        }
}

int ogg_write_live(struct vorbis_desc *s, std::queue <char> *spybuffer, short *data)
{
        float **buffer;

        buffer = vorbis_analysis_buffer(&s->vd, 1);
	buffer[0][0] = (double)*data / 32768.0;
        vorbis_analysis_wrote(&s->vd, 1);

        write_stream_live(s, spybuffer);

        return 0;
}


static void ogg_close(struct vorbis_desc *s, FILE *f)
{
	/* Tell the Vorbis encoder that the stream is finished
	 * and write out the rest of the data */
	vorbis_analysis_wrote(&s->vd, 0);
	write_stream(s, f);

        ogg_stream_clear(&s->os);
        vorbis_block_clear(&s->vb);
        vorbis_dsp_clear(&s->vd);
        vorbis_comment_clear(&s->vc);
        vorbis_info_clear(&s->vi);

	//ogg_sync_destroy(&s->oy);
}

int ogg_mix(char *in1, char *in2, char *out, int stereo, int samplerate, double quality, int swap) {
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

	vorbis_desc ogg;
	ogg_header(f_out, &ogg, stereo, samplerate, quality);

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
				char buf[4];
				if(swap){
					memcpy(buf, p[1], 2);
					memcpy(buf + 2, p[0], 2);
				} else {
					memcpy(buf, p[0], 2);
					memcpy(buf + 2, p[1], 2);
				}
				ogg_write2(&ogg, f_out, buf, 4, 0);
			} else {
				slinear_saturated_add((short int*)p[0], (short int*)p[1]);
				ogg_write(&ogg, f_out, (short int*)p[0]);
			}
			buff_pos[0] += 2;
			buff_pos[1] += 2;
		} else if (p[0]) {
			if(stereo) {
				char buf[4];
				if(swap) {
					memcpy(buf, &zero, 2);
					memcpy(buf + 2, p[0], 2);
				} else {
					memcpy(buf, p[0], 2);
					memcpy(buf + 2, &zero, 2);
				}
				ogg_write2(&ogg, f_out, buf, 4, 0);
			} else {
				ogg_write(&ogg, f_out, (short int*)p[0]);
				ogg_write(&ogg, f_out, &zero);
			}
			buff_pos[0] += 2;
		} else if (p[1]) {
			if(stereo) {
				char buf[4];
				if(swap) {
					memcpy(buf, p[1], 2);
					memcpy(buf + 2, &zero, 2);
				} else {
					memcpy(buf, &zero, 2);
					memcpy(buf + 2, p[1], 2);
				}
				ogg_write2(&ogg, f_out, buf, 4, 0);
			} else {
				ogg_write(&ogg, f_out, (short int*)p[1]);
				ogg_write(&ogg, f_out, &zero);
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

	ogg_close(&ogg, f_out);
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
