/*#include "format_wav.h"*/

#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <syslog.h>

#include <vorbis/codec.h>
#include <vorbis/vorbisenc.h>

#include "format_slinear.h"

struct vorbis_desc {    /* format specific parameters */
        /* structures for handling the Ogg container */
        ogg_sync_state oy;
        ogg_stream_state os;
        ogg_page og;
        ogg_packet op;

        /* structures for handling Vorbis audio data */
        vorbis_info vi;
        vorbis_comment vc;
        vorbis_dsp_state vd;
        vorbis_block vb;

        /*! \brief Indicates whether an End of Stream condition has been detected. */
        int eos;
};

static int ogg_header(FILE *f, struct vorbis_desc *tmp)
{
        ogg_packet header;
        ogg_packet header_comm;
        ogg_packet header_code;

        vorbis_info_init(&tmp->vi);

        if (vorbis_encode_init_vbr(&tmp->vi, 1, 8000, 0.4)) {
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

static void write_stream(struct vorbis_desc *s, FILE *f)
{
        while (vorbis_analysis_blockout(&s->vd, &s->vb) == 1) {
                vorbis_analysis(&s->vb, NULL);
                vorbis_bitrate_addblock(&s->vb);

                while (vorbis_bitrate_flushpacket(&s->vd, &s->op)) {
                        ogg_stream_packetin(&s->os, &s->op);
                        while (!s->eos) {
                                if (ogg_stream_pageout(&s->os, &s->og) == 0) {
                                        break;
                                }
                                if (!fwrite(s->og.header, 1, s->og.header_len, f)) {
					syslog(LOG_ERR, "fwrite() failed: %s\n", strerror(errno));
                                }
                                if (!fwrite(s->og.body, 1, s->og.body_len, f)) {
					syslog(LOG_ERR, "fwrite() failed: %s\n", strerror(errno));
                                }
                                if (ogg_page_eos(&s->og)) {
                                        s->eos = 1;
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

	ogg_sync_destroy(&s->oy);
}


int ogg_mix(char *in1, char *in2, char *out) {
	FILE *f_in1;
	FILE *f_in2;
	FILE *f_out;

	char *bitstream_buf1 = NULL;
	char *bitstream_buf2 = NULL;
	char *p1;
	char *f1;
	char *p2;
	char *f2;
	long file_size1;
	long file_size2;

	/* combine two wavs */
	f_in1 = fopen(in1, "r");
	if(!f_in1) {
		syslog(LOG_ERR,"File [%s] cannot be opened for read.\n", in1);
		return 1;
	}
	f_in2 = fopen(in2, "r");
	if(!f_in2) {
		fclose(f_in1);
		syslog(LOG_ERR,"File [%s] cannot be opened for read.\n", in2);
		return 1;
	}
	f_out = fopen(out, "w");
	if(!f_out) {
		fclose(f_in1);
		fclose(f_in2);
		syslog(LOG_ERR,"File [%s] cannot be opened for write.\n", out);
		return 1;
	}
	char f_out_buffer[32768];
	setvbuf(f_out, f_out_buffer, _IOFBF, 32768);

	vorbis_desc ogg;
	ogg_header(f_out, &ogg);

	fseek(f_in1, 0, SEEK_END);
	file_size1 = ftell(f_in1);
	fseek(f_in1, 0, SEEK_SET);

	fseek(f_in2, 0, SEEK_END);
	file_size2 = ftell(f_in2);
	fseek(f_in2, 0, SEEK_SET);

	bitstream_buf1 = (char *)malloc(file_size1);
	if(!bitstream_buf1) {
		fclose(f_in1);
		fclose(f_in2);
		fclose(f_out);
		syslog(LOG_ERR,"Cannot malloc bitsream_buf1[%ld]", file_size1);
		return 1;
	}
	bitstream_buf2 = (char *)malloc(file_size2);
	if(!bitstream_buf2) {
		fclose(f_in1);
		fclose(f_in2);
		fclose(f_out);
		free(bitstream_buf1);
		syslog(LOG_ERR,"Cannot malloc bitsream_buf2[%ld]", file_size1);
		return 1;
	}
	fread(bitstream_buf1, file_size1, 1, f_in1);
	fread(bitstream_buf2, file_size2, 1, f_in2);
	p1 = bitstream_buf1;
	f1 = bitstream_buf1 + file_size1;
	p2 = bitstream_buf2;
	f2 = bitstream_buf2 + file_size2;

	while(p1 < f1 || p2 < f2 ) {
		if(p1 < f1 && p2 < f2) {
			slinear_saturated_add((short int*)p1, (short int*)p2);
			ogg_write(&ogg, f_out, (short int*)p1);
			//fwrite(p1, 2, 1, f_out);
			p1 += 2;
			p2 += 2;
		} else if ( p1 < f1 ) {
			//fwrite(p1, 2, 1, f_out);
			ogg_write(&ogg, f_out, (short int*)p1);
			p1 += 2;
		} else {
			ogg_write(&ogg, f_out, (short int*)p2);
			//fwrite(p2, 2, 1, f_out);
			p2 += 2;
		}
	}

	if(bitstream_buf1)
		free(bitstream_buf1);
	if(bitstream_buf2)
		free(bitstream_buf2);
	ogg_close(&ogg, f_out);
	fclose(f_out);
	fclose(f_in1);
	fclose(f_in2);

	return 0;
}
