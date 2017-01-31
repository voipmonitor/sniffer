#ifndef FORMAT_OGG_H
#define FORMAT_OGG_H


#include <vorbis/codec.h>
#include <vorbis/vorbisenc.h>

#include <queue>

#define MAX_FIFOOUT 128

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

int ogg_mix(char *in1, char *in2, char *out, int stereo, int samplerate, double quality, int swap);
int ogg_header(FILE *f, struct vorbis_desc *tmp, int stereo, int samplerate, float quality);
void write_stream_live(struct vorbis_desc *s, std::queue <char> spybuffer);
int ogg_write_live(struct vorbis_desc *s, std::queue <char> *spybuffer, short *data);
int ogg_header_live(std::queue <char> *spybuffer, struct vorbis_desc *tmp);


#endif //FORMAT_OGG_H
