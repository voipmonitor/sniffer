#include <vorbis/codec.h>
#include <vorbis/vorbisenc.h>

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


int ogg_mix(char *, char *, char *);
int ogg_header(FILE *, struct vorbis_desc *);
int ogg_header_live(int, vorbis_desc*);
void write_stream_live(struct vorbis_desc *, int *);
int ogg_write_live(struct vorbis_desc *, int *, short *);
