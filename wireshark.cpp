#include "config.h"

#include <pcap.h>
#include <string>

#if HAVE_LIBWIRESHARK

#define WS_NORETURN 

#include <stdlib.h>
#include <iostream>
#include <ostream>

#include <glib.h>
#include <wireshark/wsutil/privileges.h>
#include <wireshark/register.h>
#include <wireshark/epan/epan.h>
#include <wireshark/cfile.h>
#include <wireshark/file.h>
#include <wireshark/wiretap/wtap.h>


using namespace std;
 

static epan_t *ws_epan_new(capture_file *cf);
static tvbuff_t *frame_tvbuff_new(const frame_data *fd, const guint8 *buf);

static bool ws_init_ok;
static epan_t *ws_epan;


void ws_init() {
	if(!ws_init_ok) {
		init_process_policies();
		wtap_init();
		epan_init(register_all_protocols, register_all_protocol_handoffs, NULL, NULL);
		ws_init_ok = true;
	}
}

void ws_epan_init() {
	if(!ws_epan) {
		ws_epan = ws_epan_new(NULL);
	}
}

void ws_epan_term() {
	if(ws_epan) {
		epan_free(ws_epan);
		ws_epan = NULL;
	}
}

capture_file *ws_open_pcap(const char *fileName) {
	wtap_opttypes_initialize();
	capture_file *cfile = new capture_file;
	cap_file_init(cfile);
	int err = 0;
	if(cf_open(cfile, fileName, 0, FALSE, &err) != CF_OK) {
		cerr << "cf_open failed" << endl;
		delete cfile;
		return(NULL);
	}
	return(cfile);
}

bool ws_read_packet(capture_file *cfile, wtap_pkthdr **whdr, const guchar **pd, gint64 *data_offset) {
	gchar *err_info = NULL;
	int err;
	if(wtap_read(cfile->wth, &err, &err_info, data_offset)) {
		cfile->count++;
		*whdr = wtap_phdr(cfile->wth);
		*pd = wtap_buf_ptr(cfile->wth);
		return(true);
	} else {
		*whdr = NULL;
		*pd = NULL;
		*data_offset = 0;
		return(false);
	}
}

void ws_gener_json(epan_dissect_t *edt, string *rslt) {
	rslt->resize(0);
	unsigned buff_size = 1000000;
	char *buff = new char[buff_size];
	FILE *file = fmemopen(buff, buff_size, "w");
	if(file) {
		output_fields_t* output_fields  = NULL;
		print_args_t print_args;
		memset(&print_args, 0, sizeof(print_args));
		print_args.print_dissections = print_dissections_expanded;
		gchar **protocolfilter = NULL;
		write_json_proto_tree(output_fields, &print_args, protocolfilter, edt, file);
		fclose(file);
		*rslt = buff;
	}
	delete [] buff;
}

void ws_gener_pdml(epan_dissect_t *edt, string *rslt) {
	rslt->resize(0);
	unsigned buff_size = 1000000;
	char *buff = new char[buff_size];
	FILE *file = fmemopen(buff, buff_size, "w");
	if(file) {
		output_fields_t* output_fields  = NULL;
		gchar **protocolfilter = NULL;
		write_pdml_proto_tree(output_fields, protocolfilter, edt, file);
		fclose(file);
		*rslt = buff;
	}
	delete [] buff;
}

void ws_dissect_packet(wtap_pkthdr *whdr, const guchar *pd, capture_file *cfile, gint64 data_offset, string *rslt) {

	frame_data fdlocal;
	guint32 cum_bytes = 0;
	
	frame_data_init(&fdlocal, 
			cfile->count, 
			whdr, 
			data_offset, 
			cum_bytes);

	epan_dissect_t *edt = epan_dissect_new(cfile->epan, 
					       TRUE, 
					       TRUE);

	frame_data_set_before_dissect(&fdlocal, 
				      &cfile->elapsed_time, 
				      &cfile->ref, 
				      cfile->prev_dis);
	cfile->ref = &fdlocal;

	tvbuff_t *tvb = frame_tvbuff_new(&fdlocal, pd);

	epan_dissect_run(edt, 
			 cfile->cd_t, 
			 whdr, 
			 tvb, 
			 &fdlocal, 
			 NULL);

	frame_data_set_after_dissect(&fdlocal, 
				     &cum_bytes);

	ws_gener_json(edt, rslt);
 
}

void ws_dissect_packet(pcap_pkthdr* header, const u_char* packet, int dlt, string *rslt) {
 
	ws_init();
	ws_epan_init();
	
	frame_data fdlocal;
	guint32 cum_bytes = 0;
	
	wtap_pkthdr whdr;
	memset(&whdr, 0, sizeof(wtap_pkthdr));
	whdr.ts.secs = header->ts.tv_sec;
	whdr.ts.nsecs = header->ts.tv_usec * 1000;
	whdr.caplen = header->caplen;
	whdr.len = header->len;
	whdr.pkt_encap = dlt == DLT_MTP2 ? WTAP_ENCAP_MTP2 :
			 WTAP_ENCAP_ETHERNET;
	whdr.presence_flags = 3;
	
	frame_data_init(&fdlocal, 
			1, // cfile->count, 
			&whdr, 
			0, // data_offset, 
			cum_bytes);

	epan_dissect_t *edt = epan_dissect_new(ws_epan, // cfile->epan, 
					       TRUE, 
					       TRUE);

	nstime_t elapsed_time = { 0, 0 };
	const frame_data *ref = NULL;
	frame_data_set_before_dissect(&fdlocal, 
				      &elapsed_time, // &cfile->elapsed_time, 
				      &ref, // &cfile->ref, 
				      NULL); //cfile->prev_dis);
	// cfile->ref = &fdlocal;

	tvbuff_t *tvb = frame_tvbuff_new(&fdlocal, packet);

	epan_dissect_run_with_taps(edt, 
			 1, // cfile->cd_t, 
			 &whdr, 
			 tvb, 
			 &fdlocal, 
			 NULL);

	frame_data_set_after_dissect(&fdlocal, 
				     &cum_bytes);
	
	ws_gener_json(edt, rslt);
	
	frame_data_destroy(&fdlocal);
	
	epan_dissect_reset(edt);
	epan_dissect_free(edt);
	postseq_cleanup_all_protocols();
	
	static unsigned _counter;
	if(!((++_counter) % 1000)) {
		ws_epan_term();
	}
	
}

void ws_test(const char *pcapFile) {
 
	ws_init();
	
	capture_file *cfile = ws_open_pcap(pcapFile);
	if(!cfile) {
		return;
	}

	struct wtap_pkthdr *whdr;
	const guchar *pd;
	gint64 data_offset = 0;
	while(ws_read_packet(cfile, &whdr, &pd, &data_offset)) {
		string rslt;
		ws_dissect_packet(whdr, pd, cfile, data_offset, &rslt);
		cout << rslt << endl;
	}

}


// -----------------------------------------------------------------------------


// epan/tvbuff-int.h
struct tvbuff {
	/* Doubly linked list pointers */
	tvbuff_t                *next;

	/* Record-keeping */
	const struct tvb_ops   *ops;
	gboolean		initialized;
	guint			flags;
	struct tvbuff		*ds_tvb;  /**< data source top-level tvbuff */

	/** We're either a TVBUFF_REAL_DATA or a
	 * TVBUFF_SUBSET that has a backing buffer that
	 * has real_data != NULL, or a TVBUFF_COMPOSITE
	 * which has flattened its data due to a call
	 * to tvb_get_ptr().
	 */
	const guint8		*real_data;

	/** Length of virtual buffer (and/or real_data). */
	guint			length;

	/** Reported length. */
	guint			reported_length;

	/* Offset from beginning of first TVBUFF_REAL. */
	gint			raw_offset;
};

// epan/tvbuff-int.h
struct tvb_ops {
	gsize tvb_size;
	void (*tvb_free)(struct tvbuff *tvb);
	guint (*tvb_offset)(const struct tvbuff *tvb, guint counter);
	const guint8 *(*tvb_get_ptr)(struct tvbuff *tvb, guint abs_offset, guint abs_length);
	void *(*tvb_memcpy)(struct tvbuff *tvb, void *target, guint offset, guint length);

	gint (*tvb_find_guint8)(tvbuff_t *tvb, guint abs_offset, guint limit, guint8 needle);
	gint (*tvb_ws_mempbrk_pattern_guint8)(tvbuff_t *tvb, guint abs_offset, guint limit, const ws_mempbrk_pattern* pattern, guchar *found_needle);

	tvbuff_t *(*tvb_clone)(tvbuff_t *tvb, guint abs_offset, guint abs_length);
};

// frame_tvbuff.c
struct tvb_frame {
	struct tvbuff tvb;

	Buffer *buf;         /* Packet data */

	wtap *wth;           /**< Wiretap session */
	gint64 file_off;     /**< File offset */

	guint offset;
};

// epan/epan-int.h
struct epan_session {
	void *data;

	const nstime_t *(*get_frame_ts)(void *data, guint32 frame_num);
	const char *(*get_interface_name)(void *data, guint32 interface_id);
	const char *(*get_user_comment)(void *data, const frame_data *fd);
};

// file.c
static epan_t *ws_epan_new(capture_file *cf)
{
  epan_t *epan = epan_new();

  epan->data = cf;
  epan->get_frame_ts = NULL; //ws_get_frame_ts;
  epan->get_interface_name = NULL; //cap_file_get_interface_name;
  epan->get_user_comment = NULL; //ws_get_user_comment;

  return epan;
}

// cfile.c
void cap_file_init(capture_file *cf)
{
  /* Initialize the capture file struct */
  memset(cf, 0, sizeof(capture_file));
  cf->snap            = WTAP_MAX_PACKET_SIZE;
}

// file.c
cf_status_t cf_open(capture_file *cf, const char *fname, unsigned int type, gboolean is_tempfile, int *err)
{
  wtap  *wth;
  gchar *err_info;

  wth = wtap_open_offline(fname, type, err, &err_info, TRUE);
  if (wth == NULL)
    goto fail;

  /* The open succeeded.  Close whatever capture file we had open,
     and fill in the information for this file. */
  #if 0
  cf_close(cf);
  #endif

  /* Initialize the packet header. */
  wtap_phdr_init(&cf->phdr);

  /* XXX - we really want to initialize this after we've read all
     the packets, so we know how much we'll ultimately need. */
  ws_buffer_init(&cf->buf, 1500);

  /* Create new epan session for dissection.
   * (The old one was freed in cf_close().)
   */
  cf->epan = ws_epan_new(cf);

  /* We're about to start reading the file. */
  cf->state = FILE_READ_IN_PROGRESS;

  cf->wth = wth;
  cf->f_datalen = 0;

  /* Set the file name because we need it to set the follow stream filter.
     XXX - is that still true?  We need it for other reasons, though,
     in any case. */
  cf->filename = g_strdup(fname);

  /* Indicate whether it's a permanent or temporary file. */
  cf->is_tempfile = is_tempfile;

  /* No user changes yet. */
  cf->unsaved_changes = FALSE;

  cf->computed_elapsed = 0;

  cf->cd_t        = wtap_file_type_subtype(cf->wth);
  cf->open_type   = type;
  cf->linktypes = g_array_sized_new(FALSE, FALSE, (guint) sizeof(int), 1);
  cf->count     = 0;
  cf->packet_comment_count = 0;
  cf->displayed_count = 0;
  cf->marked_count = 0;
  cf->ignored_count = 0;
  cf->ref_time_count = 0;
  cf->drops_known = FALSE;
  cf->drops     = 0;
  cf->snap      = wtap_snapshot_length(cf->wth);
  if (cf->snap == 0) {
    /* Snapshot length not known. */
    cf->has_snap = FALSE;
    cf->snap = WTAP_MAX_PACKET_SIZE;
  } else
    cf->has_snap = TRUE;

  /* Allocate a frame_data_sequence for the frames in this file */
  cf->frames = new_frame_data_sequence();

  nstime_set_zero(&cf->elapsed_time);
  cf->ref = NULL;
  cf->prev_dis = NULL;
  cf->prev_cap = NULL;
  cf->cum_bytes = 0;

  #if 0
  packet_list_queue_draw();
  cf_callback_invoke(cf_cb_file_opened, cf);

  if (cf->cd_t == WTAP_FILE_TYPE_SUBTYPE_BER) {
    /* tell the BER dissector the file name */
    ber_set_filename(cf->filename);
  }

  wtap_set_cb_new_ipv4(cf->wth, add_ipv4_name);
  wtap_set_cb_new_ipv6(cf->wth, (wtap_new_ipv6_callback_t) add_ipv6_name);
  #endif

  return CF_OK;

fail:
  #if 0
  cf_open_failure_alert_box(fname, *err, err_info, FALSE, 0);
  #endif
  return CF_ERROR;
}

// epan/tvbuff.c
tvbuff_t *tvb_new(const struct tvb_ops *ops)
{
	tvbuff_t *tvb;
	gsize     size = ops->tvb_size;

	g_assert(size >= sizeof(*tvb));

	tvb = (tvbuff_t *) g_slice_alloc(size);

	tvb->next	     = NULL;
	tvb->ops	     = ops;
	tvb->initialized     = FALSE;
	tvb->flags	     = 0;
	tvb->length	     = 0;
	tvb->reported_length = 0;
	tvb->real_data	     = NULL;
	tvb->raw_offset	     = -1;
	tvb->ds_tvb	     = NULL;

	return tvb;
}

// frame_tvbuff.c
static const guint8 *frame_get_ptr(tvbuff_t *tvb, guint abs_offset, guint abs_length)
{
	//struct tvb_frame *frame_tvb = (struct tvb_frame *) tvb;

	//frame_cache(frame_tvb);

	return tvb->real_data + abs_offset;
}

// frame_tvbuff.c
static guint frame_offset(const tvbuff_t *tvb, const guint counter)
{
	/* XXX: frame_tvb->offset */
	return counter;
}

// frame_tvbuff.c
static const struct tvb_ops tvb_frame_ops = {
	sizeof(struct tvb_frame), /* size */

	NULL, //frame_free,           /* free */
	frame_offset,         /* offset */
	frame_get_ptr,        /* get_ptr */
	NULL, //frame_memcpy,         /* memcpy */
	NULL, //frame_find_guint8,    /* find_guint8 */
	NULL, //frame_pbrk_guint8,    /* pbrk_guint8 */
	NULL, //frame_clone,          /* clone */
};

// frame_tvbuff.c
tvbuff_t *frame_tvbuff_new(const frame_data *fd, const guint8 *buf)
{
	//struct tvb_frame *frame_tvb;
	tvbuff_t *tvb;

	tvb = tvb_new(&tvb_frame_ops);

	/*
	 * XXX - currently, the length arguments in
	 * tvbuff structure are signed, but the captured
	 * and reported length values are unsigned; this means
	 * that length values > 2^31 - 1 will appear as
	 * negative lengths
	 *
	 * Captured length values that large will already
	 * have been filtered out by the Wiretap modules
	 * (the file will be reported as corrupted), to
	 * avoid trying to allocate large chunks of data.
	 *
	 * Reported length values will not have been
	 * filtered out, and should not be filtered out,
	 * as those lengths are not necessarily invalid.
	 *
	 * For now, we clip the reported length at G_MAXINT
	 *
	 * (XXX, is this still a problem?) There was an exception when we call
	 * tvb_new_real_data() now there's no one
	 */

	tvb->real_data       = buf;
	tvb->length          = fd->cap_len;
	tvb->reported_length = fd->pkt_len > G_MAXINT ? G_MAXINT : fd->pkt_len;
	tvb->initialized     = TRUE;

	/*
	 * This is the top-level real tvbuff for this data source,
	 * so its data source tvbuff is itself.
	 */
	tvb->ds_tvb = tvb;
	
#if 0

	frame_tvb = (struct tvb_frame *) tvb;

	/* XXX, wtap_can_seek() */
	if (cfile.wth && cfile.wth->random_fh
#ifdef WANT_PACKET_EDITOR
		&& fd->file_off != -1 /* generic clone for modified packets */
#endif
	) {
		frame_tvb->wth = cfile.wth;
		frame_tvb->file_off = fd->file_off;
		frame_tvb->offset = 0;
	} else
		frame_tvb->wth = NULL;

	frame_tvb->buf = NULL;
	
#endif

	return tvb;
	
}

#else

using namespace std;

void ws_dissect_packet(pcap_pkthdr* header, const u_char* packet, int dlt, string *rslt) {
	rslt->resize(0);
}
void ws_test(const char *pcapFile) {
}

#endif //HAVE_LIBWIRESHARK
