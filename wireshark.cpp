#include "config.h"

#include <pcap.h>
#include <string>
#include <vector>
#include <syslog.h>

#if HAVE_LIBWIRESHARK

#define WS_NORETURN 

#include <stdlib.h>
#include <iostream>
#include <ostream>

#include <gnutls/gnutls.h> 
#include <gnutls/x509.h> 
#include <gnutls/pkcs12.h> 

#include <glib.h>
#include <wireshark/wsutil/privileges.h>
#include <wireshark/register.h>
#include <wireshark/epan/epan.h>
#include <wireshark/cfile.h>
#include <wireshark/wiretap/wtap.h>

#if not defined(LIBWIRESHARK_VERSION) or LIBWIRESHARK_VERSION < 20403
#define _U_
#include <wireshark/file.h>
#include <wireshark/epan/prefs.h>
#include <wireshark/epan/prefs-int.h>
#endif

#if defined(LIBWIRESHARK_VERSION) and LIBWIRESHARK_VERSION >= 20605
#include <wireshark/epan/prefs-int.h>
#include <wireshark/epan/print.h>
#endif

#include "heap_safe.h"


using namespace std;
 

extern std::string trim_str(std::string s, const char *trimChars = NULL);

static epan_t *ws_epan_new(capture_file *cf);
static tvbuff_t *frame_tvbuff_new(const frame_data *fd, const guint8 *buf);
static void ws_set_params();
static bool ws_set_param(string param, string value);
static void ws_set_dissectors();
static bool ws_set_disector(const char *table, unsigned port, const char *new_dissector);

static bool ws_init_ok;
static epan_t *ws_epan;


void ws_init() {
	if(!ws_init_ok) {
		gnutls_global_init();
		init_process_policies();
		#if defined(LIBWIRESHARK_VERSION) and LIBWIRESHARK_VERSION >= 20605
		wtap_init(true);
		#else
		wtap_init();
		#endif
		#if defined(LIBWIRESHARK_VERSION) and LIBWIRESHARK_VERSION >= 30000
		epan_init(NULL, NULL, false);
		#else
		epan_init(register_all_protocols, register_all_protocol_handoffs, NULL, NULL);
		#endif
		ws_init_ok = true;
	}
}

void ws_epan_init() {
	if(!ws_epan) {
		ws_epan = ws_epan_new(NULL);
		ws_set_params();
		ws_set_dissectors();
	}
}

void ws_epan_term() {
	if(ws_epan) {
		epan_free(ws_epan);
		ws_epan = NULL;
	}
}

void ws_set_params() {
	#if defined(LIBWIRESHARK_VERSION) and LIBWIRESHARK_VERSION >= 20605
	ws_set_param("ip.use_geoip", "FALSE");
	#endif
	extern vector<string> opt_ws_params;
	for(unsigned i = 0; i < opt_ws_params.size(); i++) {
		size_t pv_separator = opt_ws_params[i].find(":");
		if(pv_separator != string::npos) {
			string param = trim_str(opt_ws_params[i].substr(0, pv_separator));
			string value = trim_str(opt_ws_params[i].substr(pv_separator + 1));
			ws_set_param(param, value);
		}
	}
}

bool ws_set_param(string param, string value) {
	size_t mp_separator = param.find(".");
	if(mp_separator == string::npos) {
		return(false);
	}
	string module = trim_str(param.substr(0, mp_separator));
	string pref = trim_str(param.substr(mp_separator + 1));
	module_t *ws_module = prefs_find_module(module.c_str());
	if(!ws_module) {
		syslog(LOG_NOTICE, "unknown ws prefs module %s", module.c_str());
		return(false);
	}
	pref_t *ws_pref = prefs_find_preference(ws_module, pref.c_str());
	if(!ws_pref) {
		syslog(LOG_NOTICE, "unknown ws prefs %s.%s", module.c_str(), pref.c_str());
		return(false);
	}
	int ws_pref_type = prefs_get_type(ws_pref);
	if(ws_pref_type == PREF_UINT) {
		prefs_set_uint_value(ws_pref, atoi(value.c_str()), pref_current);
	} else if(ws_pref_type == PREF_BOOL) {
		prefs_set_bool_value(ws_pref, !strcasecmp(value.c_str(), "true") || !strcasecmp(value.c_str(), "yes"), pref_current);
	} else if(ws_pref_type == PREF_STRING) {
		prefs_set_string_value(ws_pref, value.c_str(), pref_current);
	} else if(ws_pref_type == PREF_ENUM) {
		int ev = -1;
		const enum_val_t* ev_list = prefs_get_enumvals(ws_pref);
		for(unsigned i = 0; ev_list[i].name; i++) {
			if(!strcasecmp(ev_list[i].name, value.c_str())) {
				ev = ev_list[i].value;
				break;
			}
		}
		if(ev != -1) {
			prefs_set_enum_value(ws_pref, ev, pref_current);
		} else {
			syslog(LOG_NOTICE, "unknown ws value %s for prefs %s.%s", value.c_str(), module.c_str(), pref.c_str());
			return(false);
		}
	} else {
		syslog(LOG_NOTICE, "unsupported ws type %i for prefs %s.%s", ws_pref_type, module.c_str(), pref.c_str());
		return(false);
	}
	return(true);
}

void ws_set_dissectors() {
	extern char *ss7_rudp_portmatrix;
	for(unsigned i = 0; i <= 0xFFFF; i++) {
		if(ss7_rudp_portmatrix[i]) {
			ws_set_disector("udp.port", i, "RUDP");
		}
	}
}

bool ws_set_disector(const char *table, unsigned port, const char *new_dissector) {
	dissector_table_t dis_table = find_dissector_table(table);
	if(!dis_table) {
		syslog(LOG_ERR, "ws set dissector : unknown table '%s'", table);
		return(false);
	}
	dissector_handle_t dis_handle_new = dissector_table_get_dissector_handle(dis_table, (gchar*)new_dissector);
	if(!dis_handle_new) {
		syslog(LOG_ERR, "ws set dissector : unknown new dissector '%s'", new_dissector);
		return(false);
	}
	ftenum_t selector_type = dissector_table_get_type(dis_table);
	if(selector_type == FT_UINT16) {
		dissector_change_uint(table, port, dis_handle_new);
	} else {
		syslog(LOG_ERR, "ws set dissector : bad selector-type for table '%s' (need FT_UINT16)", table);
		return(false);
	}
	return(true);
}

void ws_gener_json(epan_dissect_t *edt, string *rslt) {
	rslt->resize(0);
	unsigned buff_size = 1000000;
	char *buff = new FILE_LINE(0) char[buff_size];
	FILE *file = fmemopen(buff, buff_size, "w");
	if(file) {
		output_fields_t* output_fields  = NULL;
		gchar **protocolfilter = NULL;
		#if defined(LIBWIRESHARK_VERSION) and LIBWIRESHARK_VERSION >= 30000
		json_dumper json_dump;
		memset(&json_dump, 0, sizeof(json_dump));
		json_dump.output_file = file;
		write_json_proto_tree(output_fields, print_dissections_expanded, false, protocolfilter, PF_NONE, edt, NULL, proto_node_group_children_by_unique, &json_dump);
		#elif defined(LIBWIRESHARK_VERSION) and LIBWIRESHARK_VERSION >= 20605
		write_json_proto_tree(output_fields, print_dissections_expanded, false, protocolfilter, PF_NONE, edt, NULL, proto_node_group_children_by_unique, file);
		#elif defined(LIBWIRESHARK_VERSION) and LIBWIRESHARK_VERSION >= 20403
		write_json_proto_tree(output_fields, print_dissections_expanded, false, protocolfilter, PF_NONE, edt, file);
		#else
			print_args_t print_args;
			memset(&print_args, 0, sizeof(print_args));
			print_args.print_dissections = print_dissections_expanded;
			#if defined(LIBWIRESHARK_VERSION) and LIBWIRESHARK_VERSION >= 20208
			write_json_proto_tree(output_fields, &print_args, protocolfilter, edt, file);
			#else
			pf_flags protocolfilter_flags = PF_NONE;
			write_json_proto_tree(output_fields, &print_args, protocolfilter, protocolfilter_flags, edt, file);
			#endif
		#endif
		fclose(file);
		*rslt = buff;
	}
	delete [] buff;
}

void ws_dissect_packet(pcap_pkthdr* header, const u_char* packet, int dlt, string *rslt) {
 
	ws_init();
	ws_epan_init();
	
	frame_data fdlocal;
	guint32 cum_bytes = 0;
	
	#if defined(LIBWIRESHARK_VERSION) and LIBWIRESHARK_VERSION >= 20605
	wtap_rec whdr;
	#else
	wtap_pkthdr whdr;
	#endif
	memset(&whdr, 0, sizeof(whdr));
	whdr.ts.secs = header->ts.tv_sec;
	whdr.ts.nsecs = header->ts.tv_usec * 1000;
	whdr.presence_flags = 3;
	unsigned ws_dlt = dlt == DLT_MTP2 ? WTAP_ENCAP_MTP2 :
			  dlt == DLT_MTP2_WITH_PHDR ? WTAP_ENCAP_MTP2_WITH_PHDR :
			  dlt == DLT_LINUX_SLL ? WTAP_ENCAP_SLL :
			  WTAP_ENCAP_ETHERNET;
	unsigned skip_hdr = dlt == DLT_MTP2_WITH_PHDR ? 4 : 0;
	#if defined(LIBWIRESHARK_VERSION) and LIBWIRESHARK_VERSION >= 20605
	whdr.rec_header.packet_header.caplen = header->caplen - skip_hdr;
	whdr.rec_header.packet_header.len = header->len - skip_hdr;
	whdr.rec_header.packet_header.pkt_encap = ws_dlt;
	#else
	whdr.caplen = header->caplen - skip_hdr;
	whdr.len = header->len - skip_hdr;
	whdr.pkt_encap = ws_dlt;
	#endif
	
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

	tvbuff_t *tvb = frame_tvbuff_new(&fdlocal, packet + skip_hdr);

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

  #if defined(LIBWIRESHARK_VERSION) and LIBWIRESHARK_VERSION >= 20605
  packet_provider_funcs ppf;
  memset(&ppf, 0, sizeof(ppf));
  epan_t *epan = epan_new(NULL, &ppf);
  #else
  epan_t *epan = epan_new();
  #endif

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
  #if not defined(LIBWIRESHARK_VERSION) or LIBWIRESHARK_VERSION < 20403
  cf->snap            = WTAP_MAX_PACKET_SIZE;
  #endif
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
	
	return tvb;
}

#else

using namespace std;

void ws_dissect_packet(pcap_pkthdr* /*header*/, const u_char* /*packet*/, int /*dlt*/, string *rslt) {
	rslt->resize(0);
}

#endif //HAVE_LIBWIRESHARK
