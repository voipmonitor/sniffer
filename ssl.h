#ifndef SSL_H
#define SSL_H


#if defined(HAVE_LIBGNUTLS) and defined(HAVE_SSL_WS)

#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/pkcs12.h>
#include <gcrypt.h>
#include <zlib.h>
#include <string>
#include <vector>


/*
// GLIB COMPATIBILITY DEBUG BEGIN

#define __GLIB_H_INSIDE__
#define __G_MEM_H__
#define __G_TYPES_H__

#define G_BEGIN_DECLS  extern "C" {
#define G_END_DECLS    }

#define GLIB_AVAILABLE_IN_ALL extern
#define GLIB_AVAILABLE_IN_2_30 extern
#define GLIB_AVAILABLE_IN_2_34 extern

#define G_GNUC_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#define G_GNUC_CONST __attribute__((__const__))

#define TRUE true
#define FALSE false

#define MIN(a, b) ((a < b) ? (a) : (b))
#define MAX(a, b) ((a > b) ? (a) : (b))

typedef char   gchar;
typedef short  gshort;
typedef long   glong;
typedef int    gint;
typedef gint   gboolean;
typedef unsigned char   guchar;
typedef unsigned short  gushort;
typedef unsigned long   gulong;
typedef unsigned int    guint;
typedef float   gfloat;
typedef double  gdouble;
typedef signed char gint8;
typedef unsigned char guint8;
typedef signed short gint16;
typedef unsigned short guint16;
typedef signed int gint32;
typedef unsigned int guint32;
typedef signed long gint64;
typedef unsigned long guint64;
typedef unsigned long gsize;
typedef gint   gboolean;
typedef void* gpointer;
typedef const void *gconstpointer;
typedef guint           (*GHashFunc)            (gconstpointer  key);
typedef gboolean        (*GEqualFunc)           (gconstpointer  a,
                                                 gconstpointer  b);
typedef void            (*GDestroyNotify)       (gpointer       data);
typedef void            (*GHFunc)               (gpointer       key,
                                                 gpointer       value,
                                                 gpointer       user_data);
typedef gint            (*GCompareFunc)         (gconstpointer  a,
                                                 gconstpointer  b);
typedef gint            (*GCompareDataFunc)     (gconstpointer  a,
                                                 gconstpointer  b,
						 gpointer       user_data);
typedef void            (*GFunc)                (gpointer       data,
                                                 gpointer       user_data);
#include <glib-2.0/glib/gnode.h>
#include <glib-2.0/glib/glist.h>
#include <glib-2.0/glib/ghash.h>

// GLIB COMPATIBILITY DEBUG END
*/


#define __GLIB_H_INSIDE__
#include <glib-2.0/glib/gnode.h>
#include <glib-2.0/glib/glist.h>
#include <glib-2.0/glib/ghash.h>


#define FREE(pointer) free(pointer)

using namespace std;

#define HAVE_LIBGCRYPT 1

#ifdef HAVE_LIBGCRYPT
#define SSL_CIPHER_CTX gcry_cipher_hd_t
#ifdef SSL_FAST
#define SSL_PRIVATE_KEY gcry_mpi_t
#else /* SSL_FAST */
#define SSL_PRIVATE_KEY struct gcry_sexp
#endif /* SSL_FAST */
#else  /* HAVE_LIBGCRYPT */
#define SSL_CIPHER_CTX void*
#define SSL_PRIVATE_KEY void
#endif /* HAVE_LIBGCRYPT */

/*
typedef unsigned int guchar;
typedef unsigned int guint;
typedef int gint;
typedef int8_t gint8;
typedef uint8_t guint8;
typedef int16_t gint16;
typedef uint32_t guint32;
typedef uint16_t guint16;
typedef char gchar;
typedef bool gboolean;
*/

void decrypt_ssl(char *data, unsigned int datalen);
static void ssl_cipher_cleanup(gcry_cipher_hd_t *cipher);
void ssl_clean();

/* other defines */
typedef enum {
	SSL_ID_CHG_CIPHER_SPEC		 = 0x14,
	SSL_ID_ALERT				   = 0x15,
	SSL_ID_HANDSHAKE			   = 0x16,
	SSL_ID_APP_DATA				= 0x17,
	SSL_ID_HEARTBEAT			   = 0x18
} ContentType;	  
	
typedef enum {
	SSL_HND_HELLO_REQUEST		  = 0,
	SSL_HND_CLIENT_HELLO		   = 1,
	SSL_HND_SERVER_HELLO		   = 2,
	SSL_HND_HELLO_VERIFY_REQUEST   = 3,
	SSL_HND_NEWSESSION_TICKET	  = 4,
	SSL_HND_CERTIFICATE			= 11,
	SSL_HND_SERVER_KEY_EXCHG	   = 12,
	SSL_HND_CERT_REQUEST		   = 13,
	SSL_HND_SVR_HELLO_DONE		 = 14,
	SSL_HND_CERT_VERIFY			= 15,
	SSL_HND_CLIENT_KEY_EXCHG	   = 16,
	SSL_HND_FINISHED			   = 20,
	SSL_HND_CERT_URL			   = 21,
	SSL_HND_CERT_STATUS			= 22,
	SSL_HND_SUPPLEMENTAL_DATA	  = 23,
	/* Encrypted Extensions was NextProtocol in draft-agl-tls-nextprotoneg-03
	 * and changed in draft 04 */
	SSL_HND_ENCRYPTED_EXTS		 = 67
} HandshakeType;


/* Types of port numbers Wireshark knows about. */
typedef enum {			 
	PT_NONE,			/* no port number */
	PT_SCTP,			/* SCTP */
	PT_TCP,			 /* TCP */
	PT_UDP,			 /* UDP */
	PT_DCCP,			/* DCCP */
	PT_IPX,			 /* IPX sockets */
	PT_NCP,			 /* NCP connection */
	PT_EXCHG,		   /* Fibre Channel exchange */
	PT_DDP,			 /* DDP AppleTalk connection */
	PT_SBCCS,		   /* FICON */
	PT_IDP,			 /* XNS IDP sockets */
	PT_TIPC,			/* TIPC PORT */
	PT_USB,			 /* USB endpoint 0xffff means the host */
	PT_I2C,				
	PT_IBQP,			/* Infiniband QP number */
	PT_BLUETOOTH		   
} port_type;



/* Types of addresses Wireshark knows about. */
/* If a new address type is added here, a string representation procedure should */
/* also be included in address_to_str_buf defined in to_str.c, for presentation purposes */

typedef enum {
	AT_NONE,			   /* no link-layer address */
	AT_ETHER,			  /* MAC (Ethernet, 802.x, FDDI) address */
	AT_IPv4,			   /* IPv4 */
	AT_IPv6,			   /* IPv6 */
	AT_IPX,				/* IPX */
	AT_SNA,				/* SNA */
	AT_ATALK,			  /* Appletalk DDP */
	AT_VINES,			  /* Banyan Vines */
	AT_OSI,				/* OSI NSAP */
	AT_ARCNET,			 /* ARCNET */
	AT_FC,				 /* Fibre Channel */
	AT_SS7PC,			  /* SS7 Point Code */
	AT_STRINGZ,			/* null-terminated string */
	AT_EUI64,			  /* IEEE EUI-64 */
	AT_URI,				/* URI/URL/URN */
	AT_TIPC,			   /* TIPC Address Zone,Subnetwork,Processor */
	AT_IB,				 /* Infiniband GID/LID */
	AT_USB,				/* USB Device address
							* (0xffffffff represents the host) */
	AT_AX25,			   /* AX.25 */
	AT_IEEE_802_15_4_SHORT,/* IEEE 802.15.4 16-bit short address */
						   /* (the long addresses are EUI-64's */
	AT_J1939,			  /* J1939 */
	AT_DEVICENET		   /* DeviceNet */
} address_type;

typedef struct _address {
	address_type  type;		 /* type of address */
	int		   hf;		   /* the specific field that this addr is */
	int		   len;		  /* length of address, in bytes */
	const void  *data;		  /* pointer to address data */
} address;

/** Perform a shallow copy of the address (both addresses point to the same
 * memory location).
 *
 * @param to [in,out] The destination address.
 * @param from [in] The source address.
 */
static inline void
copy_address_shallow(address *to, const address *from) {
	memcpy(to, from, sizeof(address));
	/*
	to->type = from->type;
	to->len = from->len;
	to->hf = from->hf;
	to->data = from->data;
	*/
}

/** Copy an address, allocating a new buffer for the address data
 *  using seasonal memory.
 *
 * @param to [in,out] The destination address.
 * @param from [in] The source address.
 */
/*
#define SE_COPY_ADDRESS(to, from)	 \
	do {							  \
		void *SE_COPY_ADDRESS_data; \
		copy_address_shallow((to), (from)); \
		SE_COPY_ADDRESS_data = new FILE_LINE(32001) guchar[(from)->len]; \
		memcpy(SE_COPY_ADDRESS_data, (from)->data, (from)->len); \
		(to)->data = SE_COPY_ADDRESS_data; \
	} while (0)
*/

/** Initialize an address with the given values.
 *										   
 * @param addr [in,out] The address to initialize.
 * @param addr_type [in] Address type.
 * @param addr_len [in] The length in bytes of the address data. For example, 4 for
 *					 AT_IPv4 or sizeof(struct e_in6_addr) for AT_IPv6.
 * @param addr_data [in] Pointer to the address data.
 */
static inline void
set_address(address *addr, address_type addr_type, int addr_len, const void * addr_data) {
	addr->data = addr_data;
	addr->type = addr_type;
	addr->hf   = -1;
	addr->len  = addr_len;
}
#define SET_ADDRESS(addr, addr_type, addr_len, addr_data) \
	set_address((addr), (addr_type), (addr_len), (addr_data))


#define SSLV3_VERSION		  0x300
#define TLSV1_VERSION		  0x301
#define TLSV1DOT1_VERSION	  0x302
#define TLSV1DOT2_VERSION	  0x303
#define DTLSV1DOT0_VERSION	 0xfeff
#define DTLSV1DOT0_VERSION_NOT 0x100
#define DTLSV1DOT2_VERSION	 0xfefd

#define SSL_CLIENT_RANDOM	   (1<<0)
#define SSL_SERVER_RANDOM	   (1<<1)
#define SSL_CIPHER			  (1<<2)
#define SSL_HAVE_SESSION_KEY	(1<<3)
#define SSL_VERSION			 (1<<4)
#define SSL_MASTER_SECRET	   (1<<5)
#define SSL_PRE_MASTER_SECRET   (1<<6)

/* version state tables */
#define SSL_VER_UNKNOWN				   0
#define SSL_VER_SSLv2					 1
#define SSL_VER_SSLv3					 2
#define SSL_VER_TLS					   3
#define SSL_VER_TLSv1DOT1				 4
#define SSL_VER_DTLS					  5
#define SSL_VER_DTLS1DOT2				 8
#define SSL_VER_DTLS_OPENSSL			  9
#define SSL_VER_PCT					   6
#define SSL_VER_TLSv1DOT2				 7

#define SSL2_HND_ERROR                 0x00
#define SSL2_HND_CLIENT_HELLO          0x01
#define SSL2_HND_CLIENT_MASTER_KEY     0x02
#define SSL2_HND_CLIENT_FINISHED       0x03
#define SSL2_HND_SERVER_HELLO          0x04
#define SSL2_HND_SERVER_VERIFY         0x05
#define SSL2_HND_SERVER_FINISHED       0x06
#define SSL2_HND_REQUEST_CERTIFICATE   0x07
#define SSL2_HND_CLIENT_CERTIFICATE    0x08

#define PCT_VERSION_1                  0x8001

#define PCT_MSG_CLIENT_HELLO           0x01
#define PCT_MSG_SERVER_HELLO           0x02
#define PCT_MSG_CLIENT_MASTER_KEY      0x03
#define PCT_MSG_SERVER_VERIFY          0x04
#define PCT_MSG_ERROR                  0x05

#define PCT_CH_OFFSET_V1               0xa

#define PCT_CIPHER_DES                 0x01
#define PCT_CIPHER_IDEA                0x02
#define PCT_CIPHER_RC2                 0x03
#define PCT_CIPHER_RC4                 0x04
#define PCT_CIPHER_DES_112             0x05
#define PCT_CIPHER_DES_168             0x06

#define SSLV2_MAX_SESSION_ID_LENGTH_IN_BYTES 16


typedef struct _StringInfo {
	guchar *data; /* Backing storage which may be larger than data_len */
	guint data_len; /* Length of the meaningful part of data */
	guint max_len;
} StringInfo;


/* SSL Cipher Suite modes */
typedef enum {
	MODE_STREAM,	/* GenericStreamCipher */
	MODE_CBC,	   /* GenericBlockCipher */
	MODE_GCM,	   /* GenericAEADCipher */
	MODE_CCM,	   /* AEAD_AES_{128,256}_CCM with 16 byte auth tag */
	MODE_CCM_8	  /* AEAD_AES_{128,256}_CCM with 8 byte auth tag */
} ssl_cipher_mode_t;

typedef struct _SslCipherSuite {
	gint number;
	gint kex;
	gint enc;
	gint block; /* IV block size */
	gint bits;				
	gint eff_bits;			
	gint dig;
	ssl_cipher_mode_t mode;
} SslCipherSuite;


#ifdef HAVE_LIBGCRYPT
#define SSL_CIPHER_CTX gcry_cipher_hd_t
#ifdef SSL_FAST
#define SSL_PRIVATE_KEY gcry_mpi_t
#else /* SSL_FAST */
#define SSL_PRIVATE_KEY struct gcry_sexp
#endif /* SSL_FAST */
#else  /* HAVE_LIBGCRYPT */
#define SSL_CIPHER_CTX void*
#define SSL_PRIVATE_KEY void
#endif /* HAVE_LIBGCRYPT */

typedef struct _SslDecompress SslDecompress;

typedef struct _SslFlow {
	guint32 byte_seq;
	guint16 flags;
	//wmem_tree_t *multisegment_pdus;
} SslFlow;

typedef struct _SslDecoder {
	SslCipherSuite* cipher_suite;
	gint compression;
	guchar _mac_key_or_write_iv[48];
	StringInfo mac_key; /* for block and stream ciphers */
	StringInfo write_iv; /* for AEAD ciphers (at least GCM, CCM) */
	SSL_CIPHER_CTX evp;
	SslDecompress *decomp;
	guint32 seq;
	guint16 epoch;
	SslFlow *flow;
} SslDecoder;

typedef struct _SslSession {
	gint cipher;
	gint compression;
	guint32 version;
	gint8 client_cert_type;
	gint8 server_cert_type;
} SslSession;

/* RFC 5246, section 8.1 says that the master secret is always 48 bytes */
#define SSL_MASTER_SECRET_LENGTH		48

typedef struct _Ssl_private_key {
	gnutls_x509_crt_t	 x509_cert;
	gnutls_x509_privkey_t x509_pkey;
	SSL_PRIVATE_KEY	   *sexp_pkey;
} Ssl_private_key_t;

/* This holds state information for a SSL conversation */
typedef struct _SslDecryptSession {
	guchar _master_secret[SSL_MASTER_SECRET_LENGTH];
	guchar _session_id[256];
	guchar _client_random[32];
	guchar _server_random[32];
	StringInfo session_id;
	StringInfo session_ticket;
	StringInfo server_random;
	StringInfo client_random;
	StringInfo master_secret;
	/* the data store for this StringInfo must be allocated explicitly with a capture lifetime scope */
	StringInfo pre_master_secret;
	guchar _server_data_for_iv[24];
	StringInfo server_data_for_iv;
	guchar _client_data_for_iv[24];
	StringInfo client_data_for_iv;

	gint state;
	SslCipherSuite cipher_suite;
	SslDecoder *server;
	SslDecoder *client;
	SslDecoder *server_new;
	SslDecoder *client_new;
	SSL_PRIVATE_KEY* private_key;
	Ssl_private_key_t *private_key_c;
	StringInfo psk;
	guint16 version_netorder;
	StringInfo app_data_segment;  
	SslSession session;		   

	unsigned int srv_addr2;
	address srv_addr;			 
	port_type srv_ptype;		  
	guint srv_port;

} SslDecryptSession;

typedef struct _packet_info {
	port_type ptype;				  /**< type of the following two port numbers */
	guint32 srcport;				  /**< source port */
	guint32 destport;				 /**< destination port */
	address net_src;				  /**< network-layer source address */
	address net_dst;				  /**< network-layer destination address */
	address src;					  /**< source address (net if present, DL otherwise )*/
	address dst;					  /**< destination address (net if present, DL otherwise )*/
	unsigned int src2;
	unsigned int dst2;
	vector<string> *decrypt_vec;

	int vetsion;
} packet_info;


typedef struct _value_string {
	guint32	  value;
	const gchar *strptr;
} value_string;
typedef struct _value_string_ext value_string_ext;
typedef const value_string *(*_value_string_match2_t)(const guint32, value_string_ext*);

struct _value_string_ext {
	_value_string_match2_t _vs_match2;
	guint32				_vs_first_value; /* first value of the value_string array	   */
	guint				  _vs_num_entries; /* number of entries in the value_string array */
											/*  (excluding final {0, NULL})				*/
	const value_string	*_vs_p;		   /* the value string array address			  */
	const gchar		   *_vs_name;		/* vse "Name" (for error messages)			 */
};
/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr, and sets "*idx" to the index in
   that table, on a match, and returns NULL, and sets "*idx" to -1,
   on failure. */
const gchar *
try_val_to_str_idx(const guint32 val, const value_string *vs, gint *idx)
{
	gint i = 0;

	if(idx == NULL) return NULL;
	//DISSECTOR_ASSERT(idx != NULL);

	if(vs) {
		while (vs[i].strptr) {
			if (vs[i].value == val) {
				*idx = i;
				return(vs[i].strptr);
			}
			i++;
		}
	}

	*idx = -1;
	return NULL;
}   
/* Like try_val_to_str_idx for extended value strings */
const gchar *
try_val_to_str_idx_ext(const guint32 val, value_string_ext *vse, gint *idx)
{   
	if (vse) {
		const value_string *vs = vse->_vs_match2(val, vse);
		if (vs) {
			*idx = (gint) (vs - vse->_vs_p);
			return vs->strptr;
		}
	}
	*idx = -1;
	return NULL;
}
/* Like try_val_to_str_idx(), but doesn't return the index. */
const gchar *
try_val_to_str(const guint32 val, const value_string *vs)
{
	gint ignore_me;
	return try_val_to_str_idx(val, vs, &ignore_me);
}   
/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr on a match.
   Returns 'unknown_str', on failure. */
const gchar *
val_to_str_const(const guint32 val, const value_string *vs,
		const char *unknown_str)
{	   
	const gchar *ret;
	
	if(unknown_str == NULL) return NULL;
//	DISSECTOR_ASSERT(unknown_str != NULL);
	
	ret = try_val_to_str(val, vs);
	if (ret != NULL)
		return ret;
		
	return unknown_str;
}


const value_string ssl_31_content_type[] = {  
	{ 20, "Change Cipher Spec" },  
	{ 21, "Alert" },  
	{ 22, "Handshake" },  
	{ 23, "Application Data" },  
	{ 24, "Heartbeat" },  
	{ 0x00, NULL }  
};

/** Check two addresses for equality.
 *
 * Given two addresses, return "true" if they're equal, "false" otherwise.
 * Addresses are equal only if they have the same type; if the type is
 * AT_NONE, they are then equal, otherwise they must have the same
 * amount of data and the data must be the same.
 *
 * @param addr1 [in] The first address to compare.
 * @param addr2 [in] The second address to compare.
 * @return TRUE if the adresses are equal, FALSE otherwise.
 */
static inline gboolean
addresses_equal(const address *addr1, const address *addr2) {
	if (addr1->type == addr2->type
			&& ( addr1->type == AT_NONE
				 || ( addr1->len == addr2->len
					  && memcmp(addr1->data, addr2->data, addr1->len) == 0
					  )
				 )
			) return TRUE;
	return FALSE;
}
#define ADDRESSES_EQUAL(addr1, addr2) addresses_equal((addr1), (addr2))


/* Pointer versions of g_ntohs and g_ntohl.  Given a pointer to a member of a
 * byte array, returns the value of the two or four bytes at the pointer.
 * The pletohXX versions return the little-endian representation.
 */

#define pntoh16(p)  ((guint16)					   \
					 ((guint16)*((const guint8 *)(p)+0)<<8|  \
					  (guint16)*((const guint8 *)(p)+1)<<0))
	   
#define pntoh24(p)  ((guint32)*((const guint8 *)(p)+0)<<16|  \
					 (guint32)*((const guint8 *)(p)+1)<<8|   \
					 (guint32)*((const guint8 *)(p)+2)<<0)

#define pntoh32(p)  ((guint32)*((const guint8 *)(p)+0)<<24|  \
					 (guint32)*((const guint8 *)(p)+1)<<16|  \
					 (guint32)*((const guint8 *)(p)+2)<<8|   \
					 (guint32)*((const guint8 *)(p)+3)<<0)

#define pntoh40(p)  ((guint64)*((const guint8 *)(p)+0)<<32|  \
					 (guint64)*((const guint8 *)(p)+1)<<24|  \
					 (guint64)*((const guint8 *)(p)+2)<<16|  \
					 (guint64)*((const guint8 *)(p)+3)<<8|   \
					 (guint64)*((const guint8 *)(p)+4)<<0)

#define pntoh48(p)  ((guint64)*((const guint8 *)(p)+0)<<40|  \
					 (guint64)*((const guint8 *)(p)+1)<<32|  \
					 (guint64)*((const guint8 *)(p)+2)<<24|  \
					 (guint64)*((const guint8 *)(p)+3)<<16|  \
					 (guint64)*((const guint8 *)(p)+4)<<8|   \
					 (guint64)*((const guint8 *)(p)+5)<<0)

#define pntoh56(p)  ((guint64)*((const guint8 *)(p)+0)<<48|  \
					 (guint64)*((const guint8 *)(p)+1)<<40|  \
					 (guint64)*((const guint8 *)(p)+2)<<32|  \
					 (guint64)*((const guint8 *)(p)+3)<<24|  \
					 (guint64)*((const guint8 *)(p)+4)<<16|  \
					 (guint64)*((const guint8 *)(p)+5)<<8|   \
					 (guint64)*((const guint8 *)(p)+6)<<0)

#define pntoh64(p)  ((guint64)*((const guint8 *)(p)+0)<<56|  \
					 (guint64)*((const guint8 *)(p)+1)<<48|  \
					 (guint64)*((const guint8 *)(p)+2)<<40|  \
					 (guint64)*((const guint8 *)(p)+3)<<32|  \
					 (guint64)*((const guint8 *)(p)+4)<<24|  \
					 (guint64)*((const guint8 *)(p)+5)<<16|  \
					 (guint64)*((const guint8 *)(p)+6)<<8|   \
					 (guint64)*((const guint8 *)(p)+7)<<0)

const value_string ssl_31_handshake_type[] = {
	{ SSL_HND_HELLO_REQUEST,	 "Hello Request" },
	{ SSL_HND_CLIENT_HELLO,	  "Client Hello" },
	{ SSL_HND_SERVER_HELLO,	  "Server Hello" },
	{ SSL_HND_HELLO_VERIFY_REQUEST, "Hello Verify Request"},
	{ SSL_HND_NEWSESSION_TICKET, "New Session Ticket" },
	{ SSL_HND_CERTIFICATE,	   "Certificate" },
	{ SSL_HND_SERVER_KEY_EXCHG,  "Server Key Exchange" },
	{ SSL_HND_CERT_REQUEST,	  "Certificate Request" },
	{ SSL_HND_SVR_HELLO_DONE,	"Server Hello Done" },
	{ SSL_HND_CERT_VERIFY,	   "Certificate Verify" },
	{ SSL_HND_CLIENT_KEY_EXCHG,  "Client Key Exchange" },
	{ SSL_HND_FINISHED,		  "Finished" },
	{ SSL_HND_CERT_URL,		  "Client Certificate URL" },
	{ SSL_HND_CERT_STATUS,	   "Certificate Status" },
	{ SSL_HND_SUPPLEMENTAL_DATA, "Supplemental Data" },
	{ SSL_HND_ENCRYPTED_EXTS,	"Encrypted Extensions" },
	{ 0x00, NULL }
};



typedef struct _SslService {
	address addr;
	guint port;
} SslService;

/* Header fields specific to DTLS. See packet-dtls.c */
typedef struct {
    gint hf_dtls_handshake_cookie_len;
    gint hf_dtls_handshake_cookie;
    
    /* Do not forget to initialize dtls_hfs to -1 in packet-dtls.c! */
} dtls_hfs_t;

#define KEX_RSA         0x10
#define KEX_DH          0x11
#define KEX_PSK         0x12
#define KEX_ECDH        0x13
#define KEX_RSA_PSK     0x14

#define ENC_DES         0x30
#define ENC_3DES        0x31
#define ENC_RC4         0x32
#define ENC_RC2         0x33
#define ENC_IDEA        0x34
#define ENC_AES         0x35
#define ENC_AES256      0x36
#define ENC_CAMELLIA128 0x37
#define ENC_CAMELLIA256 0x38
#define ENC_SEED        0x39
#define ENC_NULL        0x3A

#define DIG_MD5         0x40
#define DIG_SHA         0x41
#define DIG_SHA256      0x42
#define DIG_SHA384      0x43
#define DIG_NA          0x44 /* Not Applicable */

static SslCipherSuite cipher_suites[]={
    {0x0001,KEX_RSA,    ENC_NULL,        1,  0,  0,DIG_MD5,    MODE_STREAM},   /* TLS_RSA_WITH_NULL_MD5 */
    {0x0002,KEX_RSA,    ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_RSA_WITH_NULL_SHA */
    {0x0003,KEX_RSA,    ENC_RC4,         1,128, 40,DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT_WITH_RC4_40_MD5 */
    {0x0004,KEX_RSA,    ENC_RC4,         1,128,128,DIG_MD5,    MODE_STREAM},   /* TLS_RSA_WITH_RC4_128_MD5 */
    {0x0005,KEX_RSA,    ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_RSA_WITH_RC4_128_SHA */
    {0x0006,KEX_RSA,    ENC_RC2,         8,128, 40,DIG_MD5,    MODE_CBC   },   /* TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 */
    {0x0007,KEX_RSA,    ENC_IDEA,        8,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_IDEA_CBC_SHA */
    {0x0008,KEX_RSA,    ENC_DES,         8, 64, 40,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_EXPORT_WITH_DES40_CBC_SHA */
    {0x0009,KEX_RSA,    ENC_DES,         8, 64, 64,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_DES_CBC_SHA */
    {0x000A,KEX_RSA,    ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_3DES_EDE_CBC_SHA */
    {0x000B,KEX_DH,     ENC_DES,         8, 64, 40,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA */
    {0x000C,KEX_DH,     ENC_DES,         8, 64, 64,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_DES_CBC_SHA */
    {0x000D,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA */
    {0x000E,KEX_DH,     ENC_DES,         8, 64, 40,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA */
    {0x000F,KEX_DH,     ENC_DES,         8, 64, 64,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_DES_CBC_SHA */
    {0x0010,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA */
    {0x0011,KEX_DH,     ENC_DES,         8, 64, 40,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA */
    {0x0012,KEX_DH,     ENC_DES,         8, 64, 64,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_DES_CBC_SHA */
    {0x0013,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA */
    {0x0014,KEX_DH,     ENC_DES,         8, 64, 40,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA */
    {0x0015,KEX_DH,     ENC_DES,         8, 64, 64,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_DES_CBC_SHA */
    {0x0016,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA */
    {0x0017,KEX_DH,     ENC_RC4,         1,128, 40,DIG_MD5,    MODE_STREAM},   /* TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 */
    {0x0018,KEX_DH,     ENC_RC4,         1,128,128,DIG_MD5,    MODE_STREAM},   /* TLS_DH_anon_WITH_RC4_128_MD5 */
    {0x0019,KEX_DH,     ENC_DES,         8, 64, 40,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA */
    {0x001A,KEX_DH,     ENC_DES,         8, 64, 64,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_DES_CBC_SHA */
    {0x001B,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_3DES_EDE_CBC_SHA */
    {0x002C,KEX_PSK,    ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA */
    {0x002D,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA */
    {0x002E,KEX_RSA_PSK,ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA */
    {0x002F,KEX_RSA,    ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_AES_128_CBC_SHA */
    {0x0030,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_128_CBC_SHA */
    {0x0031,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_128_CBC_SHA */
    {0x0032,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA */
    {0x0033,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA */
    {0x0034,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_AES_128_CBC_SHA */
    {0x0035,KEX_RSA,    ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_AES_256_CBC_SHA */
    {0x0036,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_256_CBC_SHA */
    {0x0037,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_256_CBC_SHA */
    {0x0038,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA */
    {0x0039,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA */
    {0x003A,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_AES_256_CBC_SHA */
    {0x003B,KEX_RSA,    ENC_NULL,        1,  0,  0,DIG_SHA256, MODE_STREAM},   /* TLS_RSA_WITH_NULL_SHA256 */
    {0x003C,KEX_RSA,    ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_AES_128_CBC_SHA256 */
    {0x003D,KEX_RSA,    ENC_AES256,     16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_AES_256_CBC_SHA256 */
    {0x003E,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_128_CBC_SHA256 */
    {0x003F,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_128_CBC_SHA256 */
    {0x0040,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 */
    {0x0041,KEX_RSA,    ENC_CAMELLIA128,16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA */
    {0x0042,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA */
    {0x0043,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA */
    {0x0044,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA */
    {0x0045,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA */
    {0x0046,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA */
    {0x0060,KEX_RSA,    ENC_RC4,         1,128, 56,DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 */
    {0x0061,KEX_RSA,    ENC_RC2,         1,128, 56,DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 */
    {0x0062,KEX_RSA,    ENC_DES,         8, 64, 56,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA */
    {0x0063,KEX_DH,     ENC_DES,         8, 64, 56,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA */
    {0x0064,KEX_RSA,    ENC_RC4,         1,128, 56,DIG_SHA,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC4_56_SHA */
    {0x0065,KEX_DH,     ENC_RC4,         1,128, 56,DIG_SHA,    MODE_STREAM},   /* TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA */
    {0x0066,KEX_DH,     ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_DHE_DSS_WITH_RC4_128_SHA */
    {0x0067,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 */
    {0x0068,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_256_CBC_SHA256 */
    {0x0069,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_256_CBC_SHA256 */
    {0x006A,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 */
    {0x006B,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 */
    {0x006C,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_AES_128_CBC_SHA256 */
    {0x006D,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_AES_256_CBC_SHA256 */
    {0x0084,KEX_RSA,    ENC_CAMELLIA256,16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA */
    {0x0085,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA */
    {0x0086,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA */
    {0x0087,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA */
    {0x0088,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA */
    {0x0089,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA */
    {0x008A,KEX_PSK,    ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_PSK_WITH_RC4_128_SHA */
    {0x008B,KEX_PSK,    ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_PSK_WITH_3DES_EDE_CBC_SHA */
    {0x008C,KEX_PSK,    ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_PSK_WITH_AES_128_CBC_SHA */
    {0x008D,KEX_PSK,    ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_PSK_WITH_AES_256_CBC_SHA */
    {0x008E,KEX_DH,     ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_DHE_PSK_WITH_RC4_128_SHA */
    {0x008F,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA */
    {0x0090,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_128_CBC_SHA */
    {0x0091,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_256_CBC_SHA */
    {0x0092,KEX_RSA_PSK,ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_RSA_PSK_WITH_RC4_128_SHA */
    {0x0093,KEX_RSA_PSK,ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA */
    {0x0094,KEX_RSA_PSK,ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_128_CBC_SHA */
    {0x0095,KEX_RSA_PSK,ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_256_CBC_SHA */
    {0x0096,KEX_RSA,    ENC_SEED,       16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_SEED_CBC_SHA */
    {0x0097,KEX_DH,     ENC_SEED,       16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_SEED_CBC_SHA */
    {0x0098,KEX_DH,     ENC_SEED,       16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_SEED_CBC_SHA */
    {0x0099,KEX_DH,     ENC_SEED,       16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_SEED_CBC_SHA */
    {0x009A,KEX_DH,     ENC_SEED,       16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_SEED_CBC_SHA */
    {0x009B,KEX_DH,     ENC_SEED,       16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_SEED_CBC_SHA */
    {0x009C,KEX_RSA,    ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_RSA_WITH_AES_128_GCM_SHA256 */
    {0x009D,KEX_RSA,    ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_RSA_WITH_AES_256_GCM_SHA384 */
    {0x009E,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 */
    {0x009F,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 */
    {0x00A0,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_RSA_WITH_AES_128_GCM_SHA256 */
    {0x00A1,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_RSA_WITH_AES_256_GCM_SHA384 */
    {0x00A2,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 */
    {0x00A3,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 */
    {0x00A4,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_DSS_WITH_AES_128_GCM_SHA256 */
    {0x00A5,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_DSS_WITH_AES_256_GCM_SHA384 */
    {0x00A6,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_anon_WITH_AES_128_GCM_SHA256 */
    {0x00A7,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_anon_WITH_AES_256_GCM_SHA384 */
    {0x00A8,KEX_PSK,    ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_PSK_WITH_AES_128_GCM_SHA256 */
    {0x00A9,KEX_PSK,    ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_PSK_WITH_AES_256_GCM_SHA384 */
    {0x00AA,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 */
    {0x00AB,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 */
    {0x00AC,KEX_RSA_PSK,ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 */
    {0x00AD,KEX_RSA_PSK,ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 */
    {0x00AE,KEX_PSK,    ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_PSK_WITH_AES_128_CBC_SHA256 */
    {0x00AF,KEX_PSK,    ENC_AES256,     16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_PSK_WITH_AES_256_CBC_SHA384 */
    {0x00B0,KEX_PSK,    ENC_NULL,        1,  0,  0,DIG_SHA256, MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA256 */
    {0x00B1,KEX_PSK,    ENC_NULL,        1,  0,  0,DIG_SHA384, MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA384 */
    {0x00B2,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 */
    {0x00B3,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 */
    {0x00B4,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA256, MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA256 */
    {0x00B5,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA384, MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA384 */
    {0x00B6,KEX_RSA_PSK,ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 */
    {0x00B7,KEX_RSA_PSK,ENC_AES256,     16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 */
    {0x00B8,KEX_RSA_PSK,ENC_NULL,        1,  0,  0,DIG_SHA256, MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA256 */
    {0x00B9,KEX_RSA_PSK,ENC_NULL,        1,  0,  0,DIG_SHA384, MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA384 */
    {0x00BA,KEX_RSA,    ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BB,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BC,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BD,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BE,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BF,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00C0,KEX_RSA,    ENC_CAMELLIA256,16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C1,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C2,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C3,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C4,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C5,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 */
    {0xC001,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_ECDSA_WITH_NULL_SHA */
    {0xC002,KEX_DH,     ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_ECDSA_WITH_RC4_128_SHA */
    {0xC003,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA */
    {0xC004,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA */
    {0xC005,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA */
    {0xC006,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_ECDSA_WITH_NULL_SHA */
    {0xC007,KEX_DH,     ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_ECDSA_WITH_RC4_128_SHA */
    {0xC008,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA */
    {0xC009,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA */
    {0xC00A,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA */
    {0xC00B,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_RSA_WITH_NULL_SHA */
    {0xC00C,KEX_DH,     ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_RSA_WITH_RC4_128_SHA */
    {0xC00D,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA */
    {0xC00E,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA */
    {0xC00F,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_256_CBC_SHA */
    {0xC010,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_RSA_WITH_NULL_SHA */
    {0xC011,KEX_DH,     ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_RSA_WITH_RC4_128_SHA */
    {0xC012,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA */
    {0xC013,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */
    {0xC014,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */
    {0xC015,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_anon_WITH_NULL_SHA */
    {0xC016,KEX_DH,     ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_anon_WITH_RC4_128_SHA */
    {0xC017,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA */
    {0xC018,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_anon_WITH_AES_128_CBC_SHA */
    {0xC019,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_anon_WITH_AES_256_CBC_SHA */
    {0xC023,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 */
    {0xC024,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 */
    {0xC025,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 */
    {0xC026,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 */
    {0xC027,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 */
    {0xC028,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 */
    {0xC029,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 */
    {0xC02A,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 */
    {0xC02B,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
    {0xC02C,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
    {0xC02D,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 */
    {0xC02E,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 */
    {0xC02F,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
    {0xC030,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
    {0xC031,KEX_DH,     ENC_AES,         4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 */
    {0xC032,KEX_DH,     ENC_AES256,      4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 */
    {0xC033,KEX_DH,     ENC_RC4,         1,128,128,DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_RC4_128_SHA */
    {0xC034,KEX_DH,     ENC_3DES,        8,192,192,DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA */
    {0xC035,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA */
    {0xC036,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA */
    {0xC037,KEX_DH,     ENC_AES,        16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 */
    {0xC038,KEX_DH,     ENC_AES256,     16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 */
    {0xC039,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA */
    {0xC03A,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA256, MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA256 */
    {0xC03B,KEX_DH,     ENC_NULL,        1,  0,  0,DIG_SHA384, MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA384 */
    {0xC072,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC073,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC074,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC075,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC076,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC077,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC078,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC079,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC07A,KEX_RSA,    ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC07B,KEX_RSA,    ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC07C,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC07D,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC07E,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC07F,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC080,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC081,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC082,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC083,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC084,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC085,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC086,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC087,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC088,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC089,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC08A,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC08B,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC08C,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC08D,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC08E,KEX_PSK,    ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC08F,KEX_PSK,    ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC090,KEX_DH,     ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC091,KEX_DH,     ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC092,KEX_RSA_PSK,ENC_CAMELLIA128, 4,128,128,DIG_SHA256, MODE_GCM   },   /* TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC093,KEX_RSA_PSK,ENC_CAMELLIA256, 4,256,256,DIG_SHA384, MODE_GCM   },   /* TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC094,KEX_PSK,    ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC095,KEX_PSK,    ENC_CAMELLIA256,16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC096,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC097,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC098,KEX_RSA_PSK,ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC099,KEX_RSA_PSK,ENC_CAMELLIA256,16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC09A,KEX_DH,     ENC_CAMELLIA128,16,128,128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC09B,KEX_DH,     ENC_CAMELLIA256,16,256,256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC09C,KEX_RSA,    ENC_AES,         4,128,128,DIG_NA,     MODE_CCM   },   /* TLS_RSA_WITH_AES_128_CCM */
    {0xC09D,KEX_RSA,    ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM   },   /* TLS_RSA_WITH_AES_256_CCM */
    {0xC09E,KEX_DH,     ENC_AES,         4,128,128,DIG_NA,     MODE_CCM   },   /* TLS_DHE_RSA_WITH_AES_128_CCM */
    {0xC09F,KEX_DH,     ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM   },   /* TLS_DHE_RSA_WITH_AES_256_CCM */
    {0xC0A0,KEX_RSA,    ENC_AES,         4,128,128,DIG_NA,     MODE_CCM_8 },   /* TLS_RSA_WITH_AES_128_CCM_8 */
    {0xC0A1,KEX_RSA,    ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM_8 },   /* TLS_RSA_WITH_AES_256_CCM_8 */
    {0xC0A2,KEX_DH,     ENC_AES,         4,128,128,DIG_NA,     MODE_CCM_8 },   /* TLS_DHE_RSA_WITH_AES_128_CCM_8 */
    {0xC0A3,KEX_DH,     ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM_8 },   /* TLS_DHE_RSA_WITH_AES_256_CCM_8 */
    {0xC0A4,KEX_PSK,    ENC_AES,         4,128,128,DIG_NA,     MODE_CCM   },   /* TLS_PSK_WITH_AES_128_CCM */
    {0xC0A5,KEX_PSK,    ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM   },   /* TLS_PSK_WITH_AES_256_CCM */
    {0xC0A6,KEX_DH,     ENC_AES,         4,128,128,DIG_NA,     MODE_CCM   },   /* TLS_DHE_PSK_WITH_AES_128_CCM */
    {0xC0A7,KEX_DH,     ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM   },   /* TLS_DHE_PSK_WITH_AES_256_CCM */
    {0xC0A8,KEX_PSK,    ENC_AES,         4,128,128,DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_WITH_AES_128_CCM_8 */
    {0xC0A9,KEX_PSK,    ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_WITH_AES_256_CCM_8 */
    {0xC0AA,KEX_DH,     ENC_AES,         4,128,128,DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_DHE_WITH_AES_128_CCM_8 */
    {0xC0AB,KEX_DH,     ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_DHE_WITH_AES_256_CCM_8 */
    {0xC0AC,KEX_ECDH,   ENC_AES,         4,128,128,DIG_NA,     MODE_CCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM */
    {0xC0AD,KEX_ECDH,   ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CCM */
    {0xC0AE,KEX_ECDH,   ENC_AES,         4,128,128,DIG_NA,     MODE_CCM_8 },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 */
    {0xC0AF,KEX_ECDH,   ENC_AES256,      4,256,256,DIG_NA,     MODE_CCM_8 },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 */
    {-1,    0,          0,               0,  0,  0,0,          MODE_STREAM}
};


void ssl_print_data(const gchar* name, const guchar* data, size_t len);

void
ssl_print_string(const gchar* name, const StringInfo* data)
{	  
	ssl_print_data(name, data->data, data->data_len);
}

/** Map from something to a (pre-)master secret */
typedef struct {
	GHashTable *session;	/* Session ID/Ticket to master secret. It uses the
							   observation that Session IDs are 1-32 bytes and
							   tickets are much longer */
	GHashTable *crandom;	/* Client Random to master secret */
	GHashTable *pre_master; /* First 8 bytes of encrypted pre-master secret to
							   pre-master secret */
} ssl_master_key_map_t;


gint ssl_get_keyex_alg(gint cipher)
{       
    switch(cipher) {
    case 0x0001:
    case 0x0002:
    case 0x0003:
    case 0x0004:                 
    case 0x0005:                                 
    case 0x0006:                                 
    case 0x0007:
    case 0x0008:        
    case 0x0009:
    case 0x000a:        
    case 0x002f:
    case 0x0035:
    case 0x003b:
    case 0x003c:
    case 0x003d:
    case 0x0041:          
    case 0x0060:          
    case 0x0061:
    case 0x0062:
    case 0x0064:
    case 0x0084:
    case 0x0096:
    case 0x009c:
    case 0x009d:
    case 0x00ba:
    case 0x00c0:
    case 0xfefe:
    case 0xfeff:
    case 0xffe0:
    case 0xffe1:
        return KEX_RSA;
    case 0x000b:  
    case 0x000c:  
    case 0x000d:  
    case 0x000e:  
    case 0x000f:  
    case 0x0010:  
    case 0x0011:  
    case 0x0012:  
    case 0x0013:  
    case 0x0014:  
    case 0x0015:  
    case 0x0016:  
    case 0x0017:  
    case 0x0018:  
    case 0x0019:  
    case 0x001a:  
    case 0x001b:  
    case 0x002d:  
    case 0x0030:  
    case 0x0031:  
    case 0x0032:  
    case 0x0033:  
    case 0x0034:  
    case 0x0036:  
    case 0x0037:  
    case 0x0038:  
    case 0x0039:  
    case 0x003a:  
    case 0x003e:  
    case 0x003f:  
    case 0x0040:  
    case 0x0042:  
    case 0x0043:  
    case 0x0044:  
    case 0x0045:  
    case 0x0046:  
    case 0x0063:  
    case 0x0065:  
    case 0x0066:  
    case 0x0067:  
    case 0x0068:  
    case 0x0069:  
    case 0x006a:  
    case 0x006b:  
    case 0x006c:  
    case 0x006d:  
    case 0x0085:  
    case 0x0086:  
    case 0x0087:  
    case 0x0088:  
    case 0x0089:  
    case 0x008e:  
    case 0x008f:  
    case 0x0090:  
    case 0x0091:  
    case 0x0097:  
    case 0x0098:  
    case 0x0099:  
    case 0x009a:  
    case 0x009b:  
    case 0x009e:  
    case 0x009f:  
    case 0x00a0:  
    case 0x00a1:  
    case 0x00a2:  
    case 0x00a3:  
    case 0x00a4:  
    case 0x00a5:  
    case 0x00a6:  
    case 0x00a7:  
    case 0x00aa:  
    case 0x00ab:  
    case 0x00b2:  
    case 0x00b3:  
    case 0x00b4:  
    case 0x00b5:  
    case 0x00bb:  
    case 0x00bc:  
    case 0x00bd:  
    case 0x00be:  
    case 0x00bf:  
    case 0x00c1:  
    case 0x00c2:  
    case 0x00c3:  
    case 0x00c4:  
    case 0x00c5:  
        return KEX_DH;
    case 0xc001:                           
    case 0xc002:                           
    case 0xc003:                           
    case 0xc004:                           
    case 0xc005:
    case 0xc006:
    case 0xc007:
    case 0xc008:
    case 0xc009:
    case 0xc00a:
    case 0xc00b:
    case 0xc00c:
    case 0xc00d:
    case 0xc00e:
    case 0xc00f:
    case 0xc010:
    case 0xc011:
    case 0xc012:
    case 0xc013:
    case 0xc014:
    case 0xc015:
    case 0xc016:
    case 0xc017:
    case 0xc018:
    case 0xc019:
    case 0xc023:
    case 0xc024:
    case 0xc025:
    case 0xc026:
    case 0xc027:
    case 0xc028:
    case 0xc029:
    case 0xc02a:
    case 0xc02b:
    case 0xc02c:
    case 0xc02d:
    case 0xc02e:
    case 0xc02f:
    case 0xc030:
    case 0xc031:
    case 0xc032:
    case 0xc033:
    case 0xc034:
    case 0xc035:
    case 0xc036:
    case 0xc037:
    case 0xc038:
    case 0xc039:
    case 0xc03a:
    case 0xc03b:
    case 0xc0ac:
    case 0xc0ad:
    case 0xc0ae:
    case 0xc0af:
        return KEX_ECDH;
    case 0x002C:
    case 0x008A:
    case 0x008B:
    case 0x008C:
    case 0x008D:
    case 0x00A8:
    case 0x00A9:
    case 0x00AE:
    case 0x00AF:
    case 0x00B0:
    case 0x00B1:
    case 0xC064:
    case 0xC065:
    case 0xC06A:
    case 0xC06B:
    case 0xC08E:
    case 0xC08F:
    case 0xC094:
    case 0xC095:
    case 0xC0A4:
    case 0xC0A5:
    case 0xC0A8:
    case 0xC0A9:
    case 0xC0AA:
    case 0xC0AB:
        return KEX_PSK;
    case 0x002E:
    case 0x0092:
    case 0x0093:
    case 0x0094:
    case 0x0095:
    case 0x00AC:                           
    case 0x00AD:                           
    case 0x00B6:                           
    case 0x00B7:                           
    case 0x00B8:
    case 0x00B9:
    case 0xC068:
    case 0xC069:
    case 0xC06E:
    case 0xC06F:
    case 0xC092:
    case 0xC093:
    case 0xC098:
    case 0xC099:
        return KEX_RSA_PSK;
    default:
        break;
    }

    return 0;
}


int
ws_xton(char ch)
{
		switch (ch) {
				case '0': return 0;
				case '1': return 1;
				case '2': return 2;
				case '3': return 3;
				case '4': return 4;
				case '5': return 5;
				case '6': return 6;
				case '7': return 7;
				case '8': return 8;
				case '9': return 9;
				case 'a':  case 'A': return 10;
				case 'b':  case 'B': return 11;
				case 'c':  case 'C': return 12;
				case 'd':  case 'D': return 13;
				case 'e':  case 'E': return 14;
				case 'f':  case 'F': return 15;
				default: return -1;
		}
}



/* from_hex converts |hex_len| bytes of hex data from |in| and sets |*out| to
 * the result. |out->data| will be allocated using se_alloc. Returns TRUE on
 * success. */
static gboolean from_hex(StringInfo* out, const char* in, gsize hex_len) {
	gsize i;

	if (hex_len & 1)
		return FALSE;

	out->data = new FILE_LINE(32002) guchar[hex_len / 2];
	for (i = 0; i < hex_len / 2; i++) {
		int a = ws_xton(in[i*2]);
		int b = ws_xton(in[i*2 + 1]);
		if (a == -1 || b == -1) {
			delete [] out->data;
			return FALSE;
		}
		out->data[i] = a << 4 | b;
	}
	out->data_len = (guint)hex_len / 2;
	return TRUE;
}

typedef struct ssl_common_options {
	const gchar        *psk;
	const gchar        *keylog_filename;
} ssl_common_options_t;

/* Max string length for displaying byte string.  */
#define MAX_BYTE_STR_LEN		48


static inline char
low_nibble_of_octet_to_hex(guint8 oct)
{
		/* At least one version of Apple's C compiler/linker is buggy, causing
		   a complaint from the linker about the "literal C string section"
		   not ending with '\0' if we initialize a 16-element "char" array with
		   a 16-character string, the fact that initializing such an array with
		   such a string is perfectly legitimate ANSI C nonwithstanding, the 17th
		   '\0' byte in the string nonwithstanding. */
		static const gchar hex_digits[16] =
		{ '0', '1', '2', '3', '4', '5', '6', '7',
		  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
		
		return hex_digits[oct & 0xF];
}	   


static inline char *
byte_to_hex(char *out, guint32 dword)
{	  
		*out++ = low_nibble_of_octet_to_hex(dword >> 4);
		*out++ = low_nibble_of_octet_to_hex(dword);
		return out;
}

/*	 
 * This does *not* null-terminate the string.  It returns a pointer
 * to the position in the string following the last character it
 * puts there, so that the caller can either put the null terminator   
 * in or can append more stuff to the buffer.						  
 *	 
 * There needs to be at least len * 2 bytes left in the buffer.		
 */	
char * 
bytes_to_hexstr(char *out, const guint8 *ad, guint32 len)
{	  
		guint32 i;
		
		if (!ad)
			return NULL;
				//REPORT_DISSECTOR_BUG("Null pointer passed to bytes_to_hexstr()");

		for (i = 0; i < len; i++)
				out = byte_to_hex(out, ad[i]);
		return out;
}	   


gchar *
bytes_to_ep_str(const guint8 *bd, int bd_len)
{
		gchar *cur;
		gchar *cur_ptr;   
		int truncated = 0;

		if (!bd)	  
			//REPORT_DISSECTOR_BUG("Null pointer passed to bytes_to_ep_str()");
			return NULL;

		cur = new FILE_LINE(32003) gchar[MAX_BYTE_STR_LEN+3+1];
		if (bd_len <= 0) { cur[0] = '\0'; return cur; }

		if (bd_len > MAX_BYTE_STR_LEN/2) {	  /* bd_len > 24 */
				truncated = 1;
				bd_len = MAX_BYTE_STR_LEN/2;
		}

		cur_ptr = bytes_to_hexstr(cur, bd, bd_len);	 /* max MAX_BYTE_STR_LEN bytes */

		if (truncated) {
				strcpy(cur_ptr, "...");	 /* 3 bytes */
				cur_ptr += 3;
		}

		*cur_ptr = '\0';								/* 1 byte */
		return cur;			 
}

/*
 * This does *not* null-terminate the string.  It returns a pointer
 * to the position in the string following the last character it
 * puts there, so that the caller can either put the null terminator
 * in or can append more stuff to the buffer.
 *
 * There needs to be at least len * 3 - 1 bytes left in the buffer.
 */
char *
bytes_to_hexstr_punct(char *out, const guint8 *ad, guint32 len, char punct)
{
		guint32 i;

		if (!ad)
			return NULL;
				//REPORT_DISSECTOR_BUG("Null pointer passed to bytes_to_hexstr_punct()");

		out = byte_to_hex(out, ad[0]);
		for (i = 1; i < len; i++) {
				*out++ = punct;
				out = byte_to_hex(out, ad[i]);
		}
		return out;
}


/* Turn an array of bytes into a string showing the bytes in hex with
 * punct as a bytes separator.
 */
gchar *
bytes_to_ep_str_punct(const guint8 *bd, int bd_len, gchar punct)
{	  
		gchar *cur;
		gchar *cur_ptr;
		int truncated = 0;

		if (!punct)
			return bytes_to_ep_str(bd, bd_len);
	   
		cur = new FILE_LINE(32004) gchar[MAX_BYTE_STR_LEN+3+1];
		if (bd_len <= 0) { cur[0] = '\0'; return cur; }
	   
		if (bd_len > MAX_BYTE_STR_LEN/3) {	  /* bd_len > 16 */
				truncated = 1;
				bd_len = MAX_BYTE_STR_LEN/3;
		}

		cur_ptr = bytes_to_hexstr_punct(cur, bd, bd_len, punct); /* max MAX_BYTE_STR_LEN-1 bytes */
	   
		if (truncated) {
				*cur_ptr++ = punct;					 /* 1 byte */
				strcpy(cur_ptr, "...");  /* 3 bytes */
				cur_ptr += 3;
		}

		*cur_ptr = '\0';
		return cur;
}	  

#if 0
static const char *
BAGTYPE(gnutls_pkcs12_bag_type_t x) {
    switch (x) {    
        case GNUTLS_BAG_EMPTY:               return "Empty";
        case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY: return "PKCS#8 Encrypted key";
        case GNUTLS_BAG_PKCS8_KEY:           return "PKCS#8 Key";
        case GNUTLS_BAG_CERTIFICATE:         return "Certificate";
        case GNUTLS_BAG_CRL:                 return "CRL";
        case GNUTLS_BAG_ENCRYPTED:           return "Encrypted";
        case GNUTLS_BAG_UNKNOWN:             return "Unknown";
        default:                             return "<undefined>";
    }
}
#endif

static gint     
ssl_data_alloc(StringInfo* str, size_t len)
{                       
	str->data = new FILE_LINE(32005) guchar[len];
	/* the allocator can return a null pointer for a size equal to 0,
	 * and that must be allowed */
	if (len > 0 && !str->data)
		return -1;	  
	str->data_len = (guint) len;
	return 0;   
}

#define SSL_EX_NONCE_LEN_GCM    8 /* RFC 5288 - section 3 */

typedef struct {
	const gchar *name;
	gint len;
} SslDigestAlgo;

#define MAX_BLOCK_SIZE 16
#define MAX_KEY_SIZE 32


/** Hash an address into a hash value (which must already have been set).
 *
 * @param hash_val The existing hash value.
 * @param addr The address to add.
 * @return The new hash value.
 */
static inline guint
add_address_to_hash(guint hash_val, const address *addr) {
	const guint8 *hash_data = (const guint8 *)(addr)->data;
	int idx;

	for (idx = 0; idx < (addr)->len; idx++) {
		hash_val += hash_data[idx];
		hash_val += ( hash_val << 10 );
		hash_val ^= ( hash_val >> 6 );
	}
	return hash_val;	  
}
#define ADD_ADDRESS_TO_HASH(hash_val, addr) do { hash_val = add_address_to_hash(hash_val, (addr)); } while (0)

void ssl_free_key(Ssl_private_key_t* key);

class SslDecryptSessionC {
public:
        guchar _master_secret[SSL_MASTER_SECRET_LENGTH];
        guchar _session_id[256];
        guchar _client_random[32];
        guchar _server_random[32];
        StringInfo session_id;
        StringInfo session_ticket;
        StringInfo server_random;
        StringInfo client_random;
        StringInfo master_secret;
        /* the data store for this StringInfo must be allocated explicitly with a capture lifetime scope */
        StringInfo pre_master_secret;
        guchar _server_data_for_iv[24];
        StringInfo server_data_for_iv;
        guchar _client_data_for_iv[24];
        StringInfo client_data_for_iv;
       
        gint state;
        SslCipherSuite cipher_suite;
        SslDecoder *server;
        SslDecoder *client;
        SslDecoder *server_new;
        SslDecoder *client_new;
        SSL_PRIVATE_KEY* private_key;
        Ssl_private_key_t *private_key_c;
        StringInfo psk;
        guint16 version_netorder;
        StringInfo app_data_segment;
        SslSession session;
       
        unsigned int srv_addr2;
        address srv_addr;
        port_type srv_ptype;
        guint srv_port;
       
        // constructor
        SslDecryptSessionC() {
                //if(debug) printf("ssl_session_init: initializing ptr %p size %" "u\n", (void *)ssl_session, sizeof(SslDecryptSessionC));
               
                /* data_len is the part that is meaningful, not the allocated length */
		this->pre_master_secret.data = NULL;
                this->master_secret.data_len = 0;
                this->master_secret.data = this->_master_secret;
                this->session_id.data_len = 0;
                this->session_id.data = this->_session_id;
                this->client_random.data_len = 0;
                this->client_random.data = this->_client_random;
                this->server_random.data_len = 0;
                this->server_random.data = this->_server_random;
                this->session_ticket.data_len = 0;
                this->session_ticket.data = NULL; /* will be re-alloced as needed */
                this->server_data_for_iv.data_len = 0;
                this->server_data_for_iv.data = this->_server_data_for_iv;
                this->client_data_for_iv.data_len = 0;
                this->client_data_for_iv.data = this->_client_data_for_iv;
                this->app_data_segment.data = NULL;
                this->app_data_segment.data_len = 0;
               
                //SET_ADDRESS(&ssl_session->srv_addr, AT_NONE, 0, NULL);
               
                this->srv_addr2 = 0;
                this->srv_ptype = PT_NONE;
                this->srv_port = 0;
                this->state = 0;
                this->private_key = NULL;
                this->private_key_c = NULL;
                this->server = NULL;
                this->client = NULL;
                this->server_new = NULL;
                this->client_new = NULL;
                //this->cipher = 0;
                this->session.version = SSL_VER_UNKNOWN;
        }
       
        ~SslDecryptSessionC() {
		if(pre_master_secret.data) delete [] pre_master_secret.data;
                if(session_ticket.data) delete [] session_ticket.data;
                if(private_key_c) ssl_free_key(private_key_c);

		if(server_new and server_new->evp) {
			ssl_cipher_cleanup(&server_new->evp);
			delete server_new;
		}
		if(client_new and client_new->evp) {
			ssl_cipher_cleanup(&client_new->evp);
			delete client_new;
		}
		if(server and server->evp) {
			ssl_cipher_cleanup(&server->evp);
			delete server;
		}
		if(client and client->evp) {
			ssl_cipher_cleanup(&client->evp);
			delete client;
		}
        }

	void 
	ssl_set_server(address *addr, port_type ptype, guint32 port) 
	{	
		//SE_COPY_ADDRESS(&ssl->srv_addr, addr); 
		this->srv_addr2 = (unsigned int)*(unsigned int*)addr->data; 
		this->srv_ptype = ptype; 
		this->srv_port = port; 
	}	 

	SslDecoder*
	ssl_create_decoder(guint8 *mk, guint8 *sk, guint8 *iv);

	SslDecoder*
	ssl_create_decoder_client(guint8 *mk, guint8 *sk, guint8 *iv) {
		client_new = this->ssl_create_decoder(mk, sk, iv);
		return client_new;
	}

	SslDecoder*
	ssl_create_decoder_server(guint8 *mk, guint8 *sk, guint8 *iv) {
		server_new = this->ssl_create_decoder(mk, sk, iv);
		return server_new;
	}

};

struct session_t {
        SslDecryptSessionC *session;
        time_t created_at;
};


#endif

#endif //SSL_H
