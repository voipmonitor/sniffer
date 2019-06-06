#include "config.h"

#if defined(HAVE_LIBGNUTLS) and defined(HAVE_SSL_WS)

#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <map>
#include <string>
#include <iostream>
#include <unistd.h>

#include "tools.h"
#include "ssl.h"
#include "ssl-test.h"
#include "heap_safe.h"

using namespace std;
//TODO: overit ssl_decrypted_data_avail thread safe
static gint				ssl_decrypted_data_avail = 0;
static StringInfo		  ssl_decrypted_data	   = {NULL, 0};
static StringInfo		  ssl_compressed_data	  = {NULL, 0};
static GHashTable		 *ssl_key_hash			 = NULL;
static ssl_master_key_map_t	   ssl_master_key_map = {NULL, NULL, NULL};
static ssl_common_options_t ssl_options = { NULL, NULL};
extern map<vmIPport, string> ssl_ipport;
map<SslDecryptSessionC*, std::queue<string> > ssl_map_hash;
map<SslDecryptSessionC*, std::queue<string> >::iterator ssl_map_hash_it;


map<string, session_t*> sessions;
map<string, session_t*>::iterator sessions_it;

gboolean ssl_ignore_mac_failed = FALSE;

struct ssl_keys_t {
	unsigned int ip;
	int port;
	string filename;
	
};
std::vector<ssl_keys_t*> ssl_keys;


#define debug (sverb.ssldecode_debug)


string
find_ssl_keys(unsigned int ip1, int port1, unsigned int ip2, int port2) {
	for(std::vector<ssl_keys_t*>::iterator it = ssl_keys.begin(); it != ssl_keys.end(); ++it) {
		if((port1 == (*it)->port && ip1 == (*it)->ip) || (port2 == (*it)->port && ip2 == (*it)->ip)) {
			return (*it)->filename;
		}
	}
	return "";
}

/* we keep this internal to packet-ssl-utils, as there should be
   no need to access it any other way.

   This also allows us to hide the dependency on zlib.
*/
struct _SslDecompress {
	gint compression;
	z_stream istream;
};

static const gchar *ciphers[]={
	"DES",
	"3DES",
	"ARCFOUR", /* libgcrypt does not support rc4, but this should be 100% compatible*/
	"RFC2268_128", /* libgcrypt name for RC2 with a 128-bit key */
	"IDEA",
	"AES",
	"AES256",
	"CAMELLIA128",
	"CAMELLIA256",
	"SEED",
	"*UNKNOWN*"
};

static const SslDigestAlgo digests[]={
	{"MD5",	 16},
	{"SHA1",	20},
	{"SHA256",  32},
	{"SHA384",  48},
	{"Not Applicable",  0},
};
/* stream cipher abstraction layer*/
static gint
ssl_cipher_init(gcry_cipher_hd_t *cipher, gint algo, guchar* sk,
		guchar* iv, gint mode)
{	  
	gint gcry_modes[]={GCRY_CIPHER_MODE_STREAM,GCRY_CIPHER_MODE_CBC,GCRY_CIPHER_MODE_CTR,GCRY_CIPHER_MODE_CTR,GCRY_CIPHER_MODE_CTR};
	gint err;
	if (algo == -1) {
		/* NULL mode */
		*(cipher) = (gcry_cipher_hd_t)-1;
		return 0;
	}		  
	err = gcry_cipher_open(cipher, algo, gcry_modes[mode], 0);
	if (err !=0)
		return  -1;
	err = gcry_cipher_setkey(*(cipher), sk, gcry_cipher_get_algo_keylen (algo));
	if (err != 0)
		return -1;
	err = gcry_cipher_setiv(*(cipher), iv, gcry_cipher_get_algo_blklen (algo));
	if (err != 0)
		return -1;
	return 0;
}	  

static inline gint
ssl_get_digest_by_name(const gchar*name)
{	   
	return gcry_md_map_name(name);
}			  
static inline gint
ssl_get_cipher_by_name(const gchar* name)
{			  
	return gcry_cipher_map_name(name);
}			  
static void
ssl_cipher_cleanup(gcry_cipher_hd_t *cipher)
{	  
	if ((*cipher) != (gcry_cipher_hd_t)-1)
		gcry_cipher_close(*cipher);
	*cipher = NULL;
}
static inline gint
ssl_cipher_decrypt(gcry_cipher_hd_t *cipher, guchar * out, gint outl,
				   const guchar * in, gint inl)
{
	if ((*cipher) == (gcry_cipher_hd_t)-1)
	{  
		if (in && inl)
			memcpy(out, in, outl < inl ? outl : inl);
		return 0;
	}
	return gcry_cipher_decrypt ( *(cipher), out, outl, in, inl);
}

#define SSL_MD gcry_md_hd_t

static inline gint
ssl_md_init(SSL_MD* md, gint algo)
{	   
	gcry_error_t  err;
	const char   *err_str, *err_src;
	err = gcry_md_open(md,algo, 0);
	if (err != 0) {
		err_str = gcry_strerror(err);
		err_src = gcry_strsource(err);
		if (debug) printf("ssl_md_init(): gcry_md_open failed %s/%s", err_str, err_src);
		return -1;
	}   
	return 0;
}	   
static inline void
ssl_md_update(SSL_MD* md, guchar* data, gint len)
{	   
	gcry_md_write(*(md), data, len);
}	   
static inline void
ssl_md_final(SSL_MD* md, guchar* data, guint* datalen)
{	   
	gint algo;
	gint len;
	algo = gcry_md_get_algo (*(md));
	len = gcry_md_get_algo_dlen (algo);
	memcpy(data, gcry_md_read(*(md),  algo), len);
	*datalen = len;
}	   
static inline void
ssl_md_cleanup(SSL_MD* md)
{	   
	gcry_md_close(*(md));
}	   

/* memory allocation functions for zlib initialization */
static void* ssl_zalloc(void* /*opaque*/, unsigned int no, unsigned int size)
{   
	return(new FILE_LINE(31001) guchar[no*size]);
}
static void ssl_zfree(void* /*opaque*/, void* addr)
{	   
	delete [] ((guchar*)addr);
}	  

static SslDecompress*
ssl_create_decompressor(gint compression)
{
	SslDecompress *decomp;
	int err;

	if (compression == 0) return NULL;
	if (debug) printf("ssl_create_decompressor: compression method %d\n", compression);
	decomp = new FILE_LINE(31002) SslDecompress;
	memset(decomp, 0, sizeof(SslDecompress));
	decomp->compression = compression;
	switch (decomp->compression) {
		case 1:  /* DEFLATE */
			decomp->istream.zalloc = ssl_zalloc;
			decomp->istream.zfree = ssl_zfree;
			decomp->istream.opaque = Z_NULL;
			decomp->istream.next_in = Z_NULL;
			decomp->istream.next_out = Z_NULL;
			decomp->istream.avail_in = 0;
			decomp->istream.avail_out = 0;
			err = inflateInit_(&decomp->istream, ZLIB_VERSION, sizeof(z_stream));
			if (err != Z_OK) {
				if (debug) printf("ssl_create_decompressor: inflateInit_() failed - %d\n", err);
				return NULL;
			}
			break;
		default:
			if (debug) printf("ssl_create_decompressor: unsupported compression method %d\n", decomp->compression);
			return NULL;
	}   
	return decomp;
}   

#define DIGEST_MAX_SIZE 48
/* get index digest index */
static const SslDigestAlgo *
ssl_cipher_suite_dig(SslCipherSuite *cs) {
	return &digests[cs->dig - DIG_MD5];
}

/* convert network byte order 32 byte number to right-aligned host byte order *
 * 8 bytes buffer */
static gint fmt_seq(guint32 num, guint8* buf)
{
	guint32 netnum;

	memset(buf,0,8);
	netnum=htonl(num);
	memcpy(buf+4,&netnum,4);
	
	return(0);				  
}			
	
static int
ssl3_check_mac(SslDecoder*decoder,int ct,guint8* data,
		guint32 datalen, guint8* mac)
{
	SSL_MD  mc;
	gint	md;
	guint32 len;
	guint8  buf[64],dgst[20];
	gint	pad_ct;
	gint16  temp;

	pad_ct=(decoder->cipher_suite->dig==DIG_SHA)?40:48;

	/* get cipher used for digest comptuation */
	md=ssl_get_digest_by_name(ssl_cipher_suite_dig(decoder->cipher_suite)->name);
	if (ssl_md_init(&mc,md) !=0)
		return -1;

	/* do hash computation on data && padding */
	ssl_md_update(&mc,decoder->mac_key.data,decoder->mac_key.data_len);

	/* hash padding*/
	memset(buf,0x36,pad_ct);
	ssl_md_update(&mc,buf,pad_ct); 

	/* hash sequence number */
	fmt_seq(decoder->seq,buf);
	decoder->seq++;
	ssl_md_update(&mc,buf,8);

	/* hash content type */
	buf[0]=ct;
	ssl_md_update(&mc,buf,1);

	/* hash data length in network byte order and data*/
	/* *((gint16* )buf) = g_htons(datalen); */
	temp = htons(datalen);
	memcpy(buf, &temp, 2);
	ssl_md_update(&mc,buf,2);
	ssl_md_update(&mc,data,datalen);

	/* get partial digest */
	ssl_md_final(&mc,dgst,&len);
	ssl_md_cleanup(&mc);

	ssl_md_init(&mc,md);

	/* hash mac key */
	ssl_md_update(&mc,decoder->mac_key.data,decoder->mac_key.data_len);

	/* hash padding and partial digest*/
	memset(buf,0x5c,pad_ct);
	ssl_md_update(&mc,buf,pad_ct);
	ssl_md_update(&mc,dgst,len);
   
	ssl_md_final(&mc,dgst,&len);
	ssl_md_cleanup(&mc);
   
	if(memcmp(mac,dgst,len))
		return -1;
	   
	return(0);
}  

int
ssl_packet_from_server(SslDecryptSessionC *ssl, packet_info *pinfo)
{	  

	gint ret = 0;
	if (ssl && (ssl->srv_ptype != PT_NONE)) {
		ret = (ssl->srv_ptype == pinfo->ptype) && (ssl->srv_port == pinfo->srcport) && (ssl->srv_addr2 == pinfo->src2);
	} else {
		for(std::vector<ssl_keys_t*>::iterator it = ssl_keys.begin(); it != ssl_keys.end(); ++it) {
			if((unsigned int)pinfo->srcport == (unsigned int)(*it)->port && (unsigned int)pinfo->src2 == (unsigned int)(*it)->ip) {
				ret = 1;
				break;
			}
		}
	}

	if(debug) printf("packet_from_server: is from server - %s [srcport:%u]\n", (ret)?"TRUE":"FALSE", pinfo->srcport);
	return ret;
}


/* get ssl data for this session. if no ssl data is found allocate a new one*/
void
ssl_session_init(SslDecryptSession* ssl_session)
{
	if(debug) printf("ssl_session_init: initializing ptr %p size %lu" "u\n",
					 (void *)ssl_session, sizeof(SslDecryptSession));
	
	/* data_len is the part that is meaningful, not the allocated length */
	ssl_session->master_secret.data_len = 0;
	ssl_session->master_secret.data = ssl_session->_master_secret;
	ssl_session->session_id.data_len = 0;
	ssl_session->session_id.data = ssl_session->_session_id;
	ssl_session->client_random.data_len = 0;
	ssl_session->client_random.data = ssl_session->_client_random;
	ssl_session->server_random.data_len = 0;
	ssl_session->server_random.data = ssl_session->_server_random;
	ssl_session->session_ticket.data_len = 0;
	ssl_session->session_ticket.data = NULL; /* will be re-alloced as needed */
	ssl_session->server_data_for_iv.data_len = 0;
	ssl_session->server_data_for_iv.data = ssl_session->_server_data_for_iv;
	ssl_session->client_data_for_iv.data_len = 0;
	ssl_session->client_data_for_iv.data = ssl_session->_client_data_for_iv;
	ssl_session->app_data_segment.data = NULL;
	ssl_session->app_data_segment.data_len = 0;

	//SET_ADDRESS(&ssl_session->srv_addr, AT_NONE, 0, NULL);
	
	ssl_session->srv_addr2 = 0;
	ssl_session->srv_ptype = PT_NONE;
	ssl_session->srv_port = 0;
	ssl_session->state = 0;
	ssl_session->private_key = NULL;
	ssl_session->private_key_c = NULL;
	ssl_session->server = NULL;
	ssl_session->client = NULL;
//	ssl_session->cipher = 0;
}		   

bool
ssl_is_valid_content_type(uint8_t type)
{
	switch ((ContentType) type) {
	case SSL_ID_CHG_CIPHER_SPEC:
	case SSL_ID_ALERT:
	case SSL_ID_HANDSHAKE:
	case SSL_ID_APP_DATA:
	case SSL_ID_HEARTBEAT:
		return true;	 
	}
	return false;
}

						
/* this applies a heuristic to determine whether
 * or not the data beginning at offset looks like a
 * valid sslv2 record.  this isn't really possible,
 * but we'll try to do a reasonable job anyway.
 */
static gint
ssl_looks_like_sslv2(char *data, const guint32 offset)
{   
	/* here's the current approach:
	 *
	 * we only try to catch unencrypted handshake messages, so we can
	 * assume that there is not padding.  This means that the
	 * first byte must be >= 0x80 and there must be a valid sslv2
	 * msg_type in the third byte
	 */ 
		
	/* get the first byte; must have high bit set */
	guint8 byte;
	byte = (guint8)*(data + offset);	  
		
	if (byte < 0x80)
	{   
		return 0;
	}   
		
	/* get the supposed msg_type byte; since we only care about
	 * unencrypted handshake messages (we can't tell the type for
	 * encrypted messages), we just check against that list
	 */		 
	byte = (guint8)*(data + offset + 2);	  
	switch (byte) {
	case SSL2_HND_ERROR:
	case SSL2_HND_CLIENT_HELLO:
	case SSL2_HND_CLIENT_MASTER_KEY:
	case SSL2_HND_SERVER_HELLO:
	case PCT_MSG_CLIENT_MASTER_KEY:
	case PCT_MSG_ERROR:
		return 1;
	}		   
	return 0;   
}	   


/* this applies a heuristic to determine whether
 * or not the data beginning at offset looks like a
 * valid sslv3 record.  this is somewhat more reliable
 * than sslv2 due to the structure of the v3 protocol
 */		 
static gint 
ssl_looks_like_sslv3(char *data, const guint32 offset)
{		   
	/* have to have a valid content type followed by a valid
	 * protocol version
	 */ 
	guint8 byte;
	guint16 version;
				
	/* see if the first byte is a valid content type */
	byte = (guint8)*(data + offset);	  
	if (!ssl_is_valid_content_type(byte))	
	{										
		return 0;							
	}	   
			
	/* now check to see if the version byte appears valid */
	version = pntoh16(data + offset + 1);
	switch (version) {
	case SSLV3_VERSION:					  
	case TLSV1_VERSION:					  
	case TLSV1DOT1_VERSION:				  
	case TLSV1DOT2_VERSION:				  
		return 1;
	}	   
	return 0;
}			   

gboolean
ssl_is_valid_handshake_type(guint8 hs_type, gboolean is_dtls)
{
	switch ((HandshakeType) hs_type) {
	case SSL_HND_HELLO_VERIFY_REQUEST:
		/* hello_verify_request is DTLS-only */
		return is_dtls;
		
	case SSL_HND_HELLO_REQUEST:
	case SSL_HND_CLIENT_HELLO:
	case SSL_HND_SERVER_HELLO:
	case SSL_HND_NEWSESSION_TICKET:
	case SSL_HND_CERTIFICATE:
	case SSL_HND_SERVER_KEY_EXCHG:
	case SSL_HND_CERT_REQUEST:
	case SSL_HND_SVR_HELLO_DONE:
	case SSL_HND_CERT_VERIFY:
	case SSL_HND_CLIENT_KEY_EXCHG:
	case SSL_HND_FINISHED:
	case SSL_HND_CERT_URL:
	case SSL_HND_CERT_STATUS:
	case SSL_HND_SUPPLEMENTAL_DATA:
	case SSL_HND_ENCRYPTED_EXTS:
		return true;
	}   
	return false;
}   


static gint
ssl_is_authoritative_version_message(const guint8 content_type, const guint8 next_byte){		   
	if (content_type == SSL_ID_HANDSHAKE && ssl_is_valid_handshake_type(next_byte, false)) {	   
		return (next_byte != SSL_HND_CLIENT_HELLO);
	} else if (ssl_is_valid_content_type(content_type) && content_type != SSL_ID_HANDSHAKE){		   
		return 1;
	}
	return 0;   
}


/*********************************************************************
 *
 * SSL version 3 and TLS Dissection Routines
 *
 *********************************************************************/

void													   
ssl_data_set(StringInfo* str, const guchar* data, guint len)
{
	if(!data) return;
	//DISSECTOR_ASSERT(data);
	memcpy(str->data, data, len);
	str->data_len = len;
}

/* stringinfo interface */
static gint
ssl_data_realloc(StringInfo* str, guint len)
{		   
	guchar *newdata = new FILE_LINE(31003) guchar[len];
	if(!newdata)
		return -1;
	if(str->data) {
		memcpy(newdata, str->data, str->data_len);
		delete [] str->data;
	}
	str->data = newdata;
	str->data_len = len;
	return 0;
}		  


#define SSL_HMAC gcry_md_hd_t
static inline gint
ssl_hmac_init(SSL_HMAC* md, const void * key, gint len, gint algo)
{	   
	gcry_error_t  err;
	const char   *err_str, *err_src;
				
	err = gcry_md_open(md,algo, GCRY_MD_FLAG_HMAC);
	if (err != 0) {
		err_str = gcry_strerror(err);
		err_src = gcry_strsource(err);
		if (debug) printf("ssl_hmac_init(): gcry_md_open failed %s/%s", err_str, err_src);
		return -1;
	}
	gcry_md_setkey (*(md), key, len);
	return 0;
}
static inline void
ssl_hmac_update(SSL_HMAC* md, const void* data, gint len)
{	   
	gcry_md_write(*(md), data, len);
}	   
static inline void
ssl_hmac_final(SSL_HMAC* md, guchar* data, guint* datalen)
{   
	gint  algo;
	guint len;
		
	algo = gcry_md_get_algo (*(md));
	len  = gcry_md_get_algo_dlen(algo);
	if(!(len <= *datalen)) return;
//	DISSECTOR_ASSERT(len <= *datalen);
	memcpy(data, gcry_md_read(*(md), algo), len);
	*datalen = len;
}	   
static inline void
ssl_hmac_cleanup(SSL_HMAC* md)
{   
	gcry_md_close(*(md));
}	   

static gint
tls_check_mac(SslDecoder*decoder, gint ct, gint ver, guint8* data,
		guint32 datalen, guint8* mac)
{   
	SSL_HMAC hm;
	gint	 md;
	guint32  len;
	guint8   buf[DIGEST_MAX_SIZE];
	gint16   temp;
				
	md=ssl_get_digest_by_name(ssl_cipher_suite_dig(decoder->cipher_suite)->name);
	if (debug) printf("tls_check_mac mac type:%s md %d\n",
		ssl_cipher_suite_dig(decoder->cipher_suite)->name, md);
				
	if (ssl_hmac_init(&hm,decoder->mac_key.data,decoder->mac_key.data_len,md) != 0)
		return -1; 
								
	/* hash sequence number */  
	fmt_seq(decoder->seq,buf);

	decoder->seq++;

	ssl_hmac_update(&hm,buf,8);
								
	/* hash content type */	 
	buf[0]=ct;  
	ssl_hmac_update(&hm,buf,1);
				
	/* hash version,data length and data*/
	/* *((gint16*)buf) = g_htons(ver); */
	temp = htons(ver);
	memcpy(buf, &temp, 2);
	ssl_hmac_update(&hm,buf,2);
	
	/* *((gint16*)buf) = g_htons(datalen); */
	temp = htons(datalen);
	memcpy(buf, &temp, 2);
	ssl_hmac_update(&hm,buf,2);
	ssl_hmac_update(&hm,data,datalen);	   
		
	/* get digest and digest len*/		   
	len = sizeof(buf);					   
	ssl_hmac_final(&hm,buf,&len);
	ssl_hmac_cleanup(&hm);
	ssl_print_data("Mac", buf, len);
	if(memcmp(mac,buf,len))
		return -1;

	return 0;
}	   

static int
ssl_decompress_record(SslDecompress* decomp, const guchar* in, guint inl, StringInfo* out_str, guint* outl)
{			   
	gint err;

	switch (decomp->compression) {
		case 1:  /* DEFLATE */
			err = Z_OK;
			if (out_str->data_len < 16384) {  /* maximal plain length */
				ssl_data_realloc(out_str, 16384);
			}
			decomp->istream.next_in = (guchar*)in;
			decomp->istream.avail_in = inl;
			decomp->istream.next_out = out_str->data;
			decomp->istream.avail_out = out_str->data_len;
			if (inl > 0) 
				err = inflate(&decomp->istream, Z_SYNC_FLUSH);
			if (err != Z_OK) {
				if (debug) printf("ssl_decompress_record: inflate() failed - %d\n", err);
				return -1;
			}
			*outl = out_str->data_len - decomp->istream.avail_out;
			break;
		default:
			if (debug) printf("ssl_decompress_record: unsupported compression method %d\n", decomp->compression);
			return -1;
	}
	return 0;
}


static gint
ssl_data_copy(StringInfo* dst, StringInfo* src)
{	  
	if (dst->data_len < src->data_len) {
	  if (ssl_data_realloc(dst, src->data_len))
		return -1;
	}
	memcpy(dst->data, src->data, src->data_len);
	dst->data_len = src->data_len;
	return 0;
}


static gint
dtls_check_mac(SslDecoder*decoder, gint ct,int ver, guint8* data,
		guint32 datalen, guint8* mac)
{	  
	SSL_HMAC hm;
	gint	 md;
	guint32  len;
	guint8   buf[DIGEST_MAX_SIZE];
	gint16   temp;

	md=ssl_get_digest_by_name(ssl_cipher_suite_dig(decoder->cipher_suite)->name);
	if (debug) printf("dtls_check_mac mac type:%s md %d\n",
		ssl_cipher_suite_dig(decoder->cipher_suite)->name, md);
			   
	if (ssl_hmac_init(&hm,decoder->mac_key.data,decoder->mac_key.data_len,md) != 0)
		return -1;
	if (debug) printf("dtls_check_mac seq: %d epoch: %d\n",decoder->seq,decoder->epoch);
	/* hash sequence number */
	fmt_seq(decoder->seq,buf);
	buf[0]=decoder->epoch>>8;
	buf[1]=(guint8)decoder->epoch;
	   
	ssl_hmac_update(&hm,buf,8);
			   
	/* hash content type */
	buf[0]=ct;
	ssl_hmac_update(&hm,buf,1);

	/* hash version,data length and data */
	temp = htons(ver);
	memcpy(buf, &temp, 2);
	ssl_hmac_update(&hm,buf,2);

	temp = htons(datalen);
	memcpy(buf, &temp, 2);
	ssl_hmac_update(&hm,buf,2);
	ssl_hmac_update(&hm,data,datalen);
	/* get digest and digest len */
	len = sizeof(buf);
	ssl_hmac_final(&hm,buf,&len);
	ssl_hmac_cleanup(&hm);
	ssl_print_data("Mac", buf, len);
	if(memcmp(mac,buf,len))
		return -1;
	   
	return(0);
}	  

int
ssl_decrypt_record(SslDecryptSessionC *ssl,SslDecoder* decoder, gint ct, const guchar* in, guint inl, StringInfo* comp_str, StringInfo* out_str, guint* outl)
{
	guint   pad, worklen, uncomplen;
	guint8 *mac;

	if (debug) printf("ssl_decrypt_record ciphertext len %d\n", inl);
	ssl_print_data("Ciphertext",in, inl);

	/* ensure we have enough storage space for decrypted data */
	if (inl > out_str->data_len)
	{  
		if (debug) printf("ssl_decrypt_record: allocating %d bytes for decrypt data (old len %d)\n",
				inl + 32, out_str->data_len);
		ssl_data_realloc(out_str, inl + 32);
	}

	/* RFC 6101/2246: SSLCipherText/TLSCipherText has two structures for types:
	 * (notation: { unencrypted, [ encrypted ] })
	 * GenericStreamCipher: { [content, mac] }
	 * GenericBlockCipher: { IV (TLS 1.1+), [content, mac, padding, padding_len] }
	 * RFC 5426 (TLS 1.2): TLSCipherText has additionally:
	 * GenericAEADCipher: { nonce_explicit, [content] }
	 * RFC 4347 (DTLS): based on TLS 1.1, only GenericBlockCipher is supported.
	 * RFC 6347 (DTLS 1.2): based on TLS 1.2, includes GenericAEADCipher too.
	 */

	/* (TLS 1.1 and later, DTLS) Extract explicit IV for GenericBlockCipher */
	if (decoder->cipher_suite->mode == MODE_CBC) {
		switch (ssl->version_netorder) {
		case TLSV1DOT1_VERSION:
		case TLSV1DOT2_VERSION:
		case DTLSV1DOT0_VERSION:
		case DTLSV1DOT2_VERSION:
		case DTLSV1DOT0_VERSION_NOT:
			if ((gint)inl < decoder->cipher_suite->block) {
				if (debug) printf("ssl_decrypt_record failed: input %d has no space for IV %d\n",
						inl, decoder->cipher_suite->block);
				return -1;
			}
			pad = gcry_cipher_setiv(decoder->evp, in, decoder->cipher_suite->block);
			if (pad != 0) {
				if (debug) printf("ssl_decrypt_record failed: failed to set IV: %s %s\n",
						gcry_strsource (pad), gcry_strerror (pad));
			}

			inl -= decoder->cipher_suite->block;
			in += decoder->cipher_suite->block;
			break;
		}
	}

	/* Nonce for GenericAEADCipher */
	if (decoder->cipher_suite->mode == MODE_GCM ||
		decoder->cipher_suite->mode == MODE_CCM ||
		decoder->cipher_suite->mode == MODE_CCM_8) {
		/* 4 bytes write_iv, 8 bytes explicit_nonce, 4 bytes counter */
		guchar gcm_nonce[16] = { 0 };

		if ((gint)inl < SSL_EX_NONCE_LEN_GCM) {
			if (debug) printf("ssl_decrypt_record failed: input %d has no space for nonce %d\n",
				inl, SSL_EX_NONCE_LEN_GCM);
			return -1;
		}

		if (decoder->cipher_suite->mode == MODE_GCM) {
			memcpy(gcm_nonce, decoder->write_iv.data, decoder->write_iv.data_len); /* salt */
			memcpy(gcm_nonce + decoder->write_iv.data_len, in, SSL_EX_NONCE_LEN_GCM);
			/* NIST SP 800-38D, sect. 7.2 says that the 32-bit counter part starts
			 * at 1, and gets incremented before passing to the block cipher. */
			gcm_nonce[4 + SSL_EX_NONCE_LEN_GCM + 3] = 2;
		} else { /* MODE_CCM and MODE_CCM_8 */
			/* The nonce for CCM and GCM are the same, but the nonce is used as input
			 * in the CCM algorithm described in RFC 3610. The nonce generated here is
			 * the one from RFC 3610 sect 2.3. Encryption. */
			/* Flags: (L-1) ; L = 16 - 1 - nonceSize */
			gcm_nonce[0] = 3 - 1;

			memcpy(gcm_nonce + 1, decoder->write_iv.data, decoder->write_iv.data_len); /* salt */
			memcpy(gcm_nonce + 1 + decoder->write_iv.data_len, in, SSL_EX_NONCE_LEN_GCM);
			gcm_nonce[4 + SSL_EX_NONCE_LEN_GCM + 3] = 1;
		}

		pad = gcry_cipher_setctr (decoder->evp, gcm_nonce, sizeof (gcm_nonce));
		if (pad != 0) {
			if (debug) printf("ssl_decrypt_record failed: failed to set CTR: %s %s\n",
					gcry_strsource (pad), gcry_strerror (pad));
			return -1;
		}
		inl -= SSL_EX_NONCE_LEN_GCM;
		in += SSL_EX_NONCE_LEN_GCM;
	}

	/* First decrypt*/
	if ((pad = ssl_cipher_decrypt(&decoder->evp, out_str->data, out_str->data_len, in, inl))!= 0) {
		if (debug) printf("ssl_decrypt_record failed: ssl_cipher_decrypt: %s %s\n", gcry_strsource (pad),
					gcry_strerror (pad));
		return -1;
	}

	ssl_print_data("Plaintext", out_str->data, inl);
	worklen=inl;

	/* RFC 5116 sect 5.1/5.3: AES128/256 GCM/CCM uses 16 bytes for auth tag
	 * RFC 6655 sect 6.1: AEAD_AES_128_CCM uses 16 bytes for auth tag */
	if (decoder->cipher_suite->mode == MODE_GCM ||
		decoder->cipher_suite->mode == MODE_CCM) {
		if (worklen < 16) {
			if (debug) printf("ssl_decrypt_record failed: missing tag, work %d\n", worklen);
			return -1;
		}
		/* XXX - validate auth tag */
		worklen -= 16;
	}
	/* RFC 6655 sect 6.1: AEAD_AES_128_CCM_8 uses 8 bytes for auth tag */
	if (decoder->cipher_suite->mode == MODE_CCM_8) {
		if (worklen < 8) {
			if (debug) printf("ssl_decrypt_record failed: missing tag, work %d\n", worklen);
			return -1;
		}
		/* XXX - validate auth tag */
		worklen -= 8;
	}

	/* strip padding for GenericBlockCipher */
	if (decoder->cipher_suite->mode == MODE_CBC) {
		pad=out_str->data[inl-1];
		if (worklen <= pad) {
			if (debug) printf("ssl_decrypt_record failed: padding %d too large for work %d\n",
				pad, worklen);
			return -1;
		}
		worklen-=(pad+1);
		if (debug) printf("ssl_decrypt_record found padding %d final len %d\n",
			pad, worklen);
	}

	/* MAC for GenericStreamCipher and GenericBlockCipher */
	if (decoder->cipher_suite->mode == MODE_STREAM ||
		decoder->cipher_suite->mode == MODE_CBC) {
		if (ssl_cipher_suite_dig(decoder->cipher_suite)->len > (gint)worklen) {
			if (debug) printf("ssl_decrypt_record wrong record len/padding outlen %d\n work %d\n",*outl, worklen);
			return -1;
		}
		worklen-=ssl_cipher_suite_dig(decoder->cipher_suite)->len;
		mac = out_str->data + worklen;
	} else /* if (decoder->cipher_suite->mode == MODE_GCM) */ {
		/* GenericAEADCipher has no MAC */
		goto skip_mac;
	}

	/* Now check the MAC */
	if (debug) printf("checking mac (len %d, version %X, ct %d seq %d)\n",
		worklen, ssl->version_netorder, ct, decoder->seq);
	if(ssl->version_netorder==SSLV3_VERSION){
		if(ssl3_check_mac(decoder,ct,out_str->data,worklen,mac) < 0) {
			if(ssl_ignore_mac_failed) {
				if (debug) printf("ssl_decrypt_record: mac failed, but ignored for troubleshooting ;-)\n");
			}
			else{
				if (debug) printf("ssl_decrypt_record: mac failed\n");
				return -1;
			}
		}
		else{
			if (debug) printf("ssl_decrypt_record: mac ok\n");
		}
	}
	else if(ssl->version_netorder==TLSV1_VERSION || ssl->version_netorder==TLSV1DOT1_VERSION || ssl->version_netorder==TLSV1DOT2_VERSION){
		if(tls_check_mac(decoder,ct,ssl->version_netorder,out_str->data,worklen,mac)< 0) {
			if(ssl_ignore_mac_failed) {
				if (debug) printf("ssl_decrypt_record: mac failed, but ignored for troubleshooting ;-)\n");
			}
			else{
				if (debug) printf("ssl_decrypt_record: mac failed\n");
				return -1;
			}
		}
		else{
			if (debug) printf("ssl_decrypt_record: mac ok\n");
		}
	}
	else if(ssl->version_netorder==DTLSV1DOT0_VERSION ||
		ssl->version_netorder==DTLSV1DOT2_VERSION ||
		ssl->version_netorder==DTLSV1DOT0_VERSION_NOT){
		/* Try rfc-compliant mac first, and if failed, try old openssl's non-rfc-compliant mac */
		if(dtls_check_mac(decoder,ct,ssl->version_netorder,out_str->data,worklen,mac)>= 0) {
			if (debug) printf("ssl_decrypt_record: mac ok\n");
		}
		else if(tls_check_mac(decoder,ct,TLSV1_VERSION,out_str->data,worklen,mac)>= 0) {
			if (debug) printf("ssl_decrypt_record: dtls rfc-compliant mac failed, but old openssl's non-rfc-compliant mac ok\n");
		}
		else if(ssl_ignore_mac_failed) {
			if (debug) printf("ssl_decrypt_record: mac failed, but ignored for troubleshooting ;-)\n");
		}
		else{
			if (debug) printf("ssl_decrypt_record: mac failed\n");
			return -1;
		}
	}
skip_mac:

	*outl = worklen;

	if (decoder->compression > 0) {
		if (debug) printf("ssl_decrypt_record: compression method %d\n", decoder->compression);
		ssl_data_copy(comp_str, out_str);
		ssl_print_data("Plaintext compressed", comp_str->data, worklen);
		if (!decoder->decomp) {
			if (debug) printf("decrypt_ssl3_record: no decoder available\n");
			return -1;
		}
		if (ssl_decompress_record(decoder->decomp, comp_str->data, worklen, out_str, &uncomplen) < 0) return -1;
		ssl_print_data("Plaintext uncompressed", out_str->data, uncomplen);
		*outl = uncomplen;
	}

	return 0;
}


static gint
decrypt_ssl3_record(char *data, int /*datalen*/, packet_info *pinfo, guint32 offset,
		guint32 record_length, guint8 content_type, SslDecryptSessionC *ssl,
		gboolean save_plaintext)
{
	gint		ret;
	gint		direction;
	StringInfo *data_for_iv;
	gint		data_for_iv_len;
	SslDecoder *decoder;

	ret = 0;
	/* if we can decrypt and decryption was a success
	 * add decrypted data to this packet info */
	if(debug) printf("decrypt_ssl3_record: app_data len %d, ssl state 0x%02X\n", record_length, ssl->state);
	direction = ssl_packet_from_server(ssl, pinfo);

	/* retrieve decoder for this packet direction */
	if (direction != 0) {
		if(debug) printf("decrypt_ssl3_record: using server decoder\n");
		decoder = ssl->server;
	}  
	else {
		if(debug) printf("decrypt_ssl3_record: using client decoder\n");
		decoder = ssl->client;
	}  

	/* save data to update IV if decoder is available or updated later */
	data_for_iv = (direction != 0) ? &ssl->server_data_for_iv : &ssl->client_data_for_iv;
	data_for_iv_len = (record_length < 24) ? record_length : 24;
	ssl_data_set(data_for_iv, (const guchar*)(guint8*)(data + offset + record_length - data_for_iv_len), data_for_iv_len);
   
	if (!decoder) {
		if(debug) printf("decrypt_ssl3_record: no decoder available\n");
		return ret;
	}  
   
	/* run decryption and add decrypted payload to protocol data, if decryption
	 * is successful*/

	ssl_decrypted_data_avail = ssl_decrypted_data.data_len;
	if (ssl_decrypt_record(ssl, decoder, content_type, (const guchar*)(data + offset), record_length, &ssl_compressed_data, &ssl_decrypted_data, (guint*)&ssl_decrypted_data_avail) == 0)
		ret = 1;		  
	/*  */
	if (!ret) {
		/* save data to update IV if valid session key is obtained later */
		data_for_iv = (direction != 0) ? &ssl->server_data_for_iv : &ssl->client_data_for_iv;
		data_for_iv_len = (record_length < 24) ? record_length : 24;
		ssl_data_set(data_for_iv, (const guchar*)(data + offset + record_length - data_for_iv_len), data_for_iv_len);
	}  
	if (ret && save_plaintext) {
		//TODO
		//ssl_add_data_info(proto_ssl, pinfo, ssl_decrypted_data.data, ssl_decrypted_data_avail,  tvb_raw_offset(tvb)+offset, decoder->flow);
		pinfo->decrypt_vec->push_back(string((char*)ssl_decrypted_data.data, ssl_decrypted_data_avail));
	}
	return ret;
}

#define RSA_PARS 6
static SSL_PRIVATE_KEY*
ssl_privkey_to_sexp(struct gnutls_x509_privkey_int* priv_key)
{
	gnutls_datum_t rsa_datum[RSA_PARS]; /* m, e, d, p, q, u */
	size_t		 tmp_size;
	gcry_sexp_t	rsa_priv_key = NULL;
	gint		   i;
	int			ret;
	size_t		 buf_len;
	unsigned char  buf_keyid[32];

	gcry_mpi_t rsa_params[RSA_PARS];

	buf_len = sizeof(buf_keyid);
	ret = gnutls_x509_privkey_get_key_id(priv_key, 0, buf_keyid, &buf_len);
	if (ret != 0) {
		if (debug) printf( "gnutls_x509_privkey_get_key_id(ssl_pkey, 0, buf_keyid, &buf_len) - %s\n", gnutls_strerror(ret));
	} else {
		if(debug) {
			gchar *tmp = bytes_to_ep_str_punct(buf_keyid, (int) buf_len, ':');
			printf( "Private key imported: KeyID %s\n", tmp);
			delete [] tmp;
		}
	}

	/* RSA get parameter */
	if(debug) printf("gnutls_x509_privkey_export_rsa_raw [%p] (x509_pkey)\n", priv_key);
	if (gnutls_x509_privkey_export_rsa_raw(priv_key,
										   &rsa_datum[0],
										   &rsa_datum[1],
										   &rsa_datum[2],
										   &rsa_datum[3],
										   &rsa_datum[4],
										   &rsa_datum[5])  != 0) {
		if (debug) printf("ssl_load_key: can't export rsa param (is a rsa private key file ?!?)\n");
		return NULL;
	}

	/* convert each rsa parameter to mpi format*/
	for(i=0; i<RSA_PARS; i++) {
		if (gcry_mpi_scan(&rsa_params[i], GCRYMPI_FMT_USG, rsa_datum[i].data, rsa_datum[i].size,&tmp_size) != 0) {
			if (debug) printf("ssl_load_key: can't convert m rsa param to int (size %d)\n", rsa_datum[i].size);
			if(rsa_datum[i].data)
				FREE(rsa_datum[i].data);
			return NULL;
		}
	}
   
	/* libgcrypt expects p < q, and gnutls might not return it as such, depending on gnutls version and its crypto backend */
	if (gcry_mpi_cmp(rsa_params[3], rsa_params[4]) > 0)
	{
		if (debug) printf("ssl_load_key: swapping p and q parameters and recomputing u\n");
		gcry_mpi_swap(rsa_params[3], rsa_params[4]);
		gcry_mpi_invm(rsa_params[5], rsa_params[3], rsa_params[4]);
	}  
   
	if  (gcry_sexp_build( &rsa_priv_key, NULL,
			"(private-key(rsa((n%m)(e%m)(d%m)(p%m)(q%m)(u%m))))", rsa_params[0],
			rsa_params[1], rsa_params[2], rsa_params[3], rsa_params[4],
			rsa_params[5]) != 0) {
		if (debug) printf("ssl_load_key: can't build rsa private key s-exp\n");
		for (i = 0; i < RSA_PARS; i++) {
			if(rsa_datum[i].data)
				FREE(rsa_datum[i].data);
		}
		return NULL;
	}  
   
	for (i = 0; i < RSA_PARS; i++) {
		if(rsa_datum[i].data)
			FREE(rsa_datum[i].data);
		gcry_mpi_release(rsa_params[i]);
	}
	return rsa_priv_key;
}

Ssl_private_key_t *
ssl_load_key(FILE* fp)
{
	/* gnutls makes our work much harder, since we have to work internally with
	 * s-exp formatted data, but PEM loader exports only in "gnutls_datum_t"
	 * format, and a datum -> s-exp convertion function does not exist.
	 */
	gnutls_x509_privkey_t priv_key;
	gnutls_datum_t		key;
	long				  size;
	gint				  ret;
	guint				 bytes;

	Ssl_private_key_t *private_key = new FILE_LINE(31004) Ssl_private_key_t;
	memset(private_key, 0, sizeof(Ssl_private_key_t));

	/* init private key data*/
	gnutls_x509_privkey_init(&priv_key);

	/* compute file size and load all file contents into a datum buffer*/
	if (fseek(fp, 0, SEEK_END) < 0) {
		if (debug) printf("ssl_load_key: can't fseek file\n");
		delete private_key;
		return NULL;
	}  
	if ((size = ftell(fp)) < 0) {
		if (debug) printf("ssl_load_key: can't ftell file\n");
		delete private_key;
		return NULL;
	}  
	if (fseek(fp, 0, SEEK_SET) < 0) {
		if (debug) printf("ssl_load_key: can't re-fseek file\n");
		delete private_key;
		return NULL;
	}  
	key.data = new FILE_LINE(31005) guchar[size];
	key.size = (int)size;
	bytes = (guint) fread(key.data, 1, key.size, fp);
	if (bytes < key.size) {
		if (debug) printf("ssl_load_key: can't read from file %d bytes, got %d\n",
			key.size, bytes);
		delete private_key;
		delete [] key.data;
		return NULL;
	}  
   
	/* import PEM data*/
	if ((ret = gnutls_x509_privkey_import(priv_key, &key, GNUTLS_X509_FMT_PEM)) != GNUTLS_E_SUCCESS) {
		if (debug) printf("ssl_load_key: can't import pem data: %s\n", gnutls_strerror(ret));
		delete private_key;
		delete [] key.data;
		return NULL;
	}  
   
	if (gnutls_x509_privkey_get_pk_algorithm(priv_key) != GNUTLS_PK_RSA) {
		if (debug) printf("ssl_load_key: private key public key algorithm isn't RSA\n");
		delete private_key;
		delete [] key.data;
		return NULL;
	}  
   
	delete [] key.data;
  
	if(debug) printf("private_key->x509_pkey[%p] = priv_key[%p]\n", private_key->x509_pkey, priv_key);
	private_key->x509_pkey = priv_key;
	private_key->sexp_pkey = ssl_privkey_to_sexp(priv_key);
	if ( !private_key->sexp_pkey ) {
		delete private_key;
		return NULL;
	}  
	return private_key;
}

void
ssl_find_private_key(SslDecryptSessionC *ssl_session, GHashTable *key_hash, packet_info *pinfo) {
	SslService dummy;
	char	   ip_addr_any[] = {0,0,0,0};
	guint32	port	= 0;
	gchar	 addr_string[32];
	Ssl_private_key_t * private_key;

	if (!ssl_session) {
		return;
	}  

	/* we need to know which side of the conversation is speaking */
	if (ssl_packet_from_server(ssl_session, pinfo)) {
		dummy.addr = pinfo->src;
		dummy.port = port = pinfo->srcport;
	} else {
		dummy.addr = pinfo->dst;
		dummy.port = port = pinfo->destport;
	}  
	inet_ntop(AF_INET, dummy.addr.data, addr_string, INET_ADDRSTRLEN);
	if (debug) printf("ssl_find_private_key server %s:%u\n",
					 addr_string, dummy.port);
	if (g_hash_table_size(key_hash) == 0) {
		if (debug) printf("ssl_find_private_key: no keys found\n");
		return;
	} else {
		if (debug) printf("ssl_find_private_key: testing %i keys\n",
			g_hash_table_size(key_hash));
	}	  

	/* try to retrieve private key for this service. Do it now 'cause pinfo
	 * is not always available
	 * Note that with HAVE_LIBGNUTLS undefined private_key is allways 0
	 * and thus decryption never engaged*/


	ssl_session->private_key = 0;
	private_key = (Ssl_private_key_t *)g_hash_table_lookup(key_hash, &dummy);

	if (!private_key) {
		if (debug) printf("ssl_find_private_key can't find private key for this server! Try it again with universal port 0\n");
	   
		dummy.port = 0;
		private_key = (Ssl_private_key_t *)g_hash_table_lookup(key_hash, &dummy);
	}  

	if (!private_key) {
		if (debug) printf("ssl_find_private_key can't find private key for this server (universal port)! Try it again with universal address 0.0.0.0\n");
	   
		dummy.addr.type = AT_IPv4;
		dummy.addr.len = 4;
		dummy.addr.data = ip_addr_any;
	   
		dummy.port = port;
		private_key = (Ssl_private_key_t *)g_hash_table_lookup(key_hash, &dummy);
	}  

	if (!private_key) {
		if (debug) printf("ssl_find_private_key can't find private key for this server! Try it again with universal address 0.0.0.0 and universal port 0\n");
	   
		dummy.port = 0;
		private_key = (Ssl_private_key_t *)g_hash_table_lookup(key_hash, &dummy);
	}  
   
	if (!private_key) {
		if (debug) printf("ssl_find_private_key can't find any private key!\n");
	} else {
		ssl_session->private_key = private_key->sexp_pkey;
	}  
}

static gint
//ssl_dissect_hnd_hello_common(ssl_common_dissect_t *hf, tvbuff_t *tvb,
ssl_dissect_hnd_hello_common(char *data, unsigned int /*datalen*/, guint32 offset, SslDecryptSessionC *ssl, gboolean from_server)
{
//	nstime_t	 gmt_unix_time;
	guint8	   sessid_length;

	if (ssl) {
		StringInfo *rnd;
		if (from_server)			
			rnd = &ssl->server_random;
		else
			rnd = &ssl->client_random;
		   
		/* save provided random for later keyring generation */
		memcpy(rnd->data, data + offset, 32);
		rnd->data_len = 32;
		if (from_server)
			ssl->state |= SSL_SERVER_RANDOM;
		else
			ssl->state |= SSL_CLIENT_RANDOM;
		if (debug) printf("%s found %s RANDOM -> state 0x%02X\n", __FUNCTION__, from_server ? "SERVER" : "CLIENT", ssl->state);
	   
		/* show the time */			  
//		gmt_unix_time.secs  = tvb_get_ntohl(tvb, offset);
//		gmt_unix_time.nsecs = 0;
		offset += 4;	   
	   
		/* show the random bytes */
		offset += 28;	  
	   
		/* show the session id (length followed by actual Session ID) */
		sessid_length = (guint8)*(data + offset);
		offset++;		  
	   
		if (ssl) {
			/* save the authorative SID for later use in ChangeCipherSpec.
			 * (D)TLS restricts the SID to 32 chars, it does not make sense to
			 * save more, so ignore larger ones. */
			if (from_server && sessid_length <= 32) {
				memcpy(ssl->session_id.data, data + offset, sessid_length);
				ssl->session_id.data_len = sessid_length;
			}  
		}  
		if (sessid_length > 0) {
			offset += sessid_length;
		}  
	}  
   
	return offset;
}  


void
//ssl_dissect_hnd_cli_hello(ssl_common_dissect_t *hf, char *data, unsigned int datalen,
ssl_dissect_hnd_cli_hello(char *data, unsigned int datalen,
						  packet_info */*pinfo*/, guint32 offset,
						  guint32 /*length*/, SslSession */*session*/,
						  SslDecryptSessionC *ssl, dtls_hfs_t *dtls_hfs)
{
	/* struct {
	 *	 ProtocolVersion client_version;
	 *	 Random random;
	 *	 SessionID session_id;
	 *	 opaque cookie<0..32>;				   //new field for DTLS
	 *	 CipherSuite cipher_suites<2..2^16-1>;
	 *	 CompressionMethod compression_methods<1..2^8-1>;
	 *	 Extension client_hello_extension_list<0..2^16-1>;
	 * } ClientHello;
	 *
	 */
	guint16	 cipher_suite_length;
//	guint8	  compression_methods_length;
//	guint8	  compression_method;
//	guint16	 start_offset = offset;

	/* show the client version */
	offset += 2;

	/* dissect fields that are also present in ClientHello */
	offset = ssl_dissect_hnd_hello_common(data, datalen, offset, ssl, FALSE);

	/* fields specific for DTLS (cookie_len, cookie) */
	if (dtls_hfs != NULL) {
		/* look for a cookie */
		guint8 cookie_length = (guint8)*(data + offset);

		offset++;
		if (cookie_length > 0) {
			offset += cookie_length;
		}
	}

	/* tell the user how many cipher suites there are */
	cipher_suite_length = pntoh16(data + offset);
	offset += 2;
	if (cipher_suite_length > 0) {
		if (cipher_suite_length % 2) {
			if(debug) printf("Cipher suite length (%d) must be a multiple of 2", cipher_suite_length);
			return;
		}

		while (cipher_suite_length > 0) {
			//proto_tree_add_item(cs_tree, hf->hf.hs_cipher_suite, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			cipher_suite_length -= 2;
		}
	}
#if 0
	/* tell the user how many compression methods there are */
	compression_methods_length = (guint8)*(data + offset);
	offset += 1;
	if (compression_methods_length > 0) {
		
		while (compression_methods_length > 0) {
			compression_method = (guint8)*(data + offset);
			offset++;
			compression_methods_length--;
		}
	}
	if (length > offset - start_offset) {
		// no need to parse 
		//ssl_dissect_hnd_hello_ext(data, datalen, offset, length - (offset - start_offset), TRUE, session, ssl);
	}
#endif
}


int	 
ssl_find_cipher(int num, SslCipherSuite* cs)
{
	SslCipherSuite *c;
	
	for(c = cipher_suites; c->number != -1; c++){
		if(c->number == num){
			*cs = *c;
			return 0;
		}
	}   
	
	return -1;
}


void
ssl_dissect_hnd_srv_hello(char *data, unsigned int datalen, 
						  guint32 offset, guint32 length,
						  SslSession */*session*/, SslDecryptSessionC *ssl)
{
	/* struct {
	 *	 ProtocolVersion server_version;
	 *	 Random random;
	 *	 SessionID session_id;
	 *	 CipherSuite cipher_suite;
	 *	 CompressionMethod compression_method;
	 *	 Extension server_hello_extension_list<0..2^16-1>;
	 * } ServerHello;
	 */
	guint16 start_offset = offset;

	/* show the server version */
	offset += 2;	   

	/* dissect fields that are also present in ClientHello */
	offset = ssl_dissect_hnd_hello_common(data, datalen, offset, ssl, TRUE);

	if (ssl) {
		/* store selected cipher suite for decryption */
		ssl->session.cipher = pntoh16(data + offset);
		if(debug) printf("ssl_dissect_hnd_srv_hello ssl->session.cipher[%u]\n", ssl->session.cipher);
	   
		if (ssl_find_cipher(ssl->session.cipher, &ssl->cipher_suite) < 0) {
			if (debug) printf("%s can't find cipher suite 0x%04X\n", __FUNCTION__, ssl->session.cipher);
		} else {			
			/* Cipher found, save this for the delayed decoder init */
			ssl->state |= SSL_CIPHER;
			if (debug) printf("%s found CIPHER 0x%04X -> state 0x%02X\n", __FUNCTION__, ssl->session.cipher, ssl->state);
		}				   
	}  

	/* now the server-selected cipher suite */
	offset += 2;	   

	if (ssl) {
		/* store selected compression method for decryption */
		ssl->session.compression = (guint8)*(data + offset);
	}  
	/* and the server-selected compression method */
	offset++;		  
   
	/* remaining data are extensions */

	if (length > offset - start_offset) {
		// no need to dissect this
		//ssl_dissect_hnd_hello_ext(hf, tvb, tree, offset, length - (offset - start_offset), FALSE, session, ssl);
	}
}  

static StringInfo *
ssl_data_clone(StringInfo *str)
{	   
	StringInfo *cloned_str;
	cloned_str = (StringInfo*) new FILE_LINE(31006) guchar[sizeof(StringInfo) + str->data_len];
	memset(cloned_str, 0, sizeof(StringInfo) + str->data_len);
	cloned_str->data = (guchar *) (cloned_str + 1);
	ssl_data_set(cloned_str, str->data, str->data_len);
	return cloned_str;
}


/** store a known (pre-)master secret into cache */
static void
ssl_save_master_key(SslDecryptSessionC *ssl, const char *label, GHashTable *ht, StringInfo *key,
					StringInfo *mk)
{
	StringInfo *ht_key, *master_secret;

	if (key->data_len == 0) {
		if (debug) printf("%s: not saving empty %s!\n", __FUNCTION__, label);
		return;
	}

	if (mk->data_len == 0) {
		if (debug) printf("%s not saving empty (pre-)master secret for %s!\n", __FUNCTION__, label);
		return;
	}

	/* ssl_hash() depends on session_ticket->data being aligned for guint access
	 * so be careful in changing how it is allocated. */
	ht_key = ssl_data_clone(key);
	master_secret = ssl_data_clone(mk);
	ssl_map_hash[ssl].push(string((char*)(ht_key->data), (unsigned int)(ht_key->data_len)));
	g_hash_table_insert(ht, ht_key, master_secret);

	if (debug) printf("%s inserted (pre-)master secret for %s\n", __FUNCTION__, label);
	if (debug) ssl_print_string("stored key", ht_key);
	if (debug) ssl_print_string("stored (pre-)master secret", master_secret);
}


void
ssl_dissect_hnd_new_ses_ticket(char *data, unsigned int datalen, guint32 offset, SslDecryptSessionC *ssl, GHashTable *session_hash)
{
	guint16	  ticket_len;

	/* length of session ticket, may be 0 if the server has sent the
	 * SessionTicket extension, but decides not to use one. */
	ticket_len = pntoh16(data + offset + 4);

	/* ticket lifetime hint */
	offset += 4;

	/* opaque ticket (length, data) */
	offset += 2;
	/* Content depends on implementation, so just show data! */
	/* save the session ticket to cache for ssl_finalize_decryption */
	if (ssl) {
		if(ssl->session_ticket.data) {
			if(ticket_len > ssl->session_ticket.max_len) {
				delete [] ssl->session_ticket.data;
				ssl->session_ticket.data = new FILE_LINE(31007) guchar[ticket_len];
				ssl->session_ticket.max_len = ticket_len;
			}
		} else {
			ssl->session_ticket.data = new FILE_LINE(31008) guchar[ticket_len];
			ssl->session_ticket.max_len = ticket_len;
		}
		ssl->session_ticket.data_len = ticket_len;
		memcpy(ssl->session_ticket.data, data + offset, MIN(datalen - offset, ticket_len));
		/* NewSessionTicket is received after the first (client)
		 * ChangeCipherSpec, and before the second (server) ChangeCipherSpec.
		 * Since the second CCS has already the session key available it will
		 * just return. To ensure that the session ticket is mapped to a
		 * master key (from the first CCS), save the ticket here too. */
		ssl_save_master_key(ssl, "Session Ticket", session_hash, &ssl->session_ticket, &ssl->master_secret);
	}
}

/* decrypt data with private key. Store decrypted data directly into input
 * buffer */
static int
ssl_private_decrypt(const guint len, guchar* data, SSL_PRIVATE_KEY* pk)
{
	gint		rc = 0;
	size_t	  decr_len = 0, i = 0;
	gcry_sexp_t s_data = NULL, s_plain = NULL;
	gcry_mpi_t  encr_mpi = NULL, text = NULL;

	/* create mpi representation of encrypted data */
	rc = gcry_mpi_scan(&encr_mpi, GCRYMPI_FMT_USG, data, len, NULL);
	if (rc != 0 ) {
		if (debug) printf("pcry_private_decrypt: can't convert data to mpi (size %d):%s\n",
			len, gcry_strerror(rc));
		return 0;
	}

	/* put the data into a simple list */
	rc = gcry_sexp_build(&s_data, NULL, "(enc-val(rsa(a%m)))", encr_mpi);
	if (rc != 0) {
		if (debug) printf("pcry_private_decrypt: can't build encr_sexp:%s\n",
			 gcry_strerror(rc));
		decr_len = 0;
		goto out;
	}	   

	/* pass it to libgcrypt */
	rc = gcry_pk_decrypt(&s_plain, s_data, pk);
	if (rc != 0)
	{   
		if (debug) printf("pcry_private_decrypt: can't decrypt key:%s\n",
			gcry_strerror(rc));
		decr_len = 0;
		goto out;
	}

	/* convert plain text sexp to mpi format */
	text = gcry_sexp_nth_mpi(s_plain, 0, 0);
	if (! text) {
		if (debug) printf("pcry_private_decrypt: can't convert sexp to mpi\n");
		decr_len = 0;
		goto out;
	}		   
		
	/* compute size requested for plaintext buffer */
	rc = gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &decr_len, text);
	if (rc != 0) {
		if (debug) printf("pcry_private_decrypt: can't compute decr size:%s\n",
			gcry_strerror(rc));
		decr_len = 0;
		goto out;
	}   
		
   
	/* sanity check on out buffer */
	if (decr_len > len) {
		if (debug) printf("pcry_private_decrypt: decrypted data is too long ?!? (%lu max %d)\n", decr_len, len);
		decr_len = 0;
		goto out;
	}
   
	/* write plain text to newly allocated buffer */
	rc = gcry_mpi_print(GCRYMPI_FMT_USG, data, len, &decr_len, text);
	if (rc != 0) {
		if (debug) printf("pcry_private_decrypt: can't print decr data to mpi (size %lu):%s\n", decr_len, gcry_strerror(rc));
		decr_len = 0;
		goto out;
	}
   
	ssl_print_data("decrypted_unstrip_pre_master", data, decr_len);
   
	/* strip the padding*/
	rc = 0;
	for (i = 1; i < decr_len; i++) {
		if (data[i] == 0) {
			rc = (gint) i+1;
			break;
		}
	}
   
	if (debug) printf("pcry_private_decrypt: stripping %d bytes, decr_len %lu\n", rc, decr_len);
	decr_len -= rc;
	memmove(data, data+rc, decr_len);

out:
	gcry_sexp_release(s_data);
	gcry_sexp_release(s_plain);
	gcry_mpi_release(encr_mpi);
	gcry_mpi_release(text);
	return (int) decr_len;
}


static gboolean
ssl_decrypt_pre_master_secret(SslDecryptSessionC *ssl_session, StringInfo* encrypted_pre_master, SSL_PRIVATE_KEY *pk)
{			  

	if(debug) printf("entering ssl_decrypt_pre_master_secret\n");

	gint i;
		   
	if (!encrypted_pre_master)
		return FALSE;

	if(ssl_session->cipher_suite.kex == KEX_DH) {
		if (debug) printf("%s: session uses DH (%d) key exchange, which is "
						 "impossible to decrypt\n", __FUNCTION__, KEX_DH);
		return FALSE;
	} else if(ssl_session->cipher_suite.kex != KEX_RSA) {
		 if (debug) printf("%s key exchange %d different from KEX_RSA (%d)\n",
						  __FUNCTION__, ssl_session->cipher_suite.kex, KEX_RSA);
		return FALSE;
	}
	   
	/* with tls key loading will fail if not rsa type, so no need to check*/
	ssl_print_string("pre master encrypted",encrypted_pre_master);
	if (debug) printf("%s: RSA_private_decrypt\n", __FUNCTION__);
	i = ssl_private_decrypt(encrypted_pre_master->data_len, encrypted_pre_master->data, pk);

	if (i != 48) {
		if (debug) printf("%s wrong pre_master_secret length (%d, expected "
						 "%d)\n", __FUNCTION__, i, 48);
		return FALSE;
	}

	/* the decrypted data has been written into the pre_master key buffer */
	if(ssl_session->pre_master_secret.data) delete [] ssl_session->pre_master_secret.data;
	ssl_session->pre_master_secret.data = encrypted_pre_master->data;
	ssl_session->pre_master_secret.data_len=48;
	ssl_print_string("pre master secret",&ssl_session->pre_master_secret);
	   
	/* Remove the master secret if it was there.
	   This forces keying material regeneration in
	   case we're renegotiating */
	ssl_session->state &= ~(SSL_MASTER_SECRET|SSL_HAVE_SESSION_KEY);
	ssl_session->state |= SSL_PRE_MASTER_SECRET;
	return TRUE;
}

/** restore a (pre-)master secret given some key in the cache */
static gboolean
ssl_restore_master_key(SslDecryptSessionC *ssl, const char *label,
					   gboolean is_pre_master, GHashTable *ht, StringInfo *key)
{		  
	StringInfo *ms;

	if (key->data_len == 0) { 
		if (debug) printf("%s can't restore %smaster secret using an empty %s\n",
						 __FUNCTION__, is_pre_master ? "pre-" : "", label);
		return FALSE;
	}

	ms = (StringInfo *)g_hash_table_lookup(ht, key);
	if (!ms) {
		if (debug) printf("%s can't find %smaster secret by %s\n", __FUNCTION__,
						 is_pre_master ? "pre-" : "", label);
		return FALSE;   
	}

	/* (pre)master secret found, clear knowledge of other keys and set it in the
	 * current conversation */
	ssl->state &= ~(SSL_MASTER_SECRET | SSL_PRE_MASTER_SECRET |
					SSL_HAVE_SESSION_KEY);
	if (is_pre_master) {
		/* unlike master secret, pre-master secret has a variable size (48 for
		 * RSA, varying for PSK) and is therefore not statically allocated */
		if(ssl->pre_master_secret.data) delete [] ssl->pre_master_secret.data;
		ssl->pre_master_secret.data = new FILE_LINE(31009) guchar[ms->data_len];
		memset(ssl->pre_master_secret.data, 0, ms->data_len);
		ssl_data_set(&ssl->pre_master_secret, ms->data, ms->data_len);
		ssl->state |= SSL_PRE_MASTER_SECRET;
	} else {
		ssl_data_set(&ssl->master_secret, ms->data, ms->data_len);
		ssl->state |= SSL_MASTER_SECRET;
	}  
	if (debug) printf("%s %smaster secret retrieved using %s\n", __FUNCTION__,
					 is_pre_master ? "pre-" : "", label);
	ssl_print_string(label, key);
	ssl_print_string("(pre-)master secret", ms);
	return TRUE;
}	  


gboolean
ssl_generate_pre_master_secret(SslDecryptSessionC *ssl_session,
							   guint32 length, char *data, unsigned int /*datalen*/, guint32 offset,
							   const gchar *ssl_psk,
							   const ssl_master_key_map_t *mk_map)
{		  
	/* check for required session data */
	if (debug) printf("%s: found SSL_HND_CLIENT_KEY_EXCHG, state %X\n",
					 __FUNCTION__, ssl_session->state);
	if ((ssl_session->state & (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION)) !=
		(SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION)) {
		if (debug) printf("%s: not enough data to generate key (required state %X)\n", __FUNCTION__,
						 (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION));
		return FALSE;
	}	  
			   
	if (ssl_session->cipher_suite.kex == KEX_PSK)
	{  
		/* calculate pre master secret*/
		StringInfo pre_master_secret;
		guint psk_len, pre_master_len;

		if (!ssl_psk || (ssl_psk[0] == 0)) {
			if (debug) printf("%s: can't find pre-shared-key\n", __FUNCTION__);
			return FALSE;
		}
		   
		/* convert hex string into char*/
		if (!from_hex(&ssl_session->psk, ssl_psk, strlen(ssl_psk))) {
			if (debug) printf("%s: ssl.psk/dtls.psk contains invalid hex\n",
							 __FUNCTION__);
			return FALSE;
		}

		psk_len = ssl_session->psk.data_len;
		if (psk_len >= (2 << 15)) {
			if (debug) printf("%s: ssl.psk/dtls.psk must not be larger than 2^15 - 1\n",
							 __FUNCTION__);
			return FALSE;
		}

   
		pre_master_len = psk_len * 2 + 4;

		pre_master_secret.data = new FILE_LINE(31010) guchar[pre_master_len];
		memset(pre_master_secret.data, 0, pre_master_len);
		pre_master_secret.data_len = pre_master_len;
		/* 2 bytes psk_len*/
		pre_master_secret.data[0] = psk_len >> 8;
		pre_master_secret.data[1] = psk_len & 0xFF;
		/* psk_len bytes times 0*/
		memset(&pre_master_secret.data[2], 0, psk_len);
		/* 2 bytes psk_len*/
		pre_master_secret.data[psk_len + 2] = psk_len >> 8;
		pre_master_secret.data[psk_len + 3] = psk_len & 0xFF;
		/* psk*/
		memcpy(&pre_master_secret.data[psk_len + 4], ssl_session->psk.data, psk_len);
		delete [] ssl_session->psk.data;
		ssl_session->psk.data = NULL;
	   
		if(ssl_session->pre_master_secret.data) delete [] ssl_session->pre_master_secret.data;
		ssl_session->pre_master_secret.data = pre_master_secret.data;
		ssl_session->pre_master_secret.data_len = pre_master_len;
		/*if (debug) printf("pre master secret",&ssl->pre_master_secret);*/
			   
		/* Remove the master secret if it was there.
		   This forces keying material regeneration in
		   case we're renegotiating */
		ssl_session->state &= ~(SSL_MASTER_SECRET|SSL_HAVE_SESSION_KEY);
		ssl_session->state |= SSL_PRE_MASTER_SECRET;
		return TRUE;
	}  
	else
	{   
		StringInfo encrypted_pre_master;
		guint encrlen, skip;
		encrlen = length;
		skip = 0;
		
		/* get encrypted data, on tls1 we have to skip two bytes
		 * (it's the encrypted len and should be equal to record len - 2)
		 * in case of rsa1024 that would be 128 + 2 = 130; for psk not necessary
		 */
		if (ssl_session->cipher_suite.kex == KEX_RSA &&
		   (ssl_session->session.version == SSL_VER_TLS || ssl_session->session.version == SSL_VER_TLSv1DOT1 ||
			ssl_session->session.version == SSL_VER_TLSv1DOT2 || ssl_session->session.version == SSL_VER_DTLS ||
			ssl_session->session.version == SSL_VER_DTLS1DOT2))
		{   
			encrlen  = pntoh16(data + offset);
			skip = 2;
			if (encrlen > length - 2)
			{
				if (debug) printf("%s: wrong encrypted length (%d max %d)\n",
								 __FUNCTION__, encrlen, length);
				return FALSE;   
			}  
		}  
		/* the valid lower bound is higher than 8, but it is sufficient for the
		 * ssl keylog file below */
		if (encrlen < 8) {
			if (debug) printf("%s: invalid encrypted pre-master key length %d\n",
							 __FUNCTION__, encrlen);
			return FALSE;   
		}  
	   
		encrypted_pre_master.data = new FILE_LINE(31011) guchar[encrlen];
		memset(encrypted_pre_master.data, 0, encrlen);
		encrypted_pre_master.data_len = encrlen;
		memcpy(encrypted_pre_master.data, data + offset + skip, encrlen);
	   
		if (ssl_session->private_key) {
			/* try to decrypt encrypted pre-master with RSA key */
			if (ssl_decrypt_pre_master_secret(ssl_session, &encrypted_pre_master, ssl_session->private_key)) {
				return TRUE;
			}
			   
			if (debug) printf("%s: can't decrypt pre-master secret\n", __FUNCTION__);
		}				   
	   
		/* try to find the pre-master secret from the encrypted one. The
		 * ssl key logfile stores only the first 8 bytes, so truncate it */
		encrypted_pre_master.data_len = 8;
		if (ssl_restore_master_key(ssl_session, "Encrypted pre-master secret", TRUE, mk_map->pre_master, &encrypted_pre_master)) {
			return TRUE;
		}
		
		delete [] encrypted_pre_master.data;
	}	  
	return FALSE;
}

#if 0
/**	
 * Load a RSA private key from a PKCS#12 file.
 * @param fp the file that contains the key data.
 * @param cert_passwd password to decrypt the PKCS#12 file.
 * @param[out] err error message upon failure; NULL upon success.
 * @return a pointer to the loaded key on success; NULL upon failure.
 */	
static Ssl_private_key_t *
ssl_load_pkcs12(FILE* fp, const gchar *cert_passwd, string &err) {
			   
	int					   i, j, ret;
	int					   rest;
	unsigned char			*p;
	gnutls_datum_t			data;
	gnutls_pkcs12_bag_t	   bag = NULL;
	gnutls_pkcs12_bag_type_t  bag_type;
	size_t					len, buf_len;
	static char			   buf_name[256];
	static char			   buf_email[128];
	unsigned char			 buf_keyid[32];

	gnutls_pkcs12_t	   ssl_p12  = NULL;
	gnutls_x509_crt_t	 ssl_cert = NULL;
	gnutls_x509_privkey_t ssl_pkey = NULL;

	Ssl_private_key_t *private_key = new FILE_LINE(31012) Ssl_private_key_t;
	err = "";

	rest = 4096;
	data.data = new FILE_LINE(31013) guchar[rest];
	data.size = rest;
	p = data.data;
	while ((len = fread(p, 1, rest, fp)) > 0) {
		p += len;
		rest -= (int) len;
		if (!rest) {
			rest = 1024;
			guchar *newdata = new FILE_LINE(31014) guchar[data.size + rest];
			memcpy(newdata, data.data, data.size);
			delete [] data.data;
			data.data = newdata;
			p = data.data + data.size;
			data.size += rest;
		}
	}
	data.size -= rest;
	if (debug) printf("%d bytes read\n", data.size);
	if (!feof(fp)) {			   
		err = "Error during certificate reading.";
		if (debug) printf("%s\n", err.c_str());
		delete private_key;
		delete [] data.data;
		return 0;
	}					  
	   
	ret = gnutls_pkcs12_init(&ssl_p12);
	if (ret < 0) {
		char errbuff[2048];
		err = sprintf(errbuff, "gnutls_pkcs12_init(&st_p12) - %s", gnutls_strerror(ret));
		if (debug) printf("%s\n", err.c_str());
		delete private_key;
		delete [] data.data;
		return 0;
	}

	/* load PKCS#12 in DER or PEM format */
	ret = gnutls_pkcs12_import(ssl_p12, &data, GNUTLS_X509_FMT_DER, 0);
	if (ret < 0) {
		char errbuff[2048];
		err = sprintf(errbuff, "could not load PKCS#12 in DER format: %s", gnutls_strerror(ret));
		if (debug) printf("%s\n", err.c_str());

		ret = gnutls_pkcs12_import(ssl_p12, &data, GNUTLS_X509_FMT_PEM, 0);
		if (ret < 0) {
			char errbuff[2048];
			err = sprintf(errbuff, "could not load PKCS#12 in PEM format: %s", gnutls_strerror(ret));
			if (debug) printf("%s\n", err.c_str());
		} else {
			err = "";
		}
	}
	delete [] data.data;
	if (ret < 0) {
		delete private_key;
		return 0;
	}
	if (debug) printf( "PKCS#12 imported\n");
			
	for (i=0; ret==0; i++) {
			
		if (bag) { gnutls_pkcs12_bag_deinit(bag); bag = NULL; }
	
		ret = gnutls_pkcs12_bag_init(&bag);
		if (ret < 0) continue;
		
		ret = gnutls_pkcs12_get_bag(ssl_p12, i, bag);
		if (ret < 0) continue;

		for (j=0; ret==0 && j<gnutls_pkcs12_bag_get_count(bag); j++) {

			bag_type = gnutls_pkcs12_bag_get_type(bag, j);
			if (bag_type >= GNUTLS_BAG_UNKNOWN) continue;
			if (debug) printf( "Bag %d/%d: %s\n", i, j, BAGTYPE(bag_type));
			if (bag_type == GNUTLS_BAG_ENCRYPTED) {
				ret = gnutls_pkcs12_bag_decrypt(bag, cert_passwd);
				if (ret == 0) {
					bag_type = gnutls_pkcs12_bag_get_type(bag, j);
					if (bag_type >= GNUTLS_BAG_UNKNOWN) continue;
					if (debug) printf( "Bag %d/%d decrypted: %s\n", i, j, BAGTYPE(bag_type));
				}
			}

			ret = gnutls_pkcs12_bag_get_data(bag, j, &data);
			if (ret < 0) continue;

			switch (bag_type) {

				case GNUTLS_BAG_CERTIFICATE:

					ret = gnutls_x509_crt_init(&ssl_cert);
					if (ret < 0) {
						char errbuff[2048];
						err = sprintf(errbuff,  "gnutls_x509_crt_init(&ssl_cert) - %s", gnutls_strerror(ret));
						if (debug) printf("%s\n", err.c_str());
						delete private_key;
						return 0;
					}

					ret = gnutls_x509_crt_import(ssl_cert, &data, GNUTLS_X509_FMT_DER);
					if (ret < 0) {
						char errbuff[2048];
						err = sprintf(errbuff, "gnutls_x509_crt_import(ssl_cert, &data, GNUTLS_X509_FMT_DER) - %s", gnutls_strerror(ret));
						if (debug) printf("%s\n", err.c_str());
						delete private_key;
						return 0;
					}

					buf_len = sizeof(buf_name);
					ret = gnutls_x509_crt_get_dn_by_oid(ssl_cert, GNUTLS_OID_X520_COMMON_NAME, 0, 0, buf_name, &buf_len);
					if (ret < 0) { strcpy(buf_name, "<ERROR>"); }
					buf_len = sizeof(buf_email);
					ret = gnutls_x509_crt_get_dn_by_oid(ssl_cert, GNUTLS_OID_PKCS9_EMAIL, 0, 0, buf_email, &buf_len);
					if (ret < 0) { strcpy(buf_email, "<ERROR>"); }

					buf_len = sizeof(buf_keyid);
					ret = gnutls_x509_crt_get_key_id(ssl_cert, 0, buf_keyid, &buf_len);
					if (ret < 0) { strcpy((gchar*)buf_keyid, "<ERROR>"); }

					private_key->x509_cert = ssl_cert;
					if (debug) {
						gchar *tmp = bytes_to_ep_str(buf_keyid, (int) buf_len);
						printf( "Certificate imported: %s <%s>, KeyID %s\n", buf_name, buf_email, tmp);
						delete [] tmp;
					}
					break;

				case GNUTLS_BAG_PKCS8_KEY:
				case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY:

					ret = gnutls_x509_privkey_init(&ssl_pkey);
					if (ret < 0) {
						char errbuff[2048];
						err = sprintf(errbuff, "gnutls_x509_privkey_init(&ssl_pkey) - %s", gnutls_strerror(ret));
						if (debug) printf("%s\n", err.c_str());
						delete private_key;
						return 0;
					}
					ret = gnutls_x509_privkey_import_pkcs8(ssl_pkey, &data, GNUTLS_X509_FMT_DER, cert_passwd,
														   (bag_type==GNUTLS_BAG_PKCS8_KEY) ? GNUTLS_PKCS_PLAIN : 0);
					if (ret < 0) {
						char errbuff[2048];
						err = sprintf(errbuff, "Can not decrypt private key - %s", gnutls_strerror(ret));
						if (debug) printf("%s\n", err.c_str());
						delete private_key;
						return 0;
					}

					if (gnutls_x509_privkey_get_pk_algorithm(ssl_pkey) != GNUTLS_PK_RSA) {
						err = "ssl_load_pkcs12: private key public key algorithm isn't RSA";
						if (debug) printf("%s\n", err.c_str());
						delete private_key;
						return 0;
					}
					private_key->x509_pkey = ssl_pkey;
					7rivate_key->sexp_pkey = ssl_privkey_to_sexp(ssl_pkey);
					if ( !7rivate_key->sexp_pkey ) {
						err = "ssl_load_pkcs12: could not create sexp_pkey";
						if (debug) printf("%s\n", err.c_str());
						delete private_key;
						return NULL;
					}
					break;

				default: ;
			}
		}  /* j */
	}  /* i */

	return private_key;
}
#endif

/* dissects the handshake protocol, filling the tree */
static void
dissect_ssl3_handshake(char *data, unsigned int datalen, packet_info *pinfo,
					   guint32 offset,
					   guint32 record_length, SslSession *session,
					   gint /*is_from_server*/,
					   SslDecryptSessionC *ssl, const guint8 /*content_type*/)
{   

	if(debug) printf("dissect_ssl3_handshake\n");

	/*	 struct {
	 *		 HandshakeType msg_type;
	 *		 uint24 length;
	 *		 select (HandshakeType) {
	 *			 case hello_request:	   HelloRequest;
	 *			 case client_hello:		ClientHello;
	 *			 case server_hello:		ServerHello;
	 *			 case certificate:		 Certificate;
	 *			 case server_key_exchange: ServerKeyExchange;
	 *			 case certificate_request: CertificateRequest;
	 *			 case server_hello_done:   ServerHelloDone;
	 *			 case certificate_verify:  CertificateVerify;
	 *			 case client_key_exchange: ClientKeyExchange;
	 *			 case finished:			Finished;
	 *			 case certificate_url:	 CertificateURL;
	 *			 case certificate_status:  CertificateStatus;
	 *			 case encrypted_extensions:NextProtocolNegotiationEncryptedExtension;
	 *		 } body;
	 *	 } Handshake;
	 */
	const gchar *msg_type_str;
	guint8	   msg_type;
	guint32	  length;
	gboolean	 first_iteration;
		
	first_iteration = TRUE;

	/* just as there can be multiple records per packet, there
	 * can be multiple messages per record as long as they have
	 * the same content type			
	 *								  
	 * we really only care about this for handshake messages
	 */ 
	
	/* set record_length to the max offset */
	record_length += offset;
	if(debug) printf("dissect_ssl3_handshake rl:%d of:%d\n", record_length, offset);
	while (offset < record_length)
	{   
		msg_type = (guint8)*(data + offset);
		length   = pntoh24(data + offset + 1);

		/* Check the length in the handshake message. Assume it's an
		 * encrypted handshake message if the message would pass
		 * the record_length boundary. This is a workaround for the
		 * situation where the first octet of the encrypted handshake
		 * message is actually a known handshake message type.
		 */
		if (offset + length <= record_length)
			msg_type_str = try_val_to_str(msg_type, ssl_31_handshake_type);
		else
			msg_type_str = NULL;

		if (debug) printf("dissect_ssl3_handshake iteration %d type %d offset %d length %d "
			"bytes, remaining %d \n", first_iteration, msg_type, offset, length, record_length);
		if (!msg_type_str && !first_iteration)
		{   
			/* only dissect / report messages if they're
			 * either the first message in this record
			 * or they're a valid message type
			 */		  
			return;
		}

		/* if we don't have a valid handshake type, just quit dissecting */
		if (!msg_type_str)
			return;

		/* PAOLO: if we are doing ssl decryption we must dissect some requests type */
		if (ssl) {
			if(debug) printf("ssl0\n");
			/* add nodes for the message type and message length */
			offset += 1;
			offset += 3;

			/* now dissect the handshake message, if necessary */
			switch ((HandshakeType) msg_type) {
			case SSL_HND_HELLO_REQUEST:
				/* hello_request has no fields, so nothing to do! */
				break;

			case SSL_HND_CLIENT_HELLO:
				if (ssl) {
					/* ClientHello is first packet so set direction and try to
					 * find a private key matching the server port */
					ssl->ssl_set_server(&pinfo->dst, pinfo->ptype, pinfo->destport);
				
					if(!ssl->private_key_c) {
						//FILE *fp = fopen("/root/vox.key", "r");
						string filename = find_ssl_keys(pinfo->src2, pinfo->srcport, pinfo->dst2, pinfo->destport);
						if(debug) printf("Key file:%s\n", filename.c_str());
						if(filename != "") {
							FILE *fp = fopen(filename.c_str(), "r");
							if(fp) {
								ssl->private_key_c = ssl_load_key(fp);
								if(ssl->private_key_c) {
									ssl->private_key = ssl->private_key_c->sexp_pkey;
								}
								fclose(fp);
							} else {
								//TODO: syslog
							}
						}
#if 0
						string err;
						ssl->private_key = ssl_load_pkcs12(fp, "", err)->sexp_pkey;
						if (err.length()) {
							fprintf(stderr, "%s\n", err.c_str());
						}
						if(fp) fclose(fp);
#endif
					}


					//ssl_find_private_key(ssl, ssl_key_hash, pinfo);
				}
				//ssl_dissect_hnd_cli_hello(&dissect_ssl3_hf, data, datalen, pinfo,
				ssl_dissect_hnd_cli_hello(data, datalen, pinfo, offset, length, session, ssl, NULL);
				break;

			case SSL_HND_SERVER_HELLO:
				ssl_dissect_hnd_srv_hello(data, datalen, offset, length, session, ssl);
				break;

			case SSL_HND_HELLO_VERIFY_REQUEST:
				/* only valid for DTLS */
				break;

			case SSL_HND_NEWSESSION_TICKET:
				/* no need to load keylog file here as it only links a previous
				 * master key with this Session Ticket */
				ssl_dissect_hnd_new_ses_ticket(data, datalen, offset, ssl, ssl_master_key_map.session);
				break;

			case SSL_HND_CERTIFICATE:
				//ssl_dissect_hnd_cert(&dissect_ssl3_hf, tvb, ssl_hand_tree, offset, pinfo, session, is_from_server);
				break;

			case SSL_HND_SERVER_KEY_EXCHG:
				//no need to dissect 
				break;	  

			case SSL_HND_CERT_REQUEST:
				//ssl_dissect_hnd_cert_req(&dissect_ssl3_hf, tvb, ssl_hand_tree, offset, pinfo, session);
				break;

			case SSL_HND_SVR_HELLO_DONE:
				/* server_hello_done has no fields, so nothing to do! */
				break;

			case SSL_HND_CERT_VERIFY:
				//dissect_ssl3_hnd_cli_cert_verify(tvb, ssl_hand_tree, offset, length);
				break;

			case SSL_HND_CLIENT_KEY_EXCHG:
				// no need to dissect ssl_dissect_hnd_cli_keyex(data, datalen, offset, length, session);

				if (!ssl)
					break;

				/* try to find master key from pre-master key */
				if (!ssl_generate_pre_master_secret(ssl, length, data, datalen, offset, ssl_options.psk, &ssl_master_key_map)) {
					if (debug) printf("dissect_ssl3_handshake can't generate pre master secret\n");
				}
				break;

			case SSL_HND_FINISHED:
//				ssl_dissect_hnd_finished(&dissect_ssl3_hf, tvb, ssl_hand_tree, offset, session, &ssl_hfs);
				break;

			case SSL_HND_CERT_URL:
//				ssl_dissect_hnd_cert_url(&dissect_ssl3_hf, tvb, ssl_hand_tree, offset);
				break;

			case SSL_HND_CERT_STATUS:
//				dissect_ssl3_hnd_cert_status(tvb, ssl_hand_tree, offset, pinfo);
				break;

			case SSL_HND_SUPPLEMENTAL_DATA:
				/* TODO: dissect this? */
				break;

			case SSL_HND_ENCRYPTED_EXTS:
//				dissect_ssl3_hnd_encrypted_exts(tvb, ssl_hand_tree, offset);
				break;
			}

		}
		else
			offset += 4;		/* skip the handshake header when handshake is not processed*/

		offset += length;
		first_iteration = FALSE; /* set up for next pass, if any */
		if(debug) printf("ssl1 of:%u datalen:%u\n", offset, datalen);
	}
}

void	
ssl_change_cipher(SslDecryptSessionC *ssl_session, gboolean server)
{								   
	if (debug) printf("ssl_change_cipher %s\n", (server)?"SERVER":"CLIENT");
	if (server) {
		ssl_session->server = ssl_session->server_new;
		ssl_session->server_new = NULL;
	} else {
		ssl_session->client = ssl_session->client_new;
		ssl_session->client_new = NULL;
	}   
}		

static void
tls_hash(StringInfo *secret, StringInfo *seed, gint md,
		 StringInfo *out, guint out_len)
{
	/* RFC 2246 5. HMAC and the pseudorandom function
	 * '+' denotes concatenation.
	 * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
	 *						HMAC_hash(secret, A(2) + seed) + ...
	 * A(0) = seed
	 * A(i) = HMAC_hash(secret, A(i - 1))
	 */
	guint8   *ptr;
	guint	 left, tocpy;
	guint8   *A;
	guint8	_A[DIGEST_MAX_SIZE], tmp[DIGEST_MAX_SIZE];
	guint	 A_l, tmp_l;
	SSL_HMAC  hm;

	memset(tmp, 0, DIGEST_MAX_SIZE);

	ptr  = out->data;
	left = out_len;

	ssl_print_string("tls_hash: hash secret", secret);
	ssl_print_string("tls_hash: hash seed", seed);
	/* A(0) = seed */
	A = seed->data;
	A_l = seed->data_len;

	while (left) {
		/* A(i) = HMAC_hash(secret, A(i-1)) */
		ssl_hmac_init(&hm, secret->data, secret->data_len, md);
		ssl_hmac_update(&hm, A, A_l);
		A_l = sizeof(_A); /* upper bound len for hash output */
		ssl_hmac_final(&hm, _A, &A_l);
		ssl_hmac_cleanup(&hm);
		A = _A;
	   
		/* HMAC_hash(secret, A(i) + seed) */
		ssl_hmac_init(&hm, secret->data, secret->data_len, md);
		ssl_hmac_update(&hm, A, A_l);
		ssl_hmac_update(&hm, seed->data, seed->data_len);
		tmp_l = sizeof(tmp); /* upper bound len for hash output */
		ssl_hmac_final(&hm, tmp, &tmp_l);
		ssl_hmac_cleanup(&hm);
	   
		/* ssl_hmac_final puts the actual digest output size in tmp_l */
		tocpy = MIN(left, tmp_l);
		memcpy(ptr, tmp, tocpy);
		ptr += tocpy;
		left -= tocpy;
	}
	out->data_len = out_len;
   
	ssl_print_string("hash out", out);
}

static gboolean
tls_prf(StringInfo* secret, const gchar *usage,
		StringInfo* rnd1, StringInfo* rnd2, StringInfo* out, guint out_len)
{
	StringInfo  seed, sha_out, md5_out;
	guint8	 *ptr;
	StringInfo  s1, s2;
	guint	   i,s_l;
	size_t	  usage_len;
	gboolean	success = FALSE;
	usage_len = strlen(usage);

	/* initalize buffer for sha, md5 random seed*/
	if (ssl_data_alloc(&sha_out, MAX(out_len, 20)) < 0) {
		if (debug) printf("tls_prf: can't allocate sha out\n");
		return FALSE;
	}  
	if (ssl_data_alloc(&md5_out, MAX(out_len, 16)) < 0) {
		if (debug) printf("tls_prf: can't allocate md5 out\n");
		goto free_sha;
	}  
	if (ssl_data_alloc(&seed, usage_len+rnd1->data_len+rnd2->data_len) < 0) {
		if (debug) printf("tls_prf: can't allocate rnd %d\n",
						 (int) (usage_len+rnd1->data_len+rnd2->data_len));
		goto free_md5;  
	}  

	ptr=seed.data;
	memcpy(ptr,usage,usage_len);
	ptr+=usage_len;
	memcpy(ptr,rnd1->data,rnd1->data_len);
	ptr+=rnd1->data_len;
	memcpy(ptr,rnd2->data,rnd2->data_len);
	/*ptr+=rnd2->data_len;*/

	/* initalize buffer for client/server seeds*/
	s_l=secret->data_len/2 + secret->data_len%2;
	if (ssl_data_alloc(&s1, s_l) < 0) {
		if (debug) printf("tls_prf: can't allocate secret %d\n", s_l);
		goto free_seed;
	}  
	if (ssl_data_alloc(&s2, s_l) < 0) {
		if (debug) printf("tls_prf: can't allocate secret(2) %d\n", s_l);
		goto free_s1;
	}  

	memcpy(s1.data,secret->data,s_l);
	memcpy(s2.data,secret->data + (secret->data_len - s_l),s_l);

	if (debug) printf("tls_prf: tls_hash(md5 secret_len %d seed_len %d )\n", s1.data_len, seed.data_len);
	tls_hash(&s1, &seed, ssl_get_digest_by_name("MD5"), &md5_out, out_len);
	if (debug) printf("tls_prf: tls_hash(sha)\n");
	tls_hash(&s2, &seed, ssl_get_digest_by_name("SHA1"), &sha_out, out_len);
   
	for (i = 0; i < out_len; i++)
		out->data[i] = md5_out.data[i] ^ sha_out.data[i];
	/* success, now store the new meaningful data length */
	out->data_len = out_len;
	success = TRUE;
   
	ssl_print_string("PRF out",out);
	delete [] s2.data;
free_s1:
	delete [] s1.data;
free_seed:
	delete [] seed.data;
free_md5:
	delete [] md5_out.data;
free_sha:
	delete [] sha_out.data;
	return success;
}  

/* md5 /sha abstraction layer */
#define SSL_SHA_CTX gcry_md_hd_t
#define SSL_MD5_CTX gcry_md_hd_t
		
static inline void
ssl_sha_init(SSL_SHA_CTX* md)
{
	gcry_md_open(md,GCRY_MD_SHA1, 0);
}
static inline void
ssl_sha_update(SSL_SHA_CTX* md, guchar* data, gint len)
{
	gcry_md_write(*(md), data, len);
}
static inline void
ssl_sha_final(guchar* buf, SSL_SHA_CTX* md)
{
	memcpy(buf, gcry_md_read(*(md),  GCRY_MD_SHA1),
		   gcry_md_get_algo_dlen(GCRY_MD_SHA1));
}
static inline void
ssl_sha_cleanup(SSL_SHA_CTX* md)
{
	gcry_md_close(*(md));
}

static inline gint
ssl_md5_init(SSL_MD5_CTX* md)
{
	return gcry_md_open(md,GCRY_MD_MD5, 0);
}
static inline void
ssl_md5_update(SSL_MD5_CTX* md, guchar* data, gint len)
{
	gcry_md_write(*(md), data, len);
}
static inline void
ssl_md5_final(guchar* buf, SSL_MD5_CTX* md)
{
	memcpy(buf, gcry_md_read(*(md),  GCRY_MD_MD5),
		   gcry_md_get_algo_dlen(GCRY_MD_MD5));
}
static inline void
ssl_md5_cleanup(SSL_MD5_CTX* md)
{
	gcry_md_close(*(md));
}

static void
ssl3_generate_export_iv(StringInfo *r1, StringInfo *r2,
						StringInfo *out, guint out_len)
{
	SSL_MD5_CTX md5;
	guint8	  tmp[16];

	ssl_md5_init(&md5);
	ssl_md5_update(&md5,r1->data,r1->data_len);
	ssl_md5_update(&md5,r2->data,r2->data_len);
	ssl_md5_final(tmp,&md5);
	ssl_md5_cleanup(&md5);

	if(!(out_len <= sizeof(tmp))) return;
//	DISSECTOR_ASSERT(out_len <= sizeof(tmp));
	ssl_data_set(out, tmp, out_len);
	ssl_print_string("export iv", out);
}

static gboolean
tls12_prf(gint md, StringInfo* secret, const gchar* usage,
		  StringInfo* rnd1, StringInfo* rnd2, StringInfo* out, guint out_len)
{
	StringInfo label_seed;
	size_t	 usage_len;
	
	usage_len = strlen(usage);
	if (ssl_data_alloc(&label_seed, usage_len+rnd1->data_len+rnd2->data_len) < 0) {
		if (debug) printf("tls12_prf: can't allocate label_seed\n");
		return FALSE;
	}
	memcpy(label_seed.data, usage, usage_len);
	memcpy(label_seed.data+usage_len, rnd1->data, rnd1->data_len);
	memcpy(label_seed.data+usage_len+rnd1->data_len, rnd2->data, rnd2->data_len);
		
	if (debug) printf("tls12_prf: tls_hash(hash_alg %s secret_len %d seed_len %d )\n", gcry_md_algo_name(md), secret->data_len, label_seed.data_len);
	tls_hash(secret, &label_seed, md, out, out_len);
	delete [] label_seed.data;
	ssl_print_string("PRF out", out);
	return TRUE;
}	   

static gboolean
ssl3_prf(StringInfo* secret, const gchar* usage,
		 StringInfo* r1, StringInfo* r2, StringInfo* out, guint out_len)
{
	SSL_MD5_CTX  md5;
	SSL_SHA_CTX  sha;
	StringInfo  *rnd1,*rnd2;
	guint		off;
	gint		 i = 0,j;
	guint8	   buf[20];
		
	rnd1=r1; rnd2=r2;
		
	for (off = 0; off < out_len; off += 16) {
		guchar outbuf[16];
		i++;
		
		if (debug) printf("ssl3_prf: sha1_hash(%d)\n",i);
		/* A, BB, CCC,  ... */
		for(j=0;j<i;j++){
			buf[j]=64+i;
		}
		
		ssl_sha_init(&sha);
		ssl_sha_update(&sha,buf,i);
		ssl_sha_update(&sha,secret->data,secret->data_len);
		
		if(!strcmp(usage,"client write key") || !strcmp(usage,"server write key")){
			ssl_sha_update(&sha,rnd2->data,rnd2->data_len);
			ssl_sha_update(&sha,rnd1->data,rnd1->data_len);
		}
		else{
			ssl_sha_update(&sha,rnd1->data,rnd1->data_len);
			ssl_sha_update(&sha,rnd2->data,rnd2->data_len);
		}
		
		ssl_sha_final(buf,&sha);
		ssl_sha_cleanup(&sha);
		
		if (debug) printf("ssl3_prf: md5_hash(%d) datalen %d\n",i,
			secret->data_len);
		ssl_md5_init(&md5);
		ssl_md5_update(&md5,secret->data,secret->data_len);
		ssl_md5_update(&md5,buf,20);
		ssl_md5_final(outbuf,&md5);
		ssl_md5_cleanup(&md5);

		memcpy(out->data + off, outbuf, MIN(out_len - off, 16));
	}
	out->data_len = out_len;
	
	return TRUE;
}	   


/* out_len is the wanted output length for the pseudorandom function */
static gboolean
prf(SslDecryptSessionC *ssl, StringInfo *secret, const gchar *usage,
	StringInfo *rnd1, StringInfo *rnd2, StringInfo *out, guint out_len)
{
	switch (ssl->version_netorder) {
	case SSLV3_VERSION:
		return ssl3_prf(secret, usage, rnd1, rnd2, out, out_len);

	case TLSV1_VERSION:
	case TLSV1DOT1_VERSION:
	case DTLSV1DOT0_VERSION:
	case DTLSV1DOT0_VERSION_NOT:
		return tls_prf(secret, usage, rnd1, rnd2, out, out_len);

	default: /* TLSv1.2 */
		switch (ssl->cipher_suite.dig) {
		case DIG_SHA384:
			return tls12_prf(GCRY_MD_SHA384, secret, usage, rnd1, rnd2,
							 out, out_len);
		default:
			return tls12_prf(GCRY_MD_SHA256, secret, usage, rnd1, rnd2,
							 out, out_len);
		}
	}
}

SslDecoder*
SslDecryptSessionC::ssl_create_decoder(guint8 *mk, guint8 *sk, guint8 *iv)
{
	SslDecoder *dec;
	gint		ciph;

	dec = new FILE_LINE(31015) SslDecoder;
	memset(dec, 0, sizeof(SslDecoder));
	/* Find the SSLeay cipher */
	if(cipher_suite.enc != ENC_NULL) {
		if (debug) printf("ssl_create_decoder CIPHER: %s\n", ciphers[cipher_suite.enc-0x30]);
		ciph = ssl_get_cipher_by_name(ciphers[cipher_suite.enc-0x30]);
	} else {
		if (debug) printf("ssl_create_decoder CIPHER: %s\n", "NULL");
		ciph = -1;
	}  
	if (ciph == 0) {
		if (debug) printf("ssl_create_decoder can't find cipher %s\n",
			ciphers[cipher_suite.enc > ENC_NULL ? ENC_NULL-0x30 : (cipher_suite.enc-0x30)]);
		return NULL;
	}  

	/* init mac buffer: mac storage is embedded into decoder struct to save a
	 memory allocation and waste samo more memory*/
	dec->cipher_suite = &cipher_suite;
	dec->compression = session.compression;
	/* AEED ciphers don't have a MAC but need to keep the write IV instead */
	if (mk == NULL) {
		dec->write_iv.data = dec->_mac_key_or_write_iv;
		ssl_data_set(&dec->write_iv, iv, cipher_suite.block);
	} else {
		dec->mac_key.data = dec->_mac_key_or_write_iv;
		ssl_data_set(&dec->mac_key, mk, ssl_cipher_suite_dig(&cipher_suite)->len);
	}  
	dec->seq = 0;
	dec->decomp = ssl_create_decompressor(session.compression);
//	dec->flow = ssl_create_flow();

	if (dec->evp)
		ssl_cipher_cleanup(&dec->evp);

	if (ssl_cipher_init(&dec->evp,ciph,sk,iv,cipher_suite.mode) < 0) {
		if (debug) printf("ssl_create_decoder: can't create cipher id:%d mode:%d\n",
			ciph, cipher_suite.mode);
		return NULL;
	}  

	if (debug) printf("decoder initialized (digest len %d)\n", ssl_cipher_suite_dig(&cipher_suite)->len);
	return dec;
}

int
ssl_generate_keyring_material(SslDecryptSessionC *ssl_session)
{

	if(debug) printf("ssl_generate_keyring_material\n");
	StringInfo  key_block;
	guint8	  _iv_c[MAX_BLOCK_SIZE],_iv_s[MAX_BLOCK_SIZE];   
	guint8	  _key_c[MAX_KEY_SIZE],_key_s[MAX_KEY_SIZE];
	gint		needed;										
	guint8	 *ptr,*c_wk,*s_wk,*c_mk,*s_mk,*c_iv = _iv_c,*s_iv = _iv_s;
			   
	/* check for enough info to proced */
	guint need_all = SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION;
	guint need_any = SSL_MASTER_SECRET | SSL_PRE_MASTER_SECRET;
	if (((ssl_session->state & need_all) != need_all) || ((ssl_session->state & need_any) == 0)) {
		if (debug) printf("ssl_generate_keyring_material not enough data to generate key "
						 "(0x%02X required 0x%02X or 0x%02X)\n", ssl_session->state,
						 need_all|SSL_MASTER_SECRET, need_all|SSL_PRE_MASTER_SECRET);
		return -1;			  
	}   
								
	/* if master key is not available, generate is from the pre-master secret */
	if (!(ssl_session->state & SSL_MASTER_SECRET)) {
		if (debug) printf("ssl_generate_keyring_material:PRF(pre_master_secret)\n");
		ssl_print_string("pre master secret",&ssl_session->pre_master_secret);
		ssl_print_string("client random",&ssl_session->client_random);
		ssl_print_string("server random",&ssl_session->server_random);
		if (!prf(ssl_session, &ssl_session->pre_master_secret, "master secret",
				&ssl_session->client_random,
				&ssl_session->server_random, &ssl_session->master_secret,
				SSL_MASTER_SECRET_LENGTH)) {
			if (debug) printf("ssl_generate_keyring_material can't generate master_secret\n");
			return -1;
		}			   
		ssl_print_string("master secret",&ssl_session->master_secret);

		/* the pre-master secret has been 'consumend' so we must clear it now */
		ssl_session->state &= ~SSL_PRE_MASTER_SECRET;
		ssl_session->state |= SSL_MASTER_SECRET;
	}
	
	/* Compute the key block. First figure out how much data we need*/
	needed=ssl_cipher_suite_dig(&ssl_session->cipher_suite)->len*2;
	needed+=ssl_session->cipher_suite.bits / 4;
	if(ssl_session->cipher_suite.block>1)
		needed+=ssl_session->cipher_suite.block*2;
	
	key_block.data = new FILE_LINE(31016) guchar[needed];
	if (debug) printf("ssl_generate_keyring_material sess key generation\n");
	if (!prf(ssl_session, &ssl_session->master_secret, "key expansion",
			&ssl_session->server_random,&ssl_session->client_random,
			&key_block, needed)) {
		if (debug) printf("ssl_generate_keyring_material can't generate key_block\n");
		goto fail;
	}
	ssl_print_string("key expansion", &key_block);

	ptr=key_block.data;
	/* AEAD ciphers do not have a separate MAC */
	if (ssl_session->cipher_suite.mode == MODE_GCM ||
		ssl_session->cipher_suite.mode == MODE_CCM ||
		ssl_session->cipher_suite.mode == MODE_CCM_8) {
		c_mk = s_mk = NULL;
	} else {
		c_mk=ptr; ptr+=ssl_cipher_suite_dig(&ssl_session->cipher_suite)->len;
		s_mk=ptr; ptr+=ssl_cipher_suite_dig(&ssl_session->cipher_suite)->len;
	}

	c_wk=ptr; ptr+=ssl_session->cipher_suite.eff_bits/8;
	s_wk=ptr; ptr+=ssl_session->cipher_suite.eff_bits/8;

	if(ssl_session->cipher_suite.block>1){
		c_iv=ptr; ptr+=ssl_session->cipher_suite.block;
		s_iv=ptr; /*ptr+=ssl_session->cipher_suite.block;*/
	}

	/* export ciphers work with a smaller key length */
	if (ssl_session->cipher_suite.eff_bits < ssl_session->cipher_suite.bits) {
		if(ssl_session->cipher_suite.block>1){

			/* We only have room for MAX_BLOCK_SIZE bytes IVs, but that's
			 all we should need. This is a sanity check */
			if(ssl_session->cipher_suite.block>MAX_BLOCK_SIZE) {
				if (debug) printf("ssl_generate_keyring_material cipher suite block must be at most %d nut is %d\n",
					MAX_BLOCK_SIZE, ssl_session->cipher_suite.block);
				goto fail;
			}

			if(ssl_session->version_netorder==SSLV3_VERSION){
				/* The length of these fields are ignored by this caller */
				StringInfo iv_c, iv_s;
				iv_c.data = _iv_c;
				iv_s.data = _iv_s;
				
				if (debug) printf("ssl_generate_keyring_material ssl3_generate_export_iv\n");
				ssl3_generate_export_iv(&ssl_session->client_random,
						&ssl_session->server_random, &iv_c,
						ssl_session->cipher_suite.block);
				if (debug) printf("ssl_generate_keyring_material ssl3_generate_export_iv(2)\n");
				ssl3_generate_export_iv(&ssl_session->server_random,
						&ssl_session->client_random, &iv_s,
						ssl_session->cipher_suite.block);
			}
			else{
				guint8 _iv_block[MAX_BLOCK_SIZE * 2];
				StringInfo iv_block;
				StringInfo key_null;
				guint8 _key_null;

				key_null.data = &_key_null;
				key_null.data_len = 0;

				iv_block.data = _iv_block;

				if (debug) printf("ssl_generate_keyring_material prf(iv_block)\n");
				if (!prf(ssl_session, &key_null, "IV block",
						&ssl_session->client_random,
						&ssl_session->server_random, &iv_block,
						ssl_session->cipher_suite.block * 2)) {
					if (debug) printf("ssl_generate_keyring_material can't generate tls31 iv block\n");
					goto fail;
				}

				memcpy(_iv_c,iv_block.data,ssl_session->cipher_suite.block);
				memcpy(_iv_s,iv_block.data+ssl_session->cipher_suite.block,
					ssl_session->cipher_suite.block);
			}

			c_iv=_iv_c;
			s_iv=_iv_s;
		}

		if (ssl_session->version_netorder==SSLV3_VERSION){

			SSL_MD5_CTX md5;
			if (debug) printf("ssl_generate_keyring_material MD5(client_random)\n");

			ssl_md5_init(&md5);
			ssl_md5_update(&md5,c_wk,ssl_session->cipher_suite.eff_bits/8);
			ssl_md5_update(&md5,ssl_session->client_random.data,
				ssl_session->client_random.data_len);
			ssl_md5_update(&md5,ssl_session->server_random.data,
				ssl_session->server_random.data_len);
			ssl_md5_final(_key_c,&md5);
			ssl_md5_cleanup(&md5);
			c_wk=_key_c;

			ssl_md5_init(&md5);
			if (debug) printf("ssl_generate_keyring_material MD5(server_random)\n");
			ssl_md5_update(&md5,s_wk,ssl_session->cipher_suite.eff_bits/8);
			ssl_md5_update(&md5,ssl_session->server_random.data,
				ssl_session->server_random.data_len);
			ssl_md5_update(&md5,ssl_session->client_random.data,
				ssl_session->client_random.data_len);
			ssl_md5_final(_key_s,&md5);
			ssl_md5_cleanup(&md5);
			s_wk=_key_s;
		}
		else{
			StringInfo key_c, key_s, k;
			key_c.data = _key_c;
			key_s.data = _key_s;

			k.data = c_wk;
			k.data_len = ssl_session->cipher_suite.eff_bits/8;
			if (debug) printf("ssl_generate_keyring_material PRF(key_c)\n");
			if (!prf(ssl_session, &k, "client write key",
					&ssl_session->client_random,
					&ssl_session->server_random, &key_c, sizeof(_key_c))) {
				if (debug) printf("ssl_generate_keyring_material can't generate tll31 server key \n");
				goto fail;
			}
			c_wk=_key_c;

			k.data = s_wk;
			k.data_len = ssl_session->cipher_suite.eff_bits/8;
			if (debug) printf("ssl_generate_keyring_material PRF(key_s)\n");
			if (!prf(ssl_session, &k, "server write key",
					&ssl_session->client_random,
					&ssl_session->server_random, &key_s, sizeof(_key_s))) {
				if (debug) printf("ssl_generate_keyring_material can't generate tll31 client key \n");
				goto fail;
			}
			s_wk=_key_s;
		}
	}

	/* show key material info */
	if (c_mk != NULL) {
		ssl_print_data("Client MAC key",c_mk,ssl_cipher_suite_dig(&ssl_session->cipher_suite)->len);
		ssl_print_data("Server MAC key",s_mk,ssl_cipher_suite_dig(&ssl_session->cipher_suite)->len);
	}
	ssl_print_data("Client Write key",c_wk,ssl_session->cipher_suite.bits/8);
	ssl_print_data("Server Write key",s_wk,ssl_session->cipher_suite.bits/8);

	if(ssl_session->cipher_suite.block>1) {
		ssl_print_data("Client Write IV",c_iv,ssl_session->cipher_suite.block);
		ssl_print_data("Server Write IV",s_iv,ssl_session->cipher_suite.block);
	}
	else {
		ssl_print_data("Client Write IV",c_iv,8);
		ssl_print_data("Server Write IV",s_iv,8);
	}

	/* create both client and server ciphers*/
	if (debug) printf("ssl_generate_keyring_material ssl_create_decoder(client)\n");
	if(!(ssl_session->ssl_create_decoder_client(c_mk, c_wk, c_iv))) {
		if (debug) printf("ssl_generate_keyring_material can't init client decoder\n");
		goto fail;
	}
	if (debug) printf("ssl_generate_keyring_material ssl_create_decoder(server)\n");
	if(!(ssl_session->ssl_create_decoder_server(s_mk, s_wk, s_iv))) {
		if (debug) printf("ssl_generate_keyring_material can't init client decoder\n");
		goto fail;
	}

	if (debug) printf("ssl_generate_keyring_material: client seq %d, server seq %d\n", ssl_session->client_new->seq, ssl_session->server_new->seq);
	delete [] key_block.data;
	ssl_session->state |= SSL_HAVE_SESSION_KEY;
	return 0;

fail:
	delete [] key_block.data;
	return -1;
}

/* Should be called when all parameters are ready (after ChangeCipherSpec), and
 * the decoder should be attempted to be initialized. */
void				   
ssl_finalize_decryption(SslDecryptSessionC *ssl, ssl_master_key_map_t *mk_map)
{
	if (debug) printf("%s state = 0x%02X\n", __FUNCTION__, ssl->state);
	if (ssl->state & SSL_HAVE_SESSION_KEY) {
		if (debug) printf("  session key already available, nothing to do.\n");
		return;
	}  
	   
	/* for decryption, there needs to be a master secret (which can be derived
	 * from pre-master secret). If missing, try to pick a master key from cache
	 * (an earlier packet in the capture or key logfile). */
	if (!(ssl->state & (SSL_MASTER_SECRET | SSL_PRE_MASTER_SECRET)) &&
		!ssl_restore_master_key(ssl, "Session ID", FALSE,
								mk_map->session, &ssl->session_id) &&
		!ssl_restore_master_key(ssl, "Session Ticket", FALSE,
								mk_map->session, &ssl->session_ticket) &&
		!ssl_restore_master_key(ssl, "Client Random", FALSE,
								mk_map->crandom, &ssl->client_random)) {
		/* how unfortunate, the master secret could not be found */
		if (debug) printf("  Cannot find master secret\n");
		return;	 
	}   

	if (ssl_generate_keyring_material(ssl) < 0) {
		if (debug) printf("%s can't generate keyring material\n", __FUNCTION__);
		return;
	}
	if(debug) printf("saving ssl_save_master_key\n");
	ssl_save_master_key(ssl, "Session ID", mk_map->session,
						&ssl->session_id, &ssl->master_secret);
	ssl_save_master_key(ssl, "Session Ticket", mk_map->session,
						&ssl->session_ticket, &ssl->master_secret);
}

const value_string ssl_versions[] = {
    { 0xfefd, "DTLS 1.2" },
    { 0xfeff, "DTLS 1.0" },
    { 0x0100, "DTLS 1.0 (OpenSSL pre 0.9.8f)" },
    { 0x0303, "TLS 1.2" },
    { 0x0302, "TLS 1.1" },
    { 0x0301, "TLS 1.0" },
    { 0x0300, "SSL 3.0" },
    { 0x0002, "SSL 2.0" },
    { 0x00, NULL }
};

static gint
ssl_is_valid_ssl_version(const guint16 version)
{
	const gchar *version_str;
		
	version_str = try_val_to_str(version, ssl_versions);
	return version_str != NULL;
}		




/* applies a heuristic to determine whether
 * or not the data beginning at offset looks
 * like a valid, unencrypted v2 handshake message.
 * since it isn't possible to completely tell random
 * data apart from a valid message without state,
 * we try to help the odds.	 
 */
static gint
ssl_looks_like_valid_v2_handshake(char *data, const guint32 offset, const guint32 record_length)
{
	/* first byte should be a msg_type.
	 *
	 *   - we know we only see client_hello, client_master_key,
	 *	 and server_hello in the clear, so check to see if
	 *	 msg_type is one of those (this gives us a 3 in 2^8
	 *	 chance of saying yes with random payload)
	 *
	 *   - for those three types that we know about, do some
	 *	 further validation to reduce the chance of an error
	 */
	guint8  msg_type;
	guint16 version;
	guint32 sum;
	gint	ret = 0;

	/* fetch the msg_type */
	msg_type = (guint8)*(data + offset);

	switch (msg_type) {
	case SSL2_HND_CLIENT_HELLO:
		/* version follows msg byte, so verify that this is valid */
		version = pntoh16(data + offset + 1);
		ret = ssl_is_valid_ssl_version(version);
		break;
		
	case SSL2_HND_SERVER_HELLO:
		/* version is three bytes after msg_type */
		version = pntoh16(data + offset + 3);
		ret = ssl_is_valid_ssl_version(version);
		break;
		
	case SSL2_HND_CLIENT_MASTER_KEY:
		/* sum of clear_key_length, encrypted_key_length, and key_arg_length
		 * must be less than record length
		 */
		sum  = pntoh16(data + offset + 4); /* clear_key_length */
		sum += pntoh16(data + offset + 6); /* encrypted_key_length */
		sum += pntoh16(data + offset + 8); /* key_arg_length */
		if (sum <= record_length) {
			ret = 1;
		}   
		break;
		
	default:
		break;
	}   
	
	return ret;
}   

/* applies a heuristic to determine whether
 * or not the data beginning at offset looks
 * like a valid, unencrypted pct handshake message.
 * since it isn't possible to completely tell random
 * data apart from a valid message without state,
 * we try to help the odds.
 */
static gint
ssl_looks_like_valid_pct_handshake(char *data, const guint32 offset, const guint32 record_length)
{
	/* first byte should be a msg_type.
	 *
	 *   - we know we only see client_hello, client_master_key,
	 *	 and server_hello in the clear, so check to see if
	 *	 msg_type is one of those (this gives us a 3 in 2^8
	 *	 chance of saying yes with random payload)
	 *
	 *   - for those three types that we know about, do some
	 *	 further validation to reduce the chance of an error
	 */
	guint8  msg_type;
	guint16 version;
	guint32 sum;
	gint	ret = 0;

	/* fetch the msg_type */
	msg_type = (guint8)*(data + offset);

	switch (msg_type) {
	case PCT_MSG_CLIENT_HELLO:
		/* version follows msg byte, so verify that this is valid */
		version = pntoh16(data + offset + 1);
		ret = (version == PCT_VERSION_1);
		break;
		
	case PCT_MSG_SERVER_HELLO:
		/* version is one byte after msg_type */
		version = pntoh16(data + offset + 2);
		ret = (version == PCT_VERSION_1);
		break;
		
	case PCT_MSG_CLIENT_MASTER_KEY:
		/* sum of various length fields must be less than record length */
		sum  = pntoh16(data + offset +  6); /* clear_key_length */
		sum += pntoh16(data + offset +  8); /* encrypted_key_length */
		sum += pntoh16(data + offset + 10); /* key_arg_length */
		sum += pntoh16(data + offset + 12); /* verify_prelude_length */
		sum += pntoh16(data + offset + 14); /* client_cert_length */
		sum += pntoh16(data + offset + 16); /* response_length */
		if (sum <= record_length) {
			ret = 1;
		}   
		break;
		
	case PCT_MSG_SERVER_VERIFY:
		/* record is 36 bytes longer than response_length */
		sum = pntoh16(data + offset + 34); /* response_length */
		if ((sum + 36) == record_length) {
			ret = 1;
		}   
		break;
		
	default:
		break;
	}   
	
	return ret;
}   


/*********************************************************************
 *                                           
 * SSL version 2 Dissectors
 *          
 *********************************************************************/

static void
dissect_ssl2_hnd_client_hello(char *data, packet_info *pinfo, guint32 offset, SslDecryptSessionC *ssl)
{
	/* struct {
	 *	uint8 msg_type;
	 *	 Version version;
	 *	 uint16 cipher_spec_length;
	 *	 uint16 session_id_length;
	 *	 uint16 challenge_length;
	 *	 V2CipherSpec cipher_specs[V2ClientHello.cipher_spec_length];
	 *	 opaque session_id[V2ClientHello.session_id_length];
	 *	 Random challenge;
	 * } V2ClientHello;
	 *
	 * Note: when we get here, offset's already pointing at Version
	 *
	 */
	guint16 version;
	guint16 cipher_spec_length;
	guint16 session_id_length;
	guint16 challenge_length;

	version = pntoh16(data + offset);
	if (!ssl_is_valid_ssl_version(version))
	{
		if(debug) printf("dissect_ssl2_hnd_client_hello: invalid version; probably encrypted data\n");
		return;
	}

	if (ssl) {
		ssl->ssl_set_server(&pinfo->dst, pinfo->ptype, pinfo->destport);

		offset += 2;

		cipher_spec_length = pntoh16(data + offset);
		offset += 2;

		session_id_length = pntoh16(data + offset);
		if (session_id_length > SSLV2_MAX_SESSION_ID_LENGTH_IN_BYTES) {
			if(debug) printf("Invalid session ID length: %d. Session ID length (%u) must be less than %u.", session_id_length, session_id_length, SSLV2_MAX_SESSION_ID_LENGTH_IN_BYTES);
			return;
		}
		offset += 2;

		challenge_length = pntoh16(data + offset);
		offset += 2;

		/* iterate through the cipher specs, showing them */
		while (cipher_spec_length > 0)
		{
			offset += 3;		/* length of one cipher spec */
			cipher_spec_length -= 3;
		}

		/* if there's a session id, show it */
		if (session_id_length > 0)
		{
			/* PAOLO: get session id and reset session state for key [re]negotiation */
			if (ssl)
			{
				memcpy(&ssl->session_id.data, data + offset, session_id_length);
				ssl->session_id.data_len = session_id_length;
				ssl->state &= ~(SSL_HAVE_SESSION_KEY|SSL_MASTER_SECRET|SSL_PRE_MASTER_SECRET|SSL_CIPHER|SSL_SERVER_RANDOM);
			}
			offset += session_id_length;
		}

		/* if there's a challenge, show it */
		if (challenge_length > 0)
		{
			if (ssl)
			{
				/* PAOLO: get client random data; we get at most 32 bytes from
				 challenge */
				gint max;
				max = challenge_length > 32 ? 32 : challenge_length;

				if(debug) printf("client random len: %d padded to 32\n", challenge_length);

				/* client random is padded with zero and 'right' aligned */
				memset(ssl->client_random.data, 0, 32 - max);
				memcpy(&ssl->client_random.data[32 - max], data + offset, max);
				ssl->client_random.data_len = 32;
				ssl->state |= SSL_CLIENT_RANDOM;
				if(debug) printf("dissect_ssl2_hnd_client_hello found CLIENT RANDOM -> state 0x%02X\n", ssl->state);
			}
		}
	}
}

const value_string pct_msg_types[] = {
    { PCT_MSG_CLIENT_HELLO,         "Client Hello" },
    { PCT_MSG_SERVER_HELLO,         "Server Hello" },
    { PCT_MSG_CLIENT_MASTER_KEY,    "Client Master Key" },
    { PCT_MSG_SERVER_VERIFY,        "Server Verify" },
    { PCT_MSG_ERROR,                "Error" },
    { 0x00, NULL }
};

const value_string ssl_20_msg_types[] = {
    { SSL2_HND_ERROR,               "Error" },
    { SSL2_HND_CLIENT_HELLO,        "Client Hello" },
    { SSL2_HND_CLIENT_MASTER_KEY,   "Client Master Key" },
    { SSL2_HND_CLIENT_FINISHED,     "Client Finished" },
    { SSL2_HND_SERVER_HELLO,        "Server Hello" },
    { SSL2_HND_SERVER_VERIFY,       "Server Verify" },
    { SSL2_HND_SERVER_FINISHED,     "Server Finished" },
    { SSL2_HND_REQUEST_CERTIFICATE, "Request Certificate" },
    { SSL2_HND_CLIENT_CERTIFICATE,  "Client Certificate" },
    { 0x00, NULL }
};  
            
/* record layer dissector */
static gint
dissect_ssl2_record(char *data, unsigned int datalen, packet_info *pinfo,
					guint32 offset,
					SslSession *session, gint /*is_from_server*/,
					SslDecryptSessionC *ssl)
{											
	guint32	  initial_offset;			 
	guint8	   byte;					   
	guint8	   record_length_length;	   
	guint32	  record_length;
	guint8	   msg_type;
	const gchar *msg_type_str;
	guint32	  available_bytes;			
											 
	initial_offset  = offset;
	record_length   = 0;
	msg_type_str	= NULL;
				
	/* pull first byte; if high bit is unset, then record
	 * length is three bytes due to padding; otherwise
	 * record length is two bytes
	 */		 
	byte = (guint8)*(data + offset);
	record_length_length = (byte & 0x80) ? 2 : 3;
				
	available_bytes = datalen - offset;
								   
	/*  
	 * Is the record header split across segment boundaries?
	 */		 
	if (available_bytes < record_length_length) {
		/* Not enough bytes available. Stop here. */
		return offset + available_bytes;
	}

	/* parse out the record length */
	switch (record_length_length) {
	case 2:					 /* two-byte record length */
		record_length = (byte & 0x7f) << 8;
		byte = (guint8)*(data + offset + 1);
		record_length += byte;
		break;
	case 3:					 /* three-byte record length */
		record_length = (byte & 0x3f) << 8;
		byte = (guint8)*(data + offset + 1);
		record_length += byte;
		byte = (guint8)*(data + offset + 2);
	}
	/*  
	 * Is the record split across segment boundaries?
	 */
	if (available_bytes < (record_length_length + record_length)) {
		/* Not enough bytes available. Stop here. */
		return offset + available_bytes;
	}
	offset += record_length_length;

	/* pull the msg_type so we can bail if it's unknown */
	msg_type = (guint8)*(data + initial_offset + record_length_length);

	/* if we get a server_hello or later handshake in v2, then set
	 * this to sslv2
	 */
	if (session->version == SSL_VER_UNKNOWN)
	{
		if (ssl_looks_like_valid_pct_handshake(data, (initial_offset + record_length_length), record_length)) {
			session->version = SSL_VER_PCT;
			/*ssl_set_conv_version(pinfo, ssl->session.version);*/
		}
		else if (msg_type >= 2 && msg_type <= 8)
		{
			session->version = SSL_VER_SSLv2;
			/*ssl_set_conv_version(pinfo, ssl->session.version);*/
		}
	}

	/* if we get here, but don't have a version set for the
	 * conversation, then set a version for just this frame
	 * (e.g., on a client hello)
	 */
//	col_set_str(pinfo->cinfo, COL_PROTOCOL,
//					(session->version == SSL_VER_PCT) ? "PCT" : "SSLv2");

	/* see if the msg_type is valid; if not the payload is
	 * probably encrypted, so note that fact and bail
	 */
	msg_type_str = try_val_to_str(msg_type, (session->version == SSL_VER_PCT) ? pct_msg_types : ssl_20_msg_types);

	if (!msg_type_str
		|| ((session->version != SSL_VER_PCT) &&
			!ssl_looks_like_valid_v2_handshake(data, initial_offset + record_length_length, record_length))
		|| ((session->version == SSL_VER_PCT) &&
			!ssl_looks_like_valid_pct_handshake(data, initial_offset + record_length_length, record_length)))
	{
		//col_append_str(pinfo->cinfo, COL_INFO, "Encrypted Data");
		return initial_offset + record_length_length + record_length;
	} else {
		if(debug) printf("%s Record Layer: %s", (session->version == SSL_VER_PCT) ? "PCT" : "SSLv2", msg_type_str);
	}


	/*
	 * dissect the record data
	 */

	/* jump forward to the start of the record data */
	offset = initial_offset + record_length_length;

	offset += 1;				   /* move past msg_type byte */

	if (session->version != SSL_VER_PCT)
	{   
		/* dissect the message (only handle client hello right now) */
		switch (msg_type) {
		case SSL2_HND_CLIENT_HELLO:
			dissect_ssl2_hnd_client_hello(data, pinfo, offset, ssl);
			if (ssl) {
				/* ClientHello is first packet so set direction and try to
				 * find a private key matching the server port */
				ssl->ssl_set_server(&pinfo->dst, pinfo->ptype, pinfo->destport);
				if(!ssl->private_key_c) {
					//FILE *fp = fopen("/root/vox.key", "r");
					string filename = find_ssl_keys(pinfo->src2, pinfo->srcport, pinfo->dst2, pinfo->destport);
					if(debug) printf("Key file:%s\n", filename.c_str());
					if(filename != "") {
						FILE *fp = fopen(filename.c_str(), "r");
						if(fp) {
							ssl->private_key_c = ssl_load_key(fp);
							if(ssl->private_key_c) {
								ssl->private_key = ssl->private_key_c->sexp_pkey;
							}
							fclose(fp);
						} else {
							//TODO: syslog
						}
					}
				}
				//ssl_find_private_key(ssl, ssl_key_hash, pinfo);
			}
			break;

		case SSL2_HND_CLIENT_MASTER_KEY:
			//dissect_ssl2_hnd_client_master_key(tvb, ssl_record_tree, offset);
			break;		  
							
		case SSL2_HND_SERVER_HELLO:
			//dissect_ssl2_hnd_server_hello(tvb, ssl_record_tree, offset, pinfo);
			break;

		case SSL2_HND_ERROR:
		case SSL2_HND_CLIENT_FINISHED:
		case SSL2_HND_SERVER_VERIFY:
		case SSL2_HND_SERVER_FINISHED:
		case SSL2_HND_REQUEST_CERTIFICATE:
		case SSL2_HND_CLIENT_CERTIFICATE:
			/* unimplemented */
			break;

		default:					/* unknown */
			break;
		}
	}
	else
	{
		/* dissect the message */
		switch (msg_type) {
		case PCT_MSG_CLIENT_HELLO:
			//dissect_pct_msg_client_hello(tvb, ssl_record_tree, offset);
			break;
		case PCT_MSG_SERVER_HELLO:
			//dissect_pct_msg_server_hello(tvb, ssl_record_tree, offset, pinfo);
			break;
		case PCT_MSG_CLIENT_MASTER_KEY:
			//dissect_pct_msg_client_master_key(tvb, ssl_record_tree, offset);
			break;
		case PCT_MSG_SERVER_VERIFY:
			//dissect_pct_msg_server_verify(tvb, ssl_record_tree, offset);
			break;
		case PCT_MSG_ERROR:
			//dissect_pct_msg_error(tvb, ssl_record_tree, offset);
			break;

		default:					/* unknown */
			break;
		}
	}
	return (initial_offset + record_length_length + record_length);
}



static gint
dissect_ssl3_record(char *data, unsigned int datalen, packet_info *pinfo,
					guint32 offset,
					SslSession *session, gint is_from_server,
					SslDecryptSessionC *ssl)
{				  

	/*
	 *	struct {
	 *		uint8 major, minor;
	 *	} ProtocolVersion;
	 *
	 *
	 *	enum {
	 *		change_cipher_spec(20), alert(21), handshake(22),
	 *		application_data(23), (255)
	 *	} ContentType;
	 *
	 *	struct {
	 *		ContentType type;
	 *		ProtocolVersion version;
	 *		uint16 length;
	 *		opaque fragment[TLSPlaintext.length];
	 *	} TLSPlaintext;
	 */
	guint32		 record_length;
	guint16		 version;
	guint8		  content_type;
	guint8		  next_byte;
//	proto_tree	 *ti;
//	proto_tree	 *ssl_record_tree;
//	SslAssociation *association;
	guint32		 available_bytes;
   
//	ti = NULL;
//	ssl_record_tree = NULL;
   
	available_bytes = datalen - offset;
   
	/* TLS 1.0/1.1 just ignores unknown records - RFC 2246 chapter 6. The TLS Record Protocol */
	if ((session->version == SSL_VER_TLS || session->version == SSL_VER_TLSv1DOT1 || session->version == SSL_VER_TLSv1DOT2) &&
		(available_bytes >=1 ) && !ssl_is_valid_content_type((guint8)*(data + offset))) {

		if(debug) printf("dissect_ssl3_record: Ignored Unknown Record\n");

		/* on second and subsequent records per frame
		 * add a delimiter on info column
		 */
		return offset + available_bytes;
	}  
   
	/*
	 * Is the record header split across segment boundaries?
	 */
	if (available_bytes < 5) {
		/* Not enough bytes available. Stop here. */
		return offset + available_bytes;
	}  
   
	/*
	 * Get the record layer fields of interest
	 */
	content_type = (guint8)*(data + offset);
	version	   = pntoh16(data + offset + 1);
	record_length = pntoh16(data + offset + 3);
	if(debug) printf("ct:%u rl:%u version:%d test:%x 1:%x 2:%x 3:%x\n", content_type, record_length, version, (short int)*((short int*)(data + offset + 3)), (char)*data, *(data+1), *(data+2));
	if (ssl_is_valid_content_type(content_type)) {
	
		/*
		 * Is the record split across segment boundaries?
		 */
		if (available_bytes < record_length + 5) {
			/* Not enough bytes available. Stop here. */
			return offset + available_bytes;
		}
	} else {

		/* if we don't have a valid content_type, there's no sense
		 * continuing any further
		 */
		return offset + 5 + record_length;
	}

	offset++;
	/* add the version */
	offset += 2;
	/* add the length */
	offset += 2;	/* move past length field itself */

	/*
	 * if we don't already have a version set for this conversation,
	 * but this message's version is authoritative (i.e., it's
	 * not client_hello, then save the version to to conversation
	 * structure and print the column version
	 */
	next_byte = (guint8)*(data + offset);
	if (session->version == SSL_VER_UNKNOWN && ssl_is_authoritative_version_message(content_type, next_byte))
	{				  
		if (version == SSLV3_VERSION)
		{   
			session->version = SSL_VER_SSLv3;
			if (ssl) {
				ssl->version_netorder = version;
				ssl->state |= SSL_VERSION;
				if(debug) printf("dissect_ssl3_record found version 0x%04X -> state 0x%02X\n", ssl->version_netorder, ssl->state);
			}
		}	  
		else if (version == TLSV1_VERSION)
		{

			session->version = SSL_VER_TLS;
			if (ssl) {
				ssl->version_netorder = version;
				ssl->state |= SSL_VERSION;
				if(debug) printf("dissect_ssl3_record found version 0x%04X(TLS 1.0) -> state 0x%02X\n", ssl->version_netorder, ssl->state);
			}
		}
		else if (version == TLSV1DOT1_VERSION)
		{

			session->version = SSL_VER_TLSv1DOT1;
			if (ssl) {
				ssl->version_netorder = version;
				ssl->state |= SSL_VERSION;
				if(debug) printf("dissect_ssl3_record found version 0x%04X(TLS 1.1) -> state 0x%02X\n", ssl->version_netorder, ssl->state);
			}
		}
		else if (version == TLSV1DOT2_VERSION)
		{

			session->version = SSL_VER_TLSv1DOT2;
			if (ssl) {
				ssl->version_netorder = version;
				ssl->state |= SSL_VERSION;
				if(debug) printf("dissect_ssl3_record found version 0x%04X(TLS 1.2) -> state 0x%02X\n", ssl->version_netorder, ssl->state);
			}
		}
	}

	/*
	 * now dissect the next layer
	 */
	if(debug) printf("dissect_ssl3_record: content_type %d %s\n", content_type, val_to_str_const(content_type, ssl_31_content_type, "unknown"));

	/* PAOLO try to decrypt each record (we must keep ciphers "in sync")
	 * store plain text only for app data */

	switch ((ContentType) content_type) {
	case SSL_ID_CHG_CIPHER_SPEC:
		if(debug) printf("dissect_ssl3 SSL_ID_CHG_CIPHER_SPEC\n");
		if (ssl) {
//TODO			ssl_load_keyfile(ssl_options.keylog_filename, &ssl_keylog_file, &ssl_master_key_map);
			ssl_finalize_decryption(ssl, &ssl_master_key_map);
			ssl_change_cipher(ssl, ssl_packet_from_server(ssl, pinfo));
		}
		break;
	case SSL_ID_ALERT:
	{   
		if(debug) printf("dissect_ssl3 SSL_ID_ALERT\n");
		break;
	}
	case SSL_ID_HANDSHAKE:
	{
		if(debug) printf("dissect_ssl3 SSL_ID_HANDSHAKE\n");

		/* try to decrypt handshake record, if possible. Store decrypted
		 * record for later usage. The offset is used as 'key' to identify
		 * this record in the packet (we can have multiple handshake records
		 * in the same frame) */
		if (ssl && decrypt_ssl3_record(data, datalen, pinfo, offset, record_length, content_type, ssl, false)) {
			dissect_ssl3_handshake((char*)ssl_decrypted_data.data, ssl_decrypted_data_avail, pinfo, 0, ssl_decrypted_data_avail, session, is_from_server, ssl, content_type);
		} else {
			dissect_ssl3_handshake(data, datalen, pinfo, offset, record_length, session, is_from_server, ssl, content_type);
		}
		break;
	}
	case SSL_ID_APP_DATA:
		if(debug) printf("dissect_ssl3 SSL_ID_APP_DATA\n");
		if (ssl){
			if(decrypt_ssl3_record(data, datalen, pinfo, offset, record_length, content_type, ssl, true)) {
				//printf("[%s]\n", (char*)ssl_decrypted_data.data);
			}
		}
		break;
	case SSL_ID_HEARTBEAT:
	  { 
		if(debug) printf("dissect_ssl3 SSL_ID_HEARTBEAT\n");
#if 0 // TODO
		tvbuff_t *decrypted;
	   
		if (ssl && decrypt_ssl3_record(tvb, pinfo, offset,
				record_length, content_type, ssl, false))
			ssl_add_record_info(proto_ssl, pinfo, ssl_decrypted_data.data,
								ssl_decrypted_data_avail, offset);

		/* try to retrieve and use decrypted handshake record, if any. */
		decrypted = ssl_get_record_info(tvb, proto_ssl, pinfo, offset);
		if (decrypted) {
			add_new_data_source(pinfo, decrypted, "Decrypted SSL record");
			dissect_ssl3_heartbeat(decrypted, pinfo, ssl_record_tree, 0, session, tvb_reported_length (decrypted), true);
		} else {
			gboolean plaintext = true;
			/* heartbeats before ChangeCipherSpec are unencrypted */
			if (ssl) {
				if (ssl_packet_from_server(ssl, ssl_associations, pinfo)) {
					plaintext = ssl->server == NULL;
				} else {
					plaintext = ssl->client == NULL;
				}
			}
			dissect_ssl3_heartbeat(tvb, pinfo, ssl_record_tree, offset, session, record_length, plaintext);
		}
#endif
		break;
	  }
	}
	offset += record_length; /* skip to end of record */

	return offset;
}



string
pinfohash1(packet_info *pinfo) {
	char tmp[13];
	memcpy(tmp, &pinfo->src2, 4);
	memcpy(tmp + 4, &pinfo->srcport, 2);
	memcpy(tmp + 6, &pinfo->dst2, 4);
	memcpy(tmp + 10, &pinfo->destport, 2);
	tmp[12] = '\0';
	
	return string(tmp, 12);
}
string
pinfohash2(packet_info *pinfo) {
	char tmp[13];
	memcpy(tmp, &pinfo->dst2, 4);
	memcpy(tmp + 4, &pinfo->destport, 2);
	memcpy(tmp + 6, &pinfo->src2, 4);
	memcpy(tmp + 10, &pinfo->srcport, 2);
	tmp[12] = '\0';

	return string(tmp, 12);
}

SslDecryptSessionC*
find_or_create_session(packet_info *pinfo) {
	string hash[2];
	for(int pass = 0; pass < 2; pass++) {
		hash[pass] = pass ? pinfohash2(pinfo) : pinfohash1(pinfo);
		/*printf("find_or_create_session:hash%i: %x %x %x %x %x %x %x %x %x %x %x %x | src2[%u] srcport[%u] dst2[%u] dstport[%u]\n", pass + 1, 
		       hash[pass][0], hash[pass][1],hash[pass][2],hash[pass][3],hash[pass][4],hash[pass][5],hash[pass][6],hash[pass][7],hash[pass][8],hash[pass][9],hash[pass][10],hash[pass][11],
		       pinfo->src2, pinfo->srcport, pinfo->dst2, pinfo->destport);*/
		sessions_it = sessions.find(hash[pass]);
		if(sessions_it != sessions.end()) {
			//printf("find_or_create_session:find\n");
			return (*sessions_it).second->session;
		}
	}
	//printf("find_or_create_session:create\n");
	SslDecryptSessionC *ssl_session = new FILE_LINE(31017) SslDecryptSessionC;
	session_t *s = new FILE_LINE(31018) session_t;
	s->session = ssl_session;
	sessions[hash[0]] = s;
	return s->session;
}

void
delete_session(packet_info *pinfo) {
	for(int pass = 0; pass < 2; pass++) {
		string hash = pass ? pinfohash2(pinfo) : pinfohash1(pinfo);
		/*printf("delete_session:hash: %x %x %x %x %x %x %x %x %x %x %x %x | src2[%u] srcport[%u] dst2[%u] dstport[%u]\n", 
		       hash[0], hash[1],hash[2],hash[3],hash[4],hash[5],hash[6],hash[7],hash[8],hash[9],hash[10],hash[11],
		       pinfo->src2, pinfo->srcport, pinfo->dst2, pinfo->destport);*/
		sessions_it = sessions.find(hash);
		if(sessions_it != sessions.end()) {
			// remove all associated keys in hash table ssl_master_key_map.session) 
			ssl_map_hash_it = ssl_map_hash.find(sessions_it->second->session);
			if(ssl_map_hash_it != ssl_map_hash.end()) {
				while(ssl_map_hash_it->second.size()) {
					string key = ssl_map_hash_it->second.front();
					ssl_map_hash_it->second.pop();
					StringInfo keys;
					keys.data = new FILE_LINE(31019) guchar[key.size()];
					keys.data_len = key.size();
					memcpy(keys.data, key.c_str(), key.size());
					g_hash_table_remove(ssl_master_key_map.session, &keys);
					delete [] keys.data;
				}
				ssl_map_hash.erase(ssl_map_hash_it);
			}

			delete sessions_it->second->session;
			delete sessions_it->second;
			sessions.erase(sessions_it);
			break;
		}
	}
}

void decrypt_ssl(vector<string> *rslt_decrypt, char *data, unsigned int datalen, unsigned int saddr, unsigned int daddr, int sport, int dport) {

	packet_info pinfo;
	pinfo.ptype = PT_TCP;
	pinfo.destport = dport;
	pinfo.srcport = sport;
	pinfo.dst2 = daddr;
	pinfo.src2 = saddr;
	set_address(&pinfo.dst, AT_IPv4, 4, &daddr);
	set_address(&pinfo.src, AT_IPv4, 4, &saddr);
	
	rslt_decrypt->clear();
	pinfo.decrypt_vec = rslt_decrypt;

	SslDecryptSessionC *ssl_session = find_or_create_session(&pinfo);
	SslSession		*session = &ssl_session->session;

	// check if packet is in configuration and should be observed

	// find or create 


	if(debug) printf("\n\ndl:%u session[%p]\n", datalen, session);

	bool is_from_server;

	is_from_server = ssl_packet_from_server(ssl_session, &pinfo);

	/* TCP packets and SSL records are orthogonal.
	 * A tcp packet may contain multiple ssl records and an ssl
	 * record may be spread across multiple tcp packets.
	 *
	 * This loop accounts for multiple ssl records in a single
	 * frame, but not a single ssl record across multiple tcp
	 * packets.
	 */
	unsigned int offset = 0;
	while (offset < datalen) {
		if(ssl_looks_like_sslv2(data, offset)) {
			offset = dissect_ssl2_record(data, datalen, &pinfo, offset, session, is_from_server, ssl_session);
			if(debug) printf("it is sslv2 off:%u\n", offset);
		} else if(ssl_looks_like_sslv3(data, offset)) {
			offset = dissect_ssl3_record(data, datalen, &pinfo, offset, session, is_from_server, ssl_session);
			if(debug) printf("it is sslv3 off:%u\n", offset);
		} else {
			if(debug) printf("continuos data\n");
			offset = datalen;
		}
	}

/*
	for(std::vector<string>::iterator it = pinfo.decrypt_vec.begin(); it != pinfo.decrypt_vec.end(); ++it) {	
		cout << "------------------\n";
		cout << *it << "\n";
		cout << "------------------\n";
	}
*/
}

void end_decrypt_ssl(unsigned int saddr, unsigned int daddr, int sport, int dport) {
	packet_info pinfo;
	pinfo.ptype = PT_TCP;
	pinfo.destport = dport;
	pinfo.srcport = sport;
	pinfo.dst2 = daddr;
	pinfo.src2 = saddr;
	set_address(&pinfo.dst, AT_IPv4, 4, &daddr);
	set_address(&pinfo.src, AT_IPv4, 4, &saddr);
	
	delete_session(&pinfo);
}


void ssl_free_key(Ssl_private_key_t* key)
{	  

	if(debug) printf("ssl_free_key key->sexp_pkey[%p] key->x509_pkey[%p]\n", key->sexp_pkey, key->x509_pkey);

	gcry_sexp_release(key->sexp_pkey);

	if (key->x509_cert)
		gnutls_x509_crt_deinit (key->x509_cert);

	if (key->x509_pkey) {
		if(debug) printf("gnutls_x509_privkey_deinit(key->x509_pkey)[%p]\n", key->x509_pkey);
		gnutls_x509_privkey_deinit(key->x509_pkey);
	}

	delete key;
}

void
free_sessions(map<string, session_t*> *sessions) {
	map<string, session_t*>::iterator it;
	for(it = sessions->begin(); it != sessions->end(); it++) {
		delete (it->second)->session;
		delete it->second;
	}
}

/* private key table entries have a scope 'larger' then packet capture,
 * so we can't relay on se_alloc** function */
void
ssl_private_key_free(gpointer id, gpointer key, gpointer /*dummy*/)
{
	if (id != NULL) {		   
		delete ((StringInfo*)id);
		ssl_free_key((Ssl_private_key_t*) key);
	}  
}

void
print_decvec(vector<string> *decrypt_vec) {
	for(std::vector<string>::iterator it = decrypt_vec->begin(); it != decrypt_vec->end(); ++it) {	
		cout << "------------------\n";
		cout << *it << "\n";
		cout << "------------------\n";
	}
}

/* Hash Functions for TLS/DTLS sessions table and private keys table*/
gint
ssl_equal (gconstpointer v, gconstpointer v2)
{	   
	const StringInfo *val1;
	const StringInfo *val2;
	val1 = (const StringInfo *)v;
	val2 = (const StringInfo *)v2;

	if (val1->data_len == val2->data_len &&
		!memcmp(val1->data, val2->data, val2->data_len)) {
		return 1;
	}   
	return 0;
}

guint
ssl_hash  (gconstpointer v)
{
	guint l,hash;
	const StringInfo* id;
	const guint* cur;
	hash = 0;
	id = (const StringInfo*) v;

	/*  id and id->data are mallocated in ssl_save_master_key().  As such 'data'
	 *  should be aligned for any kind of access (for example as a guint as
	 *  is done below).  The intermediate void* cast is to prevent "cast
	 *  increases required alignment of target type" warnings on CPUs (such
	 *  as SPARCs) that do not allow misaligned memory accesses.
	 */
	cur = (const guint*)(void*) id->data;

	for (l=4; (l < id->data_len); l+=4, cur++)
		hash = hash ^ (*cur);

	return hash;
}

void 
free_stringinfo(void *p) {
	StringInfo *si = (StringInfo *)p;
	delete si;
}

void
ssl_init() {

	gnutls_global_init();
	
	extern bool init_lib_gcrypt();
	init_lib_gcrypt();

	if(debug) printf("gnutls version: %s\n", gnutls_check_version(NULL));

	if (ssl_master_key_map.session)
		g_hash_table_remove_all(ssl_master_key_map.session);
	else
		ssl_master_key_map.session = g_hash_table_new_full(ssl_hash, ssl_equal, free_stringinfo, free_stringinfo);

	if (ssl_master_key_map.crandom)
		g_hash_table_remove_all(ssl_master_key_map.crandom);
	else
		ssl_master_key_map.crandom = g_hash_table_new_full(ssl_hash, ssl_equal, free_stringinfo, free_stringinfo);

	if (ssl_master_key_map.pre_master)
		g_hash_table_remove_all(ssl_master_key_map.pre_master);
	else
		ssl_master_key_map.pre_master = g_hash_table_new_full(ssl_hash, ssl_equal, free_stringinfo, free_stringinfo);

	ssl_data_alloc(&ssl_decrypted_data, 32);
	ssl_data_alloc(&ssl_compressed_data, 32);

	map<d_u_int32_t, string>::iterator it;

	//init keys
	for(it = ssl_ipport.begin(); it != ssl_ipport.end(); it++) {
		ssl_keys_t *key = new(ssl_keys_t);
		
		d_u_int32_t ipport = it->first;
		key->ip = ipport[0];
		key->port = ipport[1];
		key->filename = it->second;

		ssl_keys.push_back(key);

	}
}

void
ssl_clean(){
	if(!ssl_master_key_map.session) {
		return;
	}
 
	if(ssl_master_key_map.session) {
		g_hash_table_destroy(ssl_master_key_map.session);
		ssl_master_key_map.session = NULL;
	}
	if(ssl_master_key_map.crandom) {
		g_hash_table_destroy(ssl_master_key_map.crandom);
		ssl_master_key_map.crandom = NULL;
	}
	if(ssl_master_key_map.pre_master) {
		g_hash_table_destroy(ssl_master_key_map.pre_master);
		ssl_master_key_map.pre_master = NULL;
	}
//	g_hash_table_destroy(ssl_key_hash);

	free_sessions(&sessions);

	if (ssl_key_hash)
	{	  
		g_hash_table_foreach(ssl_key_hash, ssl_private_key_free, NULL);
		g_hash_table_destroy(ssl_key_hash);
	}  


	delete [] ssl_decrypted_data.data;
	delete [] ssl_compressed_data.data;
	gnutls_global_deinit();
	
}


void test_ssl() {
	ssl_init();



	vector<string> dec;


// test keys 
	ssl_keys_t *vox = new(ssl_keys_t);
	vox->ip = 3633813416;//216.151.151.168
	vox->port = 5061;
	vox->filename = string("/root/vox.key");

	ssl_keys.push_back(vox);

	ssl_keys_t *devo = new(ssl_keys_t);
	devo->ip = 1123116675;//66.241.102.131
	devo->port = 5061;
	devo->filename = string("/root/devoteam.key");

	ssl_keys.push_back(devo);

// test data 

#if 1

	decrypt_ssl(&dec, (char*)ssl1_peer0_0, sizeof(ssl1_peer0_0), 1, 3633813416, 123, 5061);
	print_decvec(&dec);
	decrypt_ssl(&dec, (char*)ssl1_peer1_0, sizeof(ssl1_peer1_0), 3633813416, 1, 5061, 123);
	print_decvec(&dec);
	decrypt_ssl(&dec, (char*)ssl1_peer0_1, sizeof(ssl1_peer0_1), 1, 3633813416, 123, 5061);
	print_decvec(&dec);
	decrypt_ssl(&dec, (char*)ssl1_peer1_1, sizeof(ssl1_peer1_1), 3633813416, 1, 5061, 123);
	print_decvec(&dec);
	decrypt_ssl(&dec, (char*)ssl1_peer0_2, sizeof(ssl1_peer0_2), 1, 3633813416, 123, 5061);
	print_decvec(&dec);
	decrypt_ssl(&dec, (char*)ssl1_peer1_2, sizeof(ssl1_peer1_2), 3633813416, 1, 5061, 123);
	print_decvec(&dec);
	decrypt_ssl(&dec, (char*)ssl1_peer0_3, sizeof(ssl1_peer0_3), 1, 3633813416, 123, 5061);
	print_decvec(&dec);
	decrypt_ssl(&dec, (char*)ssl1_peer1_3, sizeof(ssl1_peer1_3), 3633813416, 1, 5061, 123);
#endif

#if 1
	printf("############################################\n");
	decrypt_ssl(&dec, (char*)ssl2peer0_0, sizeof(ssl2peer0_0), 1, 1123116675, 123, 5061);
	print_decvec(&dec);
	decrypt_ssl(&dec, (char*)ssl2peer1_0, sizeof(ssl2peer1_0), 1123116675, 1, 5061, 123);
	print_decvec(&dec);
	decrypt_ssl(&dec, (char*)ssl2peer0_2, sizeof(ssl2peer0_2), 1, 1123116675, 123, 5061);
	print_decvec(&dec);
	decrypt_ssl(&dec, (char*)ssl2peer1_2, sizeof(ssl2peer1_2), 1123116675, 1, 5061, 123);
	print_decvec(&dec);
	decrypt_ssl(&dec, (char*)ssl2peer0_8, sizeof(ssl2peer0_8), 1, 1123116675, 123, 5061);
	print_decvec(&dec);
	decrypt_ssl(&dec, (char*)ssl2peer1_3, sizeof(ssl2peer1_3), 1123116675, 1, 5061, 123);
	print_decvec(&dec);
	decrypt_ssl(&dec, (char*)ssl2peer0_12, sizeof(ssl2peer0_12), 1, 1123116675, 123, 5061);
	print_decvec(&dec);
#endif

	ssl_clean();

	dec.clear();
	delete vox;
	delete devo;

}


string getSslStat() {
	extern unsigned int glob_ssl_calls;
	ostringstream outStr;
	if(sessions.size() or glob_ssl_calls) {
		outStr << "tls[" << glob_ssl_calls << "|" << sessions.size() << "]";
	}
	return(outStr.str());
}


void   
ssl_print_data(const gchar* name, const guchar* data, size_t len)
{	  
	if(!debug) return;
	size_t i, j, k;
	fprintf(stdout,"%s[%d]:\n",name, (int) len);
	for (i=0; i<len; i+=16) {
		fprintf(stdout,"| ");
		for (j=i, k=0; k<16 && j<len; ++j, ++k)
			fprintf(stdout,"%.2x ",data[j]);
		for (; k<16; ++k)
			fprintf(stdout,"   ");
		fputc('|', stdout);
		for (j=i, k=0; k<16 && j<len; ++j, ++k) {
			guchar c = data[j];
			if (c < 32 || c > 126) c = '.';
			fputc(c, stdout);
		}
		for (; k<16; ++k)
			fputc(' ', stdout);
		fprintf(stdout,"|\n");
	}  
}	  


#endif
