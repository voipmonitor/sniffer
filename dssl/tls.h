#ifndef __DSSL_TLS_H__
#define __DSSL_TLS_H__


#include "../config.h"

#if defined(HAVE_OPENSSL101) and defined(HAVE_LIBGNUTLS) and defined(HAVE_DSSL_TLS13) and HAVE_DSSL_TLS13

#include <glib.h>
#include <gcrypt.h>
#include <zlib.h>

#include "../ip.h"
#include "../tools_global.h"


#define HAVE_ZLIB true

#if GCRYPT_VERSION_NUMBER >= 0x010600 /* 1.6.0 */
/* Whether to provide support for authentication in addition to decryption. */
#define HAVE_LIBGCRYPT_AEAD
#endif
#if GCRYPT_VERSION_NUMBER >= 0x010700 /* 1.7.0 */
/* Whether AEAD_CHACHA20_POLY1305 can be supported. */
#define HAVE_LIBGCRYPT_CHACHA20_POLY1305
#endif


typedef SimpleBuffer StringInfo;
typedef void *dissector_handle_t;
typedef vmIP address;
typedef int port_type;


#define SSL_VER_UNKNOWN         0
#define SSLV2_VERSION           0x0002 /* not in record layer, SSL_CLIENT_SERVER from
                                          http://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html */
#define SSLV3_VERSION          0x300
#define TLSV1_VERSION          0x301
#define TLSV1DOT1_VERSION      0x302
#define TLSV1DOT2_VERSION      0x303
#define TLSV1DOT3_VERSION      0x304
#define DTLSV1DOT0_VERSION     0xfeff
#define DTLSV1DOT0_OPENSSL_VERSION 0x100
#define DTLSV1DOT2_VERSION     0xfefd

#define KEX_DHE_DSS     0x10
#define KEX_DHE_PSK     0x11
#define KEX_DHE_RSA     0x12
#define KEX_DH_ANON     0x13
#define KEX_DH_DSS      0x14
#define KEX_DH_RSA      0x15
#define KEX_ECDHE_ECDSA 0x16
#define KEX_ECDHE_PSK   0x17
#define KEX_ECDHE_RSA   0x18
#define KEX_ECDH_ANON   0x19
#define KEX_ECDH_ECDSA  0x1a
#define KEX_ECDH_RSA    0x1b
#define KEX_KRB5        0x1c
#define KEX_PSK         0x1d
#define KEX_RSA         0x1e
#define KEX_RSA_PSK     0x1f
#define KEX_SRP_SHA     0x20
#define KEX_SRP_SHA_DSS 0x21
#define KEX_SRP_SHA_RSA 0x22
#define KEX_IS_DH(n)    ((n) >= KEX_DHE_DSS && (n) <= KEX_ECDH_RSA)
#define KEX_TLS13       0x23
#define KEX_ECJPAKE     0x24

#define DIG_MD5         0x40
#define DIG_SHA         0x41
#define DIG_SHA256      0x42
#define DIG_SHA384      0x43
#define DIG_NA          0x44 /* Not Applicable */

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
#define ENC_CHACHA20    0x3A
#define ENC_NULL        0x3B

#define IMPLICIT_NONCE_LEN  4
#define EXPLICIT_NONCE_LEN  8
#define TLS13_AEAD_NONCE_LENGTH     12

#define SSL_CLIENT_RANDOM       (1<<0)
#define SSL_SERVER_RANDOM       (1<<1)
#define SSL_CIPHER              (1<<2)
#define SSL_HAVE_SESSION_KEY    (1<<3)
#define SSL_VERSION             (1<<4)
#define SSL_MASTER_SECRET       (1<<5)
#define SSL_PRE_MASTER_SECRET   (1<<6)
#define SSL_CLIENT_EXTENDED_MASTER_SECRET (1<<7)
#define SSL_SERVER_EXTENDED_MASTER_SECRET (1<<8)
#define SSL_NEW_SESSION_TICKET  (1<<10)
#define SSL_ENCRYPT_THEN_MAC    (1<<11)
#define SSL_SEEN_0RTT_APPDATA   (1<<12)
#define SSL_QUIC_RECORD_LAYER   (1<<13) /* For QUIC (draft >= -13) */

#define DIGEST_MAX_SIZE 48


/* SSL Cipher Suite modes */
typedef enum {
    MODE_STREAM,    /* GenericStreamCipher */
    MODE_CBC,       /* GenericBlockCipher */
    MODE_GCM,       /* GenericAEADCipher */
    MODE_CCM,       /* AEAD_AES_{128,256}_CCM with 16 byte auth tag */
    MODE_CCM_8,     /* AEAD_AES_{128,256}_CCM with 8 byte auth tag */
    MODE_POLY1305,  /* AEAD_CHACHA20_POLY1305 with 16 byte auth tag (RFC 7905) */
} ssl_cipher_mode_t;


#define SSL_CIPHER_CTX gcry_cipher_hd_t
#define SSL_HMAC gcry_md_hd_t
#define SSL_MD gcry_md_hd_t
#define SSL_MASTER_SECRET_LENGTH        48


struct SslDigestAlgo {
    const gchar *name;
    guint len;
};

struct SslDecompress {
    gint compression;
#ifdef HAVE_ZLIB
    z_stream istream;
#endif
};

struct SslCipherSuite {
    gint number;
    gint kex;
    gint enc;
    gint dig;
    ssl_cipher_mode_t mode;
};

struct SslDecoder {
    SslDecoder() {
	#if __GNUC__ >= 8
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wclass-memaccess"
	#endif
	memset(this, 0, sizeof(*this));
	#if __GNUC__ >= 8
	#pragma GCC diagnostic pop
	#endif
    }
    ~SslDecoder();
    const SslCipherSuite *cipher_suite;
    gint compression;
    guchar _mac_key_or_write_iv[48];
    StringInfo mac_key; /* for block and stream ciphers */
    StringInfo write_iv; /* for AEAD ciphers (at least GCM, CCM) */
    SSL_CIPHER_CTX evp;
    SslDecompress *decomp;
    guint64 seq;    /**< Implicit (TLS) or explicit (DTLS) record sequence number. */
    guint16 epoch;
    /*
    SslFlow *flow;
    */
    StringInfo app_traffic_secret;  /**< TLS 1.3 application traffic secret (if applicable), wmem file scope. */
    gboolean restore_session;
};

struct SslSession {
    SslSession() {
	#if __GNUC__ >= 8
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wclass-memaccess"
	#endif
	memset(this, 0, sizeof(*this));
	#if __GNUC__ >= 8
	#pragma GCC diagnostic pop
	#endif
    }
    gint cipher;
    gint compression;
    guint16 version;
    guchar tls13_draft_version;
    gint8 client_cert_type;
    gint8 server_cert_type;
    guint32 client_ccs_frame;
    guint32 server_ccs_frame;

    /* The address/proto/port of the server as determined from heuristics
     * (e.g. ClientHello) or set externally (via ssl_set_master_secret()). */
    address srv_addr;
    port_type srv_ptype;
    guint srv_port;

    /* The Application layer protocol if known (for STARTTLS support) */
    dissector_handle_t   app_handle;
    const char          *alpn_name;
    guint32              last_nontls_frame;
    gboolean             is_session_resumed;

    /* First pass only: track an in-progress handshake reassembly (>0) */
    guint32     client_hs_reassembly_id;
    guint32     server_hs_reassembly_id;
};

struct SslDecryptSession {
    SslDecryptSession() {
	#if __GNUC__ >= 8
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wclass-memaccess"
	#endif
	memset(this, 0, sizeof(*this));
	#if __GNUC__ >= 8
	#pragma GCC diagnostic pop
	#endif
    }
    ~SslDecryptSession() {
	if(server)
	    delete server;
	if(client)
	    delete client;
    }
    guchar _master_secret[SSL_MASTER_SECRET_LENGTH];
    guchar _session_id[256];
    guchar _client_random[32];
    guchar _server_random[32];
    StringInfo session_id;
    StringInfo session_ticket;
    StringInfo server_random;
    StringInfo client_random;
    StringInfo master_secret;
    StringInfo handshake_data;
    /* the data store for this StringInfo must be allocated explicitly with a capture lifetime scope */
    StringInfo pre_master_secret;
    guchar _server_data_for_iv[24];
    StringInfo server_data_for_iv;
    guchar _client_data_for_iv[24];
    StringInfo client_data_for_iv;
    gint state;
    const SslCipherSuite *cipher_suite;
    SslDecoder *server;
    SslDecoder *client;
    SslDecoder *server_new;
    SslDecoder *client_new;
#if defined(HAVE_LIBGNUTLS)
    struct cert_key_id *cert_key_id;   /**< SHA-1 Key ID of public key in certificate. */
#endif
    StringInfo psk;
    StringInfo app_data_segment;
    SslSession session;
    gboolean   has_early_data;

};

#endif

#endif

